const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// MIDDLEWARE CONFIGURATION
// ============================================================

// CORS Configuration - Restrictive
const corsOptions = {
  origin: process.env.CORS_ORIGIN || "http://localhost:3000",
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: false,
  maxAge: 3600
};

app.use(cors(corsOptions));
app.use(express.json({ limit: "1kb" })); // Prevent large payloads
app.use(express.static("public"));

// ============================================================
// RATE LIMITING
// ============================================================

// License validation rate limiter (strict)
const licenseRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per IP
  message: "Too many validation attempts. Please try again later.",
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    // Log for audit
    console.warn(`[RATE_LIMIT] License validation attempt from ${req.ip}`);
    return false;
  }
});

// General API rate limiter (moderate)
const apiRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // 30 requests per IP
  standardHeaders: true,
  legacyHeaders: false
});

// Verification rate limiter
const verifyRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60, // Allow frequent verification
  standardHeaders: true,
  legacyHeaders: false
});

// ============================================================
// CONFIGURATION & CONSTANTS
// ============================================================

const EXTERNAL_API = "https://draw.ar-lottery01.com/WinGo/WinGo_1M/GetHistoryIssuePage.json";

// License database (replace with real DB)
const LICENSES = new Map([
  ["LALATENDU-DEMO-2026", {
    expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000,
    features: ["statistics", "history", "backtest"],
    revoked: false
  }]
]);

// Session store (replace with Redis or DB in production)
const sessions = new Map();

// Audit log
const auditLog = [];

// ============================================================
// UTILITY FUNCTIONS
// ============================================================

const logAudit = (action, details) => {
  const entry = {
    timestamp: new Date().toISOString(),
    action,
    ...details
  };
  auditLog.push(entry);
  
  // Keep last 1000 entries
  if (auditLog.length > 1000) {
    auditLog.shift();
  }
  
  console.log(`[AUDIT] ${action}:`, details);
};

const validateLicenseFormat = (license) => {
  if (typeof license !== "string") return false;
  if (license.length < 5 || license.length > 100) return false;
  // Basic format validation
  if (!/^[a-zA-Z0-9\-]+$/.test(license)) return false;
  return true;
};

const generateSessionToken = () => {
  return crypto.randomBytes(32).toString("hex");
};

const getClientIP = (req) => {
  return req.headers["x-forwarded-for"]?.split(",")[0].trim() ||
    req.connection.remoteAddress ||
    "UNKNOWN";
};

// ============================================================
// LICENSE VALIDATION ENDPOINT
// ============================================================

app.post("/api/v1/license/validate", licenseRateLimiter, (req, res) => {
  const clientIP = getClientIP(req);
  const license = String(req.body?.license || "").trim();
  const timestamp = req.body?.timestamp;

  // Input validation
  if (!license) {
    logAudit("LICENSE_VALIDATE_EMPTY", { ip: clientIP });
    return res.status(400).json({
      valid: false,
      error: "INVALID_FORMAT",
      message: "License key is required"
    });
  }

  if (!validateLicenseFormat(license)) {
    logAudit("LICENSE_VALIDATE_INVALID_FORMAT", { ip: clientIP, license: license.slice(0, 10) });
    return res.status(400).json({
      valid: false,
      error: "INVALID_FORMAT",
      message: "License format is invalid"
    });
  }

  // Timestamp validation (prevent replay attacks)
  if (typeof timestamp !== "number") {
    logAudit("LICENSE_VALIDATE_MISSING_TIMESTAMP", { ip: clientIP });
    return res.status(400).json({
      valid: false,
      error: "INVALID_REQUEST",
      message: "Timestamp is required"
    });
  }

  const timeDiff = Math.abs(Date.now() - timestamp);
  if (timeDiff > 5000) { // 5 second tolerance
    logAudit("LICENSE_VALIDATE_REPLAY_DETECTED", { 
      ip: clientIP, 
      timeDiff,
      license: license.slice(0, 10) 
    });
    return res.status(400).json({
      valid: false,
      error: "INVALID_REQUEST",
      message: "Invalid request timestamp"
    });
  }

  // License lookup
  const record = LICENSES.get(license);

  if (!record) {
    logAudit("LICENSE_VALIDATE_NOT_FOUND", { ip: clientIP });
    return res.status(401).json({
      valid: false,
      error: "INVALID_LICENSE",
      message: "Invalid license key"
    });
  }

  // Check revocation
  if (record.revoked) {
    logAudit("LICENSE_VALIDATE_REVOKED", { 
      ip: clientIP, 
      license: license.slice(0, 10) 
    });
    return res.status(401).json({
      valid: false,
      error: "REVOKED",
      message: "License has been revoked"
    });
  }

  // Check expiration
  if (record.expiresAt < Date.now()) {
    logAudit("LICENSE_VALIDATE_EXPIRED", { 
      ip: clientIP, 
      license: license.slice(0, 10) 
    });
    return res.status(401).json({
      valid: false,
      error: "EXPIRED",
      message: "License has expired"
    });
  }

  // Generate session token
  const token = generateSessionToken();
  const sessionExpiry = Math.min(
    record.expiresAt,
    Date.now() + 24 * 60 * 60 * 1000 // Max 24 hour session
  );

  sessions.set(token, {
    license: license.slice(0, 10), // Store truncated for logs
    createdAt: Date.now(),
    expiresAt: sessionExpiry,
    ip: clientIP,
    features: record.features || []
  });

  logAudit("LICENSE_VALIDATE_SUCCESS", { 
    ip: clientIP, 
    license: license.slice(0, 10),
    sessionExpiry
  });

  res.json({
    valid: true,
    token,
    expires_at: sessionExpiry,
    features: record.features || ["statistics", "history"]
  });
});

// ============================================================
// SESSION VERIFICATION ENDPOINT
// ============================================================

app.get("/api/v1/license/verify", verifyRateLimiter, (req, res) => {
  const clientIP = getClientIP(req);
  const auth = req.headers.authorization || "";

  if (!auth.startsWith("Bearer ")) {
    logAudit("VERIFY_MISSING_TOKEN", { ip: clientIP });
    return res.status(401).json({
      valid: false,
      error: "MISSING_TOKEN",
      message: "Missing session token"
    });
  }

  const token = auth.slice(7);

  // Validate token format
  if (!/^[a-f0-9]{64}$/.test(token)) {
    logAudit("VERIFY_INVALID_TOKEN_FORMAT", { ip: clientIP });
    return res.status(401).json({
      valid: false,
      error: "INVALID_TOKEN",
      message: "Invalid session token"
    });
  }

  const session = sessions.get(token);

  if (!session) {
    logAudit("VERIFY_TOKEN_NOT_FOUND", { ip: clientIP });
    return res.status(401).json({
      valid: false,
      error: "INVALID_TOKEN",
      message: "Session not found"
    });
  }

  // Verify IP hasn't changed (optional, can be disabled for mobile)
  if (session.ip !== clientIP && process.env.STRICT_IP_CHECK === "true") {
    logAudit("VERIFY_IP_MISMATCH", { 
      ip: clientIP, 
      sessionIP: session.ip 
    });
    sessions.delete(token);
    return res.status(401).json({
      valid: false,
      error: "IP_MISMATCH",
      message: "Session IP mismatch"
    });
  }

  // Check expiration
  if (session.expiresAt < Date.now()) {
    logAudit("VERIFY_SESSION_EXPIRED", { ip: clientIP });
    sessions.delete(token);
    return res.status(401).json({
      valid: false,
      error: "SESSION_EXPIRED",
      message: "Session has expired"
    });
  }

  res.json({
    valid: true,
    expires_at: session.expiresAt,
    features: session.features
  });
});

// ============================================================
// EXTERNAL DATA PROXY (with auth)
// ============================================================

app.get("/api/v1/data", apiRateLimiter, async (req, res) => {
  const clientIP = getClientIP(req);
  const auth = req.headers.authorization || "";

  // Require authentication
  if (!auth.startsWith("Bearer ")) {
    logAudit("DATA_MISSING_TOKEN", { ip: clientIP });
    return res.status(401).json({
      error: "UNAUTHORIZED",
      message: "Authentication required"
    });
  }

  const token = auth.slice(7);
  const session = sessions.get(token);

  if (!session || session.expiresAt < Date.now()) {
    if (session) sessions.delete(token);
    logAudit("DATA_INVALID_SESSION", { ip: clientIP });
    return res.status(401).json({
      error: "UNAUTHORIZED",
      message: "Invalid or expired session"
    });
  }

  // Verify feature access
  if (!session.features?.includes("statistics")) {
    logAudit("DATA_FEATURE_NOT_ALLOWED", { 
      ip: clientIP, 
      features: session.features 
    });
    return res.status(403).json({
      error: "FORBIDDEN",
      message: "Feature not available for this license"
    });
  }

  try {
    logAudit("DATA_FETCH_START", { ip: clientIP });

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000); // 15 second timeout

    const response = await fetch(EXTERNAL_API, {
      headers: {
        Accept: "application/json",
        "User-Agent": "LALATENDU-PRO/1.0"
      },
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      logAudit("DATA_EXTERNAL_API_ERROR", { 
        ip: clientIP, 
        status: response.status 
      });
      return res.status(502).json({
        error: "EXTERNAL_API_ERROR",
        message: `External API returned HTTP ${response.status}`
      });
    }

    const data = await response.json();

    // Validate response structure
    if (
      !data ||
      typeof data !== "object" ||
      !data.data ||
      !Array.isArray(data.data.list)
    ) {
      logAudit("DATA_INVALID_RESPONSE", { ip: clientIP });
      return res.status(502).json({
        error: "INVALID_EXTERNAL_DATA",
        message: "External API returned unexpected data structure"
      });
    }

    // Validate data list not empty
    if (data.data.list.length === 0) {
      logAudit("DATA_EMPTY_LIST", { ip: clientIP });
      return res.status(502).json({
        error: "NO_DATA",
        message: "External API returned empty data"
      });
    }

    logAudit("DATA_FETCH_SUCCESS", { 
      ip: clientIP, 
      items: data.data.list.length 
    });

    res.json({
      success: true,
      data: {
        list: data.data.list
      }
    });

  } catch (error) {
    if (error.name === "AbortError") {
      logAudit("DATA_TIMEOUT", { ip: clientIP });
      return res.status(504).json({
        error: "TIMEOUT",
        message: "External API request timed out"
      });
    }

    console.error("External API error:", error.message);
    logAudit("DATA_FETCH_FAILED", { 
      ip: clientIP, 
      error: error.message 
    });

    res.status(502).json({
      error: "DATA_FETCH_FAILED",
      message: "Unable to fetch external data"
    });
  }
});

// ============================================================
// HEALTH CHECK
// ============================================================

app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    time: new Date().toISOString(),
    activeSessions: sessions.size
  });
});

// ============================================================
// ADMIN ENDPOINTS (for development only)
// ============================================================

// Only enable in development
if (process.env.NODE_ENV === "development") {
  app.get("/admin/audit", (req, res) => {
    // Add basic auth in production
    res.json(auditLog.slice(-100));
  });

  app.get("/admin/sessions", (req, res) => {
    // Add basic auth in production
    const sessionList = Array.from(sessions.entries()).map(([token, session]) => ({
      token: token.slice(0, 16) + "...",
      license: session.license,
      createdAt: new Date(session.createdAt).toISOString(),
      expiresAt: new Date(session.expiresAt).toISOString(),
      ip: session.ip
    }));
    res.json(sessionList);
  });

  app.post("/admin/add-license", (req, res) => {
    const { license, days } = req.body;
    if (!license || !days) {
      return res.status(400).json({ error: "Missing parameters" });
    }

    LICENSES.set(license, {
      expiresAt: Date.now() + days * 24 * 60 * 60 * 1000,
      features: ["statistics", "history", "backtest"],
      revoked: false
    });

    res.json({ success: true, license, expiresAt: LICENSES.get(license).expiresAt });
  });

  app.post("/admin/revoke-license", (req, res) => {
    const { license } = req.body;
    if (!license) {
      return res.status(400).json({ error: "Missing license" });
    }

    const record = LICENSES.get(license);
    if (!record) {
      return res.status(404).json({ error: "License not found" });
    }

    record.revoked = true;

    // Invalidate all sessions with this license
    for (const [token, session] of sessions.entries()) {
      if (session.license === license.slice(0, 10)) {
        sessions.delete(token);
      }
    }

    res.json({ success: true });
  });
}

// ============================================================
// 404 HANDLER
// ============================================================

app.use((req, res) => {
  res.status(404).json({
    error: "NOT_FOUND",
    message: "Endpoint not found"
  });
});

// ============================================================
// ERROR HANDLER
// ============================================================

app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  logAudit("ERROR", { message: err.message });

  res.status(500).json({
    error: "INTERNAL_ERROR",
    message: process.env.NODE_ENV === "development" ? err.message : "Internal server error"
  });
});

// ============================================================
// SERVER STARTUP
// ============================================================

app.listen(PORT, "0.0.0.0", () => {
  console.log(`[SERVER] LALATENDU PRO running on port ${PORT}`);
  console.log(`[CONFIG] NODE_ENV: ${process.env.NODE_ENV || "production"}`);
  console.log(`[CONFIG] CORS Origin: ${process.env.CORS_ORIGIN || "http://localhost:3000"}`);
});

module.exports = app;
