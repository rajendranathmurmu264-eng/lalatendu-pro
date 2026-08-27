#!/bin/bash

# LALATENDU PRO - Quick Setup Script
# This script sets up the project for development

set -e

echo "============================================"
echo "LALATENDU PRO - Setup"
echo "============================================"
echo ""

# Check Node.js
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 14+"
    exit 1
fi

echo "✅ Node.js version: $(node -v)"
echo ""

# Install dependencies
echo "📦 Installing dependencies..."
npm install
echo "✅ Dependencies installed"
echo ""

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file..."
    cp .env.example .env
    echo "✅ .env created (edit with your configuration)"
else
    echo "✅ .env already exists"
fi

echo ""
echo "============================================"
echo "Setup Complete!"
echo "============================================"
echo ""
echo "Next steps:"
echo ""
echo "1. Edit .env file with your configuration:"
echo "   nano .env"
echo ""
echo "2. Start the server:"
echo "   npm run dev"
echo ""
echo "3. In another terminal, serve the frontend:"
echo "   python -m http.server 8000 --directory public"
echo ""
echo "4. Visit: http://localhost:8000/lalatendu-pro-improved.html"
echo ""
echo "5. Test with license: LALATENDU-DEMO-2026"
echo ""
