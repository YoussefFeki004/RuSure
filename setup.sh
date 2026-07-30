#!/bin/bash

echo "========================================="
echo "  RuSure - Setup Script"
echo "========================================="

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to print colored output
print_success() { echo -e "${GREEN} $1${NC}"; }
print_warning() { echo -e "${YELLOW}  $1${NC}"; }
print_error() { echo -e "${RED} $1${NC}"; }

# Check Python
echo ""
echo "[1/6] Checking Python..."
if command -v python3 &>/dev/null; then
  print_success "Python found: $(python3 --version)"
else
  print_error "Python not found. Please install Python 3.8+"
  exit 1
fi

# Check Node.js
echo ""
echo "[2/6] Checking Node.js..."
if command -v node &>/dev/null; then
  print_success "Node.js found: $(node --version)"
else
  print_error "Node.js not found. Please install Node.js 16+"
  exit 1
fi

# Check npm
echo ""
echo "[3/6] Checking npm..."
if command -v npm &>/dev/null; then
  print_success "npm found: $(npm --version)"
else
  print_error "npm not found. Please install npm"
  exit 1
fi

# Backend Setup
echo ""
echo "[4/6] Setting up Backend..."
cd backend

# Create virtual environment
if [ ! -d ".venv" ]; then
  print_warning "Creating virtual environment..."
  python3 -m venv .venv
fi

# Activate virtual environment
source .venv/bin/activate

# Install Python dependencies
print_warning "Installing Python dependencies..."
pip install -r requirements.txt >/dev/null 2>&1

if [ $? -eq 0 ]; then
  print_success "Python dependencies installed"
else
  print_error "Failed to install Python dependencies"
  exit 1
fi

# Install Node dependencies for backend (XSS scanner)
print_warning "Installing Node dependencies for backend..."
if [ -f "package.json" ]; then
  npm install >/dev/null 2>&1
  print_success "Backend Node dependencies installed"
else
  print_warning "No package.json found in backend"
fi

# Install Playwright browsers
print_warning "Installing Playwright browsers (this may take a few minutes)..."
npx playwright install chromium >/dev/null 2>&1
print_success "Playwright browsers installed"

cd ..

# Frontend Setup
echo ""
echo "[5/6] Setting up Frontend..."
cd frontend

# Install frontend dependencies
if [ ! -d "node_modules" ]; then
  print_warning "Installing frontend dependencies..."
  npm install --legacy-peer-deps >/dev/null 2>&1
  print_success "Frontend dependencies installed"
else
  print_success "Frontend dependencies already installed"
fi

cd ..

# Create uploads directory
echo ""
echo "[6/6] Creating directories..."
mkdir -p backend/uploads
print_success "Uploads directory created"

# Create .env file (if not exists)
if [ ! -f ".env" ]; then
  cat >.env <<'ENV'
# RuSure Configuration
APP_NAME=RuSure
APP_ENV=development
HOST=0.0.0.0
PORT=5000
FRONTEND_PORT=5173
ENV
  print_success ".env file created"
fi

echo ""
echo "========================================="
echo "   Setup Complete!"
echo "========================================="
echo ""
echo "To start the application:"
echo "  ./start.sh"
echo ""
echo "Or manually:"
echo "  Terminal 1: cd backend && source .venv/bin/activate && python app.py"
echo "  Terminal 2: cd frontend && npm run dev"
echo ""
echo "Access at: http://localhost:5173"
echo "========================================="
