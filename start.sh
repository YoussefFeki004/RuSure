#!/bin/bash

echo "========================================="
echo "  RuSure - Vulnerability Verification"
echo "========================================="

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_success() { echo -e "${GREEN} $1${NC}"; }
print_warning() { echo -e "${YELLOW}  $1${NC}"; }
print_error() { echo -e "${RED} $1${NC}"; }

# Kill old processes
echo "Cleaning up old processes..."
pkill -f "python.*app.py" 2>/dev/null
pkill -f "vite" 2>/dev/null
sudo fuser -k 5000/tcp 2>/dev/null

# Start Backend
echo ""
echo "[1/2] Starting Flask backend..."
cd "$(dirname "$0")/backend"

# Check and create virtual environment
if [ ! -d ".venv" ]; then
  print_warning "Creating virtual environment..."
  python3 -m venv .venv
fi

# Activate virtual environment
source .venv/bin/activate

# Check if dependencies are installed
if ! pip show flask &>/dev/null; then
  print_warning "Installing Python dependencies..."
  pip install -r requirements.txt >/dev/null 2>&1
fi

# Start the backend
python app.py &
BACKEND_PID=$!
print_success "Backend started on http://localhost:5000 (PID: $BACKEND_PID)"

# Wait for backend to start
sleep 3

# Start Frontend
echo ""
echo "[2/2] Starting React frontend..."
cd ../frontend

# Check and install frontend dependencies
if [ ! -d "node_modules" ]; then
  print_warning "Installing frontend dependencies..."
  npm install --legacy-peer-deps >/dev/null 2>&1
fi

# Start the frontend
npm run dev &
FRONTEND_PID=$!
print_success "Frontend started on http://localhost:5173 (PID: $FRONTEND_PID)"

echo ""
echo "========================================="
echo "  RuSure is running!"
echo "  Frontend: http://localhost:5173"
echo "  Backend:  http://localhost:5000"
echo "========================================="
echo ""
echo "Press Ctrl+C to stop both servers"
echo ""

# Wait for user to press Ctrl+C
wait $BACKEND_PID $FRONTEND_PID
