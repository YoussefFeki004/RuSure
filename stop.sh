#!/bin/bash

echo "========================================="
echo "  Stopping RuSure..."
echo "========================================="

# Kill backend processes
echo "Stopping backend..."
pkill -f "python.*app.py" 2>/dev/null
sudo fuser -k 5000/tcp 2>/dev/null

# Kill frontend processes
echo "Stopping frontend..."
pkill -f "vite" 2>/dev/null
pkill -f "react-scripts" 2>/dev/null
sudo fuser -k 5173/tcp 2>/dev/null

echo " RuSure stopped successfully!"
