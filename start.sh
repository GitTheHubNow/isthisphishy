#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/backend"
if [ ! -d ".venv" ]; then
  echo "Creating virtual environment..."
  python3 -m venv .venv
fi
source .venv/bin/activate
echo "Installing dependencies..."
pip install -q -r requirements.txt
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🐡 Is This Phishy? is starting..."
echo "  Open http://localhost:8000 in your browser"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
uvicorn app.main:app --host 0.0.0.0 --port 8000
