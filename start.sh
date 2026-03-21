#!/bin/bash
set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"

echo "═══════════════════════════════════════════════"
echo "  Exposure Command Center"
echo "  Supports: HTML · .nessus XML · CSV"
echo "═══════════════════════════════════════════════"

# ── Backend setup ────────────────────────────────
echo ""
echo "→ Setting up Python backend..."
cd "$ROOT/backend"

if [ ! -d ".venv" ]; then
  echo "  Creating virtualenv..."
  python3 -m venv .venv
fi

source .venv/bin/activate

echo "  Installing Python dependencies..."
pip install -q -r requirements.txt

# Kill any existing backend on 8000
lsof -ti:8000 | xargs kill -9 2>/dev/null || true
sleep 0.5

echo "  Starting backend on http://localhost:8000 ..."
uvicorn app:app --host 0.0.0.0 --port 8000 --reload --env-file .env > /tmp/nessus-backend.log 2>&1 &
BACKEND_PID=$!
echo "  Backend PID: $BACKEND_PID"

# Wait for backend to be ready
for i in $(seq 1 15); do
  if curl -sf http://localhost:8000/api/scans > /dev/null 2>&1; then
    echo "  ✓ Backend ready"
    break
  fi
  sleep 0.5
done

# ── Frontend setup ───────────────────────────────
echo ""
echo "→ Setting up React frontend..."
cd "$ROOT/frontend"

if [ ! -d "node_modules" ]; then
  echo "  Installing npm dependencies..."
  npm install --silent
fi

# Kill any existing frontend on 3000
lsof -ti:3000 | xargs kill -9 2>/dev/null || true
sleep 0.5

echo "  Starting frontend on http://localhost:3000 ..."
npm run dev > /tmp/nessus-frontend.log 2>&1 &
FRONTEND_PID=$!
echo "  Frontend PID: $FRONTEND_PID"

# Wait a moment for Vite
sleep 3

# ── Summary ─────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════"
echo "  ✓ Platform running!"
echo ""
echo "  Frontend:  http://localhost:3000"
echo "  Backend:   http://localhost:8000"
echo "  API docs:  http://localhost:8000/docs"
echo ""
echo "  Logs:"
echo "    Backend:  tail -f /tmp/nessus-backend.log"
echo "    Frontend: tail -f /tmp/nessus-frontend.log"
echo ""
echo "  Press Ctrl+C to stop all services"
echo "═══════════════════════════════════════════════"
echo ""

# Open browser
if command -v open &> /dev/null; then
  open http://localhost:3000
elif command -v xdg-open &> /dev/null; then
  xdg-open http://localhost:3000
fi

# ── Cleanup on exit ──────────────────────────────
cleanup() {
  echo ""
  echo "Shutting down services..."
  kill $BACKEND_PID $FRONTEND_PID 2>/dev/null
  lsof -ti:8000 | xargs kill -9 2>/dev/null || true
  lsof -ti:3000 | xargs kill -9 2>/dev/null || true
  echo "Done."
  exit 0
}
trap cleanup INT TERM
wait
