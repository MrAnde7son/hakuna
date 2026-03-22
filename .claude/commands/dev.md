Start the development servers (backend + frontend).

Run both servers:
1. Start the FastAPI backend: `cd /Users/itamar/Documents/Git/hakuna/backend && source .venv/bin/activate && uvicorn app:app --port 8000 --reload --env-file .env`
2. Start the Vite frontend: `cd /Users/itamar/Documents/Git/hakuna/frontend && npm run dev`

Run both in the background and report their status.
