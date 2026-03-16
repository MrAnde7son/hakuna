# Deployment Guide

## Development

### Quick Start

```bash
./start.sh
```

This starts both backend (port 8000) and frontend (port 3000) in development mode with hot-reload.

### Manual Development Setup

**Backend:**

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --port 8000 --reload
```

**Frontend:**

```bash
cd frontend
npm install
npm run dev
```

## Docker

### Build and Run

```bash
docker compose up --build
```

- Backend: `http://localhost:8000`
- Frontend: `http://localhost:3000`
- SQLite database is persisted in a Docker volume

### Production Build

```bash
docker compose -f docker-compose.yml up -d --build
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite:///./nessus.db` | Database connection string |
| `JWT_SECRET` | Auto-generated | Secret key for JWT token signing |
| `CORS_ORIGINS` | `http://localhost:3000` | Allowed CORS origins |
| `EASM_SERVICE_URL` | — | URL of external EASM scanner service |

## Data Persistence

The platform uses SQLite by default. The database file (`nessus.db`) is stored in the backend directory. In Docker, it is mounted as a volume for persistence across container restarts.

## Configuration Portability

To migrate settings between environments:

1. **Export** current config via `POST /api/config/export`
2. **Import** into new environment via `POST /api/config/import`

This includes risk configuration, auto-tag rules, report templates, campaign workflows, and dedup settings. Use `merge` strategy to preserve existing settings while adding new ones.
