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
- Postgres runs as the `postgres` compose service; data is persisted in the `postgres-data` volume.

### Production Build

```bash
docker compose -f docker-compose.yml up -d --build
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | — (required) | Postgres connection string, e.g. `postgresql://hakuna:hakuna@postgres:5432/hakuna` |
| `JWT_SECRET` | Auto-generated | Secret key for JWT token signing |
| `CORS_ORIGINS` | `http://localhost:3000` | Allowed CORS origins |
| `EASM_SERVICE_URL` | — | URL of external EASM scanner service |

## Data Persistence

The platform runs on PostgreSQL (Cloud SQL in production, a `postgres` compose service in dev). The dev DB is persisted in the `postgres-data` volume across container restarts.

## Configuration Portability

To migrate settings between environments:

1. **Export** current config via `POST /api/config/export`
2. **Import** into new environment via `POST /api/config/import`

This includes risk configuration, auto-tag rules, report templates, campaign workflows, and dedup settings. Use `merge` strategy to preserve existing settings while adding new ones.
