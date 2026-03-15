# hakuna-scanner

External asset discovery and enrichment pipeline using ProjectDiscovery open-source tools. Designed for MSSP/multi-tenant use — scalable to 300 customers (~15K assets) on a single VM.

## Architecture

```
┌─────────┐    ┌────────┐    ┌──────────┐
│ FastAPI  │    │ Celery │    │ Celery   │
│  (API)   │    │ Worker │    │  Beat    │
└────┬─────┘    └───┬────┘    └────┬─────┘
     │              │              │
     └──────┬───────┘──────────────┘
            │
     ┌──────┴──────┐    ┌───────────┐
     │  PostgreSQL  │    │   Redis   │
     │  (assets)    │    │  (broker) │
     └─────────────┘    └───────────┘
```

**Pipeline tools**: subfinder, dnsx, naabu, httpx, tlsx, cdncheck, asnmap, uncover

## Setup

```bash
# 1. Copy env file and add your API keys
cp .env.example .env

# 2. Start everything
docker compose up --build -d

# 3. Verify
curl http://localhost:8000/health
```

## First Run

### 1. Create an org

```bash
curl -X POST http://localhost:8000/api/v1/orgs \
  -H 'Content-Type: application/json' \
  -d '{"name": "Acme Corp"}'
```

Save the returned `id` (UUID).

### 2. Add target domains

```bash
curl -X POST http://localhost:8000/api/v1/orgs/{org_id}/domains \
  -H 'Content-Type: application/json' \
  -d '{"domain": "acme.com"}'
```

### 3. Trigger a scan

```bash
# Full scan (discovery + enrichment)
curl -X POST http://localhost:8000/api/v1/orgs/{org_id}/scans \
  -H 'Content-Type: application/json' \
  -d '{"scan_type": "full"}'

# Or discovery only / enrichment only
curl -X POST ... -d '{"scan_type": "discovery"}'
curl -X POST ... -d '{"scan_type": "enrichment"}'
```

### 4. Check scan status

```bash
curl http://localhost:8000/api/v1/orgs/{org_id}/scans
```

### 5. View discovered assets

```bash
curl http://localhost:8000/api/v1/orgs/{org_id}/assets
curl http://localhost:8000/api/v1/orgs/{org_id}/assets/stats
```

## Export API (for Nuclei / Nessus correlation)

```bash
# JSONL export — feed directly to nuclei
curl "http://localhost:8000/api/v1/orgs/{org_id}/assets/export?format=jsonl"

# CSV export
curl "http://localhost:8000/api/v1/orgs/{org_id}/assets/export?format=csv"

# Filter: only assets with open ports
curl "http://localhost:8000/api/v1/orgs/{org_id}/assets/export?ports_only=true"

# Filter: only HTTPS assets
curl "http://localhost:8000/api/v1/orgs/{org_id}/assets/export?https_only=true"

# Filter: by tech stack
curl "http://localhost:8000/api/v1/orgs/{org_id}/assets/export?tech=nginx"
```

## Events / Change Tracking

```bash
# All events
curl "http://localhost:8000/api/v1/orgs/{org_id}/events"

# Filter by type
curl "http://localhost:8000/api/v1/orgs/{org_id}/events?event_type=new_asset"
curl "http://localhost:8000/api/v1/orgs/{org_id}/events?event_type=cert_expiring"

# Since timestamp
curl "http://localhost:8000/api/v1/orgs/{org_id}/events?since=2026-03-14T00:00:00Z"
```

Event types: `new_asset`, `ip_change`, `port_change`, `tech_change`, `cert_expiring`, `asset_gone`

## Nessus Correlation

Link a hakuna asset to a Nessus internal asset:

```bash
curl -X POST http://localhost:8000/api/v1/orgs/{org_id}/assets/{asset_id}/nessus \
  -H 'Content-Type: application/json' \
  -d '{"nessus_asset_id": "nessus-uuid-here"}'
```

## Scheduled Scans

Celery Beat runs automatically:
- **2:00 AM UTC** — discovery chain for all orgs (subfinder → asnmap → uncover → dnsx → naabu)
- **4:00 AM UTC** — enrichment chain for all orgs (httpx → tlsx → cdncheck → auto-tag → delta)

Orgs are staggered by 30s to avoid thundering herd.

## API Keys

For best results, add API keys in `.env`:
- `SHODAN_API_KEY` — used by uncover for Shodan queries
- `CENSYS_API_ID` + `CENSYS_API_SECRET` — Censys search
- `FOFA_EMAIL` + `FOFA_KEY` — FOFA search

Tools degrade gracefully without keys (fewer results, not errors).

## Development

```bash
# Logs
docker compose logs -f worker
docker compose logs -f api

# Run migrations manually
docker compose exec api alembic upgrade head

# Scale workers
docker compose up -d --scale worker=3
```
