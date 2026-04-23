# CLAUDE.md — Hakuna Codebase Guide

## What is Hakuna?

Multi-tenant exposure management platform. Ingests scan data (Nessus, Qualys, Rapid7, OpenVAS), deduplicates and prioritizes findings, tracks remediation campaigns, and integrates with ticketing/chat systems. Supports MSSP parent-child tenancy, AI agents, workflow automation, and threat intelligence enrichment.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.11, FastAPI 0.115, SQLAlchemy 2.0, Pydantic 2.9 |
| Frontend | React 18, Vite 7, React Router 6, Recharts, i18next (12 languages) |
| Database | PostgreSQL 15 (dev via docker-compose, prod via Cloud SQL) |
| Auth | JWT (python-jose) + RBAC with 30+ granular permissions |
| AI | Claude, GPT, Gemini, Groq/Llama — multi-provider with graceful fallback |
| Infra | Docker Compose (local), GCP Cloud Run + Cloud SQL (prod), Terraform |
| Error tracking | Sentry |

## Repository Structure

```
hakuna/
├── backend/                 # FastAPI application
│   ├── app.py               # Main entry — mounts all routers (~400KB monolith)
│   ├── models/models.py     # SQLAlchemy ORM (40+ tables, ~80KB)
│   ├── core/                # Auth, database, audit, i18n, risk config
│   ├── routes/              # API endpoint handlers by domain
│   ├── services/            # Business logic (prioritizer, dedup, rule engine, etc.)
│   ├── agents/              # AI agent system with 50+ security tools
│   ├── parsers/             # Scanner file parsers (Nessus, Qualys, Rapid7, OpenVAS)
│   ├── integrations/        # Jira, ServiceNow, Slack, Teams, Email adapters
│   ├── config/              # dedup_config.json, risk_config.json
│   ├── migrations/          # Python migration scripts (NNN_description.py)
│   ├── tests/               # pytest unit tests
│   └── requirements.txt     # Python dependencies
├── frontend/                # React SPA
│   ├── src/
│   │   ├── App.jsx          # Router + nav + lazy loading (~27KB)
│   │   ├── api.js           # API client with auth headers (~40KB)
│   │   ├── components/      # Feature-organized: agents, assets, findings, campaigns, etc.
│   │   ├── contexts/        # AuthContext, ThemeContext
│   │   ├── i18n/            # Translations + RTL support
│   │   └── utils/           # Shared utilities
│   ├── tests/smoke.spec.js  # Playwright E2E smoke tests
│   └── package.json
├── hakuna/                  # Scanner/integration packages
├── hakuna-scanner/          # EASM scanner component
├── hakuna-vm-scanner/       # VM vulnerability scanner (Nuclei-based)
├── docs/                    # User documentation (getting-started, api-reference, etc.)
├── terraform/               # GCP infrastructure as code
├── docker-compose.yml       # Local multi-container orchestration
├── start.sh                 # Dev bootstrap (venv, deps, start backend+frontend)
└── deploy.sh                # Production deployment automation
```

## Quick Start

```bash
# Full containerized dev (backend + postgres + frontend + minio).
# Add --profile audits to also run redis + audit-worker.
docker compose up -d
docker compose --profile audits up -d   # with audit worker

# Host-running backend (against the compose Postgres on :5433):
cd backend && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
DATABASE_URL=postgresql://hakuna:hakuna@localhost:5433/hakuna \
  uvicorn app:app --host 0.0.0.0 --port 8000 --reload --env-file .env

cd frontend && npm install && npm run dev
```

- Backend: `http://localhost:8000` (Swagger docs at `/docs`)
- Frontend: `http://localhost:3000` (proxies `/api` to backend)
- Postgres: `localhost:5433` (user/pw `hakuna/hakuna`, db `hakuna`)
- Backend logs: `/tmp/nessus-backend.log`
- Frontend logs: `/tmp/nessus-frontend.log`

## Common Commands

```bash
# Backend tests
cd backend && python -m pytest tests/

# Frontend smoke tests (requires dev server running)
cd frontend && npm run smoke-test

# Frontend build
cd frontend && npm run build

# Docker
docker compose up --build

# Database migrations (run from backend/)
python migrations/001_add_sbom_tables.py
```

## Architecture Decisions

### Backend

- **Monolith app.py**: All routes are mounted in `app.py`. Route handlers are split into `routes/` modules but all registered centrally.
- **No Alembic**: Migrations are standalone Python scripts in `backend/migrations/` with `upgrade()` and `downgrade()` functions. Run them directly.
- **Multi-tenancy**: Organization-scoped via `X-Org-Context` header. Every query filters by `org_id`. MSSP hierarchy supports parent-child access.
- **Dependency injection**: FastAPI `Depends()` for auth (`get_current_user`), DB sessions (`get_db`), and org access (`get_accessible_org_ids`).
- **Configuration**: Business rules in JSON files (`config/dedup_config.json`, `config/risk_config.json`), not hardcoded.

### Frontend

- **Lazy loading**: Every page is `React.lazy()` imported in `App.jsx` for code splitting.
- **No CSS framework**: Inline style objects + CSS variables for theming. Dark mode via `[data-theme="dark"]` selector on `<html>`.
- **i18n**: All user-facing strings go through `t()` from react-i18next. 12 languages, RTL support for Arabic/Hebrew.
- **Auth flow**: JWT token in localStorage (`auth_token`). `AuthContext` provides user state. 401 responses auto-redirect to `/login`.

## Code Conventions

### Python (Backend)

- **snake_case** for functions, variables, file names
- **CamelCase** for SQLAlchemy model classes
- Type hints on all function signatures
- Async route handlers (`async def`)
- Pydantic `BaseModel` for request/response schemas (define inline or in route files)
- Routes prefixed with `/api/`
- Error responses: `raise HTTPException(status_code=..., detail="...")`

### JavaScript (Frontend)

- **Functional components** with hooks — no class components
- **PascalCase** for component names and files (e.g., `AssetInventory.jsx`)
- Default export for page components, named exports for shared components
- `api.js` handles all HTTP calls — don't use `fetch` directly in components
- Icons from `lucide-react`
- Charts from `recharts`

### Database

- Table names: **snake_case plural** (`findings`, `assets`, `custom_roles`)
- Column names: **snake_case** (`created_at`, `org_id`)
- Foreign keys: `{table_singular}_id` (e.g., `scan_id`, `asset_id`)
- Index naming: `ix_{table}_{column}`
- All tables include `org_id` for tenant isolation

## Key Subsystems

### Prioritization (`services/prioritizer.py`)
0–10 priority score combining CVSS, VPR, exploit maturity, asset criticality, and plugin family weights.

### Deduplication (`services/dedup.py`)
Cross-scan dedup for assets (by IP/FQDN/hostname) and findings (by plugin_id + asset_id + port). Configurable via `config/dedup_config.json`.

### Rule Engine (`services/rule_engine.py`)
Unified condition evaluation used by campaigns, auto-tag rules, and criticality rules. Supports operators: eq, neq, contains, regex, cidr, has_tag, etc. with AND/OR logic.

### Workflow Engine (`services/workflow_engine.py`)
DAG-based automation with 30+ node types. Persisted execution state and logging.

### Agent System (`agents/`)
Multi-provider LLM agents with 50+ security tools, streaming execution, scheduling via APScheduler, and pre-built templates.

### Integration System (`services/integrations.py`, `integrations/`)
Bidirectional sync with Jira, ServiceNow. Notifications via Slack, Teams, Email. Credential vault for secure secret storage.

### Threat Intelligence (`routes/threat_intel_routes.py`, `models/threat_intel_models.py`)
MITRE ATT&CK STIX sync, CVE enrichment (NVD v2, CISA KEV), TTP mapping, exploit tracking.

## API Patterns

```python
# Typical route handler pattern
@router.get("/api/findings")
async def list_findings(
    page: int = 1,
    page_size: int = 50,
    search: str = None,
    severity: str = None,
    sort_by: str = "priority_score",
    order: str = "desc",
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    # Always filter by org_ids for tenant isolation
    query = db.query(Finding).filter(Finding.org_id.in_(org_ids))
    ...
```

Standard query parameters: `page`, `page_size`, `search`, `sort_by`, `order`, plus domain-specific filters.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | Yes | PostgreSQL connection string (e.g. `postgresql://hakuna:hakuna@postgres:5432/hakuna`). SQLite is not supported. |
| `JWT_SECRET` | Yes (prod) | Secret for JWT signing |
| `ANTHROPIC_API_KEY` | No | Claude API access for AI agents |
| `OPENAI_API_KEY` | No | GPT API access for AI agents |
| `GOOGLE_API_KEY` | No | Gemini API access for AI agents |
| `SENTRY_DSN` | No | Error tracking |
| `SHODAN_API_KEY` | No | Threat intel enrichment |

## Testing Strategy

- **Backend**: pytest in `backend/tests/`. Tests cover parsers, services (transports, upsert handler, credential vault, field mapper).
- **Frontend**: Playwright smoke tests (`npm run smoke-test`) verify all lazy-loaded routes render without JS errors. Seeds a fake auth token to bypass login.
- Always run `npm run smoke-test` after frontend changes.
- Always run `python -m pytest tests/` after backend changes.

## Common Pitfalls

- `app.py` is very large (~400KB). Search for specific route prefixes or function names rather than reading the whole file.
- `models.py` is also large (~80KB). Models are defined in order of dependency.
- The frontend proxies `/api` to `localhost:8000` in dev — don't hardcode backend URLs in components.
- All database queries MUST filter by `org_id` / `org_ids` for tenant isolation.
- Migrations are NOT Alembic — they're standalone scripts. Run them individually.
- Dev runs against Postgres via docker-compose (`postgres` service on port 5433). The backend boot sequence auto-creates the schema via `init_db()` on first connect — no separate bootstrap step.
