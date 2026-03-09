# CLAUDE.md — Nessus Remediation Platform

## Project Overview

**Hakuna Exposure Center** — A full-stack vulnerability remediation and intelligence platform. Parses Nessus scan files (HTML/XML/CSV), manages findings and assets, deduplicates data, scores risk, runs automated workflows, integrates threat intelligence (CISA KEV, EPSS), and manages remediation campaigns.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python, FastAPI 0.115, SQLAlchemy 2.0, Pydantic 2.9 |
| Frontend | React 18.3, Vite 5.4, Recharts, @xyflow/react |
| Database | SQLite (`backend/nessus_remediation.db`) |
| Server | Uvicorn (port 8000), Vite dev server (port 3000) |

## Repository Structure

```
nessus-remediation/
├── backend/
│   ├── app.py                  # Main FastAPI app — all API routes
│   ├── models.py               # SQLAlchemy ORM models
│   ├── database.py             # DB session management
│   ├── parser.py               # Nessus HTML/XML/CSV scan parsing
│   ├── inventory_extractor.py  # WMI/system inventory extraction
│   ├── prioritizer.py          # Risk scoring engine
│   ├── dedup.py                # Finding & asset deduplication
│   ├── dedup_config.json       # Dedup strategies & key fields
│   ├── risk_config.py          # Risk scoring formulas
│   ├── risk_config.json        # Risk weights & criticality rules
│   ├── rule_engine.py          # Unified condition evaluator
│   ├── campaign_query.py       # Campaign condition logic
│   ├── workflow_engine.py      # DAG-based workflow execution
│   ├── tags.py                 # Tag management & auto-tagging
│   ├── threat_intel_models.py  # Threat intel ORM models
│   ├── threat_intel_routes.py  # Threat intel API endpoints
│   ├── threat_intel_sync.py    # CISA KEV & EPSS sync
│   └── requirements.txt        # Python dependencies
├── frontend/
│   ├── src/
│   │   ├── main.jsx            # React entry point
│   │   ├── App.jsx             # Router & navigation
│   │   ├── api.js              # Centralized API client (50+ methods)
│   │   └── components/         # ~20 React components
│   │       ├── ui.jsx          # Shared UI primitives (badges, tables, modals)
│   │       ├── Dashboard.jsx
│   │       ├── AssetInventory.jsx
│   │       ├── FindingExplorer.jsx
│   │       ├── InventoryExplorer.jsx
│   │       ├── Campaigns.jsx / CampaignDetail.jsx
│   │       ├── ThreatIntelCenter.jsx
│   │       ├── WorkflowBuilder.jsx
│   │       ├── ReportBuilder.jsx
│   │       ├── TagManager.jsx
│   │       ├── RiskSettings.jsx / DedupSettings.jsx / SLASettings.jsx
│   │       ├── RuleBuilder.jsx
│   │       ├── BlastRadiusPanel.jsx
│   │       └── RemediationQueue.jsx
│   ├── index.html              # HTML entry with CSS design tokens
│   ├── vite.config.js          # API proxy to backend
│   └── package.json
├── start.sh                    # Launches both backend & frontend
├── intel.json                  # Threat intelligence seed data
└── .gitignore
```

## Development Commands

### Start the full application
```bash
./start.sh
```
This script:
1. Creates/activates Python virtualenv at `backend/.venv`
2. Installs Python deps from `backend/requirements.txt`
3. Starts Uvicorn on port 8000 with auto-reload
4. Installs npm deps and starts Vite on port 3000
5. Opens browser automatically

### Start services individually
```bash
# Backend only
cd backend && source .venv/bin/activate && uvicorn app:app --host 0.0.0.0 --port 8000 --reload

# Frontend only
cd frontend && npm run dev
```

### Verify backend is running
```bash
curl -s http://localhost:8000/api/scans
```

## Architecture & Key Patterns

### Backend Patterns
- **All routes in `app.py`** — single-file API definition (~3,200 lines)
- **Dependency injection** via FastAPI `Depends()` for DB sessions
- **Pydantic models** for request/response validation
- **Async file handling** with `aiofiles`
- **Background tasks** via FastAPI `BackgroundTasks` (threat intel sync)
- **JSON config files** for runtime-tunable settings (risk, dedup)
- **CORS**: `allow_origins=["*"]` (development mode)

### Frontend Patterns
- **Plain JavaScript** — no TypeScript
- **Inline CSS** with CSS custom properties defined in `index.html`
- **React hooks** (useState, useEffect, useContext, useRef) for all state
- **ScanContext** for cross-component scan selection state
- **Centralized API client** (`api.js`) — all fetch calls go through here
- **No external state library** — local state + Context API only

### Database Patterns
- **SQLite** — single-file embedded DB, auto-created on first run
- **Cascade deletes** on foreign keys for referential integrity
- **JSON columns** for storing CVE lists, attack vectors, config blobs
- **Indexed columns**: plugin_id, asset_id for query performance

### API Conventions
- All endpoints prefixed with `/api/`
- **Pagination**: `limit` + `offset` query params
- **Sorting**: `sort_by` + `order` (asc/desc) params
- **Filtering**: entity-specific query params (severity, scan_id, plugin_family, etc.)
- **Response format**: JSON with nested related objects

## Core Modules

### Rule Engine (`rule_engine.py`)
Unified condition evaluator used by auto-tag rules, campaigns, and criticality rules. Supports operators: `eq`, `neq`, `contains`, `regex`, `glob`, `cidr`, `gt`, `lt`, `gte`, `lte`, `is_true`, `is_false`, `has_tag`, `not_has_tag`. Fields span assets, findings, inventory, and tags.

### Deduplication (`dedup.py`)
Within-scan and cross-scan dedup for assets (keyed on IP/FQDN) and findings (keyed on plugin_id/asset_id/port). Strategies: `merge`, `keep_first`, `keep_last`. Configured via `dedup_config.json`.

### Risk Scoring (`prioritizer.py`, `risk_config.py`)
Formula: 70% severity + 30% criticality, with multipliers for exploit maturity and asset criticality (1-5 scale). Auto-criticality rules assign scores based on rule engine conditions.

### Workflow Engine (`workflow_engine.py`)
DAG-based automation with node types: trigger (manual/schedule), action (tag/email/webhook/ticket), decision (condition), merge/split. Execution logged per-run.

### Threat Intelligence (`threat_intel_sync.py`)
Syncs CISA KEV and EPSS data. Links CVEs to threat groups, TTPs, and campaigns. Impact search finds affected assets/findings.

## Key Data Models

- **Scan** — uploaded scan file metadata
- **Asset** — scanned host (IP, FQDN, OS, criticality 1-5)
- **Finding** — vulnerability instance (plugin_id, severity, CVSS, CVE refs)
- **Campaign** / **CampaignFinding** — remediation campaign with query-based finding selection
- **Workflow** — automation DAG (nodes, edges, execution logs)
- **Tag** / **TagAssignment** / **AutoTagRule** — flexible tagging system
- **SLAConfig** — SLA thresholds per severity
- **Inventory*** — 15+ WMI/system inventory entity types
- **ThreatGroup** / **TTP** / **ThreatCVE** / **ThreatCampaign** — threat intel

## Frontend Routes

| Path | Component | Description |
|------|-----------|-------------|
| `/` | Dashboard | KPI cards, severity chart, trends |
| `/assets` | AssetInventory | Asset list with search/filter/sort |
| `/findings` | FindingExplorer | Finding list with grouping/filtering |
| `/findings/:id` | FindingDetail | Single finding deep-dive |
| `/inventory` | InventoryExplorer | WMI/system inventory data |
| `/campaigns` | Campaigns | Campaign list & creation |
| `/campaigns/:id` | CampaignDetail | Campaign findings & blast radius |
| `/threat-intel` | ThreatIntelCenter | KEV/EPSS/threat groups/campaigns |
| `/settings` | Settings tabs | Dedup, Risk, SLA, Tags, Workflows |

## Important Notes

- **No test suite** — no pytest or Jest tests exist yet
- **No CI/CD** — no GitHub Actions or pipeline configuration
- **No Docker** — orchestrated via `start.sh` shell script only
- **SQLite only** — no multi-database support; MVP-scoped
- **Vite proxy** — frontend dev server proxies `/api` to `localhost:8000` (configured in `vite.config.js`)
- **Logs** written to `/tmp/nessus-backend.log` and `/tmp/nessus-frontend.log`

## Conventions for AI Assistants

1. **Backend changes**: All API routes go in `app.py`. New models go in `models.py` (or `threat_intel_models.py` for intel). Keep the single-file-per-concern pattern.
2. **Frontend changes**: Components live in `frontend/src/components/`. API calls go through `api.js`. Use inline CSS with design token variables from `index.html`.
3. **Configuration**: Externalize tunable settings in JSON config files, not hardcoded values.
4. **Rule conditions**: Use the unified rule engine (`rule_engine.py`) for any condition evaluation. Check the catalog at `/api/rule-engine/catalog`.
5. **Database migrations**: SQLAlchemy models auto-create tables. For schema changes, update models and recreate the DB (no migration framework).
6. **No TypeScript**: This project uses plain JavaScript. Do not add `.ts`/`.tsx` files.
7. **No CSS modules/libraries**: Styling is inline. Use CSS custom properties defined in `index.html`.
8. **Parsing new formats**: Extend `parser.py` following the existing pattern of format-specific parse functions.
