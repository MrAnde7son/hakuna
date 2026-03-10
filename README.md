# Nessus Remediation Platform

An open-source web platform that imports Nessus scan results, prioritizes vulnerabilities, and helps security teams plan and track remediation — all from a single dashboard.

![Python](https://img.shields.io/badge/python-3.8+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green)
![React](https://img.shields.io/badge/React-18-61DAFB)
![License](https://img.shields.io/badge/license-MIT-brightgreen)

## Features

- **Multi-format import** — Upload `.html`, `.nessus` (XML), or `.csv` exports from Tenable Nessus. Format is auto-detected.
- **Smart prioritization** — Findings are scored using a weighted formula combining CVSS, VPR, exploit availability, asset criticality, and plugin family.
- **Asset & finding inventory** — Browse all assets and findings with filtering, sorting, and drill-down detail views.
- **Tagging system** — Hierarchical tags with colors, bulk assignment, and auto-tag rules that fire on upload.
- **Remediation campaigns** — Rule-based campaign builder with condition catalog, blast-radius preview, owner assignment, and progress tracking.
- **Workflow builder** — Visual drag-and-drop workflow editor with node catalog, templates, and execution engine.
- **Integrations** — Connect to Jira, ServiceNow, Slack, Teams, and Email (SMTP) for workflow automation. Configure and test from the UI.
- **Threat intelligence** — MITRE ATT&CK sync, threat group/TTP mapping, CVE enrichment, and a dedicated Threat Intel Center with impact search.
- **Attack surface inventory** — Auto-extracts users, groups, services, network connections, scheduled tasks, patches, logged-on users, shares, software, certificates, security controls, computers, password policies, environment variables, and AI tools from informational plugin outputs.
- **Ownership inference** — Automatically derives asset ownership from inventory data (primary user, admin contacts, responsible team based on running services).
- **Global exceptions** — Define exception rules to accept risk or mark findings as false positives, with expiration dates and re-evaluation.
- **Scan comparison** — Compare scans side-by-side with delta timelines, regression reports, temporal summaries, and remediation velocity metrics.
- **SLA tracking** — Configure SLA deadlines per severity, track compliance, and recalculate across scans.
- **Deduplication** — Configurable dedup settings to merge duplicate findings across scans.
- **Risk configuration** — Tune scoring weights and thresholds from the UI, recalculate scores in bulk.
- **Reports** — Dashboard with charts (Recharts), exportable report builder, metrics timeline, and top automation requests.
- **Docker support** — Run the full stack with `docker compose up`.

## Quick Start

### Prerequisites

- Python 3.8+ and Node.js 18+, **or**
- Docker and Docker Compose

### One command

```bash
./start.sh
```

This will:
1. Create a Python virtualenv and install backend dependencies
2. Install frontend npm packages
3. Start the backend on `http://localhost:8000`
4. Start the frontend on `http://localhost:3000`
5. Open the app in your browser

### Docker

```bash
docker compose up --build
```

Backend on port 8000, frontend on port 3000. SQLite data is persisted in a Docker volume.

### Manual setup

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

## Usage

1. Open `http://localhost:3000`
2. Click **Upload Scan** and drop in a Nessus export file (`.html`, `.nessus`, or `.csv`)
3. Findings are parsed, scored, and enriched automatically
4. Use the sidebar to navigate between Dashboard, Assets, Findings, Campaigns, Tags, and more

## Architecture

```
├── backend/                    # Python/FastAPI
│   ├── app.py                  # API routes (~4600 lines)
│   ├── parser.py               # Multi-format Nessus parser
│   ├── prioritizer.py          # Scoring engine
│   ├── inventory_extractor.py  # Attack surface extraction
│   ├── models.py               # SQLAlchemy models (30+ tables)
│   ├── tags.py                 # Tagging engine
│   ├── rule_engine.py          # Auto-tag & campaign rule evaluator
│   ├── workflow_engine.py      # Workflow execution engine
│   ├── integrations.py         # Jira, ServiceNow, Slack, Teams, Email connectors
│   ├── ownership_inference.py  # Auto-derive asset ownership
│   ├── threat_intel_routes.py  # Threat intel API (MITRE ATT&CK)
│   ├── threat_intel_sync.py    # MITRE STIX bundle sync
│   ├── campaign_query.py       # Campaign rule query builder
│   ├── dedup.py                # Deduplication logic
│   ├── risk_config.py          # Risk scoring configuration
│   └── database.py             # SQLite setup
├── frontend/                   # React/Vite
│   └── src/
│       ├── App.jsx             # Router, context, layout
│       └── components/
│           ├── Dashboard.jsx           # Charts & summary
│           ├── AssetInventory.jsx      # Asset browser
│           ├── FindingExplorer.jsx     # Finding browser
│           ├── FindingDetail.jsx       # Finding drill-down
│           ├── CampaignDetail.jsx      # Campaign management
│           ├── InventoryExplorer.jsx   # Attack surface explorer
│           ├── ThreatIntelCenter.jsx   # Threat intel dashboard
│           ├── GlobalExceptions.jsx    # Exception management
│           ├── IntegrationSettings.jsx # Integration config
│           ├── ReportBuilder.jsx       # Report generation
│           ├── RemediationQueue.jsx    # Prioritized queue
│           ├── RiskSettings.jsx        # Risk tuning
│           ├── DedupSettings.jsx       # Dedup config
│           └── ui.jsx                  # Shared UI primitives
├── intel.json                  # CVE enrichment data
├── docker-compose.yml          # Docker orchestration
└── start.sh                    # One-command launcher
```

**Stack:** FastAPI + SQLAlchemy + SQLite (backend) · React 18 + Vite + Recharts + React Flow (frontend)

## API

Interactive API docs are available at `http://localhost:8000/docs` (Swagger UI) when the backend is running.

Key endpoints:

| Endpoint | Description |
|---|---|
| `POST /api/upload` | Upload a Nessus scan file |
| `GET /api/scans` | List all imported scans |
| `GET /api/scans/compare` | Compare two scans (delta) |
| `GET /api/assets` | List assets (supports tag filtering) |
| `GET /api/findings` | List findings (supports tag filtering) |
| `PATCH /api/findings/:id/status` | Update finding status |
| `GET /api/inventory/*` | Attack surface inventory (users, groups, services, certs, etc.) |
| `POST /api/tags` | Create/manage tags |
| `POST /api/auto-tag-rules` | Auto-tagging rules |
| `GET /api/campaigns` | Remediation campaigns |
| `POST /api/campaigns/preview` | Preview campaign blast radius |
| `GET /api/workflows` | Workflow definitions |
| `POST /api/workflows/:id/execute` | Execute a workflow |
| `GET /api/integrations` | Integration configs (Jira, Slack, etc.) |
| `GET /api/exceptions` | Global finding exceptions |
| `GET /api/sla/config` | SLA configuration |
| `GET /api/threat-intel/*` | Threat groups, TTPs, campaigns |
| `GET /api/reports/*` | Summary, trending, velocity, regressions |

## Prioritization

Findings are scored on a 0–10 scale:

```
score = (0.30 × CVSS_norm + 0.30 × VPR_norm + 0.20 × exploit_bonus
       + 0.10 × criticality_norm + 0.10 × family_bonus) × 10
```

- Critical findings get a score floor of 7.0, High a floor of 5.0
- Informational findings are capped at 2.5
- Each finding is assigned an **effort level** (quick win / medium / complex) and a suggested **owner team** (IT / DevOps / SecOps / AppSec)

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

MIT
