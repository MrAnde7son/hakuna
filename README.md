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
- **Remediation campaigns** — Group findings into campaigns, assign owners, and track progress.
- **Workflow builder** — Visual drag-and-drop workflow editor for remediation automation.
- **Threat intelligence** — CVE enrichment via bundled `intel.json`, with a dedicated Threat Intel Center view.
- **Attack surface inventory** — Auto-extracts users, groups, services, network connections, scheduled tasks, patches, logged-on users, shares, software, certificates, and more from informational plugin outputs.
- **SLA tracking** — Configure SLA deadlines per severity and track compliance.
- **Deduplication** — Configurable dedup settings to merge duplicate findings across scans.
- **Risk configuration** — Tune scoring weights and thresholds from the UI.
- **Reports** — Dashboard with charts (Recharts), exportable report builder, and top automation requests.

## Quick Start

### Prerequisites

- Python 3.8+
- Node.js 18+

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
├── backend/                # Python/FastAPI
│   ├── app.py              # API routes
│   ├── parser.py           # Multi-format Nessus parser
│   ├── prioritizer.py      # Scoring engine
│   ├── inventory_extractor.py  # Attack surface extraction
│   ├── models.py           # SQLAlchemy models
│   ├── tags.py             # Tagging engine
│   ├── rule_engine.py      # Auto-tag rule evaluator
│   ├── workflow_engine.py  # Workflow execution
│   ├── dedup.py            # Deduplication logic
│   ├── risk_config.py      # Risk scoring configuration
│   └── database.py         # SQLite setup
├── frontend/               # React/Vite
│   └── src/
│       ├── App.jsx         # Router, context, layout
│       └── components/     # All views and shared UI
├── intel.json              # CVE enrichment data
└── start.sh                # One-command launcher
```

**Stack:** FastAPI + SQLAlchemy + SQLite (backend) · React 18 + Vite + Recharts + React Flow (frontend)

## API

Interactive API docs are available at `http://localhost:8000/docs` (Swagger UI) when the backend is running.

Key endpoints:

| Endpoint | Description |
|---|---|
| `POST /api/upload` | Upload a Nessus scan file |
| `GET /api/scans` | List all imported scans |
| `GET /api/assets` | List assets (supports tag filtering) |
| `GET /api/findings` | List findings (supports tag filtering) |
| `GET /api/inventory/*` | Attack surface inventory queries |
| `POST /api/tags` | Create/manage tags |
| `POST /api/auto-tag-rules` | Auto-tagging rules |
| `GET /api/campaigns` | Remediation campaigns |

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
