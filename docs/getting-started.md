# Getting Started

## Prerequisites

- **Python 3.8+** and **Node.js 18+**, or
- **Docker** and **Docker Compose**

## Installation

### Option 1: Quick Start Script

```bash
git clone https://github.com/MrAnde7son/hakuna.git
cd hakuna
./start.sh
```

The script will:
1. Create a Python virtualenv and install backend dependencies
2. Install frontend npm packages
3. Start the backend on `http://localhost:8000`
4. Start the frontend on `http://localhost:3000`
5. Open the app in your browser

### Option 2: Docker

```bash
docker compose up --build
```

Backend runs on port 8000, frontend on port 3000. PostgreSQL runs as the `postgres` service and data is persisted in the `postgres-data` volume.

### Option 3: Manual Setup

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

## First Steps

1. Open `http://localhost:3000`
2. **Register** — The first user automatically becomes the superadmin. An onboarding wizard guides the initial org setup.
3. **Add data** — Either drag and drop a `.nessus`, `.html`, or `.csv` file, or launch an active VM scan from **Scan Management → New Scan**
4. **Explore** — Findings are automatically parsed, scored, enriched, correlated into attack paths, and deduplicated

## Onboarding Checklist

After your first login, consider completing these steps:

1. **Configure risk weights** — Go to Settings > Risk Configuration to tune scoring for your environment
2. **Set up SLAs** — Define remediation deadlines per severity in Settings > SLA
3. **Create tags** — Organize assets and findings with hierarchical tags
4. **Set up auto-tag rules** — Automatically tag new findings on upload (including passthrough from integration source values)
5. **Configure integrations** — Connect Jira, ServiceNow, Slack, Teams, Email, Tenable.io, or CrowdStrike. Build custom connectors with the Integration Builder (Settings > Integration Builder). For on-prem products, deploy a relay agent (Settings > Integrations > Relay Agents).
6. **Add auth profiles for authenticated VM scans** — Settings > Scans > Authentication Profiles. Use static credentials or Playwright form-login flows with optional TOTP.
7. **Set up SIEM ingest** — Create webhook or Splunk HEC endpoints in Settings > Event Ingest, then author detection rules in `/siem/rules` (custom, Sigma import, or built-in templates).
8. **Invite team members** — Add analysts and viewers in Settings > Users. Assign built-in team roles (IT, DevOps, SOC, VM) to scope what each user sees.
9. **Review asset type rules** — Check Settings > Asset Type Rules to customize how assets are classified (host, web app, API endpoint, cloud instance, etc.)
10. **Create your first campaign** — Group related findings into a remediation campaign with a blast-radius preview
11. **Configure SSO** — Settings > SSO for SAML or OIDC if you require enterprise identity

## Navigation

The sidebar is organized into four groups:

**Intelligence**
- Reports — Dashboard, charts, NLP report builder, metrics
- Threat Intel — MITRE ATT&CK data, threat groups, CVE enrichment

**Exposure**
- Assets — Asset inventory with filtering and classification
- Findings — Finding explorer with NLP search
- Attack Paths — Correlated entry → pivot → target chains with LLM narration
- Inventory — Attack surface data (users, groups, services, software, etc.)

**SIEM**
- Event Search — Hot-tier event search with histogram
- Detection Rules — Custom rules, Sigma import, rule library
- Alerts — Triage queue with status/assignee/campaign tracking

**Response**
- Campaigns — Remediation campaign management
- Remediation — Aggregated solutions grouped by root cause
- Agents — AI-powered security automation agents

**Copilot** is always accessible — sliding panel on the right on desktop, full-screen via the bottom tab bar on mobile. Press `Cmd/Ctrl+K` anywhere for the command palette.
