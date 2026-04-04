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

Backend runs on port 8000, frontend on port 3000. SQLite data is persisted in a Docker volume.

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
2. **Register** — The first user automatically becomes the superadmin
3. **Upload a scan** — Drag and drop a `.nessus`, `.html`, or `.csv` file
4. **Explore** — Findings are automatically parsed, scored, enriched, and deduplicated

## Onboarding Checklist

After your first login, consider completing these steps:

1. **Configure risk weights** — Go to Settings > Risk Configuration to tune scoring for your environment
2. **Set up SLAs** — Define remediation deadlines per severity in Settings > SLA
3. **Create tags** — Organize assets and findings with hierarchical tags
4. **Set up auto-tag rules** — Automatically tag new findings on upload
5. **Configure integrations** — Connect Jira, ServiceNow, Slack, Teams, or Email
6. **Invite team members** — Add analysts and viewers in Settings > Users
7. **Review asset type rules** — Check Settings > Asset Type Rules to customize how assets are classified (host, web app, cloud instance, etc.)
8. **Create your first campaign** — Group related findings into a remediation campaign

## Navigation

The sidebar is organized into three groups:

**Intelligence**
- Reports — Dashboard, charts, NLP report builder, metrics
- Threat Intel — MITRE ATT&CK data, threat groups, CVE enrichment

**Exposure**
- Assets — Asset inventory with filtering and classification
- Findings — Finding explorer with NLP search
- Inventory — Attack surface data (users, groups, services, software, etc.)

**Response**
- Campaigns — Remediation campaign management
- Remediation — Aggregated solutions grouped by root cause
- Agents — AI-powered security automation agents
