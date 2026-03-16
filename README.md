# Nessus Remediation Platform

An open-source vulnerability management platform that imports scan results from multiple scanners, prioritizes vulnerabilities with AI-powered analysis, and helps security teams plan, track, and automate remediation — all from a single dashboard.

![Python](https://img.shields.io/badge/python-3.8+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green)
![React](https://img.shields.io/badge/React-18-61DAFB)
![License](https://img.shields.io/badge/license-MIT-brightgreen)

## Features

### Scan Management & Import
- **Multi-format import** — Upload `.nessus` (XML), `.html`, or `.csv` exports from Tenable Nessus, plus Qualys, Rapid7, and OpenVAS formats. Auto-detected on upload.
- **Cross-source normalization** — Canonical vulnerability identity across scanners via CVE references for consistent deduplication.
- **Scan comparison** — Side-by-side delta timelines, regression reports, temporal summaries, and remediation velocity metrics.
- **Deduplication** — Configurable dedup settings to merge duplicate findings across scans.

### Prioritization & Risk
- **Smart prioritization** — Findings scored 0–10 using a weighted formula combining CVSS, VPR, exploit availability, asset criticality, and plugin family.
- **Risk configuration** — Tune scoring weights and thresholds from the UI, recalculate scores in bulk.
- **Effort estimation** — Each finding is assigned an effort level (quick win / medium / complex) and a suggested owner team (IT / DevOps / SecOps / AppSec).

### Asset Intelligence
- **Asset & finding explorer** — Browse all assets and findings with filtering, sorting, NLP search, and drill-down detail views.
- **Attack surface inventory** — Auto-extracts 18+ entity types from informational plugins: users, groups, services, network connections, scheduled tasks, patches, logged-on users, shares, software, certificates, security controls, computers, password policies, environment variables, AI tools, processes, database instances, and credentials.
- **Asset classification** — Automatically infers environment (production/staging/dev/DMZ/external) from hostname patterns and IP ranges, and detects asset roles (domain controller, database, web server, etc.).
- **Ownership inference** — Derives asset ownership from inventory data (primary user, admin contacts, responsible team) with configurable ownership rules and priority-based assignment.
- **SBOM pipeline** — Software Bill of Materials extracted from inventory, correlated with CVE data and product end-of-life tracking via endoflife.date.
- **External Attack Surface Management (EASM)** — Discovers external-facing domains, ports, technologies, and certificates. Auto-inferred from registration email domain with synthetic scan import.

### Remediation & Automation
- **Remediation campaigns** — Rule-based campaign builder with condition catalog, blast-radius preview (attack path graph visualization), owner assignment, and progress tracking.
- **Aggregated solutions** — Groups related vulnerabilities into single remediation actions by root cause (outdated version, EOL software, missing patch, misconfiguration, deprecated protocol) with downstream impact assessment.
- **AI agent system** — Multi-provider agent framework (Claude, GPT, Gemini, Llama/Mixtral) with 50+ security tools, template gallery (Daily Triage, Weekly Summary, Incident Response, Compliance Report, Executive Dashboard), cron scheduling, streaming execution, and document uploads.
- **Workflow builder** — Visual drag-and-drop workflow editor with node catalog, templates, and execution engine.
- **Integrations** — Connect to Jira, ServiceNow, Slack, Teams, and Email (SMTP) for workflow automation. Configure and test from the UI.

### Threat Intelligence
- **MITRE ATT&CK** — Full STIX bundle sync, threat group/TTP mapping, and CVE enrichment with a dedicated Threat Intel Center.
- **TTP matching** — Maps findings to ATT&CK techniques via plugin ID (high confidence), keyword match (medium), or family heuristics.
- **Auto-updating intel** — Fetches fresh CVE data every 24 hours from NVD API v2 + CISA KEV, marks weaponized exploits.
- **Security tool catalog** — 100+ mappings of service/software patterns to security products (EDR, AV, SIEM, etc.) for coverage gap analysis.

### Governance & Compliance
- **Authentication & RBAC** — JWT-based auth with role-based access control (superadmin, org_admin, analyst, viewer, custom). 30+ granular permissions with tri-state toggles and per-tag restrictions.
- **Multi-tenancy & MSSP** — Multi-org management, org switching, parent-child hierarchies for reseller models, and separate client workspaces.
- **SLA tracking** — Configure SLA deadlines per severity, track compliance, and recalculate across scans.
- **Global exceptions** — Accept risk or mark findings as false positives with expiration dates and automatic re-evaluation.
- **Audit logging** — Immutable activity trail tracking all create/update/delete actions with diff viewer showing old-to-new values.
- **Peer benchmarking** — Compare org metrics (risk grade, MTTR, SLA compliance, critical density) against industry baselines (financial, healthcare, technology, government) and platform-wide aggregates.

### Reporting & Search
- **Reports** — Dashboard with charts (Recharts), exportable report builder, metrics timeline, and top automation requests.
- **NLP report builder** — Natural language queries like "show critical findings on Windows" or "ransomware-linked vulnerabilities" generate instant reports with save-as-template.
- **NLP search bar** — Type queries like "critical Windows servers with exploits" or "quick wins in production" across findings and assets with filter chips and result counts.
- **Data export** — Streaming CSV and JSON export for assets, findings, and all inventory tables.

### Platform
- **Tagging system** — Hierarchical tags with colors, bulk assignment, auto-tag rules, tag mappings from field values, and external tag sources (CSV, ServiceNow, REST API).
- **Config portability** — Export/import organizational configs (risk config, auto-tag rules, report templates, campaign workflows, dedup configs) with conflict resolution strategies.
- **Internationalization** — 12 supported languages: English, Japanese, French, German, Hebrew, Russian, Chinese, Spanish, Portuguese, Dutch, Arabic, and Italian.
- **Dark mode** — System-preference-aware theme toggle with localStorage persistence.
- **In-app documentation** — Searchable user docs covering all features, onboarding, API reference, and keyboard shortcuts.
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
2. Register an account (first user becomes superadmin)
3. Upload a scan file — drag and drop `.nessus`, `.html`, `.csv`, or other supported formats
4. Findings are parsed, scored, enriched, and deduplicated automatically
5. Use the sidebar to navigate between Reports, Assets, Findings, Inventory, Campaigns, Remediation, Agents, Threat Intel, and Settings

## Architecture

```
├── backend/                         # Python/FastAPI
│   ├── app.py                       # Core API routes
│   ├── core/
│   │   ├── auth.py                  # JWT auth, RBAC, multi-tenancy
│   │   ├── audit.py                 # Audit logging
│   │   ├── database.py              # SQLite/SQLAlchemy setup
│   │   ├── i18n.py                  # Internationalization (12 languages)
│   │   └── risk_config.py           # Risk scoring configuration
│   ├── models/
│   │   ├── models.py                # SQLAlchemy models (40+ tables)
│   │   └── threat_intel_models.py   # MITRE ATT&CK models
│   ├── parsers/
│   │   ├── parser.py                # Multi-format scan parser
│   │   ├── nessus_parser.py         # Nessus-specific parser
│   │   ├── inventory_extractor.py   # Attack surface extraction
│   │   └── registry.py              # Parser auto-detection registry
│   ├── routes/
│   │   ├── auth_routes.py           # Registration, login, org management
│   │   ├── threat_intel_routes.py   # Threat intel API
│   │   ├── agent_routes.py          # AI agent CRUD & execution
│   │   ├── export.py                # CSV/JSON data export
│   │   ├── easm_routes.py           # External attack surface management
│   │   ├── sbom_routes.py           # Software bill of materials
│   │   ├── benchmark_routes.py      # Peer benchmarking
│   │   └── config_portability.py    # Config export/import
│   ├── services/
│   │   ├── prioritizer.py           # Scoring engine
│   │   ├── dedup.py                 # Deduplication logic
│   │   ├── tags.py                  # Tagging engine
│   │   ├── rule_engine.py           # Auto-tag & campaign rules
│   │   ├── workflow_engine.py        # Workflow execution engine
│   │   ├── integrations.py          # Jira, ServiceNow, Slack, Teams, Email
│   │   ├── ownership_inference.py   # Auto-derive asset ownership
│   │   ├── campaign_query.py        # Campaign rule query builder
│   │   ├── nlp_search.py            # Natural language search parser
│   │   ├── solution_aggregator.py   # Group findings by root cause
│   │   ├── downstream_impact.py     # Upgrade safety assessment
│   │   ├── asset_classifier.py      # Environment & role inference
│   │   ├── normalizer.py            # Cross-scanner normalization
│   │   ├── easm.py                  # EASM domain discovery
│   │   └── sbom_pipeline.py         # SBOM extraction & EOL tracking
│   ├── agents/
│   │   ├── agent_engine.py          # Multi-LLM execution engine
│   │   ├── agent_pipeline.py        # Multi-stage agent pipelines
│   │   ├── agent_tools.py           # 50+ security tool registry
│   │   ├── agent_prompts.py         # Template system prompts
│   │   ├── agent_scheduler.py       # Cron-based scheduling
│   │   └── agent_context.py         # Agent state management
│   └── threat_intel/
│       ├── threat_intel_sync.py     # MITRE STIX bundle sync
│       ├── intel_updater.py         # NVD + CISA KEV auto-update
│       ├── ttp_matcher.py           # Finding → ATT&CK mapping
│       └── security_tool_catalog.py # Security product detection
├── frontend/                        # React 18 / Vite
│   └── src/
│       ├── App.jsx                  # Router, layout, context providers
│       ├── contexts/
│       │   ├── AuthContext.jsx       # JWT session & permissions
│       │   └── ThemeContext.jsx      # Dark/light mode
│       └── components/
│           ├── reports/             # Dashboard, ReportBuilder, NLPReportBuilder
│           ├── assets/              # AssetInventory, InventoryExplorer
│           ├── findings/            # FindingExplorer, FindingDetail
│           ├── campaigns/           # Campaigns, CampaignDetail, BlastRadiusPanel, RuleBuilder
│           ├── remediation/         # RemediationQueue, AggregatedSolutions
│           ├── agents/              # AgentBuilder, AutomateModal
│           ├── threats/             # ThreatIntelCenter, ExternalSources
│           ├── workflows/           # WorkflowBuilder
│           ├── settings/            # Settings, TagManager, RiskSettings, SLASettings,
│           │                        #   IntegrationSettings, GlobalExceptions, UserManagement,
│           │                        #   RoleManager, AuditLog, OrgsPanel, OwnershipRules,
│           │                        #   TagMappings, UsersPanel
│           ├── upload/              # UploadScan (multi-format, EASM setup)
│           ├── auth/                # Login, Register
│           ├── docs/                # UserDocs (in-app documentation)
│           └── shared/              # ui.jsx, NLPSearchBar
├── intel.json                       # CVE enrichment data
├── docker-compose.yml               # Docker orchestration
└── start.sh                         # One-command launcher
```

**Stack:** FastAPI + SQLAlchemy + SQLite (backend) · React 18 + Vite + Recharts + React Flow (frontend)

## API

Interactive API docs are available at `http://localhost:8000/docs` (Swagger UI) when the backend is running.

Key endpoints:

| Endpoint | Description |
|---|---|
| **Auth** | |
| `POST /api/auth/register` | Register a new account |
| `POST /api/auth/login` | Login and receive JWT token |
| `POST /api/auth/orgs` | Create organization |
| `POST /api/auth/invite` | Invite user to org |
| **Scans** | |
| `POST /api/upload` | Upload a scan file (Nessus, Qualys, Rapid7, OpenVAS) |
| `GET /api/scans` | List all imported scans |
| `GET /api/scans/compare` | Compare two scans (delta) |
| **Assets & Findings** | |
| `GET /api/assets` | List assets (supports tag, NLP, and environment filtering) |
| `GET /api/findings` | List findings (supports tag, NLP, and severity filtering) |
| `PATCH /api/findings/:id/status` | Update finding status |
| `GET /api/nlp-search` | Natural language search |
| **Inventory** | |
| `GET /api/inventory/*` | Attack surface inventory (users, groups, services, certs, software, etc.) |
| `GET /api/sbom/components` | SBOM components with CVE/EOL data |
| **Remediation** | |
| `GET /api/campaigns` | Remediation campaigns |
| `POST /api/campaigns/preview` | Preview campaign blast radius |
| `GET /api/aggregated-solutions` | Grouped remediation recommendations |
| **Automation** | |
| `GET /api/workflows` | Workflow definitions |
| `POST /api/workflows/:id/execute` | Execute a workflow |
| `GET /api/agents` | AI agent definitions |
| `POST /api/agents/:id/run` | Execute an agent (supports streaming) |
| **Tagging** | |
| `POST /api/tags` | Create/manage tags |
| `POST /api/auto-tag-rules` | Auto-tagging rules |
| **Integrations** | |
| `GET /api/integrations` | Integration configs (Jira, ServiceNow, Slack, Teams, Email) |
| **Threat Intel** | |
| `GET /api/threat-intel/*` | Threat groups, TTPs, campaigns, CVE enrichment |
| **Governance** | |
| `GET /api/exceptions` | Global finding exceptions |
| `GET /api/sla/config` | SLA configuration |
| `GET /api/audit-log` | Audit trail |
| `GET /api/benchmarks/*` | Peer benchmarking data |
| **EASM** | |
| `POST /api/easm/setup` | EASM setup wizard |
| `POST /api/easm/scan` | Trigger external domain scan |
| **Data** | |
| `GET /api/export/*` | CSV/JSON export (assets, findings, inventory) |
| `POST /api/config/export` | Export org configuration |
| `POST /api/config/import` | Import org configuration |
| **Reports** | |
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
- Weights and thresholds are fully configurable from Settings > Risk Configuration

## AI Agents

The platform includes a built-in AI agent framework for security automation:

- **Multi-provider support** — Claude (Anthropic), GPT (OpenAI), Gemini (Google), Llama/Mixtral (Groq)
- **50+ built-in tools** — Query findings, check SLA status, identify risk assets, find quick wins, lookup exploit data, and more
- **Template gallery** — Pre-built agents for daily triage, weekly summaries, incident response, compliance reports, and executive dashboards
- **Scheduled execution** — Cron-based scheduling with next-run tracking
- **Streaming output** — Real-time agent responses in the UI
- **Document uploads** — Attach knowledge base documents for agent context

## Multi-Tenancy

Built for MSSPs and enterprise teams with multiple business units:

- **Organizations** — Isolated workspaces with separate data, configs, and users
- **Org switching** — Users with access to multiple orgs can switch context from the sidebar
- **Parent-child hierarchies** — Support for reseller/MSSP models with linked client orgs
- **Per-org configuration** — Independent risk settings, SLA configs, tag rules, and integrations per org

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

MIT
