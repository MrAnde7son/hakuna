# Hakuna Exposure Management Platform

A vulnerability management platform that supports multi domain scans and integration, prioritizes vulnerabilities with AI-powered analysis, and helps security teams plan, track, and automate remediation — all from a single dashboard.

![Python](https://img.shields.io/badge/python-3.8+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green)
![React](https://img.shields.io/badge/React-18-61DAFB)
![License](https://img.shields.io/badge/license-MIT-brightgreen)

## Features

### Scan Management & Import
- **Multi-format import** — Upload `.nessus` (XML), `.html`, or `.csv` exports from Tenable Nessus, plus Qualys, Rapid7, and OpenVAS formats. Auto-detected on upload.
- **Active VM scanning** — Built-in Nuclei-based scanner (`hakuna-vm-scanner`) runs signature, DAST, and LLM-driven vulnerability agents against live targets. Templates routed by CPE, tech stack, and open ports with dedicated coverage for OT (Siemens PLCs), IoT (Hikvision), and AI surfaces (Ollama, LangChain, vector DBs).
- **Schemathesis API fuzzing** — Property-based fuzzing for OpenAPI and GraphQL endpoints discovered during EASM. Catches 5xx crashes, schema violations, and content-type drift.
- **Specialist LLM agents** — Opt-in vulnerability specialists (injection, XSS, SSRF, authentication, authorization) plus protocol-specific LDAP, SMB, SNMP, SSH, and Linux host audits run per-asset with bounded iteration budgets and typed tool palettes.
- **Agent scheduler & typed capabilities** — A frontier scheduler re-runs applicable specialists after each one commits facts. Structured capabilities (credentials, JWTs, SSRF primitives, internal hosts, WAF presence) flow between agents with confidence, scope, and provenance — powering multi-step exploit composition.
- **CIDR target expansion** — Paste `192.168.1.0/24` into scan targets and Hakuna fans out a job per host. URLs and hostnames pass through untouched; a 1,024-host cap prevents runaway expansion.
- **Atomic rescan swap** — Rescans run in an isolated `scan_run_id` so the last known-good results stay visible until the new run succeeds. Failed rescans auto-revert; successful ones swap findings in a single commit and auto-resolve linked tickets.
- **Authenticated scanning** — `AuthProfile` model supports static credentials and Playwright-driven `form_login` flows with TOTP, session caching (AES-256-GCM), and automatic reuse across Nuclei, Schemathesis, and agent workers.
- **HTTP security header audit** — Every HTTPS response captured during EASM is graded against OWASP Secure Headers guidance (HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy) with per-cookie `Secure`/`HttpOnly`/`SameSite` checks.
- **TLS deep audit** — Enumerates every accepted TLS version and cipher suite, validates the full certificate chain, checks OCSP revocation, and cross-checks DNS CAA records against the cert's actual issuer. Flags deprecated protocols, weak ciphers, untrusted chains, and CAA mismatches.
- **Cross-source normalization** — Canonical vulnerability identity across scanners via CVE references for consistent deduplication.
- **Scan comparison** — Side-by-side delta timelines, regression reports, temporal summaries, and remediation velocity metrics.
- **Scan progress tracking** — Live per-job status with Celery-backed refresh/rescan endpoints and edit-and-rerun.
- **Deduplication** — Per-type dedup configuration with type-specific key fields, match modes (AND/OR), and merge strategies. Supports cross-scan and within-scan scopes for all asset types and entity types. Per-org overrides inherit from platform defaults.

### Prioritization & Risk
- **Smart prioritization** — Findings scored 0–10 using a weighted formula combining CVSS, VPR, exploit availability, asset criticality, and plugin family.
- **Risk configuration** — Tune scoring weights and thresholds from the UI, recalculate scores in bulk.
- **Effort estimation** — Each finding is assigned an effort level (quick win / medium / complex) and a suggested owner team (IT / DevOps / SecOps / AppSec).

### Asset Intelligence
- **Multi-type asset model** — Assets aren't just hosts. The platform natively supports 8 built-in types (host, web app, cloud instance, API endpoint, identity, container image, code repo, K8s workload) plus user-defined custom types. Each type has structured identity keys and type-specific deduplication.
- **Asset type rules** — Low-code classification rules that automatically assign asset types during ingestion based on configurable conditions (e.g., web service detected → web_app). Rules support identity mapping with field copy, domain extraction, static values, and coalesce functions.
- **Asset & finding observations** — Per-source snapshots showing what each scanner or integration contributed to a merged asset or finding. See exactly which fields came from Nessus vs. CrowdStrike vs. EASM.
- **Asset & finding explorer** — Browse all assets and findings with filtering, sorting, NLP search, and drill-down detail views.
- **API endpoint inventory** — OpenAPI/GraphQL specs discovered during EASM are stored as first-class `api_endpoint` assets and fed into Schemathesis fuzzing.
- **Subsidiary domain discovery** — Parent-child domain hierarchies with provenance tracking expand EASM coverage across business units and M&A assets.
- **Attack surface inventory** — Auto-extracts 18+ entity types from informational plugins: users, groups, services, network connections, scheduled tasks, patches, logged-on users, shares, software, certificates, security controls, computers, password policies, environment variables, AI tools, processes, database instances, and credentials.
- **Asset classification** — Automatically infers environment (production/staging/dev/DMZ/external) from hostname patterns and IP ranges, and detects asset roles (domain controller, database, web server, etc.).
- **Ownership inference** — Derives asset ownership from inventory data (primary user, admin contacts, responsible team) with configurable ownership rules and priority-based assignment.
- **Custom fields** — Define arbitrary metadata fields for assets and findings with backfill across existing records.
- **SBOM pipeline** — Software Bill of Materials extracted from inventory, correlated with CVE data and product end-of-life tracking via endoflife.date.
- **External Attack Surface Management (EASM)** — Discovers external-facing domains, ports, technologies, certificates, and screenshots. Auto-inferred from registration email domain with synthetic scan import.

### Attack Paths & Correlation
- **Attack path generation** — Correlation engine builds entry → pivot → target chains with scoring by pivot quality (exploit path verified, service exposed, reachability, identity primitive, inference).
- **LLM-narrated paths** — Each path gets a plain-English narrative explaining the chain, plus recommended mitigations and score breakdowns.
- **Corroboration view** — Findings confirmed by multiple scanners surface separately with higher confidence.
- **Blast radius API** — Risk propagation across attack graph with team-scoped visibility (entry and target must both match the user's owner role scope).

### SIEM & Detection
- **Event ingest** — Hot-tier event ingestion via webhooks, Splunk HEC, and generic CEF/LEEF parsers with HMAC-SHA256 signature verification and token-bucket rate limiting.
- **Event search** — Time-range, severity, source-system, and free-text filtering with histogram visualization.
- **Detection rules** — Custom rules with JSON queries, threshold + time window (5m–24h), group-by fields, MITRE technique tagging, and scheduled evaluation. Supports user-authored, Sigma-imported, and built-in template rules.
- **Suppression rules** — Silence low-fidelity alerts with condition-based matching.
- **Alert triage** — Status workflow (new/investigating/resolved/false positive), campaign linking, assigned-to tracking, and triage notes.
- **Detection rule library** — Template catalog for one-click deployment of common detections.

### Remediation & Automation
- **Remediation campaigns** — Rule-based campaign builder with condition catalog, blast-radius preview (attack path graph visualization), owner assignment, and progress tracking.
- **Aggregated solutions** — Groups related vulnerabilities into single remediation actions by root cause (outdated version, EOL software, missing patch, misconfiguration, deprecated protocol) with downstream impact assessment.
- **AI agent system** — Multi-provider agent framework (Claude, GPT, Gemini, Vertex AI, Groq/Llama, Ollama) with 50+ security tools, template gallery (Daily Triage, Weekly Summary, Incident Response, Compliance Report, Executive Dashboard), cron scheduling, streaming execution, and document uploads.
- **Agent pipelines** — Multi-stage agent chains with model routing (reasoning/deterministic/balanced), structured context handoff, automatic compression, and graceful error handling.
- **Validation agent framework** — Per-finding LLM validation writes `verdict`, `confidence`, and `validated_at` back to findings; prioritizer consumes true-positive signals.
- **LLM feedback loop** — Every LLM interaction (agent, validator, triage, planner) is recorded with tokens, latency, tool calls, and an outcome score in [-1, +1]. On Postgres, pgvector embeddings power exemplar retrieval for future runs.
- **Copilot (web + mobile)** — Context-aware AI assistant in a sliding desktop panel and full-screen mobile experience. Suggested prompts adapt per page, and three autonomy levels (Conservative/Standard/Autonomous) control action approval.
- **Workflow builder** — Visual drag-and-drop workflow editor with node catalog, templates, and execution engine.
- **Integration Builder** — No-code connector platform supporting API (REST/GraphQL), SQL, File upload, LDAP, MCP, and Webhook transports. Auth templates: None, Bearer, OAuth2 client credentials, API Key (header), Basic. Includes multi-step wizard with auto-mapping, sample detection, credential vaulting, and scheduled sync.
- **Integrations** — Connect to Jira, ServiceNow, Slack, Teams, Email (SMTP), Tenable.io/Tenable.sc, and CrowdStrike. Configure and test from the UI. Tenable.io integration guides API-key generation end-to-end.

### Threat Intelligence
- **MITRE ATT&CK** — Full STIX bundle sync, threat group/TTP mapping, and CVE enrichment with a dedicated Threat Intel Center.
- **TTP matching** — Maps findings to ATT&CK techniques via plugin ID (high confidence), keyword match (medium), or family heuristics.
- **Auto-updating intel** — Fetches fresh CVE data every 24 hours from NVD API v2 + CISA KEV, marks weaponized exploits.
- **Security tool catalog** — 100+ mappings of service/software patterns to security products (EDR, AV, SIEM, etc.) for coverage gap analysis.

### Governance & Compliance
- **Authentication & RBAC** — JWT-based auth, SAML/OIDC SSO, and role-based access control (superadmin, org_admin, analyst, viewer, custom). 30+ granular permissions with tri-state toggles and per-tag restrictions.
- **Built-in team roles** — IT, DevOps, SOC, and VM scoped roles with automatic asset/finding filtering. Ownership rules support auto-tag passthrough so team assignment propagates into tags.
- **Multi-tenancy & MSSP** — Multi-org management, org switching, parent-child hierarchies for reseller models, and separate client workspaces.
- **SLA tracking** — Configure SLA deadlines per severity, track compliance, and recalculate across scans.
- **Global exceptions** — Accept risk or mark findings as false positives with expiration dates and automatic re-evaluation.
- **Audit logging** — Immutable activity trail tracking all create/update/delete actions with diff viewer showing old-to-new values.
- **Peer benchmarking** — Compare org metrics (risk grade, MTTR, SLA compliance, critical density) against industry baselines (financial, healthcare, technology, government) and platform-wide aggregates.
- **Control assessments** — Map findings and inventory data to compliance controls for coverage analysis.

### Reporting & Search
- **Reports** — Dashboard with charts (Recharts), exportable report builder, metrics timeline, and top automation requests.
- **NLP report builder** — Natural language queries like "show critical findings on Windows" or "ransomware-linked vulnerabilities" generate instant reports with save-as-template.
- **NLP search bar** — Type queries like "critical Windows servers with exploits" or "quick wins in production" across findings and assets with filter chips and result counts.
- **Data export** — Streaming CSV and JSON export for assets, findings, and all inventory tables.

### Platform
- **Tagging system** — Hierarchical tags with colors, bulk assignment, auto-tag rules (including passthrough from integration sources), tag mappings from field values, and external tag sources (CSV, ServiceNow, REST API).
- **Config portability** — Export/import organizational configs (risk config, auto-tag rules, report templates, campaign workflows, dedup configs) with conflict resolution strategies.
- **On-prem relay agents** — Lightweight Docker agents bridge cloud Hakuna to on-prem products (Jira DC, ServiceNow, CrowdStrike GovCloud). Outbound-only WebSocket connection, `agent_local` or `cloud_managed` credential modes, token rotation, and allowed-host scoping.
- **Command palette** — Cmd+K / Ctrl+K global search across pages, findings, and assets.
- **Notifications** — In-app notification center with unread counts and targeted delivery.
- **Onboarding wizard** — First-run guided setup for new orgs.
- **Internationalization** — 12 supported languages: English, Japanese, French, German, Hebrew, Russian, Chinese, Spanish, Portuguese, Dutch, Arabic, and Italian.
- **Dark mode** — System-preference-aware theme toggle with localStorage persistence.
- **Mobile UI** — Responsive layout with a bottom tab bar that surfaces Copilot as a primary action.
- **In-app documentation** — Searchable user docs covering all features, onboarding, API reference, and keyboard shortcuts.
- **Production-ready infra** — Cloud Run + Cloud SQL deployment via Terraform, Sentry error tracking, migration runner resilient to concurrent replicas, and 500 MB scan upload ceiling.
- **Docker support** — Run the full stack with `docker compose up`.

## Setup

### Prerequisites

- Docker and Docker Compose (recommended for the full stack), **or**
- Python 3.11+ and Node.js 18+ for host-running backend/frontend
- (Optional) `gcloud auth application-default login` if you want Vertex AI / Claude-on-GCP / Gemini providers

### Core stack (backend, frontend, Postgres, MinIO)

The default `docker compose up` brings up everything you need to log in, upload scans, and use the UI.

```bash
cp .env.example .env   # if present; otherwise create one (see env vars below)
docker compose up -d
```

| Service | Port | Notes |
|---|---|---|
| Frontend (Vite) | `http://localhost:3000` | Proxies `/api` to backend |
| Backend (FastAPI) | `http://localhost:8000` | Swagger UI at `/docs` |
| Postgres | `localhost:5433` | user/pw `hakuna/hakuna`, db `hakuna`. Schema auto-created on first boot. The init script also creates `hakuna_easm` for the EASM scanner. |
| Redis | `localhost:6380` | DB 0/1 = VM scanner, DB 2 = audits, DB 3 = EASM |
| MinIO | `9000` (S3) / `9001` (console) | SIEM event lake, bucket `hakuna-events-dev` auto-created |

First user to register becomes superadmin.

### Host-running backend + frontend

Useful when iterating on backend code without a rebuild loop.

```bash
# Postgres still comes from compose
docker compose up -d postgres

# Backend
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
DATABASE_URL=postgresql://hakuna:hakuna@localhost:5433/hakuna \
  uvicorn app:app --host 0.0.0.0 --port 8000 --reload --env-file .env

# Frontend (separate terminal)
cd frontend && npm install && npm run dev
```

`./start.sh` automates the above for both services.

> **Hybrid setups work out of the box.** The `audit-worker`, `cloud-scanner`, and on-prem `relay` containers default `HAKUNA_BACKEND_URL` to `http://host.docker.internal:8000` and alias `host-gateway` so they reach the backend whether it runs as a sibling Compose service (port 8000 published to the host) or as a host process via `./start.sh`. Override `HAKUNA_BACKEND_URL` in `.env` only if your backend lives elsewhere.

### Audit worker (Protocol Audit + agent runs)

The Protocol Audit scratch-agent loop runs out-of-process so the API doesn't serialize behind minute-long agent runs. Activated by Compose profile.

```bash
# Generate a shared secret for the internal relay dispatch endpoint
echo "INTERNAL_SHARED_SECRET=$(openssl rand -hex 32)" >> .env

docker compose --profile audits up -d
```

This adds a `redis` (already up if you started Postgres with audits) and an `audit-worker` celery process consuming the `audits` queue. The worker shares the credential vault key (`INTEGRATION_SECRET_KEY`) with the backend, so set that in `.env` before first boot.

**Works with either backend mode.** The worker reaches the backend's `/internal/relay/dispatch` endpoint via `host.docker.internal:8000` by default, which resolves whether the backend runs in Compose (the `backend` service publishes :8000 to the host) or directly on the host via `./start.sh`. To force a different target — e.g. service-to-service inside Compose — set in `.env`:

```bash
HAKUNA_BACKEND_URL=http://backend:8000
```

### EASM scanner (`hakuna-scanner/`)

External attack surface discovery — subfinder, dnsx, naabu, httpx, tlsx, asnmap. Joins the main stack's Postgres (`hakuna_easm` DB) and Redis (DB 3).

```bash
cd hakuna-scanner
cp .env.example .env   # add API keys (Shodan, Censys, etc.) as needed
docker compose up -d
```

Exposed on `http://localhost:8001`. The main backend reaches it as `easm-api` over the shared `hakuna_default` network.

If your `postgres-data` volume predates the EASM init script, create the database manually:

```bash
docker compose exec postgres createdb -U hakuna hakuna_easm
```

### VM scanner (`hakuna-vm-scanner/`)

Active vulnerability scanner — Nuclei templates, Schemathesis API fuzzing, and specialist LLM agents (injection, XSS, SSRF, AuthN, AuthZ, plus protocol audits for LDAP/SMB/SNMP/SSH/Linux). Shares Postgres with the main backend.

```bash
cd hakuna-vm-scanner
cp .env.example .env
docker compose up -d
```

Exposed on `http://localhost:8002`. Backend reaches it as `vm-api`. The worker mounts your host `~/.config/gcloud` so Vertex-based LLM specialists pick up your ADC.

### Lab — intentionally vulnerable scan targets

Spin up DVWA, SMB, LDAP, SSH, SNMP, and LocalStack on a shared `hakuna-lab` network so the VM scanner and audit worker can reach them by hostname.

```bash
docker compose -f docker-compose.lab.yml up -d
```

Seeded credentials (add to the credential vault for audit runs):

| Service | Credentials |
|---|---|
| SMB | `lab` / `labpass` (guest on `public`) |
| LDAP | `cn=admin,dc=lab,dc=local` / `adminpass` (anon bind enabled) |
| SSH | `lab` / `labpass` on port 2222 |
| SNMP | community `public` (v1/v2c read-only) |
| AWS (LocalStack) | `test` / `test`, `endpoint_url=http://localstack:4566` |

> **Security:** these targets are deliberately weak. Bind only to localhost — never expose this compose to a shared network.

Tear down with `docker compose -f docker-compose.lab.yml down -v`.

### Relay agent (on-prem bridge)

Lightweight Docker agent that bridges cloud Hakuna to on-prem products (Jira DC, ServiceNow on-prem, CrowdStrike GovCloud) over a single outbound WebSocket.

**Production / customer install** — issue a token in *Settings → Relay Agents*, then run:

```bash
cd hakuna-relay-agent
HAKUNA_AGENT_TOKEN=<token-from-ui> \
HAKUNA_CLOUD_URL=wss://app.hakuna.io/ws/relay \
docker compose up -d
```

Add per-product creds (`JIRA_*`, `SERVICENOW_*`, `CROWDSTRIKE_*`) to `docker-compose.yml` or pass them via env.

**Local dev** — bring the relay up attached to both `hakuna_default` (so it reaches `backend:8000` over Compose DNS) and the lab network (so it resolves `smb`, `ldap`, etc.):

```bash
HAKUNA_AGENT_TOKEN=<token> \
HAKUNA_CLOUD_URL=ws://backend:8000/ws/relay \
docker compose -f docker-compose.lab.yml --profile relay up -d
```

### Environment variables

Required for full functionality (set in root `.env`):

| Variable | When | Notes |
|---|---|---|
| `JWT_SECRET` | non-dev | Mandatory outside `ENVIRONMENT=development` |
| `INTEGRATION_SECRET_KEY` | always | AES key for the credential vault — must be stable across backend + audit-worker |
| `INTERNAL_SHARED_SECRET` | with audits profile | Auth for `/internal/relay/dispatch` between worker and backend |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `GOOGLE_API_KEY` / `GROQ_API_KEY` | optional | Pick whichever LLM providers you want available |
| `GOOGLE_CLOUD_PROJECT` | optional | Enables Vertex AI / Claude-on-GCP via mounted ADC |
| `GOOGLE_CLIENT_ID` | optional | Google SSO |
| `SHODAN_API_KEY` | optional | Threat intel + EASM enrichment |

### Logs

```bash
docker compose logs -f backend frontend          # core stack
docker compose logs -f audit-worker              # Protocol Audit
docker compose -f hakuna-vm-scanner/docker-compose.yml logs -f vm-worker
docker compose -f hakuna-scanner/docker-compose.yml logs -f worker
```

Host-running backend/frontend write to `/tmp/nessus-backend.log` and `/tmp/nessus-frontend.log`.

## Usage

1. Open `http://localhost:3000`
2. Register an account (first user becomes superadmin)
3. Upload a scan file — drag and drop `.nessus`, `.html`, `.csv`, or other supported formats — or launch an active VM scan from Scan Management
4. Findings are parsed, scored, enriched, correlated into attack paths, and deduplicated automatically
5. Use the sidebar to navigate between Reports, Assets, Findings, Attack Paths, Inventory, SIEM (Events/Rules/Alerts), Campaigns, Remediation, Agents, Threat Intel, and Settings. Copilot is always one tap away on the right rail (or the mobile tab bar).

## Architecture

```
├── backend/                         # Python/FastAPI
│   ├── app.py                       # Core API routes
│   ├── core/
│   │   ├── auth.py                  # JWT auth, RBAC, multi-tenancy
│   │   ├── audit.py                 # Audit logging
│   │   ├── database.py              # Postgres/SQLAlchemy setup
│   │   ├── i18n.py                  # Internationalization (12 languages)
│   │   └── risk_config.py           # Risk scoring configuration
│   ├── models/
│   │   ├── models.py                # SQLAlchemy models (40+ tables)
│   │   ├── entity_registry.py       # Importable entity metadata registry
│   │   └── threat_intel_models.py   # MITRE ATT&CK models
│   ├── parsers/
│   │   ├── parser.py                # Multi-format scan parser
│   │   ├── nessus_parser.py         # Nessus-specific parser
│   │   ├── inventory_extractor.py   # Attack surface extraction
│   │   └── registry.py              # Parser auto-detection registry
│   ├── routes/
│   │   ├── auth_routes.py           # Registration, login, org management
│   │   ├── auth_profile_routes.py   # Scan credential profiles (form_login, static)
│   │   ├── threat_intel_routes.py   # Threat intel API
│   │   ├── agent_routes.py          # AI agent CRUD & execution
│   │   ├── copilot_routes.py        # Security Copilot conversations
│   │   ├── correlation_routes.py    # Attack path generation & narration
│   │   ├── detection_routes.py      # Detection rules, alerts, suppressions
│   │   ├── siem_routes.py           # SIEM events, search, endpoints
│   │   ├── siem_ingest_routes.py    # Webhook / HEC event ingest
│   │   ├── vm_routes.py             # Active VM scanner integration
│   │   ├── integration_builder_routes.py  # No-code connector platform
│   │   ├── relay_routes.py          # On-prem relay agent management
│   │   ├── validation_routes.py     # Finding validation workflows
│   │   ├── control_assessment_routes.py   # Compliance control mapping
│   │   ├── custom_field_routes.py   # Custom asset/finding metadata
│   │   ├── graph_routes.py          # Attack graph materialization
│   │   ├── blast_radius_routes.py   # Risk propagation analysis
│   │   ├── notification_routes.py   # In-app notifications
│   │   ├── onboarding_routes.py     # First-run onboarding wizard
│   │   ├── billing_routes.py        # Billing plans, checkout, usage
│   │   ├── saml_routes.py           # SAML SSO
│   │   ├── scan_planner_routes.py   # Intelligent scan plan generation
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
│   │   ├── asset_type_rules.py      # Multi-type asset classification engine
│   │   ├── asset_observations.py    # Per-source observation tracking
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
│   ├── integrations/
│   │   └── connectors/              # Tenable.io, ServiceNow, Jira, Slack, Teams, CrowdStrike, ...
│   └── threat_intel/
│       ├── threat_intel_sync.py     # MITRE STIX bundle sync
│       ├── intel_updater.py         # NVD + CISA KEV auto-update
│       ├── ttp_matcher.py           # Finding → ATT&CK mapping
│       └── security_tool_catalog.py # Security product detection
├── hakuna-scanner/                  # Passive discovery scanner (EASM)
├── hakuna-vm-scanner/               # Active VM scanner
│   └── scanner/vm/
│       ├── nuclei_worker.py         # Nuclei template execution
│       ├── schemathesis_worker.py   # OpenAPI / GraphQL fuzzing
│       ├── agent_worker.py          # Specialist vuln agent orchestrator
│       ├── agent_specialists.py     # Injection, XSS, SSRF, AuthN, AuthZ agents
│       ├── session_broker.py        # Playwright-driven authenticated scanning
│       ├── llm_provider.py          # Multi-provider LLM adapter
│       └── router.py                # Template routing (CPE, tech, port, OT/IoT/AI)
├── hakuna-relay-agent/              # On-prem relay agent Docker image
├── frontend/                        # React 18 / Vite
│   └── src/
│       ├── App.jsx                  # Router, layout, context providers
│       ├── contexts/
│       │   ├── AuthContext.jsx       # JWT session & permissions
│       │   └── ThemeContext.jsx      # Dark/light mode
│       └── components/
│           ├── reports/             # Dashboard, ReportBuilder, NLPReportBuilder
│           ├── assets/              # AssetInventory, AssetDetail, InventoryExplorer
│           ├── findings/            # FindingExplorer, FindingDetail
│           ├── attackpaths/         # AttackPaths, AttackPathGraph
│           ├── siem/                # EventSearch, DetectionRules, AlertTriage
│           ├── copilot/             # CopilotPanel, RichBlockRenderer (web + mobile)
│           ├── campaigns/           # Campaigns, CampaignDetail, BlastRadiusPanel, RuleBuilder
│           ├── remediation/         # RemediationQueue, AggregatedSolutions
│           ├── agents/              # AgentBuilder, AutomateModal
│           ├── threats/             # ThreatIntelCenter, ExternalSources
│           ├── workflows/           # WorkflowBuilder
│           ├── integrations/        # IntegrationBuilder, IntegrationList, RelayAgentManager
│           ├── scans/               # ScanManagement, AuthProfileManager, AuthProfileForm
│           ├── settings/            # Settings, TagManager, RiskSettings, SLASettings,
│           │                        #   IntegrationBuilderTab, GlobalExceptions, UserManagement,
│           │                        #   RoleManager, AuditLog, OrgsPanel, OwnershipRules,
│           │                        #   TagMappings, CustomFieldManager, SSOSettings, UsersPanel
│           ├── upload/              # UploadScan (multi-format, EASM setup)
│           ├── auth/                # Login, Register, SSO callback, invite flow
│           ├── docs/                # UserDocs (in-app documentation)
│           └── shared/              # ui.jsx, NLPSearchBar, CommandPalette, MobileBottomTabs
├── intel.json                       # CVE enrichment data
├── docker-compose.yml               # Docker orchestration
└── start.sh                         # One-command launcher
```

**Stack:** FastAPI + SQLAlchemy + PostgreSQL (backend) · React 18 + Vite + Recharts + React Flow (frontend)

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
| **VM Scanner** | |
| `POST /api/vm/scan` | Launch an active Nuclei-based scan (supports auth profiles, agent specialists) |
| `POST /api/vm/refresh/{id}` | Refresh scan status and ingest new findings |
| `POST /api/vm/rescan/{id}` | Re-run a scan with optional overrides |
| `GET /api/vm/health` | VM scanner container health |
| **Auth Profiles** | |
| `GET /api/auth-profiles` | List scan authentication profiles (static + form_login) |
| `POST /api/auth-profiles` | Create an auth profile |
| `POST /api/auth-profiles/{id}/test` | Test login flow (Playwright) |
| **Assets & Findings** | |
| `GET /api/assets` | List assets (supports tag, NLP, type, and environment filtering) |
| `GET /api/assets/:id/sources` | Per-source observation snapshots for an asset |
| `GET /api/findings` | List findings (supports tag, NLP, and severity filtering) |
| `GET /api/findings/:id/sources` | Per-source observation snapshots for a finding |
| `PATCH /api/findings/:id/status` | Update finding status |
| `GET /api/nlp-search` | Natural language search |
| **Asset Type Rules** | |
| `GET /api/asset-type-rules` | List asset type classification rules |
| `POST /api/asset-type-rules` | Create a classification rule |
| `PATCH /api/asset-type-rules/:id` | Update a rule |
| `DELETE /api/asset-type-rules/:id` | Delete a rule |
| `POST /api/asset-type-rules/test` | Test a rule against sample data |
| `GET /api/asset-type-rules/condition-catalog` | Available conditions for rules |
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
| `POST /api/copilot/message` | Chat with the security Copilot |
| **Attack Paths & Correlation** | |
| `POST /api/correlations/run` | Dispatch correlation as background job |
| `GET /api/correlations/attack-paths` | List attack paths (filter by severity, score, scan) |
| `GET /api/correlations/corroborated` | Findings corroborated by multiple scanners |
| `GET /api/blast-radius/*` | Risk propagation analysis |
| **SIEM** | |
| `GET /api/siem/events` | Event search with histogram |
| `POST /api/ingest/*` | Webhook / Splunk HEC / generic event ingest (HMAC-signed) |
| `GET /api/detection-rules` | Detection rules (custom, Sigma, built-in) |
| `POST /api/detection-rules/import-sigma` | Import Sigma rule |
| `GET /api/alerts` | Alert triage queue |
| `GET /api/suppression-rules` | Alert suppression rules |
| **Tagging** | |
| `POST /api/tags` | Create/manage tags |
| `POST /api/auto-tag-rules` | Auto-tagging rules (supports passthrough from integration values) |
| `GET /api/custom-fields` | Custom metadata fields for assets/findings |
| **Integrations** | |
| `GET /api/integrations` | Integration configs (Jira, ServiceNow, Slack, Teams, Email, Tenable.io, CrowdStrike) |
| `GET /api/integration-builder/*` | No-code connector platform (schema, auth, auto-mapping, credentials) |
| `GET /api/relay-agents` | On-prem relay agent management |
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

- **Multi-provider support** — Claude (Anthropic), GPT (OpenAI), Gemini (Google), Vertex AI, Llama/Mixtral (Groq), and self-hosted Ollama with automatic fallback across configured providers
- **50+ built-in tools** — Query findings, check SLA status, identify risk assets, find quick wins, lookup exploit data, and more
- **Template gallery** — Pre-built agents for daily triage, weekly summaries, incident response, compliance reports, and executive dashboards
- **Specialist vulnerability agents** — Opt-in LLM specialists for injection, XSS, SSRF, authentication, and authorization flaws run alongside Nuclei in active VM scans
- **Validation framework** — Per-finding LLM verdicts (true positive / false positive / uncertain) with confidence scores feed back into prioritization
- **Feedback loop** — Every LLM call is tracked with tokens, latency, and tool traces; outcome scores train future exemplar retrieval via pgvector on Postgres
- **Scheduled execution** — Cron-based scheduling with next-run tracking
- **Streaming output** — Real-time agent responses in the UI
- **Agent pipelines** — Multi-stage chains with per-stage model routing and structured context handoff
- **Document uploads** — Attach knowledge base documents for agent context
- **Copilot** — Context-aware assistant (web + mobile full-screen) with Conservative/Standard/Autonomous action-approval modes

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
