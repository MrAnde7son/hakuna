# Feature Reference

## Scan Management

### Active VM Scanning (`hakuna-vm-scanner`)

Hakuna ships with a dedicated active scanner container that runs alongside the backend:

- **Nuclei worker** — Signature and DAST coverage using the full community template set (4,800+) plus custom categories for OT (Siemens PLCs), IoT (Hikvision cameras), and AI surfaces (Ollama, LangChain, vector DBs)
- **Template routing** — Templates are dispatched based on detected CPEs, tech stack fingerprints, and open ports. Port-based gating blocks irrelevant templates (e.g., web templates never hit a database-only host)
- **Schemathesis worker** — Property-based fuzzing for OpenAPI and GraphQL schemas discovered during EASM. Catches 5xx crashes, response-schema violations, and content-type drift
- **Specialist LLM agents** — Opt-in via `enable_agents: true` on scan creation. Five specialists (injection, XSS, SSRF, authentication, authorization) each get a 60-second/10-iteration budget per asset with a shared tool registry (`http_request`, `check_pattern`, `emit_finding`)
- **Multi-provider LLM** — Specialists use the same provider chain as backend agents (Anthropic → OpenAI → Vertex AI → Gemini → Groq → Ollama) and gracefully skip when no key is configured
- **Health endpoint** — `GET /api/vm/health` confirms the scanner container is reachable

Trigger a scan from **Scan Management → New Scan** or via `POST /api/vm/scan`. Refresh or rescan via `/api/vm/refresh/{id}` and `/api/vm/rescan/{id}`.

### Authenticated Scanning (Auth Profiles)

`AuthProfile` enables authenticated scans across all VM workers:

| Profile Type | Description |
|--------------|-------------|
| `static` | Direct credential (basic, bearer, api_key, cookie) from the credential vault |
| `form_login` | Playwright-driven login flow with ordered steps, configurable success condition, and optional TOTP |

Sessions are cached (AES-256-GCM encrypted cookies + scraped headers) per-org with configurable TTL. The session broker returns the cached blob to Nuclei, Schemathesis, and agent workers so a single login covers the whole scan. Rotate or invalidate sessions by updating the underlying credential — `session_credential_hash` tracks changes.

Manage auth profiles in **Settings → Scans → Authentication Profiles** or via `/api/auth-profiles`. The detect-login-flow endpoint uses an LLM to suggest a flow from an observed login page.

### Multi-Format Import

Upload scan files from multiple vulnerability scanners:

| Scanner | Formats |
|---------|---------|
| Tenable Nessus | `.nessus` (XML), `.html`, `.csv` |
| Qualys | XML export |
| Rapid7 InsightVM | XML export |
| OpenVAS | XML export |

Format is auto-detected on upload. Drag-and-drop is supported.

### Cross-Source Normalization

When importing from multiple scanners, findings are normalized using CVE references to produce a canonical vulnerability identity. This prevents the same vulnerability from appearing as separate findings when detected by different tools.

### Scan Comparison

Compare any two scans side-by-side to see:
- **New findings** — Vulnerabilities that appeared
- **Resolved findings** — Vulnerabilities that were remediated
- **Persistent findings** — Vulnerabilities still present
- **Regression report** — Findings that were fixed but reappeared
- **Remediation velocity** — Rate of fix over time

### Deduplication

Deduplication is configured per asset type and entity type in Settings:

- **Per-type configuration** — Each asset type (host, web_app, cloud_instance, etc.) has independent dedup settings with type-specific key fields
- **Key fields** — Define which fields constitute a unique record (e.g., `ip` + `fqdn` for hosts, `url` for web apps, `instance_id` for cloud instances)
- **Key mode** — `AND` (all fields must match) or `OR` (any field match triggers dedup)
- **Merge strategy** — `merge` (combine fields from both records) or `keep_last` (newer record wins)
- **Scope** — `cross_scan` (deduplicate across all scans) or `within_scan` (only within a single scan)

Entity-level dedup (findings, users, groups, services, etc.) is also configurable with the same options.

---

## Prioritization & Risk Scoring

### Scoring Formula

Every finding receives a priority score from 0 to 10:

```
score = (0.30 x CVSS_norm + 0.30 x VPR_norm + 0.20 x exploit_bonus
       + 0.10 x criticality_norm + 0.10 x family_bonus) x 10
```

**Score floors and caps:**
- Critical severity: minimum score of 7.0
- High severity: minimum score of 5.0
- Informational: capped at 2.5

### Effort Estimation

Each finding is automatically tagged with:
- **Effort level** — Quick win, medium, or complex
- **Suggested owner team** — IT, DevOps, SecOps, or AppSec

### Risk Configuration

Go to **Settings > Risk Configuration** to:
- Adjust scoring weight percentages
- Modify score floors and caps
- Recalculate all scores in bulk after changes

---

## Asset Intelligence

### Multi-Type Asset Model

Assets support multiple types beyond traditional hosts:

| Type | Identity Keys | Description |
|------|--------------|-------------|
| `host` | ip, hostname, fqdn, netbios_name | Traditional network hosts, servers, endpoints |
| `web_app` | url, domain | Web applications and sites |
| `cloud_instance` | cloud_provider, instance_id, account_id, region | AWS EC2, Azure VM, GCP Compute |
| `api_endpoint` | method, url | REST/GraphQL API endpoints |
| `identity` | provider, principal_id, tenant_id | IAM users, service accounts, principals |
| `container_image` | registry, repository, tag, digest | Docker/OCI container images |
| `code_repo` | provider, org, repo | GitHub, GitLab, Bitbucket repositories |
| `k8s_workload` | cluster, namespace, kind, name | Kubernetes deployments, pods, services |
| *custom* | user-defined | Any custom type via asset type rules |

Each type has its own structured identity (`asset_identity` JSON field) and type-specific metadata (`asset_attributes` JSON field).

### Asset Type Rules

Low-code classification rules that automatically assign asset types during ingestion:

- **Condition-based matching** — Uses the unified rule engine (same format as auto-tag rules and campaigns)
- **Priority ordering** — First matching rule (lowest priority number) wins
- **Identity mapping** — Flexible field mapping with functions:
  - Direct copy: `{"url": "hostname"}`
  - Domain extraction: `{"domain": "@extract_domain(hostname)"}`
  - Static values: `{"provider": "@static(nessus)"}`
  - Coalesce (first non-empty): `{"url": "@coalesce(http_url,hostname)"}`
- **Source filtering** — Rules can target specific sources (nessus, qualys, easm, integration)
- **Built-in heuristics** — Auto-detects web apps from HTTP ports, web CPEs, and service names even without explicit rules

Manage rules from **Settings > Asset Type Rules** or via the `/api/asset-type-rules` API.

### Asset & Finding Observations

Every asset and finding tracks per-source observations — one snapshot per source system (Nessus, CrowdStrike, EASM, integrations, etc.):

- View which fields each source contributed to the merged record
- Track first seen, last seen, and times seen per source
- Access via the **Sources** tab on asset and finding detail pages
- API: `GET /api/assets/{id}/sources` and `GET /api/findings/{id}/sources`

### Asset Explorer

Browse all discovered assets with:
- Filtering by hostname, IP, OS, environment, asset type, tags
- NLP search (e.g., "production Windows servers")
- Drill-down to findings, inventory, observations, and ownership

### Asset Classification

Assets are automatically classified by:
- **Environment** — Production, staging, development, DMZ, external, internal (inferred from hostname patterns and IP ranges)
- **Role** — Domain controller, database server, web server, identity provider, etc.
- **Business context** — Tags applied from classification for workflow routing

### Attack Surface Inventory

Informational plugin outputs are parsed to extract 18+ entity types:

| Entity | Description |
|--------|-------------|
| Users | Local and domain user accounts |
| Groups | Group memberships and nested groups |
| Domain Trusts | Active Directory trust relationships |
| Services | Running Windows/Linux services |
| Network Connections | Listening ports and established connections |
| Scheduled Tasks | Cron jobs and Windows scheduled tasks |
| Patches | Installed hotfixes and updates |
| Logged-On Users | Currently logged-in users |
| Shares | Network file shares |
| Software | Installed applications |
| Security Controls | EDR, AV, firewall, SIEM products |
| Computers | Domain-joined computer objects |
| Password Policies | Domain and local password policies |
| Environment Variables | System environment configuration |
| Certificates | SSL/TLS certificates with expiry tracking |
| AI Tools | Detected AI/ML tools and frameworks |
| Processes | Running processes |
| Database Instances | SQL Server, MySQL, PostgreSQL, Oracle instances |
| Credentials | Discovered credential artifacts |

### SBOM (Software Bill of Materials)

The SBOM pipeline:
1. Extracts software components from inventory data
2. Correlates with CVE databases
3. Checks end-of-life status via endoflife.date
4. Assigns priority tiers based on risk
5. Tracks component hierarchies (parent/child relationships)

Query SBOM data at `/api/sbom/components` with filters for CVEs, EOL status, running state, and priority tier.

### Ownership Inference

Asset ownership is automatically derived from:
- Primary logged-on user
- Admin contacts from group memberships
- Responsible team based on running services

Configure ownership rules in **Settings > Ownership Rules** with:
- Condition-based matching (AND/OR logic)
- Priority ordering (lower number = higher priority)
- Overwrite control (replace existing or skip if assigned)

### External Attack Surface Management (EASM)

EASM discovers your external-facing attack surface:
1. **Domain inference** — Auto-extracts corporate domains from registration email
2. **External scanning** — Discovers subdomains, open ports, technologies, certificates, CDN/WAF presence, and screenshots
3. **API spec discovery** — OpenAPI and GraphQL schemas are parsed and stored as `api_endpoint` assets for downstream Schemathesis fuzzing
4. **Subsidiary domains** — Parent-child domain hierarchy with provenance tracking expands coverage to M&A and business-unit subsidiaries
5. **Synthetic import** — Results are imported as synthetic scans for correlation with internal data

Setup is triggered automatically on registration with a corporate email, or manually via the scan management page.

### Custom Fields

Define arbitrary metadata fields for assets and findings:
- Supported types: string, number, boolean, date, enum (single/multi)
- Backfill across existing records on creation
- Filterable and sortable in explorers
- Exposed in exports, NLP search, and API responses

Manage in **Settings → Custom Fields** or via `/api/custom-fields`.

---

## Remediation

### Campaigns

Create remediation campaigns with:
- **Rule builder** — Condition catalog with AND/OR logic to select findings
- **Blast radius preview** — Attack path graph visualization (Dagre layout with ReactFlow) showing assets, privilege escalation paths, and lateral movement vectors
- **Owner assignment** — Assign campaigns to teams or individuals
- **Progress tracking** — Monitor remediation progress across all campaign findings

### Aggregated Solutions

Findings are automatically grouped into actionable remediation recommendations:

| Root Cause | Example Action |
|-----------|---------------|
| Outdated version | "Upgrade Node.js 16 → 20 on 5 hosts" |
| EOL software | "Migrate off Windows Server 2012 R2" |
| Missing patch | "Apply KB5034441 across 12 servers" |
| Misconfiguration | "Disable SSLv3 on web servers" |
| Deprecated protocol | "Replace TLS 1.0 with TLS 1.2+" |

Each recommendation includes:
- Efficiency score (high/medium/low effort)
- Affected asset count and severity distribution
- **Downstream impact assessment** — Warns if an upgrade would introduce new CVEs

### AI Agents

Build and run AI-powered security automation agents:

**Supported LLM Providers:**
- Anthropic Claude
- OpenAI GPT
- Google Gemini
- Groq (Llama, Mixtral)

**Built-in Templates:**
- Daily Triage — Prioritized summary of new findings
- Weekly Summary — Week-over-week risk trends
- Incident Response — Guided investigation playbook
- Compliance Report — Regulatory compliance assessment
- Executive Dashboard — C-suite risk summary

**Capabilities:**
- 50+ security tools (query findings, check SLA, find quick wins, etc.)
- Cron-based scheduled execution
- Streaming real-time output
- Document uploads for agent knowledge base
- Run history with token usage and step tracking

### Workflow Builder

Visual drag-and-drop workflow editor:
- Node catalog with action types
- Pre-built workflow templates
- Integration nodes (Jira, Slack, ServiceNow, Teams, Email)
- Execution engine with logging

### Validation Framework

Automatic per-finding LLM validation writes structured verdicts back onto findings:

- **Verdict** — `true_positive`, `false_positive`, or `uncertain`
- **Confidence** — numeric score 0–1
- **Validated at** — timestamp of last validation pass

The prioritizer rewards confirmed true positives. Verdicts are recorded via the LLM interaction feedback loop so future runs retrieve similar exemplars.

### Copilot

Context-aware security assistant available on every page:

- **Desktop** — Sliding right-side panel (480px default, resizable)
- **Mobile** — Full-screen modal launched from the bottom tab bar
- **Context-aware prompts** — Suggested prompts change per page (e.g., on `/findings`: "Show me critical unresolved findings")
- **Rich block rendering** — Markdown, structured data tables, finding/asset cards
- **Autonomy levels** — `Conservative` (approve everything), `Standard` (auto-approve low-risk), `Autonomous` (external-only approvals)
- **Conversation persistence** — Chats retained per org; autonomy mode persisted per user

---

## Attack Paths & Correlation

The correlation engine builds attack chains and scores them end-to-end.

### Attack Path Generation

- **Entry selection** — Critical/High finding or internet-facing asset, plus optional public exploit availability
- **Pivot scoring** — Each step scored by: `exploit_path_verified`, `service_exposed`, `reachability`, `identity_primitive`, `inference`
- **Target labels** — Domain controller, internet-facing, host-with-critical-finding
- **Narrative** — LLM generates a plain-English description of the chain
- **Recommended mitigations** — Prioritized remediation steps for each path
- **Team scoping** — Both entry and target must match the viewer's owner-role scope; users only see paths relevant to their team

### Running Correlations

- `POST /api/correlations/run` dispatches a background Celery job and returns a `job_id`
- `GET /api/correlations/attack-paths` lists paths with filters (severity, min score, narrated, scan_id)
- `GET /api/correlations/corroborated` surfaces findings confirmed by multiple scanners

### Blast Radius & Graph

- `GET /api/blast-radius/*` quantifies downstream risk propagation
- `GET /api/graph/*` materializes the attack graph for visualization

---

## SIEM Module

### Event Ingest

Hot-tier event ingestion for integration-driven SIEM correlation:

- **Webhook** — Generic JSON with configurable parser
- **Splunk HEC** — Native HTTP Event Collector compatibility
- **CEF / LEEF** — Palo Alto, Check Point, and other vendor formats
- **HMAC-SHA256** signature verification on every payload
- **Rate limiting** — In-memory token bucket (1,000 tokens/sec, 1,000 capacity per endpoint)
- **Asset resolution** — Events are correlated to assets by source IP or hostname automatically

Create endpoints in **Integrations → Event Ingest**. The secret is shown once at creation; rotate via `POST /api/ingest/{id}/rotate`.

### Event Search

- Time range: 1h, 6h, 24h, 7d, 30d, custom
- Filter: severity, source system, free-text
- Histogram visualization for volume
- Sort by event time, severity, or source

### Detection Rules

Custom alerting rules with scheduled evaluation:

- **Query** — JSON filter expression against event fields
- **Threshold + window** — `N events within M minutes` (5m–24h)
- **Group by** — Field list to aggregate before thresholding
- **MITRE tagging** — Link rules to ATT&CK techniques for threat intel correlation
- **Sources** — `user` (custom), `sigma` (imported), `builtin` (template library)
- **Rule library** — Pre-built templates for common detections; enable with one click
- **Dry-run testing** — Test against recent events before enabling
- **Schedule** — Background evaluation on configurable interval

Manage in `/siem/rules` or via `/api/detection-rules`. Import Sigma via `POST /api/detection-rules/import-sigma`.

### Suppression Rules

Silence low-fidelity alerts with condition-based matching. Tracked separately from detection rules so suppressions can be audited independently.

### Alert Triage

- Status workflow: `new` → `investigating` → `resolved` / `false_positive`
- Campaign linking — attach an alert to an active remediation campaign
- Assigned-to tracking with owner-role filtering
- Triage notes and reasoning
- Alert dashboards at `/siem/alerts` with severity/source aggregations

---

## Threat Intelligence

### MITRE ATT&CK Integration

Full STIX bundle sync providing:
- Threat group profiles
- Technique/tactic mappings
- Campaign tracking
- CVE-to-technique correlation

### TTP Matching

Findings are mapped to ATT&CK techniques via three methods:
1. **Plugin ID match** — High confidence, direct mapping
2. **Keyword match** — Medium confidence, description analysis
3. **Family heuristics** — Fallback based on plugin family

### Auto-Updating Intelligence

- **NVD API v2** — Fresh CVE data fetched every 24 hours
- **CISA KEV** — Known Exploited Vulnerabilities catalog
- Weaponized exploits are flagged automatically

### Security Tool Catalog

100+ mappings of Windows services and software patterns to security product categories:
- EDR, antivirus, firewall, SIEM, DLP, backup, etc.
- Used for coverage gap analysis across your asset inventory

---

## Governance & Compliance

### Authentication

JWT-based authentication with:
- User registration and login
- Password hashing (bcrypt)
- Session management via AuthContext
- Locale preference persistence
- SAML and OIDC SSO (configure in **Settings → SSO**)
- Password reset via email, invite acceptance flow, email verification

### Role-Based Access Control (RBAC)

**Built-in roles:**
- Superadmin — Full platform access
- Org Admin — Full access within their organization
- Analyst — Read/write access to operational features
- Viewer — Read-only access
- Custom — Admin-defined permission sets

**30+ granular permissions** organized into:
- Page access (13 pages)
- Data access (6 categories)
- Actions (10 operations)

Tri-state permission toggles (off/allow/deny) with per-tag restrictions for fine-grained data access control.

### Team Roles & Ownership Scopes

Built-in team-scoped roles add another axis of access control on top of RBAC:

| Team Role | Default Scope |
|-----------|---------------|
| `it` | IT-managed assets (endpoints, servers) |
| `devops` | Cloud, container, and code-repo assets |
| `soc` | Detection rules, alerts, attack paths |
| `vm` | Vulnerability management (findings, campaigns) |

- Users are assigned one or more team roles — visible data is filtered by `user_owner_scopes`
- Ownership rules can reference team roles so assignment propagates automatically
- Passthrough auto-tag rules create tags from integration source values (e.g., Jira project → `team:platform`)
- Audit logging captures every ownership change

### Multi-Tenancy

- **Organizations** — Isolated workspaces with separate data
- **MSSP support** — Manage multiple client organizations
- **Org switching** — Users with multi-org access switch from the sidebar
- **Parent-child hierarchies** — Reseller models with linked client orgs

### SLA Tracking

- Configure deadlines per severity level
- Track compliance rates
- Recalculate SLA status across scans
- NLP search supports "SLA breached" queries

### Global Exceptions

Define exception rules to:
- Accept risk for specific findings
- Mark findings as false positives
- Set expiration dates for automatic re-evaluation
- Track exception history in audit log

### Audit Logging

Immutable trail of all system changes:
- Tracked actions: create, update, delete, enable, disable, assign
- Tracked entities: exceptions, SLA configs, campaigns, workflows, tags, rules, ownership
- Diff viewer showing old-to-new value changes
- Filterable by action, entity type, actor, and date range

### Peer Benchmarking

Compare your security posture against:
- **Industry baselines** — Financial, healthcare, technology, government (sourced from Qualys, H-ISAC, CISA)
- **Platform aggregates** — Anonymous cross-tenant metrics

Metrics compared: risk grade, mean time to remediate, SLA compliance rate, critical vulnerability density.

### Control Assessments

Map findings and inventory data to compliance controls for coverage analysis. Useful for CIS, NIST CSF, ISO 27001, and custom frameworks. Available via `/api/control-assessments`.

### LLM Feedback Loop

Every LLM call — from agents, the validator, alert triage, or the scan planner — is persisted for auditing and learning:

- **LLMInteraction** — Provider, model, system prompt hash, messages, response, tool calls, tokens, latency, surface (agent/validator/etc.), org context
- **LLMInteractionOutcome** — Asynchronously linked outcome score in [-1, +1] (e.g., "did the agent's action succeed?")
- **Semantic retrieval** — On Postgres, pgvector embeddings power exemplar retrieval so future runs can condition on similar past successes
- **Audit access** — Admin-only view of recent LLM traces for debugging and compliance

This makes AI behavior observable, reviewable, and steerable over time.

---

## Reporting & Export

### Dashboard

Charts and visualizations powered by Recharts:
- Severity distribution
- Risk score trends
- Remediation velocity
- Top findings and assets

### Report Builder

Configurable report templates with:
- Widget-based layout
- Exportable output
- Metrics timeline
- Save and reuse templates

### NLP Report Builder

Generate reports with natural language:
- "Show critical findings on Windows servers"
- "Quick wins with CVE in CISA KEV"
- "Ransomware-linked vulnerabilities in production"

Results include severity breakdown, asset/finding counts, and can be saved as reusable templates.

### Data Export

Stream CSV or JSON exports for:
- Assets (all fields)
- Findings (all fields)
- All inventory tables (users, groups, software, patches, etc.)

### Config Portability

Export and import organizational configuration:
- Risk configuration
- Auto-tag rules
- Report templates
- Campaign workflows
- Dedup settings

Conflict resolution strategies: overwrite, skip, or merge.

---

## Tagging

### Tag Management

- Hierarchical tag structure
- Custom colors per tag
- Bulk assignment to assets and findings

### Auto-Tag Rules

Rules that automatically tag new findings on upload based on configurable conditions.

### Tag Mappings

Map field values to tags automatically:
- Hostname → `env:production`
- OS type → `platform:windows`
- Applies to assets, findings, or both

### External Tag Sources

Import tags from external systems:
- **CSV upload** — Bulk tag import
- **ServiceNow** — CMDB integration with table/field mapping
- **REST API** — Generic API with basic or token auth
- On-demand or scheduled sync

---

## Integrations

Configure and test integrations from **Settings > Integrations**:

| Integration | Capabilities |
|-------------|-------------|
| Jira | Create issues, sync status, link findings |
| ServiceNow | Create incidents, CMDB enrichment, tag sync |
| Slack | Notifications, alerts, campaign updates |
| Microsoft Teams | Notifications, alerts, campaign updates |
| Email (SMTP) | Reports, alerts, campaign notifications |
| Tenable.io / Tenable.sc | Pull findings via API key; guided key generation wizard |
| CrowdStrike | EDR correlation, asset enrichment, control assessment |

### Integration Builder (No-Code Connectors)

Build custom connectors without code. The multi-step wizard covers schema discovery, authentication, field mapping, and scheduled sync.

**Supported transport types:**

| Transport | Use Case |
|-----------|----------|
| API | REST / GraphQL with paging, cursor, and incremental sync |
| SQL | Direct database queries (Postgres, MySQL, SQL Server) |
| File | Scheduled file upload or S3/GCS pull |
| LDAP | Active Directory / LDAP directory sync |
| MCP | Model Context Protocol tool discovery |
| Webhook | Inbound HTTP ingest with HMAC validation |

**Authentication templates:**

| Auth Type | Description |
|-----------|-------------|
| `none` | Unauthenticated sources |
| `bearer` | Static Bearer token in `Authorization` header |
| `oauth2_client_credentials` | OAuth2 with client ID/secret, auto token refresh |
| `api_key_header` | Named header with key (e.g., `X-ApiKey`) |
| `basic` | HTTP Basic with username/password |

**Wizard steps (API example):** Choose Source → Authenticate → Connect → Pick Records → Pick Target → Map Fields → Preview → Save.

**Wizard steps (Webhook example):** Choose Source → Parser → Pick Target → Create Endpoint → Setup & Test → Map Fields → Done.

**Features:**
- Auto-mapping suggestions based on field name similarity and sample data
- JSON-path extraction for nested source fields
- Dedup key configuration per target model
- Preview & test before save
- OAuth2 auto-discovery (well-known metadata URL)
- Credential vault — credentials encrypted at rest, scoped per-org
- Relay agent routing for on-prem sources

### On-Prem Relay Agents

Connect to on-premises products (Jira Server/DC, ServiceNow, CrowdStrike GovCloud, etc.) that are not reachable from the cloud via lightweight relay agents.

**How it works:**

1. **Register an agent** in **Settings > Integrations > Relay Agents** — a one-time authentication token is generated
2. **Deploy the agent** as a Docker container inside your network
3. The agent opens an outbound WebSocket connection to Hakuna (`wss://<host>/ws/relay`) — no inbound firewall rules required
4. Integration traffic is routed through the agent transparently — field mapping, scheduling, and upsert logic remain in the cloud

**Credential modes:**

| Mode | Description |
|------|-------------|
| `agent_local` (default) | Credentials are stored as environment variables on the agent container — secrets never leave your network |
| `cloud_managed` | Credentials are stored in Hakuna's credential vault and sent to the agent per-request over the encrypted WebSocket |

**Agent management features:**

- **Allowed hosts** — Restrict which on-prem hosts the agent can reach
- **Labels** — Organize agents by site, environment, or team
- **Token rotation** — Generate a new token without redeploying (old token is invalidated, agent disconnects)
- **Live status** — Real-time connected/disconnected status via the WebSocket broker
- **Setup instructions** — Docker run and Docker Compose examples with env var reference, available per-agent

**Deployment:**

```bash
docker run -d --restart=unless-stopped \
  --name hakuna-relay-agent \
  -e HAKUNA_AGENT_TOKEN=<your-agent-token> \
  -e HAKUNA_CLOUD_URL=wss://<your-hakuna-host>/ws/relay \
  hakuna/relay-agent:latest
```

For agent-local credentials, add product-specific env vars (e.g., `JIRA_BASE_URL`, `JIRA_USERNAME`, `JIRA_PASSWORD`).

---

## Internationalization

12 supported languages:

| Language | Code |
|----------|------|
| English | en |
| Japanese | ja |
| French | fr |
| German | de |
| Hebrew | he |
| Russian | ru |
| Chinese | zh |
| Spanish | es |
| Portuguese | pt |
| Dutch | nl |
| Arabic | ar |
| Italian | it |

Language preference is persisted per-user and synced with the backend.

---

## Dark Mode

Toggle between light and dark themes:
- Automatically detects system preference on first load
- Persisted in localStorage
- Toggle available in the sidebar

---

## Mobile Experience

Hakuna's responsive layout adapts to phone and tablet viewports:

- **Bottom tab bar** — Primary navigation at the bottom of the screen with Copilot centered as a primary action
- **Full-screen Copilot** — On small viewports, Copilot takes the full screen instead of a sidebar
- **Touch-optimized controls** — Larger hit targets and swipe gestures where appropriate
- **Responsive tables** — Collapse to card views on narrow screens

---

## Command Palette

Keyboard-driven global search with `Cmd+K` (macOS) or `Ctrl+K` (Windows/Linux):

- Navigate to any page by name
- Search across findings and assets inline
- Arrow keys + Enter for selection
- Static shortcut list plus live backend search

---

## Notifications

In-app notification center:

- Unread count badge in the header
- Targeted per-user delivery
- Actions like "Assign me to this finding" or "Campaign ready for review"
- Retrieve via `GET /api/notifications`

---

## Onboarding

First-run guided setup for new organizations:

- Integrates with Settings to capture initial risk/SLA config
- Seeds default tags, team roles, and auto-tag rules
- Suggests integrations based on the registration email domain
