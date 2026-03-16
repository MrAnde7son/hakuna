# Feature Reference

## Scan Management

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

Configure deduplication settings in Settings to control how duplicate findings are merged across scans. Settings include match criteria and merge behavior.

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

### Asset Explorer

Browse all discovered assets with:
- Filtering by hostname, IP, OS, environment, tags
- NLP search (e.g., "production Windows servers")
- Drill-down to findings, inventory, and ownership

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
2. **External scanning** — Discovers subdomains, open ports, technologies, certificates, CDN/WAF presence
3. **Synthetic import** — Results are imported as synthetic scans for correlation with internal data

Setup is triggered automatically on registration with a corporate email, or manually via the scan management page.

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
