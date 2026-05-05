# Hakuna Exposure Management Platform
## Partner Whitepaper for Managed Security Service Providers

---

## Executive Summary

Hakuna is a multi-tenant exposure management platform purpose-built for MSSPs to deliver **Vulnerability Management as a Service (VMaaS)** and **Exposure Management as a Service (EMaaS)** at scale. It consolidates vulnerability data from 125+ security tools, automates triage and prioritization, powers remediation workflows, and produces client-ready deliverables — all from a single platform with native MSSP multi-tenancy.

This document outlines the platform's capabilities, the services MSSPs can build on top of it, and the value proposition for organizations looking to operationalize exposure management across their client base.

---

## The Problem

MSSPs face compounding complexity as they scale their vulnerability management practices:

- **Tool sprawl**: Clients use different scanners (Nessus, Qualys, Rapid7, Defender, cloud-native tools). Normalizing and correlating findings across scanners is manual and error-prone.
- **Analyst bottleneck**: Security analysts spend 60–70% of their time on data wrangling — deduplicating findings, enriching with context, and formatting reports — instead of driving remediation.
- **Client isolation**: Managing dozens of client tenants requires strict data segregation, role-based access, and per-client reporting — most tools weren't designed for this.
- **Reactive posture**: Without automation, MSSPs are stuck in a scan-report-repeat cycle. There is no continuous monitoring, no proactive triage, and no way to scale analyst judgment.
- **Limited service differentiation**: When every MSSP uses the same scanner with the same output, it's hard to deliver differentiated, high-value services.

---

## Platform Overview

### Architecture at a Glance

| Layer | Technology |
|-------|-----------|
| Backend | Python, FastAPI, SQLAlchemy |
| Frontend | React SPA with dark/light theme and 12-language i18n (including Japanese) |
| Database | PostgreSQL (Cloud SQL in production, docker-compose `postgres` service in development) |
| Auth | JWT + RBAC with 30+ granular permissions, SAML 2.0 SSO |
| AI | Multi-provider (Claude, GPT, Gemini, Llama) with graceful fallback |
| Deployment | Docker Compose (on-prem), GCP Cloud Run (cloud), Relay Agent (hybrid) |

### Deployment Flexibility

Hakuna supports three deployment models to match client requirements:

1. **Cloud-hosted (SaaS)**: Fully managed on GCP Cloud Run with Cloud SQL. Zero infrastructure overhead for the MSSP.
2. **On-premises**: Docker Compose deployment behind the client's firewall. Full data sovereignty.
3. **Hybrid**: Cloud-hosted platform with an on-premises **Relay Agent** that tunnels integration calls to internal systems (on-prem Jira, ServiceNow, internal scanners) via secure WebSocket connection.

---

## Core Capabilities

### 1. Universal Scanner Ingestion

Hakuna normalizes and correlates data from **125+ security tools** across categories:

| Category | Examples |
|----------|---------|
| Vulnerability Scanners | Nessus, Qualys, Rapid7 InsightVM, Tenable.io/sc, Microsoft Defender |
| Cloud Security (CSPM) | AWS Security Hub, Azure Defender, GCP Security Command Center, Wiz, Prisma Cloud, Orca |
| Application Security | Snyk, Checkmarx, Veracode, GitHub Advanced Security, Burp Enterprise, OWASP ZAP |
| Endpoint & Patch Management | CrowdStrike, SentinelOne, Automox, Ivanti, Tanium, Carbon Black |
| OT/ICS/IoT | Claroty, Dragos, Nozomi, Armis |
| Identity & Access | Okta, Azure AD, CyberArk, BeyondTrust, SailPoint, Active Directory |
| Pen Test & BAS | Pentera, AttackIQ, SafeBreach, HackerOne, Bugcrowd, Cobalt |
| Threat Intelligence | Recorded Future, MISP, VirusTotal, Shodan |
| Network & Firewall | Checkpoint, Palo Alto NGFW, Fortinet FortiGate |
| Cloud Asset Discovery | AWS (EC2, S3, Lambda, Route 53, IAM), Azure (VMs, Functions, DNS, Storage), GCP (Compute, Cloud Functions, DNS, Storage, IAM) |

Each connector uses a standardized **field mapping** engine that normalizes findings, assets, and metadata into a unified data model — enabling cross-scanner correlation, deduplication, and a single pane of glass regardless of the client's tooling.

New connectors can be built using the **Integration Builder** with JSON schema definitions, OAuth2 support, and automatic OpenAPI discovery.

### 2. Intelligent Asset Management

Hakuna maintains a continuously updated **asset inventory** with deep context:

**Asset Types:**
- Hosts (servers, endpoints, network devices)
- Web Applications
- Cloud Instances (AWS, Azure, GCP)
- API Endpoints
- Identities (human and non-human: service accounts, machine identities, bots)
- Container Images
- Code Repositories
- Kubernetes Workloads
- Custom types via low-code rules

**Asset Intelligence:**
- **Criticality scoring** (1–10, user-configurable per asset)
- **Internet-facing detection** (public IP + listening port heuristics, DNS signals, cloud provider metadata)
- **OS fingerprinting** and system type classification
- **Asset relationships** (directional graph edges: DNS record → cloud workload, host → container, etc.)
- **Reachability analysis** (multi-signal: public IP, network routes, scan protocol results)
- **Ownership inference** (automated routing rules: OS-based → IT team, web apps → AppSec, etc.)
- **Auto-tagging** (pattern-based rules: by OS, IP range, hostname, plugin family, environment)

**Software Inventory & SBOM:**
- Full software inventory extracted from scan data (installed applications, libraries, runtimes)
- SBOM pipeline correlates software → CVEs → affected assets
- **End-of-life tracking** for 30+ product families (Python, Node.js, Java, .NET, OpenSSL, PostgreSQL, MySQL, Docker, Kubernetes, Ubuntu, Windows, and more)
- CPE-based vulnerability correlation
- Blast radius analysis: component → linked findings → affected asset graph

**Deep Inventory Extraction** (from Nessus and other authenticated scans):
- Users, Groups (with org hierarchy), Domain Controllers
- Services, Network Connections, Scheduled Tasks
- Installed & Missing Patches
- SMB/NFS Shares (writeable share detection)
- Security Controls (AV, EDR, firewall, SIEM coverage)
- Certificates (expiry tracking, self-signed detection)
- Password Policies (weak policy detection)
- Credentials (exposed/cleartext detection)
- Database Instances
- Domain Trusts
- AI Tools in the environment
- Running Processes

### 3. Risk-Based Prioritization

Raw vulnerability counts are not actionable. Hakuna computes a **0–10 priority score** for every finding using multiple risk signals:

| Signal | Weight | Source |
|--------|--------|--------|
| CVSS v3/v2 | Base severity | NVD, scanner |
| VPR (Vulnerability Priority Rating) | Tenable's predictive score | Nessus |
| Exploit availability & maturity | Weaponized (2.0x), Functional (1.5x), PoC (1.2x) | NVD, ExploitDB, threat intel feeds |
| EPSS | Probability of exploitation in next 30 days | FIRST.org |
| CISA KEV | Known exploited in the wild | CISA catalog |
| Ransomware linkage | Associated with ransomware campaigns | Threat intel |
| Asset criticality | Business impact of the affected asset | User-defined (1–10) |
| Internet-facing exposure | Reachable from the internet | Multi-signal detection |
| Plugin family weights | "Gain a shell remotely" = 1.5x, "Backdoors" = 1.5x | Configurable |
| Trending in news | Active media/researcher attention | Threat intel |

**Effort classification** automatically categorizes each finding:
- **Quick Win**: Patch available, low complexity — ideal for rapid risk reduction
- **Medium**: Reboot required or moderate complexity
- **Complex**: Architectural change, EOL system, vendor dependency

**Cross-scanner deduplication** ensures the same vulnerability reported by multiple tools is counted once, correlated by CVE, plugin, asset, and port.

**Cross-source normalization** uses CVE-based normalized IDs to correlate findings across scanners — a Nessus finding and a Qualys finding for CVE-2024-XXXX are linked automatically.

### 4. SLA Management & Compliance Tracking

Define and enforce remediation timelines per severity:

| Severity | Default SLA | Warning Threshold |
|----------|------------|-------------------|
| Critical | 15 days | 5 days before breach |
| High | 30 days | 10 days before breach |
| Medium | 90 days | 20 days before breach |
| Low | 180 days | 30 days before breach |

SLA timelines are fully configurable per organization. Status tracking (`on_track`, `at_risk`, `breached`, `resolved`) provides real-time visibility into remediation velocity.

**Exception management** with full audit trail:
- **Risk Acceptance**: Documented justification, approver, expiry date, review schedule
- **False Positive**: Mark findings that are scanner errors
- **Compensating Control**: Document alternative mitigations
- **Severity Override**: Adjust severity based on context
- **Technical Debt**: Track legacy system vulnerabilities with mitigation plans and categories (legacy_system, business_requirement, vendor_dependency, compatibility, cost)

All exceptions include scope controls (per-finding or per-plugin across all assets), expiry dates, and can be excluded from report totals for clean compliance metrics.

### 5. Remediation Campaigns & Ticketing

**Campaigns** group related findings into actionable remediation projects:

- Create campaigns using any combination of filters (severity, CVE, asset, tag, exploit status, SLA, owner, etc.)
- Preview campaign scope before committing
- Assign to owners (by user, role, or team)
- Track per-finding status within the campaign
- **Auto-ticket creation**: Generate Jira issues, ServiceNow incidents, or tickets in Azure DevOps/Linear/GitHub Issues — configurable grouping (one ticket per finding, per asset, or one for all)
- **Dedicated Slack channels**: Automatically create a Slack channel per campaign and invite collaborators
- Campaign-attached workflows fire on execution

**Solution aggregation** groups findings by remediation action (e.g., "Apply KB5034763 — fixes 47 findings across 12 assets"), surfacing the most impactful patches first.

**Bi-directional ticket sync**: Ticket status in Jira/ServiceNow syncs back to Hakuna automatically — when a ticket is resolved, the corresponding findings update.

**Patch management integrations**: Trigger patch actions directly in Automox, Ivanti, or Tanium from within Hakuna.

### 6. Threat Intelligence

Hakuna enriches every finding with real-time threat context:

- **CISA KEV**: All findings are checked against the Known Exploited Vulnerabilities catalog. KEV findings are flagged and prioritized.
- **NVD Enrichment**: CVSS v2/v3/v4 scores, CWE mappings, affected CPE ranges, descriptions — batch backfill for any missing data.
- **EPSS Scores**: Exploit Prediction Scoring System probability and percentile from FIRST.org.
- **MITRE ATT&CK Mapping**: Three-signal TTP matching (plugin ID → technique, keyword analysis, plugin family → tactic heuristic). Findings are mapped to ATT&CK techniques with confidence levels.
- **Patch Reliability Scoring**: Signal-based 0–1 reliability score per patch (recall, regression, known issues, rollback history, supersedence). Time-decayed scoring reflects current patch stability.
- **Have I Been Pwned**: Domain-based breach monitoring for EASM-discovered domains.
- **Corporate Structure Intelligence**: GLEIF (Legal Entity Identifiers), SEC EDGAR (10-K subsidiary lists), and Wikidata enrichment for M&A attack surface discovery.

### 7. External Attack Surface Management (EASM)

Built-in EASM capabilities for continuous external reconnaissance:

**Discovery Pipeline:**
- Passive subdomain enumeration (50+ DNS sources via Subfinder)
- DNS bruteforce with wildcard detection (PuredNS)
- DNS resolution for A, CNAME, MX, TXT records (DNSx)
- ASN-based IP range discovery (ASNmap)
- Passive search engine discovery via Shodan, Censys, Fofa, Hunter (Uncover)
- Fast port scanning with configurable rate limits (Naabu)
- Liveness validation (Naabu recheck + httpx HEAD probe)

**Enrichment Pipeline:**
- HTTP/HTTPS fingerprinting (headers, status, title, redirect chains)
- TLS certificate inspection (expiry, SANs, cipher suites, JARM fingerprints)
- CDN/WAF provider identification (Cloudflare, Akamai, Fastly, etc.)
- Web crawling for endpoint discovery (Katana)
- Service fingerprinting with banner analysis (Nmap)
- Favicon, JavaScript, and banner-based technology detection
- Protocol identification (layer 4)
- CPE inference from detected tech stack
- Automatic asset type classification

**Automated Finding Generation:**
- Expired TLS certificates
- Weak TLS configurations (old protocols, weak ciphers)
- Exposed databases (MongoDB, Redis, Elasticsearch)
- Dangling DNS records
- Open sensitive ports

**Delta Detection:**
- New asset alerts (previously unseen hosts)
- Gone assets (no longer resolving)
- Port change tracking (opened/closed since last scan)
- Tech stack change detection
- Certificate expiry warnings

EASM findings are unified into the main findings explorer — the same prioritization, SLA tracking, and remediation workflows apply.

### 8. AI-Powered Security Copilot & Agents

**Security Copilot**: Conversational AI assistant with access to 111+ platform tools. Analysts can ask natural language questions ("Show me all critical findings on internet-facing assets with known exploits that are past SLA"), run ad-hoc investigations, search uploaded documents, and execute platform actions — all through conversation.

**20 Pre-Built Agent Templates:**

| Agent | What It Does |
|-------|-------------|
| Daily Triage Report | Morning briefing: top risks, SLA breaches, new criticals, quick wins |
| Patch Tuesday Prep | Missing patches grouped by KB, impacted assets, recommended patching order |
| Executive Summary | Non-technical risk posture report with trends for leadership |
| SLA Watchdog | Monitors deadlines, alerts on breaches, suggests escalations |
| Attack Surface Mapper | Internet-facing hosts, admin accounts, open shares, weak certs |
| Auto-Ticket Creator | Analyzes critical findings and creates Jira/ServiceNow tickets |
| Remediation Campaign Builder | Builds targeted campaigns, assigns to teams |
| Threat Intelligence Analyst | Correlates threat groups, CVEs, and campaigns with your environment |
| Auto-Tagger | Classifies assets and findings with environment/role/owner/risk tags |
| Scan Coverage Auditor | Identifies unscanned assets, credential failures, scan gaps |
| Regression Detector | Finds vulnerabilities that were fixed but reappeared |
| Exception Reviewer | Audits expiring risk acceptances, false positives, and compensating controls |
| Asset Owner Accountability | Per-team scorecards with SLA compliance rates |
| Zero-Day Exposure Check | Rapid blast radius assessment for a specific CVE |
| Change Window Validator | Confirms patches landed in post-change scans |
| Noise Reducer / Tuning Advisor | Identifies low-value findings, recommends scan tuning |
| Asset Classifier | Classifies all assets with OS/environment/segment/role tags |
| Auto-Tag Rule Builder | Builds persistent auto-tag rules from scan patterns |
| Escalation Detective | Investigates chronic remediation failures |
| Compliance Auditor | Maps posture to PCI-DSS, SOC 2, NIST CSF, CIS Controls |

**Multi-Provider AI**: Agents can run on Claude (Anthropic), GPT-4o (OpenAI), Gemini (Google), Llama (Groq), or locally via Ollama — choose based on cost, performance, or data residency requirements.

**Autonomy Controls**: Three levels — `auto` (fully autonomous), `confirm` (human approval for write actions), `conservative` (approve all actions). Configurable per agent.

**Agent Scheduling**: Run agents on cron schedules (hourly, daily, weekly, monthly, or custom cron expressions) for continuous automated operations.

**Multi-Agent Pipelines**: Pre-built multi-stage workflows with typed handoffs:
- Vulnerability Triage (Scan Ingest → Risk Scoring → Triage Decisions)
- Patch Planning (Gap Analysis → Impact Assessment → Patch Plan)
- Auto-Ticketing (Finding Analysis → Ticket Drafting → Ticket Creation)
- Exception Review (Expiry Scan → Risk Reassessment → Recertification)
- Compliance Posture (SLA Audit → Owner Accountability → Board Report)
- Threat-Driven Prioritization (Threat Intel Match → Exposure Mapping → Response Plan)

### 9. Workflow Automation Engine

Visual, node-based workflow builder with three node types:

**8 Trigger Types:**
- Manual / On Campaign Run
- Schedule (cron or simple interval)
- On Scan Upload
- On Integration Completion
- On New Threat Intelligence (new CVEs, KEV entries, exploits — with severity threshold)
- On New Asset Discovery (any / internet-facing / high criticality)
- On New Finding (configurable severity threshold, exploit-only filter)

**6 Filter Types:**
- Severity, Score (CVSS/VPR/EPSS), Exploit status, Tag, Asset properties, Custom conditions (any field with AND/OR logic)

**12 Action Types:**
- Assign Owner, Add Tag, Change Status, Set Criticality
- Send Email (templated with findings table)
- Send Webhook (any URL with custom headers)
- Create Ticket (Jira, ServiceNow, Azure DevOps, Linear, GitHub Issues)
- Slack Notify, Teams Notify
- Run AI Agent (inline agent execution with downstream data passing)
- Create Exception (bulk risk acceptance/false positive/compensating control)

**Pre-Built Workflow Templates:**
- Critical Finding Triage → Assign SecOps → Slack notify
- Patch Tuesday → High+ findings → Jira tickets grouped by asset
- Exploitable Finding Response → Tag urgent → Raise criticality → Email
- Smart Owner Routing → Severity-based team assignment
- SLA Breach Escalation → Email owner → Create ServiceNow ticket
- KEV Alert → Filter affected assets → Slack + Jira
- New Internet-Facing Asset → Enrich + Notify SecOps

### 10. Reporting & Client Deliverables

**Report Builder** with 14 widget types: KPI cards, bar/line/pie charts, funnels, radar charts, gauges, treemaps, heatmaps, risk grades (A–F), tables, headers, dividers, and images.

**50+ built-in data presets** across categories:
- Severity distribution, risk grades, SLA compliance
- Exploit counts, quick wins, zombie vulnerabilities, regressions
- Assessment coverage (credentialed vs. uncredentialed)
- Inventory insights (domain admins, kerberoastable accounts, lateral movement paths, writeable shares, expired certs, credential exposures, weak password policies, AI tools)
- EASM metrics (discovered assets, open ports, CDN coverage, tech stack, change events)
- Control validation coverage
- Filtered finding/asset counts
- Tabular views (top risky assets, quick wins, aggregated solutions, solutions by owner)

**3 Out-of-the-Box Report Templates:**
- **Security Overview Dashboard**: KPI-focused operational view
- **Executive Summary**: Non-technical leadership report with trends
- **Operational Dashboard**: Team-level with remediation focus

**NLP Report Builder**: Natural language interface — describe what you want to see and Hakuna generates the widget ("show me critical findings by team over the last 90 days").

**Scheduled Reports**: Attach a schedule (hourly, daily, weekly, monthly, or custom cron) to any report template. Reports are rendered as PDF via headless browser (preserving all charts and styling) and delivered via email.

**Export Formats**: CSV and JSON export for all entity types (assets, findings, inventory tables) with full query filter support.

**Industry Benchmarking**: Compare client posture against industry peers (Financial, Healthcare, Technology, Government, Retail, Education, Manufacturing) across metrics like risk grade, MTTR, SLA compliance, and exploit density. Live platform percentiles (p25/p50/p75/p90) from cross-tenant anonymous aggregates.

### 11. Security Control Assessment

- Define security control policies mapped to products (CrowdStrike, Defender, etc.)
- Per-finding control assessment: verdict (mitigated, partially mitigated, not mitigated), confidence score, AI-generated explanation
- MITRE ATT&CK technique matching per assessment
- Control policy assignment to asset groups
- Coverage percentage and statistics
- Bulk assessment across all findings for a scan
- Dedicated report widgets for control validation

### 12. MSSP Multi-Tenancy

**Organization Hierarchy:**
- MSSP organizations with parent-child client structure
- Explicit access grants via `MSSPOrgAccess` (activate/deactivate without deleting)
- Self-serve client onboarding via tokenized invite links (24-hour expiry, optional pre-filled email and org name)
- Automatic parent-child linking when MSSP admin creates client orgs

**Org Switcher:**
- Sidebar dropdown for MSSP users to switch between client contexts or view aggregated data across all clients
- `X-Org-Context` header ensures all API calls are scoped to the selected tenant
- "All Orgs" view for cross-client visibility

**Per-Tenant Isolation:**
- Every database query filters by `org_id` — strict tenant data isolation
- Per-org configuration: risk scoring weights, SLA timelines, dedup rules, auto-tag rules
- Per-org integrations and credentials
- Per-org AI agent configurations

**RBAC:**
- 5 built-in roles: Superadmin, Org Admin, Analyst, Viewer, Custom
- 30+ granular permissions (page access, data read/write, action permissions)
- Custom roles with allow/deny permission merging
- Tag-scoped permissions (restrict access to specific asset/finding tags)
- SAML 2.0 SSO with per-org IdP configuration

**Configuration Portability:**
- Export/import risk config, dedup config, auto-tag rules, and report templates
- Replicate proven configurations across client tenants

**Onboarding Packages:**
- Industry-specific pre-configured packages that auto-provision SLA configs, campaigns, workflows, and dashboards (IT/Security, DevSecOps, Cloud Security, Risk & Compliance)

---

## Services MSSPs Can Build on Hakuna

### Tier 1: VMaaS (Vulnerability Management as a Service)

The foundational service most MSSPs deliver. Hakuna automates the manual work:

**What you deliver:**
- Continuous vulnerability scanning and data ingestion from client scanners
- Cross-scanner normalization and deduplication
- Risk-based prioritization (not just CVSS — exploit context, asset criticality, threat intelligence)
- SLA tracking and breach alerting
- Regular remediation reports (automated PDF delivery)
- Ticketing integration for remediation handoff
- Monthly/quarterly executive summary reports

**How Hakuna enables it:**
- Universal scanner ingestion (125+ tools) eliminates data normalization effort
- Automated prioritization replaces manual analyst triage
- Scheduled reports with PDF delivery remove report generation work
- SLA engine with breach alerts keeps remediation on track
- Campaign system groups findings into actionable remediation projects
- Bi-directional Jira/ServiceNow sync closes the loop on remediation

**Analyst time saved:** 60–70% reduction in data wrangling, report generation, and manual triage. Analysts focus on client communication and strategic guidance.

### Tier 2: EMaaS (Exposure Management as a Service)

The premium tier that goes beyond vulnerability scanning:

**What you deliver (VMaaS plus):**
- Full asset inventory with software, identity, and relationship context
- External attack surface monitoring (EASM)
- Threat intelligence overlay (CISA KEV, EPSS, MITRE ATT&CK mapping)
- Security control validation (is the client's EDR actually catching what it should?)
- Blast radius and lateral movement analysis
- End-of-life software tracking and SBOM
- Compliance posture mapping (PCI-DSS, SOC 2, NIST CSF, CIS Controls)
- Industry benchmarking (how does this client compare to peers?)
- Risk trending and improvement tracking over time

**How Hakuna enables it:**
- EASM scanner discovers unknown external assets automatically
- Threat intel enrichment (KEV, EPSS, ATT&CK, patch reliability) adds context no scanner provides alone
- Software inventory and SBOM pipeline tracks component-level risk
- Control assessment engine validates security tool effectiveness
- Benchmarking compares client posture to industry and platform peers
- Report builder visualizes all of this in client-ready dashboards

### Tier 3: Managed Detection & Response Augmentation

Extend VMaaS/EMaaS with proactive, AI-driven operations:

**What you deliver:**
- AI-powered daily triage reports per client
- Automated zero-day exposure checks when new CVEs drop
- Regression detection (fixed vulnerabilities that reappeared)
- Continuous scan coverage auditing
- Automated exception review and recertification
- Proactive patch reliability advisories

**How Hakuna enables it:**
- 20 pre-built AI agent templates cover common MSSP workflows
- Agent scheduling runs daily/weekly automated analyses per client
- Multi-agent pipelines chain analysis → decision → action
- Human-in-the-loop controls ensure MSSP analysts approve critical actions

### Tier 4: Compliance & Risk Advisory

Position your practice as a strategic risk advisor:

**What you deliver:**
- Continuous compliance posture mapping to frameworks (PCI-DSS, SOC 2, NIST CSF, CIS)
- Exception management and risk acceptance governance
- Audit-ready evidence packages (exception audit trails, SLA compliance records, control assessments)
- Technical debt tracking and mitigation planning
- Industry benchmark reports demonstrating client maturity

**How Hakuna enables it:**
- Compliance Auditor AI agent maps findings to framework controls
- Exception workflow with approver tracking and expiry enforcement
- Full audit log of all configuration changes
- Benchmarking engine provides peer comparison data
- Report builder creates framework-specific compliance dashboards

### Tier 5: Automation & Integration Services

Help clients operationalize their security program:

**What you deliver:**
- Custom workflow design and implementation
- Integration buildout (connect client's tools to Hakuna)
- Auto-tag and auto-assignment rule configuration
- Reporting customization and scheduled delivery
- API integration with client's internal tools

**How Hakuna enables it:**
- Visual workflow builder with 12 action types and 8 trigger types
- Integration Builder with 125 pre-built connectors + custom connector support
- Auto-tag rule engine with pattern matching
- Report builder with 50+ presets and custom widget creation
- Full REST API for all platform functions

---

## Value Proposition Summary

### For the MSSP

| Benefit | Impact |
|---------|--------|
| **Unified platform** | Replace 3–5 tools with one. No more stitching together scanners, ticketing, reporting, and threat intel manually. |
| **Multi-tenant by design** | Purpose-built org hierarchy, not bolted-on. Onboard clients in minutes with invite links. |
| **Analyst efficiency** | 60–70% less time on data wrangling. Automated prioritization, dedup, and reporting. |
| **Service differentiation** | Deliver EMaaS (not just VMaaS) with EASM, threat intel, control validation, and AI agents. |
| **Scalable operations** | AI agents and workflow automation scale analyst judgment without scaling headcount. |
| **Deployment flexibility** | Cloud, on-prem, or hybrid. Meet any client's data residency requirements. |
| **Revenue expansion** | Tiered service model from VMaaS ($) through EMaaS ($$) to Compliance Advisory ($$$). |

### For the MSSP's Clients

| Benefit | Impact |
|---------|--------|
| **Risk-based prioritization** | Fix what matters most, not just what scores highest on CVSS. |
| **Reduced mean time to remediation** | Automated triage, ticketing, and SLA tracking accelerate fix cycles. |
| **Visibility** | Single pane of glass across all scanners, cloud providers, and security tools. |
| **Compliance readiness** | Continuous framework mapping with audit-ready evidence. |
| **Actionable intelligence** | Threat intel context (KEV, EPSS, exploits, ATT&CK) on every finding. |
| **Self-service reporting** | Clients can access their own dashboards without MSSP intervention. |

---

## Internationalization

Hakuna's frontend supports **12 languages** with full translations:

English, Spanish, French, German, Portuguese, **Japanese (日本語)**, Chinese, Korean, Arabic (RTL), Hebrew (RTL), Italian, Dutch

All user-facing strings, navigation, reports, and notifications are localized. Right-to-left (RTL) layout support is built in for Arabic and Hebrew.

---

## Integration Ecosystem

### Scanner & Security Tool Connectors (125+)

Hakuna's Integration Builder provides pre-built connectors across the full security stack:

- **Vulnerability Management**: Nessus, Qualys, Rapid7, Tenable.io/sc, Defender
- **Cloud Security**: AWS Security Hub, Azure Defender, GCP SCC, Wiz, Prisma Cloud, Orca
- **Application Security**: Snyk, Checkmarx, Veracode, GitHub Advanced Security, Burp
- **Endpoint**: CrowdStrike, SentinelOne, Carbon Black, Automox, Ivanti, Tanium
- **OT/ICS/IoT**: Claroty, Dragos, Nozomi, Armis
- **Identity**: Okta, Azure AD, CyberArk, BeyondTrust, SailPoint, Active Directory
- **Pen Test & BAS**: Pentera, AttackIQ, SafeBreach, HackerOne, Bugcrowd
- **Threat Intel**: Recorded Future, MISP, VirusTotal, Shodan
- **ITSM**: Jira, ServiceNow, PagerDuty, Linear, Freshservice
- **Collaboration**: Slack, Microsoft Teams, Email (SMTP), Generic Webhooks
- **Cloud Infrastructure**: AWS (EC2, S3, Lambda, Route 53, IAM), Azure (VMs, Functions, DNS, Storage), GCP (Compute, Functions, DNS, Storage, IAM)
- **HR/Identity Governance**: BambooHR, HiBob, Rippling, Workday

---

## Design Partnership Opportunity

As a design partner, you will have direct influence on the platform roadmap. We are actively building:

- **Cross-tenant comparison dashboards**: Side-by-side client posture comparison for MSSP operators
- **Per-client org labeling**: Asset and finding attribution in the aggregated MSSP view
- **MSSP-managed template distribution**: Push report templates, workflow configs, and campaign templates to client tenants
- **White-label reporting**: Custom branding on client-facing reports and dashboards
- **Client self-service portal**: Read-only client access to their own dashboards and reports

Your feedback as a design partner will shape these features to match real MSSP operational needs.

---

## Getting Started

1. **Deploy**: Cloud-hosted (fastest), Docker Compose (on-prem), or hybrid with Relay Agent
2. **Configure**: Set up your MSSP organization, define SLA policies, configure risk scoring weights
3. **Onboard clients**: Use invite links or create client orgs directly. Apply onboarding packages for rapid setup.
4. **Connect scanners**: Import scan files or configure Integration Builder connectors for automated ingestion
5. **Automate**: Set up workflows for triage, ticketing, and alerting. Schedule AI agents for daily operations.
6. **Report**: Build client dashboards, schedule PDF delivery, and configure executive summary reports

---

*For technical documentation, API reference, and integration guides, contact us for access to the full developer portal.*
