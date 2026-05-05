# Hakuna Demo Scripts

Three tailored walkthroughs for different buyer personas. Each demo is designed for ~15 minutes but can be shortened or extended based on audience engagement.

---

## Pre-Demo Setup

1. **Seed data**: Upload the sample Nessus scan via Settings > Upload Scans (use `nessus basic scan.nessus` from the repo root)
2. **Seed notifications**: Run `python backend/seed_notifications.py`
3. **Create sample campaign**: Add a remediation campaign targeting Critical findings
4. **Create sample agent**: Set up a "Vulnerability Analyst" agent from templates
5. **Theme**: Use dark mode for a polished look
6. **Browser**: Clear tab bar, use full-screen, bump font size (Cmd +)

---

## Demo 1: CISO — "Risk Visibility in 15 Minutes"

**Goal**: Show how Hakuna gives a CISO instant clarity on organizational risk posture, threat exposure, and remediation progress — without needing to ask anyone.

**Opening hook**: _"How long does it take you today to answer 'What's our risk posture?' Let me show you how Hakuna answers that in seconds."_

### Act 1 — The Executive View (3 min)

1. **Dashboard** (`/`)
   - Walk through the risk summary: total findings by severity, priority score distribution, trending over time
   - Highlight the priority scoring: "This isn't just CVSS — it combines exploit maturity, asset criticality, VPR, and threat intel to surface what actually matters"
   - Show the trend line: "Are we getting better or worse over time? This answers that at a glance"

2. **Reports** (`/reports`)
   - Open the NLP report builder
   - Type a natural-language query like "Show me critical findings on production servers from the last 30 days"
   - Show the generated report with charts and tables
   - Mention export to CSV/Excel for board decks

### Act 2 — Threat Intelligence (4 min)

3. **Threat Intel Center** (`/threat-intel`)
   - Show the CISA KEV (Known Exploited Vulnerabilities) tab: "These are the vulns actively being exploited in the wild — and here's how many you have"
   - Show MITRE ATT&CK coverage: "Here's your exposure mapped to adversary tactics and techniques"
   - Show Threat Groups tab: "If APT29 targeted your industry, here's exactly what they'd exploit in your environment"
   - Show EPSS scores: "This is the probability each vuln gets exploited in the next 30 days"

### Act 3 — Remediation Accountability (4 min)

4. **Campaigns** (`/campaigns`)
   - Open the sample campaign
   - Show progress tracking: how many findings are resolved vs. open
   - Show SLA tracking and ownership: "Every finding has an owner and a deadline"
   - "Your team leads see their queue. You see the big picture."

5. **Inventory Explorer** (`/inventory`)
   - Show the deep OS inventory: installed software, security controls, certificates, patching status
   - "This isn't just vulns — it's a live inventory of what's running, who has access, and what controls are in place"

### Act 4 — AI-Powered Analysis (3 min)

6. **Copilot** (floating button, bottom-right)
   - Ask: "What are our top 5 risks right now and what should we prioritize?"
   - Show the AI analyzing your actual data and giving actionable recommendations
   - "Your team doesn't need to build a slide deck — the AI reads your data and gives you the answer"

**Closing**: _"You just saw your entire risk posture — trending, threat exposure, remediation progress, and AI-driven recommendations — in one place, with zero manual work."_

---

## Demo 2: MSSP — "Multi-Tenant at Scale"

**Goal**: Show how an MSSP can manage dozens of clients from a single pane of glass, with strict tenant isolation, white-label flexibility, and operational efficiency.

**Opening hook**: _"You're managing 30 clients with 3 analysts. Let me show you how Hakuna makes that possible without losing your mind — or your margins."_

### Act 1 — Multi-Tenancy (4 min)

1. **Org Switcher** (sidebar)
   - Show the organization dropdown: switch between client orgs
   - "Every client's data is completely isolated — separate findings, assets, users, integrations"
   - Switch to a different org — show how the entire UI updates: dashboard, findings, assets
   - "Your analysts see only what they're authorized to see. Your clients see only their own data"

2. **User Management** (Settings > Users & Roles)
   - Show custom roles: "You can create a 'Client Viewer' role that only sees reports, or an 'Analyst' role with full triage access"
   - Show the 30+ granular permissions: page-level, action-level, tag-level restrictions
   - "Deny always wins — so you can give broad access and lock down specific areas"

### Act 2 — Operational Efficiency (4 min)

3. **Scan Upload & Parsing** (Settings > Upload)
   - Show multi-scanner support: Nessus, Qualys, Rapid7, OpenVAS, Tenable.sc/io, WIZ
   - "One platform for all your clients regardless of what scanner they use"
   - Show auto-deduplication: "Upload two scans from the same client — assets and findings are automatically deduplicated by IP, hostname, and plugin ID"

4. **Finding Explorer** (`/findings`)
   - Show filters: severity, status, asset, tags, ownership
   - Show bulk actions: assign, tag, change status, create tickets
   - "An analyst can triage 200 findings in 10 minutes with bulk actions and smart filters"

5. **Aggregated Solutions** (`/aggregated-solutions`)
   - Show the remediation playlist: "Instead of 500 individual findings, your client gets 20 actionable remediation steps — grouped by solution"
   - "This is what you send to the client. Not a 500-page PDF — a prioritized action plan"

### Act 3 — Integrations (4 min)

6. **Integrations** (Settings > Integrations)
   - Show connector library: Jira, ServiceNow, Slack, Teams, Email, CrowdStrike, Splunk, PagerDuty
   - Show per-org integration setup: "Each client can have their own Jira project, Slack channel, or ServiceNow instance"
   - Show credential vault: "API keys are encrypted at rest — your analysts never see raw credentials"
   - Show bidirectional Jira sync: "Create a ticket from a finding, and when the ticket is resolved in Jira, the finding is automatically closed in Hakuna"

### Act 4 — Deployment & Going Live (4 min)

7. **Deployment Options**
   - "Hakuna runs wherever you need it — Docker Compose for a quick POC, GCP Cloud Run for production with auto-scaling, or your own infrastructure with Terraform"
   - Show Swagger UI (`/docs`): "300+ API endpoints, fully documented, ready to integrate from day one"
   - Show the config export/import (`/api/config/export`): "Set up risk scoring, auto-tag rules, report templates for one client — then export and import into the next client in seconds. Cookie-cutter onboarding."
   - "Database is tenant-isolated by design — PostgreSQL end-to-end, from the compose stack in dev to Cloud SQL in production"

### Act 5 — Delivering VMaaS & EMaaS (5 min)

_"Most MSPs want to sell Vulnerability Management as a Service or Exposure Management as a Service. Let me show you how Hakuna is the engine behind both."_

8. **VMaaS — Vulnerability Management as a Service**
   - "VMaaS is your bread and butter — scan, triage, report, repeat. Here's how Hakuna operationalizes it:"
   - **Ingest any scanner**: "Client A uses Nessus, Client B uses Qualys, Client C has Tenable.sc — Hakuna normalizes them all into one data model. You don't need separate tools."
   - **Automated triage** (`/agents`): Show a scheduled agent — "This agent runs nightly across all clients. It auto-prioritizes findings using CVSS + exploit maturity + asset criticality, tags the critical ones, and drafts a triage summary. Your analyst reviews it in the morning instead of starting from scratch."
   - **Client deliverables** (`/reports`): Show the report builder + export — "Monthly client report? NLP query: 'Critical and high findings resolved this month with remediation velocity.' Export to PDF. Done in 30 seconds, not 3 hours."
   - **SLA tracking** (`/campaigns`): "Every finding has an owner and a deadline. When the client asks 'are we on track?' — you show them the campaign dashboard, not a spreadsheet."
   - **Aggregated solutions** (`/aggregated-solutions`): "Don't send the client 400 findings. Send them 15 remediation actions in priority order. That's what they can actually act on."

9. **EMaaS — Exposure Management as a Service**
   - "EMaaS is the premium tier — it's VMaaS plus context. Here's what makes Hakuna an EMaaS platform:"
   - **Deep asset inventory** (`/inventory`): "Not just vulns — Hakuna extracts installed software, running services, security controls, certificates, patch status, domain trusts, local users. You see the full attack surface, not just CVEs."
   - **Threat intel overlay** (`/threat-intel`): "Map your client's findings to MITRE ATT&CK techniques, show which threat groups target their industry, flag CISA KEV vulns that are actively exploited. This is the context that turns a scan report into a risk briefing."
   - **Security control validation** (`/inventory` > Security Controls): "CrowdStrike installed but policy disabled? EDR coverage gap on 12 servers? Hakuna surfaces control gaps alongside vulnerabilities — that's exposure management."
   - **Risk trending & regression** (`/reports`): "Show the client their risk posture over time. Are they getting better? Where are they regressing? This is the QBR slide that renews contracts."
   - **EPSS + SSVC**: "Exploit Prediction Scoring tells you probability of exploitation in the next 30 days. SSVC gives stakeholder-specific remediation decisions. These aren't in a basic VM report — this is EMaaS differentiation."

10. **Building Your Practice on the Platform**
    - **Config portability**: "Set up risk scoring, auto-tag rules, report templates for one client — export and import into the next client in seconds. Cookie-cutter onboarding."
    - **Custom connectors** (Settings > Integrations): "Client uses a ticketing system we don't support? Add a connector with JSON — define auth, map fields, done. No code."
    - **API-first**: "Everything in the UI is an API call — 300+ endpoints. Pipe data into your PSA, your client portal, your SIEM. Build your own dashboards if you want."
    - **Credential vault**: "Every client's API keys encrypted and isolated. Analysts connect integrations without seeing raw credentials."
    - "You're not reselling a scanner — you're running a VMaaS/EMaaS practice on a platform that scales with you."

### Act 6 — Automation & AI (3 min)

11. **Agents** (`/agents`)
    - Show an agent template: "Vulnerability Analyst agent that auto-triages new findings, enriches with threat intel, and drafts client reports"
    - Show scheduled agent runs: "This agent runs every Monday morning and prepares your weekly client briefing"
    - "One agent replaces 2 hours of analyst work per client per week. Multiply that by 30 clients."

12. **Workflows**
    - Briefly mention: "DAG-based workflows automate ticket creation, notifications, and escalations — no code required"

**Closing**: _"VMaaS or EMaaS — Hakuna is the engine. 30 clients, 3 analysts, any scanner, automated triage, threat intel, and AI that works while your team sleeps. Strict tenant isolation, full API, and config portability so you can onboard clients in minutes. That's how you build a practice that scales."_

---

## Demo 3: Analyst — "From Scan to Fix, Fast"

**Goal**: Show how an analyst's daily workflow — upload, triage, investigate, remediate, report — is faster and smarter in Hakuna.

**Opening hook**: _"You just got a scan from the client. Let me show you how you go from raw scan file to prioritized action plan in under 10 minutes."_

### Act 1 — Ingest & Discover (3 min)

1. **Upload** (Settings > Upload Scans)
   - Drag and drop a Nessus file
   - Show auto-detection of scanner format
   - Show the upload progress and parsing results: "X assets discovered, Y findings imported"
   - "Assets are automatically deduplicated — if this host was in a previous scan, it's updated, not duplicated"

2. **Asset Inventory** (`/assets`)
   - Show the asset list with risk scores, device types, OS info
   - Click into an asset detail page
   - Show everything Hakuna extracted: ports, services, installed software, users, security controls, certificates
   - "This is everything the scanner found on this host — not just vulns, but the full picture"

### Act 2 — Triage & Prioritize (4 min)

3. **Finding Explorer** (`/findings`)
   - Sort by priority score (desc): "These are your top priorities — not just by CVSS, but weighted by exploit availability, asset criticality, and threat intel"
   - Show a critical finding detail page:
     - CVSS and VPR scores
     - Exploit maturity and EPSS probability
     - CISA KEV status (actively exploited?)
     - Affected assets
     - Remediation guidance
   - "In one view, you know: how bad is it, is it being exploited, what's affected, and how to fix it"

4. **Tags & Auto-Rules**
   - Show tagging a finding or asset
   - Show auto-tag rules: "Any finding matching 'Log4j' automatically gets tagged 'critical-patch' and assigned to the infrastructure team"
   - "Tags flow into campaigns, reports, and RBAC — tag once, filter everywhere"

### Act 3 — Investigate with AI (4 min)

5. **Copilot** (from a finding detail page)
   - Open Copilot and ask: "Explain this vulnerability in plain English and give me a remediation plan"
   - Show the AI analyzing the specific finding with full context
   - Ask: "Is there a public exploit for this? What's the risk if we delay patching by 2 weeks?"
   - "This is like having a senior analyst on call 24/7 — except it already read every CVE advisory"

6. **Agents** (`/agents`)
   - Show running an agent: "Analyze all critical findings from today's scan, group by remediation action, and draft a client summary"
   - Show the streaming execution with tool calls
   - Show the generated output: structured, actionable, ready to share

### Act 4 — Remediate & Report (4 min)

7. **Campaigns** (`/campaigns`)
   - Create a new campaign: select Critical + High findings from today's scan
   - Assign owners, set SLA deadlines
   - "Now every finding has an owner and a due date. No more 'I thought you were handling that.'"

8. **Aggregated Solutions** (`/aggregated-solutions`)
   - Show the remediation playlist grouped by solution
   - "Instead of sending the client 300 findings, send them 15 remediation steps in priority order"

9. **Integrations** — Create a Jira ticket from a finding
   - Show one-click ticket creation with pre-populated fields
   - "The ticket has the finding details, affected assets, remediation steps — ready for the ops team"

10. **Export & Report**
    - Export findings to CSV/Excel
    - Show the report builder for custom analytics
    - "Client deliverable done. No copy-pasting from scanner PDFs."

**Closing**: _"You went from a raw scan file to a prioritized, assigned, ticketed remediation plan — with AI analysis and a client-ready report — in under 15 minutes. That's the Hakuna workflow."_

---

## Quick Reference: Feature-to-Persona Map

| Feature | CISO | MSSP | Analyst |
|---------|------|------|---------|
| Dashboard & Trends | Primary | Mention | Mention |
| Threat Intel (KEV, ATT&CK, EPSS) | Primary | Mention | Secondary |
| Reports & NLP Builder | Primary | Secondary | Secondary |
| Multi-Tenancy & Org Switching | -- | Primary | -- |
| RBAC & Custom Roles | Mention | Primary | -- |
| VMaaS Delivery | -- | Primary | -- |
| EMaaS Delivery | -- | Primary | -- |
| Deployment & Infrastructure | -- | Primary | -- |
| API & Platform Extensibility | -- | Primary | -- |
| Custom Connectors (No-Code) | -- | Primary | -- |
| Config Export/Import | -- | Primary | -- |
| Scan Upload & Parsing | -- | Secondary | Primary |
| Finding Triage & Bulk Actions | -- | Secondary | Primary |
| Campaigns & SLA Tracking | Secondary | Secondary | Primary |
| Aggregated Solutions | Mention | Primary | Primary |
| AI Copilot & Agents | Secondary | Primary | Primary |
| Integrations (Jira, Slack, etc.) | Mention | Primary | Secondary |
| Deep Inventory | Secondary | -- | Primary |
| Workflows & Automation | Mention | Secondary | Mention |

---

## Tips for All Demos

- **Use real data**: Always demo with actual scan data, not empty screens
- **Tell a story**: Each demo follows a narrative arc — don't jump around randomly
- **Pause for questions**: After each Act, briefly pause — engagement > coverage
- **Handle "Can it do X?"**: If you don't know, say "Let me check" — don't guess
- **Leave-behind**: Offer a sandbox environment where they can upload their own scan
- **Follow-up**: Send the persona-relevant report/export as a follow-up artifact
