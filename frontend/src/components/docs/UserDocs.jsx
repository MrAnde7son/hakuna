import { useState, useRef, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import {
  BookOpen, ChevronRight, ChevronDown, Search, Upload, Server, Bug, Database,
  Target, Layers, Bot, BarChart3, ShieldAlert, Settings, Tag, Shield, Clock,
  Users, Workflow, Link2, FileDown, Key, Building2, Zap, AlertTriangle,
  ExternalLink, ArrowRight, CheckCircle2, Info, HelpCircle, Globe, BookMarked,
} from 'lucide-react'

const SECTIONS = [
  { id: 'getting-started', labelKey: 'docs.sections.gettingStarted', icon: BookOpen },
  { id: 'onboarding', labelKey: 'docs.sections.onboarding', icon: Upload },
  { id: 'scans', labelKey: 'docs.sections.scans', icon: Globe },
  { id: 'dashboard', labelKey: 'docs.sections.dashboard', icon: BarChart3 },
  { id: 'assets', labelKey: 'docs.sections.assets', icon: Server },
  { id: 'findings', labelKey: 'docs.sections.findings', icon: Bug },
  { id: 'inventory', labelKey: 'docs.sections.inventory', icon: Database },
  { id: 'campaigns', labelKey: 'docs.sections.campaigns', icon: Target },
  { id: 'remediation', labelKey: 'docs.sections.remediation', icon: Layers },
  { id: 'agents', labelKey: 'docs.sections.agents', icon: Bot },
  { id: 'threat-intel', labelKey: 'docs.sections.threatIntel', icon: ShieldAlert },
  { id: 'tags', labelKey: 'docs.sections.tags', icon: Tag },
  { id: 'workflows', labelKey: 'docs.sections.workflows', icon: Workflow },
  { id: 'integrations', labelKey: 'docs.sections.integrations', icon: Link2 },
  { id: 'exceptions', labelKey: 'docs.sections.exceptions', icon: Shield },
  { id: 'sla', labelKey: 'docs.sections.sla', icon: Clock },
  { id: 'ownership', labelKey: 'docs.sections.ownership', icon: Users },
  { id: 'mssp', labelKey: 'docs.sections.mssp', icon: Building2 },
  { id: 'exports', labelKey: 'docs.sections.exports', icon: FileDown },
  { id: 'risk-config', labelKey: 'docs.sections.riskConfig', icon: Zap },
  { id: 'api-reference', labelKey: 'docs.sections.apiReference', icon: Globe },
  { id: 'keyboard-tips', labelKey: 'docs.sections.keyboardTips', icon: BookMarked },
]

function Heading({ children, id }) {
  return (
    <h2 id={id} style={{
      fontSize: 22, fontWeight: 700, color: 'var(--text)',
      margin: '0 0 12px', paddingTop: 8, display: 'flex', alignItems: 'center', gap: 8,
    }}>
      {children}
    </h2>
  )
}

function SubHeading({ children }) {
  return (
    <h3 style={{
      fontSize: 16, fontWeight: 600, color: 'var(--text)',
      margin: '20px 0 8px', display: 'flex', alignItems: 'center', gap: 6,
    }}>
      {children}
    </h3>
  )
}

function P({ children }) {
  return <p style={{ fontSize: 14, lineHeight: 1.7, color: 'var(--text-secondary)', margin: '0 0 12px' }}>{children}</p>
}

function Ul({ children }) {
  return <ul style={{ margin: '0 0 12px', paddingLeft: 20, fontSize: 14, lineHeight: 1.8, color: 'var(--text-secondary)' }}>{children}</ul>
}

function Code({ children }) {
  return (
    <code style={{
      background: 'var(--bg-muted)', border: '1px solid var(--border)',
      borderRadius: 4, padding: '1px 6px', fontSize: 12.5, fontFamily: 'monospace',
      color: 'var(--accent)',
    }}>
      {children}
    </code>
  )
}

function CodeBlock({ children }) {
  return (
    <pre style={{
      background: 'var(--bg)', border: '1px solid var(--border)',
      borderRadius: 8, padding: 16, fontSize: 12.5, fontFamily: 'monospace',
      color: 'var(--text-secondary)', overflowX: 'auto', margin: '0 0 12px',
      lineHeight: 1.6,
    }}>
      {children}
    </pre>
  )
}

function Tip({ children, type = 'info' }) {
  const styles = {
    info: { bg: 'rgba(59,130,246,0.08)', border: '#3b82f6', icon: Info, color: '#60a5fa' },
    success: { bg: 'rgba(34,197,94,0.08)', border: '#22c55e', icon: CheckCircle2, color: '#4ade80' },
    warning: { bg: 'rgba(234,179,8,0.08)', border: '#eab308', icon: AlertTriangle, color: '#facc15' },
  }
  const s = styles[type]
  const Icon = s.icon
  return (
    <div style={{
      background: s.bg, borderLeft: `3px solid ${s.border}`,
      borderRadius: '0 8px 8px 0', padding: '12px 16px', margin: '12px 0',
      display: 'flex', gap: 10, alignItems: 'flex-start',
    }}>
      <Icon size={16} style={{ color: s.color, marginTop: 2, flexShrink: 0 }} />
      <div style={{ fontSize: 13, lineHeight: 1.6, color: 'var(--text-secondary)' }}>{children}</div>
    </div>
  )
}

function ApiTable({ rows }) {
  const { t } = useTranslation()
  return (
    <div style={{ overflowX: 'auto', margin: '0 0 16px' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
        <thead>
          <tr style={{ borderBottom: '2px solid var(--border)' }}>
            <th style={{ textAlign: 'left', padding: '8px 12px', color: 'var(--text-muted)', fontWeight: 600, fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.05em' }}>{t('api.method')}</th>
            <th style={{ textAlign: 'left', padding: '8px 12px', color: 'var(--text-muted)', fontWeight: 600, fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.05em' }}>{t('api.endpoint')}</th>
            <th style={{ textAlign: 'left', padding: '8px 12px', color: 'var(--text-muted)', fontWeight: 600, fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.05em' }}>{t('api.description')}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i} style={{ borderBottom: '1px solid var(--border)' }}>
              <td style={{ padding: '6px 12px' }}>
                <span style={{
                  display: 'inline-block', padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 700, fontFamily: 'monospace',
                  background: r[0] === 'GET' ? 'rgba(34,197,94,0.15)' : r[0] === 'POST' ? 'rgba(59,130,246,0.15)' : r[0] === 'PATCH' ? 'rgba(234,179,8,0.15)' : r[0] === 'PUT' ? 'rgba(168,85,247,0.15)' : 'rgba(239,68,68,0.15)',
                  color: r[0] === 'GET' ? '#4ade80' : r[0] === 'POST' ? '#60a5fa' : r[0] === 'PATCH' ? '#facc15' : r[0] === 'PUT' ? '#c084fc' : '#f87171',
                }}>{r[0]}</span>
              </td>
              <td style={{ padding: '6px 12px', fontFamily: 'monospace', fontSize: 12, color: 'var(--text)' }}>{r[1]}</td>
              <td style={{ padding: '6px 12px', color: 'var(--text-secondary)' }}>{r[2]}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function Section({ id, children }) {
  return (
    <section id={`doc-${id}`} style={{ marginBottom: 40 }}>
      {children}
    </section>
  )
}

/* ──────────────────── Documentation Content ──────────────────── */

function DocContent() {
  return (
    <>
      {/* Getting Started */}
      <Section id="getting-started">
        <Heading id="getting-started"><BookOpen size={22} /> Getting Started</Heading>
        <P>
          Hakuna Exposure Center is a vulnerability management platform that consolidates scan results from multiple sources,
          prioritizes vulnerabilities with AI-powered analysis, and helps security teams plan, track, and automate remediation
          — all from a single dashboard.
        </P>
        <SubHeading>What You Can Do</SubHeading>
        <Ul>
          <li><strong>Import scans</strong> — Upload <Code>.nessus</Code>, <Code>.html</Code>, or <Code>.csv</Code> exports from Tenable Nessus, Qualys, Rapid7, or OpenVAS. Format is auto-detected.</li>
          <li><strong>Run active scans</strong> — Discover external-facing assets with the built-in EASM scanner, or run authenticated vulnerability scans with the VM scanner (powered by Nuclei).</li>
          <li><strong>Prioritize findings</strong> — Findings are scored 0–10 using CVSS, VPR, exploit availability, SSVC decision, asset criticality, and plugin family.</li>
          <li><strong>Manage assets</strong> — Browse all assets with risk scores, ownership, environment tags, and blast-radius analysis.</li>
          <li><strong>Track remediation</strong> — Create campaigns from templates, assign owners, attach workflows, and monitor progress.</li>
          <li><strong>Automate</strong> — Build workflows that create tickets, send notifications, and tag findings automatically.</li>
          <li><strong>Report</strong> — Generate visual reports with 50+ widget types, export to PDF, PowerPoint, CSV, or JSON.</li>
          <li><strong>Threat intelligence</strong> — Map findings to MITRE ATT&CK, enrich CVEs with SSVC/MSRC/GreyNoise/ExploitDB data, and track threat groups.</li>
        </Ul>
        <SubHeading>Navigation</SubHeading>
        <P>Use the sidebar to navigate between the platform's main areas:</P>
        <Ul>
          <li><strong>Intelligence</strong> — Reports dashboard and Threat Intel Center.</li>
          <li><strong>Exposure</strong> — Assets, Findings, and Inventory Explorer. Switch between scans using the <strong>Active Scan</strong> selector.</li>
          <li><strong>Response</strong> — Remediation Campaigns, Aggregated Solutions, and AI Agents.</li>
          <li><strong>Settings</strong> — Integrations, users, roles, SLA, risk config, tags, workflows, and more.</li>
        </Ul>
        <Tip type="info">Use the <strong>Active Scan</strong> dropdown in the sidebar to scope all views to a specific scan, or select "All Scans" for an organization-wide view.</Tip>
      </Section>

      {/* Onboarding */}
      <Section id="onboarding">
        <Heading id="onboarding"><Upload size={22} /> Onboarding</Heading>
        <SubHeading>1. Register Your Organization</SubHeading>
        <P>
          Navigate to <Code>/register</Code> and create your first account. This registers a new organization
          and creates an admin user. You will need to provide an organization name, your email, display name, and password.
        </P>
        <SubHeading>2. Bring in Your First Data</SubHeading>
        <P>
          Click <strong>Upload</strong> in the sidebar (or navigate to <Code>/scans</Code>). Choose how to add data:
        </P>
        <Ul>
          <li><strong>Upload a scan file</strong> — Drag and drop a Nessus, Qualys, Rapid7, or OpenVAS export. Supported formats: <Code>.nessus</Code> (XML, richest data), <Code>.html</Code>, <Code>.csv</Code>. Format is auto-detected.</li>
          <li><strong>EASM scan</strong> — Enter a domain to run an external attack surface discovery scan. Discovers subdomains, open ports, technologies, and TLS certificates without uploading a file.</li>
          <li><strong>VM scan</strong> — Run an authenticated Nuclei-powered vulnerability scan against targets in your environment.</li>
        </Ul>
        <P>
          After import, findings are parsed, scored, enriched with CVSS/VPR/SSVC data, and deduplicated automatically.
        </P>
        <SubHeading>3. Explore the Dashboard</SubHeading>
        <P>
          After your first scan, go to <strong>Reports</strong> (the default landing page) to see a summary of your security posture.
          Use the <strong>Active Scan</strong> selector in the sidebar to filter data by scan.
        </P>
        <SubHeading>4. Invite Your Team</SubHeading>
        <P>
          Go to <strong>Settings &gt; Users</strong> and click <strong>Invite User</strong> to add
          team members with appropriate roles (Admin, Analyst, or Viewer). Custom roles with granular permissions are also available.
        </P>
        <SubHeading>5. Configure Integrations</SubHeading>
        <P>
          In <strong>Settings &gt; Integrations</strong>, connect your ticketing system (Jira, ServiceNow), notification channels
          (Slack, Microsoft Teams, Email), and optionally AI providers (Claude, OpenAI, Gemini) for AI agent features.
        </P>
        <Tip type="success">Once your first scan is in and integrations are configured, you are ready to create campaigns, build workflows, and start remediating.</Tip>
      </Section>

      {/* Scans & Discovery */}
      <Section id="scans">
        <Heading id="scans"><Globe size={22} /> Scans & Discovery</Heading>
        <P>
          The Scans page (<Code>/scans</Code>) is your hub for all scan data — imported files, EASM discoveries, and VM scan results.
          All scan types appear in the same list and can be selected in the <strong>Active Scan</strong> sidebar filter.
        </P>

        <SubHeading>Scan Import (File Upload)</SubHeading>
        <P>Upload exported scan files from any supported scanner. The parser auto-detects the format and extracts findings, assets, and inventory data.</P>
        <Ul>
          <li><strong>Nessus</strong> — <Code>.nessus</Code> XML (recommended), <Code>.html</Code>, or <Code>.csv</Code></li>
          <li><strong>Qualys</strong> — XML report export</li>
          <li><strong>Rapid7 InsightVM</strong> — XML export</li>
          <li><strong>OpenVAS / Greenbone</strong> — XML export</li>
        </Ul>
        <Tip type="info">Use <Code>.nessus</Code> XML exports for the richest data — these include full plugin output, inventory extraction, VPR scores, and CVSS details.</Tip>

        <SubHeading>EASM — External Attack Surface Management</SubHeading>
        <P>
          The EASM scanner discovers your internet-facing exposure without requiring any credentials or file uploads.
          It auto-infers your domain from your registration email on first setup.
        </P>
        <Ul>
          <li><strong>Subdomain discovery</strong> — Enumerates subdomains via passive and active DNS techniques.</li>
          <li><strong>Port scanning</strong> — Identifies open ports and running services on discovered hosts.</li>
          <li><strong>Technology detection</strong> — Fingerprints web technologies, frameworks, and server software.</li>
          <li><strong>TLS / certificate analysis</strong> — Detects expiring or misconfigured certificates.</li>
          <li><strong>Continuous monitoring</strong> — Re-run scans at any time to detect new exposure.</li>
        </Ul>
        <P>
          To start an EASM scan, click <strong>New Scan → EASM Scan</strong> on the Scans page, enter your target domain, and click <strong>Start Discovery</strong>.
          Results are imported automatically as a new scan entry with source type <em>EASM</em>.
        </P>

        <SubHeading>VM Scanner — Active Vulnerability Scanning</SubHeading>
        <P>
          The VM scanner runs authenticated vulnerability checks against your internal or external assets using Nuclei templates.
          It is designed for assets that are confirmed alive (validated via liveness checks) and have been enriched with port/service data.
        </P>
        <Ul>
          <li><strong>Nuclei-powered</strong> — Runs a curated set of Nuclei templates matched to each asset's detected tech stack and open services.</li>
          <li><strong>Template routing</strong> — Templates are automatically selected based on CPE data, detected technologies, and service fingerprints.</li>
          <li><strong>Custom templates</strong> — Upload your own Nuclei YAML templates for organization-specific checks.</li>
          <li><strong>Deduplication</strong> — Findings are deduplicated on <Code>(org, asset, finding_type, title)</Code> — re-scanning updates existing open findings rather than creating duplicates.</li>
          <li><strong>Celery scheduling</strong> — VM scan jobs run as background tasks and can be scheduled for continuous coverage.</li>
        </Ul>
        <P>
          To start a VM scan, click <strong>New Scan → VM Scan</strong> and select the target scope.
          Results appear as a new scan entry with source type <em>VM</em>.
        </P>

        <SubHeading>Scan Comparison</SubHeading>
        <P>
          Compare any two scans side-by-side to see what changed: new findings introduced, findings that were resolved, regressions, and remediation velocity.
          Access via the scan list using the <strong>Compare</strong> action.
        </P>
      </Section>

      {/* Dashboard & Reports */}
      <Section id="dashboard">
        <Heading id="dashboard"><BarChart3 size={22} /> Reports & Dashboard</Heading>
        <P>
          The Reports page (<Code>/</Code>) is a fully customizable report builder with drag-and-drop widgets. It serves as both
          your main dashboard and your reporting engine.
        </P>
        <SubHeading>Report Builder</SubHeading>
        <Ul>
          <li><strong>Widget canvas</strong> — Drag and drop widgets onto a canvas to build custom report layouts.</li>
          <li><strong>50+ data sources</strong> — Choose from summary stats, asset lists, finding breakdowns, inventory data, SLA compliance, remediation velocity, trending charts, and more.</li>
          <li><strong>Live preview</strong> — Widgets render with real data as you build.</li>
          <li><strong>Templates</strong> — Save report layouts as templates. Load and share them across your team.</li>
        </Ul>
        <SubHeading>Available Widgets</SubHeading>
        <Ul>
          <li><strong>Summary cards</strong> — Total findings, assets, risk grade (A-F), SLA compliance rate.</li>
          <li><strong>Severity breakdown</strong> — Pie or bar charts by Critical/High/Medium/Low/Info.</li>
          <li><strong>Plugin families</strong> — Vulnerability distribution by plugin family.</li>
          <li><strong>Trending</strong> — Line charts showing finding counts over time.</li>
          <li><strong>Remediation velocity</strong> — How fast findings are being resolved.</li>
          <li><strong>Regressions</strong> — New vulnerabilities that appeared between scans.</li>
          <li><strong>SLA compliance</strong> — Percentage of findings within SLA deadlines.</li>
          <li><strong>Risk by tags</strong> — Risk scores grouped by organizational tags.</li>
          <li><strong>Inventory widgets</strong> — Software counts, patch levels, certificate expiry, and more.</li>
        </Ul>
        <SubHeading>Exporting Reports</SubHeading>
        <Ul>
          <li><strong>PDF</strong> — Full visual report with charts and tables.</li>
          <li><strong>PowerPoint</strong> — Presentation-ready slides.</li>
          <li><strong>CSV / JSON</strong> — Raw data export for further analysis.</li>
        </Ul>
        <SubHeading>NLP Report Builder</SubHeading>
        <P>
          Use natural language queries to generate reports. Type questions like <em>"show me all critical findings on Windows servers"</em>
          or <em>"which assets have the most unpatched vulnerabilities"</em>, and the system generates the appropriate data view.
        </P>
      </Section>

      {/* Assets */}
      <Section id="assets">
        <Heading id="assets"><Server size={22} /> Assets</Heading>
        <P>
          The Assets page (<Code>/assets</Code>) shows all discovered hosts from your scans with risk scoring, severity breakdowns, and ownership information.
        </P>
        <SubHeading>Asset List</SubHeading>
        <Ul>
          <li><strong>Risk score</strong> — Each asset receives a 0-10 risk score based on its findings.</li>
          <li><strong>Severity breakdown</strong> — Visual indicators showing Critical, High, Medium, Low, and Info finding counts.</li>
          <li><strong>Environment</strong> — Classify assets as Internet-facing, DMZ, Internal, or OT.</li>
          <li><strong>Criticality</strong> — Assign a 1-10 criticality rating to reflect business importance.</li>
          <li><strong>Tags</strong> — Assign organizational tags for grouping and filtering.</li>
        </Ul>
        <SubHeading>Asset Detail</SubHeading>
        <P>
          Click any asset to see its full details, including all findings, inventory data, ownership history, and blast-radius analysis.
        </P>
        <SubHeading>Blast Radius</SubHeading>
        <P>
          The blast-radius feature shows the potential impact if an asset is compromised. It analyzes network connections,
          shared services, domain relationships, and trust chains to map lateral movement paths.
        </P>
        <SubHeading>Ownership</SubHeading>
        <P>
          Assign owners to assets manually, or use <strong>Ownership Rules</strong> (under Settings) to auto-assign based on
          hostname patterns, IP ranges, running services, or inventory data like primary logged-on users.
        </P>
      </Section>

      {/* Findings */}
      <Section id="findings">
        <Heading id="findings"><Bug size={22} /> Findings</Heading>
        <P>
          The Findings page (<Code>/findings</Code>) is the central view for all vulnerabilities discovered across your scans.
        </P>
        <SubHeading>Filtering & Grouping</SubHeading>
        <Ul>
          <li><strong>Group by</strong> — Severity, Asset, Owner, Effort Level, Plugin Family, Root Cause, or CVE.</li>
          <li><strong>Filter by</strong> — Severity, workflow status, SLA status, exploit availability, KEV (Known Exploited Vulnerability), tags, and more.</li>
          <li><strong>NLP Search</strong> — Use the search bar to type natural language queries. The system parses them into structured filters.</li>
        </Ul>
        <SubHeading>Finding Detail</SubHeading>
        <P>Click any finding to open its detail view (<Code>/findings/:id</Code>), which includes:</P>
        <Ul>
          <li><strong>Plugin output</strong> — Full Nessus plugin output with technical details.</li>
          <li><strong>Solution</strong> — Recommended remediation steps.</li>
          <li><strong>MITRE ATT&CK</strong> — Mapped techniques and tactics with confidence scores.</li>
          <li><strong>Blast radius</strong> — Impact analysis showing affected assets.</li>
          <li><strong>Context editor</strong> — Add custom notes, business context, or investigation details.</li>
          <li><strong>Exception handling</strong> — Accept risk or mark as false positive directly from the finding.</li>
        </Ul>
        <SubHeading>Workflow Status</SubHeading>
        <P>Each finding has a status that tracks its remediation lifecycle:</P>
        <Ul>
          <li><strong>Open</strong> — Newly discovered, awaiting action.</li>
          <li><strong>In Progress</strong> — Being actively remediated.</li>
          <li><strong>Resolved</strong> — Fixed and verified.</li>
          <li><strong>Accepted Risk</strong> — Risk accepted via an exception rule.</li>
          <li><strong>False Positive</strong> — Identified as not a real vulnerability.</li>
        </Ul>
        <SubHeading>Prioritization Scoring</SubHeading>
        <P>Findings are scored on a 0-10 scale using this formula:</P>
        <CodeBlock>{`score = (0.30 x CVSS + 0.30 x VPR + 0.20 x Exploit Bonus
       + 0.10 x Criticality + 0.10 x Family Bonus) x 10`}</CodeBlock>
        <Ul>
          <li>Critical findings have a score floor of 7.0; High a floor of 5.0.</li>
          <li>Informational findings are capped at 2.5.</li>
          <li>Each finding is assigned an <strong>effort level</strong> (Quick Win, Medium, Complex) and a suggested <strong>owner team</strong> (IT, DevOps, SecOps, AppSec).</li>
        </Ul>
        <Tip type="info">Scoring weights and thresholds are fully configurable under Settings &gt; Risk Configuration.</Tip>
      </Section>

      {/* Inventory */}
      <Section id="inventory">
        <Heading id="inventory"><Database size={22} /> Inventory Explorer</Heading>
        <P>
          The Inventory Explorer (<Code>/inventory</Code>) reveals deep system configuration data extracted from informational
          Nessus plugin outputs. This gives you an attack surface inventory without additional scanning tools.
        </P>
        <SubHeading>Inventory Categories</SubHeading>
        <Ul>
          <li><strong>Users</strong> — Windows/domain user accounts with OU hierarchy view.</li>
          <li><strong>Groups</strong> — Local and domain group memberships.</li>
          <li><strong>Services</strong> — Running services with startup type and account info.</li>
          <li><strong>Software</strong> — Installed software with versions.</li>
          <li><strong>Patches</strong> — Installed Windows patches / hotfixes.</li>
          <li><strong>Network Connections</strong> — Active TCP/UDP connections and listening ports.</li>
          <li><strong>Scheduled Tasks</strong> — Scheduled tasks with triggers and actions.</li>
          <li><strong>Shares</strong> — Network file shares.</li>
          <li><strong>Logged-On Users</strong> — Currently or recently logged-on users.</li>
          <li><strong>Certificates</strong> — SSL/TLS certificates with expiry dates.</li>
          <li><strong>Security Controls</strong> — Antivirus, firewall, and security products detected.</li>
          <li><strong>Computers</strong> — Domain computer objects.</li>
          <li><strong>Password Policies</strong> — Password complexity and expiry settings.</li>
          <li><strong>Databases</strong> — Database instances (SQL Server, Oracle, MySQL, etc.).</li>
          <li><strong>Processes</strong> — Running processes.</li>
          <li><strong>Credentials</strong> — Cached credentials found during scanning.</li>
          <li><strong>Environment Variables</strong> — System environment variables.</li>
          <li><strong>Domain Trusts</strong> — Active Directory trust relationships.</li>
          <li><strong>AI Tools</strong> — AI/ML tools and frameworks detected on assets.</li>
        </Ul>
        <P>
          Each category supports filtering by scan and asset. All inventory data is exportable to CSV or JSON.
        </P>
        <Tip type="info">Inventory data is auto-extracted on scan upload. You can re-extract from Settings or via the API.</Tip>
      </Section>

      {/* Campaigns */}
      <Section id="campaigns">
        <Heading id="campaigns"><Target size={22} /> Remediation Campaigns</Heading>
        <P>
          Campaigns (<Code>/campaigns</Code>) are targeted remediation programs that group related findings and track their resolution.
        </P>
        <SubHeading>Campaign Templates</SubHeading>
        <P>When creating a new campaign, choose from pre-built templates to get started immediately:</P>
        <Ul>
          <li><strong>Exploitable Now</strong> — Critical & High findings with a known weaponized or functional exploit. Highest-risk items demanding immediate remediation.</li>
          <li><strong>Patch Tuesday</strong> — Critical and High severity findings with missing patches. Run this every Patch Tuesday to scope your monthly patching effort.</li>
          <li><strong>SLA Breached</strong> — All findings that have already exceeded their SLA deadline. Prioritize for escalation.</li>
          <li><strong>Internet-Facing Critical Risk</strong> — High and Critical findings on internet-facing assets.</li>
          <li><strong>Quick Wins</strong> — High/Critical findings with low estimated remediation effort — maximum impact, minimal engineering work.</li>
          <li><strong>New Vulnerabilities</strong> — Findings first seen in the latest scan. Focus on newly introduced risk before it spreads.</li>
          <li><strong>Resurfaced & Regressions</strong> — Previously resolved findings that came back. Often indicates incomplete fixes.</li>
          <li><strong>Zero-Day Exposure</strong> — Assets affected by zero-days with no vendor patch yet. Requires compensating controls.</li>
          <li><strong>Ransomware Exposure</strong> — High/Critical findings with known exploits and high EPSS probability — targets ransomware operators actively use for initial access.</li>
          <li><strong>Blank</strong> — Start from scratch with a custom condition builder.</li>
        </Ul>
        <SubHeading>Creating a Campaign</SubHeading>
        <Ul>
          <li><strong>Name and description</strong> — Give the campaign a clear purpose.</li>
          <li><strong>Query builder</strong> — Define which findings to include using conditions (severity, plugin family, asset environment, tags, CVSS range, EPSS, etc.).</li>
          <li><strong>Preview</strong> — See the blast radius before launching: how many findings and assets will be affected.</li>
          <li><strong>Owner</strong> — Assign a responsible person or team.</li>
          <li><strong>Workflow</strong> — Attach an automation workflow to execute when the campaign runs.</li>
        </Ul>
        <SubHeading>Campaign Lifecycle</SubHeading>
        <Ul>
          <li><strong>Draft</strong> — Campaign is being designed, not yet active.</li>
          <li><strong>Active</strong> — Campaign is running, findings are being tracked.</li>
          <li><strong>Paused</strong> — Temporarily halted.</li>
          <li><strong>Completed</strong> — All findings resolved or campaign closed.</li>
        </Ul>
        <SubHeading>Condition Catalog</SubHeading>
        <P>
          The campaign query builder offers a full catalog of conditions, including severity ranges, plugin families,
          exploit availability, KEV status, EPSS probability, SSVC decision, SLA compliance, asset environment, hostname patterns, OS type, tag membership, and more.
        </P>
      </Section>

      {/* Aggregated Solutions */}
      <Section id="remediation">
        <Heading id="remediation"><Layers size={22} /> Aggregated Solutions</Heading>
        <P>
          The Remediation page (<Code>/aggregated-solutions</Code>) clusters findings by root cause to show you the most
          efficient remediation actions.
        </P>
        <Ul>
          <li><strong>Root cause clustering</strong> — Instead of showing 50 individual findings, shows "Apply patch KB5012345 to 50 assets."</li>
          <li><strong>Effort scoring</strong> — Each solution is scored by effort level (quick win vs complex).</li>
          <li><strong>Severity aggregation</strong> — See the combined risk of all findings that a single action resolves.</li>
          <li><strong>Action types</strong> — Solutions are categorized as Patch, Upgrade, Migrate, Disable, or Configure.</li>
          <li><strong>Efficiency metrics</strong> — Shows how many vulnerabilities and assets each action addresses, helping you maximize impact per effort.</li>
        </Ul>
        <Tip type="success">Use Aggregated Solutions to identify "quick wins" — single actions that resolve many vulnerabilities at once.</Tip>
      </Section>

      {/* AI Agents */}
      <Section id="agents">
        <Heading id="agents"><Bot size={22} /> AI Agents</Heading>
        <P>
          The Agents page (<Code>/agents</Code>) lets you build and run LLM-powered agents that automate analysis and remediation tasks.
        </P>
        <SubHeading>Building an Agent</SubHeading>
        <Ul>
          <li><strong>Model selection</strong> — Choose from Claude (Anthropic), GPT-4o (OpenAI), Gemini (Google), or Llama (Groq).</li>
          <li><strong>System prompt</strong> — Define the agent's role and instructions.</li>
          <li><strong>Tool selection</strong> — Pick from available tools: asset search, finding lookup, policy query, remediation suggestions, and more.</li>
          <li><strong>Guardrails</strong> — Set max steps and enforce read-only mode to prevent unintended changes.</li>
        </Ul>
        <SubHeading>Templates</SubHeading>
        <P>Start from pre-built templates for common use cases:</P>
        <Ul>
          <li><strong>Daily Triage Report</strong> — Summarizes new findings and priority changes.</li>
          <li><strong>Patch Tuesday Prep</strong> — Identifies Microsoft patches needed across your environment.</li>
          <li><strong>Executive Summary</strong> — Generates a management-ready security overview.</li>
          <li><strong>SLA Watchdog</strong> — Monitors SLA breaches and sends alerts.</li>
          <li><strong>Attack Surface Mapper</strong> — Analyzes inventory data for exposure patterns.</li>
          <li><strong>Auto-Ticket Creator</strong> — Creates tickets in Jira/ServiceNow for high-priority findings.</li>
          <li><strong>Remediation Campaign Builder</strong> — Proposes and creates campaigns automatically.</li>
          <li><strong>Threat Intelligence Analyst</strong> — Correlates findings with threat intelligence data.</li>
          <li><strong>Auto-Tagger</strong> — Suggests and applies tags based on finding patterns.</li>
        </Ul>
        <SubHeading>Scheduling</SubHeading>
        <P>
          Agents can be scheduled to run automatically using cron expressions. For example, run a daily triage
          report every morning at 8 AM, or an SLA watchdog every hour.
        </P>
        <SubHeading>Pipelines</SubHeading>
        <P>
          Chain multiple agents together in a pipeline for multi-stage analysis. Pipelines run agents sequentially,
          passing context between stages.
        </P>
        <Tip type="warning">AI agent features require at least one AI provider (Claude, OpenAI, Gemini, or Groq) to be configured under Settings &gt; Integrations.</Tip>
      </Section>

      {/* Threat Intelligence */}
      <Section id="threat-intel">
        <Heading id="threat-intel"><ShieldAlert size={22} /> Threat Intelligence</Heading>
        <P>
          The Threat Intel Center (<Code>/threat-intel</Code>) provides threat context for your vulnerabilities through multiple tabs.
        </P>
        <SubHeading>Newsroom</SubHeading>
        <P>A real-time feed of security advisories, CISA KEV updates, and relevant threat news.</P>
        <SubHeading>CVE Intelligence</SubHeading>
        <P>Search and browse CVEs affecting your environment, enriched from multiple intel sources:</P>
        <Ul>
          <li><strong>NVD / CVSS</strong> — Base scores and vector strings from the National Vulnerability Database, auto-updated every 24 hours.</li>
          <li><strong>CISA KEV</strong> — Flags CVEs in the Known Exploited Vulnerabilities catalog with CISA's required remediation deadlines.</li>
          <li><strong>EPSS</strong> — Exploit Prediction Scoring System probability showing likelihood of exploitation in the next 30 days.</li>
          <li><strong>SSVC</strong> — CISA's Stakeholder-Specific Vulnerability Categorization decision (Act / Attend / Track* / Track). Displayed as a colored badge on findings and CVE detail.</li>
          <li><strong>ExploitDB</strong> — Links to public proof-of-concept exploits when available.</li>
          <li><strong>GreyNoise</strong> — Indicates whether a CVE is being actively mass-exploited on the internet (GreyNoise scanner observations).</li>
          <li><strong>MSRC</strong> — Microsoft Security Response Center patch information and KB article IDs for Microsoft CVEs.</li>
          <li><strong>CWE</strong> — Common Weakness Enumeration classifications surfaced in CVE detail views.</li>
        </Ul>
        <Tip type="info">Intel data is auto-updated every 24 hours. You can force a refresh from Settings → Threat Intel → Sync.</Tip>
        <SubHeading>Threat Groups</SubHeading>
        <P>
          Browse threat actors with motivation (financial, espionage, destruction), country attribution, and known TTPs.
          See which threat groups could exploit vulnerabilities in your environment.
        </P>
        <SubHeading>MITRE ATT&CK Coverage</SubHeading>
        <P>
          View your exposure mapped to the MITRE ATT&CK framework. See which techniques and tactics your vulnerabilities
          enable, and identify coverage gaps. Run TTP matching to correlate findings with known attack patterns.
        </P>
        <SubHeading>Threat Campaigns</SubHeading>
        <P>
          Create remediation campaigns directly from threat intelligence data to address specific threat group activities or attack techniques.
        </P>
        <SubHeading>MITRE Sync</SubHeading>
        <P>
          Sync the latest MITRE ATT&CK STIX bundle from Settings to keep your threat intelligence data current.
        </P>
      </Section>

      {/* Tags */}
      <Section id="tags">
        <Heading id="tags"><Tag size={22} /> Tags & Auto-Tagging</Heading>
        <SubHeading>Tag Management</SubHeading>
        <P>
          Tags provide a hierarchical labeling system for assets and findings. Navigate to <Code>/tags</Code> or
          <strong> Settings &gt; Tags</strong> to manage them.
        </P>
        <Ul>
          <li><strong>Hierarchical</strong> — Create parent-child tag relationships (e.g., Location &gt; US-East &gt; Virginia).</li>
          <li><strong>Colors</strong> — Assign colors for quick visual identification.</li>
          <li><strong>Bulk assignment</strong> — Assign tags to multiple assets or findings at once from list views.</li>
          <li><strong>Filtering</strong> — Filter assets, findings, and reports by tags throughout the platform.</li>
        </Ul>
        <SubHeading>Auto-Tag Rules</SubHeading>
        <P>
          Auto-tag rules automatically apply tags to assets and findings when scans are uploaded. Configure rules under <strong>Settings</strong>:
        </P>
        <Ul>
          <li><strong>Conditions</strong> — Match on hostname pattern, IP range, OS type, severity, plugin family, environment, and more.</li>
          <li><strong>Actions</strong> — Assign one or more tags when conditions match.</li>
          <li><strong>Run on upload</strong> — Rules fire automatically when new scan data is imported.</li>
          <li><strong>Manual run</strong> — Run individual rules or all rules on-demand.</li>
        </Ul>
        <SubHeading>External Tag Sources</SubHeading>
        <P>
          Import tags from external systems (CMDB, CSV files, etc.) and map them to internal tags.
          Sources can be synced periodically to keep tags up-to-date.
        </P>
      </Section>

      {/* Workflows */}
      <Section id="workflows">
        <Heading id="workflows"><Workflow size={22} /> Workflows</Heading>
        <P>
          The Workflow Builder (<Code>/workflows/:id</Code>) is a visual drag-and-drop editor for creating automation workflows.
        </P>
        <SubHeading>Workflow Nodes</SubHeading>
        <P>Build workflows by connecting nodes from these categories:</P>
        <Ul>
          <li><strong>Triggers</strong> — Manual, Schedule (cron), On Upload, On Campaign Run.</li>
          <li><strong>Filters</strong> — Filter findings by severity, status, or attributes. Filter assets by environment or properties. Filter inventory data.</li>
          <li><strong>Actions</strong>:
            <Ul>
              <li>Create Jira tickets (with grouping: per finding, per asset, or one for all)</li>
              <li>Create ServiceNow incidents</li>
              <li>Send Slack notifications</li>
              <li>Send Microsoft Teams notifications</li>
              <li>Send email alerts</li>
              <li>Send webhooks to any URL</li>
              <li>Tag findings or assets</li>
              <li>Create remediation campaigns</li>
              <li>Run auto-tag rules</li>
              <li>Update workflow context</li>
            </Ul>
          </li>
          <li><strong>Decision nodes</strong> — Branch logic based on conditions.</li>
          <li><strong>Aggregators</strong> — Group items before passing to actions.</li>
        </Ul>
        <SubHeading>Templates</SubHeading>
        <P>Start from pre-built workflow templates for common patterns like "critical findings to Jira" or "daily email digest."</P>
        <SubHeading>Execution</SubHeading>
        <P>
          Workflows can be executed manually, triggered by events (scan upload, campaign run), or scheduled via cron.
          View execution history with detailed logs showing which nodes fired and what actions were taken.
        </P>
        <SubHeading>Version History</SubHeading>
        <P>
          Workflows maintain version history. You can view previous versions and restore them if needed.
        </P>
      </Section>

      {/* Integrations */}
      <Section id="integrations">
        <Heading id="integrations"><Link2 size={22} /> Integrations</Heading>
        <P>
          Configure external integrations under <strong>Settings &gt; Integrations</strong>. Each integration can be tested from the UI before use.
        </P>
        <SubHeading>Ticketing Systems</SubHeading>
        <Ul>
          <li><strong>Jira</strong> — Create issues with custom templates, priority mapping, assignee, and labels. Supports grouping strategies (one per finding, one per asset, one for all). Requires: server URL, email, API token, project key.</li>
          <li><strong>ServiceNow</strong> — Create incidents with assignment groups, urgency/impact levels, and custom table support. Requires: instance URL, username, password.</li>
        </Ul>
        <SubHeading>Notifications</SubHeading>
        <Ul>
          <li><strong>Slack</strong> — Rich block notifications with severity summaries via incoming webhook.</li>
          <li><strong>Microsoft Teams</strong> — Adaptive card notifications with theme colors via incoming webhook.</li>
          <li><strong>Email (SMTP)</strong> — Send emails with findings tables. Supports TLS/SSL. Requires: SMTP host, port, username, password, from/to addresses.</li>
        </Ul>
        <SubHeading>Webhooks</SubHeading>
        <P>Send custom HTTP requests to any URL for integrating with other systems.</P>
        <SubHeading>AI Providers</SubHeading>
        <Ul>
          <li><strong>Anthropic (Claude)</strong> — For AI agent features. Requires API key.</li>
          <li><strong>OpenAI (GPT-4o)</strong> — Alternative AI provider. Requires API key.</li>
          <li><strong>Google Gemini</strong> — Alternative AI provider. Requires API key.</li>
          <li><strong>Groq (Llama)</strong> — Open-source model provider. Requires API key.</li>
        </Ul>
        <SubHeading>Integration Builder</SubHeading>
        <P>
          The Integration Builder is a guided wizard for connecting any external data source to the platform — beyond the built-in connectors above.
          Access it from <strong>Settings &gt; Integrations &gt; New Integration</strong>.
        </P>
        <Ul>
          <li><strong>Choose Source</strong> — Select a connector type: REST API, SQL database, file upload, or MCP server.</li>
          <li><strong>Authenticate</strong> — Configure credentials: Bearer token, API key, Basic Auth, or OAuth. Credentials are validated before saving.</li>
          <li><strong>Connect</strong> — Discover available endpoints or tables from the source automatically.</li>
          <li><strong>Pick Records</strong> — Choose which data records or tables to pull from the source.</li>
          <li><strong>Map Fields</strong> — Map source fields to platform fields (assets, findings, tags) using the visual field mapper.</li>
          <li><strong>Preview</strong> — Preview the data import before committing.</li>
          <li><strong>Save</strong> — Save the integration for on-demand or scheduled sync.</li>
        </Ul>
        <Tip type="info">Use the <strong>Test</strong> button on each built-in integration to verify connectivity before using it in workflows or agents.</Tip>
      </Section>

      {/* Exceptions */}
      <Section id="exceptions">
        <Heading id="exceptions"><Shield size={22} /> Global Exceptions</Heading>
        <P>
          Global exceptions let you define rules to accept risk or mark findings as false positives across your environment.
          Manage exceptions under <strong>Settings &gt; Exceptions</strong>.
        </P>
        <SubHeading>Exception Types</SubHeading>
        <Ul>
          <li><strong>Accepted Risk</strong> — The finding is real but the risk is accepted with a documented justification.</li>
          <li><strong>False Positive</strong> — The finding is not actually a real vulnerability.</li>
          <li><strong>Temporary Exception</strong> — Risk accepted for a limited time with an expiration date.</li>
        </Ul>
        <SubHeading>Creating Exceptions</SubHeading>
        <Ul>
          <li>Use the <strong>condition builder</strong> to define which findings the exception applies to (plugin ID, severity, asset hostname, etc.).</li>
          <li>Set an optional <strong>expiration date</strong> for temporary exceptions.</li>
          <li>Add a <strong>justification</strong> documenting why the exception was granted.</li>
          <li>Apply exceptions immediately or schedule them via the "Apply All" action.</li>
        </Ul>
        <P>Exceptions can also be created directly from a finding's detail page.</P>
      </Section>

      {/* SLA */}
      <Section id="sla">
        <Heading id="sla"><Clock size={22} /> SLA Tracking</Heading>
        <P>
          SLA tracking helps ensure vulnerabilities are remediated within defined timeframes. Configure under <strong>Settings &gt; SLA</strong>.
        </P>
        <SubHeading>Configuration</SubHeading>
        <Ul>
          <li>Set remediation deadlines per severity level (e.g., Critical: 7 days, High: 30 days, Medium: 90 days).</li>
          <li>SLA timers start when a finding is first discovered.</li>
          <li>Recalculate SLA status across all findings on-demand.</li>
        </Ul>
        <SubHeading>Monitoring</SubHeading>
        <Ul>
          <li>View SLA compliance summary via the Reports dashboard.</li>
          <li>Filter findings by SLA status (within SLA, approaching breach, breached).</li>
          <li>Use workflows to trigger alerts when SLA deadlines approach.</li>
        </Ul>
      </Section>

      {/* Ownership & RBAC */}
      <Section id="ownership">
        <Heading id="ownership"><Users size={22} /> Ownership & Access Control</Heading>
        <SubHeading>Built-in Roles</SubHeading>
        <Ul>
          <li><strong>Superadmin</strong> — Full access across all organizations. Can create and manage organizations.</li>
          <li><strong>Org Admin</strong> — Full access within their organization. Can manage users, roles, and all settings.</li>
          <li><strong>Analyst</strong> — Can read and write findings, assets, campaigns. Cannot manage users or organization settings.</li>
          <li><strong>Viewer</strong> — Read-only access to dashboards, findings, and assets.</li>
          <li><strong>Custom</strong> — Granular permissions defined per role.</li>
        </Ul>
        <SubHeading>Custom Roles</SubHeading>
        <P>
          Create custom roles under <strong>Settings &gt; Roles</strong> with fine-grained permissions:
        </P>
        <Ul>
          <li><strong>Page access</strong> — Control which pages a user can see (Dashboard, Assets, Findings, Reports, Inventory, Campaigns, etc.).</li>
          <li><strong>Data permissions</strong> — Read/write access to scans, assets, findings, tags, campaigns, workflows, exceptions, integrations.</li>
          <li><strong>Action permissions</strong> — Upload scans, delete scans, export reports, manage users.</li>
          <li><strong>Tag-level permissions</strong> — Restrict access by tag or tag category (e.g., user can only see findings tagged "US-East").</li>
          <li><strong>Deny rules</strong> — Explicitly deny specific permissions. Deny always wins over allow.</li>
        </Ul>
        <SubHeading>Ownership Inference</SubHeading>
        <P>
          The platform can automatically infer asset ownership from inventory data:
        </P>
        <Ul>
          <li><strong>Primary user</strong> — Derived from logged-on user data.</li>
          <li><strong>Admin contacts</strong> — Identified from local admin group membership.</li>
          <li><strong>Team assignment</strong> — Inferred from running services (e.g., database servers assigned to DBA team).</li>
          <li><strong>Ownership rules</strong> — Define rules that auto-assign owners based on hostname patterns, IP ranges, or other attributes.</li>
        </Ul>
      </Section>

      {/* MSSP */}
      <Section id="mssp">
        <Heading id="mssp"><Building2 size={22} /> Multi-Tenancy (MSSP)</Heading>
        <P>
          Hakuna supports multi-tenant architectures for Managed Security Service Providers (MSSPs) and enterprises with multiple business units.
        </P>
        <SubHeading>Organizations</SubHeading>
        <Ul>
          <li><strong>Create organizations</strong> — Superadmins can create separate organizations, each with its own data, users, and settings.</li>
          <li><strong>MSSP linking</strong> — Link an MSSP organization to client organizations to provide managed services.</li>
          <li><strong>Org context switching</strong> — MSSP users see an organization switcher in the sidebar to switch between client contexts.</li>
          <li><strong>Data isolation</strong> — All queries are automatically filtered by organization. Users only see data belonging to their org (or linked client orgs for MSSP).</li>
        </Ul>
        <SubHeading>Access Model</SubHeading>
        <Ul>
          <li><strong>Superadmin</strong> — Sees all organizations and can manage any.</li>
          <li><strong>MSSP users</strong> — See their own org plus linked client organizations.</li>
          <li><strong>Standard users</strong> — Only see their own organization's data.</li>
        </Ul>
        <P>
          The <Code>X-Org-Context</Code> header is used to narrow API requests to a specific organization when operating in multi-tenant mode.
        </P>
      </Section>

      {/* Exports */}
      <Section id="exports">
        <Heading id="exports"><FileDown size={22} /> Exports & Configuration Portability</Heading>
        <SubHeading>Data Exports</SubHeading>
        <P>Export data from any list view using the export button. Available formats:</P>
        <Ul>
          <li><strong>CSV</strong> — Comma-separated values for spreadsheets.</li>
          <li><strong>JSON</strong> — Structured data for programmatic processing.</li>
        </Ul>
        <P>Exportable entities: Assets, Findings, and all 16+ Inventory categories.</P>
        <SubHeading>Configuration Portability</SubHeading>
        <P>
          Export and import platform configurations to replicate setups across environments or share with other teams:
        </P>
        <Ul>
          <li><strong>Risk configuration</strong> — Scoring weights and thresholds.</li>
          <li><strong>Dedup configuration</strong> — Deduplication rules.</li>
          <li><strong>Auto-tag rules</strong> — Rules with referenced tags (supports conflict resolution: skip or overwrite).</li>
          <li><strong>Report templates</strong> — Widget layouts and configurations.</li>
          <li><strong>Campaign + Workflow bundles</strong> — Export a campaign with all attached workflows.</li>
          <li><strong>Agent configurations</strong> — Export/import AI agent definitions.</li>
        </Ul>
      </Section>

      {/* Risk Config */}
      <Section id="risk-config">
        <Heading id="risk-config"><Zap size={22} /> Risk & Scoring Configuration</Heading>
        <P>
          Customize how findings are prioritized under <strong>Settings &gt; Risk Configuration</strong>.
        </P>
        <SubHeading>Scoring Weights</SubHeading>
        <P>Adjust the weight of each factor in the priority score calculation:</P>
        <Ul>
          <li><strong>CVSS weight</strong> (default 0.30) — Common Vulnerability Scoring System.</li>
          <li><strong>VPR weight</strong> (default 0.30) — Vulnerability Priority Rating from Tenable.</li>
          <li><strong>Exploit weight</strong> (default 0.20) — Bonus for findings with known exploits.</li>
          <li><strong>Criticality weight</strong> (default 0.10) — Based on asset criticality rating.</li>
          <li><strong>Family weight</strong> (default 0.10) — Based on plugin family risk level.</li>
        </Ul>
        <SubHeading>Score Floors & Caps</SubHeading>
        <P>
          Set minimum scores for Critical and High severity findings, and maximum scores for Informational findings.
          These ensure that severity-based prioritization is respected regardless of other factors.
        </P>
        <SubHeading>Recalculation</SubHeading>
        <P>
          After changing weights or thresholds, click <strong>Recalculate</strong> to re-score all findings in bulk.
          This applies the new configuration retroactively.
        </P>
        <SubHeading>Deduplication</SubHeading>
        <P>
          Configure deduplication under <strong>Settings</strong> to automatically merge duplicate findings across scans.
          Choose which fields constitute a "key" for matching (plugin ID, asset, port, etc.).
        </P>
      </Section>

      {/* API Reference */}
      <Section id="api-reference">
        <Heading id="api-reference"><Globe size={22} /> API Reference</Heading>
        <P>
          The platform exposes a comprehensive REST API. Interactive Swagger documentation is available at <Code>/api/docs</Code>.
        </P>
        <SubHeading>Authentication</SubHeading>
        <P>
          All API requests (except <Code>/api/auth/register</Code> and <Code>/api/auth/login</Code>) require a Bearer token.
          Include the header: <Code>Authorization: Bearer &lt;token&gt;</Code>
        </P>
        <CodeBlock>{`# Login and get a token
POST /api/auth/login
Body: { "email": "user@example.com", "password": "..." }
Response: { "token": "eyJ...", "user": {...} }

# Use the token in subsequent requests
GET /api/findings
Headers: Authorization: Bearer eyJ...`}</CodeBlock>
        <P>Tokens are JWT (HS256) and expire after 8 hours by default.</P>

        <SubHeading>Core Endpoints</SubHeading>
        <ApiTable rows={[
          ['POST', '/api/auth/register', 'Register new organization and admin user'],
          ['POST', '/api/auth/login', 'Authenticate and receive JWT token'],
          ['GET', '/api/auth/me', 'Get current user info and permissions'],
          ['POST', '/api/upload', 'Upload a scan file (Nessus, Qualys, Rapid7, OpenVAS)'],
          ['GET', '/api/scans', 'List all scans (imported, EASM, VM)'],
          ['DELETE', '/api/scans/:id', 'Delete a scan and its data'],
          ['POST', '/api/easm/setup', 'Configure EASM and start domain discovery'],
          ['POST', '/api/easm/scan', 'Trigger an EASM scan for a domain'],
          ['GET', '/api/easm/status/:id', 'Get EASM scan status'],
          ['POST', '/api/vm/scan', 'Trigger a VM (Nuclei) scan'],
          ['GET', '/api/vm/scan/:id/status', 'Get VM scan status'],
        ]} />

        <SubHeading>Assets & Findings</SubHeading>
        <ApiTable rows={[
          ['GET', '/api/assets', 'List assets (supports filtering, sorting, pagination)'],
          ['GET', '/api/assets/:id', 'Get single asset detail'],
          ['PATCH', '/api/assets/:id', 'Update asset fields (environment, criticality)'],
          ['GET', '/api/findings', 'List findings (supports complex filtering)'],
          ['GET', '/api/findings/:id', 'Get single finding detail'],
          ['PATCH', '/api/findings/:id/status', 'Update finding workflow status'],
          ['POST', '/api/findings/bulk-status', 'Bulk update finding statuses'],
          ['PATCH', '/api/findings/:id/resolve', 'Mark finding as resolved'],
          ['GET', '/api/scans/compare', 'Compare two scans side-by-side'],
        ]} />

        <SubHeading>Inventory</SubHeading>
        <ApiTable rows={[
          ['GET', '/api/inventory/summary', 'Summary counts across all categories'],
          ['GET', '/api/inventory/users', 'Windows/domain users'],
          ['GET', '/api/inventory/groups', 'Local and domain groups'],
          ['GET', '/api/inventory/services', 'Running services'],
          ['GET', '/api/inventory/software', 'Installed software'],
          ['GET', '/api/inventory/patches', 'Installed patches'],
          ['GET', '/api/inventory/netconns', 'Network connections'],
          ['GET', '/api/inventory/certificates', 'SSL/TLS certificates'],
          ['GET', '/api/inventory/security-controls', 'AV, firewall, security products'],
          ['GET', '/api/inventory/databases', 'Database instances'],
        ]} />

        <SubHeading>Tags & Campaigns</SubHeading>
        <ApiTable rows={[
          ['POST', '/api/tags', 'Create a tag'],
          ['GET', '/api/tags', 'List all tags'],
          ['POST', '/api/tags/assign', 'Assign tags to assets/findings'],
          ['GET', '/api/auto-tag-rules', 'List auto-tag rules'],
          ['POST', '/api/auto-tag-rules', 'Create auto-tag rule'],
          ['GET', '/api/campaigns', 'List campaigns'],
          ['POST', '/api/campaigns', 'Create a campaign'],
          ['POST', '/api/campaigns/:id/run', 'Execute a campaign'],
          ['POST', '/api/campaigns/preview', 'Preview campaign blast radius'],
        ]} />

        <SubHeading>Workflows & Integrations</SubHeading>
        <ApiTable rows={[
          ['GET', '/api/workflows', 'List workflows'],
          ['POST', '/api/workflows', 'Create a workflow'],
          ['POST', '/api/workflows/:id/execute', 'Execute a workflow'],
          ['GET', '/api/workflows/node-catalog', 'Available workflow node types'],
          ['GET', '/api/integrations', 'List integration configurations'],
          ['PUT', '/api/integrations/:provider', 'Configure an integration'],
          ['POST', '/api/integrations/:provider/test', 'Test integration connectivity'],
        ]} />

        <SubHeading>Reports & Analytics</SubHeading>
        <ApiTable rows={[
          ['GET', '/api/reports/summary', 'Overall risk metrics'],
          ['GET', '/api/reports/risk-grade', 'Risk grade (A-F)'],
          ['GET', '/api/reports/trending', 'Finding trends over time'],
          ['GET', '/api/reports/remediation-velocity', 'Remediation speed metrics'],
          ['GET', '/api/reports/regressions', 'New findings since last scan'],
          ['GET', '/api/sla/summary', 'SLA compliance summary'],
          ['GET', '/api/search/nlp', 'Natural language search'],
        ]} />

        <SubHeading>Agents</SubHeading>
        <ApiTable rows={[
          ['GET', '/api/agents', 'List agents'],
          ['POST', '/api/agents', 'Create an agent'],
          ['POST', '/api/agents/:id/run', 'Run an agent'],
          ['POST', '/api/agents/:id/run/stream', 'Run agent with SSE streaming'],
          ['GET', '/api/agents/templates', 'List agent templates'],
          ['POST', '/api/agents/from-template', 'Create agent from template'],
          ['GET', '/api/agents/schedules', 'List agent schedules'],
          ['POST', '/api/agents/schedules', 'Create cron-based schedule'],
        ]} />

        <SubHeading>Threat Intelligence</SubHeading>
        <ApiTable rows={[
          ['GET', '/api/threat-intel/stats', 'Threat intel statistics'],
          ['GET', '/api/threat-intel/feed', 'Threat news feed'],
          ['GET', '/api/threat-intel/cves', 'CVE intelligence'],
          ['GET', '/api/threat-intel/groups', 'Threat group profiles'],
          ['GET', '/api/threat-intel/ttps', 'MITRE ATT&CK TTPs'],
          ['GET', '/api/threat-intel/ttp-coverage', 'TTP coverage analysis'],
          ['POST', '/api/threat-intel/sync', 'Sync MITRE ATT&CK data'],
        ]} />

        <SubHeading>Exports & Configuration</SubHeading>
        <ApiTable rows={[
          ['GET', '/api/export/assets', 'Export assets (CSV/JSON)'],
          ['GET', '/api/export/findings', 'Export findings (CSV/JSON)'],
          ['GET', '/api/export/inventory/:type', 'Export inventory data'],
          ['GET', '/api/config/export/:type', 'Export platform configuration'],
          ['POST', '/api/config/import/:type', 'Import platform configuration'],
          ['GET', '/api/audit-log', 'View audit trail'],
        ]} />

        <SubHeading>Multi-Tenant</SubHeading>
        <P>For MSSP and multi-org setups, include the <Code>X-Org-Context</Code> header to scope requests to a specific organization:</P>
        <CodeBlock>{`GET /api/findings
Headers:
  Authorization: Bearer eyJ...
  X-Org-Context: <org-id>`}</CodeBlock>
      </Section>

      {/* Tips */}
      <Section id="keyboard-tips">
        <Heading id="keyboard-tips"><BookMarked size={22} /> Tips & Best Practices</Heading>
        <SubHeading>Getting the Most Out of Scans</SubHeading>
        <Ul>
          <li>Use <Code>.nessus</Code> XML exports for the richest data (inventory extraction, plugin output, etc.).</li>
          <li>Upload scans regularly to track remediation progress and detect regressions.</li>
          <li>Use the Scan Comparison feature to see delta changes between two scans.</li>
        </Ul>
        <SubHeading>Efficient Remediation</SubHeading>
        <Ul>
          <li>Start with <strong>Aggregated Solutions</strong> to find quick wins — single actions that fix many findings.</li>
          <li>Use <strong>Campaigns</strong> to organize remediation into trackable programs with deadlines.</li>
          <li>Attach <strong>Workflows</strong> to campaigns for automatic ticket creation and notification.</li>
          <li>Configure <strong>SLA deadlines</strong> to ensure timely remediation.</li>
        </Ul>
        <SubHeading>Automation</SubHeading>
        <Ul>
          <li>Set up <strong>auto-tag rules</strong> so new scan data is automatically categorized.</li>
          <li>Create <strong>workflows</strong> with upload triggers to automatically process new scan data.</li>
          <li>Schedule <strong>AI agents</strong> for recurring analysis (daily triage, SLA monitoring).</li>
          <li>Use <strong>ownership rules</strong> to automatically assign asset owners.</li>
        </Ul>
        <SubHeading>Reporting</SubHeading>
        <Ul>
          <li>Save frequently-used report layouts as <strong>templates</strong>.</li>
          <li>Use <strong>NLP queries</strong> for ad-hoc data exploration.</li>
          <li>Export reports to <strong>PowerPoint</strong> for executive presentations.</li>
          <li>Track <strong>remediation velocity</strong> to demonstrate security improvement over time.</li>
        </Ul>
        <SubHeading>Security Best Practices</SubHeading>
        <Ul>
          <li>Use <strong>custom roles</strong> with least-privilege permissions.</li>
          <li>Enable <strong>tag-level permissions</strong> to restrict visibility by organizational boundary.</li>
          <li>Review the <strong>audit log</strong> regularly for unusual activity.</li>
          <li>Use <strong>deny rules</strong> in custom roles to explicitly restrict sensitive operations.</li>
          <li>Set <strong>agent guardrails</strong> (max steps, read-only) to prevent unintended AI actions.</li>
        </Ul>
      </Section>
    </>
  )
}

/* ──────────────────── Main Component ──────────────────── */

export default function UserDocs() {
  const { t } = useTranslation()
  const [activeSection, setActiveSection] = useState('getting-started')
  const [search, setSearch] = useState('')
  const [tocCollapsed, setTocCollapsed] = useState({})
  const contentRef = useRef(null)

  const filteredSections = search
    ? SECTIONS.filter(s => t(s.labelKey).toLowerCase().includes(search.toLowerCase()))
    : SECTIONS

  const scrollTo = (id) => {
    setActiveSection(id)
    const el = document.getElementById(`doc-${id}`)
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  // Track active section on scroll
  useEffect(() => {
    const container = contentRef.current
    if (!container) return

    const handleScroll = () => {
      const scrollTop = container.scrollTop + 100
      let current = 'getting-started'
      for (const s of SECTIONS) {
        const el = document.getElementById(`doc-${s.id}`)
        if (el && el.offsetTop <= scrollTop) current = s.id
      }
      setActiveSection(current)
    }

    container.addEventListener('scroll', handleScroll, { passive: true })
    return () => container.removeEventListener('scroll', handleScroll)
  }, [])

  return (
    <div style={{ display: 'flex', gap: 0, height: 'calc(100vh - 36px)', margin: -18 }}>
      {/* Table of Contents sidebar */}
      <div style={{
        width: 260, flexShrink: 0, background: 'var(--bg)',
        borderRight: '1px solid var(--border)', display: 'flex', flexDirection: 'column',
        overflow: 'hidden',
      }}>
        {/* Header */}
        <div style={{
          padding: '20px 16px 12px', borderBottom: '1px solid var(--border)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
            <BookOpen size={20} color="var(--accent)" />
            <span style={{ fontSize: 15, fontWeight: 700, color: 'var(--text)' }}>{t('docs.title')}</span>
          </div>
          <div style={{
            display: 'flex', alignItems: 'center', gap: 6,
            background: 'var(--bg-muted)', border: '1px solid var(--border)',
            borderRadius: 8, padding: '6px 10px',
          }}>
            <Search size={14} color="var(--muted)" />
            <input
              type="text"
              placeholder={t('docs.search')}
              value={search}
              onChange={e => setSearch(e.target.value)}
              style={{
                flex: 1, border: 'none', background: 'transparent',
                outline: 'none', fontSize: 13, color: 'var(--text)',
              }}
            />
          </div>
        </div>

        {/* Section links */}
        <nav style={{ flex: 1, overflowY: 'auto', padding: '8px 0' }}>
          {filteredSections.map(s => {
            const Icon = s.icon
            const isActive = activeSection === s.id
            return (
              <button
                key={s.id}
                onClick={() => scrollTo(s.id)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 8,
                  width: '100%', padding: '8px 16px', border: 'none',
                  background: isActive ? 'var(--nav-active-bg)' : 'transparent',
                  color: isActive ? 'var(--nav-active-text)' : 'var(--text-secondary)',
                  cursor: 'pointer', fontSize: 13, fontWeight: isActive ? 600 : 400,
                  textAlign: 'left', borderRadius: 0,
                  borderLeft: isActive ? '3px solid var(--accent)' : '3px solid transparent',
                  transition: 'all 0.15s ease',
                }}
                onMouseEnter={e => { if (!isActive) e.currentTarget.style.background = 'var(--bg-hover)' }}
                onMouseLeave={e => { if (!isActive) e.currentTarget.style.background = 'transparent' }}
              >
                <Icon size={15} style={{ flexShrink: 0, opacity: isActive ? 1 : 0.6 }} />
                <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{t(s.labelKey)}</span>
              </button>
            )
          })}
        </nav>
      </div>

      {/* Content */}
      <div
        ref={contentRef}
        style={{
          flex: 1, overflowY: 'auto', padding: '28px 40px 60px',
          maxWidth: 900,
        }}
      >
        <DocContent />
      </div>
    </div>
  )
}
