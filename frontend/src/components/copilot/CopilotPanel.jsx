import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import {
  X, Send, Plus, Trash2, MessageSquare, Bot, Loader2,
  ChevronDown, ChevronRight, Wrench, ShieldAlert, Zap,
  Clock, Globe, Bug, Target, Briefcase, Clipboard,
  Copy, Check, RotateCcw, ThumbsUp, ThumbsDown,
  Search, Tags, LayoutDashboard, Settings,
} from 'lucide-react'
import {
  getCopilotConversations,
  createCopilotConversation,
  getCopilotConversation,
  deleteCopilotConversation,
  getCopilotSuggestedPrompts,
  getCopilotAutonomy,
  setCopilotAutonomy,
  decideAgentApproval,
  getStoredToken,
  getOrgContext,
  getBillingUsage,
} from '../../api.js'

const API_ORIGIN = import.meta.env.VITE_API_URL || ''

// ── Relative time formatting ─────────────────────────────────────
function formatRelativeTime(dateStr) {
  if (!dateStr) return ''
  const date = new Date(dateStr)
  const now = new Date()
  const diffMs = now - date
  const diffMin = Math.floor(diffMs / 60000)
  const diffHr = Math.floor(diffMs / 3600000)
  const diffDay = Math.floor(diffMs / 86400000)

  if (diffMin < 1) return 'Just now'
  if (diffMin < 60) return `${diffMin}m ago`
  if (diffHr < 24) return `${diffHr}h ago`
  if (diffDay < 7) return `${diffDay}d ago`
  return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}

function getDateGroup(dateStr) {
  if (!dateStr) return 'Older'
  const date = new Date(dateStr)
  const now = new Date()
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate())
  const yesterday = new Date(today); yesterday.setDate(today.getDate() - 1)
  const weekAgo = new Date(today); weekAgo.setDate(today.getDate() - 7)

  if (date >= today) return 'Today'
  if (date >= yesterday) return 'Yesterday'
  if (date >= weekAgo) return 'This week'
  return 'Older'
}

const DEFAULT_PANEL_WIDTH = 480
const MIN_PANEL_WIDTH = 360
const MAX_PANEL_WIDTH_RATIO = 0.9 // 90% of viewport

const ICON_MAP = {
  'shield-alert': ShieldAlert,
  'alarm': Clock,
  'zap': Zap,
  'clipboard': Clipboard,
  'globe': Globe,
  'bug': Bug,
  'target': Target,
  'briefcase': Briefcase,
  'tags': Tags,
  'bot': Bot,
  'layout-dashboard': LayoutDashboard,
}

const AUTONOMY_LABELS = {
  conservative: { label: 'Conservative', desc: 'Approve every action', color: '#16a34a' },
  standard: { label: 'Standard', desc: 'Auto-approve low-risk actions', color: '#d97706' },
  autonomous: { label: 'Autonomous', desc: 'Only approve external actions', color: '#dc2626' },
}

// ── Context-aware suggested prompts by page ────────────────────────
const CONTEXTUAL_PROMPTS = {
  '/findings': [
    { text: 'Show me the most critical unresolved findings', icon: 'shield-alert' },
    { text: 'Which findings have known exploits in the wild?', icon: 'bug' },
    { text: 'Find findings that are past their SLA deadline', icon: 'alarm' },
    { text: 'Group findings by solution and show quick wins', icon: 'zap' },
  ],
  '/findings/': [
    { text: 'Explain this finding and its impact', icon: 'shield-alert' },
    { text: 'What is the recommended remediation for this?', icon: 'target' },
    { text: 'Are there other assets affected by this same vulnerability?', icon: 'globe' },
    { text: 'Create a campaign to fix this finding across all affected assets', icon: 'zap' },
  ],
  '/assets': [
    { text: 'Which assets have the most critical vulnerabilities?', icon: 'shield-alert' },
    { text: 'Find internet-facing assets with open critical findings', icon: 'globe' },
    { text: 'Show assets that haven\'t been scanned in over 30 days', icon: 'alarm' },
    { text: 'List assets with the highest risk scores', icon: 'target' },
  ],
  '/assets/': [
    { text: 'Summarize the risk posture of this asset', icon: 'shield-alert' },
    { text: 'What are the open findings on this asset?', icon: 'bug' },
    { text: 'Has this asset been scanned recently?', icon: 'alarm' },
    { text: 'Create a remediation campaign for this asset\'s critical findings', icon: 'target' },
  ],
  '/campaigns': [
    { text: 'Show campaign progress and completion percentages', icon: 'alarm' },
    { text: 'Create a new campaign for all critical unresolved findings', icon: 'target' },
    { text: 'Which campaign owners have the most open findings?', icon: 'briefcase' },
    { text: 'Find findings not covered by any campaign', icon: 'shield-alert' },
  ],
  '/campaigns/': [
    { text: 'How is this campaign progressing?', icon: 'clipboard' },
    { text: 'Which findings in this campaign are still open?', icon: 'bug' },
    { text: 'Send a Slack update on this campaign\'s progress', icon: 'alarm' },
    { text: 'Which owners in this campaign have the most open items?', icon: 'zap' },
  ],
  '/': [
    { text: 'Give me an executive summary of our security posture', icon: 'briefcase' },
    { text: 'What changed since the last scan?', icon: 'clipboard' },
    { text: 'Find the top 10 risks I should focus on today', icon: 'shield-alert' },
    { text: 'Check for SLA breaches and escalate overdue findings', icon: 'alarm' },
  ],
  '/inventory': [
    { text: 'Which software has known CVEs?', icon: 'bug' },
    { text: 'Show missing patches with the most affected vulnerabilities', icon: 'alarm' },
    { text: 'List the most common software across all assets', icon: 'clipboard' },
    { text: 'Which assets have expiring or self-signed certificates?', icon: 'shield-alert' },
  ],
  '/threat-intel': [
    { text: 'Are any of my findings linked to active threat campaigns?', icon: 'shield-alert' },
    { text: 'Show findings that match CISA KEV entries', icon: 'bug' },
    { text: 'Map my top risks to MITRE ATT&CK techniques', icon: 'target' },
    { text: 'Which exploitable findings should I prioritize?', icon: 'zap' },
  ],
  '/aggregated-solutions': [
    { text: 'Which solution would fix the most findings?', icon: 'zap' },
    { text: 'Create a campaign from the top solution group', icon: 'target' },
    { text: 'Which solutions fix the most critical findings?', icon: 'briefcase' },
    { text: 'How many findings would be resolved by patching the top 5 solutions?', icon: 'clipboard' },
  ],
  '/tags': [
    { text: 'Show tag distribution across assets', icon: 'clipboard' },
    { text: 'Which tags have the most critical findings?', icon: 'shield-alert' },
    { text: 'Run auto-tag rules and show what was tagged', icon: 'zap' },
  ],
  '/settings': [
    { text: 'Walk me through the current configuration on this page', icon: 'clipboard' },
    { text: 'What should I configure first for a new deployment?', icon: 'zap' },
    { text: 'Are there any settings I should optimize based on my data?', icon: 'target' },
    { text: 'What integrations are configured?', icon: 'globe' },
  ],
  '/settings?tab=upload': [
    { text: 'List all scans and show finding counts by severity', icon: 'clipboard' },
    { text: 'Delete old or test scans to clean up data', icon: 'target' },
    { text: 'Compare my two most recent scans', icon: 'zap' },
    { text: 'Which scan has the most critical findings?', icon: 'shield-alert' },
  ],
  '/settings?tab=dedup': [
    { text: 'Show me the current dedup configuration', icon: 'clipboard' },
    { text: 'Explain the difference between keep_first, keep_last, and merge', icon: 'target' },
    { text: 'Change the dedup strategy for assets to merge', icon: 'zap' },
    { text: 'Run deduplication on all assets now', icon: 'shield-alert' },
  ],
  '/settings?tab=risk': [
    { text: 'Show the current risk scoring formula and weights', icon: 'clipboard' },
    { text: 'List all criticality auto-rules', icon: 'target' },
    { text: 'Create a criticality rule for production servers', icon: 'zap' },
    { text: 'Recalculate risk scores with current config', icon: 'shield-alert' },
  ],
  '/settings?tab=tags': [
    { text: 'Suggest a tagging strategy based on my assets', icon: 'zap' },
    { text: 'List all auto-tag rules and their status', icon: 'clipboard' },
    { text: 'Create an auto-tag rule for Windows servers', icon: 'target' },
    { text: 'Run all auto-tag rules now', icon: 'shield-alert' },
  ],
  '/settings?tab=sla': [
    { text: 'Show current SLA deadlines by severity', icon: 'clipboard' },
    { text: 'Change the critical SLA deadline to 7 days', icon: 'zap' },
    { text: 'How many findings are currently breaching SLA?', icon: 'shield-alert' },
    { text: 'Recalculate SLA status for all findings', icon: 'target' },
  ],
  '/settings?tab=exceptions': [
    { text: 'List all active exceptions and waivers', icon: 'clipboard' },
    { text: 'Create a false positive exception for a specific plugin', icon: 'zap' },
    { text: 'Show exceptions expiring in the next 30 days', icon: 'alarm' },
    { text: 'How many findings are covered by exceptions?', icon: 'target' },
  ],
  '/settings?tab=ownership': [
    { text: 'List all ownership rules', icon: 'clipboard' },
    { text: 'Create an ownership rule for the DevOps team', icon: 'zap' },
    { text: 'Show the current workload distribution by owner', icon: 'target' },
    { text: 'Run all ownership rules to assign owners', icon: 'shield-alert' },
  ],
  '/settings?tab=roles': [
    { text: 'List all custom roles and their permissions', icon: 'clipboard' },
    { text: 'Create a read-only analyst role', icon: 'zap' },
    { text: 'What permissions are available for custom roles?', icon: 'target' },
    { text: 'Create a role for team leads with campaign management', icon: 'shield-alert' },
  ],
  '/settings?tab=integrations': [
    { text: 'What integrations are currently configured?', icon: 'clipboard' },
    { text: 'Trigger a sync for all pull integrations', icon: 'zap' },
    { text: 'Show the last sync status for each integration', icon: 'target' },
    { text: 'Send a test Slack notification', icon: 'globe' },
  ],
  '/settings?tab=integration-builder': [
    { text: 'List all active integration pipelines', icon: 'clipboard' },
    { text: 'Set up a new integration to pull assets from our CMDB', icon: 'zap' },
    { text: 'Which integrations have failed recently?', icon: 'shield-alert' },
    { text: 'Show available connector templates', icon: 'globe' },
  ],
  '/agents': [
    { text: 'Which agents have run recently and what did they find?', icon: 'clipboard' },
    { text: 'Create a new agent to monitor for critical findings daily', icon: 'zap' },
    { text: 'Show me the output from the last agent run', icon: 'target' },
    { text: 'Which agents are scheduled and when do they next run?', icon: 'alarm' },
  ],
  '/workflows': [
    { text: 'Which workflows are active and what do they automate?', icon: 'clipboard' },
    { text: 'Show recent workflow execution history and failures', icon: 'alarm' },
    { text: 'Are any workflows failing or stuck?', icon: 'bug' },
    { text: 'What does each workflow trigger on?', icon: 'target' },
  ],
  '/workflows/': [
    { text: 'Explain what this workflow does step by step', icon: 'clipboard' },
    { text: 'Are there any errors in the recent runs of this workflow?', icon: 'bug' },
    { text: 'Suggest improvements to this workflow', icon: 'zap' },
  ],
  '/docs': [
    { text: 'How do I upload a Nessus scan file?', icon: 'clipboard' },
    { text: 'How does the priority scoring algorithm work?', icon: 'shield-alert' },
    { text: 'How do I set up Jira integration?', icon: 'globe' },
    { text: 'What scan formats are supported?', icon: 'target' },
  ],
  '/profile': [
    { text: 'Give me an executive summary of our security posture', icon: 'shield-alert' },
    { text: 'What are the top risks I should focus on?', icon: 'clipboard' },
    { text: 'Show SLA breaches across all severity levels', icon: 'target' },
  ],
}

// Get the page label for context injection
const PAGE_LABELS = {
  '/': 'Dashboard / Reports',
  '/findings': 'Findings list',
  '/assets': 'Asset Inventory',
  '/campaigns': 'Campaigns',
  '/inventory': 'Software Inventory',
  '/threat-intel': 'Threat Intelligence',
  '/aggregated-solutions': 'Aggregated Solutions',
  '/tags': 'Tag Manager',
  '/agents': 'AI Agents',
  '/workflows': 'Workflows',
  '/settings': 'Settings',
  '/profile': 'User Profile',
  '/docs': 'Documentation',
}

// Settings tab labels for richer context injection
const SETTINGS_TAB_LABELS = {
  'upload': 'Scan Management',
  'dedup': 'Deduplication Settings',
  'risk': 'Risk Scoring Configuration',
  'tags': 'Tag Manager',
  'sla': 'SLA Configuration',
  'exceptions': 'Exceptions & Waivers',
  'ownership': 'Ownership Rules',
  'roles': 'RBAC / Custom Roles',
  'users': 'User Management',
  'integrations': 'Integrations',
  'integration-builder': 'Integration Builder',
  'audit-log': 'Audit Log',
  'orgs': 'Organization Management',
}

function _getSettingsTab(path, search) {
  if (!path || !path.startsWith('/settings')) return null
  // Check search params for tab
  if (search) {
    const params = new URLSearchParams(search)
    return params.get('tab') || 'upload'
  }
  return 'upload'
}

function getContextualPrompts(path, search) {
  if (!path) return null
  // Settings with tab query param — try exact tab match first
  if (path === '/settings' && search) {
    const tab = _getSettingsTab(path, search)
    const tabKey = `/settings?tab=${tab}`
    if (CONTEXTUAL_PROMPTS[tabKey]) return CONTEXTUAL_PROMPTS[tabKey]
  }
  // Exact match (e.g., /findings, /assets, /campaigns)
  if (CONTEXTUAL_PROMPTS[path]) return CONTEXTUAL_PROMPTS[path]
  // Detail page match (e.g., /findings/123 → /findings/)
  // Sort keys longest-first so /workflows/ matches before /
  const prefixKeys = Object.keys(CONTEXTUAL_PROMPTS)
    .filter(k => k.endsWith('/') && k !== '/')
    .sort((a, b) => b.length - a.length)
  for (const key of prefixKeys) {
    if (path.startsWith(key)) return CONTEXTUAL_PROMPTS[key]
  }
  return null
}

function getPageLabel(path, search) {
  if (!path) return null
  // Settings with tab
  if (path === '/settings') {
    const tab = _getSettingsTab(path, search)
    return SETTINGS_TAB_LABELS[tab] || 'Settings'
  }
  if (PAGE_LABELS[path]) return PAGE_LABELS[path]
  // Detail pages
  if (path.startsWith('/findings/')) return 'Finding detail'
  if (path.startsWith('/assets/')) return 'Asset detail'
  if (path.startsWith('/campaigns/')) return 'Campaign detail'
  if (path.startsWith('/workflows/')) return 'Workflow builder'
  if (path.startsWith('/reports/')) return 'Report detail'
  if (path.startsWith('/threat-intel')) return 'Threat Intelligence'
  return null
}

// ── Human-readable filter labels for context injection ──────────────
const FILTER_LABELS = {
  // Findings
  severity: 'Severity', family: 'Plugin family', exploit: 'Has exploit', has_exploit: 'Has exploit',
  group: 'Group by', asset_id: 'Asset ID', sla_status: 'SLA status',
  effort_level: 'Effort level', cve: 'CVE', is_kev: 'CISA KEV',
  ransomware: 'Ransomware-linked', trending: 'Trending', has_ttps: 'Has TTPs',
  tactic: 'MITRE tactic', technique_id: 'MITRE technique', threat_group_id: 'Threat group',
  workflow_status: 'Workflow status', has_exception: 'Has exception',
  has_ticket: 'Has ticket', ticket_status: 'Ticket status',
  control_status: 'Control status', product: 'Product', cpe: 'CPE', source: 'Source',
  // Assets
  env: 'Environment', criticality: 'Criticality', minRisk: 'Min risk score',
  maxRisk: 'Max risk score', minCritical: 'Min critical findings',
  minHigh: 'Min high findings', serverRole: 'Server role', minSources: 'Min sources',
  // Shared
  search: 'Search', sort: 'Sort by', order: 'Sort order', page: 'Page',
  // Remediation
  effort: 'Effort', owner: 'Owner', min_severity: 'Min severity',
  root_cause: 'Root cause', highlight: 'Highlighted solution',
  // Inventory
  tab: 'Tab', asset_name: 'Asset name',
}

function describeActiveFilters(searchStr) {
  if (!searchStr) return null
  const params = new URLSearchParams(searchStr)
  const parts = []
  for (const [key, value] of params.entries()) {
    if (!value) continue
    if (key === 'page' && value === '1') continue
    const label = FILTER_LABELS[key] || key
    parts.push(`${label}: ${value}`)
  }
  return parts.length > 0 ? parts.join(', ') : null
}

// ── App route map for copilot link generation ───────────────────────
const APP_ROUTES_CONTEXT = `
Available app pages and their URL query parameters:
- /findings — Findings list. Filters: severity (Critical|High|Medium|Low|Info), search, family, exploit (true), sla_status (breached|at_risk|on_track), effort_level (low|medium|high), cve, is_kev (true), ransomware (true), trending (true), has_ttps (true), tactic, technique_id, threat_group_id, workflow_status, has_exception (true|false), has_ticket (true|false), ticket_status, control_status, product, cpe, source, asset_id, group (solution|family|asset), sort, order (asc|desc), page
- /findings/:id — Finding detail page
- /assets — Asset Inventory. Filters: search, env, criticality (critical|high|medium|low), minRisk, maxRisk, minCritical, minHigh, serverRole, source, minSources, sort, order, page
- /assets/:id — Asset detail page
- /campaigns — Campaigns list
- /campaigns/:id — Campaign detail
- /inventory — Software Inventory. Params: tab, asset_id, asset_name
- /threat-intel — Threat Intelligence (tabs: overview, cves, groups, campaigns, ttps)
- /aggregated-solutions — Aggregated Solutions. Filters: root_cause, sort, highlight
- /workflows — Workflows list
- /workflows/:id — Workflow builder
- /agents — AI Agents
- /tags — Tag Manager
- / — Dashboard / Reports
- /settings — Settings. Tabs (via ?tab= param): upload (Scan Management), dedup (Deduplication), risk (Risk Scoring), tags (Tag Manager), sla (SLA Config), exceptions (Exceptions/Waivers), ownership (Ownership Rules), roles (RBAC Roles), users (User Management), integrations (Integrations), integration-builder (Integration Builder), audit-log (Audit Log)

When suggesting navigation, provide markdown links like: [View critical findings](/findings?severity=Critical)
When referencing currently filtered data, acknowledge the active filters.`

// ── Markdown components (matches AgentBuilder pattern) ──────────────

const baseMdComponents = {
  h1: ({ children }) => <h1 style={{ fontSize: 16, fontWeight: 700, margin: '12px 0 6px', borderBottom: '1px solid var(--border)', paddingBottom: 4 }}>{children}</h1>,
  h2: ({ children }) => <h2 style={{ fontSize: 14, fontWeight: 700, margin: '10px 0 4px', color: 'var(--accent)' }}>{children}</h2>,
  h3: ({ children }) => <h3 style={{ fontSize: 13, fontWeight: 600, margin: '8px 0 3px' }}>{children}</h3>,
  p: ({ children }) => <p style={{ margin: '4px 0' }}>{children}</p>,
  ul: ({ children }) => <ul style={{ margin: '3px 0', paddingLeft: 18 }}>{children}</ul>,
  ol: ({ children }) => <ol style={{ margin: '3px 0', paddingLeft: 18 }}>{children}</ol>,
  li: ({ children }) => <li style={{ margin: '1px 0' }}>{children}</li>,
  strong: ({ children }) => <strong style={{ fontWeight: 700, color: 'var(--text)' }}>{children}</strong>,
  code: ({ inline, children }) => inline
    ? <code style={{ background: 'var(--bg-secondary)', padding: '1px 4px', borderRadius: 3, fontSize: 11, fontFamily: 'monospace' }}>{children}</code>
    : <pre style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 6, padding: 8, overflowX: 'auto', fontSize: 11, fontFamily: 'monospace', margin: '6px 0', color: 'var(--text)' }}><code>{children}</code></pre>,
  table: ({ children }) => <div style={{ overflowX: 'auto' }}><table style={{ borderCollapse: 'collapse', width: '100%', margin: '6px 0', fontSize: 11 }}>{children}</table></div>,
  th: ({ children }) => <th style={{ border: '1px solid var(--border)', padding: '4px 8px', background: 'var(--bg-secondary)', fontWeight: 600, textAlign: 'left' }}>{children}</th>,
  td: ({ children }) => <td style={{ border: '1px solid var(--border)', padding: '3px 8px' }}>{children}</td>,
  hr: () => <hr style={{ border: 'none', borderTop: '1px solid var(--border)', margin: '8px 0' }} />,
  blockquote: ({ children }) => <blockquote style={{ borderLeft: '3px solid var(--accent)', paddingLeft: 10, margin: '6px 0', color: 'var(--text-muted)', fontStyle: 'italic' }}>{children}</blockquote>,
}


// ── Message action bar (copy, retry, feedback) ──────────────────────

function MessageActions({ content, onRetry, messageIndex }) {
  const [copied, setCopied] = useState(false)
  const [feedback, setFeedback] = useState(null) // 'up' | 'down' | null

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(content)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {}
  }

  const actionBtnStyle = (active, color) => ({
    background: 'none', border: 'none', cursor: 'pointer', padding: 4,
    borderRadius: 4, display: 'flex', alignItems: 'center', justifyContent: 'center',
    color: active ? (color || 'var(--accent)') : 'var(--text-muted)',
    opacity: active ? 1 : 0.6,
    transition: 'opacity 0.15s, color 0.15s',
  })

  return (
    <div style={{
      display: 'flex', gap: 2, marginTop: 4, marginLeft: 34,
    }}>
      <button onClick={handleCopy} title="Copy message" style={actionBtnStyle(copied)}>
        {copied ? <Check size={13} /> : <Copy size={13} />}
      </button>
      {onRetry && (
        <button onClick={onRetry} title="Retry" style={actionBtnStyle(false)}>
          <RotateCcw size={13} />
        </button>
      )}
      <button
        onClick={() => setFeedback(f => f === 'up' ? null : 'up')}
        title="Helpful"
        style={actionBtnStyle(feedback === 'up', '#22c55e')}
      >
        <ThumbsUp size={13} />
      </button>
      <button
        onClick={() => setFeedback(f => f === 'down' ? null : 'down')}
        title="Not helpful"
        style={actionBtnStyle(feedback === 'down', '#ef4444')}
      >
        <ThumbsDown size={13} />
      </button>
    </div>
  )
}


// ── Tool call display ───────────────────────────────────────────────

function ToolCallEvent({ event }) {
  const [expanded, setExpanded] = useState(false)
  const hasResult = !!event.result
  const Icon = expanded ? ChevronDown : ChevronRight
  return (
    <div style={{
      margin: '4px 0', padding: '6px 10px', borderRadius: 6,
      background: 'var(--bg-secondary)', border: '1px solid var(--border)',
      fontSize: 11,
    }}>
      <div
        onClick={() => setExpanded(!expanded)}
        style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', color: 'var(--text-muted)' }}
      >
        {hasResult ? (
          <Wrench size={12} style={{ color: '#22c55e' }} />
        ) : (
          <Loader2 size={12} style={{ animation: 'spin 1s linear infinite', color: 'var(--accent)' }} />
        )}
        <span style={{ fontFamily: 'monospace', fontWeight: 600 }}>{event.name}</span>
        {!hasResult && <span style={{ color: 'var(--accent)', fontSize: 10 }}>running...</span>}
        <Icon size={12} style={{ marginLeft: 'auto' }} />
      </div>
      {expanded && event.input && (
        <pre style={{
          marginTop: 6, padding: 6, borderRadius: 4,
          background: 'var(--bg-secondary)', color: 'var(--text-muted, #94a3b8)',
          fontSize: 10, fontFamily: 'monospace', overflowX: 'auto',
          maxHeight: 120,
        }}>
          {JSON.stringify(event.input, null, 2)}
        </pre>
      )}
      {expanded && event.result && (
        <pre style={{
          marginTop: 4, padding: 6, borderRadius: 4,
          background: 'var(--bg-secondary)', color: 'var(--success, #6ee7b7)',
          fontSize: 10, fontFamily: 'monospace', overflowX: 'auto',
          maxHeight: 150,
        }}>
          {typeof event.result === 'string' ? event.result.slice(0, 1500) : JSON.stringify(event.result, null, 2).slice(0, 1500)}
        </pre>
      )}
    </div>
  )
}


// ── Approval inline ─────────────────────────────────────────────────

function ApprovalEvent({ event, onDecide }) {
  const [deciding, setDeciding] = useState(false)
  const [decided, setDecided] = useState(null)

  const handleDecide = async (decision) => {
    setDeciding(true)
    try {
      await decideAgentApproval(event.approval_id, decision)
      setDecided(decision)
    } catch (e) {
      console.error('Approval failed:', e)
    } finally {
      setDeciding(false)
    }
  }

  return (
    <div style={{
      margin: '6px 0', padding: '10px 12px', borderRadius: 8,
      background: decided ? 'var(--bg-secondary)' : 'rgba(251, 191, 36, 0.1)',
      border: `1px solid ${decided ? 'var(--border)' : 'rgba(251, 191, 36, 0.3)'}`,
      fontSize: 12,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
        <ShieldAlert size={14} style={{ color: '#f59e0b' }} />
        <span style={{ fontWeight: 600 }}>Approval required: </span>
        <code style={{ fontFamily: 'monospace', fontSize: 11, background: 'var(--bg-secondary)', padding: '1px 4px', borderRadius: 3 }}>{event.tool_name}</code>
      </div>
      {decided ? (
        <div style={{ color: decided === 'approved' ? '#22c55e' : '#ef4444', fontWeight: 500, fontSize: 11 }}>
          {decided === 'approved' ? 'Approved' : 'Rejected'}
        </div>
      ) : (
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            onClick={() => handleDecide('approved')}
            disabled={deciding}
            style={{
              padding: '4px 14px', borderRadius: 5, border: 'none', cursor: 'pointer',
              background: '#22c55e', color: '#fff', fontSize: 11, fontWeight: 600,
              opacity: deciding ? 0.6 : 1,
            }}
          >
            Approve
          </button>
          <button
            onClick={() => handleDecide('rejected')}
            disabled={deciding}
            style={{
              padding: '4px 14px', borderRadius: 5, border: '1px solid var(--border)', cursor: 'pointer',
              background: 'var(--bg)', color: 'var(--text)', fontSize: 11, fontWeight: 500,
              opacity: deciding ? 0.6 : 1,
            }}
          >
            Reject
          </button>
        </div>
      )}
    </div>
  )
}


// ── Thinking indicator ──────────────────────────────────────────────

function ThinkingIndicator({ step }) {
  const labels = [
    'Analyzing your request...',
    'Querying data...',
    'Processing results...',
    'Analyzing findings...',
    'Preparing response...',
  ]
  const label = step < labels.length ? labels[step] : `Working (step ${step + 1})...`
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px',
      color: 'var(--text-muted)', fontSize: 12, marginTop: 4,
    }}>
      <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} />
      <span>{label}</span>
      <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
    </div>
  )
}


// ── Token Usage Bar ─────────────────────────────────────────────────

function TokenUsageBar({ usage }) {
  if (!usage || usage.tier === 'free') return null
  const pct = usage.percentage || 0
  const used = usage.used || 0
  const limit = usage.limit || 0
  const barColor = usage.exceeded ? '#ef4444' : usage.warning ? '#f59e0b' : 'var(--accent)'
  const formatTokens = (n) => n >= 1_000_000 ? `${(n / 1_000_000).toFixed(1)}M` : n >= 1_000 ? `${(n / 1_000).toFixed(0)}K` : n

  return (
    <div style={{ padding: '6px 16px', fontSize: 11, color: 'var(--text-muted)' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
        <span>AI tokens</span>
        <span>{formatTokens(used)} / {formatTokens(limit)}</span>
      </div>
      <div style={{ height: 4, borderRadius: 2, background: 'var(--border)', overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${Math.min(pct, 100)}%`, background: barColor, borderRadius: 2, transition: 'width 0.3s ease' }} />
      </div>
      {usage.exceeded && (
        <div style={{ color: '#ef4444', fontSize: 10, marginTop: 2 }}>Monthly quota exceeded</div>
      )}
    </div>
  )
}


// ── Main Panel ──────────────────────────────────────────────────────

export default function CopilotPanel({ open, onClose, currentPath, currentSearch }) {
  const { t } = useTranslation()
  const [conversations, setConversations] = useState([])
  const [activeConv, setActiveConv] = useState(null)
  const [messages, setMessages] = useState([])
  const [input, setInput] = useState('')
  const [streaming, setStreaming] = useState(false)
  const [streamEvents, setStreamEvents] = useState([])
  const [streamText, setStreamText] = useState('')
  const [suggestedPrompts, setSuggestedPrompts] = useState([])
  const [showHistory, setShowHistory] = useState(false)
  const [historySearch, setHistorySearch] = useState('')
  const [panelW, setPanelW] = useState(DEFAULT_PANEL_WIDTH)
  const [dragging, setDragging] = useState(false)
  const [thinkingStep, setThinkingStep] = useState(-1)
  const [tokenUsage, setTokenUsage] = useState(null)
  const [recommendations, setRecommendations] = useState([])
  const [autonomy, setAutonomy] = useState(null)
  const [showAutonomy, setShowAutonomy] = useState(false)
  const messagesEndRef = useRef(null)
  const textareaRef = useRef(null)
  const abortRef = useRef(null)
  const navigate = useNavigate()

  // Markdown components with SPA-aware link handling for internal routes
  const mdComponents = useMemo(() => ({
    ...baseMdComponents,
    a: ({ href, children }) => {
      const isInternal = href && href.startsWith('/')
      if (isInternal) {
        // Normalize copilot tool param names to frontend URL param names
        const normalizedHref = href.replace(/([?&])has_exploit(=)/g, '$1exploit$2')
        return (
          <a
            href={normalizedHref}
            onClick={(e) => {
              e.preventDefault()
              navigate(normalizedHref)
            }}
            style={{ color: 'var(--accent)', textDecoration: 'underline', cursor: 'pointer' }}
          >
            {children}
          </a>
        )
      }
      return <a href={href} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent)', textDecoration: 'underline' }}>{children}</a>
    },
  }), [navigate])

  // Load conversations, suggested prompts, token usage, and autonomy on open
  useEffect(() => {
    if (open) {
      getCopilotConversations().then(setConversations).catch(() => {})
      getCopilotSuggestedPrompts().then(setSuggestedPrompts).catch(() => {})
      getBillingUsage().then(setTokenUsage).catch(() => {})
      getCopilotAutonomy().then(setAutonomy).catch(() => {})
    }
  }, [open])

  // Auto-scroll to bottom
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, streamText, streamEvents])

  // Focus textarea when panel opens
  useEffect(() => {
    if (open && textareaRef.current) {
      setTimeout(() => textareaRef.current?.focus(), 300)
    }
  }, [open, activeConv])

  const startNewConversation = useCallback(async () => {
    try {
      const conv = await createCopilotConversation()
      setActiveConv(conv)
      setMessages([])
      setStreamEvents([])
      setStreamText('')
      setRecommendations([])
      setShowHistory(false)
      setConversations(prev => [conv, ...prev])
    } catch (e) {
      console.error('Failed to create conversation:', e)
    }
  }, [])

  const loadConversation = useCallback(async (conv) => {
    try {
      const full = await getCopilotConversation(conv.id)
      setActiveConv(full)
      setMessages(full.messages || [])
      setStreamEvents([])
      setStreamText('')
      setRecommendations([])
      setShowHistory(false)
    } catch (e) {
      console.error('Failed to load conversation:', e)
    }
  }, [])

  const deleteConv = useCallback(async (convId, e) => {
    e.stopPropagation()
    try {
      await deleteCopilotConversation(convId)
      setConversations(prev => prev.filter(c => c.id !== convId))
      if (activeConv?.id === convId) {
        setActiveConv(null)
        setMessages([])
      }
    } catch (err) {
      console.error('Failed to delete conversation:', err)
    }
  }, [activeConv])

  const sendMessage = useCallback(async (text) => {
    const msg = (text || input).trim()
    if (!msg || streaming) return
    setShowAutonomy(false)

    // Auto-create conversation if none active
    let conv = activeConv
    if (!conv) {
      try {
        conv = await createCopilotConversation()
        setActiveConv(conv)
        setConversations(prev => [conv, ...prev])
      } catch (e) {
        console.error('Failed to create conversation:', e)
        return
      }
    }

    setInput('')
    setStreaming(true)
    setStreamText('')
    setStreamEvents([])
    setThinkingStep(0)
    setRecommendations([])

    // Add user message to local state (show original text in chat bubble)
    const userMsg = { role: 'user', content: msg, timestamp: new Date().toISOString() }
    setMessages(prev => [...prev, userMsg])

    // Build context-enriched message for the backend
    const pageLabel = getPageLabel(currentPath, currentSearch)
    const idMatch = currentPath?.match(/\/.+\/(\d+)/)
    const entityId = idMatch ? idMatch[1] : null
    const settingsTab = _getSettingsTab(currentPath, currentSearch)
    let contextPrefix = ''
    if (pageLabel) {
      contextPrefix = `[User is currently viewing: ${pageLabel}${entityId ? ` (ID: ${entityId})` : ''}]`
      // Add active filter context from URL search params
      const filterDesc = describeActiveFilters(currentSearch)
      if (filterDesc) {
        contextPrefix += `\n[Active filters: ${filterDesc}]`
        contextPrefix += `\n[Current URL: ${currentPath}${currentSearch}]`
      }
      // Add tool hints for settings tabs
      if (currentPath === '/settings' && settingsTab) {
        const tabHints = {
          'upload': '[Use list_scans, get_scan_summary, delete_scan, rename_scan to help manage scans on this page]',
          'dedup': '[Use get_dedup_config, update_dedup_config, run_dedup to help configure deduplication on this page]',
          'risk': '[Use get_risk_config, update_risk_config, manage_criticality_rules, recalculate_risk_scores to help configure risk scoring on this page]',
          'tags': '[Use create_tag, manage_tag, create_auto_tag_rule, manage_auto_tag_rule, run_auto_tag_rules, suggest_tagging_schema to help manage tags on this page]',
          'sla': '[Use get_sla_config, update_sla_config, recalculate_sla, get_sla_status to help configure SLA deadlines on this page]',
          'exceptions': '[Use list_exceptions, manage_exception, create_exception to help manage exceptions/waivers on this page]',
          'ownership': '[Use list_ownership_rules, manage_ownership_rule, run_ownership_rules, get_owner_workload to help configure ownership on this page]',
          'roles': '[Use list_custom_roles, manage_custom_role to help manage RBAC roles and permissions on this page]',
          'integrations': '[Use list_integrations, call_integration_fetch, call_integration_push to help manage integrations on this page]',
          'integration-builder': '[Use list_integration_builder_connectors, get_integration_builder_connector_detail, get_integration_builder_targets, list_integration_credentials, create_integration_credential, create_integration, update_integration, get_integration_detail, suggest_field_mapping, manage_integration, get_integration_runs to help build and manage integration pipelines on this page]',
        }
        if (tabHints[settingsTab]) contextPrefix += `\n${tabHints[settingsTab]}`
      }
      // Add tool hints for detail pages so the agent knows which tool to call
      else if (entityId) {
        if (currentPath.startsWith('/workflows/')) contextPrefix += `\n[Use get_workflow_detail with workflow_id=${entityId} to answer questions about this workflow]`
        else if (currentPath.startsWith('/findings/')) contextPrefix += `\n[Use get_finding_detail with finding_id=${entityId} to answer questions about this finding]`
        else if (currentPath.startsWith('/assets/')) contextPrefix += `\n[Use get_asset_profile with asset_id=${entityId} to answer questions about this asset]`
        else if (currentPath.startsWith('/campaigns/')) contextPrefix += `\n[Use query_findings with campaign context to answer questions about this campaign]`
        else if (currentPath.startsWith('/reports/')) contextPrefix += `\n[This is a saved report/dashboard. There is no report lookup tool — use query_findings, get_top_risky_assets, get_exploit_findings, get_quick_wins, get_sla_status, and other analysis tools to answer questions about the organization's security posture. Do NOT attempt to fetch a report by ID.]`
      }
      contextPrefix += `\n${APP_ROUTES_CONTEXT}`
    }

    try {
      const token = getStoredToken()
      const orgContext = getOrgContext()
      const headers = { 'Content-Type': 'application/json' }
      if (token) headers['Authorization'] = `Bearer ${token}`
      if (orgContext) headers['X-Org-Context'] = orgContext

      const abortController = new AbortController()
      abortRef.current = abortController

      const resp = await fetch(`${API_ORIGIN}/api/copilot/conversations/${conv.id}/message`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ message: msg, context: contextPrefix || undefined }),
        signal: abortController.signal,
      })

      if (!resp.ok || !resp.body) {
        let errMsg = `Request failed: ${resp.status}`
        try {
          const errBody = await resp.json()
          errMsg = errBody.detail || errBody.message || errMsg
        } catch {}
        throw new Error(errMsg)
      }

      const reader = resp.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''
      let textAccum = ''
      const events = []

      while (true) {
        const { done, value } = await reader.read()
        if (done) break

        buffer += decoder.decode(value, { stream: true })
        const lines = buffer.split('\n')
        buffer = lines.pop()

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue
          const payload = line.slice(6).trim()
          if (payload === '[DONE]') continue

          try {
            const event = JSON.parse(payload)
            events.push(event)
            setStreamEvents([...events])

            if (event.type === 'text') {
              textAccum += event.text
              setStreamText(textAccum)
              setThinkingStep(-1)
            } else if (event.type === 'thinking') {
              setThinkingStep(event.step)
            } else if (event.type === 'tool_call') {
              // Show the tool call with spinner, hide thinking
              setThinkingStep(-1)
            } else if (event.type === 'tool_result') {
              // Tool finished — update events so spinner becomes checkmark
              setStreamEvents([...events])
            } else if (event.type === 'done') {
              setStreamText('')
              setMessages(prev => [...prev, {
                role: 'assistant',
                content: event.output || textAccum,
                timestamp: new Date().toISOString(),
              }])
            } else if (event.type === 'recommendations') {
              setRecommendations(event.recommendations || [])
            } else if (event.type === 'error') {
              setMessages(prev => [...prev, {
                role: 'error',
                content: event.error,
                timestamp: new Date().toISOString(),
              }])
            }
          } catch {}
        }
      }

      // If stream ended without done event, use accumulated text
      if (textAccum && !events.some(e => e.type === 'done')) {
        setStreamText('')
        setMessages(prev => [...prev, {
          role: 'assistant',
          content: textAccum,
          timestamp: new Date().toISOString(),
        }])
      }

      // Update conversation title in sidebar
      if (conv.title === 'New conversation') {
        setConversations(prev => prev.map(c =>
          c.id === conv.id ? { ...c, title: msg.slice(0, 80) } : c
        ))
      }
    } catch (e) {
      if (e.name !== 'AbortError') {
        setMessages(prev => [...prev, {
          role: 'error',
          content: e.message,
          timestamp: new Date().toISOString(),
        }])
      }
    } finally {
      setStreaming(false)
      setThinkingStep(-1)
      abortRef.current = null
      getBillingUsage().then(setTokenUsage).catch(() => {})
    }
  }, [input, streaming, activeConv])

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      sendMessage()
    }
  }

  const handleStop = () => {
    abortRef.current?.abort()
    setStreaming(false)
    setThinkingStep(-1)
  }

  // Drag-to-resize logic
  const dragRef = useRef(null)

  const handleDragStart = useCallback((e) => {
    e.preventDefault()
    setDragging(true)
    const startX = e.clientX
    const startW = panelW

    const onMove = (ev) => {
      const delta = startX - ev.clientX
      const maxW = window.innerWidth * MAX_PANEL_WIDTH_RATIO
      setPanelW(Math.max(MIN_PANEL_WIDTH, Math.min(maxW, startW + delta)))
    }
    const onUp = () => {
      setDragging(false)
      document.removeEventListener('mousemove', onMove)
      document.removeEventListener('mouseup', onUp)
    }
    document.addEventListener('mousemove', onMove)
    document.addEventListener('mouseup', onUp)
  }, [panelW])

  // Double-click to reset width
  const handleDragDoubleClick = useCallback(() => {
    setPanelW(DEFAULT_PANEL_WIDTH)
  }, [])

  const clampedWidth = Math.min(panelW, window.innerWidth - 20)

  if (!open) return null

  return (
    <>
      {/* Backdrop */}
      <div
        onClick={onClose}
        style={{
          position: 'fixed', inset: 0, zIndex: 199,
          background: 'rgba(0,0,0,0.3)',
          opacity: open ? 1 : 0,
          transition: 'opacity 0.2s ease',
        }}
      />

      {/* Panel */}
      <div style={{
        position: 'fixed', top: 0, right: 0, bottom: 0,
        width: clampedWidth,
        zIndex: 200,
        background: 'var(--bg)',
        borderLeft: '1px solid var(--border)',
        display: 'flex', flexDirection: 'column',
        boxShadow: '-4px 0 24px rgba(0,0,0,0.15)',
        transform: open ? 'translateX(0)' : 'translateX(100%)',
        transition: dragging ? 'none' : 'transform 0.25s ease, width 0.2s ease',
      }}>
        {/* Drag handle — left edge */}
        <div
          ref={dragRef}
          onMouseDown={handleDragStart}
          onDoubleClick={handleDragDoubleClick}
          title="Drag to resize, double-click to reset"
          style={{
            position: 'absolute', top: 0, left: -3, bottom: 0, width: 6,
            cursor: 'col-resize', zIndex: 210,
            background: dragging ? 'var(--accent)' : 'transparent',
            transition: 'background 0.15s',
          }}
          onMouseEnter={e => { if (!dragging) e.currentTarget.style.background = 'var(--accent)'; e.currentTarget.style.opacity = '0.4' }}
          onMouseLeave={e => { if (!dragging) { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.opacity = '1' } }}
        />

        {/* Header */}
        <div style={{
          padding: '12px 16px', borderBottom: '1px solid var(--border)',
          display: 'flex', alignItems: 'center', gap: 10,
          background: 'var(--bg-secondary)',
        }}>
          <Bot size={20} style={{ color: 'var(--accent)' }} />
          <div style={{ flex: 1, display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontWeight: 700, fontSize: 15 }}>Neo AI</span>
            <span style={{
              fontSize: 9, color: 'var(--accent)', fontWeight: 700, letterSpacing: 0.5,
              background: 'rgba(var(--accent-rgb, 99,102,241), 0.1)',
              padding: '2px 6px', borderRadius: 4, textTransform: 'uppercase',
            }}>Agent</span>
          </div>
          <button
            onClick={() => { setShowHistory(!showHistory); setHistorySearch('') }}
            title="Conversation history"
            style={{
              background: showHistory ? 'var(--bg)' : 'none',
              border: showHistory ? '1px solid var(--border)' : 'none',
              cursor: 'pointer',
              color: showHistory ? 'var(--accent)' : 'var(--text-muted)',
              padding: 4, borderRadius: 4,
            }}
          >
            <MessageSquare size={16} />
          </button>
          <div style={{ position: 'relative' }}>
            <button
              onClick={() => setShowAutonomy(!showAutonomy)}
              title="Autonomy level"
              style={{
                background: showAutonomy ? 'var(--bg)' : 'none',
                border: showAutonomy ? '1px solid var(--border)' : 'none',
                cursor: 'pointer',
                color: showAutonomy ? 'var(--accent)' : 'var(--text-muted)',
                padding: 4, borderRadius: 4, display: 'flex', alignItems: 'center', gap: 4,
              }}
            >
              <Settings size={16} />
              {autonomy && (
                <span style={{
                  width: 6, height: 6, borderRadius: '50%',
                  background: AUTONOMY_LABELS[autonomy.level]?.color || '#6b7280',
                  flexShrink: 0,
                }} />
              )}
            </button>
            {showAutonomy && (
              <div style={{
                position: 'absolute', top: '100%', right: 0, marginTop: 4,
                background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                borderRadius: 8, padding: 8, width: 240, zIndex: 100,
                boxShadow: '0 8px 24px rgba(0,0,0,0.15)',
              }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', marginBottom: 6, padding: '0 4px' }}>
                  AUTONOMY LEVEL
                </div>
                {Object.entries(AUTONOMY_LABELS).map(([key, { label, desc, color }]) => (
                  <button
                    key={key}
                    onClick={() => {
                      setCopilotAutonomy(key).then(r => {
                        setAutonomy({ ...autonomy, level: key })
                        setShowAutonomy(false)
                      }).catch(err => {
                        console.error('Failed to set autonomy:', err)
                        alert(err?.detail || err?.message || 'Failed to update autonomy level')
                      })
                    }}
                    style={{
                      display: 'flex', alignItems: 'flex-start', gap: 8,
                      width: '100%', padding: '8px', borderRadius: 6,
                      border: autonomy?.level === key ? `1px solid ${color}` : '1px solid transparent',
                      background: autonomy?.level === key ? `${color}10` : 'none',
                      cursor: 'pointer', textAlign: 'left',
                    }}
                    onMouseEnter={e => { if (autonomy?.level !== key) e.currentTarget.style.background = 'var(--bg)' }}
                    onMouseLeave={e => { if (autonomy?.level !== key) e.currentTarget.style.background = 'none' }}
                  >
                    <span style={{
                      width: 8, height: 8, borderRadius: '50%', background: color,
                      flexShrink: 0, marginTop: 3,
                    }} />
                    <div>
                      <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text)' }}>{label}</div>
                      <div style={{ fontSize: 10, color: 'var(--text-muted)', lineHeight: 1.3 }}>{desc}</div>
                    </div>
                    {autonomy?.level === key && <Check size={14} style={{ color, flexShrink: 0, marginTop: 1, marginLeft: 'auto' }} />}
                  </button>
                ))}
              </div>
            )}
          </div>
          <button
            onClick={startNewConversation}
            title="New conversation"
            style={{
              background: 'none', border: 'none', cursor: 'pointer',
              color: 'var(--text-muted)', padding: 4, borderRadius: 4,
            }}
          >
            <Plus size={16} />
          </button>
          <button
            onClick={onClose}
            style={{
              background: 'none', border: 'none', cursor: 'pointer',
              color: 'var(--text-muted)', padding: 4, borderRadius: 4,
            }}
          >
            <X size={16} />
          </button>
        </div>

        {/* Conversation history panel */}
        {showHistory && (() => {
          const filtered = conversations.filter(c =>
            !historySearch || (c.title || '').toLowerCase().includes(historySearch.toLowerCase())
          )
          const grouped = filtered.reduce((acc, conv) => {
            const group = getDateGroup(conv.updated_at || conv.created_at)
            if (!acc[group]) acc[group] = []
            acc[group].push(conv)
            return acc
          }, {})
          const groupOrder = ['Today', 'Yesterday', 'This week', 'Older']

          return (
            <div style={{
              borderBottom: '1px solid var(--border)',
              maxHeight: 350, overflowY: 'auto',
              background: 'var(--bg)',
            }}>
              {/* Search bar */}
              <div style={{ padding: '8px 12px', borderBottom: '1px solid var(--border)', background: 'var(--bg-secondary)' }}>
                <div style={{
                  display: 'flex', alignItems: 'center', gap: 6,
                  background: 'var(--bg)', border: '1px solid var(--border)',
                  borderRadius: 6, padding: '4px 8px',
                }}>
                  <Search size={12} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
                  <input
                    value={historySearch}
                    onChange={e => setHistorySearch(e.target.value)}
                    placeholder="Search conversations..."
                    style={{
                      flex: 1, border: 'none', outline: 'none', background: 'transparent',
                      color: 'var(--text)', fontSize: 11, fontFamily: 'inherit',
                    }}
                  />
                  {historySearch && (
                    <button
                      onClick={() => setHistorySearch('')}
                      style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 0, display: 'flex' }}
                    >
                      <X size={10} />
                    </button>
                  )}
                </div>
              </div>

              {filtered.length === 0 ? (
                <div style={{ padding: '20px 16px', color: 'var(--text-muted)', fontSize: 12, textAlign: 'center' }}>
                  {historySearch ? 'No matching conversations' : 'No conversations yet'}
                </div>
              ) : groupOrder.filter(g => grouped[g]).map(group => (
                <div key={group}>
                  <div style={{
                    padding: '6px 14px', fontSize: 10, fontWeight: 600,
                    color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5,
                    background: 'var(--bg-secondary)',
                    borderBottom: '1px solid var(--border)',
                  }}>
                    {group}
                  </div>
                  {grouped[group].map(conv => (
                    <div
                      key={conv.id}
                      onClick={() => loadConversation(conv)}
                      style={{
                        padding: '10px 14px', cursor: 'pointer', fontSize: 12,
                        display: 'flex', alignItems: 'center', gap: 10,
                        background: activeConv?.id === conv.id ? 'rgba(var(--accent-rgb, 99,102,241), 0.08)' : 'transparent',
                        borderBottom: '1px solid var(--border)',
                        borderLeft: activeConv?.id === conv.id ? '3px solid var(--accent)' : '3px solid transparent',
                        transition: 'background 0.12s ease',
                      }}
                      onMouseEnter={e => { if (activeConv?.id !== conv.id) e.currentTarget.style.background = 'var(--bg-secondary)' }}
                      onMouseLeave={e => { if (activeConv?.id !== conv.id) e.currentTarget.style.background = 'transparent' }}
                    >
                      <MessageSquare size={14} style={{
                        color: activeConv?.id === conv.id ? 'var(--accent)' : 'var(--text-muted)',
                        flexShrink: 0,
                      }} />
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{
                          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                          fontWeight: activeConv?.id === conv.id ? 600 : 400,
                          color: activeConv?.id === conv.id ? 'var(--text)' : 'var(--text)',
                        }}>
                          {conv.title || 'New conversation'}
                        </div>
                        <div style={{
                          fontSize: 10, color: 'var(--text-muted)', marginTop: 2,
                          display: 'flex', alignItems: 'center', gap: 6,
                        }}>
                          <span>{conv.message_count || 0} messages</span>
                          <span style={{ opacity: 0.4 }}>·</span>
                          <span>{formatRelativeTime(conv.updated_at || conv.created_at)}</span>
                        </div>
                      </div>
                      <button
                        onClick={(e) => deleteConv(conv.id, e)}
                        style={{
                          background: 'none', border: 'none', cursor: 'pointer',
                          color: 'var(--text-muted)', padding: 4, borderRadius: 4,
                          opacity: 0.4, transition: 'opacity 0.12s',
                          display: 'flex', alignItems: 'center',
                        }}
                        onMouseEnter={e => e.currentTarget.style.opacity = '1'}
                        onMouseLeave={e => e.currentTarget.style.opacity = '0.4'}
                        title="Delete conversation"
                      >
                        <Trash2 size={13} />
                      </button>
                    </div>
                  ))}
                </div>
              ))}
            </div>
          )
        })()}

        {/* Messages area */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '12px 16px' }}>
          {/* Empty state with suggested prompts */}
          {messages.length === 0 && !streaming && (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '40px 10px', gap: 20 }}>
              <div style={{
                width: 56, height: 56, borderRadius: '50%',
                background: 'var(--bg-secondary)', border: '2px solid var(--border)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                <Bot size={28} style={{ color: 'var(--accent)' }} />
              </div>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontWeight: 700, fontSize: 16, marginBottom: 6 }}>Neo AI</div>
                <div style={{ color: 'var(--text-muted)', fontSize: 12, lineHeight: 1.5, maxWidth: 320 }}>
                  {getPageLabel(currentPath, currentSearch)
                    ? <>You're on <strong style={{ color: 'var(--text)' }}>{getPageLabel(currentPath, currentSearch)}</strong>
                      {describeActiveFilters(currentSearch) && <> with filters: <em style={{ color: 'var(--text)' }}>{describeActiveFilters(currentSearch)}</em></>}
                      . Ask me anything about what you see, or try a suggestion below.</>
                    : 'Your autonomous security agent. It queries your scan data, analyzes risk, creates campaigns, opens tickets, and notifies your team — all in one conversation.'
                  }
                </div>
              </div>

              {/* Capability badges */}
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', justifyContent: 'center', maxWidth: 360 }}>
                {['Analyze attack surface', 'Build reports', 'Orchestrate actions', 'Open tickets', 'Deploy agents'].map(cap => (
                  <span key={cap} style={{
                    padding: '3px 10px', borderRadius: 20, fontSize: 10, fontWeight: 600,
                    background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                    color: 'var(--text-muted)', letterSpacing: 0.3,
                  }}>
                    {cap}
                  </span>
                ))}
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, justifyContent: 'center', maxWidth: 380 }}>
                {(getContextualPrompts(currentPath, currentSearch) || suggestedPrompts).map((p, i) => {
                  const SIcon = ICON_MAP[p.icon] || ShieldAlert
                  return (
                    <button
                      key={i}
                      onClick={() => sendMessage(p.text)}
                      style={{
                        padding: '8px 12px', borderRadius: 8, fontSize: 11,
                        border: '1px solid var(--border)', background: 'var(--bg-secondary)',
                        color: 'var(--text)', cursor: 'pointer',
                        display: 'flex', alignItems: 'center', gap: 6,
                        transition: 'border-color 0.15s ease, background 0.15s ease',
                        textAlign: 'left', lineHeight: 1.3,
                      }}
                      onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent)'; e.currentTarget.style.background = 'var(--bg)' }}
                      onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.background = 'var(--bg-secondary)' }}
                    >
                      <SIcon size={13} style={{ color: 'var(--accent)', flexShrink: 0 }} />
                      {p.text}
                    </button>
                  )
                })}
              </div>
            </div>
          )}

          {/* Rendered messages */}
          {messages.map((msg, i) => (
            <div key={i} style={{ marginBottom: 12 }}>
              {msg.role === 'user' ? (
                <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                  <div style={{
                    maxWidth: '85%', padding: '8px 14px', borderRadius: '14px 14px 4px 14px',
                    background: 'var(--accent)', color: '#fff', fontSize: 13, lineHeight: 1.5,
                    whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                  }}>
                    {msg.content}
                  </div>
                </div>
              ) : msg.role === 'error' ? (
                <div style={{
                  padding: '8px 12px', borderRadius: 8,
                  background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.2)',
                  color: '#ef4444', fontSize: 12,
                }}>
                  Error: {msg.content}
                </div>
              ) : (
                <>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start' }}>
                    <div style={{
                      width: 26, height: 26, borderRadius: '50%', flexShrink: 0,
                      background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      marginTop: 2,
                    }}>
                      <Bot size={14} style={{ color: 'var(--accent)' }} />
                    </div>
                    <div style={{
                      flex: 1, minWidth: 0, fontSize: 13, lineHeight: 1.6,
                      color: 'var(--text)',
                    }}>
                      <ReactMarkdown remarkPlugins={[remarkGfm]} components={mdComponents}>{msg.content}</ReactMarkdown>
                    </div>
                  </div>
                  {!streaming && (
                    <MessageActions
                      content={msg.content}
                      messageIndex={i}
                      onRetry={(() => {
                        // Find the user message that preceded this assistant message
                        for (let j = i - 1; j >= 0; j--) {
                          if (messages[j].role === 'user') return () => sendMessage(messages[j].content)
                        }
                        return null
                      })()}
                    />
                  )}
                </>
              )}
            </div>
          ))}

          {/* Live streaming activity — interleaved tool calls, results, text, approvals */}
          {streaming && (
            <div style={{ marginBottom: 12 }}>
              {/* Tool calls and results in order */}
              {streamEvents.filter(e =>
                e.type === 'tool_call' || e.type === 'tool_result' || e.type === 'approval_required'
              ).map((event, i) => (
                event.type === 'approval_required' ? (
                  <ApprovalEvent key={`evt-${i}`} event={event} />
                ) : event.type === 'tool_call' ? (
                  <ToolCallEvent
                    key={`evt-${i}`}
                    event={{
                      ...event,
                      // Attach result if we have one for this tool
                      result: streamEvents.find(
                        e => e.type === 'tool_result' && e.name === event.name && e.step === event.step
                      )?.result,
                    }}
                  />
                ) : null
              ))}

              {/* Streaming text output */}
              {streamText && (
                <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start', marginTop: 8 }}>
                  <div style={{
                    width: 26, height: 26, borderRadius: '50%', flexShrink: 0,
                    background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    marginTop: 2,
                  }}>
                    <Bot size={14} style={{ color: 'var(--accent)' }} />
                  </div>
                  <div style={{ flex: 1, minWidth: 0, fontSize: 13, lineHeight: 1.6 }}>
                    <ReactMarkdown remarkPlugins={[remarkGfm]} components={mdComponents}>{streamText}</ReactMarkdown>
                  </div>
                </div>
              )}

              {/* Thinking indicator — shown when waiting for LLM or between tool calls */}
              {thinkingStep >= 0 && (
                <ThinkingIndicator step={thinkingStep} />
              )}
            </div>
          )}

          {/* Context-aware follow-up recommendations */}
          {!streaming && recommendations.length > 0 && messages.length > 0 && (
            <div style={{
              display: 'flex', flexDirection: 'column', gap: 6,
              padding: '8px 0', marginLeft: 34,
            }}>
              <span style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600, letterSpacing: 0.3, textTransform: 'uppercase' }}>
                Suggested follow-ups
              </span>
              {recommendations.map((rec, i) => {
                const SIcon = ICON_MAP[rec.icon] || Zap
                return (
                  <button
                    key={i}
                    onClick={() => sendMessage(rec.text)}
                    style={{
                      padding: '6px 10px', borderRadius: 8, fontSize: 11,
                      border: '1px solid var(--border)', background: 'var(--bg-secondary)',
                      color: 'var(--text)', cursor: 'pointer',
                      display: 'flex', alignItems: 'center', gap: 6,
                      transition: 'border-color 0.15s ease, background 0.15s ease',
                      textAlign: 'left', lineHeight: 1.3,
                    }}
                    onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent)'; e.currentTarget.style.background = 'var(--bg)' }}
                    onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.background = 'var(--bg-secondary)' }}
                  >
                    <SIcon size={12} style={{ color: 'var(--accent)', flexShrink: 0 }} />
                    {rec.text}
                  </button>
                )
              })}
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Token usage + Input area */}
        <div style={{
          borderTop: '1px solid var(--border)',
          background: 'var(--bg-secondary)',
        }}>
          <TokenUsageBar usage={tokenUsage} />
        </div>
        <div style={{
          padding: '12px 16px',
          background: 'var(--bg-secondary)',
        }}>
          <div style={{
            display: 'flex', gap: 8, alignItems: 'flex-end',
            background: 'var(--bg)', border: '1px solid var(--border)',
            borderRadius: 12, padding: '6px 6px 6px 14px',
          }}>
            <textarea
              ref={textareaRef}
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Tell the agent what to do..."
              rows={1}
              style={{
                flex: 1, border: 'none', outline: 'none', resize: 'none',
                background: 'transparent', color: 'var(--text)',
                fontSize: 13, lineHeight: 1.5, fontFamily: 'inherit',
                maxHeight: 100, minHeight: 20,
              }}
              onInput={e => {
                e.target.style.height = '20px'
                e.target.style.height = Math.min(e.target.scrollHeight, 100) + 'px'
              }}
            />
            {streaming ? (
              <button
                onClick={handleStop}
                style={{
                  width: 32, height: 32, borderRadius: 8, border: 'none',
                  background: '#ef4444', color: '#fff', cursor: 'pointer',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  flexShrink: 0,
                }}
                title="Stop"
              >
                <X size={16} />
              </button>
            ) : (
              <button
                onClick={() => sendMessage()}
                disabled={!input.trim()}
                style={{
                  width: 32, height: 32, borderRadius: 8, border: 'none',
                  background: input.trim() ? 'var(--accent)' : 'var(--bg-secondary)',
                  color: input.trim() ? '#fff' : 'var(--text-muted)',
                  cursor: input.trim() ? 'pointer' : 'default',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  flexShrink: 0,
                  transition: 'background 0.15s ease',
                }}
                title="Send"
              >
                <Send size={15} />
              </button>
            )}
          </div>
        </div>
      </div>
    </>
  )
}
