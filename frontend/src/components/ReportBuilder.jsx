/**
 * Self-service Report Builder
 * Drag-and-drop (via up/down controls) widget canvas with live data previews.
 * Reports are saved to localStorage.
 */
import React, { useState, useEffect, useCallback, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  BarChart2, PieChart as PieChartIcon, Table2, Hash, AlignLeft, Wrench,
  Shield, Users, Server, Bug, Plus, Trash2, ChevronUp, ChevronDown,
  Save, Eye, EyeOff, ArrowLeft, Copy, Settings2, GripVertical,
  CheckCircle, LayoutGrid, Maximize2, Minimize2, X, PenLine,
  TrendingUp, Zap, Clock, Home, Upload, GitCompare, Activity
} from 'lucide-react'
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, Legend, CartesianGrid, LineChart, Line
} from 'recharts'
import { useScan } from '../App.jsx'
import {
  getSummary, getAssets, getFindings, getRemediationQueue, getPluginFamilies,
  getTrending, getSLASummary, getAutomateClicks, getScanDeltaTimeline, getMetricsTimeline,
  getTemporalSummary, getRemediationVelocity
} from '../api.js'
import { Card, SeverityBadge, ScoreBar, Spinner, EffortBadge, OwnerBadge, Button, Pill } from './ui.jsx'

// ─── Storage helpers ─────────────────────────────────────────────────────────

const STORAGE_KEY = 'nessus_custom_reports'
const LANDING_KEY = 'nessus_landing_report'
const DEFAULT_REPORT_ID = 'default-security-overview'

function loadReports() {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]') } catch { return [] }
}
function saveReports(reports) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(reports))
}
function loadLandingId() {
  return localStorage.getItem(LANDING_KEY) || DEFAULT_REPORT_ID
}
function saveLandingId(id) {
  localStorage.setItem(LANDING_KEY, id)
}
function uid() {
  return Math.random().toString(36).slice(2, 10)
}

const DEFAULT_DASHBOARD = {
  id: DEFAULT_REPORT_ID,
  name: 'Security Overview',
  createdAt: new Date(0).toISOString(),
  widgets: [
    { id: 'dw1', type: 'stat_card', title: 'Critical', width: 'quarter', config: { metric: 'critical', label: 'Critical Findings' } },
    { id: 'dw2', type: 'stat_card', title: 'High', width: 'quarter', config: { metric: 'high', label: 'High Findings' } },
    { id: 'dw3', type: 'stat_card', title: 'With Exploit', width: 'quarter', config: { metric: 'exploit_count', label: 'Known Exploits' } },
    { id: 'dw4', type: 'stat_card', title: 'Assets', width: 'quarter', config: { metric: 'total_assets', label: 'Assets Scanned' } },
    { id: 'dw5', type: 'severity_chart', title: 'Severity Breakdown', width: 'half', config: { chartType: 'donut' } },
    { id: 'dw6', type: 'trend_chart', title: 'Vulnerability Trend', width: 'half', config: {} },
    { id: 'dw7', type: 'metrics_timeline', title: 'Severity Over Time', width: 'full', config: { preset: 'severity', series: ['critical', 'high', 'medium', 'low'], chartType: 'line' } },
    { id: 'dw7b', type: 'scan_delta_chart', title: 'Scan Delta — New vs Fixed', width: 'full', config: {} },
    { id: 'dw8', type: 'owner_chart', title: 'Findings by Owner', width: 'half', config: {} },
    { id: 'dw9', type: 'sla_widget', title: 'SLA Compliance', width: 'half', config: {} },
    { id: 'dw10', type: 'effort_chart', title: 'Remediation Effort', width: 'half', config: { chartType: 'donut' } },
    { id: 'dw11', type: 'automation_wishlist', title: 'Automation Wishlist', width: 'half', config: { limit: 5 } },
    { id: 'dw12', type: 'scan_delta_table', title: 'Scan Delta History', width: 'full', config: {} },
    { id: 'dw13', type: 'family_chart', title: 'Top Vulnerability Families', width: 'full', config: { limit: 8 } },
    { id: 'dw14', type: 'remediation_queue', title: 'Remediation Queue', width: 'full', config: { limit: 8 } },
  ],
}

// ─── Widget catalogue ────────────────────────────────────────────────────────

const WIDGET_CATALOGUE = [
  {
    category: 'Summary',
    items: [
      { type: 'stat_card', label: 'Stat Card', icon: Hash, desc: 'Single metric number', defaultWidth: 'quarter', defaultConfig: { metric: 'critical', label: 'Critical Findings' } },
      { type: 'severity_chart', label: 'Severity Breakdown', icon: PieChartIcon, desc: 'Findings by severity level', defaultWidth: 'half', defaultConfig: { chartType: 'pie' } },
      { type: 'effort_chart', label: 'Effort Distribution', icon: Wrench, desc: 'Quick win vs complex split', defaultWidth: 'half', defaultConfig: { chartType: 'donut' } },
      { type: 'owner_chart', label: 'Owner Breakdown', icon: Users, desc: 'Findings by responsible team', defaultWidth: 'half', defaultConfig: {} },
    ]
  },
  {
    category: 'Assets & Findings',
    items: [
      { type: 'asset_table', label: 'Asset Risk Table', icon: Server, desc: 'Assets ranked by risk score', defaultWidth: 'full', defaultConfig: { limit: 10 } },
      { type: 'family_chart', label: 'Plugin Families', icon: BarChart2, desc: 'Top vulnerability families', defaultWidth: 'full', defaultConfig: { limit: 8 } },
      { type: 'findings_table', label: 'Findings Table', icon: Bug, desc: 'Filterable findings list', defaultWidth: 'full', defaultConfig: { limit: 10, severity: '', family: '' } },
    ]
  },
  {
    category: 'Remediation',
    items: [
      { type: 'remediation_queue', label: 'Remediation Queue', icon: Shield, desc: 'Top prioritized findings', defaultWidth: 'full', defaultConfig: { limit: 8, effort: '', owner: '' } },
    ]
  },
  {
    category: 'Custom',
    items: [
      { type: 'text_block', label: 'Text / Notes', icon: AlignLeft, desc: 'Free-text annotation block', defaultWidth: 'full', defaultConfig: { content: 'Add your notes here...', fontSize: '14' } },
      { type: 'section_header', label: 'Section Header', icon: PenLine, desc: 'Visual divider with title', defaultWidth: 'full', defaultConfig: { title: 'Section Title', subtitle: '' } },
    ]
  },
  {
    category: 'Trends & Ops',
    items: [
      { type: 'trend_chart', label: 'Trend Chart', icon: TrendingUp, desc: 'Vulnerability trend across scans', defaultWidth: 'full', defaultConfig: {} },
      { type: 'metrics_timeline', label: 'Metric Timeline', icon: TrendingUp, desc: 'Any metric over time (SLA, MTTR, risk, counts…)', defaultWidth: 'full', defaultConfig: { preset: 'severity', series: ['critical', 'high', 'medium', 'low'] } },
      { type: 'scan_delta_chart', label: 'Scan Delta Chart', icon: GitCompare, desc: 'New vs fixed findings per scan', defaultWidth: 'full', defaultConfig: {} },
      { type: 'scan_delta_table', label: 'Scan Delta History', icon: Activity, desc: 'Scan-over-scan change table', defaultWidth: 'full', defaultConfig: {} },
      { type: 'sla_widget', label: 'SLA Compliance', icon: Clock, desc: 'SLA status and MTTR by severity', defaultWidth: 'half', defaultConfig: {} },
      { type: 'automation_wishlist', label: 'Automation Wishlist', icon: Zap, desc: 'Most-requested automation findings', defaultWidth: 'half', defaultConfig: { limit: 5 } },
      { type: 'temporal_summary', label: 'Finding Age & Regressions', icon: Clock, desc: 'Age distribution, zombie vulns, and regression alerts', defaultWidth: 'half', defaultConfig: {} },
      { type: 'velocity_chart', label: 'Remediation Velocity', icon: Activity, desc: 'Findings resolved per month/week with trend', defaultWidth: 'half', defaultConfig: { period: 'month' } },
    ]
  },
]

const WIDTH_OPTIONS = [
  { value: 'quarter', label: '¼ Width' },
  { value: 'third', label: '⅓ Width' },
  { value: 'half', label: '½ Width' },
  { value: 'two-thirds', label: '⅔ Width' },
  { value: 'full', label: 'Full Width' },
]
const WIDTH_COL = { quarter: 1, third: 1, half: 2, 'two-thirds': 3, full: 4 }

const STAT_METRICS = [
  { value: 'critical', label: 'Critical Findings' },
  { value: 'high', label: 'High Findings' },
  { value: 'medium', label: 'Medium Findings' },
  { value: 'total_findings', label: 'Total Findings' },
  { value: 'total_assets', label: 'Total Assets' },
  { value: 'exploit_count', label: 'With Known Exploit' },
  { value: 'high_priority_count', label: 'High Priority (≥7.0)' },
]

// ─── Live widget renderers ────────────────────────────────────────────────────

const SEV_COLORS = ['#0ea5e9', '#65a30d', '#d97706', '#ea580c', '#dc2626']
const EFFORT_COLORS = { quick_win: '#16a34a', medium: '#d97706', complex: '#dc2626' }

function useWidgetData(type, scanId) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    let cancelled = false

    const fetchers = {
      stat_card: () => getSummary(scanId),
      severity_chart: () => getSummary(scanId),
      effort_chart: () => getSummary(scanId),
      owner_chart: () => getSummary(scanId),
      family_chart: () => getSummary(scanId),
      asset_table: () => getAssets({ scan_id: scanId }),
      findings_table: () => getFindings({ scan_id: scanId, page_size: 50 }),
      remediation_queue: () => getRemediationQueue({ scan_id: scanId, limit: 20 }),
      trend_chart: () => getTrending(),
      metrics_timeline: () => getMetricsTimeline(),
      scan_delta_chart: () => getScanDeltaTimeline(),
      scan_delta_table: () => getScanDeltaTimeline(),
      sla_widget: () => getSLASummary(scanId),
      automation_wishlist: () => getAutomateClicks(),
      temporal_summary: () => getTemporalSummary(scanId),
      velocity_chart: () => getRemediationVelocity('month'),
    }

    const fetch = fetchers[type]
    if (!fetch) { setLoading(false); return }

    fetch().then(d => { if (!cancelled) { setData(d); setLoading(false) } })
           .catch(() => { if (!cancelled) setLoading(false) })

    return () => { cancelled = true }
  }, [type, scanId])

  return { data, loading }
}

function WidgetRenderer({ widget, scanId, preview }) {
  const { data, loading } = useWidgetData(widget.type, scanId)
  const navigate = useNavigate()
  const go = (path) => navigate(path)
  const cfg = widget.config || {}

  if (widget.type === 'text_block') {
    return (
      <div style={{ fontSize: parseInt(cfg.fontSize || 14), color: 'var(--text-secondary)', lineHeight: 1.7, whiteSpace: 'pre-wrap', minHeight: 60 }}>
        {cfg.content || 'No content set.'}
      </div>
    )
  }

  if (widget.type === 'section_header') {
    return (
      <div style={{ borderLeft: '3px solid var(--accent)', paddingLeft: 14 }}>
        <div style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)' }}>{cfg.title || 'Section'}</div>
        {cfg.subtitle && <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 4 }}>{cfg.subtitle}</div>}
      </div>
    )
  }

  if (loading) return <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 100 }}><Spinner /></div>
  if (!data) return <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '20px 0' }}>No data available</div>

  switch (widget.type) {
    case 'stat_card': {
      const summary = data
      const metricValues = {
        critical: summary.severity_breakdown?.critical ?? 0,
        high: summary.severity_breakdown?.high ?? 0,
        medium: summary.severity_breakdown?.medium ?? 0,
        total_findings: summary.total_findings ?? 0,
        total_assets: summary.total_assets ?? 0,
        exploit_count: summary.exploit_count ?? 0,
        high_priority_count: summary.high_priority_count ?? 0,
      }
      const METRIC_COLORS = {
        critical: '#dc2626', high: '#ea580c', medium: '#d97706',
        total_findings: 'var(--text-primary)', total_assets: '#6366f1',
        exploit_count: '#f59e0b', high_priority_count: '#ea580c',
      }
      const METRIC_LINKS = {
        critical: '/findings?severity=4', high: '/findings?severity=3', medium: '/findings?severity=2',
        total_findings: '/findings', total_assets: '/assets',
        exploit_count: '/findings?exploit=true', high_priority_count: '/findings',
      }
      const val = metricValues[cfg.metric] ?? 0
      const color = METRIC_COLORS[cfg.metric] || 'var(--text-primary)'
      const link = METRIC_LINKS[cfg.metric]
      return (
        <div onClick={link ? () => go(link) : undefined}
          style={{ textAlign: 'center', padding: '8px 0', cursor: link ? 'pointer' : 'default' }}>
          <div style={{ fontSize: 48, fontWeight: 800, color, lineHeight: 1 }}>{val.toLocaleString()}</div>
          <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 8 }}>{cfg.label || 'Findings'}</div>
        </div>
      )
    }

    case 'severity_chart': {
      const sev = data.severity_breakdown || {}
      const labels = ['Info', 'Low', 'Medium', 'High', 'Critical']
      const pieData = labels.map((l, i) => ({ name: l, severity: i, value: sev[l.toLowerCase()] || 0, color: SEV_COLORS[i] })).filter(d => d.value > 0)
      const isBar = cfg.chartType === 'bar'
      const tooltipStyle = { background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }
      return (
        <ResponsiveContainer width="100%" height={180}>
          {isBar ? (
            <BarChart data={pieData}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis dataKey="name" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} />
              <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 11 }} />
              <Tooltip contentStyle={tooltipStyle} />
              <Bar dataKey="value" radius={[4, 4, 0, 0]} cursor="pointer"
                onClick={e => go(`/findings?severity=${e.severity}`)}>
                {pieData.map((e, i) => <Cell key={i} fill={e.color} />)}
              </Bar>
            </BarChart>
          ) : (
            <PieChart>
              <Pie data={pieData} cx="50%" cy="50%" innerRadius={cfg.chartType === 'donut' ? 50 : 0} outerRadius={70} paddingAngle={2} dataKey="value"
                cursor="pointer"
                onClick={e => go(`/findings?severity=${e.severity}`)}>
                {pieData.map((e, i) => <Cell key={i} fill={e.color} />)}
              </Pie>
              <Tooltip contentStyle={tooltipStyle} />
              <Legend iconType="circle" iconSize={9} formatter={v => <span style={{ color: 'var(--text-secondary)', fontSize: 11 }}>{v}</span>} />
            </PieChart>
          )}
        </ResponsiveContainer>
      )
    }

    case 'effort_chart': {
      const eb = data.effort_breakdown || {}
      const EFFORT_KEYS = { 'Quick Win': 'quick_win', 'Medium': 'medium', 'Complex': 'complex' }
      const effortData = [
        { name: 'Quick Win', value: eb.quick_win || 0, color: '#16a34a' },
        { name: 'Medium', value: eb.medium || 0, color: '#d97706' },
        { name: 'Complex', value: eb.complex || 0, color: '#dc2626' },
      ].filter(d => d.value > 0)
      return (
        <ResponsiveContainer width="100%" height={180}>
          <PieChart>
            <Pie data={effortData} cx="50%" cy="50%" innerRadius={50} outerRadius={70} paddingAngle={2} dataKey="value"
              cursor="pointer"
              onClick={e => go(`/findings?effort=${EFFORT_KEYS[e.name] || ''}`)}>
              {effortData.map((e, i) => <Cell key={i} fill={e.color} />)}
            </Pie>
            <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }} />
            <Legend iconType="circle" iconSize={9} formatter={v => <span style={{ color: 'var(--text-secondary)', fontSize: 11 }}>{v}</span>} />
          </PieChart>
        </ResponsiveContainer>
      )
    }

    case 'owner_chart': {
      const ownerData = (data.owner_breakdown || []).map(o => ({ name: o.owner || 'Unknown', value: o.count }))
      return (
        <ResponsiveContainer width="100%" height={180}>
          <BarChart data={ownerData}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
            <XAxis dataKey="name" tick={{ fill: 'var(--text-secondary)', fontSize: 12 }} />
            <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 11 }} />
            <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }} />
            <Bar dataKey="value" fill="#6366f1" radius={[4, 4, 0, 0]} cursor="pointer"
              onClick={e => go(`/findings?owner=${encodeURIComponent(e.name)}`)} />
          </BarChart>
        </ResponsiveContainer>
      )
    }

    case 'family_chart': {
      const limit = parseInt(cfg.limit || 8)
      const families = (data.top_plugin_families || []).slice(0, limit).map(f => ({ family: f.family || 'Unknown', count: f.count }))
      return (
        <ResponsiveContainer width="100%" height={Math.max(160, families.length * 28)}>
          <BarChart data={families} layout="vertical">
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" horizontal={false} />
            <XAxis type="number" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} />
            <YAxis type="category" dataKey="family" tick={{ fill: 'var(--text-secondary)', fontSize: 11 }} width={160} />
            <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }} />
            <Bar dataKey="count" fill="#6366f1" radius={[0, 4, 4, 0]} cursor="pointer"
              onClick={e => e.family && go(`/findings?family=${encodeURIComponent(e.family)}`)} />
          </BarChart>
        </ResponsiveContainer>
      )
    }

    case 'asset_table': {
      const limit = parseInt(cfg.limit || 10)
      const assets = (Array.isArray(data) ? data : []).slice(0, limit)
      return (
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)' }}>
              {['Asset', 'OS', 'C', 'H', 'M', 'Risk Score'].map(h => (
                <th key={h} style={{ padding: '6px 8px', textAlign: 'left', color: 'var(--text-muted)', fontWeight: 600, fontSize: 11, textTransform: 'uppercase' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {assets.map((a, i) => (
              <tr key={i} onClick={() => go(`/assets?id=${a.id}`)}
                style={{ borderBottom: '1px solid rgba(45,49,85,0.4)', cursor: 'pointer', transition: 'opacity 0.15s' }}
                onMouseEnter={e => e.currentTarget.style.opacity = '0.75'}
                onMouseLeave={e => e.currentTarget.style.opacity = '1'}>
                <td style={{ padding: '6px 8px', fontWeight: 500 }}>{a.hostname || a.ip}</td>
                <td style={{ padding: '6px 8px', color: 'var(--text-muted)', maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.os ? a.os.split(' ').slice(0, 3).join(' ') : '—'}</td>
                <td style={{ padding: '6px 8px', color: '#dc2626', fontWeight: 600 }}>{a.critical_count}</td>
                <td style={{ padding: '6px 8px', color: '#ea580c', fontWeight: 600 }}>{a.high_count}</td>
                <td style={{ padding: '6px 8px', color: '#d97706', fontWeight: 600 }}>{a.medium_count}</td>
                <td style={{ padding: '6px 8px', minWidth: 120 }}><ScoreBar score={a.risk_score} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )
    }

    case 'findings_table': {
      const limit = parseInt(cfg.limit || 10)
      const findings = (data.findings || []).slice(0, limit)
      return (
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)' }}>
              {['Sev', 'Plugin', 'Asset', 'Priority'].map(h => (
                <th key={h} style={{ padding: '6px 8px', textAlign: 'left', color: 'var(--text-muted)', fontWeight: 600, fontSize: 11, textTransform: 'uppercase' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {findings.map((f, i) => (
              <tr key={i} onClick={() => go(`/findings/${f.id}`)}
                style={{ borderBottom: '1px solid rgba(45,49,85,0.4)', cursor: 'pointer', transition: 'opacity 0.15s' }}
                onMouseEnter={e => e.currentTarget.style.opacity = '0.75'}
                onMouseLeave={e => e.currentTarget.style.opacity = '1'}>
                <td style={{ padding: '6px 8px' }}><SeverityBadge severity={f.severity} label={f.severity_label} /></td>
                <td style={{ padding: '6px 8px', maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontWeight: 500 }}>{f.plugin_name}</td>
                <td style={{ padding: '6px 8px', color: 'var(--text-muted)' }}>{f.asset_hostname || f.asset_ip}</td>
                <td style={{ padding: '6px 8px', minWidth: 100 }}><ScoreBar score={f.priority_score} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )
    }

    case 'remediation_queue': {
      const limit = parseInt(cfg.limit || 8)
      const findings = (Array.isArray(data) ? data : [])
        .filter(f => !cfg.effort || f.effort_level === cfg.effort)
        .filter(f => !cfg.owner || f.owner_suggestion === cfg.owner)
        .slice(0, limit)
      return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {findings.map((f, i) => (
            <div key={i} onClick={() => go(`/findings/${f.id}`)} style={{
              display: 'flex', gap: 10, padding: '8px 10px', borderRadius: 8,
              background: 'var(--bg-secondary)', border: '1px solid var(--border)',
              borderLeft: `3px solid ${SEV_COLORS[f.severity] || '#0ea5e9'}`,
              alignItems: 'center', cursor: 'pointer',
              transition: 'opacity 0.15s',
            }}
              onMouseEnter={e => e.currentTarget.style.opacity = '0.75'}
              onMouseLeave={e => e.currentTarget.style.opacity = '1'}>
              <span style={{ fontWeight: 700, color: 'var(--text-muted)', minWidth: 20, fontSize: 12 }}>{i + 1}</span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontWeight: 600, fontSize: 12, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.plugin_name}</div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{f.asset_hostname || f.asset_ip}</div>
              </div>
              <SeverityBadge severity={f.severity} label={f.severity_label} />
              <EffortBadge effort={f.effort_level} />
            </div>
          ))}
        </div>
      )
    }

    case 'trend_chart': {
      if (!Array.isArray(data) || data.length < 2) {
        return <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '20px 0' }}>Need at least 2 scans for trend data</div>
      }
      const TREND_COLORS = { critical: '#dc2626', high: '#ea580c', medium: '#d97706', low: '#65a30d' }
      return (
        <ResponsiveContainer width="100%" height={220}>
          <LineChart data={data}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
            <XAxis dataKey="scan_name" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} />
            <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 11 }} />
            <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }} />
            <Legend formatter={v => <span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>{v}</span>} />
            <Line type="monotone" dataKey="critical" stroke={TREND_COLORS.critical} strokeWidth={2} dot={{ fill: TREND_COLORS.critical }} />
            <Line type="monotone" dataKey="high" stroke={TREND_COLORS.high} strokeWidth={2} dot={{ fill: TREND_COLORS.high }} />
            <Line type="monotone" dataKey="medium" stroke={TREND_COLORS.medium} strokeWidth={2} dot={{ fill: TREND_COLORS.medium }} />
            <Line type="monotone" dataKey="low" stroke={TREND_COLORS.low} strokeWidth={2} dot={{ fill: TREND_COLORS.low }} />
          </LineChart>
        </ResponsiveContainer>
      )
    }

    case 'metrics_timeline': {
      if (!Array.isArray(data) || data.length < 2) {
        return <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '20px 0' }}>Need at least 2 scans for timeline data</div>
      }
      const METRIC_SERIES_DEFS = {
        critical:              { label: 'Critical',           color: '#dc2626' },
        high:                  { label: 'High',               color: '#ea580c' },
        medium:                { label: 'Medium',             color: '#d97706' },
        low:                   { label: 'Low',                color: '#65a30d' },
        info:                  { label: 'Info',               color: '#6b7280' },
        total_findings:        { label: 'Total Findings',     color: '#6366f1' },
        actionable_findings:   { label: 'Actionable',         color: '#8b5cf6' },
        total_assets:          { label: 'Total Assets',       color: '#0ea5e9' },
        exploit_count:         { label: 'Exploitable',        color: '#f59e0b' },
        sla_on_track:          { label: 'SLA On Track',       color: '#16a34a' },
        sla_at_risk:           { label: 'SLA At Risk',        color: '#d97706' },
        sla_breached:          { label: 'SLA Breached',       color: '#dc2626' },
        sla_resolved:          { label: 'SLA Resolved',       color: '#6366f1' },
        sla_compliance_pct:    { label: 'SLA Compliance %',   color: '#16a34a' },
        workflow_open:         { label: 'Open',               color: '#6b7280' },
        workflow_in_progress:  { label: 'In Progress',        color: '#3b82f6' },
        workflow_resolved:     { label: 'Resolved',           color: '#22c55e' },
        workflow_excepted:     { label: 'Excepted',           color: '#d97706' },
        avg_risk_score:        { label: 'Avg Risk Score',     color: '#ef4444' },
        max_risk_score:        { label: 'Max Risk Score',     color: '#dc2626' },
        avg_mttr_days:         { label: 'Avg MTTR (days)',    color: '#8b5cf6' },
      }
      const series = cfg.series || ['critical', 'high', 'medium', 'low']
      const chartData = data.map(d => {
        const point = { name: (d.scan_name || '').length > 18 ? (d.scan_name || '').slice(0, 18) + '…' : d.scan_name }
        series.forEach(s => { point[s] = d[s] ?? null })
        return point
      })
      const chartType = cfg.chartType || 'line'
      return (
        <ResponsiveContainer width="100%" height={240}>
          {chartType === 'bar' ? (
            <BarChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis dataKey="name" tick={{ fill: 'var(--text-muted)', fontSize: 10 }} />
              <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 11 }} />
              <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }} />
              <Legend formatter={v => <span style={{ color: 'var(--text-secondary)', fontSize: 11 }}>{METRIC_SERIES_DEFS[v]?.label || v}</span>} />
              {series.map(s => (
                <Bar key={s} dataKey={s} fill={METRIC_SERIES_DEFS[s]?.color || '#6366f1'} radius={[3, 3, 0, 0]} />
              ))}
            </BarChart>
          ) : chartType === 'area' ? (
            <LineChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis dataKey="name" tick={{ fill: 'var(--text-muted)', fontSize: 10 }} />
              <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 11 }} />
              <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }} />
              <Legend formatter={v => <span style={{ color: 'var(--text-secondary)', fontSize: 11 }}>{METRIC_SERIES_DEFS[v]?.label || v}</span>} />
              {series.map(s => (
                <Line key={s} type="monotone" dataKey={s} stroke={METRIC_SERIES_DEFS[s]?.color || '#6366f1'} strokeWidth={2} fill={METRIC_SERIES_DEFS[s]?.color || '#6366f1'} fillOpacity={0.1} dot={{ fill: METRIC_SERIES_DEFS[s]?.color, r: 3 }} connectNulls />
              ))}
            </LineChart>
          ) : (
            <LineChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis dataKey="name" tick={{ fill: 'var(--text-muted)', fontSize: 10 }} />
              <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 11 }} />
              <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }} />
              <Legend formatter={v => <span style={{ color: 'var(--text-secondary)', fontSize: 11 }}>{METRIC_SERIES_DEFS[v]?.label || v}</span>} />
              {series.map(s => (
                <Line key={s} type="monotone" dataKey={s} stroke={METRIC_SERIES_DEFS[s]?.color || '#6366f1'} strokeWidth={2} dot={{ fill: METRIC_SERIES_DEFS[s]?.color, r: 3 }} connectNulls />
              ))}
            </LineChart>
          )}
        </ResponsiveContainer>
      )
    }

    case 'scan_delta_chart': {
      if (!Array.isArray(data) || data.length < 1) {
        return <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '20px 0' }}>Need at least 2 scans for delta data</div>
      }
      const deltaData = data.map(d => ({
        name: (d.scan_name || '').length > 20 ? (d.scan_name || '').slice(0, 20) + '…' : d.scan_name,
        'New': d.new_count,
        'Fixed': -d.fixed_count,
        'Net': d.net_change,
      }))
      return (
        <div>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={deltaData} stackOffset="sign">
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis dataKey="name" tick={{ fill: 'var(--text-muted)', fontSize: 10 }} />
              <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 11 }} />
              <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }} />
              <Legend formatter={v => <span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>{v}</span>} />
              <Bar dataKey="New" fill="#ef4444" stackId="a" radius={[3, 3, 0, 0]} />
              <Bar dataKey="Fixed" fill="#22c55e" stackId="a" radius={[0, 0, 3, 3]} />
            </BarChart>
          </ResponsiveContainer>
          <div style={{ marginTop: 12 }}>
            <ResponsiveContainer width="100%" height={100}>
              <LineChart data={deltaData}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                <XAxis dataKey="name" tick={{ fill: 'var(--text-muted)', fontSize: 10 }} hide />
                <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 11 }} />
                <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }} />
                <Line type="monotone" dataKey="Net" stroke="#8b5cf6" strokeWidth={2} dot={{ fill: '#8b5cf6', r: 3 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      )
    }

    case 'scan_delta_table': {
      if (!Array.isArray(data) || data.length < 1) {
        return <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '20px 0' }}>Need at least 2 scans for delta data</div>
      }
      return (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ borderBottom: '2px solid var(--border)' }}>
                {['Scan', 'Date', 'New', 'Fixed', 'Recurring', 'Net Change'].map(h => (
                  <th key={h} style={{ padding: '8px 10px', textAlign: 'left', color: 'var(--text-muted)', fontWeight: 600, fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.04em' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.map((d, i) => (
                <tr key={i} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '8px 10px', fontWeight: 500 }}>{d.scan_name || `Scan #${d.scan_id}`}</td>
                  <td style={{ padding: '8px 10px', color: 'var(--text-muted)' }}>{d.scan_date ? new Date(d.scan_date).toLocaleDateString() : '—'}</td>
                  <td style={{ padding: '8px 10px', color: '#ef4444', fontWeight: 600 }}>+{d.new_count}</td>
                  <td style={{ padding: '8px 10px', color: '#22c55e', fontWeight: 600 }}>-{d.fixed_count}</td>
                  <td style={{ padding: '8px 10px', color: 'var(--text-muted)' }}>{d.recurring_count}</td>
                  <td style={{ padding: '8px 10px', fontWeight: 700, color: d.net_change > 0 ? '#ef4444' : d.net_change < 0 ? '#22c55e' : 'var(--text-muted)' }}>
                    {d.net_change > 0 ? '+' : ''}{d.net_change}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )
    }

    case 'sla_widget': {
      if (!data || !data.total_with_sla) {
        return <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '20px 0' }}>No SLA data — set deadlines on findings to track compliance</div>
      }
      const { on_track, at_risk, breached, resolved, total_with_sla, compliance_pct, avg_mttr_days } = data
      const bars = [
        { label: 'On Track', value: on_track, color: '#16a34a' },
        { label: 'At Risk', value: at_risk, color: '#d97706' },
        { label: 'Breached', value: breached, color: '#dc2626' },
        { label: 'Resolved', value: resolved, color: '#6366f1' },
      ]
      const mttrEntries = Object.entries(avg_mttr_days || {})
      return (
        <div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
            <span style={{ fontSize: 13, color: 'var(--text-secondary)' }}>Compliance</span>
            <span style={{ fontSize: 24, fontWeight: 800, color: compliance_pct >= 80 ? '#16a34a' : compliance_pct >= 50 ? '#d97706' : '#dc2626' }}>
              {compliance_pct}%
            </span>
          </div>
          {bars.map(b => (
            <div key={b.label} style={{ marginBottom: 8 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, marginBottom: 3 }}>
                <span style={{ color: 'var(--text-secondary)' }}>{b.label}</span>
                <span style={{ fontWeight: 600, color: b.color }}>{b.value}</span>
              </div>
              <div style={{ height: 4, background: 'var(--border)', borderRadius: 3, overflow: 'hidden' }}>
                <div style={{ width: `${Math.min((b.value / total_with_sla) * 100, 100)}%`, height: '100%', background: b.color, borderRadius: 3 }} />
              </div>
            </div>
          ))}
          {mttrEntries.length > 0 && (
            <div style={{ marginTop: 12, paddingTop: 12, borderTop: '1px solid var(--border)' }}>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8 }}>Avg MTTR (days)</div>
              <div style={{ display: 'flex', gap: 16 }}>
                {mttrEntries.map(([sev, days]) => {
                  const color = sev === 'critical' ? '#dc2626' : sev === 'high' ? '#ea580c' : sev === 'medium' ? '#d97706' : '#65a30d'
                  return (
                    <div key={sev} style={{ textAlign: 'center' }}>
                      <div style={{ fontSize: 20, fontWeight: 700, color }}>{Math.round(days)}</div>
                      <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'capitalize' }}>{sev}</div>
                    </div>
                  )
                })}
              </div>
            </div>
          )}
        </div>
      )
    }

    case 'automation_wishlist': {
      const limit = parseInt(cfg.limit || 5)
      const items = (Array.isArray(data) ? data : []).slice(0, limit)
      if (items.length === 0) return <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '20px 0' }}>No automation requests yet — click "Automate This" on findings</div>
      return (
        <div style={{ display: 'flex', flexDirection: 'column' }}>
          {items.map((item, i) => (
            <div key={i} style={{ display: 'flex', gap: 10, padding: '8px 0', borderBottom: '1px solid rgba(45,49,85,0.4)', alignItems: 'center' }}>
              <span style={{ fontWeight: 700, color: '#6366f1', minWidth: 22, fontSize: 13 }}>#{i + 1}</span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{item.plugin_name || `Plugin ${item.plugin_id}`}</div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Plugin {item.plugin_id}</div>
              </div>
              <span style={{ fontWeight: 600, color: '#818cf8', fontSize: 13 }}>{item.click_count}×</span>
            </div>
          ))}
        </div>
      )
    }

    case 'temporal_summary': {
      const { regression_count = 0, zombie_count = 0, age_distribution = {} } = data || {}
      const ageBars = [
        { label: '< 30 days', value: age_distribution.under_30d || 0, color: '#16a34a' },
        { label: '30–90 days', value: age_distribution['30_90d'] || 0, color: '#d97706' },
        { label: '90–180 days', value: age_distribution['90_180d'] || 0, color: '#ea580c' },
        { label: '> 180 days', value: age_distribution.over_180d || 0, color: '#dc2626' },
      ]
      const total = ageBars.reduce((s, b) => s + b.value, 0) || 1
      return (
        <div>
          {ageBars.map(b => (
            <div key={b.label} style={{ marginBottom: 10 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 3 }}>
                <span style={{ color: 'var(--text-secondary)' }}>{b.label}</span>
                <span style={{ fontWeight: 600, color: b.color }}>{b.value}</span>
              </div>
              <div style={{ height: 5, background: 'var(--border)', borderRadius: 3, overflow: 'hidden' }}>
                <div style={{ width: `${(b.value / total) * 100}%`, height: '100%', background: b.color, borderRadius: 3 }} />
              </div>
            </div>
          ))}
          <div style={{ display: 'flex', gap: 12, marginTop: 12, fontSize: 12 }}>
            {regression_count > 0 && <span style={{ color: '#fca5a5' }}>{regression_count} regression{regression_count !== 1 ? 's' : ''}</span>}
            {zombie_count > 0 && <span style={{ color: '#fdba74' }}>{zombie_count} zombie vuln{zombie_count !== 1 ? 's' : ''}</span>}
          </div>
        </div>
      )
    }

    case 'velocity_chart': {
      const { buckets = [], avg_per_period = 0, velocity_trend_pct, period = 'month' } = data || {}
      const recent = buckets.slice(-8)
      if (recent.length === 0) return <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>No resolved findings yet</div>
      return (
        <div>
          <div style={{ display: 'flex', gap: 12, marginBottom: 10, fontSize: 12, color: 'var(--text-muted)' }}>
            <span>avg {avg_per_period}/{period}</span>
            {velocity_trend_pct != null && (
              <span style={{ fontWeight: 600, color: velocity_trend_pct > 0 ? '#16a34a' : velocity_trend_pct < 0 ? '#dc2626' : 'var(--text-muted)' }}>
                {velocity_trend_pct > 0 ? '+' : ''}{velocity_trend_pct}% trend
              </span>
            )}
          </div>
          <ResponsiveContainer width="100%" height={160}>
            <BarChart data={recent} margin={{ right: 8 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis dataKey="period_label" tick={{ fill: 'var(--text-muted)', fontSize: 10 }} />
              <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 10 }} width={30} />
              <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }} />
              <Bar dataKey="critical" stackId="a" fill="#dc2626" />
              <Bar dataKey="high" stackId="a" fill="#ea580c" />
              <Bar dataKey="medium" stackId="a" fill="#d97706" />
              <Bar dataKey="low" stackId="a" fill="#65a30d" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )
    }

    default:
      return <div style={{ color: 'var(--text-muted)', fontSize: 12 }}>Unknown widget type: {widget.type}</div>
  }
}

// ─── Widget config panel ──────────────────────────────────────────────────────

function ConfigPanel({ widget, onUpdate, onClose }) {
  const cfg = widget.config || {}
  const set = (key, val) => onUpdate({ ...widget, config: { ...cfg, [key]: val } })
  const setTitle = (t) => onUpdate({ ...widget, title: t })
  const setWidth = (w) => onUpdate({ ...widget, width: w })

  const Field = ({ label, children }) => (
    <div style={{ marginBottom: 14 }}>
      <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6 }}>{label}</div>
      {children}
    </div>
  )

  const Select = ({ value, onChange, options }) => (
    <select value={value || ''} onChange={e => onChange(e.target.value)}
      style={{ width: '100%', background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)', borderRadius: 6, padding: '7px 10px', fontSize: 13 }}>
      {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
    </select>
  )

  const TextInput = ({ value, onChange, placeholder }) => (
    <input value={value || ''} onChange={e => onChange(e.target.value)} placeholder={placeholder}
      style={{ width: '100%', background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)', borderRadius: 6, padding: '7px 10px', fontSize: 13, boxSizing: 'border-box' }} />
  )

  const Textarea = ({ value, onChange, rows = 5 }) => (
    <textarea value={value || ''} onChange={e => onChange(e.target.value)} rows={rows}
      style={{ width: '100%', background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)', borderRadius: 6, padding: '7px 10px', fontSize: 13, resize: 'vertical', boxSizing: 'border-box', fontFamily: 'inherit' }} />
  )

  return (
    <div style={{ width: 260, flexShrink: 0, background: 'var(--bg-secondary)', borderLeft: '1px solid var(--border)', padding: 16, overflowY: 'auto' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <div style={{ fontWeight: 600, fontSize: 13, display: 'flex', alignItems: 'center', gap: 6 }}>
          <Settings2 size={14} color="var(--accent)" /> Widget Config
        </div>
        <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
          <X size={14} />
        </button>
      </div>

      <Field label="Widget Title">
        <TextInput value={widget.title} onChange={setTitle} placeholder="Widget title..." />
      </Field>

      <Field label="Width">
        <Select value={widget.width} onChange={setWidth} options={WIDTH_OPTIONS} />
      </Field>

      {/* Type-specific config */}
      {widget.type === 'stat_card' && (
        <>
          <Field label="Metric">
            <Select value={cfg.metric} onChange={v => set('metric', v)}
              options={STAT_METRICS} />
          </Field>
          <Field label="Display Label">
            <TextInput value={cfg.label} onChange={v => set('label', v)} placeholder="e.g. Critical Findings" />
          </Field>
        </>
      )}

      {widget.type === 'severity_chart' && (
        <Field label="Chart Type">
          <Select value={cfg.chartType} onChange={v => set('chartType', v)}
            options={[{ value: 'pie', label: 'Pie Chart' }, { value: 'donut', label: 'Donut Chart' }, { value: 'bar', label: 'Bar Chart' }]} />
        </Field>
      )}

      {widget.type === 'effort_chart' && (
        <Field label="Chart Type">
          <Select value={cfg.chartType} onChange={v => set('chartType', v)}
            options={[{ value: 'donut', label: 'Donut Chart' }, { value: 'pie', label: 'Pie Chart' }]} />
        </Field>
      )}

      {widget.type === 'family_chart' && (
        <Field label="Max Families">
          <Select value={String(cfg.limit || 8)} onChange={v => set('limit', v)}
            options={[{ value: '5', label: 'Top 5' }, { value: '8', label: 'Top 8' }, { value: '10', label: 'Top 10' }, { value: '15', label: 'Top 15' }]} />
        </Field>
      )}

      {widget.type === 'asset_table' && (
        <Field label="Max Rows">
          <Select value={String(cfg.limit || 10)} onChange={v => set('limit', v)}
            options={[{ value: '5', label: '5 rows' }, { value: '10', label: '10 rows' }, { value: '20', label: '20 rows' }]} />
        </Field>
      )}

      {widget.type === 'findings_table' && (
        <>
          <Field label="Max Rows">
            <Select value={String(cfg.limit || 10)} onChange={v => set('limit', v)}
              options={[{ value: '5', label: '5 rows' }, { value: '10', label: '10 rows' }, { value: '20', label: '20 rows' }, { value: '50', label: '50 rows' }]} />
          </Field>
        </>
      )}

      {widget.type === 'remediation_queue' && (
        <>
          <Field label="Max Items">
            <Select value={String(cfg.limit || 8)} onChange={v => set('limit', v)}
              options={[{ value: '5', label: '5 items' }, { value: '8', label: '8 items' }, { value: '10', label: '10 items' }, { value: '15', label: '15 items' }]} />
          </Field>
          <Field label="Filter by Effort">
            <Select value={cfg.effort || ''} onChange={v => set('effort', v)}
              options={[{ value: '', label: 'All efforts' }, { value: 'quick_win', label: 'Quick Wins' }, { value: 'medium', label: 'Medium' }, { value: 'complex', label: 'Complex' }]} />
          </Field>
          <Field label="Filter by Owner">
            <Select value={cfg.owner || ''} onChange={v => set('owner', v)}
              options={[{ value: '', label: 'All owners' }, { value: 'IT', label: 'IT' }, { value: 'DevOps', label: 'DevOps' }, { value: 'SecOps', label: 'SecOps' }, { value: 'AppSec', label: 'AppSec' }]} />
          </Field>
        </>
      )}

      {widget.type === 'text_block' && (
        <>
          <Field label="Content">
            <Textarea value={cfg.content} onChange={v => set('content', v)} rows={8} />
          </Field>
          <Field label="Font Size">
            <Select value={String(cfg.fontSize || 14)} onChange={v => set('fontSize', v)}
              options={[{ value: '12', label: 'Small (12px)' }, { value: '14', label: 'Normal (14px)' }, { value: '16', label: 'Large (16px)' }]} />
          </Field>
        </>
      )}

      {widget.type === 'section_header' && (
        <>
          <Field label="Title">
            <TextInput value={cfg.title} onChange={v => set('title', v)} placeholder="Section title" />
          </Field>
          <Field label="Subtitle">
            <TextInput value={cfg.subtitle} onChange={v => set('subtitle', v)} placeholder="Optional subtitle" />
          </Field>
        </>
      )}

      {widget.type === 'automation_wishlist' && (
        <Field label="Max Items">
          <Select value={String(cfg.limit || 5)} onChange={v => set('limit', v)}
            options={[{ value: '3', label: '3 items' }, { value: '5', label: '5 items' }, { value: '10', label: '10 items' }]} />
        </Field>
      )}

      {widget.type === 'metrics_timeline' && (() => {
        const PRESETS = [
          { value: 'severity', label: 'Severity Counts', series: ['critical', 'high', 'medium', 'low'] },
          { value: 'sla', label: 'SLA Status', series: ['sla_on_track', 'sla_at_risk', 'sla_breached', 'sla_compliance_pct'] },
          { value: 'workflow', label: 'Workflow States', series: ['workflow_open', 'workflow_in_progress', 'workflow_resolved', 'workflow_excepted'] },
          { value: 'risk', label: 'Risk Scores', series: ['avg_risk_score', 'max_risk_score'] },
          { value: 'mttr', label: 'MTTR', series: ['avg_mttr_days'] },
          { value: 'overview', label: 'Overview', series: ['total_findings', 'actionable_findings', 'total_assets', 'exploit_count'] },
          { value: 'custom', label: 'Custom…' },
        ]
        const ALL_SERIES = [
          { value: 'critical', label: 'Critical' }, { value: 'high', label: 'High' },
          { value: 'medium', label: 'Medium' }, { value: 'low', label: 'Low' }, { value: 'info', label: 'Info' },
          { value: 'total_findings', label: 'Total Findings' }, { value: 'actionable_findings', label: 'Actionable' },
          { value: 'total_assets', label: 'Total Assets' }, { value: 'exploit_count', label: 'Exploitable' },
          { value: 'sla_on_track', label: 'SLA On Track' }, { value: 'sla_at_risk', label: 'SLA At Risk' },
          { value: 'sla_breached', label: 'SLA Breached' }, { value: 'sla_resolved', label: 'SLA Resolved' },
          { value: 'sla_compliance_pct', label: 'SLA Compliance %' },
          { value: 'workflow_open', label: 'Open' }, { value: 'workflow_in_progress', label: 'In Progress' },
          { value: 'workflow_resolved', label: 'Resolved' }, { value: 'workflow_excepted', label: 'Excepted' },
          { value: 'avg_risk_score', label: 'Avg Risk Score' }, { value: 'max_risk_score', label: 'Max Risk Score' },
          { value: 'avg_mttr_days', label: 'Avg MTTR (days)' },
        ]
        const currentPreset = cfg.preset || 'severity'
        const activeSeries = cfg.series || ['critical', 'high', 'medium', 'low']
        const toggleSeries = (s) => {
          const next = activeSeries.includes(s) ? activeSeries.filter(x => x !== s) : [...activeSeries, s]
          if (next.length > 0) onUpdate({ ...widget, config: { ...cfg, series: next, preset: 'custom' } })
        }
        return (
          <>
            <Field label="Preset">
              <Select value={currentPreset} onChange={v => {
                const p = PRESETS.find(x => x.value === v)
                if (p && p.series) onUpdate({ ...widget, config: { ...cfg, preset: v, series: p.series } })
                else set('preset', v)
              }} options={PRESETS} />
            </Field>
            <Field label="Chart Type">
              <Select value={cfg.chartType || 'line'} onChange={v => set('chartType', v)}
                options={[{ value: 'line', label: 'Line' }, { value: 'bar', label: 'Bar' }, { value: 'area', label: 'Area' }]} />
            </Field>
            <Field label="Active Series">
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4, maxHeight: 200, overflowY: 'auto' }}>
                {ALL_SERIES.map(s => (
                  <label key={s.value} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, cursor: 'pointer', padding: '2px 0' }}>
                    <input type="checkbox" checked={activeSeries.includes(s.value)} onChange={() => toggleSeries(s.value)} />
                    {s.label}
                  </label>
                ))}
              </div>
            </Field>
          </>
        )
      })()}
    </div>
  )
}

// ─── Widget library sidebar ───────────────────────────────────────────────────

function WidgetLibrary({ onAdd }) {
  return (
    <div style={{ width: 220, flexShrink: 0, background: 'var(--bg-secondary)', borderRight: '1px solid var(--border)', overflowY: 'auto', padding: '12px 0' }}>
      <div style={{ padding: '0 14px 10px', fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.07em' }}>Widget Library</div>
      {WIDGET_CATALOGUE.map(cat => (
        <div key={cat.category}>
          <div style={{ padding: '8px 14px 6px', fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.07em', opacity: 0.6 }}>{cat.category}</div>
          {cat.items.map(w => {
            const Icon = w.icon
            return (
              <div
                key={w.type}
                onClick={() => onAdd(w)}
                style={{
                  display: 'flex', alignItems: 'flex-start', gap: 10, padding: '8px 14px',
                  cursor: 'pointer', transition: 'background 0.1s', borderRadius: 0,
                }}
                onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-hover)'}
                onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
              >
                <div style={{ width: 28, height: 28, borderRadius: 8, background: '#6366f122', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginTop: 1 }}>
                  <Icon size={14} color="#818cf8" />
                </div>
                <div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)' }}>{w.label}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.4 }}>{w.desc}</div>
                </div>
              </div>
            )
          })}
        </div>
      ))}
    </div>
  )
}

// ─── Main canvas widget card ──────────────────────────────────────────────────

function CanvasWidget({ widget, index, total, scanId, isSelected, onSelect, onUpdate, onDelete, onMoveUp, onMoveDown, preview }) {
  const col = WIDTH_COL[widget.width] || 4

  return (
    <div
      style={{
        gridColumn: `span ${col}`,
        background: 'var(--bg-card)',
        border: `1px solid ${isSelected && !preview ? 'var(--accent)' : 'var(--border)'}`,
        borderRadius: 10,
        overflow: 'hidden',
        boxShadow: isSelected && !preview ? '0 0 0 2px rgba(99,102,241,0.2)' : 'none',
        transition: 'border-color 0.15s, box-shadow 0.15s',
        position: 'relative',
      }}
      onClick={() => !preview && onSelect()}
    >
      {/* Widget header */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '10px 14px', borderBottom: '1px solid var(--border)',
        background: isSelected && !preview ? 'rgba(99,102,241,0.05)' : 'transparent',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {!preview && <GripVertical size={14} color="var(--text-muted)" style={{ cursor: 'grab' }} />}
          <span style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-primary)' }}>{widget.title}</span>
        </div>
        {!preview && (
          <div style={{ display: 'flex', gap: 4 }} onClick={e => e.stopPropagation()}>
            <button onClick={() => onMoveUp()} disabled={index === 0} title="Move up"
              style={{ background: 'none', border: 'none', color: index === 0 ? 'var(--text-muted)' : 'var(--text-secondary)', cursor: index === 0 ? 'default' : 'pointer', padding: 3 }}>
              <ChevronUp size={14} />
            </button>
            <button onClick={() => onMoveDown()} disabled={index === total - 1} title="Move down"
              style={{ background: 'none', border: 'none', color: index === total - 1 ? 'var(--text-muted)' : 'var(--text-secondary)', cursor: index === total - 1 ? 'default' : 'pointer', padding: 3 }}>
              <ChevronDown size={14} />
            </button>
            <button onClick={() => onDelete()} title="Remove widget"
              style={{ background: 'none', border: 'none', color: '#dc2626', cursor: 'pointer', padding: 3, opacity: 0.7 }}>
              <Trash2 size={13} />
            </button>
          </div>
        )}
      </div>

      {/* Widget content */}
      <div style={{ padding: 16 }}>
        <WidgetRenderer widget={widget} scanId={scanId} preview={preview} />
      </div>
    </div>
  )
}

// ─── Builder view ─────────────────────────────────────────────────────────────

function Builder({ report, onSave, onBack, isLanding, onSetLanding }) {
  const { activeScanId, scans } = useScan()
  const navigate = useNavigate()
  const [widgets, setWidgets] = useState(report.widgets || [])
  const [name, setName] = useState(report.name || 'Untitled Report')
  const [selectedId, setSelectedId] = useState(null)
  const [preview, setPreview] = useState(true)
  const [saved, setSaved] = useState(false)
  const [editingName, setEditingName] = useState(false)

  const selectedWidget = widgets.find(w => w.id === selectedId)

  const addWidget = (catalogItem) => {
    const newWidget = {
      id: uid(),
      type: catalogItem.type,
      title: catalogItem.label,
      width: catalogItem.defaultWidth || 'full',
      config: { ...catalogItem.defaultConfig },
    }
    setWidgets(prev => [...prev, newWidget])
    setSelectedId(newWidget.id)
  }

  const updateWidget = (updated) => {
    setWidgets(prev => prev.map(w => w.id === updated.id ? updated : w))
  }

  const deleteWidget = (id) => {
    setWidgets(prev => prev.filter(w => w.id !== id))
    if (selectedId === id) setSelectedId(null)
  }

  const moveWidget = (id, dir) => {
    setWidgets(prev => {
      const idx = prev.findIndex(w => w.id === id)
      const next = [...prev]
      if (dir === 'up' && idx > 0) {
        [next[idx - 1], next[idx]] = [next[idx], next[idx - 1]]
      } else if (dir === 'down' && idx < next.length - 1) {
        [next[idx], next[idx + 1]] = [next[idx + 1], next[idx]]
      }
      return next
    })
  }

  const handleSave = () => {
    onSave({ ...report, name, widgets })
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Top bar */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 12, padding: '10px 16px',
        background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)', flexShrink: 0,
      }}>
        <button onClick={onBack} style={{ background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4, fontSize: 13, padding: '4px 8px', borderRadius: 6 }}>
          <ArrowLeft size={15} /> Reports
        </button>

        <div style={{ width: 1, height: 20, background: 'var(--border)' }} />

        {/* Editable report name */}
        {editingName ? (
          <input
            autoFocus
            value={name}
            onChange={e => setName(e.target.value)}
            onBlur={() => setEditingName(false)}
            onKeyDown={e => e.key === 'Enter' && setEditingName(false)}
            style={{
              background: 'var(--bg-card)', border: '1px solid var(--accent)', color: 'var(--text-primary)',
              borderRadius: 6, padding: '4px 10px', fontSize: 14, fontWeight: 600, width: 240,
            }}
          />
        ) : (
          <div
            onClick={() => setEditingName(true)}
            style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', padding: '4px 8px', borderRadius: 6 }}
            onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-hover)'}
            onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
          >
            <span style={{ fontWeight: 700, fontSize: 14 }}>{name}</span>
            <PenLine size={12} color="var(--text-muted)" />
          </div>
        )}

        <div style={{ flex: 1 }} />

        <button
          onClick={() => setPreview(p => !p)}
          style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 12px', background: preview ? '#6366f122' : 'transparent', border: '1px solid var(--border)', color: preview ? '#818cf8' : 'var(--text-secondary)', borderRadius: 6, cursor: 'pointer', fontSize: 13, fontWeight: 500 }}
        >
          {preview ? <><EyeOff size={14} /> Edit</> : <><Eye size={14} /> Preview</>}
        </button>

        <button
          onClick={isLanding ? undefined : onSetLanding}
          title={isLanding ? 'This is your landing page' : 'Set as landing page'}
          style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 12px', background: isLanding ? '#16a34a22' : 'transparent', border: `1px solid ${isLanding ? '#16a34a' : 'var(--border)'}`, color: isLanding ? '#16a34a' : 'var(--text-secondary)', borderRadius: 6, cursor: isLanding ? 'default' : 'pointer', fontSize: 13, fontWeight: 500 }}
        >
          <Home size={14} /> {isLanding ? 'Landing' : 'Set as Home'}
        </button>

        <button
          onClick={handleSave}
          style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 14px', background: saved ? '#16a34a' : 'var(--accent)', border: 'none', color: '#fff', borderRadius: 6, cursor: 'pointer', fontSize: 13, fontWeight: 600, transition: 'background 0.2s' }}
        >
          {saved ? <><CheckCircle size={14} /> Saved!</> : <><Save size={14} /> Save</>}
        </button>
      </div>

      {/* Body */}
      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        {/* Widget library */}
        {!preview && <WidgetLibrary onAdd={addWidget} />}

        {/* Canvas */}
        <div
          style={{ flex: 1, overflowY: 'auto', padding: 20, background: preview ? 'var(--bg-primary)' : '#0d0f1a' }}
          onClick={() => setSelectedId(null)}
        >
          {preview && (
            <div style={{ maxWidth: 900, margin: '0 auto 20px', textAlign: 'center' }}>
              <h1 style={{ fontSize: 24, fontWeight: 800 }}>{name}</h1>
              <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 4 }}>Custom Security Report · Generated {new Date().toLocaleDateString()}</div>
            </div>
          )}

          {preview && (!scans || scans.length === 0) && (
            <div style={{
              maxWidth: 560, margin: '0 auto 28px', padding: '32px 28px',
              background: 'linear-gradient(135deg, rgba(99,102,241,0.08), rgba(139,92,246,0.06))',
              border: '1px solid rgba(99,102,241,0.25)', borderRadius: 14,
              display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 14, textAlign: 'center',
            }}>
              <div style={{
                width: 52, height: 52, borderRadius: 14,
                background: 'rgba(99,102,241,0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                <Upload size={26} color="#818cf8" />
              </div>
              <div>
                <div style={{ fontSize: 17, fontWeight: 700, color: 'var(--text-primary)' }}>Upload your first scan</div>
                <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 6, lineHeight: 1.5 }}>
                  Import a Nessus scan (.nessus, .csv, or .html) to populate your dashboard with vulnerability data, asset inventory, and remediation priorities.
                </div>
              </div>
              <button
                onClick={() => navigate('/upload')}
                style={{
                  marginTop: 4, padding: '10px 24px', background: 'var(--accent)', border: 'none',
                  color: '#fff', borderRadius: 8, cursor: 'pointer', fontWeight: 600, fontSize: 14,
                  display: 'flex', alignItems: 'center', gap: 8,
                }}
              >
                <Upload size={16} /> Upload Scan
              </button>
            </div>
          )}

          {widgets.length === 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: 300, color: 'var(--text-muted)', gap: 12 }}>
              <LayoutGrid size={48} color="var(--text-muted)" style={{ opacity: 0.4 }} />
              <div style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-secondary)' }}>Canvas is empty</div>
              <div style={{ fontSize: 13, textAlign: 'center', maxWidth: 280 }}>Click any widget from the library on the left to add it to your report</div>
            </div>
          ) : (
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(4, 1fr)',
              gap: 14,
              maxWidth: preview ? 1000 : 'none',
              margin: preview ? '0 auto' : 0,
            }}
              onClick={e => e.stopPropagation()}
            >
              {widgets.map((widget, i) => (
                <CanvasWidget
                  key={widget.id}
                  widget={widget}
                  index={i}
                  total={widgets.length}
                  scanId={activeScanId}
                  isSelected={selectedId === widget.id}
                  preview={preview}
                  onSelect={() => setSelectedId(widget.id === selectedId ? null : widget.id)}
                  onUpdate={updateWidget}
                  onDelete={() => deleteWidget(widget.id)}
                  onMoveUp={() => moveWidget(widget.id, 'up')}
                  onMoveDown={() => moveWidget(widget.id, 'down')}
                />
              ))}
            </div>
          )}
        </div>

        {/* Config panel */}
        {!preview && selectedWidget && (
          <ConfigPanel
            widget={selectedWidget}
            onUpdate={updateWidget}
            onClose={() => setSelectedId(null)}
          />
        )}
      </div>
    </div>
  )
}

// ─── Report list (landing) ────────────────────────────────────────────────────

function ReportList({ reports, onCreate, onOpen, onDelete, onDuplicate, landingId, onSetLanding }) {
  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h2 style={{ fontSize: 18, fontWeight: 700 }}>Reports</h2>
          <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 4 }}>Build and save custom dashboards — set any as your landing page</div>
        </div>
        <button
          onClick={onCreate}
          style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '9px 18px', background: 'var(--accent)', border: 'none', color: '#fff', borderRadius: 8, cursor: 'pointer', fontWeight: 600, fontSize: 14 }}
        >
          <Plus size={16} /> New Report
        </button>
      </div>

      {reports.length === 0 ? (
        <div style={{
          border: '2px dashed var(--border)', borderRadius: 14, padding: '60px 24px',
          display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 14, textAlign: 'center',
        }}>
          <LayoutGrid size={48} color="var(--text-muted)" style={{ opacity: 0.4 }} />
          <div style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-secondary)' }}>No custom reports yet</div>
          <div style={{ fontSize: 13, color: 'var(--text-muted)', maxWidth: 320 }}>
            Create your first report by clicking "New Report". Mix and match widgets — stat cards, charts, tables, and text — and save for reuse.
          </div>
          <button
            onClick={onCreate}
            style={{ marginTop: 4, padding: '9px 20px', background: 'var(--accent)', border: 'none', color: '#fff', borderRadius: 8, cursor: 'pointer', fontWeight: 600, fontSize: 13, display: 'flex', alignItems: 'center', gap: 6 }}
          >
            <Plus size={15} /> Create first report
          </button>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 14 }}>
          {reports.map(report => {
            const isHome = report.id === landingId
            return (
              <div key={report.id} style={{ background: 'var(--bg-card)', border: `1px solid ${isHome ? '#16a34a55' : 'var(--border)'}`, borderRadius: 12, overflow: 'hidden' }}>
                {/* Preview strip */}
                <div style={{ height: 80, background: 'linear-gradient(135deg, #1e2235 0%, #252840 100%)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 16px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    {(report.widgets || []).slice(0, 4).map((w, i) => {
                      const catItem = WIDGET_CATALOGUE.flatMap(c => c.items).find(x => x.type === w.type)
                      const Icon = catItem?.icon || LayoutGrid
                      return (
                        <div key={i} style={{ width: 32, height: 32, borderRadius: 8, background: '#6366f133', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                          <Icon size={15} color="#818cf8" />
                        </div>
                      )
                    })}
                    {(report.widgets || []).length > 4 && (
                      <div style={{ fontSize: 12, color: '#818cf8', fontWeight: 600 }}>+{report.widgets.length - 4}</div>
                    )}
                    {(report.widgets || []).length === 0 && (
                      <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Empty report</div>
                    )}
                  </div>
                  {isHome && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, fontWeight: 600, color: '#16a34a', background: '#16a34a22', padding: '4px 8px', borderRadius: 6 }}>
                      <Home size={11} /> Landing
                    </div>
                  )}
                </div>

                <div style={{ padding: '14px 16px' }}>
                  <div style={{ fontWeight: 700, fontSize: 14, marginBottom: 4 }}>{report.name}</div>
                  <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 14 }}>
                    {(report.widgets || []).length} widget{(report.widgets || []).length !== 1 ? 's' : ''} ·
                    Created {new Date(report.createdAt).toLocaleDateString()}
                  </div>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button onClick={() => onOpen(report)} style={{ flex: 1, padding: '7px', background: 'var(--accent)', border: 'none', color: '#fff', borderRadius: 6, cursor: 'pointer', fontWeight: 600, fontSize: 13 }}>
                      Open
                    </button>
                    {!isHome && (
                      <button onClick={() => onSetLanding(report.id)} title="Set as landing page" style={{ padding: '7px 10px', background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-secondary)', borderRadius: 6, cursor: 'pointer' }}>
                        <Home size={14} />
                      </button>
                    )}
                    <button onClick={() => onDuplicate(report)} title="Duplicate" style={{ padding: '7px 10px', background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-secondary)', borderRadius: 6, cursor: 'pointer' }}>
                      <Copy size={14} />
                    </button>
                    <button onClick={() => onDelete(report.id)} title="Delete" style={{ padding: '7px 10px', background: 'transparent', border: '1px solid var(--border)', color: '#dc2626', borderRadius: 6, cursor: 'pointer' }}>
                      <Trash2 size={14} />
                    </button>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ─── Root export ──────────────────────────────────────────────────────────────

export default function ReportBuilder() {
  const [reports, setReports] = useState(() => {
    const saved = loadReports()
    if (saved.length === 0) {
      saveReports([DEFAULT_DASHBOARD])
      return [DEFAULT_DASHBOARD]
    }
    return saved
  })
  const [landingId, setLandingId] = useState(loadLandingId)
  const [activeReport, setActiveReport] = useState(() => {
    // Auto-open the landing report on first load
    const id = loadLandingId()
    const saved = loadReports()
    const all = saved.length === 0 ? [DEFAULT_DASHBOARD] : saved
    return all.find(r => r.id === id) || all[0] || null
  })

  const persistAndSet = (newReports) => {
    setReports(newReports)
    saveReports(newReports)
  }

  const setLanding = (id) => {
    setLandingId(id)
    saveLandingId(id)
  }

  const createReport = () => {
    const report = { id: uid(), name: 'Untitled Report', createdAt: new Date().toISOString(), widgets: [] }
    setActiveReport(report)
  }

  const openReport = (report) => setActiveReport(report)

  const saveReport = (updated) => {
    const existing = reports.find(r => r.id === updated.id)
    if (existing) {
      persistAndSet(reports.map(r => r.id === updated.id ? { ...updated, updatedAt: new Date().toISOString() } : r))
    } else {
      persistAndSet([...reports, { ...updated, updatedAt: new Date().toISOString() }])
    }
    setActiveReport(updated)
  }

  const deleteReport = (id) => {
    if (!confirm('Delete this report?')) return
    const next = reports.filter(r => r.id !== id)
    persistAndSet(next)
    if (activeReport?.id === id) setActiveReport(null)
    if (landingId === id) {
      const fallback = next[0]?.id || DEFAULT_REPORT_ID
      setLanding(fallback)
    }
  }

  const duplicateReport = (report) => {
    const copy = { ...report, id: uid(), name: `${report.name} (copy)`, createdAt: new Date().toISOString(), widgets: report.widgets.map(w => ({ ...w, id: uid() })) }
    persistAndSet([...reports, copy])
  }

  if (activeReport) {
    return (
      <div style={{ margin: '-24px', height: 'calc(100vh - 49px)', display: 'flex', flexDirection: 'column' }}>
        <Builder
          report={activeReport}
          onSave={saveReport}
          onBack={() => setActiveReport(null)}
          isLanding={activeReport.id === landingId}
          onSetLanding={() => setLanding(activeReport.id)}
        />
      </div>
    )
  }

  return (
    <ReportList
      reports={reports}
      onCreate={createReport}
      onOpen={openReport}
      onDelete={deleteReport}
      onDuplicate={duplicateReport}
      landingId={landingId}
      onSetLanding={setLanding}
    />
  )
}
