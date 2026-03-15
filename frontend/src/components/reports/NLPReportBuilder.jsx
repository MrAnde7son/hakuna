/**
 * NLPReportBuilder — natural language query → instant report
 * Type a query like "show critical findings on Windows assets" and get a live report.
 */
import React, { useState, useRef } from 'react'
import { Search, Sparkles, X, AlertTriangle, ChevronRight, Shield, Server, Zap, Save, CheckCircle } from 'lucide-react'
import { nlpReportQuery, createReportTemplate } from '../../api.js'
import { useScan } from '../../App.jsx'
import { SeverityBadge, Card, ScoreBar } from '../shared/ui.jsx'

const EXAMPLE_QUERIES = [
  'show me all critical findings on Windows assets',
  'critical and high findings with known exploits',
  'quick wins in production environment',
  'SLA breached findings sorted by priority',
  'findings with CVSS above 9',
  'ransomware-linked vulnerabilities',
  'KEV findings on Linux hosts',
  'critical assets with more than 5 critical findings',
  'zero-day vulnerabilities on internet-facing assets',
  'regression findings that came back',
  'findings with MITRE ATT&CK lateral movement tactics',
  'false positives and accepted risk findings',
  'findings on port 443 with VPR above 7',
  'stale assets not recently scanned',
  'high-value assets with critical findings in DMZ',
  'findings tagged with PCI',
]

const SEV_COLORS = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#d97706',
  low: '#65a30d',
  info: '#0ea5e9',
}

function ChipBar({ chips }) {
  if (!chips?.length) return null
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 10 }}>
      {chips.map((c, i) => (
        <span key={i} style={{
          display: 'inline-flex', alignItems: 'center', gap: 5,
          background: c.color + '22', color: c.color,
          border: `1px solid ${c.color}55`,
          borderRadius: 20, padding: '3px 10px', fontSize: 12, fontWeight: 600,
        }}>
          <span style={{ opacity: 0.7, fontWeight: 400 }}>{c.label}:</span>
          {c.value}
        </span>
      ))}
    </div>
  )
}

function SummaryStat({ label, value, color, icon: Icon }) {
  return (
    <div style={{
      background: 'var(--bg-card)', border: '1px solid var(--border)',
      borderRadius: 10, padding: '14px 18px',
      display: 'flex', alignItems: 'center', gap: 12,
    }}>
      {Icon && (
        <div style={{
          width: 36, height: 36, borderRadius: 8,
          background: color + '22', display: 'flex', alignItems: 'center', justifyContent: 'center',
          flexShrink: 0,
        }}>
          <Icon size={18} color={color} />
        </div>
      )}
      <div>
        <div style={{ fontSize: 24, fontWeight: 700, color: color || 'var(--text)' }}>{value?.toLocaleString()}</div>
        <div style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{label}</div>
      </div>
    </div>
  )
}

function SeverityBreakdown({ byS }) {
  if (!byS) return null
  const order = ['critical', 'high', 'medium', 'low', 'info']
  const total = order.reduce((s, k) => s + (byS[k] || 0), 0)
  if (!total) return null
  return (
    <Card style={{ padding: '16px 20px' }}>
      <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 12 }}>Severity Breakdown</div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {order.map(s => {
          const count = byS[s] || 0
          if (!count) return null
          const pct = total ? Math.round((count / total) * 100) : 0
          return (
            <div key={s} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ minWidth: 60, fontSize: 12, fontWeight: 600, color: SEV_COLORS[s], textTransform: 'capitalize' }}>{s}</span>
              <div style={{ flex: 1, height: 8, background: 'var(--border)', borderRadius: 4, overflow: 'hidden' }}>
                <div style={{ width: `${pct}%`, height: '100%', background: SEV_COLORS[s], borderRadius: 4, transition: 'width 0.4s ease' }} />
              </div>
              <span style={{ minWidth: 40, fontSize: 12, fontWeight: 600, color: 'var(--text)', textAlign: 'right' }}>{count.toLocaleString()}</span>
            </div>
          )
        })}
      </div>
    </Card>
  )
}

function FindingsTable({ findings }) {
  if (!findings?.length) return null
  return (
    <Card style={{ padding: 0, overflow: 'hidden' }}>
      <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{ fontSize: 13, fontWeight: 600 }}>Top Findings</span>
        <span style={{ fontSize: 12, color: 'var(--muted)' }}>Sorted by priority score</span>
      </div>
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)' }}>
              {['Severity', 'Plugin Name', 'Family', 'CVSS3', 'Priority', 'Exploit', 'KEV', 'Effort', 'Port', 'Workflow'].map(h => (
                <th key={h} style={{ padding: '8px 12px', textAlign: 'left', color: 'var(--muted)', fontWeight: 600, whiteSpace: 'nowrap', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.04em' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {findings.map((f, i) => (
              <tr key={f.id} style={{ borderBottom: '1px solid var(--border)', background: i % 2 === 0 ? 'transparent' : 'var(--bg-subtle)' }}>
                <td style={{ padding: '8px 12px', whiteSpace: 'nowrap' }}>
                  <SeverityBadge severity={f.severity} label={f.severity_label} />
                </td>
                <td style={{ padding: '8px 12px', maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text)' }}>
                  <span title={f.plugin_name}>{f.plugin_name}</span>
                </td>
                <td style={{ padding: '8px 12px', color: 'var(--muted)', whiteSpace: 'nowrap' }}>{f.plugin_family || '—'}</td>
                <td style={{ padding: '8px 12px', whiteSpace: 'nowrap' }}>
                  {f.cvss3_score != null ? (
                    <span style={{ fontWeight: 600, color: f.cvss3_score >= 9 ? '#dc2626' : f.cvss3_score >= 7 ? '#ea580c' : '#d97706' }}>{f.cvss3_score.toFixed(1)}</span>
                  ) : '—'}
                </td>
                <td style={{ padding: '8px 12px', whiteSpace: 'nowrap' }}>
                  {f.priority_score != null ? (
                    <span style={{ fontWeight: 600, color: f.priority_score >= 8 ? '#dc2626' : f.priority_score >= 6 ? '#ea580c' : 'var(--text)' }}>{f.priority_score.toFixed(1)}</span>
                  ) : '—'}
                </td>
                <td style={{ padding: '8px 12px', whiteSpace: 'nowrap' }}>
                  {f.exploit_available ? <span style={{ color: '#ef4444', fontWeight: 700 }}>Yes</span> : <span style={{ color: 'var(--muted)' }}>No</span>}
                </td>
                <td style={{ padding: '8px 12px', whiteSpace: 'nowrap' }}>
                  {f.is_kev ? <span style={{ color: '#b91c1c', fontWeight: 700, fontSize: 11 }}>KEV</span> : <span style={{ color: 'var(--muted)' }}>—</span>}
                </td>
                <td style={{ padding: '8px 12px', whiteSpace: 'nowrap' }}>
                  {f.effort_level ? (
                    <span style={{
                      fontSize: 10, fontWeight: 600, padding: '2px 7px', borderRadius: 10, textTransform: 'capitalize',
                      background: f.effort_level === 'quick_win' ? '#16a34a22' : f.effort_level === 'complex' ? '#dc262622' : '#d9770622',
                      color: f.effort_level === 'quick_win' ? '#16a34a' : f.effort_level === 'complex' ? '#dc2626' : '#d97706',
                      border: `1px solid ${f.effort_level === 'quick_win' ? '#16a34a44' : f.effort_level === 'complex' ? '#dc262644' : '#d9770644'}`,
                    }}>
                      {f.effort_level.replace('_', ' ')}
                    </span>
                  ) : '—'}
                </td>
                <td style={{ padding: '8px 12px', whiteSpace: 'nowrap', color: 'var(--muted)' }}>
                  {f.port || '—'}
                </td>
                <td style={{ padding: '8px 12px', whiteSpace: 'nowrap' }}>
                  {f.workflow_status ? (
                    <span style={{
                      fontSize: 10, fontWeight: 600, padding: '2px 7px', borderRadius: 10, textTransform: 'capitalize',
                      background: f.workflow_status === 'resolved' ? '#16a34a22' : f.workflow_status === 'in_progress' ? '#3b82f622' : f.workflow_status === 'accepted_risk' ? '#8b5cf622' : '#6b728022',
                      color: f.workflow_status === 'resolved' ? '#16a34a' : f.workflow_status === 'in_progress' ? '#3b82f6' : f.workflow_status === 'accepted_risk' ? '#8b5cf6' : '#6b7280',
                    }}>
                      {f.workflow_status.replace(/_/g, ' ')}
                    </span>
                  ) : '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  )
}

function AssetsTable({ assets }) {
  if (!assets?.length) return null
  return (
    <Card style={{ padding: 0, overflow: 'hidden' }}>
      <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{ fontSize: 13, fontWeight: 600 }}>Matching Assets</span>
        <span style={{ fontSize: 12, color: 'var(--muted)' }}>By risk score</span>
      </div>
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)' }}>
              {['Host / IP', 'OS', 'Environment', 'Risk Score', 'Critical', 'High', 'Medium'].map(h => (
                <th key={h} style={{ padding: '8px 12px', textAlign: 'left', color: 'var(--muted)', fontWeight: 600, whiteSpace: 'nowrap', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.04em' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {assets.map((a, i) => (
              <tr key={a.id} style={{ borderBottom: '1px solid var(--border)', background: i % 2 === 0 ? 'transparent' : 'var(--bg-subtle)' }}>
                <td style={{ padding: '8px 12px' }}>
                  <div style={{ fontWeight: 600, color: 'var(--text)' }}>{a.hostname || a.fqdn || a.ip}</div>
                  {(a.hostname || a.fqdn) && <div style={{ fontSize: 11, color: 'var(--muted)' }}>{a.ip}</div>}
                </td>
                <td style={{ padding: '8px 12px', color: 'var(--muted)', maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  <span title={a.os}>{a.os || '—'}</span>
                </td>
                <td style={{ padding: '8px 12px', color: 'var(--muted)', textTransform: 'capitalize' }}>{a.environment_tag || '—'}</td>
                <td style={{ padding: '8px 12px', minWidth: 100 }}>
                  <ScoreBar score={a.risk_score || 0} max={10} />
                </td>
                <td style={{ padding: '8px 12px', fontWeight: 700, color: a.critical_count > 0 ? '#dc2626' : 'var(--muted)' }}>{a.critical_count}</td>
                <td style={{ padding: '8px 12px', fontWeight: 600, color: a.high_count > 0 ? '#ea580c' : 'var(--muted)' }}>{a.high_count}</td>
                <td style={{ padding: '8px 12px', color: a.medium_count > 0 ? '#d97706' : 'var(--muted)' }}>{a.medium_count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  )
}

function uid() {
  return Math.random().toString(36).slice(2, 10)
}

/** Build a set of report widgets from an NLP query result. */
function buildWidgetsFromResult(result) {
  const ff = result.parsed_filters?.finding_filters || {}
  const af = result.parsed_filters?.asset_filters || {}
  const hasAssetFilters = Object.keys(af).length > 0
  const hasFindingFilters = Object.keys(ff).length > 0
  const chipText = result.explanation?.map(c => `${c.label}: ${c.value}`).join(' · ') || ''

  const widgets = []

  // Section header
  widgets.push({
    id: uid(), type: 'header', title: '', width: 'full',
    config: { title: result.original_query, subtitle: chipText || 'Generated by AI Query' },
  })

  // Stat cards row
  widgets.push({
    id: uid(), type: 'card', title: 'Matching Findings', width: 'quarter',
    config: { preset: 'finding_count_filtered', filters: hasFindingFilters ? ff : {} },
  })
  widgets.push({
    id: uid(), type: 'card', title: 'Matching Assets', width: 'quarter',
    config: { preset: 'asset_count_filtered', filters: hasAssetFilters ? af : {} },
  })
  // Show critical/high stat cards if relevant
  if (!ff.severity || ff.severity >= 3) {
    widgets.push({
      id: uid(), type: 'card', title: 'Critical Findings', width: 'quarter',
      config: { preset: 'critical_count' },
    })
    widgets.push({
      id: uid(), type: 'card', title: 'High Findings', width: 'quarter',
      config: { preset: 'high_count' },
    })
  }

  // Contextual stat cards based on query type
  if (ff.has_exploit || ff.is_kev) {
    widgets.push({
      id: uid(), type: 'card', title: 'Known Exploits', width: 'quarter',
      config: { preset: 'exploit_count' },
    })
  }
  if (ff.sla_status) {
    widgets.push({
      id: uid(), type: 'card', title: 'SLA Breached', width: 'quarter',
      config: { preset: 'sla_breached' },
    })
    widgets.push({
      id: uid(), type: 'card', title: 'SLA Compliance', width: 'quarter',
      config: { preset: 'sla_compliance' },
    })
  }
  if (ff.effort_level === 'quick_win') {
    widgets.push({
      id: uid(), type: 'card', title: 'Quick Wins', width: 'quarter',
      config: { preset: 'quick_wins' },
    })
  }
  if (ff.is_regression) {
    widgets.push({
      id: uid(), type: 'card', title: 'Regressions', width: 'quarter',
      config: { preset: 'regression_count' },
    })
  }

  // Severity breakdown pie (shows severity mix in results)
  widgets.push({
    id: uid(), type: 'pie_chart', title: 'Severity Distribution', width: 'half',
    config: { preset: 'severity_breakdown', donut: true, filters: hasFindingFilters ? ff : {} },
  })

  // Contextual charts based on query type
  if (ff.sla_status || ff.sla_status === undefined) {
    // If SLA-related query, add SLA breakdown
    if (ff.sla_status) {
      widgets.push({
        id: uid(), type: 'pie_chart', title: 'SLA Status', width: 'half',
        config: { preset: 'sla_status', donut: true },
      })
    }
  }

  if (ff.effort_level) {
    widgets.push({
      id: uid(), type: 'pie_chart', title: 'Effort Distribution', width: 'half',
      config: { preset: 'effort_breakdown', donut: true },
    })
  }

  if (ff.has_ttps || ff.tactic || ff.technique_id) {
    // Show severity trend for ATT&CK related queries
    widgets.push({
      id: uid(), type: 'bar_chart', title: 'Severity Breakdown', width: 'half',
      config: { preset: 'severity_breakdown' },
    })
  }

  // Add trend line for broader queries (no narrow single-filter)
  const narrowFilters = ['cve', 'port', 'search']
  const isNarrow = narrowFilters.some(k => ff[k]) && Object.keys(ff).length <= 2
  if (!isNarrow) {
    widgets.push({
      id: uid(), type: 'line_chart', title: 'Severity Trend', width: 'full',
      config: { preset: 'severity_trend' },
    })
  }

  // Findings table with NLP filters applied
  widgets.push({
    id: uid(), type: 'table', title: 'Findings', width: 'full',
    config: { preset: 'findings_list', filters: hasFindingFilters ? { ...ff, page_size: 25 } : { page_size: 25 } },
  })

  // Quick wins table if effort-related
  if (ff.effort_level === 'quick_win') {
    widgets.push({
      id: uid(), type: 'table', title: 'Quick Wins', width: 'full',
      config: { preset: 'quick_wins_table' },
    })
  }

  // Assets table if asset filters were used
  if (hasAssetFilters) {
    widgets.push({
      id: uid(), type: 'table', title: 'Matching Assets', width: 'full',
      config: { preset: 'asset_list', filters: af },
    })
  }

  return widgets
}

export default function NLPReportBuilder() {
  const { activeScanId } = useScan()
  const [query, setQuery] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const [saving, setSaving] = useState(false)
  const [savedName, setSavedName] = useState(null)
  const inputRef = useRef(null)

  async function runQuery(q) {
    const text = (q || query).trim()
    if (!text) return
    setLoading(true)
    setError(null)
    setResult(null)
    setSavedName(null)
    try {
      const data = await nlpReportQuery(text, activeScanId)
      setResult(data)
    } catch (e) {
      setError(e.message || 'Query failed')
    } finally {
      setLoading(false)
    }
  }

  async function saveAsTemplate() {
    if (!result) return
    setSaving(true)
    try {
      const widgets = buildWidgetsFromResult(result)
      const name = result.original_query.slice(0, 60)
      await createReportTemplate({
        name,
        description: `AI-generated report for: "${result.original_query}"`,
        config: { widgets, createdAt: new Date().toISOString() },
      })
      setSavedName(name)
    } catch (e) {
      setError(e.message || 'Failed to save template')
    } finally {
      setSaving(false)
    }
  }

  function handleKeyDown(e) {
    if (e.key === 'Enter') runQuery()
  }

  function useExample(q) {
    setQuery(q)
    runQuery(q)
    inputRef.current?.focus()
  }

  function clear() {
    setQuery('')
    setResult(null)
    setError(null)
    inputRef.current?.focus()
  }

  const hasResult = result && !loading

  return (
    <div style={{ maxWidth: 1200, margin: '0 auto' }}>
      {/* Header */}
      <div style={{ marginBottom: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
          <Sparkles size={20} color="#6366f1" />
          <h2 style={{ fontSize: 18, fontWeight: 700, margin: 0 }}>AI Report Query</h2>
        </div>
        <p style={{ fontSize: 13, color: 'var(--muted)', margin: 0 }}>
          Describe the data you want in plain English and get an instant report.
          {activeScanId ? ' Scoped to active scan.' : ' Querying across all scans.'}
        </p>
      </div>

      {/* Search bar */}
      <div style={{ position: 'relative', marginBottom: 12 }}>
        <Search size={16} style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)', color: 'var(--muted)', pointerEvents: 'none' }} />
        <input
          ref={inputRef}
          value={query}
          onChange={e => setQuery(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder='e.g. "show me critical findings on Windows assets with known exploits"'
          style={{
            width: '100%', boxSizing: 'border-box',
            padding: '12px 120px 12px 40px',
            background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: 10, fontSize: 14, color: 'var(--text)',
            outline: 'none',
          }}
          onFocus={e => e.target.style.borderColor = '#6366f1'}
          onBlur={e => e.target.style.borderColor = 'var(--border)'}
        />
        {query && (
          <button
            onClick={clear}
            style={{
              position: 'absolute', right: 90, top: '50%', transform: 'translateY(-50%)',
              background: 'none', border: 'none', cursor: 'pointer', padding: 4,
              color: 'var(--muted)', display: 'flex', alignItems: 'center',
            }}
          >
            <X size={14} />
          </button>
        )}
        <button
          onClick={() => runQuery()}
          disabled={!query.trim() || loading}
          style={{
            position: 'absolute', right: 8, top: '50%', transform: 'translateY(-50%)',
            background: loading || !query.trim() ? 'var(--border)' : '#6366f1',
            color: loading || !query.trim() ? 'var(--muted)' : '#fff',
            border: 'none', borderRadius: 7, padding: '7px 16px',
            fontSize: 13, fontWeight: 600, cursor: loading || !query.trim() ? 'not-allowed' : 'pointer',
            transition: 'background 0.15s',
          }}
        >
          {loading ? 'Querying…' : 'Generate'}
        </button>
      </div>

      {/* Example queries */}
      {!hasResult && !loading && (
        <div style={{ marginBottom: 28 }}>
          <div style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>Try an example</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {EXAMPLE_QUERIES.map(q => (
              <button
                key={q}
                onClick={() => useExample(q)}
                style={{
                  background: 'var(--bg-card)', border: '1px solid var(--border)',
                  borderRadius: 20, padding: '5px 12px', fontSize: 12, color: 'var(--text)',
                  cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 5,
                  transition: 'border-color 0.15s, background 0.15s',
                }}
                onMouseEnter={e => { e.currentTarget.style.borderColor = '#6366f1'; e.currentTarget.style.background = '#6366f111' }}
                onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.background = 'var(--bg-card)' }}
              >
                <ChevronRight size={11} color="#6366f1" />
                {q}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Loading */}
      {loading && (
        <div style={{ textAlign: 'center', padding: '48px 0', color: 'var(--muted)' }}>
          <div style={{ marginBottom: 12 }}>
            <Sparkles size={32} color="#6366f1" />
          </div>
          <div style={{ fontSize: 14 }}>Generating report…</div>
        </div>
      )}

      {/* Error */}
      {error && (
        <div style={{
          background: '#450a0a', border: '1px solid #991b1b', borderRadius: 10,
          padding: '14px 18px', display: 'flex', alignItems: 'center', gap: 10, color: '#fca5a5',
          marginBottom: 20,
        }}>
          <AlertTriangle size={16} />
          {error}
        </div>
      )}

      {/* Results */}
      {hasResult && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {/* Explanation chips */}
          {result.explanation?.length > 0 && (
            <div>
              <div style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 6 }}>Interpreted as</div>
              <ChipBar chips={result.explanation} />
            </div>
          )}

          {/* Summary stats */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 12 }}>
            <SummaryStat label="Matching Findings" value={result.summary.total_findings} color="#6366f1" icon={Shield} />
            <SummaryStat label="Matching Assets" value={result.summary.total_assets} color="#0ea5e9" icon={Server} />
            {result.summary.by_severity?.critical > 0 && (
              <SummaryStat label="Critical" value={result.summary.by_severity.critical} color="#dc2626" icon={AlertTriangle} />
            )}
            {result.summary.by_severity?.high > 0 && (
              <SummaryStat label="High" value={result.summary.by_severity.high} color="#ea580c" icon={Zap} />
            )}
          </div>

          {/* No results */}
          {result.summary.total_findings === 0 && result.summary.total_assets === 0 && (
            <Card style={{ textAlign: 'center', padding: '40px 20px', color: 'var(--muted)' }}>
              <Shield size={32} style={{ marginBottom: 12, opacity: 0.4 }} />
              <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 4 }}>No results found</div>
              <div style={{ fontSize: 13 }}>Try broadening your query or removing some filters.</div>
            </Card>
          )}

          {/* Severity breakdown + assets side by side */}
          {(result.summary.total_findings > 0 || result.summary.total_assets > 0) && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <SeverityBreakdown byS={result.summary.by_severity} />
              {result.assets?.length > 0 && (
                <Card style={{ padding: '16px 20px' }}>
                  <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 12 }}>
                    Top Affected Assets ({result.summary.total_assets})
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {result.assets.slice(0, 5).map(a => (
                      <div key={a.id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                        <div style={{ minWidth: 0 }}>
                          <div style={{ fontSize: 13, fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {a.hostname || a.fqdn || a.ip}
                          </div>
                          <div style={{ fontSize: 11, color: 'var(--muted)' }}>{a.ip}{a.os ? ` · ${a.os.split(' ')[0]}` : ''}</div>
                        </div>
                        <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
                          {a.critical_count > 0 && <span style={{ fontSize: 11, fontWeight: 700, color: '#dc2626' }}>{a.critical_count}C</span>}
                          {a.high_count > 0 && <span style={{ fontSize: 11, fontWeight: 600, color: '#ea580c' }}>{a.high_count}H</span>}
                        </div>
                        <div style={{ minWidth: 80 }}>
                          <ScoreBar score={a.risk_score || 0} max={10} />
                        </div>
                      </div>
                    ))}
                    {result.assets.length > 5 && (
                      <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 4 }}>
                        +{result.assets.length - 5} more assets below
                      </div>
                    )}
                  </div>
                </Card>
              )}
            </div>
          )}

          {/* Findings table */}
          {result.findings?.length > 0 && (
            <FindingsTable findings={result.findings} />
          )}

          {/* Assets table */}
          {result.assets?.length > 0 && (
            <AssetsTable assets={result.assets} />
          )}

          {/* Footer: save as template + note */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingBottom: 8 }}>
            <div style={{ fontSize: 12, color: 'var(--muted)' }}>
              Showing up to 50 findings and 20 assets · {result.summary.total_findings.toLocaleString()} total findings matched
            </div>
            {savedName ? (
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13, color: '#16a34a', fontWeight: 600 }}>
                <CheckCircle size={15} />
                Saved as "{savedName}"
              </div>
            ) : (
              <button
                onClick={saveAsTemplate}
                disabled={saving}
                style={{
                  display: 'flex', alignItems: 'center', gap: 6,
                  padding: '7px 14px', borderRadius: 7, fontSize: 13, fontWeight: 600,
                  background: saving ? 'var(--border)' : '#6366f1',
                  color: saving ? 'var(--muted)' : '#fff',
                  border: 'none', cursor: saving ? 'not-allowed' : 'pointer',
                  transition: 'background 0.15s',
                }}
              >
                <Save size={14} />
                {saving ? 'Saving…' : 'Save as Template'}
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
