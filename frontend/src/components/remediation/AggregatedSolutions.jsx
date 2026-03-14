import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Layers, ChevronDown, ChevronUp, ExternalLink, RefreshCw, ArrowRight, Monitor, Shield, Zap } from 'lucide-react'
import { useScan } from '../../App.jsx'
import { getAggregatedSolutions, rebuildAggregatedSolutions } from '../../api.js'
import { Card, PageHeader, Spinner, EmptyState, SeverityBadge, EffortBadge, Select, FilterBar } from '../shared/ui.jsx'

const ROOT_CAUSE_LABELS = {
  eol_software: 'End-of-Life',
  deprecated_protocol: 'Deprecated Protocol',
  outdated_version: 'Outdated Version',
  misconfiguration: 'Misconfiguration',
  missing_patch: 'Missing Patches',
}

const ROOT_CAUSE_COLORS = {
  eol_software: '#dc2626',
  deprecated_protocol: '#ea580c',
  outdated_version: '#d97706',
  misconfiguration: '#7c3aed',
  missing_patch: '#2563eb',
}

const ACTION_LABELS = {
  migrate_to_supported: 'Migrate',
  disable_protocol: 'Disable',
  upgrade_component: 'Upgrade',
  remediate_config: 'Fix Config',
  apply_patch: 'Patch',
  bulk_patch: 'Bulk Patch',
}

const ACTION_ICONS = {
  migrate_to_supported: '🔄',
  disable_protocol: '🚫',
  upgrade_component: '⬆️',
  remediate_config: '🔧',
  apply_patch: '🩹',
  bulk_patch: '📦',
}

function RootCauseBadge({ type }) {
  const color = ROOT_CAUSE_COLORS[type] || '#6b7280'
  const label = ROOT_CAUSE_LABELS[type] || type
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600,
      background: color + '18', color, border: `1px solid ${color}40`,
    }}>
      {label}
    </span>
  )
}

function ActionBadge({ type }) {
  const label = ACTION_LABELS[type] || type
  const icon = ACTION_ICONS[type] || '🔨'
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600,
      background: '#10b98118', color: '#10b981', border: '1px solid #10b98140',
    }}>
      {icon} {label}
    </span>
  )
}

function EfficiencyBar({ score, max = 100 }) {
  const pct = Math.min((score / max) * 100, 100)
  const color = pct > 60 ? '#10b981' : pct > 30 ? '#f59e0b' : '#6b7280'
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ flex: 1, height: 6, borderRadius: 3, background: 'var(--bg-tertiary)', overflow: 'hidden' }}>
        <div style={{ width: pct + '%', height: '100%', borderRadius: 3, background: color, transition: 'width 0.3s' }} />
      </div>
      <span style={{ fontSize: 11, fontWeight: 700, color, minWidth: 36, textAlign: 'right' }}>
        {score.toFixed(1)}
      </span>
    </div>
  )
}

function RecommendationCard({ rec }) {
  const [expanded, setExpanded] = useState(false)
  const navigate = useNavigate()

  return (
    <Card style={{ marginBottom: 12 }}>
      <div
        style={{ cursor: 'pointer', padding: '16px 20px' }}
        onClick={() => setExpanded(!expanded)}
      >
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
          <div style={{ flex: 1 }}>
            {/* Badges row */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8, flexWrap: 'wrap' }}>
              <ActionBadge type={rec.action_type} />
              <RootCauseBadge type={rec.root_cause_type} />
              <SeverityBadge severity={rec.severity_max} />
              <EffortBadge effort={rec.effort_level} />
            </div>

            {/* Title */}
            <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-primary)', lineHeight: 1.4 }}>
              {rec.title}
            </div>

            {/* Stats row */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginTop: 8, fontSize: 12, color: 'var(--text-muted)' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <Shield size={12} />
                {rec.finding_count} findings
              </span>
              {rec.cve_count > 0 && (
                <span>{rec.cve_count} CVEs</span>
              )}
              <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <Monitor size={12} />
                {rec.asset_count} {rec.asset_count === 1 ? 'host' : 'hosts'}
              </span>
              {rec.risk_reduction > 0 && (
                <span style={{ color: '#10b981', fontWeight: 600 }}>
                  {rec.risk_reduction.toFixed(1)}% risk reduction
                </span>
              )}
            </div>

            {/* Version upgrade indicator */}
            {rec.affected_component && (rec.current_version || rec.target_version) && (
              <div style={{
                display: 'inline-flex', alignItems: 'center', gap: 6, marginTop: 8,
                padding: '4px 10px', borderRadius: 6, fontSize: 12, fontWeight: 500,
                background: 'var(--bg-secondary)', color: 'var(--text-secondary)',
              }}>
                {rec.affected_component}
                {rec.current_version && <span style={{ color: 'var(--text-muted)' }}>{rec.current_version}</span>}
                {rec.target_version && (
                  <>
                    <ArrowRight size={12} style={{ color: '#10b981' }} />
                    <span style={{ color: '#10b981', fontWeight: 600 }}>{rec.target_version}</span>
                  </>
                )}
              </div>
            )}

            {/* Efficiency score */}
            <div style={{ marginTop: 8, maxWidth: 200 }}>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 2, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Efficiency
              </div>
              <EfficiencyBar score={rec.efficiency_score} max={Math.max(rec.efficiency_score * 1.5, 50)} />
            </div>
          </div>

          <div style={{ padding: 4, color: 'var(--text-muted)' }}>
            {expanded ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
          </div>
        </div>
      </div>

      {expanded && (
        <div style={{ padding: '0 20px 16px', borderTop: '1px solid var(--border)' }}>
          {/* vs Alternative */}
          {rec.vs_alternative && (
            <div style={{
              marginTop: 14, padding: '10px 14px', borderRadius: 8,
              background: '#10b98110', border: '1px solid #10b98130',
              fontSize: 12, color: '#10b981', fontWeight: 500,
              display: 'flex', alignItems: 'center', gap: 8,
            }}>
              <Zap size={14} />
              {rec.vs_alternative}
            </div>
          )}

          {/* Description */}
          <div style={{
            marginTop: 14, fontSize: 13, color: 'var(--text-secondary)',
            lineHeight: 1.7, whiteSpace: 'pre-wrap',
          }}>
            {rec.description}
          </div>

          {/* Affected hosts */}
          {rec.asset_hostnames && rec.asset_hostnames.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>
                Affected Hosts ({rec.asset_count})
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {rec.asset_hostnames.map((h, i) => (
                  <span key={i} style={{
                    padding: '3px 10px', borderRadius: 4, fontSize: 12,
                    background: 'var(--bg-secondary)', color: 'var(--text-secondary)',
                    border: '1px solid var(--border)',
                  }}>
                    {h}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* CVEs */}
          {rec.cve_ids && rec.cve_ids.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>
                CVEs Resolved ({rec.cve_ids.length})
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                {rec.cve_ids.slice(0, 30).map(cve => (
                  <span key={cve} style={{
                    padding: '2px 6px', borderRadius: 3, fontSize: 10, fontFamily: 'monospace',
                    background: 'var(--bg-tertiary)', color: 'var(--text-muted)',
                  }}>
                    {cve}
                  </span>
                ))}
                {rec.cve_ids.length > 30 && (
                  <span style={{ fontSize: 10, color: 'var(--text-muted)', padding: '2px 4px' }}>
                    +{rec.cve_ids.length - 30} more
                  </span>
                )}
              </div>
            </div>
          )}

          {/* Grouped findings */}
          {rec.finding_ids && rec.finding_ids.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>
                Collapsed Findings ({rec.finding_count})
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {rec.finding_ids.slice(0, 20).map(fid => (
                  <span
                    key={fid}
                    onClick={(e) => { e.stopPropagation(); navigate(`/findings/${fid}`) }}
                    style={{
                      cursor: 'pointer', padding: '2px 8px', borderRadius: 4,
                      fontSize: 11, background: 'var(--bg-secondary)', color: 'var(--text-secondary)',
                      border: '1px solid var(--border)', display: 'inline-flex', alignItems: 'center', gap: 4,
                    }}
                  >
                    <ExternalLink size={10} /> #{fid}
                  </span>
                ))}
                {rec.finding_ids.length > 20 && (
                  <span style={{ fontSize: 11, color: 'var(--text-muted)', padding: '2px 4px' }}>
                    +{rec.finding_ids.length - 20} more
                  </span>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </Card>
  )
}

export default function AggregatedSolutions() {
  const { activeScanId } = useScan()
  const [solutions, setSolutions] = useState([])
  const [loading, setLoading] = useState(true)
  const [rebuilding, setRebuilding] = useState(false)
  const [rootCauseFilter, setRootCauseFilter] = useState('')
  const [sortBy, setSortBy] = useState('efficiency')

  const loadSolutions = () => {
    setLoading(true)
    const params = {}
    if (activeScanId) params.scan_id = activeScanId
    getAggregatedSolutions(params)
      .then(setSolutions)
      .catch(console.error)
      .finally(() => setLoading(false))
  }

  useEffect(() => { loadSolutions() }, [activeScanId])

  const handleRebuild = () => {
    setRebuilding(true)
    rebuildAggregatedSolutions(activeScanId)
      .then(() => loadSolutions())
      .catch(console.error)
      .finally(() => setRebuilding(false))
  }

  // Filter client-side
  const filtered = rootCauseFilter ? solutions.filter(s => s.root_cause_type === rootCauseFilter) : solutions

  // Sort
  const sorted = [...filtered].sort((a, b) => {
    if (sortBy === 'efficiency') return (b.efficiency_score || 0) - (a.efficiency_score || 0)
    if (sortBy === 'risk') return (b.risk_reduction || 0) - (a.risk_reduction || 0)
    if (sortBy === 'severity') return (b.severity_max || 0) - (a.severity_max || 0)
    if (sortBy === 'findings') return (b.finding_count || 0) - (a.finding_count || 0)
    return 0
  })

  const totalFindings = filtered.reduce((sum, s) => sum + s.finding_count, 0)
  const totalCVEs = filtered.reduce((sum, s) => sum + (s.cve_count || 0), 0)
  const totalRiskReduction = filtered.reduce((sum, s) => sum + (s.risk_reduction || 0), 0)

  // Summary stats by root cause
  const rootCauseSummary = {}
  for (const s of solutions) {
    const rc = s.root_cause_type
    if (!rootCauseSummary[rc]) rootCauseSummary[rc] = { count: 0, findings: 0, cves: 0 }
    rootCauseSummary[rc].count++
    rootCauseSummary[rc].findings += s.finding_count
    rootCauseSummary[rc].cves += s.cve_count || 0
  }

  return (
    <div style={{ padding: 24, maxWidth: 1100, margin: '0 auto' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
        <PageHeader
          title="Remediation"
          subtitle={`${filtered.length} actions collapse ${totalFindings} findings (${totalCVEs} CVEs) into single fixes`}
        />
        <button
          onClick={handleRebuild}
          disabled={rebuilding}
          style={{
            display: 'inline-flex', alignItems: 'center', gap: 6,
            padding: '8px 14px', borderRadius: 6, fontSize: 13, fontWeight: 600,
            background: 'var(--bg-secondary)', color: 'var(--text-secondary)',
            border: '1px solid var(--border)', cursor: rebuilding ? 'wait' : 'pointer',
            opacity: rebuilding ? 0.6 : 1,
          }}
        >
          <RefreshCw size={14} style={rebuilding ? { animation: 'spin 1s linear infinite' } : {}} />
          {rebuilding ? 'Rebuilding…' : 'Rebuild'}
        </button>
      </div>

      {/* Top-level KPIs */}
      {solutions.length > 0 && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 20 }}>
          <Card style={{ padding: '14px 18px' }}>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Actions</div>
            <div style={{ fontSize: 28, fontWeight: 700, color: 'var(--text-primary)' }}>{filtered.length}</div>
            <div style={{ fontSize: 11, color: '#10b981' }}>vs {totalFindings} individual fixes</div>
          </Card>
          <Card style={{ padding: '14px 18px' }}>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>CVEs Resolved</div>
            <div style={{ fontSize: 28, fontWeight: 700, color: 'var(--text-primary)' }}>{totalCVEs}</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>collapsed into {filtered.length} actions</div>
          </Card>
          <Card style={{ padding: '14px 18px' }}>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Risk Reduction</div>
            <div style={{ fontSize: 28, fontWeight: 700, color: '#10b981' }}>{totalRiskReduction.toFixed(1)}%</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>of total scan risk</div>
          </Card>
          <Card style={{ padding: '14px 18px' }}>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Efficiency</div>
            <div style={{ fontSize: 28, fontWeight: 700, color: 'var(--text-primary)' }}>
              {totalFindings > 0 ? (totalFindings / filtered.length).toFixed(1) : 0}x
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>avg findings per action</div>
          </Card>
        </div>
      )}

      {/* Root cause stat cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 12, marginBottom: 20 }}>
        {Object.entries(ROOT_CAUSE_LABELS).map(([rc, label]) => {
          const data = rootCauseSummary[rc]
          if (!data) return null
          const color = ROOT_CAUSE_COLORS[rc]
          return (
            <Card
              key={rc}
              onClick={() => setRootCauseFilter(rootCauseFilter === rc ? '' : rc)}
              style={{
                padding: '12px 16px', cursor: 'pointer',
                border: rootCauseFilter === rc ? `2px solid ${color}` : undefined,
              }}
            >
              <div style={{ fontSize: 11, color, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                {label}
              </div>
              <div style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary)', marginTop: 2 }}>
                {data.count}
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                {data.findings} findings · {data.cves} CVEs
              </div>
            </Card>
          )
        })}
      </div>

      {/* Filters */}
      <FilterBar>
        <Select
          value={rootCauseFilter}
          onChange={setRootCauseFilter}
          options={[
            { value: '', label: 'All Root Causes' },
            ...Object.entries(ROOT_CAUSE_LABELS).map(([v, l]) => ({ value: v, label: l })),
          ]}
        />
        <Select
          value={sortBy}
          onChange={setSortBy}
          options={[
            { value: 'efficiency', label: 'Sort: Efficiency' },
            { value: 'risk', label: 'Sort: Risk Reduction' },
            { value: 'severity', label: 'Sort: Severity' },
            { value: 'findings', label: 'Sort: Finding Count' },
          ]}
        />
      </FilterBar>

      {loading ? (
        <Spinner />
      ) : solutions.length === 0 ? (
        <EmptyState
          icon={Layers}
          title="No remediation actions"
          sub={activeScanId
            ? 'Click "Rebuild" to analyze findings, or upload a scan with related vulnerabilities'
            : 'Select a scan to view remediation actions'}
        />
      ) : (
        sorted.map(s => <RecommendationCard key={s.id} rec={s} />)
      )}
    </div>
  )
}
