import React, { useState, useEffect, useRef } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Layers, ChevronDown, ChevronUp, ExternalLink, RefreshCw, ArrowRight, Monitor, Shield, Zap, AlertTriangle, Info, CheckCircle } from 'lucide-react'
import { useScan } from '../../App.jsx'
import { getAggregatedSolutions, rebuildAggregatedSolutions } from '../../api.js'
import { Card, PageHeader, Spinner, EmptyState, SeverityBadge, EffortBadge, Select, FilterBar } from '../shared/ui.jsx'

const ROOT_CAUSE_KEYS = ['eol_software', 'deprecated_protocol', 'outdated_version', 'misconfiguration', 'missing_patch']

const ROOT_CAUSE_COLORS = {
  eol_software: '#dc2626',
  deprecated_protocol: '#ea580c',
  outdated_version: '#d97706',
  misconfiguration: '#7c3aed',
  missing_patch: '#2563eb',
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
  const { t } = useTranslation()
  const color = ROOT_CAUSE_COLORS[type] || '#6b7280'
  const label = t(`aggregated.rootCauseLabels.${type}`, type)
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
  const { t } = useTranslation()
  const label = t(`aggregated.actionLabels.${type}`, type)
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

const VERDICT_STYLES = {
  high_risk: { bg: '#dc262618', border: '#dc262640', color: '#dc2626', icon: AlertTriangle, label: 'High Risk' },
  needs_review: { bg: '#f59e0b18', border: '#f59e0b40', color: '#f59e0b', icon: Info, label: 'Needs Review' },
  safe: { bg: '#10b98118', border: '#10b98140', color: '#10b981', icon: CheckCircle, label: 'Safe' },
}

function VerdictBadge({ verdict }) {
  const style = VERDICT_STYLES[verdict]
  if (!style) return null
  const Icon = style.icon
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600,
      background: style.bg, color: style.color, border: `1px solid ${style.border}`,
    }}>
      <Icon size={11} /> {style.label}
    </span>
  )
}

function DownstreamImpactBanner({ impact }) {
  if (!impact) return null
  const style = VERDICT_STYLES[impact.verdict] || VERDICT_STYLES.safe
  const Icon = style.icon
  const remainingCount = impact.introduced_cves?.length || 0
  const wasUpgraded = impact.upgraded_to && impact.original_version

  return (
    <div style={{
      marginTop: 14, padding: '12px 16px', borderRadius: 8,
      background: style.bg, border: `1px solid ${style.border}`,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
        <Icon size={16} style={{ color: style.color }} />
        <span style={{ fontSize: 13, fontWeight: 700, color: style.color }}>
          Post-Upgrade Assessment: {style.label}
        </span>
        <span style={{ fontSize: 12, color: 'var(--text-muted)', marginLeft: 'auto' }}>
          {remainingCount === 0
            ? 'No known CVEs remain after upgrade'
            : `${remainingCount} CVE${remainingCount !== 1 ? 's' : ''} remain post-upgrade`
          }
        </span>
      </div>

      {wasUpgraded && (
        <div style={{
          fontSize: 12, color: 'var(--text-secondary)', marginBottom: 8,
          padding: '6px 10px', borderRadius: 4, background: 'var(--bg-secondary)',
        }}>
          Auto-selected <strong>{impact.upgraded_to}</strong> over {impact.original_version} as the best available target version
        </div>
      )}

      {remainingCount > 0 && (
        <div style={{ marginTop: 8 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 6 }}>
            CVEs Remaining Post-Upgrade ({remainingCount})
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
            {impact.introduced_cves.slice(0, 20).map(cve => (
              <span key={cve.cve_id} style={{
                padding: '2px 8px', borderRadius: 3, fontSize: 10, fontFamily: 'monospace',
                background: cve.severity === 'critical' ? '#dc262620' : cve.severity === 'high' ? '#ea580c20' : 'var(--bg-tertiary)',
                color: cve.severity === 'critical' ? '#dc2626' : cve.severity === 'high' ? '#ea580c' : 'var(--text-muted)',
                fontWeight: cve.severity === 'critical' || cve.severity === 'high' ? 600 : 400,
              }}>
                {cve.cve_id} ({cve.severity}{cve.cvss3_score ? ` ${cve.cvss3_score}` : ''})
              </span>
            ))}
            {remainingCount > 20 && (
              <span style={{ fontSize: 10, color: 'var(--text-muted)', padding: '2px 4px' }}>
                +{remainingCount - 20} more
              </span>
            )}
          </div>
        </div>
      )}

      {impact.alternative_versions && impact.alternative_versions.length > 0 && (
        <div style={{ marginTop: 10 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 6 }}>
            Other Versions Considered
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {impact.alternative_versions.map(alt => {
              const altStyle = VERDICT_STYLES[alt.verdict] || VERDICT_STYLES.safe
              return (
                <div key={alt.version} style={{
                  padding: '6px 12px', borderRadius: 6, fontSize: 12,
                  background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                  display: 'flex', alignItems: 'center', gap: 8,
                }}>
                  <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{alt.version}</span>
                  <span style={{ fontSize: 10, color: altStyle.color, fontWeight: 600 }}>
                    {alt.verdict === 'safe' ? 'Safe' : alt.verdict === 'needs_review' ? 'Review' : 'Risk'}
                  </span>
                  <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                    {alt.introduced_cve_count} CVE{alt.introduced_cve_count !== 1 ? 's' : ''} remain
                  </span>
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}

function RecommendationCard({ rec, highlighted }) {
  const { t } = useTranslation()
  const [expanded, setExpanded] = useState(highlighted || false)
  const navigate = useNavigate()
  const cardRef = useRef(null)

  useEffect(() => {
    if (highlighted && cardRef.current) {
      cardRef.current.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }
  }, [highlighted])

  return (
    <div ref={cardRef}>
    <Card style={{ marginBottom: 12, ...(highlighted ? { outline: '2px solid #7c3aed', outlineOffset: 2 } : {}) }}>
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
              {rec.downstream_impact && rec.downstream_impact.verdict !== 'safe' && (
                <VerdictBadge verdict={rec.downstream_impact.verdict} />
              )}
            </div>

            {/* Title */}
            <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-primary)', lineHeight: 1.4 }}>
              {rec.title}
            </div>

            {/* Stats row */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginTop: 8, fontSize: 12, color: 'var(--text-muted)' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <Shield size={12} />
                {rec.finding_count} {t('aggregated.affectedFindings').toLowerCase()}
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
                {t('aggregated.efficiency')}
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

          {/* Downstream impact assessment */}
          <DownstreamImpactBanner impact={rec.downstream_impact} />

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
                {t('aggregated.affectedAssets')} ({rec.asset_count})
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
                {t('aggregated.affectedFindings')} ({rec.finding_count})
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
    </div>
  )
}

export default function AggregatedSolutions() {
  const { t } = useTranslation()
  const { activeScanId } = useScan()
  const [searchParams] = useSearchParams()
  const highlightId = searchParams.get('highlight')
  const [solutions, setSolutions] = useState([])
  const [findingPriorityMap, setFindingPriorityMap] = useState({})
  const [totalScanRisk, setTotalScanRisk] = useState(0)
  const [loading, setLoading] = useState(true)
  const [rebuilding, setRebuilding] = useState(false)
  const [rootCauseFilter, setRootCauseFilter] = useState('')
  const [sortBy, setSortBy] = useState('efficiency')

  const loadSolutions = () => {
    setLoading(true)
    const params = {}
    if (activeScanId) params.scan_id = activeScanId
    getAggregatedSolutions(params)
      .then(data => {
        setSolutions(data.solutions || [])
        setFindingPriorityMap(data.finding_priority_map || {})
        setTotalScanRisk(data.total_scan_risk || 0)
      })
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

  // Deduplicate finding IDs across all filtered solutions before summing
  // priority scores — a finding may appear in multiple solution groups, and
  // naively summing per-solution risk_reduction would double-count it.
  const uniqueFindingIds = new Set(filtered.flatMap(s => s.finding_ids || []))
  const deduplicatedRiskSum = [...uniqueFindingIds].reduce(
    (sum, fid) => sum + (findingPriorityMap[fid] || 0), 0
  )
  const totalRiskReduction = totalScanRisk > 0 && deduplicatedRiskSum > 0
    ? (deduplicatedRiskSum / totalScanRisk) * 100
    // Fallback for old solution records without finding_ids stored: cap at 100%
    : Math.min(filtered.reduce((sum, s) => sum + (s.risk_reduction || 0), 0), 100)

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
          title={t('aggregated.title')}
          subtitle={t('aggregated.subtitle')}
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
          {rebuilding ? t('aggregated.rebuilding') : t('aggregated.rebuild')}
        </button>
      </div>

      {/* Top-level KPIs */}
      {solutions.length > 0 && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 20 }}>
          <Card style={{ padding: '14px 18px' }}>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>{t('common.actions')}</div>
            <div style={{ fontSize: 28, fontWeight: 700, color: 'var(--text-primary)' }}>{filtered.length}</div>
            <div style={{ fontSize: 11, color: '#10b981' }}>vs {totalFindings} individual fixes</div>
          </Card>
          <Card style={{ padding: '14px 18px' }}>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>CVEs Resolved</div>
            <div style={{ fontSize: 28, fontWeight: 700, color: 'var(--text-primary)' }}>{totalCVEs.toLocaleString()}</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>collapsed into {filtered.length} actions</div>
          </Card>
          <Card style={{ padding: '14px 18px' }}>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Risk Reduction</div>
            <div style={{ fontSize: 28, fontWeight: 700, color: '#10b981' }}>{totalRiskReduction.toFixed(1)}%</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>of total scan risk</div>
          </Card>
          <Card style={{ padding: '14px 18px' }}>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>{t('aggregated.efficiency')}</div>
            <div style={{ fontSize: 28, fontWeight: 700, color: 'var(--text-primary)' }}>
              {totalFindings > 0 ? (totalFindings / filtered.length).toFixed(1) : 0}x
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>avg findings per action</div>
          </Card>
        </div>
      )}

      {/* Root cause stat cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 12, marginBottom: 20 }}>
        {ROOT_CAUSE_KEYS.map(rc => {
          const data = rootCauseSummary[rc]
          if (!data) return null
          const color = ROOT_CAUSE_COLORS[rc]
          const label = t(`aggregated.rootCauseLabels.${rc}`, rc)
          const isActive = rootCauseFilter === rc
          return (
            <Card
              key={rc}
              onClick={() => setRootCauseFilter(isActive ? '' : rc)}
              activeBorderColor={isActive ? color : null}
              style={{
                padding: '12px 16px', cursor: 'pointer',
                border: isActive ? `2px solid ${color}` : undefined,
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
            { value: '', label: t('aggregated.allRootCauses') },
            ...ROOT_CAUSE_KEYS.map(rc => ({ value: rc, label: t(`aggregated.rootCauseLabels.${rc}`, rc) })),
          ]}
        />
        <Select
          value={sortBy}
          onChange={setSortBy}
          options={[
            { value: 'efficiency', label: 'Sort: ' + t('aggregated.efficiency') },
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
          title={t('aggregated.noSolutions')}
          sub={activeScanId
            ? t('aggregated.noSolutionsDesc')
            : 'Select a scan to view remediation actions'}
        />
      ) : (
        sorted.map(s => <RecommendationCard key={s.id} rec={s} highlighted={highlightId === String(s.id)} />)
      )}
    </div>
  )
}
