/**
 * Home — landing overview for Hakuna. Two-row grid of big, clickable widgets
 * summarizing the org's security posture. Top row has a featured campaigns
 * card (2/3 width) with a mini Sankey, and the posture grade on the right
 * (1/3). Bottom row has three tiles (critical & high, assets covered, total
 * findings) each with a compact breakdown footer.
 */
import React, { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Shield, Target, AlertTriangle, Server, Bug, TrendingUp, ArrowRight,
} from 'lucide-react'
import { useScan } from '../../App.jsx'
import { useAuth } from '../../contexts/AuthContext.jsx'
import {
  getRiskGrade, getAggregatedSolutions, getSummary,
} from '../../api.js'
import { Spinner } from '../shared/ui.jsx'

// ─── Utilities / palette ──────────────────────────────────────────────────

const SEV_COLORS = {
  critical: 'var(--critical)',
  high:     'var(--high)',
  medium:   'var(--medium)',
  low:      'var(--low)',
  info:     'var(--info)',
}

const ACTION_TYPE_META = {
  upgrade_component:    { label: 'Upgrade',   color: 'var(--primary)' },
  apply_patch:          { label: 'Patch',     color: 'var(--info)' },
  migrate_to_supported: { label: 'Migrate',   color: 'var(--violet)' },
  disable_protocol:     { label: 'Disable',   color: 'var(--warning)' },
  remediate_config:     { label: 'Fix config', color: 'var(--medium)' },
}
const ACTION_FALLBACK = { label: 'Other', color: 'var(--muted)' }

// ─── Generic widget card ─────────────────────────────────────────────────

function WidgetCard({ children, accent, onClick }) {
  const color = accent || 'var(--primary)'
  return (
    <button
      onClick={onClick}
      disabled={!onClick}
      style={{
        display: 'flex', flexDirection: 'column',
        textAlign: 'left',
        padding: '18px 22px',
        background: 'var(--bg-card)',
        border: `2px solid var(--border)`,
        borderRadius: 12,
        cursor: onClick ? 'pointer' : 'default',
        transition: 'border-color 160ms, box-shadow 160ms, background 160ms',
        position: 'relative',
        overflow: 'hidden',
        width: '100%',
        height: '100%',
        color: 'var(--text)',
        font: 'inherit',
      }}
      onMouseEnter={e => {
        if (!onClick) return
        e.currentTarget.style.borderColor = color
        e.currentTarget.style.boxShadow = '0 0 20px var(--ring)'
        e.currentTarget.style.background = `color-mix(in srgb, ${color} 4%, var(--bg-card))`
      }}
      onMouseLeave={e => {
        e.currentTarget.style.borderColor = 'var(--border)'
        e.currentTarget.style.boxShadow = 'none'
        e.currentTarget.style.background = 'var(--bg-card)'
      }}
    >
      <span style={{
        position: 'absolute', left: 0, top: 0, bottom: 0, width: 3,
        background: color,
      }} />
      {onClick && (
        <ArrowRight size={14} color="var(--text-muted)"
          style={{ position: 'absolute', top: 14, right: 14, opacity: 0.5 }} />
      )}
      {children}
    </button>
  )
}

function CardHeader({ icon: Icon, label, accent }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
      {Icon && (
        <div style={{
          position: 'relative',
          width: 28, height: 28, borderRadius: 8,
          color: accent, display: 'grid', placeItems: 'center', flexShrink: 0,
        }}>
          <div style={{
            position: 'absolute', inset: 0,
            background: accent, opacity: 0.14, borderRadius: 8,
          }} />
          <Icon size={15} style={{ position: 'relative' }} />
        </div>
      )}
      <div style={{
        fontSize: 11, fontWeight: 700,
        color: 'var(--text-secondary)',
        textTransform: 'uppercase', letterSpacing: '0.06em',
      }}>
        {label}
      </div>
    </div>
  )
}

function BigValue({ children, size = 80, loading }) {
  return (
    <div style={{
      fontSize: size, fontWeight: 800,
      color: 'var(--text)', lineHeight: 1,
      fontVariantNumeric: 'tabular-nums', letterSpacing: '-0.02em',
      display: 'flex', alignItems: 'center', minHeight: size * 0.9,
    }}>
      {loading ? <Spinner /> : (children ?? '—')}
    </div>
  )
}

function SubText({ children, style }) {
  return (
    <div style={{
      fontSize: 13, color: 'var(--text-secondary)',
      display: 'flex', alignItems: 'center', gap: 6,
      ...(style || {}),
    }}>
      {children}
    </div>
  )
}

// ─── Breakdown bar (stacked segment + legend) ────────────────────────────

function BreakdownBar({ items }) {
  const total = items.reduce((a, i) => a + (Number(i.value) || 0), 0) || 1
  return (
    <div style={{ marginTop: 'auto', paddingTop: 16 }}>
      <div style={{
        display: 'flex', height: 6, borderRadius: 3,
        overflow: 'hidden', background: 'var(--border)',
      }}>
        {items.map(i => i.value > 0 && (
          <div key={i.label}
            title={`${i.label}: ${i.value}`}
            style={{ background: i.color, width: `${(i.value / total) * 100}%` }} />
        ))}
      </div>
      <div style={{
        display: 'flex', gap: 12, marginTop: 8, flexWrap: 'wrap',
        fontSize: 11, color: 'var(--text-secondary)',
      }}>
        {items.map(i => (
          <div key={i.label} style={{
            display: 'flex', alignItems: 'center', gap: 4, whiteSpace: 'nowrap',
          }}>
            <span style={{ width: 6, height: 6, borderRadius: 2, background: i.color }} />
            <strong style={{ color: 'var(--text)', fontVariantNumeric: 'tabular-nums' }}>
              {(i.value ?? 0).toLocaleString()}
            </strong>
            <span>{i.label}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────

export default function Home() {
  const navigate = useNavigate()
  const { activeScanId } = useScan()
  const { user } = useAuth() || {}

  const [posture, setPosture] = useState({ loading: true, grade: null, score: null, delta: null })
  const [summary, setSummary] = useState({ loading: true, data: null })
  const [solutions, setSolutions] = useState({ loading: true, list: [], count: null, lift: null })

  useEffect(() => {
    getRiskGrade(activeScanId)
      .then(d => setPosture({
        loading: false,
        grade: d?.grade ?? null,
        score: d?.score ?? d?.risk_score ?? null,
        delta: d?.delta ?? null,
      }))
      .catch(() => setPosture({ loading: false, grade: null, score: null, delta: null }))

    getSummary(activeScanId)
      .then(d => setSummary({ loading: false, data: d }))
      .catch(() => setSummary({ loading: false, data: null }))

    const params = {}
    if (activeScanId) params.scan_id = activeScanId
    getAggregatedSolutions(params)
      .then(d => {
        const sols = d?.solutions || []
        const lift = sols.reduce((a, s) => a + (Number(s.risk_reduction) || 0), 0)
        setSolutions({
          loading: false, list: sols, count: sols.length,
          lift: Math.round(lift * 10) / 10,
        })
      })
      .catch(() => setSolutions({ loading: false, list: [], count: null, lift: null }))
  }, [activeScanId])

  const gradeColor = {
    A: 'var(--success)', B: 'var(--low)',  C: 'var(--warning)',
    D: 'var(--high)',    F: 'var(--critical)',
  }[String(posture.grade || '').toUpperCase()] || 'var(--primary)'

  const greeting = user?.display_name ? `, ${user.display_name.split(' ')[0]}` : ''

  // ─── Derived breakdowns ───
  const sev = summary.data?.severity_breakdown || {}
  const crit = Number(sev.critical) || 0
  const high = Number(sev.high) || 0
  const med  = Number(sev.medium) || 0
  const low  = Number(sev.low) || 0
  const info = Number(sev.info) || 0
  const critHighTotal = crit + high
  const findingsTotal = crit + high + med + low + info
  const coverage = summary.data?.coverage || {}
  const assetsTotal = summary.data?.total_assets ?? null

  const critHighBreakdown = [
    { label: 'Critical', value: crit, color: SEV_COLORS.critical },
    { label: 'High',     value: high, color: SEV_COLORS.high },
  ]
  const findingsBreakdown = [
    { label: 'Critical', value: crit, color: SEV_COLORS.critical },
    { label: 'High',     value: high, color: SEV_COLORS.high },
    { label: 'Medium',   value: med,  color: SEV_COLORS.medium },
    { label: 'Low',      value: low,  color: SEV_COLORS.low },
    { label: 'Info',     value: info, color: SEV_COLORS.info },
  ]
  const assetBreakdown = [
    { label: 'Credentialed', value: Number(coverage.credentialed_count) || 0, color: 'var(--success)' },
    { label: 'Uncredentialed', value: Number(coverage.uncredentialed_count) || 0, color: 'var(--muted)' },
  ]

  // Campaigns grouped by action_type — e.g. Upgrade 3, Patch 2, Migrate 1, etc.
  const campaignsByType = useMemo(() => {
    const counts = new Map()
    for (const s of solutions.list) {
      const at = s.action_type || 'upgrade_component'
      counts.set(at, (counts.get(at) || 0) + 1)
    }
    return Array.from(counts.entries())
      .map(([at, value]) => {
        const meta = ACTION_TYPE_META[at] || ACTION_FALLBACK
        return { label: meta.label, value, color: meta.color }
      })
      .sort((a, b) => b.value - a.value)
  }, [solutions.list])

  return (
    <div style={{
      display: 'flex', flexDirection: 'column',
      // Center the grid and leave ~100px margin either side.
      maxWidth: 'calc(100% - 200px)',
      margin: '0 auto',
      width: '100%',
      gap: 16,
    }}>
      <div>
        <h1 style={{
          fontSize: 26, fontWeight: 800, color: 'var(--text)',
          margin: 0, letterSpacing: '-0.02em',
        }}>
          Welcome{greeting}
        </h1>
        <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 4 }}>
          Your security posture at a glance — click any tile to dive in.
        </div>
      </div>

      {/* Main grid — 3 cols, 2 rows.
          Row 1: Campaigns (cols 1-2 = 2/3) | Posture (col 3 = 1/3)
          Row 2: Critical & High | Assets | Findings */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(3, minmax(0, 1fr))',
        gridTemplateRows: '260px 260px',
        gridTemplateAreas: `
          "posture campaigns campaigns"
          "critical assets    findings"
        `,
        gap: 16,
      }}>
        {/* 1. Campaigns (featured — spans 2 cols) */}
        <div style={{ gridArea: 'campaigns' }}>
          <WidgetCard accent="var(--primary)" onClick={() => navigate('/campaigns-v2')}>
            <CardHeader icon={Target} label="Recommended campaigns" accent="var(--primary)" />
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 16 }}>
              <BigValue size={56} loading={solutions.loading}>
                {solutions.count}
              </BigValue>
              {solutions.lift != null && (
                <div style={{
                  display: 'inline-flex', alignItems: 'center', gap: 5,
                  padding: '4px 10px',
                  background: 'var(--success-subtle)',
                  border: '1px solid var(--success)',
                  borderRadius: 999,
                  color: 'var(--success)', fontSize: 12, fontWeight: 700,
                }}>
                  <TrendingUp size={12} />
                  +{solutions.lift}% posture
                </div>
              )}
            </div>
            <SubText style={{ marginTop: 4 }}>Click to review all recommended campaigns</SubText>
            {campaignsByType.length > 0 && (
              <BreakdownBar items={campaignsByType} />
            )}
          </WidgetCard>
        </div>

        {/* 2. Security posture (1/3) */}
        <div style={{ gridArea: 'posture' }}>
          <WidgetCard accent={gradeColor} onClick={() => navigate('/')}>
            <CardHeader icon={Shield} label="Security posture" accent={gradeColor} />
            <div style={{
              flex: 1,
              display: 'grid', placeItems: 'center',
            }}>
              {posture.loading ? <Spinner /> : (
                <div style={{ textAlign: 'center' }}>
                  <div style={{
                    color: gradeColor, fontSize: 120, fontWeight: 900,
                    lineHeight: 0.85, letterSpacing: '-0.04em',
                  }}>
                    {posture.grade ?? '—'}
                  </div>
                  {posture.score != null && (
                    <div style={{
                      fontSize: 14, color: 'var(--text-muted)', fontWeight: 600,
                      marginTop: 8, fontVariantNumeric: 'tabular-nums',
                    }}>
                      Score {typeof posture.score === 'number' ? posture.score.toFixed(1) : posture.score}
                    </div>
                  )}
                </div>
              )}
            </div>
            <SubText>
              {posture.delta != null ? (
                <>
                  <TrendingUp size={12} color={posture.delta >= 0 ? 'var(--success)' : 'var(--danger)'} />
                  <span>{posture.delta >= 0 ? '+' : ''}{posture.delta} vs. last scan</span>
                </>
              ) : (
                <span>Open the reports dashboard →</span>
              )}
            </SubText>
          </WidgetCard>
        </div>

        {/* 3. Critical & High */}
        <div style={{ gridArea: 'critical' }}>
          <WidgetCard accent="var(--critical)" onClick={() => navigate('/findings?severity=3,4')}>
            <CardHeader icon={AlertTriangle} label="Critical & high to tackle" accent="var(--critical)" />
            <BigValue size={52} loading={summary.loading}>
              {summary.data ? critHighTotal.toLocaleString() : null}
            </BigValue>
            <SubText>Findings at severity ≥ High</SubText>
            <BreakdownBar items={critHighBreakdown} />
          </WidgetCard>
        </div>

        {/* 4. Assets covered */}
        <div style={{ gridArea: 'assets' }}>
          <WidgetCard accent="var(--info)" onClick={() => navigate('/assets')}>
            <CardHeader icon={Server} label="Assets covered" accent="var(--info)" />
            <BigValue size={52} loading={summary.loading}>
              {assetsTotal != null ? assetsTotal.toLocaleString() : null}
            </BigValue>
            <SubText>
              {coverage.coverage_pct != null
                ? `${Math.round(coverage.coverage_pct * 100)}% credentialed coverage`
                : 'Across all sources'}
            </SubText>
            <BreakdownBar items={assetBreakdown} />
          </WidgetCard>
        </div>

        {/* 5. Total findings */}
        <div style={{ gridArea: 'findings' }}>
          <WidgetCard accent="var(--warning)" onClick={() => navigate('/findings')}>
            <CardHeader icon={Bug} label="Total findings" accent="var(--warning)" />
            <BigValue size={52} loading={summary.loading}>
              {summary.data ? findingsTotal.toLocaleString() : null}
            </BigValue>
            <SubText>By severity, all scans</SubText>
            <BreakdownBar items={findingsBreakdown} />
          </WidgetCard>
        </div>
      </div>
    </div>
  )
}
