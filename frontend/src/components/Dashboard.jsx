import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, Legend, CartesianGrid
} from 'recharts'
import { AlertTriangle, Bug, Server, Zap, TrendingUp, Shield, Clock, AlertCircle, RotateCcw, Skull, Activity } from 'lucide-react'
import { useScan } from '../App.jsx'
import { getSummary, getTrending, getSLASummary, getTemporalSummary, getRemediationVelocity } from '../api.js'
import { Card, StatCard, ScoreBar, SeverityBadge, Spinner, EmptyState, Button } from './ui.jsx'

const SEV_COLORS = ['var(--info)', 'var(--low)', 'var(--medium)', 'var(--high)', 'var(--critical)']
const SEV_LABELS = ['Info', 'Low', 'Medium', 'High', 'Critical']

function SeverityDonut({ data }) {
  const navigate = useNavigate()
  const pieData = SEV_LABELS.map((label, i) => ({
    name: label, value: data[label.toLowerCase()] || 0, color: SEV_COLORS[i], severity: i
  })).filter(d => d.value > 0)

  return (
    <Card>
      <div style={{ fontWeight: 600, marginBottom: 16, fontSize: 14 }}>Findings by Severity</div>
      <ResponsiveContainer width="100%" height={220}>
        <PieChart>
          <Pie
            data={pieData} cx="50%" cy="50%" innerRadius={55} outerRadius={85} paddingAngle={3} dataKey="value"
            cursor="pointer"
            onClick={(entry) => navigate(`/findings?severity=${entry.severity}`)}
          >
            {pieData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
          </Pie>
          <Tooltip
            contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }}
            formatter={(v, n) => [v.toLocaleString(), n]}
          />
          <Legend iconType="circle" iconSize={10} formatter={(v) => <span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>{v}</span>} />
        </PieChart>
      </ResponsiveContainer>
    </Card>
  )
}

function FamilyBar({ data }) {
  const navigate = useNavigate()
  return (
    <Card>
      <div style={{ fontWeight: 600, marginBottom: 16, fontSize: 14 }}>Top Plugin Families (non-Info)</div>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={data} layout="vertical" margin={{ left: 0, right: 16, top: 0, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" horizontal={false} />
          <XAxis type="number" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} />
          <YAxis type="category" dataKey="family" tick={{ fill: 'var(--text-secondary)', fontSize: 11 }} width={140} />
          <Tooltip
            contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }}
          />
          <Bar dataKey="count" fill="#6366f1" radius={[0, 4, 4, 0]} cursor="pointer"
            onClick={(entry) => navigate(`/findings?family=${encodeURIComponent(entry.family)}`)}
          />
        </BarChart>
      </ResponsiveContainer>
    </Card>
  )
}

function TrendChart({ data }) {
  if (data.length < 2) return null
  return (
    <Card>
      <div style={{ fontWeight: 600, marginBottom: 16, fontSize: 14 }}>Findings Trend Across Scans</div>
      <ResponsiveContainer width="100%" height={200}>
        <BarChart data={data} margin={{ right: 16 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
          <XAxis dataKey="scan_name" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} />
          <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 11 }} />
          <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }} />
          <Legend formatter={(v) => <span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>{v}</span>} />
          <Bar dataKey="critical" stackId="a" fill="var(--critical)" />
          <Bar dataKey="high" stackId="a" fill="var(--high)" />
          <Bar dataKey="medium" stackId="a" fill="var(--medium)" />
          <Bar dataKey="low" stackId="a" fill="var(--low)" />
        </BarChart>
      </ResponsiveContainer>
    </Card>
  )
}

function SLAWidget({ sla }) {
  if (!sla || sla.total_with_sla === 0) return null
  const { on_track, at_risk, breached, resolved, total_with_sla, compliance_pct, avg_mttr_days } = sla
  const mttrEntries = Object.entries(avg_mttr_days || {})

  const bars = [
    { label: 'On Track', value: on_track, color: 'var(--success)' },
    { label: 'At Risk',  value: at_risk,  color: 'var(--warning)' },
    { label: 'Breached', value: breached, color: 'var(--danger)' },
    { label: 'Resolved', value: resolved, color: 'var(--accent)' },
  ]

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, marginBottom: 20 }}>
      <Card>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
          <div style={{ fontWeight: 600, fontSize: 14, display: 'flex', alignItems: 'center', gap: 6 }}>
            <Clock size={14} color="var(--accent)" /> SLA Compliance
          </div>
          <span style={{
            fontSize: 18, fontWeight: 700,
            color: compliance_pct >= 80 ? 'var(--success)' : compliance_pct >= 50 ? 'var(--warning)' : 'var(--danger)',
          }}>
            {compliance_pct}%
          </span>
        </div>
        {bars.map(b => (
          <div key={b.label} style={{ marginBottom: 10 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 3 }}>
              <span style={{ color: 'var(--text-secondary)' }}>{b.label}</span>
              <span style={{ fontWeight: 600, color: b.color }}>{b.value}</span>
            </div>
            <div style={{ height: 5, background: 'var(--border)', borderRadius: 3, overflow: 'hidden' }}>
              <div style={{
                width: `${Math.min((b.value / total_with_sla) * 100, 100)}%`,
                height: '100%', background: b.color, borderRadius: 3,
              }} />
            </div>
          </div>
        ))}
      </Card>

      <Card>
        <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, display: 'flex', alignItems: 'center', gap: 6 }}>
          <AlertCircle size={14} color="var(--accent)" /> Avg MTTR (days to resolve)
        </div>
        {mttrEntries.length === 0 ? (
          <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>No resolved findings yet</div>
        ) : (
          mttrEntries.map(([sev, days]) => {
            const color = sev === 'critical' ? 'var(--critical)' : sev === 'high' ? 'var(--high)' : sev === 'medium' ? 'var(--medium)' : 'var(--low)'
            return (
              <div key={sev} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border)', fontSize: 13 }}>
                <span style={{ color: 'var(--text-secondary)', textTransform: 'capitalize' }}>{sev}</span>
                <span style={{ fontWeight: 700, color }}>{days}d</span>
              </div>
            )
          })
        )}
        {breached > 0 && (
          <div style={{ marginTop: 12, padding: '8px 10px', background: 'rgba(220,38,38,0.08)', border: '1px solid rgba(220,38,38,0.25)', borderRadius: 6, display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--danger)' }}>
            <AlertTriangle size={12} />
            {breached} finding{breached !== 1 ? 's' : ''} past SLA deadline
          </div>
        )}
      </Card>
    </div>
  )
}

function TemporalWidget({ temporal }) {
  if (!temporal || temporal.total_with_temporal === 0) return null
  const { regression_count, zombie_count, age_distribution } = temporal

  const ageBars = [
    { label: '< 30 days', value: age_distribution.under_30d, color: 'var(--success)' },
    { label: '30–90 days', value: age_distribution['30_90d'], color: 'var(--warning)' },
    { label: '90–180 days', value: age_distribution['90_180d'], color: 'var(--high)' },
    { label: '> 180 days', value: age_distribution.over_180d, color: 'var(--critical)' },
  ]
  const total = ageBars.reduce((s, b) => s + b.value, 0) || 1

  return (
    <Card>
      <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 14, display: 'flex', alignItems: 'center', gap: 6 }}>
        <Clock size={14} color="var(--accent)" /> Finding Age Distribution
      </div>
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
      <div style={{ display: 'flex', gap: 14, marginTop: 14 }}>
        {regression_count > 0 && (
          <div style={{ padding: '8px 10px', background: 'rgba(220,38,38,0.08)', border: '1px solid rgba(220,38,38,0.25)', borderRadius: 6, display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--danger)' }}>
            <RotateCcw size={12} /> {regression_count} regression{regression_count !== 1 ? 's' : ''}
          </div>
        )}
        {zombie_count > 0 && (
          <div style={{ padding: '8px 10px', background: 'rgba(234,88,12,0.08)', border: '1px solid rgba(234,88,12,0.25)', borderRadius: 6, display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--warning)' }}>
            <Skull size={12} /> {zombie_count} zombie vuln{zombie_count !== 1 ? 's' : ''} (open &gt;180d)
          </div>
        )}
      </div>
    </Card>
  )
}

function VelocityWidget({ velocity }) {
  if (!velocity || velocity.total_resolved === 0) return null
  const { buckets, avg_per_period, velocity_trend_pct, period } = velocity
  const recent = buckets.slice(-6)

  return (
    <Card>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
        <div style={{ fontWeight: 600, fontSize: 14, display: 'flex', alignItems: 'center', gap: 6 }}>
          <Activity size={14} color="var(--accent)" /> Remediation Velocity
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            avg {avg_per_period}/{period}
          </span>
          {velocity_trend_pct != null && (
            <span style={{
              fontSize: 12, fontWeight: 600,
              color: velocity_trend_pct > 0 ? 'var(--success)' : velocity_trend_pct < 0 ? 'var(--danger)' : 'var(--text-muted)',
            }}>
              {velocity_trend_pct > 0 ? '+' : ''}{velocity_trend_pct}%
            </span>
          )}
        </div>
      </div>
      <ResponsiveContainer width="100%" height={140}>
        <BarChart data={recent} margin={{ right: 8 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
          <XAxis dataKey="period_label" tick={{ fill: 'var(--text-muted)', fontSize: 10 }} />
          <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 10 }} width={30} />
          <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }} />
          <Bar dataKey="critical" stackId="a" fill="var(--critical)" />
          <Bar dataKey="high" stackId="a" fill="var(--high)" />
          <Bar dataKey="medium" stackId="a" fill="var(--medium)" />
          <Bar dataKey="low" stackId="a" fill="var(--low)" />
        </BarChart>
      </ResponsiveContainer>
    </Card>
  )
}

export default function Dashboard() {
  const { activeScanId } = useScan()
  const [summary, setSummary] = useState(null)
  const [trending, setTrending] = useState([])
  const [sla, setSla] = useState(null)
  const [temporal, setTemporal] = useState(null)
  const [velocity, setVelocity] = useState(null)
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  useEffect(() => {
    setLoading(true)
    Promise.all([
      getSummary(activeScanId),
      getTrending(),
      getSLASummary(activeScanId),
      getTemporalSummary(activeScanId).catch(() => null),
      getRemediationVelocity('month').catch(() => null),
    ])
      .then(([s, t, sl, tmp, vel]) => {
        setSummary(s)
        setTrending(t)
        setSla(sl)
        setTemporal(tmp)
        setVelocity(vel)
      })
      .finally(() => setLoading(false))
  }, [activeScanId])

  if (loading) return <Spinner />

  if (!summary || summary.total_findings === 0) {
    return (
      <EmptyState
        icon={Shield}
        title="No scan data yet"
        sub="Upload a Nessus HTML report to get started. Every insight traces back to real plugin output."
      >
        <Button onClick={() => navigate('settings?tab=upload')} style={{ marginTop: 16 }}>Upload First Scan</Button>
      </EmptyState>
    )
  }

  const { severity_breakdown: sev, top_plugin_families, top_risky_assets,
    effort_breakdown, owner_breakdown, exploit_count, high_priority_count,
    total_assets, total_findings, quick_wins } = summary

  const effortData = [
    { name: 'Quick Win', value: effort_breakdown.quick_win, color: 'var(--success)' },
    { name: 'Medium', value: effort_breakdown.medium, color: 'var(--warning)' },
    { name: 'Complex', value: effort_breakdown.complex, color: 'var(--danger)' },
  ]

  return (
    <div>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700 }}>Security Dashboard</h1>
        <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 4 }}>
          Actionable exposure summary from your Nessus scan data
        </div>
      </div>

      {/* Top stats */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 14, marginBottom: 20 }}>
        <StatCard label="Total Assets" value={total_assets.toLocaleString()} icon={Server} color="#6366f1"
          onClick={() => navigate('/assets')} />
        <StatCard label="Total Findings" value={total_findings.toLocaleString()} icon={Bug} color="var(--text-primary)"
          onClick={() => navigate('/findings')} />
        <StatCard label="Critical" value={sev.critical.toLocaleString()} icon={AlertTriangle} color="var(--critical)"
          sub={`+ ${sev.high} High`} onClick={() => navigate('/findings?severity=4')} />
        <StatCard label="High Priority" value={high_priority_count.toLocaleString()} icon={TrendingUp} color="var(--high)"
          sub="Score ≥ 7.0" onClick={() => navigate('/findings')} />
        <StatCard label="w/ Known Exploit" value={exploit_count.toLocaleString()} icon={Zap} color="var(--warning)"
          sub="Active threat" onClick={() => navigate('/findings?exploit=true')} />
      </div>

      {/* Charts row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 14, marginBottom: 20 }}>
        <SeverityDonut data={sev} />
        <FamilyBar data={top_plugin_families.map(f => ({ family: f.family || 'Unknown', count: f.count }))} />
      </div>

      {/* Effort & Owners */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 14, marginBottom: 20 }}>
        <Card>
          <div style={{ fontWeight: 600, marginBottom: 16, fontSize: 14 }}>Remediation Effort Mix</div>
          {effortData.map(e => (
            <div key={e.name} style={{ marginBottom: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4, fontSize: 13 }}>
                <span style={{ color: 'var(--text-secondary)' }}>{e.name}</span>
                <span style={{ color: e.color, fontWeight: 600 }}>{e.value}</span>
              </div>
              <div style={{ height: 6, background: 'var(--border)', borderRadius: 3, overflow: 'hidden' }}>
                <div style={{
                  width: `${Math.min((e.value / (effort_breakdown.quick_win + effort_breakdown.medium + effort_breakdown.complex || 1)) * 100, 100)}%`,
                  height: '100%', background: e.color, borderRadius: 3
                }} />
              </div>
            </div>
          ))}
        </Card>

        <Card>
          <div style={{ fontWeight: 600, marginBottom: 16, fontSize: 14 }}>Findings by Owner</div>
          {owner_breakdown.map(o => (
            <div key={o.owner} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 0', borderBottom: '1px solid var(--border)', fontSize: 13 }}>
              <span style={{ color: 'var(--text-secondary)' }}>{o.owner}</span>
              <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{o.count}</span>
            </div>
          ))}
        </Card>

        <Card>
          <div style={{ fontWeight: 600, marginBottom: 16, fontSize: 14 }}>Riskiest Assets</div>
          {top_risky_assets.map(a => (
            <div
              key={a.id}
              onClick={() => navigate(`/findings?asset_id=${a.id}`)}
              style={{ cursor: 'pointer', padding: '8px 0', borderBottom: '1px solid var(--border)', transition: 'opacity 0.15s' }}
              onMouseEnter={e => e.currentTarget.style.opacity = '0.75'}
              onMouseLeave={e => e.currentTarget.style.opacity = '1'}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4, fontSize: 13 }}>
                <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{a.hostname || a.ip}</span>
                <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{a.os ? a.os.split(' ').slice(0, 3).join(' ') : '—'}</span>
              </div>
              <ScoreBar score={a.risk_score} />
            </div>
          ))}
        </Card>

        {quick_wins && quick_wins.length > 0 && (
          <Card>
            <div style={{ fontWeight: 600, marginBottom: 16, fontSize: 14, display: 'flex', alignItems: 'center', gap: 6 }}>
              <Zap size={14} color="var(--success)" /> Quick Wins
            </div>
            {quick_wins.map(qw => (
              <div
                key={qw.id}
                onClick={() => navigate(`/findings?asset_id=${qw.asset_id}`)}
                style={{ cursor: 'pointer', padding: '8px 0', borderBottom: '1px solid var(--border)', transition: 'opacity 0.15s' }}
                onMouseEnter={e => e.currentTarget.style.opacity = '0.75'}
                onMouseLeave={e => e.currentTarget.style.opacity = '1'}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 3 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, minWidth: 0, flex: 1 }}>
                    <SeverityBadge severity={qw.severity} />
                    <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {qw.plugin_name}
                    </span>
                  </div>
                  <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--success)', marginLeft: 8 }}>{qw.priority_score.toFixed(1)}</span>
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{qw.host}</div>
              </div>
            ))}
          </Card>
        )}
      </div>

      {/* SLA */}
      <SLAWidget sla={sla} />

      {/* Temporal & Velocity */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 14, marginBottom: 20 }}>
        <TemporalWidget temporal={temporal} />
        <VelocityWidget velocity={velocity} />
      </div>

      {/* Trend */}
      <TrendChart data={trending} />
    </div>
  )
}
