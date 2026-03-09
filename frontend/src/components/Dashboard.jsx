import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, Legend, CartesianGrid
} from 'recharts'
import { AlertTriangle, Bug, Server, Zap, TrendingUp, Shield, Clock, AlertCircle } from 'lucide-react'
import { useScan } from '../App.jsx'
import { getSummary, getTrending, getSLASummary } from '../api.js'
import { Card, StatCard, ScoreBar, SeverityBadge, Spinner, EmptyState, Button } from './ui.jsx'

const SEV_COLORS = ['#0ea5e9', '#65a30d', '#d97706', '#ea580c', '#dc2626']
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
          <Bar dataKey="critical" stackId="a" fill="#dc2626" />
          <Bar dataKey="high" stackId="a" fill="#ea580c" />
          <Bar dataKey="medium" stackId="a" fill="#d97706" />
          <Bar dataKey="low" stackId="a" fill="#65a30d" />
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
    { label: 'On Track', value: on_track, color: '#16a34a' },
    { label: 'At Risk',  value: at_risk,  color: '#d97706' },
    { label: 'Breached', value: breached, color: '#dc2626' },
    { label: 'Resolved', value: resolved, color: '#6366f1' },
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
            color: compliance_pct >= 80 ? '#16a34a' : compliance_pct >= 50 ? '#d97706' : '#dc2626',
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
            const color = sev === 'critical' ? '#dc2626' : sev === 'high' ? '#ea580c' : sev === 'medium' ? '#d97706' : '#65a30d'
            return (
              <div key={sev} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid rgba(45,49,85,0.4)', fontSize: 13 }}>
                <span style={{ color: 'var(--text-secondary)', textTransform: 'capitalize' }}>{sev}</span>
                <span style={{ fontWeight: 700, color }}>{days}d</span>
              </div>
            )
          })
        )}
        {breached > 0 && (
          <div style={{ marginTop: 12, padding: '8px 10px', background: 'rgba(220,38,38,0.08)', border: '1px solid rgba(220,38,38,0.25)', borderRadius: 6, display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: '#fca5a5' }}>
            <AlertTriangle size={12} />
            {breached} finding{breached !== 1 ? 's' : ''} past SLA deadline
          </div>
        )}
      </Card>
    </div>
  )
}

export default function Dashboard() {
  const { activeScanId } = useScan()
  const [summary, setSummary] = useState(null)
  const [trending, setTrending] = useState([])
  const [sla, setSla] = useState(null)
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  useEffect(() => {
    setLoading(true)
    Promise.all([getSummary(activeScanId), getTrending(), getSLASummary(activeScanId)])
      .then(([s, t, sl]) => {
        setSummary(s)
        setTrending(t)
        setSla(sl)
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
    total_assets, total_findings } = summary

  const effortData = [
    { name: 'Quick Win', value: effort_breakdown.quick_win, color: '#16a34a' },
    { name: 'Medium', value: effort_breakdown.medium, color: '#d97706' },
    { name: 'Complex', value: effort_breakdown.complex, color: '#dc2626' },
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
        <StatCard label="Critical" value={sev.critical.toLocaleString()} icon={AlertTriangle} color="#dc2626"
          sub={`+ ${sev.high} High`} onClick={() => navigate('/findings?severity=4')} />
        <StatCard label="High Priority" value={high_priority_count.toLocaleString()} icon={TrendingUp} color="#ea580c"
          sub="Score ≥ 7.0" onClick={() => navigate('/findings')} />
        <StatCard label="w/ Known Exploit" value={exploit_count.toLocaleString()} icon={Zap} color="#f59e0b"
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
            <div key={o.owner} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 0', borderBottom: '1px solid rgba(45,49,85,0.4)', fontSize: 13 }}>
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
              style={{ cursor: 'pointer', padding: '8px 0', borderBottom: '1px solid rgba(45,49,85,0.4)', transition: 'opacity 0.15s' }}
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
      </div>

      {/* SLA / MTTR */}
      <SLAWidget sla={sla} />

      {/* Trend */}
      <TrendChart data={trending} />
    </div>
  )
}
