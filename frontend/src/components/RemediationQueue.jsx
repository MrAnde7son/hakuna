import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Wrench, Zap, ChevronRight, AlertTriangle } from 'lucide-react'
import { useScan } from '../App.jsx'
import { getRemediationQueue, createCampaign, runCampaign } from '../api.js'
import {
  Card, SeverityBadge, ScoreBar, PageHeader, Select, Spinner,
  EmptyState, Button, EffortBadge, ResolvedOwnerBadge, Pill
} from './ui.jsx'

const EFFORT_OPTIONS = [
  { value: 'quick_win', label: 'Quick Win' },
  { value: 'medium', label: 'Medium' },
  { value: 'complex', label: 'Complex' },
]

const OWNER_OPTIONS = [
  { value: 'IT', label: 'IT' },
  { value: 'DevOps', label: 'DevOps' },
  { value: 'SecOps', label: 'SecOps' },
  { value: 'AppSec', label: 'AppSec' },
]

const SEV_COLORS = ['#0ea5e9', '#65a30d', '#d97706', '#ea580c', '#dc2626']

function FindingCard({ finding, rank, scanId }) {
  const navigate = useNavigate()
  const [expanded, setExpanded] = useState(false)
  const [creatingCampaign, setCreatingCampaign] = useState(false)

  const handleAutomate = async () => {
    setCreatingCampaign(true)
    try {
      const query = [{ field: 'finding.plugin_id', op: 'eq', value: String(finding.plugin_id) }]
      const campaign = await createCampaign({
        name: `Remediate: ${finding.plugin_name}`,
        description: `Campaign to remediate plugin ${finding.plugin_id} — ${finding.plugin_name}`,
        scan_id: scanId,
        query,
        query_logic: 'AND',
      })
      await runCampaign(campaign.id)
      navigate(`/campaigns/${campaign.id}`)
    } finally {
      setCreatingCampaign(false)
    }
  }
  const sevColor = SEV_COLORS[finding.severity] || '#0ea5e9'

  return (
    <div style={{
      background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 10,
      marginBottom: 10, overflow: 'hidden',
      borderLeft: `3px solid ${sevColor}`,
    }}>
      {/* Header row */}
      <div
        onClick={() => setExpanded(e => !e)}
        style={{ padding: '14px 16px', cursor: 'pointer', display: 'flex', gap: 14, alignItems: 'flex-start' }}
      >
        {/* Rank */}
        <div style={{
          width: 32, height: 32, borderRadius: 8, background: 'var(--bg-secondary)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontWeight: 700, fontSize: 13, color: 'var(--text-muted)', flexShrink: 0,
        }}>
          {rank}
        </div>

        {/* Content */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', marginBottom: 6 }}>
            <SeverityBadge severity={finding.severity} label={finding.severity_label} />
            <EffortBadge effort={finding.effort_level} />
            <ResolvedOwnerBadge resolved={finding.resolved_owner} />
            {finding.zero_day && <Pill label="0-DAY" color="#dc2626" />}
            {finding.exploit_available && !finding.zero_day && <Pill label="Exploit" color="#ea580c" />}
          </div>
          <div style={{ fontWeight: 600, fontSize: 14, color: 'var(--text-primary)', marginBottom: 4 }}>
            {finding.plugin_name}
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            {finding.asset_hostname || finding.asset_ip}
            {finding.plugin_family && ` · ${finding.plugin_family}`}
            {finding.port && ` · Port ${finding.port}/${finding.protocol}`}
          </div>
          {finding.synopsis && (
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 6, lineHeight: 1.5 }}>
              {finding.synopsis}
            </div>
          )}
        </div>

        {/* Score */}
        <div style={{ textAlign: 'right', flexShrink: 0, minWidth: 90 }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Priority</div>
          <ScoreBar score={finding.priority_score} />
          {(finding.cvss3_score || finding.cvss2_score) && (
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
              CVSS: {(finding.cvss3_score || finding.cvss2_score).toFixed(1)}
            </div>
          )}
        </div>
      </div>

      {/* Expanded content */}
      {expanded && (
        <div style={{ padding: '0 16px 16px', borderTop: '1px solid var(--border)' }}>
          {finding.cves && finding.cves.length > 0 && (
            <div style={{ marginTop: 12, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {finding.cves.map(cve => <Pill key={cve} label={cve} color="#f59e0b" />)}
            </div>
          )}

          {/* Quick action buttons */}
          <div style={{ display: 'flex', gap: 8, marginTop: 14 }}>
            <Button
              onClick={() => navigate(`/findings/${finding.id}`)}
              variant="ghost"
              size="sm"
            >
              View Details <ChevronRight size={13} />
            </Button>
            <Button
              onClick={handleAutomate}
              disabled={creatingCampaign}
              size="sm"
              style={{ background: '#6366f122', color: '#818cf8', border: '1px solid #6366f144' }}
            >
              <Zap size={13} /> {creatingCampaign ? 'Creating…' : 'Automate This'}
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}

export default function RemediationQueue() {
  const { activeScanId } = useScan()
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [effort, setEffort] = useState(null)
  const [owner, setOwner] = useState(null)
  const [minSev, setMinSev] = useState(2)
  useEffect(() => {
    setLoading(true)
    getRemediationQueue({ scan_id: activeScanId, effort, owner, min_severity: minSev, limit: 100 })
      .then(setFindings)
      .finally(() => setLoading(false))
  }, [activeScanId, effort, owner, minSev])

  const quickWins = findings.filter(f => f.effort_level === 'quick_win')
  const critical = findings.filter(f => f.severity >= 4)

  return (
    <div>
      <PageHeader
        title="Remediation"
        subtitle={`${findings.length} actionable findings, prioritized by risk`}
      />

      {/* Summary banner */}
      {findings.length > 0 && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12, marginBottom: 20 }}>
          <div style={{ background: '#dc262622', border: '1px solid #dc262644', borderRadius: 10, padding: '14px 16px' }}>
            <div style={{ fontSize: 11, color: '#fca5a5', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>Critical Findings</div>
            <div style={{ fontSize: 28, fontWeight: 700, color: '#fca5a5' }}>{critical.length}</div>
            <div style={{ fontSize: 12, color: '#fca5a580' }}>Immediate action</div>
          </div>
          <div style={{ background: '#16a34a22', border: '1px solid #16a34a44', borderRadius: 10, padding: '14px 16px' }}>
            <div style={{ fontSize: 11, color: '#86efac', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>Quick Wins</div>
            <div style={{ fontSize: 28, fontWeight: 700, color: '#86efac' }}>{quickWins.length}</div>
            <div style={{ fontSize: 12, color: '#86efac80' }}>Low effort, immediate value</div>
          </div>
          <div style={{ background: '#6366f122', border: '1px solid #6366f144', borderRadius: 10, padding: '14px 16px' }}>
            <div style={{ fontSize: 11, color: '#a5b4fc', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>Automatable</div>
            <div style={{ fontSize: 28, fontWeight: 700, color: '#a5b4fc' }}>{findings.length}</div>
            <div style={{ fontSize: 12, color: '#a5b4fc80' }}>Contact us to enable</div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 16 }}>
        <Select value={effort} onChange={setEffort} placeholder="All Effort Levels" options={EFFORT_OPTIONS} />
        <Select value={owner} onChange={setOwner} placeholder="All Owners" options={OWNER_OPTIONS} />
        <Select
          value={String(minSev)}
          onChange={v => setMinSev(Number(v))}
          placeholder="Min Severity"
          options={[
            { value: '1', label: 'Low+' },
            { value: '2', label: 'Medium+' },
            { value: '3', label: 'High+' },
            { value: '4', label: 'Critical only' },
          ]}
        />
      </div>

      {loading ? <Spinner /> : (
        findings.length === 0 ? (
          <EmptyState icon={Wrench} title="Queue is empty" sub="No findings match your current filters. Try adjusting severity or effort level." />
        ) : (
          <div>
            {findings.map((f, i) => (
              <FindingCard key={f.id} finding={f} rank={i + 1} scanId={activeScanId} />
            ))}
          </div>
        )
      )}

    </div>
  )
}
