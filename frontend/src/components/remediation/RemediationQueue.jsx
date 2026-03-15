import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Wrench, Zap, ChevronRight, AlertTriangle } from 'lucide-react'
import { useScan } from '../../App.jsx'
import { getRemediationQueue, createCampaign, runCampaign } from '../../api.js'
import {
  Card, SeverityBadge, ScoreBar, PageHeader, Select, Spinner,
  EmptyState, Button, EffortBadge, ResolvedOwnerBadge, Pill
} from '../shared/ui.jsx'

const SEV_COLORS = ['var(--info)', 'var(--low)', 'var(--medium)', 'var(--high)', 'var(--critical)']

function FindingCard({ finding, rank, scanId }) {
  const { t } = useTranslation()
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
  const sevColor = SEV_COLORS[finding.severity] || 'var(--info)'

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
            {finding.zero_day && <Pill label={t('findings.zeroDay')} color="var(--critical)" />}
            {finding.exploit_available && !finding.zero_day && <Pill label={t('findings.exploit')} color="var(--high)" />}
          </div>
          <div style={{ fontWeight: 600, fontSize: 14, color: 'var(--text-primary)', marginBottom: 4 }}>
            {finding.plugin_name}
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            {finding.asset_hostname || finding.asset_ip}
            {finding.plugin_family && ` · ${finding.plugin_family}`}
            {finding.port && ` · ${t('findings.port')} ${finding.port}/${finding.protocol}`}
          </div>
          {finding.synopsis && (
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 6, lineHeight: 1.5 }}>
              {finding.synopsis}
            </div>
          )}
        </div>

        {/* Score */}
        <div style={{ textAlign: 'right', flexShrink: 0, minWidth: 90 }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>{t('findings.priority')}</div>
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
              {finding.cves.map(cve => <Pill key={cve} label={cve} color="var(--warning)" />)}
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
              style={{ background: 'rgba(99,102,241,0.13)', color: 'var(--accent)', border: '1px solid rgba(99,102,241,0.27)' }}
            >
              <Zap size={13} /> {creatingCampaign ? t('remediation.creatingCampaign') : t('remediation.createCampaign')}
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}

export default function RemediationQueue() {
  const { t } = useTranslation()
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
        title={t('remediation.title')}
        subtitle={t('remediation.subtitle')}
      />

      {/* Summary banner */}
      {findings.length > 0 && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12, marginBottom: 20 }}>
          <div style={{ background: 'var(--danger-subtle)', border: '1px solid var(--danger)', borderRadius: 10, padding: '14px 16px' }}>
            <div style={{ fontSize: 11, color: 'var(--danger)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>Critical Findings</div>
            <div style={{ fontSize: 28, fontWeight: 700, color: 'var(--danger)' }}>{critical.length}</div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Immediate action</div>
          </div>
          <div style={{ background: 'var(--success-subtle)', border: '1px solid var(--success)', borderRadius: 10, padding: '14px 16px' }}>
            <div style={{ fontSize: 11, color: 'var(--success)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>Quick Wins</div>
            <div style={{ fontSize: 28, fontWeight: 700, color: 'var(--success)' }}>{quickWins.length}</div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Low effort, immediate value</div>
          </div>
          <div style={{ background: 'rgba(99,102,241,0.1)', border: '1px solid rgba(99,102,241,0.3)', borderRadius: 10, padding: '14px 16px' }}>
            <div style={{ fontSize: 11, color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>Automatable</div>
            <div style={{ fontSize: 28, fontWeight: 700, color: 'var(--accent)' }}>{findings.length}</div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Contact us to enable</div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 16 }}>
        <Select value={effort} onChange={setEffort} placeholder={t('remediation.allEfforts')} options={[
          { value: 'quick_win', label: t('remediation.quickWin') },
          { value: 'medium', label: t('remediation.medium') },
          { value: 'complex', label: t('remediation.complex') },
        ]} />
        <Select value={owner} onChange={setOwner} placeholder={t('remediation.allOwners')} options={[
          { value: 'IT', label: t('roles.it') },
          { value: 'DevOps', label: t('roles.devops') },
          { value: 'SecOps', label: t('roles.secops') },
          { value: 'AppSec', label: t('roles.appsec') },
        ]} />
        <Select
          value={String(minSev)}
          onChange={v => setMinSev(Number(v))}
          placeholder={`${t('severity.medium')}+`}
          options={[
            { value: '1', label: `${t('severity.low')}+` },
            { value: '2', label: `${t('severity.medium')}+` },
            { value: '3', label: `${t('severity.high')}+` },
            { value: '4', label: t('severity.critical') },
          ]}
        />
      </div>

      {loading ? <Spinner /> : (
        findings.length === 0 ? (
          <EmptyState icon={Wrench} title={t('remediation.noFindings')} sub={t('remediation.noFindingsDesc')} />
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
