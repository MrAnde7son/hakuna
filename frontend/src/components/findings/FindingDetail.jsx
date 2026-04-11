import React, { useState, useEffect } from 'react'
import { useParams, useNavigate, useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { ArrowLeft, ExternalLink, Zap, Shield, ShieldCheck, Terminal, Info, Crosshair, Clock, CheckCircle, RotateCcw, ShieldOff, UserCheck, MessageSquare, Eye, Briefcase, ChevronDown, ChevronRight, Layers, RefreshCw, Ticket, Wrench } from 'lucide-react'
import { getFinding, getFindingSources, getFindingAssessments, resolveFinding, unresolveFinding, updateFindingStatus, updateFindingContext, createException, createCampaign, runCampaign, syncFindingTickets, getPatchAdvisories } from '../../api.js'
import { Card, SeverityBadge, ScoreBar, Spinner, Button, EffortBadge, ResolvedOwnerBadge, Pill, Select, Input, ErrorBanner, SkeletonDetail, useToast, buildFindingBreakdown, useRiskWeights, PatchReliabilityBadge } from '../shared/ui.jsx'
import CustomAttributesCard from '../shared/CustomAttributesCard.jsx'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import BlastRadiusPanel from '../campaigns/BlastRadiusPanel.jsx'
import { getFindingAssetDisplay } from '../../utils/assetDisplay.js'

function Section({ title, icon: Icon, children, defaultOpen = true }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <Card style={{ marginBottom: 14 }}>
      <div
        onClick={() => setOpen(!open)}
        style={{ display: 'flex', alignItems: 'center', gap: 8, paddingBottom: open ? 12 : 0, marginBottom: open ? 14 : 0, borderBottom: open ? '1px solid var(--border)' : 'none', cursor: 'pointer', userSelect: 'none' }}
      >
        {open ? <ChevronDown size={14} color="var(--text-muted)" /> : <ChevronRight size={14} color="var(--text-muted)" />}
        {Icon && <Icon size={16} color="var(--accent)" />}
        <span style={{ fontWeight: 600, fontSize: 14 }}>{title}</span>
      </div>
      {open && children}
    </Card>
  )
}

function KeyVal({ label, value, mono }) {
  if (!value && value !== 0) return null
  return (
    <div style={{ display: 'flex', gap: 12, padding: '6px 0', borderBottom: '1px solid var(--border)', fontSize: 13 }}>
      <div style={{ minWidth: 160, color: 'var(--text-muted)', flexShrink: 0 }}>{label}</div>
      <div style={{ color: 'var(--text-primary)', fontFamily: mono ? 'monospace' : 'inherit', wordBreak: 'break-all' }}>
        {value}
      </div>
    </div>
  )
}

function PreText({ text }) {
  if (!text) return <span style={{ color: 'var(--text-muted)' }}>—</span>
  const lines = text.split('\n')
  return (
    <div style={{ borderRadius: 8, overflow: 'hidden', border: '1px solid var(--border)', fontFamily: 'monospace' }}>
      {/* Terminal title bar */}
      <div style={{
        background: '#1e1e2e', padding: '8px 14px',
        display: 'flex', alignItems: 'center', gap: 10,
        borderBottom: '1px solid rgba(255,255,255,0.08)',
      }}>
        <div style={{ display: 'flex', gap: 6 }}>
          <span style={{ width: 11, height: 11, borderRadius: '50%', background: '#ff5f57', display: 'inline-block' }} />
          <span style={{ width: 11, height: 11, borderRadius: '50%', background: '#febc2e', display: 'inline-block' }} />
          <span style={{ width: 11, height: 11, borderRadius: '50%', background: '#28c840', display: 'inline-block' }} />
        </div>
        <span style={{ color: 'rgba(255,255,255,0.35)', fontSize: 11, letterSpacing: '0.04em' }}>plugin output</span>
        <span style={{ marginLeft: 'auto', color: 'rgba(255,255,255,0.2)', fontSize: 10 }}>{lines.length} lines</span>
      </div>
      {/* Content */}
      <div style={{
        background: '#0d1117', padding: '12px 0',
        maxHeight: 420, overflowY: 'auto',
        fontSize: 12, lineHeight: 1.65,
      }}>
        {lines.map((line, i) => (
          <div key={i} style={{ display: 'flex', minHeight: '1.65em' }}>
            <span style={{
              width: 44, minWidth: 44, textAlign: 'right', paddingRight: 16,
              color: 'rgba(255,255,255,0.18)', userSelect: 'none', fontSize: 11,
              paddingTop: 1,
            }}>
              {i + 1}
            </span>
            <span style={{
              flex: 1, paddingRight: 16,
              color: line.trim().startsWith('#') ? 'rgba(255,255,255,0.35)'
                   : line.match(/^\s*(error|fail|critical|warning)/i) ? '#ff7b7b'
                   : line.match(/^\s*(ok|success|pass|found|enabled)/i) ? '#7ec8a4'
                   : line.trim() === '' ? 'transparent'
                   : '#c9d1d9',
              whiteSpace: 'pre-wrap', wordBreak: 'break-all',
            }}>
              {line || ' '}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

function RemediationSteps({ text }) {
  if (!text) return <span style={{ color: 'var(--text-muted)' }}>No remediation steps available.</span>
  const parts = text.split('\n\n').filter(Boolean)
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
      {parts.map((part, i) => {
        const isBold = part.startsWith('**')
        const cleaned = part.replace(/\*\*/g, '')
        return (
          <div key={i} style={{
            display: 'flex', gap: 12, padding: '10px 14px',
            borderLeft: isBold ? '3px solid var(--danger)' : '3px solid var(--border)',
            background: isBold ? 'rgba(220,38,38,0.06)' : 'transparent',
            fontSize: 13, lineHeight: 1.6,
            color: isBold ? 'var(--danger)' : 'var(--text-secondary)',
            fontWeight: isBold ? 500 : 400,
          }}>
            {!isBold && (
              <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', minWidth: 18, paddingTop: 2 }}>
                {i}
              </span>
            )}
            <span>{cleaned}</span>
          </div>
        )
      })}
    </div>
  )
}

export default function FindingDetail() {
  const { t } = useTranslation()
  const { id } = useParams()
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const activeTab = searchParams.get('tab') || 'overview'
  const setActiveTab = (tab) => {
    setSearchParams(prev => {
      const next = new URLSearchParams(prev)
      if (tab === 'overview') next.delete('tab')
      else next.set('tab', tab)
      return next
    }, { replace: true })
  }
  const toast = useToast()
  const riskWeights = useRiskWeights()
  const [finding, setFinding] = useState(null)
  const [loading, setLoading] = useState(true)
  const [creatingCampaign, setCreatingCampaign] = useState(false)
  const [resolving, setResolving] = useState(false)
  const [statusUpdating, setStatusUpdating] = useState(false)
  const [showExceptionForm, setShowExceptionForm] = useState(false)
  const [showAllCves, setShowAllCves] = useState(false)
  const [showAllControls, setShowAllControls] = useState(false)
  const [exceptionReason, setExceptionReason] = useState('')
  const [ctxSaving, setCtxSaving] = useState(false)
  const [fetchError, setFetchError] = useState(null)
  const [assessments, setAssessments] = useState([])
  const [patches, setPatches] = useState([])
  const [patchesLoading, setPatchesLoading] = useState(false)

  const loadFinding = () => {
    setLoading(true)
    setFetchError(null)
    getFinding(id)
      .then(setFinding)
      .catch(() => setFetchError('Failed to load finding details.'))
      .finally(() => setLoading(false))
  }

  useEffect(() => { loadFinding() }, [id])

  useEffect(() => {
    if (!finding) return
    getFindingAssessments(finding.id)
      .then(r => setAssessments(r.items || []))
      .catch(() => {})
  }, [finding?.id])

  // Fetch available patches + reliability for the finding's CVEs. We dedupe
  // by (source, advisory_id) across all CVEs so a Linux package shared by two
  // CVEs only shows once. Capped at the first few CVEs to keep this cheap —
  // findings with 50+ CVEs are rare but not unheard of (chromium updates).
  useEffect(() => {
    if (!finding?.cves || finding.cves.length === 0) {
      setPatches([])
      return
    }
    const cvesToFetch = finding.cves.slice(0, 8)
    setPatchesLoading(true)
    Promise.all(
      cvesToFetch.map(cve =>
        getPatchAdvisories({ cve_id: cve }).catch(() => ({ items: [] }))
      )
    ).then(responses => {
      const dedup = new Map()
      responses.forEach(resp => {
        (resp.items || []).forEach(p => {
          const key = `${p.source}:${p.advisory_id}`
          if (!dedup.has(key)) dedup.set(key, p)
        })
      })
      // Sort: recalled first (action required), then known_issues, then stable/unknown.
      const order = { recalled: 0, known_issues: 1, stable: 2, superseded: 3, unknown: 4 }
      const list = [...dedup.values()].sort((a, b) => {
        const sa = order[a.reliability?.status || 'unknown'] ?? 4
        const sb = order[b.reliability?.status || 'unknown'] ?? 4
        return sa - sb
      })
      setPatches(list)
    }).finally(() => setPatchesLoading(false))
  }, [finding?.id, finding?.cves?.join(',')])

  const handleCreateCampaign = async () => {
    if (!finding) return
    setCreatingCampaign(true)
    try {
      const query = [{ field: 'finding.plugin_id', op: 'eq', value: String(finding.plugin_id) }]
      const campaign = await createCampaign({
        name: `Remediate: ${finding.plugin_name}`,
        description: `Campaign to remediate plugin ${finding.plugin_id} — ${finding.plugin_name}`,
        scan_id: finding.scan_id,
        query,
        query_logic: 'AND',
      })
      await runCampaign(campaign.id)
      navigate(`/campaigns/${campaign.id}`)
    } finally {
      setCreatingCampaign(false)
    }
  }

  const handleResolve = async () => {
    setResolving(true)
    try {
      const res = await resolveFinding(id)
      setFinding(prev => ({ ...prev, sla_status: 'resolved', resolved_at: res.resolved_at }))
      toast.success('Finding resolved')
    } finally {
      setResolving(false)
    }
  }

  const handleUnresolve = async () => {
    setResolving(true)
    try {
      const res = await unresolveFinding(id)
      setFinding(prev => ({ ...prev, sla_status: res.sla_status, resolved_at: null }))
      toast.success('Finding reopened')
    } finally {
      setResolving(false)
    }
  }

  const handleStatusChange = async (newStatus) => {
    setStatusUpdating(true)
    try {
      await updateFindingStatus(id, { status: newStatus })
      setFinding(prev => ({ ...prev, workflow_status: newStatus, status_changed_at: new Date().toISOString() }))
    } finally {
      setStatusUpdating(false)
    }
  }

  const handleCreateException = async (type) => {
    try {
      await createException({
        plugin_id: finding.plugin_id,
        plugin_name: finding.plugin_name,
        asset_ip: null, // global
        exception_type: type,
        reason: exceptionReason || `Created from finding #${finding.id}`,
      })
      setFinding(prev => ({ ...prev, workflow_status: type, exception_id: -1 }))
      setShowExceptionForm(false)
      setExceptionReason('')
      toast.success('Exception created')
    } catch (e) {
      toast.error('Failed to create exception: ' + e.message)
    }
  }

  const handleContextChange = async (field, value) => {
    setCtxSaving(true)
    try {
      const updated = await updateFindingContext(id, { [field]: value || null })
      setFinding(prev => ({ ...prev, ...updated }))
      toast.success('Ownership updated')
    } finally {
      setCtxSaving(false)
    }
  }

  if (loading) return <SkeletonDetail />
  if (fetchError) return <ErrorBanner error={fetchError} onRetry={loadFinding} />
  if (!finding) return <div style={{ color: 'var(--text-muted)', padding: 32 }}>Finding not found.</div>

  const bestScore = finding.cvss3_score || finding.cvss2_score

  return (
    <div style={{ maxWidth: 900 }}>
      {/* Back */}
      <button onClick={() => navigate(-1)} style={{
        display: 'flex', alignItems: 'center', gap: 6, background: 'none', border: 'none',
        color: 'var(--text-muted)', cursor: 'pointer', fontSize: 13, marginBottom: 16, padding: 0
      }}>
        <ArrowLeft size={14} /> {t('findingDetail.backToFindings')}
      </button>

      {/* Header */}
      <Card style={{ marginBottom: 14 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
          <div style={{ flex: 1 }}>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', marginBottom: 8 }}>
              <SeverityBadge severity={finding.severity} label={finding.severity_label} />
              {finding.zero_day && <Pill label="0-DAY" color="#dc2626" />}
              {finding.exploit_available && <Pill label="Exploit Known" color="#ea580c" />}
              {finding.exploit_maturity && <Pill label={finding.exploit_maturity} color="#d97706" />}
              {finding.is_kev && <Pill label="CISA KEV" color="#dc2626" />}
              {finding.ssvc_decision && <Pill label={`SSVC: ${finding.ssvc_decision}`} color={finding.ssvc_decision === 'Act' ? '#dc2626' : finding.ssvc_decision === 'Attend' ? '#ea580c' : '#d97706'} />}
              {finding.exploit_count > 0 && <Pill label={`${finding.exploit_count} Exploits`} color="#ea580c" />}
              {finding.exploit_maturity_level && finding.exploit_maturity_level !== 'none' && <Pill label={finding.exploit_maturity_level} color={finding.exploit_maturity_level === 'weaponized' ? '#dc2626' : finding.exploit_maturity_level === 'functional' ? '#ea580c' : '#d97706'} />}
            </div>
            <h1 style={{ fontSize: 18, fontWeight: 700, lineHeight: 1.3, marginBottom: 6 }}>{finding.plugin_name}</h1>
            <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
              {t('findingDetail.pluginId')} {finding.plugin_id}
              {finding.plugin_family && ` · ${finding.plugin_family}`}
              {finding.asset_hostname && ` · ${finding.asset_hostname}`}
              {finding.port && ` · ${t('findingDetail.port')} ${finding.port}/${finding.protocol}`}
            </div>
          </div>

          {finding.asset_hostname && (
            <div style={{ fontSize: 12, color: 'var(--text-muted)', background: 'var(--bg-secondary)', padding: '5px 12px', borderRadius: 6, flexShrink: 0 }}>
              ASSET &nbsp;<span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{finding.asset_hostname}</span>
            </div>
          )}
        </div>

        {/* Score strip */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 16, marginTop: 20, paddingTop: 16, borderTop: '1px solid var(--border)' }}>
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>{t('findingDetail.priorityScore').toUpperCase()}</div>
            <ScoreBar score={finding.priority_score} breakdown={buildFindingBreakdown(finding, riskWeights)} />
          </div>
          {bestScore && (
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>
                {finding.cvss3_score ? t('findingDetail.cvss3BaseScore') : t('findingDetail.cvssBaseScore')}
              </div>
              <ScoreBar score={bestScore} />
            </div>
          )}
          {finding.vpr_score && (
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>{t('findingDetail.vprScore').toUpperCase()}</div>
              <ScoreBar score={finding.vpr_score} />
            </div>
          )}
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>{t('findingDetail.effortLevel').toUpperCase()}</div>
            <EffortBadge effort={finding.effort_level} />
          </div>
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>{t('findingDetail.ownerSuggestion').toUpperCase()}</div>
            <ResolvedOwnerBadge resolved={finding.resolved_owner} />
          </div>
        </div>

        {/* Synopsis */}
        {finding.synopsis && (
          <div style={{ marginTop: 16, padding: '12px 14px', background: 'var(--bg-secondary)', borderRadius: 8, fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
            {finding.synopsis}
          </div>
        )}
      </Card>

      {/* Custom attributes (user-defined fields) */}
      <CustomAttributesCard
        entityType="finding"
        entityId={finding.id}
        values={finding.custom_fields}
        onChange={next => setFinding(prev => ({ ...prev, custom_fields: next }))}
      />

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 0, marginBottom: 20, borderBottom: '1px solid var(--border)' }}>
        {[
          { key: 'overview', icon: Zap, label: 'Overview' },
          { key: 'context', icon: Eye, label: 'Context' },
          { key: 'remediation', icon: Shield, label: 'Remediation' },
          { key: 'technical', icon: Terminal, label: 'Technical' },
          { key: 'sources', icon: Layers, label: 'Sources' },
        ].map(({ key, icon: Icon, label }) => {
          const active = activeTab === key
          return (
            <button
              key={key}
              onClick={() => setActiveTab(key)}
              style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '10px 18px', background: 'none', border: 'none',
                borderBottom: active ? '2px solid var(--accent)' : '2px solid transparent',
                color: active ? 'var(--accent)' : 'var(--text-muted)',
                fontSize: 13, fontWeight: 600, cursor: 'pointer', transition: 'color 0.15s',
              }}
            >
              <Icon size={14} />
              {label}
            </button>
          )
        })}
      </div>

      {activeTab === 'overview' && (<>
      {/* Blast Radius */}
      {finding.asset_id && (
        <div style={{ marginBottom: 14 }}>
          <BlastRadiusPanel assetId={finding.asset_id} findingId={finding.id} />
        </div>
      )}

      {/* SLA */}
      {finding.sla_status && finding.sla_status !== 'n/a' && (() => {
        const now = new Date()
        const due = finding.sla_due_date ? new Date(finding.sla_due_date) : null
        const daysLeft = due ? Math.ceil((due - now) / 86400000) : null
        const resolvedDate = finding.resolved_at ? new Date(finding.resolved_at) : null

        const statusCfg = {
          on_track: { color: '#16a34a', bg: 'rgba(22,163,74,0.08)', border: 'rgba(22,163,74,0.3)', label: t('findingDetail.slaOnTrack') },
          at_risk:  { color: '#d97706', bg: 'rgba(217,119,6,0.08)',  border: 'rgba(217,119,6,0.3)',  label: t('findingDetail.slaAtRisk') },
          breached: { color: '#dc2626', bg: 'rgba(220,38,38,0.08)',  border: 'rgba(220,38,38,0.3)',  label: t('findingDetail.slaBreached') },
          resolved: { color: '#6366f1', bg: 'rgba(99,102,241,0.08)', border: 'rgba(99,102,241,0.3)', label: t('findingDetail.slaResolved') },
        }[finding.sla_status] || { color: '#6b7280', bg: 'transparent', border: 'var(--border)', label: finding.sla_status }

        return (
          <Card style={{ marginBottom: 14, background: statusCfg.bg, borderColor: statusCfg.border }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <Clock size={16} color={statusCfg.color} />
                <div>
                  <div style={{ fontSize: 13, fontWeight: 600, color: statusCfg.color }}>{statusCfg.label}</div>
                  <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
                    {finding.sla_status === 'resolved' && resolvedDate
                      ? `Resolved on ${resolvedDate.toLocaleDateString()}`
                      : due
                        ? daysLeft >= 0
                          ? `Due ${due.toLocaleDateString()} · ${daysLeft} day${daysLeft !== 1 ? 's' : ''} remaining`
                          : `Due ${due.toLocaleDateString()} · ${Math.abs(daysLeft)} day${Math.abs(daysLeft) !== 1 ? 's' : ''} overdue`
                        : 'No SLA due date set'}
                    {finding.sla_observed_date && (
                      <span style={{ marginLeft: 8, opacity: 0.7 }}>
                        · Observed {new Date(finding.sla_observed_date).toLocaleDateString()}
                      </span>
                    )}
                  </div>
                </div>
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                {finding.sla_status !== 'resolved' ? (
                  <Button onClick={handleResolve} disabled={resolving} size="sm">
                    <CheckCircle size={13} />
                    {resolving ? 'Marking…' : t('findingDetail.resolve')}
                  </Button>
                ) : (
                  <Button variant="ghost" onClick={handleUnresolve} disabled={resolving} size="sm">
                    <RotateCcw size={13} />
                    {resolving ? 'Reopening…' : t('findingDetail.unresolve')}
                  </Button>
                )}
              </div>
            </div>
          </Card>
        )
      })()}

      {/* Temporal Tracking */}
      {(finding.first_seen || finding.is_regression) && (
        <Card style={{
          marginBottom: 14,
          ...(finding.is_regression ? { background: 'rgba(220,38,38,0.06)', borderColor: 'rgba(220,38,38,0.25)' } : {}),
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            {finding.is_regression && (
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '3px 8px', borderRadius: 4, background: 'rgba(220,38,38,0.15)', color: 'var(--danger)', fontSize: 12, fontWeight: 600 }}>
                <RotateCcw size={11} /> {t('findings.regression')}
              </span>
            )}
            {finding.first_seen && (
              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                {t('findingDetail.firstSeen')}: {new Date(finding.first_seen).toLocaleDateString()}
              </span>
            )}
            {finding.last_seen && (
              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                · {t('findingDetail.lastSeen')}: {new Date(finding.last_seen).toLocaleDateString()}
              </span>
            )}
            {finding.times_seen > 1 && (
              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                · {t('findingDetail.timesSeen')}: {finding.times_seen} {t('findingDetail.scans')}
              </span>
            )}
          </div>
        </Card>
      )}

      {/* Workflow Status */}
      <Card style={{ marginBottom: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14, paddingBottom: 12, borderBottom: '1px solid var(--border)' }}>
          <UserCheck size={16} color="var(--accent)" />
          <span style={{ fontWeight: 600, fontSize: 14 }}>{t('findingDetail.workflow')} {t('findingDetail.workflowStatus')}</span>
        </div>
        {(() => {
          const steps = [
            { value: 'open', label: t('findings.open'), color: '#6b7280' },
            { value: 'in_progress', label: t('findingDetail.inProgress'), color: '#3b82f6' },
            { value: 'resolved', label: t('findingDetail.slaResolved'), color: '#22c55e' },
          ]
          const currentStatus = finding.workflow_status || 'open'
          const currentIdx = steps.findIndex(s => s.value === currentStatus)
          return (
            <div style={{ display: 'flex', alignItems: 'center', gap: 0, marginBottom: 12 }}>
              {steps.map((s, i) => {
                const isActive = s.value === currentStatus
                const isPast = i < currentIdx
                const stepColor = isActive || isPast ? s.color : 'var(--border)'
                return (
                  <React.Fragment key={s.value}>
                    {i > 0 && (
                      <div style={{
                        flex: 1, height: 2, maxWidth: 40,
                        background: isPast || isActive ? steps[Math.min(i, currentIdx)].color : 'var(--border)',
                        transition: 'background 0.2s',
                      }} />
                    )}
                    <button
                      disabled={statusUpdating}
                      onClick={() => handleStatusChange(s.value)}
                      style={{
                        display: 'flex', alignItems: 'center', gap: 6,
                        padding: '6px 14px', borderRadius: 20, fontSize: 12, fontWeight: 600,
                        border: `2px solid ${stepColor}`,
                        background: isActive ? stepColor : isPast ? `${stepColor}18` : 'transparent',
                        color: isActive ? '#fff' : isPast ? stepColor : 'var(--text-muted)',
                        cursor: statusUpdating ? 'wait' : 'pointer',
                        transition: 'all 0.15s ease',
                      }}
                    >
                      {isPast && <CheckCircle size={12} />}
                      {s.label}
                    </button>
                  </React.Fragment>
                )
              })}
              <div style={{ flex: 1 }} />
              <button
                disabled={statusUpdating}
                onClick={() => setShowExceptionForm(!showExceptionForm)}
                style={{
                  padding: '6px 14px', borderRadius: 20, fontSize: 12, fontWeight: 600,
                  border: '2px solid #d97706',
                  background: ['accepted_risk', 'false_positive', 'compensating_control'].includes(currentStatus) ? '#d97706' : 'transparent',
                  color: ['accepted_risk', 'false_positive', 'compensating_control'].includes(currentStatus) ? '#fff' : '#d97706',
                  cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4,
                }}
              >
                <ShieldOff size={13} />
                {finding.exception_id ? t('findingDetail.exception') : t('findingDetail.createException')}
              </button>
            </div>
          )
        })()}

        {finding.workflow_assigned_to && (
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 8 }}>
            {t('findings.assignedTo')}: <span style={{ color: 'var(--text)', fontWeight: 500 }}>{finding.workflow_assigned_to}</span>
          </div>
        )}
        {finding.status_changed_at && (
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            Last status change: {new Date(finding.status_changed_at).toLocaleString()}
          </div>
        )}

        {/* Linked External Tickets */}
        {finding.tickets && finding.tickets.length > 0 && (
          <div style={{ marginTop: 12, padding: 12, background: 'var(--bg-muted)', borderRadius: 8, border: '1px solid var(--border)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
              <Ticket size={14} color="var(--accent)" />
              <span style={{ fontSize: 13, fontWeight: 600 }}>Linked Tickets</span>
              <button
                onClick={async () => {
                  try {
                    const result = await syncFindingTickets(finding.id)
                    if (result.tickets) {
                      setFinding(prev => ({ ...prev, tickets: result.tickets }))
                    }
                  } catch (e) { console.error('Ticket sync failed', e) }
                }}
                style={{ marginLeft: 'auto', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 4, fontSize: 11 }}
                title="Sync ticket status"
              >
                <RefreshCw size={12} /> Sync
              </button>
            </div>
            {finding.tickets.map((ticket) => (
              <div key={ticket.id} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 0', borderTop: '1px solid var(--border)', fontSize: 12 }}>
                <span style={{ textTransform: 'capitalize', color: 'var(--text-muted)', minWidth: 70, fontSize: 11 }}>{ticket.ticket_system}</span>
                <a href={ticket.ticket_url} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent)', fontWeight: 500, display: 'flex', alignItems: 'center', gap: 4 }}>
                  {ticket.ticket_key} <ExternalLink size={10} />
                </a>
                {ticket.external_status && (
                  <Pill color={ticket.mapped_status === 'resolved' ? '#22c55e' : ticket.mapped_status === 'in_progress' ? '#3b82f6' : '#6b7280'}>
                    {ticket.external_status}
                  </Pill>
                )}
                {ticket.last_synced_at && (
                  <span style={{ color: 'var(--text-muted)', marginLeft: 'auto', fontSize: 10 }}>
                    Synced {new Date(ticket.last_synced_at).toLocaleString()}
                  </span>
                )}
                {ticket.sync_error && (
                  <span style={{ color: '#ef4444', fontSize: 10 }} title={ticket.sync_error}>⚠</span>
                )}
              </div>
            ))}
          </div>
        )}

        {showExceptionForm && (
          <div style={{ marginTop: 12, padding: 14, background: 'var(--bg-muted)', borderRadius: 8, border: '1px solid var(--border)' }}>
            <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 8 }}>{t('findingDetail.createException')} — {t('findingDetail.pluginId')} {finding.plugin_id}</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 10 }}>
              This will apply to all findings with this plugin across all scans.
            </div>
            <textarea
              value={exceptionReason}
              onChange={e => setExceptionReason(e.target.value)}
              placeholder="Reason for exception..."
              style={{
                width: '100%', minHeight: 60, padding: '8px 12px', borderRadius: 8,
                border: '1px solid var(--border)', fontSize: 12, resize: 'vertical',
                background: 'var(--bg-card)', color: 'var(--text-primary)', marginBottom: 10, boxSizing: 'border-box',
              }}
            />
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              <Button size="sm" onClick={() => handleCreateException('accepted_risk')} style={{ background: '#d97706' }}>
                {t('findingDetail.acceptedRisk')}
              </Button>
              <Button size="sm" onClick={() => handleCreateException('false_positive')} style={{ background: '#3b82f6' }}>
                {t('findings.falsePositive')}
              </Button>
              <Button size="sm" onClick={() => handleCreateException('compensating_control')} style={{ background: '#10b981' }}>
                {t('findingDetail.compensatingControl')}
              </Button>
              <Button size="sm" onClick={() => handleCreateException('technical_debt')} style={{ background: '#7c3aed' }}>
                {t('findingDetail.technicalDebt')}
              </Button>
              <Button variant="ghost" size="sm" onClick={() => setShowExceptionForm(false)}>{t('common.cancel')}</Button>
            </div>
          </div>
        )}
      </Card>
      </>)}

      {activeTab === 'context' && (<>
      {/* Validated Context */}
      {(() => {
        const ctx = finding.context || {}
        const ctxVal = (field) => ctx[field]?.value || ''
        const ctxSource = (field) => ctx[field]?.source
        const sourceBadge = (field) => {
          const s = ctxSource(field)
          if (!s) return null
          const isInferred = s === 'inferred'
          return (
            <span style={{
              fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em',
              padding: '1px 5px', borderRadius: 3, marginLeft: 6,
              background: isInferred ? 'rgba(59,130,246,0.12)' : 'rgba(16,185,129,0.12)',
              color: isInferred ? '#3b82f6' : '#10b981',
            }}>
              {isInferred ? 'auto' : 'manual'}
            </span>
          )
        }
        const selectStyle = {
          width: '100%', padding: '7px 10px', borderRadius: 6, fontSize: 13,
          border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text-primary)',
          cursor: 'pointer',
        }
        const fmtOption = (o) => o.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())

        return (
            <Section title="Context & Risk Factors" icon={Eye}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                {[
                  { field: 'ctx_reachability', label: 'Reachability', options: ['unreachable', 'internal_only', 'internet_facing', 'unknown'] },
                  { field: 'ctx_exploitability', label: 'Exploitability', options: ['not_exploitable', 'requires_conditions', 'easily_exploitable', 'unknown'] },
                  { field: 'ctx_accessibility', label: 'Accessibility', options: ['restricted', 'authenticated_only', 'public', 'unknown'] },
                ].map(({ field, label, options }) => (
                  <div key={field}>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.05em', display: 'flex', alignItems: 'center' }}>
                      {label}{sourceBadge(field)}
                    </div>
                    <select value={ctxVal(field)} onChange={e => handleContextChange(field, e.target.value)} style={selectStyle}>
                      <option value="">— Not set —</option>
                      {options.map(o => <option key={o} value={o}>{fmtOption(o)}</option>)}
                    </select>
                  </div>
                ))}
                <div style={{ gridColumn: '1 / -1' }}>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.05em', display: 'flex', alignItems: 'center' }}>
                    Compensating Control{sourceBadge('ctx_compensating_control')}
                  </div>
                  {(() => {
                    const raw = ctxVal('ctx_compensating_control') || '';
                    const controlTypeColors = { EDR: '#8b5cf6', AV: '#3b82f6', FIREWALL: '#f59e0b', IDS: '#ef4444', IPS: '#ef4444', DLP: '#06b6d4', SIEM: '#ec4899', WAF: '#10b981', HIPS: '#f97316', IDENTITY: '#a855f7', BACKUP: '#0ea5e9' };
                    let parsedControls = [];
                    if (raw.includes('Active security controls on host:')) {
                      const afterPrefix = raw.split('Active security controls on host:')[1] || '';
                      parsedControls = afterPrefix.split(';').map(s => s.trim()).filter(Boolean).map(entry => {
                        // Match TYPE: Product (Vendor) [outdated] — vendor is last parenthesized group
                        const typeMatch = entry.match(/^([A-Z_]+):\s*(.+)$/);
                        if (!typeMatch) return { type: null, product: entry.replace(/\s*\[outdated\]/, ''), vendor: null, outdated: entry.includes('[outdated]') };
                        const type = typeMatch[1];
                        let rest = typeMatch[2];
                        const outdated = rest.includes('[outdated]');
                        rest = rest.replace(/\s*\[outdated\]/, '').trim();
                        // Extract last (Vendor) if present
                        const vendorMatch = rest.match(/^(.+)\s+\(([^)]+)\)$/);
                        const product = vendorMatch ? vendorMatch[1].trim() : rest;
                        const vendor = vendorMatch ? vendorMatch[2] : null;
                        return { type, product, vendor, outdated };
                      });
                    }

                    if (parsedControls.length === 0 && !raw) {
                      return <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>No compensating controls detected</span>;
                    }

                    const MAX_CONTROLS = 4;
                    const visibleControls = showAllControls ? parsedControls : parsedControls.slice(0, MAX_CONTROLS);
                    const hiddenControlCount = parsedControls.length - MAX_CONTROLS;

                    return (
                      <>
                        {parsedControls.length > 0 ? (
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>
                            <span style={{ fontSize: 12, color: 'var(--text-muted)', fontWeight: 600 }}>{parsedControls.length} controls</span>
                            {visibleControls.map((ctrl, i) => (
                              <div key={i} style={{
                                display: 'flex', alignItems: 'center', gap: 6, padding: '6px 12px',
                                borderRadius: 8, fontSize: 12, fontWeight: 500,
                                background: `${controlTypeColors[ctrl.type] || '#6b7280'}18`,
                                border: `1px solid ${controlTypeColors[ctrl.type] || '#6b7280'}40`,
                                color: 'var(--text-primary)',
                              }}>
                                <span style={{
                                  fontSize: 9, fontWeight: 700, letterSpacing: '0.05em',
                                  padding: '2px 5px', borderRadius: 4,
                                  background: controlTypeColors[ctrl.type] || '#6b7280',
                                  color: '#fff',
                                }}>{ctrl.type || 'CTRL'}</span>
                                <span>{ctrl.product}</span>
                                {ctrl.vendor && <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>({ctrl.vendor})</span>}
                                {ctrl.outdated && <span style={{
                                  fontSize: 9, fontWeight: 600, padding: '1px 5px', borderRadius: 4,
                                  background: '#ef444425', color: '#ef4444', border: '1px solid #ef444440',
                                }}>outdated</span>}
                              </div>
                            ))}
                            {hiddenControlCount > 0 && !showAllControls && (
                              <button onClick={() => setShowAllControls(true)} style={{
                                padding: '4px 10px', borderRadius: 12, fontSize: 12, fontWeight: 600,
                                border: '1px solid var(--border)', background: 'var(--bg-secondary)',
                                color: 'var(--text-muted)', cursor: 'pointer',
                              }}>+{hiddenControlCount} more</button>
                            )}
                            {showAllControls && hiddenControlCount > 0 && (
                              <button onClick={() => setShowAllControls(false)} style={{
                                padding: '4px 10px', borderRadius: 12, fontSize: 12, fontWeight: 600,
                                border: '1px solid var(--border)', background: 'var(--bg-secondary)',
                                color: 'var(--text-muted)', cursor: 'pointer',
                              }}>Show less</button>
                            )}
                          </div>
                        ) : (
                          <div style={{
                            padding: '8px 10px', borderRadius: 6, fontSize: 13,
                            background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                            color: 'var(--text-primary)', lineHeight: 1.5,
                          }}>{raw}</div>
                        )}
                      </>
                    );
                  })()}
                </div>
              </div>
              {/* Business Context sub-section */}
              <div style={{ marginTop: 16, paddingTop: 14, borderTop: '1px solid var(--border)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                  <Briefcase size={14} color="var(--text-muted)" />
                  <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Business Context</span>
                  <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>— {getFindingAssetDisplay(finding)}</span>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
                  <div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.05em', display: 'flex', alignItems: 'center' }}>
                      Function{sourceBadge('biz_function')}
                    </div>
                    <input
                      type="text"
                      value={finding._localBizFunc ?? ctxVal('biz_function')}
                      onChange={e => setFinding(prev => ({ ...prev, _localBizFunc: e.target.value }))}
                      onBlur={e => { handleContextChange('biz_function', e.target.value); setFinding(prev => { const { _localBizFunc, ...rest } = prev; return rest }) }}
                      placeholder="e.g. Payment Processing"
                      style={{
                        width: '100%', padding: '7px 10px', borderRadius: 6, fontSize: 13,
                        border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text-primary)',
                        boxSizing: 'border-box',
                      }}
                    />
                  </div>
                  <div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.05em', display: 'flex', alignItems: 'center' }}>
                      No. of Users{sourceBadge('biz_num_users')}
                    </div>
                    <input
                      type="number"
                      min="0"
                      value={finding._localBizUsers ?? (ctx.biz_num_users?.value ?? '')}
                      onChange={e => setFinding(prev => ({ ...prev, _localBizUsers: e.target.value === '' ? '' : parseInt(e.target.value) }))}
                      onBlur={e => { handleContextChange('biz_num_users', e.target.value === '' ? null : parseInt(e.target.value)); setFinding(prev => { const { _localBizUsers, ...rest } = prev; return rest }) }}
                      placeholder="0"
                      style={{
                        width: '100%', padding: '7px 10px', borderRadius: 6, fontSize: 13,
                        border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text-primary)',
                        boxSizing: 'border-box',
                      }}
                    />
                  </div>
                  <div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.05em', display: 'flex', alignItems: 'center' }}>
                      Revenue Impact{sourceBadge('biz_revenue_impact')}
                    </div>
                    <select value={ctxVal('biz_revenue_impact')} onChange={e => handleContextChange('biz_revenue_impact', e.target.value)} style={selectStyle}>
                      <option value="">— Not set —</option>
                      <option value="none">None</option>
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                      <option value="critical">Critical</option>
                    </select>
                  </div>
                </div>
              </div>
            </Section>
        )
      })()}
      </>)}

      {activeTab === 'remediation' && (<>

      {/* Control Validation */}
      {(finding.control_mitigation_status || assessments.length > 0) && (
        <Card style={{ marginBottom: 14, border: `1px solid ${finding.control_mitigation_status === 'mitigated' ? '#22c55e40' : finding.control_mitigation_status === 'partially_mitigated' ? '#f59e0b40' : finding.control_mitigation_status === 'not_mitigated' ? '#dc262640' : 'var(--border)'}`, background: finding.control_mitigation_status === 'mitigated' ? '#22c55e08' : 'var(--bg-card)' }}>
          <div style={{ padding: '14px 18px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
              <ShieldCheck size={18} color={finding.control_mitigation_status === 'mitigated' ? '#22c55e' : finding.control_mitigation_status === 'partially_mitigated' ? '#f59e0b' : '#dc2626'} />
              <span style={{
                fontSize: 13, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em',
                color: finding.control_mitigation_status === 'mitigated' ? '#22c55e' : finding.control_mitigation_status === 'partially_mitigated' ? '#f59e0b' : '#dc2626',
              }}>
                {finding.control_mitigation_status === 'mitigated' ? 'Mitigated' : finding.control_mitigation_status === 'partially_mitigated' ? 'Partially Mitigated' : 'Not Mitigated'}
              </span>
            </div>
            {finding.control_mitigation_summary && (
              <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: 12 }}>
                {finding.control_mitigation_summary}
              </div>
            )}
            {assessments.length > 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {assessments.map(a => (
                  <div key={a.id} style={{
                    display: 'flex', alignItems: 'flex-start', gap: 10, padding: '10px 12px',
                    borderRadius: 8, background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                  }}>
                    <ShieldCheck size={14} color={a.verdict === 'mitigated' ? '#22c55e' : a.verdict === 'partially_mitigated' ? '#f59e0b' : '#dc2626'} style={{ marginTop: 2, flexShrink: 0 }} />
                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                        <span style={{ fontSize: 13, fontWeight: 600 }}>{a.policy?.product_name || a.policy?.product_key}</span>
                        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{a.policy?.policy_name}</span>
                        <span style={{
                          fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em',
                          padding: '2px 6px', borderRadius: 4, marginLeft: 'auto',
                          background: a.confidence === 'high' ? '#22c55e18' : a.confidence === 'medium' ? '#f59e0b18' : '#6b728018',
                          color: a.confidence === 'high' ? '#22c55e' : a.confidence === 'medium' ? '#f59e0b' : '#6b7280',
                        }}>{a.confidence}</span>
                      </div>
                      <div style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.5 }}>{a.explanation}</div>
                      {a.matched_techniques?.length > 0 && (
                        <div style={{ display: 'flex', gap: 4, marginTop: 6, flexWrap: 'wrap' }}>
                          {a.matched_techniques.map(t => (
                            <span key={t} style={{
                              fontSize: 10, fontWeight: 600, padding: '2px 6px', borderRadius: 4,
                              background: 'var(--bg-muted)', border: '1px solid var(--border)', color: 'var(--text-muted)',
                            }}>{t}</span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </Card>
      )}

      {/* Aggregated Solution Banner */}
      {finding.aggregated_solution && (
        <Card style={{ marginBottom: 14, border: '1px solid #7c3aed40', background: '#7c3aed08' }}>
          <div style={{ padding: '14px 18px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
              <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 700, background: '#7c3aed20', color: '#7c3aed', border: '1px solid #7c3aed40' }}>
                ROOT CAUSE
              </span>
              <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>
                {finding.aggregated_solution.title}
              </span>
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
              This finding is part of a group of {finding.aggregated_solution.finding_count} related findings
              that share the same root cause. Instead of fixing each individually, apply the aggregated solution below.
            </div>
            <div style={{ marginTop: 10, fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.7, background: 'var(--bg-secondary)', padding: '12px 14px', borderRadius: 8 }}>
              <ReactMarkdown remarkPlugins={[remarkGfm]}>{finding.aggregated_solution.description}</ReactMarkdown>
            </div>
            <div style={{ marginTop: 12 }}>
              <Button
                onClick={() => navigate(`/aggregated-solutions?highlight=${finding.aggregated_solution.id}`)}
                style={{ background: '#7c3aed', color: '#fff', border: 'none', display: 'inline-flex', alignItems: 'center', gap: 6, padding: '8px 14px', fontSize: 13 }}
              >
                <Layers size={14} /> View Aggregated Remediation
              </Button>
            </div>
          </div>
        </Card>
      )}

      {/* Technical Debt Banner */}
      {finding.technical_debt && (
        <Card style={{ marginBottom: 14, border: '1px solid #d9770640', background: '#d9770608' }}>
          <div style={{ padding: '14px 18px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
              <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 700, background: '#d9770620', color: '#d97706', border: '1px solid #d9770640' }}>
                TECHNICAL DEBT
              </span>
              <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>
                {finding.technical_debt.title}
              </span>
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: 6 }}>
              <strong>Why it can't be fixed:</strong> {finding.technical_debt.reason}
            </div>
            {finding.technical_debt.mitigation_plan && (
              <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                <strong>Mitigation:</strong> {finding.technical_debt.mitigation_plan}
              </div>
            )}
            {finding.technical_debt.review_status === 'overdue' && (
              <div style={{ marginTop: 8, fontSize: 12, fontWeight: 600, color: '#dc2626', display: 'flex', alignItems: 'center', gap: 4 }}>
                <Clock size={14} /> Review overdue — last review date: {new Date(finding.technical_debt.review_by).toLocaleDateString()}
              </div>
            )}
          </div>
        </Card>
      )}

      {/* Remediation */}
      <Section title={t('findingDetail.solution')} icon={Shield}>
        <RemediationSteps text={finding.remediation_steps} />
        {finding.solution && (
          <div style={{ marginTop: 14 }}>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.05em' }}>{t('findingDetail.solution')}</div>
            <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6, whiteSpace: 'pre-wrap' }}>{finding.solution}</div>
          </div>
        )}
        <div style={{ marginTop: 16 }}>
          <Button onClick={handleCreateCampaign} disabled={creatingCampaign} style={{ width: '100%', justifyContent: 'center', padding: '11px 16px' }}>
            <Zap size={16} /> {creatingCampaign ? 'Creating…' : t('findingDetail.createCampaign')}
          </Button>
        </div>
      </Section>
      </>)}

      {activeTab === 'technical' && (<>
      {/* Description */}
      {finding.description && (
        <Section title={t('findingDetail.description')} icon={Info} defaultOpen={false}>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.7, whiteSpace: 'pre-wrap' }}>
            {finding.description}
          </div>
        </Section>
      )}

      {/* Plugin Output */}
      {finding.plugin_output && (
        <Section title={t('findingDetail.pluginOutput')} icon={Terminal} defaultOpen={false}>
          <PreText text={finding.plugin_output} />
        </Section>
      )}

      {/* Technical Details */}
      <Section title={t('findingDetail.pluginDetails')} icon={Info} defaultOpen={false}>
        <KeyVal label={t('findingDetail.pluginId')} value={finding.plugin_id} />
        <KeyVal label={t('findingDetail.pluginFamily')} value={finding.plugin_family} />
        <KeyVal label={t('findingDetail.riskFactor')} value={finding.risk_factor} />
        <KeyVal label={t('findingDetail.vulnerabilityState')} value={finding.vulnerability_state} />
        <KeyVal label={`${t('findingDetail.port')} / ${t('findingDetail.protocol')}`} value={finding.port ? `${finding.port} / ${finding.protocol}` : null} />
        <KeyVal label={t('findingDetail.cvss3BaseScore')} value={finding.cvss3_score ? `${finding.cvss3_score} (${finding.cvss3_vector || ''})` : null} />
        <KeyVal label={t('findingDetail.cvssBaseScore')} value={finding.cvss2_score ? `${finding.cvss2_score} (${finding.cvss2_vector || ''})` : null} />
        <KeyVal label={t('findingDetail.vprScore')} value={finding.vpr_score} />
        <KeyVal label={t('findingDetail.exploitAvailable')} value={finding.exploit_available ? t('common.yes') : t('common.no')} />
        <KeyVal label={t('findingDetail.exploitMaturity')} value={finding.exploit_maturity} />
        <KeyVal label={t('findingDetail.zeroDay')} value={finding.zero_day ? t('common.yes') : null} />
        <KeyVal label="Plugin Published" value={finding.plugin_pub_date} />
        <KeyVal label="Plugin Modified" value={finding.plugin_mod_date} />

        {/* CVEs */}
        {finding.cves && finding.cves.length > 0 && (() => {
          const MAX_VISIBLE = 6
          const visibleCves = showAllCves ? finding.cves : finding.cves.slice(0, MAX_VISIBLE)
          const hiddenCount = finding.cves.length - MAX_VISIBLE
          return (
            <div style={{ padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
              <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 8 }}>{t('findingDetail.cves')} ({finding.cves.length})</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, alignItems: 'center' }}>
                {visibleCves.map(cve => (
                  <span key={cve} style={{ display: 'inline-flex', alignItems: 'center', gap: 2 }}>
                    <a
                      href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{ display: 'flex', alignItems: 'center', gap: 4 }}
                    >
                      <Pill label={cve} color="#f59e0b" />
                    </a>
                    <a
                      href={`/inventory?tab=software`}
                      onClick={e => { e.preventDefault(); navigate(`/inventory?tab=software`) }}
                      title="View in software inventory"
                      style={{ fontSize: 10, color: 'var(--accent)', fontWeight: 600, textDecoration: 'none', whiteSpace: 'nowrap' }}
                    >
                      software
                    </a>
                  </span>
                ))}
                {hiddenCount > 0 && !showAllCves && (
                  <button
                    onClick={() => setShowAllCves(true)}
                    style={{
                      padding: '4px 10px', borderRadius: 12, fontSize: 12, fontWeight: 600,
                      border: '1px solid var(--border)', background: 'var(--bg-secondary)',
                      color: 'var(--text-muted)', cursor: 'pointer',
                    }}
                  >
                    +{hiddenCount} more
                  </button>
                )}
                {showAllCves && hiddenCount > 0 && (
                  <button
                    onClick={() => setShowAllCves(false)}
                    style={{
                      padding: '4px 10px', borderRadius: 12, fontSize: 12, fontWeight: 600,
                      border: '1px solid var(--border)', background: 'var(--bg-secondary)',
                      color: 'var(--text-muted)', cursor: 'pointer',
                    }}
                  >
                    Show less
                  </button>
                )}
              </div>
            </div>
          )
        })()}

        {/* See Also */}
        {finding.see_also && finding.see_also.length > 0 && (
          <div style={{ padding: '8px 0' }}>
            <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 8 }}>{t('findingDetail.references')}</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {finding.see_also.map((url, i) => (
                <a key={i} href={url} target="_blank" rel="noopener noreferrer" style={{ fontSize: 12, color: 'var(--accent)', display: 'flex', alignItems: 'center', gap: 4 }}>
                  <ExternalLink size={11} /> {url}
                </a>
              ))}
            </div>
          </div>
        )}
      </Section>

      {/* Available patches for the finding's CVEs, annotated with reliability */}
      {finding.cves && finding.cves.length > 0 && (
        <Section title="Available Patches" icon={Wrench} defaultOpen={true}>
          {patchesLoading ? (
            <Spinner />
          ) : patches.length === 0 ? (
            <div style={{ fontSize: 13, color: 'var(--text-muted)', padding: '8px 0' }}>
              No patch advisories found for this finding's CVEs.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {patches.map((p, i) => {
                const isRecalled = p.reliability?.status === 'recalled'
                const hasKnown = p.reliability?.status === 'known_issues'
                return (
                  <div key={i} style={{
                    display: 'flex', alignItems: 'flex-start', gap: 10,
                    padding: '10px 12px', borderRadius: 6,
                    background: isRecalled ? '#dc262608' : hasKnown ? '#f59e0b08' : 'var(--bg-secondary)',
                    border: `1px solid ${isRecalled ? '#dc262640' : hasKnown ? '#f59e0b40' : 'var(--border)'}`,
                  }}>
                    <Wrench size={14} style={{ color: 'var(--text-muted)', marginTop: 3, flexShrink: 0 }} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                        <Pill label={p.source} color="#6366f1" />
                        <span style={{ fontWeight: 600, fontSize: 13, fontFamily: 'monospace', color: 'var(--text-primary)' }}>
                          {p.advisory_id}
                        </span>
                        {p.severity && <SeverityBadge severity={p.severity} />}
                        <PatchReliabilityBadge reliability={p.reliability} size="sm" />
                      </div>
                      {p.title && (
                        <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4 }}>
                          {p.title}
                        </div>
                      )}
                      {(isRecalled || hasKnown) && (
                        <div style={{ marginTop: 6, fontSize: 12, color: 'var(--text-secondary)' }}>
                          {p.reliability?.recall_reason && (
                            <div style={{ color: '#dc2626', fontWeight: 600, marginBottom: 4 }}>
                              {p.reliability.recall_reason}
                            </div>
                          )}
                          {Array.isArray(p.reliability?.known_issues) && p.reliability.known_issues.length > 0 && (
                            <ul style={{ margin: 0, paddingLeft: 16 }}>
                              {p.reliability.known_issues.slice(0, 3).map((iss, idx) => (
                                <li key={idx}>
                                  {iss.url ? (
                                    <a href={iss.url} target="_blank" rel="noreferrer" style={{ color: 'var(--accent)' }}>
                                      {iss.title || 'Issue'}
                                    </a>
                                  ) : (iss.title || 'Issue')}
                                </li>
                              ))}
                              {p.reliability.known_issues.length > 3 && (
                                <li style={{ color: 'var(--text-muted)' }}>
                                  +{p.reliability.known_issues.length - 3} more
                                </li>
                              )}
                            </ul>
                          )}
                        </div>
                      )}
                    </div>
                    {p.url && (
                      <a
                        href={p.url}
                        target="_blank"
                        rel="noreferrer"
                        style={{ color: 'var(--accent)', flexShrink: 0 }}
                        title="Open advisory"
                      >
                        <ExternalLink size={13} />
                      </a>
                    )}
                  </div>
                )
              })}
              {finding.cves.length > 8 && (
                <div style={{ fontSize: 11, color: 'var(--text-muted)', fontStyle: 'italic' }}>
                  Showing patches for the first 8 CVEs (of {finding.cves.length}).
                </div>
              )}
            </div>
          )}
        </Section>
      )}
      </>)}

      {activeTab === 'sources' && <FindingSourcesTab finding={finding} />}

    </div>
  )
}


const FINDING_SOURCE_LABELS = {
  nessus: 'Nessus', tenable_sc: 'Tenable.sc', qualys: 'Qualys', rapid7: 'Rapid7',
  openvas: 'OpenVAS', crowdstrike: 'CrowdStrike', wiz: 'Wiz', easm: 'EASM',
  vm_scanner: 'VM Scanner',
}

const FINDING_FIELD_LABELS = {
  plugin_id: 'Plugin ID', plugin_name: 'Name', plugin_family: 'Family',
  severity: 'Severity', severity_label: 'Severity Label', cvss3_score: 'CVSS3 Score',
  cvss3_vector: 'CVSS3 Vector', cvss2_score: 'CVSS2 Score', vpr_score: 'VPR Score',
  description: 'Description', solution: 'Solution', synopsis: 'Synopsis',
  port: 'Port', protocol: 'Protocol', plugin_output: 'Plugin Output',
  exploit_available: 'Exploit Available', exploit_maturity: 'Exploit Maturity',
  title: 'Title', cve_id: 'CVE', template_id: 'Template ID', matched_at: 'Matched At',
}

function FindingSourcesTab({ finding }) {
  const [sources, setSources] = useState([])
  const [loading, setLoading] = useState(true)
  const [expanded, setExpanded] = useState(null)

  useEffect(() => {
    setLoading(true)
    getFindingSources(finding.id)
      .then(data => {
        setSources(data || [])
        if (data?.length) setExpanded(data[0].source_system)
      })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [finding.id])

  if (loading) return <div style={{ padding: 32, textAlign: 'center' }}><Spinner /></div>

  if (!sources.length) {
    return (
      <Card style={{ padding: 32, textAlign: 'center' }}>
        <Layers size={28} style={{ color: 'var(--text-muted)', marginBottom: 8 }} />
        <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>No Source Data</div>
        <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>
          Source observations are recorded when findings are imported from scanners or integrations.
        </div>
      </Card>
    )
  }

  return (
    <div>
      <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 16 }}>
        Raw data from each source that reported this finding ({sources.length} source{sources.length !== 1 ? 's' : ''})
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {sources.map(src => {
          const isOpen = expanded === src.source_system
          const fields = src.raw_fields || {}
          const displayName = FINDING_SOURCE_LABELS[src.source_system] || src.source_system
          return (
            <Card key={src.source_system} style={{ padding: 0, overflow: 'hidden' }}>
              <button
                onClick={() => setExpanded(isOpen ? null : src.source_system)}
                style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  width: '100%', padding: '14px 16px', background: 'none', border: 'none',
                  cursor: 'pointer', textAlign: 'left',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span style={{
                    display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                    width: 28, height: 28, borderRadius: 6,
                    background: 'var(--accent-muted)', color: 'var(--accent)',
                    fontSize: 12, fontWeight: 700,
                  }}>
                    {displayName.charAt(0)}
                  </span>
                  <div>
                    <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>{displayName}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                      {src.times_seen} scan{src.times_seen !== 1 ? 's' : ''}
                      {src.first_seen && ` · First seen ${new Date(src.first_seen).toLocaleDateString()}`}
                      {src.last_seen && ` · Last seen ${new Date(src.last_seen).toLocaleDateString()}`}
                    </div>
                  </div>
                </div>
                {isOpen ? <ChevronDown size={16} color="var(--text-muted)" /> : <ChevronRight size={16} color="var(--text-muted)" />}
              </button>
              {isOpen && (
                <div style={{ padding: '0 16px 16px', borderTop: '1px solid var(--border)' }}>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 0 }}>
                    {Object.entries(fields)
                      .filter(([, v]) => v != null && v !== '' && typeof v !== 'object')
                      .map(([key, value]) => (
                        <div key={key} style={{ padding: '10px 0', borderBottom: '1px solid var(--border)' }}>
                          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 3 }}>
                            {FINDING_FIELD_LABELS[key] || key.replace(/_/g, ' ')}
                          </div>
                          <div style={{ fontSize: 13, color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                            {typeof value === 'boolean' ? (value ? 'Yes' : 'No') : String(value)}
                          </div>
                        </div>
                      ))}
                  </div>
                  {Object.entries(fields)
                    .filter(([, v]) => v != null && typeof v === 'object')
                    .map(([key, value]) => (
                      <div key={key} style={{ marginTop: 12 }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>
                          {FINDING_FIELD_LABELS[key] || key.replace(/_/g, ' ')}
                        </div>
                        <pre style={{
                          fontSize: 11, background: 'var(--bg-secondary)', padding: 12,
                          borderRadius: 6, overflow: 'auto', maxHeight: 200,
                          color: 'var(--text-secondary)', margin: 0,
                        }}>
                          {JSON.stringify(value, null, 2)}
                        </pre>
                      </div>
                    ))}
                </div>
              )}
            </Card>
          )
        })}
      </div>
    </div>
  )
}
