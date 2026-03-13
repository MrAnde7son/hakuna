import React, { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, ExternalLink, Zap, Shield, Terminal, Info, Crosshair, Clock, CheckCircle, RotateCcw, ShieldOff, UserCheck, MessageSquare, Eye, Briefcase, ChevronDown, ChevronRight } from 'lucide-react'
import { getFinding, resolveFinding, unresolveFinding, updateFindingStatus, updateFindingContext, createException, createCampaign, runCampaign } from '../../api.js'
import { Card, SeverityBadge, ScoreBar, Spinner, Button, EffortBadge, ResolvedOwnerBadge, Pill, Select, Input } from '../shared/ui.jsx'
import BlastRadiusPanel from '../campaigns/BlastRadiusPanel.jsx'

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
  const { id } = useParams()
  const navigate = useNavigate()
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

  useEffect(() => {
    getFinding(id)
      .then(setFinding)
      .finally(() => setLoading(false))
  }, [id])

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
    } finally {
      setResolving(false)
    }
  }

  const handleUnresolve = async () => {
    setResolving(true)
    try {
      const res = await unresolveFinding(id)
      setFinding(prev => ({ ...prev, sla_status: res.sla_status, resolved_at: null }))
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
    } catch (e) {
      alert('Failed to create exception: ' + e.message)
    }
  }

  const handleContextChange = async (field, value) => {
    setCtxSaving(true)
    try {
      const updated = await updateFindingContext(id, { [field]: value || null })
      setFinding(prev => ({ ...prev, ...updated }))
    } finally {
      setCtxSaving(false)
    }
  }

  if (loading) return <Spinner />
  if (!finding) return <div style={{ color: 'var(--text-muted)', padding: 32 }}>Finding not found.</div>

  const bestScore = finding.cvss3_score || finding.cvss2_score

  return (
    <div style={{ maxWidth: 900 }}>
      {/* Back */}
      <button onClick={() => navigate(-1)} style={{
        display: 'flex', alignItems: 'center', gap: 6, background: 'none', border: 'none',
        color: 'var(--text-muted)', cursor: 'pointer', fontSize: 13, marginBottom: 16, padding: 0
      }}>
        <ArrowLeft size={14} /> Back to findings
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
            </div>
            <h1 style={{ fontSize: 18, fontWeight: 700, lineHeight: 1.3, marginBottom: 6 }}>{finding.plugin_name}</h1>
            <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
              Plugin {finding.plugin_id}
              {finding.plugin_family && ` · ${finding.plugin_family}`}
              {finding.asset_hostname && ` · ${finding.asset_hostname}`}
              {finding.port && ` · Port ${finding.port}/${finding.protocol}`}
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
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>PRIORITY SCORE</div>
            <ScoreBar score={finding.priority_score} />
          </div>
          {bestScore && (
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>
                {finding.cvss3_score ? 'CVSS v3' : 'CVSS v2'}
              </div>
              <ScoreBar score={bestScore} />
            </div>
          )}
          {finding.vpr_score && (
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>VPR SCORE</div>
              <ScoreBar score={finding.vpr_score} />
            </div>
          )}
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>EFFORT</div>
            <EffortBadge effort={finding.effort_level} />
          </div>
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>OWNER</div>
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

      {/* Blast Radius */}
      {finding.asset_id && finding.scan_id && (
        <div style={{ marginBottom: 14 }}>
          <BlastRadiusPanel scanId={finding.scan_id} assetId={finding.asset_id} />
        </div>
      )}

      {/* SLA */}
      {finding.sla_status && finding.sla_status !== 'n/a' && (() => {
        const now = new Date()
        const due = finding.sla_due_date ? new Date(finding.sla_due_date) : null
        const daysLeft = due ? Math.ceil((due - now) / 86400000) : null
        const resolvedDate = finding.resolved_at ? new Date(finding.resolved_at) : null

        const statusCfg = {
          on_track: { color: '#16a34a', bg: 'rgba(22,163,74,0.08)', border: 'rgba(22,163,74,0.3)', label: 'On Track' },
          at_risk:  { color: '#d97706', bg: 'rgba(217,119,6,0.08)',  border: 'rgba(217,119,6,0.3)',  label: 'At Risk' },
          breached: { color: '#dc2626', bg: 'rgba(220,38,38,0.08)',  border: 'rgba(220,38,38,0.3)',  label: 'SLA Breached' },
          resolved: { color: '#6366f1', bg: 'rgba(99,102,241,0.08)', border: 'rgba(99,102,241,0.3)', label: 'Resolved' },
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
                    {resolving ? 'Marking…' : 'Mark Resolved'}
                  </Button>
                ) : (
                  <Button variant="ghost" onClick={handleUnresolve} disabled={resolving} size="sm">
                    <RotateCcw size={13} />
                    {resolving ? 'Reopening…' : 'Reopen'}
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
                <RotateCcw size={11} /> Regression
              </span>
            )}
            {finding.first_seen && (
              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                First seen: {new Date(finding.first_seen).toLocaleDateString()}
              </span>
            )}
            {finding.last_seen && (
              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                · Last seen: {new Date(finding.last_seen).toLocaleDateString()}
              </span>
            )}
            {finding.times_seen > 1 && (
              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                · Seen in {finding.times_seen} scan{finding.times_seen !== 1 ? 's' : ''}
              </span>
            )}
          </div>
        </Card>
      )}

      {/* Workflow Status */}
      <Card style={{ marginBottom: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14, paddingBottom: 12, borderBottom: '1px solid var(--border)' }}>
          <UserCheck size={16} color="var(--accent)" />
          <span style={{ fontWeight: 600, fontSize: 14 }}>Workflow Status</span>
        </div>
        {(() => {
          const steps = [
            { value: 'open', label: 'Open', color: '#6b7280' },
            { value: 'in_progress', label: 'In Progress', color: '#3b82f6' },
            { value: 'resolved', label: 'Resolved', color: '#22c55e' },
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
                {finding.exception_id ? 'Has Exception' : 'Create Exception'}
              </button>
            </div>
          )
        })()}

        {finding.workflow_assigned_to && (
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 8 }}>
            Assigned to: <span style={{ color: 'var(--text)', fontWeight: 500 }}>{finding.workflow_assigned_to}</span>
          </div>
        )}
        {finding.status_changed_at && (
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            Last status change: {new Date(finding.status_changed_at).toLocaleString()}
          </div>
        )}

        {showExceptionForm && (
          <div style={{ marginTop: 12, padding: 14, background: 'var(--bg-muted)', borderRadius: 8, border: '1px solid var(--border)' }}>
            <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 8 }}>Create Global Exception for Plugin {finding.plugin_id}</div>
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
                Accept Risk
              </Button>
              <Button size="sm" onClick={() => handleCreateException('false_positive')} style={{ background: '#3b82f6' }}>
                False Positive
              </Button>
              <Button size="sm" onClick={() => handleCreateException('compensating_control')} style={{ background: '#10b981' }}>
                Compensating Control
              </Button>
              <Button size="sm" onClick={() => handleCreateException('technical_debt')} style={{ background: '#7c3aed' }}>
                Technical Debt
              </Button>
              <Button variant="ghost" size="sm" onClick={() => setShowExceptionForm(false)}>Cancel</Button>
            </div>
          </div>
        )}
      </Card>

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
                  <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>— {finding.asset_hostname || finding.asset_ip}</span>
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
            <div style={{ marginTop: 10, fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.7, whiteSpace: 'pre-wrap', background: 'var(--bg-secondary)', padding: '12px 14px', borderRadius: 8 }}>
              {finding.aggregated_solution.description}
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
      <Section title="Remediation Steps" icon={Shield}>
        <RemediationSteps text={finding.remediation_steps} />
        {finding.solution && (
          <div style={{ marginTop: 14 }}>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Original Nessus Solution</div>
            <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6, whiteSpace: 'pre-wrap' }}>{finding.solution}</div>
          </div>
        )}
        <div style={{ marginTop: 16 }}>
          <Button onClick={handleCreateCampaign} disabled={creatingCampaign} style={{ width: '100%', justifyContent: 'center', padding: '11px 16px' }}>
            <Zap size={16} /> {creatingCampaign ? 'Creating…' : 'Start a Campaign'}
          </Button>
        </div>
      </Section>

      {/* Description */}
      {finding.description && (
        <Section title="Description" icon={Info} defaultOpen={false}>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.7, whiteSpace: 'pre-wrap' }}>
            {finding.description}
          </div>
        </Section>
      )}

      {/* Plugin Output */}
      {finding.plugin_output && (
        <Section title="Plugin Output" icon={Terminal} defaultOpen={false}>
          <PreText text={finding.plugin_output} />
        </Section>
      )}

      {/* Technical Details */}
      <Section title="Technical Details" icon={Info} defaultOpen={false}>
        <KeyVal label="Plugin ID" value={finding.plugin_id} />
        <KeyVal label="Plugin Family" value={finding.plugin_family} />
        <KeyVal label="Risk Factor" value={finding.risk_factor} />
        <KeyVal label="Vulnerability State" value={finding.vulnerability_state} />
        <KeyVal label="Port / Protocol" value={finding.port ? `${finding.port} / ${finding.protocol}` : null} />
        <KeyVal label="CVSS v3 Score" value={finding.cvss3_score ? `${finding.cvss3_score} (${finding.cvss3_vector || ''})` : null} />
        <KeyVal label="CVSS v2 Score" value={finding.cvss2_score ? `${finding.cvss2_score} (${finding.cvss2_vector || ''})` : null} />
        <KeyVal label="VPR Score" value={finding.vpr_score} />
        <KeyVal label="Exploit Available" value={finding.exploit_available ? 'Yes' : 'No'} />
        <KeyVal label="Exploit Maturity" value={finding.exploit_maturity} />
        <KeyVal label="Zero Day" value={finding.zero_day ? 'Yes' : null} />
        <KeyVal label="Plugin Published" value={finding.plugin_pub_date} />
        <KeyVal label="Plugin Modified" value={finding.plugin_mod_date} />

        {/* CVEs */}
        {finding.cves && finding.cves.length > 0 && (() => {
          const MAX_VISIBLE = 6
          const visibleCves = showAllCves ? finding.cves : finding.cves.slice(0, MAX_VISIBLE)
          const hiddenCount = finding.cves.length - MAX_VISIBLE
          return (
            <div style={{ padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
              <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 8 }}>CVE References ({finding.cves.length})</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, alignItems: 'center' }}>
                {visibleCves.map(cve => (
                  <a
                    key={cve}
                    href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{ display: 'flex', alignItems: 'center', gap: 4 }}
                  >
                    <Pill label={cve} color="#f59e0b" />
                  </a>
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
            <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 8 }}>See Also</div>
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

    </div>
  )
}
