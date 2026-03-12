import React, { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, ExternalLink, Zap, Shield, Terminal, Info, Crosshair, Clock, CheckCircle, RotateCcw, ShieldOff, UserCheck, MessageSquare } from 'lucide-react'
import { getFinding, resolveFinding, unresolveFinding, updateFindingStatus, createException, createCampaign, runCampaign } from '../api.js'
import { Card, SeverityBadge, ScoreBar, Spinner, Button, EffortBadge, ResolvedOwnerBadge, Pill, Select, Input } from './ui.jsx'
import BlastRadiusPanel from './BlastRadiusPanel.jsx'

function Section({ title, icon: Icon, children }) {
  return (
    <Card style={{ marginBottom: 14 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14, paddingBottom: 12, borderBottom: '1px solid var(--border)' }}>
        {Icon && <Icon size={16} color="var(--accent)" />}
        <span style={{ fontWeight: 600, fontSize: 14 }}>{title}</span>
      </div>
      {children}
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
  const parts = text.split('\n\n')
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {parts.map((part, i) => {
        const isBold = part.startsWith('**')
        const cleaned = part.replace(/\*\*/g, '')
        return (
          <div key={i} style={{
            padding: '10px 14px', borderRadius: 8,
            background: isBold ? 'rgba(220,38,38,0.08)' : 'var(--bg-secondary)',
            border: isBold ? '1px solid rgba(220,38,38,0.3)' : '1px solid var(--border)',
            fontSize: 13, lineHeight: 1.6, color: isBold ? 'var(--danger)' : 'var(--text-secondary)',
            fontWeight: isBold ? 500 : 400,
          }}>
            {cleaned}
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
  const [exceptionReason, setExceptionReason] = useState('')

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

          <Button onClick={handleCreateCampaign} disabled={creatingCampaign} style={{ flexShrink: 0, padding: '10px 18px' }}>
            <Zap size={16} /> {creatingCampaign ? 'Creating…' : 'Start a Campaign'}
          </Button>
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
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 12 }}>
          {[
            { value: 'open', label: 'Open', color: '#6b7280' },
            { value: 'in_progress', label: 'In Progress', color: '#3b82f6' },
            { value: 'resolved', label: 'Resolved', color: '#22c55e' },
          ].map(s => (
            <button
              key={s.value}
              disabled={statusUpdating}
              onClick={() => handleStatusChange(s.value)}
              style={{
                padding: '6px 14px', borderRadius: 8, fontSize: 12, fontWeight: 600,
                border: '2px solid ' + s.color,
                background: (finding.workflow_status || 'open') === s.value ? s.color : 'transparent',
                color: (finding.workflow_status || 'open') === s.value ? '#fff' : s.color,
                cursor: statusUpdating ? 'wait' : 'pointer',
                transition: 'all 0.15s ease',
              }}
            >
              {s.label}
            </button>
          ))}
          <div style={{ borderLeft: '1px solid var(--border)', margin: '0 4px' }} />
          <button
            disabled={statusUpdating}
            onClick={() => setShowExceptionForm(!showExceptionForm)}
            style={{
              padding: '6px 14px', borderRadius: 8, fontSize: 12, fontWeight: 600,
              border: '2px solid #d97706',
              background: ['accepted_risk', 'false_positive', 'compensating_control'].includes(finding.workflow_status) ? '#d97706' : 'transparent',
              color: ['accepted_risk', 'false_positive', 'compensating_control'].includes(finding.workflow_status) ? '#fff' : '#d97706',
              cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4,
            }}
          >
            <ShieldOff size={13} />
            {finding.exception_id ? 'Has Exception' : 'Create Exception'}
          </button>
        </div>

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
              <Button variant="ghost" size="sm" onClick={() => setShowExceptionForm(false)}>Cancel</Button>
            </div>
          </div>
        )}
      </Card>

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
        <Section title="Description" icon={Info}>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.7, whiteSpace: 'pre-wrap' }}>
            {finding.description}
          </div>
        </Section>
      )}

      {/* Plugin Output */}
      {finding.plugin_output && (
        <Section title="Plugin Output" icon={Terminal}>
          <PreText text={finding.plugin_output} />
        </Section>
      )}

      {/* Technical Details */}
      <Section title="Technical Details" icon={Info}>
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
        {finding.cves && finding.cves.length > 0 && (
          <div style={{ padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
            <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 8 }}>CVE References</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {finding.cves.map(cve => (
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
            </div>
          </div>
        )}

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
