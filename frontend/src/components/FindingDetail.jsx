import React, { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, ExternalLink, Zap, Shield, Terminal, Info, Crosshair, Clock, CheckCircle, RotateCcw } from 'lucide-react'
import { getFinding, resolveFinding, unresolveFinding } from '../api.js'
import { Card, SeverityBadge, ScoreBar, Spinner, Button, EffortBadge, OwnerBadge, Pill } from './ui.jsx'
import AutomateModal from './AutomateModal.jsx'
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
    <div style={{ display: 'flex', gap: 12, padding: '6px 0', borderBottom: '1px solid rgba(45,49,85,0.3)', fontSize: 13 }}>
      <div style={{ minWidth: 160, color: 'var(--text-muted)', flexShrink: 0 }}>{label}</div>
      <div style={{ color: 'var(--text-primary)', fontFamily: mono ? 'monospace' : 'inherit', wordBreak: 'break-all' }}>
        {value}
      </div>
    </div>
  )
}

function PreText({ text }) {
  if (!text) return <span style={{ color: 'var(--text-muted)' }}>—</span>
  return (
    <div style={{
      background: 'var(--bg-secondary)', borderRadius: 8, padding: '14px 16px',
      fontFamily: 'monospace', fontSize: 12, color: '#a5f3fc', lineHeight: 1.6,
      whiteSpace: 'pre-wrap', wordBreak: 'break-word', maxHeight: 400, overflowY: 'auto',
    }}>
      {text}
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
            border: isBold ? '1px solid rgba(220,38,38,0.3)' : '1px solid rgba(45,49,85,0.5)',
            fontSize: 13, lineHeight: 1.6, color: isBold ? '#fca5a5' : 'var(--text-secondary)',
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
  const [showAutomate, setShowAutomate] = useState(false)
  const [resolving, setResolving] = useState(false)

  useEffect(() => {
    getFinding(id)
      .then(setFinding)
      .finally(() => setLoading(false))
  }, [id])

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

          <Button onClick={() => setShowAutomate(true)} style={{ flexShrink: 0, padding: '10px 18px' }}>
            <Zap size={16} /> Automate This
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
            <OwnerBadge owner={finding.owner_suggestion} />
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
          <Button onClick={() => setShowAutomate(true)} style={{ width: '100%', justifyContent: 'center', padding: '11px 16px' }}>
            <Zap size={16} /> Automate This Remediation
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
          <div style={{ padding: '8px 0', borderBottom: '1px solid rgba(45,49,85,0.3)' }}>
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

      {showAutomate && <AutomateModal finding={finding} onClose={() => setShowAutomate(false)} />}
    </div>
  )
}
