import React, { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { ShieldCheck, Plus, Trash2, ExternalLink, Target } from 'lucide-react'
import {
  PageHeader, Card, Table, Button, Pill, EmptyState, ErrorBanner,
  SkeletonTable, Spinner, useToast, useConfirm, SeverityBadge,
} from '../shared/ui.jsx'
import {
  getComplianceControl, getComplianceControlFindings,
  createCompensatingControl, deleteCompensatingControl,
  createCampaignFromControl,
} from '../../api.js'

function stateColor(state) {
  switch (state) {
    case 'passing':              return 'var(--success, #16a34a)'
    case 'failing':              return 'var(--critical, #dc2626)'
    case 'partial':              return 'var(--high, #ea580c)'
    case 'compensating_control': return 'var(--medium, #d97706)'
    case 'not_applicable':       return 'var(--text-muted)'
    default:                     return 'var(--text-muted)'
  }
}

function verdictColor(v) {
  switch (v) {
    case 'failing':                   return 'var(--critical, #dc2626)'
    case 'satisfied_by_compensating': return 'var(--medium, #d97706)'
    case 'exception_suppressed':      return 'var(--text-muted)'
    case 'resolved':                  return 'var(--success, #16a34a)'
    default:                          return 'var(--text-muted)'
  }
}

// ────────────────────────────────────────────────────────────────
// Compensating control add modal — minimal inline form
// ────────────────────────────────────────────────────────────────

function AddCompensatingForm({ controlId, onCreated, onCancel, t, toast }) {
  const [rationale, setRationale] = useState('')
  const [validUntil, setValidUntil] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState(null)

  const submit = async () => {
    if (rationale.trim().length < 4) {
      setErr('Rationale must be at least 4 characters')
      return
    }
    setBusy(true); setErr(null)
    try {
      const body = { rationale }
      if (validUntil) body.valid_until = new Date(validUntil).toISOString()
      const created = await createCompensatingControl(controlId, body)
      toast(t('compliance.compensatingCreated'))
      onCreated(created)
    } catch (e) {
      setErr(e.message || 'Failed to add compensating control')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card style={{ borderColor: 'var(--accent)', borderWidth: 2, marginBottom: 12 }}>
      <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 10 }}>
        {t('compliance.control_detail.addCompensating')}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        <div>
          <label style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>
            {t('compliance.control_detail.rationale')} *
          </label>
          <textarea
            value={rationale}
            onChange={e => setRationale(e.target.value)}
            placeholder={t('compliance.control_detail.rationalePlaceholder')}
            rows={3}
            style={{
              width: '100%', fontSize: 13, padding: 8,
              border: '1px solid var(--border)', borderRadius: 6,
              background: 'var(--bg-card)', color: 'var(--text-primary)',
              fontFamily: 'inherit', resize: 'vertical',
            }}
          />
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
            {t('compliance.control_detail.rationaleHelp')}
          </div>
        </div>
        <div>
          <label style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>
            {t('compliance.control_detail.validUntil')}
          </label>
          <input
            type="datetime-local"
            value={validUntil}
            onChange={e => setValidUntil(e.target.value)}
            style={{
              fontSize: 13, padding: 6,
              border: '1px solid var(--border)', borderRadius: 6,
              background: 'var(--bg-card)', color: 'var(--text-primary)',
            }}
          />
        </div>
      </div>
      {err && <div style={{ fontSize: 12, color: 'var(--critical, #dc2626)', marginTop: 8 }}>{err}</div>}
      <div style={{ display: 'flex', gap: 8, marginTop: 14 }}>
        <Button variant="primary" size="sm" disabled={busy} onClick={submit}>
          {busy ? <Spinner /> : <><Plus size={13} /> {t('compliance.control_detail.addCompensating')}</>}
        </Button>
        <Button variant="ghost" size="sm" onClick={onCancel}>Cancel</Button>
      </div>
    </Card>
  )
}

// ────────────────────────────────────────────────────────────────
// Main page
// ────────────────────────────────────────────────────────────────

export default function ComplianceControlDetail() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const { slug, id } = useParams()
  const toast = useToast()
  const confirm = useConfirm()

  const [control, setControl] = useState(null)
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [showAddCC, setShowAddCC] = useState(false)

  const load = async () => {
    setLoading(true); setError(null)
    try {
      const [c, f] = await Promise.all([
        getComplianceControl(id),
        getComplianceControlFindings(id, { page_size: 200 }),
      ])
      setControl(c)
      setFindings(f.items || [])
    } catch (e) {
      setError(e.message || 'Failed to load control')
    } finally {
      setLoading(false)
    }
  }
  useEffect(() => { load() }, [id])

  const removeCC = async (ccId) => {
    const ok = await confirm(
      t('compliance.control_detail.deleteCCConfirm'),
      {
        title: t('compliance.control_detail.deleteCC'),
        confirmLabel: t('compliance.control_detail.deleteCC'),
      },
    )
    if (!ok) return
    await deleteCompensatingControl(ccId)
    toast(t('compliance.compensatingDeleted'))
    await load()
  }

  const [creatingCampaign, setCreatingCampaign] = useState(false)
  const failingCount = findings.filter(f => f.verdict === 'failing').length
  const onCreateCampaign = async () => {
    const ok = await confirm(
      t(
        'compliance.control_detail.createCampaignConfirm',
        {
          defaultValue: 'A new draft campaign will be created with {{count}} failing finding(s) under {{ref}}. Continue?',
          count: failingCount,
          ref: control?.ref,
        },
      ),
      {
        title: t('compliance.control_detail.createCampaignTitle', 'Create remediation campaign'),
        confirmLabel: t('compliance.control_detail.createCampaign', 'Create campaign'),
        destructive: false,
      },
    )
    if (!ok) return
    setCreatingCampaign(true)
    try {
      const res = await createCampaignFromControl(control.id, {})
      toast.success(t('compliance.control_detail.campaignCreated', { defaultValue: 'Campaign created' }))
      navigate(`/campaigns/${res.id}`)
    } catch (e) {
      toast.error(e.message || 'Failed to create campaign')
    } finally {
      setCreatingCampaign(false)
    }
  }

  return (
    <div>
      <PageHeader
        title={control?.title || (loading ? '…' : 'Control')}
        subtitle={
          <Button variant="ghost" size="sm" onClick={() => navigate(`/compliance/${slug}`)}>
            ← {control?.ref ? `${control.ref}` : 'Back'}
          </Button>
        }
        action={control && (
          <Pill
            label={t(`compliance.states.${control.state || 'not_evaluated'}`, control.state || 'not_evaluated')}
            color={stateColor(control.state)}
          />
        )}
      />

      {error && <ErrorBanner error={error} onRetry={load} onDismiss={() => setError(null)} />}

      {loading
        ? <SkeletonTable rows={6} columns={3} />
        : control && (
          <>
            {/* Guidance */}
            {control.canonical_guidance && (
              <Card style={{ marginBottom: 12 }}>
                <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 6 }}>
                  {t('compliance.control_detail.guidance')}
                </div>
                <div style={{ fontSize: 13, color: 'var(--text-secondary)', whiteSpace: 'pre-wrap', lineHeight: 1.5 }}>
                  {control.canonical_guidance}
                </div>
              </Card>
            )}

            {/* Mappings */}
            <Card style={{ marginBottom: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 8 }}>
                <div style={{ fontSize: 13, fontWeight: 700 }}>
                  {t('compliance.control_detail.mappings')}
                </div>
                <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                  testability: {control.testability}
                </span>
              </div>
              {(control.mappings || []).length === 0
                ? <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                    {t('compliance.control_detail.noMappings')}
                  </div>
                : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {control.mappings.map(m => (
                      <div key={m.id} style={{
                        padding: 8, border: '1px solid var(--border)', borderRadius: 6,
                        display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12,
                      }}>
                        <div style={{ minWidth: 0, flex: 1 }}>
                          <code style={{ fontSize: 12, color: 'var(--text-primary)' }}>{m.mapping_key}</code>
                          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                            {(m.rule?.conditions || []).length} condition(s) · {(m.rule?.logic || 'AND').toUpperCase()}
                          </div>
                        </div>
                        <Pill
                          label={t('compliance.control_detail.ruleVersion', { version: m.rule_version })}
                          color="var(--text-muted)"
                        />
                      </div>
                    ))}
                  </div>
                )
              }
            </Card>

            {/* Compensating controls */}
            <Card style={{ marginBottom: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 8 }}>
                <div style={{ fontSize: 13, fontWeight: 700 }}>
                  {t('compliance.control_detail.compensatingControls')}
                </div>
                {!showAddCC && (
                  <Button variant="ghost" size="sm" onClick={() => setShowAddCC(true)}>
                    <Plus size={13} /> {t('compliance.control_detail.addCompensating')}
                  </Button>
                )}
              </div>
              {showAddCC && (
                <AddCompensatingForm
                  controlId={control.id}
                  t={t}
                  toast={toast}
                  onCancel={() => setShowAddCC(false)}
                  onCreated={() => { setShowAddCC(false); load() }}
                />
              )}
              {(control.compensating_controls || []).length === 0 && !showAddCC
                ? <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                    {t('compliance.control_detail.noCompensating')}
                  </div>
                : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {(control.compensating_controls || []).map(cc => (
                      <div key={cc.id} style={{
                        padding: 8, border: '1px solid var(--border)', borderRadius: 6,
                      }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12 }}>
                          <div style={{ minWidth: 0, flex: 1 }}>
                            <div style={{ fontSize: 13, color: 'var(--text-primary)', whiteSpace: 'pre-wrap' }}>
                              {cc.rationale}
                            </div>
                            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 6 }}>
                              {cc.created_at ? new Date(cc.created_at).toLocaleString() : ''}
                              {cc.valid_until && <> · valid until {new Date(cc.valid_until).toLocaleString()}</>}
                              {cc.linked_exception_id && <> · {t('compliance.control_detail.linkedException')} #{cc.linked_exception_id}</>}
                            </div>
                          </div>
                          <Button variant="ghost" size="sm" onClick={() => removeCC(cc.id)}>
                            <Trash2 size={13} />
                          </Button>
                        </div>
                      </div>
                    ))}
                  </div>
                )
              }
            </Card>

            {/* Findings */}
            <Card style={{ padding: 0 }}>
              <div style={{
                padding: '12px 14px', borderBottom: '1px solid var(--border)',
                display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12,
              }}>
                <div style={{ fontSize: 13, fontWeight: 700 }}>
                  {t('compliance.findings.header')} ({findings.length})
                </div>
                {failingCount > 0 && (
                  <Button variant="primary" size="sm" disabled={creatingCampaign} onClick={onCreateCampaign}>
                    {creatingCampaign ? <Spinner /> : <><Target size={13} /> {t('compliance.control_detail.createCampaign', 'Create remediation campaign')}</>}
                  </Button>
                )}
              </div>
              {findings.length === 0
                ? <EmptyState icon={ShieldCheck} title={t('compliance.findings.noFindings')} sub="" />
                : (
                  <Table
                    columns={[
                      { key: 'verdict', label: t('compliance.findings.verdict'), width: '180px',
                        render: (v) => <Pill label={t(`compliance.verdicts.${v}`, v)} color={verdictColor(v)} /> },
                      { key: 'finding', label: 'Plugin',
                        render: (f) => f
                          ? <div>
                              <div style={{ fontSize: 13, color: 'var(--text-primary)' }}>{f.plugin_name || f.plugin_id}</div>
                              <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                                {f.cves?.slice(0, 2).join(', ') || ''}
                                {f.cwe_ids?.length > 0 && (f.cves?.length > 0 ? ' · ' : '') + f.cwe_ids.slice(0, 2).join(', ')}
                              </div>
                            </div>
                          : '—'
                      },
                      { key: 'finding', label: 'Severity', width: '120px',
                        render: (f) => f ? <SeverityBadge severity={f.severity} label={f.severity_label} /> : '—' },
                      { key: 'matched_via', label: t('compliance.findings.matchedVia'), width: '140px',
                        render: (v) => <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{v || '—'}</span> },
                      { key: '_actions', label: '', width: '100px',
                        render: (_, row) => row.finding && (
                          <Button variant="ghost" size="sm" onClick={(e) => {
                            e.stopPropagation()
                            navigate(`/findings/${row.finding.id}`)
                          }}>
                            <ExternalLink size={13} />
                          </Button>
                        )
                      },
                    ]}
                    rows={findings}
                  />
                )
              }
            </Card>
          </>
        )
      }
    </div>
  )
}
