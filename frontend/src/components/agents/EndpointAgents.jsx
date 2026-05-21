import React, { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import {
  MonitorCheck, Plus, Trash2, RefreshCw, Copy, Check, X, AlertTriangle,
  Server, Cpu, Zap, ShieldCheck, Activity, Sparkles, ChevronRight,
} from 'lucide-react'
import {
  getEndpointAgents, getEndpointAgent, createEndpointAgent, updateEndpointAgent,
  deleteEndpointAgent, createEndpointAgentAction, createEndpointAgentEdrDetection,
} from '../../api'
import { PageHeader, EmptyState, Button, useToast, useConfirm } from '../shared/ui'

// ── Visual constants ────────────────────────────────────

const STATUS_COLORS = {
  active: '#22c55e',
  pending: '#eab308',
  stale: '#f97316',
  disabled: '#6b7280',
}

const SEVERITY_COLORS = ['#6b7280', '#3b82f6', '#eab308', '#f97316', '#ef4444']

const ACTION_TYPES = ['kill_process', 'quarantine_file', 'apply_patch', 'isolate_host']

const ACTION_STATUS_COLORS = {
  pending: '#eab308',
  dispatched: '#3b82f6',
  completed: '#22c55e',
  failed: '#ef4444',
}

// ── Helpers ─────────────────────────────────────────────

function relativeTime(iso, t) {
  if (!iso) return t('endpointAgents.never', 'never')
  const then = new Date(iso).getTime()
  if (Number.isNaN(then)) return '—'
  const diff = Date.now() - then
  const sec = Math.round(diff / 1000)
  if (sec < 60) return t('endpointAgents.justNow', 'just now')
  const min = Math.round(sec / 60)
  if (min < 60) return t('endpointAgents.minutesAgo', '{{count}}m ago', { count: min })
  const hr = Math.round(min / 60)
  if (hr < 24) return t('endpointAgents.hoursAgo', '{{count}}h ago', { count: hr })
  const day = Math.round(hr / 24)
  return t('endpointAgents.daysAgo', '{{count}}d ago', { count: day })
}

// ── Small UI atoms ──────────────────────────────────────

function StatusBadge({ status, t }) {
  const color = STATUS_COLORS[status] || '#6b7280'
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 5,
      padding: '2px 9px', borderRadius: 12, fontSize: 11, fontWeight: 600,
      background: color + '22', color,
    }}>
      <span style={{ width: 6, height: 6, borderRadius: '50%', background: color }} />
      {t(`endpointAgents.status.${status}`, status)}
    </span>
  )
}

function Tag({ label, color }) {
  return (
    <span style={{
      padding: '1px 7px', borderRadius: 4, fontSize: 10, fontWeight: 700,
      background: color + '22', color, whiteSpace: 'nowrap',
    }}>
      {label}
    </span>
  )
}

function CopyBlock({ value, label }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard?.writeText(value).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1800)
    }).catch(() => {})
  }
  return (
    <div>
      {label && <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 4 }}>{label}</div>}
      <div style={{
        display: 'flex', alignItems: 'flex-start', gap: 8,
        padding: '10px 12px', borderRadius: 8, background: 'var(--bg-hover)',
        border: '1px solid var(--border)',
      }}>
        <code style={{
          flex: 1, minWidth: 0, fontSize: 12, fontFamily: 'var(--mono, monospace)',
          color: 'var(--text)', wordBreak: 'break-all', lineHeight: 1.5,
        }}>{value}</code>
        <button onClick={copy} title="Copy" style={{
          background: 'none', border: 'none', cursor: 'pointer', flexShrink: 0,
          color: copied ? '#22c55e' : 'var(--text-muted)', padding: 0,
        }}>
          {copied ? <Check size={15} /> : <Copy size={15} />}
        </button>
      </div>
    </div>
  )
}

// ── Page ────────────────────────────────────────────────

export default function EndpointAgents() {
  const { t } = useTranslation()
  const toast = useToast()
  const confirm = useConfirm()
  const [agents, setAgents] = useState([])
  const [loading, setLoading] = useState(true)
  const [showRegister, setShowRegister] = useState(false)
  const [detailId, setDetailId] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await getEndpointAgents()
      setAgents(Array.isArray(data) ? data : [])
    } catch (e) {
      toast.error(e?.message || t('endpointAgents.loadFailed', 'Failed to load endpoint agents'))
    } finally {
      setLoading(false)
    }
  }, [t, toast])

  useEffect(() => { load() }, [load])

  const handleDelete = async (agent) => {
    const ok = await confirm(
      t('endpointAgents.confirmDelete', 'Remove agent "{{name}}"? The host will stop reporting.', { name: agent.name }),
      { danger: true, confirmLabel: t('common.delete', 'Delete') },
    )
    if (!ok) return
    try {
      await deleteEndpointAgent(agent.id)
      toast.success(t('endpointAgents.deleted', 'Agent removed'))
      load()
    } catch (e) {
      toast.error(e?.message || t('endpointAgents.deleteFailed', 'Failed to remove agent'))
    }
  }

  return (
    <div>
      <PageHeader
        title={t('endpointAgents.title', 'Vulnerability Detection & Response')}
        subtitle={t('endpointAgents.subtitle', 'Host-resident agents that detect, contextualize and respond to live vulnerabilities')}
        action={(
          <div style={{ display: 'flex', gap: 8 }}>
            <Button variant="ghost" onClick={load}>
              <RefreshCw size={14} /> {t('common.refresh', 'Refresh')}
            </Button>
            <Button onClick={() => setShowRegister(true)}>
              <Plus size={14} /> {t('endpointAgents.registerAgent', 'Register Agent')}
            </Button>
          </div>
        )}
      />

      {loading ? (
        <EmptyState icon={MonitorCheck} title={t('common.loading', 'Loading...')} />
      ) : agents.length === 0 ? (
        <EmptyState
          icon={MonitorCheck}
          title={t('endpointAgents.empty', 'No endpoint agents yet')}
          sub={t('endpointAgents.emptyHint', 'Register an agent and install it on a host to start live vulnerability detection.')}
        >
          <Button onClick={() => setShowRegister(true)}>
            <Plus size={14} /> {t('endpointAgents.registerAgent', 'Register Agent')}
          </Button>
        </EmptyState>
      ) : (
        <div style={{
          display: 'grid', gap: 12,
          gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))',
        }}>
          {agents.map(agent => (
            <AgentCard
              key={agent.id}
              agent={agent}
              t={t}
              onOpen={() => setDetailId(agent.id)}
              onDelete={() => handleDelete(agent)}
            />
          ))}
        </div>
      )}

      {showRegister && (
        <RegisterModal
          t={t}
          toast={toast}
          onClose={() => setShowRegister(false)}
          onCreated={() => { setShowRegister(false); load() }}
        />
      )}

      {detailId != null && (
        <AgentDetailDrawer
          agentId={detailId}
          t={t}
          toast={toast}
          onClose={() => setDetailId(null)}
          onChanged={load}
        />
      )}
    </div>
  )
}

// ── Agent card ──────────────────────────────────────────

function AgentCard({ agent, t, onOpen, onDelete }) {
  return (
    <div
      onClick={onOpen}
      style={{
        padding: 16, borderRadius: 10, border: '1px solid var(--border)',
        background: 'var(--bg-secondary)', cursor: 'pointer',
        display: 'flex', flexDirection: 'column', gap: 10,
        transition: 'border-color 0.15s ease',
      }}
      onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent)' }}
      onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)' }}
    >
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8 }}>
        <div style={{ minWidth: 0 }}>
          <div style={{
            fontWeight: 600, fontSize: 15, overflow: 'hidden',
            textOverflow: 'ellipsis', whiteSpace: 'nowrap',
          }}>{agent.name}</div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
            {agent.hostname || t('endpointAgents.awaitingCheckin', 'awaiting first check-in')}
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
          <StatusBadge status={agent.status} t={t} />
          <button
            onClick={e => { e.stopPropagation(); onDelete() }}
            title={t('common.delete', 'Delete')}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 0 }}
          >
            <Trash2 size={15} />
          </button>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 14, fontSize: 12, color: 'var(--text-muted)', flexWrap: 'wrap' }}>
        <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <Server size={13} /> {agent.platform || '—'}{agent.os_version ? ` ${agent.os_version}` : ''}
        </span>
        {agent.ip_address && (
          <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <Activity size={13} /> {agent.ip_address}
          </span>
        )}
      </div>

      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        gap: 8, fontSize: 12, paddingTop: 8, borderTop: '1px solid var(--border)',
      }}>
        <span style={{ color: 'var(--text-muted)' }}>
          {t('endpointAgents.lastCheckin', 'Last check-in')}: {relativeTime(agent.last_checkin_at, t)}
        </span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {agent.pending_actions > 0 && (
            <Tag label={t('endpointAgents.pendingActions', '{{count}} pending', { count: agent.pending_actions })} color="#f97316" />
          )}
          {agent.auto_respond && (
            <span title={t('endpointAgents.autoRespondOn', 'Auto-response enabled')}
              style={{ display: 'flex', alignItems: 'center', gap: 3, color: '#22c55e', fontWeight: 600 }}>
              <Zap size={12} /> {t('endpointAgents.auto', 'Auto')}
            </span>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Register modal ──────────────────────────────────────

function ModalShell({ children, onClose, maxWidth = 480 }) {
  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 1000,
        display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16,
      }}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{
          background: 'var(--bg)', borderRadius: 12, padding: 24,
          width: '100%', maxWidth, maxHeight: '85vh', overflow: 'auto',
        }}
      >
        {children}
      </div>
    </div>
  )
}

function RegisterModal({ t, toast, onClose, onCreated }) {
  const [form, setForm] = useState({ name: '', auto_respond: false, checkin_interval: 300 })
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(null)
  const [created, setCreated] = useState(null) // { agent, token, install_command }

  const nameValid = form.name.trim().length > 0
  const intervalValid = Number.isInteger(form.checkin_interval) && form.checkin_interval >= 30

  const handleSubmit = async () => {
    setError(null)
    if (!nameValid) { setError(t('endpointAgents.nameRequired', 'Agent name is required.')); return }
    if (!intervalValid) { setError(t('endpointAgents.intervalInvalid', 'Check-in interval must be at least 30 seconds.')); return }
    setSaving(true)
    try {
      const res = await createEndpointAgent({
        name: form.name.trim(),
        auto_respond: form.auto_respond,
        checkin_interval: form.checkin_interval,
        labels: {},
      })
      setCreated(res)
    } catch (e) {
      setError(e?.message || t('endpointAgents.registerFailed', 'Failed to register agent.'))
    } finally {
      setSaving(false)
    }
  }

  const inputStyle = (valid = true) => ({
    width: '100%', padding: 9, borderRadius: 6,
    border: `1px solid ${valid ? 'var(--border)' : '#dc2626'}`,
    background: 'var(--bg-secondary)', color: 'var(--text)', boxSizing: 'border-box',
  })

  if (created) {
    return (
      <ModalShell onClose={() => { onCreated(); }} maxWidth={560}>
        <h2 style={{ margin: '0 0 6px', fontSize: 18, display: 'flex', alignItems: 'center', gap: 8 }}>
          <Check size={18} color="#22c55e" /> {t('endpointAgents.agentRegistered', 'Agent registered')}
        </h2>
        <p style={{ margin: '0 0 16px', fontSize: 13, color: 'var(--text-muted)' }}>
          {t('endpointAgents.registeredHint', 'Install the agent on the target host using the command below.')}
        </p>

        <div style={{
          display: 'flex', gap: 8, alignItems: 'flex-start',
          padding: '10px 12px', marginBottom: 16, borderRadius: 8,
          background: 'var(--warning-subtle)', border: '1px solid var(--warning)',
        }}>
          <AlertTriangle size={16} color="var(--warning)" style={{ flexShrink: 0, marginTop: 1 }} />
          <span style={{ fontSize: 12, color: 'var(--text)' }}>
            {t('endpointAgents.tokenWarning', 'This enrollment token is shown only once. Copy it now — it cannot be retrieved later.')}
          </span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <CopyBlock label={t('endpointAgents.enrollmentToken', 'Enrollment token')} value={created.token || ''} />
          <CopyBlock label={t('endpointAgents.installCommand', 'Install command')} value={created.install_command || ''} />
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 20 }}>
          <Button onClick={() => onCreated()}>{t('endpointAgents.done', 'Done')}</Button>
        </div>
      </ModalShell>
    )
  }

  return (
    <ModalShell onClose={onClose}>
      <h2 style={{ margin: '0 0 16px', fontSize: 18 }}>{t('endpointAgents.registerAgent', 'Register Agent')}</h2>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div>
          <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
            {t('common.name', 'Name')}
          </label>
          <input
            autoFocus
            placeholder={t('endpointAgents.namePlaceholder', 'e.g. prod-web-01')}
            value={form.name}
            onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
            style={inputStyle(nameValid || form.name.length === 0)}
          />
        </div>

        <div>
          <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
            {t('endpointAgents.checkinInterval', 'Check-in interval (seconds)')}
          </label>
          <input
            type="number" min="30" step="30"
            value={form.checkin_interval}
            onChange={e => {
              const n = parseInt(e.target.value, 10)
              setForm(f => ({ ...f, checkin_interval: Number.isFinite(n) ? n : f.checkin_interval }))
            }}
            style={inputStyle(intervalValid)}
          />
        </div>

        <label style={{
          display: 'flex', alignItems: 'flex-start', gap: 9, cursor: 'pointer',
          padding: '10px 12px', borderRadius: 8, background: 'var(--bg-hover)',
          border: '1px solid var(--border)',
        }}>
          <input
            type="checkbox"
            checked={form.auto_respond}
            onChange={e => setForm(f => ({ ...f, auto_respond: e.target.checked }))}
            style={{ marginTop: 2 }}
          />
          <span>
            <span style={{ fontSize: 13, fontWeight: 600, display: 'block' }}>
              {t('endpointAgents.autoRespondLabel', 'Automatically create EDR detections for critical findings')}
            </span>
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
              {t('endpointAgents.autoRespondHint', 'When enabled, the cloud responds to critical detections without waiting for an analyst.')}
            </span>
          </span>
        </label>
      </div>

      {error && (
        <div style={{
          marginTop: 14, padding: '8px 10px', borderRadius: 6, fontSize: 12,
          background: 'var(--danger-subtle)', border: '1px solid var(--danger)', color: 'var(--danger)',
        }}>
          {error}
        </div>
      )}

      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 20 }}>
        <Button variant="ghost" onClick={onClose}>{t('common.cancel', 'Cancel')}</Button>
        <Button onClick={handleSubmit} disabled={saving}>
          {saving ? t('endpointAgents.registering', 'Registering…') : t('endpointAgents.registerAgent', 'Register Agent')}
        </Button>
      </div>
    </ModalShell>
  )
}

// ── Agent detail drawer ─────────────────────────────────

function AgentDetailDrawer({ agentId, t, toast, onClose, onChanged }) {
  const [agent, setAgent] = useState(null)
  const [loading, setLoading] = useState(true)
  const [expandedFinding, setExpandedFinding] = useState(null)
  const [actionFinding, setActionFinding] = useState(null) // finding to queue an action against
  const [busyEdr, setBusyEdr] = useState(null) // finding id currently creating an EDR detection

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await getEndpointAgent(agentId)
      setAgent(data)
    } catch (e) {
      toast.error(e?.message || t('endpointAgents.loadFailed', 'Failed to load endpoint agents'))
      onClose()
    } finally {
      setLoading(false)
    }
  }, [agentId, t, toast, onClose])

  useEffect(() => { load() }, [load])

  const findings = [...(agent?.findings || [])].sort(
    (a, b) => (b.priority_score || 0) - (a.priority_score || 0),
  )

  const toggleAutoRespond = async () => {
    if (!agent) return
    try {
      const updated = await updateEndpointAgent(agent.id, { auto_respond: !agent.auto_respond })
      setAgent(a => ({ ...a, ...updated }))
      onChanged?.()
    } catch (e) {
      toast.error(e?.message || t('endpointAgents.updateFailed', 'Failed to update agent'))
    }
  }

  const handleEdrDetection = async (finding) => {
    setBusyEdr(finding.id)
    try {
      const rule = await createEndpointAgentEdrDetection(agentId, finding.id)
      toast.success(t('endpointAgents.edrCreated', 'EDR detection "{{name}}" created', { name: rule?.name || '' }))
      load()
    } catch (e) {
      toast.error(e?.message || t('endpointAgents.edrFailed', 'Failed to create EDR detection'))
    } finally {
      setBusyEdr(null)
    }
  }

  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 1000,
        display: 'flex', justifyContent: 'flex-end',
      }}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{
          background: 'var(--bg)', width: '100%', maxWidth: 720, height: '100%',
          overflowY: 'auto', boxShadow: 'var(--shadow)',
        }}
      >
        {/* Header */}
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '16px 20px', borderBottom: '1px solid var(--border)',
          position: 'sticky', top: 0, background: 'var(--bg)', zIndex: 2,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0 }}>
            <MonitorCheck size={20} color="var(--accent)" />
            <div style={{ minWidth: 0 }}>
              <div style={{ fontWeight: 700, fontSize: 16, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {agent?.name || t('common.loading', 'Loading...')}
              </div>
              {agent && (
                <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                  {agent.hostname || t('endpointAgents.awaitingCheckin', 'awaiting first check-in')}
                </div>
              )}
            </div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}>
            <X size={20} />
          </button>
        </div>

        {loading || !agent ? (
          <EmptyState icon={MonitorCheck} title={t('common.loading', 'Loading...')} />
        ) : (
          <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 20 }}>
            {/* Host facts */}
            <section>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                <StatusBadge status={agent.status} t={t} />
                <button
                  onClick={toggleAutoRespond}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 5, cursor: 'pointer',
                    padding: '2px 9px', borderRadius: 12, fontSize: 11, fontWeight: 600,
                    border: '1px solid var(--border)',
                    background: agent.auto_respond ? '#22c55e22' : 'var(--bg-secondary)',
                    color: agent.auto_respond ? '#22c55e' : 'var(--text-muted)',
                  }}
                >
                  <Zap size={12} />
                  {agent.auto_respond
                    ? t('endpointAgents.autoRespondOn', 'Auto-response enabled')
                    : t('endpointAgents.autoRespondOff', 'Auto-response off')}
                </button>
              </div>
              <div style={{
                display: 'grid', gap: 10,
                gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))',
                padding: 14, borderRadius: 8, background: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
              }}>
                <Fact label={t('endpointAgents.platform', 'Platform')} value={agent.platform} />
                <Fact label={t('endpointAgents.osVersion', 'OS version')} value={agent.os_version} />
                <Fact label={t('endpointAgents.ipAddress', 'IP address')} value={agent.ip_address} />
                <Fact label={t('endpointAgents.agentVersion', 'Agent version')} value={agent.agent_version} />
                <Fact label={t('endpointAgents.lastCheckin', 'Last check-in')} value={relativeTime(agent.last_checkin_at, t)} />
                <Fact
                  label={t('endpointAgents.checkinInterval', 'Check-in interval (seconds)')}
                  value={agent.checkin_interval != null ? `${agent.checkin_interval}s` : null}
                />
                <Fact label={t('endpointAgents.tokenPrefix', 'Token prefix')} value={agent.token_prefix} />
              </div>
            </section>

            {/* Findings */}
            <section>
              <h3 style={{ margin: '0 0 10px', fontSize: 14, display: 'flex', alignItems: 'center', gap: 6 }}>
                <ShieldCheck size={15} />
                {t('endpointAgents.detectedVulns', 'Detected vulnerabilities')}
                <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>({findings.length})</span>
              </h3>
              {findings.length === 0 ? (
                <div style={{ fontSize: 13, color: 'var(--text-muted)', padding: '8px 0' }}>
                  {t('endpointAgents.noFindings', 'No vulnerabilities detected on this host yet.')}
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {findings.map(f => (
                    <FindingRow
                      key={f.id}
                      finding={f}
                      t={t}
                      expanded={expandedFinding === f.id}
                      onToggle={() => setExpandedFinding(p => (p === f.id ? null : f.id))}
                      onCreateEdr={() => handleEdrDetection(f)}
                      onQueueAction={() => setActionFinding(f)}
                      busyEdr={busyEdr === f.id}
                    />
                  ))}
                </div>
              )}
            </section>

            {/* Actions list */}
            <section>
              <h3 style={{ margin: '0 0 10px', fontSize: 14, display: 'flex', alignItems: 'center', gap: 6 }}>
                <Cpu size={15} />
                {t('endpointAgents.responseActions', 'Response actions')}
                <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>({(agent.actions || []).length})</span>
              </h3>
              {(agent.actions || []).length === 0 ? (
                <div style={{ fontSize: 13, color: 'var(--text-muted)', padding: '8px 0' }}>
                  {t('endpointAgents.noActions', 'No response actions queued.')}
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {agent.actions.map(a => <ActionRow key={a.id} action={a} t={t} />)}
                </div>
              )}
            </section>
          </div>
        )}
      </div>

      {actionFinding && (
        <QueueActionModal
          agentId={agentId}
          finding={actionFinding}
          t={t}
          toast={toast}
          onClose={() => setActionFinding(null)}
          onQueued={() => { setActionFinding(null); load() }}
        />
      )}
    </div>
  )
}

function Fact({ label, value }) {
  return (
    <div>
      <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
        {label}
      </div>
      <div style={{ fontSize: 13, color: 'var(--text)', marginTop: 2 }}>{value || '—'}</div>
    </div>
  )
}

// ── Finding row + contextualization ─────────────────────

function FindingRow({ finding, t, expanded, onToggle, onCreateEdr, onQueueAction, busyEdr }) {
  const sevColor = SEVERITY_COLORS[finding.severity] || '#6b7280'
  const ctx = finding.endpoint_context || {}
  const ai = finding.ai_threat_signal

  return (
    <div style={{ borderRadius: 8, border: '1px solid var(--border)', background: 'var(--bg-secondary)', overflow: 'hidden' }}>
      {/* Row header */}
      <div
        onClick={onToggle}
        style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 12px', cursor: 'pointer' }}
      >
        <ChevronRight
          size={15}
          style={{ flexShrink: 0, transform: expanded ? 'rotate(90deg)' : 'none', transition: 'transform 0.15s ease', color: 'var(--text-muted)' }}
        />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            {finding.cve && (
              <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--accent)', fontFamily: 'var(--mono, monospace)' }}>
                {finding.cve}
              </span>
            )}
            <span style={{ fontSize: 13, fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {finding.plugin_name}
            </span>
          </div>
          <div style={{ display: 'flex', gap: 5, marginTop: 5, flexWrap: 'wrap' }}>
            {finding.is_kev && <Tag label={t('endpointAgents.kev', 'KEV')} color="#ef4444" />}
            {finding.exploit_available && <Tag label={t('endpointAgents.exploit', 'Exploit')} color="#f97316" />}
            {ctx.runtime_active && <Tag label={t('endpointAgents.runtimeActive', 'Runtime active')} color="#eab308" />}
            {ctx.reachability && <Tag label={ctx.reachability} color="#3b82f6" />}
            {finding.trending_in_news && <Tag label={t('endpointAgents.trending', 'Trending')} color="#8b5cf6" />}
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
          <span style={{
            padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 700,
            background: sevColor + '22', color: sevColor,
          }}>
            {finding.severity_label || finding.severity}
          </span>
          <span title={t('endpointAgents.priorityScore', 'Priority score')} style={{
            fontSize: 13, fontWeight: 700, color: 'var(--text)',
            minWidth: 34, textAlign: 'right',
          }}>
            {Number(finding.priority_score || 0).toFixed(1)}
          </span>
        </div>
      </div>

      {/* Expanded contextualization */}
      {expanded && (
        <div style={{ padding: '0 12px 12px 37px', display: 'flex', flexDirection: 'column', gap: 14 }}>
          {finding.description && (
            <div style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.5 }}>{finding.description}</div>
          )}

          {/* Endpoint context */}
          <div style={{
            padding: 12, borderRadius: 8, background: 'var(--bg-hover)', border: '1px solid var(--border)',
          }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 8 }}>
              {t('endpointAgents.endpointContext', 'Endpoint context')}
            </div>
            <div style={{ display: 'grid', gap: 8, gridTemplateColumns: 'repeat(auto-fill, minmax(140px, 1fr))' }}>
              <Fact label={t('endpointAgents.detectedSoftware', 'Detected software')} value={ctx.detected_software} />
              <Fact label={t('endpointAgents.installedVersion', 'Installed version')} value={ctx.installed_version} />
              <Fact label={t('endpointAgents.fixedVersion', 'Fixed version')} value={ctx.fixed_version} />
              <Fact
                label={t('endpointAgents.runtimeStatus', 'Runtime')}
                value={ctx.runtime_active ? t('endpointAgents.active', 'Active') : t('endpointAgents.inactive', 'Inactive')}
              />
              <Fact
                label={t('endpointAgents.networkReachable', 'Network reachable')}
                value={ctx.network_reachable ? t('common.yes', 'Yes') : t('common.no', 'No')}
              />
              <Fact label={t('endpointAgents.reachability', 'Reachability')} value={ctx.reachability} />
              <Fact
                label={t('endpointAgents.edrPresent', 'EDR present')}
                value={ctx.edr_present ? t('common.yes', 'Yes') : t('common.no', 'No')}
              />
            </div>
            {Array.isArray(ctx.running_processes) && ctx.running_processes.length > 0 && (
              <div style={{ marginTop: 8, fontSize: 12 }}>
                <span style={{ color: 'var(--text-muted)' }}>{t('endpointAgents.runningProcesses', 'Running processes')}: </span>
                {ctx.running_processes.map(p => `${p.name} (${p.pid})`).join(', ')}
              </div>
            )}
            {Array.isArray(ctx.listening_ports) && ctx.listening_ports.length > 0 && (
              <div style={{ marginTop: 4, fontSize: 12 }}>
                <span style={{ color: 'var(--text-muted)' }}>{t('endpointAgents.listeningPorts', 'Listening ports')}: </span>
                {ctx.listening_ports.join(', ')}
              </div>
            )}
          </div>

          {/* AI threat signal — highlighted */}
          {ai && <AiThreatSignal ai={ai} isKev={finding.is_kev} t={t} />}

          {/* Solution */}
          {finding.solution && (
            <div style={{ fontSize: 12 }}>
              <span style={{ fontWeight: 600, color: 'var(--text-muted)' }}>{t('endpointAgents.solution', 'Solution')}: </span>
              {finding.solution}
            </div>
          )}

          {/* Response actions */}
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <Button onClick={onCreateEdr} disabled={busyEdr}>
              <ShieldCheck size={14} />
              {busyEdr ? t('endpointAgents.creating', 'Creating…') : t('endpointAgents.createEdr', 'Create EDR detection')}
            </Button>
            <Button variant="ghost" onClick={onQueueAction}>
              <Cpu size={14} /> {t('endpointAgents.queueAction', 'Queue host action')}
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}

function AiThreatSignal({ ai, isKev, t }) {
  const confidencePct = Math.round((ai.confidence || 0) * 100)
  const leadsFeeds = ai.predicted_exploitation && !isKev

  return (
    <div style={{
      padding: 14, borderRadius: 8,
      background: 'linear-gradient(135deg, rgba(139,92,246,0.12), rgba(59,130,246,0.08))',
      border: '1px solid #8b5cf6',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 8 }}>
        <Sparkles size={15} color="#8b5cf6" />
        <span style={{ fontSize: 12, fontWeight: 800, color: '#8b5cf6', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
          {t('endpointAgents.aiThreatSignal', 'Model-based threat intelligence')}
        </span>
      </div>

      {ai.title && <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 4 }}>{ai.title}</div>}
      {ai.summary && <div style={{ fontSize: 12.5, color: 'var(--text)', lineHeight: 1.55, marginBottom: 8 }}>{ai.summary}</div>}

      <div style={{ display: 'grid', gap: 8, gridTemplateColumns: 'repeat(auto-fill, minmax(130px, 1fr))', marginBottom: 8 }}>
        <Fact label={t('endpointAgents.confidence', 'Confidence')} value={`${confidencePct}%`} />
        <Fact label={t('endpointAgents.predictedScore', 'Predicted score')} value={Number(ai.predicted_score || 0).toFixed(1)} />
        <Fact
          label={t('endpointAgents.predictedExploitation', 'Predicted exploitation')}
          value={ai.predicted_exploitation ? t('common.yes', 'Yes') : t('common.no', 'No')}
        />
        <Fact
          label={t('endpointAgents.forecastHorizon', 'Forecast horizon')}
          value={ai.horizon_days != null ? t('endpointAgents.horizonDays', '{{count}} days', { count: ai.horizon_days }) : null}
        />
        <Fact label={t('endpointAgents.model', 'Model')} value={ai.generated_by_model} />
      </div>

      {ai.reasoning && (
        <div style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.5, marginBottom: 8 }}>
          <span style={{ fontWeight: 600 }}>{t('endpointAgents.reasoning', 'Reasoning')}: </span>
          {ai.reasoning}
        </div>
      )}

      {Array.isArray(ai.indicators) && ai.indicators.length > 0 && (
        <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginBottom: leadsFeeds ? 8 : 0 }}>
          {ai.indicators.map((ind, i) => <Tag key={i} label={ind} color="#8b5cf6" />)}
        </div>
      )}

      {leadsFeeds && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 7,
          padding: '8px 10px', borderRadius: 6,
          background: 'var(--warning-subtle)', border: '1px solid var(--warning)',
          fontSize: 12, fontWeight: 600, color: 'var(--text)',
        }}>
          <AlertTriangle size={14} color="var(--warning)" />
          {t('endpointAgents.modelLeadsFeeds', 'Model forecast leads the classic feeds — exploitation predicted before KEV listing.')}
        </div>
      )}
    </div>
  )
}

// ── Action row ──────────────────────────────────────────

function ActionRow({ action, t }) {
  const color = ACTION_STATUS_COLORS[action.status] || '#6b7280'
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 10,
      padding: '8px 12px', borderRadius: 6, background: 'var(--bg-secondary)',
      border: '1px solid var(--border)', fontSize: 12,
    }}>
      <span style={{ fontWeight: 600 }}>{t(`endpointAgents.actionType.${action.action_type}`, action.action_type)}</span>
      <span style={{ color: 'var(--text-muted)', flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {action.reason || (action.params && Object.keys(action.params).length ? JSON.stringify(action.params) : '')}
      </span>
      {action.origin && (
        <Tag
          label={t(`endpointAgents.origin.${action.origin}`, action.origin)}
          color={action.origin === 'auto_respond' ? '#8b5cf6' : '#6b7280'}
        />
      )}
      <span style={{
        padding: '2px 8px', borderRadius: 4, fontWeight: 700,
        background: color + '22', color, flexShrink: 0,
      }}>
        {t(`endpointAgents.actionStatus.${action.status}`, action.status)}
      </span>
    </div>
  )
}

// ── Queue action modal ──────────────────────────────────

function QueueActionModal({ agentId, finding, t, toast, onClose, onQueued }) {
  const [actionType, setActionType] = useState(ACTION_TYPES[0])
  const [paramsText, setParamsText] = useState('{}')
  const [reason, setReason] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(null)

  const handleSubmit = async () => {
    setError(null)
    let params
    try {
      params = paramsText.trim() ? JSON.parse(paramsText) : {}
      if (typeof params !== 'object' || Array.isArray(params)) throw new Error()
    } catch {
      setError(t('endpointAgents.invalidParams', 'Params must be a valid JSON object.'))
      return
    }
    setSaving(true)
    try {
      await createEndpointAgentAction(agentId, {
        action_type: actionType,
        params,
        finding_id: finding?.id ?? null,
        reason: reason.trim(),
      })
      toast.success(t('endpointAgents.actionQueued', 'Host action queued'))
      onQueued()
    } catch (e) {
      setError(e?.message || t('endpointAgents.queueFailed', 'Failed to queue action'))
    } finally {
      setSaving(false)
    }
  }

  const fieldStyle = {
    width: '100%', padding: 9, borderRadius: 6, border: '1px solid var(--border)',
    background: 'var(--bg-secondary)', color: 'var(--text)', boxSizing: 'border-box',
    fontFamily: 'var(--sans)',
  }

  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 1100,
        display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16,
      }}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{ background: 'var(--bg)', borderRadius: 12, padding: 24, width: '100%', maxWidth: 460 }}
      >
        <h2 style={{ margin: '0 0 6px', fontSize: 18 }}>{t('endpointAgents.queueAction', 'Queue host action')}</h2>
        {finding && (
          <p style={{ margin: '0 0 16px', fontSize: 12, color: 'var(--text-muted)' }}>
            {finding.cve ? `${finding.cve} · ` : ''}{finding.plugin_name}
          </p>
        )}

        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div>
            <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
              {t('endpointAgents.actionTypeLabel', 'Action type')}
            </label>
            <select value={actionType} onChange={e => setActionType(e.target.value)} style={fieldStyle}>
              {ACTION_TYPES.map(a => (
                <option key={a} value={a}>{t(`endpointAgents.actionType.${a}`, a)}</option>
              ))}
            </select>
          </div>

          <div>
            <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
              {t('endpointAgents.paramsLabel', 'Params (JSON)')}
            </label>
            <textarea
              value={paramsText}
              onChange={e => setParamsText(e.target.value)}
              rows={3}
              placeholder='{"pid": 1234}'
              style={{ ...fieldStyle, fontFamily: 'var(--mono, monospace)', resize: 'vertical' }}
            />
          </div>

          <div>
            <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
              {t('endpointAgents.reasonLabel', 'Reason')}
            </label>
            <input
              value={reason}
              onChange={e => setReason(e.target.value)}
              placeholder={t('endpointAgents.reasonPlaceholder', 'Why this action is needed')}
              style={fieldStyle}
            />
          </div>
        </div>

        {error && (
          <div style={{
            marginTop: 14, padding: '8px 10px', borderRadius: 6, fontSize: 12,
            background: 'var(--danger-subtle)', border: '1px solid var(--danger)', color: 'var(--danger)',
          }}>
            {error}
          </div>
        )}

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 20 }}>
          <Button variant="ghost" onClick={onClose}>{t('common.cancel', 'Cancel')}</Button>
          <Button onClick={handleSubmit} disabled={saving}>
            {saving ? t('endpointAgents.queuing', 'Queuing…') : t('endpointAgents.queueAction', 'Queue host action')}
          </Button>
        </div>
      </div>
    </div>
  )
}
