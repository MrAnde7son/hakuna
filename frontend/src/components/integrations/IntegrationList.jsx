import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Plus, Play, Pencil, Power, PowerOff, Trash2, Clock, CheckCircle2, AlertCircle,
  Circle, History, ChevronDown, ChevronUp, Loader, XCircle, AlertTriangle,
} from 'lucide-react'
import { Card, Button, PageHeader, EmptyState, Spinner, useToast, useConfirm } from '../shared/ui.jsx'
import {
  ibGetIntegrations, ibRunIntegration, ibDeleteIntegration,
  ibEnableIntegration, ibDisableIntegration, ibGetIntegrationRuns,
} from '../../api.js'

const STATUS_DOTS = {
  success: { color: '#22c55e', label: 'Last run succeeded' },
  error: { color: '#ef4444', label: 'Last run failed' },
  partial: { color: '#eab308', label: 'Last run partial' },
  running: { color: '#eab308', label: 'Running...' },
  never: { color: '#71717a', label: 'Never run' },
  needs_reauth: { color: '#eab308', label: 'Needs re-authentication' },
}

const DIRECTION_BADGE = {
  pull: { bg: '#1e3a5f', text: '#7dd3fc', label: 'PULL' },
  push: { bg: '#3b1f5e', text: '#d8b4fe', label: 'PUSH' },
}

const ENTITY_BADGE = {
  asset: { bg: '#1a2e05', text: '#86efac', label: 'ASSET' },
  finding: { bg: '#451a03', text: '#fcd34d', label: 'FINDING' },
  action: { bg: '#1e3a5f', text: '#7dd3fc', label: 'ACTION' },
}

const TRANSPORT_BADGE = {
  api: 'API', sql: 'SQL', file: 'FILE', mcp: 'MCP',
}

function Badge({ bg, text, label }) {
  return (
    <span style={{
      display: 'inline-block', background: bg, color: text,
      borderRadius: 4, padding: '2px 6px', fontSize: 10,
      fontWeight: 600, letterSpacing: '0.05em',
    }}>
      {label}
    </span>
  )
}

function StatusDot({ status }) {
  const s = STATUS_DOTS[status] || STATUS_DOTS.never
  return (
    <span title={s.label} style={{
      display: 'inline-block', width: 8, height: 8, borderRadius: '50%',
      background: s.color, flexShrink: 0,
    }} />
  )
}

function IntegrationLogo({ logoUrl, name }) {
  const [error, setError] = useState(false)
  if (!logoUrl || error) {
    // Fallback: first letter avatar
    const letter = (name || '?')[0].toUpperCase()
    return (
      <div style={{
        width: 32, height: 32, borderRadius: 8, flexShrink: 0,
        background: 'var(--accent)', display: 'flex', alignItems: 'center', justifyContent: 'center',
        color: '#fff', fontSize: 14, fontWeight: 700,
      }}>
        {letter}
      </div>
    )
  }
  return (
    <img
      src={logoUrl}
      alt={name}
      onError={() => setError(true)}
      style={{
        width: 32, height: 32, borderRadius: 8, flexShrink: 0,
        objectFit: 'contain', background: 'var(--bg-secondary)',
      }}
    />
  )
}

function formatDuration(ms) {
  if (!ms) return '—'
  if (ms < 1000) return `${ms}ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
  return `${Math.round(ms / 60000)}m`
}

function formatAge(isoDate) {
  if (!isoDate) return '—'
  const d = new Date(isoDate.endsWith?.('Z') ? isoDate : isoDate + 'Z')
  const now = new Date()
  const mins = Math.floor((now - d) / 60000)
  if (mins < 1) return 'Just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  const days = Math.floor(hrs / 24)
  if (days < 30) return `${days}d ago`
  return d.toLocaleDateString()
}


// ── Run history panel (expandable inside card) ────────────────────────

function RunHistory({ integrationId, expanded }) {
  const [runs, setRuns] = useState(null)
  const [loading, setLoading] = useState(false)
  const [expandedRunId, setExpandedRunId] = useState(null)

  useEffect(() => {
    if (!expanded) return
    setLoading(true)
    ibGetIntegrationRuns(integrationId)
      .then(data => setRuns(data || []))
      .catch(() => setRuns([]))
      .finally(() => setLoading(false))
  }, [expanded, integrationId])

  if (!expanded) return null

  const statusColor = (s) => {
    if (s === 'success') return '#22c55e'
    if (s === 'error') return '#ef4444'
    if (s === 'partial') return '#eab308'
    if (s === 'running') return '#3b82f6'
    return '#71717a'
  }

  const StatusIcon = ({ status }) => {
    if (status === 'success') return <CheckCircle2 size={12} color="#22c55e" />
    if (status === 'error') return <XCircle size={12} color="#ef4444" />
    if (status === 'partial') return <AlertTriangle size={12} color="#eab308" />
    if (status === 'running') return <Loader size={12} color="#3b82f6" style={{ animation: 'spin 1.5s linear infinite' }} />
    return <Circle size={12} color="#71717a" />
  }

  return (
    <div style={{
      borderTop: '1px solid var(--border)', padding: '10px 14px',
      background: 'var(--bg-secondary)',
    }}
      onClick={e => e.stopPropagation()}
    >
      <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 4 }}>
        <History size={11} /> Run History
      </div>

      {loading && (
        <div style={{ fontSize: 12, color: 'var(--text-muted)', padding: '4px 0' }}>
          <Loader size={12} style={{ animation: 'spin 1.5s linear infinite', marginRight: 4, verticalAlign: -1 }} />
          Loading...
        </div>
      )}

      {runs && runs.length === 0 && (
        <div style={{ fontSize: 12, color: 'var(--text-muted)', padding: '4px 0' }}>No runs yet.</div>
      )}

      {runs && runs.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          {runs.slice(0, 10).map(run => (
            <div key={run.id}>
              <div
                onClick={() => setExpandedRunId(expandedRunId === run.id ? null : run.id)}
                style={{
                  display: 'flex', gap: 8, alignItems: 'center', fontSize: 12,
                  padding: '6px 8px', borderRadius: 5, background: 'var(--bg)',
                  border: '1px solid var(--border)', cursor: 'pointer',
                  transition: 'background 0.1s',
                }}
                onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-card)'}
                onMouseLeave={e => e.currentTarget.style.background = 'var(--bg)'}
              >
                <StatusIcon status={run.status} />
                <span style={{ fontWeight: 500, minWidth: 55, textTransform: 'capitalize', color: statusColor(run.status) }}>
                  {run.status}
                </span>
                <span style={{ color: 'var(--text-muted)', flex: 1, fontSize: 11 }}>
                  {run.started_at ? formatAge(run.started_at) : '—'}
                </span>
                <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  {run.records_fetched > 0 && `${run.records_fetched} fetched`}
                  {run.records_inserted > 0 && ` · ${run.records_inserted} new`}
                  {run.records_updated > 0 && ` · ${run.records_updated} upd`}
                </span>
                {run.duration_ms && (
                  <span style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                    {formatDuration(run.duration_ms)}
                  </span>
                )}
                <span style={{ fontSize: 10, color: 'var(--text-muted)', opacity: 0.6 }}>
                  {run.triggered_by === 'schedule' ? '⏰' : '▶'}
                </span>
                {expandedRunId === run.id ? <ChevronUp size={10} /> : <ChevronDown size={10} />}
              </div>

              {/* Expanded run detail */}
              {expandedRunId === run.id && (
                <div style={{
                  padding: '8px 12px', fontSize: 11, background: 'var(--bg)',
                  borderLeft: `3px solid ${statusColor(run.status)}`,
                  borderRadius: '0 0 5px 5px', marginTop: -1,
                }}>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 8, marginBottom: 6 }}>
                    <div><span style={{ color: 'var(--text-muted)' }}>Fetched:</span> {run.records_fetched}</div>
                    <div><span style={{ color: 'var(--text-muted)' }}>Inserted:</span> {run.records_inserted}</div>
                    <div><span style={{ color: 'var(--text-muted)' }}>Updated:</span> {run.records_updated}</div>
                    <div><span style={{ color: 'var(--text-muted)' }}>Skipped:</span> {run.records_skipped}</div>
                  </div>
                  {run.started_at && (
                    <div style={{ color: 'var(--text-muted)', marginBottom: 4 }}>
                      Started: {new Date(run.started_at).toLocaleString()}
                      {run.finished_at && ` → ${new Date(run.finished_at).toLocaleString()}`}
                      {run.duration_ms && ` (${formatDuration(run.duration_ms)})`}
                    </div>
                  )}
                  {run.error_message && (
                    <div style={{
                      padding: '6px 8px', borderRadius: 4, marginTop: 4,
                      background: '#ef444418', color: '#ef4444', fontSize: 11,
                      fontFamily: 'monospace', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                    }}>
                      {run.error_message}
                    </div>
                  )}
                  {run.error_count > 0 && !run.error_message && (
                    <div style={{ color: '#ef4444', marginTop: 4 }}>
                      {run.error_count} error{run.error_count !== 1 ? 's' : ''} during mapping/upsert
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
      <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
    </div>
  )
}


// ── Integration card ──────────────────────────────────────────────────

function IntegrationCard({ integration, onRun, onDelete, onToggle, onDetail, onEdit }) {
  const [running, setRunning] = useState(false)
  const [showHistory, setShowHistory] = useState(false)
  const dir = DIRECTION_BADGE[integration.direction] || DIRECTION_BADGE.pull
  const ent = ENTITY_BADGE[integration.entity] || ENTITY_BADGE.finding

  const handleRun = async (e) => {
    e.stopPropagation()
    setRunning(true)
    try { await onRun(integration.id) } finally { setRunning(false) }
  }

  return (
    <Card
      style={{ display: 'flex', flexDirection: 'column', gap: 0, minHeight: 140, padding: 0, overflow: 'hidden', opacity: integration.enabled ? 1 : 0.55 }}
      onClick={() => onDetail(integration.id)}
    >
      <div style={{ padding: '14px 14px 12px', display: 'flex', flexDirection: 'column', gap: 10, flex: 1 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <IntegrationLogo logoUrl={integration.logo_url} name={integration.name} />
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <StatusDot status={integration.last_run_status} />
                <span style={{ fontWeight: 600, fontSize: 14 }}>{integration.name}</span>
                {!integration.enabled && (
                  <span style={{
                    fontSize: 9, fontWeight: 600, color: 'var(--text-muted)',
                    background: 'var(--border)', borderRadius: 4, padding: '1px 5px',
                    letterSpacing: '0.05em',
                  }}>
                    DISABLED
                  </span>
                )}
              </div>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 4 }}>
            <Badge {...dir} />
            <Badge {...ent} />
          </div>
        </div>

        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <span style={{
            background: 'var(--border)', borderRadius: 4, padding: '1px 6px',
            fontSize: 10, fontWeight: 500, color: 'var(--text-muted)',
          }}>
            {TRANSPORT_BADGE[integration.transport_type] || integration.transport_type}
          </span>
          {integration.schedule && (
            <span style={{ fontSize: 11, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 3 }}>
              <Clock size={11} /> {integration.schedule}
            </span>
          )}
        </div>

        {integration.last_run_at && (
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            Last run: {new Date(integration.last_run_at).toLocaleString()}
            {integration.last_run_records > 0 && ` — ${integration.last_run_records} records`}
          </div>
        )}

        <div style={{ marginTop: 'auto', display: 'flex', gap: 6, paddingTop: 8, borderTop: '1px solid var(--border)' }}>
          <button
            onClick={handleRun}
            disabled={running}
            style={{
              display: 'flex', alignItems: 'center', gap: 4,
              background: 'var(--accent)', color: '#fff', border: 'none',
              borderRadius: 6, padding: '4px 10px', fontSize: 11, fontWeight: 600,
              cursor: running ? 'wait' : 'pointer', opacity: running ? 0.6 : 1,
            }}
          >
            <Play size={12} /> {running ? 'Running...' : 'Run Now'}
          </button>
          <button
            onClick={(e) => { e.stopPropagation(); onEdit(integration.id) }}
            style={{
              display: 'flex', alignItems: 'center', gap: 3,
              background: 'transparent', color: 'var(--text-muted)', border: '1px solid var(--border)',
              borderRadius: 6, padding: '4px 8px', fontSize: 11, cursor: 'pointer',
            }}
          >
            <Pencil size={11} /> Edit
          </button>
          <button
            onClick={(e) => { e.stopPropagation(); setShowHistory(h => !h) }}
            title="Run history"
            style={{
              display: 'flex', alignItems: 'center', gap: 3,
              background: 'transparent',
              color: showHistory ? 'var(--accent)' : 'var(--text-muted)',
              border: `1px solid ${showHistory ? 'var(--accent)' : 'var(--border)'}`,
              borderRadius: 6, padding: '4px 8px', fontSize: 11, cursor: 'pointer',
            }}
          >
            <History size={11} />
            {showHistory ? <ChevronUp size={9} /> : <ChevronDown size={9} />}
          </button>
          <button
            onClick={(e) => { e.stopPropagation(); onToggle(integration.id, integration.enabled) }}
            style={{
              display: 'flex', alignItems: 'center', gap: 3,
              background: 'transparent', color: 'var(--text-muted)', border: '1px solid var(--border)',
              borderRadius: 6, padding: '4px 8px', fontSize: 11, cursor: 'pointer',
            }}
            title={integration.enabled ? 'Disable' : 'Enable'}
          >
            {integration.enabled ? <PowerOff size={11} /> : <Power size={11} />}
          </button>
        </div>
      </div>

      {/* Expandable run history */}
      <RunHistory integrationId={integration.id} expanded={showHistory} />
    </Card>
  )
}

export default function IntegrationList({ embedded, onNew, onEdit, onDetail }) {
  const navigate = !embedded ? useNavigate() : null
  const goNew = onNew || (() => navigate('/integrations/new'))
  const goEdit = onEdit || ((id) => navigate(`/integrations/${id}/edit`))
  const goDetail = onDetail || ((id) => navigate(`/integrations/${id}`))
  const toast = useToast()
  const confirm = useConfirm()
  const [integrations, setIntegrations] = useState([])
  const [loading, setLoading] = useState(true)

  const load = async () => {
    try {
      const data = await ibGetIntegrations()
      setIntegrations(data)
    } catch (e) {
      console.error('Failed to load integrations:', e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const handleRun = async (id) => {
    try {
      await ibRunIntegration(id)
      setTimeout(load, 1000) // refresh after a moment
    } catch (e) {
      toast.error('Run failed: ' + e.message)
    }
  }

  const handleDelete = async (id) => {
    if (!await confirm('Delete this integration?')) return
    await ibDeleteIntegration(id)
    load()
  }

  const handleToggle = async (id, currentEnabled) => {
    if (currentEnabled) await ibDisableIntegration(id)
    else await ibEnableIntegration(id)
    load()
  }

  if (loading) return <div style={{ padding: 40, textAlign: 'center' }}><Spinner /></div>

  return (
    <div style={{ padding: '24px 32px', maxWidth: 1200 }}>
      <PageHeader
        title="Integrations"
        subtitle="Connect external security tools to pull data in or push actions out"
        action={
          <Button onClick={goNew} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <Plus size={16} /> New Integration
          </Button>
        }
      />

      {integrations.length === 0 ? (
        <EmptyState
          icon={Plus}
          title="No integrations yet"
          subtitle="Connect your first security tool to start pulling data into Hakuna"
        />
      ) : (
        <div style={{
          display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))',
          gap: 16, marginTop: 24,
        }}>
          {integrations.map(i => (
            <IntegrationCard
              key={i.id}
              integration={i}
              onRun={handleRun}
              onDelete={handleDelete}
              onToggle={handleToggle}
              onDetail={goDetail}
              onEdit={goEdit}
            />
          ))}
          {/* Add Integration card */}
          <Card
            onClick={goNew}
            style={{
              display: 'flex', flexDirection: 'column', alignItems: 'center',
              justifyContent: 'center', minHeight: 140, gap: 8,
              border: '2px dashed var(--border)', cursor: 'pointer',
            }}
          >
            <Plus size={28} color="var(--text-muted)" />
            <span style={{ fontSize: 13, color: 'var(--text-muted)', fontWeight: 500 }}>Add Integration</span>
          </Card>
        </div>
      )}
    </div>
  )
}
