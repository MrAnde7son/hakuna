import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Plus, Play, Pencil, Power, PowerOff, Trash2, Clock, CheckCircle2, AlertCircle, Circle } from 'lucide-react'
import { Card, Button, PageHeader, EmptyState, Spinner } from '../shared/ui.jsx'
import { ibGetIntegrations, ibRunIntegration, ibDeleteIntegration, ibEnableIntegration, ibDisableIntegration } from '../../api.js'

const STATUS_DOTS = {
  success: { color: '#22c55e', label: 'Last run succeeded' },
  error: { color: '#ef4444', label: 'Last run failed' },
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

function IntegrationCard({ integration, onRun, onDelete, onToggle, onDetail, onEdit }) {
  const [running, setRunning] = useState(false)
  const dir = DIRECTION_BADGE[integration.direction] || DIRECTION_BADGE.pull
  const ent = ENTITY_BADGE[integration.entity] || ENTITY_BADGE.finding

  const handleRun = async (e) => {
    e.stopPropagation()
    setRunning(true)
    try { await onRun(integration.id) } finally { setRunning(false) }
  }

  return (
    <Card
      style={{ display: 'flex', flexDirection: 'column', gap: 12, minHeight: 140 }}
      onClick={() => onDetail(integration.id)}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <StatusDot status={integration.last_run_status} />
          <span style={{ fontWeight: 600, fontSize: 14 }}>{integration.name}</span>
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
    </Card>
  )
}

export default function IntegrationList({ embedded, onNew, onEdit, onDetail }) {
  const navigate = !embedded ? useNavigate() : null
  const goNew = onNew || (() => navigate('/integrations/new'))
  const goEdit = onEdit || ((id) => navigate(`/integrations/${id}/edit`))
  const goDetail = onDetail || ((id) => navigate(`/integrations/${id}`))
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
      alert('Run failed: ' + e.message)
    }
  }

  const handleDelete = async (id) => {
    if (!confirm('Delete this integration?')) return
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
          display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340, 1fr))',
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
