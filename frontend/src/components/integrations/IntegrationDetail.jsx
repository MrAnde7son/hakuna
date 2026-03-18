import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, Play, Pencil, Power, PowerOff, Trash2, CheckCircle2, XCircle, Clock } from 'lucide-react'
import { Card, Button, Spinner, PageHeader } from '../shared/ui.jsx'
import {
  ibGetIntegration, ibGetIntegrationRuns, ibRunIntegration,
  ibDeleteIntegration, ibEnableIntegration, ibDisableIntegration,
} from '../../api.js'

const STATUS_COLORS = {
  success: '#22c55e', error: '#ef4444', partial: '#eab308', running: '#3b82f6',
}

export default function IntegrationDetail({ embedded, integrationId: embeddedId, onBack, onEdit }) {
  const routeParams = !embedded ? useParams() : {}
  const navigate = !embedded ? useNavigate() : null
  const id = embeddedId || routeParams.id
  const goBack = onBack || (() => goBack())
  const goEdit = onEdit || ((editId) => navigate(`/integrations/${editId}/edit`))
  const [integration, setIntegration] = useState(null)
  const [runs, setRuns] = useState([])
  const [loading, setLoading] = useState(true)
  const [running, setRunning] = useState(false)

  const load = async () => {
    try {
      const [i, r] = await Promise.all([ibGetIntegration(id), ibGetIntegrationRuns(id)])
      setIntegration(i)
      setRuns(r)
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [id])

  const handleRun = async () => {
    setRunning(true)
    try {
      await ibRunIntegration(id)
      setTimeout(load, 1500)
    } catch (e) {
      alert('Run failed: ' + e.message)
    } finally {
      setRunning(false)
    }
  }

  const handleDelete = async () => {
    if (!confirm('Delete this integration? This cannot be undone.')) return
    await ibDeleteIntegration(id)
    goBack()
  }

  const handleToggle = async () => {
    if (integration.enabled) await ibDisableIntegration(id)
    else await ibEnableIntegration(id)
    load()
  }

  if (loading) return <div style={{ padding: 40, textAlign: 'center' }}><Spinner /></div>
  if (!integration) return <div style={{ padding: 40 }}>Integration not found</div>

  const lastRun = runs[0]

  return (
    <div style={{ padding: '24px 32px', maxWidth: 1000 }}>
      <button onClick={() => goBack()}
        style={{ display: 'flex', alignItems: 'center', gap: 4, background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', marginBottom: 16, fontSize: 13 }}>
        <ArrowLeft size={14} /> Back to Integrations
      </button>

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 24 }}>
        <div>
          <h2 style={{ margin: '0 0 4px', fontSize: 20 }}>{integration.name}</h2>
          <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            <StatusBadge status={integration.last_run_status} />
            <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              {integration.direction.toUpperCase()} · {integration.entity.toUpperCase()} · {integration.transport_type.toUpperCase()}
            </span>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <Button onClick={handleRun} disabled={running} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <Play size={14} /> {running ? 'Running...' : 'Run Now'}
          </Button>
          <Button onClick={() => goEdit(id)}
            style={{ background: 'transparent', border: '1px solid var(--border)', color: 'var(--text)', display: 'flex', alignItems: 'center', gap: 4 }}>
            <Pencil size={14} /> Edit
          </Button>
          <Button onClick={handleToggle}
            style={{ background: 'transparent', border: '1px solid var(--border)', color: 'var(--text)' }}>
            {integration.enabled ? <PowerOff size={14} /> : <Power size={14} />}
          </Button>
          <Button onClick={handleDelete}
            style={{ background: 'transparent', border: '1px solid #ef4444', color: '#ef4444' }}>
            <Trash2 size={14} />
          </Button>
        </div>
      </div>

      {/* Last run summary */}
      {lastRun && (
        <Card style={{ marginBottom: 24 }}>
          <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 12 }}>Last Run</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 16 }}>
            <Stat label="Status" value={lastRun.status} color={STATUS_COLORS[lastRun.status]} />
            <Stat label="Fetched" value={lastRun.records_fetched} />
            <Stat label="Inserted" value={lastRun.records_inserted} />
            <Stat label="Updated" value={lastRun.records_updated} />
            <Stat label="Skipped" value={lastRun.records_skipped} />
          </div>
          {lastRun.started_at && (
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 8 }}>
              Started: {new Date(lastRun.started_at).toLocaleString()}
              {lastRun.finished_at && ` · Finished: ${new Date(lastRun.finished_at).toLocaleString()}`}
            </div>
          )}
        </Card>
      )}

      {/* Configuration summary */}
      <Card style={{ marginBottom: 24 }}>
        <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 12 }}>Configuration</div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px 24px', fontSize: 12 }}>
          <KV label="Schedule" value={integration.schedule || 'On demand'} />
          <KV label="Enabled" value={integration.enabled ? 'Yes' : 'No'} />
          <KV label="Template" value={integration.template_id || 'Custom'} />
          <KV label="Records Path" value={integration.records_path || '—'} />
          <KV label="Dedup Key" value={(integration.dedup_key || []).join(', ') || '—'} />
          <KV label="Field Mappings" value={`${(integration.field_map || []).length} mappings`} />
        </div>
      </Card>

      {/* Run history */}
      <div style={{ marginBottom: 12, fontSize: 14, fontWeight: 600 }}>Run History</div>
      {runs.length === 0 ? (
        <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
          No runs yet. Click "Run Now" to execute this integration.
        </div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                <th style={thStyle}>Started</th>
                <th style={thStyle}>Status</th>
                <th style={thStyle}>Fetched</th>
                <th style={thStyle}>Inserted</th>
                <th style={thStyle}>Updated</th>
                <th style={thStyle}>Skipped</th>
                <th style={thStyle}>Finished</th>
              </tr>
            </thead>
            <tbody>
              {runs.map(r => (
                <tr key={r.id} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={tdStyle}>{r.started_at ? new Date(r.started_at).toLocaleString() : '—'}</td>
                  <td style={tdStyle}><StatusBadge status={r.status} /></td>
                  <td style={tdStyle}>{r.records_fetched}</td>
                  <td style={tdStyle}>{r.records_inserted}</td>
                  <td style={tdStyle}>{r.records_updated}</td>
                  <td style={tdStyle}>{r.records_skipped}</td>
                  <td style={tdStyle}>{r.finished_at ? new Date(r.finished_at).toLocaleString() : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function StatusBadge({ status }) {
  const colors = {
    success: { bg: '#22c55e20', text: '#22c55e', label: 'Success' },
    error: { bg: '#ef444420', text: '#ef4444', label: 'Error' },
    partial: { bg: '#eab30820', text: '#eab308', label: 'Partial' },
    running: { bg: '#3b82f620', text: '#3b82f6', label: 'Running' },
    never: { bg: '#71717a20', text: '#71717a', label: 'Never run' },
  }
  const c = colors[status] || colors.never
  return (
    <span style={{
      display: 'inline-block', background: c.bg, color: c.text,
      borderRadius: 4, padding: '2px 8px', fontSize: 11, fontWeight: 600,
    }}>
      {c.label}
    </span>
  )
}

function Stat({ label, value, color }) {
  return (
    <div>
      <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 2 }}>{label}</div>
      <div style={{ fontSize: 18, fontWeight: 700, color: color || 'var(--text)' }}>{value}</div>
    </div>
  )
}

function KV({ label, value }) {
  return (
    <div>
      <span style={{ color: 'var(--text-muted)' }}>{label}: </span>
      <span style={{ color: 'var(--text)', fontFamily: 'var(--mono)' }}>{value}</span>
    </div>
  )
}

const thStyle = { padding: '8px', textAlign: 'left', fontSize: 11, color: 'var(--text-muted)', fontWeight: 600 }
const tdStyle = { padding: '8px' }
