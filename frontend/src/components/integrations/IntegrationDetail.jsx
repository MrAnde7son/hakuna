import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  ArrowLeft, Play, Pencil, Power, PowerOff, Trash2, CheckCircle2, XCircle,
  Clock, ChevronDown, ChevronUp, AlertTriangle, Loader, Image,
} from 'lucide-react'
import { Card, Button, Spinner, PageHeader } from '../shared/ui.jsx'
import {
  ibGetIntegration, ibGetIntegrationRuns, ibGetIntegrationRun, ibRunIntegration,
  ibDeleteIntegration, ibEnableIntegration, ibDisableIntegration, ibUpdateLogo,
} from '../../api.js'

const STATUS_COLORS = {
  success: '#22c55e', error: '#ef4444', partial: '#eab308', running: '#3b82f6',
}

function formatDuration(ms) {
  if (!ms) return '—'
  if (ms < 1000) return `${ms}ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
  return `${Math.round(ms / 60000)}m ${Math.round((ms % 60000) / 1000)}s`
}

export default function IntegrationDetail({ embedded, integrationId: embeddedId, onBack, onEdit }) {
  const routeParams = !embedded ? useParams() : {}
  const navigate = !embedded ? useNavigate() : null
  const id = embeddedId || routeParams.id
  const goBack = onBack || (() => navigate(-1))
  const goEdit = onEdit || ((editId) => navigate(`/integrations/${editId}/edit`))
  const [integration, setIntegration] = useState(null)
  const [runs, setRuns] = useState([])
  const [loading, setLoading] = useState(true)
  const [running, setRunning] = useState(false)
  const [expandedRunId, setExpandedRunId] = useState(null)
  const [runDetail, setRunDetail] = useState({})
  const [logoInput, setLogoInput] = useState(false)
  const [logoUrl, setLogoUrl] = useState('')

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

  const handleExpandRun = async (runId) => {
    if (expandedRunId === runId) {
      setExpandedRunId(null)
      return
    }
    setExpandedRunId(runId)
    // Load full run detail with errors and step_log
    if (!runDetail[runId]) {
      try {
        const detail = await ibGetIntegrationRun(id, runId)
        setRunDetail(prev => ({ ...prev, [runId]: detail }))
      } catch (e) {
        console.error('Failed to load run detail:', e)
      }
    }
  }

  const handleSetLogo = async (url) => {
    try {
      const res = await ibUpdateLogo(id, url ? { logo_url: url } : { auto: true })
      setIntegration(prev => ({ ...prev, logo_url: res.logo_url }))
      setLogoInput(false)
    } catch (e) {
      alert('Failed to update logo: ' + e.message)
    }
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
        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          {/* Logo */}
          <div style={{ position: 'relative', cursor: 'pointer' }}
            onClick={() => setLogoInput(l => !l)}
            title="Click to change logo"
          >
            {integration.logo_url ? (
              <img src={integration.logo_url} alt={integration.name}
                style={{ width: 40, height: 40, borderRadius: 10, objectFit: 'contain', background: 'var(--bg-secondary)' }}
                onError={e => e.target.style.display = 'none'}
              />
            ) : (
              <div style={{
                width: 40, height: 40, borderRadius: 10,
                background: 'var(--accent)', display: 'flex', alignItems: 'center', justifyContent: 'center',
                color: '#fff', fontSize: 18, fontWeight: 700,
              }}>
                {(integration.name || '?')[0].toUpperCase()}
              </div>
            )}
            <div style={{
              position: 'absolute', bottom: -2, right: -2, width: 16, height: 16,
              borderRadius: '50%', background: 'var(--bg-card)', border: '1px solid var(--border)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <Image size={8} color="var(--text-muted)" />
            </div>
          </div>
          <div>
            <h2 style={{ margin: '0 0 4px', fontSize: 20 }}>{integration.name}</h2>
            <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
              <StatusBadge status={integration.last_run_status} />
              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                {integration.direction.toUpperCase()} · {integration.entity.toUpperCase()} · {integration.transport_type.toUpperCase()}
              </span>
            </div>
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

      {/* Logo input */}
      {logoInput && (
        <Card style={{ marginBottom: 16, padding: '12px 16px' }}>
          <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 8 }}>Integration Logo</div>
          <div style={{ display: 'flex', gap: 8 }}>
            <input
              value={logoUrl}
              onChange={e => setLogoUrl(e.target.value)}
              placeholder="https://example.com/logo.png"
              style={{
                flex: 1, padding: '6px 10px', borderRadius: 6,
                border: '1px solid var(--border)', background: 'var(--bg)',
                color: 'var(--text-primary)', fontSize: 12,
              }}
            />
            <Button onClick={() => handleSetLogo(logoUrl)} style={{ fontSize: 12, padding: '6px 12px' }}>
              Set Logo
            </Button>
            <Button onClick={() => handleSetLogo(null)}
              style={{ fontSize: 12, padding: '6px 12px', background: 'transparent', border: '1px solid var(--border)', color: 'var(--text)' }}>
              Auto-detect
            </Button>
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 6 }}>
            Enter a URL to a logo image, or click "Auto-detect" to fetch the favicon from the integration's URL.
          </div>
        </Card>
      )}

      {/* Last run summary */}
      {lastRun && (
        <Card style={{ marginBottom: 24 }}>
          <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 12 }}>Last Run</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 16 }}>
            <Stat label="Status" value={lastRun.status} color={STATUS_COLORS[lastRun.status]} />
            <Stat label="Fetched" value={lastRun.records_fetched} />
            <Stat label="Inserted" value={lastRun.records_inserted} />
            <Stat label="Updated" value={lastRun.records_updated} />
            <Stat label="Skipped" value={lastRun.records_skipped} />
            <Stat label="Duration" value={formatDuration(lastRun.duration_ms)} />
          </div>
          {lastRun.started_at && (
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 8 }}>
              Started: {new Date(lastRun.started_at).toLocaleString()}
              {lastRun.finished_at && ` · Finished: ${new Date(lastRun.finished_at).toLocaleString()}`}
              {lastRun.triggered_by && ` · Triggered by: ${lastRun.triggered_by}`}
            </div>
          )}
          {lastRun.error_message && (
            <div style={{
              padding: '8px 10px', borderRadius: 6, marginTop: 8,
              background: '#ef444415', color: '#ef4444', fontSize: 12,
              fontFamily: 'monospace', whiteSpace: 'pre-wrap',
            }}>
              {lastRun.error_message}
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
          <KV label="Field Mappings" value={`${(integration.field_map || []).length} mappings`} />
        </div>
      </Card>

      {/* Run history */}
      <div style={{ marginBottom: 12, fontSize: 14, fontWeight: 600 }}>
        Run History
        <span style={{ fontSize: 12, color: 'var(--text-muted)', fontWeight: 400, marginLeft: 8 }}>
          ({runs.length} run{runs.length !== 1 ? 's' : ''})
        </span>
      </div>
      {runs.length === 0 ? (
        <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
          No runs yet. Click "Run Now" to execute this integration.
        </div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                <th style={thStyle}></th>
                <th style={thStyle}>Started</th>
                <th style={thStyle}>Status</th>
                <th style={thStyle}>Trigger</th>
                <th style={thStyle}>Fetched</th>
                <th style={thStyle}>Inserted</th>
                <th style={thStyle}>Updated</th>
                <th style={thStyle}>Skipped</th>
                <th style={thStyle}>Errors</th>
                <th style={thStyle}>Duration</th>
              </tr>
            </thead>
            <tbody>
              {runs.map(r => {
                const isExpanded = expandedRunId === r.id
                const detail = runDetail[r.id]
                return (
                  <RunRow
                    key={r.id}
                    run={r}
                    detail={detail}
                    isExpanded={isExpanded}
                    onToggle={() => handleExpandRun(r.id)}
                  />
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}


function RunRow({ run: r, detail, isExpanded, onToggle }) {
  return (
    <>
      <tr
        style={{ borderBottom: '1px solid var(--border)', cursor: 'pointer' }}
        onClick={onToggle}
        onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-secondary)'}
        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
      >
        <td style={tdStyle}>
          {isExpanded ? <ChevronUp size={12} color="var(--text-muted)" /> : <ChevronDown size={12} color="var(--text-muted)" />}
        </td>
        <td style={tdStyle}>{r.started_at ? new Date(r.started_at).toLocaleString() : '—'}</td>
        <td style={tdStyle}><StatusBadge status={r.status} /></td>
        <td style={tdStyle}>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            {r.triggered_by === 'schedule' ? '⏰ schedule' : '▶ manual'}
          </span>
        </td>
        <td style={tdStyle}>{r.records_fetched}</td>
        <td style={tdStyle}>{r.records_inserted}</td>
        <td style={tdStyle}>{r.records_updated}</td>
        <td style={tdStyle}>{r.records_skipped}</td>
        <td style={tdStyle}>
          {r.error_count > 0 && (
            <span style={{ color: '#ef4444', fontWeight: 600 }}>{r.error_count}</span>
          )}
        </td>
        <td style={tdStyle}>
          <span style={{ fontFamily: 'monospace', fontSize: 11 }}>
            {r.duration_ms ? formatDuration(r.duration_ms) : '—'}
          </span>
        </td>
      </tr>
      {isExpanded && (
        <tr>
          <td colSpan={10} style={{ padding: 0 }}>
            <RunDetailPanel run={r} detail={detail} />
          </td>
        </tr>
      )}
    </>
  )
}


function RunDetailPanel({ run, detail }) {
  const d = detail || run

  return (
    <div style={{
      padding: '12px 20px', background: 'var(--bg-secondary)',
      borderLeft: `3px solid ${STATUS_COLORS[run.status] || '#71717a'}`,
    }}>
      {/* Error message */}
      {(d.error_message || run.error_message) && (
        <div style={{
          padding: '8px 10px', borderRadius: 6, marginBottom: 10,
          background: '#ef444415', color: '#ef4444', fontSize: 12,
          fontFamily: 'monospace', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
        }}>
          <strong>Error:</strong> {d.error_message || run.error_message}
        </div>
      )}

      {/* Mapping/upsert errors */}
      {detail?.errors && detail.errors.length > 0 && (
        <div style={{ marginBottom: 10 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 6 }}>
            Errors ({detail.errors.length})
          </div>
          <div style={{ maxHeight: 200, overflowY: 'auto' }}>
            {detail.errors.slice(0, 50).map((err, i) => (
              <div key={i} style={{
                display: 'flex', gap: 8, fontSize: 11, padding: '4px 8px',
                borderRadius: 4, background: 'var(--bg)', marginBottom: 2,
                fontFamily: 'monospace',
              }}>
                {err.record_index != null && (
                  <span style={{ color: 'var(--text-muted)', minWidth: 50 }}>
                    Row {err.record_index}
                  </span>
                )}
                <span style={{ color: '#ef4444' }}>
                  {err.message !== undefined && err.message !== ''
                    ? err.message
                    : err.target || JSON.stringify(err)}
                </span>
              </div>
            ))}
            {detail.errors.length > 50 && (
              <div style={{ fontSize: 11, color: 'var(--text-muted)', padding: '4px 8px' }}>
                ... and {detail.errors.length - 50} more errors
              </div>
            )}
          </div>
        </div>
      )}

      {/* Step log */}
      {detail?.step_log && detail.step_log.length > 0 && (
        <div>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 6 }}>
            Execution Log
          </div>
          <div style={{ maxHeight: 200, overflowY: 'auto' }}>
            {detail.step_log.map((step, i) => (
              <div key={i} style={{
                display: 'flex', gap: 8, fontSize: 11, padding: '3px 8px',
                color: step.type === 'error' ? '#ef4444' : 'var(--text-secondary)',
              }}>
                <span style={{
                  color: step.type === 'complete' ? '#22c55e'
                    : step.type === 'error' ? '#ef4444'
                    : step.type === 'progress' ? '#3b82f6'
                    : 'var(--text-muted)',
                  fontWeight: 600, minWidth: 60, textTransform: 'uppercase', fontSize: 10,
                }}>
                  {step.type}
                </span>
                <span>
                  {step.message || ''}
                  {step.records_fetched != null && `${step.records_fetched} fetched, ${step.records_processed || 0} processed`}
                  {step.status && !step.message && `Status: ${step.status}`}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {!detail && (
        <div style={{ fontSize: 12, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 6 }}>
          <Loader size={12} style={{ animation: 'spin 1.5s linear infinite' }} />
          Loading run details...
          <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
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
