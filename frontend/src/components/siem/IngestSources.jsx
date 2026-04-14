import React, { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { Plug, Plus, Trash2, Copy, Check, RefreshCw } from 'lucide-react'
import { getSiemEndpoints, createSiemEndpoint, deleteSiemEndpoint, getVectorTemplates, generateVectorConfig } from '../../api'
import { PageHeader, EmptyState, Button } from '../shared/ui'

export default function IngestSources() {
  const { t } = useTranslation()
  const [endpoints, setEndpoints] = useState([])
  const [templates, setTemplates] = useState([])
  const [loading, setLoading] = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [newEndpoint, setNewEndpoint] = useState(null)
  const [vectorConfig, setVectorConfig] = useState(null)
  const [copied, setCopied] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [eps, tmpls] = await Promise.all([getSiemEndpoints(), getVectorTemplates()])
      setEndpoints(eps || [])
      setTemplates(tmpls || [])
    } catch (e) { console.error(e) }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { load() }, [load])

  const handleCreate = async (name, parserType) => {
    try {
      const result = await createSiemEndpoint({ name, parser_type: parserType })
      setNewEndpoint(result)
      setShowCreate(false)
      load()
    } catch (e) { console.error(e) }
  }

  const handleDelete = async (id) => {
    if (!confirm(t('siem.confirmDeleteEndpoint', 'Delete this ingest endpoint?'))) return
    await deleteSiemEndpoint(id)
    load()
  }

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const handleGenerateConfig = async (endpointId, templateId, token) => {
    try {
      const result = await generateVectorConfig({
        endpoint_id: endpointId, template_id: templateId,
        token: token || '<YOUR_TOKEN>', hakuna_url: window.location.origin,
      })
      setVectorConfig(result.config)
    } catch (e) { console.error(e) }
  }

  return (
    <div>
      <PageHeader
        title={t('siem.ingestSources', 'Ingest Sources')}
        subtitle={t('siem.ingestSourcesDesc', 'Webhook endpoints for receiving security events')}
        action={
          <Button onClick={() => setShowCreate(true)}>
            <Plus size={14} /> {t('siem.addSource', 'Add Source')}
          </Button>
        }
      />

      {/* New endpoint credentials (shown once after creation) */}
      {newEndpoint && (
        <div style={{ padding: 16, marginBottom: 16, borderRadius: 8, background: '#22c55e15', border: '1px solid #22c55e' }}>
          <div style={{ fontWeight: 700, marginBottom: 8 }}>{t('siem.endpointCreated', 'Endpoint Created')} — {t('siem.saveNow', 'Save these credentials now!')}</div>
          <div style={{ fontFamily: 'monospace', fontSize: 12 }}>
            <div><strong>Token:</strong> {newEndpoint.token}
              <button onClick={() => handleCopy(newEndpoint.token)} style={{ marginLeft: 8, background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}>
                {copied ? <Check size={14} /> : <Copy size={14} />}
              </button>
            </div>
            <div style={{ marginTop: 4 }}><strong>HMAC Secret:</strong> {newEndpoint.hmac_secret}</div>
            <div style={{ marginTop: 4 }}><strong>Endpoint ID:</strong> {newEndpoint.id}</div>
          </div>
          <button onClick={() => setNewEndpoint(null)} style={{ marginTop: 8, padding: '4px 12px', borderRadius: 4, border: '1px solid var(--border)', background: 'var(--bg)', cursor: 'pointer', fontSize: 12, color: 'var(--text)' }}>
            {t('common.dismiss', 'Dismiss')}
          </button>
        </div>
      )}

      {/* Endpoints list */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {loading ? <EmptyState icon={Plug} title={t('app.loading')} />
        : endpoints.length === 0 ? <EmptyState icon={Plug} title={t('siem.noEndpoints', 'No ingest endpoints configured')} sub={t('siem.noEndpointsHint', 'Add an ingest source to start receiving security events via webhook.')} />
        : endpoints.map(ep => (
          <div key={ep.id} style={{ padding: '14px 18px', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--bg-secondary)',
                                     display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{ flex: 1 }}>
              <div style={{ fontWeight: 600, fontSize: 14 }}>{ep.name}</div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
                {ep.parser_type.toUpperCase()} · Token: {ep.token_prefix}... · {ep.request_count || 0} requests
                {ep.last_used_at && <> · Last: {new Date(ep.last_used_at).toLocaleDateString()}</>}
              </div>
            </div>
            <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 11, background: ep.is_active ? '#22c55e20' : '#ef444420',
                           color: ep.is_active ? '#22c55e' : '#ef4444', fontWeight: 600 }}>
              {ep.is_active ? 'Active' : 'Inactive'}
            </span>
            <button onClick={() => handleDelete(ep.id)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}><Trash2 size={16} /></button>
          </div>
        ))}
      </div>

      {/* Vector templates */}
      {templates.length > 0 && (
        <div style={{ marginTop: 32 }}>
          <h2 style={{ fontSize: 16, fontWeight: 700, marginBottom: 12 }}>{t('siem.vectorTemplates', 'Vector Collector Templates')}</h2>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 12 }}>
            {templates.map(tmpl => (
              <div key={tmpl.id} style={{ padding: '14px 16px', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--bg-secondary)' }}>
                <div style={{ fontWeight: 600, fontSize: 14 }}>{tmpl.display_name}</div>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>{tmpl.description}</div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                  {tmpl.source_type} · Port {tmpl.default_port}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Vector config viewer */}
      {vectorConfig && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div style={{ background: 'var(--bg)', borderRadius: 12, padding: 24, width: 600, maxHeight: '80vh', overflow: 'auto' }}>
            <h3 style={{ margin: '0 0 12px' }}>{t('siem.vectorConfig', 'Vector Configuration')}</h3>
            <pre style={{ fontSize: 11, background: 'var(--bg-secondary)', padding: 16, borderRadius: 8, overflow: 'auto', maxHeight: '60vh', color: 'var(--text)' }}>
              {vectorConfig}
            </pre>
            <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
              <button onClick={() => handleCopy(vectorConfig)} style={{ padding: '8px 16px', borderRadius: 6, border: 'none', background: 'var(--accent)', color: '#fff', cursor: 'pointer' }}>
                {copied ? t('common.copied', 'Copied!') : t('common.copy', 'Copy')}
              </button>
              <button onClick={() => setVectorConfig(null)} style={{ padding: '8px 16px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text)', cursor: 'pointer' }}>
                {t('common.close', 'Close')}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Create modal */}
      {showCreate && <CreateEndpointModal onClose={() => setShowCreate(false)} onCreate={handleCreate} t={t} />}
    </div>
  )
}

function CreateEndpointModal({ onClose, onCreate, t }) {
  const [name, setName] = useState('')
  const [parser, setParser] = useState('json')

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ background: 'var(--bg)', borderRadius: 12, padding: 24, width: 400 }}>
        <h2 style={{ margin: '0 0 16px', fontSize: 18 }}>{t('siem.addSource', 'Add Ingest Source')}</h2>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <input placeholder="Endpoint name" value={name} onChange={e => setName(e.target.value)}
                 style={{ padding: 8, borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text)' }} />
          <select value={parser} onChange={e => setParser(e.target.value)}
                  style={{ padding: 8, borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text)' }}>
            <option value="json">JSON</option>
            <option value="hec">Splunk HEC</option>
            <option value="cef">CEF (ArcSight)</option>
            <option value="leef">LEEF (QRadar)</option>
          </select>
        </div>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 16 }}>
          <button onClick={onClose} style={{ padding: '8px 16px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text)', cursor: 'pointer' }}>
            {t('common.cancel', 'Cancel')}
          </button>
          <button onClick={() => onCreate(name, parser)} disabled={!name}
                  style={{ padding: '8px 16px', borderRadius: 6, border: 'none', background: 'var(--accent)', color: '#fff', fontWeight: 600, cursor: 'pointer' }}>
            {t('common.create', 'Create')}
          </button>
        </div>
      </div>
    </div>
  )
}
