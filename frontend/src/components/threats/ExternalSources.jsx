/**
 * ExternalSources — Connect external CMDB / CSV sources and map their tags to internal tags.
 * Supported source types: csv, servicenow, api
 */
import React, { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { Link2, Plus, Upload, RefreshCw, Settings2, Trash2, Save, X, Edit2, ArrowRight } from 'lucide-react'
import { Card, Button, Spinner, useConfirm, useToast } from '../shared/ui.jsx'
import {
  getTags,
  getExternalTagSources, createExternalTagSource, updateExternalTagSource, deleteExternalTagSource,
  upsertExternalTagMap, deleteExternalTagMap,
  importExternalTagsCsv, syncExternalTagSource,
} from '../../api.js'

const labelStyle = { fontSize: 11, fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 4, display: 'block' }
const inputStyle = { width: '100%', padding: '6px 10px', fontSize: 13, background: 'var(--bg-input)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text-primary)', boxSizing: 'border-box' }
const iconBtnStyle = { background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', padding: 4, borderRadius: 4 }

const getSourceTypes = (t) => [
  { value: 'csv',        label: t('threats.csvFileUpload') },
  { value: 'servicenow', label: t('threats.servicenowCmdb') },
  { value: 'api',        label: t('threats.genericRestApi') },
]
const getMatchFields = (t) => [
  { value: 'any',      label: t('threats.anyIpHostFqdn') },
  { value: 'ip',       label: t('assets.ip') },
  { value: 'hostname', label: t('assets.hostname') },
  { value: 'fqdn',     label: 'FQDN' },
]

// ─── Source config form ───────────────────────────────────────────────────────
function SourceForm({ source, onSave, onCancel }) {
  const { t } = useTranslation()
  const toast = useToast()
  const [name, setName]             = useState(source?.name || '')
  const [type, setType]             = useState(source?.source_type || 'csv')
  const [matchField, setMatchField] = useState(source?.match_field || 'any')
  const [apiUrl, setApiUrl]         = useState(source?.api_url || '')
  const [autoCreate, setAutoCreate] = useState(source?.auto_create_tags !== false)
  const [authType, setAuthType]     = useState(source?.api_config?.auth_type || 'basic')
  const [username, setUsername]     = useState(source?.api_config?.username || '')
  const [password, setPassword]     = useState('')
  const [token, setToken]           = useState('')
  const [idField, setIdField]       = useState(source?.api_config?.id_field || 'ip_address')
  const [tagField, setTagField]     = useState(source?.api_config?.tag_field || 'sys_tags')
  const [table, setTable]           = useState(source?.api_config?.table || 'cmdb_ci_computer')
  const [saving, setSaving]         = useState(false)
  const [error, setError]           = useState(null)

  const SOURCE_TYPES = getSourceTypes(t)
  const MATCH_FIELDS = getMatchFields(t)

  const submit = async () => {
    if (!name.trim()) { setError(t('threats.nameRequired')); return }
    setSaving(true); setError(null)
    try {
      const apiConfig = type !== 'csv' ? {
        auth_type: authType,
        ...(authType === 'basic' ? { username, ...(password ? { password } : {}) } : {}),
        ...(authType === 'token' ? { ...(token ? { token } : {}) } : {}),
        id_field: idField,
        tag_field: tagField,
        ...(type === 'servicenow' ? { table } : {}),
      } : {}
      const payload = { name, source_type: type, match_field: matchField, api_url: apiUrl || null, api_config: apiConfig, auto_create_tags: autoCreate }
      if (source) await updateExternalTagSource(source.id, payload)
      else await createExternalTagSource(payload)
      toast.success(source ? 'Source updated' : 'Source created')
      onSave()
    } catch (e) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
          {source ? t('threats.editSource') : t('threats.newExternalSource')}
        </span>
        <button onClick={onCancel} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', display: 'flex' }}><X size={14} /></button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
        <div>
          <label style={labelStyle}>{t('threats.sourceName')}</label>
          <input value={name} onChange={e => setName(e.target.value)} onKeyDown={e => e.key === 'Enter' && submit()} placeholder="e.g. ServiceNow CMDB" style={inputStyle} />
        </div>
        <div>
          <label style={labelStyle}>{t('threats.sourceType')}</label>
          <select value={type} onChange={e => setType(e.target.value)} style={inputStyle}>
            {SOURCE_TYPES.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </div>
        <div>
          <label style={labelStyle}>{t('threats.matchField')}</label>
          <select value={matchField} onChange={e => setMatchField(e.target.value)} style={inputStyle}>
            {MATCH_FIELDS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </div>
      </div>

      {type !== 'csv' && (
        <>
          <div>
            <label style={labelStyle}>{t('threats.apiUrl')}</label>
            <input value={apiUrl} onChange={e => setApiUrl(e.target.value)} onKeyDown={e => e.key === 'Enter' && submit()} placeholder="https://your-instance.service-now.com" style={inputStyle} />
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            <div>
              <label style={labelStyle}>{t('threats.authType')}</label>
              <select value={authType} onChange={e => setAuthType(e.target.value)} style={inputStyle}>
                <option value="basic">Basic (user / password)</option>
                <option value="token">Bearer token</option>
              </select>
            </div>
            {authType === 'basic' ? (
              <>
                <div>
                  <label style={labelStyle}>Username</label>
                  <input value={username} onChange={e => setUsername(e.target.value)} onKeyDown={e => e.key === 'Enter' && submit()} style={inputStyle} />
                </div>
                <div>
                  <label style={labelStyle}>Password</label>
                  <input type="password" value={password} onChange={e => setPassword(e.target.value)} onKeyDown={e => e.key === 'Enter' && submit()} placeholder={source ? '(unchanged)' : ''} style={inputStyle} />
                </div>
              </>
            ) : (
              <div>
                <label style={labelStyle}>Token</label>
                <input type="password" value={token} onChange={e => setToken(e.target.value)} onKeyDown={e => e.key === 'Enter' && submit()} placeholder={source ? '(unchanged)' : ''} style={inputStyle} />
              </div>
            )}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            <div>
              <label style={labelStyle}>Asset identifier field</label>
              <input value={idField} onChange={e => setIdField(e.target.value)} onKeyDown={e => e.key === 'Enter' && submit()} placeholder="ip_address" style={inputStyle} />
            </div>
            <div>
              <label style={labelStyle}>Tag field</label>
              <input value={tagField} onChange={e => setTagField(e.target.value)} onKeyDown={e => e.key === 'Enter' && submit()} placeholder="sys_tags" style={inputStyle} />
            </div>
            {type === 'servicenow' && (
              <div>
                <label style={labelStyle}>CMDB Table</label>
                <input value={table} onChange={e => setTable(e.target.value)} onKeyDown={e => e.key === 'Enter' && submit()} placeholder="cmdb_ci_computer" style={inputStyle} />
              </div>
            )}
          </div>
        </>
      )}

      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <input type="checkbox" id="auto_create" checked={autoCreate} onChange={e => setAutoCreate(e.target.checked)} style={{ cursor: 'pointer' }} />
        <label htmlFor="auto_create" style={{ fontSize: 12, color: 'var(--text-secondary)', cursor: 'pointer' }}>
          {t('threats.autoCreateTags')}
        </label>
      </div>

      {error && <div style={{ fontSize: 12, color: '#dc2626', background: '#450a0a', borderRadius: 6, padding: '6px 10px' }}>{error}</div>}
      <div style={{ display: 'flex', gap: 8 }}>
        <Button onClick={submit} disabled={saving} style={{ flex: 1 }}><Save size={13} /> {saving ? 'Saving…' : t('common.save')}</Button>
        <Button variant="ghost" onClick={onCancel}>{t('common.cancel')}</Button>
      </div>
    </div>
  )
}

// ─── Tag map row ──────────────────────────────────────────────────────────────
function TagMapRow({ sourceId, map, allTags, onSaved, onDelete }) {
  const { t } = useTranslation()
  const [editing, setEditing]   = useState(false)
  const [extTag, setExtTag]     = useState(map?.external_tag || '')
  const [intTagId, setIntTagId] = useState(map?.internal_tag_id || '')
  const [saving, setSaving]     = useState(false)

  const handleSave = async () => {
    if (!extTag.trim()) return
    setSaving(true)
    try {
      await upsertExternalTagMap(sourceId, { external_tag: extTag, internal_tag_id: intTagId ? Number(intTagId) : null })
      onSaved()
      setEditing(false)
    } finally { setSaving(false) }
  }

  if (!editing && map) {
    const tagColor = map.internal_tag_color || '#6366f1'
    return (
      <tr style={{ borderBottom: '1px solid var(--border)' }}>
        <td style={{ padding: '7px 10px', fontSize: 13, fontFamily: 'monospace', color: 'var(--text-primary)' }}>{map.external_tag}</td>
        <td style={{ padding: '7px 10px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 16 }}>→</td>
        <td style={{ padding: '7px 10px' }}>
          {map.internal_tag_label ? (
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, background: `${tagColor}18`, color: tagColor, border: `1px solid ${tagColor}44`, borderRadius: 999, padding: '2px 8px', fontSize: 11, fontWeight: 600 }}>
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: tagColor }} />
              {map.internal_tag_label}
            </span>
          ) : (
            <span style={{ fontSize: 11, color: 'var(--text-muted)', fontStyle: 'italic' }}>auto-create from name</span>
          )}
        </td>
        <td style={{ padding: '7px 10px', textAlign: 'right' }}>
          <div style={{ display: 'flex', gap: 4, justifyContent: 'flex-end' }}>
            <button onClick={() => setEditing(true)} style={iconBtnStyle}><Edit2 size={12} /></button>
            <button onClick={() => onDelete(map.id)} style={{ ...iconBtnStyle, color: '#dc2626' }}><Trash2 size={12} /></button>
          </div>
        </td>
      </tr>
    )
  }

  return (
    <tr style={{ borderBottom: '1px solid var(--border)', background: 'var(--bg-hover)' }}>
      <td colSpan={4} style={{ padding: 8 }}>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <input value={extTag} onChange={e => setExtTag(e.target.value)} onKeyDown={e => { if (e.key === 'Enter' && extTag.trim()) handleSave() }} placeholder='External tag (e.g. "network:dmz")' style={{ ...inputStyle, width: 220, fontFamily: 'monospace' }} />
          <ArrowRight size={14} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
          <select value={intTagId} onChange={e => setIntTagId(e.target.value)} style={{ ...inputStyle, width: 200 }}>
            <option value="">— Auto-create from name —</option>
            {allTags.map(tg => <option key={tg.id} value={tg.id}>{tg.label}</option>)}
          </select>
          <Button size="sm" onClick={handleSave} disabled={saving || !extTag.trim()}>
            <Save size={12} /> {saving ? '…' : map ? 'Update' : 'Add'}
          </Button>
          <button onClick={() => map ? setEditing(false) : onDelete(null)} style={iconBtnStyle}><X size={13} /></button>
        </div>
      </td>
    </tr>
  )
}

// ─── Source card ──────────────────────────────────────────────────────────────
function SourceCard({ source, allTags, onRefresh }) {
  const { t } = useTranslation()
  const toast = useToast()
  const confirm = useConfirm()
  const [expanded, setExpanded]     = useState(false)
  const [editOpen, setEditOpen]     = useState(false)
  const [addingMap, setAddingMap]   = useState(false)
  const [importing, setImporting]   = useState(false)
  const [syncing, setSyncing]       = useState(false)
  const [syncResult, setSyncResult] = useState(null)
  const fileRef = React.useRef()

  const SOURCE_TYPES = getSourceTypes(t)

  const handleDelete = async () => {
    if (!await confirm(`Delete source "${source.name}"? Existing tag assignments are kept.`)) return
    await deleteExternalTagSource(source.id)
    toast.success('Source deleted')
    onRefresh()
  }

  const handleDeleteMap = async (mapId) => {
    if (mapId === null) { setAddingMap(false); return }
    await deleteExternalTagMap(source.id, mapId)
    onRefresh()
  }

  const handleImport = async (e) => {
    const file = e.target.files?.[0]
    if (!file) return
    setImporting(true); setSyncResult(null)
    try {
      const res = await importExternalTagsCsv(source.id, file)
      setSyncResult({ ok: true, ...res })
      onRefresh()
    } catch (err) {
      setSyncResult({ ok: false, error: err.message })
    } finally {
      setImporting(false)
      e.target.value = ''
    }
  }

  const handleSync = async () => {
    setSyncing(true); setSyncResult(null)
    try {
      const res = await syncExternalTagSource(source.id)
      setSyncResult({ ok: true, ...res })
      onRefresh()
    } catch (err) {
      setSyncResult({ ok: false, error: err.message })
    } finally { setSyncing(false) }
  }

  if (editOpen) {
    return (
      <Card style={{ padding: 16 }}>
        <SourceForm source={source} onSave={() => { setEditOpen(false); onRefresh() }} onCancel={() => setEditOpen(false)} />
      </Card>
    )
  }

  const typeLabel = SOURCE_TYPES.find(st => st.value === source.source_type)?.label || source.source_type

  return (
    <Card style={{ padding: 0, overflow: 'hidden' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '12px 16px' }}>
        <button onClick={() => setExpanded(p => !p)} style={{ ...iconBtnStyle, marginLeft: -4 }}>
          <ArrowRight size={14} style={{ transform: expanded ? 'rotate(90deg)' : 'none', transition: 'transform 0.15s' }} />
        </button>
        <Link2 size={14} style={{ color: '#818cf8', flexShrink: 0 }} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontWeight: 600, fontSize: 14, color: 'var(--text-primary)' }}>{source.name}</span>
            <span style={{ fontSize: 11, background: 'var(--bg-hover)', color: 'var(--text-muted)', borderRadius: 4, padding: '1px 6px' }}>{typeLabel}</span>
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>· match by {source.match_field}</span>
            {source.maps?.length > 0 && (
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>· {source.maps.length} mapping{source.maps.length !== 1 ? 's' : ''}</span>
            )}
          </div>
          {source.last_synced_at && (
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
              Last sync: {new Date(source.last_synced_at).toLocaleString()} · {source.last_sync_count ?? 0} asset(s) tagged
              {source.last_sync_error && <span style={{ color: '#dc2626' }}> · {source.last_sync_error}</span>}
            </div>
          )}
        </div>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexShrink: 0 }}>
          {source.source_type === 'csv' ? (
            <>
              <input ref={fileRef} type="file" accept=".csv,.txt" style={{ display: 'none' }} onChange={handleImport} />
              <Button size="sm" variant="ghost" onClick={() => fileRef.current?.click()} disabled={importing}>
                <Upload size={12} /> {importing ? 'Importing…' : t('threats.uploadCsv')}
              </Button>
            </>
          ) : (
            <Button size="sm" variant="ghost" onClick={handleSync} disabled={syncing}>
              <RefreshCw size={12} /> {syncing ? 'Syncing…' : t('threats.syncNow')}
            </Button>
          )}
          <button onClick={() => setEditOpen(true)} style={iconBtnStyle} title={t('common.edit')}><Settings2 size={13} /></button>
          <button onClick={handleDelete} style={{ ...iconBtnStyle, color: '#dc2626' }} title={t('common.delete')}><Trash2 size={13} /></button>
        </div>
      </div>

      {syncResult && (
        <div style={{ margin: '0 16px 10px', fontSize: 12, color: syncResult.ok ? '#22c55e' : '#dc2626', background: syncResult.ok ? '#052e16' : '#450a0a', borderRadius: 6, padding: '6px 10px' }}>
          {syncResult.ok
            ? `✓ ${syncResult.assets_matched ?? 0} asset(s) matched · ${syncResult.tags_applied ?? 0} tag(s) applied · ${syncResult.tags_created ?? 0} new · ${syncResult.unmatched ?? 0} unmatched rows`
            : `Error: ${syncResult.error}`}
        </div>
      )}

      {expanded && (
        <div style={{ borderTop: '1px solid var(--border)', padding: '12px 16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              {t('threats.tagMappings')}
            </span>
            <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
              {source.source_type === 'csv' && (
                <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  CSV format: <code style={{ fontSize: 11 }}>identifier,tag1|tag2</code>
                </span>
              )}
              <Button size="sm" variant="ghost" onClick={() => setAddingMap(true)} disabled={addingMap}>
                <Plus size={12} /> {t('threats.addMapping')}
              </Button>
            </div>
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 10 }}>
            Map external tag names → internal tags. Leave blank to auto-create using the external name.
          </div>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                {['External tag', '', 'Internal tag', ''].map((h, i) => (
                  <th key={i} style={{ padding: '5px 10px', fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textAlign: 'left', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {source.maps?.map(m => (
                <TagMapRow key={m.id} sourceId={source.id} map={m} allTags={allTags} onSaved={onRefresh} onDelete={handleDeleteMap} />
              ))}
              {(source.maps?.length === 0 && !addingMap) && (
                <tr><td colSpan={4} style={{ padding: '12px 10px', fontSize: 12, color: 'var(--text-muted)', fontStyle: 'italic' }}>
                  No mappings — external tags will be auto-created if enabled.
                </td></tr>
              )}
              {addingMap && (
                <TagMapRow sourceId={source.id} map={null} allTags={allTags}
                  onSaved={() => { setAddingMap(false); onRefresh() }}
                  onDelete={() => setAddingMap(false)} />
              )}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  )
}

// ─── Main export ──────────────────────────────────────────────────────────────
export default function ExternalSources() {
  const { t } = useTranslation()
  const [sources, setSources] = useState([])
  const [allTags, setAllTags] = useState([])
  const [loading, setLoading] = useState(true)
  const [creating, setCreating] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [srcs, flat] = await Promise.all([getExternalTagSources(), getTags()])
      setSources(srcs)
      setAllTags(flat)
    } finally { setLoading(false) }
  }, [])

  useEffect(() => { load() }, [load])

  if (loading) return <Spinner />

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
        <div style={{ fontSize: 12, color: 'var(--text-muted)', maxWidth: 620 }}>
          {t('threats.noSourcesDesc')}
        </div>
        <Button size="sm" onClick={() => setCreating(true)} disabled={creating}>
          <Plus size={13} /> {t('threats.addSource')}
        </Button>
      </div>

      {creating && (
        <Card style={{ padding: 16 }}>
          <SourceForm onSave={() => { setCreating(false); load() }} onCancel={() => setCreating(false)} />
        </Card>
      )}

      {sources.length === 0 && !creating ? (
        <Card style={{ textAlign: 'center', padding: '48px 24px' }}>
          <Link2 size={32} style={{ color: 'var(--text-muted)', opacity: 0.3, marginBottom: 12 }} />
          <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>{t('threats.noSources')}</div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 16, maxWidth: 420, margin: '0 auto 16px' }}>
            {t('threats.noSourcesDesc')}
          </div>
          <Button onClick={() => setCreating(true)}><Plus size={13} /> {t('threats.addSource')}</Button>
        </Card>
      ) : (
        sources.map(src => (
          <SourceCard key={src.id} source={src} allTags={allTags} onRefresh={load} />
        ))
      )}
    </div>
  )
}
