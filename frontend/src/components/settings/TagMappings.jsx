/**
 * TagMappings — "read field value → auto-create tag" table.
 * Each mapping is stored as a single passthrough AutoTagRule named "map:*".
 */
import React, { useState, useEffect, useCallback } from 'react'
import { Tag, Plus, Play, Edit2, Trash2, Save, X, ArrowRight } from 'lucide-react'
import { Card, Button, Spinner, useConfirm } from '../shared/ui.jsx'
import {
  getAutoTagRules, createAutoTagRule, updateAutoTagRule,
  deleteAutoTagRule, runAutoTagRule, getTagConditionCatalog,
} from '../../api.js'

const inputStyle = { width: '100%', padding: '6px 10px', fontSize: 13, background: 'var(--bg-input)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text-primary)', boxSizing: 'border-box' }
const iconBtnStyle = { background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', padding: 4, borderRadius: 4 }

const TARGET_OPTIONS = [
  { value: 'asset', label: 'Assets only' },
  { value: 'finding', label: 'Findings only' },
  { value: 'both', label: 'Assets + Findings' },
]

function TagMappingRow({ mapping, catalog, onSave, onDelete }) {
  const [editing, setEditing]         = useState(!mapping)
  const [field, setField]             = useState(mapping?.conditions?.[0]?.field || '')
  const [customField, setCustomField] = useState('')
  const [prefix, setPrefix]           = useState(mapping?.conditions?.[0]?.value || '')
  const [target, setTarget]           = useState(mapping?.target_type || 'asset')
  const [saving, setSaving]           = useState(false)

  const allFields      = catalog.flatMap(g => g.conditions || [])
  const effectiveField = field === '__custom__' ? customField : field

  const handleSave = async () => {
    if (!effectiveField) return
    setSaving(true)
    try {
      const payload = {
        name: `map:${effectiveField}→tag${prefix ? `:${prefix}*` : ''}`,
        target_type: target,
        conditions: [{ field: effectiveField, op: 'passthrough', value: prefix || '' }],
        condition_logic: 'AND',
        tag_id: null,
        is_enabled: true,
      }
      let ruleId = mapping?.id
      if (mapping) await updateAutoTagRule(mapping.id, payload)
      else { const r = await createAutoTagRule(payload); ruleId = r.id }
      // Auto-run in background — don't await, let UI update immediately
      if (ruleId) runAutoTagRule(ruleId).catch(() => {})
      onSave()
      setEditing(false)
    } finally {
      setSaving(false)
    }
  }

  if (!mapping && !editing) return null

  if (!editing && mapping) {
    const cond   = mapping.conditions?.[0] || {}
    const prefix = cond.value || ''
    return (
      <tr style={{ borderBottom: '1px solid var(--border)' }}>
        <td style={{ padding: '8px 10px', fontSize: 12, color: 'var(--text-primary)', fontFamily: 'monospace' }}>{cond.field || '—'}</td>
        <td style={{ padding: '8px 10px', fontSize: 12, color: 'var(--text-muted)' }}>
          {prefix ? <span style={{ fontFamily: 'monospace' }}>{prefix}:<em style={{ opacity: 0.5 }}>&lt;value&gt;</em></span> : <em style={{ opacity: 0.5 }}>field value</em>}
        </td>
        <td style={{ padding: '8px 10px', fontSize: 12, color: 'var(--text-muted)' }}>{mapping.target_type}</td>
        <td style={{ padding: '8px 10px', textAlign: 'right' }}>
          <div style={{ display: 'flex', gap: 4, justifyContent: 'flex-end' }}>
            <button onClick={() => setEditing(true)} style={iconBtnStyle} title="Edit"><Edit2 size={13} /></button>
            <button onClick={() => onDelete(mapping.id)} style={{ ...iconBtnStyle, color: '#dc2626' }} title="Delete"><Trash2 size={13} /></button>
          </div>
        </td>
      </tr>
    )
  }

  return (
    <tr style={{ borderBottom: '1px solid var(--border)', background: 'var(--bg-hover)' }}>
      <td colSpan={4} style={{ padding: 10 }}>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <select value={field} onChange={e => setField(e.target.value)} style={{ ...inputStyle, width: field === '__custom__' ? 140 : 200 }}>
            <option value="">— Field —</option>
            <option value="__custom__">— Custom field —</option>
            {catalog.map(g => (
              <optgroup key={g.group} label={g.group}>
                {(g.conditions || []).map(c => <option key={c.field} value={c.field}>{c.label}</option>)}
              </optgroup>
            ))}
          </select>
          {field === '__custom__' && (
            <input value={customField} onChange={e => setCustomField(e.target.value)} placeholder="field name" style={{ ...inputStyle, width: 140 }} />
          )}
          <ArrowRight size={14} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <input value={prefix} onChange={e => setPrefix(e.target.value)} placeholder="prefix (e.g. env)" style={{ ...inputStyle, width: 140 }} />
            <span style={{ fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>:&lt;field value&gt;</span>
          </div>
          <select value={target} onChange={e => setTarget(e.target.value)} style={{ ...inputStyle, width: 130 }}>
            {TARGET_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
          <Button size="sm" onClick={handleSave} disabled={saving || !effectiveField}>
            <Save size={12} /> {saving ? '…' : mapping ? 'Update' : 'Add'}
          </Button>
          <button onClick={() => { if (mapping) setEditing(false); else onDelete(null) }} style={iconBtnStyle}><X size={14} /></button>
        </div>
      </td>
    </tr>
  )
}

export default function TagMappings() {
  const confirm = useConfirm()
  const [mappings, setMappings]   = useState([])
  const [catalog, setCatalog]     = useState([])
  const [loading, setLoading]     = useState(true)
  const [addingNew, setAddingNew] = useState(false)
  const [runStatus, setRunStatus] = useState({})

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [rules, cat] = await Promise.all([getAutoTagRules(), getTagConditionCatalog()])
      setMappings(rules.filter(r => r.name?.startsWith('map:')))
      setCatalog(cat)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const handleDelete = async (id) => {
    if (id === null) { setAddingNew(false); return }
    if (!await confirm('Delete this tag mapping?')) return
    await deleteAutoTagRule(id)
    load()
  }

  const handleRun = async (id) => {
    setRunStatus(s => ({ ...s, [id]: 'running' }))
    try {
      const res = await runAutoTagRule(id)
      setRunStatus(s => ({ ...s, [id]: res.tagged ?? 0 }))
    } catch {
      setRunStatus(s => ({ ...s, [id]: 'error' }))
    }
  }

  if (loading) return <Spinner />

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
        <div style={{ fontSize: 12, color: 'var(--text-muted)', maxWidth: 600 }}>
          Read a field's value from each asset or finding and auto-create a tag from it.
          Optionally add a prefix (e.g. <code>dept:</code>) so values become <code>dept:Engineering</code>.
        </div>
        <Button size="sm" onClick={() => setAddingNew(true)} disabled={addingNew}>
          <Plus size={13} /> Add Mapping
        </Button>
      </div>

      {(mappings.length === 0 && !addingNew) ? (
        <Card style={{ textAlign: 'center', padding: '40px 24px' }}>
          <Tag size={28} style={{ color: 'var(--text-muted)', opacity: 0.3, marginBottom: 10 }} />
          <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>No tag mappings yet</div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 16 }}>
            Map a scan field's value directly to an auto-created tag.
          </div>
          <Button onClick={() => setAddingNew(true)}><Plus size={13} /> Add First Mapping</Button>
        </Card>
      ) : (
        <Card style={{ padding: 0, overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: 'var(--bg-hover)', borderBottom: '1px solid var(--border)' }}>
                {['Field', 'Creates Tag', 'Target', 'Actions'].map(h => (
                  <th key={h} style={{ padding: '7px 10px', fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textAlign: 'left', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {mappings.map(m => (
                <React.Fragment key={m.id}>
                  <TagMappingRow mapping={m} catalog={catalog} onSave={load} onDelete={handleDelete} />
                  {runStatus[m.id] !== undefined && (
                    <tr>
                      <td colSpan={4} style={{ padding: '4px 10px', fontSize: 11, color: runStatus[m.id] === 'error' ? '#dc2626' : '#22c55e', background: 'var(--bg-hover)' }}>
                        {runStatus[m.id] === 'running' ? 'Running…' : runStatus[m.id] === 'error' ? 'Run failed' : `✓ ${runStatus[m.id]} new assignment(s)`}
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
              {addingNew && (
                <TagMappingRow mapping={null} catalog={catalog}
                  onSave={() => { setAddingNew(false); load() }}
                  onDelete={() => setAddingNew(false)} />
              )}
            </tbody>
          </table>
        </Card>
      )}

      {mappings.length > 0 && (
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <Button size="sm" variant="ghost" onClick={() => mappings.forEach(m => handleRun(m.id))}>
            <Play size={12} /> Run All Mappings
          </Button>
        </div>
      )}
    </div>
  )
}
