/**
 * OwnershipRules — Rule-based ownership assignment for assets and findings.
 * Rendered as a tab inside Settings → Ownership.
 */
import React, { useState, useEffect, useCallback } from 'react'
import { UserCheck, Plus, Play, Edit2, Trash2, ToggleLeft, ToggleRight, X, Save, ArrowRight } from 'lucide-react'
import { Card, Button, Spinner, useConfirm, useToast } from '../shared/ui.jsx'
import RuleBuilder from '../campaigns/RuleBuilder.jsx'
import {
  getOwnershipRules, createOwnershipRule, updateOwnershipRule,
  deleteOwnershipRule, runOwnershipRule, runAllOwnershipRules,
  getTagConditionCatalog,
} from '../../api.js'

const labelStyle = { fontSize: 11, fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 4, display: 'block' }
const inputStyle = { width: '100%', padding: '6px 10px', fontSize: 13, background: 'var(--bg-input)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text-primary)', boxSizing: 'border-box' }
const iconBtnStyle = { background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', padding: 4, borderRadius: 4 }

const ROLE_OPTIONS = ['IT', 'DevOps', 'SecOps', 'AppSec', 'Custom']
const TARGET_OPTIONS = [
  { value: 'asset',   label: 'Assets only' },
  { value: 'finding', label: 'Findings only' },
  { value: 'both',    label: 'Assets + Findings' },
]

// ─── Rule form ────────────────────────────────────────────────────────────────
function OwnershipRuleForm({ rule, onSave, onCancel }) {
  const [name, setName]             = useState(rule?.name || '')
  const [description, setDescription] = useState(rule?.description || '')
  const [targetType, setTargetType] = useState(rule?.target_type || 'asset')
  const [logic, setLogic]           = useState(rule?.condition_logic || 'AND')
  const [conditions, setConditions] = useState(rule?.conditions || [])
  const [priority, setPriority]     = useState(rule?.priority ?? 100)
  const [ownerName, setOwnerName]   = useState(rule?.owner_name || '')
  const [ownerEmail, setOwnerEmail] = useState(rule?.owner_email || '')
  const [ownerRole, setOwnerRole]   = useState(rule?.owner_role || '')
  const [team, setTeam]             = useState(rule?.team || '')
  const [notes, setNotes]           = useState(rule?.notes || '')
  const [overwrite, setOverwrite]   = useState(rule?.overwrite_existing || false)
  const [enabled, setEnabled]       = useState(rule?.is_enabled !== false)
  const [saving, setSaving]         = useState(false)
  const [error, setError]           = useState(null)
  const toast = useToast()

  const submit = async () => {
    if (!name.trim()) { setError('Name is required'); return }
    if (conditions.length === 0) { setError('Add at least one condition'); return }
    if (!ownerName && !ownerEmail && !ownerRole && !team && !notes) {
      setError('Specify at least one ownership field to set'); return
    }
    setSaving(true); setError(null)
    try {
      const payload = {
        name, description, target_type: targetType,
        conditions: conditions.filter(c => c.field), condition_logic: logic,
        priority: Number(priority),
        owner_name: ownerName || null, owner_email: ownerEmail || null,
        owner_role: ownerRole || null, team: team || null, notes: notes || null,
        overwrite_existing: overwrite, is_enabled: enabled,
      }
      if (rule) { await updateOwnershipRule(rule.id, payload); toast.success('Rule updated') }
      else { await createOwnershipRule(payload); toast.success('Rule created') }
      onSave()
    } catch (e) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
          {rule ? 'Edit Ownership Rule' : 'New Ownership Rule'}
        </span>
        <button onClick={onCancel} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', display: 'flex' }}>
          <X size={14} />
        </button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 90px', gap: 10 }}>
        <div>
          <label style={labelStyle}>Rule name</label>
          <input value={name} onChange={e => setName(e.target.value)} placeholder="e.g. Assign DMZ assets to SecOps" style={inputStyle} />
        </div>
        <div>
          <label style={labelStyle}>Priority</label>
          <input type="number" value={priority} onChange={e => setPriority(e.target.value)} min={1} style={inputStyle} title="Lower = higher priority (runs first)" />
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
        <div>
          <label style={labelStyle}>Applies to</label>
          <select value={targetType} onChange={e => setTargetType(e.target.value)} style={inputStyle}>
            {TARGET_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </div>
        <div>
          <label style={labelStyle}>Logic</label>
          <select value={logic} onChange={e => setLogic(e.target.value)} style={inputStyle}>
            <option value="AND">Match ALL conditions (AND)</option>
            <option value="OR">Match ANY condition (OR)</option>
          </select>
        </div>
      </div>

      <div>
        <label style={{ ...labelStyle, fontWeight: 600 }}>Conditions (when to apply)</label>
        <RuleBuilder
          conditions={conditions}
          logic={logic}
          onChange={(conds, lgc) => { setConditions(conds); setLogic(lgc) }}
          showLogic={false}
          addLabel="Add condition"
        />
      </div>

      <div style={{ background: 'var(--bg-hover)', borderRadius: 8, padding: 12, border: '1px solid var(--border)' }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 10 }}>
          Ownership to assign
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
          <div>
            <label style={labelStyle}>Owner name</label>
            <input value={ownerName} onChange={e => setOwnerName(e.target.value)} placeholder="e.g. John Smith" style={inputStyle} />
          </div>
          <div>
            <label style={labelStyle}>Owner email</label>
            <input value={ownerEmail} onChange={e => setOwnerEmail(e.target.value)} placeholder="e.g. john@company.com" style={inputStyle} />
          </div>
          <div>
            <label style={labelStyle}>Role / team type</label>
            <select value={ownerRole} onChange={e => setOwnerRole(e.target.value)} style={inputStyle}>
              <option value="">— Leave unchanged —</option>
              {ROLE_OPTIONS.map(r => <option key={r} value={r}>{r}</option>)}
            </select>
          </div>
          <div>
            <label style={labelStyle}>Team</label>
            <input value={team} onChange={e => setTeam(e.target.value)} placeholder="e.g. Infrastructure" style={inputStyle} />
          </div>
        </div>
        <div style={{ marginTop: 10 }}>
          <label style={labelStyle}>Notes</label>
          <input value={notes} onChange={e => setNotes(e.target.value)} placeholder="Optional note added to ownership record" style={inputStyle} />
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 10 }}>
          <input type="checkbox" id="overwrite" checked={overwrite} onChange={e => setOverwrite(e.target.checked)} style={{ cursor: 'pointer' }} />
          <label htmlFor="overwrite" style={{ fontSize: 12, color: 'var(--text-secondary)', cursor: 'pointer' }}>
            Overwrite existing manually-set ownership
          </label>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <button onClick={() => setEnabled(p => !p)} style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex', color: enabled ? '#22c55e' : 'var(--text-muted)' }}>
          {enabled ? <ToggleRight size={20} /> : <ToggleLeft size={20} />}
        </button>
        <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Rule {enabled ? 'enabled' : 'disabled'}</span>
      </div>

      {error && <div style={{ fontSize: 12, color: '#dc2626', background: '#450a0a', borderRadius: 6, padding: '6px 10px' }}>{error}</div>}

      <div style={{ display: 'flex', gap: 8, paddingTop: 4 }}>
        <Button onClick={submit} disabled={saving} style={{ flex: 1 }}>
          <Save size={13} /> {saving ? 'Saving…' : rule ? 'Update Rule' : 'Create Rule'}
        </Button>
        <Button variant="ghost" onClick={onCancel}>Cancel</Button>
      </div>
    </div>
  )
}

const ASSIGN_TO_OPTIONS = [
  { value: 'owner_name',  label: 'Owner Name' },
  { value: 'owner_email', label: 'Owner Email' },
  { value: 'owner_role',  label: 'Owner Role' },
  { value: 'team',        label: 'Team' },
]

// ─── Ownership Mapping (simplified table) ─────────────────────────────────────
function OwnershipMappingRow({ mapping, catalog, onSave, onDelete }) {
  const [editing, setEditing]         = useState(!mapping)
  const [field, setField]             = useState(mapping?.conditions?.[0]?.field || '')
  const [customField, setCustomField] = useState('')
  const [assignTo, setAssignTo]       = useState(mapping?.conditions?.[0]?.value || 'owner_name')
  const [target, setTarget]           = useState(mapping?.target_type || 'asset')
  const [saving, setSaving]           = useState(false)
  const toast = useToast()

  const effectiveField = field === '__custom__' ? customField : field

  const handleSave = async () => {
    if (!effectiveField) return
    setSaving(true)
    try {
      const assignLabel = ASSIGN_TO_OPTIONS.find(o => o.value === assignTo)?.label || assignTo
      const payload = {
        name: `ownermap:${effectiveField}→${assignLabel}`,
        target_type: target,
        conditions: [{ field: effectiveField, op: 'passthrough', value: assignTo }],
        condition_logic: 'AND',
        priority: 100,
        is_enabled: true,
        overwrite_existing: true,
      }
      let ruleId = mapping?.id
      if (mapping) { await updateOwnershipRule(mapping.id, payload); toast.success('Mapping updated') }
      else { const r = await createOwnershipRule(payload); ruleId = r.id; toast.success('Mapping created') }
      // Auto-run in background — don't await, let UI update immediately
      if (ruleId) runOwnershipRule(ruleId).catch(() => {})
      onSave()
      setEditing(false)
    } finally {
      setSaving(false)
    }
  }

  if (!mapping && !editing) return null

  if (!editing && mapping) {
    const cond       = mapping.conditions?.[0] || {}
    const assignLabel = ASSIGN_TO_OPTIONS.find(o => o.value === cond.value)?.label || cond.value || '—'
    return (
      <tr style={{ borderBottom: '1px solid var(--border)' }}>
        <td style={{ padding: '8px 10px', fontSize: 12, color: 'var(--text-primary)', fontFamily: 'monospace' }}>{cond.field || '—'}</td>
        <td style={{ padding: '8px 10px', fontSize: 12, color: 'var(--text-muted)' }}>{assignLabel}</td>
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
          <span style={{ fontSize: 12, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>assign value as</span>
          <select value={assignTo} onChange={e => setAssignTo(e.target.value)} style={{ ...inputStyle, width: 140 }}>
            {ASSIGN_TO_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
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

function OwnershipMappingTab() {
  const confirm = useConfirm()
  const toast = useToast()
  const [mappings, setMappings]     = useState([])
  const [catalog, setCatalog]       = useState([])
  const [loading, setLoading]       = useState(true)
  const [addingNew, setAddingNew]   = useState(false)
  const [runAllStatus, setRunAllStatus] = useState(null)
  const [overwriteExisting, setOverwriteExisting] = useState(true)

  const handleRunAll = async () => {
    setRunAllStatus('running')
    try {
      const res = await runAllOwnershipRules(null, overwriteExisting)
      setRunAllStatus(res.total_updated ?? 0)
    } catch {
      setRunAllStatus('error')
    }
  }

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [rules, cat] = await Promise.all([getOwnershipRules(), getTagConditionCatalog()])
      setMappings(rules.filter(r => r.name?.startsWith('ownermap:')))
      setCatalog(cat)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const handleDelete = async (id) => {
    if (id === null) { setAddingNew(false); return }
    if (!await confirm('Delete this ownership mapping?')) return
    await deleteOwnershipRule(id)
    toast.success('Mapping deleted')
    load()
  }

  if (loading) return <Spinner />

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
        <div style={{ fontSize: 12, color: 'var(--text-muted)', maxWidth: 600 }}>
          Read a field's value from each asset or finding and use it directly as the owner name, role, or team.
          For example: map <code>assetOwner</code> → Owner Name to set each asset's owner from that scan field.
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {mappings.length > 0 && (
            <>
              <label style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 12, color: 'var(--text-muted)', cursor: 'pointer', userSelect: 'none' }}>
                <input
                  type="checkbox"
                  checked={overwriteExisting}
                  onChange={e => setOverwriteExisting(e.target.checked)}
                  style={{ cursor: 'pointer' }}
                />
                Overwrite existing
              </label>
              <Button size="sm" variant="ghost" onClick={handleRunAll} disabled={runAllStatus === 'running'}>
                <Play size={12} /> {runAllStatus === 'running' ? 'Running…' : 'Run All'}
              </Button>
            </>
          )}
          <Button size="sm" onClick={() => setAddingNew(true)} disabled={addingNew}>
            <Plus size={13} /> Add Mapping
          </Button>
        </div>
      </div>
      {runAllStatus !== null && (
        <div style={{ fontSize: 12, color: runAllStatus === 'error' ? '#dc2626' : '#22c55e', padding: '6px 10px', background: 'var(--bg-hover)', borderRadius: 6 }}>
          {runAllStatus === 'running' ? 'Running all mappings…' : runAllStatus === 'error' ? 'Run failed' : `✓ ${runAllStatus} ownership record(s) updated`}
        </div>
      )}

      {(mappings.length === 0 && !addingNew) ? (
        <Card style={{ textAlign: 'center', padding: '40px 24px' }}>
          <UserCheck size={28} style={{ color: 'var(--text-muted)', opacity: 0.3, marginBottom: 10 }} />
          <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>No ownership mappings yet</div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 16 }}>
            Define simple property → owner mappings without a full rule builder.
          </div>
          <Button onClick={() => setAddingNew(true)}><Plus size={13} /> Add First Mapping</Button>
        </Card>
      ) : (
        <Card style={{ padding: 0, overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: 'var(--bg-hover)', borderBottom: '1px solid var(--border)' }}>
                {['Field', 'Assign As', 'Target', 'Actions'].map(h => (
                  <th key={h} style={{ padding: '7px 10px', fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textAlign: 'left', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {mappings.map(m => (
                <OwnershipMappingRow key={m.id} mapping={m} catalog={catalog} onSave={load} onDelete={handleDelete} />
              ))}
              {addingNew && (
                <OwnershipMappingRow mapping={null} catalog={catalog}
                  onSave={() => { setAddingNew(false); load() }}
                  onDelete={() => setAddingNew(false)} />
              )}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  )
}

// ─── Main export ──────────────────────────────────────────────────────────────
export default function OwnershipRules() {
  const confirm = useConfirm()
  const toast = useToast()
  const [activeTab, setActiveTab] = useState('mapping')
  const [rules, setRules]             = useState([])
  const [loading, setLoading]         = useState(true)
  const [editingRule, setEditingRule] = useState(null)
  const [runStatus, setRunStatus]     = useState({})
  const [runAllStatus, setRunAllStatus] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    try { setRules(await getOwnershipRules()) }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { load() }, [load])

  const handleToggle = async (rule) => {
    await updateOwnershipRule(rule.id, { is_enabled: !rule.is_enabled })
    toast.success(rule.is_enabled ? 'Rule disabled' : 'Rule enabled')
    load()
  }

  const handleDelete = async (rule) => {
    if (!await confirm(`Delete rule "${rule.name}"?`)) return
    await deleteOwnershipRule(rule.id)
    toast.success('Rule deleted')
    load()
  }

  const handleRun = async (rule) => {
    setRunStatus(s => ({ ...s, [rule.id]: 'running' }))
    try {
      const res = await runOwnershipRule(rule.id)
      setRunStatus(s => ({ ...s, [rule.id]: res.updated ?? 0 }))
    } catch {
      setRunStatus(s => ({ ...s, [rule.id]: 'error' }))
    }
  }

  const handleRunAll = async () => {
    setRunAllStatus('running')
    try {
      const res = await runAllOwnershipRules()
      setRunAllStatus(res.total_updated ?? 0)
    } catch {
      setRunAllStatus('error')
    }
  }

  const TABS = [
    { id: 'mapping', label: 'Ownership Mapping' },
    { id: 'advanced', label: 'Advanced Rules' },
  ]

  if (loading && activeTab === 'advanced') return <Spinner />

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
      {/* Tab bar */}
      <div style={{ display: 'flex', gap: 0, borderBottom: '1px solid var(--border)', marginBottom: 20 }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setActiveTab(t.id)} style={{
            background: 'none', border: 'none', cursor: 'pointer',
            padding: '8px 16px', fontSize: 13, fontWeight: activeTab === t.id ? 700 : 500,
            color: activeTab === t.id ? 'var(--accent)' : 'var(--text-muted)',
            borderBottom: activeTab === t.id ? '2px solid var(--accent)' : '2px solid transparent',
            marginBottom: -1,
          }}>
            {t.label}
          </button>
        ))}
      </div>

      {activeTab === 'mapping' && <OwnershipMappingTab />}

      {activeTab === 'advanced' && (
    <div style={{ display: 'grid', gridTemplateColumns: editingRule !== null ? '1fr 440px' : '1fr', gap: 16, alignItems: 'start' }}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {/* Toolbar */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <UserCheck size={14} style={{ color: 'var(--text-muted)' }} />
            <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Ownership Rules
            </span>
            {rules.length > 0 && (
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>· {rules.length} rule{rules.length !== 1 ? 's' : ''}</span>
            )}
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            {rules.length > 0 && (
              <Button size="sm" variant="ghost" onClick={handleRunAll} disabled={runAllStatus === 'running'}>
                <Play size={12} /> Run All
              </Button>
            )}
            <Button size="sm" onClick={() => setEditingRule('new')} disabled={editingRule !== null}>
              <Plus size={13} /> New Rule
            </Button>
          </div>
        </div>

        <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 8 }}>
          Define conditions to automatically assign owners, teams, and roles to assets or findings in bulk.
        </div>

        {runAllStatus !== null && (
          <div style={{ fontSize: 12, color: runAllStatus === 'error' ? '#dc2626' : '#22c55e', padding: '6px 10px', background: 'var(--bg-hover)', borderRadius: 6 }}>
            {runAllStatus === 'running' ? 'Running all rules…' : runAllStatus === 'error' ? 'Run failed' : `✓ ${runAllStatus} ownership record(s) updated`}
          </div>
        )}

        {rules.length === 0 && editingRule === null ? (
          <Card style={{ textAlign: 'center', padding: '48px 24px' }}>
            <UserCheck size={32} style={{ color: 'var(--text-muted)', opacity: 0.3, marginBottom: 12 }} />
            <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>No ownership rules</div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 16, maxWidth: 380, margin: '0 auto 16px' }}>
              Create a rule to bulk-assign owners based on asset properties, tags, or finding attributes.
            </div>
            <Button onClick={() => setEditingRule('new')}><Plus size={13} /> Create First Rule</Button>
          </Card>
        ) : (
          rules.map(rule => {
            const status = runStatus[rule.id]
            const actionParts = [rule.owner_role, rule.team, rule.owner_name].filter(Boolean)
            return (
              <Card key={rule.id} style={{ padding: '14px 16px' }}>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
                  <button onClick={() => handleToggle(rule)} style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex', color: rule.is_enabled ? '#22c55e' : 'var(--text-muted)', paddingTop: 1, flexShrink: 0 }}>
                    {rule.is_enabled ? <ToggleRight size={20} /> : <ToggleLeft size={20} />}
                  </button>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                      <span style={{ fontWeight: 600, fontSize: 14, color: 'var(--text-primary)' }}>{rule.name}</span>
                      <span style={{ fontSize: 10, background: 'var(--bg-hover)', color: 'var(--text-muted)', borderRadius: 4, padding: '1px 6px' }}>priority {rule.priority}</span>
                      {!rule.is_enabled && <span style={{ fontSize: 10, background: 'var(--bg-hover)', color: 'var(--text-muted)', borderRadius: 4, padding: '1px 6px' }}>disabled</span>}
                    </div>
                    {rule.description && <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 6 }}>{rule.description}</div>}
                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
                      <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                        {rule.conditions?.length || 0} condition{rule.conditions?.length !== 1 ? 's' : ''} ({rule.condition_logic}) · {rule.target_type}
                      </span>
                      {actionParts.length > 0 && (
                        <span style={{ fontSize: 11, color: '#818cf8' }}>
                          → {actionParts.join(' / ')}{rule.owner_email ? ` <${rule.owner_email}>` : ''}
                        </span>
                      )}
                      {rule.overwrite_existing && (
                        <span style={{ fontSize: 10, background: '#450a0a', color: '#dc2626', borderRadius: 4, padding: '1px 6px' }}>overwrites</span>
                      )}
                      {rule.last_run_at && (
                        <span style={{ fontSize: 11, color: 'var(--text-muted)', marginLeft: 'auto' }}>
                          Last: {new Date(rule.last_run_at).toLocaleDateString()} · {rule.last_run_count ?? 0} updated
                        </span>
                      )}
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: 4, alignItems: 'center', flexShrink: 0 }}>
                    <Button size="sm" variant="ghost" onClick={() => handleRun(rule)} disabled={status === 'running'}>
                      <Play size={11} /> {status === 'running' ? 'Running…' : 'Run'}
                    </Button>
                    <button onClick={() => setEditingRule(rule)} style={iconBtnStyle}><Edit2 size={13} /></button>
                    <button onClick={() => handleDelete(rule)} style={{ ...iconBtnStyle, color: '#dc2626' }}><Trash2 size={13} /></button>
                  </div>
                </div>
                {(typeof status === 'number' || status === 'error') && (
                  <div style={{ marginTop: 8, paddingTop: 8, borderTop: '1px solid var(--border)' }}>
                    {typeof status === 'number'
                      ? <span style={{ fontSize: 11, color: '#22c55e' }}>✓ {status} ownership record{status !== 1 ? 's' : ''} updated</span>
                      : <span style={{ fontSize: 11, color: '#dc2626' }}>Run failed</span>}
                  </div>
                )}
              </Card>
            )
          })
        )}
      </div>

      {editingRule !== null && (
        <Card>
          <OwnershipRuleForm
            rule={editingRule === 'new' ? null : editingRule}
            onSave={() => { setEditingRule(null); load() }}
            onCancel={() => setEditingRule(null)}
          />
        </Card>
      )}
    </div>
      )}
    </div>
  )
}
