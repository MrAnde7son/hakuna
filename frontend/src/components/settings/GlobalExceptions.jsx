import React, { useState, useEffect, useCallback } from 'react'
import { ShieldOff, ShieldCheck, ShieldAlert, Plus, Trash2, Edit3, RefreshCw, Clock, AlertTriangle, CheckCircle, X, Filter, ArrowDownUp, Tag, CalendarClock } from 'lucide-react'
import { getExceptions, createException, updateException, deleteException, applyAllExceptions, getExceptionConditionCatalog, getAssets, getTags } from '../../api.js'
import { Card, StatCard, PageHeader, Button, Select, Input, Spinner, Table, FilterBar, EmptyState, Pill } from '../shared/ui.jsx'
import RuleBuilder from '../campaigns/RuleBuilder.jsx'

// ─── Toast ───────────────────────────────────────────────────────────────────

function Toast({ message, type = 'success', onClose }) {
  useEffect(() => {
    const t = setTimeout(onClose, 3500)
    return () => clearTimeout(t)
  }, [onClose])

  const bg = type === 'success' ? '#16a34a' : type === 'error' ? '#dc2626' : '#d97706'
  const Icon = type === 'success' ? CheckCircle : type === 'error' ? X : AlertTriangle

  return (
    <div style={{
      position: 'fixed', bottom: 24, right: 24, zIndex: 9999,
      display: 'flex', alignItems: 'center', gap: 8,
      background: bg, color: '#fff', padding: '10px 18px',
      borderRadius: 8, fontSize: 13, fontWeight: 600,
      boxShadow: '0 4px 20px rgba(0,0,0,0.25)',
      animation: 'toastIn 0.25s ease-out',
    }}>
      <Icon size={16} />
      {message}
      <style>{`@keyframes toastIn { from { opacity:0; transform:translateY(12px) } to { opacity:1; transform:translateY(0) } }`}</style>
    </div>
  )
}

// ─── Confirm Dialog ──────────────────────────────────────────────────────────

function ConfirmDialog({ message, onConfirm, onCancel }) {
  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 9000,
      background: 'rgba(0,0,0,0.5)', display: 'flex',
      alignItems: 'center', justifyContent: 'center',
    }}>
      <div style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)',
        borderRadius: 12, padding: 24, maxWidth: 400, width: '90%',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
          <AlertTriangle size={20} color="#d97706" />
          <span style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-primary)' }}>Confirm</span>
        </div>
        <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 20, lineHeight: 1.5 }}>{message}</p>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
          <Button variant="ghost" onClick={onCancel}>Cancel</Button>
          <Button variant="danger" onClick={onConfirm}><Trash2 size={14} /> Delete</Button>
        </div>
      </div>
    </div>
  )
}

// ─── Create / Edit Modal ─────────────────────────────────────────────────────

const SEVERITY_OPTIONS = [
  { value: 4, label: 'Critical', color: '#dc2626' },
  { value: 3, label: 'High', color: '#f97316' },
  { value: 2, label: 'Medium', color: '#eab308' },
  { value: 1, label: 'Low', color: '#22c55e' },
  { value: 0, label: 'Info', color: '#6b7280' },
]

const DEBT_CATEGORIES = [
  { value: 'legacy_system', label: 'Legacy System' },
  { value: 'business_requirement', label: 'Business Requirement' },
  { value: 'vendor_dependency', label: 'Vendor Dependency' },
  { value: 'compatibility', label: 'Compatibility' },
  { value: 'cost', label: 'Cost Prohibitive' },
]

const EMPTY_FORM = {
  exception_type: 'accepted_risk',
  override_severity: 3,
  compensating_control_detail: '',
  debt_category: 'legacy_system',
  mitigation_plan: '',
  scope: 'global',
  asset_ip: '',
  scope_tags_str: '',
  conditions: [],
  condition_logic: 'AND',
  reason: '',
  approved_by: '',
  exclude_from_reports: true,
  expires_mode: 'permanent',
  expires_at: '',
  review_mode: 'none',
  review_by: '',
}

// When editing an old exception that has plugin_id but no conditions,
// migrate plugin_id into a condition so the user sees it in the RuleBuilder.
function _migrateInitial(initial) {
  const conds = [...(initial.conditions || [])]
  if (initial.plugin_id && !conds.some(c => c.field === 'finding.plugin_id')) {
    conds.unshift({ field: 'finding.plugin_id', op: 'eq', value: String(initial.plugin_id) })
  }
  return conds
}

function ExceptionModal({ initial, onSave, onClose, saving }) {
  const [form, setForm] = useState(() => {
    if (!initial) return { ...EMPTY_FORM }
    const scopeTags = initial.scope_tags || []
    return {
      exception_type: initial.exception_type || 'accepted_risk',
      override_severity: initial.override_severity ?? 3,
      compensating_control_detail: initial.compensating_control_detail || '',
      debt_category: initial.debt_category || 'legacy_system',
      mitigation_plan: initial.mitigation_plan || '',
      scope: scopeTags.length > 0 ? 'tags' : initial.asset_ip ? 'specific' : 'global',
      asset_ip: initial.asset_ip || '',
      scope_tags_str: scopeTags.join(', '),
      conditions: _migrateInitial(initial),
      condition_logic: initial.condition_logic || 'AND',
      reason: initial.reason || '',
      approved_by: initial.approved_by || '',
      exclude_from_reports: initial.exclude_from_reports ?? true,
      expires_mode: initial.expires_at ? 'date' : 'permanent',
      expires_at: initial.expires_at ? initial.expires_at.split('T')[0] : '',
      review_mode: initial.review_by ? 'date' : 'none',
      review_by: initial.review_by ? initial.review_by.split('T')[0] : '',
    }
  })
  const [catalog, setCatalog] = useState(null)
  const [assetIps, setAssetIps] = useState([])
  const [tagLabels, setTagLabels] = useState([])

  useEffect(() => {
    getExceptionConditionCatalog().then(setCatalog).catch(console.error)
    getAssets({ limit: 500 }).then(data => {
      const list = (Array.isArray(data) ? data : data.assets || [])
      setAssetIps([...new Set(list.map(a => a.ip).filter(Boolean))])
    }).catch(() => {})
    getTags().then(data => {
      const list = Array.isArray(data) ? data : data.tags || []
      setTagLabels(list.map(t => `${t.category}:${t.value}`))
    }).catch(() => {})
  }, [])

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }))

  const handleSave = () => {
    if (form.conditions.length === 0) return
    const scopeTags = form.scope === 'tags'
      ? form.scope_tags_str.split(',').map(s => s.trim()).filter(Boolean)
      : null
    const payload = {
      plugin_id: null,
      plugin_name: null,
      exception_type: form.exception_type,
      override_severity: form.exception_type === 'severity_override' ? Number(form.override_severity) : null,
      compensating_control_detail: form.exception_type === 'compensating_control' ? form.compensating_control_detail.trim() || null : null,
      debt_category: form.exception_type === 'technical_debt' ? form.debt_category : null,
      mitigation_plan: form.exception_type === 'technical_debt' ? form.mitigation_plan.trim() || null : null,
      asset_ip: form.scope === 'specific' ? form.asset_ip.trim() || null : null,
      scope_tags: scopeTags && scopeTags.length > 0 ? scopeTags : null,
      conditions: form.conditions,
      condition_logic: form.condition_logic,
      reason: form.reason.trim() || null,
      approved_by: form.approved_by.trim() || null,
      exclude_from_reports: form.exclude_from_reports,
      expires_at: form.expires_mode === 'date' && form.expires_at ? form.expires_at : null,
      review_by: form.review_mode === 'date' && form.review_by ? form.review_by : null,
    }
    onSave(payload)
  }

  const canSave = form.conditions.length > 0
    && (form.exception_type !== 'severity_override' || form.override_severity != null)

  const inputStyle = {
    width: '100%', boxSizing: 'border-box',
    border: '1px solid var(--border)', borderRadius: 8,
    padding: '8px 12px', fontSize: 13,
    background: 'var(--bg)', color: 'var(--text)',
    outline: 'none',
  }

  const labelStyle = { fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 4, display: 'block' }

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 8000,
      background: 'rgba(0,0,0,0.5)', display: 'flex',
      alignItems: 'center', justifyContent: 'center',
    }}>
      <div style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)',
        borderRadius: 12, padding: 24, maxWidth: 640, width: '94%',
        maxHeight: '90vh', overflowY: 'auto',
      }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
          <h2 style={{ fontSize: 17, fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
            {initial ? 'Edit Exception' : 'New Exception'}
          </h2>
          <button onClick={onClose} style={{
            background: 'none', border: 'none', cursor: 'pointer',
            color: 'var(--text-muted)', padding: 4,
          }}><X size={18} /></button>
        </div>

        {/* Type + severity override in one row */}
        <div style={{ display: 'flex', gap: 12, marginBottom: 14 }}>
          <div style={{ flex: 1 }}>
            <label style={labelStyle}>Type</label>
            <select
              value={form.exception_type}
              onChange={e => set('exception_type', e.target.value)}
              style={{ ...inputStyle, cursor: 'pointer' }}
            >
              <option value="accepted_risk">Accepted Risk</option>
              <option value="false_positive">False Positive</option>
              <option value="compensating_control">Compensating Control</option>
              <option value="severity_override">Severity Override</option>
              <option value="technical_debt">Technical Debt</option>
            </select>
          </div>
          {form.exception_type === 'severity_override' && (
            <div style={{ flex: 1 }}>
              <label style={labelStyle}>Change Severity To</label>
              <div style={{ display: 'flex', gap: 4 }}>
                {SEVERITY_OPTIONS.map(opt => (
                  <button
                    key={opt.value}
                    onClick={() => set('override_severity', opt.value)}
                    style={{
                      flex: 1, padding: '7px 2px', borderRadius: 6, cursor: 'pointer',
                      fontSize: 11, fontWeight: 600, textAlign: 'center',
                      border: `2px solid ${form.override_severity === opt.value ? opt.color : 'var(--border)'}`,
                      background: form.override_severity === opt.value ? `${opt.color}18` : 'var(--bg)',
                      color: form.override_severity === opt.value ? opt.color : 'var(--text-muted)',
                    }}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>
          )}
          {form.exception_type === 'compensating_control' && (
            <div style={{ flex: 1 }}>
              <label style={labelStyle}>Compensating Control</label>
              <textarea
                value={form.compensating_control_detail}
                onChange={e => set('compensating_control_detail', e.target.value)}
                placeholder="Describe the compensating control (e.g. WAF blocks exploitation, network segmentation isolates host)"
                rows={2}
                style={{ ...inputStyle, resize: 'vertical', fontFamily: 'inherit' }}
              />
            </div>
          )}
          {form.exception_type === 'technical_debt' && (
            <>
              <div style={{ flex: 1 }}>
                <label style={labelStyle}>Debt Category</label>
                <select
                  value={form.debt_category}
                  onChange={e => set('debt_category', e.target.value)}
                  style={{ ...inputStyle, cursor: 'pointer' }}
                >
                  {DEBT_CATEGORIES.map(c => <option key={c.value} value={c.value}>{c.label}</option>)}
                </select>
              </div>
              <div style={{ flex: 1 }}>
                <label style={labelStyle}>Mitigation Plan</label>
                <textarea
                  value={form.mitigation_plan}
                  onChange={e => set('mitigation_plan', e.target.value)}
                  placeholder="What compensating controls or mitigations are in place?"
                  rows={2}
                  style={{ ...inputStyle, resize: 'vertical', fontFamily: 'inherit' }}
                />
              </div>
            </>
          )}
        </div>

        {/* Scope */}
        <div style={{ marginBottom: 14 }}>
          <label style={labelStyle}>Asset Scope</label>
          <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', marginBottom: 6 }}>
            {[
              { value: 'global', label: 'All Assets' },
              { value: 'specific', label: 'Specific Asset' },
              { value: 'tags', label: 'By Tags' },
            ].map(opt => (
              <label key={opt.value} style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', fontSize: 13, color: 'var(--text)' }}>
                <input type="radio" name="scope" checked={form.scope === opt.value} onChange={() => set('scope', opt.value)} />
                {opt.label}
              </label>
            ))}
          </div>
          {form.scope === 'specific' && (
            <>
              <input
                value={form.asset_ip}
                onChange={e => set('asset_ip', e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter' && canSave) handleSave() }}
                placeholder="Asset IP address"
                list="exc-asset-ips"
                style={inputStyle}
              />
              <datalist id="exc-asset-ips">
                {assetIps.map(ip => <option key={ip} value={ip} />)}
              </datalist>
            </>
          )}
          {form.scope === 'tags' && (
            <>
              <input
                value={form.scope_tags_str}
                onChange={e => set('scope_tags_str', e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter' && canSave) handleSave() }}
                placeholder="e.g. env:prod, net:dmz"
                list="exc-tag-labels"
                style={inputStyle}
              />
              <datalist id="exc-tag-labels">
                {tagLabels.map(t => <option key={t} value={t} />)}
              </datalist>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                Comma-separated category:value pairs. Exception applies only to assets with matching tags.
              </div>
            </>
          )}
        </div>

        {/* Matching Conditions (RuleBuilder) */}
        <div style={{ marginBottom: 14 }}>
          <label style={labelStyle}>Matching Conditions</label>
          {catalog ? (
            <RuleBuilder
              conditions={form.conditions}
              logic={form.condition_logic}
              onChange={(conds, logic) => setForm(f => ({ ...f, conditions: conds, condition_logic: logic }))}
              catalog={catalog}
              showLogic
              addLabel="Add Condition"
            />
          ) : (
            <div style={{ fontSize: 12, color: 'var(--text-muted)', padding: '8px 0' }}>Loading conditions...</div>
          )}
          {form.conditions.length === 0 && (
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 6, fontStyle: 'italic' }}>
              Add at least one condition to define what this exception matches.
            </div>
          )}
        </div>

        {/* Reason */}
        <div style={{ marginBottom: 14 }}>
          <label style={labelStyle}>Reason</label>
          <textarea
            value={form.reason}
            onChange={e => set('reason', e.target.value)}
            placeholder="Why is this exception being created?"
            rows={2}
            style={{ ...inputStyle, resize: 'vertical', fontFamily: 'inherit' }}
          />
        </div>

        {/* Exclude from reports toggle */}
        <div style={{ marginBottom: 14 }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: 13, color: 'var(--text)' }}>
            <input
              type="checkbox"
              checked={form.exclude_from_reports}
              onChange={e => set('exclude_from_reports', e.target.checked)}
            />
            <span style={{ fontWeight: 600 }}>Exclude from reports & scoring</span>
          </label>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2, marginLeft: 24 }}>
            When checked, matched findings won't count toward severity totals or priority metrics.
          </div>
        </div>

        {/* Approved By + Expiration row */}
        <div style={{ display: 'flex', gap: 12, marginBottom: 14 }}>
          <div style={{ flex: 1 }}>
            <label style={labelStyle}>Approved By</label>
            <input
              value={form.approved_by}
              onChange={e => set('approved_by', e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter' && canSave) handleSave() }}
              placeholder="Name or email"
              style={inputStyle}
            />
          </div>
          <div style={{ flex: 1 }}>
            <label style={labelStyle}>Expiration</label>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              {['permanent', 'date'].map(mode => (
                <label key={mode} style={{ display: 'flex', alignItems: 'center', gap: 4, cursor: 'pointer', fontSize: 12, color: 'var(--text)' }}>
                  <input type="radio" name="expires" checked={form.expires_mode === mode} onChange={() => set('expires_mode', mode)} />
                  {mode === 'permanent' ? 'Permanent' : 'Date'}
                </label>
              ))}
            </div>
            {form.expires_mode === 'date' && (
              <input
                type="date"
                value={form.expires_at}
                onChange={e => set('expires_at', e.target.value)}
                style={{ ...inputStyle, marginTop: 6 }}
              />
            )}
          </div>
        </div>

        {/* Review / Recertification date */}
        <div style={{ display: 'flex', gap: 12, marginBottom: 20 }}>
          <div style={{ flex: 1 }}>
            <label style={labelStyle}>Review / Recertification</label>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              {[{ value: 'none', label: 'None' }, { value: 'date', label: 'Date' }].map(opt => (
                <label key={opt.value} style={{ display: 'flex', alignItems: 'center', gap: 4, cursor: 'pointer', fontSize: 12, color: 'var(--text)' }}>
                  <input type="radio" name="review" checked={form.review_mode === opt.value} onChange={() => set('review_mode', opt.value)} />
                  {opt.label}
                </label>
              ))}
            </div>
            {form.review_mode === 'date' && (
              <input
                type="date"
                value={form.review_by}
                onChange={e => set('review_by', e.target.value)}
                style={{ ...inputStyle, marginTop: 6 }}
              />
            )}
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
              Soft reminder to re-evaluate this exception. Does not auto-deactivate.
            </div>
          </div>
        </div>

        {/* Actions */}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
          <Button variant="ghost" onClick={onClose} disabled={saving}>Cancel</Button>
          <Button onClick={handleSave} disabled={saving || !canSave}>
            {saving ? <RefreshCw size={14} style={{ animation: 'spin 0.8s linear infinite' }} /> : <CheckCircle size={14} />}
            {initial ? 'Update' : 'Create'}
          </Button>
        </div>
      </div>
    </div>
  )
}

// ─── Main Component ──────────────────────────────────────────────────────────

export default function GlobalExceptions() {
  const [exceptions, setExceptions] = useState([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState(null)
  const [statusFilter, setStatusFilter] = useState('active')
  const [modalOpen, setModalOpen] = useState(false)
  const [editItem, setEditItem] = useState(null)
  const [saving, setSaving] = useState(false)
  const [applying, setApplying] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [toast, setToast] = useState(null)

  const showToast = useCallback((message, type = 'success') => {
    setToast({ message, type })
  }, [])

  const load = useCallback(async () => {
    try {
      setLoading(true)
      const data = await getExceptions()
      setExceptions(Array.isArray(data) ? data : data.exceptions || [])
    } catch (e) {
      showToast('Failed to load exceptions', 'error')
    } finally {
      setLoading(false)
    }
  }, [showToast])

  useEffect(() => { load() }, [load])

  // ── Filters ──
  const filtered = exceptions.filter(ex => {
    if (statusFilter === 'active' && ex.is_active === false) return false
    if (typeFilter && ex.exception_type !== typeFilter) return false
    if (search) {
      const q = search.toLowerCase()
      const matchId = String(ex.plugin_id || '').toLowerCase().includes(q)
      const matchName = (ex.plugin_name || '').toLowerCase().includes(q)
      const matchReason = (ex.reason || '').toLowerCase().includes(q)
      const matchConds = (ex.conditions || []).some(c =>
        String(c.value || '').toLowerCase().includes(q) ||
        (c.field || '').toLowerCase().includes(q)
      )
      if (!matchId && !matchName && !matchReason && !matchConds) return false
    }
    return true
  })

  const activeCount = exceptions.filter(ex => ex.is_active !== false).length
  const acceptedRiskCount = exceptions.filter(ex => ex.exception_type === 'accepted_risk' && ex.is_active !== false).length
  const falsePositiveCount = exceptions.filter(ex => ex.exception_type === 'false_positive' && ex.is_active !== false).length
  const compensatingControlCount = exceptions.filter(ex => ex.exception_type === 'compensating_control' && ex.is_active !== false).length
  const severityOverrideCount = exceptions.filter(ex => ex.exception_type === 'severity_override' && ex.is_active !== false).length
  const needsReviewCount = exceptions.filter(ex => ex.is_active !== false && ex.review_by && new Date(ex.review_by) <= new Date()).length

  // ── Handlers ──
  const handleSave = async (payload) => {
    try {
      setSaving(true)
      if (editItem) {
        await updateException(editItem.id, payload)
        showToast('Exception updated')
      } else {
        await createException(payload)
        showToast('Exception created')
      }
      setModalOpen(false)
      setEditItem(null)
      await load()
    } catch (e) {
      showToast(e.message || 'Failed to save exception', 'error')
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async () => {
    if (!deleteTarget) return
    try {
      await deleteException(deleteTarget.id)
      showToast('Exception deleted')
      setDeleteTarget(null)
      await load()
    } catch (e) {
      showToast(e.message || 'Failed to delete exception', 'error')
      setDeleteTarget(null)
    }
  }

  const handleApplyAll = async () => {
    try {
      setApplying(true)
      const result = await applyAllExceptions()
      const count = result?.applied ?? result?.count ?? 0
      showToast(`Re-applied exceptions (${count} findings affected)`)
    } catch (e) {
      showToast(e.message || 'Failed to apply exceptions', 'error')
    } finally {
      setApplying(false)
    }
  }

  const openEdit = (ex) => {
    setEditItem(ex)
    setModalOpen(true)
  }

  const openCreate = () => {
    setEditItem(null)
    setModalOpen(true)
  }

  // ── Format helpers ──
  const formatDate = (d) => {
    if (!d) return 'Permanent'
    try {
      return new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
    } catch { return d }
  }

  const isExpired = (d) => {
    if (!d) return false
    try { return new Date(d) < new Date() } catch { return false }
  }

  // ── Describe conditions for table display ──
  const describeConditions = (ex) => {
    const conds = ex.conditions || []
    if (conds.length === 0 && ex.plugin_id) return `Plugin ${ex.plugin_id}`
    if (conds.length === 0) return 'No criteria'
    // Show first condition as a readable summary
    const first = conds[0]
    const OP_LABELS = { eq: '=', neq: '\u2260', contains: 'contains', startswith: 'starts with', gte: '\u2265', lte: '\u2264', gt: '>', lt: '<', is_true: 'is present', is_false: 'is not present', has_tag: 'has tag', not_has_tag: 'not has tag' }
    const label = first.field?.replace('finding.', '').replace('inventory.', '')
    const op = OP_LABELS[first.op] || first.op
    const val = ['is_true', 'is_false'].includes(first.op) ? '' : ` ${first.value ?? ''}`
    const extra = conds.length > 1 ? ` +${conds.length - 1} more` : ''
    return `${label} ${op}${val}${extra}`
  }

  // ── Table columns ──
  const columns = [
    { key: '_match', label: 'Match', render: (_, row) => {
      const desc = describeConditions(row)
      const conds = row.conditions || []
      return (
        <span
          title={conds.map(c => `${c.field} ${c.op} ${c.value ?? ''}`).join('\n')}
          style={{ fontSize: 12, color: 'var(--text-primary)', maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'inline-block' }}
        >
          {desc}
        </span>
      )
    }},
    { key: 'exception_type', label: 'Type', width: 170, render: (v, row) => {
      if (v === 'severity_override') {
        const sev = SEVERITY_OPTIONS.find(s => s.value === row.override_severity) || { label: '?', color: '#6b7280' }
        return (
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 11, fontWeight: 600 }}>
            <Pill label="Override" color="#8b5cf6" />
            <span style={{ color: sev.color }}>{sev.label}</span>
          </span>
        )
      }
      if (v === 'compensating_control') return <Pill label="Compensating Ctrl" color="#10b981" />
      if (v === 'technical_debt') return <Pill label="Tech Debt" color="#d97706" />
      const isAccepted = v === 'accepted_risk'
      return <Pill label={isAccepted ? 'Accepted Risk' : 'False Positive'} color={isAccepted ? '#d97706' : '#3b82f6'} />
    }},
    { key: '_criteria', label: 'Criteria', width: 200, render: (_, row) => {
      const conds = row.conditions || []
      const tags = row.scope_tags || []
      const hasScope = row.asset_ip || tags.length > 0
      return (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, alignItems: 'center' }}>
          {row.asset_ip && (
            <span style={{ fontSize: 11, padding: '1px 6px', borderRadius: 4, background: 'rgba(99,102,241,0.12)', color: '#6366f1', fontFamily: 'monospace' }}>
              {row.asset_ip}
            </span>
          )}
          {tags.map(t => (
            <span key={t} style={{
              fontSize: 11, padding: '1px 6px', borderRadius: 4,
              background: 'rgba(139,92,246,0.12)', color: '#7c3aed',
              display: 'inline-flex', alignItems: 'center', gap: 3,
            }}>
              <Tag size={9} />{t}
            </span>
          ))}
          {!hasScope && !conds.length && (
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Global</span>
          )}
          {conds.length > 0 && (
            <span
              title={conds.map(c => `${c.field} ${c.op} ${c.value ?? ''}`).join(', ')}
              style={{
                fontSize: 11, padding: '1px 6px', borderRadius: 4,
                background: 'rgba(234,179,8,0.12)', color: '#ca8a04',
                display: 'inline-flex', alignItems: 'center', gap: 3, cursor: 'default',
              }}
            >
              <Filter size={10} />
              {conds.length} rule{conds.length > 1 ? 's' : ''}
            </span>
          )}
        </div>
      )
    }},
    { key: 'reason', label: 'Reason', render: (v) => (
      <span style={{ maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'inline-block', fontSize: 12, color: 'var(--text-secondary)' }}>
        {v || '\u2014'}
      </span>
    )},
    { key: 'approved_by', label: 'Approved By', width: 110, render: (v) => (
      <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{v || '\u2014'}</span>
    )},
    { key: 'expires_at', label: 'Expires', width: 110, render: (v) => {
      const expired = isExpired(v)
      return (
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 12, color: expired ? '#dc2626' : 'var(--text-secondary)' }}>
          {v && <Clock size={12} />}
          {expired ? 'Expired' : formatDate(v)}
        </span>
      )
    }},
    { key: 'review_by', label: 'Review', width: 100, render: (v) => {
      if (!v) return <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{'\u2014'}</span>
      const overdue = new Date(v) <= new Date()
      return (
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 12, color: overdue ? '#dc2626' : 'var(--text-secondary)', fontWeight: overdue ? 600 : 400 }}>
          <CalendarClock size={12} />
          {overdue ? 'Overdue' : formatDate(v)}
        </span>
      )
    }},
    { key: '_actions', label: '', width: 70, render: (_, row) => (
      <div style={{ display: 'flex', gap: 6 }}>
        <button
          onClick={e => { e.stopPropagation(); openEdit(row) }}
          title="Edit exception"
          style={{
            background: 'none', border: 'none', cursor: 'pointer',
            color: 'var(--text-muted)', padding: 4, borderRadius: 4,
            display: 'flex', alignItems: 'center',
          }}
          onMouseEnter={e => e.currentTarget.style.color = 'var(--text-primary)'}
          onMouseLeave={e => e.currentTarget.style.color = 'var(--text-muted)'}
        >
          <Edit3 size={14} />
        </button>
        <button
          onClick={e => { e.stopPropagation(); setDeleteTarget(row) }}
          title="Delete exception"
          style={{
            background: 'none', border: 'none', cursor: 'pointer',
            color: 'var(--text-muted)', padding: 4, borderRadius: 4,
            display: 'flex', alignItems: 'center',
          }}
          onMouseEnter={e => e.currentTarget.style.color = '#dc2626'}
          onMouseLeave={e => e.currentTarget.style.color = 'var(--text-muted)'}
        >
          <Trash2 size={14} />
        </button>
      </div>
    )},
  ]

  // ── Render ──
  if (loading) return <Spinner />

  return (
    <div>
      {/* Header */}
      <PageHeader
        title="Global Exceptions"
        subtitle="Manage accepted risks, false positives, and compensating controls across all scans"
        action={
          <div style={{ display: 'flex', gap: 8 }}>
            <Button variant="ghost" onClick={handleApplyAll} disabled={applying}>
              <RefreshCw size={14} style={applying ? { animation: 'spin 0.8s linear infinite' } : undefined} />
              Re-apply All
            </Button>
            <Button onClick={openCreate}>
              <Plus size={14} /> New Exception
            </Button>
          </div>
        }
      />

      {/* Summary Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16, marginBottom: 16 }}>
        <StatCard label="Total Active" value={activeCount} icon={ShieldOff} color="var(--text-primary)" />
        <StatCard label="Accepted Risks" value={acceptedRiskCount} icon={AlertTriangle} color="#d97706" />
        <StatCard label="False Positives" value={falsePositiveCount} icon={ShieldCheck} color="#3b82f6" />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16, marginBottom: 24 }}>
        <StatCard label="Compensating Controls" value={compensatingControlCount} icon={ShieldAlert} color="#10b981" />
        <StatCard label="Severity Overrides" value={severityOverrideCount} icon={ArrowDownUp} color="#8b5cf6" />
        <StatCard label="Needs Review" value={needsReviewCount} icon={CalendarClock} color={needsReviewCount > 0 ? '#dc2626' : '#6b7280'} />
      </div>

      {/* Filter Bar */}
      <FilterBar>
        <Input
          value={search}
          onChange={setSearch}
          placeholder="Search exceptions..."
          style={{ minWidth: 220 }}
        />
        <Select
          value={typeFilter}
          onChange={setTypeFilter}
          placeholder="All Types"
          options={[
            { value: 'accepted_risk', label: 'Accepted Risk' },
            { value: 'false_positive', label: 'False Positive' },
            { value: 'compensating_control', label: 'Compensating Control' },
            { value: 'severity_override', label: 'Severity Override' },
            { value: 'technical_debt', label: 'Technical Debt' },
          ]}
        />
        <Select
          value={statusFilter}
          onChange={v => setStatusFilter(v || 'active')}
          options={[
            { value: 'active', label: 'Active Only' },
            { value: 'all', label: 'All' },
          ]}
        />
      </FilterBar>

      {/* Table */}
      {filtered.length === 0 && !loading ? (
        <Card>
          <EmptyState
            icon={ShieldOff}
            title="No exceptions found"
            sub={search || typeFilter ? 'Try adjusting your filters' : 'Create your first exception to accept a risk or mark a false positive'}
          >
            {!search && !typeFilter && (
              <Button onClick={openCreate} style={{ marginTop: 8 }}><Plus size={14} /> New Exception</Button>
            )}
          </EmptyState>
        </Card>
      ) : (
        <Card style={{ padding: 0, overflow: 'hidden' }}>
          <Table columns={columns} rows={filtered} emptyMessage="No exceptions match your filters" />
        </Card>
      )}

      {/* Modal */}
      {modalOpen && (
        <ExceptionModal
          initial={editItem}
          onSave={handleSave}
          onClose={() => { setModalOpen(false); setEditItem(null) }}
          saving={saving}
        />
      )}

      {/* Confirm Delete */}
      {deleteTarget && (
        <ConfirmDialog
          message={`Delete this exception${deleteTarget.plugin_id ? ` (plugin ${deleteTarget.plugin_id})` : ''}? This cannot be undone.`}
          onConfirm={handleDelete}
          onCancel={() => setDeleteTarget(null)}
        />
      )}

      {/* Toast */}
      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
    </div>
  )
}
