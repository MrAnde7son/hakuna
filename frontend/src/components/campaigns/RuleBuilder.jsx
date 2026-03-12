/**
 * RuleBuilder — Shared condition builder used by:
 *   - RiskSettings (criticality auto-rules)
 *   - TagManager (auto-tag rules)
 *   - CampaignDetail (campaign query builder)
 *
 * Props:
 *   conditions   [{field, op, value}]  — current condition list
 *   logic        "AND" | "OR"
 *   onChange     (conditions, logic) => void
 *   catalog      already-loaded catalog array (optional; loads from API if not provided)
 *   filterGroups string[] — show only these group names (optional)
 *   showLogic    bool — show AND/OR toggle (default true)
 *   addLabel     string — label for the Add Condition button (default "Add Condition")
 *   compact      bool — tighter layout for inline use (default false)
 */
import React, { useState, useEffect } from 'react'
import { Plus, Minus } from 'lucide-react'
import { getRuleEngineCatalog } from '../../api.js'

// ─── Operator labels ──────────────────────────────────────────────────────────
const OP_LABELS = {
  eq:           '=',
  neq:          '≠',
  gt:           '>',
  lt:           '<',
  gte:          '≥',
  lte:          '≤',
  contains:     'contains',
  not_contains: 'not contains',
  startswith:   'starts with',
  endswith:     'ends with',
  regex:        'regex',
  glob:         'glob',
  cidr:         'in CIDR',
  is_true:      'is present',
  is_false:     'is not present',
  has_tag:      'has tag',
  not_has_tag:  'not has tag',
}

// ─── Single condition row ─────────────────────────────────────────────────────
function ConditionRow({ cond, catalog, allConditions, onChange, onRemove, showRemove, compact }) {
  const field    = cond.field || ''
  const meta     = allConditions.find(c => c.field === field) || null
  const availOps = meta?.ops || ['eq']
  const op       = availOps.includes(cond.op) ? cond.op : availOps[0]
  const noValue  = ['is_true', 'is_false'].includes(op)

  const handleFieldChange = (newField) => {
    const newMeta = allConditions.find(c => c.field === newField)
    const newOp   = newMeta?.ops[0] || 'eq'
    onChange({ field: newField, op: newOp, value: null })
  }

  const handleOpChange = (newOp) => {
    const clearVal = ['is_true', 'is_false'].includes(newOp)
    onChange({ ...cond, op: newOp, value: clearVal ? null : cond.value })
  }

  const gap   = compact ? 4 : 6
  const mb    = compact ? 4 : 6
  const fsize = compact ? 11 : 12

  const sel = {
    padding: compact ? '3px 6px' : '4px 8px',
    borderRadius: 5, border: '1px solid var(--border)',
    background: 'var(--bg)', color: 'var(--text)', fontSize: fsize,
  }
  const inp = { ...sel, flex: 1 }

  return (
    <div style={{ display: 'flex', gap, alignItems: 'center', marginBottom: mb }}>
      {/* Field — grouped by catalog section */}
      <select
        value={field}
        onChange={e => handleFieldChange(e.target.value)}
        style={{ ...sel, minWidth: compact ? 120 : 150 }}
      >
        {!field && <option value="">— Field —</option>}
        {catalog.map(group => (
          <optgroup key={group.group} label={group.group}>
            {group.conditions.map(c => (
              <option key={c.field} value={c.field}>{c.label}</option>
            ))}
          </optgroup>
        ))}
      </select>

      {/* Operator */}
      {meta && (
        <select
          value={op}
          onChange={e => handleOpChange(e.target.value)}
          style={{ ...sel, minWidth: compact ? 90 : 110 }}
        >
          {availOps.map(o => (
            <option key={o} value={o}>{OP_LABELS[o] || o}</option>
          ))}
        </select>
      )}

      {/* Value — hidden for is_true/is_false */}
      {meta && !noValue && (
        meta.value_type === 'enum' ? (
          <select
            value={cond.value ?? ''}
            onChange={e => onChange({ ...cond, value: e.target.value === '' ? null : e.target.value })}
            style={inp}
          >
            <option value=''>— Select —</option>
            {(meta.options || []).map(o =>
              typeof o === 'object'
                ? <option key={o.value} value={o.value}>{o.label}</option>
                : <option key={o} value={o}>{o}</option>
            )}
          </select>
        ) : (
          <input
            type={meta.value_type === 'float' || meta.value_type === 'integer' ? 'number' : 'text'}
            step={meta.value_type === 'float' ? '0.1' : meta.value_type === 'integer' ? '1' : undefined}
            value={cond.value ?? ''}
            placeholder={meta.placeholder || 'value'}
            onChange={e => onChange({ ...cond, value: e.target.value })}
            style={inp}
          />
        )
      )}

      {/* Spacer to keep alignment when value is hidden */}
      {meta && noValue && <div style={{ flex: 1 }} />}

      {/* Remove button */}
      {showRemove ? (
        <button
          onClick={onRemove}
          title="Remove condition"
          style={{
            display: 'flex', alignItems: 'center',
            padding: compact ? '3px 5px' : '4px 6px',
            borderRadius: 5, border: '1px solid var(--border)',
            background: 'transparent', cursor: 'pointer',
          }}
        >
          <Minus size={compact ? 11 : 12} color="#ef4444" />
        </button>
      ) : (
        <div style={{ width: compact ? 24 : 26 }} />
      )}
    </div>
  )
}

// ─── Main RuleBuilder component ───────────────────────────────────────────────
export default function RuleBuilder({
  conditions = [],
  logic = 'AND',
  onChange,
  catalog: catalogProp = null,
  filterGroups = null,
  showLogic = true,
  addLabel = 'Add Condition',
  compact = false,
}) {
  const [catalog, setCatalog] = useState(catalogProp)

  useEffect(() => {
    if (!catalogProp) {
      getRuleEngineCatalog().then(setCatalog).catch(console.error)
    } else {
      setCatalog(catalogProp)
    }
  }, [catalogProp])

  if (!catalog) {
    return <div style={{ fontSize: 12, color: 'var(--text-muted)', padding: '8px 0' }}>Loading conditions…</div>
  }

  const visibleCatalog = filterGroups
    ? catalog.filter(g => filterGroups.includes(g.group))
    : catalog

  const allConditions = visibleCatalog.flatMap(g => g.conditions)

  const defaultCondition = () => {
    const first = allConditions[0]
    if (!first) return { field: '', op: 'eq', value: null }
    return { field: first.field, op: first.ops[0], value: null }
  }

  const add = () => onChange([...conditions, defaultCondition()], logic)

  const update = (i, c) => onChange(conditions.map((x, j) => j === i ? c : x), logic)

  const remove = (i) => onChange(conditions.filter((_, j) => j !== i), logic)

  const setLogic = (l) => onChange(conditions, l)

  const fsize    = compact ? 11 : 12
  const btnStyle = {
    display: 'flex', alignItems: 'center', gap: 4,
    fontSize: fsize, padding: compact ? '2px 6px' : '3px 8px',
    borderRadius: 5, cursor: 'pointer',
    border: '1px dashed var(--border)',
    background: 'transparent', color: 'var(--text-muted)',
    marginTop: conditions.length > 0 ? (compact ? 2 : 4) : 0,
  }

  return (
    <div>
      {/* AND / OR toggle — only shown when multiple conditions and showLogic is true */}
      {showLogic && conditions.length > 1 && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: compact ? 6 : 8 }}>
          <span style={{ fontSize: fsize, color: 'var(--text-muted)' }}>Match</span>
          {['AND', 'OR'].map(l => (
            <button
              key={l}
              onClick={() => setLogic(l)}
              style={{
                fontSize: fsize, padding: '2px 8px', borderRadius: 5, cursor: 'pointer',
                border: `1px solid ${logic === l ? 'var(--accent)' : 'var(--border)'}`,
                background: logic === l ? 'rgba(99,102,241,0.15)' : 'transparent',
                color: logic === l ? 'var(--accent)' : 'var(--text-muted)',
              }}
            >
              {l}
            </button>
          ))}
          <span style={{ fontSize: fsize, color: 'var(--text-muted)' }}>conditions</span>
        </div>
      )}

      {/* Condition rows */}
      {conditions.map((cond, i) => (
        <ConditionRow
          key={i}
          cond={cond}
          catalog={visibleCatalog}
          allConditions={allConditions}
          onChange={c => update(i, c)}
          onRemove={() => remove(i)}
          showRemove={conditions.length > 1}
          compact={compact}
        />
      ))}

      {/* Add Condition */}
      <button onClick={add} style={btnStyle}>
        <Plus size={compact ? 9 : 10} /> {addLabel}
      </button>
    </div>
  )
}
