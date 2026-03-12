/**
 * Shared UI primitives
 */
import { useState, useEffect, useRef, useCallback } from 'react'
import { getTags, createCampaign, createAutoTagRule } from '../api.js'

export function SeverityBadge({ severity, label }) {
  const SEV_COLORS = {
    4: { bg: '#450a0a', text: '#fca5a5', border: '#991b1b' },
    3: { bg: '#431407', text: '#fdba74', border: '#9a3412' },
    2: { bg: '#451a03', text: '#fcd34d', border: '#92400e' },
    1: { bg: '#1a2e05', text: '#86efac', border: '#166534' },
    0: { bg: '#0c1a2e', text: '#7dd3fc', border: '#0369a1' },
  }
  const c = SEV_COLORS[severity] || SEV_COLORS[0]
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      background: c.bg, color: c.text, border: `1px solid ${c.border}`,
      borderRadius: 4, padding: '2px 8px', fontSize: 11, fontWeight: 600,
      textTransform: 'uppercase', letterSpacing: '0.05em', whiteSpace: 'nowrap',
    }}>
      {label || ['Info', 'Low', 'Medium', 'High', 'Critical'][severity] || 'Info'}
    </span>
  )
}

export function ScoreBar({ score, max = 10, color }) {
  const pct = Math.min((score / max) * 100, 100)
  const c = color || (score >= 8 ? 'var(--critical)' : score >= 6 ? 'var(--high)' : score >= 4 ? 'var(--medium)' : 'var(--low)')
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ flex: 1, height: 6, background: 'var(--border)', borderRadius: 3, overflow: 'hidden' }}>
        <div style={{ width: `${pct}%`, height: '100%', background: c, borderRadius: 3, transition: 'width 0.3s' }} />
      </div>
      <span style={{ fontSize: 12, color: c, fontWeight: 600, minWidth: 28 }}>{score?.toFixed(1)}</span>
    </div>
  )
}

export function Card({ children, style = {}, onClick }) {
  return (
    <div
      onClick={onClick}
      style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)',
        borderRadius: 10, padding: 20, ...style,
        ...(onClick && { cursor: 'pointer', transition: 'border-color 0.15s' }),
      }}
      onMouseEnter={onClick ? e => e.currentTarget.style.borderColor = 'var(--accent)' : undefined}
      onMouseLeave={onClick ? e => e.currentTarget.style.borderColor = 'var(--border)' : undefined}
    >
      {children}
    </div>
  )
}

export function StatCard({ label, value, sub, color, icon: Icon, onClick }) {
  return (
    <Card style={{ display: 'flex', flexDirection: 'column', gap: 8 }} onClick={onClick}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div style={{ fontSize: 12, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{label}</div>
        {Icon && <Icon size={16} color={color || 'var(--text-muted)'} />}
      </div>
      <div style={{ fontSize: 32, fontWeight: 700, color: color || 'var(--text-primary)' }}>{value}</div>
      {sub && <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>{sub}</div>}
    </Card>
  )
}

export function Table({ columns, rows, onRowClick, onSort, sortBy, sortOrder, emptyMessage = 'No data' }) {
  return (
    <div style={{ overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
        <thead>
          <tr style={{ borderBottom: '1px solid var(--border)' }}>
            {columns.map(col => {
              const isSorted = sortBy === col.key
              const canSort = col.sortable && onSort
              return (
                <th
                  key={col.key}
                  onClick={canSort ? () => onSort(col.key) : undefined}
                  style={{
                    padding: '10px 12px', textAlign: 'left', fontWeight: 600,
                    color: isSorted ? 'var(--text-primary)' : 'var(--text-muted)',
                    fontSize: 11, textTransform: 'uppercase',
                    letterSpacing: '0.05em', whiteSpace: 'nowrap',
                    width: col.width,
                    cursor: canSort ? 'pointer' : 'default',
                    userSelect: 'none',
                  }}
                >
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                    {col.label}
                    {canSort && (
                      <span style={{ fontSize: 10, opacity: isSorted ? 1 : 0.3 }}>
                        {isSorted ? (sortOrder === 'asc' ? '▲' : '▼') : '⇅'}
                      </span>
                    )}
                  </span>
                </th>
              )
            })}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr><td colSpan={columns.length} style={{ padding: '32px 12px', textAlign: 'center', color: 'var(--text-muted)' }}>{emptyMessage}</td></tr>
          ) : rows.map((row, i) => (
            <tr
              key={i}
              onClick={() => onRowClick && onRowClick(row)}
              style={{
                borderBottom: '1px solid var(--border)',
                cursor: onRowClick ? 'pointer' : 'default',
                transition: 'background 0.1s',
              }}
              onMouseEnter={e => onRowClick && (e.currentTarget.style.background = 'var(--bg-hover)')}
              onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
            >
              {columns.map(col => (
                <td key={col.key} style={{ padding: '10px 12px', color: 'var(--text-primary)', verticalAlign: 'middle' }}>
                  {col.render ? col.render(row[col.key], row) : row[col.key]}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function FilterBar({ children }) {
  return (
    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 16 }}>
      {children}
    </div>
  )
}

export function Select({ value, onChange, options, placeholder }) {
  return (
    <select
      value={value || ''}
      onChange={e => onChange(e.target.value || null)}
      style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)',
        color: value ? 'var(--text-primary)' : 'var(--text-muted)',
        borderRadius: 6, padding: '7px 12px', fontSize: 13, cursor: 'pointer',
        outline: 'none',
      }}
    >
      {placeholder && <option value="">{placeholder}</option>}
      {options.map(o => (
        <option key={o.value} value={o.value}>{o.label}</option>
      ))}
    </select>
  )
}

export function Input({ value, onChange, placeholder, style = {} }) {
  return (
    <input
      value={value}
      onChange={e => onChange(e.target.value)}
      placeholder={placeholder}
      style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)',
        color: 'var(--text-primary)', borderRadius: 6, padding: '7px 12px',
        fontSize: 13, outline: 'none', ...style
      }}
    />
  )
}

export function Button({ children, onClick, variant = 'primary', size = 'md', disabled, style = {} }) {
  const base = {
    display: 'inline-flex', alignItems: 'center', gap: 6,
    border: 'none', borderRadius: 6, cursor: disabled ? 'not-allowed' : 'pointer',
    fontWeight: 600, transition: 'all 0.15s', fontSize: size === 'sm' ? 12 : 13,
    padding: size === 'sm' ? '5px 10px' : '8px 16px',
    opacity: disabled ? 0.5 : 1, ...style
  }
  const variants = {
    primary: { background: 'var(--accent)', color: 'var(--primary-foreground)' },
    danger: { background: 'var(--danger)', color: '#fff' },
    ghost: { background: 'transparent', color: 'var(--text-secondary)', border: '1px solid var(--border)' },
    success: { background: 'var(--success)', color: '#fff' },
    warning: { background: 'var(--warning)', color: '#fff' },
  }
  return (
    <button onClick={disabled ? undefined : onClick} style={{ ...base, ...variants[variant] }}>
      {children}
    </button>
  )
}

export function Pill({ label, color = 'var(--text-muted)' }) {
  return (
    <span style={{
      display: 'inline-block', padding: '2px 8px', borderRadius: 999,
      background: `${color}22`, color, border: `1px solid ${color}44`,
      fontSize: 11, fontWeight: 600,
    }}>{label}</span>
  )
}

export function PageHeader({ title, subtitle, action }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 24 }}>
      <div>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary)' }}>{title}</h1>
        {subtitle && <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 4 }}>{subtitle}</div>}
      </div>
      {action}
    </div>
  )
}

export function EmptyState({ icon: Icon, title, sub, children }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '64px 24px', gap: 12 }}>
      {Icon && <Icon size={40} color="var(--text-muted)" />}
      <div style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-secondary)' }}>{title}</div>
      {sub && <div style={{ fontSize: 13, color: 'var(--text-muted)', textAlign: 'center', maxWidth: 320 }}>{sub}</div>}
      {children}
    </div>
  )
}

export function EffortBadge({ effort }) {
  const MAP = {
    quick_win: { label: 'Quick Win', color: 'var(--success)' },
    medium: { label: 'Medium', color: 'var(--warning)' },
    complex: { label: 'Complex', color: 'var(--danger)' },
  }
  const c = MAP[effort] || { label: effort || '—', color: 'var(--text-muted)' }
  return <Pill label={c.label} color={c.color} />
}

export function OwnerBadge({ owner }) {
  const MAP = {
    IT: '#0ea5e9',
    DevOps: '#8b5cf6',
    SecOps: '#dc2626',
    AppSec: '#f59e0b',
    DBA: '#06b6d4',
  }
  return <Pill label={owner || '—'} color={MAP[owner] || 'var(--text-muted)'} />
}

const SOURCE_LABELS = {
  manual_finding: 'Manual',
  manual_asset: 'Asset',
  inferred_service: 'Auto',
  inferred_user: 'Auto',
  plugin_family: 'Default',
}
const SOURCE_COLORS = {
  manual_finding: '#22c55e',
  manual_asset: '#22c55e',
  inferred_service: '#60a5fa',
  inferred_user: '#60a5fa',
  plugin_family: 'var(--text-muted)',
}

export function ResolvedOwnerBadge({ resolved }) {
  if (!resolved) return <OwnerBadge owner={null} />
  const role = resolved.owner_role || '—'
  const name = resolved.owner_name
  const src = SOURCE_LABELS[resolved.source] || 'Default'
  const srcColor = SOURCE_COLORS[resolved.source] || 'var(--text-muted)'
  const MAP = { IT: '#0ea5e9', DevOps: '#8b5cf6', SecOps: '#dc2626', AppSec: '#f59e0b', DBA: '#06b6d4' }
  const roleColor = MAP[role] || 'var(--text-muted)'

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
        <Pill label={role} color={roleColor} />
        <span style={{ fontSize: 9, color: srcColor, fontWeight: 600, textTransform: 'uppercase' }}>{src}</span>
      </div>
      {name && name !== role && (
        <span style={{ fontSize: 11, color: 'var(--text-secondary)', maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
              title={name}>
          {name}
        </span>
      )}
    </div>
  )
}

const ROLE_OPTIONS = ['', 'IT', 'DevOps', 'SecOps', 'AppSec', 'DBA', 'Networking', 'CloudOps']

export function OwnershipEditPopover({ current, onSave, onClose }) {
  const [form, setForm] = useState({
    owner_name:  current?.owner_name  || '',
    owner_email: current?.owner_email || '',
    owner_role:  current?.owner_role  || '',
    team:        current?.team        || '',
    notes:       current?.notes       || '',
  })
  const [saving, setSaving] = useState(false)
  const ref = useRef(null)

  useEffect(() => {
    const handler = (e) => { if (ref.current && !ref.current.contains(e.target)) onClose() }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [onClose])

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }))

  const handleSave = async () => {
    setSaving(true)
    try { await onSave(form) } finally { setSaving(false) }
  }

  const fieldStyle = {
    background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 6,
    color: 'var(--text-primary)', fontSize: 12, padding: '5px 8px', width: '100%', outline: 'none',
  }

  return (
    <div ref={ref} onClick={e => e.stopPropagation()} style={{
      position: 'absolute', zIndex: 1000, background: 'var(--bg-card)',
      border: '1px solid var(--border)', borderRadius: 10, boxShadow: '0 8px 24px rgba(0,0,0,0.4)',
      padding: 14, width: 260, display: 'flex', flexDirection: 'column', gap: 8,
    }}>
      <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 2 }}>Edit Ownership</div>
      {[
        { key: 'owner_name',  label: 'Name' },
        { key: 'owner_email', label: 'Email' },
        { key: 'team',        label: 'Team' },
        { key: 'notes',       label: 'Notes' },
      ].map(({ key, label }) => (
        <div key={key}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 3 }}>{label}</div>
          <input value={form[key]} onChange={e => set(key, e.target.value)} style={fieldStyle} placeholder={label} />
        </div>
      ))}
      <div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 3 }}>Role</div>
        <select value={form.owner_role} onChange={e => set('owner_role', e.target.value)} style={fieldStyle}>
          {ROLE_OPTIONS.map(r => <option key={r} value={r}>{r || '— none —'}</option>)}
        </select>
      </div>
      <div style={{ display: 'flex', gap: 6, marginTop: 4 }}>
        <button onClick={handleSave} disabled={saving} style={{
          flex: 1, background: 'var(--accent)', color: '#fff', border: 'none', borderRadius: 6,
          fontSize: 12, fontWeight: 600, padding: '6px 0', cursor: 'pointer',
        }}>
          {saving ? 'Saving…' : 'Save'}
        </button>
        <button onClick={onClose} style={{
          flex: 1, background: 'var(--bg-hover)', color: 'var(--text-secondary)', border: '1px solid var(--border)',
          borderRadius: 6, fontSize: 12, padding: '6px 0', cursor: 'pointer',
        }}>
          Cancel
        </button>
      </div>
    </div>
  )
}

export function ConfidenceDot({ confidence }) {
  const colors = { high: '#22c55e', medium: '#f59e0b', low: '#6b7280' }
  const c = colors[confidence] || colors.low
  return (
    <span title={`${confidence} confidence`} style={{
      display: 'inline-block', width: 8, height: 8, borderRadius: '50%',
      background: c, flexShrink: 0,
    }} />
  )
}

export function Spinner() {
  return (
    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', padding: 48 }}>
      <div style={{
        width: 32, height: 32, border: '3px solid var(--border)',
        borderTop: '3px solid var(--accent)', borderRadius: '50%',
        animation: 'spin 0.8s linear infinite',
      }} />
      <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
    </div>
  )
}

// ─────────────────────────────────────────────────────────
// Tag primitives
// ─────────────────────────────────────────────────────────

/**
 * TagPill – displays a single tag with its color dot.
 * onRemove: optional callback — renders an × button when provided.
 */
export function TagPill({ tag, onRemove, size = 'sm' }) {
  const color = tag.color || '#6366f1'
  const pad = size === 'xs' ? '1px 6px' : '2px 8px'
  const fs = size === 'xs' ? 10 : 11
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      background: `${color}18`, color, border: `1px solid ${color}44`,
      borderRadius: 999, padding: pad, fontSize: fs, fontWeight: 600,
      whiteSpace: 'nowrap', lineHeight: 1.4,
    }}>
      <span style={{
        width: size === 'xs' ? 5 : 6, height: size === 'xs' ? 5 : 6,
        borderRadius: '50%', background: color, flexShrink: 0,
      }} />
      {tag.label || `${tag.category}:${tag.value}`}
      {onRemove && (
        <button
          onClick={e => { e.stopPropagation(); onRemove(tag) }}
          style={{
            background: 'none', border: 'none', cursor: 'pointer',
            color, padding: 0, lineHeight: 1, fontSize: fs + 1, opacity: 0.7,
          }}
          title="Remove tag"
        >×</button>
      )}
    </span>
  )
}

/**
 * TagPicker – typeahead input for selecting/assigning tags.
 * Props:
 *   selectedTags: [{tag_id, label, category, value, color}]
 *   onChange(tags): called with updated selection
 *   placeholder: string
 *   multi: boolean (default true)
 */
export function TagPicker({ selectedTags = [], onChange, placeholder = 'Add tag…', multi = true }) {
  const [query, setQuery] = useState('')
  const [allTags, setAllTags] = useState([])
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

  useEffect(() => {
    getTags().then(setAllTags).catch(() => {})
  }, [])

  useEffect(() => {
    const handler = e => { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const selectedIds = new Set(selectedTags.map(t => t.tag_id))

  const filtered = allTags.filter(t => {
    if (selectedIds.has(t.id)) return false
    const q = query.toLowerCase()
    return !q || t.label.toLowerCase().includes(q) || t.category.toLowerCase().includes(q) || t.value.toLowerCase().includes(q)
  })

  // Group by category
  const grouped = {}
  for (const t of filtered) {
    if (!grouped[t.category]) grouped[t.category] = []
    grouped[t.category].push(t)
  }

  const select = (tag) => {
    const entry = { tag_id: tag.id, label: tag.label, category: tag.category, value: tag.value, color: tag.color }
    onChange(multi ? [...selectedTags, entry] : [entry])
    setQuery('')
    if (!multi) setOpen(false)
  }

  const remove = (tag) => onChange(selectedTags.filter(t => t.tag_id !== tag.tag_id))

  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <div
        style={{
          display: 'flex', flexWrap: 'wrap', gap: 4, alignItems: 'center',
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: 6, padding: '5px 8px', minHeight: 36, cursor: 'text',
        }}
        onClick={() => setOpen(true)}
      >
        {selectedTags.map(t => (
          <TagPill key={t.tag_id} tag={t} onRemove={remove} />
        ))}
        <input
          value={query}
          onChange={e => { setQuery(e.target.value); setOpen(true) }}
          onFocus={() => setOpen(true)}
          placeholder={selectedTags.length === 0 ? placeholder : ''}
          style={{
            flex: 1, minWidth: 80, border: 'none', background: 'transparent',
            outline: 'none', fontSize: 13, color: 'var(--text-primary)',
          }}
        />
      </div>
      {open && (
        <div style={{
          position: 'absolute', top: '100%', left: 0, right: 0, zIndex: 200,
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: 6, marginTop: 2, maxHeight: 280, overflowY: 'auto',
          boxShadow: '0 4px 16px rgba(0,0,0,0.18)',
        }}>
          {Object.keys(grouped).length === 0 ? (
            <div style={{ padding: '10px 14px', fontSize: 12, color: 'var(--text-muted)' }}>
              {allTags.length === 0 ? 'No tags defined yet' : 'No matching tags'}
            </div>
          ) : Object.entries(grouped).map(([cat, tags]) => (
            <div key={cat}>
              <div style={{
                padding: '6px 12px 2px', fontSize: 10, fontWeight: 700,
                color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em',
              }}>{cat}</div>
              {tags.map(t => (
                <div
                  key={t.id}
                  onClick={() => select(t)}
                  style={{
                    padding: '6px 12px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8,
                    fontSize: 13, color: 'var(--text-primary)',
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-hover)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <span style={{ width: 8, height: 8, borderRadius: '50%', background: t.color || '#6366f1', flexShrink: 0 }} />
                  {t.label}
                  {t.description && (
                    <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text-muted)', maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {t.description}
                    </span>
                  )}
                </div>
              ))}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

/**
 * ColumnSelector – dropdown menu to toggle column visibility.
 * Props:
 *   columns: [{key, label, defaultVisible?}] – all available columns
 *   visible: {key: bool} – current visibility state
 *   onChange(visible) – called with updated visibility map
 *   storageKey: string – localStorage key for persistence
 */
export function ColumnSelector({ columns, visible, onChange }) {
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

  useEffect(() => {
    const handler = e => { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const toggle = (key) => {
    const next = { ...visible, [key]: !visible[key] }
    onChange(next)
  }

  const toggleable = columns.filter(c => c.key !== '_select')

  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <button
        onClick={() => setOpen(!open)}
        style={{
          display: 'inline-flex', alignItems: 'center', gap: 5,
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: 6, padding: '6px 10px', fontSize: 12,
          color: 'var(--text-secondary)', cursor: 'pointer', fontWeight: 600,
          whiteSpace: 'nowrap',
        }}
        title="Show/Hide columns"
      >
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/>
          <rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/>
        </svg>
        Columns
      </button>
      {open && (
        <div style={{
          position: 'absolute', top: '100%', right: 0, zIndex: 200, minWidth: 200,
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: 8, marginTop: 4, maxHeight: 360, overflowY: 'auto',
          boxShadow: '0 4px 16px rgba(0,0,0,0.18)', padding: '6px 0',
        }}>
          {toggleable.map(col => (
            <label
              key={col.key}
              style={{
                display: 'flex', alignItems: 'center', gap: 8,
                padding: '6px 14px', cursor: 'pointer', fontSize: 13,
                color: 'var(--text-primary)',
              }}
              onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-hover)'}
              onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
            >
              <input
                type="checkbox"
                checked={visible[col.key] !== false}
                onChange={() => toggle(col.key)}
                style={{ accentColor: 'var(--accent)' }}
              />
              {typeof col.label === 'string' ? col.label : col.key}
            </label>
          ))}
        </div>
      )}
    </div>
  )
}


/**
 * TagFilterBar – compact multi-tag filter with AND/OR toggle.
 * Props: tags (array of tag objects with label/color), onChange, logic ('AND'|'OR'), onLogicChange
 */
export function TagFilterBar({ tags = [], onChange, logic = 'AND', onLogicChange }) {
  const [allTags, setAllTags] = useState([])
  const [query, setQuery] = useState('')
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

  useEffect(() => {
    getTags().then(setAllTags).catch(() => {})
  }, [])

  useEffect(() => {
    const handler = e => { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const selectedIds = new Set(tags.map(t => t.id || t.tag_id))
  const filtered = allTags.filter(t => {
    if (selectedIds.has(t.id)) return false
    const q = query.toLowerCase()
    return !q || t.label.toLowerCase().includes(q)
  })

  const add = (tag) => { onChange([...tags, tag]); setQuery(''); setOpen(false) }
  const remove = (tag) => onChange(tags.filter(t => (t.id || t.tag_id) !== (tag.id || tag.tag_id)))

  return (
    <div ref={ref} style={{ position: 'relative', display: 'flex', alignItems: 'center', gap: 4, flexWrap: 'wrap' }}>
      {tags.map((t, i) => (
        <span key={t.id || t.tag_id} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          {i > 0 && (
            <button
              onClick={() => onLogicChange && onLogicChange(logic === 'AND' ? 'OR' : 'AND')}
              style={{
                background: 'var(--bg-hover)', border: '1px solid var(--border)',
                borderRadius: 4, padding: '1px 6px', fontSize: 10, cursor: 'pointer',
                color: 'var(--text-muted)', fontWeight: 700,
              }}
              title="Click to toggle AND/OR"
            >{logic}</button>
          )}
          <TagPill tag={t} onRemove={() => remove(t)} size="sm" />
        </span>
      ))}
      <div style={{ position: 'relative' }}>
        <input
          value={query}
          onChange={e => { setQuery(e.target.value); setOpen(true) }}
          onFocus={() => setOpen(true)}
          placeholder={tags.length === 0 ? 'Filter by tag…' : '+tag'}
          style={{
            background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: 6, padding: '7px 12px', fontSize: 13,
            color: tags.length === 0 && !query ? 'var(--text-muted)' : 'var(--text-primary)',
            outline: 'none', width: tags.length === 0 ? 140 : 80, cursor: 'pointer',
          }}
        />
        {open && filtered.length > 0 && (
          <div style={{
            position: 'absolute', top: '100%', left: 0, zIndex: 200, minWidth: 200,
            background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: 6, marginTop: 2, maxHeight: 240, overflowY: 'auto',
            boxShadow: '0 4px 16px rgba(0,0,0,0.18)',
          }}>
            {filtered.map(t => (
              <div
                key={t.id}
                onClick={() => add(t)}
                style={{ padding: '7px 12px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}
                onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-hover)'}
                onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
              >
                <span style={{ width: 7, height: 7, borderRadius: '50%', background: t.color || '#6366f1' }} />
                {t.label}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}


/**
 * Export / Import buttons for config portability.
 *
 * Props:
 *   configType   — "risk_config" | "auto_tag_rules" | "report_template" | "campaign_workflow"
 *   exportFn     — async () => envelope JSON (if custom, e.g. with params). Falls back to exportConfig(configType).
 *   importFn     — async (file, conflict) => result. Falls back to importConfig(configType, file, conflict).
 *   onImported   — callback after successful import (e.g. to refresh data)
 *   label        — optional button label prefix (default: "Config")
 *   showConflict — show skip/overwrite dropdown (default: true)
 *   style        — wrapper style
 */
export function ExportImportButtons({
  configType, exportFn, importFn, onImported, label = 'Config',
  showConflict = true, style = {},
}) {
  const fileRef = useRef(null)
  const [conflict, setConflict] = useState('skip')
  const [status, setStatus] = useState(null) // {type: 'ok'|'error', msg: string}

  const handleExport = useCallback(async () => {
    try {
      setStatus(null)
      const data = exportFn ? await exportFn() : await (await import('../api.js')).exportConfig(configType)
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${configType}-${new Date().toISOString().slice(0, 10)}.json`
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
      setStatus({ type: 'ok', msg: 'Exported' })
      setTimeout(() => setStatus(null), 2000)
    } catch (e) {
      setStatus({ type: 'error', msg: e.message || 'Export failed' })
    }
  }, [exportFn, configType])

  const handleImport = useCallback(async (e) => {
    const file = e.target.files?.[0]
    if (!file) return
    try {
      setStatus(null)
      const result = importFn
        ? await importFn(file, conflict)
        : await (await import('../api.js')).importConfig(configType, file, conflict)
      const msg = result.message || `Imported${result.imported != null ? ` ${result.imported}` : ''}`
      setStatus({ type: 'ok', msg })
      onImported?.()
      setTimeout(() => setStatus(null), 3000)
    } catch (err) {
      setStatus({ type: 'error', msg: err.message || 'Import failed' })
    }
    // Reset file input so same file can be re-selected
    e.target.value = ''
  }, [importFn, configType, conflict, onImported])

  const btnStyle = {
    display: 'inline-flex', alignItems: 'center', gap: 5,
    padding: '5px 12px', borderRadius: 6, fontSize: 12, fontWeight: 600,
    cursor: 'pointer', border: '1px solid var(--border)',
    background: 'transparent', color: 'var(--text)',
  }

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', ...style }}>
      {exportFn !== null && (
        <button onClick={handleExport} style={btnStyle} title={`Export ${label}`}>
          <span style={{ fontSize: 13 }}>{'\u2B07'}</span> Export
        </button>
      )}
      <button onClick={() => fileRef.current?.click()} style={btnStyle} title={`Import ${label}`}>
        <span style={{ fontSize: 13 }}>{'\u2B06'}</span> Import
      </button>
      <input
        ref={fileRef} type="file" accept=".json"
        style={{ display: 'none' }}
        onChange={handleImport}
      />
      {showConflict && (
        <select
          value={conflict} onChange={e => setConflict(e.target.value)}
          style={{
            padding: '4px 8px', borderRadius: 6, fontSize: 11, border: '1px solid var(--border)',
            background: 'var(--bg-secondary)', color: 'var(--text)',
          }}
          title="Conflict resolution on import"
        >
          <option value="skip">Skip duplicates</option>
          <option value="overwrite">Overwrite</option>
        </select>
      )}
      {status && (
        <span style={{
          fontSize: 11, fontWeight: 600,
          color: status.type === 'ok' ? 'var(--success)' : 'var(--danger)',
        }}>
          {status.msg}
        </span>
      )}
    </div>
  )
}

// ─── Save as Campaign / Auto-tag Rule modal ───────────────────────────────────
// Converts a filter conditions array (from filtersToConditions) into a Campaign
// or Auto-tag Rule. Caller is responsible for navigation after creation.
export function SaveAsRuleModal({ conditions = [], scanId, onClose, onCreated }) {
  const [tab, setTab] = useState('campaign')
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(null)
  const [success, setSuccess] = useState(null)

  // Auto-tag specific
  const [selectedTag, setSelectedTag] = useState([])
  const [targetType, setTargetType] = useState('asset')

  const hasConditions = conditions.length > 0

  const handleCreateCampaign = async () => {
    if (!name.trim()) { setError('Name is required'); return }
    if (!hasConditions) { setError('No mappable filters — add at least one supported filter first'); return }
    setSaving(true); setError(null)
    try {
      const result = await createCampaign({
        name: name.trim(),
        description: description.trim() || null,
        scan_id: scanId || null,
        query: conditions,
        query_logic: 'AND',
        status: 'planned',
      })
      onCreated('campaign', result)
    } catch (e) {
      setError(e.message || 'Failed to create campaign')
    } finally {
      setSaving(false)
    }
  }

  const handleCreateRule = async () => {
    if (!name.trim()) { setError('Name is required'); return }
    if (!selectedTag.length) { setError('Select a tag to apply'); return }
    if (!hasConditions) { setError('No mappable filters — add at least one supported filter first'); return }
    setSaving(true); setError(null)
    try {
      const tagId = selectedTag[0]?.tag_id || selectedTag[0]?.id
      await createAutoTagRule({
        name: name.trim(),
        tag_id: Number(tagId),
        target_type: targetType,
        conditions,
        condition_logic: 'AND',
        is_enabled: true,
      })
      setSuccess('Rule created!')
      setTimeout(() => { onClose(); onCreated('autotag', null) }, 1500)
    } catch (e) {
      setError(e.message || 'Failed to create rule')
    } finally {
      setSaving(false)
    }
  }

  const tabStyle = (active) => ({
    flex: 1, padding: '8px 0', fontSize: 13, fontWeight: active ? 600 : 400,
    color: active ? 'var(--accent)' : 'var(--text-muted)',
    background: 'none', border: 'none', borderBottom: `2px solid ${active ? 'var(--accent)' : 'transparent'}`,
    cursor: 'pointer', marginBottom: -1,
  })

  const inp = {
    width: '100%', background: 'var(--bg)', border: '1px solid var(--border)',
    color: 'var(--text-primary)', borderRadius: 6, padding: '7px 10px',
    fontSize: 13, outline: 'none', boxSizing: 'border-box',
  }
  const lbl = { fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 1000,
      background: 'rgba(0,0,0,0.55)', display: 'flex', alignItems: 'center', justifyContent: 'center',
    }} onClick={e => { if (e.target === e.currentTarget) onClose() }}>
      <div style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 12,
        padding: 24, width: 460, maxWidth: '95vw', display: 'flex', flexDirection: 'column', gap: 16,
      }}>
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)' }}>Save as…</span>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', display: 'flex' }}>
            ✕
          </button>
        </div>

        {/* Conditions preview */}
        <div style={{
          fontSize: 12, color: 'var(--text-muted)', background: 'var(--bg-secondary)',
          borderRadius: 6, padding: '8px 12px', border: '1px solid var(--border)',
        }}>
          {hasConditions
            ? <><span style={{ color: 'var(--accent)', fontWeight: 600 }}>{conditions.length}</span> condition{conditions.length !== 1 ? 's' : ''} from your current filters will define the scope</>
            : <span style={{ color: 'var(--danger)' }}>No mappable filters active — set severity, family, hostname, etc. first</span>
          }
        </div>

        {/* Tab bar */}
        <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', marginBottom: -8 }}>
          <button style={tabStyle(tab === 'campaign')} onClick={() => { setTab('campaign'); setError(null) }}>Campaign</button>
          <button style={tabStyle(tab === 'autotag')} onClick={() => { setTab('autotag'); setError(null) }}>Auto-tag Rule</button>
        </div>

        {/* Campaign form */}
        {tab === 'campaign' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div>
              <label style={lbl}>Campaign name *</label>
              <input value={name} onChange={e => setName(e.target.value)} placeholder="e.g. Critical Windows — Q1 2026" style={inp} autoFocus />
            </div>
            <div>
              <label style={lbl}>Description</label>
              <textarea value={description} onChange={e => setDescription(e.target.value)} placeholder="Optional description" rows={2}
                style={{ ...inp, resize: 'vertical', fontFamily: 'inherit' }} />
            </div>
          </div>
        )}

        {/* Auto-tag rule form */}
        {tab === 'autotag' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div>
              <label style={lbl}>Rule name *</label>
              <input value={name} onChange={e => setName(e.target.value)} placeholder="e.g. Tag critical findings" style={inp} autoFocus />
            </div>
            <div>
              <label style={lbl}>Apply tag *</label>
              <TagPicker selectedTags={selectedTag} onChange={setSelectedTag} placeholder="Search tags…" multi={false} />
            </div>
            <div>
              <label style={lbl}>Applies to</label>
              <select value={targetType} onChange={e => setTargetType(e.target.value)} style={inp}>
                <option value="asset">Assets only</option>
                <option value="finding">Findings only</option>
                <option value="both">Assets + Findings</option>
              </select>
            </div>
          </div>
        )}

        {/* Error / success */}
        {error && <div style={{ fontSize: 12, color: 'var(--danger)', background: 'var(--danger-subtle)', borderRadius: 6, padding: '6px 10px' }}>{error}</div>}
        {success && <div style={{ fontSize: 12, color: 'var(--success)', background: 'var(--success-subtle)', borderRadius: 6, padding: '6px 10px' }}>✓ {success}</div>}

        {/* Footer */}
        {!success && (
          <div style={{ display: 'flex', gap: 8, paddingTop: 4 }}>
            <Button
              onClick={tab === 'campaign' ? handleCreateCampaign : handleCreateRule}
              disabled={saving || !hasConditions}
              style={{ flex: 1 }}
            >
              {saving ? 'Creating…' : tab === 'campaign' ? 'Create Campaign' : 'Create Rule'}
            </Button>
            <Button variant="ghost" onClick={onClose}>Cancel</Button>
          </div>
        )}
      </div>
    </div>
  )
}
