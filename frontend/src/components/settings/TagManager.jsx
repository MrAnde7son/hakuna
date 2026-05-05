import React, { useState, useEffect, useCallback } from 'react'
import { Tag, Plus, ChevronRight, ChevronLeft, ChevronDown, Trash2, Edit2, Play, ToggleLeft, ToggleRight, X, Save, Zap, Settings2, ExternalLink, Monitor, AlertTriangle, Search } from 'lucide-react'
import {
  getTags, createTag, updateTag, deleteTag,
  getAutoTagRules, createAutoTagRule, updateAutoTagRule, deleteAutoTagRule,
  runAutoTagRule, runAllAutoTagRules, exportConfig, getAssets, getFindings,
} from '../../api.js'
import { Card, PageHeader, Button, Input, Select, Spinner, EmptyState, ExportImportButtons, useToast, useConfirm } from '../shared/ui.jsx'
import { useNavigate } from 'react-router-dom'
import RuleBuilder from '../campaigns/RuleBuilder.jsx'
import TagMappings from './TagMappings.jsx'
import { getAssetDisplayName, getFindingAssetDisplay } from '../../utils/assetDisplay.js'
import { capture } from '../../utils/analytics.js'

const PALETTE = [
  '#6366f1', '#8b5cf6', '#ec4899', '#ef4444', '#f97316',
  '#eab308', '#22c55e', '#14b8a6', '#06b6d4', '#3b82f6',
]

const TAGS_PER_PAGE = 20

// Recursively filter tree nodes that match search/category
function filterTree(nodes, search, category) {
  if (!search && !category) return nodes
  const lowerSearch = search?.toLowerCase() || ''
  return nodes.reduce((acc, node) => {
    const label = `${node.category}:${node.value}`.toLowerCase()
    const matchesSelf = (!search || label.includes(lowerSearch) || (node.description || '').toLowerCase().includes(lowerSearch))
      && (!category || node.category === category)
    const filteredChildren = node.children ? filterTree(node.children, search, category) : []
    if (matchesSelf || filteredChildren.length > 0) {
      acc.push({ ...node, children: matchesSelf ? (node.children || []) : filteredChildren })
    }
    return acc
  }, [])
}

// Count all visible nodes in a filtered tree
function countTreeNodes(nodes) {
  return nodes.reduce((sum, n) => sum + 1 + (n.children ? countTreeNodes(n.children) : 0), 0)
}

// ─── Tag tree node ─────────────────────────────────────────
function TagNode({ node, depth = 0, selected, onSelect, onDelete, onEdit }) {
  const [expanded, setExpanded] = useState(depth < 1)
  const hasChildren = node.children && node.children.length > 0
  const isSelected = selected?.id === node.id
  const color = node.color || '#6366f1'

  return (
    <div>
      <div
        onClick={() => onSelect(node)}
        style={{
          display: 'flex', alignItems: 'center', gap: 6,
          padding: `5px 8px 5px ${8 + depth * 16}px`,
          borderRadius: 6, cursor: 'pointer', userSelect: 'none',
          background: isSelected ? `${color}18` : 'transparent',
          border: isSelected ? `1px solid ${color}44` : '1px solid transparent',
          marginBottom: 2,
        }}
        onMouseEnter={e => { if (!isSelected) e.currentTarget.style.background = 'var(--bg-hover)' }}
        onMouseLeave={e => { if (!isSelected) e.currentTarget.style.background = 'transparent' }}
      >
        {hasChildren ? (
          <button
            onClick={e => { e.stopPropagation(); setExpanded(p => !p) }}
            style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, color: 'var(--text-muted)', display: 'flex' }}
          >
            {expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
          </button>
        ) : (
          <span style={{ width: 12 }} />
        )}
        <span style={{ width: 8, height: 8, borderRadius: '50%', background: color, flexShrink: 0 }} />
        <span style={{ fontSize: 12, color: 'var(--text-secondary)', fontWeight: 500, flex: 1 }}>
          <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>{node.category}:</span>
          {node.value}
        </span>
        <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
          {(node.asset_count || 0) + (node.finding_count || 0) > 0
            ? `${node.asset_count || 0}A · ${node.finding_count || 0}F`
            : ''}
        </span>
        <button
          onClick={e => { e.stopPropagation(); onEdit(node) }}
          style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 2, opacity: 0.7 }}
          title="Edit"
        ><Edit2 size={11} /></button>
        <button
          onClick={e => { e.stopPropagation(); onDelete(node) }}
          style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--danger)', padding: 2, opacity: 0.7 }}
          title="Delete"
        ><Trash2 size={11} /></button>
      </div>
      {expanded && hasChildren && (
        <div>
          {node.children.map(child => (
            <TagNode
              key={child.id} node={child} depth={depth + 1}
              selected={selected} onSelect={onSelect} onDelete={onDelete} onEdit={onEdit}
            />
          ))}
        </div>
      )}
    </div>
  )
}

// ─── Tag form ──────────────────────────────────────────────
function TagForm({ tag, allTags, onSave, onCancel }) {
  const [category, setCategory] = useState(tag?.category || '')
  const [value, setValue] = useState(tag?.value || '')
  const [parentId, setParentId] = useState(tag?.parent_id || '')
  const [color, setColor] = useState(tag?.color || '#6366f1')
  const [description, setDescription] = useState(tag?.description || '')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(null)
  const toast = useToast()

  const isEdit = !!tag
  const categories = [...new Set(allTags.map(t => t.category))].sort()
  const validParents = allTags.filter(t => t.id !== tag?.id)

  const submit = async () => {
    if (!category.trim() || !value.trim()) { setError('Category and value are required'); return }
    setSaving(true); setError(null)
    try {
      const payload = {
        category: category.trim().toLowerCase().replace(/\s+/g, '-'),
        value: value.trim().toLowerCase().replace(/\s+/g, '-'),
        parent_id: parentId || null,
        color,
        description: description.trim() || null,
      }
      if (isEdit) {
        await updateTag(tag.id, payload)
        toast.success('Tag updated')
      } else {
        await createTag(payload)
        capture('tag_created', { category: payload.category, has_parent: !!payload.parent_id })
        toast.success('Tag created')
      }
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
          {isEdit ? 'Edit Tag' : 'New Tag'}
        </span>
        <button onClick={onCancel} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', display: 'flex' }}>
          <X size={14} />
        </button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
        <div>
          <label style={labelStyle}>Category</label>
          <input value={category} onChange={e => setCategory(e.target.value)} onKeyDown={e => e.key === 'Enter' && submit()} list="tag-categories" placeholder="e.g. network" style={inputStyle} />
          <datalist id="tag-categories">{categories.map(c => <option key={c} value={c} />)}</datalist>
        </div>
        <div>
          <label style={labelStyle}>Value</label>
          <input value={value} onChange={e => setValue(e.target.value)} onKeyDown={e => e.key === 'Enter' && submit()} placeholder="e.g. dmz" style={inputStyle} />
        </div>
      </div>

      <div>
        <label style={labelStyle}>Parent tag (optional)</label>
        <select value={parentId || ''} onChange={e => setParentId(e.target.value || '')} style={inputStyle}>
          <option value="">— None (root tag) —</option>
          {validParents.map(t => <option key={t.id} value={t.id}>{t.label}</option>)}
        </select>
      </div>

      <div>
        <label style={labelStyle}>Color</label>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
          {PALETTE.map(c => (
            <button key={c} onClick={() => setColor(c)} style={{
              width: 20, height: 20, borderRadius: '50%', background: c, border: 'none', cursor: 'pointer',
              outline: color === c ? `2px solid ${c}` : 'none', outlineOffset: 2,
            }} />
          ))}
          <input type="color" value={color} onChange={e => setColor(e.target.value)}
            style={{ width: 24, height: 24, border: 'none', borderRadius: 4, cursor: 'pointer', padding: 0 }} />
        </div>
      </div>

      <div>
        <label style={labelStyle}>Description</label>
        <input value={description} onChange={e => setDescription(e.target.value)} onKeyDown={e => e.key === 'Enter' && submit()} placeholder="Optional description" style={inputStyle} />
      </div>

      {(category || value) && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Preview:</span>
          <span style={{
            display: 'inline-flex', alignItems: 'center', gap: 4,
            background: `${color}18`, color, border: `1px solid ${color}44`,
            borderRadius: 999, padding: '2px 8px', fontSize: 11, fontWeight: 600,
          }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: color }} />
            {(category || 'category').toLowerCase()}:{(value || 'value').toLowerCase()}
          </span>
        </div>
      )}

      {error && <div style={{ fontSize: 12, color: 'var(--danger)', background: 'var(--danger-subtle)', borderRadius: 6, padding: '6px 10px' }}>{error}</div>}

      <div style={{ display: 'flex', gap: 8, paddingTop: 4 }}>
        <Button onClick={submit} disabled={saving} style={{ flex: 1 }}>
          <Save size={13} /> {saving ? 'Saving…' : isEdit ? 'Update Tag' : 'Create Tag'}
        </Button>
        <Button variant="ghost" onClick={onCancel}>Cancel</Button>
      </div>
    </div>
  )
}

// ─── Auto-tag rule form ────────────────────────────────────
function AutoTagRuleForm({ rule, allTags, onSave, onCancel }) {
  const [name, setName] = useState(rule?.name || '')
  const [description, setDescription] = useState(rule?.description || '')
  const [tagId, setTagId] = useState(rule?.tag_id || '')
  const [targetType, setTargetType] = useState(rule?.target_type || 'asset')
  const [logic, setLogic] = useState(rule?.condition_logic || 'AND')
  const [conditions, setConditions] = useState(rule?.conditions || [])
  const [enabled, setEnabled] = useState(rule?.is_enabled !== false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(null)
  const toast = useToast()

  const submit = async () => {
    if (!name.trim()) { setError('Name is required'); return }
    if (!tagId) { setError('Select a tag to apply'); return }
    if (conditions.length === 0) { setError('Add at least one condition'); return }
    const validConditions = conditions.filter(c => c.field)
    if (validConditions.length === 0) { setError('All conditions need a field selected'); return }
    setSaving(true); setError(null)
    try {
      const payload = {
        name, description, tag_id: Number(tagId), target_type: targetType,
        conditions: validConditions, condition_logic: logic, is_enabled: enabled,
      }
      if (rule) { await updateAutoTagRule(rule.id, payload); toast.success('Rule updated') }
      else { await createAutoTagRule(payload); toast.success('Rule created') }
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
          {rule ? 'Edit Rule' : 'New Auto-tag Rule'}
        </span>
        <button onClick={onCancel} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', display: 'flex' }}>
          <X size={14} />
        </button>
      </div>

      <div>
        <label style={labelStyle}>Rule name</label>
        <input value={name} onChange={e => setName(e.target.value)} onKeyDown={e => e.key === 'Enter' && submit()} placeholder="e.g. Tag critical findings p0" style={inputStyle} />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
        <div>
          <label style={labelStyle}>Apply tag</label>
          <select value={tagId} onChange={e => setTagId(e.target.value)} style={inputStyle}>
            <option value="">— Select tag —</option>
            {allTags.map(t => <option key={t.id} value={t.id}>{t.label}</option>)}
          </select>
        </div>
        <div>
          <label style={labelStyle}>Applies to</label>
          <select value={targetType} onChange={e => setTargetType(e.target.value)} style={inputStyle}>
            <option value="asset">Assets only</option>
            <option value="finding">Findings only</option>
            <option value="both">Assets + Findings</option>
          </select>
        </div>
      </div>

      <div>
        <label style={{ ...labelStyle, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Conditions
        </label>
        <RuleBuilder
          conditions={conditions}
          logic={logic}
          onChange={(conds, lgc) => { setConditions(conds); setLogic(lgc) }}
          showLogic
          addLabel="Add condition"
        />
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <button onClick={() => setEnabled(p => !p)} style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex', color: enabled ? 'var(--success)' : 'var(--text-muted)' }}>
          {enabled ? <ToggleRight size={20} /> : <ToggleLeft size={20} />}
        </button>
        <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Rule {enabled ? 'enabled' : 'disabled'}</span>
      </div>

      {error && <div style={{ fontSize: 12, color: 'var(--danger)', background: 'var(--danger-subtle)', borderRadius: 6, padding: '6px 10px' }}>{error}</div>}

      <div style={{ display: 'flex', gap: 8, paddingTop: 4 }}>
        <Button onClick={submit} disabled={saving} style={{ flex: 1 }}>
          <Save size={13} /> {saving ? 'Saving…' : rule ? 'Update Rule' : 'Create Rule'}
        </Button>
        <Button variant="ghost" onClick={onCancel}>Cancel</Button>
      </div>
    </div>
  )
}

// ─── Delete confirm ────────────────────────────────────────
function DeleteConfirm({ tag, onConfirm, onCancel }) {
  const [strategy, setStrategy] = useState('reparent')
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--danger)' }}>Delete tag?</span>
        <button onClick={onCancel} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', display: 'flex' }}><X size={14} /></button>
      </div>
      <div style={{ fontSize: 12, color: 'var(--text-secondary)', background: 'var(--bg-hover)', borderRadius: 6, padding: '8px 10px' }}>
        <strong style={{ color: 'var(--text-primary)' }}>"{tag.label}"</strong>
        {tag.children?.length > 0 && ` and its ${tag.children.length} child tag(s)`}
        {' '}will be permanently deleted.
      </div>
      {tag.children?.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          <label style={labelStyle}>Handle child tags</label>
          {[
            { value: 'reparent', label: 'Re-parent children to grandparent' },
            { value: 'cascade', label: 'Delete all children recursively' },
          ].map(o => (
            <label key={o.value} style={{ display: 'flex', gap: 8, alignItems: 'center', cursor: 'pointer', fontSize: 13, color: 'var(--text-secondary)' }}>
              <input type="radio" value={o.value} checked={strategy === o.value} onChange={() => setStrategy(o.value)} />
              {o.label}
            </label>
          ))}
        </div>
      )}
      <div style={{ display: 'flex', gap: 8 }}>
        <Button variant="danger" onClick={() => onConfirm(strategy)}>Delete</Button>
        <Button variant="ghost" onClick={onCancel}>Cancel</Button>
      </div>
    </div>
  )
}

// ─── Tag assets panel ─────────────────────────────────────
const PREVIEW_LIMIT = 5

const SEV_COLORS = {
  4: { bg: '#450a0a', text: '#fca5a5', border: '#991b1b', label: 'Critical' },
  3: { bg: '#431407', text: '#fdba74', border: '#9a3412', label: 'High' },
  2: { bg: '#451a03', text: '#fcd34d', border: '#92400e', label: 'Medium' },
  1: { bg: '#1a2e05', text: '#86efac', border: '#166534', label: 'Low' },
  0: { bg: '#0c1a2e', text: '#7dd3fc', border: '#0369a1', label: 'Info' },
}

function SeverityDot({ severity }) {
  const c = SEV_COLORS[severity] ?? SEV_COLORS[0]
  return (
    <span style={{
      display: 'inline-block', width: 7, height: 7, borderRadius: '50%',
      background: c.text, flexShrink: 0,
    }} title={c.label} />
  )
}

function TagAssetsPanel({ tag, onClose }) {
  const [activeTab, setActiveTab] = useState('assets')
  const [assets, setAssets] = useState([])
  const [assetsTotal, setAssetsTotal] = useState(0)
  const [assetsLoading, setAssetsLoading] = useState(true)
  const [findings, setFindings] = useState([])
  const [findingsTotal, setFindingsTotal] = useState(0)
  const [findingsLoading, setFindingsLoading] = useState(false)
  const navigate = useNavigate()
  const color = tag.color || '#6366f1'
  const tagQuery = `${tag.category}:${tag.value}`
  const hasFindingCount = (tag.finding_count || 0) > 0

  useEffect(() => {
    let cancelled = false
    setAssetsLoading(true)
    setFindingsLoading(true)
    // Fetch assets and findings count in parallel
    Promise.all([
      getAssets({ tags: tagQuery, page_size: PREVIEW_LIMIT }),
      getFindings({ tags: tagQuery, page_size: 1 }),
    ]).then(([assetRes, findingRes]) => {
      if (cancelled) return
      setAssets(Array.isArray(assetRes) ? assetRes : assetRes.assets || assetRes.items || [])
      setAssetsTotal(assetRes.total ?? (Array.isArray(assetRes) ? assetRes.length : (assetRes.assets || assetRes.items || []).length))
      setFindingsTotal(findingRes.total ?? 0)
    }).catch(() => {
      if (!cancelled) { setAssets([]); setAssetsTotal(0); setFindingsTotal(0) }
    }).finally(() => {
      if (!cancelled) { setAssetsLoading(false); setFindingsLoading(false) }
    })
    return () => { cancelled = true }
  }, [tag.id, tagQuery])

  // Fetch full findings list only when tab is active
  const [findingsLoaded, setFindingsLoaded] = useState(false)
  useEffect(() => {
    if (activeTab !== 'findings' || findingsLoaded) return
    let cancelled = false
    setFindingsLoading(true)
    getFindings({ tags: tagQuery, page_size: PREVIEW_LIMIT })
      .then(res => {
        if (cancelled) return
        const items = res.findings || res.items || (Array.isArray(res) ? res : [])
        setFindings(items)
        setFindingsTotal(res.total ?? items.length)
        setFindingsLoaded(true)
      })
      .catch(() => { if (!cancelled) setFindings([]) })
      .finally(() => { if (!cancelled) setFindingsLoading(false) })
    return () => { cancelled = true }
  }, [activeTab, tag.id, tagQuery, findingsLoaded])

  const assetLabel = (a) => getAssetDisplayName(a)
  const assetSub = (a) => {
    if (a.ip && a.hostname) return a.hostname
    return null
  }

  const tabStyle = (active) => ({
    border: 'none', cursor: 'pointer',
    padding: '4px 10px', borderRadius: 6, fontSize: 11, fontWeight: 600,
    color: active ? 'var(--text-primary)' : 'var(--text-muted)',
    background: active ? 'var(--bg-hover)' : 'none',
  })

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{
            display: 'inline-flex', alignItems: 'center', gap: 4,
            background: `${color}18`, color, border: `1px solid ${color}44`,
            borderRadius: 999, padding: '2px 8px', fontSize: 11, fontWeight: 600,
          }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: color }} />
            {tagQuery}
          </span>
        </div>
        <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', display: 'flex' }}>
          <X size={14} />
        </button>
      </div>

      {tag.description && (
        <div style={{ fontSize: 12, color: 'var(--text-muted)', fontStyle: 'italic' }}>{tag.description}</div>
      )}

      {/* Stats row */}
      <div style={{ display: 'flex', gap: 12, fontSize: 11 }}>
        <span style={{ color: 'var(--text-muted)' }}>
          <strong style={{ color: 'var(--text-primary)', fontSize: 14 }}>{assetsLoading ? '…' : assetsTotal}</strong> assets
        </span>
        {(findingsTotal > 0 || hasFindingCount) && (
          <span style={{ color: 'var(--text-muted)' }}>
            <strong style={{ color: 'var(--text-primary)', fontSize: 14 }}>{findingsLoading ? '…' : findingsTotal}</strong> findings
          </span>
        )}
      </div>

      {/* Tab switcher — only show if there are findings to explore */}
      {hasFindingCount && (
        <div style={{ display: 'flex', gap: 2, background: 'var(--bg-secondary)', borderRadius: 8, padding: 2 }}>
          <button style={tabStyle(activeTab === 'assets')} onClick={() => setActiveTab('assets')}>
            <Monitor size={10} style={{ marginRight: 4 }} />Assets
          </button>
          <button style={tabStyle(activeTab === 'findings')} onClick={() => setActiveTab('findings')}>
            <AlertTriangle size={10} style={{ marginRight: 4 }} />Findings
          </button>
        </div>
      )}

      {/* Assets tab */}
      {activeTab === 'assets' && (
        <>
          {assetsLoading ? (
            <div style={{ textAlign: 'center', padding: 20 }}><Spinner /></div>
          ) : assets.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '20px 16px', color: 'var(--text-muted)', fontSize: 12 }}>
              No assets tagged
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 2 }}>
                Tagged Assets
              </div>
              {assets.map(a => {
                const sub = assetSub(a)
                return (
                  <div
                    key={a.id}
                    onClick={() => navigate(`/assets?highlight=${a.id}`)}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 8,
                      padding: '6px 8px', borderRadius: 6, cursor: 'pointer',
                      fontSize: 12, transition: 'background 0.15s',
                    }}
                    onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-hover)'}
                    onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                  >
                    <Monitor size={12} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
                    <span style={{ fontWeight: 500, color: 'var(--text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', minWidth: 0 }}>
                      {assetLabel(a)}
                    </span>
                    {sub && (
                      <span style={{ fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', minWidth: 0 }}>
                        {sub}
                      </span>
                    )}
                    <ExternalLink size={10} style={{ color: 'var(--text-muted)', flexShrink: 0, marginLeft: 'auto' }} />
                  </div>
                )
              })}
            </div>
          )}
          {assetsTotal > PREVIEW_LIMIT && (
            <Button size="sm" variant="ghost" onClick={() => navigate(`/assets?tags=${encodeURIComponent(tagQuery)}`)} style={{ alignSelf: 'center' }}>
              View all {assetsTotal} assets <ExternalLink size={11} />
            </Button>
          )}
          {assets.length > 0 && assetsTotal <= PREVIEW_LIMIT && (
            <Button size="sm" variant="ghost" onClick={() => navigate(`/assets?tags=${encodeURIComponent(tagQuery)}`)} style={{ alignSelf: 'center' }}>
              Open in Asset Inventory <ExternalLink size={11} />
            </Button>
          )}
        </>
      )}

      {/* Findings tab */}
      {activeTab === 'findings' && (
        <>
          {findingsLoading ? (
            <div style={{ textAlign: 'center', padding: 20 }}><Spinner /></div>
          ) : findings.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '20px 16px', color: 'var(--text-muted)', fontSize: 12 }}>
              No findings for this tag
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 2 }}>
                Tagged Findings
              </div>
              {findings.map(f => (
                <div
                  key={f.id}
                  onClick={() => navigate(`/findings?tags=${encodeURIComponent(tagQuery)}&highlight=${f.id}`)}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 8,
                    padding: '6px 8px', borderRadius: 6, cursor: 'pointer',
                    fontSize: 12, transition: 'background 0.15s',
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-hover)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <SeverityDot severity={f.severity} />
                  <span style={{ fontWeight: 500, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', minWidth: 0 }}>
                    {f.plugin_name || `Finding #${f.id}`}
                  </span>
                  <span style={{ fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', minWidth: 0, marginLeft: 'auto' }}>
                    {getFindingAssetDisplay(f)}
                  </span>
                  <ExternalLink size={10} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
                </div>
              ))}
            </div>
          )}
          {findingsTotal > PREVIEW_LIMIT && (
            <Button size="sm" variant="ghost" onClick={() => navigate(`/findings?tags=${encodeURIComponent(tagQuery)}`)} style={{ alignSelf: 'center' }}>
              View all {findingsTotal} findings <ExternalLink size={11} />
            </Button>
          )}
          {findings.length > 0 && findingsTotal <= PREVIEW_LIMIT && (
            <Button size="sm" variant="ghost" onClick={() => navigate(`/findings?tags=${encodeURIComponent(tagQuery)}`)} style={{ alignSelf: 'center' }}>
              Open in Finding Explorer <ExternalLink size={11} />
            </Button>
          )}
        </>
      )}
    </div>
  )
}

// ─── Main TagManager page ──────────────────────────────────
export default function TagManager() {
  const [tags, setTags] = useState([])
  const [tree, setTree] = useState([])
  const [rules, setRules] = useState([])
  const [loading, setLoading] = useState(true)
  const [tab, setTab] = useState('tags')

  const [selectedTag, setSelectedTag] = useState(null)
  const [editingTag, setEditingTag] = useState(null)   // null | 'new' | tagObj
  const [deletingTag, setDeletingTag] = useState(null)
  const [editingRule, setEditingRule] = useState(null) // null | 'new' | ruleObj
  const [runStatus, setRunStatus] = useState({})
  const [runAllStatus, setRunAllStatus] = useState(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [categoryFilter, setCategoryFilter] = useState('')
  const [currentPage, setCurrentPage] = useState(1)
  const toast = useToast()
  const confirm = useConfirm()

  // Derived: unique categories for filter dropdown
  const categories = [...new Set(tags.map(t => t.category))].sort()

  // Derived: filtered tree + pagination
  const filteredTree = filterTree(tree, searchQuery, categoryFilter)
  const totalFiltered = countTreeNodes(filteredTree)
  const totalPages = Math.max(1, Math.ceil(filteredTree.length / TAGS_PER_PAGE))
  const paginatedTree = filteredTree.slice((currentPage - 1) * TAGS_PER_PAGE, currentPage * TAGS_PER_PAGE)

  // Reset page when filters change
  useEffect(() => { setCurrentPage(1) }, [searchQuery, categoryFilter])

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [flat, treeData, ruleList] = await Promise.all([
        getTags(),
        getTags({ tree: true }),
        getAutoTagRules(),
      ])
      setTags(flat)
      setTree(treeData)
      setRules(ruleList)
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const handleDeleteTag = async (strategy) => {
    try {
      await deleteTag(deletingTag.id, strategy)
      toast.success('Tag deleted')
      setDeletingTag(null); setSelectedTag(null); load()
    } catch (e) { toast.error(e.message) }
  }

  const handleRunRule = async (rule) => {
    setRunStatus(s => ({ ...s, [rule.id]: 'running' }))
    try {
      const res = await runAutoTagRule(rule.id)
      setRunStatus(s => ({ ...s, [rule.id]: res.tagged }))
      // Silently refresh rules without full loading state
      const ruleList = await getAutoTagRules()
      setRules(ruleList)
    } catch (e) {
      setRunStatus(s => ({ ...s, [rule.id]: 'error' }))
    }
  }

  const handleRunAll = async () => {
    setRunAllStatus('running')
    try {
      const res = await runAllAutoTagRules()
      setRunAllStatus(res.total_tagged ?? 0)
      load()
    } catch (e) {
      setRunAllStatus('error')
    }
  }

  const handleToggleRule = async (rule) => {
    try {
      await updateAutoTagRule(rule.id, { is_enabled: !rule.is_enabled })
      toast.success(rule.is_enabled ? 'Rule disabled' : 'Rule enabled')
      load()
    } catch (e) { toast.error(e.message) }
  }

  const handleDeleteRule = async (rule) => {
    if (!await confirm(`Delete rule "${rule.name}"?`)) return
    try { await deleteAutoTagRule(rule.id); toast.success('Rule deleted'); load() }
    catch (e) { toast.error(e.message) }
  }

  if (loading) return <Spinner />

  const panelOpen = editingTag !== null || deletingTag !== null || selectedTag !== null

  return (
    <div>
      <PageHeader
        title="Tag Manager"
        subtitle="Organize assets and findings with hierarchical tags and auto-tagging rules"
      />

      {/* Tab bar */}
      <div style={{ display: 'flex', alignItems: 'center', borderBottom: '1px solid var(--border)', marginBottom: 20 }}>
        {[
          { id: 'tags',     label: 'Tags',           count: tags.length },
          { id: 'rules',    label: 'Auto-tag Rules', count: rules.length },
          { id: 'mappings', label: 'Tag Mappings',   count: null },
        ].map(t => (
          <button
            key={t.id}
            onClick={() => { setTab(t.id); setEditingTag(null); setEditingRule(null); setDeletingTag(null) }}
            style={{
              padding: '10px 18px', fontSize: 13, fontWeight: tab === t.id ? 600 : 400,
              color: tab === t.id ? 'var(--accent)' : 'var(--text-muted)',
              background: 'none', border: 'none', cursor: 'pointer',
              borderBottom: tab === t.id ? '2px solid var(--accent)' : '2px solid transparent',
              marginBottom: -1, display: 'flex', alignItems: 'center', gap: 6,
            }}
          >
            {t.label}
            {t.count !== null && (
              <span style={{
                fontSize: 10, fontWeight: 600,
                background: tab === t.id ? 'var(--accent)' : 'var(--bg-hover)',
                color: tab === t.id ? 'var(--nav-active-text)' : 'var(--text-muted)',
                borderRadius: 10, padding: '1px 6px',
              }}>{t.count}</span>
            )}
          </button>
        ))}
      </div>

      {/* ── Tags tab ── */}
      {tab === 'tags' && (
        <div style={{ display: 'grid', gridTemplateColumns: panelOpen ? '1fr 360px' : '1fr', gap: 16, alignItems: 'start' }}>
          <Card style={{ padding: 0, overflow: 'hidden' }}>
            {/* Toolbar */}
            <div style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              padding: '12px 16px', borderBottom: '1px solid var(--border)',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Tag size={14} style={{ color: 'var(--text-muted)' }} />
                <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Tag Hierarchy
                </span>
                {tags.length > 0 && (
                  <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>· {tags.length} total</span>
                )}
              </div>
              <Button size="sm" onClick={() => { setEditingTag('new'); setDeletingTag(null) }} disabled={editingTag !== null}>
                <Plus size={13} /> New Tag
              </Button>
            </div>

            {/* Search & Filters */}
            {tags.length > 0 && (
              <div style={{
                display: 'flex', alignItems: 'center', gap: 8,
                padding: '10px 16px', borderBottom: '1px solid var(--border)',
                background: 'var(--bg-secondary)',
              }}>
                <div style={{ position: 'relative', flex: 1, minWidth: 0 }}>
                  <Search size={13} style={{ position: 'absolute', left: 8, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', pointerEvents: 'none' }} />
                  <input
                    value={searchQuery}
                    onChange={e => setSearchQuery(e.target.value)}
                    placeholder="Search tags…"
                    style={{ ...inputStyle, paddingLeft: 28, fontSize: 12, padding: '6px 10px 6px 28px' }}
                  />
                </div>
                <select
                  value={categoryFilter}
                  onChange={e => setCategoryFilter(e.target.value)}
                  style={{ ...inputStyle, width: 'auto', minWidth: 120, fontSize: 12, padding: '6px 10px' }}
                >
                  <option value="">All categories</option>
                  {categories.map(c => <option key={c} value={c}>{c}</option>)}
                </select>
                {(searchQuery || categoryFilter) && (
                  <button
                    onClick={() => { setSearchQuery(''); setCategoryFilter('') }}
                    style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', display: 'flex', padding: 4 }}
                    title="Clear filters"
                  >
                    <X size={14} />
                  </button>
                )}
              </div>
            )}

            {/* Tree */}
            <div style={{ padding: '12px 10px', minHeight: 120 }}>
              {tree.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '32px 16px' }}>
                  <Tag size={28} style={{ color: 'var(--text-muted)', marginBottom: 8, opacity: 0.4 }} />
                  <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 4 }}>No tags yet</div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', opacity: 0.7 }}>
                    Create your first tag, e.g. category: "network", value: "dmz"
                  </div>
                </div>
              ) : filteredTree.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '24px 16px', color: 'var(--text-muted)', fontSize: 12 }}>
                  No tags match your search
                </div>
              ) : (
                <>
                  {(searchQuery || categoryFilter) && (
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', padding: '0 6px 8px', borderBottom: '1px solid var(--border)', marginBottom: 8 }}>
                      Showing {totalFiltered} tag{totalFiltered !== 1 ? 's' : ''} matching filters
                    </div>
                  )}
                  {paginatedTree.map(node => (
                    <TagNode
                      key={node.id} node={node}
                      selected={selectedTag}
                      onSelect={n => { setSelectedTag(n); setEditingTag(null); setDeletingTag(null) }}
                      onDelete={n => { setDeletingTag(n); setEditingTag(null) }}
                      onEdit={n => { setEditingTag(n); setDeletingTag(null) }}
                    />
                  ))}
                </>
              )}
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                padding: '10px 16px', borderTop: '1px solid var(--border)',
                fontSize: 12, color: 'var(--text-muted)',
              }}>
                <span>
                  Page {currentPage} of {totalPages}
                  <span style={{ marginLeft: 8, opacity: 0.7 }}>({filteredTree.length} root tag{filteredTree.length !== 1 ? 's' : ''})</span>
                </span>
                <div style={{ display: 'flex', gap: 4 }}>
                  <button
                    onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                    disabled={currentPage <= 1}
                    style={{
                      ...iconBtnStyle, borderRadius: 6,
                      opacity: currentPage <= 1 ? 0.3 : 1,
                      cursor: currentPage <= 1 ? 'default' : 'pointer',
                    }}
                  >
                    <ChevronLeft size={14} />
                  </button>
                  {Array.from({ length: totalPages }, (_, i) => i + 1)
                    .filter(p => p === 1 || p === totalPages || Math.abs(p - currentPage) <= 1)
                    .reduce((acc, p, i, arr) => {
                      if (i > 0 && p - arr[i - 1] > 1) acc.push('...')
                      acc.push(p)
                      return acc
                    }, [])
                    .map((p, i) =>
                      p === '...' ? (
                        <span key={`dot-${i}`} style={{ padding: '2px 4px', color: 'var(--text-muted)' }}>…</span>
                      ) : (
                        <button
                          key={p}
                          onClick={() => setCurrentPage(p)}
                          style={{
                            ...iconBtnStyle, borderRadius: 6, minWidth: 28, justifyContent: 'center',
                            fontWeight: currentPage === p ? 700 : 400, fontSize: 12,
                            color: currentPage === p ? 'var(--accent)' : 'var(--text-muted)',
                            background: currentPage === p ? 'var(--bg-hover)' : 'none',
                          }}
                        >
                          {p}
                        </button>
                      )
                    )}
                  <button
                    onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                    disabled={currentPage >= totalPages}
                    style={{
                      ...iconBtnStyle, borderRadius: 6,
                      opacity: currentPage >= totalPages ? 0.3 : 1,
                      cursor: currentPage >= totalPages ? 'default' : 'pointer',
                    }}
                  >
                    <ChevronRight size={14} />
                  </button>
                </div>
              </div>
            )}
          </Card>

          {/* Side panel */}
          {panelOpen && (
            <Card>
              {deletingTag ? (
                <DeleteConfirm tag={deletingTag} onConfirm={handleDeleteTag} onCancel={() => setDeletingTag(null)} />
              ) : editingTag ? (
                <TagForm
                  tag={editingTag === 'new' ? null : editingTag}
                  allTags={tags}
                  onSave={() => { setEditingTag(null); load() }}
                  onCancel={() => setEditingTag(null)}
                />
              ) : selectedTag ? (
                <TagAssetsPanel tag={selectedTag} onClose={() => setSelectedTag(null)} />
              ) : null}
            </Card>
          )}
        </div>
      )}

      {/* ── Rules tab ── */}
      {tab === 'rules' && (
        <div style={{ display: 'grid', gridTemplateColumns: editingRule !== null ? '1fr 420px' : '1fr', gap: 16, alignItems: 'start' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
            {/* Toolbar */}
            <div style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              marginBottom: 12,
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Zap size={14} style={{ color: 'var(--text-muted)' }} />
                <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Auto-tag Rules
                </span>
                {rules.length > 0 && (
                  <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>· {rules.length} rule{rules.length !== 1 ? 's' : ''}</span>
                )}
              </div>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <ExportImportButtons
                  configType="auto_tag_rules"
                  exportFn={() => exportConfig('auto_tag_rules')}
                  onImported={load}
                  label="Auto-Tag Rules"
                />
                {rules.length > 0 && (
                  <Button size="sm" variant="ghost" onClick={handleRunAll} disabled={runAllStatus === 'running'}>
                    <Play size={12} /> {runAllStatus === 'running' ? 'Running...' : 'Run All'}
                  </Button>
                )}
                <Button size="sm" onClick={() => setEditingRule('new')}>
                  <Plus size={13} /> New Rule
                </Button>
              </div>
            </div>

            {/* Run-all status banner — outside toolbar to avoid expanding the header */}
            {runAllStatus !== null && runAllStatus !== 'running' && (
              <div style={{
                fontSize: 12, color: runAllStatus === 'error' ? 'var(--danger)' : 'var(--success)',
                padding: '8px 12px', background: runAllStatus === 'error' ? 'var(--danger-subtle)' : 'var(--success-subtle, var(--bg-hover))',
                borderRadius: 8, marginBottom: 12, display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              }}>
                <span>{runAllStatus === 'error' ? 'Run failed' : `${runAllStatus} asset/finding(s) tagged across all rules`}</span>
                <button onClick={() => setRunAllStatus(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', display: 'flex', padding: 2 }}>
                  <X size={12} />
                </button>
              </div>
            )}

            {/* Rule list */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {rules.length === 0 && editingRule === null && (
                <Card style={{ textAlign: 'center', padding: '48px 24px' }}>
                  <Zap size={32} style={{ color: 'var(--text-muted)', opacity: 0.3, marginBottom: 12 }} />
                  <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>No auto-tag rules</div>
                  <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 16, maxWidth: 340, margin: '0 auto 16px' }}>
                    Rules automatically apply tags when scans are imported or run on demand.
                  </div>
                  <Button onClick={() => setEditingRule('new')}>
                    <Plus size={13} /> Create First Rule
                  </Button>
                </Card>
              )}

              {rules.map(rule => {
                const status = runStatus[rule.id]
                const isPassthrough = rule.conditions?.some(c => c.op === 'passthrough')
                const tagColor = rule.tag_color || '#6366f1'
                const isEditing = editingRule && editingRule !== 'new' && editingRule.id === rule.id

                return (
                  <div
                    key={rule.id}
                    onClick={() => { if (!isPassthrough) setEditingRule(rule) }}
                    style={{
                      background: 'var(--bg-card)', border: isEditing ? '1px solid var(--accent)' : '1px solid var(--border)',
                      borderRadius: 10, padding: '12px 16px', cursor: isPassthrough ? 'default' : 'pointer',
                      transition: 'border-color 0.15s, box-shadow 0.15s',
                      boxShadow: isEditing ? '0 0 0 1px var(--accent)' : 'none',
                      opacity: rule.is_enabled ? 1 : 0.7,
                    }}
                    onMouseEnter={e => { if (!isEditing && !isPassthrough) e.currentTarget.style.borderColor = 'var(--accent-muted, var(--text-muted))' }}
                    onMouseLeave={e => { if (!isEditing) e.currentTarget.style.borderColor = isEditing ? 'var(--accent)' : 'var(--border)' }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      {/* Enable toggle */}
                      <button
                        onClick={e => { e.stopPropagation(); handleToggleRule(rule) }}
                        style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex', color: rule.is_enabled ? 'var(--success)' : 'var(--text-muted)', flexShrink: 0 }}
                        title={rule.is_enabled ? 'Disable rule' : 'Enable rule'}
                      >
                        {rule.is_enabled ? <ToggleRight size={20} /> : <ToggleLeft size={20} />}
                      </button>

                      {/* Content */}
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3 }}>
                          <span style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-primary)' }}>{rule.name}</span>
                          {isPassthrough && (
                            <span title="This rule is auto-managed via team ownership. Edit it from Settings → Ownership." style={{ fontSize: 10, background: 'var(--accent-subtle, var(--bg-hover))', color: 'var(--accent)', borderRadius: 4, padding: '1px 6px', flexShrink: 0, cursor: 'help' }}>auto-managed</span>
                          )}
                          {!rule.is_enabled && (
                            <span style={{ fontSize: 10, background: 'var(--bg-hover)', color: 'var(--text-muted)', borderRadius: 4, padding: '1px 6px', flexShrink: 0 }}>disabled</span>
                          )}
                        </div>

                        {/* Meta row */}
                        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
                          <span style={{
                            display: 'inline-flex', alignItems: 'center', gap: 4,
                            background: `${tagColor}18`, color: tagColor, border: `1px solid ${tagColor}44`,
                            borderRadius: 999, padding: '1px 8px', fontSize: 11, fontWeight: 600,
                          }}>
                            <span style={{ width: 6, height: 6, borderRadius: '50%', background: tagColor }} />
                            {rule.tag_label || (isPassthrough ? `${rule.conditions[0]?.value || ''}:*` : '—')}
                          </span>
                          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                            → {rule.target_type === 'both' ? 'assets + findings' : rule.target_type === 'asset' ? 'assets' : 'findings'}
                          </span>
                          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                            {isPassthrough
                              ? `maps ${rule.conditions[0]?.field || 'field'} → ${rule.conditions[0]?.value || ''}:*`
                              : `${rule.conditions?.length || 0} condition${rule.conditions?.length !== 1 ? 's' : ''} (${rule.condition_logic})`}
                          </span>
                          {rule.last_run_at && (
                            <span style={{ fontSize: 11, color: 'var(--text-muted)', marginLeft: 'auto' }}>
                              Last: {new Date(rule.last_run_at).toLocaleDateString()} · {rule.last_run_count ?? 0} tagged
                            </span>
                          )}
                        </div>
                      </div>

                      {/* Actions */}
                      <div style={{ display: 'flex', gap: 2, alignItems: 'center', flexShrink: 0 }} onClick={e => e.stopPropagation()}>
                        <Button size="sm" variant="ghost" onClick={() => handleRunRule(rule)} disabled={status === 'running'} title="Run now">
                          <Play size={11} /> {status === 'running' ? '...' : 'Run'}
                        </Button>
                        <button onClick={() => handleDeleteRule(rule)} style={{ ...iconBtnStyle, color: 'var(--danger)' }} title="Delete"><Trash2 size={13} /></button>
                      </div>
                    </div>

                    {(typeof status === 'number' || status === 'error') && (
                      <div style={{ marginTop: 8, paddingTop: 8, borderTop: '1px solid var(--border)', marginLeft: 30 }}>
                        {typeof status === 'number' && (
                          <span style={{ fontSize: 11, color: 'var(--success)' }}>{status} matched</span>
                        )}
                        {status === 'error' && <span style={{ fontSize: 11, color: 'var(--danger)' }}>Run failed</span>}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          </div>

          {/* Rule form panel */}
          {editingRule !== null && (
            <Card style={{ position: 'sticky', top: 16 }}>
              <AutoTagRuleForm
                key={editingRule === 'new' ? 'new' : editingRule.id}
                rule={editingRule === 'new' ? null : editingRule}
                allTags={tags}
                onSave={() => { setEditingRule(null); load() }}
                onCancel={() => setEditingRule(null)}
              />
            </Card>
          )}
        </div>
      )}

      {/* ── Tag Mappings tab ── */}
      {tab === 'mappings' && <TagMappings />}
    </div>
  )
}

const labelStyle = {
  fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4,
}

const inputStyle = {
  width: '100%', background: 'var(--bg-card)', border: '1px solid var(--border)',
  color: 'var(--text-primary)', borderRadius: 6, padding: '7px 10px',
  fontSize: 13, outline: 'none', boxSizing: 'border-box',
}

const iconBtnStyle = {
  background: 'none', border: 'none', cursor: 'pointer',
  color: 'var(--text-muted)', display: 'flex', padding: 4, borderRadius: 4,
}
