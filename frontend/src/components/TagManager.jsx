import React, { useState, useEffect, useCallback } from 'react'
import { Tag, Plus, ChevronRight, ChevronDown, Trash2, Edit2, Play, ToggleLeft, ToggleRight, X, Save, Zap } from 'lucide-react'
import {
  getTags, createTag, updateTag, deleteTag,
  getAutoTagRules, createAutoTagRule, updateAutoTagRule, deleteAutoTagRule,
  runAutoTagRule,
} from '../api.js'
import { Card, PageHeader, Button, Input, Select, Spinner, EmptyState } from './ui.jsx'
import RuleBuilder from './RuleBuilder.jsx'

// ─────────────────────────────────────────────────────────
// Color palette for tag creation
// ─────────────────────────────────────────────────────────
const PALETTE = [
  '#6366f1', '#8b5cf6', '#ec4899', '#ef4444', '#f97316',
  '#eab308', '#22c55e', '#14b8a6', '#06b6d4', '#3b82f6',
]

// ─────────────────────────────────────────────────────────
// Tag tree node
// ─────────────────────────────────────────────────────────
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
          style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 2 }}
          title="Edit"
        ><Edit2 size={11} /></button>
        <button
          onClick={e => { e.stopPropagation(); onDelete(node) }}
          style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#dc2626', padding: 2 }}
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

// ─────────────────────────────────────────────────────────
// Tag form (create / edit)
// ─────────────────────────────────────────────────────────
function TagForm({ tag, allTags, onSave, onCancel }) {
  const [category, setCategory] = useState(tag?.category || '')
  const [value, setValue] = useState(tag?.value || '')
  const [parentId, setParentId] = useState(tag?.parent_id || '')
  const [color, setColor] = useState(tag?.color || '#6366f1')
  const [description, setDescription] = useState(tag?.description || '')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(null)

  const isEdit = !!tag
  const categories = [...new Set(allTags.map(t => t.category))].sort()

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
      } else {
        await createTag(payload)
      }
      onSave()
    } catch (e) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  const validParents = allTags.filter(t => t.id !== tag?.id)

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>
        {isEdit ? 'Edit Tag' : 'New Tag'}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
        <div>
          <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Category</label>
          <input
            value={category}
            onChange={e => setCategory(e.target.value)}
            list="tag-categories"
            placeholder="e.g. network"
            style={inputStyle}
          />
          <datalist id="tag-categories">
            {categories.map(c => <option key={c} value={c} />)}
          </datalist>
        </div>
        <div>
          <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Value</label>
          <input
            value={value}
            onChange={e => setValue(e.target.value)}
            placeholder="e.g. dmz"
            style={inputStyle}
          />
        </div>
      </div>

      <div>
        <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Parent tag (optional)</label>
        <select value={parentId || ''} onChange={e => setParentId(e.target.value || '')} style={inputStyle}>
          <option value="">— None (root) —</option>
          {validParents.map(t => (
            <option key={t.id} value={t.id}>{t.label}</option>
          ))}
        </select>
      </div>

      <div>
        <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Color</label>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
          {PALETTE.map(c => (
            <button
              key={c}
              onClick={() => setColor(c)}
              style={{
                width: 22, height: 22, borderRadius: '50%', background: c, border: 'none', cursor: 'pointer',
                outline: color === c ? `2px solid ${c}` : 'none', outlineOffset: 2,
              }}
            />
          ))}
          <input type="color" value={color} onChange={e => setColor(e.target.value)}
            style={{ width: 26, height: 26, border: 'none', borderRadius: 4, cursor: 'pointer', padding: 0 }} />
        </div>
      </div>

      <div>
        <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Description</label>
        <input value={description} onChange={e => setDescription(e.target.value)}
          placeholder="Optional description" style={inputStyle} />
      </div>

      {/* Preview */}
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

      {error && <div style={{ fontSize: 12, color: '#dc2626', background: '#450a0a', borderRadius: 6, padding: '6px 10px' }}>{error}</div>}

      <div style={{ display: 'flex', gap: 8 }}>
        <Button onClick={submit} disabled={saving}>
          <Save size={14} /> {saving ? 'Saving…' : isEdit ? 'Update' : 'Create Tag'}
        </Button>
        <Button variant="ghost" onClick={onCancel}>Cancel</Button>
      </div>
    </div>
  )
}


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
      if (rule) await updateAutoTagRule(rule.id, payload)
      else await createAutoTagRule(payload)
      onSave()
    } catch (e) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>
        {rule ? 'Edit Rule' : 'New Auto-tag Rule'}
      </div>

      <div>
        <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Rule name</label>
        <input value={name} onChange={e => setName(e.target.value)} placeholder="e.g. Tag critical findings p0" style={inputStyle} />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
        <div>
          <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Apply tag</label>
          <select value={tagId} onChange={e => setTagId(e.target.value)} style={inputStyle}>
            <option value="">— Select tag —</option>
            {allTags.map(t => <option key={t.id} value={t.id}>{t.label}</option>)}
          </select>
        </div>
        <div>
          <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Applies to</label>
          <select value={targetType} onChange={e => setTargetType(e.target.value)} style={inputStyle}>
            <option value="asset">Assets only</option>
            <option value="finding">Findings only</option>
            <option value="both">Assets + Findings</option>
          </select>
        </div>
      </div>

      <div>
        <label style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', display: 'block', marginBottom: 8 }}>
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
        <button onClick={() => setEnabled(p => !p)} style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex', color: enabled ? '#22c55e' : 'var(--text-muted)' }}>
          {enabled ? <ToggleRight size={20} /> : <ToggleLeft size={20} />}
        </button>
        <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Rule {enabled ? 'enabled' : 'disabled'}</span>
      </div>

      {error && <div style={{ fontSize: 12, color: '#dc2626', background: '#450a0a', borderRadius: 6, padding: '6px 10px' }}>{error}</div>}

      <div style={{ display: 'flex', gap: 8 }}>
        <Button onClick={submit} disabled={saving}>
          <Save size={14} /> {saving ? 'Saving…' : rule ? 'Update Rule' : 'Create Rule'}
        </Button>
        <Button variant="ghost" onClick={onCancel}>Cancel</Button>
      </div>
    </div>
  )
}

// ─────────────────────────────────────────────────────────
// Delete confirm modal
// ─────────────────────────────────────────────────────────
function DeleteConfirm({ tag, onConfirm, onCancel }) {
  const [strategy, setStrategy] = useState('reparent')
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ fontSize: 14, fontWeight: 700, color: '#dc2626' }}>Delete tag "{tag.label}"?</div>
      {tag.children?.length > 0 && (
        <>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
            This tag has <strong>{tag.children.length}</strong> child tag(s). Choose what to do with them:
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {[
              { value: 'reparent', label: 'Re-parent children to grandparent' },
              { value: 'cascade', label: 'Delete all children recursively' },
            ].map(o => (
              <label key={o.value} style={{ display: 'flex', gap: 8, alignItems: 'center', cursor: 'pointer', fontSize: 13 }}>
                <input type="radio" value={o.value} checked={strategy === o.value} onChange={() => setStrategy(o.value)} />
                {o.label}
              </label>
            ))}
          </div>
        </>
      )}
      <div style={{ display: 'flex', gap: 8 }}>
        <Button variant="danger" onClick={() => onConfirm(strategy)}>Delete</Button>
        <Button variant="ghost" onClick={onCancel}>Cancel</Button>
      </div>
    </div>
  )
}

// ─────────────────────────────────────────────────────────
// Main TagManager page
// ─────────────────────────────────────────────────────────
export default function TagManager() {
  const [tags, setTags] = useState([])
  const [tree, setTree] = useState([])
  const [rules, setRules] = useState([])
  const [loading, setLoading] = useState(true)
  const [tab, setTab] = useState('tags')  // 'tags' | 'rules'

  // Panel state
  const [selectedTag, setSelectedTag] = useState(null)
  const [editingTag, setEditingTag] = useState(null)       // null | 'new' | tagObj
  const [deletingTag, setDeletingTag] = useState(null)
  const [editingRule, setEditingRule] = useState(null)     // null | 'new' | ruleObj
  const [runStatus, setRunStatus] = useState({})           // {ruleId: 'running'|count}

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
      setDeletingTag(null)
      setSelectedTag(null)
      load()
    } catch (e) {
      alert(e.message)
    }
  }

  const handleRunRule = async (rule) => {
    setRunStatus(s => ({ ...s, [rule.id]: 'running' }))
    try {
      const res = await runAutoTagRule(rule.id)
      setRunStatus(s => ({ ...s, [rule.id]: res.tagged }))
      load()
    } catch (e) {
      setRunStatus(s => ({ ...s, [rule.id]: 'error' }))
    }
  }

  const handleToggleRule = async (rule) => {
    try {
      await updateAutoTagRule(rule.id, { is_enabled: !rule.is_enabled })
      load()
    } catch (e) {
      alert(e.message)
    }
  }

  const handleDeleteRule = async (rule) => {
    if (!confirm(`Delete rule "${rule.name}"?`)) return
    try {
      await deleteAutoTagRule(rule.id)
      load()
    } catch (e) {
      alert(e.message)
    }
  }

  if (loading) return <Spinner />

  const panelOpen = editingTag !== null || deletingTag !== null

  return (
    <div>
      <PageHeader
        title="Tag Manager"
        subtitle="Organize assets and findings with hierarchical tags and auto-tagging rules"
        action={
          <div style={{ display: 'flex', gap: 8 }}>
            {tab === 'tags' && (
              <Button onClick={() => setEditingTag('new')} disabled={editingTag !== null}>
                <Plus size={14} /> New Tag
              </Button>
            )}
            {tab === 'rules' && (
              <Button onClick={() => setEditingRule('new')} disabled={editingRule !== null}>
                <Zap size={14} /> New Rule
              </Button>
            )}
          </div>
        }
      />

      {/* Tab bar */}
      <div style={{ display: 'flex', gap: 0, marginBottom: 16, borderBottom: '1px solid var(--border)' }}>
        {[{ id: 'tags', label: `Tags (${tags.length})` }, { id: 'rules', label: `Auto-tag Rules (${rules.length})` }].map(t => (
          <button
            key={t.id}
            onClick={() => { setTab(t.id); setEditingTag(null); setEditingRule(null); setDeletingTag(null) }}
            style={{
              padding: '8px 16px', fontSize: 13, fontWeight: tab === t.id ? 700 : 400,
              color: tab === t.id ? 'var(--accent)' : 'var(--text-muted)',
              background: 'none', border: 'none', cursor: 'pointer',
              borderBottom: tab === t.id ? '2px solid var(--accent)' : '2px solid transparent',
              marginBottom: -1,
            }}
          >{t.label}</button>
        ))}
      </div>

      {/* ── Tags tab ── */}
      {tab === 'tags' && (
        <div style={{ display: 'grid', gridTemplateColumns: panelOpen ? '1fr 380px' : '1fr', gap: 16 }}>
          {/* Tree */}
          <Card>
            {tree.length === 0 ? (
              <EmptyState
                icon={Tag}
                title="No tags yet"
                sub='Create your first tag above (e.g. category: "network", value: "dmz")'
              />
            ) : (
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 10 }}>
                  Tag hierarchy · {tags.length} tags
                </div>
                {tree.map(node => (
                  <TagNode
                    key={node.id} node={node}
                    selected={selectedTag}
                    onSelect={n => { setSelectedTag(n); setEditingTag(null); setDeletingTag(null) }}
                    onDelete={n => { setDeletingTag(n); setEditingTag(null) }}
                    onEdit={n => { setEditingTag(n); setDeletingTag(null) }}
                  />
                ))}
              </div>
            )}
          </Card>

          {/* Side panel */}
          {panelOpen && (
            <Card>
              {deletingTag ? (
                <DeleteConfirm
                  tag={deletingTag}
                  onConfirm={handleDeleteTag}
                  onCancel={() => setDeletingTag(null)}
                />
              ) : editingTag ? (
                <TagForm
                  tag={editingTag === 'new' ? null : editingTag}
                  allTags={tags}
                  onSave={() => { setEditingTag(null); load() }}
                  onCancel={() => setEditingTag(null)}
                />
              ) : null}
            </Card>
          )}
        </div>
      )}

      {/* ── Rules tab ── */}
      {tab === 'rules' && (
        <div style={{ display: 'grid', gridTemplateColumns: editingRule !== null ? '1fr 420px' : '1fr', gap: 16 }}>
          {/* Rule list */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {rules.length === 0 && editingRule === null && (
              <Card>
                <EmptyState
                  icon={Zap}
                  title="No auto-tag rules"
                  sub="Rules automatically apply tags when new scans are imported or when run on demand."
                />
              </Card>
            )}
            {rules.map(rule => {
              const status = runStatus[rule.id]
              const tagColor = rule.tag_color || '#6366f1'
              return (
                <Card key={rule.id} style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{ fontWeight: 600, fontSize: 14, color: 'var(--text-primary)' }}>{rule.name}</span>
                        {!rule.is_enabled && (
                          <span style={{ fontSize: 10, background: 'var(--bg-hover)', color: 'var(--text-muted)', borderRadius: 4, padding: '1px 6px' }}>disabled</span>
                        )}
                      </div>
                      {rule.description && <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>{rule.description}</div>}
                    </div>
                    <div style={{ display: 'flex', gap: 6 }}>
                      <button onClick={() => handleToggleRule(rule)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: rule.is_enabled ? '#22c55e' : 'var(--text-muted)', display: 'flex' }} title={rule.is_enabled ? 'Disable' : 'Enable'}>
                        {rule.is_enabled ? <ToggleRight size={18} /> : <ToggleLeft size={18} />}
                      </button>
                      <button onClick={() => { setEditingRule(rule) }} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', display: 'flex' }} title="Edit"><Edit2 size={14} /></button>
                      <button onClick={() => handleDeleteRule(rule)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#dc2626', display: 'flex' }} title="Delete"><Trash2 size={14} /></button>
                    </div>
                  </div>

                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                    <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Applies</span>
                    <span style={{
                      display: 'inline-flex', alignItems: 'center', gap: 4,
                      background: `${tagColor}18`, color: tagColor, border: `1px solid ${tagColor}44`,
                      borderRadius: 999, padding: '1px 8px', fontSize: 11, fontWeight: 600,
                    }}>
                      <span style={{ width: 6, height: 6, borderRadius: '50%', background: tagColor }} />
                      {rule.tag_label}
                    </span>
                    <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>to {rule.target_type}</span>
                    <span style={{ fontSize: 11, color: 'var(--text-muted)', marginLeft: 'auto' }}>
                      {rule.conditions?.length || 0} condition{rule.conditions?.length !== 1 ? 's' : ''} · {rule.condition_logic}
                    </span>
                  </div>

                  <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <Button size="sm" variant="ghost" onClick={() => handleRunRule(rule)} disabled={status === 'running'}>
                      <Play size={12} /> {status === 'running' ? 'Running…' : 'Run now'}
                    </Button>
                    {typeof status === 'number' && (
                      <span style={{ fontSize: 11, color: '#22c55e' }}>✓ {status} new assignment{status !== 1 ? 's' : ''}</span>
                    )}
                    {status === 'error' && <span style={{ fontSize: 11, color: '#dc2626' }}>Run failed</span>}
                    {rule.last_run_at && (
                      <span style={{ fontSize: 11, color: 'var(--text-muted)', marginLeft: 'auto' }}>
                        Last run: {new Date(rule.last_run_at).toLocaleString()} · {rule.last_run_count ?? 0} tagged
                      </span>
                    )}
                  </div>
                </Card>
              )
            })}
          </div>

          {/* Rule form panel */}
          {editingRule !== null && (
            <Card>
              <AutoTagRuleForm
                rule={editingRule === 'new' ? null : editingRule}
                allTags={tags}
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

const inputStyle = {
  width: '100%', background: 'var(--bg-card)', border: '1px solid var(--border)',
  color: 'var(--text-primary)', borderRadius: 6, padding: '7px 10px',
  fontSize: 13, outline: 'none', boxSizing: 'border-box',
}
