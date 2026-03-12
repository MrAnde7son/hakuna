import React, { useState, useEffect, useRef } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { Server, RefreshCw, Edit2, Tag, X, Crosshair, Download, Bookmark, SlidersHorizontal, X as XIcon, Database, MoreHorizontal, AlertTriangle } from 'lucide-react'
import { useScan } from '../App.jsx'
import { getAssets, updateAsset, getBlastRadiusBulk, assignTags, unassignTags, confirmAssetOwner, exportDownload, advancedSearch, setAssetOwnership } from '../api.js'
import { Card, ScoreBar, Table, PageHeader, Select, Spinner, EmptyState, Button, TagPill, TagFilterBar, TagPicker, OwnerBadge, ConfidenceDot, ColumnSelector, SaveAsRuleModal, OwnershipEditPopover } from './ui.jsx'
import RuleBuilder from './RuleBuilder.jsx'
import { filtersToConditions } from '../utils/filtersToConditions.js'
import BlastRadiusPanel, { BlastRadiusScore } from './BlastRadiusPanel.jsx'
import NLPSearchBar from './NLPSearchBar.jsx'

function RiskScore({ score }) {
  const color = score >= 8 ? '#dc2626' : score >= 6 ? '#ea580c' : score >= 4 ? '#d97706' : '#65a30d'
  return (
    <div style={{ minWidth: 120 }}>
      <ScoreBar score={score} color={color} />
    </div>
  )
}

function SevCounts({ asset }) {
  const items = [
    { label: 'C', count: asset.critical_count, color: '#dc2626' },
    { label: 'H', count: asset.high_count, color: '#ea580c' },
    { label: 'M', count: asset.medium_count, color: '#d97706' },
    { label: 'L', count: asset.low_count, color: '#65a30d' },
    { label: 'I', count: asset.info_count, color: '#0ea5e9' },
  ]
  return (
    <div style={{ display: 'flex', gap: 6 }}>
      {items.map(({ label, count, color }) => (
        count > 0 && (
          <span key={label} style={{
            display: 'inline-flex', alignItems: 'center', gap: 2,
            background: `${color}22`, color, border: `1px solid ${color}44`,
            borderRadius: 4, padding: '1px 6px', fontSize: 11, fontWeight: 600,
          }}>
            {label}: {count}
          </span>
        )
      ))}
    </div>
  )
}

function CriticalityEditor({ asset, onUpdate }) {
  const [editing, setEditing] = useState(false)
  const [val, setVal] = useState(asset.criticality)

  const save = async () => {
    await updateAsset(asset.id, { criticality: val })
    onUpdate()
    setEditing(false)
  }

  const LABELS = { 1: 'Minimal', 2: 'Very Low', 3: 'Low', 4: 'Low-Med', 5: 'Medium', 6: 'Med-High', 7: 'High', 8: 'Very High', 9: 'Critical', 10: 'Maximum' }

  if (!editing) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }} onClick={e => { e.stopPropagation(); setEditing(true) }}>
        <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{LABELS[asset.criticality] || asset.criticality}</span>
        <Edit2 size={10} color="var(--text-muted)" />
      </div>
    )
  }

  return (
    <div style={{ display: 'flex', gap: 4, alignItems: 'center' }} onClick={e => e.stopPropagation()}>
      <select
        value={val}
        onChange={e => setVal(Number(e.target.value))}
        style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)', borderRadius: 4, padding: '2px 4px', fontSize: 12 }}
      >
        {[1,2,3,4,5,6,7,8,9,10].map(n => <option key={n} value={n}>{n} – {LABELS[n]}</option>)}
      </select>
      <Button size="sm" onClick={save}>Save</Button>
      <Button size="sm" variant="ghost" onClick={() => setEditing(false)}>✕</Button>
    </div>
  )
}

const ENV_COLORS = { internet: '#dc2626', dmz: '#ea580c', internal: '#65a30d', ot: '#d97706' }

function RowActions({ row, onNavigate }) {
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

  useEffect(() => {
    if (!open) return
    const handler = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [open])

  const items = [
    { icon: AlertTriangle, label: 'View Findings', action: () => onNavigate(`/findings?asset_id=${row.id}`) },
    { icon: Database, label: 'View Inventory', action: () => onNavigate(`/inventory?asset_id=${row.id}&asset_name=${encodeURIComponent(row.hostname || row.ip)}`) },
  ]

  return (
    <div ref={ref} style={{ position: 'relative' }} onClick={e => e.stopPropagation()}>
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          width: 28, height: 28, borderRadius: 6,
          background: open ? 'var(--bg-muted)' : 'transparent',
          border: '1px solid transparent',
          cursor: 'pointer', color: 'var(--text-muted)',
          transition: 'all 0.15s',
        }}
        onMouseEnter={e => { e.currentTarget.style.background = 'var(--bg-muted)'; e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-primary)' }}
        onMouseLeave={e => { if (!open) { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.borderColor = 'transparent'; e.currentTarget.style.color = 'var(--text-muted)' } }}
        title="Actions"
      >
        <MoreHorizontal size={15} />
      </button>
      {open && (
        <div style={{
          position: 'absolute', right: 0, top: '100%', marginTop: 4, zIndex: 200,
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: 8, boxShadow: '0 8px 24px rgba(0,0,0,0.2)',
          padding: '4px 0', minWidth: 170,
        }}>
          {items.map(({ icon: Icon, label, action }) => (
            <button
              key={label}
              onClick={() => { setOpen(false); action() }}
              style={{
                display: 'flex', alignItems: 'center', gap: 9, width: '100%',
                padding: '8px 14px', background: 'none', border: 'none',
                cursor: 'pointer', fontSize: 13, color: 'var(--text-secondary)',
                textAlign: 'left',
              }}
              onMouseEnter={e => { e.currentTarget.style.background = 'var(--bg-muted)'; e.currentTarget.style.color = 'var(--text-primary)' }}
              onMouseLeave={e => { e.currentTarget.style.background = 'none'; e.currentTarget.style.color = 'var(--text-secondary)' }}
            >
              <Icon size={13} style={{ flexShrink: 0 }} />
              {label}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

function ResizablePanel({ children, onClose }) {
  const [width, setWidth] = useState(680)
  const dragging = useRef(false)

  useEffect(() => {
    const onMouseMove = (e) => {
      if (!dragging.current) return
      const newWidth = Math.min(Math.max(window.innerWidth - e.clientX, 400), window.innerWidth * 0.9)
      setWidth(newWidth)
    }
    const onMouseUp = () => { dragging.current = false; document.body.style.cursor = '' }
    window.addEventListener('mousemove', onMouseMove)
    window.addEventListener('mouseup', onMouseUp)
    return () => { window.removeEventListener('mousemove', onMouseMove); window.removeEventListener('mouseup', onMouseUp) }
  }, [])

  return (
    <div style={{
      position: 'fixed', top: 0, right: 0, bottom: 0, zIndex: 901,
      width, maxWidth: '90vw',
      background: 'var(--bg-card)', borderLeft: '1px solid var(--border)',
      boxShadow: '-4px 0 24px rgba(0,0,0,0.2)',
      display: 'flex', flexDirection: 'column',
      animation: 'slideInRight 0.2s ease-out',
    }}>
      {/* Drag handle */}
      <div
        onMouseDown={() => { dragging.current = true; document.body.style.cursor = 'col-resize' }}
        style={{
          position: 'absolute', top: 0, left: -3, bottom: 0, width: 6,
          cursor: 'col-resize', zIndex: 10,
        }}
      />
      {children}
    </div>
  )
}

// Blast radius score cell (uses pre-fetched bulk data)
function BlastCell({ br, onExpand }) {
  return (
    <BlastRadiusScore
      score={br?.score ?? null}
      reachable={br?.reachable_assets ?? 0}
      daExposed={br?.da_exposed}
      dcReachable={br?.dc_reachable}
      onClick={onExpand}
    />
  )
}

// Bulk tag modal
function BulkTagModal({ assetIds, onClose, onDone }) {
  const [selected, setSelected] = useState([])
  const [saving, setSaving] = useState(false)

  const apply = async () => {
    if (!selected.length) return
    setSaving(true)
    try {
      await assignTags({ tag_ids: selected.map(t => t.tag_id), asset_ids: assetIds })
      onDone()
    } finally {
      setSaving(false)
    }
  }

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 1000,
      background: 'rgba(0,0,0,0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center',
    }}>
      <div style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 12,
        padding: 24, width: 420, display: 'flex', flexDirection: 'column', gap: 14,
        boxShadow: '0 8px 32px rgba(0,0,0,0.3)',
      }}>
        <div style={{ fontSize: 15, fontWeight: 700 }}>
          Tag {assetIds.length} asset{assetIds.length !== 1 ? 's' : ''}
        </div>
        <TagPicker selectedTags={selected} onChange={setSelected} placeholder="Search tags…" />
        <div style={{ display: 'flex', gap: 8 }}>
          <Button onClick={apply} disabled={saving || !selected.length}>
            <Tag size={14} /> {saving ? 'Applying…' : 'Apply Tags'}
          </Button>
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
        </div>
      </div>
    </div>
  )
}

const CRITICALITY_LABELS = { 1: 'Minimal', 2: 'Very Low', 3: 'Low', 4: 'Low-Med', 5: 'Medium', 6: 'Med-High', 7: 'High', 8: 'Very High', 9: 'Critical', 10: 'Maximum' }

export default function AssetInventory() {
  const { activeScanId } = useScan()
  const [assets, setAssets] = useState([])
  const [loading, setLoading] = useState(true)
  const [blastMap, setBlastMap] = useState({})
  const [expandedAsset, setExpandedAsset] = useState(null)
  const [selectedIds, setSelectedIds] = useState(new Set())
  const [showBulkTag, setShowBulkTag] = useState(false)
  const [showSaveAs, setShowSaveAs] = useState(false)
  const [tagFilter, setTagFilter] = useState([])
  const [tagLogic, setTagLogic] = useState('AND')
  const [ownershipEdit, setOwnershipEdit] = useState(null) // { assetId, current, anchorRef }

  // Advanced rule-engine search
  const [advancedMode, setAdvancedMode] = useState(false)
  const [advancedConditions, setAdvancedConditions] = useState([])
  const [advancedLogic, setAdvancedLogic] = useState('AND')
  const [advancedLoading, setAdvancedLoading] = useState(false)
  const [colVis, setColVis] = useState(() => {
    try { const s = localStorage.getItem('assetColumns'); return s ? JSON.parse(s) : {} } catch { return {} }
  })
  const updateColVis = (next) => { setColVis(next); localStorage.setItem('assetColumns', JSON.stringify(next)) }
  const [filters, setFilters] = useState({
    search: '', env: '', criticality: '', minRisk: '', maxRisk: '', minCritical: '', minHigh: '',
  })
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()

  const sortBy = searchParams.get('sort') || 'risk_score'
  const sortOrder = searchParams.get('order') || 'desc'

  const handleSort = (key) => {
    setSearchParams(prev => {
      const next = new URLSearchParams(prev)
      if (prev.get('sort') === key) {
        next.set('order', prev.get('order') === 'asc' ? 'desc' : 'asc')
      } else {
        next.set('sort', key)
        next.set('order', 'desc')
      }
      return next
    }, { replace: true })
  }

  const clearFilters = () => setFilters({
    search: '', env: '', criticality: '', minRisk: '', maxRisk: '', minCritical: '', minHigh: '',
  })

  const activeFilterCount = Object.values(filters).filter(Boolean).length

  const load = () => {
    setLoading(true)
    const params = {
      scan_id: activeScanId,
      environment: filters.env || undefined,
      criticality: filters.criticality || undefined,
      search: filters.search || undefined,
      min_risk: filters.minRisk || undefined,
      max_risk: filters.maxRisk || undefined,
      min_critical: filters.minCritical || undefined,
      min_high: filters.minHigh || undefined,
      sort_by: sortBy,
      order: sortOrder,
    }
    if (tagFilter.length) {
      params.tags = tagFilter.map(t => t.label || `${t.category}:${t.value}`).join(',')
      params.tag_logic = tagLogic
    }
    getAssets(params)
      .then(data => {
        setAssets(data)
        const scanIds = activeScanId
          ? [activeScanId]
          : [...new Set(data.map(a => a.scan_id).filter(Boolean))]
        if (scanIds.length) {
          Promise.all(scanIds.map(sid => getBlastRadiusBulk(sid)))
            .then(results => setBlastMap(Object.assign({}, ...results)))
            .catch(err => console.error('Blast radius bulk fetch failed:', err))
        }
      })
      .finally(() => setLoading(false))
  }

  const debounceRef = useRef(null)
  useEffect(() => {
    if (advancedMode) return
    clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(load, filters.search ? 300 : 0)
    return () => clearTimeout(debounceRef.current)
  }, [activeScanId, sortBy, sortOrder, tagFilter, tagLogic, filters, advancedMode])

  const runAdvancedSearch = () => {
    if (!advancedConditions.length) return
    setAdvancedLoading(true)
    advancedSearch({
      query: advancedConditions,
      query_logic: advancedLogic,
      scan_id: activeScanId,
      type: 'asset',
    }).then(data => setAssets(data.assets || []))
      .finally(() => setAdvancedLoading(false))
  }

  const enterAdvancedMode = () => {
    const conds = filtersToConditions({ ...filters, tagFilter }, 'asset')
    setAdvancedConditions(conds)
    setAdvancedLogic('AND')
    setAdvancedMode(true)
  }

  const exitAdvancedMode = () => {
    setAdvancedMode(false)
    setAdvancedConditions([])
    setAssets([])
  }

  const toggleSelect = (id) => {
    setSelectedIds(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  const toggleSelectAll = () => {
    setSelectedIds(prev => prev.size === assets.length ? new Set() : new Set(assets.map(a => a.id)))
  }

  const handleUntagAsset = async (assetId, tag) => {
    await unassignTags({ tag_ids: [tag.tag_id], asset_ids: [assetId] })
    load()
  }

  const allColumns = [
    {
      key: '_select', label: (
        <input type="checkbox" checked={assets.length > 0 && selectedIds.size === assets.length} onChange={toggleSelectAll} />
      ), width: '36px',
      render: (_, row) => (
        <input type="checkbox" checked={selectedIds.has(row.id)} onChange={() => toggleSelect(row.id)} onClick={e => e.stopPropagation()} />
      )
    },
    {
      key: 'hostname', label: 'Asset', width: '22%', sortable: true,
      render: (_, row) => (
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: 13 }}>{row.hostname || row.ip}</span>
            {row.is_domain_controller && (
              <span style={{
                display: 'inline-block', padding: '1px 5px', borderRadius: 4,
                background: '#dc262622', color: '#dc2626', border: '1px solid #dc262644',
                fontSize: 10, fontWeight: 700, lineHeight: '16px',
              }}>DC</span>
            )}
          </div>
          {row.fqdn && row.fqdn !== row.hostname && <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{row.fqdn}</div>}
          {row.ip && row.ip !== row.hostname && <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{row.ip}</div>}
          {row.tags?.length > 0 && (
            <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap', marginTop: 4 }}>
              {row.tags.map(t => (
                <TagPill key={t.tag_id} tag={t} size="xs" onRemove={(tag) => handleUntagAsset(row.id, tag)} />
              ))}
            </div>
          )}
        </div>
      )
    },
    {
      key: 'os', label: 'OS', width: '15%', sortable: true,
      render: (_, row) => <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{row.os || '—'}</span>
    },
    {
      key: 'environment_tag', label: 'Env', sortable: true,
      render: (v) => {
        const color = ENV_COLORS[v] || 'var(--text-muted)'
        return (
          <span style={{
            display: 'inline-block', padding: '2px 8px', borderRadius: 999,
            background: `${color}22`, color, border: `1px solid ${color}44`,
            fontSize: 11, fontWeight: 600, textTransform: 'capitalize',
          }}>{v || 'internal'}</span>
        )
      }
    },
    {
      key: 'criticality', label: 'Crit.', sortable: true,
      render: (_, row) => <CriticalityEditor asset={row} onUpdate={load} />
    },
    {
      key: 'critical_count', label: 'Findings', sortable: true,
      render: (_, row) => <SevCounts asset={row} />
    },
    {
      key: 'inferred_team', label: 'Owner', width: '140px',
      render: (_, row) => {
        const own = row.ownership
        const isOpen = ownershipEdit?.assetId === row.id
        const trigger = (
          <button
            onClick={e => { e.stopPropagation(); setOwnershipEdit(isOpen ? null : { assetId: row.id, current: own }) }}
            style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, textAlign: 'left', width: '100%' }}
            title="Click to edit ownership"
          >
            {own ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                <OwnerBadge owner={own.owner_role || own.owner_name} />
                {own.owner_name && <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{own.owner_name}</span>}
                <span style={{ fontSize: 9, color: '#22c55e', fontWeight: 600 }}>MANUAL</span>
              </div>
            ) : row.inferred_team ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <OwnerBadge owner={row.inferred_team} />
                  <ConfidenceDot confidence={row.owner_confidence} />
                </div>
                {row.inferred_primary_user && (
                  <span style={{ fontSize: 11, color: 'var(--text-secondary)', maxWidth: 130, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                        title={row.inferred_primary_user}>
                    {row.inferred_primary_user}
                  </span>
                )}
              </div>
            ) : (
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>+ Set owner</span>
            )}
          </button>
        )
        return (
          <div style={{ position: 'relative' }}>
            {trigger}
            {isOpen && (
              <OwnershipEditPopover
                current={own}
                onClose={() => setOwnershipEdit(null)}
                onSave={async (data) => {
                  await setAssetOwnership(row.id, data)
                  setOwnershipEdit(null)
                  load()
                }}
              />
            )}
          </div>
        )
      }
    },
    {
      key: 'risk_score', label: 'Risk Score', width: '130px', sortable: true,
      render: (v) => <RiskScore score={v} />
    },
    {
      key: 'blast_radius', label: 'Blast Radius', width: '160px',
      render: (_, row) => (
        <BlastCell
          br={blastMap[String(row.id)]}
          onExpand={() => setExpandedAsset(prev => prev === row.id ? null : row.id)}
        />
      )
    },
    {
      key: 'is_internet_facing', label: 'Internet Facing',
      render: (v) => v
        ? <span style={{ display: 'inline-block', padding: '2px 8px', borderRadius: 999, background: '#dc262622', color: '#dc2626', border: '1px solid #dc262644', fontSize: 11, fontWeight: 600 }}>Internet</span>
        : <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
    },
    {
      key: 'scan_start', label: 'Scan Start', width: '110px',
      render: (v) => {
        if (!v) return <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
        const date = new Date(v)
        return <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{date.toLocaleDateString()}</span>
      }
    },
    {
      key: 'business_context', label: 'Business Context',
      render: (v) => v
        ? <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{v}</span>
        : <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
    },
    {
      key: '_actions', label: '', width: '40px',
      render: (_, row) => <RowActions row={row} onNavigate={navigate} />,
    },
  ]

  const defaultHidden = new Set(['is_internet_facing', 'scan_start', 'business_context'])
  const visibleColumns = allColumns.filter(c =>
    c.key === '_select' || c.key === '_actions' || (colVis[c.key] !== undefined ? colVis[c.key] : !defaultHidden.has(c.key))
  )

  return (
    <div>
      <PageHeader
        title="Assets"
        subtitle={advancedMode ? `${assets.length} assets matched` : `${assets.length} assets discovered`}
        action={
          <div style={{ display: 'flex', gap: 8 }}>
            {selectedIds.size > 0 && (
              <Button size="sm" variant="ghost" onClick={() => setShowBulkTag(true)}>
                <Tag size={14} /> Tag {selectedIds.size} selected
              </Button>
            )}
            <Button variant="ghost" size="sm" onClick={() => exportDownload('assets', { scan_id: activeScanId, environment: filters.environment, search: filters.search })}>
              <Download size={14} /> Export CSV
            </Button>
            <Button variant="ghost" size="sm" onClick={load}>
              <RefreshCw size={14} /> Refresh
            </Button>
          </div>
        }
      />

      {/* Advanced search panel */}
      {advancedMode && (
        <Card style={{ marginBottom: 16, padding: '16px 18px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <SlidersHorizontal size={14} style={{ color: 'var(--accent)' }} />
              <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>Advanced Search</span>
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>— uses the full rule engine condition catalog</span>
            </div>
            <button onClick={exitAdvancedMode} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 4, fontSize: 12 }}>
              <XIcon size={13} /> Exit advanced
            </button>
          </div>
          <RuleBuilder
            conditions={advancedConditions}
            logic={advancedLogic}
            onChange={(conds, lgc) => { setAdvancedConditions(conds); setAdvancedLogic(lgc) }}
            showLogic
            addLabel="Add condition"
          />
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 12 }}>
            <Button
              onClick={runAdvancedSearch}
              disabled={advancedLoading || !advancedConditions.length}
            >
              {advancedLoading ? 'Searching…' : 'Run Search'}
            </Button>
            {assets.length > 0 && !advancedLoading && (
              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                <span style={{ color: 'var(--accent)', fontWeight: 600 }}>{assets.length}</span> assets matched
              </span>
            )}
            {advancedConditions.length > 0 && (
              <Button variant="ghost" size="sm" onClick={() => setShowSaveAs(true)} style={{ marginLeft: 'auto' }}>
                <Bookmark size={13} /> Save as…
              </Button>
            )}
          </div>
        </Card>
      )}

      {/* Filters */}
      <div style={{ display: advancedMode ? 'none' : 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 16, alignItems: 'flex-start' }}>
        <div style={{ flex: '1 1 280px', minWidth: 280, maxWidth: 480 }}>
          <NLPSearchBar
            scanId={activeScanId}
            onResult={({ asset_filters, sort }) => {
              setFilters(f => ({
                ...f,
                search: asset_filters.search || '',
                env: asset_filters.environment || f.env,
                minRisk: asset_filters.min_risk != null ? String(asset_filters.min_risk) : f.minRisk,
                minCritical: asset_filters.min_critical != null ? String(asset_filters.min_critical) : f.minCritical,
                minHigh: asset_filters.min_high != null ? String(asset_filters.min_high) : f.minHigh,
              }))
              if (sort) {
                setSearchParams(prev => {
                  const next = new URLSearchParams(prev)
                  next.set('sort', sort.sort_by)
                  next.set('order', sort.order)
                  return next
                }, { replace: true })
              }
            }}
            onClear={() => setFilters(f => ({ ...f, search: '', env: '', minRisk: '', minCritical: '', minHigh: '' }))}
          />
        </div>

        <Select
          value={filters.env}
          onChange={v => setFilters(f => ({ ...f, env: v }))}
          placeholder="All Environments"
          options={[
            { value: 'dmz', label: 'DMZ' },
            { value: 'internal', label: 'Internal' },
            { value: 'cloud', label: 'Cloud' },
            { value: 'development', label: 'Development' },
            { value: 'production', label: 'Production' },
            { value: 'staging', label: 'Staging' },
            { value: 'ot', label: 'OT/ICS' },
          ]}
        />

        <Select
          value={filters.criticality}
          onChange={v => setFilters(f => ({ ...f, criticality: v }))}
          placeholder="Any Criticality"
          options={[1,2,3,4,5,6,7,8,9,10].map(n => ({ value: String(n), label: `${n} – ${CRITICALITY_LABELS[n]}` }))}
        />

        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ fontSize: 12, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>Risk</span>
          <input
            type="number" min={0} max={10} step={0.1}
            value={filters.minRisk}
            onChange={e => setFilters(f => ({ ...f, minRisk: e.target.value }))}
            placeholder="Min"
            style={{
              width: 60, background: 'var(--bg-card)', border: '1px solid var(--border)',
              color: 'var(--text-primary)', borderRadius: 6, padding: '7px 8px', fontSize: 13, outline: 'none',
            }}
          />
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>–</span>
          <input
            type="number" min={0} max={10} step={0.1}
            value={filters.maxRisk}
            onChange={e => setFilters(f => ({ ...f, maxRisk: e.target.value }))}
            placeholder="Max"
            style={{
              width: 60, background: 'var(--bg-card)', border: '1px solid var(--border)',
              color: 'var(--text-primary)', borderRadius: 6, padding: '7px 8px', fontSize: 13, outline: 'none',
            }}
          />
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ fontSize: 12, color: '#dc2626', whiteSpace: 'nowrap' }}>Min Critical</span>
          <input
            type="number" min={0}
            value={filters.minCritical}
            onChange={e => setFilters(f => ({ ...f, minCritical: e.target.value }))}
            placeholder="0"
            style={{
              width: 56, background: 'var(--bg-card)', border: '1px solid var(--border)',
              color: 'var(--text-primary)', borderRadius: 6, padding: '7px 8px', fontSize: 13, outline: 'none',
            }}
          />
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ fontSize: 12, color: '#ea580c', whiteSpace: 'nowrap' }}>Min High</span>
          <input
            type="number" min={0}
            value={filters.minHigh}
            onChange={e => setFilters(f => ({ ...f, minHigh: e.target.value }))}
            placeholder="0"
            style={{
              width: 56, background: 'var(--bg-card)', border: '1px solid var(--border)',
              color: 'var(--text-primary)', borderRadius: 6, padding: '7px 8px', fontSize: 13, outline: 'none',
            }}
          />
        </div>

        <TagFilterBar
          tags={tagFilter}
          onChange={setTagFilter}
          logic={tagLogic}
          onLogicChange={setTagLogic}
        />

        <ColumnSelector
          columns={allColumns}
          visible={colVis}
          onChange={updateColVis}
        />

        <Button size="sm" variant="ghost" onClick={enterAdvancedMode} title="Switch to rule-engine query builder">
          <SlidersHorizontal size={13} /> Advanced
        </Button>

        {(activeFilterCount > 0 || tagFilter.length > 0) && (
          <>
            <Button size="sm" variant="ghost" onClick={() => setShowSaveAs(true)}>
              <Bookmark size={13} /> Save as…
            </Button>
            <Button size="sm" variant="ghost" onClick={() => { clearFilters(); setTagFilter([]) }}>
              <X size={13} /> Clear
            </Button>
          </>
        )}
      </div>

      {(loading || advancedLoading) ? <Spinner /> : (
        assets.length === 0 ? (
          <EmptyState icon={Server}
            title={advancedMode ? "No assets matched" : "No assets found"}
            sub={advancedMode ? "Build conditions above and click Run Search" : "Upload a Nessus scan to populate asset inventory"}
          />
        ) : (
          <Card style={{ padding: 0 }}>
            <Table
              columns={visibleColumns}
              rows={assets}
              onRowClick={row => navigate(`/findings?asset_id=${row.id}`)}
              onSort={handleSort}
              sortBy={sortBy}
              sortOrder={sortOrder}
              emptyMessage="No assets match the current filters"
            />
          </Card>
        )
      )}

      {showBulkTag && (
        <BulkTagModal
          assetIds={[...selectedIds]}
          onClose={() => setShowBulkTag(false)}
          onDone={() => { setShowBulkTag(false); setSelectedIds(new Set()); load() }}
        />
      )}

      {showSaveAs && (
        <SaveAsRuleModal
          conditions={advancedMode ? advancedConditions : filtersToConditions({ ...filters, tagFilter }, 'asset')}
          scanId={activeScanId}
          onClose={() => setShowSaveAs(false)}
          onCreated={(type, result) => {
            setShowSaveAs(false)
            if (type === 'campaign') navigate(`/campaigns/${result.id}`)
          }}
        />
      )}

      {/* Blast Radius sidebar */}
      {expandedAsset && (activeScanId || assets.find(a => a.id === expandedAsset)?.scan_id) && (
        <>
          {/* Backdrop */}
          <div
            onClick={() => setExpandedAsset(null)}
            style={{
              position: 'fixed', inset: 0, zIndex: 900,
              background: 'rgba(0,0,0,0.3)',
            }}
          />
          {/* Slide-in panel */}
          <ResizablePanel onClose={() => setExpandedAsset(null)}>
            {/* Header */}
            <div style={{
              display: 'flex', alignItems: 'center', gap: 10,
              padding: '14px 20px', borderBottom: '1px solid var(--border)', flexShrink: 0,
            }}>
              <Crosshair size={15} color="var(--accent)" />
              <span style={{ flex: 1, fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>
                Blast Radius — {assets.find(a => a.id === expandedAsset)?.hostname ||
                                assets.find(a => a.id === expandedAsset)?.ip}
              </span>
              <button
                onClick={() => setExpandedAsset(null)}
                style={{
                  background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                  borderRadius: 6, padding: '4px 10px', cursor: 'pointer',
                  fontSize: 13, color: 'var(--text-muted)', lineHeight: 1,
                }}
              >
                <X size={14} />
              </button>
            </div>
            {/* Content */}
            <div style={{ flex: 1, overflow: 'auto', padding: 16 }}>
              <BlastRadiusPanel
                scanId={activeScanId || assets.find(a => a.id === expandedAsset)?.scan_id}
                assetId={expandedAsset}
                defaultExpanded={true}
              />
            </div>
          </ResizablePanel>
          <style>{`
            @keyframes slideInRight {
              from { transform: translateX(100%); }
              to { transform: translateX(0); }
            }
          `}</style>
        </>
      )}
    </div>
  )
}
