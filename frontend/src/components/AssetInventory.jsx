import React, { useState, useEffect, useRef } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { Server, RefreshCw, Edit2, Tag, Search, X } from 'lucide-react'
import { useScan } from '../App.jsx'
import { getAssets, updateAsset, getBlastRadius, assignTags, unassignTags } from '../api.js'
import { Card, ScoreBar, Table, PageHeader, Select, Spinner, EmptyState, Button, TagPill, TagFilterBar, TagPicker } from './ui.jsx'
import BlastRadiusPanel, { BlastRadiusScore } from './BlastRadiusPanel.jsx'

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

  const LABELS = { 1: 'Very Low', 2: 'Low', 3: 'Medium', 4: 'High', 5: 'Critical' }

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
        {[1,2,3,4,5].map(n => <option key={n} value={n}>{n} – {LABELS[n]}</option>)}
      </select>
      <Button size="sm" onClick={save}>Save</Button>
      <Button size="sm" variant="ghost" onClick={() => setEditing(false)}>✕</Button>
    </div>
  )
}

const ENV_COLORS = { internet: '#dc2626', dmz: '#ea580c', internal: '#65a30d', ot: '#d97706' }

// Lazy-loaded blast radius score per asset
function BlastCell({ scanId, assetId, onExpand }) {
  const [br, setBr] = useState(null)

  useEffect(() => {
    if (!scanId || !assetId) return
    getBlastRadius(scanId, assetId)
      .then(setBr)
      .catch(() => {})
  }, [scanId, assetId])

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

const CRITICALITY_LABELS = { 1: 'Very Low', 2: 'Low', 3: 'Medium', 4: 'High', 5: 'Critical' }

export default function AssetInventory() {
  const { activeScanId } = useScan()
  const [assets, setAssets] = useState([])
  const [loading, setLoading] = useState(true)
  const [expandedAsset, setExpandedAsset] = useState(null)
  const [selectedIds, setSelectedIds] = useState(new Set())
  const [showBulkTag, setShowBulkTag] = useState(false)
  const [tagFilter, setTagFilter] = useState([])
  const [tagLogic, setTagLogic] = useState('AND')
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
      .then(setAssets)
      .finally(() => setLoading(false))
  }

  const debounceRef = useRef(null)
  useEffect(() => {
    clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(load, filters.search ? 300 : 0)
    return () => clearTimeout(debounceRef.current)
  }, [activeScanId, sortBy, sortOrder, tagFilter, tagLogic, filters])

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

  const columns = [
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
          <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: 13 }}>{row.hostname || row.ip}</div>
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
      key: 'risk_score', label: 'Risk Score', width: '130px', sortable: true,
      render: (v) => <RiskScore score={v} />
    },
    {
      key: 'blast_radius', label: 'Blast Radius', width: '160px',
      render: (_, row) => (
        <BlastCell
          scanId={activeScanId}
          assetId={row.id}
          onExpand={() => setExpandedAsset(prev => prev === row.id ? null : row.id)}
        />
      )
    },
  ]

  return (
    <div>
      <PageHeader
        title="Assets"
        subtitle={`${assets.length} assets discovered`}
        action={
          <div style={{ display: 'flex', gap: 8 }}>
            {selectedIds.size > 0 && (
              <Button size="sm" variant="ghost" onClick={() => setShowBulkTag(true)}>
                <Tag size={14} /> Tag {selectedIds.size} selected
              </Button>
            )}
            <Button variant="ghost" size="sm" onClick={load}>
              <RefreshCw size={14} /> Refresh
            </Button>
          </div>
        }
      />

      {/* Filters */}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 16, alignItems: 'center' }}>
        <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
          <Search size={14} style={{ position: 'absolute', left: 10, color: 'var(--text-muted)' }} />
          <input
            value={filters.search}
            onChange={e => setFilters(f => ({ ...f, search: e.target.value }))}
            placeholder="Search hostname, IP, OS…"
            style={{
              background: 'var(--bg-card)', border: '1px solid var(--border)',
              color: 'var(--text-primary)', borderRadius: 6, padding: '7px 12px 7px 32px',
              fontSize: 13, outline: 'none', width: 220,
            }}
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
          options={[1,2,3,4,5].map(n => ({ value: String(n), label: `${n} – ${CRITICALITY_LABELS[n]}` }))}
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

        {(activeFilterCount > 0 || tagFilter.length > 0) && (
          <Button size="sm" variant="ghost" onClick={() => { clearFilters(); setTagFilter([]) }}>
            <X size={13} /> Clear
          </Button>
        )}
      </div>

      {loading ? <Spinner /> : (
        assets.length === 0 ? (
          <EmptyState icon={Server} title="No assets found" sub="Upload a Nessus scan to populate asset inventory" />
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
            <Card style={{ padding: 0 }}>
              <Table
                columns={columns}
                rows={assets}
                onRowClick={row => navigate(`/findings?asset_id=${row.id}`)}
                onSort={handleSort}
                sortBy={sortBy}
                sortOrder={sortOrder}
                emptyMessage="No assets match the current filters"
              />
            </Card>

            {/* Inline blast radius panel for expanded asset */}
            {expandedAsset && activeScanId && (
              <Card style={{ marginTop: 12, padding: 0 }}>
                <div style={{ padding: '10px 16px', borderBottom: '1px solid var(--border)',
                  display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>
                    Blast Radius — {assets.find(a => a.id === expandedAsset)?.hostname ||
                                    assets.find(a => a.id === expandedAsset)?.ip}
                  </span>
                  <button
                    onClick={() => setExpandedAsset(null)}
                    style={{ marginLeft: 'auto', background: 'none', border: 'none',
                      cursor: 'pointer', color: 'var(--text-muted)', fontSize: 18, lineHeight: 1 }}
                  >×</button>
                </div>
                <div style={{ padding: 16 }}>
                  <BlastRadiusPanel
                    scanId={activeScanId}
                    assetId={expandedAsset}
                    defaultExpanded={true}
                  />
                </div>
              </Card>
            )}
          </div>
        )
      )}

      {showBulkTag && (
        <BulkTagModal
          assetIds={[...selectedIds]}
          onClose={() => setShowBulkTag(false)}
          onDone={() => { setShowBulkTag(false); setSelectedIds(new Set()); load() }}
        />
      )}
    </div>
  )
}
