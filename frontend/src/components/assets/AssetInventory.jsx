import React, { useState, useEffect, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate, useSearchParams } from 'react-router-dom'
import useURLFilters from '../../hooks/useURLFilters.js'
import { Server, RefreshCw, Edit2, Tag, X, Crosshair, Download, Bookmark, SlidersHorizontal, X as XIcon, Database, MoreHorizontal, AlertTriangle, ChevronLeft, ChevronRight, Zap, Radar } from 'lucide-react'
import { useScan } from '../../App.jsx'
import { getAssets, updateAsset, getBlastRadiusBulk, assignTags, unassignTags, confirmAssetOwner, exportDownload, advancedSearch, setAssetOwnership, getSBOMComponents, syncEasmAssets, getEasmStatus, getTags, createCampaign, startVmScan } from '../../api.js'
import { Card, ScoreBar, Table, PageHeader, Select, Spinner, EmptyState, Button, TagPill, TagFilterBar, TagPicker, OwnerBadge, ConfidenceDot, ColumnSelector, SaveAsRuleModal, OwnershipEditPopover, ContextEditPopover, SourceDots, SourceFilter, ErrorBanner, SkeletonTable } from '../shared/ui.jsx'
import RuleBuilder from '../campaigns/RuleBuilder.jsx'
import { filtersToConditions } from '../../utils/filtersToConditions.js'
import BlastRadiusPanel, { BlastRadiusScore } from '../campaigns/BlastRadiusPanel.jsx'
import NLPSearchBar from '../shared/NLPSearchBar.jsx'

function RiskScore({ score }) {
  const color = score >= 8 ? 'var(--critical)' : score >= 6 ? 'var(--high)' : score >= 4 ? 'var(--medium)' : 'var(--low)'
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
  const { t } = useTranslation()
  const [editing, setEditing] = useState(false)
  const [val, setVal] = useState(asset.criticality)

  const save = async () => {
    await updateAsset(asset.id, { criticality: val })
    onUpdate()
    setEditing(false)
  }

  const LABELS = Object.fromEntries([1,2,3,4,5,6,7,8,9,10].map(n => [n, t(`assets.critLabels.${n}`)]))

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
      <Button size="sm" onClick={save}>{t('common.save')}</Button>
      <Button size="sm" variant="ghost" onClick={() => setEditing(false)}>✕</Button>
    </div>
  )
}

const ENV_COLORS = { internet: 'var(--critical)', dmz: 'var(--high)', internal: 'var(--low)', ot: 'var(--medium)' }

function RowActions({ row, onNavigate }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

  useEffect(() => {
    if (!open) return
    const handler = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [open])

  const items = [
    { icon: AlertTriangle, label: t('assets.viewFindings'), action: () => onNavigate(`/assets/${row.id}?tab=findings`) },
    { icon: Database, label: t('assets.viewInventory'), action: () => onNavigate(`/assets/${row.id}?tab=inventory`) },
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
  const { t } = useTranslation()
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
          {t('assets.tagCount', { count: assetIds.length })}
        </div>
        <TagPicker selectedTags={selected} onChange={setSelected} placeholder={t('findings.searchTags')} />
        <div style={{ display: 'flex', gap: 8 }}>
          <Button onClick={apply} disabled={saving || !selected.length}>
            <Tag size={14} /> {saving ? t('findings.applying') : t('findings.applyTags')}
          </Button>
          <Button variant="ghost" onClick={onClose}>{t('common.cancel')}</Button>
        </div>
      </div>
    </div>
  )
}

// Bulk campaign modal
function BulkCampaignModal({ selectedAssets, scanId, onClose, onCreated }) {
  const [name, setName] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(null)

  const handleCreate = async () => {
    if (!name.trim()) { setError('Name is required'); return }
    setSaving(true); setError(null)
    try {
      // Build valid rule-engine conditions using ip (preferred) or hostname
      const conditions = selectedAssets.map(a => {
        if (a.ip) return { field: 'ip', op: 'eq', value: a.ip }
        if (a.hostname) return { field: 'hostname', op: 'eq', value: a.hostname }
        return { field: 'fqdn', op: 'eq', value: a.fqdn }
      }).filter(c => c.value)
      if (conditions.length === 0) { setError('Selected assets have no IP, hostname, or FQDN'); setSaving(false); return }
      const result = await createCampaign({
        name: name.trim(),
        scan_id: scanId || null,
        query: conditions,
        query_logic: 'OR',
        status: 'planned',
      })
      onCreated(result)
    } catch (e) {
      setError(e.message || 'Failed to create campaign')
      setSaving(false)
    }
  }

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 1000,
      background: 'rgba(0,0,0,0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center',
    }} onClick={e => { if (e.target === e.currentTarget) onClose() }}>
      <div style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 12,
        padding: 24, width: 420, display: 'flex', flexDirection: 'column', gap: 14,
        boxShadow: '0 8px 32px rgba(0,0,0,0.3)',
      }}>
        <div style={{ fontSize: 15, fontWeight: 700 }}>
          <Zap size={15} style={{ verticalAlign: 'middle', marginRight: 6, color: 'var(--accent)' }} />
          Create Campaign from {selectedAssets.length} asset{selectedAssets.length !== 1 ? 's' : ''}
        </div>
        <div>
          <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Campaign name</label>
          <input
            autoFocus
            value={name}
            onChange={e => setName(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleCreate()}
            placeholder="e.g. Q2 Remediation"
            style={{
              width: '100%', background: 'var(--bg)', border: '1px solid var(--border)',
              color: 'var(--text-primary)', borderRadius: 6, padding: '7px 10px',
              fontSize: 13, outline: 'none', boxSizing: 'border-box',
            }}
          />
        </div>
        {error && <div style={{ fontSize: 12, color: 'var(--critical)' }}>{error}</div>}
        <div style={{ display: 'flex', gap: 8 }}>
          <Button onClick={handleCreate} disabled={saving || !name.trim()}>
            <Zap size={14} /> {saving ? 'Creating…' : 'Create Campaign'}
          </Button>
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
        </div>
      </div>
    </div>
  )
}

const ASSET_FILTER_SCHEMA = {
  search: { default: '' },
  env: { default: '' },
  criticality: { default: '' },
  minRisk: { default: '' },
  maxRisk: { default: '' },
  minCritical: { default: '' },
  minHigh: { default: '' },
  serverRole: { default: '' },
  source: { default: '' },
  minSources: { default: '' },
  sort: { default: 'risk_score' },
  order: { default: 'desc' },
  page: { default: 1, type: 'number' },
}

export default function AssetInventory() {
  const { t } = useTranslation()
  const ASSET_PAGE_SIZE = 25
  const { activeScanId } = useScan()
  const CRITICALITY_LABELS = Object.fromEntries([1,2,3,4,5,6,7,8,9,10].map(n => [n, t(`assets.critLabels.${n}`)]))
  const { filters, setFilter, setFilters: setURLFilters, clearFilters } = useURLFilters(ASSET_FILTER_SCHEMA)
  const page = filters.page || 1
  const sortBy = filters.sort || 'risk_score'
  const sortOrder = filters.order || 'desc'

  const [assets, setAssets] = useState([])
  const [totalAssets, setTotalAssets] = useState(0)
  const [loading, setLoading] = useState(true)
  const [blastMap, setBlastMap] = useState({})
  const [sbomRiskMap, setSbomRiskMap] = useState({})
  const [expandedAsset, setExpandedAsset] = useState(null)
  const [selectedIds, setSelectedIds] = useState(new Set())
  const [showBulkTag, setShowBulkTag] = useState(false)
  const [showSaveAs, setShowSaveAs] = useState(false)
  const [showBulkCampaign, setShowBulkCampaign] = useState(false)
  const [bulkScanState, setBulkScanState] = useState(null) // null | 'scanning' | 'done' | 'error'
  const [bulkScanError, setBulkScanError] = useState(null)
  const [tagFilter, setTagFilter] = useState([])
  const [tagLogic, setTagLogic] = useState('AND')
  const [ownershipEdit, setOwnershipEdit] = useState(null) // { assetId, current, anchorRef }
  const [contextEdit, setContextEdit] = useState(null) // { assetId, field, currentValue }
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()

  // Sync tagFilter from URL ?tags= param on mount
  const tagsSynced = useRef(false)
  useEffect(() => {
    if (tagsSynced.current) return
    const urlTags = searchParams.get('tags')
    if (!urlTags) return
    tagsSynced.current = true
    const tagStrings = urlTags.split(',').map(s => s.trim()).filter(Boolean)
    if (!tagStrings.length) return
    getTags().then(allTags => {
      const matched = tagStrings.map(ts => {
        const [cat, ...rest] = ts.split(':')
        const val = rest.join(':')
        // Try matching by label first, then by category:value
        return allTags.find(t => t.label === ts) ||
               allTags.find(t => t.category === cat && t.value === val)
      }).filter(Boolean).map(t => ({ tag_id: t.id, label: t.label, category: t.category, value: t.value, color: t.color }))
      if (matched.length) setTagFilter(matched)
    }).catch(() => {})
  }, [searchParams])

  // Advanced rule-engine search
  const [advancedMode, setAdvancedMode] = useState(false)
  const [advancedConditions, setAdvancedConditions] = useState([])
  const [advancedLogic, setAdvancedLogic] = useState('AND')
  const [advancedLoading, setAdvancedLoading] = useState(false)
  const [fetchError, setFetchError] = useState(null)
  const [colVis, setColVis] = useState(() => {
    try { const s = localStorage.getItem('assetColumns'); return s ? JSON.parse(s) : {} } catch { return {} }
  })
  const updateColVis = (next) => { setColVis(next); localStorage.setItem('assetColumns', JSON.stringify(next)) }

  const handleSort = (key) => {
    if (sortBy === key) {
      setFilter('order', sortOrder === 'asc' ? 'desc' : 'asc')
    } else {
      setURLFilters({ sort: key, order: 'desc' })
    }
  }

  const activeFilterCount = ['search', 'env', 'criticality', 'minRisk', 'maxRisk', 'minCritical', 'minHigh', 'serverRole', 'source', 'minSources']
    .filter(k => filters[k]).length

  const load = () => {
    setLoading(true)
    setFetchError(null)
    const params = {
      scan_id: activeScanId,
      environment: filters.env || undefined,
      criticality: filters.criticality || undefined,
      search: filters.search || undefined,
      min_risk: filters.minRisk || undefined,
      max_risk: filters.maxRisk || undefined,
      min_critical: filters.minCritical || undefined,
      min_high: filters.minHigh || undefined,
      server_role: filters.serverRole || undefined,
      source: filters.source || undefined,
      min_sources: filters.minSources || undefined,
      sort_by: sortBy,
      order: sortOrder,
      page,
      page_size: ASSET_PAGE_SIZE,
    }
    if (tagFilter.length) {
      params.tags = tagFilter.map(t => t.label || `${t.category}:${t.value}`).join(',')
      params.tag_logic = tagLogic
    }
    getAssets(params)
      .then(data => {
        setAssets(data.assets)
        setTotalAssets(data.total)
        const assetList = data.assets
        const scanIds = activeScanId
          ? [activeScanId]
          : [...new Set(assetList.map(a => a.scan_id).filter(Boolean))]
        if (scanIds.length) {
          Promise.all(scanIds.map(sid => getBlastRadiusBulk(sid)))
            .then(results => setBlastMap(Object.assign({}, ...results)))
            .catch(err => console.error('Blast radius bulk fetch failed:', err))
          // Fetch SBOM risk per asset
          Promise.all(scanIds.map(sid => getSBOMComponents({ scan_id: sid, page_size: 0 })))
            .then(results => {
              const riskMap = {}
              for (const data of results) {
                for (const c of (data.components || [])) {
                  if (!riskMap[c.asset_id]) riskMap[c.asset_id] = { p1: 0, p2: 0, cves: 0, eol: 0 }
                  if (c.priority_tier === 'P1') riskMap[c.asset_id].p1++
                  if (c.priority_tier === 'P2') riskMap[c.asset_id].p2++
                  riskMap[c.asset_id].cves += (c.cve_count || 0)
                  if (c.eol_status === 'eol' || c.eol_status === 'approaching_eol') riskMap[c.asset_id].eol++
                }
              }
              setSbomRiskMap(riskMap)
            })
            .catch(() => {})
        }
      })
      .catch(() => setFetchError('Failed to load assets.'))
      .finally(() => setLoading(false))
  }

  // Page reset is handled by useURLFilters (setFilter auto-resets page)

  const debounceRef = useRef(null)
  useEffect(() => {
    if (advancedMode) return
    clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(load, filters.search ? 300 : 0)
    return () => clearTimeout(debounceRef.current)
  }, [activeScanId, sortBy, sortOrder, tagFilter, tagLogic, filters, advancedMode, page])

  // EASM sync is intentionally NOT auto-triggered on mount — it runs the full import
  // pipeline (N+1 queries + finalize_scan) and caused 20s+ page loads. Sync is
  // triggered manually or via scheduled tasks instead.

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

  const handleBulkScan = async () => {
    const selectedAssets = assets.filter(a => selectedIds.has(a.id))
    const assetEntries = selectedAssets.map(a => ({
      asset_id: a.id,
      target: a.ip || a.hostname || a.fqdn,
    })).filter(e => e.target)
    if (assetEntries.length === 0) {
      setBulkScanError('Selected assets have no IP or hostname')
      setBulkScanState('error')
      return
    }
    setBulkScanState('scanning')
    setBulkScanError(null)
    try {
      await startVmScan({
        targets: assetEntries.map(e => e.target),
        asset_ids: assetEntries.map(e => e.asset_id),
      })
      setBulkScanState('done')
      setTimeout(() => { setBulkScanState(null); setSelectedIds(new Set()) }, 3000)
    } catch (err) {
      setBulkScanError(err.message)
      setBulkScanState('error')
    }
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
      key: 'hostname', label: t('assets.title'), width: '22%', sortable: true,
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
            {(row.server_roles || []).map(role => {
              const ROLE_COLORS = {
                web_server: { bg: '#0ea5e922', color: '#0ea5e9', border: '#0ea5e944' },
                dns_server: { bg: '#8b5cf622', color: '#8b5cf6', border: '#8b5cf644' },
                database: { bg: '#f59e0b22', color: '#f59e0b', border: '#f59e0b44' },
                mail_server: { bg: '#10b98122', color: '#10b981', border: '#10b98144' },
                ftp_server: { bg: '#6b728022', color: '#6b7280', border: '#6b728044' },
                domain_controller: null,
              }
              const ROLE_LABELS = { web_server: 'WEB', dns_server: 'DNS', database: 'DB', mail_server: 'MAIL', ftp_server: 'FTP', domain_controller: null }
              const c = ROLE_COLORS[role]
              const label = ROLE_LABELS[role]
              if (!c || !label) return null
              return (
                <span key={role} style={{
                  display: 'inline-block', padding: '1px 5px', borderRadius: 4,
                  background: c.bg, color: c.color, border: `1px solid ${c.border}`,
                  fontSize: 10, fontWeight: 700, lineHeight: '16px',
                }}>{label}</span>
              )
            })}
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
      key: 'os', label: t('assets.os'), width: '15%', sortable: true,
      render: (_, row) => <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{row.os || '—'}</span>
    },
    {
      key: 'source_systems', label: 'Source', width: '90px',
      render: (v) => <SourceDots sources={v} />
    },
    {
      key: 'environment_tag', label: t('assets.env'), sortable: true,
      render: (v, row) => {
        const color = ENV_COLORS[v] || 'var(--text-muted)'
        const confirmed = row.environment_confirmed
        const isOpen = contextEdit?.assetId === row.id && contextEdit?.field === 'environment'
        return (
          <div style={{ position: 'relative' }}>
            <button
              onClick={e => { e.stopPropagation(); setContextEdit(isOpen ? null : { assetId: row.id, field: 'environment', currentValue: v }) }}
              style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, textAlign: 'left' }}
              title="Click to edit environment"
            >
              <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                <span style={{
                  display: 'inline-block', padding: '2px 8px', borderRadius: 999,
                  background: `${color}22`, color, border: `1px solid ${color}44`,
                  fontSize: 11, fontWeight: 600, textTransform: 'capitalize',
                }}>{v || 'internal'}</span>
                {confirmed
                  ? <span style={{ fontSize: 9, color: '#22c55e', fontWeight: 600 }}>{t('assets.confirmed')}</span>
                  : <span style={{ fontSize: 9, color: 'var(--text-muted)', fontWeight: 600 }}>{t('assets.inferred')}</span>}
              </div>
            </button>
            {isOpen && (
              <ContextEditPopover
                field="environment"
                currentValue={v}
                onClose={() => setContextEdit(null)}
                onConfirm={async () => {
                  await updateAsset(row.id, { environment_confirmed: true })
                  setContextEdit(null); load()
                }}
                onSave={async (val) => {
                  await updateAsset(row.id, { environment_tag: val })
                  setContextEdit(null); load()
                }}
              />
            )}
          </div>
        )
      }
    },
    {
      key: 'criticality', label: t('assets.crit'), sortable: true,
      render: (_, row) => <CriticalityEditor asset={row} onUpdate={load} />
    },
    {
      key: 'critical_count', label: t('assets.findingsCount'), sortable: true,
      render: (_, row) => <SevCounts asset={row} />
    },
    {
      key: 'inferred_team', label: t('findings.owner'), width: '140px',
      render: (_, row) => {
        const own = row.ownership
        const inferredOwn = !own && (row.inferred_team || row.inferred_primary_user)
          ? { owner_role: row.inferred_team, owner_name: row.inferred_primary_user }
          : null
        const currentOwn = own || inferredOwn
        const isOpen = ownershipEdit?.assetId === row.id
        const trigger = (
          <button
            onClick={e => { e.stopPropagation(); setOwnershipEdit(isOpen ? null : { assetId: row.id, current: currentOwn }) }}
            style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, textAlign: 'left', width: '100%' }}
            title="Click to edit ownership"
          >
            {own ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                <OwnerBadge owner={own.owner_role || own.owner_name} />
                {own.owner_name && <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{own.owner_name}</span>}
                <span style={{ fontSize: 9, color: '#22c55e', fontWeight: 600 }}>{t('assets.manual')}</span>
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
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{t('assets.setOwner')}</span>
            )}
          </button>
        )
        return (
          <div style={{ position: 'relative' }}>
            {trigger}
            {isOpen && (
              <OwnershipEditPopover
                current={currentOwn}
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
      key: 'risk_score', label: t('assets.riskScore'), width: '130px', sortable: true,
      render: (v) => <RiskScore score={v} />
    },
    {
      key: 'blast_radius', label: t('assets.blastRadius'), width: '160px',
      render: (_, row) => (
        <BlastCell
          br={blastMap[String(row.id)]}
          onExpand={() => setExpandedAsset(prev => prev === row.id ? null : row.id)}
        />
      )
    },
    {
      key: 'sbom_risk', label: 'SBOM', width: '80px',
      render: (_, row) => {
        const risk = sbomRiskMap[row.id]
        if (!risk || (risk.p1 === 0 && risk.p2 === 0 && risk.cves === 0 && risk.eol === 0)) return null
        const color = risk.p1 > 0 ? '#dc2626' : risk.p2 > 0 ? '#ea580c' : risk.eol > 0 ? '#d97706' : '#3b82f6'
        return (
          <span title={`P1:${risk.p1} P2:${risk.p2} CVEs:${risk.cves} EOL:${risk.eol}`} style={{
            display: 'inline-flex', alignItems: 'center', gap: 3,
            fontSize: 10, fontWeight: 700, padding: '1px 7px',
            borderRadius: 9999, background: color + '18', color,
          }}>
            <AlertTriangle size={10} />
            {risk.p1 > 0 ? `${risk.p1} P1` : risk.p2 > 0 ? `${risk.p2} P2` : `${risk.cves} CVE`}
          </span>
        )
      }
    },
    {
      key: 'is_internet_facing', label: t('assets.internetFacing'),
      render: (v) => v
        ? <span style={{ display: 'inline-block', padding: '2px 8px', borderRadius: 999, background: '#dc262622', color: '#dc2626', border: '1px solid #dc262644', fontSize: 11, fontWeight: 600 }}>{t('assets.internet')}</span>
        : <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
    },
    {
      key: 'scan_start', label: t('assets.scanStart'), width: '110px',
      render: (v) => {
        if (!v) return <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
        const date = new Date(v)
        return <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{date.toLocaleDateString()}</span>
      }
    },
    {
      key: 'business_context', label: t('assets.businessContext'),
      render: (v, row) => {
        const confirmed = row.business_context_confirmed
        const isOpen = contextEdit?.assetId === row.id && contextEdit?.field === 'business_context'
        const revenueColors = { none: '#6b7280', low: '#22c55e', medium: '#eab308', high: '#f97316', critical: '#dc2626' }
        return (
          <div style={{ position: 'relative' }}>
            <button
              onClick={e => { e.stopPropagation(); setContextEdit(isOpen ? null : { assetId: row.id, field: 'business_context', currentValue: v }) }}
              style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, textAlign: 'left' }}
              title="Click to edit business context"
            >
              {(v || row.biz_num_users != null || row.biz_revenue_impact) ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                  {v && <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{v}</span>}
                  <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
                    {row.biz_num_users != null && <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>{row.biz_num_users} users</span>}
                    {row.biz_revenue_impact && <span style={{ fontSize: 10, fontWeight: 600, color: revenueColors[row.biz_revenue_impact] || 'var(--text-muted)', textTransform: 'uppercase' }}>{row.biz_revenue_impact}</span>}
                  </div>
                  {confirmed
                    ? <span style={{ fontSize: 9, color: '#22c55e', fontWeight: 600 }}>{t('assets.confirmed')}</span>
                    : <span style={{ fontSize: 9, color: 'var(--text-muted)', fontWeight: 600 }}>{t('assets.inferred')}</span>}
                </div>
              ) : (
                <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{t('assets.setContext')}</span>
              )}
            </button>
            {isOpen && (
              <ContextEditPopover
                field="business_context"
                currentValue={v}
                assetData={row}
                onClose={() => setContextEdit(null)}
                onConfirm={v ? async () => {
                  await updateAsset(row.id, { business_context_confirmed: true })
                  setContextEdit(null); load()
                } : null}
                onSave={async (val, extra) => {
                  await updateAsset(row.id, { business_context: val, ...extra })
                  setContextEdit(null); load()
                }}
              />
            )}
          </div>
        )
      }
    },
    {
      key: 'biz_revenue_impact', label: t('assets.revenueImpact'),
      render: (v) => {
        if (!v) return <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>—</span>
        const colors = { none: '#6b7280', low: '#22c55e', medium: '#eab308', high: '#f97316', critical: '#dc2626' }
        return <span style={{ fontSize: 11, fontWeight: 600, color: colors[v] || 'var(--text-secondary)', textTransform: 'uppercase' }}>{v}</span>
      },
    },
    {
      key: '_actions', label: '', width: '40px',
      render: (_, row) => <RowActions row={row} onNavigate={navigate} />,
    },
  ]

  const defaultHidden = new Set(['is_internet_facing', 'scan_start', 'biz_revenue_impact', 'sbom_risk', 'source_systems'])
  const visibleColumns = allColumns.filter(c =>
    c.key === '_select' || c.key === '_actions' || (colVis[c.key] !== undefined ? colVis[c.key] : !defaultHidden.has(c.key))
  )

  return (
    <div>
      <PageHeader
        title={t('assets.title')}
        subtitle={advancedMode ? t('assets.assetsMatched', { count: assets.length }) : t('assets.assetsDiscovered', { count: totalAssets })}
        action={
          <div style={{ display: 'flex', gap: 8 }}>
            {selectedIds.size > 0 && (
              <>
                <Button size="sm" variant="ghost" onClick={() => setShowBulkTag(true)}>
                  <Tag size={14} /> {t('assets.tagSelected', { count: selectedIds.size })}
                </Button>
                <Button size="sm" variant="ghost" onClick={() => setShowBulkCampaign(true)}>
                  <Zap size={14} /> Campaign
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={handleBulkScan}
                  disabled={bulkScanState === 'scanning'}
                  style={bulkScanState === 'done' ? { color: 'var(--success)' } : bulkScanState === 'error' ? { color: 'var(--critical)' } : {}}
                >
                  <Radar size={14} />
                  {bulkScanState === 'scanning' ? 'Scanning…' : bulkScanState === 'done' ? 'Queued!' : bulkScanState === 'error' ? 'Failed' : 'Scan'}
                </Button>
              </>
            )}
            <Button variant="ghost" size="sm" onClick={() => exportDownload('assets', { scan_id: activeScanId, environment: filters.env, search: filters.search })}>
              <Download size={14} /> {t('assets.exportCsv')}
            </Button>
            <Button variant="ghost" size="sm" onClick={load}>
              <RefreshCw size={14} /> {t('common.refresh')}
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
              <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>{t('assets.advancedSearch')}</span>
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>— {t('assets.advancedSearchHint')}</span>
            </div>
            <button onClick={exitAdvancedMode} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 4, fontSize: 12 }}>
              <XIcon size={13} /> {t('assets.exitAdvanced')}
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
              {advancedLoading ? t('assets.searching') : t('assets.runSearch')}
            </Button>
            {assets.length > 0 && !advancedLoading && (
              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                {t('assets.assetsMatched', { count: assets.length })}
              </span>
            )}
            {advancedConditions.length > 0 && (
              <Button variant="ghost" size="sm" onClick={() => setShowSaveAs(true)} style={{ marginLeft: 'auto' }}>
                <Bookmark size={13} /> {t('assets.saveAs')}
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
              const updates = {
                search: asset_filters.search || '',
                env: asset_filters.environment || filters.env,
                minRisk: asset_filters.min_risk != null ? String(asset_filters.min_risk) : filters.minRisk,
                minCritical: asset_filters.min_critical != null ? String(asset_filters.min_critical) : filters.minCritical,
                minHigh: asset_filters.min_high != null ? String(asset_filters.min_high) : filters.minHigh,
                source: asset_filters.source || '',
                minSources: asset_filters.min_sources != null ? String(asset_filters.min_sources) : filters.minSources,
              }
              if (sort) {
                updates.sort = sort.sort_by
                updates.order = sort.order
              }
              setURLFilters(updates)
            }}
            onClear={() => setURLFilters({ search: '', env: '', minRisk: '', minCritical: '', minHigh: '', source: '', minSources: '' })}
          />
        </div>

        <Select
          value={filters.env}
          onChange={v => setFilter('env', v)}
          placeholder={t('assets.allEnvironments')}
          options={[
            { value: 'internet', label: t('assets.envOptions.internet') },
            { value: 'external', label: t('assets.envOptions.external') },
            { value: 'dmz', label: t('assets.envOptions.dmz') },
            { value: 'internal', label: t('assets.envOptions.internal') },
            { value: 'cloud', label: t('assets.envOptions.cloud') },
            { value: 'development', label: t('assets.envOptions.development') },
            { value: 'production', label: t('assets.envOptions.production') },
            { value: 'staging', label: t('assets.envOptions.staging') },
            { value: 'ot', label: t('assets.envOptions.ot') },
          ]}
        />

        <SourceFilter
          value={filters.source}
          onChange={v => setFilter('source', v)}
        />

        <Select
          value={filters.criticality}
          onChange={v => setFilter('criticality', v)}
          placeholder={t('assets.anyCriticality')}
          options={[1,2,3,4,5,6,7,8,9,10].map(n => ({ value: String(n), label: `${n} – ${CRITICALITY_LABELS[n]}` }))}
        />

        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ fontSize: 12, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>{t('assets.risk')}</span>
          <input
            type="number" min={0} max={10} step={0.1}
            value={filters.minRisk}
            onChange={e => setFilter('minRisk', e.target.value)}
            placeholder={t('assets.min')}
            style={{
              width: 60, background: 'var(--bg-card)', border: '1px solid var(--border)',
              color: 'var(--text-primary)', borderRadius: 6, padding: '7px 8px', fontSize: 13, outline: 'none',
            }}
          />
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>–</span>
          <input
            type="number" min={0} max={10} step={0.1}
            value={filters.maxRisk}
            onChange={e => setFilter('maxRisk', e.target.value)}
            placeholder={t('assets.max')}
            style={{
              width: 60, background: 'var(--bg-card)', border: '1px solid var(--border)',
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
          <SlidersHorizontal size={13} /> {t('assets.advanced')}
        </Button>

        {(activeFilterCount > 0 || tagFilter.length > 0) && (
          <>
            <Button size="sm" variant="ghost" onClick={() => setShowSaveAs(true)}>
              <Bookmark size={13} /> {t('assets.saveAs')}
            </Button>
            <Button size="sm" variant="ghost" onClick={() => { clearFilters(); setTagFilter([]); setTagLogic('AND') }}>
              <X size={13} /> {t('assets.clear')}
            </Button>
          </>
        )}
      </div>

      <ErrorBanner error={fetchError} onRetry={load} onDismiss={() => setFetchError(null)} />
      {(loading || advancedLoading) ? <SkeletonTable rows={10} columns={6} /> : (
        assets.length === 0 ? (
          <EmptyState icon={Server}
            title={advancedMode ? t('assets.noAssetsMatched') : t('assets.noAssetsFound')}
            sub={advancedMode ? t('assets.buildConditions') : t('assets.uploadToPopulate')}
          />
        ) : (
          <Card style={{ padding: 0 }}>
            <Table
              columns={visibleColumns}
              rows={assets}
              onRowClick={row => navigate(`/assets/${row.id}`)}
              onSort={handleSort}
              sortBy={sortBy}
              sortOrder={sortOrder}
              emptyMessage={t('assets.noFiltersMatch')}
            />
            {!advancedMode && Math.ceil(totalAssets / ASSET_PAGE_SIZE) > 1 && (
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 16px', borderTop: '1px solid var(--border)' }}>
                <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                  {totalAssets.toLocaleString()} assets
                </span>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Button variant="ghost" size="sm" disabled={page <= 1} onClick={() => setFilter('page', page - 1)}>
                    <ChevronLeft size={14} /> {t('assets.prev')}
                  </Button>
                  <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                    {page} / {Math.ceil(totalAssets / ASSET_PAGE_SIZE)}
                  </span>
                  <Button variant="ghost" size="sm" disabled={page >= Math.ceil(totalAssets / ASSET_PAGE_SIZE)} onClick={() => setFilter('page', page + 1)}>
                    {t('common.next')} <ChevronRight size={14} />
                  </Button>
                </div>
              </div>
            )}
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

      {showBulkCampaign && (
        <BulkCampaignModal
          selectedAssets={assets.filter(a => selectedIds.has(a.id))}
          scanId={activeScanId}
          onClose={() => setShowBulkCampaign(false)}
          onCreated={(campaign) => { setShowBulkCampaign(false); setSelectedIds(new Set()); navigate(`/campaigns/${campaign.id}`) }}
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
                {t('assets.blastRadius')} — {assets.find(a => a.id === expandedAsset)?.hostname ||
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
