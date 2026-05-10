import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import useURLFilters from '../../hooks/useURLFilters.js'
import { useTranslation } from 'react-i18next'
import { Bug, ChevronLeft, ChevronRight, ChevronDown, ChevronUp, Tag, Clock, Download, Bookmark, SlidersHorizontal, X as XIcon, Zap, Filter } from 'lucide-react'
import { useScan, useIsMobile } from '../../App.jsx'
import { getFindings, getFindingIds, getPluginFamilies, getAssets, getTags, assignTags, unassignTags, exportDownload, advancedSearch, setFindingOwnership, createCampaign, listCustomFieldDefinitions } from '../../api.js'
import useScanProgress from '../../hooks/useScanProgress.js'
import {
  Card, SeverityBadge, ScoreBar, Table, PageHeader, Select, MultiSelect,
  Spinner, EmptyState, Button, EffortBadge, ResolvedOwnerBadge, Pill, TagPill, TagFilterBar, TagPicker, ColumnSelector, SaveAsRuleModal, OwnershipEditPopover, SourceDots, SourceFilter, ErrorBanner, SkeletonTable, SelectAllBanner, useToast
} from '../shared/ui.jsx'
import RuleBuilder from '../campaigns/RuleBuilder.jsx'
import { filtersToConditions } from '../../utils/filtersToConditions.js'
import NLPSearchBar from '../shared/NLPSearchBar.jsx'
import { capture } from '../../utils/analytics.js'
import NewSinceBanner from '../notifications/NewSinceBanner.jsx'
import { getFindingAssetDisplay, getAssetDisplayName } from '../../utils/assetDisplay.js'

const TACTIC_COLORS = {
  'credential-access':    '#dc2626',
  'lateral-movement':     '#ea580c',
  'privilege-escalation': '#d97706',
  'initial-access':       '#7c3aed',
  'persistence':          '#0891b2',
  'defense-evasion':      '#64748b',
  'discovery':            '#059669',
  'execution':            '#b45309',
  'collection':           '#0ea5e9',
  'exfiltration':         '#6366f1',
}

function TtpPill({ ttp }) {
  const color = TACTIC_COLORS[ttp.tactic] || '#6b7280'
  return (
    <a
      href={ttp.mitre_url}
      target="_blank"
      rel="noreferrer"
      title={`${ttp.technique_id}: ${ttp.name}\nTactic: ${ttp.tactic}\nMatch: ${ttp.match_reason} (${ttp.confidence})`}
      onClick={e => e.stopPropagation()}
      style={{
        display: 'inline-flex', alignItems: 'center', gap: 3,
        padding: '1px 6px', borderRadius: 4,
        background: color + '18', border: `1px solid ${color}50`,
        color, fontSize: 10, fontWeight: 600, textDecoration: 'none',
        whiteSpace: 'nowrap', lineHeight: '16px',
      }}
    >
      {ttp.technique_id}
    </a>
  )
}

const getGroupOptions = (t) => [
  { value: 'severity', label: t('findings.severity') },
  { value: 'plugin', label: t('findings.plugin') },
  { value: 'plugin_family', label: t('findings.pluginFamily') },
  { value: 'asset', label: t('findings.asset') },
  { value: 'owner_suggestion', label: t('findings.owner') },
  { value: 'effort_level', label: t('findings.effort') },
  { value: 'cve', label: t('findings.cve') },
  { value: 'root_cause', label: t('findings.rootCause') },
]

const getRootCauseLabels = (t) => ({
  os_eol: t('rootCauses.osEol'),
  software_eol: t('rootCauses.softwareEol'),
  missing_patches: t('rootCauses.missingPatches'),
  ssl_tls_config: t('rootCauses.sslTls'),
  smb_hardening: t('rootCauses.smb'),
  ssh_hardening: t('rootCauses.ssh'),
  rdp_hardening: t('rootCauses.rdp'),
  default_credentials: t('rootCauses.defaultCreds'),
})

const SEV_ORDER = { 4: 0, 3: 1, 2: 2, 1: 3, 0: 4 }
const getSevLabels = (t) => ({ 4: t('severity.critical'), 3: t('severity.high'), 2: t('severity.medium'), 1: t('severity.low'), 0: t('severity.info') })
const SEV_COLORS = { 4: 'var(--critical)', 3: 'var(--high)', 2: 'var(--medium)', 1: 'var(--low)', 0: 'var(--muted)' }

function getGroupKey(finding, groupBy) {
  if (groupBy === 'severity') return String(finding.severity)
  if (groupBy === 'asset') return getFindingAssetDisplay(finding)
  if (groupBy === 'root_cause') return finding.aggregated_solution_id ? String(finding.aggregated_solution_id) : 'ungrouped'
  if (groupBy === 'plugin') return finding.plugin_name || (finding.plugin_id ? `Plugin ${finding.plugin_id}` : 'Other')
  return finding[groupBy] || 'Other'
}

function groupFindings(findings, groupBy) {
  const map = {}
  if (groupBy === 'cve') {
    // A finding can have multiple CVEs — place it in each CVE group
    for (const f of findings) {
      const cves = f.cves && f.cves.length > 0 ? f.cves : ['No CVE']
      for (const cve of cves) {
        if (!map[cve]) map[cve] = []
        map[cve].push(f)
      }
    }
  } else {
    for (const f of findings) {
      const key = getGroupKey(f, groupBy)
      if (!map[key]) map[key] = []
      map[key].push(f)
    }
  }
  const entries = Object.entries(map)
  if (groupBy === 'severity') {
    entries.sort(([a], [b]) => (SEV_ORDER[Number(a)] ?? 99) - (SEV_ORDER[Number(b)] ?? 99))
  } else {
    entries.sort(([a], [b]) => a.localeCompare(b))
  }
  return entries
}

function GroupHeader({ groupBy, groupKey, count, open, onToggle, t }) {
  const isSev = groupBy === 'severity'
  let label = isSev ? getSevLabels(t)[Number(groupKey)] : groupKey
  if (groupBy === 'root_cause') {
    label = groupKey === 'ungrouped' ? t('findings.noRootCauseGroup') : t('findings.rootCauseGroup', { id: groupKey })
  }
  const color = isSev ? SEV_COLORS[Number(groupKey)] : 'var(--text-secondary)'

  return (
    <button
      onClick={onToggle}
      style={{
        width: '100%', display: 'flex', alignItems: 'center', gap: 10,
        background: 'var(--bg-card)', border: '1px solid var(--border)',
        borderRadius: 8, padding: '10px 14px', cursor: 'pointer',
        marginBottom: open ? 0 : 8, borderBottomLeftRadius: open ? 0 : 8,
        borderBottomRightRadius: open ? 0 : 8,
      }}
    >
      <span style={{ fontWeight: 600, fontSize: 13, color }}>{label}</span>
      <span style={{
        fontSize: 11, background: 'var(--bg-hover)', color: 'var(--text-muted)',
        borderRadius: 10, padding: '1px 8px',
      }}>{count}</span>
      <span style={{ marginLeft: 'auto', color: 'var(--text-muted)' }}>
        {open ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
      </span>
    </button>
  )
}

const getSevOptions = (t) => [
  { value: '4', label: t('severity.critical') },
  { value: '3', label: t('severity.high') },
  { value: '2', label: t('severity.medium') },
  { value: '1', label: t('severity.low') },
  { value: '0', label: t('severity.info') },
]

function SLABadge({ status, dueDate, t: tProp }) {
  const { t: tHook } = useTranslation()
  const t = tProp || tHook
  if (!status || status === 'n/a') return <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>

  const now = new Date()
  const due = dueDate ? new Date(dueDate) : null
  const daysLeft = due ? Math.ceil((due - now) / 86400000) : null

  const cfg = {
    resolved: { color: 'var(--accent)',   bg: 'rgba(99,102,241,0.12)', label: t('sla.resolved') },
    on_track: { color: 'var(--success)',  bg: 'rgba(22,163,74,0.1)',   label: daysLeft !== null ? t('sla.daysLeft', { days: daysLeft }) : t('sla.onTrack') },
    at_risk:  { color: 'var(--warning)',  bg: 'rgba(217,119,6,0.12)',  label: daysLeft !== null ? t('sla.daysLeft', { days: daysLeft }) : t('sla.atRisk') },
    breached: { color: 'var(--danger)',   bg: 'rgba(220,38,38,0.12)',  label: daysLeft !== null ? t('sla.daysOver', { days: Math.abs(daysLeft) }) : t('sla.breached') },
  }[status] || { color: 'var(--muted)', bg: 'transparent', label: status }

  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      fontSize: 11, fontWeight: 600, padding: '2px 7px', borderRadius: 10,
      background: cfg.bg, color: cfg.color, whiteSpace: 'nowrap',
    }}>
      <Clock size={10} />
      {cfg.label}
    </span>
  )
}

function BulkTagModal({ findingIds, onClose, onDone }) {
  const { t } = useTranslation()
  const toast = useToast()
  const [selected, setSelected] = useState([])
  const [saving, setSaving] = useState(false)

  const apply = async () => {
    if (!selected.length) return
    setSaving(true)
    try {
      await assignTags({ tag_ids: selected.map(t => t.tag_id), finding_ids: findingIds })
      toast.success('Tags updated')
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
          {t('findings.tagCount', { count: findingIds.length })}
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

function BulkFindingCampaignModal({ selectedFindings, selectedIds, acrossPages, scanId, onClose, onCreated }) {
  const toast = useToast()
  const [name, setName] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(null)
  const totalSelected = acrossPages ? (selectedIds?.size || 0) : selectedFindings.length

  const handleCreate = async () => {
    if (!name.trim()) { setError('Name is required'); return }
    setSaving(true); setError(null)
    try {
      let conditions
      if (acrossPages && selectedIds?.size) {
        // Cross-page selection: we don't have all the finding records on hand,
        // so pin the campaign to the explicit ID set via the rule-engine
        // `finding.id` condition (comma-separated values, see rule_engine.py).
        const idCsv = [...selectedIds].join(',')
        conditions = [{ field: 'finding.id', op: 'eq', value: idCsv }]
      } else {
        // Deduplicate plugin IDs and build valid rule-engine conditions
        const uniquePluginIds = [...new Set(selectedFindings.map(f => f.plugin_id).filter(Boolean))]
        const pluginConditions = uniquePluginIds.map(pid => ({ field: 'finding.plugin_id', op: 'eq', value: String(pid) }))
        // Also scope to the specific asset IPs/hostnames
        const assetConditions = selectedFindings.reduce((acc, f) => {
          const key = f.asset_ip || f.asset_hostname
          if (key && !acc.find(c => c.value === key)) {
            acc.push({ field: f.asset_ip ? 'ip' : 'hostname', op: 'eq', value: key })
          }
          return acc
        }, [])
        conditions = pluginConditions.length > 0 ? pluginConditions : assetConditions
      }
      if (!conditions || conditions.length === 0) { setError('Could not build query from selected findings'); setSaving(false); return }
      const result = await createCampaign({
        name: name.trim(),
        scan_id: scanId || null,
        query: conditions,
        query_logic: acrossPages ? 'AND' : 'OR',
        status: 'planned',
      })
      toast.success('Campaign created')
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
          Create Campaign from {totalSelected} finding{totalSelected !== 1 ? 's' : ''}
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

// Slim banner shown at the top of FindingExplorer while the active scan is
// still running. VM scans report completed_jobs/total_jobs; EASM reports
// current_stage/stage_index/total_stages + incremental asset counts.
// The banner tells the user "what you see below is live and still growing"
// and disappears silently as soon as the scan flips terminal.
function LiveScanBanner({ status, progress, total }) {
  if (!progress) return null
  const totalTargets = progress.total_targets || 0
  const completedTargets = progress.completed_targets || 0
  const currentStage = progress.current_stage
  const stageIndex = progress.stage_index || 0
  const totalStages = progress.total_stages || 0
  const incrementalAssets = progress.incremental_asset_count || 0

  let summary
  if (totalTargets > 0) {
    summary = `${completedTargets} / ${totalTargets} target${totalTargets === 1 ? '' : 's'} scanned`
  } else if (totalStages > 0) {
    const stageLabel = currentStage ? ` · ${currentStage}` : ''
    const assetsSummary = incrementalAssets > 0 ? ` · ${incrementalAssets} assets discovered` : ''
    summary = `stage ${stageIndex} / ${totalStages}${stageLabel}${assetsSummary}`
  } else {
    summary = 'scan in progress'
  }

  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 10,
      padding: '8px 14px', marginBottom: 12,
      borderRadius: 8, background: 'rgba(14, 165, 233, 0.08)',
      border: '1px solid rgba(14, 165, 233, 0.35)', color: 'var(--text-primary)',
      fontSize: 12,
    }}>
      <span style={{
        display: 'inline-block', width: 8, height: 8, borderRadius: '50%',
        background: '#0ea5e9',
        animation: 'pulse 1.5s ease-in-out infinite',
      }} />
      <span style={{ fontWeight: 600 }}>Live scan</span>
      <span style={{ color: 'var(--text-muted)' }}>
        {summary} · {total.toLocaleString()} finding{total === 1 ? '' : 's'} so far
        {status === 'completed_with_errors' ? ' · some jobs failed' : ''}
      </span>
      <style>{`@keyframes pulse { 0%,100% { opacity: 1 } 50% { opacity: 0.3 } }`}</style>
    </div>
  )
}

export default function FindingExplorer() {
  const { t } = useTranslation()
  const { activeScanId } = useScan()
  const navigate = useNavigate()
  const FILTER_SCHEMA = useMemo(() => ({
    search: { default: '' },
    severity: { default: null },
    family: { default: null },
    exploit: { default: null, type: 'boolean' },
    group: { default: null },
    asset_id: { default: null },
    page: { default: 1, type: 'number' },
    sort: { default: 'priority_score' },
    order: { default: 'desc' },
    sla_status: { default: null },
    effort_level: { default: null },
    cve: { default: null },
    is_kev: { default: null, type: 'boolean' },
    ransomware: { default: null, type: 'boolean' },
    trending: { default: null, type: 'boolean' },
    has_ttps: { default: null, type: 'boolean' },
    tactic: { default: null },
    technique_id: { default: null },
    threat_group_id: { default: null, type: 'number' },
    workflow_status: { default: null },
    has_exception: { default: null, type: 'boolean' },
    has_ticket: { default: null, type: 'boolean' },
    ticket_status: { default: null },
    control_status: { default: null },
    product: { default: null },
    cpe: { default: null },
    source: { default: null },
    // AI validation: true_positive | false_positive | needs_review | not_validated | validated
    validation: { default: null },
    // Show validated false positives (default false — they're noise)
    hide_validated_fps: { default: null },
    // Cross-scanner corroboration flag (≥2 scanners confirm same CVE)
    corroborated: { default: null, type: 'boolean' },
  }), [])
  const { filters: urlFilters, setFilter, clearFilters } = useURLFilters(FILTER_SCHEMA)
  const [searchParams, setSearchParams] = useSearchParams()

  // Destructure for backwards-compat with existing references
  const search = urlFilters.search
  const severity = urlFilters.severity
  const family = urlFilters.family
  const hasExploit = urlFilters.exploit
  const groupBy = urlFilters.group
  const assetId = urlFilters.asset_id
  const page = urlFilters.page || 1
  const pageSize = groupBy ? 500 : 25
  const sortBy = urlFilters.sort || 'priority_score'
  const sortOrder = urlFilters.order || 'desc'
  const slaStatus = urlFilters.sla_status
  const effortLevel = urlFilters.effort_level
  const cveFilter = urlFilters.cve
  const isKev = urlFilters.is_kev
  const ransomwareLinked = urlFilters.ransomware
  const trendingInNews = urlFilters.trending
  const hasTtps = urlFilters.has_ttps
  const tacticFilter = urlFilters.tactic
  const techniqueFilter = urlFilters.technique_id
  const threatGroupId = urlFilters.threat_group_id
  const workflowStatus = urlFilters.workflow_status
  const hasException = urlFilters.has_exception
  const hasTicket = urlFilters.has_ticket
  const ticketStatus = urlFilters.ticket_status
  const productFilter = urlFilters.product
  const cpeFilter2 = urlFilters.cpe
  const sourceFilter = urlFilters.source
  const validationFilter = urlFilters.validation
  const hideValidatedFpsRaw = urlFilters.hide_validated_fps
  // Default: hide validated false positives (analysts don't want to see proven noise).
  // User can toggle `hide_validated_fps=false` or explicitly pick `validation=false_positive` to see them.
  const showValidatedFps = hideValidatedFpsRaw === 'false'
  const corroboratedFilter = urlFilters.corroborated

  const [findings, setFindings] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(() => !searchParams.get('q'))
  const [families, setFamilies] = useState([])
  const [assets, setAssets] = useState([])
  const [openGroups, setOpenGroups] = useState({})
  const [selectedIds, setSelectedIds] = useState(new Set())
  // True when selectedIds was populated by "Select all matching" — i.e., it
  // includes findings beyond the current page. Cleared whenever the user
  // touches an individual checkbox or the page resets.
  const [selectedAcrossPages, setSelectedAcrossPages] = useState(false)
  const [selectAllLoading, setSelectAllLoading] = useState(false)
  const [selectAllNotice, setSelectAllNotice] = useState(null)
  const [showBulkTag, setShowBulkTag] = useState(false)
  const [showSaveAs, setShowSaveAs] = useState(false)
  const [showBulkCampaign, setShowBulkCampaign] = useState(false)
  const [tagFilter, setTagFilter] = useState([])
  const [tagLogic, setTagLogic] = useState('AND')
  const [ownershipEdit, setOwnershipEdit] = useState(null) // { findingId, current }
  const isMobile = useIsMobile()
  const [showMobileFilters, setShowMobileFilters] = useState(false)

  // Advanced rule-engine search — restore from URL params if present
  const [advancedMode, setAdvancedMode] = useState(() => !!searchParams.get('q'))
  const [advancedConditions, setAdvancedConditions] = useState(() => {
    try { return JSON.parse(searchParams.get('q')) || [] } catch { return [] }
  })
  const [advancedLogic, setAdvancedLogic] = useState(() => searchParams.get('q_logic') || 'AND')
  const [advancedLoading, setAdvancedLoading] = useState(false)
  const [fetchError, setFetchError] = useState(null)
  const [createdAfter, setCreatedAfter] = useState(null)

  // Column visibility (persisted in localStorage)
  const [colVis, setColVis] = useState(() => {
    try {
      const saved = localStorage.getItem('findingColumns')
      return saved ? JSON.parse(saved) : {}
    } catch { return {} }
  })
  const updateColVis = (next) => {
    setColVis(next)
    localStorage.setItem('findingColumns', JSON.stringify(next))
  }

  // User-defined custom field definitions for this org
  const [customFieldDefs, setCustomFieldDefs] = useState([])
  useEffect(() => {
    listCustomFieldDefinitions('finding')
      .then(defs => setCustomFieldDefs((defs || []).filter(d => d.is_active)))
      .catch(() => setCustomFieldDefs([]))
  }, [])

  // Sync tag filter from URL params on first load (e.g. when navigating from Tag Manager)
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
        return allTags.find(t => t.label === ts) ||
               allTags.find(t => t.category === cat && t.value === val)
      }).filter(Boolean).map(t => ({ tag_id: t.id, label: t.label || `${t.category}:${t.value}`, category: t.category, value: t.value, color: t.color }))
      if (matched.length) setTagFilter(matched)
    }).catch(() => {})
  }, [searchParams])

  // NLP filter keys that we apply/remove as a unit
  const NLP_PARAM_KEYS = ['severity', 'exploit', 'is_kev', 'ransomware', 'trending', 'effort_level', 'sla_status', 'cve', 'search', 'sort', 'order', 'plugin_family']
  const nlpAppliedRef = useRef([])

  const applyNlpFilters = useCallback(({ finding_filters, sort }) => {
    const ff = finding_filters || {}
    setSearchParams(prev => {
      const next = new URLSearchParams(prev)
      // Clear previously NLP-applied keys
      nlpAppliedRef.current.forEach(k => next.delete(k))
      const applied = []
      const set = (key, val) => { if (val != null && val !== '') { next.set(key, String(val)); applied.push(key) } }
      set('severity', ff.severity)
      if (ff.has_exploit) { next.set('exploit', 'true'); applied.push('exploit') }
      if (ff.is_kev) { next.set('is_kev', 'true'); applied.push('is_kev') }
      if (ff.ransomware_linked) { next.set('ransomware', 'true'); applied.push('ransomware') }
      if (ff.trending_in_news) { next.set('trending', 'true'); applied.push('trending') }
      set('effort_level', ff.effort_level)
      set('sla_status', ff.sla_status)
      set('cve', ff.cve)
      set('search', ff.search)
      if (ff.plugin_family) { next.set('plugin_family', ff.plugin_family); applied.push('plugin_family') }
      if (sort) { next.set('sort', sort.sort_by); next.set('order', sort.order); applied.push('sort', 'order') }
      next.delete('page')
      nlpAppliedRef.current = applied
      return next
    }, { replace: true })
  }, [setSearchParams])

  const clearNlpFilters = useCallback(() => {
    setSearchParams(prev => {
      const next = new URLSearchParams(prev)
      nlpAppliedRef.current.forEach(k => next.delete(k))
      nlpAppliedRef.current = []
      return next
    }, { replace: true })
  }, [setSearchParams])

  const handleSort = useCallback((key) => {
    setSearchParams(prev => {
      const next = new URLSearchParams(prev)
      if (prev.get('sort') === key) {
        next.set('order', prev.get('order') === 'asc' ? 'desc' : 'asc')
      } else {
        next.set('sort', key)
        next.set('order', 'desc')
      }
      next.delete('page')
      return next
    }, { replace: true })
  }, [setSearchParams])

  const load = useCallback(() => {
    setLoading(true)
    const params = {
      scan_id: activeScanId,
      asset_id: assetId || null,
      severity: severity !== null ? severity : undefined,
      plugin_family: family,
      has_exploit: hasExploit,
      sla_status: slaStatus,
      effort_level: effortLevel,
      cve: cveFilter,
      is_kev: isKev,
      ransomware_linked: ransomwareLinked,
      trending_in_news: trendingInNews,
      has_ttps: hasTtps,
      tactic: tacticFilter,
      technique_id: techniqueFilter,
      threat_group_id: threatGroupId,
      workflow_status: workflowStatus,
      has_exception: hasException,
      has_ticket: hasTicket,
      ticket_status: ticketStatus,
      control_mitigation_status: urlFilters.control_status || null,
      search: search || null,
      source: sourceFilter || null,
      product: productFilter || null,
      cpe: cpeFilter2 || null,
      validation: validationFilter || null,
      // Default hide: backend hides FPs unless hide_validated_fps=false OR validation=false_positive
      hide_validated_fps: showValidatedFps ? 'false' : null,
      corroborated: corroboratedFilter === true ? 'true' : null,
      created_after: createdAfter || undefined,
      sort_by: sortBy,
      order: sortOrder,
      page,
      page_size: pageSize,
    }
    if (tagFilter.length) {
      params.tags = tagFilter.map(t => t.label || `${t.category}:${t.value}`).join(',')
      params.tag_logic = tagLogic
    }
    setFetchError(null)
    getFindings(params)
      .then(data => {
        setFindings(data.findings)
        setTotal(data.total)
      })
      .catch(() => setFetchError('Failed to load findings.'))
      .finally(() => setLoading(false))
  }, [activeScanId, assetId, severity, family, hasExploit, isKev, ransomwareLinked, trendingInNews, hasTtps, tacticFilter, techniqueFilter, threatGroupId, slaStatus, effortLevel, cveFilter, search, sourceFilter, productFilter, cpeFilter2, sortBy, sortOrder, page, pageSize, tagFilter, tagLogic, workflowStatus, hasException, hasTicket, ticketStatus, urlFilters.control_status, createdAfter])

  useEffect(() => { if (!advancedMode) load() }, [load, advancedMode])

  // Live progress for the currently-selected scan. While the scan is running,
  // this hook polls GET /api/scans/{id} every few seconds. Whenever the
  // backend reports forward progress (a new target completes, a new batch of
  // assets/findings arrives from EASM), refreshTick advances and we reload
  // the visible findings — so the explorer populates in real time instead
  // of waiting for the whole scan to finish.
  const { progress: scanProgress, status: scanStatus, isRunning: scanIsRunning, refreshTick: scanRefreshTick } = useScanProgress(activeScanId)

  useEffect(() => {
    if (!scanIsRunning) return
    if (advancedMode) return
    if (scanRefreshTick === 0) return
    load()
  }, [scanRefreshTick, scanIsRunning, advancedMode, load])

  // Auto-run advanced search if restored from URL params
  const advancedRestoredRef = useRef(false)
  useEffect(() => {
    if (advancedMode && advancedConditions.length && !advancedRestoredRef.current) {
      advancedRestoredRef.current = true
      runAdvancedSearch(1)
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const runAdvancedSearch = useCallback((page = 1) => {
    if (!advancedConditions.length) return
    setAdvancedLoading(true)
    // Sync conditions to URL params
    setSearchParams(prev => {
      const next = new URLSearchParams(prev)
      next.set('q', JSON.stringify(advancedConditions))
      next.set('q_logic', advancedLogic)
      next.delete('page')
      return next
    }, { replace: true })
    advancedSearch({
      query: advancedConditions,
      query_logic: advancedLogic,
      scan_id: activeScanId,
      type: 'finding',
      page,
      page_size: pageSize,
    }).then(data => {
      setFindings(data.findings)
      setTotal(data.total)
    }).catch(() => setFetchError('Advanced search failed.'))
      .finally(() => setAdvancedLoading(false))
  }, [advancedConditions, advancedLogic, activeScanId, pageSize, setSearchParams])

  const enterAdvancedMode = () => {
    // Pre-populate from current simple filters
    const conds = filtersToConditions({ search, severity, family, hasExploit, cveFilter, effortLevel, tagFilter, productFilter, cpeFilter: cpeFilter2 }, 'finding')
    setAdvancedConditions(conds)
    setAdvancedLogic('AND')
    setAdvancedMode(true)
  }

  const exitAdvancedMode = () => {
    setAdvancedMode(false)
    setAdvancedConditions([])
    setFindings([])
    setTotal(0)
    // Clear advanced params from URL
    setSearchParams(prev => {
      const next = new URLSearchParams(prev)
      next.delete('q')
      next.delete('q_logic')
      return next
    }, { replace: true })
  }

  useEffect(() => {
    getPluginFamilies(activeScanId).then(f => setFamilies(f)).catch(() => {})
  }, [activeScanId])

  useEffect(() => {
    getAssets({ scan_id: activeScanId, page_size: 500 }).then(data => setAssets(data.assets ?? data)).catch(() => {})
  }, [activeScanId])


  // Open all groups by default when groupBy changes
  useEffect(() => {
    if (!groupBy) { setOpenGroups({}); return }
    const keys = {}
    for (const f of findings) keys[getGroupKey(f, groupBy)] = true
    setOpenGroups(keys)
  }, [groupBy, findings])

  const toggleGroup = key => setOpenGroups(prev => ({ ...prev, [key]: !prev[key] }))

  const totalPages = Math.ceil(total / pageSize)


  const hasActiveFilters = severity !== null || family || hasExploit !== null || isKev !== null || ransomwareLinked !== null || trendingInNews !== null || hasTtps !== null || tacticFilter || techniqueFilter || threatGroupId || slaStatus || effortLevel || cveFilter || search || groupBy || assetId || tagFilter.length > 0 || workflowStatus || hasException !== null || productFilter || cpeFilter2
  const activeFilterCount = [severity !== null, family, hasExploit !== null, isKev !== null, ransomwareLinked !== null, trendingInNews !== null, hasTtps !== null, tacticFilter, techniqueFilter, threatGroupId, slaStatus, effortLevel, cveFilter, groupBy, assetId, tagFilter.length > 0, workflowStatus, hasException !== null, productFilter, cpeFilter2, sourceFilter].filter(Boolean).length

  const saveAsConditions = useMemo(
    () => advancedMode
      ? advancedConditions
      : filtersToConditions({ search, severity, family, hasExploit, cveFilter, effortLevel, tagFilter }, 'finding'),
    [advancedMode, advancedConditions, search, severity, family, hasExploit, cveFilter, effortLevel, tagFilter]
  )

  const toggleSelect = (id) => {
    // Any individual toggle invalidates the across-pages flag.
    setSelectedAcrossPages(false)
    setSelectAllNotice(null)
    setSelectedIds(prev => {
      const next = new Set(prev); next.has(id) ? next.delete(id) : next.add(id); return next
    })
  }
  const toggleSelectAll = () => {
    setSelectedAcrossPages(false)
    setSelectAllNotice(null)
    setSelectedIds(prev =>
      prev.size === findings.length ? new Set() : new Set(findings.map(f => f.id))
    )
  }
  const clearSelection = () => {
    setSelectedIds(new Set())
    setSelectedAcrossPages(false)
    setSelectAllNotice(null)
  }
  // Re-fetch finding IDs across all pages matching the current filters and
  // mark the selection as cross-page. Backend caps at 25k.
  const selectAllMatching = useCallback(async () => {
    setSelectAllLoading(true)
    try {
      let res
      if (advancedMode) {
        res = await advancedSearch({
          query: advancedConditions,
          query_logic: advancedLogic,
          scan_id: activeScanId,
          type: 'finding',
          ids_only: true,
        })
      } else {
        const params = {
          scan_id: activeScanId,
          asset_id: assetId || null,
          severity: severity !== null ? severity : undefined,
          plugin_family: family,
          has_exploit: hasExploit,
          sla_status: slaStatus,
          effort_level: effortLevel,
          cve: cveFilter,
          is_kev: isKev,
          ransomware_linked: ransomwareLinked,
          trending_in_news: trendingInNews,
          has_ttps: hasTtps,
          tactic: tacticFilter,
          technique_id: techniqueFilter,
          threat_group_id: threatGroupId,
          workflow_status: workflowStatus,
          has_exception: hasException,
          has_ticket: hasTicket,
          ticket_status: ticketStatus,
          control_mitigation_status: urlFilters.control_status || null,
          search: search || null,
          source: sourceFilter || null,
          product: productFilter || null,
          cpe: cpeFilter2 || null,
          validation: validationFilter || null,
          hide_validated_fps: showValidatedFps ? 'false' : null,
          corroborated: corroboratedFilter === true ? 'true' : null,
          created_after: createdAfter || undefined,
        }
        if (tagFilter.length) {
          params.tags = tagFilter.map(t => t.label || `${t.category}:${t.value}`).join(',')
          params.tag_logic = tagLogic
        }
        res = await getFindingIds(params)
      }
      const ids = res?.ids || []
      setSelectedIds(new Set(ids))
      setSelectedAcrossPages(true)
      if (res?.capped) {
        setSelectAllNotice(t('findings.selectAllCapped', { count: res.cap.toLocaleString() }))
      } else {
        setSelectAllNotice(null)
      }
      capture('findings_select_all_matching', { count: ids.length, capped: !!res?.capped })
    } catch (e) {
      setSelectAllNotice(e?.message || 'Failed to select all matching findings.')
    } finally {
      setSelectAllLoading(false)
    }
  }, [
    advancedMode, advancedConditions, advancedLogic, activeScanId, assetId,
    severity, family, hasExploit, slaStatus, effortLevel, cveFilter, isKev,
    ransomwareLinked, trendingInNews, hasTtps, tacticFilter, techniqueFilter,
    threatGroupId, workflowStatus, hasException, hasTicket, ticketStatus,
    urlFilters.control_status, search, sourceFilter, productFilter, cpeFilter2,
    validationFilter, showValidatedFps, corroboratedFilter, createdAfter,
    tagFilter, tagLogic, t,
  ])
  // Page changes invalidate the visible "All on this page" relationship —
  // clear the across-pages flag so the banner can re-prompt.
  useEffect(() => { setSelectedAcrossPages(false); setSelectAllNotice(null) }, [page, pageSize])
  const handleUntagFinding = async (findingId, tag) => {
    await unassignTags({ tag_ids: [tag.tag_id], finding_ids: [findingId] })
    load()
  }

  const allColumns = [
    {
      key: '_select', label: (
        <input type="checkbox"
          checked={findings.length > 0 && findings.every(f => selectedIds.has(f.id))}
          onChange={toggleSelectAll} />
      ), width: '36px',
      render: (_, row) => (
        <input type="checkbox" checked={selectedIds.has(row.id)} onChange={() => toggleSelect(row.id)} onClick={e => e.stopPropagation()} />
      )
    },
    {
      key: 'severity', label: t('findings.sev'), width: '80px', sortable: true,
      render: (v, row) => <SeverityBadge severity={v} label={row.severity_label} />
    },
    {
      key: 'priority_score', label: t('findings.priority'), width: '120px', sortable: true,
      render: (v) => <ScoreBar score={v} />
    },
    {
      key: 'validated', label: t('findings.validated', 'Validated'), width: '110px',
      render: (_, row) => {
        const v = row.llm_validation
        if (!v || !v.verdict) {
          return <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>—</span>
        }
        const styles = {
          true_positive: { bg: 'var(--critical)18', color: 'var(--critical)', border: 'var(--critical)40', label: t('findings.validationTrue', 'True positive'), icon: '✓' },
          false_positive: { bg: 'var(--success)18', color: 'var(--success)', border: 'var(--success)40', label: t('findings.validationFalse', 'False positive'), icon: '✗' },
          needs_review: { bg: 'var(--warning)18', color: 'var(--warning)', border: 'var(--warning)40', label: t('findings.validationNeedsReview', 'Needs review'), icon: '?' },
        }
        const s = styles[v.verdict]
        if (!s) return <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>—</span>
        const conf = typeof v.confidence === 'number' ? ` ${Math.round(v.confidence * 100)}%` : ''
        return (
          <span
            title={v.reasoning || ''}
            style={{
              display: 'inline-flex', alignItems: 'center', gap: 4,
              padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600,
              background: s.bg, color: s.color, border: `1px solid ${s.border}`,
              whiteSpace: 'nowrap',
            }}
          >
            <span style={{ fontWeight: 700 }}>{s.icon}</span>
            {s.label}{conf}
          </span>
        )
      }
    },
    {
      key: 'plugin_name', label: t('findings.pluginFinding'), width: '30%', sortable: true,
      render: (v, row) => {
        const isFp = row.llm_validation?.verdict === 'false_positive'
        return (
        <div style={{ opacity: isFp ? 0.55 : 1 }}>
          <div style={{
            fontWeight: 500,
            color: isFp ? 'var(--text-muted)' : 'var(--text-primary)',
            fontSize: 13,
            textDecoration: isFp ? 'line-through' : 'none',
          }}>{v}</div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{t('findings.plugin')} {row.plugin_id} · {row.plugin_family || '—'}</div>
          {row.cves && row.cves.length > 0 && (
            <div style={{ marginTop: 3, display: 'flex', gap: 4, flexWrap: 'wrap' }}>
              {row.cves.slice(0, 3).map(cve => (
                <Pill key={cve} label={cve} color="#f59e0b" />
              ))}
              {row.cves.length > 3 && <Pill label={`+${row.cves.length - 3}`} />}
            </div>
          )}
          {row.matched_ttps?.length > 0 && (
            <div style={{ marginTop: 3, display: 'flex', gap: 4, flexWrap: 'wrap' }}>
              {row.matched_ttps.slice(0, 2).map(t => (
                <TtpPill key={t.technique_id} ttp={t} />
              ))}
              {row.matched_ttps.length > 2 && (
                <span style={{ fontSize: 10, color: 'var(--text-muted)', alignSelf: 'center' }}>
                  +{row.matched_ttps.length - 2} TTPs
                </span>
              )}
            </div>
          )}
          {row.tags?.length > 0 && (
            <div style={{ marginTop: 4, display: 'flex', gap: 3, flexWrap: 'wrap' }}>
              {row.tags.map(t => (
                <TagPill key={t.tag_id} tag={t} size="xs" onRemove={(tag) => handleUntagFinding(row.id, tag)} />
              ))}
            </div>
          )}
        </div>
        )
      }
    },
    {
      key: 'asset_hostname', label: t('findings.asset'), width: '15%', sortable: true,
      render: (v, row) => (
        <div>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>{v || row.asset_ip}</div>
          {row.asset_ip && row.asset_ip !== v && <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{row.asset_ip}</div>}
        </div>
      )
    },
    {
      key: 'source_systems', label: 'Source', width: '90px',
      render: (v) => <SourceDots sources={v} />
    },
    {
      key: 'cvss3_score', label: t('findings.cvss3'), width: '70px', sortable: true,
      render: (v, row) => {
        const score = v || row.cvss2_score
        if (!score) return <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
        const color = score >= 9 ? 'var(--critical)' : score >= 7 ? 'var(--high)' : score >= 4 ? 'var(--medium)' : 'var(--low)'
        return <span style={{ fontWeight: 600, color, fontSize: 13 }}>{score.toFixed(1)}</span>
      }
    },
    {
      key: 'cvss2_score', label: t('findings.cvss2'), width: '70px', sortable: true,
      render: (v) => {
        if (!v) return <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
        const color = v >= 9 ? '#dc2626' : v >= 7 ? '#ea580c' : v >= 4 ? '#d97706' : '#65a30d'
        return <span style={{ fontWeight: 600, color, fontSize: 13 }}>{v.toFixed(1)}</span>
      }
    },
    {
      key: 'cvss4_score', label: t('findings.cvss4'), width: '70px', sortable: true,
      render: (v) => {
        if (!v) return <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
        const color = v >= 9 ? '#dc2626' : v >= 7 ? '#ea580c' : v >= 4 ? '#d97706' : '#65a30d'
        return <span style={{ fontWeight: 600, color, fontSize: 13 }}>{v.toFixed(1)}</span>
      }
    },
    {
      key: 'cves', label: t('findings.cve'), width: '160px',
      render: (v) => {
        const list = Array.isArray(v) ? v.filter(Boolean) : []
        if (list.length === 0) return <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
        const shown = list.slice(0, 2)
        const more = list.length - shown.length
        return (
          <span title={list.join(', ')} style={{ display: 'inline-flex', gap: 4, flexWrap: 'wrap' }}>
            {shown.map(c => (
              <span key={c} style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--text-secondary)', background: 'var(--bg-subtle)', padding: '1px 6px', borderRadius: 4 }}>{c}</span>
            ))}
            {more > 0 && (
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>+{more}</span>
            )}
          </span>
        )
      }
    },
    {
      key: 'cwe_ids', label: t('findings.cwe'), width: '160px',
      render: (v, row) => {
        const list = Array.isArray(v) ? v.filter(Boolean) : []
        if (list.length === 0) return <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
        const names = Array.isArray(row.cwe_names) ? row.cwe_names : []
        const shown = list.slice(0, 2)
        const more = list.length - shown.length
        const tooltip = names.length === list.length
          ? list.map((id, i) => `${id}: ${names[i]}`).join('\n')
          : list.join(', ')
        return (
          <span title={tooltip} style={{ display: 'inline-flex', gap: 4, flexWrap: 'wrap' }}>
            {shown.map(c => (
              <span key={c} style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--text-secondary)', background: 'var(--bg-subtle)', padding: '1px 6px', borderRadius: 4 }}>{c}</span>
            ))}
            {more > 0 && (
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>+{more}</span>
            )}
          </span>
        )
      }
    },
    {
      key: 'effort_level', label: t('findings.effort'),
      render: (v) => <EffortBadge effort={v} />
    },
    {
      key: 'owner_suggestion', label: t('findings.owner'),
      render: (_, row) => {
        const isOpen = ownershipEdit?.findingId === row.id
        const ro = row.resolved_owner
        const manualOwn = ro ? { owner_name: ro.owner_name, owner_email: ro.owner_email, owner_role: ro.owner_role, team: ro.owner_team || ro.team, notes: ro.notes } : null
        return (
          <div style={{ position: 'relative' }}>
            <button
              onClick={e => { e.stopPropagation(); setOwnershipEdit(isOpen ? null : { findingId: row.id, current: manualOwn }) }}
              style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, textAlign: 'left', width: '100%' }}
              title="Click to edit ownership"
            >
              {row.resolved_owner
                ? <ResolvedOwnerBadge resolved={row.resolved_owner} />
                : <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{t('findings.setOwner')}</span>}
            </button>
            {isOpen && (
              <OwnershipEditPopover
                current={manualOwn}
                onClose={() => setOwnershipEdit(null)}
                onSave={async (data) => {
                  await setFindingOwnership(row.id, data)
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
      key: 'exploit_available', label: t('findings.exploit'),
      render: (v, row) => {
        if (row.zero_day) return <Pill label={t('findings.zeroDay')} color="#dc2626" />
        if (v) return <Pill label={t('findings.known')} color="#ea580c" />
        if (row.exploit_maturity === 'unproven') return <Pill label={t('findings.unproven')} color="#d97706" />
        return <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
      }
    },
    {
      key: 'is_kev', label: t('findings.kev'), sortable: true,
      render: (v) => v ? <Pill label="KEV" color="#dc2626" /> : <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
    },
    {
      key: 'epss_score', label: t('findings.epss'), width: '80px', sortable: true,
      render: (v, row) => {
        if (v == null) return <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
        const color = v >= 0.5 ? 'var(--critical)' : v >= 0.2 ? 'var(--high)' : v >= 0.1 ? 'var(--medium)' : 'var(--low)'
        return (
          <div>
            <span style={{ fontWeight: 600, color, fontSize: 13 }}>{(v * 100).toFixed(1)}%</span>
            {row.epss_percentile != null && (
              <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>P{(row.epss_percentile * 100).toFixed(0)}</div>
            )}
          </div>
        )
      }
    },
    {
      key: 'ransomware_linked', label: t('findings.ransomware'), sortable: true,
      render: (v) => v ? <Pill label={t('findings.ransomware')} color="#7c3aed" /> : <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
    },
    {
      key: 'trending_in_news', label: t('findings.trending'), sortable: true,
      render: (v) => v ? <Pill label={t('findings.inNews')} color="#0ea5e9" /> : <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
    },
    {
      key: 'sla_status', label: t('findings.sla'), width: '90px', sortable: true,
      render: (v, row) => <SLABadge status={v} dueDate={row.sla_due_date} />
    },
    {
      key: 'vulnerability_state', label: t('findings.state'),
      render: (v) => {
        if (!v) return <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
        const color = v === 'Active' ? 'var(--danger)' : v === 'New' ? 'var(--success)' : v === 'Resurfaced' ? 'var(--warning)' : 'var(--muted)'
        return <Pill label={v} color={color} />
      }
    },
    {
      key: 'vpr_score', label: t('findings.vpr'), width: '70px', sortable: true,
      render: (v) => {
        if (v == null) return <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
        const color = v >= 7 ? 'var(--critical)' : v >= 5 ? 'var(--high)' : 'var(--low)'
        return <span style={{ fontWeight: 600, color, fontSize: 13 }}>{v.toFixed(1)}</span>
      }
    },
    {
      key: 'risk_factor', label: t('findings.riskFactor'),
      render: (v) => {
        if (!v || v === 'None') return <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
        const color = v === 'Critical' ? 'var(--critical)' : v === 'High' ? 'var(--high)' : v === 'Medium' ? 'var(--medium)' : v === 'Low' ? 'var(--low)' : 'var(--muted)'
        return <span style={{ fontSize: 12, fontWeight: 600, color }}>{v}</span>
      }
    },
    {
      key: 'port', label: t('findings.port'), width: '80px',
      render: (v, row) => {
        if (!v) return <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
        return <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{v}/{row.protocol || '?'}</span>
      }
    },
    {
      key: 'workflow_status', label: t('findings.status'),
      render: (v) => {
        if (!v || v === 'open') return <Pill label="Open" color="#6b7280" />
        const colorMap = { in_progress: '#0891b2', resolved: '#16a34a', accepted_risk: '#7c3aed', false_positive: '#6b7280', compensating_control: '#0891b2', technical_debt: '#d97706' }
        const color = colorMap[v] || '#6b7280'
        const label = v.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
        return <Pill label={label} color={color} />
      }
    },
    {
      key: 'workflow_assigned_to', label: t('findings.assignedTo'),
      render: (v) => v ? <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{v}</span> : <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
    },
    {
      key: 'has_ticket', label: 'Ticket', width: '60px',
      render: (v) => v ? <Pill label="Linked" color="#0891b2" /> : <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
    },
    {
      key: 'exploit_maturity', label: t('findings.maturity'),
      render: (v) => {
        if (!v) return <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
        const colorMap = { weaponized: '#dc2626', functional: '#ea580c', poc: '#d97706', unproven: '#6b7280' }
        const color = colorMap[v] || '#6b7280'
        const label = v.charAt(0).toUpperCase() + v.slice(1)
        return <Pill label={label} color={color} />
      }
    },
    {
      key: 'first_seen', label: t('findings.firstSeen'), width: '100px', sortable: true,
      render: (v, row) => {
        if (!v) return <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
        const date = new Date(v)
        return (
          <div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{date.toLocaleDateString()}</div>
            {row.times_seen > 1 && (
              <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>×{row.times_seen} scans</div>
            )}
          </div>
        )
      }
    },
    {
      key: 'last_seen', label: t('findings.lastSeen'), width: '100px', sortable: true,
      render: (v, row) => {
        if (!v) return <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
        const date = new Date(v)
        const ageDays = Math.floor((Date.now() - date) / 86400000)
        const color = ageDays > 90 ? 'var(--critical)' : ageDays > 30 ? 'var(--high)' : 'var(--text-secondary)'
        return (
          <div>
            <div style={{ fontSize: 12, color }}>{date.toLocaleDateString()}</div>
            {row.is_regression && <Pill label={t('findings.regression')} color="#7c3aed" />}
          </div>
        )
      }
    },
    {
      key: 'ssvc_decision', label: 'SSVC',
      render: (v) => {
        if (!v) return <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
        const colorMap = { 'Act': '#dc2626', 'Attend': '#ea580c', 'Track*': '#d97706', 'Track': '#16a34a' }
        return <Pill label={v} color={colorMap[v] || '#6b7280'} />
      }
    },
    {
      key: 'exploit_count', label: 'Exploits',
      render: (v) => v > 0 ? <span style={{ fontWeight: 700, color: '#ea580c', fontSize: 12 }}>{v}</span> : <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
    },
    {
      key: 'exploit_maturity_level', label: 'Exploit Maturity',
      render: (v) => {
        if (!v || v === 'none') return <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
        const colorMap = { weaponized: '#dc2626', functional: '#ea580c', poc: '#d97706' }
        return <Pill label={v} color={colorMap[v] || '#6b7280'} />
      }
    },
    // Dynamic user-defined custom field columns
    ...customFieldDefs.map(def => ({
      key: `custom_fields.${def.key}`,
      label: def.label,
      sortable: true,
      render: (_, row) => {
        const v = row.custom_fields?.[def.key]
        if (v === null || v === undefined || v === '') return <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
        if (def.data_type === 'boolean') {
          const b = typeof v === 'boolean' ? v : String(v).toLowerCase() === 'true'
          return <span style={{ fontSize: 12, color: b ? 'var(--success)' : 'var(--text-muted)' }}>{b ? '✓' : '—'}</span>
        }
        return <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{typeof v === 'object' ? JSON.stringify(v) : String(v)}</span>
      },
      _isCustomField: true,
      _defaultHidden: !def.show_in_list,
    })),
  ]

  // Filter columns by visibility (all visible by default, KEV/EPSS/Ransomware/Trending hidden by default)
  const defaultHidden = new Set(['cvss2_score', 'cvss4_score', 'cves', 'cwe_ids', 'is_kev', 'epss_score', 'ransomware_linked', 'trending_in_news', 'first_seen', 'last_seen', 'vulnerability_state', 'vpr_score', 'risk_factor', 'port', 'workflow_status', 'workflow_assigned_to', 'exploit_maturity', 'ssvc_decision', 'exploit_count', 'exploit_maturity_level', 'source_systems', 'has_ticket'])
  const visibleColumns = allColumns.filter(c => {
    if (c.key === '_select') return true
    if (c._isCustomField) {
      return colVis[c.key] !== undefined ? colVis[c.key] : !c._defaultHidden
    }
    return colVis[c.key] !== undefined ? colVis[c.key] : !defaultHidden.has(c.key)
  })

  return (
    <div>
      <NewSinceBanner pageKey="findings" labelKey="notifications.newFindings" filtering={!!createdAfter} onFilter={(since) => { setCreatedAfter(since) }} />
      {scanIsRunning && activeScanId && (
        <LiveScanBanner status={scanStatus} progress={scanProgress} total={total} />
      )}
      <PageHeader
        title={t('findings.title')}
        subtitle={advancedMode ? t('findings.matchedFindings', { count: total.toLocaleString() }) : t('findings.totalFindings', { count: total.toLocaleString() })}
        action={
          <div style={{ display: 'flex', gap: 8 }}>
            {selectedIds.size > 0 && (
              <>
                <Button size="sm" variant="ghost" onClick={() => {
                  capture('findings_bulk_action', { action: 'tag', count: selectedIds.size })
                  setShowBulkTag(true)
                }}>
                  <Tag size={14} /> {t('findings.tagSelected', { count: selectedIds.size })}
                </Button>
                <Button size="sm" variant="ghost" onClick={() => {
                  capture('findings_bulk_action', { action: 'campaign', count: selectedIds.size })
                  setShowBulkCampaign(true)
                }}>
                  <Zap size={14} /> Campaign
                </Button>
              </>
            )}
            <Button variant="ghost" size="sm" onClick={() => {
              capture('findings_exported', {
                format: 'csv',
                scan_id: activeScanId,
                total,
                has_filters: !!(severity || family || hasExploit || isKev || effortLevel || search),
              })
              exportDownload('findings', { scan_id: activeScanId, severity, plugin_family: family, has_exploit: hasExploit, is_kev: isKev, effort_level: effortLevel, search })
            }}>
              <Download size={14} /> {t('findings.exportCsv')}
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
              <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>{t('findings.advancedSearch')}</span>
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>— {t('findings.advancedSearchHint')}</span>
            </div>
            <button onClick={exitAdvancedMode} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 4, fontSize: 12 }}>
              <XIcon size={13} /> {t('findings.exitAdvanced')}
            </button>
          </div>
          <RuleBuilder
            conditions={advancedConditions}
            logic={advancedLogic}
            onChange={(conds, lgc) => { setAdvancedConditions(conds); setAdvancedLogic(lgc) }}
            showLogic
            addLabel={t('findings.addCondition')}
            onSubmit={() => advancedConditions.length && runAdvancedSearch(1)}
          />
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 12 }}>
            <Button
              onClick={() => runAdvancedSearch(1)}
              disabled={advancedLoading || !advancedConditions.length}
            >
              {advancedLoading ? t('findings.searching') : t('findings.runSearch')}
            </Button>
            {total > 0 && !advancedLoading && (
              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                <span style={{ color: 'var(--accent)', fontWeight: 600 }}>{total.toLocaleString()}</span> {t('findings.findingsMatched')}
              </span>
            )}
            {saveAsConditions.length > 0 && (
              <Button variant="ghost" size="sm" onClick={() => setShowSaveAs(true)} style={{ marginLeft: 'auto' }}>
                <Bookmark size={13} /> {t('findings.saveAs')}
              </Button>
            )}
          </div>
        </Card>
      )}

      {/* Filters */}
      {!advancedMode && (
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 16, alignItems: 'flex-start' }}>
          <div style={{ flex: '1 1 280px', minWidth: isMobile ? 0 : 280, maxWidth: 480 }}>
            <NLPSearchBar
              scanId={activeScanId}
              onResult={applyNlpFilters}
              onClear={clearNlpFilters}
            />
          </div>

          {isMobile && (
            <Button size="sm" variant="ghost" onClick={() => setShowMobileFilters(p => !p)} style={{ position: 'relative' }}>
              <Filter size={14} />
              {showMobileFilters ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
              {activeFilterCount > 0 && (
                <span style={{
                  position: 'absolute', top: -4, right: -4, background: 'var(--primary)',
                  color: '#fff', borderRadius: '50%', width: 16, height: 16, fontSize: 10,
                  display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 600,
                }}>{activeFilterCount}</span>
              )}
            </Button>
          )}

          {(!isMobile || showMobileFilters) && <>
            <MultiSelect
              values={severity ? severity.split(',') : []}
              onChange={vals => setFilter('severity', vals.length ? vals.join(',') : null)}
              placeholder={t('findings.allSeverities')}
              options={getSevOptions(t)}
            />

            <Select
              value={family}
              onChange={v => setFilter('family', v)}
              placeholder={t('findings.allFamilies')}
              options={families.map(f => ({ value: f, label: f }))}
            />

            <Select
              value={hasExploit !== null ? String(hasExploit) : null}
              onChange={v => setFilter('exploit', v)}
              placeholder={t('findings.exploit')}
              options={[{ value: 'true', label: t('findings.hasExploit') }, { value: 'false', label: t('findings.noExploit') }]}
            />

            <Select
              value={assetId}
              onChange={v => setFilter('asset_id', v)}
              placeholder={t('findings.allAssets')}
              options={assets.map(a => ({ value: String(a.id), label: getAssetDisplayName(a) }))}
            />

            <SourceFilter
              value={sourceFilter}
              onChange={v => setFilter('source', v)}
            />

            <Select
              value={groupBy}
              onChange={v => setFilter('group', v)}
              placeholder={t('findings.noGrouping')}
              options={getGroupOptions(t)}
            />

            {!isMobile && <div style={{ width: 1, background: 'var(--border)', margin: '0 4px', alignSelf: 'stretch' }} />}

            <TagFilterBar
              tags={tagFilter}
              onChange={setTagFilter}
              logic={tagLogic}
              onLogicChange={setTagLogic}
            />

            {!isMobile && <div style={{ width: 1, background: 'var(--border)', margin: '0 4px', alignSelf: 'stretch' }} />}

            <ColumnSelector
              columns={allColumns}
              visible={colVis}
              onChange={updateColVis}
            />

            <Button variant="ghost" size="sm" onClick={enterAdvancedMode} title={t('findings.advancedSearch')}>
              <SlidersHorizontal size={13} /> {t('findings.advanced')}
            </Button>

            {hasActiveFilters && (
              <>
                <Button variant="ghost" size="sm" onClick={() => setShowSaveAs(true)}>
                  <Bookmark size={13} /> {t('findings.saveAs')}
                </Button>
                <Button variant="ghost" size="sm" onClick={() => { clearFilters(); setTagFilter([]) }}>{t('findings.clearAll')}</Button>
              </>
            )}
          </>}
        </div>
      )}

      {/* Advanced filters row removed — Tickets & Control Status moved to main filter bar, Advanced button opens Rule Builder directly */}

      <ErrorBanner error={fetchError} onRetry={advancedMode ? runAdvancedSearch : load} onDismiss={() => setFetchError(null)} />
      <SelectAllBanner
        pageCount={findings.length}
        total={total}
        selectedCount={selectedIds.size}
        acrossPages={selectedAcrossPages}
        loading={selectAllLoading}
        notice={selectAllNotice}
        onSelectAll={selectAllMatching}
        onClear={clearSelection}
        t={t}
        entity="finding"
      />
      {(loading || advancedLoading) ? <SkeletonTable rows={10} columns={6} /> : (
        findings.length === 0 ? (
          <EmptyState icon={Bug}
            title={advancedMode ? t('findings.noFindingsMatched') : t('findings.noFindingsMatch')}
            sub={advancedMode ? t('findings.buildConditions') : t('findings.adjustFilters')}
          />
        ) : groupBy ? (
          <>
            {groupFindings(findings, groupBy).map(([key, rows]) => (
              <div key={key} style={{ marginBottom: 8 }}>
                <GroupHeader
                  groupBy={groupBy} groupKey={key} count={rows.length}
                  open={!!openGroups[key]}
                  onToggle={() => toggleGroup(key)}
                  t={t}
                />
                {openGroups[key] && (
                  <Card style={{ padding: 0, borderTopLeftRadius: 0, borderTopRightRadius: 0, marginBottom: 0 }}>
                    <Table
                      columns={visibleColumns}
                      rows={rows}
                      onRowClick={row => navigate(`/findings/${row.id}`)}
                      onSort={handleSort}
                      sortBy={sortBy}
                      sortOrder={sortOrder}
                    />
                  </Card>
                )}
              </div>
            ))}
            {total > findings.length && (
              <p style={{ fontSize: 12, color: 'var(--text-muted)', textAlign: 'center', marginTop: 8 }}>
                {t('findings.showingFirst', { shown: findings.length.toLocaleString(), total: total.toLocaleString() })}
              </p>
            )}
          </>
        ) : (
          <>
            <Card style={{ padding: 0, marginBottom: 12 }}>
              <Table
                columns={visibleColumns}
                rows={findings}
                onRowClick={row => navigate(`/findings/${row.id}`)}
                onSort={handleSort}
                sortBy={sortBy}
                sortOrder={sortOrder}
              />
            </Card>

            {/* Pagination */}
            {totalPages > 1 && (
              <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 12 }}>
                <Button variant="ghost" size="sm" disabled={page === 1} onClick={() => setFilter('page', page - 1)}>
                  <ChevronLeft size={14} /> {t('findings.prev')}
                </Button>
                <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>
                  {t('findings.pageOf', { page, totalPages, total: total.toLocaleString() })}
                </span>
                <Button variant="ghost" size="sm" disabled={page >= totalPages} onClick={() => setFilter('page', page + 1)}>
                  {t('common.next')} <ChevronRight size={14} />
                </Button>
              </div>
            )}
          </>
        )
      )}

      {showBulkTag && (
        <BulkTagModal
          findingIds={[...selectedIds]}
          onClose={() => setShowBulkTag(false)}
          onDone={() => { setShowBulkTag(false); clearSelection(); load() }}
        />
      )}

      {showBulkCampaign && (
        <BulkFindingCampaignModal
          selectedFindings={findings.filter(f => selectedIds.has(f.id))}
          selectedIds={selectedIds}
          acrossPages={selectedAcrossPages}
          scanId={activeScanId}
          onClose={() => setShowBulkCampaign(false)}
          onCreated={(campaign) => { setShowBulkCampaign(false); clearSelection(); navigate(`/campaigns/${campaign.id}`) }}
        />
      )}

      {showSaveAs && (
        <SaveAsRuleModal
          conditions={saveAsConditions}
          scanId={activeScanId}
          onClose={() => setShowSaveAs(false)}
          onCreated={(type, result) => {
            setShowSaveAs(false)
            if (type === 'campaign') navigate(`/campaigns/${result.id}`)
          }}
        />
      )}
    </div>
  )
}
