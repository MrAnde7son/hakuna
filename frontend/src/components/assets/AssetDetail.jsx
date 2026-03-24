import React, { useState, useEffect, useCallback } from 'react'
import { useParams, useNavigate, useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import {
  ArrowLeft, Server, Bug, Database, Shield, Globe, Network, Users,
  ChevronDown, ChevronRight, AlertTriangle, Activity, Clock,
  ExternalLink, Package, Lock, Layers, Copy, Check
} from 'lucide-react'
import {
  getAsset, getFindings, getBlastRadius,
  getInventoryUsers, getInventoryServices,
  getInventorySoftware, getInventoryNetconns, getInventoryPatches,
  getInventorySecurityControls, getInventoryCertificates,
} from '../../api.js'
import {
  Card, ScoreBar, Spinner, Button, Pill, SeverityBadge, Table,
  ErrorBanner, SkeletonDetail, TagPill, EmptyState, InlineSpinner
} from '../shared/ui.jsx'
import { useScan } from '../../App.jsx'

// ─── Helpers ──────────────────────────────────────────────

const SEV_COLORS = {
  4: { bg: '#450a0a', text: '#fca5a5', border: '#991b1b', label: 'Critical' },
  3: { bg: '#431407', text: '#fdba74', border: '#9a3412', label: 'High' },
  2: { bg: '#451a03', text: '#fcd34d', border: '#92400e', label: 'Medium' },
  1: { bg: '#1a2e05', text: '#86efac', border: '#166534', label: 'Low' },
  0: { bg: '#0c1a2e', text: '#7dd3fc', border: '#0369a1', label: 'Info' },
}

const ENV_COLORS = {
  production: '#dc2626', prod: '#dc2626', staging: '#f59e0b',
  development: '#0ea5e9', dev: '#0ea5e9', dmz: '#8b5cf6',
  internal: '#64748b', external: '#10b981', ot: '#ea580c', cloud: '#06b6d4',
}

const ROLE_COLORS = {
  web_server: { bg: '#0ea5e922', color: '#0ea5e9', border: '#0ea5e944', label: 'WEB' },
  dns_server: { bg: '#8b5cf622', color: '#8b5cf6', border: '#8b5cf644', label: 'DNS' },
  database: { bg: '#f59e0b22', color: '#f59e0b', border: '#f59e0b44', label: 'DB' },
  mail_server: { bg: '#10b98122', color: '#10b981', border: '#10b98144', label: 'MAIL' },
  ftp_server: { bg: '#6b728022', color: '#6b7280', border: '#6b728044', label: 'FTP' },
}

function RoleBadge({ role }) {
  const c = ROLE_COLORS[role]
  if (!c) return null
  return (
    <span style={{
      display: 'inline-block', padding: '2px 6px', borderRadius: 4,
      background: c.bg, color: c.color, border: `1px solid ${c.border}`,
      fontSize: 10, fontWeight: 700, lineHeight: '16px',
    }}>{c.label}</span>
  )
}

function EnvBadge({ env }) {
  if (!env) return null
  const color = ENV_COLORS[env.toLowerCase()] || '#64748b'
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center',
      background: color + '18', color, border: `1px solid ${color}44`,
      borderRadius: 6, padding: '3px 10px', fontSize: 11, fontWeight: 600,
      textTransform: 'uppercase', letterSpacing: '0.04em',
    }}>{env}</span>
  )
}

function StatusDot({ active }) {
  return (
    <span style={{
      display: 'inline-block', width: 8, height: 8, borderRadius: '50%',
      background: active ? '#22c55e' : '#6b7280', marginRight: 6, flexShrink: 0,
    }} />
  )
}

function KeyVal({ label, children, mono }) {
  if (children == null || children === '') return null
  return (
    <div style={{ display: 'flex', gap: 12, padding: '8px 0', borderBottom: '1px solid var(--border)', fontSize: 13 }}>
      <div style={{ minWidth: 160, color: 'var(--text-muted)', flexShrink: 0 }}>{label}</div>
      <div style={{ color: 'var(--text-primary)', fontFamily: mono ? 'var(--font-mono, monospace)' : 'inherit', wordBreak: 'break-all', flex: 1 }}>
        {children}
      </div>
    </div>
  )
}

function Section({ title, icon: Icon, children, defaultOpen = true, count, action }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <Card style={{ marginBottom: 14 }}>
      <div
        onClick={() => setOpen(!open)}
        style={{
          display: 'flex', alignItems: 'center', gap: 8,
          paddingBottom: open ? 12 : 0, marginBottom: open ? 14 : 0,
          borderBottom: open ? '1px solid var(--border)' : 'none',
          cursor: 'pointer', userSelect: 'none',
        }}
      >
        {open ? <ChevronDown size={14} color="var(--text-muted)" /> : <ChevronRight size={14} color="var(--text-muted)" />}
        {Icon && <Icon size={16} color="var(--accent)" />}
        <span style={{ fontWeight: 600, fontSize: 14 }}>{title}</span>
        {count != null && (
          <span style={{
            fontSize: 11, fontWeight: 600, color: 'var(--text-muted)',
            background: 'var(--bg-muted)', padding: '1px 8px', borderRadius: 10,
          }}>{count}</span>
        )}
        {action && <div style={{ marginLeft: 'auto' }} onClick={e => e.stopPropagation()}>{action}</div>}
      </div>
      {open && children}
    </Card>
  )
}

function CopyableValue({ value }) {
  const [copied, setCopied] = useState(false)
  if (!value) return <span style={{ color: 'var(--text-muted)' }}>—</span>
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
      <span style={{ fontFamily: 'var(--font-mono, monospace)' }}>{value}</span>
      <button
        onClick={() => { navigator.clipboard.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 1500) }}
        style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, color: 'var(--text-muted)', display: 'flex' }}
        title="Copy"
      >
        {copied ? <Check size={12} color="var(--success)" /> : <Copy size={12} />}
      </button>
    </span>
  )
}

// ─── Severity mini bar chart ─────────────────────────────
function SeverityBreakdown({ asset }) {
  const counts = [
    { sev: 4, count: asset.critical_count || 0 },
    { sev: 3, count: asset.high_count || 0 },
    { sev: 2, count: asset.medium_count || 0 },
    { sev: 1, count: asset.low_count || 0 },
    { sev: 0, count: asset.info_count || 0 },
  ]
  const total = counts.reduce((s, c) => s + c.count, 0)
  if (total === 0) return <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>No findings</span>
  return (
    <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
      {counts.map(({ sev, count }) => {
        if (count === 0) return null
        const c = SEV_COLORS[sev]
        return (
          <span key={sev} style={{
            display: 'inline-flex', alignItems: 'center', gap: 4,
            background: c.bg, color: c.text, border: `1px solid ${c.border}`,
            borderRadius: 4, padding: '2px 8px', fontSize: 12, fontWeight: 600,
          }}>
            {count} {c.label}
          </span>
        )
      })}
      <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>({total} total)</span>
    </div>
  )
}


// ─── Tab definitions ──────────────────────────────────────
const TABS = [
  { key: 'overview', icon: Server, labelKey: 'assetDetail.overview' },
  { key: 'findings', icon: Bug, labelKey: 'assetDetail.findings' },
  { key: 'inventory', icon: Database, labelKey: 'assetDetail.inventory' },
]


// ─── Overview Tab ─────────────────────────────────────────
function OverviewTab({ asset, blastRadius, onReload }) {
  const { t } = useTranslation()
  const navigate = useNavigate()

  const ownership = asset.ownership
  const hasInferred = asset.inferred_primary_user || asset.inferred_team

  return (
    <>
      {/* Vulnerability posture */}
      <Section title={t('assetDetail.vulnerabilities')} icon={AlertTriangle}>
        <SeverityBreakdown asset={asset} />
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 16, marginTop: 16, paddingTop: 16, borderTop: '1px solid var(--border)' }}>
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>{t('assetDetail.riskScore').toUpperCase()}</div>
            <ScoreBar score={asset.risk_score || 0} />
          </div>
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>{t('assetDetail.criticality').toUpperCase()}</div>
            <ScoreBar score={asset.criticality || 5} color={asset.criticality >= 8 ? 'var(--critical)' : asset.criticality >= 6 ? 'var(--high)' : asset.criticality >= 4 ? 'var(--medium)' : 'var(--low)'} />
          </div>
          {blastRadius && (
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>{t('assetDetail.blastRadius').toUpperCase()}</div>
              <div style={{ fontSize: 13, fontWeight: 600 }}>
                {blastRadius.reachable_count || 0} reachable
                {blastRadius.da_exposed && <Pill label="DA Exposed" color="#dc2626" />}
              </div>
            </div>
          )}
        </div>
      </Section>

      {/* Network & Identity */}
      <Section title={t('assetDetail.networkIdentity')} icon={Network}>
        <KeyVal label={t('assets.hostname')}><CopyableValue value={asset.hostname} /></KeyVal>
        <KeyVal label={t('assets.ip')}><CopyableValue value={asset.ip} /></KeyVal>
        <KeyVal label="FQDN"><CopyableValue value={asset.fqdn} /></KeyVal>
        <KeyVal label="NetBIOS">{asset.netbios_name}</KeyVal>
        <KeyVal label="MAC"><CopyableValue value={asset.mac_address} /></KeyVal>
        <KeyVal label={t('assets.os')}>{asset.os}</KeyVal>
        <KeyVal label={t('assetDetail.deviceType')}>{asset.device_type}</KeyVal>
        {asset.is_internet_facing && (
          <KeyVal label={t('assets.internetFacing')}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <Globe size={13} color="#dc2626" />
              <span style={{ fontWeight: 600, color: '#dc2626' }}>Yes</span>
              {asset.internet_facing_confidence && (
                <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>({asset.internet_facing_confidence})</span>
              )}
            </div>
          </KeyVal>
        )}
        {asset.is_credentialed != null && (
          <KeyVal label={t('assetDetail.credentialedScan')}>{asset.is_credentialed ? 'Yes' : 'No'}</KeyVal>
        )}
      </Section>

      {/* Ownership */}
      <Section title={t('assetDetail.ownership')} icon={Users}>
        {ownership ? (
          <>
            <KeyVal label={t('assetDetail.owner')}>{ownership.owner_name}</KeyVal>
            <KeyVal label={t('assetDetail.email')}>{ownership.owner_email}</KeyVal>
            <KeyVal label={t('assetDetail.role')}>{ownership.owner_role}</KeyVal>
            <KeyVal label={t('assetDetail.team')}>{ownership.team}</KeyVal>
            {ownership.notes && <KeyVal label={t('assetDetail.notes')}>{ownership.notes}</KeyVal>}
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 8 }}>
              <Pill label={t('assets.manual')} color="#2563eb" />
            </div>
          </>
        ) : hasInferred ? (
          <>
            <KeyVal label={t('assetDetail.primaryUser')}>{asset.inferred_primary_user}</KeyVal>
            <KeyVal label={t('assetDetail.team')}>{asset.inferred_team}</KeyVal>
            {asset.inferred_admin_contacts?.length > 0 && (
              <KeyVal label={t('assetDetail.adminContacts')}>{asset.inferred_admin_contacts.join(', ')}</KeyVal>
            )}
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 8 }}>
              <Pill label={t('assets.inferred')} color="#f59e0b" />
              {asset.owner_confidence && (
                <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{asset.owner_confidence} confidence</span>
              )}
            </div>
          </>
        ) : (
          <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>{t('assetDetail.noOwnership')}</div>
        )}
      </Section>

      {/* Business Context */}
      {(asset.business_context || asset.biz_revenue_impact || asset.biz_num_users) && (
        <Section title={t('assets.businessContext')} icon={Activity}>
          <KeyVal label={t('assets.businessContext')}>{asset.business_context}</KeyVal>
          <KeyVal label={t('assets.revenueImpact')}>{asset.biz_revenue_impact}</KeyVal>
          <KeyVal label={t('assetDetail.numUsers')}>{asset.biz_num_users}</KeyVal>
        </Section>
      )}

      {/* Lifecycle */}
      <Section title={t('assetDetail.lifecycle')} icon={Clock}>
        <KeyVal label={t('assetDetail.firstSeen')}>{asset.first_seen ? new Date(asset.first_seen).toLocaleDateString() : '—'}</KeyVal>
        <KeyVal label={t('assets.lastSeen')}>{asset.last_seen ? new Date(asset.last_seen).toLocaleDateString() : '—'}</KeyVal>
        <KeyVal label={t('assetDetail.timesSeen')}>{asset.times_seen}</KeyVal>
        <KeyVal label={t('assetDetail.status')}>
          <span style={{ display: 'inline-flex', alignItems: 'center' }}>
            <StatusDot active={asset.asset_status === 'active'} />
            {asset.asset_status || 'active'}
          </span>
        </KeyVal>
        {asset.source_systems?.length > 0 && (
          <KeyVal label={t('assetDetail.sources')}>
            <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
              {asset.source_systems.map(s => (
                <Pill key={s} label={s} color="#64748b" />
              ))}
            </div>
          </KeyVal>
        )}
      </Section>
    </>
  )
}


// ─── Findings Tab ─────────────────────────────────────────
function FindingsTab({ asset }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const [sortBy, setSortBy] = useState('priority_score')
  const [sortOrder, setSortOrder] = useState('desc')
  const pageSize = 25

  const load = useCallback(() => {
    setLoading(true)
    getFindings({ asset_id: asset.id, page, page_size: pageSize, sort_by: sortBy, order: sortOrder })
      .then(r => { setFindings(r.findings || []); setTotal(r.total || 0) })
      .finally(() => setLoading(false))
  }, [asset.id, page, sortBy, sortOrder])

  useEffect(() => { load() }, [load])

  const handleSort = (key) => {
    if (sortBy === key) setSortOrder(o => o === 'asc' ? 'desc' : 'asc')
    else { setSortBy(key); setSortOrder('desc') }
  }

  const totalPages = Math.max(1, Math.ceil(total / pageSize))

  const columns = [
    {
      key: 'severity', label: t('findings.severity'), width: '90px', sortable: true,
      render: (_, row) => <SeverityBadge severity={row.severity} label={row.severity_label} />
    },
    {
      key: 'plugin_name', label: t('assetDetail.finding'), sortable: true,
      render: (_, row) => (
        <div>
          <div style={{ fontWeight: 600, fontSize: 13 }}>{row.plugin_name}</div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            {row.plugin_id}{row.port ? ` · Port ${row.port}` : ''}{row.plugin_family ? ` · ${row.plugin_family}` : ''}
          </div>
        </div>
      )
    },
    {
      key: 'priority_score', label: t('assetDetail.priority'), width: '140px', sortable: true,
      render: (v) => <ScoreBar score={v || 0} />
    },
    {
      key: 'status', label: t('assetDetail.status'), width: '100px', sortable: true,
      render: (v) => {
        const colors = { open: '#f59e0b', resolved: '#22c55e', accepted: '#6366f1' }
        return (
          <span style={{
            fontSize: 11, fontWeight: 600, textTransform: 'uppercase',
            color: colors[v] || 'var(--text-muted)',
          }}>{v || 'open'}</span>
        )
      }
    },
  ]

  if (loading) return <div style={{ padding: 32, textAlign: 'center' }}><Spinner /></div>

  if (findings.length === 0) {
    return <EmptyState icon={Bug} title={t('assetDetail.noFindings')} sub={t('assetDetail.noFindingsSub')} />
  }

  return (
    <>
      <Card style={{ padding: 0 }}>
        <Table
          columns={columns}
          rows={findings}
          onRowClick={row => navigate(`/findings/${row.id}`)}
          onSort={handleSort}
          sortBy={sortBy}
          sortOrder={sortOrder}
        />
        {totalPages > 1 && (
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 16px', borderTop: '1px solid var(--border)' }}>
            <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{total.toLocaleString()} findings</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Button variant="ghost" size="sm" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>Prev</Button>
              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{page} / {totalPages}</span>
              <Button variant="ghost" size="sm" disabled={page >= totalPages} onClick={() => setPage(p => p + 1)}>Next</Button>
            </div>
          </div>
        )}
      </Card>
    </>
  )
}


// ─── Inventory Tab ────────────────────────────────────────
function InventoryTab({ asset }) {
  const { t } = useTranslation()
  const navigate = useNavigate()

  const [counts, setCounts] = useState({})
  const [loading, setLoading] = useState(true)

  const categories = [
    { key: 'users', label: t('inventory.users'), icon: Users, color: '#0ea5e9', fetcher: getInventoryUsers, tab: 'users' },
    { key: 'services', label: t('inventory.services'), icon: Server, color: '#8b5cf6', fetcher: getInventoryServices, tab: 'services' },
    { key: 'software', label: t('inventory.software'), icon: Package, color: '#f59e0b', fetcher: getInventorySoftware, tab: 'software' },
    { key: 'netconns', label: t('inventory.connections'), icon: Network, color: '#10b981', fetcher: getInventoryNetconns, tab: 'netconns' },
    { key: 'patches', label: t('inventory.patches'), icon: Layers, color: '#ef4444', fetcher: getInventoryPatches, tab: 'patches' },
    { key: 'certs', label: t('inventory.certificates'), icon: Lock, color: '#6366f1', fetcher: getInventoryCertificates, tab: 'certs' },
    { key: 'security', label: t('inventory.controls'), icon: Shield, color: '#22c55e', fetcher: getInventorySecurityControls, tab: 'security' },
  ]

  useEffect(() => {
    setLoading(true)
    const params = { asset_id: asset.id, page_size: 1 }
    Promise.all(categories.map(c =>
      c.fetcher(params).then(r => [c.key, r.total ?? r.items?.length ?? 0]).catch(() => [c.key, 0])
    )).then(results => {
      const map = {}
      for (const [k, v] of results) map[k] = v
      setCounts(map)
    }).finally(() => setLoading(false))
  }, [asset.id])

  const inventoryUrl = (tab) =>
    `/inventory?asset_id=${asset.id}&asset_name=${encodeURIComponent(asset.hostname || asset.ip)}${tab ? '&tab=' + tab : ''}`

  if (loading) return <div style={{ padding: 32, textAlign: 'center' }}><Spinner /></div>

  const hasAny = Object.values(counts).some(v => v > 0)

  return (
    <>
      <div style={{ marginBottom: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
          {t('assetDetail.inventoryOverview')}
        </div>
        <Button variant="ghost" size="sm" onClick={() => navigate(inventoryUrl())}>
          <ExternalLink size={13} /> {t('assetDetail.fullInventory')}
        </Button>
      </div>

      {!hasAny ? (
        <EmptyState icon={Database} title={t('assetDetail.noInventory')} sub={t('assetDetail.noInventorySub')} />
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(170px, 1fr))', gap: 10 }}>
          {categories.map(({ key, label, icon: Icon, color, tab }) => {
            const count = counts[key]
            if (!count) return null
            return (
              <Card
                key={key}
                onClick={() => navigate(inventoryUrl(tab))}
                style={{ padding: 14, display: 'flex', flexDirection: 'column', gap: 6 }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Icon size={16} color={color} />
                  <span style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary)' }}>{count}</span>
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>{label}</div>
              </Card>
            )
          })}
        </div>
      )}
    </>
  )
}

// ─── Main Component ───────────────────────────────────────
export default function AssetDetail() {
  const { t } = useTranslation()
  const { id } = useParams()
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const { activeScan } = useScan()

  const [asset, setAsset] = useState(null)
  const [loading, setLoading] = useState(true)
  const [fetchError, setFetchError] = useState(null)
  const [blastRadius, setBlastRadius] = useState(null)

  const activeTab = searchParams.get('tab') || 'overview'
  const setActiveTab = (tab) => {
    setSearchParams(prev => {
      const next = new URLSearchParams(prev)
      if (tab === 'overview') next.delete('tab')
      else next.set('tab', tab)
      return next
    }, { replace: true })
  }

  const load = useCallback(() => {
    setLoading(true)
    setFetchError(null)
    getAsset(id)
      .then(data => {
        setAsset(data)
        // Fetch blast radius in background
        if (data.scan_id) {
          getBlastRadius(data.scan_id, data.id).then(setBlastRadius).catch(() => {})
        }
      })
      .catch(() => setFetchError(t('assetDetail.loadError')))
      .finally(() => setLoading(false))
  }, [id, t])

  useEffect(() => { load() }, [load])

  if (loading) return <SkeletonDetail />
  if (fetchError) return <ErrorBanner error={fetchError} onRetry={load} />
  if (!asset) return <div style={{ color: 'var(--text-muted)', padding: 32 }}>{t('assetDetail.notFound')}</div>

  const displayName = asset.hostname || asset.ip || `Asset #${asset.id}`
  const findingTotal = (asset.critical_count || 0) + (asset.high_count || 0) + (asset.medium_count || 0) + (asset.low_count || 0) + (asset.info_count || 0)

  return (
    <div style={{ maxWidth: 960 }}>
      {/* Back */}
      <button onClick={() => navigate('/assets')} style={{
        display: 'flex', alignItems: 'center', gap: 6, background: 'none', border: 'none',
        color: 'var(--text-muted)', cursor: 'pointer', fontSize: 13, marginBottom: 16, padding: 0,
      }}>
        <ArrowLeft size={14} /> {t('assetDetail.backToAssets')}
      </button>

      {/* Header card */}
      <Card style={{ marginBottom: 20 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
          <div style={{ flex: 1, minWidth: 0 }}>
            {/* Title row */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 6 }}>
              <h1 style={{ fontSize: 20, fontWeight: 700, lineHeight: 1.3, margin: 0 }}>{displayName}</h1>
              {asset.is_domain_controller && (
                <span style={{
                  display: 'inline-block', padding: '2px 6px', borderRadius: 4,
                  background: '#dc262622', color: '#dc2626', border: '1px solid #dc262644',
                  fontSize: 10, fontWeight: 700, lineHeight: '16px',
                }}>DC</span>
              )}
              {(asset.server_roles || []).map(role => <RoleBadge key={role} role={role} />)}
            </div>

            {/* Subtitle */}
            <div style={{ fontSize: 13, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
              {asset.ip && asset.ip !== asset.hostname && <span>{asset.ip}</span>}
              {asset.fqdn && asset.fqdn !== asset.hostname && <span>· {asset.fqdn}</span>}
              {asset.os && <span>· {asset.os}</span>}
            </div>

            {/* Tags */}
            {asset.tags?.length > 0 && (
              <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 8 }}>
                {asset.tags.map(tag => <TagPill key={tag.tag_id} tag={tag} size="sm" />)}
              </div>
            )}
          </div>

          {/* Right side badges */}
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 6, flexShrink: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <StatusDot active={asset.asset_status === 'active'} />
              <span style={{ fontSize: 12, color: 'var(--text-muted)', textTransform: 'capitalize' }}>{asset.asset_status || 'active'}</span>
            </div>
            <EnvBadge env={asset.environment_tag} />
            {asset.is_internet_facing && (
              <span style={{
                display: 'inline-flex', alignItems: 'center', gap: 4,
                background: '#dc262618', color: '#dc2626', border: '1px solid #dc262644',
                borderRadius: 6, padding: '3px 10px', fontSize: 11, fontWeight: 600,
              }}>
                <Globe size={12} /> Internet Facing
              </span>
            )}
          </div>
        </div>

        {/* Score strip */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 16, marginTop: 20, paddingTop: 16, borderTop: '1px solid var(--border)' }}>
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>{t('assetDetail.riskScore').toUpperCase()}</div>
            <ScoreBar score={asset.risk_score || 0} />
          </div>
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>{t('assetDetail.criticality').toUpperCase()}</div>
            <ScoreBar score={asset.criticality || 5} color={asset.criticality >= 8 ? 'var(--critical)' : asset.criticality >= 6 ? 'var(--high)' : asset.criticality >= 4 ? 'var(--medium)' : 'var(--low)'} />
          </div>
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>{t('assetDetail.findings').toUpperCase()}</div>
            <SeverityBreakdown asset={asset} />
          </div>
        </div>
      </Card>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 0, marginBottom: 20, borderBottom: '1px solid var(--border)' }}>
        {TABS.map(({ key, icon: Icon, labelKey }) => {
          const active = activeTab === key
          const label = t(labelKey) + (key === 'findings' && findingTotal > 0 ? ` (${findingTotal})` : '')
          return (
            <button
              key={key}
              onClick={() => setActiveTab(key)}
              style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '10px 18px', background: 'none', border: 'none',
                borderBottom: active ? '2px solid var(--accent)' : '2px solid transparent',
                color: active ? 'var(--accent)' : 'var(--text-muted)',
                fontSize: 13, fontWeight: 600, cursor: 'pointer', transition: 'color 0.15s',
              }}
            >
              <Icon size={14} />
              {label}
            </button>
          )
        })}
      </div>

      {/* Tab content */}
      {activeTab === 'overview' && <OverviewTab asset={asset} blastRadius={blastRadius} onReload={load} />}
      {activeTab === 'findings' && <FindingsTab asset={asset} />}
      {activeTab === 'inventory' && <InventoryTab asset={asset} />}
    </div>
  )
}
