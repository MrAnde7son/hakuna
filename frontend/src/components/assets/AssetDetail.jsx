import React, { useState, useEffect, useCallback } from 'react'
import { useParams, useNavigate, useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import {
  ArrowLeft, Server, Bug, Database, Shield, Globe, Network, Users,
  ChevronDown, ChevronRight, AlertTriangle, Activity, Clock,
  ExternalLink, Package, Lock, Layers, Copy, Check,
  Cloud, HardDrive, Router, Container, Siren,
} from 'lucide-react'
import {
  getAsset, getAssetRiskBreakdown, getAssetSources, getFindings, getBlastRadius,
  getInventoryUsers, getInventoryServices,
  getInventorySoftware, getInventoryNetconns, getInventoryPatches,
  getInventorySecurityControls, getInventoryCertificates,
  getAssetPolicies, getAssetSiemEvents, getAssetAlerts,
} from '../../api.js'
import {
  Card, ScoreBar, Spinner, Button, Pill, SeverityBadge, Table,
  ErrorBanner, SkeletonDetail, TagPill, EmptyState, InlineSpinner,
  buildAssetBreakdown, useAssetRiskWeights
} from '../shared/ui.jsx'
import CustomAttributesCard from '../shared/CustomAttributesCard.jsx'
import { useScan } from '../../App.jsx'
import { getAssetDisplayName, getAssetSecondaryInfo, getAssetTypeLabel } from '../../utils/assetDisplay.js'

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

function prettifyKey(key) {
  if (!key) return ''
  return String(key).replace(/[_.-]+/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

function renderJsonValue(value) {
  if (value == null || value === '') return null
  if (Array.isArray(value)) {
    if (value.length === 0) return null
    if (value.every(v => v == null || typeof v !== 'object')) {
      return value.filter(v => v != null && v !== '').join(', ')
    }
    return <pre style={{ margin: 0, fontSize: 12, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{JSON.stringify(value, null, 2)}</pre>
  }
  if (typeof value === 'object') {
    return <pre style={{ margin: 0, fontSize: 12, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{JSON.stringify(value, null, 2)}</pre>
  }
  if (typeof value === 'boolean') return value ? 'Yes' : 'No'
  return String(value)
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
  { key: 'events', icon: Siren, label: 'Events' },
  { key: 'policies', icon: Shield, label: 'Policies' },
  { key: 'sources', icon: Layers, label: 'Sources' },
]


function TypeSpecificAttributesSection({ asset }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const identity = asset?.asset_identity && typeof asset.asset_identity === 'object' ? asset.asset_identity : {}
  const attributes = asset?.asset_attributes && typeof asset.asset_attributes === 'object' ? asset.asset_attributes : {}
  // Identity keys already surfaced in the Network & Identity section for host-type
  // assets — skip those to avoid duplication.
  const hostHandled = new Set(['ip', 'hostname', 'fqdn', 'netbios_name', 'mac_address', 'os', 'display_name'])
  const identityEntries = Object.entries(identity).filter(([k, v]) => {
    if (asset?.asset_type === 'host' && hostHandled.has(k)) return false
    return v != null && v !== ''
  })
  const attributeEntries = Object.entries(attributes).filter(([, v]) => v != null && v !== '')
  if (identityEntries.length === 0 && attributeEntries.length === 0) return null
  const typeLabel = getAssetTypeLabel(asset?.asset_type)

  const renderAttrValue = (k, v) => {
    if (k === 'parent_asset_id' && v) {
      return (
        <a
          href={`/assets/${v}`}
          onClick={(e) => { e.preventDefault(); navigate(`/assets/${v}`) }}
          style={{ color: 'var(--accent)', textDecoration: 'none' }}
        >
          {String(v)} →
        </a>
      )
    }
    return renderJsonValue(v)
  }

  return (
    <Section title={t('assetDetail.typeAttributes', { type: typeLabel, defaultValue: `${typeLabel} attributes` })} icon={Package}>
      {identityEntries.map(([k, v]) => (
        <KeyVal key={`id-${k}`} label={prettifyKey(k)}>{renderJsonValue(v)}</KeyVal>
      ))}
      {attributeEntries.map(([k, v]) => (
        <KeyVal key={`attr-${k}`} label={prettifyKey(k)}>{renderAttrValue(k, v)}</KeyVal>
      ))}
    </Section>
  )
}


function EasmEnrichmentSection({ asset }) {
  const { t } = useTranslation()
  const ea = asset?.easm_data
  if (!ea || typeof ea !== 'object') return null

  const ports = Array.isArray(ea.open_ports) ? ea.open_ports : []
  const services = ea.services && typeof ea.services === 'object' ? ea.services : {}
  const tech = Array.isArray(ea.tech_stack) ? ea.tech_stack : []
  const dns = ea.dns_records && typeof ea.dns_records === 'object' ? ea.dns_records : {}
  const dnsTypes = Object.keys(dns)
  const cdn = ea.cdn_provider
  const waf = ea.waf
  const httpStatus = ea.http_status
  const httpTitle = ea.http_title
  const httpUrl = ea.http_url

  const hasContent = ports.length || tech.length || dnsTypes.length || cdn || waf || httpStatus || httpUrl
  if (!hasContent) return null

  const portChip = (p) => {
    const svc = services[String(p)] || services[p] || {}
    const label = svc.name ? `${p} (${svc.name})` : String(p)
    return (
      <span key={p} title={svc.product || svc.version ? `${svc.product || ''} ${svc.version || ''}`.trim() : undefined} style={{
        display: 'inline-block', padding: '2px 7px', borderRadius: 4, fontSize: 11, fontWeight: 600,
        background: 'var(--surface-2)', color: 'var(--text-secondary)', border: '1px solid var(--border)',
      }}>{label}</span>
    )
  }

  return (
    <Section title={t('assetDetail.easmEnrichment', 'External Attack Surface')} icon={Globe}>
      {ports.length > 0 && (
        <KeyVal label={t('assets.openPorts', 'Open Ports')}>
          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>{ports.map(portChip)}</div>
        </KeyVal>
      )}
      {tech.length > 0 && (
        <KeyVal label={t('assets.techStack', 'Tech Stack')}>
          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
            {tech.map(t => (
              <span key={t} style={{
                display: 'inline-block', padding: '2px 7px', borderRadius: 4, fontSize: 11,
                background: '#8b5cf622', color: '#8b5cf6', border: '1px solid #8b5cf644',
              }}>{t}</span>
            ))}
          </div>
        </KeyVal>
      )}
      {dnsTypes.length > 0 && (
        <KeyVal label={t('assets.dnsRecords', 'DNS Records')}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {dnsTypes.map(rt => {
              const values = Array.isArray(dns[rt]) ? dns[rt] : [dns[rt]]
              return (
                <div key={rt} style={{ display: 'flex', gap: 6, alignItems: 'flex-start' }}>
                  <span style={{
                    display: 'inline-block', minWidth: 36, padding: '1px 6px', borderRadius: 4,
                    fontSize: 10, fontWeight: 700, textAlign: 'center',
                    background: 'var(--surface-2)', color: 'var(--text-secondary)',
                    border: '1px solid var(--border)',
                  }}>{rt}</span>
                  <span style={{ fontSize: 12, color: 'var(--text-secondary)', wordBreak: 'break-all' }}>
                    {values.join(', ')}
                  </span>
                </div>
              )
            })}
          </div>
        </KeyVal>
      )}
      {httpUrl && (
        <KeyVal label="HTTP">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            <a href={httpUrl} target="_blank" rel="noreferrer" style={{ fontSize: 12, color: 'var(--accent)' }}>
              {httpUrl} {httpStatus ? <span style={{ color: 'var(--text-muted)' }}>({httpStatus})</span> : null}
            </a>
            {httpTitle && <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{httpTitle}</span>}
          </div>
        </KeyVal>
      )}
      {cdn && <KeyVal label="CDN">{cdn}</KeyVal>}
      {waf && <KeyVal label="WAF">{waf}</KeyVal>}
    </Section>
  )
}


// ─── Overview Tab ─────────────────────────────────────────
function OverviewTab({ asset, blastRadius, onReload, riskComponents, assetRiskWeights }) {
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
            <ScoreBar score={asset.risk_score || 0} breakdown={buildAssetBreakdown(asset, assetRiskWeights, riskComponents)} />
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

      {/* Custom attributes (user-defined fields) */}
      <CustomAttributesCard
        entityType="asset"
        entityId={asset.id}
        values={asset.custom_fields}
        onChange={onReload}
      />

      {/* Network & Identity */}
      <Section title={t('assetDetail.networkIdentity')} icon={Network}>
        <KeyVal label={t('assets.hostname')}><CopyableValue value={asset.hostname} /></KeyVal>
        <KeyVal label={t('assets.ip')}><CopyableValue value={asset.ip} /></KeyVal>
        <KeyVal label="FQDN"><CopyableValue value={asset.fqdn} /></KeyVal>
        <KeyVal label="NetBIOS">{asset.netbios_name}</KeyVal>
        <KeyVal label="MAC"><CopyableValue value={asset.mac_address} /></KeyVal>
        <KeyVal label={t('assets.os')}>{asset.os}</KeyVal>
        <KeyVal label={t('assetDetail.deviceType')}>{asset.device_type}</KeyVal>
        <KeyVal label={t('assets.type', 'Type')}>{getAssetTypeLabel(asset.asset_type)}</KeyVal>
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

      <EasmEnrichmentSection asset={asset} />

      {/* Type-specific attributes (asset_identity + asset_attributes).
          Renders generically for any asset_type — including customer-defined
          types ingested via the integration builder (ai_agent, mcp_server, …). */}
      <TypeSpecificAttributesSection asset={asset} />

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
    `/inventory?asset_id=${asset.id}&asset_name=${encodeURIComponent(getAssetDisplayName(asset))}${tab ? '&tab=' + tab : ''}`

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


// ─── Events Tab (SIEM) ───────────────────────────────────
function EventsTab({ asset }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [events, setEvents] = useState([])
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const [alertCount, setAlertCount] = useState(0)
  const [sevFilter, setSevFilter] = useState(null)
  const [view, setView] = useState('events') // 'events' | 'alerts'
  const pageSize = 25

  const SEV_BADGE = { critical: '#dc2626', high: '#f97316', medium: '#f59e0b', low: '#22c55e', info: '#64748b' }

  const loadEvents = useCallback(() => {
    setLoading(true)
    getAssetSiemEvents(asset.id, { page, page_size: pageSize, severity: sevFilter })
      .then(r => { setEvents(r.events || []); setTotal(r.total || 0); setAlertCount(r.alert_count || 0) })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [asset.id, page, sevFilter])

  const loadAlerts = useCallback(() => {
    setLoading(true)
    getAssetAlerts(asset.id)
      .then(r => setAlerts(r || []))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [asset.id])

  useEffect(() => {
    if (view === 'events') loadEvents()
    else loadAlerts()
  }, [view, loadEvents, loadAlerts])

  const totalPages = Math.max(1, Math.ceil(total / pageSize))

  if (loading) return <div style={{ padding: 32, textAlign: 'center' }}><Spinner /></div>

  return (
    <>
      {/* Toggle + alert summary */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16, flexWrap: 'wrap', gap: 8 }}>
        <div style={{ display: 'flex', gap: 0, borderRadius: 8, border: '1px solid var(--border)', overflow: 'hidden' }}>
          {['events', 'alerts'].map(v => (
            <button key={v} onClick={() => { setView(v); setPage(1) }} style={{
              padding: '6px 16px', fontSize: 12, fontWeight: 600, border: 'none', cursor: 'pointer',
              background: view === v ? 'var(--accent)' : 'var(--card)',
              color: view === v ? '#fff' : 'var(--text-muted)',
              textTransform: 'capitalize',
            }}>
              {v}{v === 'alerts' && alertCount > 0 ? ` (${alertCount})` : ''}
            </button>
          ))}
        </div>
        {view === 'events' && (
          <div style={{ display: 'flex', gap: 4 }}>
            {[null, 'critical', 'high', 'medium', 'low'].map(sev => (
              <button key={sev || 'all'} onClick={() => { setSevFilter(sev); setPage(1) }} style={{
                padding: '4px 10px', fontSize: 11, fontWeight: 600, borderRadius: 6, cursor: 'pointer',
                border: '1px solid var(--border)',
                background: sevFilter === sev ? (sev ? SEV_BADGE[sev] + '22' : 'var(--accent-muted)') : 'transparent',
                color: sevFilter === sev ? (sev ? SEV_BADGE[sev] : 'var(--accent)') : 'var(--text-muted)',
              }}>
                {sev ? sev.charAt(0).toUpperCase() + sev.slice(1) : 'All'}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Events view */}
      {view === 'events' && (
        events.length === 0 ? (
          <EmptyState icon={Siren} title="No SIEM Events" sub="Events will appear here when this asset generates SIEM data." />
        ) : (
          <Card style={{ padding: 0 }}>
            <Table
              columns={[
                { key: 'event_time', label: 'Time', width: '150px', render: v => v ? new Date(v).toLocaleString() : '—' },
                {
                  key: 'severity', label: 'Severity', width: '90px',
                  render: v => (
                    <span style={{
                      fontSize: 11, fontWeight: 700, textTransform: 'uppercase',
                      color: SEV_BADGE[v] || 'var(--text-muted)',
                    }}>{v}</span>
                  )
                },
                { key: 'source_system', label: 'Source', width: '110px' },
                { key: 'event_type', label: 'Type', width: '110px' },
                {
                  key: 'message', label: 'Message',
                  render: v => <span style={{ fontSize: 12 }}>{(v || '').slice(0, 120)}{v?.length > 120 ? '...' : ''}</span>
                },
                { key: 'source_ip', label: 'Source IP', width: '120px' },
                { key: 'user_name', label: 'User', width: '100px' },
              ]}
              rows={events}
              onRowClick={row => navigate(`/siem/events?event_id=${row.id}`)}
            />
            {totalPages > 1 && (
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 16px', borderTop: '1px solid var(--border)' }}>
                <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{total.toLocaleString()} events</span>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Button variant="ghost" size="sm" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>Prev</Button>
                  <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{page} / {totalPages}</span>
                  <Button variant="ghost" size="sm" disabled={page >= totalPages} onClick={() => setPage(p => p + 1)}>Next</Button>
                </div>
              </div>
            )}
          </Card>
        )
      )}

      {/* Alerts view */}
      {view === 'alerts' && (
        alerts.length === 0 ? (
          <EmptyState icon={Siren} title="No SIEM Alerts" sub="Alerts are created when detection rules match events on this asset." />
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {alerts.map(a => (
              <Card key={a.id} onClick={() => navigate(`/siem/alerts?alert_id=${a.id}`)} style={{ padding: 14, cursor: 'pointer' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10 }}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                      <span style={{
                        fontSize: 11, fontWeight: 700, textTransform: 'uppercase',
                        color: SEV_BADGE[a.severity] || 'var(--text-muted)',
                      }}>{a.severity}</span>
                      <span style={{ fontSize: 13, fontWeight: 600 }}>{a.rule_name || 'Unknown Rule'}</span>
                      {a.suppressed && <Pill label="Suppressed" color="#6b7280" />}
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                      {a.event_count} event{a.event_count !== 1 ? 's' : ''}
                      {a.entity_value ? ` · ${a.entity_value}` : ''}
                      {a.fired_at ? ` · ${new Date(a.fired_at).toLocaleString()}` : ''}
                    </div>
                  </div>
                  <span style={{
                    fontSize: 11, fontWeight: 600, textTransform: 'uppercase', padding: '3px 8px', borderRadius: 4,
                    background: a.status === 'open' ? '#f59e0b18' : a.status === 'closed' ? '#22c55e18' : '#6b728018',
                    color: a.status === 'open' ? '#f59e0b' : a.status === 'closed' ? '#22c55e' : '#6b7280',
                  }}>{a.status}</span>
                </div>
              </Card>
            ))}
          </div>
        )
      )}
    </>
  )
}


// ─── Main Component ───────────────────────────────────────
// ─── Policies Tab ────────────────────────────────────────
function PoliciesTab({ asset }) {
  const [data, setData] = useState({ items: [] })
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    getAssetPolicies(asset.id)
      .then(r => setData({ items: r.items || [] }))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [asset.id])

  if (loading) return <div style={{ padding: 32, textAlign: 'center' }}><Spinner /></div>

  if (!data.items.length) {
    return <EmptyState icon={Shield} title="No Security Policies" sub="Connect a security product (e.g. CrowdStrike) via Integration Builder to see policy configurations." />
  }

  return (
    <div>
      <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 16 }}>
        Security product policies assigned to this asset
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {data.items.map(item => {
          const p = item.policy
          const stats = item.assessment_stats || {}
          const total = (stats.mitigated || 0) + (stats.partially_mitigated || 0) + (stats.not_mitigated || 0) + (stats.unknown || 0)
          return (
            <Card key={item.id} style={{ padding: 16 }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 10 }}>
                <div>
                  <div style={{ fontSize: 14, fontWeight: 600 }}>{p?.product_name || p?.product_key}</div>
                  <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
                    {p?.policy_name} · {p?.policy_type} · {p?.vendor}
                  </div>
                </div>
                {item.source_group_name && (
                  <span style={{ fontSize: 11, color: 'var(--text-muted)', background: 'var(--bg-secondary)', padding: '3px 8px', borderRadius: 4 }}>
                    {item.assignment_source}: {item.source_group_name}
                  </span>
                )}
              </div>
              {/* Policy settings preview */}
              {p?.settings && (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 10 }}>
                  {Object.entries(p.settings).slice(0, 8).map(([key, val]) => {
                    const mode = val?.mode || (val?.enabled ? 'enabled' : 'disabled')
                    const isBlock = mode === 'block' || mode === 'AGGRESSIVE' || mode === 'MODERATE' || mode === 'CAUTIOUS'
                    const isDetect = mode === 'detect' || mode === 'DISABLED'
                    return (
                      <span key={key} style={{
                        display: 'inline-flex', alignItems: 'center', gap: 4,
                        fontSize: 11, fontWeight: 500, padding: '3px 8px', borderRadius: 4,
                        background: isBlock ? '#22c55e12' : isDetect ? '#f59e0b12' : '#6b728012',
                        border: `1px solid ${isBlock ? '#22c55e30' : isDetect ? '#f59e0b30' : '#6b728030'}`,
                        color: isBlock ? '#22c55e' : isDetect ? '#f59e0b' : '#6b7280',
                      }}>
                        <span style={{ width: 6, height: 6, borderRadius: '50%', background: isBlock ? '#22c55e' : isDetect ? '#f59e0b' : '#6b7280' }} />
                        {key.replace(/_/g, ' ')}
                      </span>
                    )
                  })}
                </div>
              )}
              {/* Assessment stats */}
              {total > 0 && (
                <div style={{ display: 'flex', gap: 12, fontSize: 12 }}>
                  {stats.mitigated > 0 && <span style={{ color: '#22c55e', fontWeight: 600 }}>{stats.mitigated} mitigated</span>}
                  {stats.partially_mitigated > 0 && <span style={{ color: '#f59e0b', fontWeight: 600 }}>{stats.partially_mitigated} partial</span>}
                  {stats.not_mitigated > 0 && <span style={{ color: '#dc2626', fontWeight: 600 }}>{stats.not_mitigated} not mitigated</span>}
                </div>
              )}
            </Card>
          )
        })}
      </div>
    </div>
  )
}


// ─── Sources Tab ─────────────────────────────────────────
const SOURCE_LABELS = {
  nessus: 'Nessus', tenable_sc: 'Tenable.sc', qualys: 'Qualys', rapid7: 'Rapid7',
  openvas: 'OpenVAS', crowdstrike: 'CrowdStrike', wiz: 'Wiz', easm: 'EASM',
  vm_scanner: 'VM Audit',
}

const FIELD_LABELS = {
  ip: 'IP Address', hostname: 'Hostname', fqdn: 'FQDN', os: 'Operating System',
  mac_address: 'MAC Address', netbios_name: 'NetBIOS Name', device_type: 'Device Type',
  criticality: 'Criticality', environment: 'Environment', asset_type: 'Asset Type',
  is_credentialed: 'Credentialed Scan', is_internet_facing: 'Internet Facing',
  scan_start: 'Scan Start', scan_end: 'Scan End', system_type: 'System Type',
}

function CopyRawButton({ data }) {
  const [copied, setCopied] = useState(false)
  const handleCopy = () => {
    navigator.clipboard.writeText(JSON.stringify(data, null, 2)).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }
  return (
    <div style={{ display: 'flex', justifyContent: 'flex-end', padding: '8px 0 4px' }}>
      <button
        onClick={handleCopy}
        style={{
          display: 'inline-flex', alignItems: 'center', gap: 5,
          padding: '4px 10px', fontSize: 12, color: copied ? 'var(--success)' : 'var(--text-muted)',
          background: 'none', border: '1px solid var(--border)', borderRadius: 5,
          cursor: 'pointer',
        }}
      >
        {copied ? <Check size={13} /> : <Copy size={13} />}
        {copied ? 'Copied' : 'Copy raw data'}
      </button>
    </div>
  )
}

function SourcesTab({ asset }) {
  const [sources, setSources] = useState([])
  const [loading, setLoading] = useState(true)
  const [expanded, setExpanded] = useState(null)

  useEffect(() => {
    setLoading(true)
    getAssetSources(asset.id)
      .then(data => {
        setSources(data || [])
        if (data?.length) setExpanded(data[0].source_system)
      })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [asset.id])

  if (loading) return <div style={{ padding: 32, textAlign: 'center' }}><Spinner /></div>

  if (!sources.length) {
    return <EmptyState icon={Layers} title="No Source Data" sub="Source observations are recorded when assets are imported from scanners or integrations." />
  }

  return (
    <div>
      <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 16 }}>
        Raw data from each source that contributed to this asset ({sources.length} source{sources.length !== 1 ? 's' : ''})
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {sources.map(src => {
          const isOpen = expanded === src.source_system
          const fields = src.raw_fields || {}
          const displayName = SOURCE_LABELS[src.source_system] || src.source_system
          return (
            <Card key={src.source_system} style={{ padding: 0, overflow: 'hidden' }}>
              <button
                onClick={() => setExpanded(isOpen ? null : src.source_system)}
                style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  width: '100%', padding: '14px 16px', background: 'none', border: 'none',
                  cursor: 'pointer', textAlign: 'left',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span style={{
                    display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                    width: 28, height: 28, borderRadius: 6,
                    background: 'var(--accent-muted)', color: 'var(--accent)',
                    fontSize: 12, fontWeight: 700,
                  }}>
                    {displayName.charAt(0)}
                  </span>
                  <div>
                    <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>{displayName}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                      {src.times_seen} scan{src.times_seen !== 1 ? 's' : ''}
                      {src.first_seen && ` · First seen ${new Date(src.first_seen).toLocaleDateString()}`}
                      {src.last_seen && ` · Last seen ${new Date(src.last_seen).toLocaleDateString()}`}
                    </div>
                  </div>
                </div>
                {isOpen ? <ChevronDown size={16} color="var(--text-muted)" /> : <ChevronRight size={16} color="var(--text-muted)" />}
              </button>
              {isOpen && (
                <div style={{ padding: '0 16px 16px', borderTop: '1px solid var(--border)' }}>
                  <CopyRawButton data={fields} />
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 0 }}>
                    {Object.entries(fields)
                      .filter(([, v]) => v != null && v !== '' && typeof v !== 'object')
                      .map(([key, value]) => (
                        <div key={key} style={{ padding: '10px 0', borderBottom: '1px solid var(--border)' }}>
                          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 3 }}>
                            {FIELD_LABELS[key] || key.replace(/_/g, ' ')}
                          </div>
                          <div style={{ fontSize: 13, color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                            {typeof value === 'boolean' ? (value ? 'Yes' : 'No') : String(value)}
                          </div>
                        </div>
                      ))}
                  </div>
                  {/* Nested objects displayed as JSON */}
                  {Object.entries(fields)
                    .filter(([, v]) => v != null && typeof v === 'object')
                    .map(([key, value]) => (
                      <div key={key} style={{ marginTop: 12 }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>
                          {FIELD_LABELS[key] || key.replace(/_/g, ' ')}
                        </div>
                        <pre style={{
                          fontSize: 11, background: 'var(--bg-secondary)', padding: 12,
                          borderRadius: 6, overflow: 'auto', maxHeight: 200,
                          color: 'var(--text-secondary)', margin: 0,
                        }}>
                          {JSON.stringify(value, null, 2)}
                        </pre>
                      </div>
                    ))}
                </div>
              )}
            </Card>
          )
        })}
      </div>
    </div>
  )
}


export default function AssetDetail() {
  const { t } = useTranslation()
  const { id } = useParams()
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const { activeScan } = useScan()
  const assetRiskWeights = useAssetRiskWeights()

  const [asset, setAsset] = useState(null)
  const [loading, setLoading] = useState(true)
  const [fetchError, setFetchError] = useState(null)
  const [blastRadius, setBlastRadius] = useState(null)
  const [riskComponents, setRiskComponents] = useState(null)

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
        // Fetch blast radius and risk breakdown in background
        getBlastRadius(data.id).then(setBlastRadius).catch(() => {})
        getAssetRiskBreakdown(data.id).then(setRiskComponents).catch(() => {})
      })
      .catch(() => setFetchError(t('assetDetail.loadError')))
      .finally(() => setLoading(false))
  }, [id, t])

  useEffect(() => { load() }, [load])

  if (loading) return <SkeletonDetail />
  if (fetchError) return <ErrorBanner error={fetchError} onRetry={load} />
  if (!asset) return <div style={{ color: 'var(--text-muted)', padding: 32 }}>{t('assetDetail.notFound')}</div>

  const displayName = getAssetDisplayName(asset)
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
              {getAssetSecondaryInfo(asset).map((info, i) => <span key={i}>{i > 0 ? '· ' : ''}{info}</span>)}
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
            <ScoreBar score={asset.risk_score || 0} breakdown={buildAssetBreakdown(asset, assetRiskWeights, riskComponents)} />
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
        {TABS.map(({ key, icon: Icon, labelKey, label: rawLabel }) => {
          const active = activeTab === key
          const label = (labelKey ? t(labelKey) : rawLabel) + (key === 'findings' && findingTotal > 0 ? ` (${findingTotal})` : '')
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
      {activeTab === 'overview' && <OverviewTab asset={asset} blastRadius={blastRadius} onReload={load} riskComponents={riskComponents} assetRiskWeights={assetRiskWeights} />}
      {activeTab === 'findings' && <FindingsTab asset={asset} />}
      {activeTab === 'inventory' && <InventoryTab asset={asset} />}
      {activeTab === 'events' && <EventsTab asset={asset} />}
      {activeTab === 'policies' && <PoliciesTab asset={asset} />}
      {activeTab === 'sources' && <SourcesTab asset={asset} />}
    </div>
  )
}
