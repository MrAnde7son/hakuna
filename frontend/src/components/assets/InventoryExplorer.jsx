import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'
import {
  Users, Shield, Server, Network, Clock,
  LogIn, AlertTriangle, Key, UserCheck,
  Activity, Layers, Share2, Package, Lock, Monitor, FileText, Terminal, Eye, EyeOff, BrainCircuit,
  ChevronDown, ChevronUp, ChevronLeft, ChevronRight, Download, Database, X,
  Bot, User, Search, GitBranch, Globe, Building2, ShieldAlert, Image, ExternalLink
} from 'lucide-react'
import {
  Card, StatCard, Table, FilterBar, Select, Input,
  PageHeader, Spinner, EmptyState, Pill, Button, ErrorBanner, SkeletonCard
} from '../shared/ui.jsx'
import {
  getInventorySummary, getInventoryUsers, getInventoryUserOrgTree, getInventoryGroups,
  getInventoryServices, getInventoryNetconns, getInventoryTasks,
  getInventoryPatches, getInventoryLoggedOn,
  getInventoryShares, getInventorySoftware, getInventorySecurityControls,
  getInventoryComputers, getInventoryPasswordPolicies, getInventoryEnvVars,
  getInventoryCertificates, getInventoryAITools, getInventoryProcesses,
  getInventoryDatabases, getInventoryCredentials,
  getSecurityCoverage,
  getSBOMComponents, getSBOMComponentVulns, getSBOMAssetSummary,
  exportDownload,
  getEasmAssets, getEasmBreaches, getEasmSubsidiaries,
} from '../../api.js'
import { useScan } from '../../App.jsx'

const INV_PAGE_SIZE = 25

// ─── Pagination bar ───────────────────────────────────────
function Pagination({ page, total, pageSize, onPageChange, noun = 'items' }) {
  const { t } = useTranslation()
  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  if (totalPages <= 1) return (
    <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-muted)' }}>{total} {noun}</div>
  )
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 10 }}>
      <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
        {total.toLocaleString()} {noun}
      </span>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <Button variant="ghost" size="sm" disabled={page <= 1} onClick={() => onPageChange(page - 1)}>
          <ChevronLeft size={14} /> {t('common.prev')}
        </Button>
        <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
          {page} / {totalPages}
        </span>
        <Button variant="ghost" size="sm" disabled={page >= totalPages} onClick={() => onPageChange(page + 1)}>
          {t('common.next')} <ChevronRight size={14} />
        </Button>
      </div>
    </div>
  )
}

// ─── Tab config ───────────────────────────────────────────
function getTabGroups(t) {
  return [
    { key: 'surface', label: t('inventory.attackSurface'), icon: AlertTriangle },
    { label: t('inventory.identity'), icon: Users, children: [
      { key: 'users',     label: t('inventory.users'),     icon: Users },
      { key: 'groups',    label: t('inventory.groups'),    icon: Shield },
      { key: 'loggedon',  label: t('inventory.loggedOn'), icon: LogIn },
    ]},
    { label: t('inventory.infrastructure'), icon: Server, children: [
      { key: 'computers', label: t('inventory.computers'), icon: Monitor },
      { key: 'databases', label: t('inventory.databases'), icon: Database },
      { key: 'services',  label: t('inventory.services'),  icon: Server },
      { key: 'software',  label: t('inventory.software'),  icon: Package },
      { key: 'processes', label: t('inventory.processes'),  icon: Activity },
    ]},
    { label: t('inventory.network'), icon: Network, children: [
      { key: 'netconns',  label: t('inventory.connections'), icon: Network },
      { key: 'shares',    label: t('inventory.shares'),      icon: Share2 },
    ]},
    { label: t('inventory.security'), icon: Lock, children: [
      { key: 'security',  label: t('inventory.controls'),        icon: Lock },
      { key: 'patches',   label: t('inventory.patches'),         icon: Layers },
      { key: 'policy',    label: t('inventory.passwordPolicy'),  icon: FileText },
      { key: 'certs',     label: t('inventory.certificates'),     icon: Lock },
      { key: 'credentials', label: t('inventory.credentials'),  icon: Key },
    ]},
    { label: t('inventory.configuration'), icon: Terminal, children: [
      { key: 'tasks',    label: t('inventory.schedTasks'),   icon: Clock },
      { key: 'envvars',  label: t('inventory.envVariables'),  icon: Terminal },
      { key: 'aitools',  label: t('inventory.aiTools'),       icon: BrainCircuit },
    ]},
    { label: t('inventory.easm'), icon: Globe, children: [
      { key: 'easm_assets',    label: t('inventory.easmDomainRecords'), icon: Globe },
      { key: 'easm_breaches',  label: t('inventory.easmBreaches'),      icon: ShieldAlert },
      { key: 'easm_corporate', label: t('inventory.easmCorporate'),     icon: Building2 },
    ]},
  ]
}

// Flat list of all valid tab keys (for URL validation) — keys are static, no translation needed
const ALL_TABS = ['surface', 'users', 'groups', 'loggedon', 'computers', 'databases', 'services', 'software', 'processes', 'netconns', 'shares', 'security', 'patches', 'policy', 'certs', 'credentials', 'tasks', 'envvars', 'aitools', 'easm_assets', 'easm_breaches', 'easm_corporate']

// Find which group a tab key belongs to
function groupForTab(tabKey, tabGroups) {
  for (const g of tabGroups) {
    if (g.key === tabKey) return null
    if (g.children?.some(c => c.key === tabKey)) return g.label
  }
  return null
}

// ─── Dropdown tab button ──────────────────────────────────
function TabDropdown({ group, activeTab, onSelect }) {
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

  useEffect(() => {
    const handler = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const activeChild = group.children.find(c => c.key === activeTab)
  const isActive = !!activeChild
  const Icon = group.icon

  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <button
        onClick={() => setOpen(!open)}
        style={{
          display: 'flex', alignItems: 'center', gap: 6,
          padding: '9px 10px',
          background: 'none', border: 'none', cursor: 'pointer',
          fontSize: 12, fontWeight: isActive ? 700 : 500,
          color: isActive ? 'var(--text-primary)' : 'var(--text-muted)',
          borderBottom: isActive ? '2px solid var(--accent)' : '2px solid transparent',
          marginBottom: -1,
          whiteSpace: 'nowrap',
          transition: 'color 0.15s',
        }}
      >
        <Icon size={13} />
        {isActive ? activeChild.label : group.label}
        <ChevronDown size={11} style={{ opacity: 0.5, transition: 'transform 0.15s', transform: open ? 'rotate(180deg)' : 'none' }} />
      </button>
      {open && (
        <div style={{
          position: 'absolute', top: '100%', left: 0, zIndex: 50,
          marginTop: 2, minWidth: 170,
          background: 'var(--bg-primary)', border: '1px solid var(--border)',
          borderRadius: 8, boxShadow: '0 8px 24px rgba(0,0,0,0.18)',
          padding: '4px 0',
        }}>
          {group.children.map(({ key, label, icon: CIcon }) => {
            const active = activeTab === key
            return (
              <button
                key={key}
                onClick={() => { onSelect(key); setOpen(false) }}
                style={{
                  display: 'flex', alignItems: 'center', gap: 8, width: '100%',
                  padding: '8px 14px', background: active ? 'var(--bg-muted)' : 'none',
                  border: 'none', cursor: 'pointer', fontSize: 12,
                  fontWeight: active ? 700 : 400,
                  color: active ? 'var(--text-primary)' : 'var(--text-secondary)',
                  textAlign: 'left',
                }}
              >
                <CIcon size={13} />
                {label}
              </button>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ─── Env tag colors ────────────────────────────────────────
const ENV_COLORS = {
  production:  '#dc2626',
  prod:        '#dc2626',
  staging:     '#f59e0b',
  development: '#0ea5e9',
  dev:         '#0ea5e9',
  dmz:         '#8b5cf6',
  internal:    '#64748b',
  external:    '#10b981',
  ot:          '#ea580c',
  cloud:       '#06b6d4',
}

function EnvPill({ env }) {
  if (!env) return null
  const color = ENV_COLORS[env.toLowerCase()] || '#64748b'
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center',
      background: color + '22', color, border: `1px solid ${color}55`,
      borderRadius: 3, padding: '1px 5px', fontSize: 10, fontWeight: 600,
      textTransform: 'uppercase', letterSpacing: '0.04em', marginLeft: 4,
    }}>{env}</span>
  )
}

// ─── Group by asset helper ─────────────────────────────────
function GroupedTable({ rows, columns, emptyMessage, groupByKey = 'asset_id', groupLabelKey = 'asset_label', groupEnvKey = 'asset_env', groupIpKey = 'asset_ip', onSort, sortBy, sortOrder, renderRowExtra, onRowClick }) {
  const [collapsed, setCollapsed] = useState({})

  const groups = []
  const seen = new Map()
  for (const row of rows) {
    const key = row[groupByKey]
    if (!seen.has(key)) {
      seen.set(key, groups.length)
      groups.push({ key, label: row[groupLabelKey] || key, env: row[groupEnvKey], ip: row[groupIpKey], rows: [] })
    }
    groups[seen.get(key)].rows.push(row)
  }

  if (groups.length === 0) {
    return <div style={{ padding: '24px 0', textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>{emptyMessage || 'No data.'}</div>
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      {groups.map(g => {
        const open = !collapsed[g.key]
        return (
          <div key={g.key} style={{ border: '1px solid var(--border)', borderRadius: 6, overflow: 'hidden' }}>
            {/* Group header */}
            <div
              onClick={() => setCollapsed(c => ({ ...c, [g.key]: !c[g.key] }))}
              style={{
                display: 'flex', alignItems: 'center', gap: 8,
                padding: '8px 12px', cursor: 'pointer',
                background: open ? 'var(--bg-muted)' : 'var(--bg-card)',
                borderBottom: open ? '1px solid var(--border)' : 'none',
                userSelect: 'none',
              }}
            >
              <span style={{ fontSize: 11, color: 'var(--text-muted)', minWidth: 12 }}>
                {open ? '▼' : '▶'}
              </span>
              <span style={{ fontWeight: 700, fontSize: 13 }}>{g.label}</span>
              {g.ip && g.ip !== g.label && (
                <span style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--text-muted)' }}>{g.ip}</span>
              )}
              <EnvPill env={g.env} />
              <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text-muted)' }}>
                {g.rows.length} {g.rows.length === 1 ? 'item' : 'items'}
              </span>
            </div>
            {/* Rows */}
            {open && (
              <Table columns={columns} rows={g.rows} emptyMessage={emptyMessage} onSort={onSort} sortBy={sortBy} sortOrder={sortOrder} renderRowExtra={renderRowExtra} onRowClick={onRowClick} />
            )}
          </div>
        )
      })}
    </div>
  )
}

// ─── GroupBy toggle button ─────────────────────────────────
function GroupByToggle({ value, onChange }) {
  return (
    <Button variant={value ? 'primary' : 'ghost'} size="sm" onClick={() => onChange(!value)}>
      {value ? '✕ Flat list' : 'Group by asset'}
    </Button>
  )
}

// ─── Shared helpers ───────────────────────────────────────
const USER_TYPE_COLORS = {
  domain_user:       '#0ea5e9',
  local_user:        '#8b5cf6',
  computer_account:  '#64748b',
  service_account:   '#f59e0b',
  machine_identity:  '#64748b',
  bot:               '#a855f7',
  api_key:           '#ec4899',
  managed_identity:  '#6366f1',
  oauth_app:         '#14b8a6',
  scheduled_task:    '#78716c',
  employee:          '#0ea5e9',
  contractor:        '#f97316',
}
const USER_TYPE_LABELS = {
  domain_user:       'Domain User',
  local_user:        'Local User',
  computer_account:  'Computer',
  service_account:   'Service Acct',
  machine_identity:  'Machine',
  bot:               'Bot',
  api_key:           'API Key',
  managed_identity:  'Managed ID',
  oauth_app:         'OAuth App',
  scheduled_task:    'Sched. Task',
  employee:          'Employee',
  contractor:        'Contractor',
}
function UserTypePill({ type }) {
  return <Pill label={USER_TYPE_LABELS[type] || type} color={USER_TYPE_COLORS[type] || '#64748b'} />
}

function PrivFlag({ yes, label }) {
  if (!yes) return <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 3,
      background: 'var(--danger-subtle)', color: 'var(--danger)', border: '1px solid var(--danger)',
      borderRadius: 4, padding: '2px 7px', fontSize: 11, fontWeight: 600,
    }}>{label}</span>
  )
}

function StatePill({ state }) {
  const s = (state || '').toLowerCase()
  const color = s === 'established' ? '#16a34a' : s === 'listening' || s === 'listen' || s === 'running' ? '#0ea5e9' : '#64748b'
  return <Pill label={state} color={color} />
}

function Count({ n }) {
  return <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{n}</span>
}

// ─── Attack Surface tab ────────────────────────────────────
function AttackSurfaceTab({ scanId, onTabChange }) {
  const { t } = useTranslation()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [fetchError, setFetchError] = useState(null)

  const loadData = () => {
    setLoading(true)
    setFetchError(null)
    getInventorySummary(scanId)
      .then(setData)
      .catch(() => setFetchError('Failed to load inventory data.'))
      .finally(() => setLoading(false))
  }

  useEffect(() => { loadData() }, [scanId])

  if (loading) return <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>{[1,2,3,4,5,6].map(i => <SkeletonCard key={i} lines={2} />)}</div>
  if (fetchError) return <ErrorBanner error={fetchError} onRetry={loadData} onDismiss={() => setFetchError(null)} />
  if (!data) return <EmptyState icon={AlertTriangle} title={t('inventory.noDataYet')} sub={t('inventory.uploadToPopulate')} />

  const { counts, attack_surface: as } = data

  /* helper: section heading */
  const SectionLabel = ({ children }) => (
    <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', padding: '4px 0' }}>
      {children}
    </div>
  )

  /* helper: posture row with severity dot */
  const PostureRow = ({ label, value, severity }) => {
    const dotColor = severity === 'critical' ? '#dc2626' : severity === 'warn' ? '#f59e0b' : severity === 'good' ? '#10b981' : 'var(--text-muted)'
    const numColor = value > 0 ? dotColor : 'var(--text-muted)'
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '5px 0' }}>
        <span style={{ width: 6, height: 6, borderRadius: '50%', background: value > 0 ? dotColor : 'var(--border)', flexShrink: 0 }} />
        <span style={{ flex: 1, fontSize: 13 }}>{label}</span>
        <span style={{ fontWeight: 700, fontSize: 13, color: numColor, fontVariantNumeric: 'tabular-nums' }}>{value}</span>
      </div>
    )
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>

      {/* ── Inventory Overview ── */}
      <div>
        <SectionLabel>Inventory Overview</SectionLabel>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(9, 1fr)', gap: 10, marginTop: 8 }}>
          <StatCard label="Users"          value={counts.users}           icon={Users}    color="#0ea5e9" onClick={() => onTabChange('users')} />
          <StatCard label="Groups"         value={counts.groups}          icon={Shield}   color="#8b5cf6" onClick={() => onTabChange('groups')} />
          <StatCard label="Computers"      value={counts.computers}       icon={Monitor}  color="#06b6d4" onClick={() => onTabChange('computers')} />
          <StatCard label="Databases"      value={counts.database_instances} icon={Database} color="#f59e0b" onClick={() => onTabChange('databases')} />
          <StatCard label="Services"       value={counts.services}        icon={Server}   color="#64748b" onClick={() => onTabChange('services')} />
          <StatCard label="Shares"         value={counts.shares}          icon={Share2}   color="#f59e0b" onClick={() => onTabChange('shares')} />
          <StatCard label="Software"       value={counts.software}        icon={Package}  color="#10b981" onClick={() => onTabChange('software')} />
          <StatCard label="Net Conns"      value={counts.netconns}        icon={Network}  color="#06b6d4" onClick={() => onTabChange('netconns')} />
          <StatCard label="Sched. Tasks"   value={counts.scheduled_tasks} icon={Clock}    color="#f59e0b" onClick={() => onTabChange('tasks')} />
        </div>
      </div>

      {/* ── Security & Compliance ── */}
      <div>
        <SectionLabel>Security & Compliance</SectionLabel>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(9, 1fr)', gap: 10, marginTop: 8 }}>
          <StatCard label="Missing Patches"value={counts.missing_patches} icon={Layers}   color="#dc2626" onClick={() => onTabChange('patches')} />
          <StatCard label="Security Ctrl"  value={counts.security_controls} icon={Lock}   color="#10b981" onClick={() => onTabChange('security')} />
          <StatCard label="Certificates"   value={counts.certificates}   icon={FileText}  color="#8b5cf6" onClick={() => onTabChange('certs')} />
          <StatCard label="Pwd Policy"     value={counts.password_policies} icon={Lock}   color="#dc2626" onClick={() => onTabChange('policy')} />
          <StatCard label="Logged On"      value={counts.logged_on}      icon={LogIn}     color="#0ea5e9" onClick={() => onTabChange('loggedon')} />
          <StatCard label="Processes"      value={counts.processes}       icon={Activity}  color="#64748b" onClick={() => onTabChange('processes')} />
          <StatCard label="Env Variables"  value={counts.env_vars}        icon={Terminal}  color="#f59e0b" onClick={() => onTabChange('envvars')} />
          <StatCard label="AI Tools"       value={counts.ai_tools}        icon={BrainCircuit} color="#8b5cf6" onClick={() => onTabChange('aitools')} />
          <StatCard label="Credentials"    value={counts.credentials}     icon={Key}          color="#ef4444" onClick={() => onTabChange('credentials')} />
        </div>
      </div>

      {/* ── Critical Findings ── */}
      <div>
        <SectionLabel>Critical Findings</SectionLabel>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 14, marginTop: 8 }}>

          {/* Domain Admins */}
          <Card onClick={() => onTabChange('users')} style={{ borderLeft: '3px solid var(--danger)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
              <UserCheck size={15} color="var(--danger)" />
              <span style={{ fontWeight: 700, fontSize: 13 }}>Domain Admins</span>
              <span style={{ marginLeft: 'auto', background: as.domain_admins.length > 0 ? 'var(--danger-subtle)' : 'var(--bg-muted)', color: as.domain_admins.length > 0 ? 'var(--danger)' : 'var(--text-muted)', fontWeight: 700, fontSize: 12, padding: '1px 8px', borderRadius: 10 }}>{as.domain_admins.length}</span>
            </div>
            {as.domain_admins.length === 0
              ? <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>None detected</div>
              : as.domain_admins.slice(0, 6).map((u, i) => (
                <div key={i} style={{ padding: '5px 0', borderBottom: i < Math.min(as.domain_admins.length, 6) - 1 ? '1px solid var(--border)' : 'none', fontSize: 13 }}>
                  <span style={{ fontWeight: 600 }}>{u.domain ? `${u.domain}\\` : ''}{u.username}</span>
                  {u.spns?.length > 0 && <Pill label="Kerberoastable" color="#f59e0b" />}
                </div>
              ))
            }
            {as.domain_admins.length > 6 && <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 6 }}>+{as.domain_admins.length - 6} more</div>}
          </Card>

          {/* Kerberoastable Accounts */}
          <Card onClick={() => onTabChange('users')} style={{ borderLeft: '3px solid var(--warning)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
              <Key size={15} color="var(--warning)" />
              <span style={{ fontWeight: 700, fontSize: 13 }}>Kerberoastable Accounts</span>
              <span style={{ marginLeft: 'auto', background: as.kerberoastable_accounts.length > 0 ? 'var(--warning-subtle)' : 'var(--bg-muted)', color: as.kerberoastable_accounts.length > 0 ? 'var(--warning)' : 'var(--text-muted)', fontWeight: 700, fontSize: 12, padding: '1px 8px', borderRadius: 10 }}>{as.kerberoastable_accounts.length}</span>
            </div>
            {as.kerberoastable_accounts.length === 0
              ? <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>None detected</div>
              : as.kerberoastable_accounts.slice(0, 6).map((u, i) => (
                <div key={i} style={{ padding: '5px 0', borderBottom: i < Math.min(as.kerberoastable_accounts.length, 6) - 1 ? '1px solid var(--border)' : 'none', fontSize: 13 }}>
                  <div style={{ fontWeight: 600 }}>{u.domain ? `${u.domain}\\` : ''}{u.username}</div>
                  {u.spns?.length > 0 && (
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {u.spns.slice(0, 2).join(', ')}{u.spns.length > 2 && ` +${u.spns.length - 2}`}
                    </div>
                  )}
                </div>
              ))
            }
            {as.kerberoastable_accounts.length > 6 && <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 6 }}>+{as.kerberoastable_accounts.length - 6} more</div>}
          </Card>

          {/* Lateral Movement Paths */}
          <Card onClick={() => onTabChange('users')} style={{ borderLeft: '3px solid var(--danger)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
              <Activity size={15} color="var(--danger)" />
              <span style={{ fontWeight: 700, fontSize: 13 }}>Lateral Movement Paths</span>
              <span style={{ marginLeft: 'auto', background: as.lateral_movement_paths.length > 0 ? 'var(--danger-subtle)' : 'var(--bg-muted)', color: as.lateral_movement_paths.length > 0 ? 'var(--danger)' : 'var(--text-muted)', fontWeight: 700, fontSize: 12, padding: '1px 8px', borderRadius: 10 }}>{as.lateral_movement_paths.length}</span>
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8 }}>
              Accounts that are local admin on multiple hosts
            </div>
            {as.lateral_movement_paths.length === 0
              ? <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>None detected</div>
              : as.lateral_movement_paths.slice(0, 6).map((p, i) => (
                <div key={i} style={{ padding: '5px 0', borderBottom: i < Math.min(as.lateral_movement_paths.length, 6) - 1 ? '1px solid var(--border)' : 'none', fontSize: 13 }}>
                  <div style={{ fontWeight: 600 }}>{p.account}</div>
                  <div style={{ fontSize: 11, color: 'var(--info)', marginTop: 2 }}>
                    Admin on {p.asset_ids.length} hosts
                  </div>
                </div>
              ))
            }
          </Card>
        </div>
      </div>

      {/* ── Security Posture + Infrastructure ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>

        {/* Security Posture */}
        <Card onClick={() => onTabChange('security')}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
            <Shield size={15} color="#f59e0b" />
            <span style={{ fontWeight: 700, fontSize: 13 }}>Security Posture</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 24px' }}>
            <PostureRow label="Password never expires"  value={as.password_never_expires_count}  severity="warn" />
            <PostureRow label="Weak password policies"  value={as.weak_password_policies || 0}   severity="critical" />
            <PostureRow label="Never changed password"  value={as.never_changed_password_count}   severity="critical" />
            <PostureRow label="Local admin accounts"    value={as.local_admins_count}             severity="warn" />
            <PostureRow label="Writeable shares"        value={as.writeable_shares || 0}          severity="warn" />
            <PostureRow label="Hosts with AV enabled"   value={as.hosts_with_av || 0}            severity="good" />
            <PostureRow label="Established connections"  value={as.established_connections}        severity="info" />
            <PostureRow label="Sensitive env variables"  value={as.sensitive_env_vars || 0}        severity="critical" />
            <PostureRow label="Expired certificates"     value={as.expired_certs || 0}            severity="critical" />
            <PostureRow label="Expiring soon (≤30d)"     value={as.expiring_soon_certs || 0}      severity="warn" />
            <PostureRow label="Self-signed certificates" value={as.self_signed_certs || 0}        severity="warn" />
          </div>
        </Card>

        {/* Right column: Domain Controllers + Logged On stacked */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {/* Domain Controllers */}
          {as.domain_controllers?.length > 0 && (
            <Card onClick={() => onTabChange('computers')}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
                <Monitor size={15} color="#dc2626" />
                <span style={{ fontWeight: 700, fontSize: 13 }}>Domain Controllers</span>
                <Count n={as.domain_controllers.length} />
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {as.domain_controllers.map((c, i) => (
                  <div key={i} style={{
                    background: 'var(--bg-muted)', border: '1px solid var(--border)',
                    borderRadius: 6, padding: '4px 10px', fontSize: 12,
                  }}>
                    <span style={{ fontWeight: 600 }}>{c.computer_name}</span>
                    {c.os && <span style={{ color: 'var(--text-muted)', fontSize: 11 }}> · {c.os}</span>}
                  </div>
                ))}
              </div>
            </Card>
          )}

          {/* Logged-on users */}
          {as.logged_on_users?.length > 0 && (
            <Card onClick={() => onTabChange('loggedon')}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
                <LogIn size={15} color="#0ea5e9" />
                <span style={{ fontWeight: 700, fontSize: 13 }}>Currently Logged On</span>
                <Count n={as.logged_on_users.length} />
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {as.logged_on_users.map((u, i) => (
                  <div key={i} style={{
                    background: 'var(--bg-muted)', border: '1px solid var(--border)',
                    borderRadius: 6, padding: '4px 10px', fontSize: 12,
                  }}>
                    <span style={{ fontWeight: 600 }}>{u.domain}\\{u.username}</span>
                    <span style={{ color: 'var(--text-muted)', fontSize: 11 }}> · {u.asset_label}</span>
                  </div>
                ))}
              </div>
            </Card>
          )}
        </div>
      </div>

      {/* ── Top Missing Patches ── */}
      {as.top_missing_patches?.length > 0 && (
        <Card onClick={() => onTabChange('patches')}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
            <Layers size={15} color="#dc2626" />
            <span style={{ fontWeight: 700, fontSize: 13 }}>Top Missing Patches</span>
          </div>
          <Table
            columns={[
              { key: 'kb_id', label: 'Patch / Advisory', width: '40%' },
              { key: 'asset_label', label: 'Asset', width: '15%', render: v => <span style={{ fontSize: 12, fontFamily: 'monospace', color: 'var(--text-muted)' }}>{v}</span> },
              { key: 'vuln_count', label: 'CVEs Fixed', width: '20%',
                render: v => <span style={{ fontWeight: 700, color: v > 0 ? '#dc2626' : 'var(--text-muted)' }}>{v}</span> },
            ]}
            rows={as.top_missing_patches}
          />
        </Card>
      )}
    </div>
  )
}

// ─── Identity type & source badges ────────────────────────
const IDENTITY_TYPE_CONFIG = {
  human:     { label: 'Human',     color: '#16a34a', icon: User },
  non_human: { label: 'Non-Human', color: '#9333ea', icon: Bot },
  unknown:   { label: 'Unknown',   color: '#64748b', icon: Users },
}

function IdentityTypeBadge({ type }) {
  const cfg = IDENTITY_TYPE_CONFIG[type] || IDENTITY_TYPE_CONFIG.unknown
  const Icon = cfg.icon
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600,
      background: cfg.color + '18', color: cfg.color, border: `1px solid ${cfg.color}44`,
    }}>
      <Icon size={11} />{cfg.label}
    </span>
  )
}

const SOURCE_COLORS = {
  'Active Directory': '#0ea5e9', 'Windows': '#0078d4', 'Linux': '#f59e0b',
  'macOS': '#64748b', 'AWS': '#ff9900', 'Azure': '#0078d4', 'GCP': '#4285f4',
  'OCI': '#f80000', 'Okta': '#007dc1', 'GitHub': '#8b5cf6', 'Other': '#94a3b8',
}

function SourceBadges({ sources }) {
  if (!sources?.length) return <Count n="—" />
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
      {sources.map(s => (
        <span key={s} style={{
          display: 'inline-block', padding: '1px 6px', borderRadius: 3, fontSize: 10, fontWeight: 600,
          background: (SOURCE_COLORS[s] || '#94a3b8') + '22', color: SOURCE_COLORS[s] || '#94a3b8',
          border: `1px solid ${SOURCE_COLORS[s] || '#94a3b8'}44`, whiteSpace: 'nowrap',
        }}>{s}</span>
      ))}
    </div>
  )
}

// ─── User Detail Side Panel ───────────────────────────────
function UserDetailPanel({ user, onClose }) {
  if (!user) return null
  const sections = [
    { label: 'Identity', items: [
      ['Username', user.domain ? `${user.domain}\\${user.username}` : user.username],
      ['Identity Type', <IdentityTypeBadge type={user.identity_type} />],
      ['Account Type', <UserTypePill type={user.user_type} />],
      ['Subtype', user.identity_subtype || '—'],
      ['SID', user.sid || '—'],
      ['RID', user.rid ?? '—'],
      ['DN', user.dn || '—'],
    ]},
    { label: 'Organization', show: user.identity_type !== 'non_human', items: [
      ['Department', user.department || '—'],
      ['Job Title', user.job_title || '—'],
      ['Manager', user.manager_username ? (
        <span style={{ color: 'var(--accent)', cursor: 'pointer' }}>{user.manager_username}</span>
      ) : <span style={{ color: 'var(--text-muted)' }}>— <span style={{ fontSize: 10, color: '#0ea5e960', cursor: 'pointer' }}>Enrich</span></span>],
    ]},
    { label: 'Privileges', items: [
      ['Local Admin', user.is_local_admin ? <PrivFlag yes={true} label="Admin" /> : '—'],
      ['Domain Admin', user.is_domain_admin ? <PrivFlag yes={true} label="DA" /> : '—'],
      ['Privileged', user.is_privileged ? <PrivFlag yes={true} label="Privileged" /> : '—'],
    ]},
    { label: 'Account State', items: [
      ['Disabled', user.is_disabled ? <Pill label="Disabled" color="#64748b" /> : 'Active'],
      ['Password Never Expires', user.password_never_expires ? <Pill label="Yes" color="#dc2626" /> : 'No'],
      ['Password Last Set', user.password_last_set || '—'],
      ['Date Joined', user.date_joined || '—'],
      ['Never Logged In', user.never_logged_in ? 'Yes' : 'No'],
      ['Never Changed Password', user.never_changed_password ? 'Yes' : 'No'],
    ]},
    { label: 'Sources', items: [
      ['Systems', <SourceBadges sources={user.source_systems} />],
      ['Source Plugin', user.source_plugin || '—'],
      ['Last Logon Host', user.last_logon_host || '—'],
      ['Asset', user.asset_label || '—'],
    ]},
  ]

  return (
    <>
      <div style={{ position: 'fixed', inset: 0, zIndex: 999, background: 'rgba(0,0,0,0.35)' }} onClick={onClose} />
      <div style={{
        position: 'fixed', top: 0, right: 0, bottom: 0, width: 520, zIndex: 1000,
        background: 'var(--bg-card)', borderLeft: '1px solid var(--border)',
        boxShadow: '-8px 0 32px rgba(0,0,0,0.25)', overflowY: 'auto', padding: 0,
      }}>
        {/* Header */}
        <div style={{
          padding: '20px 24px 16px', borderBottom: '1px solid var(--border)',
          display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start',
        }}>
          <div>
            <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 6 }}>
              {user.username}
            </div>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
              <IdentityTypeBadge type={user.identity_type} />
              <SourceBadges sources={user.source_systems} />
            </div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 4 }}>
            <X size={18} />
          </button>
        </div>

        {/* Sections */}
        <div style={{ padding: '8px 24px 24px' }}>
          {sections.filter(s => s.show !== false).map(sec => (
            <div key={sec.label} style={{ marginTop: 16 }}>
              <div style={{
                fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase',
                letterSpacing: '0.06em', marginBottom: 8,
              }}>{sec.label}</div>
              <div style={{ display: 'grid', gap: 6 }}>
                {sec.items.map(([k, v]) => (
                  <div key={k} style={{ display: 'flex', fontSize: 13, gap: 8 }}>
                    <span style={{ color: 'var(--text-muted)', minWidth: 140, flexShrink: 0 }}>{k}</span>
                    <span style={{ color: 'var(--text-primary)', wordBreak: 'break-all' }}>{v}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}

          {/* Groups */}
          {user.member_of?.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <div style={{
                fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase',
                letterSpacing: '0.06em', marginBottom: 8,
              }}>Group Memberships ({user.member_of.length})</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                {user.member_of.map((g, i) => (
                  <span key={i} style={{
                    display: 'inline-block', padding: '2px 8px', fontSize: 12,
                    background: 'var(--bg-primary)', border: '1px solid var(--border)',
                    borderRadius: 4, color: 'var(--text-primary)',
                  }}>{g}</span>
                ))}
              </div>
            </div>
          )}

          {/* SPNs */}
          {user.spns?.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <div style={{
                fontSize: 11, fontWeight: 700, color: '#f59e0b', textTransform: 'uppercase',
                letterSpacing: '0.06em', marginBottom: 8,
              }}>Kerberoastable SPNs ({user.spns.length})</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                {user.spns.map((s, i) => (
                  <span key={i} style={{
                    fontSize: 12, padding: '3px 8px', background: '#f59e0b12', border: '1px solid #f59e0b33',
                    borderRadius: 4, color: '#f59e0b', fontFamily: 'monospace',
                  }}>{s}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  )
}

// ─── Org Tree View ────────────────────────────────────────
function OrgTreeNode({ node, depth, searchTerm, onSelect }) {
  const [expanded, setExpanded] = useState(depth < 2)
  const hasChildren = node.children?.length > 0
  const matchesSearch = searchTerm && node.username?.toLowerCase().includes(searchTerm.toLowerCase())
  const riskColor = node.is_domain_admin ? '#dc2626' : node.is_privileged ? '#f59e0b' : 'var(--border)'

  return (
    <div>
      <div
        onClick={() => onSelect(node)}
        style={{
          display: 'flex', alignItems: 'center', gap: 8, padding: '6px 10px',
          marginLeft: depth * 24, cursor: 'pointer',
          borderLeft: depth > 0 ? `2px solid ${riskColor}` : 'none',
          background: matchesSearch ? '#f59e0b18' : 'transparent',
          borderRadius: 4, transition: 'background 0.15s',
        }}
        onMouseEnter={e => { if (!matchesSearch) e.currentTarget.style.background = 'var(--bg-secondary)' }}
        onMouseLeave={e => { if (!matchesSearch) e.currentTarget.style.background = 'transparent' }}
      >
        {hasChildren ? (
          <button
            onClick={e => { e.stopPropagation(); setExpanded(!expanded) }}
            style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, color: 'var(--text-muted)', display: 'flex' }}
          >
            {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
          </button>
        ) : <span style={{ width: 14 }} />}
        <User size={14} style={{ color: riskColor === 'var(--border)' ? 'var(--text-muted)' : riskColor, flexShrink: 0 }} />
        <span style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-primary)' }}>{node.username}</span>
        {node.job_title && <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{node.job_title}</span>}
        {node.department && <Pill label={node.department} color="#64748b" />}
        {hasChildren && <span style={{ fontSize: 10, color: 'var(--text-muted)', marginLeft: 'auto' }}>{node.children.length} report{node.children.length !== 1 ? 's' : ''}</span>}
      </div>
      {expanded && hasChildren && node.children.map(child => (
        <OrgTreeNode key={child.id || child.username} node={child} depth={depth + 1} searchTerm={searchTerm} onSelect={onSelect} />
      ))}
    </div>
  )
}

function OrgTreeView({ scanId, onSelectUser }) {
  const [tree, setTree] = useState(null)
  const [loading, setLoading] = useState(true)
  const [treeSearch, setTreeSearch] = useState('')

  useEffect(() => {
    setLoading(true)
    getInventoryUserOrgTree({ scan_id: scanId })
      .then(data => setTree(data))
      .catch(() => setTree(null))
      .finally(() => setLoading(false))
  }, [scanId])

  if (loading) return <Spinner />
  if (!tree || !tree.roots?.length) {
    return (
      <EmptyState
        icon={GitBranch}
        message="No org tree available — manager data is required. Upload a credentialed AD scan with manager attributes."
      />
    )
  }

  const coverage = tree.total_users > 0 ? Math.round((tree.total_with_manager / tree.total_users) * 100) : 0

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12 }}>
        <div style={{ position: 'relative', flex: 1, maxWidth: 280 }}>
          <Search size={14} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
          <input
            value={treeSearch} onChange={e => setTreeSearch(e.target.value)}
            placeholder="Search tree…"
            style={{
              width: '100%', padding: '7px 10px 7px 30px', fontSize: 12,
              background: 'var(--bg-secondary)', border: '1px solid var(--border)',
              borderRadius: 6, color: 'var(--text-primary)', outline: 'none',
            }}
          />
        </div>
        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
          {tree.total_users} users, {coverage}% have manager data
        </span>
      </div>
      <div style={{ border: '1px solid var(--border)', borderRadius: 8, padding: 8, maxHeight: 600, overflowY: 'auto' }}>
        {tree.roots.map(root => (
          <OrgTreeNode key={root.id || root.username} node={root} depth={0} searchTerm={treeSearch} onSelect={onSelectUser} />
        ))}
      </div>
    </div>
  )
}

// ─── Users tab ─────────────────────────────────────────────
function UsersTab({ scanId, assetId }) {
  const [rows, setRows]               = useState([])
  const [total, setTotal]             = useState(0)
  const [page, setPage]               = useState(1)
  const [loading, setLoading]         = useState(true)
  const [search, setSearch]           = useState('')
  const [userType, setUserType]       = useState(null)
  const [identityType, setIdentityType] = useState(null)
  const [identitySubtype, setIdentitySubtype] = useState(null)
  const [department, setDepartment]   = useState('')
  const [isAdmin, setIsAdmin]         = useState(null)
  const [isDA, setIsDA]               = useState(null)
  const [groupByAsset, setGroupByAsset] = useState(false)
  const [sortBy, setSortBy]           = useState('username')
  const [sortOrder, setSortOrder]     = useState('asc')
  const [selectedUser, setSelectedUser] = useState(null)
  const [viewMode, setViewMode]       = useState('table') // 'table' | 'org_tree'

  const handleSort = (key) => {
    if (sortBy === key) { setSortOrder(o => o === 'asc' ? 'desc' : 'asc') }
    else { setSortBy(key); setSortOrder('asc') }
  }

  // Reset page when filters change
  useEffect(() => { setPage(1) }, [scanId, assetId, search, userType, identityType, identitySubtype, department, isAdmin, isDA])

  const load = useCallback(() => {
    if (viewMode === 'org_tree') return
    setLoading(true)
    getInventoryUsers({
      scan_id: scanId,
      asset_id: assetId || null,
      search: search || null,
      user_type: userType,
      identity_type: identityType,
      identity_subtype: identitySubtype,
      department: department || null,
      is_admin: isAdmin,
      is_domain_admin: isDA,
      sort_by: sortBy,
      order: sortOrder,
      page,
      page_size: INV_PAGE_SIZE,
    }).then(data => { setRows(data.users); setTotal(data.total) }).catch(() => { setRows([]); setTotal(0) }).finally(() => setLoading(false))
  }, [scanId, assetId, search, userType, identityType, identitySubtype, department, isAdmin, isDA, sortBy, sortOrder, page, viewMode])

  useEffect(() => { load() }, [load])

  const columns = [
    { key: 'username',  label: 'Username', width: '15%', sortable: true,
      render: (v, r) => (
        <span style={{ fontWeight: 600, cursor: 'pointer' }} onClick={() => setSelectedUser(r)}>
          {r.domain ? `${r.domain}\\` : ''}{v}
        </span>
      )
    },
    { key: 'identity_type', label: 'Identity', width: '9%', sortable: true,
      render: v => <IdentityTypeBadge type={v} />
    },
    { key: 'user_type', label: 'Role / Subtype', width: '11%', sortable: true,
      render: (v, r) => <UserTypePill type={r.identity_subtype || v} />
    },
    { key: 'source_systems', label: 'Sources', width: '11%',
      render: v => <SourceBadges sources={v} />
    },
    { key: 'department', label: 'Department', width: '9%', sortable: true,
      render: v => v ? <span style={{ fontSize: 12 }}>{v}</span> : <Count n="—" />
    },
    { key: 'manager_username', label: 'Manager', width: '9%', sortable: true,
      render: (v) => v ? (
        <span style={{ fontSize: 12, color: 'var(--accent)', cursor: 'pointer' }}
          onClick={e => { e.stopPropagation(); /* could filter to manager */ }}
        >{v}</span>
      ) : <Count n="—" />
    },
    { key: 'is_local_admin',   label: 'Local Admin',   width: '8%', sortable: true, render: v => <PrivFlag yes={v} label="Admin" /> },
    { key: 'is_domain_admin',  label: 'Domain Admin',  width: '8%', sortable: true, render: v => <PrivFlag yes={v} label="DA" /> },
    { key: 'spns', label: 'Kerberoastable', width: '9%',
      render: v => v?.length > 0 ? <Pill label={`${v.length} SPN`} color="#f59e0b" /> : <Count n="—" />
    },
    { key: 'asset_label', label: 'Asset', width: '11%',
      render: (v, r) => <>{v}<EnvPill env={r.asset_env} /></>
    },
  ]

  // Identity type toggle buttons
  const identityButtons = [
    { value: null,        label: 'All',       color: 'var(--text-muted)' },
    { value: 'human',     label: 'Human',     color: '#16a34a' },
    { value: 'non_human', label: 'Non-Human', color: '#9333ea' },
  ]

  const em = "No users found — try clearing filters or upload a credentialed scan."
  return (
    <Card>
      {/* Primary identity type filter */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 10 }}>
        {identityButtons.map(b => (
          <button key={String(b.value)} onClick={() => {
            setIdentityType(b.value)
            setIdentitySubtype(null)
            setDepartment('')
          }} style={{
            padding: '5px 14px', borderRadius: 6, fontSize: 12, fontWeight: 600,
            cursor: 'pointer', transition: 'all 0.15s',
            background: identityType === b.value ? b.color + '18' : 'transparent',
            color: identityType === b.value ? b.color : 'var(--text-muted)',
            border: `1px solid ${identityType === b.value ? b.color + '66' : 'var(--border)'}`,
          }}>{b.label}</button>
        ))}
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 4 }}>
          <button onClick={() => setViewMode('table')} style={{
            padding: '4px 10px', borderRadius: 4, fontSize: 11, fontWeight: 600, cursor: 'pointer',
            background: viewMode === 'table' ? 'var(--accent)' + '22' : 'transparent',
            color: viewMode === 'table' ? 'var(--accent)' : 'var(--text-muted)',
            border: `1px solid ${viewMode === 'table' ? 'var(--accent)44' : 'var(--border)'}`,
          }}>Table</button>
          <button
            onClick={() => setViewMode('org_tree')}
            title="Show org hierarchy"
            style={{
              padding: '4px 10px', borderRadius: 4, fontSize: 11, fontWeight: 600, cursor: 'pointer',
              background: viewMode === 'org_tree' ? 'var(--accent)' + '22' : 'transparent',
              color: viewMode === 'org_tree' ? 'var(--accent)' : 'var(--text-muted)',
              border: `1px solid ${viewMode === 'org_tree' ? 'var(--accent)44' : 'var(--border)'}`,
            }}>
            <GitBranch size={11} style={{ marginRight: 3, verticalAlign: -1 }} />Org Tree
          </button>
        </div>
      </div>

      {/* Secondary filters */}
      <FilterBar>
        <Input value={search} onChange={setSearch} placeholder="Search username / domain / dept…" style={{ width: 220 }} />
        <Select value={userType} onChange={setUserType} placeholder="All types" options={[
          { value: 'domain_user',      label: 'Domain User' },
          { value: 'local_user',       label: 'Local User' },
          { value: 'computer_account', label: 'Computer Account' },
          { value: 'service_account',  label: 'Service Account' },
        ]} />
        {identityType === 'non_human' && (
          <Select value={identitySubtype} onChange={setIdentitySubtype} placeholder="All subtypes" options={[
            { value: 'service_account',  label: 'Service Account' },
            { value: 'machine_identity', label: 'Machine Identity' },
            { value: 'bot',              label: 'Bot' },
            { value: 'api_key',          label: 'API Key' },
            { value: 'managed_identity', label: 'Managed Identity' },
            { value: 'oauth_app',        label: 'OAuth App' },
            { value: 'scheduled_task',   label: 'Scheduled Task' },
          ]} />
        )}
        {identityType === 'human' && (
          <Input value={department} onChange={setDepartment} placeholder="Department…" style={{ width: 150 }} />
        )}
        <Select value={isAdmin === null ? '' : String(isAdmin)} onChange={v => setIsAdmin(v === '' ? null : v === 'true')} placeholder="Any admin status" options={[
          { value: 'true',  label: 'Local Admin only' },
          { value: 'false', label: 'Non-admin only' },
        ]} />
        <Select value={isDA === null ? '' : String(isDA)} onChange={v => setIsDA(v === '' ? null : v === 'true')} placeholder="Any DA status" options={[
          { value: 'true', label: 'Domain Admins only' },
        ]} />
        {viewMode === 'table' && <GroupByToggle value={groupByAsset} onChange={setGroupByAsset} />}
      </FilterBar>

      {/* Content */}
      {viewMode === 'org_tree' ? (
        <OrgTreeView scanId={scanId} onSelectUser={setSelectedUser} />
      ) : loading ? <Spinner /> : groupByAsset
        ? <GroupedTable columns={columns} rows={rows} emptyMessage={em} onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} onRowClick={setSelectedUser} />
        : <Table columns={columns} rows={rows} emptyMessage={em} onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} onRowClick={setSelectedUser} />
      }
      {viewMode === 'table' && <Pagination page={page} total={total} pageSize={INV_PAGE_SIZE} onPageChange={setPage} noun="users" />}

      {/* Detail side panel */}
      {selectedUser && <UserDetailPanel user={selectedUser} onClose={() => setSelectedUser(null)} />}
    </Card>
  )
}

// ─── Groups tab ────────────────────────────────────────────
function GroupsTab({ scanId, assetId }) {
  const [rows, setRows]               = useState([])
  const [total, setTotal]             = useState(0)
  const [page, setPage]               = useState(1)
  const [loading, setLoading]         = useState(true)
  const [privOnly, setPrivOnly]       = useState(false)
  const [groupByAsset, setGroupByAsset] = useState(false)
  const [sortBy, setSortBy]           = useState('group_name')
  const [sortOrder, setSortOrder]     = useState('asc')
  const [expandedGroupId, setExpandedGroupId] = useState(null)

  const handleSort = (key) => {
    if (sortBy === key) { setSortOrder(o => o === 'asc' ? 'desc' : 'asc') }
    else { setSortBy(key); setSortOrder('asc') }
  }

  useEffect(() => { setPage(1) }, [scanId, assetId, privOnly])

  useEffect(() => {
    setLoading(true)
    getInventoryGroups({ scan_id: scanId, asset_id: assetId || null, is_privileged: privOnly || null, sort_by: sortBy, order: sortOrder, page, page_size: INV_PAGE_SIZE })
      .then(data => { setRows(data.groups); setTotal(data.total) }).catch(() => { setRows([]); setTotal(0) }).finally(() => setLoading(false))
  }, [scanId, assetId, privOnly, sortBy, sortOrder, page])

  const columns = [
    { key: 'group_name', label: 'Group Name', width: '23%', sortable: true, render: (v, r) => (
      <span style={{ fontWeight: 600, color: r.is_privileged ? '#fca5a5' : 'var(--text-primary)' }}>{v}</span>
    )},
    { key: 'domain',      label: 'Domain',     width: '18%', sortable: true },
    { key: 'is_privileged', label: 'Privileged', width: '12%', sortable: true,
      render: v => v ? <Pill label="High-Value" color="#dc2626" /> : <Count n="—" />
    },
    { key: 'members', label: 'Members', width: '10%',
      render: (v, r) => {
        const count = v?.length || 0
        if (count === 0) return <Count n={0} />
        return (
          <span
            style={{ fontSize: 12, color: 'var(--accent)', cursor: 'pointer', textDecoration: 'underline', fontWeight: 500 }}
            onClick={e => { e.stopPropagation(); setExpandedGroupId(prev => prev === r.id ? null : r.id) }}
          >{count}</span>
        )
      }
    },
    { key: 'description', label: 'Description', width: '25%',
      render: v => <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{v || '—'}</span>
    },
    { key: 'asset_label', label: 'Asset', width: '12%',
      render: (v, r) => <>{v}<EnvPill env={r.asset_env} /></>
    },
  ]

  const renderMembersExtra = (row) => {
    if (expandedGroupId !== row.id || !row.members?.length) return null
    return (
      <div style={{ padding: '8px 12px 12px 12px', background: 'var(--bg-secondary)' }}>
        <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6 }}>
          Members ({row.members.length})
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
          {row.members.map((m, i) => (
            <span key={i} style={{
              display: 'inline-block', padding: '2px 8px', fontSize: 12,
              background: 'var(--bg-primary)', border: '1px solid var(--border)',
              borderRadius: 4, color: 'var(--text-primary)',
            }}>{m}</span>
          ))}
        </div>
      </div>
    )
  }

  return (
    <Card>
      <FilterBar>
        <Button variant={privOnly ? 'danger' : 'ghost'} size="sm" onClick={() => setPrivOnly(p => !p)}>
          {privOnly ? '✕ Privileged only' : 'Show privileged only'}
        </Button>
        <GroupByToggle value={groupByAsset} onChange={setGroupByAsset} />
      </FilterBar>
      {loading ? <Spinner /> : groupByAsset
        ? <GroupedTable columns={columns} rows={rows} emptyMessage="No groups found." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} renderRowExtra={renderMembersExtra} />
        : <Table columns={columns} rows={rows} emptyMessage="No groups found." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} renderRowExtra={renderMembersExtra} />
      }
      <Pagination page={page} total={total} pageSize={INV_PAGE_SIZE} onPageChange={setPage} noun="groups" />
    </Card>
  )
}

// ─── Computers tab ──────────────────────────────────────
function ComputersTab({ scanId, assetId }) {
  const [rows, setRows]               = useState([])
  const [total, setTotal]             = useState(0)
  const [page, setPage]               = useState(1)
  const [loading, setLoading]         = useState(true)
  const [search, setSearch]           = useState('')
  const [dcOnly, setDcOnly]           = useState(false)
  const [groupByAsset, setGroupByAsset] = useState(false)
  const [sortBy, setSortBy]           = useState('computer_name')
  const [sortOrder, setSortOrder]     = useState('asc')

  const handleSort = (key) => {
    if (sortBy === key) { setSortOrder(o => o === 'asc' ? 'desc' : 'asc') }
    else { setSortBy(key); setSortOrder('asc') }
  }

  useEffect(() => { setPage(1) }, [scanId, assetId, search, dcOnly])

  const load = useCallback(() => {
    setLoading(true)
    getInventoryComputers({ scan_id: scanId, asset_id: assetId || null, search: search || null, is_dc: dcOnly || null, sort_by: sortBy, order: sortOrder, page, page_size: INV_PAGE_SIZE })
      .then(data => { setRows(data.computers); setTotal(data.total) }).catch(() => { setRows([]); setTotal(0) }).finally(() => setLoading(false))
  }, [scanId, assetId, search, dcOnly, sortBy, sortOrder, page])

  useEffect(() => { load() }, [load])

  const columns = [
    { key: 'computer_name', label: 'Computer Name', width: '20%', sortable: true,
      render: (v, r) => (
        <span style={{ fontWeight: 600, color: r.is_domain_controller ? '#fca5a5' : 'var(--text-primary)' }}>
          {v}
          {r.is_domain_controller && <Pill label="DC" color="#dc2626" />}
        </span>
      )
    },
    { key: 'dns_hostname', label: 'DNS Hostname', width: '20%', sortable: true,
      render: v => <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{v || '—'}</span>
    },
    { key: 'os', label: 'Operating System', width: '23%', sortable: true,
      render: (v, r) => (
        <span style={{ fontSize: 13 }}>
          {v || '—'}
          {r.os_version && <span style={{ color: 'var(--text-muted)', fontSize: 11 }}> ({r.os_version})</span>}
        </span>
      )
    },
    { key: 'is_disabled', label: 'Status', width: '10%', sortable: true,
      render: v => v ? <Pill label="Disabled" color="#64748b" /> : <Pill label="Active" color="#16a34a" />
    },
    { key: 'date_joined', label: 'Joined', width: '13%', sortable: true,
      render: v => <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{v || '—'}</span>
    },
    { key: 'asset_label', label: 'Asset', width: '14%',
      render: (v, r) => <>{v}<EnvPill env={r.asset_env} /></>
    },
  ]

  return (
    <Card>
      <FilterBar>
        <Input value={search} onChange={setSearch} placeholder="Search computer name…" style={{ width: 220 }} />
        <Button variant={dcOnly ? 'danger' : 'ghost'} size="sm" onClick={() => setDcOnly(p => !p)}>
          {dcOnly ? '✕ DCs only' : 'Show DCs only'}
        </Button>
        <GroupByToggle value={groupByAsset} onChange={setGroupByAsset} />
      </FilterBar>
      {loading ? <Spinner /> : groupByAsset
        ? <GroupedTable columns={columns} rows={rows} emptyMessage="No AD computer objects found." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
        : <Table columns={columns} rows={rows} emptyMessage="No AD computer objects found." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
      }
      <Pagination page={page} total={total} pageSize={INV_PAGE_SIZE} onPageChange={setPage} noun="computers" />
    </Card>
  )
}

// ─── Databases tab ─────────────────────────────────────────
const DB_TYPE_COLORS = {
  mssql:      { label: 'MSSQL',      bg: '#0ea5e922', color: '#0ea5e9' },
  mysql:      { label: 'MySQL',      bg: '#f59e0b22', color: '#f59e0b' },
  postgresql: { label: 'PostgreSQL', bg: '#6366f122', color: '#818cf8' },
  oracle:     { label: 'Oracle',     bg: '#dc262622', color: '#f87171' },
  mongodb:    { label: 'MongoDB',    bg: '#10b98122', color: '#34d399' },
  redis:      { label: 'Redis',      bg: '#ef444422', color: '#f87171' },
}

function DbTypePill({ type }) {
  const cfg = DB_TYPE_COLORS[type] || { label: type, bg: '#6b728022', color: '#9ca3af' }
  return (
    <span style={{
      display: 'inline-block', padding: '2px 7px', borderRadius: 4,
      background: cfg.bg, color: cfg.color, fontSize: 11, fontWeight: 700,
    }}>{cfg.label}</span>
  )
}

function DatabasesTab({ scanId, assetId }) {
  const [rows, setRows]     = useState([])
  const [total, setTotal]   = useState(0)
  const [page, setPage]     = useState(1)
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [dbType, setDbType] = useState('')
  const [sortBy, setSortBy] = useState('db_type')
  const [sortOrder, setSortOrder] = useState('asc')

  const handleSort = (key) => {
    if (sortBy === key) { setSortOrder(o => o === 'asc' ? 'desc' : 'asc') }
    else { setSortBy(key); setSortOrder('asc') }
  }

  useEffect(() => { setPage(1) }, [scanId, assetId, search, dbType])

  const load = useCallback(() => {
    setLoading(true)
    getInventoryDatabases({ scan_id: scanId, asset_id: assetId || null, search: search || null, db_type: dbType || null, sort_by: sortBy, order: sortOrder, page, page_size: INV_PAGE_SIZE })
      .then(data => { setRows(data.databases); setTotal(data.total) }).catch(() => { setRows([]); setTotal(0) }).finally(() => setLoading(false))
  }, [scanId, assetId, search, dbType, sortBy, sortOrder, page])

  useEffect(() => { load() }, [load])

  const columns = [
    { key: 'db_type', label: 'Type', width: '10%', sortable: true,
      render: v => <DbTypePill type={v} />
    },
    { key: 'instance_name', label: 'Instance', width: '18%', sortable: true,
      render: v => <span style={{ fontWeight: 600 }}>{v || <span style={{ color: 'var(--text-muted)' }}>default</span>}</span>
    },
    { key: 'version', label: 'Version', width: '22%', sortable: true,
      render: v => <span style={{ fontSize: 12, color: 'var(--text-muted)', fontFamily: 'monospace' }}>{v || '—'}</span>
    },
    { key: 'port', label: 'Port', width: '8%', sortable: true,
      render: v => v ? <span style={{ fontSize: 12, fontFamily: 'monospace' }}>{v}</span> : <span style={{ color: 'var(--text-muted)' }}>—</span>
    },
    { key: 'is_running', label: 'State', width: '9%',
      render: v => <Pill label={v ? 'Running' : 'Stopped'} color={v ? '#16a34a' : '#64748b'} />
    },
    { key: 'asset_label', label: 'Asset', width: '15%',
      render: (v, r) => <>{v}<EnvPill env={r.asset_env} /></>
    },
    { key: 'asset_ip', label: 'IP', width: '12%',
      render: v => <span style={{ fontSize: 12, color: 'var(--text-muted)', fontFamily: 'monospace' }}>{v || '—'}</span>
    },
  ]

  const dbTypes = [...new Set(rows.map(r => r.db_type).filter(Boolean))]

  return (
    <Card>
      <FilterBar>
        <Input value={search} onChange={setSearch} placeholder="Search instance or version…" style={{ width: 220 }} />
        <select
          value={dbType}
          onChange={e => setDbType(e.target.value)}
          style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: dbType ? 'var(--text-primary)' : 'var(--text-muted)', borderRadius: 6, padding: '5px 8px', fontSize: 12 }}
        >
          <option value="">All Types</option>
          {dbTypes.map(t => <option key={t} value={t}>{DB_TYPE_COLORS[t]?.label || t}</option>)}
        </select>
      </FilterBar>
      {loading ? <Spinner /> : (
        <Table columns={columns} rows={rows} emptyMessage="No database instances detected. Upload a scan that includes MSSQL (plugin 10144), MySQL (10719), PostgreSQL (26028), or Oracle (22689) detection results." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
      )}
      <Pagination page={page} total={total} pageSize={INV_PAGE_SIZE} onPageChange={setPage} noun="instances" />
    </Card>
  )
}

// ─── Services tab ──────────────────────────────────────────
function ServicesTab({ scanId, assetId }) {
  const [rows, setRows]               = useState([])
  const [total, setTotal]             = useState(0)
  const [page, setPage]               = useState(1)
  const [loading, setLoading]         = useState(true)
  const [search, setSearch]           = useState('')
  const [groupByAsset, setGroupByAsset] = useState(false)
  const [sortBy, setSortBy]           = useState('display_name')
  const [sortOrder, setSortOrder]     = useState('asc')

  const handleSort = (key) => {
    if (sortBy === key) { setSortOrder(o => o === 'asc' ? 'desc' : 'asc') }
    else { setSortBy(key); setSortOrder('asc') }
  }

  useEffect(() => { setPage(1) }, [scanId, assetId, search])

  const load = useCallback(() => {
    setLoading(true)
    getInventoryServices({ scan_id: scanId, asset_id: assetId || null, search: search || null, sort_by: sortBy, order: sortOrder, page, page_size: INV_PAGE_SIZE })
      .then(data => { setRows(data.services); setTotal(data.total) }).catch(() => { setRows([]); setTotal(0) }).finally(() => setLoading(false))
  }, [scanId, assetId, search, sortBy, sortOrder, page])

  useEffect(() => { load() }, [load])

  const columns = [
    { key: 'display_name', label: 'Display Name', width: '38%', sortable: true,
      render: v => <span style={{ fontWeight: 600 }}>{v}</span>
    },
    { key: 'service_name', label: 'Service Name', width: '25%', sortable: true,
      render: v => <code style={{ fontSize: 12, background: 'var(--bg-muted)', padding: '2px 6px', borderRadius: 4 }}>{v}</code>
    },
    { key: 'is_running', label: 'Status', width: '12%', sortable: true,
      render: v => <StatePill state={v ? 'Running' : 'Stopped'} />
    },
    { key: 'asset_label', label: 'Asset', width: '25%',
      render: (v, r) => <>{v}<EnvPill env={r.asset_env} /></>
    },
  ]

  return (
    <Card>
      <FilterBar>
        <Input value={search} onChange={setSearch} placeholder="Search service name…" style={{ width: 240 }} />
        <GroupByToggle value={groupByAsset} onChange={setGroupByAsset} />
      </FilterBar>
      {loading ? <Spinner /> : groupByAsset
        ? <GroupedTable columns={columns} rows={rows} emptyMessage="No services found." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
        : <Table columns={columns} rows={rows} emptyMessage="No services found." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
      }
      <Pagination page={page} total={total} pageSize={INV_PAGE_SIZE} onPageChange={setPage} noun="services" />
    </Card>
  )
}

// ─── Shares tab ────────────────────────────────────────────
function SharesTab({ scanId, assetId }) {
  const [rows, setRows]               = useState([])
  const [total, setTotal]             = useState(0)
  const [page, setPage]               = useState(1)
  const [loading, setLoading]         = useState(true)
  const [search, setSearch]           = useState('')
  const [writeableOnly, setWriteable] = useState(false)
  const [groupByAsset, setGroupByAsset] = useState(false)
  const [sortBy, setSortBy]           = useState('share_name')
  const [sortOrder, setSortOrder]     = useState('asc')

  const handleSort = (key) => {
    if (sortBy === key) { setSortOrder(o => o === 'asc' ? 'desc' : 'asc') }
    else { setSortBy(key); setSortOrder('asc') }
  }

  useEffect(() => { setPage(1) }, [scanId, assetId, search, writeableOnly])

  const load = useCallback(() => {
    setLoading(true)
    getInventoryShares({ scan_id: scanId, asset_id: assetId || null, search: search || null, is_writeable: writeableOnly || null, sort_by: sortBy, order: sortOrder, page, page_size: INV_PAGE_SIZE })
      .then(data => { setRows(data.shares); setTotal(data.total) }).catch(() => { setRows([]); setTotal(0) }).finally(() => setLoading(false))
  }, [scanId, assetId, search, writeableOnly, sortBy, sortOrder, page])

  useEffect(() => { load() }, [load])

  const columns = [
    { key: 'share_name', label: 'Share Name', width: '17%', sortable: true,
      render: (v, r) => (
        <span style={{ fontWeight: 600, color: r.is_writeable ? '#fca5a5' : 'var(--text-primary)' }}>{v}</span>
      )
    },
    { key: 'is_writeable', label: 'Writeable', width: '9%', sortable: true,
      render: v => v ? <Pill label="Write" color="#dc2626" /> : <Count n="—" />
    },
    { key: 'is_default_share', label: 'Type', width: '9%', sortable: true,
      render: v => v ? <Pill label="Default" color="#64748b" /> : <Pill label="Custom" color="#0ea5e9" />
    },
    { key: 'path', label: 'Local Path', width: '20%', sortable: true,
      render: v => v ? <code style={{ fontSize: 11 }}>{v}</code> : <Count n="—" />
    },
    { key: 'comment', label: 'Comment', width: '18%',
      render: v => <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{v || '—'}</span>
    },
    { key: 'acl', label: 'ACEs', width: '7%',
      render: v => <Count n={v?.length || 0} />
    },
    { key: 'asset_label', label: 'Asset', width: '20%',
      render: (v, r) => <>{v}<EnvPill env={r.asset_env} /></>
    },
  ]

  return (
    <Card>
      <FilterBar>
        <Input value={search} onChange={setSearch} placeholder="Search share name, path, comment…" style={{ width: 260 }} />
        <Button variant={writeableOnly ? 'danger' : 'ghost'} size="sm" onClick={() => setWriteable(p => !p)}>
          {writeableOnly ? '✕ Writeable only' : 'Show writeable only'}
        </Button>
        <GroupByToggle value={groupByAsset} onChange={setGroupByAsset} />
      </FilterBar>
      {loading ? <Spinner /> : groupByAsset
        ? <GroupedTable columns={columns} rows={rows} emptyMessage="No shares found." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
        : <Table columns={columns} rows={rows} emptyMessage="No shares found." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
      }
      <Pagination page={page} total={total} pageSize={INV_PAGE_SIZE} onPageChange={setPage} noun="shares" />
    </Card>
  )
}

// ─── Software tab ───────────────────────────────────────────
const SW_CATEGORY_COLORS = {
  'Security':        '#ef4444',
  'Dev Tools':       '#8b5cf6',
  'Collaboration':   '#3b82f6',
  'Productivity':    '#f59e0b',
  'Browser':         '#06b6d4',
  'Remote Access':   '#f97316',
  'Virtualization':  '#10b981',
  'Cloud & Storage': '#0ea5e9',
  'Database':        '#ec4899',
  'Media':           '#a855f7',
  'Utilities':       '#64748b',
  'Networking':      '#14b8a6',
}

function SwCategoryPill({ category }) {
  if (!category) return <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>—</span>
  const color = SW_CATEGORY_COLORS[category] || '#64748b'
  return (
    <span style={{
      display: 'inline-block', fontSize: 11, fontWeight: 600, padding: '2px 8px',
      borderRadius: 9999, background: color + '18', color, whiteSpace: 'nowrap',
    }}>{category}</span>
  )
}

// ── SBOM-aware priority / EOL / running badges ──────────

const PRIORITY_COLORS = {
  P1: '#dc2626', P2: '#ea580c', P3: '#d97706', P4: '#2563eb', P5: '#64748b',
}

function PriorityBadge({ tier }) {
  if (!tier) return null
  return (
    <span style={{
      display: 'inline-block', fontSize: 10, fontWeight: 700, padding: '1px 7px',
      borderRadius: 9999, background: (PRIORITY_COLORS[tier] || '#64748b') + '18',
      color: PRIORITY_COLORS[tier] || '#64748b',
    }}>{tier}</span>
  )
}

function EolBadge({ status, date }) {
  if (!status || status === 'active' || status === 'unknown') return null
  const color = status === 'eol' ? '#dc2626' : '#d97706'
  const label = status === 'eol' ? 'EOL' : 'EOL Soon'
  return (
    <span title={date ? `EOL: ${date}` : ''} style={{
      display: 'inline-block', fontSize: 10, fontWeight: 700, padding: '1px 7px',
      borderRadius: 9999, background: color + '18', color,
    }}>{label}</span>
  )
}

function RunningDot({ running }) {
  return (
    <span title={running ? 'Running' : 'Not running'} style={{
      display: 'inline-block', width: 8, height: 8, borderRadius: '50%',
      background: running ? '#22c55e' : '#d1d5db', marginRight: 4,
    }} />
  )
}

function CveBadge({ count, maxSeverity }) {
  if (!count) return <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>—</span>
  const colors = ['#64748b', '#3b82f6', '#f59e0b', '#ea580c', '#dc2626']
  const color = colors[maxSeverity] || '#64748b'
  return (
    <span style={{
      display: 'inline-block', fontSize: 10, fontWeight: 700, padding: '1px 7px',
      borderRadius: 9999, background: color + '18', color,
    }}>{count} CVE{count !== 1 ? 's' : ''}</span>
  )
}

const TYPE_BADGE_COLORS = {
  application: '#3b82f6', library: '#8b5cf6', runtime: '#10b981', os: '#f59e0b', firmware: '#64748b',
}

function TypeBadge({ type }) {
  const color = TYPE_BADGE_COLORS[type] || '#64748b'
  return (
    <span style={{
      display: 'inline-block', fontSize: 10, fontWeight: 600, padding: '1px 7px',
      borderRadius: 9999, background: color + '18', color, textTransform: 'capitalize',
    }}>{type || 'unknown'}</span>
  )
}


// ── Expandable CVE detail row ───────────────────────────

function SBOMVulnDetail({ componentId }) {
  const [vulns, setVulns] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    getSBOMComponentVulns(componentId)
      .then(d => setVulns(d.vulnerabilities || []))
      .catch(() => setVulns([]))
      .finally(() => setLoading(false))
  }, [componentId])

  if (loading) return <div style={{ padding: 12 }}><Spinner /></div>
  if (!vulns || vulns.length === 0) return <div style={{ padding: 12, fontSize: 12, color: 'var(--text-muted)' }}>No CVEs found.</div>

  const sevLabels = ['Info', 'Low', 'Medium', 'High', 'Critical']
  const sevColors = ['#64748b', '#3b82f6', '#f59e0b', '#ea580c', '#dc2626']

  return (
    <div style={{ padding: '8px 16px 12px', background: 'var(--bg-secondary)', borderTop: '1px solid var(--border)' }}>
      <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: 0.5 }}>
        CVE Details
      </div>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
        <thead>
          <tr style={{ borderBottom: '1px solid var(--border)' }}>
            <th style={{ textAlign: 'left', padding: '4px 8px', fontWeight: 600 }}>CVE</th>
            <th style={{ textAlign: 'left', padding: '4px 8px', fontWeight: 600 }}>Severity</th>
            <th style={{ textAlign: 'left', padding: '4px 8px', fontWeight: 600 }}>CVSS</th>
            <th style={{ textAlign: 'left', padding: '4px 8px', fontWeight: 600 }}>EPSS</th>
            <th style={{ textAlign: 'left', padding: '4px 8px', fontWeight: 600 }}>KEV</th>
            <th style={{ textAlign: 'left', padding: '4px 8px', fontWeight: 600 }}>Priority</th>
            <th style={{ textAlign: 'left', padding: '4px 8px', fontWeight: 600 }}>Remediation</th>
          </tr>
        </thead>
        <tbody>
          {vulns.map(v => (
            <tr key={v.id} style={{ borderBottom: '1px solid var(--border)' }}>
              <td style={{ padding: '4px 8px', fontFamily: 'monospace', fontWeight: 600 }}>{v.cve_id}</td>
              <td style={{ padding: '4px 8px' }}>
                <span style={{ color: sevColors[v.severity] || '#64748b', fontWeight: 600 }}>{sevLabels[v.severity] || '—'}</span>
              </td>
              <td style={{ padding: '4px 8px', fontFamily: 'monospace' }}>{v.cvss_score?.toFixed(1) || '—'}</td>
              <td style={{ padding: '4px 8px', fontFamily: 'monospace' }}>{v.epss_score != null ? (v.epss_score * 100).toFixed(1) + '%' : '—'}</td>
              <td style={{ padding: '4px 8px' }}>{v.in_kev ? <span style={{ color: '#dc2626', fontWeight: 700 }}>KEV</span> : '—'}</td>
              <td style={{ padding: '4px 8px' }}><PriorityBadge tier={v.priority_tier} /></td>
              <td style={{ padding: '4px 8px', fontSize: 11, color: 'var(--text-muted)', maxWidth: 300 }}>{v.remediation_note || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}


// ── Children (bundled libraries) row ────────────────────

function SBOMChildrenRow({ parentId, sbomMap }) {
  const children = useMemo(() => {
    if (!sbomMap) return []
    return Object.values(sbomMap).filter(c => c.parent_component_id === parentId)
  }, [parentId, sbomMap])

  if (children.length === 0) return null

  return (
    <div style={{ padding: '6px 16px 10px 36px', background: 'var(--bg-secondary)', borderTop: '1px solid var(--border)' }}>
      <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', marginBottom: 4 }}>
        Bundled Libraries ({children.length})
      </div>
      {children.map(c => (
        <div key={c.id} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '3px 0', fontSize: 12 }}>
          <span style={{ width: 8 }}>{'└'}</span>
          <span style={{ fontWeight: 600, flex: 1 }}>{c.name}</span>
          <code style={{ color: 'var(--text-muted)' }}>{c.version || '—'}</code>
          <TypeBadge type={c.component_type} />
          <RunningDot running={c.is_running} />
          <EolBadge status={c.eol_status} date={c.eol_date} />
          <CveBadge count={c.cve_count} maxSeverity={c.max_severity} />
          <PriorityBadge tier={c.priority_tier} />
        </div>
      ))}
    </div>
  )
}


function SoftwareTab({ scanId, assetId }) {
  const [rows, setRows]               = useState([])
  const [total, setTotal]             = useState(0)
  const [page, setPage]               = useState(1)
  const [loading, setLoading]         = useState(true)
  const [search, setSearch]           = useState('')
  const [category, setCategory]       = useState('')
  const [groupByAsset, setGroupByAsset] = useState(false)
  const [sortBy, setSortBy]           = useState('name')
  const [sortOrder, setSortOrder]     = useState('asc')
  const [expandedRow, setExpandedRow] = useState(null)
  const [sbomFilter, setSbomFilter]   = useState('')  // '' | 'has_cves' | 'eol' | 'running_vuln'

  // SBOM data
  const [sbomComps, setSbomComps]     = useState([])
  const [sbomSummary, setSbomSummary] = useState(null)

  const handleSort = (key) => {
    if (sortBy === key) { setSortOrder(o => o === 'asc' ? 'desc' : 'asc') }
    else { setSortBy(key); setSortOrder('asc') }
  }

  useEffect(() => { setPage(1) }, [scanId, assetId, search, category, sbomFilter])

  // Fetch software inventory
  const load = useCallback(() => {
    setLoading(true)
    getInventorySoftware({ scan_id: scanId, asset_id: assetId || null, search: search || null, category: category || null, sort_by: sortBy, order: sortOrder, page, page_size: INV_PAGE_SIZE })
      .then(data => { setRows(data.software); setTotal(data.total) }).catch(() => { setRows([]); setTotal(0) }).finally(() => setLoading(false))
  }, [scanId, assetId, search, category, sortBy, sortOrder, page])

  useEffect(() => { load() }, [load])

  // Fetch SBOM components for enrichment
  useEffect(() => {
    getSBOMComponents({ scan_id: scanId, asset_id: assetId || null, page_size: 0 })
      .then(data => setSbomComps(data.components || []))
      .catch(() => setSbomComps([]))
  }, [scanId, assetId])

  // Fetch SBOM summary
  useEffect(() => {
    getSBOMAssetSummary({ scan_id: scanId, asset_id: assetId || null })
      .then(data => setSbomSummary(data))
      .catch(() => setSbomSummary(null))
  }, [scanId, assetId])

  // Build lookup from software_id → sbom component
  const sbomMap = useMemo(() => {
    const map = {}
    for (const c of sbomComps) {
      if (c.software_id) map[c.software_id] = c
      // Also index by name+version for fallback
      map[`${(c.name || '').toLowerCase()}|${c.version || ''}`] = c
    }
    return map
  }, [sbomComps])

  // Fetch all rows for category bar
  const [allRows, setAllRows] = useState([])
  useEffect(() => {
    getInventorySoftware({ scan_id: scanId, asset_id: assetId || null, search: search || null, page_size: 0 })
      .then(data => setAllRows(data.software)).catch(() => setAllRows([]))
  }, [scanId, assetId, search])

  const categoryCounts = useMemo(() => {
    const counts = {}
    for (const r of allRows) {
      const cat = r.category || 'Uncategorized'
      counts[cat] = (counts[cat] || 0) + 1
    }
    return Object.entries(counts).sort((a, b) => b[1] - a[1])
  }, [allRows])

  // Enrich rows with SBOM data
  const enrichedRows = useMemo(() => {
    let result = rows.map(r => {
      const sbom = sbomMap[r.id] || sbomMap[`${(r.name || '').toLowerCase()}|${r.version || ''}`]
      return { ...r, sbom }
    })
    // Apply SBOM filters
    if (sbomFilter === 'has_cves') result = result.filter(r => r.sbom && r.sbom.cve_count > 0)
    if (sbomFilter === 'eol') result = result.filter(r => r.sbom && (r.sbom.eol_status === 'eol' || r.sbom.eol_status === 'approaching_eol'))
    if (sbomFilter === 'running_vuln') result = result.filter(r => r.sbom && r.sbom.is_running && r.sbom.cve_count > 0)
    return result
  }, [rows, sbomMap, sbomFilter])

  const columns = [
    { key: 'name', label: 'Software Name', width: '22%', sortable: true,
      render: (v, r) => (
        <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          {r.sbom && <RunningDot running={r.sbom.is_running} />}
          <span style={{ fontWeight: 600 }}>{v}</span>
        </span>
      )
    },
    { key: 'component_type', label: 'Type', width: '8%',
      render: (_, r) => r.sbom ? <TypeBadge type={r.sbom.component_type} /> : <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>—</span>
    },
    { key: 'category', label: 'Category', width: '10%', sortable: true,
      render: v => <SwCategoryPill category={v} />
    },
    { key: 'version', label: 'Version', width: '10%', sortable: true,
      render: v => <code style={{ fontSize: 12, color: 'var(--text-muted)' }}>{v || '—'}</code>
    },
    { key: 'vendor', label: 'Vendor', width: '10%', sortable: true,
      render: v => <span style={{ fontSize: 13 }}>{v || '—'}</span>
    },
    { key: 'eol_status', label: 'EOL', width: '7%',
      render: (_, r) => r.sbom ? <EolBadge status={r.sbom.eol_status} date={r.sbom.eol_date} /> : null
    },
    { key: 'cve_count', label: 'CVEs', width: '8%',
      render: (_, r) => r.sbom ? <CveBadge count={r.sbom.cve_count} maxSeverity={r.sbom.max_severity} /> : null
    },
    { key: 'priority', label: 'Priority', width: '7%',
      render: (_, r) => r.sbom ? <PriorityBadge tier={r.sbom.priority_tier} /> : null
    },
    { key: 'asset_label', label: 'Asset', width: '18%',
      render: (v, r) => <>{v}<EnvPill env={r.asset_env} /></>
    },
  ]

  return (
    <Card>
      {/* SBOM Summary Bar */}
      {sbomSummary && sbomSummary.total_components > 0 && (
        <div style={{ display: 'flex', gap: 12, marginBottom: 14, padding: '10px 12px', background: 'var(--bg-secondary)', borderRadius: 8 }}>
          <div style={{ fontSize: 12 }}>
            <span style={{ fontWeight: 700 }}>{sbomSummary.total_components}</span> components
          </div>
          <div style={{ fontSize: 12 }}>
            <span style={{ fontWeight: 700, color: '#dc2626' }}>{sbomSummary.total_cves}</span> CVEs
          </div>
          {Object.entries(sbomSummary.by_priority || {}).sort().map(([tier, count]) => (
            <div key={tier} style={{ fontSize: 12 }}>
              <PriorityBadge tier={tier} /> <span style={{ fontWeight: 600 }}>{count}</span>
            </div>
          ))}
          {sbomSummary.eol_components?.length > 0 && (
            <div style={{ fontSize: 12 }}>
              <span style={{ fontWeight: 700, color: '#dc2626' }}>{sbomSummary.eol_components.length}</span> EOL
            </div>
          )}
          {sbomSummary.running_vulnerable?.length > 0 && (
            <div style={{ fontSize: 12 }}>
              <span style={{ fontWeight: 700, color: '#ea580c' }}>{sbomSummary.running_vulnerable.length}</span> running + vulnerable
            </div>
          )}
        </div>
      )}

      {categoryCounts.length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 12 }}>
          <button onClick={() => setCategory('')}
            style={{
              fontSize: 12, fontWeight: category === '' ? 700 : 500, padding: '3px 10px',
              borderRadius: 9999, border: '1px solid var(--border)',
              background: category === '' ? 'var(--accent)' : 'transparent',
              color: category === '' ? '#fff' : 'var(--text)',
              cursor: 'pointer',
            }}>All ({allRows.length})</button>
          {categoryCounts.map(([cat, count]) => {
            const color = SW_CATEGORY_COLORS[cat] || '#64748b'
            const active = category === cat
            return (
              <button key={cat} onClick={() => setCategory(active ? '' : cat)}
                style={{
                  fontSize: 12, fontWeight: active ? 700 : 500, padding: '3px 10px',
                  borderRadius: 9999, border: `1px solid ${active ? color : 'var(--border)'}`,
                  background: active ? color + '20' : 'transparent',
                  color: active ? color : 'var(--text-muted)',
                  cursor: 'pointer',
                }}>{cat} ({count})</button>
            )
          })}
        </div>
      )}
      <FilterBar>
        <Input value={search} onChange={setSearch} placeholder="Search software name…" style={{ width: 260 }} />
        <Select value={sbomFilter} onChange={setSbomFilter} options={[
          { value: '', label: 'All Software' },
          { value: 'has_cves', label: 'Has SBOM findings' },
          { value: 'eol', label: 'Has EOL software' },
          { value: 'running_vuln', label: 'Running + vulnerable' },
        ]} />
        <GroupByToggle value={groupByAsset} onChange={setGroupByAsset} />
      </FilterBar>
      {loading ? <Spinner /> : groupByAsset
        ? <GroupedTable columns={columns} rows={enrichedRows} emptyMessage="No installed software found." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
        : <Table
            columns={columns}
            rows={enrichedRows}
            emptyMessage="No installed software found."
            onSort={handleSort}
            sortBy={sortBy}
            sortOrder={sortOrder}
            onRowClick={r => setExpandedRow(expandedRow === r.id ? null : r.id)}
            renderRowExtra={r => {
              if (expandedRow !== r.id || !r.sbom) return null
              return (
                <tr><td colSpan={columns.length} style={{ padding: 0 }}>
                  <SBOMChildrenRow parentId={r.sbom.id} sbomMap={Object.fromEntries(sbomComps.map(c => [c.id, c]))} />
                  {r.sbom.cve_count > 0 && <SBOMVulnDetail componentId={r.sbom.id} />}
                </td></tr>
              )
            }}
          />
      }
      <Pagination page={page} total={sbomFilter ? enrichedRows.length : total} pageSize={INV_PAGE_SIZE} onPageChange={setPage} noun="packages" />
    </Card>
  )
}

// ─── Security Controls tab ─────────────────────────────────
const CTRL_COLORS = {
  av: '#10b981', firewall: '#0ea5e9', edr: '#8b5cf6', backup: '#f59e0b',
  identity: '#f97316', vulnerability_management: '#e11d48', siem: '#0891b2',
  dlp: '#7c3aed', vpn: '#16a34a', sase: '#0284c7', nac: '#b45309',
  patch_management: '#6d28d9', ndr: '#0f766e', encryption: '#ca8a04',
  integrity_monitoring: '#9333ea', container_security: '#0369a1',
  email_security: '#be185d', remote_management: '#64748b',
}

// Critical categories every asset should have
const CRITICAL_CATS = ['EDR', 'AV', 'Firewall', 'Patch Management']

function CoverageMatrix({ scanId }) {
  const [data, setData]       = useState(null)
  const [loading, setLoading] = useState(true)
  const [expanded, setExpanded] = useState(null)

  useEffect(() => {
    setLoading(true)
    getSecurityCoverage({ scan_id: scanId || null })
      .then(setData).catch(() => setData(null)).finally(() => setLoading(false))
  }, [scanId])

  if (loading) return <Spinner />
  if (!data) return <EmptyState message="No coverage data available." />

  const { categories, assets, summary } = data

  const coverageColor = (pct) => {
    if (pct >= 80) return '#16a34a'
    if (pct >= 40) return '#f59e0b'
    return '#dc2626'
  }

  // Assets missing at least one critical control
  const assetsWithGaps = assets.map(a => {
    const coveredCats = new Set(a.controls.map(c => c.category))
    const missing = CRITICAL_CATS.filter(c => !coveredCats.has(c))
    return { ...a, coveredCats, missing }
  }).filter(a => a.missing.length > 0)

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Summary bar */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10 }}>
        <StatCard label="Total Assets"       value={summary.total_assets}            color="#0ea5e9" icon={Server} />
        <StatCard label="Avg Coverage"       value={`${summary.avg_coverage_pct}%`}  color={coverageColor(summary.avg_coverage_pct)} icon={Shield} />
        <StatCard label="Categories Covered" value={`${summary.categories_with_coverage} / ${summary.total_categories}`} color="#8b5cf6" icon={Lock} />
        <StatCard label="Coverage Gaps"      value={summary.missing_categories.length} color={summary.missing_categories.length > 0 ? '#dc2626' : '#16a34a'} icon={AlertTriangle} />
      </div>

      {/* Coverage by Category — gaps highlighted inline, no separate card */}
      <Card>
        <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 12 }}>Coverage by Category</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          {categories.map(cat => {
            const isGap = cat.covered_assets === 0
            const isCritical = CRITICAL_CATS.includes(cat.name)
            return (
              <div key={cat.name} style={{
                borderRadius: 6,
                background: isGap && isCritical ? 'rgba(220,38,38,0.06)' : 'transparent',
                padding: '3px 6px',
              }}>
                <div
                  style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: cat.products.length ? 'pointer' : 'default' }}
                  onClick={() => cat.products.length && setExpanded(expanded === cat.name ? null : cat.name)}
                >
                  {/* Gap / critical badge */}
                  <div style={{ width: 14, textAlign: 'center' }}>
                    {isGap && isCritical && <AlertTriangle size={11} color="#dc2626" />}
                  </div>
                  <div style={{ width: 130, fontSize: 12, fontWeight: isCritical ? 700 : 500, color: isGap && isCritical ? '#dc2626' : 'var(--text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {cat.name}
                  </div>
                  <div style={{ flex: 1, height: 10, background: 'var(--bg-secondary)', borderRadius: 6, overflow: 'hidden' }}>
                    {cat.coverage_pct > 0 && (
                      <div style={{
                        height: '100%',
                        width: `${cat.coverage_pct}%`,
                        background: coverageColor(cat.coverage_pct),
                        borderRadius: 6,
                        transition: 'width 0.3s ease',
                      }} />
                    )}
                  </div>
                  <div style={{ width: 100, textAlign: 'right', fontSize: 11, color: coverageColor(cat.coverage_pct), fontWeight: 700 }}>
                    {cat.covered_assets}/{cat.total_assets}
                    <span style={{ fontWeight: 400, color: 'var(--text-muted)', marginLeft: 3 }}>({cat.coverage_pct}%)</span>
                  </div>
                </div>
                {expanded === cat.name && cat.products.length > 0 && (
                  <div style={{ marginLeft: 154, marginBottom: 4, marginTop: 2, display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                    {cat.products.map(p => (
                      <Pill key={p} label={p} color={CTRL_COLORS[cat.control_type] || '#64748b'} />
                    ))}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </Card>

      {/* Asset health — only assets missing critical controls */}
      {assetsWithGaps.length > 0 && (
        <Card>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
            <AlertTriangle size={14} color="#f59e0b" />
            <span style={{ fontWeight: 700, fontSize: 13 }}>
              Assets Missing Critical Controls
            </span>
            <span style={{ fontSize: 11, color: 'var(--text-muted)', marginLeft: 4 }}>
              ({assetsWithGaps.length} of {assets.length} assets — EDR, AV, Firewall, Patch Mgmt)
            </span>
          </div>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                <th style={{ textAlign: 'left', padding: '5px 8px', color: 'var(--text-muted)', fontWeight: 600 }}>Asset</th>
                <th style={{ textAlign: 'left', padding: '5px 8px', color: 'var(--text-muted)', fontWeight: 600 }}>Missing Critical</th>
                <th style={{ textAlign: 'left', padding: '5px 8px', color: 'var(--text-muted)', fontWeight: 600 }}>Has</th>
              </tr>
            </thead>
            <tbody>
              {assetsWithGaps.map(asset => (
                <tr key={asset.asset_id} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '5px 8px', fontWeight: 600, whiteSpace: 'nowrap' }}>
                    {asset.asset_ip || asset.asset_label}
                    {asset.asset_env && <EnvPill env={asset.asset_env} />}
                  </td>
                  <td style={{ padding: '5px 8px' }}>
                    <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                      {asset.missing.map(m => <Pill key={m} label={m} color="#dc2626" />)}
                    </div>
                  </td>
                  <td style={{ padding: '5px 8px' }}>
                    {asset.controls.length === 0
                      ? <span style={{ color: 'var(--text-muted)', fontStyle: 'italic' }}>nothing</span>
                      : <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                          {[...new Set(asset.controls.map(c => c.category))].map(cat => (
                            <Pill key={cat} label={cat} color={CTRL_COLORS[asset.controls.find(c => c.category === cat)?.control_type] || '#64748b'} />
                          ))}
                        </div>
                    }
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  )
}

function SecurityControlsTab({ scanId, assetId }) {
  const [view, setView]               = useState('coverage')   // 'coverage' | 'list'
  const [rows, setRows]               = useState([])
  const [total, setTotal]             = useState(0)
  const [page, setPage]               = useState(1)
  const [loading, setLoading]         = useState(true)
  const [ctrlType, setCtrlType]       = useState(null)
  const [groupByAsset, setGroupByAsset] = useState(false)
  const [sortBy, setSortBy]           = useState('product_name')
  const [sortOrder, setSortOrder]     = useState('asc')

  const handleSort = (key) => {
    if (sortBy === key) { setSortOrder(o => o === 'asc' ? 'desc' : 'asc') }
    else { setSortBy(key); setSortOrder('asc') }
  }

  useEffect(() => { setPage(1) }, [scanId, assetId, ctrlType])

  useEffect(() => {
    if (view !== 'list') return
    setLoading(true)
    getInventorySecurityControls({ scan_id: scanId, asset_id: assetId || null, control_type: ctrlType, sort_by: sortBy, order: sortOrder, page, page_size: INV_PAGE_SIZE })
      .then(data => { setRows(data.controls); setTotal(data.total) }).catch(() => { setRows([]); setTotal(0) }).finally(() => setLoading(false))
  }, [scanId, assetId, ctrlType, sortBy, sortOrder, view, page])

  const columns = [
    { key: 'control_type', label: 'Type', width: '9%', sortable: true,
      render: v => <Pill label={v} color={CTRL_COLORS[v] || '#64748b'} />
    },
    { key: 'product_name', label: 'Product', width: '22%', sortable: true,
      render: v => <span style={{ fontWeight: 600 }}>{v || '—'}</span>
    },
    { key: 'vendor', label: 'Vendor', width: '14%', sortable: true,
      render: v => <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{v || '—'}</span>
    },
    { key: 'version', label: 'Version', width: '10%', sortable: true,
      render: v => <code style={{ fontSize: 12, color: 'var(--text-muted)' }}>{v || '—'}</code>
    },
    { key: 'is_enabled', label: 'Enabled', width: '9%', sortable: true,
      render: v => v ? <Pill label="Enabled" color="#16a34a" /> : <Pill label="Disabled" color="#dc2626" />
    },
    { key: 'is_up_to_date', label: 'Up to Date', width: '10%', sortable: true,
      render: v => v === null ? <span style={{ color: 'var(--text-muted)' }}>—</span> : v ? <Pill label="Current" color="#16a34a" /> : <Pill label="Outdated" color="#dc2626" />
    },
    { key: 'signature_date', label: 'Signature Date', width: '12%', sortable: true,
      render: v => <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{v || '—'}</span>
    },
    { key: 'asset_label', label: 'Asset', width: '14%',
      render: (v, r) => <>{v}<EnvPill env={r.asset_env} /></>
    },
  ]

  return (
    <div>
      {/* Sub-view toggle */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 14 }}>
        {[
          { key: 'coverage', label: 'Coverage Matrix' },
          { key: 'list',     label: 'All Controls' },
        ].map(t => (
          <button
            key={t.key}
            onClick={() => setView(t.key)}
            style={{
              padding: '5px 14px', borderRadius: 6, border: '1px solid var(--border)',
              background: view === t.key ? 'var(--accent)' : 'var(--bg-secondary)',
              color: view === t.key ? '#fff' : 'var(--text-primary)',
              fontWeight: 600, fontSize: 12, cursor: 'pointer',
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {view === 'coverage'
        ? <CoverageMatrix scanId={scanId} />
        : (
          <Card>
            <FilterBar>
              <Select value={ctrlType} onChange={setCtrlType} placeholder="All types" options={[
                { value: 'av',                     label: 'Antivirus' },
                { value: 'edr',                    label: 'EDR / XDR' },
                { value: 'firewall',               label: 'Firewall' },
                { value: 'vpn',                    label: 'VPN' },
                { value: 'sase',                   label: 'SASE / ZTNA' },
                { value: 'dlp',                    label: 'DLP' },
                { value: 'identity',               label: 'Identity / PAM' },
                { value: 'vulnerability_management', label: 'Vuln Management' },
                { value: 'siem',                   label: 'SIEM' },
                { value: 'backup',                 label: 'Backup' },
                { value: 'encryption',             label: 'Encryption' },
                { value: 'patch_management',       label: 'Patch Management' },
                { value: 'nac',                    label: 'NAC' },
                { value: 'ndr',                    label: 'NDR' },
                { value: 'integrity_monitoring',   label: 'Integrity Monitoring' },
                { value: 'remote_management',      label: 'RMM' },
              ]} />
              <GroupByToggle value={groupByAsset} onChange={setGroupByAsset} />
            </FilterBar>
            {loading ? <Spinner /> : groupByAsset
              ? <GroupedTable columns={columns} rows={rows} emptyMessage="No security controls found." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
              : <Table columns={columns} rows={rows} emptyMessage="No security controls found." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
            }
            <Pagination page={page} total={total} pageSize={INV_PAGE_SIZE} onPageChange={setPage} noun="controls" />
          </Card>
        )
      }
    </div>
  )
}

// ─── Network tab ───────────────────────────────────────────
function NetconnsTab({ scanId, assetId }) {
  const [rows, setRows]               = useState([])
  const [total, setTotal]             = useState(0)
  const [page, setPage]               = useState(1)
  const [loading, setLoading]         = useState(true)
  const [search, setSearch]           = useState('')
  const [state, setState]             = useState(null)
  const [groupByAsset, setGroupByAsset] = useState(false)
  const [sortBy, setSortBy]           = useState('local_port')
  const [sortOrder, setSortOrder]     = useState('asc')

  const handleSort = (key) => {
    if (sortBy === key) { setSortOrder(o => o === 'asc' ? 'desc' : 'asc') }
    else { setSortBy(key); setSortOrder('asc') }
  }

  useEffect(() => { setPage(1) }, [scanId, assetId, search, state])

  const load = useCallback(() => {
    setLoading(true)
    getInventoryNetconns({ scan_id: scanId, asset_id: assetId || null, search: search || null, state: state || null, sort_by: sortBy, order: sortOrder, page, page_size: INV_PAGE_SIZE })
      .then(data => { setRows(data.netconns); setTotal(data.total) }).catch(() => { setRows([]); setTotal(0) }).finally(() => setLoading(false))
  }, [scanId, assetId, search, state, sortBy, sortOrder, page])

  useEffect(() => { load() }, [load])

  const columns = [
    { key: 'proto',      label: 'Proto',          width: '7%',  sortable: true },
    { key: 'state',      label: 'State',          width: '12%', sortable: true, render: v => <StatePill state={v} /> },
    { key: 'local_addr', label: 'Local Address',  width: '18%', sortable: true,
      render: (v, r) => <code style={{ fontSize: 12 }}>{v}:{r.local_port}</code>
    },
    { key: 'remote_addr', label: 'Remote Address', width: '18%', sortable: true,
      render: (v, r) => (
        <code style={{ fontSize: 12, color: v && v !== '0.0.0.0' && v !== '::' && r.state?.toLowerCase() === 'established' ? '#fca5a5' : 'inherit' }}>
          {v || '—'}:{r.remote_port || '*'}
        </code>
      )
    },
    { key: 'pid',      label: 'PID',      width: '7%', sortable: true, render: v => <Count n={v || '—'} /> },
    { key: 'asset_label', label: 'Asset', width: '38%',
      render: (v, r) => <>{v}<EnvPill env={r.asset_env} /></>
    },
  ]

  return (
    <Card>
      <FilterBar>
        <Input value={search} onChange={setSearch} placeholder="Search IP address, protocol…" style={{ width: 240 }} />
        <Select value={state} onChange={setState} placeholder="All states" options={[
          { value: 'listen',      label: 'Listening' },
          { value: 'established', label: 'Established' },
          { value: 'time_wait',   label: 'Time Wait' },
        ]} />
        <GroupByToggle value={groupByAsset} onChange={setGroupByAsset} />
      </FilterBar>
      {loading ? <Spinner /> : groupByAsset
        ? <GroupedTable columns={columns} rows={rows} emptyMessage="No connections found." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
        : <Table columns={columns} rows={rows} emptyMessage="No connections found." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
      }
      <Pagination page={page} total={total} pageSize={INV_PAGE_SIZE} onPageChange={setPage} noun="connections" />
    </Card>
  )
}

// ─── Scheduled Tasks tab ───────────────────────────────────
function TasksTab({ scanId, assetId }) {
  const [rows, setRows]               = useState([])
  const [total, setTotal]             = useState(0)
  const [page, setPage]               = useState(1)
  const [loading, setLoading]         = useState(true)
  const [search, setSearch]           = useState('')
  const [triggerType, setTriggerType] = useState(null)
  const [groupByAsset, setGroupByAsset] = useState(false)
  const [sortBy, setSortBy]           = useState('task_uri')
  const [sortOrder, setSortOrder]     = useState('asc')

  const handleSort = (key) => {
    if (sortBy === key) { setSortOrder(o => o === 'asc' ? 'desc' : 'asc') }
    else { setSortBy(key); setSortOrder('asc') }
  }

  useEffect(() => { setPage(1) }, [scanId, assetId, search, triggerType])

  const load = useCallback(() => {
    setLoading(true)
    getInventoryTasks({ scan_id: scanId, asset_id: assetId || null, search: search || null, trigger_type: triggerType || null, sort_by: sortBy, order: sortOrder, page, page_size: INV_PAGE_SIZE })
      .then(data => { setRows(data.tasks); setTotal(data.total) }).catch(() => { setRows([]); setTotal(0) }).finally(() => setLoading(false))
  }, [scanId, assetId, search, triggerType, sortBy, sortOrder, page])

  useEffect(() => { load() }, [load])

  const columns = [
    { key: 'task_uri', label: 'Task URI', width: '22%', sortable: true,
      render: v => <code style={{ fontSize: 12 }}>{v || '—'}</code>
    },
    { key: 'author',   label: 'Author',   width: '12%', sortable: true,
      render: v => <span style={{ fontSize: 13 }}>{v || '—'}</span>
    },
    { key: 'run_as_sid', label: 'Run As', width: '18%', sortable: true,
      render: (v, r) => (
        <span style={{ fontSize: 12, fontFamily: 'monospace', color: v ? '#fcd34d' : 'var(--text-muted)' }}>
          {r.run_as_user || v || '—'}
        </span>
      )
    },
    { key: 'command', label: 'Command', width: '23%',
      render: v => <code style={{ fontSize: 11, color: 'var(--text-muted)' }}>{v || '—'}</code>
    },
    { key: 'trigger_type', label: 'Trigger', width: '9%', sortable: true,
      render: v => v ? <Pill label={v} color="#64748b" /> : <Count n="—" />
    },
    { key: 'asset_label', label: 'Asset', width: '16%',
      render: (v, r) => <>{v}<EnvPill env={r.asset_env} /></>
    },
  ]

  return (
    <Card>
      <FilterBar>
        <Input value={search} onChange={setSearch} placeholder="Search task, author, command…" style={{ width: 250 }} />
        <Select value={triggerType} onChange={setTriggerType} placeholder="All trigger types" options={[
          { value: 'daily',    label: 'Daily' },
          { value: 'weekly',   label: 'Weekly' },
          { value: 'monthly',  label: 'Monthly' },
          { value: 'logon',    label: 'Logon' },
          { value: 'startup',  label: 'Startup' },
          { value: 'ondemand', label: 'On Demand' },
        ]} />
        <GroupByToggle value={groupByAsset} onChange={setGroupByAsset} />
      </FilterBar>
      {loading ? <Spinner /> : groupByAsset
        ? <GroupedTable columns={columns} rows={rows} emptyMessage="No scheduled tasks found." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
        : <Table columns={columns} rows={rows} emptyMessage="No scheduled tasks found." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
      }
      <Pagination page={page} total={total} pageSize={INV_PAGE_SIZE} onPageChange={setPage} noun="tasks" />
    </Card>
  )
}

// ─── Patches tab ───────────────────────────────────────────
function PatchesTab({ scanId, assetId }) {
  const [rows, setRows]               = useState([])
  const [total, setTotal]             = useState(0)
  const [page, setPage]               = useState(1)
  const [loading, setLoading]         = useState(true)
  const [groupByAsset, setGroupByAsset] = useState(false)
  const [sortBy, setSortBy]           = useState('vuln_count')
  const [sortOrder, setSortOrder]     = useState('desc')

  const handleSort = (key) => {
    if (sortBy === key) { setSortOrder(o => o === 'asc' ? 'desc' : 'asc') }
    else { setSortBy(key); setSortOrder('desc') }
  }

  useEffect(() => { setPage(1) }, [scanId, assetId])

  useEffect(() => {
    setLoading(true)
    getInventoryPatches({ scan_id: scanId, asset_id: assetId || null, sort_by: sortBy, order: sortOrder, page, page_size: INV_PAGE_SIZE })
      .then(data => { setRows(data.patches); setTotal(data.total) }).catch(() => { setRows([]); setTotal(0) }).finally(() => setLoading(false))
  }, [scanId, assetId, sortBy, sortOrder, page])

  const columns = [
    { key: 'kb_id', label: 'Patch / Advisory', width: '25%', sortable: true,
      render: v => <span style={{ fontWeight: 600, fontFamily: 'monospace', fontSize: 13 }}>{v}</span>
    },
    { key: 'vuln_count', label: 'CVEs Fixed', width: '9%', sortable: true,
      render: v => <span style={{ fontWeight: 700, color: v > 10 ? '#dc2626' : v > 0 ? '#f59e0b' : 'var(--text-muted)' }}>{v || 0}</span>
    },
    { key: 'cves', label: 'CVE Sample', width: '27%',
      render: v => {
        const list = v?.slice(0, 3) || []
        return (
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            {list.join(', ')}{v?.length > 3 ? ` +${v.length - 3}` : ''}
          </span>
        )
      }
    },
    { key: 'description', label: 'Action', width: '20%',
      render: v => <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{v ? v.slice(0, 80) + (v.length > 80 ? '…' : '') : '—'}</span>
    },
    { key: 'asset_label', label: 'Asset', width: '19%',
      render: (v, r) => <>{v}<EnvPill env={r.asset_env} /></>
    },
  ]

  return (
    <Card>
      <FilterBar>
        <GroupByToggle value={groupByAsset} onChange={setGroupByAsset} />
      </FilterBar>
      {loading ? <Spinner /> : groupByAsset
        ? <GroupedTable columns={columns} rows={rows} emptyMessage="No missing patches found." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
        : <Table columns={columns} rows={rows} emptyMessage="No missing patches found." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
      }
      <Pagination page={page} total={total} pageSize={INV_PAGE_SIZE} onPageChange={setPage} noun="patches" />
    </Card>
  )
}

// ─── Password Policy tab ───────────────────────────────────
function PasswordPolicyTab({ scanId, assetId }) {
  const [rows, setRows]               = useState([])
  const [total, setTotal]             = useState(0)
  const [page, setPage]               = useState(1)
  const [loading, setLoading]         = useState(true)
  const [groupByAsset, setGroupByAsset] = useState(false)
  const [sortBy, setSortBy]           = useState('domain')
  const [sortOrder, setSortOrder]     = useState('asc')

  const handleSort = (key) => {
    if (sortBy === key) { setSortOrder(o => o === 'asc' ? 'desc' : 'asc') }
    else { setSortBy(key); setSortOrder('asc') }
  }

  useEffect(() => { setPage(1) }, [scanId, assetId])

  useEffect(() => {
    setLoading(true)
    getInventoryPasswordPolicies({ scan_id: scanId, asset_id: assetId || null, sort_by: sortBy, order: sortOrder, page, page_size: INV_PAGE_SIZE })
      .then(data => { setRows(data.policies); setTotal(data.total) }).catch(() => { setRows([]); setTotal(0) }).finally(() => setLoading(false))
  }, [scanId, assetId, sortBy, sortOrder, page])

  function policyBool(val, goodIfTrue = true) {
    if (val === null || val === undefined) return <Count n="—" />
    const good = goodIfTrue ? val : !val
    return <Pill label={val ? 'Yes' : 'No'} color={good ? '#16a34a' : '#dc2626'} />
  }

  function policyNum(val, { warnBelow, warnAbove, unit = '' } = {}) {
    if (val === null || val === undefined) return <Count n="—" />
    const bad = (warnBelow !== undefined && val < warnBelow) || (warnAbove !== undefined && val > warnAbove)
    return <span style={{ fontWeight: 700, color: bad ? '#dc2626' : 'var(--text-primary)' }}>{val}{unit}</span>
  }

  const columns = [
    { key: 'domain', label: 'Domain', width: '15%', sortable: true,
      render: (v, r) => (
        <span style={{ fontWeight: 600 }}>
          {v || 'Unknown'}{r.is_weak ? ' ' : ''}{r.is_weak && <Pill label="WEAK" color="#dc2626" />}
        </span>
      )
    },
    { key: 'asset_label', label: 'Asset', width: '15%',
      render: (v, r) => <>{v}<EnvPill env={r.asset_env} /></>
    },
    { key: 'min_length', label: 'Min Length', width: '9%', sortable: true,
      render: v => policyNum(v, { warnBelow: 8 })
    },
    { key: 'complexity_enabled', label: 'Complexity', width: '9%', sortable: true,
      render: v => policyBool(v, true)
    },
    { key: 'history_count', label: 'History', width: '9%', sortable: true,
      render: v => policyNum(v, { warnBelow: 5 })
    },
    { key: 'max_age_days', label: 'Max Age', width: '9%', sortable: true,
      render: v => policyNum(v, { warnAbove: 365, unit: 'd' })
    },
    { key: 'lockout_threshold', label: 'Lockout', width: '10%', sortable: true,
      render: v => v === 0
        ? <Pill label="No lockout!" color="#dc2626" />
        : <span style={{ fontWeight: 700 }}>{v} attempts</span>
    },
    { key: 'lockout_duration_mins', label: 'Lock Dur.', width: '9%', sortable: true,
      render: v => policyNum(v, { unit: ' min' })
    },
    { key: 'reversible_encryption', label: 'Rev. Encrypt', width: '9%', sortable: true,
      render: v => policyBool(v, false)
    },
  ]

  if (loading) return <Spinner />
  if (total === 0) return <EmptyState icon={FileText} title="No password policy data" sub="Requires plugin 17651 in the scan." />

  return (
    <Card>
      <FilterBar>
        <GroupByToggle value={groupByAsset} onChange={setGroupByAsset} />
      </FilterBar>
      {groupByAsset
        ? <GroupedTable columns={columns} rows={rows} emptyMessage="No password policies found." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
        : <Table columns={columns} rows={rows} emptyMessage="No password policies found." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
      }
      <Pagination page={page} total={total} pageSize={INV_PAGE_SIZE} onPageChange={setPage} noun="policies" />
    </Card>
  )
}

// ─── Logged On tab ─────────────────────────────────────────
function LoggedOnTab({ scanId, assetId }) {
  const [rows, setRows]               = useState([])
  const [total, setTotal]             = useState(0)
  const [page, setPage]               = useState(1)
  const [loading, setLoading]         = useState(true)
  const [groupByAsset, setGroupByAsset] = useState(false)
  const [sortBy, setSortBy]           = useState('username')
  const [sortOrder, setSortOrder]     = useState('asc')

  const handleSort = (key) => {
    if (sortBy === key) { setSortOrder(o => o === 'asc' ? 'desc' : 'asc') }
    else { setSortBy(key); setSortOrder('asc') }
  }

  useEffect(() => { setPage(1) }, [scanId, assetId])

  useEffect(() => {
    setLoading(true)
    getInventoryLoggedOn({ scan_id: scanId, asset_id: assetId || null, sort_by: sortBy, order: sortOrder, page, page_size: INV_PAGE_SIZE })
      .then(data => { setRows(data.logged_on); setTotal(data.total) }).catch(() => { setRows([]); setTotal(0) }).finally(() => setLoading(false))
  }, [scanId, assetId, sortBy, sortOrder, page])

  const columns = [
    { key: 'domain',   label: 'Domain',   width: '22%', sortable: true },
    { key: 'username', label: 'Username', width: '22%', sortable: true,
      render: v => <span style={{ fontWeight: 600 }}>{v}</span>
    },
    { key: 'sid', label: 'SID', width: '30%',
      render: v => <code style={{ fontSize: 11, color: 'var(--text-muted)' }}>{v}</code>
    },
    { key: 'asset_label', label: 'Asset', width: '26%',
      render: (v, r) => <>{v}<EnvPill env={r.asset_env} /></>
    },
  ]

  return (
    <Card>
      <FilterBar>
        <GroupByToggle value={groupByAsset} onChange={setGroupByAsset} />
      </FilterBar>
      {loading ? <Spinner /> : groupByAsset
        ? <GroupedTable columns={columns} rows={rows} emptyMessage="No active sessions found." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
        : <Table columns={columns} rows={rows} emptyMessage="No active sessions found." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
      }
      <Pagination page={page} total={total} pageSize={INV_PAGE_SIZE} onPageChange={setPage} noun="sessions" />
    </Card>
  )
}

// ─── Env Variables tab ─────────────────────────────────────
function EnvVarsTab({ scanId, assetId }) {
  const [rows, setRows]                 = useState([])
  const [total, setTotal]               = useState(0)
  const [page, setPage]                 = useState(1)
  const [loading, setLoading]           = useState(true)
  const [search, setSearch]             = useState('')
  const [scope, setScope]               = useState(null)
  const [sensitiveOnly, setSensitiveOnly] = useState(false)
  const [revealed, setRevealed]         = useState({})
  const [groupByAsset, setGroupByAsset] = useState(true)
  const [sortBy, setSortBy]             = useState('name')
  const [sortOrder, setSortOrder]       = useState('asc')

  const handleSort = (key) => {
    if (sortBy === key) { setSortOrder(o => o === 'asc' ? 'desc' : 'asc') }
    else { setSortBy(key); setSortOrder('asc') }
  }

  useEffect(() => { setPage(1) }, [scanId, assetId, scope, sensitiveOnly, search])

  useEffect(() => {
    setLoading(true)
    getInventoryEnvVars({ scan_id: scanId, asset_id: assetId || null, scope: scope || null, sensitive_only: sensitiveOnly || null, search: search || null, sort_by: sortBy, order: sortOrder, page, page_size: INV_PAGE_SIZE })
      .then(data => { setRows(data.env_vars); setTotal(data.total) }).catch(() => { setRows([]); setTotal(0) }).finally(() => setLoading(false))
  }, [scanId, assetId, scope, sensitiveOnly, search, sortBy, sortOrder, page])

  const sensitiveCount = rows.filter(r => r.is_sensitive).length

  const columns = [
    { key: 'name', label: 'Variable', width: '25%', sortable: true,
      render: (v, r) => (
        <span style={{ fontFamily: 'monospace', fontSize: 12, color: r.is_sensitive ? '#fcd34d' : 'inherit' }}>
          {v}
        </span>
      )
    },
    { key: 'value', label: 'Value', width: '38%',
      render: (v, r) => {
        if (!r.is_sensitive) {
          return <code style={{ fontSize: 11, color: 'var(--text-muted)', wordBreak: 'break-all' }}>{v || '—'}</code>
        }
        const show = revealed[r.id]
        return (
          <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <code style={{ fontSize: 11, color: show ? '#fca5a5' : 'var(--text-muted)', wordBreak: 'break-all' }}>
              {show ? v : '•'.repeat(Math.min((v || '').length, 24))}
            </code>
            <button
              onClick={() => setRevealed(prev => ({ ...prev, [r.id]: !prev[r.id] }))}
              style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 2, color: 'var(--text-muted)', flexShrink: 0 }}
              title={show ? 'Hide' : 'Reveal'}
            >
              {show ? <EyeOff size={12} /> : <Eye size={12} />}
            </button>
          </span>
        )
      }
    },
    { key: 'scope', label: 'Scope', width: '8%', sortable: true,
      render: v => <Pill label={v} color={v === 'global' ? '#0ea5e9' : '#8b5cf6'} />
    },
    { key: 'is_sensitive', label: 'Sensitive', width: '10%', sortable: true,
      render: v => v
        ? <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, background: '#450a0a', color: 'var(--danger)', border: '1px solid #991b1b', borderRadius: 4, padding: '2px 7px', fontSize: 11, fontWeight: 600 }}>⚠ Secret</span>
        : <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
    },
    { key: 'asset_label', label: 'Asset', width: '19%',
      render: (v, r) => <>{v}<EnvPill env={r.asset_env} /></>
    },
  ]

  return (
    <Card>
      <FilterBar>
        <Input value={search} onChange={setSearch} placeholder="Search name or value…" style={{ width: 220 }} />
        <Select value={scope} onChange={setScope} placeholder="All scopes" options={[
          { value: 'global', label: 'Global' },
          { value: 'user',   label: 'Active User' },
        ]} />
        <Button variant={sensitiveOnly ? 'primary' : 'ghost'} size="sm" onClick={() => setSensitiveOnly(v => !v)}>
          {sensitiveOnly ? '✕ Secrets only' : '⚠ Secrets only'}
        </Button>
        <GroupByToggle value={groupByAsset} onChange={setGroupByAsset} />
      </FilterBar>
      {sensitiveCount > 0 && (
        <div style={{ marginBottom: 12, padding: '8px 12px', background: '#450a0a', border: '1px solid #991b1b', borderRadius: 6, fontSize: 13, color: 'var(--danger)' }}>
          ⚠ {sensitiveCount} sensitive variable{sensitiveCount !== 1 ? 's' : ''} detected — credentials or secrets exposed in environment
        </div>
      )}
      {loading ? <Spinner /> : groupByAsset
        ? <GroupedTable columns={columns} rows={rows} emptyMessage="No environment variables found." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
        : <Table columns={columns} rows={rows} emptyMessage="No environment variables found." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
      }
      <Pagination page={page} total={total} pageSize={INV_PAGE_SIZE} onPageChange={setPage} noun="variables" />
    </Card>
  )
}


// ─── Certificates tab ──────────────────────────────────────
function CertificatesTab({ scanId, assetId }) {
  const [rows, setRows]               = useState([])
  const [total, setTotal]             = useState(0)
  const [page, setPage]               = useState(1)
  const [loading, setLoading]         = useState(true)
  const [search, setSearch]           = useState('')
  const [expiredOnly, setExpiredOnly] = useState(false)
  const [selfSignedOnly, setSelfSignedOnly] = useState(false)
  const [groupByAsset, setGroupByAsset] = useState(false)
  const [sourceFilter, setSourceFilter] = useState('') // '', 'nessus', 'easm'
  const [sortBy, setSortBy]           = useState('not_after')
  const [sortOrder, setSortOrder]     = useState('asc')
  const [easmCerts, setEasmCerts]     = useState([])

  const handleSort = (key) => {
    if (sortBy === key) { setSortOrder(o => o === 'asc' ? 'desc' : 'asc') }
    else { setSortBy(key); setSortOrder('asc') }
  }

  useEffect(() => { setPage(1) }, [scanId, assetId, search, expiredOnly, selfSignedOnly, sourceFilter])

  // Fetch Nessus certs
  useEffect(() => {
    setLoading(true)
    getInventoryCertificates({
      scan_id: scanId,
      asset_id: assetId || null,
      search: search || null,
      expired_only: expiredOnly || null,
      self_signed_only: selfSignedOnly || null,
      sort_by: sortBy,
      order: sortOrder,
      page,
      page_size: INV_PAGE_SIZE,
    }).then(data => { setRows(data.certificates); setTotal(data.total) }).catch(() => { setRows([]); setTotal(0) }).finally(() => setLoading(false))
  }, [scanId, assetId, search, expiredOnly, selfSignedOnly, sortBy, sortOrder, page])

  // Fetch EASM TLS certs (once, merge client-side)
  useEffect(() => {
    getEasmAssets().then(assets => {
      if (!Array.isArray(assets)) return
      const certs = assets
        .filter(a => a.tls_cert && (a.tls_cert.subject || a.tls_cert.subject_cn || a.tls_cert.issuer))
        .map(a => {
          const c = a.tls_cert
          // tlsx stores expiry as "expiry", asset-level may use "not_after"
          const expiryRaw = c.expiry || c.not_after || null
          const notAfter = expiryRaw ? new Date(expiryRaw) : null
          const now = new Date()
          const isExpired = notAfter ? notAfter < now : false
          const daysUntil = notAfter && !isNaN(notAfter) ? Math.ceil((notAfter - now) / 86400000) : null
          const subjectStr = c.subject || c.subject_cn || a.hostname
          const issuerStr = c.issuer || c.issuer_cn || c.issuer_o || '—'
          return {
            subject_cn: subjectStr,
            issuer_cn: issuerStr,
            port: c.port || 443,
            not_after: expiryRaw,
            days_until_expiry: daysUntil,
            is_expired: isExpired,
            is_self_signed: c.is_self_signed || (subjectStr && issuerStr && subjectStr === issuerStr) || false,
            key_algorithm: c.key_algorithm || c.cipher || null,
            key_bits: c.key_bits || c.key_size || null,
            tls_version: c.version || null,
            asset_label: a.hostname,
            asset_env: 'internet',
            _source: 'easm',
          }
        })
      setEasmCerts(certs)
    }).catch(() => {})
  }, [])

  // Merge rows based on source filter
  const mergedRows = useMemo(() => {
    const nessusRows = rows.map(r => ({ ...r, _source: r._source || 'nessus' }))
    if (sourceFilter === 'nessus') return nessusRows
    if (sourceFilter === 'easm') return easmCerts
    // Merge — avoid duplicates by subject_cn+port
    const seen = new Set(nessusRows.map(r => `${r.subject_cn}::${r.port}`))
    const unique = easmCerts.filter(c => !seen.has(`${c.subject_cn}::${c.port}`))
    return [...nessusRows, ...unique]
  }, [rows, easmCerts, sourceFilter])

  const expiredCount    = mergedRows.filter(r => r.is_expired).length
  const expiringSoon    = mergedRows.filter(r => !r.is_expired && r.days_until_expiry != null && r.days_until_expiry <= 30).length
  const selfSignedCount = mergedRows.filter(r => r.is_self_signed).length
  const easmCount       = mergedRows.filter(r => r._source === 'easm').length

  function ExpiryBadge({ row }) {
    if (row.is_expired) {
      return <span style={{ display:'inline-flex', alignItems:'center', gap:3, background:'#450a0a', color:'#fca5a5', border:'1px solid #991b1b', borderRadius:4, padding:'2px 7px', fontSize:11, fontWeight:600 }}>Expired</span>
    }
    if (row.days_until_expiry != null && row.days_until_expiry <= 30) {
      return <span style={{ display:'inline-flex', alignItems:'center', gap:3, background:'#451a03', color:'#fdba74', border:'1px solid #9a3412', borderRadius:4, padding:'2px 7px', fontSize:11, fontWeight:600 }}>{row.days_until_expiry}d</span>
    }
    if (row.days_until_expiry != null) {
      return <span style={{ color:'var(--text-muted)', fontSize:12 }}>{row.days_until_expiry}d</span>
    }
    return <span style={{ color:'var(--text-muted)', fontSize:12 }}>—</span>
  }

  const columns = [
    { key: 'subject_cn', label: 'Common Name', width: '20%', sortable: true,
      render: (v, r) => (
        <span style={{ fontWeight: 600, color: r.is_expired ? '#fca5a5' : 'inherit' }}>
          {v || '—'}
        </span>
      )
    },
    { key: 'issuer_cn', label: 'Issuer', width: '18%', sortable: true,
      render: (v, r) => (
        <span style={{ fontSize: 12, color: r.is_self_signed ? '#fcd34d' : 'var(--text-muted)' }}>
          {v || '—'}{r.is_self_signed && ' ⚠'}
        </span>
      )
    },
    { key: 'port', label: 'Port', width: '6%', sortable: true,
      render: v => <code style={{ fontSize: 12 }}>{v || '—'}</code>
    },
    { key: 'not_after', label: 'Expires', width: '12%', sortable: true,
      render: (v) => <span style={{ fontSize: 12 }}>{v ? (typeof v === 'string' && v.includes('T') ? new Date(v).toLocaleDateString() : v) : '—'}</span>
    },
    { key: 'days_until_expiry', label: 'In', width: '7%', sortable: true,
      render: (_, r) => <ExpiryBadge row={r} />
    },
    { key: 'key_bits', label: 'Key', width: '9%', sortable: true,
      render: (v, r) => <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{r.key_algorithm ? `${r.key_algorithm} ${v || ''}`.trim() : (v || '—')}</span>
    },
    { key: '_source', label: 'Source', width: '8%',
      render: v => (
        <Pill label={v === 'easm' ? 'EASM' : 'Nessus'} color={v === 'easm' ? '#0ea5e9' : '#6366f1'} />
      )
    },
    { key: 'asset_label', label: 'Asset', width: '20%',
      render: (v, r) => <>{v}<EnvPill env={r.asset_env} /></>
    },
  ]

  return (
    <Card>
      <FilterBar>
        <Input value={search} onChange={setSearch} placeholder="Search CN or issuer…" style={{ width: 240 }} />
        <Button variant={expiredOnly ? 'primary' : 'ghost'} size="sm" onClick={() => setExpiredOnly(v => !v)}>
          {expiredOnly ? '✕ Expired only' : 'Expired only'}
        </Button>
        <Button variant={selfSignedOnly ? 'primary' : 'ghost'} size="sm" onClick={() => setSelfSignedOnly(v => !v)}>
          {selfSignedOnly ? '✕ Self-signed only' : 'Self-signed only'}
        </Button>
        <select
          value={sourceFilter}
          onChange={e => setSourceFilter(e.target.value)}
          style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: sourceFilter ? 'var(--text-primary)' : 'var(--text-muted)', borderRadius: 6, padding: '5px 8px', fontSize: 12 }}
        >
          <option value="">All Sources</option>
          <option value="nessus">Nessus</option>
          <option value="easm">EASM</option>
        </select>
        <GroupByToggle value={groupByAsset} onChange={setGroupByAsset} />
      </FilterBar>
      {(expiredCount > 0 || expiringSoon > 0 || selfSignedCount > 0 || easmCount > 0) && (
        <div style={{ display:'flex', gap:10, marginBottom:12, flexWrap:'wrap' }}>
          {expiredCount > 0 && (
            <div style={{ padding:'7px 12px', background:'#450a0a', border:'1px solid #991b1b', borderRadius:6, fontSize:13, color:'#fca5a5' }}>
              ⚠ {expiredCount} expired certificate{expiredCount !== 1 ? 's' : ''}
            </div>
          )}
          {expiringSoon > 0 && (
            <div style={{ padding:'7px 12px', background:'#451a03', border:'1px solid #9a3412', borderRadius:6, fontSize:13, color:'#fdba74' }}>
              ⏰ {expiringSoon} expiring within 30 days
            </div>
          )}
          {selfSignedCount > 0 && (
            <div style={{ padding:'7px 12px', background:'#422006', border:'1px solid #92400e', borderRadius:6, fontSize:13, color:'#fcd34d' }}>
              ⚠ {selfSignedCount} self-signed certificate{selfSignedCount !== 1 ? 's' : ''}
            </div>
          )}
          {easmCount > 0 && (
            <div style={{ padding:'7px 12px', background:'#0c2d48', border:'1px solid #0ea5e944', borderRadius:6, fontSize:13, color:'#7dd3fc' }}>
              {easmCount} from EASM discovery
            </div>
          )}
        </div>
      )}
      {loading ? <Spinner /> : groupByAsset
        ? <GroupedTable columns={columns} rows={mergedRows} emptyMessage="No certificates found." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
        : <Table columns={columns} rows={mergedRows} emptyMessage="No certificates found." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
      }
      <Pagination page={page} total={sourceFilter === 'easm' ? easmCerts.length : (total + (sourceFilter === '' ? easmCerts.length : 0))} pageSize={INV_PAGE_SIZE} onPageChange={setPage} noun="certificates" />
    </Card>
  )
}


// ─── Credentials tab ──────────────────────────────────────
const CRED_TYPE_LABELS = {
  default_account: 'Default Account',
  cleartext: 'Cleartext',
  brute_forceable: 'Brute Forceable',
  weak_config: 'Weak Config',
  shared_credential: 'Shared Credential',
}

const CRED_TYPE_COLORS = {
  default_account: '#dc2626',
  cleartext: '#ea580c',
  brute_forceable: '#f59e0b',
  weak_config: '#d97706',
  shared_credential: '#8b5cf6',
}

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

function CredentialTypePill({ type }) {
  const label = CRED_TYPE_LABELS[type] || type
  const color = CRED_TYPE_COLORS[type] || '#94a3b8'
  return (
    <span style={{
      display: 'inline-block', padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600,
      background: color + '18', color, border: `1px solid ${color}44`,
    }}>{label}</span>
  )
}

function CredSeverityBadge({ severity }) {
  const colors = { critical: '#dc2626', high: '#ea580c', medium: '#d97706', low: '#65a30d', info: '#0ea5e9' }
  const color = colors[severity] || '#94a3b8'
  return (
    <span style={{
      display: 'inline-block', padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600,
      background: color + '18', color, border: `1px solid ${color}44`, textTransform: 'capitalize',
    }}>{severity}</span>
  )
}

function CredentialsTab({ scanId, assetId }) {
  const [rows, setRows]                = useState([])
  const [total, setTotal]              = useState(0)
  const [page, setPage]                = useState(1)
  const [loading, setLoading]          = useState(true)
  const [search, setSearch]            = useState('')
  const [credType, setCredType]        = useState('')
  const [protocol, setProtocol]        = useState('')
  const [severity, setSeverity]        = useState('')
  const [groupByAsset, setGroupByAsset] = useState(false)
  const [sortBy, setSortBy]            = useState('severity')
  const [sortOrder, setSortOrder]      = useState('desc')

  const handleSort = (key) => {
    if (sortBy === key) { setSortOrder(o => o === 'asc' ? 'desc' : 'asc') }
    else { setSortBy(key); setSortOrder('asc') }
  }

  useEffect(() => { setPage(1) }, [scanId, assetId, search, credType, protocol, severity])

  const load = useCallback(() => {
    setLoading(true)
    getInventoryCredentials({
      scan_id: scanId,
      asset_id: assetId || null,
      search: search || null,
      credential_type: credType || null,
      protocol: protocol || null,
      severity: severity || null,
      sort_by: sortBy,
      order: sortOrder,
      page,
      page_size: INV_PAGE_SIZE,
    }).then(data => { setRows(data.credentials); setTotal(data.total) }).catch(() => { setRows([]); setTotal(0) }).finally(() => setLoading(false))
  }, [scanId, assetId, search, credType, protocol, severity, sortBy, sortOrder, page])

  useEffect(() => { load() }, [load])

  const columns = [
    { key: 'credential_type', label: 'Type', width: '15%', sortable: true,
      render: v => <CredentialTypePill type={v} />
    },
    { key: 'protocol', label: 'Protocol', width: '10%', sortable: true,
      render: v => <code style={{ fontSize: 12, color: 'var(--accent)', background: 'var(--accent)11', padding: '2px 6px', borderRadius: 3 }}>{(v || '—').toUpperCase()}</code>
    },
    { key: 'severity', label: 'Severity', width: '10%', sortable: true,
      render: v => <CredSeverityBadge severity={v} />
    },
    { key: 'username', label: 'Username', width: '12%', sortable: true,
      render: v => v ? <code style={{ fontSize: 12 }}>{v}</code> : <span style={{ color: 'var(--text-muted)' }}>—</span>
    },
    { key: 'port', label: 'Port', width: '7%', sortable: true,
      render: v => v ? <code style={{ fontSize: 12, color: 'var(--text-muted)' }}>{v}</code> : '—'
    },
    { key: 'plugin_name', label: 'Finding', width: '26%',
      render: v => <span style={{ fontSize: 12 }}>{v}</span>
    },
    { key: 'asset_label', label: 'Asset', width: '15%',
      render: (v, r) => <>{v}<EnvPill env={r.asset_env} /></>
    },
    { key: 'asset_ip', label: 'IP', width: '5%',
      render: v => <code style={{ fontSize: 12, color: 'var(--text-muted)' }}>{v || '—'}</code>
    },
  ]

  // Summary pills
  const byType = rows.reduce((acc, r) => {
    const t = r.credential_type || 'other'
    acc[t] = (acc[t] || 0) + 1
    return acc
  }, {})

  const protocols = [...new Set(rows.map(r => r.protocol).filter(Boolean))]

  return (
    <Card>
      <FilterBar>
        <Input value={search} onChange={setSearch} placeholder="Search credentials…" style={{ width: 240 }} />
        <Select
          value={credType}
          onChange={setCredType}
          options={[
            { value: '', label: 'All types' },
            ...Object.entries(CRED_TYPE_LABELS).map(([k, v]) => ({ value: k, label: v })),
          ]}
        />
        <Select
          value={protocol}
          onChange={setProtocol}
          options={[
            { value: '', label: 'All protocols' },
            ...protocols.map(p => ({ value: p, label: p.toUpperCase() })),
          ]}
        />
        <Select
          value={severity}
          onChange={setSeverity}
          options={[
            { value: '', label: 'All severities' },
            { value: 'critical', label: 'Critical' },
            { value: 'high', label: 'High' },
            { value: 'medium', label: 'Medium' },
            { value: 'low', label: 'Low' },
          ]}
        />
        <GroupByToggle value={groupByAsset} onChange={setGroupByAsset} />
      </FilterBar>
      {rows.length > 0 && (
        <div style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap' }}>
          {Object.entries(byType).map(([type, count]) => (
            <div key={type} style={{
              padding: '5px 12px',
              background: (CRED_TYPE_COLORS[type] || '#475569') + '18',
              border: `1px solid ${(CRED_TYPE_COLORS[type] || '#475569')}44`,
              borderRadius: 6, fontSize: 12,
              color: CRED_TYPE_COLORS[type] || '#94a3b8',
              fontWeight: 600,
            }}>
              {CRED_TYPE_LABELS[type] || type}: {count}
            </div>
          ))}
        </div>
      )}
      {groupByAsset
        ? <GroupedTable rows={rows} columns={columns} loading={loading} onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
        : <Table columns={columns} rows={rows} loading={loading} onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
      }
      <Pagination page={page} total={total} pageSize={INV_PAGE_SIZE} onPageChange={setPage} noun="credentials" />
    </Card>
  )
}


// ─── AI / LLM Tools tab ────────────────────────────────────
const CATEGORY_LABELS = {
  browser_extension: 'Browser Extension',
  application:       'Application',
  cloud_service:     'Cloud Service',
  model:             'Model',
  tool:              'Tool',
  other:             'Other',
}

const CATEGORY_COLORS = {
  browser_extension: '#7c3aed',
  application:       '#0ea5e9',
  cloud_service:     '#10b981',
  model:             '#f59e0b',
  tool:              '#64748b',
  other:             '#475569',
}

function CategoryPill({ category }) {
  const label = CATEGORY_LABELS[category] || category || '—'
  const color = CATEGORY_COLORS[category] || '#475569'
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center',
      background: color + '22', color, border: `1px solid ${color}55`,
      borderRadius: 4, padding: '2px 8px', fontSize: 11, fontWeight: 600,
    }}>{label}</span>
  )
}

function AIToolsTab({ scanId, assetId }) {
  const [rows, setRows]               = useState([])
  const [total, setTotal]             = useState(0)
  const [page, setPage]               = useState(1)
  const [loading, setLoading]         = useState(true)
  const [search, setSearch]           = useState('')
  const [category, setCategory]       = useState('')
  const [groupByAsset, setGroupByAsset] = useState(false)
  const [sortBy, setSortBy]           = useState('tool_name')
  const [sortOrder, setSortOrder]     = useState('asc')

  const handleSort = (key) => {
    if (sortBy === key) { setSortOrder(o => o === 'asc' ? 'desc' : 'asc') }
    else { setSortBy(key); setSortOrder('asc') }
  }

  useEffect(() => { setPage(1) }, [scanId, assetId, search, category])

  const load = useCallback(() => {
    setLoading(true)
    getInventoryAITools({
      scan_id: scanId,
      asset_id: assetId || null,
      search: search || null,
      category: category || null,
      sort_by: sortBy,
      order: sortOrder,
      page,
      page_size: INV_PAGE_SIZE,
    }).then(data => { setRows(data.ai_tools); setTotal(data.total) }).catch(() => { setRows([]); setTotal(0) }).finally(() => setLoading(false))
  }, [scanId, assetId, search, category, sortBy, sortOrder, page])

  useEffect(() => { load() }, [load])

  const categories = [...new Set(rows.map(r => r.category).filter(Boolean))]

  const columns = [
    { key: 'tool_name', label: 'Tool / Extension', width: '40%', sortable: true,
      render: v => <span style={{ fontWeight: 600 }}>{v}</span>
    },
    { key: 'category', label: 'Category', width: '20%', sortable: true,
      render: v => <CategoryPill category={v} />
    },
    { key: 'asset_label', label: 'Asset', width: '30%',
      render: (v, r) => <>{v}<EnvPill env={r.asset_env} /></>
    },
    { key: 'asset_ip', label: 'IP', width: '10%',
      render: v => <code style={{ fontSize: 12, color: 'var(--text-muted)' }}>{v || '—'}</code>
    },
  ]

  const byCategory = rows.reduce((acc, r) => {
    const cat = r.category || 'other'
    acc[cat] = (acc[cat] || 0) + 1
    return acc
  }, {})

  return (
    <Card>
      <FilterBar>
        <Input value={search} onChange={setSearch} placeholder="Search tool name…" style={{ width: 240 }} />
        <Select
          value={category}
          onChange={setCategory}
          options={[
            { value: '', label: 'All categories' },
            ...Object.keys(CATEGORY_LABELS).map(k => ({ value: k, label: CATEGORY_LABELS[k] })),
          ]}
        />
        <GroupByToggle value={groupByAsset} onChange={setGroupByAsset} />
      </FilterBar>
      {rows.length > 0 && (
        <div style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap' }}>
          {Object.entries(byCategory).map(([cat, count]) => (
            <div key={cat} style={{
              padding: '5px 12px',
              background: (CATEGORY_COLORS[cat] || '#475569') + '18',
              border: `1px solid ${(CATEGORY_COLORS[cat] || '#475569')}44`,
              borderRadius: 6, fontSize: 12,
              color: CATEGORY_COLORS[cat] || '#94a3b8',
            }}>
              {CATEGORY_LABELS[cat] || cat}: <strong>{count}</strong>
            </div>
          ))}
        </div>
      )}
      {loading ? <Spinner /> : groupByAsset
        ? <GroupedTable columns={columns} rows={rows} emptyMessage="No AI/LLM tools detected." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
        : <Table columns={columns} rows={rows} emptyMessage="No AI/LLM tools detected." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
      }
      <Pagination page={page} total={total} pageSize={INV_PAGE_SIZE} onPageChange={setPage} noun="tools" />
    </Card>
  )
}


// ─── Processes Tab ──────────────────────────────────────────
function ProcessesTab({ scanId, assetId }) {
  const [rows, setRows]               = useState([])
  const [total, setTotal]             = useState(0)
  const [page, setPage]               = useState(1)
  const [loading, setLoading]         = useState(true)
  const [search, setSearch]           = useState('')
  const [groupByAsset, setGroupByAsset] = useState(false)
  const [sortBy, setSortBy]           = useState('process_name')
  const [sortOrder, setSortOrder]     = useState('asc')

  const handleSort = (key) => {
    if (sortBy === key) { setSortOrder(o => o === 'asc' ? 'desc' : 'asc') }
    else { setSortBy(key); setSortOrder('asc') }
  }

  useEffect(() => { setPage(1) }, [scanId, assetId, search])

  const load = useCallback(() => {
    setLoading(true)
    getInventoryProcesses({ scan_id: scanId, asset_id: assetId || null, search: search || null, sort_by: sortBy, order: sortOrder, page, page_size: INV_PAGE_SIZE })
      .then(data => { setRows(data.processes); setTotal(data.total) }).catch(() => { setRows([]); setTotal(0) }).finally(() => setLoading(false))
  }, [scanId, assetId, search, sortBy, sortOrder, page])

  useEffect(() => { load() }, [load])

  const columns = [
    { key: 'process_name', label: 'Process', width: '28%', sortable: true,
      render: (v, r) => (
        <span style={{ paddingLeft: Math.min(r.depth, 6) * 16, display: 'inline-flex', alignItems: 'center', gap: 4 }}>
          {r.depth > 0 && <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>└</span>}
          <code style={{ fontSize: 12, fontWeight: 600, background: 'var(--bg-muted)', padding: '2px 6px', borderRadius: 4 }}>{v}</code>
        </span>
      )
    },
    { key: 'pid', label: 'PID', width: '10%', sortable: true,
      render: v => <code style={{ fontSize: 11, color: 'var(--text-muted)' }}>{v}</code>
    },
    { key: 'ppid', label: 'PPID', width: '10%', sortable: true,
      render: v => v != null ? <code style={{ fontSize: 11, color: 'var(--text-muted)' }}>{v}</code> : '—'
    },
    { key: 'parent_name', label: 'Parent', width: '18%', sortable: true,
      render: v => v || '—'
    },
    { key: 'session_id', label: 'Session', width: '9%', sortable: true,
      render: v => <Pill label={v} color={v === 0 ? '#6366f1' : '#f59e0b'} />
    },
    { key: 'asset_label', label: 'Asset', width: '25%',
      render: (v, r) => <>{v}<EnvPill env={r.asset_env} /></>
    },
  ]

  // Unique process name count
  const uniqueNames = new Set(rows.map(r => r.process_name)).size

  return (
    <Card>
      <FilterBar>
        <Input value={search} onChange={setSearch} placeholder="Search process name…" style={{ width: 240 }} />
        <GroupByToggle value={groupByAsset} onChange={setGroupByAsset} />
      </FilterBar>
      {loading ? <Spinner /> : groupByAsset
        ? <GroupedTable columns={columns} rows={rows} emptyMessage="No processes found." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
        : <Table columns={columns} rows={rows} emptyMessage="No processes found." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
      }
      <Pagination page={page} total={total} pageSize={INV_PAGE_SIZE} onPageChange={setPage} noun="processes" />
    </Card>
  )
}


// ─── Root ──────────────────────────────────────────────────
// ─── EASM Assets tab ──────────────────────────────────────
function EasmAssetsTab() {
  const { t } = useTranslation()
  const [rows, setRows] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [search, setSearch] = useState('')
  const [expanded, setExpanded] = useState(null) // asset id for screenshot modal
  const [sortBy, setSortBy] = useState('last_seen')
  const [sortOrder, setSortOrder] = useState('desc')

  const handleSort = (key) => {
    if (sortBy === key) { setSortOrder(o => o === 'asc' ? 'desc' : 'asc') }
    else { setSortBy(key); setSortOrder('desc') }
  }

  useEffect(() => {
    setLoading(true)
    setError(null)
    getEasmAssets()
      .then(data => setRows(Array.isArray(data) ? data : []))
      .catch(() => setError(t('inventory.easmLoadError')))
      .finally(() => setLoading(false))
  }, [])

  const filtered = useMemo(() => {
    let list = rows
    if (search) {
      const q = search.toLowerCase()
      list = list.filter(a =>
        (a.hostname || '').toLowerCase().includes(q) ||
        (a.ip || '').toLowerCase().includes(q) ||
        (a.http_title || '').toLowerCase().includes(q) ||
        (a.cdn_provider || '').toLowerCase().includes(q) ||
        (a.waf || '').toLowerCase().includes(q) ||
        (Array.isArray(a.tech_stack) ? a.tech_stack : []).some(t => (typeof t === 'string' ? t : t?.name || '').toLowerCase().includes(q))
      )
    }
    // Sort
    list = [...list].sort((a, b) => {
      const va = a[sortBy] ?? '', vb = b[sortBy] ?? ''
      const cmp = typeof va === 'number' ? va - vb : String(va).localeCompare(String(vb))
      return sortOrder === 'asc' ? cmp : -cmp
    })
    return list
  }, [rows, search, sortBy, sortOrder])

  function TechPills({ stack }) {
    if (!stack) return <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
    const items = Array.isArray(stack) ? stack : Object.keys(stack)
    if (items.length === 0) return <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
    return (
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
        {items.slice(0, 4).map((t, i) => {
          const name = typeof t === 'string' ? t : t?.name || t?.slug || String(t)
          return <Pill key={i} label={name} color="#6366f1" />
        })}
        {items.length > 4 && <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>+{items.length - 4}</span>}
      </div>
    )
  }

  function PortsList({ ports }) {
    if (!ports || ports.length === 0) return <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
    const shown = ports.slice(0, 6)
    return (
      <span style={{ fontSize: 12, fontFamily: 'monospace' }}>
        {shown.join(', ')}{ports.length > 6 ? ` +${ports.length - 6}` : ''}
      </span>
    )
  }

  function TlsBadge({ cert }) {
    if (!cert) return <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
    const expiryRaw = cert.expiry || cert.not_after
    const expired = expiryRaw && new Date(expiryRaw) < new Date()
    const issuer = cert.issuer || cert.issuer_cn || cert.issuer_o || '—'
    return (
      <span style={{
        display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 12,
        color: expired ? '#fca5a5' : 'var(--text-muted)',
      }}>
        <Lock size={11} style={{ color: expired ? '#ef4444' : '#16a34a' }} />
        {expired ? 'Expired' : issuer}
      </span>
    )
  }

  const columns = [
    { key: 'hostname', label: t('inventory.easmHostname'), width: '22%', sortable: true,
      render: (v, r) => (
        <div>
          <div style={{ fontWeight: 600, fontSize: 13 }}>{v}</div>
          {r.http_title && <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.http_title}</div>}
        </div>
      ),
    },
    { key: 'ip', label: 'IP', width: '11%', sortable: true,
      render: v => <span style={{ fontSize: 12, fontFamily: 'monospace', color: 'var(--text-muted)' }}>{v || '—'}</span>,
    },
    { key: 'open_ports', label: t('inventory.easmPorts'), width: '12%',
      render: v => <PortsList ports={v} />,
    },
    { key: 'tech_stack', label: t('inventory.easmTechStack'), width: '18%',
      render: v => <TechPills stack={v} />,
    },
    { key: 'cdn_provider', label: 'CDN / WAF', width: '10%', sortable: true,
      render: (v, r) => {
        const parts = [v, r.waf].filter(Boolean)
        return parts.length > 0
          ? <span style={{ fontSize: 12 }}>{parts.join(' / ')}</span>
          : <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
      },
    },
    { key: 'tls_cert', label: 'TLS', width: '10%',
      render: v => <TlsBadge cert={v} />,
    },
    { key: 'http_status', label: 'HTTP', width: '7%', sortable: true,
      render: v => v != null
        ? <span style={{ fontSize: 12, fontFamily: 'monospace', fontWeight: 600, color: v >= 200 && v < 400 ? '#16a34a' : v >= 400 ? '#ef4444' : '#d97706' }}>{v}</span>
        : <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>,
    },
    { key: 'last_seen', label: t('inventory.easmLastSeen'), width: '10%', sortable: true,
      render: v => <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{v ? new Date(v).toLocaleDateString() : '—'}</span>,
    },
  ]

  // Screenshot modal
  const screenshotAsset = expanded ? rows.find(a => a.id === expanded) : null

  if (error) return <ErrorBanner error={error} onDismiss={() => setError(null)} />

  // Summary stats
  const withHttp = rows.filter(r => r.http_status != null).length
  const withCdn = rows.filter(r => r.cdn_provider).length
  const expiredTls = rows.filter(r => r.tls_cert && (r.tls_cert.expiry || r.tls_cert.not_after) && new Date(r.tls_cert.expiry || r.tls_cert.not_after) < new Date()).length

  return (
    <>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 10, marginBottom: 16 }}>
        <StatCard label={t('inventory.easmTotal')} value={rows.length} icon={Globe} color="#0ea5e9" />
        <StatCard label={t('inventory.easmWithHttp')} value={withHttp} icon={Globe} color="#16a34a" />
        <StatCard label={t('inventory.easmWithCdn')} value={withCdn} icon={Shield} color="#6366f1" />
        <StatCard label={t('inventory.easmExpiredTls')} value={expiredTls} icon={ShieldAlert} color="#ef4444" />
        <StatCard label={t('inventory.easmTechDetected')} value={rows.filter(r => r.tech_stack && (Array.isArray(r.tech_stack) ? r.tech_stack.length > 0 : Object.keys(r.tech_stack).length > 0)).length} icon={Package} color="#f59e0b" />
      </div>
      <Card>
        <FilterBar>
          <Input value={search} onChange={setSearch} placeholder={t('inventory.easmSearchPlaceholder')} style={{ width: 280 }} />
        </FilterBar>
        {loading ? <Spinner /> : (
          <Table
            columns={columns}
            rows={filtered}
            emptyMessage={t('inventory.easmNoAssets')}
            onSort={handleSort}
            sortBy={sortBy}
            sortOrder={sortOrder}
            onRowClick={(row) => setExpanded(expanded === row.id ? null : row.id)}
          />
        )}
      </Card>

      {/* Screenshot / detail modal */}
      {screenshotAsset && (
        <div
          onClick={() => setExpanded(null)}
          style={{
            position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', zIndex: 1000,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}
        >
          <div
            onClick={e => e.stopPropagation()}
            style={{
              background: 'var(--bg-primary)', borderRadius: 12, padding: 24,
              maxWidth: 720, width: '90vw', maxHeight: '85vh', overflow: 'auto',
              border: '1px solid var(--border)',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <h3 style={{ margin: 0, fontSize: 16 }}>{screenshotAsset.hostname}</h3>
              <button onClick={() => setExpanded(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}>
                <X size={18} />
              </button>
            </div>

            {/* Detail grid */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, fontSize: 13, marginBottom: 16 }}>
              <div><span style={{ color: 'var(--text-muted)' }}>IP:</span> <code>{screenshotAsset.ip || '—'}</code></div>
              <div><span style={{ color: 'var(--text-muted)' }}>HTTP Status:</span> {screenshotAsset.http_status ?? '—'}</div>
              <div><span style={{ color: 'var(--text-muted)' }}>URL:</span> {screenshotAsset.http_url ? <a href={screenshotAsset.http_url} target="_blank" rel="noreferrer" style={{ color: '#60a5fa' }}>{screenshotAsset.http_url} <ExternalLink size={11} style={{ verticalAlign: 'middle' }} /></a> : '—'}</div>
              <div><span style={{ color: 'var(--text-muted)' }}>CDN / WAF:</span> {[screenshotAsset.cdn_provider, screenshotAsset.waf].filter(Boolean).join(' / ') || '—'}</div>
              <div><span style={{ color: 'var(--text-muted)' }}>ASN:</span> {screenshotAsset.asn_org || screenshotAsset.asn || '—'}</div>
              <div><span style={{ color: 'var(--text-muted)' }}>Ports:</span> <code>{(screenshotAsset.open_ports || []).join(', ') || '—'}</code></div>
              <div style={{ gridColumn: '1 / -1' }}>
                <span style={{ color: 'var(--text-muted)' }}>Tech Stack:</span>{' '}
                <TechPills stack={screenshotAsset.tech_stack} />
              </div>
              {screenshotAsset.tls_cert && (
                <div style={{ gridColumn: '1 / -1' }}>
                  <span style={{ color: 'var(--text-muted)' }}>TLS Certificate:</span>{' '}
                  <span style={{ fontSize: 12 }}>
                    {screenshotAsset.tls_cert.subject || screenshotAsset.tls_cert.subject_cn || '—'}
                    {' — issued by '}{screenshotAsset.tls_cert.issuer || screenshotAsset.tls_cert.issuer_cn || screenshotAsset.tls_cert.issuer_o || '—'}
                    {(screenshotAsset.tls_cert.expiry || screenshotAsset.tls_cert.not_after) && ` — expires ${new Date(screenshotAsset.tls_cert.expiry || screenshotAsset.tls_cert.not_after).toLocaleDateString()}`}
                    {screenshotAsset.tls_cert.version && ` (${screenshotAsset.tls_cert.version})`}
                  </span>
                </div>
              )}
              {screenshotAsset.dns_records && Object.keys(screenshotAsset.dns_records).length > 0 && (
                <div style={{ gridColumn: '1 / -1' }}>
                  <span style={{ color: 'var(--text-muted)' }}>DNS Records:</span>{' '}
                  <span style={{ fontSize: 12, fontFamily: 'monospace' }}>
                    {Object.entries(screenshotAsset.dns_records).map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`).join(' | ')}
                  </span>
                </div>
              )}
            </div>

            {/* Tags */}
            {screenshotAsset.tags && screenshotAsset.tags.length > 0 && (
              <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 16 }}>
                {screenshotAsset.tags.map((tag, i) => <Pill key={i} label={tag} color={tag.includes('expired') ? '#ef4444' : tag.includes('cdn') ? '#16a34a' : '#64748b'} />)}
              </div>
            )}

            {/* Timestamps */}
            <div style={{ fontSize: 11, color: 'var(--text-muted)', display: 'flex', gap: 16 }}>
              {screenshotAsset.first_seen && <span>First seen: {new Date(screenshotAsset.first_seen).toLocaleDateString()}</span>}
              {screenshotAsset.last_seen && <span>Last seen: {new Date(screenshotAsset.last_seen).toLocaleDateString()}</span>}
              {screenshotAsset.last_enriched && <span>Last enriched: {new Date(screenshotAsset.last_enriched).toLocaleDateString()}</span>}
            </div>
          </div>
        </div>
      )}
    </>
  )
}


// ─── EASM Breaches tab ────────────────────────────────────
function EasmBreachesTab() {
  const { t } = useTranslation()
  const [rows, setRows] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [search, setSearch] = useState('')
  const [sortBy, setSortBy] = useState('breach_date')
  const [sortOrder, setSortOrder] = useState('desc')

  const handleSort = (key) => {
    if (sortBy === key) { setSortOrder(o => o === 'asc' ? 'desc' : 'asc') }
    else { setSortBy(key); setSortOrder('desc') }
  }

  useEffect(() => {
    setLoading(true)
    setError(null)
    getEasmBreaches()
      .then(data => setRows(Array.isArray(data) ? data : []))
      .catch(() => setError('Failed to load breach data. Ensure HIBP sync has been run.'))
      .finally(() => setLoading(false))
  }, [])

  const filtered = useMemo(() => {
    let list = rows
    if (search) {
      const q = search.toLowerCase()
      list = list.filter(b =>
        (b.title || b.breach_name || '').toLowerCase().includes(q) ||
        (b.domain || '').toLowerCase().includes(q) ||
        (b.data_classes || []).some(c => c.toLowerCase().includes(q))
      )
    }
    list = [...list].sort((a, b) => {
      const va = a[sortBy] ?? '', vb = b[sortBy] ?? ''
      const cmp = typeof va === 'number' ? va - vb : String(va).localeCompare(String(vb))
      return sortOrder === 'asc' ? cmp : -cmp
    })
    return list
  }, [rows, search, sortBy, sortOrder])

  const totalExposed = rows.reduce((sum, r) => sum + (r.exposed_count || 0), 0)
  const verifiedCount = rows.filter(r => r.is_verified).length
  const domainsAffected = new Set(rows.map(r => r.domain)).size

  const columns = [
    { key: 'title', label: t('inventory.easmBreachName'), width: '22%', sortable: true,
      render: (v, r) => (
        <div>
          <div style={{ fontWeight: 600, fontSize: 13, display: 'flex', alignItems: 'center', gap: 6 }}>
            {v || r.breach_name}
            {r.is_verified && <span title="Verified breach" style={{ color: '#ef4444', fontSize: 11 }}>verified</span>}
          </div>
          {r.description && <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2, maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.description}</div>}
        </div>
      ),
    },
    { key: 'domain', label: t('inventory.easmBreachDomain'), width: '14%', sortable: true,
      render: v => <code style={{ fontSize: 12 }}>{v}</code>,
    },
    { key: 'breach_date', label: t('inventory.easmBreachDate'), width: '10%', sortable: true,
      render: v => <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{v || '—'}</span>,
    },
    { key: 'exposed_count', label: t('inventory.easmExposedAccounts'), width: '12%', sortable: true,
      render: v => (
        <span style={{ fontWeight: 600, fontSize: 13, color: v > 0 ? '#ef4444' : 'var(--text-muted)', fontVariantNumeric: 'tabular-nums' }}>
          {(v || 0).toLocaleString()}
        </span>
      ),
    },
    { key: 'pwn_count', label: t('inventory.easmTotalPwned'), width: '12%', sortable: true,
      render: v => <span style={{ fontSize: 12, color: 'var(--text-muted)', fontVariantNumeric: 'tabular-nums' }}>{v ? v.toLocaleString() : '—'}</span>,
    },
    { key: 'data_classes', label: t('inventory.easmDataTypes'), width: '22%',
      render: v => {
        if (!v || v.length === 0) return <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
        const sensitive = ['Passwords', 'Credit cards', 'Bank account numbers', 'Social security numbers', 'IP addresses']
        return (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
            {v.slice(0, 4).map((cls, i) => (
              <Pill key={i} label={cls} color={sensitive.some(s => cls.includes(s)) ? '#ef4444' : '#64748b'} />
            ))}
            {v.length > 4 && <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>+{v.length - 4}</span>}
          </div>
        )
      },
    },
    { key: 'checked_at', label: t('inventory.easmCheckedAt'), width: '8%', sortable: true,
      render: v => <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{v ? new Date(v).toLocaleDateString() : '—'}</span>,
    },
  ]

  if (error) return <ErrorBanner error={error} onDismiss={() => setError(null)} />

  return (
    <>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10, marginBottom: 16 }}>
        <StatCard label={t('inventory.easmBreachesFound')} value={rows.length.toLocaleString()} icon={ShieldAlert} color="#ef4444" />
        <StatCard label={t('inventory.easmExposedTotal')} value={totalExposed.toLocaleString()} icon={Users} color="#dc2626" />
        <StatCard label={t('inventory.easmVerifiedBreaches')} value={verifiedCount.toLocaleString()} icon={AlertTriangle} color="#f59e0b" />
        <StatCard label={t('inventory.easmDomainsAffected')} value={domainsAffected.toLocaleString()} icon={Globe} color="#7c3aed" />
      </div>
      {totalExposed > 0 && (
        <div style={{ padding: '10px 14px', background: '#450a0a', border: '1px solid #991b1b', borderRadius: 8, fontSize: 13, color: '#fca5a5', marginBottom: 16 }}>
          {t('inventory.easmBreachWarning', { count: totalExposed.toLocaleString(), breaches: rows.length.toLocaleString() })}
        </div>
      )}
      <Card>
        <FilterBar>
          <Input value={search} onChange={setSearch} placeholder={t('inventory.easmBreachSearch')} style={{ width: 280 }} />
        </FilterBar>
        {loading ? <Spinner /> : (
          <Table columns={columns} rows={filtered} emptyMessage={t('inventory.easmNoBreaches')} onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
        )}
      </Card>
    </>
  )
}


// ─── EASM Corporate / M&A tab ─────────────────────────────
function EasmCorporateTab() {
  const { t } = useTranslation()
  const [subsidiaries, setSubsidiaries] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [search, setSearch] = useState('')
  const [groupBy, setGroupBy] = useState('all')

  useEffect(() => {
    setLoading(true)
    setError(null)
    getEasmSubsidiaries()
      .then(data => setSubsidiaries(Array.isArray(data) ? data : []))
      .catch(() => setError('Failed to load corporate structure.'))
      .finally(() => setLoading(false))
  }, [])

  const filtered = useMemo(() => {
    if (!search) return subsidiaries
    const q = search.toLowerCase()
    return subsidiaries.filter(s =>
      (s.legal_name || '').toLowerCase().includes(q) ||
      (s.trading_name || '').toLowerCase().includes(q) ||
      (s.country || '').toLowerCase().includes(q) ||
      (s.jurisdiction || '').toLowerCase().includes(q) ||
      (s.lei || '').toLowerCase().includes(q) ||
      (s.associated_domains || []).some(d => d.toLowerCase().includes(q))
    )
  }, [subsidiaries, search])

  const grouped = useMemo(() => {
    const groups = {}
    for (const entity of filtered) {
      let groupKey
      if (groupBy === 'asset') {
        // Group by parent EASM domain (the scanned domain that owns this subsidiary)
        groupKey = entity.parent_domain || 'Unlinked'
      } else if (groupBy === 'country') {
        groupKey = entity.country || 'Unknown'
      } else {
        // Default: flat list, single group
        groupKey = 'all'
      }
      if (!groups[groupKey]) groups[groupKey] = []
      groups[groupKey].push(entity)
    }
    return groups
  }, [filtered, groupBy])

  const activeCount = subsidiaries.filter(s => s.status === 'ACTIVE').length
  const countries = new Set(subsidiaries.map(s => s.country).filter(Boolean)).size
  const withDomains = subsidiaries.filter(s => s.associated_domains && s.associated_domains.length > 0).length
  const jurisdictions = new Set(subsidiaries.map(s => s.jurisdiction).filter(Boolean)).size

  const STATUS_COLORS = {
    ACTIVE: '#16a34a',
    INACTIVE: '#64748b',
    MERGED: '#7c3aed',
  }

  if (error) return <ErrorBanner error={error} onDismiss={() => setError(null)} />

  return (
    <>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10, marginBottom: 16 }}>
        <StatCard label={t('inventory.easmEntities')} value={subsidiaries.length} icon={Building2} color="#6366f1" />
        <StatCard label={t('inventory.easmActive')} value={activeCount} icon={Building2} color="#16a34a" />
        <StatCard label={t('inventory.easmCountries')} value={countries} icon={Globe} color="#0ea5e9" />
        <StatCard label="Jurisdictions" value={jurisdictions} icon={Globe} color="#f59e0b" />
      </div>
      <Card>
        <FilterBar>
          <Input value={search} onChange={setSearch} placeholder={t('inventory.easmCorporateSearch')} style={{ width: 280 }} />
          <div style={{ display: 'flex', gap: 4, marginLeft: 'auto' }}>
            {[
              { key: 'all', label: 'All' },
              { key: 'asset', label: 'Group by asset' },
              { key: 'country', label: 'Group by country' },
            ].map(opt => (
              <button key={opt.key} onClick={() => setGroupBy(opt.key)} style={{
                padding: '4px 10px', fontSize: 11, borderRadius: 6, cursor: 'pointer',
                border: '1px solid var(--border)',
                background: groupBy === opt.key ? 'var(--accent)' : 'var(--bg-secondary)',
                color: groupBy === opt.key ? '#fff' : 'var(--text-muted)',
                fontWeight: groupBy === opt.key ? 600 : 400,
              }}>{opt.label}</button>
            ))}
          </div>
        </FilterBar>
        {loading ? <Spinner /> : filtered.length === 0 ? (
          <EmptyState icon={Building2} title={t('inventory.easmNoEntities')} sub={t('inventory.easmNoEntitiesSub')} />
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {Object.entries(grouped).map(([groupKey, entities]) => {
              const groupLabel = groupKey === 'all' ? 'All Entities' : groupKey

              return (
                <div key={groupKey}>
                  <div style={{
                    fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em',
                    color: 'var(--text-muted)', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 8,
                  }}>
                    <span>{groupLabel}</span>
                    <span style={{
                      fontSize: 10, background: 'var(--bg-muted)', padding: '2px 8px', borderRadius: 10,
                      fontWeight: 600, letterSpacing: 0,
                    }}>{entities.length}</span>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                    {/* Header */}
                    <div style={{
                      padding: '6px 16px', display: 'grid', gridTemplateColumns: '1fr 140px 140px 90px',
                      gap: 12, fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em',
                      color: 'var(--text-muted)',
                    }}>
                      <div style={{ paddingLeft: 13 }}>Entity</div>
                      <div>Jurisdiction</div>
                      <div>Country</div>
                      <div>Status</div>
                    </div>
                    {entities.map((entity, i) => {
                      const statusColor = STATUS_COLORS[entity.status] || '#64748b'
                      return (
                        <div key={entity.lei || i} style={{
                          padding: '10px 16px', background: 'var(--bg-secondary)',
                          borderRadius: i === 0 ? '8px 8px 0 0' : i === entities.length - 1 ? '0 0 8px 8px' : 0,
                          border: '1px solid var(--border)', borderTop: i > 0 ? 'none' : undefined,
                          display: 'grid', gridTemplateColumns: '1fr 140px 140px 90px', alignItems: 'center', gap: 12,
                        }}>
                          {/* Name + domains */}
                          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                            <div style={{
                              width: 3, height: 28, borderRadius: 2, background: statusColor, flexShrink: 0,
                            }} />
                            <div>
                              <div style={{ fontWeight: 600, fontSize: 13 }}>{entity.legal_name}</div>
                              {entity.associated_domains?.length > 0 && (
                                <div style={{ display: 'flex', gap: 4, marginTop: 2 }}>
                                  {entity.associated_domains.map((d, j) => (
                                    <code key={j} style={{ fontSize: 10, background: 'var(--bg-muted)', padding: '1px 5px', borderRadius: 3 }}>{d}</code>
                                  ))}
                                </div>
                              )}
                            </div>
                          </div>
                          {/* Jurisdiction */}
                          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                            {entity.jurisdiction || '—'}
                          </div>
                          {/* Country */}
                          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                            {entity.country || '—'}
                          </div>
                          {/* Status */}
                          <Pill label={entity.status || 'UNKNOWN'} color={statusColor} />
                        </div>
                      )
                    })}
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </Card>
    </>
  )
}


export default function InventoryExplorer() {
  const { t } = useTranslation()
  const { activeScanId } = useScan()
  const [searchParams, setSearchParams] = useSearchParams()
  const tabParam = searchParams.get('tab')
  const activeTab = ALL_TABS.includes(tabParam) ? tabParam : 'surface'
  const setActiveTab = (key) => setSearchParams(prev => { prev.set('tab', key); return prev })
  const assetId = searchParams.get('asset_id')
  const assetName = searchParams.get('asset_name')
  const tabGroups = useMemo(() => getTabGroups(t), [t])

  const TAB_EXPORT_MAP = {
    users: 'inventory/users', groups: 'inventory/groups', computers: 'inventory/computers',
    databases: 'inventory/databases',
    services: 'inventory/services', shares: 'inventory/shares', software: 'inventory/software',
    security: 'inventory/security-controls', netconns: 'inventory/netconns',
    tasks: 'inventory/scheduled-tasks', patches: 'inventory/patches',
    policy: 'inventory/password-policies', loggedon: 'inventory/logged-on',
    envvars: 'inventory/env-vars', certs: 'inventory/certificates',
    aitools: 'inventory/ai-tools', processes: 'inventory/processes',
    credentials: 'inventory/credentials',
  }

  const TAB_COMPONENTS = {
    surface:   <AttackSurfaceTab     scanId={activeScanId} onTabChange={setActiveTab} />,
    users:     <UsersTab             scanId={activeScanId} assetId={assetId} />,
    groups:    <GroupsTab            scanId={activeScanId} assetId={assetId} />,
    computers: <ComputersTab         scanId={activeScanId} assetId={assetId} />,
    databases: <DatabasesTab         scanId={activeScanId} assetId={assetId} />,
    services:  <ServicesTab          scanId={activeScanId} assetId={assetId} />,
    shares:    <SharesTab            scanId={activeScanId} assetId={assetId} />,
    software:  <SoftwareTab          scanId={activeScanId} assetId={assetId} />,
    security:  <SecurityControlsTab  scanId={activeScanId} assetId={assetId} />,
    netconns:  <NetconnsTab          scanId={activeScanId} assetId={assetId} />,
    tasks:     <TasksTab             scanId={activeScanId} assetId={assetId} />,
    patches:   <PatchesTab           scanId={activeScanId} assetId={assetId} />,
    policy:    <PasswordPolicyTab    scanId={activeScanId} assetId={assetId} />,
    loggedon:  <LoggedOnTab          scanId={activeScanId} assetId={assetId} />,
    envvars:   <EnvVarsTab           scanId={activeScanId} assetId={assetId} />,
    certs:     <CertificatesTab      scanId={activeScanId} assetId={assetId} />,
    aitools:   <AIToolsTab           scanId={activeScanId} assetId={assetId} />,
    processes: <ProcessesTab         scanId={activeScanId} assetId={assetId} />,
    credentials: <CredentialsTab    scanId={activeScanId} assetId={assetId} />,
    easm_assets:    <EasmAssetsTab />,
    easm_breaches:  <EasmBreachesTab />,
    easm_corporate: <EasmCorporateTab />,
  }

  return (
    <div>
      <PageHeader
        title={t('inventory.title')}
        subtitle="Structured entities extracted from scan data — users, groups, computers, shares, software, security controls, and more."
        action={TAB_EXPORT_MAP[activeTab] ? (
          <Button variant="ghost" size="sm" onClick={() => exportDownload(TAB_EXPORT_MAP[activeTab], { scan_id: activeScanId })}>
            <Download size={14} /> {t('inventory.exportCsv')}
          </Button>
        ) : null}
      />

      {assetId && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12,
          padding: '8px 14px', background: '#1e3a5f', border: '1px solid #2563eb44',
          borderRadius: 8, fontSize: 13, color: '#93c5fd',
        }}>
          <Database size={14} style={{ color: '#60a5fa', flexShrink: 0 }} />
          <span>Filtered to: <strong style={{ color: '#fff' }}>{assetName || `Asset #${assetId}`}</strong></span>
          <button
            onClick={() => setSearchParams(prev => { const n = new URLSearchParams(prev); n.delete('asset_id'); n.delete('asset_name'); return n })}
            style={{ marginLeft: 'auto', background: 'none', border: 'none', cursor: 'pointer', color: '#93c5fd', fontSize: 12, display: 'flex', alignItems: 'center', gap: 4 }}
          >
            <X size={12} /> Clear filter
          </button>
        </div>
      )}

      {/* Tab bar */}
      <div style={{
        display: 'flex', gap: 2, marginBottom: 20,
        borderBottom: '1px solid var(--border)', paddingBottom: 0,
      }}>
        {tabGroups.map((group) => {
          // Top-level tab (Attack Surface)
          if (group.key) {
            const active = activeTab === group.key
            const Icon = group.icon
            return (
              <button
                key={group.key}
                onClick={() => setActiveTab(group.key)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 6,
                  padding: '9px 12px',
                  background: 'none', border: 'none', cursor: 'pointer',
                  fontSize: 12, fontWeight: active ? 700 : 500,
                  color: active ? 'var(--text-primary)' : 'var(--text-muted)',
                  borderBottom: active ? '2px solid var(--accent)' : '2px solid transparent',
                  marginBottom: -1,
                  whiteSpace: 'nowrap',
                  transition: 'color 0.15s',
                }}
              >
                <Icon size={13} />
                {group.label}
              </button>
            )
          }
          // Dropdown group
          return <TabDropdown key={group.label} group={group} activeTab={activeTab} onSelect={setActiveTab} />
        })}
      </div>

      {/* Tab content — re-mount on tab/scan change so each fetches fresh */}
      <div key={`${activeTab}-${activeScanId}`}>
        {TAB_COMPONENTS[activeTab]}
      </div>
    </div>
  )
}
