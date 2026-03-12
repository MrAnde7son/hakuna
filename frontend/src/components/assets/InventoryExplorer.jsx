import React, { useState, useEffect, useCallback, useRef } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
  Users, Shield, Server, Network, Clock,
  LogIn, AlertTriangle, Key, UserCheck,
  Activity, Layers, Share2, Package, Lock, Monitor, FileText, Terminal, Eye, EyeOff, BrainCircuit,
  ChevronDown, Download, Database, X
} from 'lucide-react'
import {
  Card, StatCard, Table, FilterBar, Select, Input,
  PageHeader, Spinner, EmptyState, Pill, Button
} from '../shared/ui.jsx'
import {
  getInventorySummary, getInventoryUsers, getInventoryGroups,
  getInventoryServices, getInventoryNetconns, getInventoryTasks,
  getInventoryPatches, getInventoryLoggedOn,
  getInventoryShares, getInventorySoftware, getInventorySecurityControls,
  getInventoryComputers, getInventoryPasswordPolicies, getInventoryEnvVars,
  getInventoryCertificates, getInventoryAITools, getInventoryProcesses,
  getInventoryDatabases,
  getSecurityCoverage,
  exportDownload,
} from '../../api.js'
import { useScan } from '../../App.jsx'

// ─── Tab config ───────────────────────────────────────────
const TAB_GROUPS = [
  { key: 'surface', label: 'Attack Surface', icon: AlertTriangle },
  { label: 'Identity', icon: Users, children: [
    { key: 'users',     label: 'Users',     icon: Users },
    { key: 'groups',    label: 'Groups',    icon: Shield },
    { key: 'loggedon',  label: 'Logged On', icon: LogIn },
  ]},
  { label: 'Infrastructure', icon: Server, children: [
    { key: 'computers', label: 'Computers', icon: Monitor },
    { key: 'databases', label: 'Databases', icon: Database },
    { key: 'services',  label: 'Services',  icon: Server },
    { key: 'software',  label: 'Software',  icon: Package },
    { key: 'processes', label: 'Processes',  icon: Activity },
  ]},
  { label: 'Network', icon: Network, children: [
    { key: 'netconns',  label: 'Connections', icon: Network },
    { key: 'shares',    label: 'Shares',      icon: Share2 },
  ]},
  { label: 'Security', icon: Lock, children: [
    { key: 'security',  label: 'Controls',        icon: Lock },
    { key: 'patches',   label: 'Patches',         icon: Layers },
    { key: 'policy',    label: 'Password Policy',  icon: FileText },
    { key: 'certs',     label: 'Certificates',     icon: Lock },
  ]},
  { label: 'Configuration', icon: Terminal, children: [
    { key: 'tasks',    label: 'Sched. Tasks',   icon: Clock },
    { key: 'envvars',  label: 'Env Variables',  icon: Terminal },
    { key: 'aitools',  label: 'AI Tools',       icon: BrainCircuit },
  ]},
]

// Flat list of all valid tab keys (for URL validation)
const ALL_TABS = TAB_GROUPS.flatMap(g => g.children ? g.children.map(c => c.key) : [g.key])

// Find which group a tab key belongs to
function groupForTab(tabKey) {
  for (const g of TAB_GROUPS) {
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
function GroupedTable({ rows, columns, emptyMessage, groupByKey = 'asset_id', groupLabelKey = 'asset_label', groupEnvKey = 'asset_env', groupIpKey = 'asset_ip', onSort, sortBy, sortOrder }) {
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
              <Table columns={columns} rows={g.rows} emptyMessage={emptyMessage} onSort={onSort} sortBy={sortBy} sortOrder={sortOrder} />
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
  domain_user:      '#0ea5e9',
  local_user:       '#8b5cf6',
  computer_account: '#64748b',
  service_account:  '#f59e0b',
}
const USER_TYPE_LABELS = {
  domain_user:      'Domain User',
  local_user:       'Local User',
  computer_account: 'Computer',
  service_account:  'Service Account',
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
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    getInventorySummary(scanId)
      .then(setData)
      .catch(() => setData(null))
      .finally(() => setLoading(false))
  }, [scanId])

  if (loading) return <Spinner />
  if (!data) return <EmptyState icon={AlertTriangle} title="No inventory data" sub="Upload a scan first — inventory is extracted automatically." />

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
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(8, 1fr)', gap: 10, marginTop: 8 }}>
          <StatCard label="Missing Patches"value={counts.missing_patches} icon={Layers}   color="#dc2626" onClick={() => onTabChange('patches')} />
          <StatCard label="Security Ctrl"  value={counts.security_controls} icon={Lock}   color="#10b981" onClick={() => onTabChange('security')} />
          <StatCard label="Certificates"   value={counts.certificates}   icon={FileText}  color="#8b5cf6" onClick={() => onTabChange('certs')} />
          <StatCard label="Pwd Policy"     value={counts.password_policies} icon={Lock}   color="#dc2626" onClick={() => onTabChange('policy')} />
          <StatCard label="Logged On"      value={counts.logged_on}      icon={LogIn}     color="#0ea5e9" onClick={() => onTabChange('loggedon')} />
          <StatCard label="Processes"      value={counts.processes}       icon={Activity}  color="#64748b" onClick={() => onTabChange('processes')} />
          <StatCard label="Env Variables"  value={counts.env_vars}        icon={Terminal}  color="#f59e0b" onClick={() => onTabChange('envvars')} />
          <StatCard label="AI Tools"       value={counts.ai_tools}        icon={BrainCircuit} color="#8b5cf6" onClick={() => onTabChange('aitools')} />
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

// ─── Users tab ─────────────────────────────────────────────
function UsersTab({ scanId, assetId }) {
  const [rows, setRows]               = useState([])
  const [loading, setLoading]         = useState(true)
  const [search, setSearch]           = useState('')
  const [userType, setUserType]       = useState(null)
  const [isAdmin, setIsAdmin]         = useState(null)
  const [isDA, setIsDA]               = useState(null)
  const [groupByAsset, setGroupByAsset] = useState(false)
  const [sortBy, setSortBy]           = useState('username')
  const [sortOrder, setSortOrder]     = useState('asc')

  const handleSort = (key) => {
    if (sortBy === key) { setSortOrder(o => o === 'asc' ? 'desc' : 'asc') }
    else { setSortBy(key); setSortOrder('asc') }
  }

  const load = useCallback(() => {
    setLoading(true)
    getInventoryUsers({
      scan_id: scanId,
      asset_id: assetId || null,
      search: search || null,
      user_type: userType,
      is_admin: isAdmin,
      is_domain_admin: isDA,
      sort_by: sortBy,
      order: sortOrder,
    }).then(setRows).catch(() => setRows([])).finally(() => setLoading(false))
  }, [scanId, assetId, search, userType, isAdmin, isDA, sortBy, sortOrder])

  useEffect(() => { load() }, [load])

  const columns = [
    { key: 'username',  label: 'Username', width: '18%', sortable: true,
      render: (v, r) => (
        <span style={{ fontWeight: 600 }}>
          {r.domain ? `${r.domain}\\` : ''}{v}
        </span>
      )
    },
    { key: 'user_type', label: 'Type',    width: '14%', sortable: true, render: v => <UserTypePill type={v} /> },
    { key: 'is_local_admin',   label: 'Local Admin',   width: '10%', sortable: true, render: v => <PrivFlag yes={v} label="Admin" /> },
    { key: 'is_domain_admin',  label: 'Domain Admin',  width: '10%', sortable: true, render: v => <PrivFlag yes={v} label="DA" /> },
    { key: 'spns', label: 'Kerberoastable', width: '12%',
      render: v => v?.length > 0 ? <Pill label={`${v.length} SPN`} color="#f59e0b" /> : <Count n="—" />
    },
    { key: 'password_never_expires', label: 'Pwd Never Expires', width: '14%', sortable: true,
      render: v => v ? <Pill label="Never Expires" color="#dc2626" /> : <Count n="—" />
    },
    { key: 'member_of', label: 'Groups', width: '10%',
      render: v => <Count n={v?.length || 0} />
    },
    { key: 'is_disabled', label: 'Disabled', width: '8%', sortable: true,
      render: v => v ? <Pill label="Disabled" color="#64748b" /> : <Count n="—" />
    },
    { key: 'asset_label', label: 'Asset', width: '14%',
      render: (v, r) => <>{v}<EnvPill env={r.asset_env} /></>
    },
  ]

  const em = "No users found — try clearing filters or upload a credentialed scan."
  return (
    <Card>
      <FilterBar>
        <Input value={search} onChange={setSearch} placeholder="Search username / domain…" style={{ width: 220 }} />
        <Select value={userType} onChange={setUserType} placeholder="All types" options={[
          { value: 'domain_user',      label: 'Domain User' },
          { value: 'local_user',       label: 'Local User' },
          { value: 'computer_account', label: 'Computer Account' },
          { value: 'service_account',  label: 'Service Account' },
        ]} />
        <Select value={isAdmin === null ? '' : String(isAdmin)} onChange={v => setIsAdmin(v === '' ? null : v === 'true')} placeholder="Any admin status" options={[
          { value: 'true',  label: 'Local Admin only' },
          { value: 'false', label: 'Non-admin only' },
        ]} />
        <Select value={isDA === null ? '' : String(isDA)} onChange={v => setIsDA(v === '' ? null : v === 'true')} placeholder="Any DA status" options={[
          { value: 'true', label: 'Domain Admins only' },
        ]} />
        <GroupByToggle value={groupByAsset} onChange={setGroupByAsset} />
      </FilterBar>
      {loading ? <Spinner /> : groupByAsset
        ? <GroupedTable columns={columns} rows={rows} emptyMessage={em} onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
        : <Table columns={columns} rows={rows} emptyMessage={em} onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
      }
      <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-muted)' }}>{rows.length} users</div>
    </Card>
  )
}

// ─── Groups tab ────────────────────────────────────────────
function GroupsTab({ scanId, assetId }) {
  const [rows, setRows]               = useState([])
  const [loading, setLoading]         = useState(true)
  const [privOnly, setPrivOnly]       = useState(false)
  const [groupByAsset, setGroupByAsset] = useState(false)
  const [sortBy, setSortBy]           = useState('group_name')
  const [sortOrder, setSortOrder]     = useState('asc')

  const handleSort = (key) => {
    if (sortBy === key) { setSortOrder(o => o === 'asc' ? 'desc' : 'asc') }
    else { setSortBy(key); setSortOrder('asc') }
  }

  useEffect(() => {
    setLoading(true)
    getInventoryGroups({ scan_id: scanId, asset_id: assetId || null, is_privileged: privOnly || null, sort_by: sortBy, order: sortOrder })
      .then(setRows).catch(() => setRows([])).finally(() => setLoading(false))
  }, [scanId, assetId, privOnly, sortBy, sortOrder])

  const columns = [
    { key: 'group_name', label: 'Group Name', width: '23%', sortable: true, render: (v, r) => (
      <span style={{ fontWeight: 600, color: r.is_privileged ? '#fca5a5' : 'var(--text-primary)' }}>{v}</span>
    )},
    { key: 'domain',      label: 'Domain',     width: '18%', sortable: true },
    { key: 'is_privileged', label: 'Privileged', width: '12%', sortable: true,
      render: v => v ? <Pill label="High-Value" color="#dc2626" /> : <Count n="—" />
    },
    { key: 'members', label: 'Members', width: '10%',
      render: v => <Count n={v?.length || 0} />
    },
    { key: 'description', label: 'Description', width: '25%',
      render: v => <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{v || '—'}</span>
    },
    { key: 'asset_label', label: 'Asset', width: '12%',
      render: (v, r) => <>{v}<EnvPill env={r.asset_env} /></>
    },
  ]

  return (
    <Card>
      <FilterBar>
        <Button variant={privOnly ? 'danger' : 'ghost'} size="sm" onClick={() => setPrivOnly(p => !p)}>
          {privOnly ? '✕ Privileged only' : 'Show privileged only'}
        </Button>
        <GroupByToggle value={groupByAsset} onChange={setGroupByAsset} />
      </FilterBar>
      {loading ? <Spinner /> : groupByAsset
        ? <GroupedTable columns={columns} rows={rows} emptyMessage="No groups found." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
        : <Table columns={columns} rows={rows} emptyMessage="No groups found." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
      }
      <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-muted)' }}>{rows.length} groups</div>
    </Card>
  )
}

// ─── Computers tab ──────────────────────────────────────
function ComputersTab({ scanId, assetId }) {
  const [rows, setRows]               = useState([])
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

  const load = useCallback(() => {
    setLoading(true)
    getInventoryComputers({ scan_id: scanId, asset_id: assetId || null, search: search || null, is_dc: dcOnly || null, sort_by: sortBy, order: sortOrder })
      .then(setRows).catch(() => setRows([])).finally(() => setLoading(false))
  }, [scanId, assetId, search, dcOnly, sortBy, sortOrder])

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
      <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-muted)' }}>{rows.length} computers</div>
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
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [dbType, setDbType] = useState('')
  const [sortBy, setSortBy] = useState('db_type')
  const [sortOrder, setSortOrder] = useState('asc')

  const handleSort = (key) => {
    if (sortBy === key) { setSortOrder(o => o === 'asc' ? 'desc' : 'asc') }
    else { setSortBy(key); setSortOrder('asc') }
  }

  const load = useCallback(() => {
    setLoading(true)
    getInventoryDatabases({ scan_id: scanId, asset_id: assetId || null, search: search || null, db_type: dbType || null, sort_by: sortBy, order: sortOrder })
      .then(setRows).catch(() => setRows([])).finally(() => setLoading(false))
  }, [scanId, assetId, search, dbType, sortBy, sortOrder])

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
      <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-muted)' }}>{rows.length} instance{rows.length !== 1 ? 's' : ''}</div>
    </Card>
  )
}

// ─── Services tab ──────────────────────────────────────────
function ServicesTab({ scanId, assetId }) {
  const [rows, setRows]               = useState([])
  const [loading, setLoading]         = useState(true)
  const [search, setSearch]           = useState('')
  const [groupByAsset, setGroupByAsset] = useState(false)
  const [sortBy, setSortBy]           = useState('display_name')
  const [sortOrder, setSortOrder]     = useState('asc')

  const handleSort = (key) => {
    if (sortBy === key) { setSortOrder(o => o === 'asc' ? 'desc' : 'asc') }
    else { setSortBy(key); setSortOrder('asc') }
  }

  const load = useCallback(() => {
    setLoading(true)
    getInventoryServices({ scan_id: scanId, asset_id: assetId || null, search: search || null, sort_by: sortBy, order: sortOrder })
      .then(setRows).catch(() => setRows([])).finally(() => setLoading(false))
  }, [scanId, assetId, search, sortBy, sortOrder])

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
      <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-muted)' }}>{rows.length} services</div>
    </Card>
  )
}

// ─── Shares tab ────────────────────────────────────────────
function SharesTab({ scanId, assetId }) {
  const [rows, setRows]               = useState([])
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

  const load = useCallback(() => {
    setLoading(true)
    getInventoryShares({ scan_id: scanId, asset_id: assetId || null, search: search || null, is_writeable: writeableOnly || null, sort_by: sortBy, order: sortOrder })
      .then(setRows).catch(() => setRows([])).finally(() => setLoading(false))
  }, [scanId, assetId, search, writeableOnly, sortBy, sortOrder])

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
      <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-muted)' }}>{rows.length} shares</div>
    </Card>
  )
}

// ─── Software tab ───────────────────────────────────────────
function SoftwareTab({ scanId, assetId }) {
  const [rows, setRows]               = useState([])
  const [loading, setLoading]         = useState(true)
  const [search, setSearch]           = useState('')
  const [groupByAsset, setGroupByAsset] = useState(false)
  const [sortBy, setSortBy]           = useState('name')
  const [sortOrder, setSortOrder]     = useState('asc')

  const handleSort = (key) => {
    if (sortBy === key) { setSortOrder(o => o === 'asc' ? 'desc' : 'asc') }
    else { setSortBy(key); setSortOrder('asc') }
  }

  const load = useCallback(() => {
    setLoading(true)
    getInventorySoftware({ scan_id: scanId, asset_id: assetId || null, search: search || null, sort_by: sortBy, order: sortOrder })
      .then(setRows).catch(() => setRows([])).finally(() => setLoading(false))
  }, [scanId, assetId, search, sortBy, sortOrder])

  useEffect(() => { load() }, [load])

  const columns = [
    { key: 'name', label: 'Software Name', width: '35%', sortable: true,
      render: v => <span style={{ fontWeight: 600 }}>{v}</span>
    },
    { key: 'version', label: 'Version', width: '18%', sortable: true,
      render: v => <code style={{ fontSize: 12, color: 'var(--text-muted)' }}>{v || '—'}</code>
    },
    { key: 'vendor', label: 'Vendor', width: '15%', sortable: true,
      render: v => <span style={{ fontSize: 13 }}>{v || '—'}</span>
    },
    { key: 'installed_on', label: 'Installed On', width: '12%', sortable: true,
      render: v => <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{v || '—'}</span>
    },
    { key: 'asset_label', label: 'Asset', width: '20%',
      render: (v, r) => <>{v}<EnvPill env={r.asset_env} /></>
    },
  ]

  return (
    <Card>
      <FilterBar>
        <Input value={search} onChange={setSearch} placeholder="Search software name…" style={{ width: 260 }} />
        <GroupByToggle value={groupByAsset} onChange={setGroupByAsset} />
      </FilterBar>
      {loading ? <Spinner /> : groupByAsset
        ? <GroupedTable columns={columns} rows={rows} emptyMessage="No installed software found." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
        : <Table columns={columns} rows={rows} emptyMessage="No installed software found." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
      }
      <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-muted)' }}>{rows.length} packages</div>
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
  const [loading, setLoading]         = useState(true)
  const [ctrlType, setCtrlType]       = useState(null)
  const [groupByAsset, setGroupByAsset] = useState(false)
  const [sortBy, setSortBy]           = useState('product_name')
  const [sortOrder, setSortOrder]     = useState('asc')

  const handleSort = (key) => {
    if (sortBy === key) { setSortOrder(o => o === 'asc' ? 'desc' : 'asc') }
    else { setSortBy(key); setSortOrder('asc') }
  }

  useEffect(() => {
    if (view !== 'list') return
    setLoading(true)
    getInventorySecurityControls({ scan_id: scanId, asset_id: assetId || null, control_type: ctrlType, sort_by: sortBy, order: sortOrder })
      .then(setRows).catch(() => setRows([])).finally(() => setLoading(false))
  }, [scanId, assetId, ctrlType, sortBy, sortOrder, view])

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
            <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-muted)' }}>{rows.length} controls</div>
          </Card>
        )
      }
    </div>
  )
}

// ─── Network tab ───────────────────────────────────────────
function NetconnsTab({ scanId, assetId }) {
  const [rows, setRows]               = useState([])
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

  const load = useCallback(() => {
    setLoading(true)
    getInventoryNetconns({ scan_id: scanId, asset_id: assetId || null, search: search || null, state: state || null, sort_by: sortBy, order: sortOrder })
      .then(setRows).catch(() => setRows([])).finally(() => setLoading(false))
  }, [scanId, assetId, search, state, sortBy, sortOrder])

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
      <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-muted)' }}>{rows.length} connections</div>
    </Card>
  )
}

// ─── Scheduled Tasks tab ───────────────────────────────────
function TasksTab({ scanId, assetId }) {
  const [rows, setRows]               = useState([])
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

  const load = useCallback(() => {
    setLoading(true)
    getInventoryTasks({ scan_id: scanId, asset_id: assetId || null, search: search || null, trigger_type: triggerType || null, sort_by: sortBy, order: sortOrder })
      .then(setRows).catch(() => setRows([])).finally(() => setLoading(false))
  }, [scanId, assetId, search, triggerType, sortBy, sortOrder])

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
      <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-muted)' }}>{rows.length} tasks</div>
    </Card>
  )
}

// ─── Patches tab ───────────────────────────────────────────
function PatchesTab({ scanId, assetId }) {
  const [rows, setRows]               = useState([])
  const [loading, setLoading]         = useState(true)
  const [groupByAsset, setGroupByAsset] = useState(false)
  const [sortBy, setSortBy]           = useState('vuln_count')
  const [sortOrder, setSortOrder]     = useState('desc')

  const handleSort = (key) => {
    if (sortBy === key) { setSortOrder(o => o === 'asc' ? 'desc' : 'asc') }
    else { setSortBy(key); setSortOrder('desc') }
  }

  useEffect(() => {
    setLoading(true)
    getInventoryPatches({ scan_id: scanId, asset_id: assetId || null, sort_by: sortBy, order: sortOrder })
      .then(setRows).catch(() => setRows([])).finally(() => setLoading(false))
  }, [scanId, assetId, sortBy, sortOrder])

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
      <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-muted)' }}>{rows.length} patches</div>
    </Card>
  )
}

// ─── Password Policy tab ───────────────────────────────────
function PasswordPolicyTab({ scanId, assetId }) {
  const [rows, setRows]               = useState([])
  const [loading, setLoading]         = useState(true)
  const [groupByAsset, setGroupByAsset] = useState(false)
  const [sortBy, setSortBy]           = useState('domain')
  const [sortOrder, setSortOrder]     = useState('asc')

  const handleSort = (key) => {
    if (sortBy === key) { setSortOrder(o => o === 'asc' ? 'desc' : 'asc') }
    else { setSortBy(key); setSortOrder('asc') }
  }

  useEffect(() => {
    setLoading(true)
    getInventoryPasswordPolicies({ scan_id: scanId, asset_id: assetId || null, sort_by: sortBy, order: sortOrder })
      .then(setRows).catch(() => setRows([])).finally(() => setLoading(false))
  }, [scanId, assetId, sortBy, sortOrder])

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
  if (rows.length === 0) return <EmptyState icon={FileText} title="No password policy data" sub="Requires plugin 17651 in the scan." />

  return (
    <Card>
      <FilterBar>
        <GroupByToggle value={groupByAsset} onChange={setGroupByAsset} />
      </FilterBar>
      {groupByAsset
        ? <GroupedTable columns={columns} rows={rows} emptyMessage="No password policies found." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
        : <Table columns={columns} rows={rows} emptyMessage="No password policies found." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
      }
      <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-muted)' }}>{rows.length} policies</div>
    </Card>
  )
}

// ─── Logged On tab ─────────────────────────────────────────
function LoggedOnTab({ scanId, assetId }) {
  const [rows, setRows]               = useState([])
  const [loading, setLoading]         = useState(true)
  const [groupByAsset, setGroupByAsset] = useState(false)
  const [sortBy, setSortBy]           = useState('username')
  const [sortOrder, setSortOrder]     = useState('asc')

  const handleSort = (key) => {
    if (sortBy === key) { setSortOrder(o => o === 'asc' ? 'desc' : 'asc') }
    else { setSortBy(key); setSortOrder('asc') }
  }

  useEffect(() => {
    setLoading(true)
    getInventoryLoggedOn({ scan_id: scanId, asset_id: assetId || null, sort_by: sortBy, order: sortOrder })
      .then(setRows).catch(() => setRows([])).finally(() => setLoading(false))
  }, [scanId, assetId, sortBy, sortOrder])

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
      <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-muted)' }}>{rows.length} sessions</div>
    </Card>
  )
}

// ─── Env Variables tab ─────────────────────────────────────
function EnvVarsTab({ scanId, assetId }) {
  const [rows, setRows]                 = useState([])
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

  useEffect(() => {
    setLoading(true)
    getInventoryEnvVars({ scan_id: scanId, asset_id: assetId || null, scope: scope || null, sensitive_only: sensitiveOnly || null, search: search || null, sort_by: sortBy, order: sortOrder })
      .then(setRows).catch(() => setRows([])).finally(() => setLoading(false))
  }, [scanId, assetId, scope, sensitiveOnly, search, sortBy, sortOrder])

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
      <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-muted)' }}>{rows.length} variables</div>
    </Card>
  )
}


// ─── Certificates tab ──────────────────────────────────────
function CertificatesTab({ scanId, assetId }) {
  const [rows, setRows]               = useState([])
  const [loading, setLoading]         = useState(true)
  const [search, setSearch]           = useState('')
  const [expiredOnly, setExpiredOnly] = useState(false)
  const [selfSignedOnly, setSelfSignedOnly] = useState(false)
  const [groupByAsset, setGroupByAsset] = useState(false)
  const [sortBy, setSortBy]           = useState('not_after')
  const [sortOrder, setSortOrder]     = useState('asc')

  const handleSort = (key) => {
    if (sortBy === key) { setSortOrder(o => o === 'asc' ? 'desc' : 'asc') }
    else { setSortBy(key); setSortOrder('asc') }
  }

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
    }).then(setRows).catch(() => setRows([])).finally(() => setLoading(false))
  }, [scanId, assetId, search, expiredOnly, selfSignedOnly, sortBy, sortOrder])

  const expiredCount    = rows.filter(r => r.is_expired).length
  const expiringSoon    = rows.filter(r => !r.is_expired && r.days_until_expiry != null && r.days_until_expiry <= 30).length
  const selfSignedCount = rows.filter(r => r.is_self_signed).length

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
    { key: 'subject_cn', label: 'Common Name', width: '22%', sortable: true,
      render: (v, r) => (
        <span style={{ fontWeight: 600, color: r.is_expired ? '#fca5a5' : 'inherit' }}>
          {v || '—'}
        </span>
      )
    },
    { key: 'issuer_cn', label: 'Issuer', width: '20%', sortable: true,
      render: (v, r) => (
        <span style={{ fontSize: 12, color: r.is_self_signed ? '#fcd34d' : 'var(--text-muted)' }}>
          {v || '—'}{r.is_self_signed && ' ⚠'}
        </span>
      )
    },
    { key: 'port', label: 'Port', width: '6%', sortable: true,
      render: v => <code style={{ fontSize: 12 }}>{v || '—'}</code>
    },
    { key: 'not_after', label: 'Expires', width: '14%', sortable: true,
      render: (v) => <span style={{ fontSize: 12 }}>{v || '—'}</span>
    },
    { key: 'days_until_expiry', label: 'In', width: '8%', sortable: true,
      render: (_, r) => <ExpiryBadge row={r} />
    },
    { key: 'key_bits', label: 'Key', width: '9%', sortable: true,
      render: (v, r) => <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{r.key_algorithm ? `${r.key_algorithm} ${v || ''}`.trim() : (v || '—')}</span>
    },
    { key: 'asset_label', label: 'Asset', width: '21%',
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
        <GroupByToggle value={groupByAsset} onChange={setGroupByAsset} />
      </FilterBar>
      {(expiredCount > 0 || expiringSoon > 0 || selfSignedCount > 0) && (
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
        </div>
      )}
      {loading ? <Spinner /> : groupByAsset
        ? <GroupedTable columns={columns} rows={rows} emptyMessage="No certificates found." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
        : <Table columns={columns} rows={rows} emptyMessage="No certificates found." onSort={handleSort} sortBy={sortBy} sortOrder={sortOrder} />
      }
      <div style={{ marginTop:8, fontSize:12, color:'var(--text-muted)' }}>{rows.length} certificate{rows.length !== 1 ? 's' : ''}</div>
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

  const load = useCallback(() => {
    setLoading(true)
    getInventoryAITools({
      scan_id: scanId,
      asset_id: assetId || null,
      search: search || null,
      category: category || null,
      sort_by: sortBy,
      order: sortOrder,
    }).then(setRows).catch(() => setRows([])).finally(() => setLoading(false))
  }, [scanId, assetId, search, category, sortBy, sortOrder])

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
      <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-muted)' }}>
        {rows.length} tool{rows.length !== 1 ? 's' : ''} across {categories.length} categor{categories.length !== 1 ? 'ies' : 'y'}
      </div>
    </Card>
  )
}


// ─── Processes Tab ──────────────────────────────────────────
function ProcessesTab({ scanId, assetId }) {
  const [rows, setRows]               = useState([])
  const [loading, setLoading]         = useState(true)
  const [search, setSearch]           = useState('')
  const [groupByAsset, setGroupByAsset] = useState(false)
  const [sortBy, setSortBy]           = useState('process_name')
  const [sortOrder, setSortOrder]     = useState('asc')

  const handleSort = (key) => {
    if (sortBy === key) { setSortOrder(o => o === 'asc' ? 'desc' : 'asc') }
    else { setSortBy(key); setSortOrder('asc') }
  }

  const load = useCallback(() => {
    setLoading(true)
    getInventoryProcesses({ scan_id: scanId, asset_id: assetId || null, search: search || null, sort_by: sortBy, order: sortOrder })
      .then(setRows).catch(() => setRows([])).finally(() => setLoading(false))
  }, [scanId, assetId, search, sortBy, sortOrder])

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
      <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-muted)' }}>{rows.length} processes ({uniqueNames} unique)</div>
    </Card>
  )
}


// ─── Root ──────────────────────────────────────────────────
export default function InventoryExplorer() {
  const { activeScanId } = useScan()
  const [searchParams, setSearchParams] = useSearchParams()
  const tabParam = searchParams.get('tab')
  const activeTab = ALL_TABS.includes(tabParam) ? tabParam : 'surface'
  const setActiveTab = (key) => setSearchParams(prev => { prev.set('tab', key); return prev })
  const assetId = searchParams.get('asset_id')
  const assetName = searchParams.get('asset_name')

  const TAB_EXPORT_MAP = {
    users: 'inventory/users', groups: 'inventory/groups', computers: 'inventory/computers',
    databases: 'inventory/databases',
    services: 'inventory/services', shares: 'inventory/shares', software: 'inventory/software',
    security: 'inventory/security-controls', netconns: 'inventory/netconns',
    tasks: 'inventory/scheduled-tasks', patches: 'inventory/patches',
    policy: 'inventory/password-policies', loggedon: 'inventory/logged-on',
    envvars: 'inventory/env-vars', certs: 'inventory/certificates',
    aitools: 'inventory/ai-tools', processes: 'inventory/processes',
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
  }

  return (
    <div>
      <PageHeader
        title="Inventory"
        subtitle="Structured entities extracted from scan data — users, groups, computers, shares, software, security controls, and more."
        action={TAB_EXPORT_MAP[activeTab] ? (
          <Button variant="ghost" size="sm" onClick={() => exportDownload(TAB_EXPORT_MAP[activeTab], { scan_id: activeScanId })}>
            <Download size={14} /> Export CSV
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
        {TAB_GROUPS.map((group) => {
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
