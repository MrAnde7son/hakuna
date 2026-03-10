import React, { useState, useEffect, useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
  Users, Shield, Server, Network, Clock,
  LogIn, AlertTriangle, Key, UserCheck,
  Activity, Layers, Share2, Package, Lock, Monitor, FileText, Terminal, Eye, EyeOff, BrainCircuit
} from 'lucide-react'
import {
  Card, StatCard, Table, FilterBar, Select, Input,
  PageHeader, Spinner, EmptyState, Pill, Button
} from './ui.jsx'
import {
  getInventorySummary, getInventoryUsers, getInventoryGroups,
  getInventoryServices, getInventoryNetconns, getInventoryTasks,
  getInventoryPatches, getInventoryLoggedOn,
  getInventoryShares, getInventorySoftware, getInventorySecurityControls,
  getInventoryComputers, getInventoryPasswordPolicies, getInventoryEnvVars,
  getInventoryCertificates, getInventoryAITools,
} from '../api.js'
import { useScan } from '../App.jsx'

// ─── Tab config ───────────────────────────────────────────
const TABS = [
  { key: 'surface',   label: 'Attack Surface',  icon: AlertTriangle },
  { key: 'users',     label: 'Users',           icon: Users },
  { key: 'groups',    label: 'Groups',          icon: Shield },
  { key: 'computers', label: 'Computers',    icon: Monitor },
  { key: 'services',  label: 'Services',        icon: Server },
  { key: 'shares',    label: 'Shares',          icon: Share2 },
  { key: 'software',  label: 'Software',        icon: Package },
  { key: 'security',  label: 'Security Controls', icon: Lock },
  { key: 'netconns',  label: 'Network',         icon: Network },
  { key: 'tasks',     label: 'Sched. Tasks',    icon: Clock },
  { key: 'patches',   label: 'Patches',         icon: Layers },
  { key: 'policy',    label: 'Password Policy', icon: FileText },
  { key: 'loggedon',  label: 'Logged On',       icon: LogIn },
  { key: 'envvars',   label: 'Env Variables',   icon: Terminal },
  { key: 'certs',     label: 'Certificates',    icon: Lock },
  { key: 'aitools',   label: 'AI',        icon: BrainCircuit },
]

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
      background: '#450a0a', color: '#fca5a5', border: '1px solid #991b1b',
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

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Inventory counts */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(130px, 1fr))', gap: 12 }}>
        <StatCard label="Users"          value={counts.users}           icon={Users}    color="#0ea5e9" onClick={() => onTabChange('users')} />
        <StatCard label="Groups"         value={counts.groups}          icon={Shield}   color="#8b5cf6" onClick={() => onTabChange('groups')} />
        <StatCard label="Computers"      value={counts.computers}       icon={Monitor}  color="#06b6d4" onClick={() => onTabChange('computers')} />
        <StatCard label="Services"       value={counts.services}        icon={Server}   color="#64748b" onClick={() => onTabChange('services')} />
        <StatCard label="Shares"         value={counts.shares}          icon={Share2}   color="#f59e0b" onClick={() => onTabChange('shares')} />
        <StatCard label="Software"       value={counts.software}        icon={Package}  color="#10b981" onClick={() => onTabChange('software')} />
        <StatCard label="Net Conns"      value={counts.netconns}        icon={Network}  color="#06b6d4" onClick={() => onTabChange('netconns')} />
        <StatCard label="Sched. Tasks"   value={counts.scheduled_tasks} icon={Clock}    color="#f59e0b" onClick={() => onTabChange('tasks')} />
        <StatCard label="Missing Patches"value={counts.missing_patches} icon={Layers}   color="#dc2626" onClick={() => onTabChange('patches')} />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        {/* Domain Admins */}
        <Card onClick={() => onTabChange('users')}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
            <UserCheck size={16} color="#dc2626" />
            <span style={{ fontWeight: 700, fontSize: 14 }}>Domain Admins</span>
            <Count n={as.domain_admins.length} />
          </div>
          {as.domain_admins.length === 0
            ? <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>None detected</div>
            : as.domain_admins.map((u, i) => (
              <div key={i} style={{ padding: '6px 0', borderBottom: '1px solid var(--border)', fontSize: 13 }}>
                <span style={{ fontWeight: 600 }}>{u.domain}\{u.username}</span>
                {u.spns?.length > 0 && <Pill label="Kerberoastable" color="#f59e0b" />}
              </div>
            ))
          }
        </Card>

        {/* Kerberoastable Accounts */}
        <Card onClick={() => onTabChange('users')}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
            <Key size={16} color="#f59e0b" />
            <span style={{ fontWeight: 700, fontSize: 14 }}>Kerberoastable Accounts</span>
            <Count n={as.kerberoastable_accounts.length} />
          </div>
          {as.kerberoastable_accounts.length === 0
            ? <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>None detected</div>
            : as.kerberoastable_accounts.map((u, i) => (
              <div key={i} style={{ padding: '6px 0', borderBottom: '1px solid var(--border)', fontSize: 13 }}>
                <div style={{ fontWeight: 600 }}>{u.domain}\{u.username}</div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                  {u.spns?.slice(0, 2).join(', ')}
                  {u.spns?.length > 2 && ` +${u.spns.length - 2} more`}
                </div>
              </div>
            ))
          }
        </Card>

        {/* Lateral Movement Paths */}
        <Card onClick={() => onTabChange('users')}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
            <Activity size={16} color="#dc2626" />
            <span style={{ fontWeight: 700, fontSize: 14 }}>Lateral Movement Paths</span>
            <Count n={as.lateral_movement_paths.length} />
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 10 }}>
            Accounts that are local admin on multiple hosts
          </div>
          {as.lateral_movement_paths.length === 0
            ? <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>None detected</div>
            : as.lateral_movement_paths.map((p, i) => (
              <div key={i} style={{ padding: '6px 0', borderBottom: '1px solid var(--border)', fontSize: 13 }}>
                <div style={{ fontWeight: 600 }}>{p.account}</div>
                <div style={{ fontSize: 11, color: '#0ea5e9', marginTop: 2 }}>
                  Admin on {p.asset_ids.length} hosts · asset IDs: {p.asset_ids.join(', ')}
                </div>
              </div>
            ))
          }
        </Card>

        {/* Credential & Security Weaknesses */}
        <Card onClick={() => onTabChange('security')}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
            <Shield size={16} color="#f59e0b" />
            <span style={{ fontWeight: 700, fontSize: 14 }}>Security Posture</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13 }}>
              <span>Password never expires</span>
              <span style={{ fontWeight: 700, color: as.password_never_expires_count > 0 ? '#f59e0b' : 'var(--text-muted)' }}>
                {as.password_never_expires_count}
              </span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13 }}>
              <span>Never changed password</span>
              <span style={{ fontWeight: 700, color: as.never_changed_password_count > 0 ? '#dc2626' : 'var(--text-muted)' }}>
                {as.never_changed_password_count}
              </span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13 }}>
              <span>Writeable shares</span>
              <span style={{ fontWeight: 700, color: (as.writeable_shares || 0) > 0 ? '#f59e0b' : 'var(--text-muted)' }}>
                {as.writeable_shares || 0}
              </span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13 }}>
              <span>Hosts with AV enabled</span>
              <span style={{ fontWeight: 700, color: '#10b981' }}>{as.hosts_with_av || 0}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13 }}>
              <span>Weak password policies</span>
              <span style={{ fontWeight: 700, color: (as.weak_password_policies || 0) > 0 ? '#dc2626' : 'var(--text-muted)' }}>
                {as.weak_password_policies || 0}
              </span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13 }}>
              <span>Established connections</span>
              <span style={{ fontWeight: 700, color: '#0ea5e9' }}>{as.established_connections}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13 }}>
              <span>Local admin accounts</span>
              <span style={{ fontWeight: 700 }}>{as.local_admins_count}</span>
            </div>
          </div>
        </Card>
      </div>

      {/* Domain Controllers */}
      {as.domain_controllers?.length > 0 && (
        <Card onClick={() => onTabChange('computers')}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
            <Monitor size={16} color="#dc2626" />
            <span style={{ fontWeight: 700, fontSize: 14 }}>Domain Controllers</span>
            <Count n={as.domain_controllers.length} />
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
            {as.domain_controllers.map((c, i) => (
              <div key={i} style={{
                background: 'var(--bg-muted)', border: '1px solid var(--border)',
                borderRadius: 6, padding: '6px 12px', fontSize: 13,
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
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
            <LogIn size={16} color="#0ea5e9" />
            <span style={{ fontWeight: 700, fontSize: 14 }}>Currently Logged On</span>
            <Count n={as.logged_on_users.length} />
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
            {as.logged_on_users.map((u, i) => (
              <div key={i} style={{
                background: 'var(--bg-muted)', border: '1px solid var(--border)',
                borderRadius: 6, padding: '6px 12px', fontSize: 13,
              }}>
                <span style={{ fontWeight: 600 }}>{u.domain}\{u.username}</span>
                <span style={{ color: 'var(--text-muted)', fontSize: 11 }}> · {u.asset_label}</span>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Top missing patches */}
      {as.top_missing_patches?.length > 0 && (
        <Card onClick={() => onTabChange('patches')}>
          <div style={{ fontWeight: 700, fontSize: 14, marginBottom: 14 }}>Top Missing Patches</div>
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
function UsersTab({ scanId }) {
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
      search: search || null,
      user_type: userType,
      is_admin: isAdmin,
      is_domain_admin: isDA,
      sort_by: sortBy,
      order: sortOrder,
    }).then(setRows).catch(() => setRows([])).finally(() => setLoading(false))
  }, [scanId, search, userType, isAdmin, isDA, sortBy, sortOrder])

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
function GroupsTab({ scanId }) {
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
    getInventoryGroups({ scan_id: scanId, is_privileged: privOnly || null, sort_by: sortBy, order: sortOrder })
      .then(setRows).catch(() => setRows([])).finally(() => setLoading(false))
  }, [scanId, privOnly, sortBy, sortOrder])

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
function ComputersTab({ scanId }) {
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
    getInventoryComputers({ scan_id: scanId, search: search || null, is_dc: dcOnly || null, sort_by: sortBy, order: sortOrder })
      .then(setRows).catch(() => setRows([])).finally(() => setLoading(false))
  }, [scanId, search, dcOnly, sortBy, sortOrder])

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

// ─── Services tab ──────────────────────────────────────────
function ServicesTab({ scanId }) {
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
    getInventoryServices({ scan_id: scanId, search: search || null, sort_by: sortBy, order: sortOrder })
      .then(setRows).catch(() => setRows([])).finally(() => setLoading(false))
  }, [scanId, search, sortBy, sortOrder])

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
function SharesTab({ scanId }) {
  const [rows, setRows]               = useState([])
  const [loading, setLoading]         = useState(true)
  const [writeableOnly, setWriteable] = useState(false)
  const [groupByAsset, setGroupByAsset] = useState(false)
  const [sortBy, setSortBy]           = useState('share_name')
  const [sortOrder, setSortOrder]     = useState('asc')

  const handleSort = (key) => {
    if (sortBy === key) { setSortOrder(o => o === 'asc' ? 'desc' : 'asc') }
    else { setSortBy(key); setSortOrder('asc') }
  }

  useEffect(() => {
    setLoading(true)
    getInventoryShares({ scan_id: scanId, is_writeable: writeableOnly || null, sort_by: sortBy, order: sortOrder })
      .then(setRows).catch(() => setRows([])).finally(() => setLoading(false))
  }, [scanId, writeableOnly, sortBy, sortOrder])

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
function SoftwareTab({ scanId }) {
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
    getInventorySoftware({ scan_id: scanId, search: search || null, sort_by: sortBy, order: sortOrder })
      .then(setRows).catch(() => setRows([])).finally(() => setLoading(false))
  }, [scanId, search, sortBy, sortOrder])

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
function SecurityControlsTab({ scanId }) {
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
    setLoading(true)
    getInventorySecurityControls({ scan_id: scanId, control_type: ctrlType, sort_by: sortBy, order: sortOrder })
      .then(setRows).catch(() => setRows([])).finally(() => setLoading(false))
  }, [scanId, ctrlType, sortBy, sortOrder])

  const CTRL_COLORS = { av: '#10b981', firewall: '#0ea5e9', edr: '#8b5cf6', backup: '#f59e0b' }

  const columns = [
    { key: 'control_type', label: 'Type', width: '9%', sortable: true,
      render: v => <Pill label={v} color={CTRL_COLORS[v] || '#64748b'} />
    },
    { key: 'product_name', label: 'Product', width: '22%', sortable: true,
      render: v => <span style={{ fontWeight: 600 }}>{v || '—'}</span>
    },
    { key: 'version', label: 'Version', width: '14%', sortable: true,
      render: v => <code style={{ fontSize: 12, color: 'var(--text-muted)' }}>{v || '—'}</code>
    },
    { key: 'is_enabled', label: 'Enabled', width: '9%', sortable: true,
      render: v => v ? <Pill label="Enabled" color="#16a34a" /> : <Pill label="Disabled" color="#dc2626" />
    },
    { key: 'is_up_to_date', label: 'Up to Date', width: '10%', sortable: true,
      render: v => v === null ? <Count n="—" /> : v ? <Pill label="Current" color="#16a34a" /> : <Pill label="Outdated" color="#dc2626" />
    },
    { key: 'signature_date', label: 'Signature Date', width: '14%', sortable: true,
      render: v => <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{v || '—'}</span>
    },
    { key: 'asset_label', label: 'Asset', width: '22%',
      render: (v, r) => <>{v}<EnvPill env={r.asset_env} /></>
    },
  ]

  return (
    <Card>
      <FilterBar>
        <Select value={ctrlType} onChange={setCtrlType} placeholder="All types" options={[
          { value: 'av',       label: 'Antivirus' },
          { value: 'firewall', label: 'Firewall' },
          { value: 'edr',      label: 'EDR' },
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

// ─── Network tab ───────────────────────────────────────────
function NetconnsTab({ scanId }) {
  const [rows, setRows]               = useState([])
  const [loading, setLoading]         = useState(true)
  const [state, setState]             = useState(null)
  const [groupByAsset, setGroupByAsset] = useState(false)
  const [sortBy, setSortBy]           = useState('local_port')
  const [sortOrder, setSortOrder]     = useState('asc')

  const handleSort = (key) => {
    if (sortBy === key) { setSortOrder(o => o === 'asc' ? 'desc' : 'asc') }
    else { setSortBy(key); setSortOrder('asc') }
  }

  useEffect(() => {
    setLoading(true)
    getInventoryNetconns({ scan_id: scanId, state: state || null, sort_by: sortBy, order: sortOrder })
      .then(setRows).catch(() => setRows([])).finally(() => setLoading(false))
  }, [scanId, state, sortBy, sortOrder])

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
function TasksTab({ scanId }) {
  const [rows, setRows]               = useState([])
  const [loading, setLoading]         = useState(true)
  const [groupByAsset, setGroupByAsset] = useState(false)
  const [sortBy, setSortBy]           = useState('task_uri')
  const [sortOrder, setSortOrder]     = useState('asc')

  const handleSort = (key) => {
    if (sortBy === key) { setSortOrder(o => o === 'asc' ? 'desc' : 'asc') }
    else { setSortBy(key); setSortOrder('asc') }
  }

  useEffect(() => {
    setLoading(true)
    getInventoryTasks({ scan_id: scanId, sort_by: sortBy, order: sortOrder })
      .then(setRows).catch(() => setRows([])).finally(() => setLoading(false))
  }, [scanId, sortBy, sortOrder])

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
function PatchesTab({ scanId }) {
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
    getInventoryPatches({ scan_id: scanId, sort_by: sortBy, order: sortOrder })
      .then(setRows).catch(() => setRows([])).finally(() => setLoading(false))
  }, [scanId, sortBy, sortOrder])

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
function PasswordPolicyTab({ scanId }) {
  const [rows, setRows]       = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    getInventoryPasswordPolicies({ scan_id: scanId })
      .then(setRows).catch(() => setRows([])).finally(() => setLoading(false))
  }, [scanId])

  function PolicyBool({ val, goodIfTrue = true }) {
    if (val === null || val === undefined) return <Count n="—" />
    const good = goodIfTrue ? val : !val
    return <Pill label={val ? 'Yes' : 'No'} color={good ? '#16a34a' : '#dc2626'} />
  }

  function PolicyNum({ val, warnBelow, warnAbove, unit = '' }) {
    if (val === null || val === undefined) return <Count n="—" />
    const bad = (warnBelow !== undefined && val < warnBelow) || (warnAbove !== undefined && val > warnAbove)
    return <span style={{ fontWeight: 700, color: bad ? '#dc2626' : 'var(--text-primary)' }}>{val}{unit}</span>
  }

  if (loading) return <Spinner />
  if (rows.length === 0) return <EmptyState icon={FileText} title="No password policy data" sub="Requires plugin 17651 in the scan." />

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {rows.map((p, i) => (
        <Card key={i}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 18 }}>
            <FileText size={16} color={p.is_weak ? '#dc2626' : '#16a34a'} />
            <span style={{ fontWeight: 700, fontSize: 15 }}>
              {p.domain || 'Unknown Domain'}
            </span>
            {p.is_weak && <Pill label="WEAK POLICY" color="#dc2626" />}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 12 }}>
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>MIN PASSWORD LENGTH</div>
              <PolicyNum val={p.min_length} warnBelow={8} />
            </div>
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>COMPLEXITY REQUIRED</div>
              <PolicyBool val={p.complexity_enabled} goodIfTrue={true} />
            </div>
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>PASSWORD HISTORY</div>
              <PolicyNum val={p.history_count} warnBelow={5} unit=" remembered" />
            </div>
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>MAX PASSWORD AGE</div>
              <PolicyNum val={p.max_age_days} warnAbove={365} unit=" days" />
            </div>
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>LOCKOUT THRESHOLD</div>
              <span style={{ fontWeight: 700, color: p.lockout_threshold === 0 ? '#dc2626' : 'var(--text-primary)' }}>
                {p.lockout_threshold === 0 ? 'No lockout!' : `${p.lockout_threshold} attempts`}
              </span>
            </div>
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>LOCKOUT DURATION</div>
              <PolicyNum val={p.lockout_duration_mins} unit=" min" />
            </div>
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>REVERSIBLE ENCRYPTION</div>
              <PolicyBool val={p.reversible_encryption} goodIfTrue={false} />
            </div>
          </div>
        </Card>
      ))}
    </div>
  )
}

// ─── Logged On tab ─────────────────────────────────────────
function LoggedOnTab({ scanId }) {
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
    getInventoryLoggedOn({ scan_id: scanId, sort_by: sortBy, order: sortOrder })
      .then(setRows).catch(() => setRows([])).finally(() => setLoading(false))
  }, [scanId, sortBy, sortOrder])

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
function EnvVarsTab({ scanId }) {
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
    getInventoryEnvVars({ scan_id: scanId, scope: scope || null, sensitive_only: sensitiveOnly || null, search: search || null, sort_by: sortBy, order: sortOrder })
      .then(setRows).catch(() => setRows([])).finally(() => setLoading(false))
  }, [scanId, scope, sensitiveOnly, search, sortBy, sortOrder])

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
        ? <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, background: '#450a0a', color: '#fca5a5', border: '1px solid #991b1b', borderRadius: 4, padding: '2px 7px', fontSize: 11, fontWeight: 600 }}>⚠ Secret</span>
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
        <div style={{ marginBottom: 12, padding: '8px 12px', background: '#450a0a', border: '1px solid #991b1b', borderRadius: 6, fontSize: 13, color: '#fca5a5' }}>
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
function CertificatesTab({ scanId }) {
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
      search: search || null,
      expired_only: expiredOnly || null,
      self_signed_only: selfSignedOnly || null,
      sort_by: sortBy,
      order: sortOrder,
    }).then(setRows).catch(() => setRows([])).finally(() => setLoading(false))
  }, [scanId, search, expiredOnly, selfSignedOnly, sortBy, sortOrder])

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

function AIToolsTab({ scanId }) {
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
      search: search || null,
      category: category || null,
      sort_by: sortBy,
      order: sortOrder,
    }).then(setRows).catch(() => setRows([])).finally(() => setLoading(false))
  }, [scanId, search, category, sortBy, sortOrder])

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


// ─── Root ──────────────────────────────────────────────────
export default function InventoryExplorer() {
  const { activeScanId } = useScan()
  const [searchParams, setSearchParams] = useSearchParams()
  const VALID_TABS = TABS.map(t => t.key)
  const tabParam = searchParams.get('tab')
  const activeTab = VALID_TABS.includes(tabParam) ? tabParam : 'surface'
  const setActiveTab = (key) => setSearchParams(prev => { prev.set('tab', key); return prev })

  const TAB_COMPONENTS = {
    surface:   <AttackSurfaceTab     scanId={activeScanId} onTabChange={setActiveTab} />,
    users:     <UsersTab             scanId={activeScanId} />,
    groups:    <GroupsTab            scanId={activeScanId} />,
    computers: <ComputersTab         scanId={activeScanId} />,
    services:  <ServicesTab          scanId={activeScanId} />,
    shares:    <SharesTab            scanId={activeScanId} />,
    software:  <SoftwareTab          scanId={activeScanId} />,
    security:  <SecurityControlsTab  scanId={activeScanId} />,
    netconns:  <NetconnsTab          scanId={activeScanId} />,
    tasks:     <TasksTab             scanId={activeScanId} />,
    patches:   <PatchesTab           scanId={activeScanId} />,
    policy:    <PasswordPolicyTab    scanId={activeScanId} />,
    loggedon:  <LoggedOnTab          scanId={activeScanId} />,
    envvars:   <EnvVarsTab           scanId={activeScanId} />,
    certs:     <CertificatesTab      scanId={activeScanId} />,
    aitools:   <AIToolsTab           scanId={activeScanId} />,
  }

  return (
    <div>
      <PageHeader
        title="Inventory"
        subtitle="Structured entities extracted from scan data — users, groups, computers, shares, software, security controls, and more."
      />

      {/* Tab bar */}
      <div style={{
        display: 'flex', gap: 2, marginBottom: 20,
        borderBottom: '1px solid var(--border)', paddingBottom: 0,
        overflowX: 'auto',
      }}>
        {TABS.map(({ key, label, icon: Icon }) => {
          const active = activeTab === key
          return (
            <button
              key={key}
              onClick={() => setActiveTab(key)}
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
              {label}
            </button>
          )
        })}
      </div>

      {/* Tab content — re-mount on tab/scan change so each fetches fresh */}
      <div key={`${activeTab}-${activeScanId}`}>
        {TAB_COMPONENTS[activeTab]}
      </div>
    </div>
  )
}
