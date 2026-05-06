import React, { useState, useEffect, useCallback, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Settings as SettingsIcon, Play, Save, RotateCcw, ChevronDown, ChevronRight, ShieldAlert, Upload, Tag, Clock, Plug, Blocks, ShieldOff, ClipboardList, UserCheck, Users, ShieldCheck, Building2, KeyRound, Plus, X, GripVertical, Layers, Antenna } from 'lucide-react'
import { getDedupConfig, saveDedupConfig, deleteDedupOrgOverride, runDedup, exportConfig, getAvailableSources, runRollup } from '../../api.js'
import { Card, ExportImportButtons } from '../shared/ui.jsx'
import { useAuth } from '../../contexts/AuthContext.jsx'
import RiskSettings from './RiskSettings.jsx'
import ScanManagement from '../scans/ScanManagement.jsx'
import AuthProfileManager from '../scans/AuthProfileManager.jsx'
import TagManager from './TagManager.jsx'
import CustomFieldManager from './CustomFieldManager.jsx'
import SLASettings from './SLASettings.jsx'
import IntegrationSettings from './IntegrationSettings.jsx'
import GlobalExceptions from './GlobalExceptions.jsx'
import AuditLog from './AuditLog.jsx'
import OwnershipRules from './OwnershipRules.jsx'
import RoleManager from './RoleManager.jsx'
import UsersPanel from './UsersPanel.jsx'
import OrgsPanel from './OrgsPanel.jsx'
import IntegrationBuilderTab from './IntegrationBuilderTab.jsx'
import SSOSettings from './SSOSettings.jsx'
import RelayAgentManager from '../integrations/relay/RelayAgentManager.jsx'
import ApiTokensPanel from './ApiTokensPanel.jsx'

// ─── Helpers ──────────────────────────────────────────────────────────────────

const KEY_FIELD_OPTIONS = {
  'assets.host': ['ip', 'hostname', 'fqdn', 'netbios_name'],
  'assets.web_app': ['url', 'domain'],
  'assets.cloud_instance': ['cloud_provider', 'instance_id', 'account_id', 'region'],
  'assets.api_endpoint': ['method', 'url'],
  'assets.identity': ['provider', 'principal_id', 'tenant_id'],
  'assets.container_image': ['registry', 'repository', 'tag', 'digest'],
  'assets.code_repo': ['provider', 'org', 'repo'],
  'assets.k8s_workload': ['cluster', 'namespace', 'kind', 'name'],
  findings: ['plugin_id', 'asset_id', 'port', 'protocol', 'cve'],
  users: ['username', 'domain', 'sid'],
  groups: ['group_name', 'domain', 'sid'],
  computers: ['computer_name', 'sid', 'dns_hostname'],
  services: ['service_name', 'asset_id'],
  software: ['name', 'version', 'asset_id'],
  shares: ['share_name', 'asset_id'],
  netconns: ['local_addr', 'local_port', 'remote_addr', 'remote_port', 'asset_id'],
  patches: ['kb_id', 'asset_id'],
  security_controls: ['control_type', 'asset_id'],
  password_policies: ['domain'],
  logged_on: ['username', 'domain', 'asset_id'],
  scheduled_tasks: ['task_uri', 'asset_id'],
  env_vars: ['name', 'asset_id'],
  processes: ['process_name', 'pid', 'asset_id'],
  certificates: ['subject_cn', 'serial_number', 'asset_id'],
}

const ENTITY_LABELS = {
  'assets.host': 'Host',
  'assets.web_app': 'Web App',
  'assets.cloud_instance': 'Cloud Instance',
  'assets.api_endpoint': 'API Endpoint',
  'assets.identity': 'Identity',
  'assets.container_image': 'Container Image',
  'assets.code_repo': 'Code Repo',
  'assets.k8s_workload': 'K8s Workload',
  findings: 'Findings',
  users: 'Users',
  groups: 'Groups',
  computers: 'Computers',
  services: 'Services',
  software: 'Software',
  shares: 'Shares',
  netconns: 'Network Connections',
  patches: 'Missing Patches',
  security_controls: 'Security Controls',
  password_policies: 'Password Policies',
  logged_on: 'Logged-On Users',
  scheduled_tasks: 'Scheduled Tasks',
  env_vars: 'Environment Variables',
  processes: 'Processes',
  certificates: 'Certificates',
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function Toggle({ checked, onChange, label }) {
  return (
    <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', userSelect: 'none' }}>
      <div
        onClick={() => onChange(!checked)}
        style={{
          width: 36, height: 20, borderRadius: 10, position: 'relative',
          background: checked ? 'var(--accent)' : 'var(--border)',
          transition: 'background 0.2s', cursor: 'pointer', flexShrink: 0,
        }}
      >
        <div style={{
          position: 'absolute', top: 2, left: checked ? 18 : 2,
          width: 16, height: 16, borderRadius: '50%', background: '#fff',
          transition: 'left 0.2s',
        }} />
      </div>
      {label && <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>{label}</span>}
    </label>
  )
}

// ─── Source Priority Editor ──────────────────────────────────────────────────

const PRIORITY_FIELD_OPTIONS = [
  'hostname', 'fqdn', 'ip', 'os', 'netbios_name', 'mac_address',
  'device_type', 'system_type', 'is_internet_facing', 'criticality',
  'environment_tag', 'asset_type',
]

function SourcePriorityEditor({ sourcePriority, availableSources, onChange }) {
  const sp = sourcePriority || { '*': [] }
  const defaultList = sp['*'] || []
  const overrides = Object.entries(sp).filter(([k]) => k !== '*')

  const moveSource = (field, fromIdx, toIdx) => {
    const list = [...(sp[field] || [])]
    const [item] = list.splice(fromIdx, 1)
    list.splice(toIdx, 0, item)
    onChange({ ...sp, [field]: list })
  }

  const addSource = (field, source) => {
    const list = [...(sp[field] || [])]
    if (!list.includes(source)) {
      onChange({ ...sp, [field]: [...list, source] })
    }
  }

  const removeSource = (field, source) => {
    onChange({ ...sp, [field]: (sp[field] || []).filter(s => s !== source) })
  }

  const addOverride = (field) => {
    if (!sp[field]) {
      onChange({ ...sp, [field]: [...defaultList] })
    }
  }

  const removeOverride = (field) => {
    const next = { ...sp }
    delete next[field]
    onChange(next)
  }

  const unusedSources = (field) => availableSources.filter(s => !(sp[field] || []).includes(s))

  const renderSortableList = (field) => {
    const list = sp[field] || []
    return (
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, alignItems: 'center', minHeight: 28 }}>
        {list.map((source, idx) => (
          <span
            key={source}
            style={{
              display: 'inline-flex', alignItems: 'center', gap: 3,
              fontSize: 12, padding: '3px 8px', borderRadius: 6,
              background: 'rgba(99,102,241,0.12)', border: '1px solid rgba(99,102,241,0.25)',
              color: 'var(--accent)', fontWeight: 500, cursor: 'grab',
            }}
          >
            <span style={{ fontSize: 10, color: 'var(--text-muted)', marginRight: 2, fontWeight: 700 }}>{idx + 1}</span>
            {idx > 0 && (
              <button
                onClick={() => moveSource(field, idx, idx - 1)}
                style={{ background: 'none', border: 'none', padding: 0, cursor: 'pointer', color: 'var(--text-muted)', fontSize: 10, lineHeight: 1 }}
                title="Move up"
              >{'<'}</button>
            )}
            {source}
            {idx < list.length - 1 && (
              <button
                onClick={() => moveSource(field, idx, idx + 1)}
                style={{ background: 'none', border: 'none', padding: 0, cursor: 'pointer', color: 'var(--text-muted)', fontSize: 10, lineHeight: 1 }}
                title="Move down"
              >{'>'}</button>
            )}
            <button
              onClick={() => removeSource(field, source)}
              style={{ background: 'none', border: 'none', padding: 0, cursor: 'pointer', color: 'var(--text-muted)', lineHeight: 1 }}
            >
              <X size={10} />
            </button>
          </span>
        ))}
        {unusedSources(field).length > 0 && (
          <select
            value=""
            onChange={e => { if (e.target.value) addSource(field, e.target.value) }}
            style={{
              fontSize: 11, padding: '2px 6px', borderRadius: 4,
              border: '1px solid var(--border)', background: 'var(--bg)',
              color: 'var(--text-muted)', cursor: 'pointer',
            }}
          >
            <option value="">+ Add</option>
            {unusedSources(field).map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        )}
      </div>
    )
  }

  const unusedFields = PRIORITY_FIELD_OPTIONS.filter(f => !sp[f])

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
        <Layers size={12} color="var(--text-muted)" />
        <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Source Priority</span>
      </div>
      <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 10 }}>
        When multiple sources report the same field, higher-ranked sources win. Drag to reorder.
      </div>

      {/* Default priority */}
      <div style={{ marginBottom: 10 }}>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4, fontWeight: 600 }}>Default (all fields)</div>
        {renderSortableList('*')}
      </div>

      {/* Per-field overrides */}
      {overrides.length > 0 && (
        <div style={{ marginBottom: 8 }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6, fontWeight: 600 }}>Per-field overrides</div>
          {overrides.map(([field]) => (
            <div key={field} style={{ marginBottom: 8, padding: '6px 10px', background: 'var(--bg)', borderRadius: 6, border: '1px solid var(--border)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
                <span style={{ fontSize: 12, fontWeight: 500, color: 'var(--text)' }}>{field}</span>
                <button
                  onClick={() => removeOverride(field)}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 2 }}
                  title="Remove override"
                >
                  <X size={12} />
                </button>
              </div>
              {renderSortableList(field)}
            </div>
          ))}
        </div>
      )}

      {/* Add override */}
      {unusedFields.length > 0 && (
        <select
          value=""
          onChange={e => { if (e.target.value) addOverride(e.target.value) }}
          style={{
            fontSize: 11, padding: '3px 8px', borderRadius: 4,
            border: '1px solid var(--border)', background: 'var(--bg)',
            color: 'var(--text-muted)', cursor: 'pointer',
          }}
        >
          <option value="">+ Add field override</option>
          {unusedFields.map(f => <option key={f} value={f}>{f}</option>)}
        </select>
      )}
    </div>
  )
}


function EntityCard({ entityKey, label, cfg, onChange, runEntityKey, availableSources }) {
  const [runResult, setRunResult] = useState(null)
  const [running, setRunning] = useState(false)
  const [expanded, setExpanded] = useState(false)
  const availableFields = KEY_FIELD_OPTIONS[entityKey] || []
  const activeFields = cfg.key_fields || []

  const toggleField = (field) => {
    const next = activeFields.includes(field)
      ? activeFields.filter(f => f !== field)
      : [...activeFields, field]
    onChange({ ...cfg, key_fields: next })
  }

  const handleRun = async () => {
    setRunning(true)
    setRunResult(null)
    try {
      const result = await runDedup(runEntityKey || entityKey)
      setRunResult(result)
    } catch (e) {
      setRunResult({ error: e.message })
    } finally {
      setRunning(false)
    }
  }

  return (
    <div style={{
      border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden',
      background: 'var(--bg-card)', marginBottom: 8,
    }}>
      {/* Header */}
      <div
        style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '10px 16px', cursor: 'pointer',
          background: cfg.enabled ? 'transparent' : 'rgba(255,255,255,0.02)',
        }}
        onClick={() => setExpanded(e => !e)}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ color: 'var(--text)', fontWeight: 500, fontSize: 14 }}>
            {label || ENTITY_LABELS[entityKey] || entityKey}
          </span>
          <span style={{
            fontSize: 11, padding: '1px 7px', borderRadius: 10,
            background: cfg.enabled ? 'rgba(99,102,241,0.15)' : 'var(--border)',
            color: cfg.enabled ? 'var(--accent)' : 'var(--text-muted)',
          }}>
            {cfg.enabled ? 'enabled' : 'disabled'}
          </span>
          {cfg.enabled && (
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
              {cfg.strategy}
              {'scope' in cfg && ` · ${cfg.scope === 'cross_scan' ? 'cross-scan' : 'within-scan'}`}
              {activeFields.length > 0 && ` · [${activeFields.join(', ')}]`}
            </span>
          )}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }} onClick={e => e.stopPropagation()}>
          <Toggle
            checked={cfg.enabled}
            onChange={val => onChange({ ...cfg, enabled: val })}
          />
          {expanded ? <ChevronDown size={14} color="var(--text-muted)" /> : <ChevronRight size={14} color="var(--text-muted)" />}
        </div>
      </div>

      {/* Body */}
      {expanded && (
        <div style={{ padding: '12px 16px', borderTop: '1px solid var(--border)', display: 'flex', flexDirection: 'column', gap: 14 }}>
          {/* Key fields */}
          <div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 6 }}>Key Fields (identity)</div>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {availableFields.map(field => (
                <button
                  key={field}
                  onClick={() => toggleField(field)}
                  style={{
                    fontSize: 12, padding: '3px 10px', borderRadius: 6, cursor: 'pointer',
                    border: `1px solid ${activeFields.includes(field) ? 'var(--accent)' : 'var(--border)'}`,
                    background: activeFields.includes(field) ? 'rgba(99,102,241,0.15)' : 'transparent',
                    color: activeFields.includes(field) ? 'var(--accent)' : 'var(--text-muted)',
                    transition: 'all 0.15s',
                  }}
                >
                  {field}
                </button>
              ))}
            </div>
          </div>

          {/* Scope (assets & findings only) */}
          {'scope' in cfg && (
            <div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 6 }}>Dedup Scope</div>
              <div style={{ display: 'flex', gap: 6 }}>
                {['within_scan', 'cross_scan'].map(s => (
                  <button
                    key={s}
                    onClick={() => onChange({ ...cfg, scope: s })}
                    style={{
                      fontSize: 12, padding: '3px 10px', borderRadius: 6, cursor: 'pointer',
                      border: `1px solid ${cfg.scope === s ? '#f59e0b' : 'var(--border)'}`,
                      background: cfg.scope === s ? 'rgba(245,158,11,0.12)' : 'transparent',
                      color: cfg.scope === s ? '#f59e0b' : 'var(--text-muted)',
                    }}
                  >
                    {s === 'within_scan' ? 'Within scan' : 'Cross-scan'}
                  </button>
                ))}
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                {cfg.scope === 'cross_scan'
                  ? 'Merge matching records across all uploaded scans'
                  : 'Only dedup within the same scan upload'}
              </div>
            </div>
          )}

          {/* Strategy */}
          <div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 6 }}>Merge Strategy</div>
            <div style={{ display: 'flex', gap: 6 }}>
              {['keep_first', 'keep_last', 'merge'].map(s => (
                <button
                  key={s}
                  onClick={() => onChange({ ...cfg, strategy: s })}
                  style={{
                    fontSize: 12, padding: '3px 10px', borderRadius: 6, cursor: 'pointer',
                    border: `1px solid ${cfg.strategy === s ? 'var(--accent)' : 'var(--border)'}`,
                    background: cfg.strategy === s ? 'rgba(99,102,241,0.15)' : 'transparent',
                    color: cfg.strategy === s ? 'var(--accent)' : 'var(--text-muted)',
                  }}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>

          {/* Source Priority (only for merge strategy + asset types) */}
          {cfg.strategy === 'merge' && availableSources?.length > 0 && entityKey.startsWith('assets.') && (
            <SourcePriorityEditor
              sourcePriority={cfg.source_priority || { '*': [] }}
              availableSources={availableSources}
              onChange={(sp) => onChange({ ...cfg, source_priority: sp })}
            />
          )}

          {/* Run Now */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <button
              onClick={handleRun}
              disabled={running}
              style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '5px 12px', borderRadius: 6, fontSize: 12, cursor: running ? 'not-allowed' : 'pointer',
                border: '1px solid var(--border)', background: 'var(--bg)',
                color: running ? 'var(--text-muted)' : 'var(--text)',
              }}
            >
              <Play size={11} />
              {running ? 'Running…' : 'Run Dedup Now'}
            </button>
            {runResult && !runResult.error && (
              <span style={{ fontSize: 12, color: '#86efac' }}>
                Removed {runResult.removed ?? 0} duplicate{(runResult.removed ?? 0) !== 1 ? 's' : ''}
              </span>
            )}
            {runResult?.error && (
              <span style={{ fontSize: 12, color: '#fca5a5' }}>{runResult.error}</span>
            )}
            {runResult?.skipped && (
              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Skipped: {runResult.reason}</span>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function Settings() {
  const [searchParams, setSearchParams] = useSearchParams()
  const { isAdmin, isSuperadmin, isMSSP } = useAuth()
  const VALID_TABS = ['upload', 'auth-profiles', 'dedup', 'risk', 'tags', 'custom-fields', 'sla', 'exceptions', 'integrations', 'integration-builder', 'relay-agents', 'audit-log', 'ownership', 'users', 'roles', 'orgs', 'sso', 'api-tokens']
  const tabParam = searchParams.get('tab')
  const activeTab = VALID_TABS.includes(tabParam) ? tabParam : 'upload'
  const setActiveTab = (id) => setSearchParams(prev => { prev.set('tab', id); return prev })
  const [cfg, setCfg] = useState(null)
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)
  const [error, setError] = useState(null)
  const [availableSources, setAvailableSources] = useState([])

  useEffect(() => {
    getDedupConfig().then(setCfg).catch(e => setError(e.message))
    getAvailableSources().then(setAvailableSources).catch(() => {})
  }, [])

  const updateInventoryEntity = useCallback((key, entityCfg) => {
    setCfg(prev => ({
      ...prev,
      inventory: { ...prev.inventory, [key]: entityCfg },
    }))
  }, [])

  const handleSave = async () => {
    setSaving(true)
    setSaved(false)
    try {
      // Strip read-only fields before sending.
      const { is_org_override: _ignored, ...toSave } = cfg
      await saveDedupConfig(toSave)
      // If any asset type has source_priority configured, trigger rollup
      const hasSourcePriority = Object.values(cfg.assets || {}).some(
        tc => tc?.source_priority && Object.values(tc.source_priority).some(v => v?.length > 0)
      )
      if (hasSourcePriority) {
        runRollup().catch(() => {})  // fire-and-forget background job
      }
      // Reload so `is_org_override` flips to true and the banner updates.
      const fresh = await getDedupConfig()
      setCfg(fresh)
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    } catch (e) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  const handleReset = () => {
    getDedupConfig().then(setCfg)
  }

  /**
   * Revert this org's dedup config to the global defaults by removing the
   * per-org override. Kept separate from handleReset (which only discards
   * unsaved UI changes).
   */
  const handleRevertToGlobal = async () => {
    if (!window.confirm(
      'Revert your organization\'s dedup config to the global defaults?\n\n'
      + 'Your customisations will be lost. Other organizations are unaffected.'
    )) return
    setSaving(true)
    setError(null)
    try {
      await deleteDedupOrgOverride()
      const fresh = await getDedupConfig()
      setCfg(fresh)
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    } catch (e) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  if (!cfg) {
    return (
      <div style={{ padding: 32, color: 'var(--text-muted)', fontSize: 14 }}>
        {error ? `Error: ${error}` : 'Loading…'}
      </div>
    )
  }

  const accessControlItems = []
  if (isAdmin) accessControlItems.push({ id: 'users', label: 'Users', icon: <Users size={14} /> })
  if (isAdmin) accessControlItems.push({ id: 'roles', label: 'Roles', icon: <ShieldCheck size={14} /> })
  if (isSuperadmin || isMSSP) accessControlItems.push({ id: 'orgs', label: 'Organizations', icon: <Building2 size={14} /> })
  if (isAdmin) accessControlItems.push({ id: 'sso', label: 'SAML SSO', icon: <KeyRound size={14} /> })

  const NAV_GROUPS = [
    {
      label: 'Data Ingestion',
      items: [
        { id: 'upload',              label: 'Scans',               icon: <Upload size={14} /> },
        { id: 'auth-profiles',       label: 'Credentials',         icon: <KeyRound size={14} /> },
        { id: 'relay-agents',        label: 'Relay Agents',        icon: <Antenna size={14} /> },
        { id: 'integration-builder', label: 'Integration Builder', icon: <Blocks size={14} /> },
      ],
    },
    {
      label: 'Data Quality',
      items: [
        { id: 'dedup',         label: 'Deduplication', icon: <SettingsIcon size={14} /> },
        { id: 'tags',          label: 'Tags',          icon: <Tag size={14} /> },
        { id: 'custom-fields', label: 'Custom Fields', icon: <Layers size={14} /> },
        { id: 'ownership',     label: 'Ownership',     icon: <UserCheck size={14} /> },
      ],
    },
    {
      label: 'Risk & Compliance',
      items: [
        { id: 'risk',       label: 'Risk Score',  icon: <ShieldAlert size={14} /> },
        { id: 'sla',        label: 'SLA',         icon: <Clock size={14} /> },
        { id: 'exceptions', label: 'Exceptions',  icon: <ShieldOff size={14} /> },
      ],
    },
    ...(accessControlItems.length > 0 ? [{
      label: 'Access Control',
      items: accessControlItems,
    }] : []),
    {
      label: 'Platform',
      items: [
        { id: 'integrations', label: 'Integrations', icon: <Plug size={14} /> },
        { id: 'api-tokens',   label: 'API Tokens',   icon: <KeyRound size={14} /> },
        { id: 'audit-log',    label: 'Audit Log',    icon: <ClipboardList size={14} /> },
      ],
    },
  ]

  return (
    <div style={{ display: 'flex', gap: 0, minHeight: '100%' }}>
      {/* Sidebar */}
      <div style={{
        width: 200, flexShrink: 0, borderRight: '1px solid var(--border)',
        padding: '24px 0', display: 'flex', flexDirection: 'column', gap: 24,
      }}>
        <div style={{ padding: '0 16px', display: 'flex', alignItems: 'center', gap: 8 }}>
          <SettingsIcon size={16} color="var(--accent)" />
          <span style={{ fontSize: 15, fontWeight: 600, color: 'var(--text)' }}>Settings</span>
        </div>
        {NAV_GROUPS.map(group => (
          <div key={group.label}>
            <div style={{
              padding: '0 16px', fontSize: 10, fontWeight: 700, letterSpacing: '0.08em',
              textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 4,
            }}>
              {group.label}
            </div>
            {group.items.map(item => (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 8,
                  width: '100%', padding: '7px 16px', fontSize: 13,
                  border: 'none', background: activeTab === item.id ? 'rgba(99,102,241,0.12)' : 'transparent',
                  cursor: 'pointer', textAlign: 'left',
                  color: activeTab === item.id ? 'var(--accent)' : 'var(--text-muted)',
                  borderRight: activeTab === item.id ? '2px solid var(--accent)' : '2px solid transparent',
                  fontWeight: activeTab === item.id ? 500 : 400,
                }}
              >
                {item.icon} {item.label}
              </button>
            ))}
          </div>
        ))}
      </div>

      {/* Content */}
      <div style={{ flex: 1, padding: 24, maxWidth: activeTab === 'users' ? 'none' : ['integration-builder', 'relay-agents', 'upload'].includes(activeTab) ? 1200 : 760 }}>

      {/* Scans tab */}
      {activeTab === 'upload' && <ScanManagement />}

      {/* Auth Profiles tab */}
      {activeTab === 'auth-profiles' && <AuthProfileManager />}

      {/* Risk tab */}
      {activeTab === 'risk' && <RiskSettings />}

      {/* Tags tab */}
      {activeTab === 'tags' && <TagManager />}

      {/* Custom Fields tab */}
      {activeTab === 'custom-fields' && <CustomFieldManager />}

      {/* SLA tab */}
      {activeTab === 'sla' && <SLASettings />}

      {/* Exceptions tab */}
      {activeTab === 'exceptions' && <GlobalExceptions />}

      {/* Integrations tab */}
      {activeTab === 'integrations' && <IntegrationSettings />}

      {/* API Tokens tab */}
      {activeTab === 'api-tokens' && <ApiTokensPanel />}

      {/* Integration Builder tab */}
      {activeTab === 'integration-builder' && <IntegrationBuilderTab />}

      {/* Relay Agents tab */}
      {activeTab === 'relay-agents' && <RelayAgentManager />}

{/* Audit Log tab */}
      {activeTab === 'audit-log' && <AuditLog />}

      {/* Ownership tab */}
      {activeTab === 'ownership' && <OwnershipRules />}

      {/* Users tab */}
      {activeTab === 'users' && isAdmin && <UsersPanel />}

      {/* Roles tab */}
      {activeTab === 'roles' && isAdmin && <RoleManager />}

      {/* Organizations tab */}
      {activeTab === 'orgs' && (isSuperadmin || isMSSP) && <OrgsPanel />}

      {/* SSO tab */}
      {activeTab === 'sso' && isAdmin && <SSOSettings />}

      {/* Dedup tab */}
      {activeTab === 'dedup' && <>

      {/* Dedup Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap', marginBottom: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <SettingsIcon size={16} color="var(--accent)" />
          <span style={{ fontSize: 15, fontWeight: 600, color: 'var(--text)', whiteSpace: 'nowrap' }}>Deduplication</span>
          {cfg.is_org_override ? (
            <span
              title="This organization has customized the dedup rules. Global defaults still apply for any fields left unchanged."
              style={{
                fontSize: 11, fontWeight: 600, padding: '2px 8px', borderRadius: 10,
                background: 'rgba(99,102,241,0.14)', color: 'var(--accent)',
                border: '1px solid rgba(99,102,241,0.3)', whiteSpace: 'nowrap',
              }}
            >
              Org override
            </span>
          ) : (
            <span
              title="This organization is using the global dedup defaults. Saving will create an override."
              style={{
                fontSize: 11, fontWeight: 500, padding: '2px 8px', borderRadius: 10,
                background: 'transparent', color: 'var(--text-muted)',
                border: '1px solid var(--border)', whiteSpace: 'nowrap',
              }}
            >
              Inherited from global
            </span>
          )}
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <ExportImportButtons
            configType="dedup_config"
            exportFn={() => exportConfig('dedup_config')}
            onImported={() => getDedupConfig().then(setCfg)}
            label="Dedup Config"
            showConflict={false}
          />
          {cfg.is_org_override && (
            <button
              onClick={handleRevertToGlobal}
              disabled={saving}
              title="Remove this org's override and use the platform-wide global defaults"
              style={{
                display: 'inline-flex', alignItems: 'center', gap: 6, padding: '7px 14px',
                borderRadius: 6, fontSize: 13, cursor: saving ? 'not-allowed' : 'pointer',
                border: '1px solid var(--border)', background: 'transparent', color: 'var(--text-muted)',
                whiteSpace: 'nowrap',
              }}
            >
              <RotateCcw size={13} /> Revert to global
            </button>
          )}
          <button
            onClick={handleReset}
            style={{
              display: 'inline-flex', alignItems: 'center', gap: 6, padding: '7px 14px',
              borderRadius: 6, fontSize: 13, cursor: 'pointer',
              border: '1px solid var(--border)', background: 'transparent', color: 'var(--text-muted)',
              whiteSpace: 'nowrap',
            }}
          >
            <RotateCcw size={13} /> Discard changes
          </button>
          <button
            onClick={handleSave}
            disabled={saving}
            style={{
              display: 'inline-flex', alignItems: 'center', gap: 6, padding: '7px 16px',
              borderRadius: 6, fontSize: 13, cursor: saving ? 'not-allowed' : 'pointer',
              border: '1px solid var(--accent)', background: 'var(--accent)', color: '#fff',
              opacity: saving ? 0.7 : 1, whiteSpace: 'nowrap',
            }}
          >
            <Save size={13} />
            {saving ? 'Saving…' : saved ? 'Saved!' : 'Save for this org'}
          </button>
        </div>
      </div>

      {!cfg.is_org_override && (
        <div style={{
          marginBottom: 16, padding: '10px 14px',
          background: 'rgba(59,130,246,0.08)', border: '1px solid rgba(59,130,246,0.25)',
          borderRadius: 6, fontSize: 12, color: 'var(--text-muted)',
        }}>
          You are viewing the global dedup defaults. Any changes you save will apply only to this organization as an override — other organizations are unaffected.
        </div>
      )}

      {error && (
        <div style={{ marginBottom: 16, padding: '10px 14px', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: 6, fontSize: 13, color: '#fca5a5' }}>
          {error}
        </div>
      )}

      {/* Global Settings */}
      <Card style={{ marginBottom: 20 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)', marginBottom: 14 }}>Global Settings</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <Toggle
            checked={cfg.enabled}
            onChange={val => setCfg(p => ({ ...p, enabled: val }))}
            label="Enable deduplication"
          />
          <Toggle
            checked={cfg.apply_on_upload}
            onChange={val => setCfg(p => ({ ...p, apply_on_upload: val }))}
            label="Apply automatically on upload"
          />
        </div>
      </Card>

      {/* Asset Types */}
      <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)', marginBottom: 10 }}>
        Asset Types
      </div>
      <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 14 }}>
        Configure deduplication per asset type. Cross-scan dedup can merge the same record seen in multiple uploads into a single asset.
      </div>
      {Object.keys(cfg.assets || {}).map(assetType => {
        const typeCfg = cfg.assets[assetType]
        if (!typeCfg || typeof typeCfg !== 'object') return null
        const entityKey = `assets.${assetType}`
        return (
          <EntityCard
            key={entityKey}
            entityKey={entityKey}
            label={ENTITY_LABELS[entityKey] || assetType.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}
            cfg={typeCfg}
            runEntityKey="assets"
            availableSources={availableSources}
            onChange={(next) => setCfg(p => ({
              ...p,
              assets: { ...p.assets, [assetType]: next },
            }))}
          />
        )
      })}

      {/* Findings */}
      <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)', marginBottom: 10, marginTop: 20 }}>
        Findings
      </div>
      <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 14 }}>
        Findings dedup is disabled by default (same vulnerability can legitimately recur across scans).
      </div>
      {cfg.findings && (
        <EntityCard
          key="findings"
          entityKey="findings"
          cfg={cfg.findings}
          onChange={(next) => setCfg(p => ({ ...p, findings: next }))}
        />
      )}

      {/* Inventory Entities */}
      <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)', marginBottom: 10, marginTop: 20 }}>
        Inventory Entities
      </div>
      <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 14 }}>
        Click an entity to expand. Toggle key fields to define what makes a record unique.
        Choose a strategy: <b>keep_first</b> keeps the earliest record, <b>keep_last</b> replaces it,
        <b> merge</b> unions lists and ORs booleans.
      </div>

      {Object.entries(cfg.inventory || {}).map(([key, entityCfg]) => (
        <EntityCard
          key={key}
          entityKey={key}
          cfg={entityCfg}
          onChange={(next) => updateInventoryEntity(key, next)}
        />
      ))}

      </>}
      </div>
    </div>
  )
}
