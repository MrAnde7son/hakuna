import React, { useState, useEffect, useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Settings as SettingsIcon, Play, Save, RotateCcw, ChevronDown, ChevronRight, ShieldAlert, Upload, Tag, Clock, Plug, ShieldOff } from 'lucide-react'
import { getDedupConfig, saveDedupConfig, runDedup } from '../api.js'
import { Card } from './ui.jsx'
import RiskSettings from './RiskSettings.jsx'
import UploadScan from './UploadScan.jsx'
import TagManager from './TagManager.jsx'
import SLASettings from './SLASettings.jsx'
import IntegrationSettings from './IntegrationSettings.jsx'
import GlobalExceptions from './GlobalExceptions.jsx'

// ─── Helpers ──────────────────────────────────────────────────────────────────

const KEY_FIELD_OPTIONS = {
  assets: ['ip', 'hostname', 'fqdn', 'netbios_name'],
  findings: ['plugin_id', 'asset_id', 'port', 'protocol'],
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
}

const ENTITY_LABELS = {
  assets: 'Assets',
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

function EntityCard({ entityKey, cfg, onChange }) {
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
      const result = await runDedup(entityKey)
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
            {ENTITY_LABELS[entityKey] || entityKey}
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
  const VALID_TABS = ['upload', 'dedup', 'risk', 'tags', 'sla', 'exceptions', 'integrations']
  const tabParam = searchParams.get('tab')
  const activeTab = VALID_TABS.includes(tabParam) ? tabParam : 'upload'
  const setActiveTab = (id) => setSearchParams(prev => { prev.set('tab', id); return prev })
  const [cfg, setCfg] = useState(null)
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    getDedupConfig().then(setCfg).catch(e => setError(e.message))
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
      await saveDedupConfig(cfg)
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

  if (!cfg) {
    return (
      <div style={{ padding: 32, color: 'var(--text-muted)', fontSize: 14 }}>
        {error ? `Error: ${error}` : 'Loading…'}
      </div>
    )
  }

  const TABS = [
    { id: 'upload', label: 'Scans',    icon: <Upload size={14} /> },
    { id: 'tags',   label: 'Tags',          icon: <Tag size={14} /> },
    { id: 'sla',    label: 'SLA',           icon: <Clock size={14} /> },
    { id: 'exceptions', label: 'Exceptions', icon: <ShieldOff size={14} /> },
    { id: 'risk', label: 'Risk Score', icon: <ShieldAlert size={14} /> },
    { id: 'dedup', label: 'Deduplication', icon: <SettingsIcon size={14} /> },
    { id: 'integrations', label: 'Integrations', icon: <Plug size={14} /> },
  ]

  return (
    <div style={{ padding: 24, maxWidth: 860 }}>
      {/* Page header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20 }}>
        <SettingsIcon size={20} color="var(--accent)" />
        <h1 style={{ fontSize: 20, fontWeight: 600, color: 'var(--text)', margin: 0 }}>Settings</h1>
      </div>

      {/* Tab bar */}
      <div style={{ display: 'flex', gap: 4, borderBottom: '1px solid var(--border)', marginBottom: 24 }}>
        {TABS.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              padding: '8px 16px', fontSize: 13, fontWeight: 500,
              border: 'none', background: 'transparent', cursor: 'pointer',
              color: activeTab === tab.id ? 'var(--accent)' : 'var(--text-muted)',
              borderBottom: `2px solid ${activeTab === tab.id ? 'var(--accent)' : 'transparent'}`,
              marginBottom: -1,
            }}
          >
            {tab.icon} {tab.label}
          </button>
        ))}
      </div>

      {/* Upload tab */}
      {activeTab === 'upload' && <UploadScan />}

      {/* Risk tab */}
      {activeTab === 'risk' && <RiskSettings />}

      {/* Tags tab */}
      {activeTab === 'tags' && <TagManager />}

      {/* SLA tab */}
      {activeTab === 'sla' && <SLASettings />}

      {/* Exceptions tab */}
      {activeTab === 'exceptions' && <GlobalExceptions />}

      {/* Integrations tab */}
      {activeTab === 'integrations' && <IntegrationSettings />}

      {/* Dedup tab */}
      {activeTab === 'dedup' && <>

      {/* Dedup Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <SettingsIcon size={16} color="var(--accent)" />
          <span style={{ fontSize: 15, fontWeight: 600, color: 'var(--text)' }}>Deduplication</span>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            onClick={handleReset}
            style={{
              display: 'flex', alignItems: 'center', gap: 6, padding: '7px 14px',
              borderRadius: 6, fontSize: 13, cursor: 'pointer',
              border: '1px solid var(--border)', background: 'transparent', color: 'var(--text-muted)',
            }}
          >
            <RotateCcw size={13} /> Reset
          </button>
          <button
            onClick={handleSave}
            disabled={saving}
            style={{
              display: 'flex', alignItems: 'center', gap: 6, padding: '7px 16px',
              borderRadius: 6, fontSize: 13, cursor: saving ? 'not-allowed' : 'pointer',
              border: '1px solid var(--accent)', background: 'var(--accent)', color: '#fff',
              opacity: saving ? 0.7 : 1,
            }}
          >
            <Save size={13} />
            {saving ? 'Saving…' : saved ? 'Saved!' : 'Save Config'}
          </button>
        </div>
      </div>

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

      {/* Assets & Findings */}
      <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)', marginBottom: 10 }}>
        Assets &amp; Findings
      </div>
      <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 14 }}>
        Cross-scan dedup can merge the same host seen in multiple uploads into a single asset record.
        Findings dedup is disabled by default (same vulnerability can legitimately recur across scans).
      </div>
      {['assets', 'findings'].map(key => {
        const entityCfg = cfg[key]
        if (!entityCfg) return null
        return (
          <EntityCard
            key={key}
            entityKey={key}
            cfg={entityCfg}
            onChange={(next) => setCfg(p => ({ ...p, [key]: next }))}
          />
        )
      })}

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
  )
}
