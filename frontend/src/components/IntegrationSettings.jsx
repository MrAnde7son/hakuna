import React, { useState, useEffect } from 'react'
import {
  Check, X, RefreshCw, Play, Eye, EyeOff, Trash2,
  ChevronDown, ChevronRight,
} from 'lucide-react'
import {
  getIntegrations, getIntegration, saveIntegration,
  testIntegration, deleteIntegration,
} from '../api.js'
import { Card, Button, Spinner, Pill } from './ui.jsx'

const PROVIDER_ICONS = {
  jira: { color: '#0052CC', label: 'Jira' },
  servicenow: { color: '#81B5A1', label: 'ServiceNow' },
  email: { color: '#ea580c', label: 'Email (SMTP)' },
  slack: { color: '#4A154B', label: 'Slack' },
  teams: { color: '#6264A7', label: 'Teams' },
}

function IntegrationCard({ integration, onRefresh }) {
  const [expanded, setExpanded] = useState(false)
  const [config, setConfig] = useState({})
  const [enabled, setEnabled] = useState(integration.is_enabled)
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [showPasswords, setShowPasswords] = useState({})

  const prov = PROVIDER_ICONS[integration.provider] || { color: '#64748b', label: integration.provider }

  const handleExpand = async () => {
    if (!expanded) {
      setLoading(true)
      try {
        const detail = await getIntegration(integration.provider)
        setConfig(detail.config || {})
        setEnabled(detail.is_enabled)
      } catch (e) {}
      setLoading(false)
    }
    setExpanded(!expanded)
  }

  const handleSave = async () => {
    setSaving(true)
    try {
      await saveIntegration(integration.provider, { config, is_enabled: enabled })
      onRefresh()
    } catch (e) {
      alert('Save failed: ' + e.message)
    }
    setSaving(false)
  }

  const handleTest = async () => {
    setTesting(true)
    setTestResult(null)
    try {
      const r = await testIntegration(integration.provider)
      setTestResult(r)
      onRefresh()
    } catch (e) {
      setTestResult({ status: 'error', detail: e.message })
    }
    setTesting(false)
  }

  const handleDelete = async () => {
    if (!confirm(`Remove ${prov.label} configuration?`)) return
    await deleteIntegration(integration.provider)
    onRefresh()
  }

  return (
    <Card style={{ padding: 0, marginBottom: 12, overflow: 'hidden' }}>
      {/* Header */}
      <button
        onClick={handleExpand}
        style={{
          width: '100%', display: 'flex', alignItems: 'center', gap: 12,
          padding: '14px 18px', border: 'none', background: 'transparent',
          cursor: 'pointer', textAlign: 'left',
        }}
      >
        <div style={{
          width: 36, height: 36, borderRadius: 8,
          background: `${prov.color}18`, display: 'flex',
          alignItems: 'center', justifyContent: 'center', flexShrink: 0,
        }}>
          <div style={{
            width: 12, height: 12, borderRadius: '50%',
            background: integration.is_enabled ? '#22c55e' : '#94a3b8',
          }} />
        </div>
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 600, fontSize: 14, color: 'var(--text)' }}>{prov.label}</div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            {integration.is_configured
              ? (integration.is_enabled ? 'Connected' : 'Configured but disabled')
              : 'Not configured'}
          </div>
        </div>
        {integration.last_test_status && (
          <Pill color={integration.last_test_status === 'ok' ? '#22c55e' : '#ef4444'}>
            {integration.last_test_status}
          </Pill>
        )}
        {expanded ? <ChevronDown size={16} color="#94a3b8" /> : <ChevronRight size={16} color="#94a3b8" />}
      </button>

      {/* Expanded config form */}
      {expanded && (
        <div style={{ padding: '0 18px 18px', borderTop: '1px solid var(--border)' }}>
          {loading ? <div style={{ padding: 16 }}><Spinner /></div> : (
            <>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginTop: 16 }}>
                {integration.fields.map(field => (
                  <div key={field.key} style={field.type === 'boolean' ? { display: 'flex', alignItems: 'center', gap: 8 } : {}}>
                    {field.type === 'boolean' ? (
                      <>
                        <button
                          onClick={() => setConfig(c => ({ ...c, [field.key]: !c[field.key] }))}
                          style={{
                            width: 40, height: 22, borderRadius: 11, border: 'none', cursor: 'pointer',
                            background: config[field.key] ? '#22c55e' : '#475569',
                            position: 'relative', transition: 'background 0.2s',
                          }}
                        >
                          <div style={{
                            width: 16, height: 16, borderRadius: '50%', background: '#fff',
                            position: 'absolute', top: 3,
                            left: config[field.key] ? 20 : 4, transition: 'left 0.2s',
                          }} />
                        </button>
                        <label style={{ fontSize: 12, fontWeight: 500 }}>{field.label}</label>
                      </>
                    ) : (
                      <>
                        <label style={labelStyle}>{field.label}</label>
                        <div style={{ position: 'relative' }}>
                          <input
                            type={field.type === 'password' && !showPasswords[field.key] ? 'password' : 'text'}
                            value={config[field.key] || ''}
                            onChange={e => setConfig(c => ({ ...c, [field.key]: field.type === 'number' ? Number(e.target.value) : e.target.value }))}
                            placeholder={field.placeholder || ''}
                            style={inputStyle}
                          />
                          {field.type === 'password' && (
                            <button
                              onClick={() => setShowPasswords(p => ({ ...p, [field.key]: !p[field.key] }))}
                              style={{ position: 'absolute', right: 8, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#94a3b8' }}
                            >
                              {showPasswords[field.key] ? <EyeOff size={13} /> : <Eye size={13} />}
                            </button>
                          )}
                        </div>
                      </>
                    )}
                  </div>
                ))}
              </div>

              {/* Enable toggle */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 14 }}>
                <button
                  onClick={() => setEnabled(!enabled)}
                  style={{
                    width: 40, height: 22, borderRadius: 11, border: 'none', cursor: 'pointer',
                    background: enabled ? '#22c55e' : '#475569',
                    position: 'relative', transition: 'background 0.2s',
                  }}
                >
                  <div style={{
                    width: 16, height: 16, borderRadius: '50%', background: '#fff',
                    position: 'absolute', top: 3,
                    left: enabled ? 20 : 4, transition: 'left 0.2s',
                  }} />
                </button>
                <span style={{ fontSize: 12, color: enabled ? '#22c55e' : '#94a3b8', fontWeight: 500 }}>
                  {enabled ? 'Enabled' : 'Disabled'}
                </span>
              </div>

              {/* Actions */}
              <div style={{ display: 'flex', gap: 8, marginTop: 14, alignItems: 'center' }}>
                <Button onClick={handleSave} disabled={saving}>
                  {saving ? <RefreshCw size={13} /> : <Check size={13} />}
                  {saving ? 'Saving...' : 'Save'}
                </Button>
                <Button variant="ghost" onClick={handleTest} disabled={testing}>
                  {testing ? <RefreshCw size={13} /> : <Play size={13} />}
                  Test Connection
                </Button>
                {integration.is_configured && (
                  <button onClick={handleDelete}
                    style={{ marginLeft: 'auto', padding: '5px 8px', borderRadius: 6, border: '1px solid var(--border)', background: 'transparent', color: '#94a3b8', cursor: 'pointer', display: 'flex' }}>
                    <Trash2 size={13} />
                  </button>
                )}
                {testResult && (
                  <Pill color={testResult.status === 'ok' ? '#22c55e' : '#ef4444'}>
                    {testResult.status === 'ok'
                      ? `Connected${testResult.user ? ` (${testResult.user})` : testResult.host ? ` (${testResult.host})` : ''}`
                      : `Error: ${testResult.detail || 'Failed'}`}
                  </Pill>
                )}
              </div>
            </>
          )}
        </div>
      )}
    </Card>
  )
}

const labelStyle = { display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--text)', marginBottom: 4 }
const inputStyle = {
  width: '100%', padding: '7px 11px', borderRadius: 7, fontSize: 13,
  border: '1px solid var(--border)', background: '#fff', color: 'var(--text)',
  boxSizing: 'border-box',
}

export default function IntegrationSettings() {
  const [integrations, setIntegrations] = useState([])
  const [loading, setLoading] = useState(true)

  const load = () => {
    getIntegrations()
      .then(setIntegrations)
      .catch(() => {})
      .finally(() => setLoading(false))
  }

  useEffect(load, [])

  if (loading) return <Spinner />

  return (
    <div>
      <div style={{ marginBottom: 16 }}>
        <div style={{ fontWeight: 600, fontSize: 15, marginBottom: 4 }}>Integrations</div>
        <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
          Configure external services for workflow actions — ticketing, notifications, and webhooks
        </div>
      </div>

      {/* Ticketing */}
      <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', color: '#818cf8', marginBottom: 8, letterSpacing: '0.05em' }}>
        Ticketing
      </div>
      {integrations.filter(i => ['jira', 'servicenow'].includes(i.provider)).map(i => (
        <IntegrationCard key={i.provider} integration={i} onRefresh={load} />
      ))}

      {/* Notifications */}
      <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', color: '#818cf8', marginBottom: 8, marginTop: 20, letterSpacing: '0.05em' }}>
        Notifications
      </div>
      {integrations.filter(i => ['email', 'slack', 'teams'].includes(i.provider)).map(i => (
        <IntegrationCard key={i.provider} integration={i} onRefresh={load} />
      ))}
    </div>
  )
}
