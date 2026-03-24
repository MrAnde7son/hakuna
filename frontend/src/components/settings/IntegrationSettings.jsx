import React, { useState, useEffect } from 'react'
import {
  Check, X, RefreshCw, Play, Eye, EyeOff, Trash2,
  ChevronDown, ChevronRight, Search, Mail,
} from 'lucide-react'
import {
  getIntegrations, getIntegration, saveIntegration,
  testIntegration, deleteIntegration,
} from '../../api.js'
import { Card, Button, Spinner, Pill, useToast, useConfirm } from '../shared/ui.jsx'

// ── SVG Logos ────────────────────────────────────────────────────────

function JiraLogo({ size = 20 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 256 256" fill="none">
      <defs>
        <linearGradient id="jira1" x1="99%" y1="99%" x2="23%" y2="60%">
          <stop offset="18%" stopColor="#0052CC" />
          <stop offset="100%" stopColor="#2684FF" />
        </linearGradient>
        <linearGradient id="jira2" x1="1%" y1="1%" x2="77%" y2="40%">
          <stop offset="18%" stopColor="#0052CC" />
          <stop offset="100%" stopColor="#2684FF" />
        </linearGradient>
      </defs>
      <path d="M244.658 0H121.707c0 55.743 45.178 100.921 100.921 100.921h22.03V123.1C244.658 178.844 289.836 224 345.58 224V22.03A22.03 22.03 0 00323.549 0h-78.891z" transform="scale(.73)" fill="#2684FF"/>
      <path d="M183.822 61.262H60.872c0 55.744 45.178 100.922 100.921 100.922h22.03v22.178c0 55.744 45.178 100.922 100.921 100.922V83.292a22.03 22.03 0 00-22.03-22.03h-78.892z" transform="scale(.73)" fill="url(#jira1)"/>
      <path d="M122.951 122.489H0c0 55.744 45.178 100.922 100.921 100.922h22.03v22.178C122.951 301.333 168.13 346.51 223.873 346.51V144.52a22.03 22.03 0 00-22.03-22.03h-78.892z" transform="scale(.73)" fill="url(#jira2)"/>
    </svg>
  )
}

function ServiceNowLogo({ size = 20 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
      <circle cx="12" cy="12" r="11" fill="#81B5A1"/>
      <circle cx="12" cy="12" r="4.5" fill="#fff"/>
      <circle cx="12" cy="12" r="2.2" fill="#81B5A1"/>
    </svg>
  )
}

function SlackLogo({ size = 20 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
      <path d="M5.042 15.165a2.528 2.528 0 01-2.52 2.523A2.528 2.528 0 010 15.165a2.527 2.527 0 012.522-2.52h2.52v2.52zm1.271 0a2.527 2.527 0 012.521-2.52 2.527 2.527 0 012.521 2.52v6.313A2.528 2.528 0 018.834 24a2.528 2.528 0 01-2.521-2.522v-6.313z" fill="#E01E5A"/>
      <path d="M8.834 5.042a2.528 2.528 0 01-2.521-2.52A2.528 2.528 0 018.834 0a2.528 2.528 0 012.521 2.522v2.52H8.834zm0 1.271a2.528 2.528 0 012.521 2.521 2.528 2.528 0 01-2.521 2.521H2.522A2.528 2.528 0 010 8.834a2.528 2.528 0 012.522-2.521h6.312z" fill="#36C5F0"/>
      <path d="M18.956 8.834a2.528 2.528 0 012.522-2.521A2.528 2.528 0 0124 8.834a2.528 2.528 0 01-2.522 2.521h-2.522V8.834zm-1.27 0a2.528 2.528 0 01-2.522 2.521 2.527 2.527 0 01-2.521-2.521V2.522A2.527 2.527 0 0115.164 0a2.528 2.528 0 012.522 2.522v6.312z" fill="#2EB67D"/>
      <path d="M15.164 18.956a2.528 2.528 0 012.522 2.522A2.528 2.528 0 0115.164 24a2.527 2.527 0 01-2.521-2.522v-2.522h2.521zm0-1.27a2.527 2.527 0 01-2.521-2.522 2.528 2.528 0 012.521-2.521h6.314A2.528 2.528 0 0124 15.164a2.528 2.528 0 01-2.522 2.522h-6.314z" fill="#ECB22E"/>
    </svg>
  )
}

function TeamsLogo({ size = 20 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
      <path d="M20.625 6.375h-4.5v3.75c0 2.07-1.68 3.75-3.75 3.75h-1.5v2.25c0 1.24 1.01 2.25 2.25 2.25h4.5l2.25 2.25v-2.25h.75c.83 0 1.5-.67 1.5-1.5V7.875c0-.83-.67-1.5-1.5-1.5z" fill="#6264A7"/>
      <circle cx="19.125" cy="4.125" r="1.875" fill="#6264A7"/>
      <rect x="1.5" y="3" width="13.5" height="10.5" rx="1.5" fill="#6264A7"/>
      <path d="M5.625 6.375h5.25v1.125H9v4.125H7.875V7.5H5.625V6.375z" fill="#fff"/>
    </svg>
  )
}

function AnthropicLogo({ size = 20 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
      <path d="M13.827 3.52h3.603L24 20.48h-3.603l-6.57-16.96zm-7.258 0h3.604L16.742 20.48h-3.603L6.57 3.52zM3.48 20.48L10.14 3.52h3.603L7.083 20.48H3.48z" fill="#d97706"/>
    </svg>
  )
}

function OpenAILogo({ size = 20 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
      <path d="M22.282 9.821a5.985 5.985 0 00-.516-4.91 6.046 6.046 0 00-6.51-2.9A6.065 6.065 0 0011.705.001a6.046 6.046 0 00-5.77 4.166 6.046 6.046 0 00-4.045 2.934 6.046 6.046 0 00.749 7.1 5.985 5.985 0 00.516 4.91 6.046 6.046 0 006.51 2.9A6.065 6.065 0 0012.295 24a6.046 6.046 0 005.77-4.166 6.046 6.046 0 004.045-2.934 6.046 6.046 0 00-.749-7.1zM12.295 22.44a4.504 4.504 0 01-2.893-1.05l.144-.083 4.806-2.774a.78.78 0 00.395-.677v-6.777l2.031 1.173a.072.072 0 01.04.055v5.612a4.524 4.524 0 01-4.523 4.521zm-9.72-4.15a4.504 4.504 0 01-.54-3.032l.144.085 4.806 2.775a.78.78 0 00.788 0l5.87-3.388v2.345a.072.072 0 01-.03.062l-4.861 2.806a4.524 4.524 0 01-6.177-1.653zm-1.266-10.49a4.504 4.504 0 012.354-1.98V11.5a.78.78 0 00.395.678l5.87 3.388-2.032 1.173a.072.072 0 01-.068.006l-4.862-2.807A4.524 4.524 0 011.31 7.8zm16.698 3.884l-5.87-3.388 2.031-1.173a.072.072 0 01.068-.006l4.862 2.807a4.524 4.524 0 01-.7 8.146v-5.708a.78.78 0 00-.391-.678zm2.02-3.044l-.144-.085-4.806-2.775a.78.78 0 00-.788 0l-5.87 3.388V6.823a.072.072 0 01.03-.062l4.861-2.806a4.524 4.524 0 016.717 4.685zm-12.71 4.18L5.287 11.65a.072.072 0 01-.04-.055V6.023a4.524 4.524 0 017.416-3.47l-.144.083L7.713 5.41a.78.78 0 00-.395.677v6.733zm1.103-2.368l2.614-1.509 2.614 1.509v3.018l-2.614 1.509-2.614-1.509z" fill="#10a37f"/>
    </svg>
  )
}

function GeminiLogo({ size = 20 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
      <path d="M12 24C12 24 12 12 24 12C12 12 12 0 12 0C12 0 12 12 0 12C12 12 12 24 12 24Z" fill="#4285F4"/>
    </svg>
  )
}

function GroqLogo({ size = 20 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="4" fill="#f55036"/>
      <text x="12" y="17" textAnchor="middle" fill="#fff" fontSize="13" fontWeight="bold" fontFamily="system-ui">G</text>
    </svg>
  )
}

function EmailLogo({ size = 20 }) {
  return (
    <div style={{ width: size, height: size, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <Mail size={size * 0.8} color="#ea580c" strokeWidth={2} />
    </div>
  )
}

const PROVIDER_META = {
  jira:        { color: '#0052CC', label: 'Jira',                 Logo: JiraLogo,        category: 'ticketing' },
  servicenow:  { color: '#81B5A1', label: 'ServiceNow',           Logo: ServiceNowLogo,  category: 'ticketing' },
  email:       { color: '#ea580c', label: 'Email (SMTP)',          Logo: EmailLogo,       category: 'notifications' },
  slack:       { color: '#4A154B', label: 'Slack',                 Logo: SlackLogo,       category: 'notifications' },
  teams:       { color: '#6264A7', label: 'Microsoft Teams',       Logo: TeamsLogo,       category: 'notifications' },
  anthropic:      { color: '#d97706', label: 'Anthropic (Claude AI)', Logo: AnthropicLogo,   category: 'ai' },
  openai:         { color: '#10a37f', label: 'OpenAI (ChatGPT)',     Logo: OpenAILogo,      category: 'ai' },
  google_gemini:  { color: '#4285F4', label: 'Google Gemini',        Logo: GeminiLogo,      category: 'ai' },
  groq:           { color: '#f55036', label: 'Groq',                 Logo: GroqLogo,        category: 'ai' },
}

const CATEGORIES = [
  { key: 'ticketing',     label: 'Ticketing' },
  { key: 'notifications', label: 'Notifications' },
  { key: 'ai',            label: 'AI / LLM' },
]

// ── Integration Card ─────────────────────────────────────────────────

function IntegrationCard({ integration, onRefresh }) {
  const toast = useToast()
  const confirm = useConfirm()
  const [expanded, setExpanded] = useState(false)
  const [config, setConfig] = useState({})
  const [enabled, setEnabled] = useState(integration.is_enabled)
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [showPasswords, setShowPasswords] = useState({})

  const meta = PROVIDER_META[integration.provider] || { color: '#64748b', label: integration.display_name || integration.provider, Logo: null }
  const Logo = meta.Logo

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
      toast.success('Settings saved')
      onRefresh()
    } catch (e) {
      toast.error('Save failed: ' + e.message)
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
    if (!await confirm(`Remove ${meta.label} configuration?`)) return
    await deleteIntegration(integration.provider)
    toast.success('Integration removed')
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
          background: `${meta.color}15`, display: 'flex',
          alignItems: 'center', justifyContent: 'center', flexShrink: 0,
        }}>
          {Logo ? <Logo size={22} /> : (
            <div style={{
              width: 12, height: 12, borderRadius: '50%',
              background: integration.is_enabled ? '#22c55e' : '#94a3b8',
            }} />
          )}
        </div>
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 600, fontSize: 14, color: 'var(--text)' }}>{meta.label}</div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            {integration.is_configured
              ? (integration.is_enabled ? 'Connected' : 'Configured but disabled')
              : 'Not configured'}
          </div>
        </div>
        {integration.is_enabled && (
          <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#22c55e', flexShrink: 0 }} />
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
                    ) : field.type === 'select' ? (
                      <>
                        <label style={labelStyle}>{field.label}</label>
                        <select
                          value={config[field.key] || ''}
                          onChange={e => setConfig(c => ({ ...c, [field.key]: e.target.value }))}
                          style={inputStyle}
                        >
                          <option value="">Select...</option>
                          {(field.options || []).map(opt => (
                            <option key={opt} value={opt}>{opt}</option>
                          ))}
                        </select>
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
                  <Pill
                    color={testResult.status === 'ok' ? '#22c55e' : '#ef4444'}
                    label={testResult.status === 'ok'
                      ? `Connected${testResult.detail ? ` — ${testResult.detail}` : ''}`
                      : `Error: ${testResult.detail || 'Failed'}`}
                  />
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

// ── Main Component ───────────────────────────────────────────────────

export default function IntegrationSettings() {
  const [integrations, setIntegrations] = useState([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')

  const load = () => {
    getIntegrations()
      .then(setIntegrations)
      .catch(() => {})
      .finally(() => setLoading(false))
  }

  useEffect(load, [])

  if (loading) return <Spinner />

  const q = search.toLowerCase().trim()
  const filtered = q
    ? integrations.filter(i => {
        const meta = PROVIDER_META[i.provider]
        const label = meta?.label || i.display_name || i.provider
        return label.toLowerCase().includes(q) || i.provider.includes(q)
      })
    : integrations

  const getForCategory = (catKey) =>
    filtered.filter(i => (PROVIDER_META[i.provider]?.category || 'other') === catKey)

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
        <div>
          <div style={{ fontWeight: 600, fontSize: 15, marginBottom: 4 }}>Integrations</div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            Configure external services for workflow actions — ticketing, notifications, AI, and webhooks
          </div>
        </div>
        <div style={{ position: 'relative', flexShrink: 0 }}>
          <Search size={14} color="#94a3b8" style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)' }} />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search integrations..."
            style={{
              padding: '7px 11px 7px 30px', borderRadius: 8, fontSize: 13, width: 220,
              border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)',
              outline: 'none',
            }}
          />
        </div>
      </div>

      {CATEGORIES.map(cat => {
        const items = getForCategory(cat.key)
        if (items.length === 0) return null
        return (
          <div key={cat.key}>
            <div style={{
              fontSize: 11, fontWeight: 700, textTransform: 'uppercase',
              color: '#818cf8', marginBottom: 8, marginTop: 20, letterSpacing: '0.05em',
            }}>
              {cat.label}
            </div>
            {items.map(i => (
              <IntegrationCard key={i.provider} integration={i} onRefresh={load} />
            ))}
          </div>
        )
      })}

      {filtered.length === 0 && (
        <div style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: 13, padding: 40 }}>
          No integrations match "{search}"
        </div>
      )}
    </div>
  )
}
