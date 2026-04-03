import React, { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { Shield, Copy, Check, Trash2, ExternalLink } from 'lucide-react'
import { getSamlConfig, createSamlConfig, updateSamlConfig, deleteSamlConfig } from '../../api.js'

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
      {label && <span style={{ fontSize: 13 }}>{label}</span>}
    </label>
  )
}

function CopyField({ label, value }) {
  const [copied, setCopied] = useState(false)
  const handleCopy = () => {
    navigator.clipboard.writeText(value)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return (
    <div style={{ marginBottom: 12 }}>
      <label style={{ display: 'block', fontSize: 12, fontWeight: 500, color: 'var(--text-muted)', marginBottom: 4 }}>
        {label}
      </label>
      <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
        <input
          readOnly
          value={value}
          style={{
            flex: 1, padding: '7px 10px', borderRadius: 6,
            border: '1px solid var(--border)', fontSize: 13,
            background: 'var(--bg-muted)', fontFamily: 'monospace',
          }}
        />
        <button onClick={handleCopy} style={{
          padding: '6px 8px', borderRadius: 6, border: '1px solid var(--border)',
          background: 'var(--bg-card)', cursor: 'pointer', display: 'flex', alignItems: 'center',
        }}>
          {copied ? <Check size={14} color="var(--success)" /> : <Copy size={14} />}
        </button>
      </div>
    </div>
  )
}

export default function SSOSettings() {
  const { t } = useTranslation()
  const [config, setConfig] = useState(null)
  const [configured, setConfigured] = useState(false)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  // Form state
  const [form, setForm] = useState({
    idp_entity_id: '',
    idp_sso_url: '',
    idp_slo_url: '',
    idp_x509_cert: '',
    sp_entity_id: '',
    default_role: 'analyst',
    auto_provision: true,
    force_sso: false,
    is_enabled: false,
    attribute_mapping: { email: '', display_name: '', role: '' },
  })

  const loadConfig = useCallback(async () => {
    try {
      const data = await getSamlConfig()
      if (data.configured) {
        setConfigured(true)
        setConfig(data)
        setForm({
          idp_entity_id: data.idp_entity_id || '',
          idp_sso_url: data.idp_sso_url || '',
          idp_slo_url: data.idp_slo_url || '',
          idp_x509_cert: '', // Don't show existing cert for security
          sp_entity_id: data.sp_entity_id || '',
          default_role: data.default_role || 'analyst',
          auto_provision: data.auto_provision ?? true,
          force_sso: data.force_sso ?? false,
          is_enabled: data.is_enabled ?? false,
          attribute_mapping: data.attribute_mapping || { email: '', display_name: '', role: '' },
        })
      }
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { loadConfig() }, [loadConfig])

  const handleSave = async () => {
    setSaving(true)
    setError('')
    setSuccess('')
    try {
      const payload = { ...form }
      // Clean up empty attribute mappings
      if (payload.attribute_mapping) {
        payload.attribute_mapping = Object.fromEntries(
          Object.entries(payload.attribute_mapping).filter(([, v]) => v)
        )
      }
      // Remove empty optional strings
      if (!payload.idp_slo_url) delete payload.idp_slo_url
      if (!payload.sp_entity_id) delete payload.sp_entity_id

      if (configured) {
        // Don't send cert if not changed (empty means keep existing)
        if (!payload.idp_x509_cert) delete payload.idp_x509_cert
        const data = await updateSamlConfig(payload)
        setConfig(data)
      } else {
        if (!payload.idp_x509_cert) {
          setError('IdP X.509 certificate is required')
          setSaving(false)
          return
        }
        const data = await createSamlConfig(payload)
        setConfig(data)
        setConfigured(true)
      }
      setSuccess('SAML configuration saved successfully')
      setTimeout(() => setSuccess(''), 3000)
      await loadConfig()
    } catch (e) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async () => {
    if (!window.confirm('Are you sure you want to delete SAML SSO configuration? Users will no longer be able to log in via SSO.')) return
    try {
      await deleteSamlConfig()
      setConfigured(false)
      setConfig(null)
      setForm({
        idp_entity_id: '', idp_sso_url: '', idp_slo_url: '', idp_x509_cert: '',
        sp_entity_id: '', default_role: 'analyst', auto_provision: true, force_sso: false,
        is_enabled: false, attribute_mapping: { email: '', display_name: '', role: '' },
      })
      setSuccess('SAML configuration deleted')
      setTimeout(() => setSuccess(''), 3000)
    } catch (e) {
      setError(e.message)
    }
  }

  const updateField = (key, value) => setForm(prev => ({ ...prev, [key]: value }))
  const updateAttrMap = (key, value) => setForm(prev => ({
    ...prev,
    attribute_mapping: { ...prev.attribute_mapping, [key]: value },
  }))

  if (loading) return <div style={{ padding: 24, color: 'var(--text-muted)' }}>Loading...</div>

  const inputStyle = {
    width: '100%', padding: '8px 12px', borderRadius: 8,
    border: '1px solid var(--border)', fontSize: 13, boxSizing: 'border-box',
  }
  const labelStyle = { display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4 }

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
        <Shield size={20} />
        <h2 style={{ margin: 0, fontSize: 18, fontWeight: 600 }}>SAML 2.0 Single Sign-On</h2>
      </div>
      <p style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 4, marginBottom: 24 }}>
        Configure SAML SSO to allow users to authenticate via your identity provider (Okta, Azure AD, OneLogin, etc.)
      </p>

      {error && (
        <div style={{
          background: 'var(--danger-subtle)', color: 'var(--danger)',
          padding: '8px 12px', borderRadius: 6, fontSize: 13, marginBottom: 16,
          border: '1px solid var(--danger)',
        }}>{error}</div>
      )}
      {success && (
        <div style={{
          background: 'var(--success-subtle, #dcfce7)', color: 'var(--success, #16a34a)',
          padding: '8px 12px', borderRadius: 6, fontSize: 13, marginBottom: 16,
          border: '1px solid var(--success, #16a34a)',
        }}>{success}</div>
      )}

      {/* SP Info for IdP setup — show only when configured */}
      {configured && config && (
        <div style={{
          background: 'var(--bg-muted)', borderRadius: 8, padding: 16, marginBottom: 24,
          border: '1px solid var(--border)',
        }}>
          <h3 style={{ fontSize: 14, fontWeight: 600, marginTop: 0, marginBottom: 12 }}>
            Service Provider Details (for your IdP)
          </h3>
          <CopyField label="SP Entity ID / Audience URI" value={config.sp_entity_id} />
          <CopyField label="ACS URL (Assertion Consumer Service)" value={config.sp_acs_url} />
          <CopyField label="SP Metadata URL" value={config.sp_metadata_url} />
        </div>
      )}

      {/* IdP Configuration */}
      <div style={{
        background: 'var(--bg-card)', borderRadius: 8, padding: 20, marginBottom: 20,
        border: '1px solid var(--border)',
      }}>
        <h3 style={{ fontSize: 14, fontWeight: 600, marginTop: 0, marginBottom: 16 }}>
          Identity Provider Configuration
        </h3>

        <div style={{ marginBottom: 14 }}>
          <label style={labelStyle}>IdP Entity ID / Issuer *</label>
          <input
            style={inputStyle}
            value={form.idp_entity_id}
            onChange={e => updateField('idp_entity_id', e.target.value)}
            placeholder="e.g., https://accounts.google.com/o/saml2?idpid=..."
          />
        </div>

        <div style={{ marginBottom: 14 }}>
          <label style={labelStyle}>IdP SSO URL *</label>
          <input
            style={inputStyle}
            value={form.idp_sso_url}
            onChange={e => updateField('idp_sso_url', e.target.value)}
            placeholder="e.g., https://login.microsoftonline.com/.../saml2"
          />
        </div>

        <div style={{ marginBottom: 14 }}>
          <label style={labelStyle}>IdP SLO URL (optional)</label>
          <input
            style={inputStyle}
            value={form.idp_slo_url}
            onChange={e => updateField('idp_slo_url', e.target.value)}
            placeholder="Single Logout URL (optional)"
          />
        </div>

        <div style={{ marginBottom: 14 }}>
          <label style={labelStyle}>
            IdP X.509 Certificate *
            {configured && <span style={{ fontWeight: 400, color: 'var(--text-muted)' }}> (leave empty to keep existing)</span>}
          </label>
          <textarea
            style={{ ...inputStyle, minHeight: 100, fontFamily: 'monospace', fontSize: 12 }}
            value={form.idp_x509_cert}
            onChange={e => updateField('idp_x509_cert', e.target.value)}
            placeholder="Paste the PEM-encoded X.509 certificate from your IdP"
          />
        </div>

        <div style={{ marginBottom: 14 }}>
          <label style={labelStyle}>SP Entity ID (optional override)</label>
          <input
            style={inputStyle}
            value={form.sp_entity_id}
            onChange={e => updateField('sp_entity_id', e.target.value)}
            placeholder="Leave empty for auto-generated"
          />
        </div>
      </div>

      {/* Attribute Mapping */}
      <div style={{
        background: 'var(--bg-card)', borderRadius: 8, padding: 20, marginBottom: 20,
        border: '1px solid var(--border)',
      }}>
        <h3 style={{ fontSize: 14, fontWeight: 600, marginTop: 0, marginBottom: 4 }}>
          Attribute Mapping
        </h3>
        <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 0, marginBottom: 16 }}>
          Map SAML assertion attributes to user fields. Leave empty to use defaults.
        </p>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
          <div>
            <label style={labelStyle}>Email attribute</label>
            <input
              style={inputStyle}
              value={form.attribute_mapping.email || ''}
              onChange={e => updateAttrMap('email', e.target.value)}
              placeholder="e.g., email or mail"
            />
          </div>
          <div>
            <label style={labelStyle}>Display name attribute</label>
            <input
              style={inputStyle}
              value={form.attribute_mapping.display_name || ''}
              onChange={e => updateAttrMap('display_name', e.target.value)}
              placeholder="e.g., displayName"
            />
          </div>
          <div>
            <label style={labelStyle}>Role attribute</label>
            <input
              style={inputStyle}
              value={form.attribute_mapping.role || ''}
              onChange={e => updateAttrMap('role', e.target.value)}
              placeholder="e.g., role"
            />
          </div>
        </div>
      </div>

      {/* Behavior Settings */}
      <div style={{
        background: 'var(--bg-card)', borderRadius: 8, padding: 20, marginBottom: 20,
        border: '1px solid var(--border)',
      }}>
        <h3 style={{ fontSize: 14, fontWeight: 600, marginTop: 0, marginBottom: 16 }}>
          SSO Behavior
        </h3>

        <div style={{ marginBottom: 14 }}>
          <label style={labelStyle}>Default role for new SSO users</label>
          <select
            style={{ ...inputStyle, cursor: 'pointer' }}
            value={form.default_role}
            onChange={e => updateField('default_role', e.target.value)}
          >
            <option value="analyst">Analyst</option>
            <option value="viewer">Viewer</option>
            <option value="org_admin">Org Admin</option>
          </select>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginTop: 16 }}>
          <Toggle
            checked={form.auto_provision}
            onChange={v => updateField('auto_provision', v)}
            label="Auto-provision users on first SSO login (JIT provisioning)"
          />
          <Toggle
            checked={form.force_sso}
            onChange={v => updateField('force_sso', v)}
            label="Require SSO for all users in this organization (disables password login)"
          />
          <Toggle
            checked={form.is_enabled}
            onChange={v => updateField('is_enabled', v)}
            label="Enable SAML SSO"
          />
        </div>
      </div>

      {/* Actions */}
      <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
        <button
          onClick={handleSave}
          disabled={saving || !form.idp_entity_id || !form.idp_sso_url}
          style={{
            padding: '10px 24px', borderRadius: 8, border: 'none',
            background: 'var(--accent)', color: '#fff', fontSize: 14, fontWeight: 600,
            cursor: saving ? 'not-allowed' : 'pointer',
            opacity: (saving || !form.idp_entity_id || !form.idp_sso_url) ? 0.6 : 1,
          }}
        >
          {saving ? 'Saving...' : configured ? 'Update Configuration' : 'Save Configuration'}
        </button>

        {configured && (
          <button
            onClick={handleDelete}
            style={{
              padding: '10px 16px', borderRadius: 8,
              border: '1px solid var(--danger)', background: 'transparent',
              color: 'var(--danger)', fontSize: 14, fontWeight: 500, cursor: 'pointer',
              display: 'flex', alignItems: 'center', gap: 6,
            }}
          >
            <Trash2 size={14} /> Delete Configuration
          </button>
        )}
      </div>
    </div>
  )
}
