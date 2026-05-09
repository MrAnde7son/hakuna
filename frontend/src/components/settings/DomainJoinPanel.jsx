import React, { useState, useEffect } from 'react'
import { Globe, Check, X as XIcon, Clock } from 'lucide-react'
import {
  authGetDomainSettings,
  authUpdateDomainSettings,
  authListJoinRequests,
  authApproveJoinRequest,
  authDenyJoinRequest,
} from '../../api.js'
import { useToast, useConfirm } from '../shared/ui.jsx'
import { useAuth } from '../../contexts/AuthContext.jsx'

const MODE_LABELS = {
  disabled: 'Disabled — every signup creates a new tenant',
  request:  'Require approval — admins approve each join request',
  auto:     'Auto-join — verified users join automatically',
}

const ROLE_OPTIONS = [
  { value: 'viewer',  label: 'Viewer (read-only)' },
  { value: 'analyst', label: 'Analyst (default)' },
  { value: 'org_admin', label: 'Admin (superadmin only)' },
]

export default function DomainJoinPanel() {
  const { isSuperadmin } = useAuth()
  const toast = useToast()
  const confirm = useConfirm()
  const [settings, setSettings] = useState(null)
  const [requests, setRequests] = useState([])
  const [savingSettings, setSavingSettings] = useState(false)
  const [error, setError] = useState('')

  const loadAll = async () => {
    setError('')
    try {
      const [s, rs] = await Promise.all([
        authGetDomainSettings(),
        authListJoinRequests('pending'),
      ])
      setSettings(s)
      setRequests(rs)
    } catch (e) {
      setError(e.message)
    }
  }

  useEffect(() => { loadAll() }, [])

  const handleFieldChange = (field, value) => {
    setSettings(prev => ({ ...prev, [field]: value }))
  }

  const handleSave = async () => {
    setSavingSettings(true)
    setError('')
    try {
      const updated = await authUpdateDomainSettings({
        claimed_domain: (settings.claimed_domain || '').trim() || null,
        domain_join_mode: settings.domain_join_mode,
        domain_join_default_role: settings.domain_join_default_role,
      })
      setSettings(updated)
      toast.success('Domain settings saved')
    } catch (e) {
      setError(e.message)
    } finally {
      setSavingSettings(false)
    }
  }

  const handleApprove = async (req) => {
    if (!await confirm(`Approve ${req.email} to join your organization?`)) return
    try {
      await authApproveJoinRequest(req.id)
      toast.success(`${req.email} added to your organization`)
      setRequests(prev => prev.filter(r => r.id !== req.id))
    } catch (e) {
      toast.error(e.message)
    }
  }

  const handleDeny = async (req) => {
    const reason = window.prompt(`Deny join request from ${req.email}?\n\nOptional reason (visible to requester):`)
    if (reason === null) return
    try {
      await authDenyJoinRequest(req.id, reason || null)
      toast.success(`Denied join request from ${req.email}`)
      setRequests(prev => prev.filter(r => r.id !== req.id))
    } catch (e) {
      toast.error(e.message)
    }
  }

  if (!settings) {
    return (
      <div style={{ padding: 24, color: 'var(--text-muted)', fontSize: 14 }}>
        {error ? `Error: ${error}` : 'Loading…'}
      </div>
    )
  }

  const labelStyle = { display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 6 }
  const inputStyle = {
    width: '100%', padding: '8px 12px', borderRadius: 6,
    border: '1px solid var(--border)', fontSize: 14, boxSizing: 'border-box',
    background: 'var(--bg)', color: 'var(--text)',
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <Globe size={16} color="var(--accent)" />
        <h2 style={{ fontSize: 15, fontWeight: 600, margin: 0 }}>Domain & Auto-Join</h2>
      </div>

      {error && (
        <div style={{
          background: 'var(--danger-subtle)', color: 'var(--danger)',
          padding: '8px 12px', borderRadius: 6, fontSize: 13,
          border: '1px solid var(--danger)',
        }}>{error}</div>
      )}

      {/* Settings card */}
      <div style={{
        border: '1px solid var(--border)', borderRadius: 8, padding: 20,
        background: 'var(--bg-card)',
      }}>
        <div style={{ marginBottom: 14 }}>
          <p style={{ fontSize: 13, color: 'var(--text-muted)', margin: 0, lineHeight: 1.5 }}>
            Control whether new users from your corporate email domain can
            join this organization at signup. Public email domains
            (gmail.com, outlook.com, etc.) cannot be claimed.
          </p>
        </div>

        <div style={{ marginBottom: 16 }}>
          <label style={labelStyle}>Claimed domain</label>
          <input
            type="text"
            value={settings.claimed_domain || ''}
            onChange={e => handleFieldChange('claimed_domain', e.target.value)}
            placeholder="acme.com"
            style={inputStyle}
            disabled={!isSuperadmin && settings.claimed_domain && settings.claimed_domain.length > 0}
          />
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>
            {isSuperadmin
              ? 'Superadmin: you can claim any domain on behalf of this org.'
              : 'Must match your own email domain. Clear the field to release the claim.'}
          </div>
        </div>

        <div style={{ marginBottom: 16 }}>
          <label style={labelStyle}>Join mode</label>
          <select
            value={settings.domain_join_mode}
            onChange={e => handleFieldChange('domain_join_mode', e.target.value)}
            style={inputStyle}
          >
            {Object.entries(MODE_LABELS).map(([v, label]) => (
              <option key={v} value={v}>{label}</option>
            ))}
          </select>
        </div>

        <div style={{ marginBottom: 16 }}>
          <label style={labelStyle}>Default role for new joiners</label>
          <select
            value={settings.domain_join_default_role}
            onChange={e => handleFieldChange('domain_join_default_role', e.target.value)}
            style={inputStyle}
          >
            {ROLE_OPTIONS.filter(o => o.value !== 'org_admin' || isSuperadmin).map(o => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
        </div>

        <button
          type="button"
          onClick={handleSave}
          disabled={savingSettings}
          style={{
            padding: '8px 16px', borderRadius: 6, fontSize: 13, fontWeight: 600,
            border: 'none', background: 'var(--nav-active-bg)',
            color: 'var(--nav-active-text)',
            cursor: savingSettings ? 'not-allowed' : 'pointer',
            opacity: savingSettings ? 0.6 : 1,
          }}
        >
          {savingSettings ? 'Saving…' : 'Save'}
        </button>
      </div>

      {/* Pending requests */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
          <Clock size={14} color="var(--accent)" />
          <h3 style={{ fontSize: 14, fontWeight: 600, margin: 0 }}>
            Pending join requests
            {requests.length > 0 && (
              <span style={{
                marginLeft: 8, fontSize: 11, fontWeight: 600,
                padding: '2px 8px', borderRadius: 999,
                background: 'rgba(99,102,241,0.14)', color: 'var(--accent)',
              }}>{requests.length}</span>
            )}
          </h3>
        </div>

        {requests.length === 0 ? (
          <div style={{
            padding: 16, border: '1px dashed var(--border)', borderRadius: 8,
            color: 'var(--text-muted)', fontSize: 13, textAlign: 'center',
          }}>
            No pending requests.
          </div>
        ) : (
          <div style={{ border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
            {requests.map((r, i) => (
              <div
                key={r.id}
                style={{
                  display: 'flex', alignItems: 'center', gap: 12,
                  padding: '12px 16px', fontSize: 13,
                  borderTop: i === 0 ? 'none' : '1px solid var(--border)',
                  background: 'var(--bg-card)',
                }}
              >
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontWeight: 500, color: 'var(--text)' }}>
                    {r.display_name || r.email}
                  </div>
                  <div style={{ color: 'var(--text-muted)', fontSize: 12 }}>
                    {r.email} · requested {new Date(r.created_at).toLocaleString()}
                  </div>
                </div>
                <button
                  onClick={() => handleApprove(r)}
                  title="Approve"
                  style={{
                    display: 'inline-flex', alignItems: 'center', gap: 4,
                    padding: '6px 12px', borderRadius: 6, fontSize: 12, fontWeight: 600,
                    border: '1px solid var(--success, #16a34a)',
                    background: 'var(--success-subtle, rgba(22,163,74,0.1))',
                    color: 'var(--success, #16a34a)', cursor: 'pointer',
                  }}
                >
                  <Check size={12} /> Approve
                </button>
                <button
                  onClick={() => handleDeny(r)}
                  title="Deny"
                  style={{
                    display: 'inline-flex', alignItems: 'center', gap: 4,
                    padding: '6px 12px', borderRadius: 6, fontSize: 12, fontWeight: 600,
                    border: '1px solid var(--border)',
                    background: 'transparent', color: 'var(--text-muted)', cursor: 'pointer',
                  }}
                >
                  <XIcon size={12} /> Deny
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
