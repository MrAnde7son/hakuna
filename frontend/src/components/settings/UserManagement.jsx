import React, { useState } from 'react'
import { useAuth } from '../../contexts/AuthContext.jsx'
import { authChangePassword } from '../../api.js'
import { KeyRound } from 'lucide-react'

const ROLE_COLORS = {
  superadmin: { bg: 'var(--warning-subtle)', color: 'var(--warning)', label: 'Super Admin' },
  org_admin:  { bg: 'rgba(37,99,235,0.1)',   color: 'var(--primary)', label: 'Admin' },
  analyst:    { bg: 'var(--success-subtle)',  color: 'var(--success)', label: 'Analyst' },
  viewer:     { bg: 'var(--secondary)',       color: 'var(--muted)',   label: 'Viewer' },
  custom:     { bg: 'rgba(109,40,217,0.1)',  color: '#6d28d9',        label: 'Custom' },
}

function RoleBadge({ role }) {
  const { bg, color, label } = ROLE_COLORS[role] || ROLE_COLORS.viewer
  return (
    <span style={{
      background: bg, color, padding: '2px 8px', borderRadius: 999,
      fontSize: 11, fontWeight: 600,
    }}>
      {label}
    </span>
  )
}

export default function UserManagement() {
  const { user: currentUser, org } = useAuth()
  const [changingPw, setChangingPw] = useState(false)
  const [pwForm, setPwForm] = useState({ current_password: '', new_password: '', confirm: '' })
  const [pwError, setPwError] = useState('')
  const [pwSuccess, setPwSuccess] = useState('')
  const [pwLoading, setPwLoading] = useState(false)

  const handleChangePw = async (e) => {
    e.preventDefault()
    setPwError('')
    setPwSuccess('')
    if (pwForm.new_password !== pwForm.confirm) { setPwError('Passwords do not match'); return }
    if (pwForm.new_password.length < 8) { setPwError('Password must be at least 8 characters'); return }
    setPwLoading(true)
    try {
      await authChangePassword({ current_password: pwForm.current_password, new_password: pwForm.new_password })
      setPwSuccess('Password changed successfully')
      setChangingPw(false)
      setPwForm({ current_password: '', new_password: '', confirm: '' })
    } catch (err) {
      setPwError(err.message || 'Failed to change password')
    } finally {
      setPwLoading(false)
    }
  }

  const initials = (currentUser.display_name || currentUser.email || '?').slice(0, 2).toUpperCase()

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
        <h2 style={{ fontSize: 18, fontWeight: 700, margin: 0 }}>Profile</h2>
      </div>

      <div style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 10, padding: 24,
        display: 'flex', alignItems: 'center', gap: 20, marginBottom: 16,
      }}>
        <div style={{
          width: 56, height: 56, borderRadius: '50%', background: 'var(--nav-active-bg)', color: 'var(--nav-active-text)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 20, fontWeight: 700, flexShrink: 0,
        }}>
          {initials}
        </div>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)' }}>{currentUser.display_name}</div>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 2 }}>{currentUser.email}</div>
          <div style={{ display: 'flex', gap: 8, marginTop: 6, alignItems: 'center' }}>
            <RoleBadge role={currentUser.role} />
            <span style={{ fontSize: 12, color: '#a1a1aa' }}>{org?.name}</span>
          </div>
        </div>
      </div>

      <div style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 10, padding: 20,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 14, fontWeight: 600 }}>
            <KeyRound size={16} /> Security
          </div>
          {!changingPw && (
            <button
              onClick={() => setChangingPw(true)}
              style={{
                padding: '5px 12px', borderRadius: 6, border: '1px solid var(--border)',
                background: 'var(--bg-card)', fontSize: 12, cursor: 'pointer',
              }}
            >
              Change Password
            </button>
          )}
        </div>

        {pwSuccess && (
          <div style={{ background: 'var(--success-subtle)', color: 'var(--success)', padding: '8px 12px', borderRadius: 6, fontSize: 13, marginBottom: 12, border: '1px solid #bbf7d0' }}>
            {pwSuccess}
          </div>
        )}

        {changingPw && (
          <form onSubmit={handleChangePw} style={{ display: 'flex', flexDirection: 'column', gap: 10, maxWidth: 360 }}>
            {pwError && (
              <div style={{ background: 'var(--danger-subtle)', color: 'var(--danger)', padding: '8px 12px', borderRadius: 6, fontSize: 13, border: '1px solid var(--danger)' }}>
                {pwError}
              </div>
            )}
            <div>
              <label style={{ fontSize: 12, fontWeight: 500 }}>Current Password</label>
              <input type="password" value={pwForm.current_password} onChange={e => setPwForm(p => ({ ...p, current_password: e.target.value }))} required
                style={{ width: '100%', padding: '7px 10px', borderRadius: 8, border: '1px solid var(--border)', fontSize: 13, boxSizing: 'border-box' }} />
            </div>
            <div>
              <label style={{ fontSize: 12, fontWeight: 500 }}>New Password</label>
              <input type="password" value={pwForm.new_password} onChange={e => setPwForm(p => ({ ...p, new_password: e.target.value }))} required minLength={8}
                style={{ width: '100%', padding: '7px 10px', borderRadius: 8, border: '1px solid var(--border)', fontSize: 13, boxSizing: 'border-box' }} />
            </div>
            <div>
              <label style={{ fontSize: 12, fontWeight: 500 }}>Confirm New Password</label>
              <input type="password" value={pwForm.confirm} onChange={e => setPwForm(p => ({ ...p, confirm: e.target.value }))} required
                style={{ width: '100%', padding: '7px 10px', borderRadius: 8, border: '1px solid var(--border)', fontSize: 13, boxSizing: 'border-box' }} />
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button type="button" onClick={() => { setChangingPw(false); setPwError('') }}
                style={{ padding: '6px 14px', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--bg-card)', fontSize: 13, cursor: 'pointer' }}>
                Cancel
              </button>
              <button type="submit" disabled={pwLoading}
                style={{ padding: '6px 14px', borderRadius: 8, border: 'none', background: 'var(--nav-active-bg)', color: 'var(--nav-active-text)', fontSize: 13, fontWeight: 600, cursor: 'pointer' }}>
                {pwLoading ? 'Saving...' : 'Update Password'}
              </button>
            </div>
          </form>
        )}

        {!changingPw && !pwSuccess && (
          <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
            Last login: {currentUser.last_login_at ? new Date(currentUser.last_login_at).toLocaleString() : 'N/A'}
          </div>
        )}
      </div>
    </div>
  )
}
