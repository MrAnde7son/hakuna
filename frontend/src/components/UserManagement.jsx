import React, { useState, useEffect } from 'react'
import { useAuth } from '../contexts/AuthContext.jsx'
import {
  authListUsers, authInviteUser, authUpdateUser, authDeleteUser,
  authListOrgs, authCreateOrg, authUpdateOrg, authDeleteOrg,
  authMSSPClients, authChangePassword,
} from '../api.js'
import { Users, Building2, Plus, Shield, Pencil, UserPlus, User, KeyRound, Trash2 } from 'lucide-react'

const ROLE_COLORS = {
  superadmin: { bg: '#fef3c7', color: '#92400e', label: 'Super Admin' },
  org_admin: { bg: '#dbeafe', color: '#1e40af', label: 'Admin' },
  analyst: { bg: '#f0fdf4', color: '#166534', label: 'Analyst' },
  viewer: { bg: '#f5f5f5', color: '#525252', label: 'Viewer' },
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

function ProfileTab({ currentUser, org }) {
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
      <div style={{
        background: '#fff', border: '1px solid var(--border)', borderRadius: 10, padding: 24,
        display: 'flex', alignItems: 'center', gap: 20, marginBottom: 16,
      }}>
        <div style={{
          width: 56, height: 56, borderRadius: '50%', background: '#18181b', color: '#fff',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 20, fontWeight: 700, flexShrink: 0,
        }}>
          {initials}
        </div>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 18, fontWeight: 700, color: '#18181b' }}>{currentUser.display_name}</div>
          <div style={{ fontSize: 13, color: '#71717a', marginTop: 2 }}>{currentUser.email}</div>
          <div style={{ display: 'flex', gap: 8, marginTop: 6, alignItems: 'center' }}>
            <RoleBadge role={currentUser.role} />
            <span style={{ fontSize: 12, color: '#a1a1aa' }}>{org?.name}</span>
          </div>
        </div>
      </div>

      <div style={{
        background: '#fff', border: '1px solid var(--border)', borderRadius: 10, padding: 20,
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
                background: '#fff', fontSize: 12, cursor: 'pointer',
              }}
            >
              Change Password
            </button>
          )}
        </div>

        {pwSuccess && (
          <div style={{ background: '#f0fdf4', color: '#166534', padding: '8px 12px', borderRadius: 6, fontSize: 13, marginBottom: 12, border: '1px solid #bbf7d0' }}>
            {pwSuccess}
          </div>
        )}

        {changingPw && (
          <form onSubmit={handleChangePw} style={{ display: 'flex', flexDirection: 'column', gap: 10, maxWidth: 360 }}>
            {pwError && (
              <div style={{ background: '#fef2f2', color: '#991b1b', padding: '8px 12px', borderRadius: 6, fontSize: 13, border: '1px solid #fecaca' }}>
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
                style={{ padding: '6px 14px', borderRadius: 8, border: '1px solid var(--border)', background: '#fff', fontSize: 13, cursor: 'pointer' }}>
                Cancel
              </button>
              <button type="submit" disabled={pwLoading}
                style={{ padding: '6px 14px', borderRadius: 8, border: 'none', background: '#18181b', color: '#fff', fontSize: 13, fontWeight: 600, cursor: 'pointer' }}>
                {pwLoading ? 'Saving...' : 'Update Password'}
              </button>
            </div>
          </form>
        )}

        {!changingPw && !pwSuccess && (
          <div style={{ fontSize: 13, color: '#71717a' }}>
            Last login: {currentUser.last_login_at ? new Date(currentUser.last_login_at).toLocaleString() : 'N/A'}
          </div>
        )}
      </div>
    </div>
  )
}

export default function UserManagement() {
  const { user: currentUser, isSuperadmin, isAdmin, isMSSP, org } = useAuth()
  const [tab, setTab] = useState('profile')
  const [users, setUsers] = useState([])
  const [orgs, setOrgs] = useState([])
  const [msspClients, setMsspClients] = useState([])
  const [showInvite, setShowInvite] = useState(false)
  const [showCreateOrg, setShowCreateOrg] = useState(false)
  const [inviteForm, setInviteForm] = useState({ email: '', display_name: '', role: 'analyst', password: '' })
  const [orgForm, setOrgForm] = useState({ name: '', org_type: 'standard' })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (isAdmin) authListUsers().then(setUsers).catch(() => {})
    if (isSuperadmin) authListOrgs().then(setOrgs).catch(() => {})
    if (isMSSP) authMSSPClients().then(setMsspClients).catch(() => {})
  }, [isAdmin, isSuperadmin, isMSSP])

  const handleInvite = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const newUser = await authInviteUser(inviteForm)
      setUsers(prev => [newUser, ...prev])
      setShowInvite(false)
      setInviteForm({ email: '', display_name: '', role: 'analyst', password: '' })
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const handleCreateOrg = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const newOrg = await authCreateOrg(orgForm)
      setOrgs(prev => [newOrg, ...prev])
      setShowCreateOrg(false)
      setOrgForm({ name: '', org_type: 'standard' })
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const handleToggleActive = async (u) => {
    try {
      const updated = await authUpdateUser(u.id, { is_active: !u.is_active })
      setUsers(prev => prev.map(x => x.id === u.id ? updated : x))
    } catch (err) {
      setError(err.message)
    }
  }

  const handleRoleChange = async (u, newRole) => {
    try {
      const updated = await authUpdateUser(u.id, { role: newRole })
      setUsers(prev => prev.map(x => x.id === u.id ? updated : x))
    } catch (err) {
      setError(err.message)
    }
  }

  const handleDeleteUser = async (u) => {
    if (!window.confirm(`Delete user "${u.display_name}" (${u.email})? This cannot be undone.`)) return
    try {
      await authDeleteUser(u.id)
      setUsers(prev => prev.filter(x => x.id !== u.id))
    } catch (err) {
      setError(err.message)
    }
  }

  const handleToggleOrgActive = async (o) => {
    try {
      const updated = await authUpdateOrg(o.id, { is_active: !o.is_active })
      setOrgs(prev => prev.map(x => x.id === o.id ? updated : x))
    } catch (err) {
      setError(err.message)
    }
  }

  const handleRenameOrg = async (o) => {
    const newName = window.prompt('New organization name:', o.name)
    if (!newName || newName === o.name) return
    try {
      const updated = await authUpdateOrg(o.id, { name: newName })
      setOrgs(prev => prev.map(x => x.id === o.id ? updated : x))
    } catch (err) {
      setError(err.message)
    }
  }

  const handleDeleteOrg = async (o) => {
    if (!window.confirm(`Delete organization "${o.name}" and ALL its users? This cannot be undone.`)) return
    try {
      await authDeleteOrg(o.id)
      setOrgs(prev => prev.filter(x => x.id !== o.id))
    } catch (err) {
      setError(err.message)
    }
  }

  const inputStyle = {
    width: '100%', padding: '7px 10px', borderRadius: 8,
    border: '1px solid var(--border)', fontSize: 13, boxSizing: 'border-box',
  }

  const tabs = [
    { id: 'profile', label: 'Profile', icon: User },
  ]
  if (isAdmin) tabs.push({ id: 'users', label: 'Users', icon: Users })
  if (isSuperadmin || isMSSP) tabs.push({ id: 'orgs', label: 'Organizations', icon: Building2 })
  if (isMSSP) tabs.push({ id: 'clients', label: 'MSSP Clients', icon: Shield })

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
        <h2 style={{ fontSize: 18, fontWeight: 700, margin: 0 }}>Profile</h2>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 16, borderBottom: '1px solid var(--border)', paddingBottom: 0 }}>
        {tabs.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              padding: '8px 16px', border: 'none', cursor: 'pointer',
              borderBottom: tab === t.id ? '2px solid #18181b' : '2px solid transparent',
              background: 'none', fontSize: 13, fontWeight: tab === t.id ? 600 : 400,
              color: tab === t.id ? '#18181b' : '#71717a',
            }}
          >
            <t.icon size={14} />
            {t.label}
          </button>
        ))}
      </div>

      {error && (
        <div style={{ background: '#fef2f2', color: '#991b1b', padding: '8px 12px', borderRadius: 6, fontSize: 13, marginBottom: 12, border: '1px solid #fecaca' }}>
          {error}
          <button onClick={() => setError('')} style={{ float: 'right', background: 'none', border: 'none', cursor: 'pointer', fontSize: 13 }}>x</button>
        </div>
      )}

      {/* Profile Tab */}
      {tab === 'profile' && <ProfileTab currentUser={currentUser} org={org} />}

      {/* Users Tab */}
      {tab === 'users' && isAdmin && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div style={{ fontSize: 13, color: '#71717a' }}>{users.length} user{users.length !== 1 ? 's' : ''}</div>
            <button
              onClick={() => setShowInvite(!showInvite)}
              style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '6px 14px', borderRadius: 8, border: 'none',
                background: '#18181b', color: '#fff', fontSize: 13, fontWeight: 600, cursor: 'pointer',
              }}
            >
              <UserPlus size={14} /> Invite User
            </button>
          </div>

          {showInvite && (
            <form onSubmit={handleInvite} style={{
              background: '#fafafa', border: '1px solid var(--border)', borderRadius: 10, padding: 16, marginBottom: 16,
              display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10,
            }}>
              <div>
                <label style={{ fontSize: 12, fontWeight: 500 }}>Email *</label>
                <input type="email" value={inviteForm.email} onChange={e => setInviteForm(p => ({ ...p, email: e.target.value }))} required style={inputStyle} />
              </div>
              <div>
                <label style={{ fontSize: 12, fontWeight: 500 }}>Name</label>
                <input type="text" value={inviteForm.display_name} onChange={e => setInviteForm(p => ({ ...p, display_name: e.target.value }))} style={inputStyle} />
              </div>
              <div>
                <label style={{ fontSize: 12, fontWeight: 500 }}>Role</label>
                <select value={inviteForm.role} onChange={e => setInviteForm(p => ({ ...p, role: e.target.value }))} style={inputStyle}>
                  <option value="analyst">Analyst</option>
                  <option value="viewer">Viewer</option>
                  <option value="org_admin">Admin</option>
                </select>
              </div>
              <div>
                <label style={{ fontSize: 12, fontWeight: 500 }}>Initial Password *</label>
                <input type="password" value={inviteForm.password} onChange={e => setInviteForm(p => ({ ...p, password: e.target.value }))} required minLength={8} style={inputStyle} />
              </div>
              <div style={{ gridColumn: '1 / -1', display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
                <button type="button" onClick={() => setShowInvite(false)} style={{ padding: '6px 14px', borderRadius: 8, border: '1px solid var(--border)', background: '#fff', fontSize: 13, cursor: 'pointer' }}>Cancel</button>
                <button type="submit" disabled={loading} style={{ padding: '6px 14px', borderRadius: 8, border: 'none', background: '#18181b', color: '#fff', fontSize: 13, fontWeight: 600, cursor: 'pointer' }}>
                  {loading ? 'Inviting...' : 'Send Invite'}
                </button>
              </div>
            </form>
          )}

          <div style={{ background: '#fff', border: '1px solid var(--border)', borderRadius: 10, overflow: 'hidden' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)', background: '#fafafa' }}>
                  <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600 }}>User</th>
                  <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600 }}>Email</th>
                  <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600 }}>Role</th>
                  {isSuperadmin && <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600 }}>Org</th>}
                  <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600 }}>Status</th>
                  <th style={{ textAlign: 'right', padding: '8px 12px', fontWeight: 600 }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map(u => (
                  <tr key={u.id} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={{ padding: '8px 12px' }}>{u.display_name}</td>
                    <td style={{ padding: '8px 12px', color: '#71717a' }}>{u.email}</td>
                    <td style={{ padding: '8px 12px' }}>
                      {u.id === currentUser?.id ? (
                        <RoleBadge role={u.role} />
                      ) : (
                        <select
                          value={u.role}
                          onChange={e => handleRoleChange(u, e.target.value)}
                          style={{ fontSize: 12, border: '1px solid var(--border)', borderRadius: 6, padding: '2px 6px' }}
                        >
                          <option value="viewer">Viewer</option>
                          <option value="analyst">Analyst</option>
                          <option value="org_admin">Admin</option>
                          {isSuperadmin && <option value="superadmin">Super Admin</option>}
                        </select>
                      )}
                    </td>
                    {isSuperadmin && <td style={{ padding: '8px 12px', fontSize: 12, color: '#71717a' }}>{u.org?.name}</td>}
                    <td style={{ padding: '8px 12px' }}>
                      <span style={{
                        fontSize: 11, fontWeight: 600,
                        color: u.is_active ? '#166534' : '#991b1b',
                      }}>
                        {u.is_active ? 'Active' : 'Disabled'}
                      </span>
                    </td>
                    <td style={{ padding: '8px 12px', textAlign: 'right' }}>
                      {u.id !== currentUser?.id && (
                        <div style={{ display: 'flex', gap: 4, justifyContent: 'flex-end' }}>
                          <button
                            onClick={() => handleToggleActive(u)}
                            style={{
                              fontSize: 12, padding: '3px 10px', borderRadius: 6,
                              border: '1px solid var(--border)', background: '#fff', cursor: 'pointer',
                            }}
                          >
                            {u.is_active ? 'Disable' : 'Enable'}
                          </button>
                          <button
                            onClick={() => handleDeleteUser(u)}
                            title="Delete user"
                            style={{
                              fontSize: 12, padding: '3px 8px', borderRadius: 6,
                              border: '1px solid #fecaca', background: '#fff', cursor: 'pointer',
                              color: '#dc2626', display: 'flex', alignItems: 'center',
                            }}
                          >
                            <Trash2 size={12} />
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Orgs Tab */}
      {tab === 'orgs' && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div style={{ fontSize: 13, color: '#71717a' }}>{orgs.length} organization{orgs.length !== 1 ? 's' : ''}</div>
            <button
              onClick={() => setShowCreateOrg(!showCreateOrg)}
              style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '6px 14px', borderRadius: 8, border: 'none',
                background: '#18181b', color: '#fff', fontSize: 13, fontWeight: 600, cursor: 'pointer',
              }}
            >
              <Plus size={14} /> New Organization
            </button>
          </div>

          {showCreateOrg && (
            <form onSubmit={handleCreateOrg} style={{
              background: '#fafafa', border: '1px solid var(--border)', borderRadius: 10, padding: 16, marginBottom: 16,
              display: 'flex', gap: 10, alignItems: 'flex-end',
            }}>
              <div style={{ flex: 1 }}>
                <label style={{ fontSize: 12, fontWeight: 500 }}>Name</label>
                <input type="text" value={orgForm.name} onChange={e => setOrgForm(p => ({ ...p, name: e.target.value }))} required style={inputStyle} />
              </div>
              <div>
                <label style={{ fontSize: 12, fontWeight: 500 }}>Type</label>
                <select value={orgForm.org_type} onChange={e => setOrgForm(p => ({ ...p, org_type: e.target.value }))} style={inputStyle}>
                  <option value="standard">Standard</option>
                  <option value="mssp">MSSP</option>
                </select>
              </div>
              <button type="submit" disabled={loading} style={{ padding: '7px 14px', borderRadius: 8, border: 'none', background: '#18181b', color: '#fff', fontSize: 13, fontWeight: 600, cursor: 'pointer', whiteSpace: 'nowrap' }}>
                Create
              </button>
            </form>
          )}

          <div style={{ background: '#fff', border: '1px solid var(--border)', borderRadius: 10, overflow: 'hidden' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)', background: '#fafafa' }}>
                  <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600 }}>Name</th>
                  <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600 }}>Slug</th>
                  <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600 }}>Type</th>
                  <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600 }}>Status</th>
                  <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600 }}>Created</th>
                  {isSuperadmin && <th style={{ textAlign: 'right', padding: '8px 12px', fontWeight: 600 }}>Actions</th>}
                </tr>
              </thead>
              <tbody>
                {orgs.map(o => (
                  <tr key={o.id} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={{ padding: '8px 12px', fontWeight: 500 }}>{o.name}</td>
                    <td style={{ padding: '8px 12px', color: '#71717a', fontFamily: 'monospace', fontSize: 12 }}>{o.slug}</td>
                    <td style={{ padding: '8px 12px' }}>
                      <span style={{
                        fontSize: 11, fontWeight: 600, padding: '2px 8px', borderRadius: 999,
                        background: o.org_type === 'mssp' ? '#ede9fe' : '#f0fdf4',
                        color: o.org_type === 'mssp' ? '#6d28d9' : '#166534',
                      }}>
                        {o.org_type === 'mssp' ? 'MSSP' : 'Standard'}
                      </span>
                    </td>
                    <td style={{ padding: '8px 12px', fontSize: 11, color: o.is_active ? '#166534' : '#991b1b' }}>
                      {o.is_active ? 'Active' : 'Disabled'}
                    </td>
                    <td style={{ padding: '8px 12px', fontSize: 12, color: '#71717a' }}>
                      {o.created_at ? new Date(o.created_at).toLocaleDateString() : '—'}
                    </td>
                    {isSuperadmin && (
                      <td style={{ padding: '8px 12px', textAlign: 'right' }}>
                        <div style={{ display: 'flex', gap: 4, justifyContent: 'flex-end' }}>
                          <button
                            onClick={() => handleRenameOrg(o)}
                            title="Rename"
                            style={{
                              fontSize: 12, padding: '3px 8px', borderRadius: 6,
                              border: '1px solid var(--border)', background: '#fff', cursor: 'pointer',
                              display: 'flex', alignItems: 'center', gap: 4, color: '#71717a',
                            }}
                          >
                            <Pencil size={12} />
                          </button>
                          <button
                            onClick={() => handleToggleOrgActive(o)}
                            style={{
                              fontSize: 12, padding: '3px 10px', borderRadius: 6,
                              border: '1px solid var(--border)', background: '#fff', cursor: 'pointer',
                            }}
                          >
                            {o.is_active ? 'Disable' : 'Enable'}
                          </button>
                          {o.id !== org?.id && (
                            <button
                              onClick={() => handleDeleteOrg(o)}
                              title="Delete organization"
                              style={{
                                fontSize: 12, padding: '3px 8px', borderRadius: 6,
                                border: '1px solid #fecaca', background: '#fff', cursor: 'pointer',
                                color: '#dc2626', display: 'flex', alignItems: 'center',
                              }}
                            >
                              <Trash2 size={12} />
                            </button>
                          )}
                        </div>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* MSSP Clients Tab */}
      {tab === 'clients' && (
        <div>
          <div style={{ fontSize: 13, color: '#71717a', marginBottom: 12 }}>{msspClients.length} client org{msspClients.length !== 1 ? 's' : ''}</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 12 }}>
            {msspClients.map(c => (
              <div key={c.id} style={{
                background: '#fff', border: '1px solid var(--border)', borderRadius: 10, padding: 16,
              }}>
                <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 6 }}>{c.name}</div>
                <div style={{ fontSize: 12, color: '#71717a', marginBottom: 8 }}>/{c.slug}</div>
                <div style={{ display: 'flex', gap: 16, fontSize: 12 }}>
                  <div><span style={{ fontWeight: 600 }}>{c.scan_count || 0}</span> scans</div>
                  <div><span style={{ fontWeight: 600 }}>{c.user_count || 0}</span> users</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
