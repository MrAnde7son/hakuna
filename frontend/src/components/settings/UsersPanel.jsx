import React, { useState, useEffect } from 'react'
import { useAuth } from '../../contexts/AuthContext.jsx'
import {
  authListUsers, authInviteUser, authUpdateUser, authDeleteUser,
  authListRoles, authGetUserCustomRoles, authAssignCustomRole, authUnassignCustomRole,
} from '../../api.js'
import { UserPlus, Trash2, X } from 'lucide-react'

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

export default function UsersPanel() {
  const { user: currentUser, isSuperadmin, isAdmin } = useAuth()
  const [users, setUsers] = useState([])
  const [showInvite, setShowInvite] = useState(false)
  const [inviteForm, setInviteForm] = useState({ email: '', display_name: '', role: 'analyst', password: '' })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [customRoles, setCustomRoles] = useState([])
  const [userCustomRoles, setUserCustomRoles] = useState({})
  const [expandedUserRoles, setExpandedUserRoles] = useState(null)

  useEffect(() => {
    if (isAdmin) {
      authListUsers().then(setUsers).catch(() => {})
      authListRoles().then(setCustomRoles).catch(() => {})
    }
  }, [isAdmin])

  useEffect(() => {
    if (!isAdmin || users.length === 0) return
    const map = {}
    Promise.all(
      users.map(u =>
        authGetUserCustomRoles(u.id)
          .then(roles => { map[u.id] = roles })
          .catch(() => { map[u.id] = [] })
      )
    ).then(() => setUserCustomRoles({ ...map }))
  }, [users, isAdmin])

  const handleToggleCustomRole = async (userId, roleId) => {
    const current = userCustomRoles[userId] || []
    const has = current.some(r => r.id === roleId)
    try {
      if (has) {
        await authUnassignCustomRole(userId, roleId)
        setUserCustomRoles(prev => ({ ...prev, [userId]: prev[userId].filter(r => r.id !== roleId) }))
      } else {
        await authAssignCustomRole(userId, roleId)
        const role = customRoles.find(r => r.id === roleId)
        setUserCustomRoles(prev => ({ ...prev, [userId]: [...(prev[userId] || []), role] }))
      }
    } catch (err) {
      setError(err.message)
    }
  }

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

  const inputStyle = {
    width: '100%', padding: '7px 10px', borderRadius: 8,
    border: '1px solid var(--border)', fontSize: 13, boxSizing: 'border-box',
  }

  return (
    <div>
      {error && (
        <div style={{ background: 'var(--danger-subtle)', color: 'var(--danger)', padding: '8px 12px', borderRadius: 6, fontSize: 13, marginBottom: 12, border: '1px solid var(--danger)' }}>
          {error}
          <button onClick={() => setError('')} style={{ float: 'right', background: 'none', border: 'none', cursor: 'pointer', fontSize: 13 }}>x</button>
        </div>
      )}

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>{users.length} user{users.length !== 1 ? 's' : ''}</div>
        <button
          onClick={() => setShowInvite(!showInvite)}
          style={{
            display: 'flex', alignItems: 'center', gap: 6,
            padding: '6px 14px', borderRadius: 8, border: 'none',
            background: 'var(--nav-active-bg)', color: 'var(--nav-active-text)', fontSize: 13, fontWeight: 600, cursor: 'pointer',
          }}
        >
          <UserPlus size={14} /> Invite User
        </button>
      </div>

      {showInvite && (
        <form onSubmit={handleInvite} style={{
          background: 'var(--bg-muted)', border: '1px solid var(--border)', borderRadius: 10, padding: 16, marginBottom: 16,
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
              <option value="custom">Custom (roles only)</option>
            </select>
          </div>
          <div>
            <label style={{ fontSize: 12, fontWeight: 500 }}>Initial Password *</label>
            <input type="password" value={inviteForm.password} onChange={e => setInviteForm(p => ({ ...p, password: e.target.value }))} required minLength={8} style={inputStyle} />
          </div>
          <div style={{ gridColumn: '1 / -1', display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
            <button type="button" onClick={() => setShowInvite(false)} style={{ padding: '6px 14px', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--bg-card)', fontSize: 13, cursor: 'pointer' }}>Cancel</button>
            <button type="submit" disabled={loading} style={{ padding: '6px 14px', borderRadius: 8, border: 'none', background: 'var(--nav-active-bg)', color: 'var(--nav-active-text)', fontSize: 13, fontWeight: 600, cursor: 'pointer' }}>
              {loading ? 'Inviting...' : 'Send Invite'}
            </button>
          </div>
        </form>
      )}

      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 10, overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)', background: 'var(--bg-muted)' }}>
              <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600 }}>User</th>
              <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600 }}>Email</th>
              <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600 }}>Role</th>
              <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600 }}>Custom Roles</th>
              {isSuperadmin && <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600 }}>Org</th>}
              <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600 }}>Status</th>
              <th style={{ textAlign: 'right', padding: '8px 12px', fontWeight: 600 }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map(u => (
              <tr key={u.id} style={{ borderBottom: '1px solid var(--border)' }}>
                <td style={{ padding: '8px 12px' }}>{u.display_name}</td>
                <td style={{ padding: '8px 12px', color: 'var(--text-secondary)' }}>{u.email}</td>
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
                      <option value="custom">Custom</option>
                      {isSuperadmin && <option value="superadmin">Super Admin</option>}
                    </select>
                  )}
                </td>
                <td style={{ padding: '8px 12px' }}>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, alignItems: 'center' }}>
                    {(userCustomRoles[u.id] || []).map(r => (
                      <span key={r.id} style={{
                        display: 'inline-flex', alignItems: 'center', gap: 3,
                        fontSize: 11, padding: '2px 7px', borderRadius: 999,
                        background: 'rgba(109,40,217,0.1)', color: '#6d28d9', fontWeight: 600,
                      }}>
                        {r.name}
                        {u.id !== currentUser?.id && (
                          <button onClick={() => handleToggleCustomRole(u.id, r.id)}
                            style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, color: '#6d28d9', lineHeight: 1 }}>
                            <X size={10} />
                          </button>
                        )}
                      </span>
                    ))}
                    {u.id !== currentUser?.id && customRoles.filter(r => !(userCustomRoles[u.id] || []).some(x => x.id === r.id)).length > 0 && (
                      <div style={{ position: 'relative' }}>
                        <button
                          onClick={() => setExpandedUserRoles(expandedUserRoles === u.id ? null : u.id)}
                          style={{ fontSize: 11, padding: '2px 7px', borderRadius: 999, border: '1px dashed #d4d4d8', background: 'var(--bg-card)', cursor: 'pointer', color: 'var(--text-secondary)' }}
                        >
                          + Add
                        </button>
                        {expandedUserRoles === u.id && (
                          <div style={{
                            position: 'absolute', top: '100%', left: 0, zIndex: 10,
                            background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8,
                            boxShadow: '0 4px 12px rgba(0,0,0,0.1)', minWidth: 160, padding: 4,
                          }}>
                            {customRoles
                              .filter(r => !(userCustomRoles[u.id] || []).some(x => x.id === r.id))
                              .map(r => (
                                <button key={r.id}
                                  onClick={() => { handleToggleCustomRole(u.id, r.id); setExpandedUserRoles(null) }}
                                  style={{
                                    display: 'block', width: '100%', textAlign: 'left',
                                    padding: '6px 10px', border: 'none', background: 'none',
                                    fontSize: 12, cursor: 'pointer', borderRadius: 6,
                                  }}
                                  onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-hover)'}
                                  onMouseLeave={e => e.currentTarget.style.background = 'none'}
                                >
                                  {r.name}
                                </button>
                              ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </td>
                {isSuperadmin && <td style={{ padding: '8px 12px', fontSize: 12, color: 'var(--text-secondary)' }}>{u.org?.name}</td>}
                <td style={{ padding: '8px 12px' }}>
                  <span style={{
                    fontSize: 11, fontWeight: 600,
                    color: u.is_active ? 'var(--success)' : 'var(--danger)',
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
                          border: '1px solid var(--border)', background: 'var(--bg-card)', cursor: 'pointer',
                        }}
                      >
                        {u.is_active ? 'Disable' : 'Enable'}
                      </button>
                      <button
                        onClick={() => handleDeleteUser(u)}
                        title="Delete user"
                        style={{
                          fontSize: 12, padding: '3px 8px', borderRadius: 6,
                          border: '1px solid var(--danger)', background: 'var(--bg-card)', cursor: 'pointer',
                          color: 'var(--danger)', display: 'flex', alignItems: 'center',
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
  )
}
