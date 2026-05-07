import React, { useState, useEffect } from 'react'
import { useAuth } from '../../contexts/AuthContext.jsx'
import {
  authListRoles, authCreateRole, authUpdateRole, authDeleteRole,
  authAddTagPermission, authRemoveTagPermission,
  authGetUserCustomRoles, authAssignCustomRole, authUnassignCustomRole,
  authListUsers, getTags,
} from '../../api.js'
import {
  Shield, Plus, Trash2, Pencil, Check, X, ChevronRight, Users, Tag, Lock, Unlock,
} from 'lucide-react'
import { useConfirm, useToast } from '../shared/ui.jsx'

const PERMISSION_SECTIONS = [
  {
    label: 'Pages',
    items: [
      { key: 'page_dashboard',    label: 'Dashboard' },
      { key: 'page_reports',      label: 'Reports' },
      { key: 'page_assets',       label: 'Assets' },
      { key: 'page_findings',     label: 'Findings' },
      { key: 'page_inventory',    label: 'Inventory' },
      { key: 'page_campaigns',    label: 'Campaigns' },
      { key: 'page_remediation',  label: 'Remediation' },
      { key: 'page_agents',       label: 'Agents' },
      { key: 'page_tags',         label: 'Tags' },
      { key: 'page_upload',       label: 'Upload' },
      { key: 'page_settings',     label: 'Settings' },
      { key: 'page_threat_intel', label: 'Threat Intel' },
      { key: 'page_workflows',    label: 'Workflows' },
    ],
  },
  {
    label: 'Data Access',
    items: [
      { key: 'read_scans',     label: 'Read Scans' },
      { key: 'write_scans',    label: 'Write Scans' },
      { key: 'read_assets',    label: 'Read Assets' },
      { key: 'write_assets',   label: 'Write Assets' },
      { key: 'read_findings',  label: 'Read Findings' },
      { key: 'write_findings', label: 'Write Findings' },
    ],
  },
  {
    label: 'Actions',
    items: [
      { key: 'upload_scan',         label: 'Upload Scans' },
      { key: 'delete_scan',         label: 'Delete Scans' },
      { key: 'export_report',       label: 'Export Reports' },
      { key: 'view_reports',        label: 'View Reports' },
      { key: 'manage_tags',         label: 'Manage Tags' },
      { key: 'manage_campaigns',    label: 'Manage Campaigns' },
      { key: 'manage_exceptions',   label: 'Manage Exceptions' },
      { key: 'manage_workflows',    label: 'Manage Workflows' },
      { key: 'manage_users',        label: 'Manage Users' },
      { key: 'manage_integrations', label: 'Manage Integrations' },
    ],
  },
]

// Flat list for backward compat
const BASE_PERMISSIONS = PERMISSION_SECTIONS.flatMap(s => s.items)

function TriStateToggle({ state, onChange }) {
  // state: "off" | "allow" | "deny"
  const colors = { off: 'var(--border)', allow: 'var(--text)', deny: 'var(--danger)' }
  const labels = { off: '', allow: '', deny: '' }
  const cycle = () => {
    const next = state === 'off' ? 'allow' : state === 'allow' ? 'deny' : 'off'
    onChange(next)
  }
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      {state === 'deny' && (
        <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--danger)', textTransform: 'uppercase' }}>Deny</span>
      )}
      <button
        onClick={cycle}
        title={state === 'off' ? 'Click to allow' : state === 'allow' ? 'Click to deny' : 'Click to unset'}
        style={{
          width: 36, height: 20, borderRadius: 999,
          background: colors[state],
          border: 'none', cursor: 'pointer', position: 'relative',
          transition: 'background 0.15s',
        }}
      >
        <span style={{
          position: 'absolute', top: 2,
          left: state === 'off' ? 2 : state === 'allow' ? 18 : 18,
          width: 16, height: 16, borderRadius: '50%', background: '#fff',
          transition: 'left 0.15s',
        }} />
      </button>
    </div>
  )
}

function RoleCard({ role, selected, onClick }) {
  return (
    <div
      onClick={onClick}
      style={{
        padding: '10px 14px', borderRadius: 8, cursor: 'pointer', marginBottom: 4,
        background: selected ? 'var(--text)' : 'var(--bg-card)',
        color: selected ? 'var(--bg-card)' : 'inherit',
        border: `1px solid ${selected ? 'var(--text)' : 'var(--border)'}`,
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      }}
    >
      <div>
        <div style={{ fontWeight: 600, fontSize: 13 }}>{role.name}</div>
        {role.description && (
          <div style={{ fontSize: 11, opacity: 0.6, marginTop: 2 }}>{role.description}</div>
        )}
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{
          fontSize: 11, padding: '2px 7px', borderRadius: 999,
          background: selected ? 'rgba(255,255,255,0.15)' : 'var(--bg-muted)',
          color: selected ? 'var(--bg-card)' : 'var(--text-muted)',
        }}>
          {role.member_count} {role.member_count === 1 ? 'user' : 'users'}
        </span>
        {!role.is_active && (
          <span style={{ fontSize: 10, color: 'var(--danger)', fontWeight: 600 }}>INACTIVE</span>
        )}
        <ChevronRight size={14} style={{ opacity: 0.5 }} />
      </div>
    </div>
  )
}

function TagPermissionRow({ perm, onRemove, canEdit }) {
  const isWrite = perm.permission === 'write'
  const isDeny = perm.effect === 'deny'
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 8, padding: '6px 10px',
      borderRadius: 6, background: isDeny ? 'var(--danger-subtle)' : 'var(--bg-muted)',
      border: `1px solid ${isDeny ? 'var(--danger)' : 'var(--border)'}`, marginBottom: 4,
    }}>
      {isDeny && (
        <span style={{
          fontSize: 11, fontWeight: 600, padding: '2px 7px', borderRadius: 999,
          background: 'var(--danger-subtle)', color: 'var(--danger)',
        }}>
          DENY
        </span>
      )}
      <span style={{
        fontSize: 11, fontWeight: 600, padding: '2px 7px', borderRadius: 999,
        background: isWrite ? '#fef3c7' : '#f0fdf4',
        color: isWrite ? '#92400e' : '#166534',
      }}>
        {isWrite ? 'WRITE' : 'READ'}
      </span>
      <span style={{ fontSize: 12, flex: 1 }}>{perm.target_label}</span>
      {canEdit && (
        <button
          onClick={() => onRemove(perm.id)}
          style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--danger)', padding: 2 }}
        >
          <X size={12} />
        </button>
      )}
    </div>
  )
}

export default function RoleManager() {
  const { isAdmin, isSuperadmin, user: currentUser } = useAuth()
  const confirm = useConfirm()
  const toast = useToast()
  const [roles, setRoles] = useState([])
  const [selectedRole, setSelectedRole] = useState(null)
  const [users, setUsers] = useState([])
  const [userRoles, setUserRoles] = useState([])  // custom roles of selected user
  const [tags, setTags] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  // Create role form
  const [showCreate, setShowCreate] = useState(false)
  const [createForm, setCreateForm] = useState({ name: '', description: '' })
  const [createLoading, setCreateLoading] = useState(false)

  // Edit name/description inline
  const [editing, setEditing] = useState(false)
  const [editForm, setEditForm] = useState({ name: '', description: '' })

  // Add tag permission form
  const [showAddPerm, setShowAddPerm] = useState(false)
  const [permForm, setPermForm] = useState({ target_type: 'category', target_id: '', target_category: '', permission: 'read', effect: 'allow' })

  // Member management
  const [showAddMember, setShowAddMember] = useState(false)
  const [memberSearch, setMemberSearch] = useState('')
  const [memberRoles, setMemberRoles] = useState({})  // userId -> [roleId]

  const canEdit = isAdmin || isSuperadmin

  const fetchRoles = async () => {
    try {
      const data = await authListRoles()
      setRoles(data)
      if (selectedRole) {
        const updated = data.find(r => r.id === selectedRole.id)
        if (updated) setSelectedRole(updated)
      }
    } catch (e) {
      setError(e.message)
    }
  }

  useEffect(() => {
    setLoading(true)
    Promise.all([
      authListRoles(),
      isAdmin ? authListUsers() : Promise.resolve([]),
      getTags(),
    ]).then(([rolesData, usersData, tagsData]) => {
      setRoles(rolesData)
      setUsers(usersData)
      // API returns flat array of tag objects
      setTags(Array.isArray(tagsData) ? tagsData : [])
    }).catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [isAdmin])

  // Load per-user custom-role assignments for the members tab
  useEffect(() => {
    if (!selectedRole || users.length === 0) return
    const map = {}
    Promise.all(
      users.map(u =>
        authGetUserCustomRoles(u.id)
          .then(roles => { map[u.id] = roles.map(r => r.id) })
          .catch(() => { map[u.id] = [] })
      )
    ).then(() => setMemberRoles({ ...map }))
  }, [selectedRole, users])

  const handleCreate = async (e) => {
    e.preventDefault()
    setCreateLoading(true)
    try {
      const role = await authCreateRole({ name: createForm.name, description: createForm.description, base_permissions: {} })
      setRoles(prev => [...prev, role])
      setSelectedRole(role)
      toast.success('Role created')
      setShowCreate(false)
      setCreateForm({ name: '', description: '' })
    } catch (err) {
      setError(err.message)
    } finally {
      setCreateLoading(false)
    }
  }

  const handleSaveEdit = async () => {
    try {
      const updated = await authUpdateRole(selectedRole.id, editForm)
      setRoles(prev => prev.map(r => r.id === updated.id ? updated : r))
      setSelectedRole(updated)
      toast.success('Role updated')
      setEditing(false)
    } catch (err) {
      setError(err.message)
    }
  }

  const handleToggleActive = async () => {
    try {
      const updated = await authUpdateRole(selectedRole.id, { is_active: !selectedRole.is_active })
      setRoles(prev => prev.map(r => r.id === updated.id ? updated : r))
      setSelectedRole(updated)
    } catch (err) {
      setError(err.message)
    }
  }

  const handleDeleteRole = async () => {
    if (!await confirm(`Delete role "${selectedRole.name}"? This will remove it from all assigned users.`)) return
    try {
      await authDeleteRole(selectedRole.id)
      setRoles(prev => prev.filter(r => r.id !== selectedRole.id))
      setSelectedRole(null)
      toast.success('Role deleted')
    } catch (err) {
      setError(err.message)
    }
  }

  const handleSetPermState = async (key, newState) => {
    // newState: "off" | "allow" | "deny"
    const basePerms = { ...(selectedRole.base_permissions || {}) }
    const denyPerms = { ...(selectedRole.deny_permissions || {}) }

    if (newState === 'allow') {
      basePerms[key] = true
      delete denyPerms[key]
    } else if (newState === 'deny') {
      delete basePerms[key]
      denyPerms[key] = true
    } else {
      delete basePerms[key]
      delete denyPerms[key]
    }

    const updated = await authUpdateRole(selectedRole.id, {
      base_permissions: basePerms,
      deny_permissions: denyPerms,
    })
    setRoles(prev => prev.map(r => r.id === updated.id ? updated : r))
    setSelectedRole(updated)
  }

  const getPermState = (key) => {
    if ((selectedRole.deny_permissions || {})[key]) return 'deny'
    if ((selectedRole.base_permissions || {})[key]) return 'allow'
    return 'off'
  }

  const handleAddTagPerm = async (e) => {
    e.preventDefault()
    try {
      const payload = {
        target_type: permForm.target_type,
        permission: permForm.permission,
        effect: permForm.effect,
      }
      if (permForm.target_type === 'tag') {
        payload.target_id = parseInt(permForm.target_id)
      } else {
        payload.target_category = permForm.target_category
      }
      const updated = await authAddTagPermission(selectedRole.id, payload)
      setRoles(prev => prev.map(r => r.id === updated.id ? updated : r))
      setSelectedRole(updated)
      setShowAddPerm(false)
      setPermForm({ target_type: 'category', target_id: '', target_category: '', permission: 'read', effect: 'allow' })
    } catch (err) {
      setError(err.message)
    }
  }

  const handleRemoveTagPerm = async (permId) => {
    try {
      const updated = await authRemoveTagPermission(selectedRole.id, permId)
      setRoles(prev => prev.map(r => r.id === updated.id ? updated : r))
      setSelectedRole(updated)
    } catch (err) {
      setError(err.message)
    }
  }

  const handleToggleMember = async (u) => {
    const has = memberRoles[u.id]?.includes(selectedRole.id)
    try {
      if (has) {
        await authUnassignCustomRole(u.id, selectedRole.id)
        setMemberRoles(prev => ({ ...prev, [u.id]: (prev[u.id] || []).filter(id => id !== selectedRole.id) }))
      } else {
        await authAssignCustomRole(u.id, selectedRole.id)
        setMemberRoles(prev => ({ ...prev, [u.id]: [...(prev[u.id] || []), selectedRole.id] }))
      }
      await fetchRoles()
    } catch (err) {
      setError(err.message)
    }
  }

  // Unique tag categories from all tags
  const categories = [...new Set(tags.map(t => t.category))].sort()
  const filteredUsers = users.filter(u =>
    !memberSearch || u.display_name?.toLowerCase().includes(memberSearch.toLowerCase()) ||
    u.email.toLowerCase().includes(memberSearch.toLowerCase())
  )

  const inputStyle = {
    width: '100%', padding: '7px 10px', borderRadius: 8,
    border: '1px solid var(--border)', fontSize: 13, boxSizing: 'border-box',
    background: 'var(--bg-card)', color: 'var(--text-primary)',
  }

  if (loading) return <div style={{ padding: 40, color: 'var(--text-muted)', textAlign: 'center' }}>Loading roles...</div>

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Shield size={18} />
          <h2 style={{ fontSize: 18, fontWeight: 700, margin: 0 }}>Role Manager</h2>
        </div>
        {canEdit && (
          <button
            onClick={() => setShowCreate(true)}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              padding: '6px 14px', borderRadius: 8, border: 'none',
              background: 'var(--accent)', color: '#fff', fontSize: 13, fontWeight: 600, cursor: 'pointer',
            }}
          >
            <Plus size={14} /> New Role
          </button>
        )}
      </div>

      {error && (
        <div style={{ background: 'var(--danger-subtle)', color: 'var(--danger)', padding: '8px 12px', borderRadius: 6, fontSize: 13, marginBottom: 12, border: '1px solid var(--danger)' }}>
          {error}
          <button onClick={() => setError('')} style={{ float: 'right', background: 'none', border: 'none', cursor: 'pointer' }}>x</button>
        </div>
      )}

      {/* Create form */}
      {showCreate && (
        <form onSubmit={handleCreate} style={{
          background: 'var(--bg-muted)', border: '1px solid var(--border)', borderRadius: 10,
          padding: 16, marginBottom: 16, display: 'flex', gap: 10, alignItems: 'flex-end',
        }}>
          <div style={{ flex: 1 }}>
            <label style={{ fontSize: 12, fontWeight: 500 }}>Role Name *</label>
            <input
              autoFocus type="text" required value={createForm.name}
              onChange={e => setCreateForm(p => ({ ...p, name: e.target.value }))}
              style={inputStyle} placeholder="e.g. Network Analyst"
            />
          </div>
          <div style={{ flex: 2 }}>
            <label style={{ fontSize: 12, fontWeight: 500 }}>Description</label>
            <input
              type="text" value={createForm.description}
              onChange={e => setCreateForm(p => ({ ...p, description: e.target.value }))}
              style={inputStyle} placeholder="Optional description"
            />
          </div>
          <button type="submit" disabled={createLoading}
            style={{ padding: '7px 16px', borderRadius: 8, border: 'none', background: 'var(--accent)', color: '#fff', fontSize: 13, fontWeight: 600, cursor: 'pointer', whiteSpace: 'nowrap' }}>
            {createLoading ? 'Creating...' : 'Create'}
          </button>
          <button type="button" onClick={() => setShowCreate(false)}
            style={{ padding: '7px 12px', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--bg-card)', color: 'var(--text-primary)', fontSize: 13, cursor: 'pointer' }}>
            Cancel
          </button>
        </form>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '280px 1fr', gap: 16, alignItems: 'start' }}>
        {/* Role list */}
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 10, padding: 12 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>
            {roles.length} role{roles.length !== 1 ? 's' : ''}
          </div>
          {roles.length === 0 && (
            <div style={{ fontSize: 13, color: 'var(--text-muted)', padding: '20px 0', textAlign: 'center' }}>
              No custom roles yet.<br />Create one to get started.
            </div>
          )}
          {roles.map(role => (
            <RoleCard
              key={role.id}
              role={role}
              selected={selectedRole?.id === role.id}
              onClick={() => { setSelectedRole(role); setEditing(false); setShowAddPerm(false) }}
            />
          ))}
        </div>

        {/* Role detail */}
        {selectedRole ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {/* Header */}
            <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 10, padding: 16 }}>
              {editing ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <div>
                    <label style={{ fontSize: 12, fontWeight: 500 }}>Name</label>
                    <input value={editForm.name} onChange={e => setEditForm(p => ({ ...p, name: e.target.value }))}
                      style={inputStyle} />
                  </div>
                  <div>
                    <label style={{ fontSize: 12, fontWeight: 500 }}>Description</label>
                    <input value={editForm.description} onChange={e => setEditForm(p => ({ ...p, description: e.target.value }))}
                      style={inputStyle} />
                  </div>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button onClick={handleSaveEdit}
                      style={{ padding: '6px 14px', borderRadius: 8, border: 'none', background: 'var(--accent)', color: '#fff', fontSize: 13, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4 }}>
                      <Check size={13} /> Save
                    </button>
                    <button onClick={() => setEditing(false)}
                      style={{ padding: '6px 12px', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--bg-card)', color: 'var(--text-primary)', fontSize: 13, cursor: 'pointer' }}>
                      Cancel
                    </button>
                  </div>
                </div>
              ) : (
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <div style={{ fontSize: 16, fontWeight: 700 }}>{selectedRole.name}</div>
                      {!selectedRole.is_active && (
                        <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--danger)', background: 'var(--danger-subtle)', padding: '2px 7px', borderRadius: 999 }}>INACTIVE</span>
                      )}
                    </div>
                    {selectedRole.description && (
                      <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 4 }}>{selectedRole.description}</div>
                    )}
                  </div>
                  {canEdit && (
                    <div style={{ display: 'flex', gap: 6 }}>
                      <button
                        onClick={() => { setEditForm({ name: selectedRole.name, description: selectedRole.description || '' }); setEditing(true) }}
                        style={{ padding: '5px 10px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-card)', color: 'var(--text-primary)', fontSize: 12, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4 }}>
                        <Pencil size={12} /> Edit
                      </button>
                      <button onClick={handleToggleActive}
                        style={{ padding: '5px 10px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-card)', color: 'var(--text-primary)', fontSize: 12, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4 }}>
                        {selectedRole.is_active ? <Lock size={12} /> : <Unlock size={12} />}
                        {selectedRole.is_active ? 'Deactivate' : 'Activate'}
                      </button>
                      <button onClick={handleDeleteRole}
                        style={{ padding: '5px 10px', borderRadius: 6, border: '1px solid var(--danger)', background: 'var(--bg-card)', fontSize: 12, cursor: 'pointer', color: 'var(--danger)', display: 'flex', alignItems: 'center', gap: 4 }}>
                        <Trash2 size={12} /> Delete
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Permissions */}
            {PERMISSION_SECTIONS.map(section => (
            <div key={section.label} style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 10, padding: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 6 }}>
                <Shield size={14} /> {section.label}
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                {section.items.map(({ key, label }) => (
                  <div key={key} style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                    padding: '6px 10px', borderRadius: 6,
                    background: getPermState(key) === 'deny' ? 'var(--danger-subtle)' : getPermState(key) === 'allow' ? 'var(--success-subtle, #f0fdf4)' : 'var(--bg-muted)',
                    border: `1px solid ${getPermState(key) === 'deny' ? 'var(--danger)' : 'var(--border)'}`,
                  }}>
                    <span style={{ fontSize: 12 }}>{label}</span>
                    <TriStateToggle
                      state={getPermState(key)}
                      onChange={canEdit ? (s) => handleSetPermState(key, s) : () => {}}
                    />
                  </div>
                ))}
              </div>
            </div>
            ))}

            {/* Tag permissions */}
            <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 10, padding: 16 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
                <div style={{ fontSize: 13, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Tag size={14} /> Tag Permissions
                </div>
                {canEdit && (
                  <button onClick={() => setShowAddPerm(v => !v)}
                    style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '4px 10px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-card)', color: 'var(--text-primary)', fontSize: 12, cursor: 'pointer' }}>
                    <Plus size={12} /> Add
                  </button>
                )}
              </div>

              {showAddPerm && canEdit && (
                <form onSubmit={handleAddTagPerm} style={{
                  background: 'var(--bg-muted)', border: '1px solid var(--border)', borderRadius: 8, padding: 12, marginBottom: 12,
                  display: 'grid', gridTemplateColumns: 'auto 1fr auto auto', gap: 8, alignItems: 'end',
                }}>
                  <div>
                    <label style={{ fontSize: 12, fontWeight: 500 }}>Scope</label>
                    <select value={permForm.target_type} onChange={e => setPermForm(p => ({ ...p, target_type: e.target.value }))} style={{ ...inputStyle, width: 'auto' }}>
                      <option value="category">Category</option>
                      <option value="tag">Specific Tag</option>
                    </select>
                  </div>
                  <div>
                    <label style={{ fontSize: 12, fontWeight: 500 }}>
                      {permForm.target_type === 'category' ? 'Category' : 'Tag'}
                    </label>
                    {permForm.target_type === 'category' ? (
                      <select value={permForm.target_category} onChange={e => setPermForm(p => ({ ...p, target_category: e.target.value }))} required style={inputStyle}>
                        <option value="">Select category...</option>
                        {categories.map(c => <option key={c} value={c}>{c}</option>)}
                      </select>
                    ) : (
                      <select value={permForm.target_id} onChange={e => setPermForm(p => ({ ...p, target_id: e.target.value }))} required style={inputStyle}>
                        <option value="">Select tag...</option>
                        {tags.map(t => <option key={t.id} value={t.id}>{t.category}:{t.value}</option>)}
                      </select>
                    )}
                  </div>
                  <div>
                    <label style={{ fontSize: 12, fontWeight: 500 }}>Access</label>
                    <select value={permForm.permission} onChange={e => setPermForm(p => ({ ...p, permission: e.target.value }))} style={{ ...inputStyle, width: 'auto' }}>
                      <option value="read">Read</option>
                      <option value="write">Write</option>
                    </select>
                  </div>
                  <div>
                    <label style={{ fontSize: 12, fontWeight: 500 }}>Effect</label>
                    <select value={permForm.effect} onChange={e => setPermForm(p => ({ ...p, effect: e.target.value }))} style={{
                      ...inputStyle, width: 'auto',
                      color: permForm.effect === 'deny' ? 'var(--danger)' : 'inherit',
                      fontWeight: permForm.effect === 'deny' ? 600 : 400,
                    }}>
                      <option value="allow">Allow</option>
                      <option value="deny">Deny</option>
                    </select>
                  </div>
                  <div style={{ gridColumn: '1 / -1', display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
                    <button type="button" onClick={() => setShowAddPerm(false)}
                      style={{ padding: '5px 12px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-card)', color: 'var(--text-primary)', fontSize: 12, cursor: 'pointer' }}>
                      Cancel
                    </button>
                    <button type="submit"
                      style={{
                        padding: '5px 12px', borderRadius: 6, border: 'none', fontSize: 12, fontWeight: 600, cursor: 'pointer',
                        background: permForm.effect === 'deny' ? 'var(--danger)' : 'var(--text)',
                        color: 'var(--bg-card)',
                      }}>
                      {permForm.effect === 'deny' ? 'Add Deny Rule' : 'Add Permission'}
                    </button>
                  </div>
                </form>
              )}

              {(selectedRole.tag_permissions || []).length === 0 ? (
                <div style={{ fontSize: 12, color: 'var(--text-muted)', textAlign: 'center', padding: '12px 0' }}>
                  No tag permissions — add one to restrict access to specific tags or categories.
                </div>
              ) : (
                (selectedRole.tag_permissions || []).map(perm => (
                  <TagPermissionRow key={perm.id} perm={perm} onRemove={handleRemoveTagPerm} canEdit={canEdit} />
                ))
              )}
            </div>

            {/* Members */}
            {isAdmin && (
              <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 10, padding: 16 }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
                  <div style={{ fontSize: 13, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6 }}>
                    <Users size={14} /> Members ({selectedRole.member_count})
                  </div>
                  <button onClick={() => setShowAddMember(v => !v)}
                    style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '4px 10px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-card)', color: 'var(--text-primary)', fontSize: 12, cursor: 'pointer' }}>
                    <Plus size={12} /> Assign Users
                  </button>
                </div>

                {showAddMember && (
                  <div style={{ marginBottom: 12 }}>
                    <input
                      placeholder="Search users..."
                      value={memberSearch}
                      onChange={e => setMemberSearch(e.target.value)}
                      style={{ ...inputStyle, marginBottom: 8 }}
                    />
                    <div style={{ maxHeight: 220, overflowY: 'auto', border: '1px solid var(--border)', borderRadius: 8 }}>
                      {filteredUsers.map(u => {
                        const has = memberRoles[u.id]?.includes(selectedRole.id)
                        return (
                          <div key={u.id} style={{
                            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                            padding: '8px 12px', borderBottom: '1px solid var(--border)',
                            background: has ? 'var(--success-subtle, #f0fdf4)' : 'var(--bg-card)',
                          }}>
                            <div>
                              <div style={{ fontSize: 13, fontWeight: 500 }}>{u.display_name}</div>
                              <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{u.email} · {u.role}</div>
                            </div>
                            <button
                              onClick={() => handleToggleMember(u)}
                              style={{
                                padding: '4px 10px', borderRadius: 6, fontSize: 12, cursor: 'pointer', fontWeight: 600,
                                border: has ? '1px solid #bbf7d0' : '1px solid var(--border)',
                                background: has ? '#dcfce7' : 'var(--bg-card)',
                                color: has ? '#166534' : 'var(--text-primary)',
                                display: 'flex', alignItems: 'center', gap: 4,
                              }}
                            >
                              {has ? <><Check size={11} /> Assigned</> : 'Assign'}
                            </button>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                )}

                {/* List current members inline */}
                {!showAddMember && (
                  <div>
                    {users.filter(u => memberRoles[u.id]?.includes(selectedRole.id)).length === 0 ? (
                      <div style={{ fontSize: 12, color: 'var(--text-muted)', textAlign: 'center', padding: '12px 0' }}>No users assigned yet.</div>
                    ) : (
                      users.filter(u => memberRoles[u.id]?.includes(selectedRole.id)).map(u => (
                        <div key={u.id} style={{
                          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                          padding: '6px 0', borderBottom: '1px solid var(--border)',
                        }}>
                          <div>
                            <span style={{ fontSize: 13, fontWeight: 500 }}>{u.display_name}</span>
                            <span style={{ fontSize: 11, color: 'var(--text-muted)', marginLeft: 8 }}>{u.email}</span>
                          </div>
                          {canEdit && (
                            <button onClick={() => handleToggleMember(u)}
                              style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--danger)', fontSize: 12, display: 'flex', alignItems: 'center', gap: 4 }}>
                              <X size={12} /> Remove
                            </button>
                          )}
                        </div>
                      ))
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        ) : (
          <div style={{
            background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 10, padding: 40,
            textAlign: 'center', color: 'var(--text-muted)',
          }}>
            <Shield size={32} style={{ opacity: 0.3, marginBottom: 8 }} />
            <div style={{ fontSize: 13 }}>Select a role to view and edit its permissions</div>
          </div>
        )}
      </div>
    </div>
  )
}
