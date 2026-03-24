import React, { useState, useEffect } from 'react'
import { useAuth } from '../../contexts/AuthContext.jsx'
import {
  authListOrgs, authCreateOrg, authUpdateOrg, authDeleteOrg,
  authMSSPClients, adminOverrideSubscription,
} from '../../api.js'
import { Plus, Pencil, Trash2, X } from 'lucide-react'
import { useConfirm } from '../shared/ui.jsx'

function EditOrgDialog({ org, onClose, onSave }) {
  const [form, setForm] = useState({
    name: org.name,
    is_active: org.is_active,
    subscription_tier: org.subscription_tier || 'free',
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      // Name / active status via authUpdateOrg
      const updated = await authUpdateOrg(org.id, {
        name: form.name,
        is_active: form.is_active,
      })
      // Plan override if changed
      let finalOrg = { ...updated, subscription_tier: org.subscription_tier, subscription_status: org.subscription_status }
      if (form.subscription_tier !== (org.subscription_tier || 'free')) {
        const planResult = await adminOverrideSubscription(org.id, form.subscription_tier)
        finalOrg.subscription_tier = planResult.subscription_tier
        finalOrg.subscription_status = planResult.subscription_status
      }
      onSave(finalOrg)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const inputStyle = {
    width: '100%', padding: '7px 10px', borderRadius: 8,
    border: '1px solid var(--border)', fontSize: 13, boxSizing: 'border-box',
    background: 'var(--bg-card)', color: 'var(--text-primary)',
  }

  const labelStyle = { fontSize: 12, fontWeight: 500, display: 'block', marginBottom: 4, color: 'var(--text-secondary)' }

  return (
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.4)', zIndex: 1000,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }} onClick={onClose}>
      <div style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 12,
        padding: 24, width: 400, maxWidth: '90vw', boxShadow: '0 8px 32px rgba(0,0,0,0.2)',
      }} onClick={e => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
          <div>
            <div style={{ fontWeight: 600, fontSize: 15 }}>Edit Organization</div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2, fontFamily: 'monospace' }}>{org.slug}</div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-secondary)', display: 'flex' }}>
            <X size={18} />
          </button>
        </div>

        {error && (
          <div style={{ background: 'var(--danger-subtle)', color: 'var(--danger)', padding: '8px 12px', borderRadius: 6, fontSize: 13, marginBottom: 16, border: '1px solid var(--danger)' }}>
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div>
            <label style={labelStyle}>Name</label>
            <input
              type="text"
              value={form.name}
              onChange={e => setForm(p => ({ ...p, name: e.target.value }))}
              required
              style={inputStyle}
            />
          </div>

          <div>
            <label style={labelStyle}>Status</label>
            <select value={form.is_active ? 'active' : 'disabled'} onChange={e => setForm(p => ({ ...p, is_active: e.target.value === 'active' }))} style={inputStyle}>
              <option value="active">Active</option>
              <option value="disabled">Disabled</option>
            </select>
          </div>

          <div>
            <label style={labelStyle}>Plan</label>
            <select value={form.subscription_tier} onChange={e => setForm(p => ({ ...p, subscription_tier: e.target.value }))} style={inputStyle}>
              <option value="free">Free</option>
              <option value="pro">Pro</option>
            </select>
          </div>

          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 4 }}>
            <button type="button" onClick={onClose} style={{
              padding: '7px 16px', borderRadius: 8, border: '1px solid var(--border)',
              background: 'var(--bg-card)', color: 'var(--text-secondary)', fontSize: 13, cursor: 'pointer',
            }}>
              Cancel
            </button>
            <button type="submit" disabled={loading} style={{
              padding: '7px 16px', borderRadius: 8, border: 'none',
              background: 'var(--nav-active-bg)', color: 'var(--nav-active-text)', fontSize: 13, fontWeight: 600, cursor: 'pointer',
            }}>
              {loading ? 'Saving…' : 'Save'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

export default function OrgsPanel() {
  const { isSuperadmin, isMSSP, org } = useAuth()
  const confirm = useConfirm()
  const [orgs, setOrgs] = useState([])
  const [msspClients, setMsspClients] = useState([])
  const [showCreateOrg, setShowCreateOrg] = useState(false)
  const [orgForm, setOrgForm] = useState({ name: '', org_type: 'standard' })
  const [editingOrg, setEditingOrg] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [view, setView] = useState(isSuperadmin ? 'orgs' : 'clients')

  useEffect(() => {
    if (isSuperadmin) authListOrgs().then(setOrgs).catch(() => {})
    if (isMSSP) authMSSPClients().then(setMsspClients).catch(() => {})
  }, [isSuperadmin, isMSSP])

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

  const handleEditSave = (updated) => {
    setOrgs(prev => prev.map(x => x.id === updated.id ? { ...x, ...updated } : x))
    setEditingOrg(null)
  }

  const handleDeleteOrg = async (o) => {
    if (!await confirm(`Delete organization "${o.name}" and ALL its users? This cannot be undone.`)) return
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

  const showBothViews = isSuperadmin && isMSSP

  return (
    <div>
      {editingOrg && (
        <EditOrgDialog
          org={editingOrg}
          onClose={() => setEditingOrg(null)}
          onSave={handleEditSave}
        />
      )}

      {error && (
        <div style={{ background: 'var(--danger-subtle)', color: 'var(--danger)', padding: '8px 12px', borderRadius: 6, fontSize: 13, marginBottom: 12, border: '1px solid var(--danger)' }}>
          {error}
          <button onClick={() => setError('')} style={{ float: 'right', background: 'none', border: 'none', cursor: 'pointer', fontSize: 13 }}>x</button>
        </div>
      )}

      {showBothViews && (
        <div style={{ display: 'flex', gap: 4, marginBottom: 16, borderBottom: '1px solid var(--border)' }}>
          {['orgs', 'clients'].map(v => (
            <button
              key={v}
              onClick={() => setView(v)}
              style={{
                padding: '8px 16px', border: 'none', cursor: 'pointer',
                borderBottom: view === v ? '2px solid var(--text-primary)' : '2px solid transparent',
                background: 'none', fontSize: 13, fontWeight: view === v ? 600 : 400,
                color: view === v ? 'var(--text-primary)' : 'var(--text-secondary)',
              }}
            >
              {v === 'orgs' ? 'Organizations' : 'MSSP Clients'}
            </button>
          ))}
        </div>
      )}

      {/* Organizations */}
      {(isSuperadmin && (!showBothViews || view === 'orgs')) && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>{orgs.length} organization{orgs.length !== 1 ? 's' : ''}</div>
            <button
              onClick={() => setShowCreateOrg(!showCreateOrg)}
              style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '6px 14px', borderRadius: 8, border: 'none',
                background: 'var(--nav-active-bg)', color: 'var(--nav-active-text)', fontSize: 13, fontWeight: 600, cursor: 'pointer',
              }}
            >
              <Plus size={14} /> New Organization
            </button>
          </div>

          {showCreateOrg && (
            <form onSubmit={handleCreateOrg} style={{
              background: 'var(--bg-muted)', border: '1px solid var(--border)', borderRadius: 10, padding: 16, marginBottom: 16,
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
              <button type="submit" disabled={loading} style={{ padding: '7px 14px', borderRadius: 8, border: 'none', background: 'var(--nav-active-bg)', color: 'var(--nav-active-text)', fontSize: 13, fontWeight: 600, cursor: 'pointer', whiteSpace: 'nowrap' }}>
                Create
              </button>
            </form>
          )}

          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 10, overflow: 'hidden' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)', background: 'var(--bg-muted)' }}>
                  <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600 }}>Name</th>
                  <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600 }}>Slug</th>
                  <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600 }}>Type</th>
                  <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600 }}>Status</th>
                  <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600 }}>Plan</th>
                  <th style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600 }}>Created</th>
                  {isSuperadmin && <th style={{ textAlign: 'right', padding: '8px 12px', fontWeight: 600 }}>Actions</th>}
                </tr>
              </thead>
              <tbody>
                {orgs.map(o => (
                  <tr key={o.id} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={{ padding: '8px 12px', fontWeight: 500 }}>{o.name}</td>
                    <td style={{ padding: '8px 12px', color: 'var(--text-secondary)', fontFamily: 'monospace', fontSize: 12 }}>{o.slug}</td>
                    <td style={{ padding: '8px 12px' }}>
                      <span style={{
                        fontSize: 11, fontWeight: 600, padding: '2px 8px', borderRadius: 999,
                        background: o.org_type === 'mssp' ? 'rgba(109,40,217,0.1)' : 'var(--success-subtle)',
                        color: o.org_type === 'mssp' ? '#6d28d9' : 'var(--success)',
                      }}>
                        {o.org_type === 'mssp' ? 'MSSP' : 'Standard'}
                      </span>
                    </td>
                    <td style={{ padding: '8px 12px', fontSize: 11, color: o.is_active ? 'var(--success)' : 'var(--danger)' }}>
                      {o.is_active ? 'Active' : 'Disabled'}
                    </td>
                    <td style={{ padding: '8px 12px' }}>
                      <span style={{
                        fontSize: 11, fontWeight: 600, padding: '2px 8px', borderRadius: 999,
                        background: (o.subscription_tier || 'free') === 'pro' ? 'rgba(234,179,8,0.15)' : 'var(--bg-muted)',
                        color: (o.subscription_tier || 'free') === 'pro' ? '#b45309' : 'var(--text-secondary)',
                      }}>
                        {(o.subscription_tier || 'free').toUpperCase()}
                      </span>
                    </td>
                    <td style={{ padding: '8px 12px', fontSize: 12, color: 'var(--text-secondary)' }}>
                      {o.created_at ? new Date(o.created_at).toLocaleDateString() : '—'}
                    </td>
                    {isSuperadmin && (
                      <td style={{ padding: '8px 12px', textAlign: 'right' }}>
                        <div style={{ display: 'flex', gap: 4, justifyContent: 'flex-end' }}>
                          <button
                            onClick={() => setEditingOrg(o)}
                            title="Edit organization"
                            style={{
                              fontSize: 12, padding: '3px 8px', borderRadius: 6,
                              border: '1px solid var(--border)', background: 'var(--bg-card)', cursor: 'pointer',
                              display: 'flex', alignItems: 'center', gap: 4, color: 'var(--text-secondary)',
                            }}
                          >
                            <Pencil size={12} />
                          </button>
                          {o.id !== org?.id && (
                            <button
                              onClick={() => handleDeleteOrg(o)}
                              title="Delete organization"
                              style={{
                                fontSize: 12, padding: '3px 8px', borderRadius: 6,
                                border: '1px solid var(--danger)', background: 'var(--bg-card)', cursor: 'pointer',
                                color: 'var(--danger)', display: 'flex', alignItems: 'center',
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

      {/* MSSP Clients */}
      {(isMSSP && (!showBothViews || view === 'clients')) && (
        <div>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 12 }}>{msspClients.length} client org{msspClients.length !== 1 ? 's' : ''}</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 12 }}>
            {msspClients.map(c => (
              <div key={c.id} style={{
                background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 10, padding: 16,
              }}>
                <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 6 }}>{c.name}</div>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 8 }}>/{c.slug}</div>
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
