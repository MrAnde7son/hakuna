import React, { useState, useEffect } from 'react'
import { useAuth } from '../../contexts/AuthContext.jsx'
import {
  authListOrgs, authCreateOrg, authUpdateOrg, authDeleteOrg,
  authMSSPClients, adminOverrideSubscription,
} from '../../api.js'
import { Plus, Pencil, Trash2 } from 'lucide-react'

export default function OrgsPanel() {
  const { isSuperadmin, isMSSP, org } = useAuth()
  const [orgs, setOrgs] = useState([])
  const [msspClients, setMsspClients] = useState([])
  const [showCreateOrg, setShowCreateOrg] = useState(false)
  const [orgForm, setOrgForm] = useState({ name: '', org_type: 'standard' })
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

  const handleTogglePlan = async (o) => {
    const newTier = (o.subscription_tier || 'free') === 'pro' ? 'free' : 'pro'
    try {
      const updated = await adminOverrideSubscription(o.id, newTier)
      setOrgs(prev => prev.map(x => x.id === o.id ? { ...x, subscription_tier: updated.subscription_tier, subscription_status: updated.subscription_status } : x))
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

  const showBothViews = isSuperadmin && isMSSP

  return (
    <div>
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
                            onClick={() => handleRenameOrg(o)}
                            title="Rename"
                            style={{
                              fontSize: 12, padding: '3px 8px', borderRadius: 6,
                              border: '1px solid var(--border)', background: 'var(--bg-card)', cursor: 'pointer',
                              display: 'flex', alignItems: 'center', gap: 4, color: 'var(--text-secondary)',
                            }}
                          >
                            <Pencil size={12} />
                          </button>
                          <button
                            onClick={() => handleToggleOrgActive(o)}
                            style={{
                              fontSize: 12, padding: '3px 10px', borderRadius: 6,
                              border: '1px solid var(--border)', background: 'var(--bg-card)', cursor: 'pointer',
                            }}
                          >
                            {o.is_active ? 'Disable' : 'Enable'}
                          </button>
                          <button
                            onClick={() => handleTogglePlan(o)}
                            style={{
                              fontSize: 12, padding: '3px 10px', borderRadius: 6,
                              border: `1px solid ${(o.subscription_tier || 'free') === 'pro' ? 'var(--border)' : 'rgba(234,179,8,0.5)'}`,
                              background: 'var(--bg-card)', cursor: 'pointer',
                              color: (o.subscription_tier || 'free') === 'pro' ? 'var(--text-secondary)' : '#b45309',
                            }}
                          >
                            {(o.subscription_tier || 'free') === 'pro' ? '↓ Free' : '↑ Pro'}
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
