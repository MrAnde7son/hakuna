import React, { useState, useEffect } from 'react'
import { useAuth } from '../../contexts/AuthContext.jsx'
import {
  authListOrgs, authCreateOrg, authUpdateOrg, authDeleteOrg,
  authMSSPClients, adminOverrideSubscription, authMSSPInviteClient,
} from '../../api.js'
import { Plus, Pencil, Trash2, X, Link, Mail, Copy, Check } from 'lucide-react'
import { useConfirm, useToast } from '../shared/ui.jsx'

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

function InviteClientModal({ onClose, onInvited }) {
  const [form, setForm] = useState({ invited_email: '', client_org_name: '' })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState(null)
  const [copied, setCopied] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const data = await authMSSPInviteClient({
        invited_email: form.invited_email || null,
        client_org_name: form.client_org_name || null,
      })
      setResult(data)
      if (onInvited) onInvited()
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const handleCopy = () => {
    navigator.clipboard.writeText(result.invite_url).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
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
        padding: 24, width: 440, maxWidth: '90vw', boxShadow: '0 8px 32px rgba(0,0,0,0.2)',
      }} onClick={e => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
          <div>
            <div style={{ fontWeight: 600, fontSize: 15 }}>Invite a client</div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>
              Generate a self-serve onboarding link for a new client organization
            </div>
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

        {result ? (
          <div>
            <div style={{
              background: 'var(--success-subtle)', color: 'var(--success)',
              padding: '10px 14px', borderRadius: 8, fontSize: 13, marginBottom: 16,
              border: '1px solid var(--success)',
            }}>
              {result.email_sent
                ? `Invite sent to ${form.invited_email}`
                : 'Invite link generated — share it with your client'}
            </div>

            <label style={labelStyle}>Invite link</label>
            <div style={{ display: 'flex', gap: 8, marginBottom: 20 }}>
              <input
                readOnly
                value={result.invite_url}
                style={{ ...inputStyle, flex: 1, fontFamily: 'monospace', fontSize: 11 }}
                onFocus={e => e.target.select()}
              />
              <button
                onClick={handleCopy}
                style={{
                  padding: '7px 12px', borderRadius: 8, border: '1px solid var(--border)',
                  background: 'var(--bg-card)', cursor: 'pointer',
                  display: 'flex', alignItems: 'center', gap: 4,
                  color: copied ? 'var(--success)' : 'var(--text-secondary)', fontSize: 13,
                  whiteSpace: 'nowrap',
                }}
              >
                {copied ? <Check size={14} /> : <Copy size={14} />}
                {copied ? 'Copied' : 'Copy'}
              </button>
            </div>

            <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 16 }}>
              Expires: {new Date(result.expires_at).toLocaleDateString()}
            </div>

            <button onClick={onClose} style={{
              width: '100%', padding: '8px 0', borderRadius: 8, border: '1px solid var(--border)',
              background: 'var(--bg-card)', color: 'var(--text-secondary)', fontSize: 13, cursor: 'pointer',
            }}>
              Done
            </button>
          </div>
        ) : (
          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div>
              <label style={labelStyle}>Client email <span style={{ fontWeight: 400 }}>(optional — sends invite email if configured)</span></label>
              <div style={{ position: 'relative' }}>
                <Mail size={14} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-secondary)' }} />
                <input
                  type="email"
                  value={form.invited_email}
                  onChange={e => setForm(p => ({ ...p, invited_email: e.target.value }))}
                  placeholder="client@example.com"
                  style={{ ...inputStyle, paddingLeft: 30 }}
                  autoFocus
                />
              </div>
            </div>

            <div>
              <label style={labelStyle}>Organization name <span style={{ fontWeight: 400 }}>(optional — pre-fills registration form)</span></label>
              <input
                type="text"
                value={form.client_org_name}
                onChange={e => setForm(p => ({ ...p, client_org_name: e.target.value }))}
                placeholder="Acme Corp"
                style={inputStyle}
              />
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
                background: 'var(--nav-active-bg)', color: 'var(--nav-active-text)',
                fontSize: 13, fontWeight: 600, cursor: loading ? 'not-allowed' : 'pointer',
                display: 'flex', alignItems: 'center', gap: 6,
              }}>
                <Link size={13} />
                {loading ? 'Generating…' : 'Generate invite link'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  )
}

export default function OrgsPanel() {
  const { isSuperadmin, isMSSP, org } = useAuth()
  const confirm = useConfirm()
  const toast = useToast()
  const [orgs, setOrgs] = useState([])
  const [msspClients, setMsspClients] = useState([])
  const [showCreateOrg, setShowCreateOrg] = useState(false)
  const [showInviteClient, setShowInviteClient] = useState(false)
  const [orgForm, setOrgForm] = useState({ name: '', org_type: 'standard', admin_email: '' })
  const [createResult, setCreateResult] = useState(null)
  const [copiedActivation, setCopiedActivation] = useState(false)
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
      if (orgForm.admin_email && !newOrg.admin_email_sent && newOrg.admin_activation_link) {
        setCreateResult(newOrg)
      } else {
        toast.success('Organization created' + (newOrg.admin_email_sent ? ' — activation email sent' : ''))
        setShowCreateOrg(false)
        setOrgForm({ name: '', org_type: 'standard', admin_email: '' })
      }
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
      toast.success('Organization deleted')
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

      {showInviteClient && (
        <InviteClientModal
          onClose={() => setShowInviteClient(false)}
          onInvited={() => authMSSPClients().then(setMsspClients).catch(() => {})}
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
            <div style={{ background: 'var(--bg-muted)', border: '1px solid var(--border)', borderRadius: 10, padding: 16, marginBottom: 16 }}>
              {createResult ? (
                <div>
                  <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 8 }}>
                    "{createResult.name}" created
                  </div>
                  <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 12 }}>
                    Email couldn't be sent. Share this activation link with the admin:
                  </div>
                  <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
                    <input
                      readOnly
                      value={createResult.admin_activation_link}
                      style={{ ...inputStyle, flex: 1, fontFamily: 'monospace', fontSize: 11 }}
                      onFocus={e => e.target.select()}
                    />
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(createResult.admin_activation_link)
                        setCopiedActivation(true)
                        setTimeout(() => setCopiedActivation(false), 2000)
                      }}
                      style={{ padding: '7px 12px', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--bg-card)', cursor: 'pointer', fontSize: 13, whiteSpace: 'nowrap' }}
                    >
                      {copiedActivation ? 'Copied!' : 'Copy'}
                    </button>
                  </div>
                  <button onClick={() => { setCreateResult(null); setShowCreateOrg(false); setOrgForm({ name: '', org_type: 'standard', admin_email: '' }) }}
                    style={{ padding: '6px 14px', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--bg-card)', fontSize: 13, cursor: 'pointer' }}>
                    Done
                  </button>
                </div>
              ) : (
                <form onSubmit={handleCreateOrg} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                  <div>
                    <label style={{ fontSize: 12, fontWeight: 500 }}>Name</label>
                    <input type="text" value={orgForm.name} onChange={e => setOrgForm(p => ({ ...p, name: e.target.value }))} required style={inputStyle} autoFocus />
                  </div>
                  <div>
                    <label style={{ fontSize: 12, fontWeight: 500 }}>Type</label>
                    <select value={orgForm.org_type} onChange={e => setOrgForm(p => ({ ...p, org_type: e.target.value }))} style={inputStyle}>
                      <option value="standard">Standard</option>
                      <option value="mssp">MSSP</option>
                    </select>
                  </div>
                  <div style={{ gridColumn: '1 / -1' }}>
                    <label style={{ fontSize: 12, fontWeight: 500 }}>Admin email <span style={{ fontWeight: 400, color: 'var(--text-secondary)' }}>(optional — sends activation link)</span></label>
                    <input type="email" value={orgForm.admin_email} onChange={e => setOrgForm(p => ({ ...p, admin_email: e.target.value }))} placeholder="admin@company.com" style={inputStyle} />
                  </div>
                  <div style={{ gridColumn: '1 / -1', display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
                    <button type="button" onClick={() => setShowCreateOrg(false)} style={{ padding: '6px 14px', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--bg-card)', fontSize: 13, cursor: 'pointer' }}>Cancel</button>
                    <button type="submit" disabled={loading} style={{ padding: '7px 14px', borderRadius: 8, border: 'none', background: 'var(--nav-active-bg)', color: 'var(--nav-active-text)', fontSize: 13, fontWeight: 600, cursor: 'pointer', whiteSpace: 'nowrap' }}>
                      {loading ? 'Creating…' : 'Create'}
                    </button>
                  </div>
                </form>
              )}
            </div>
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
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>{msspClients.length} client org{msspClients.length !== 1 ? 's' : ''}</div>
            <button
              onClick={() => setShowInviteClient(true)}
              style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '6px 14px', borderRadius: 8, border: 'none',
                background: 'var(--nav-active-bg)', color: 'var(--nav-active-text)', fontSize: 13, fontWeight: 600, cursor: 'pointer',
              }}
            >
              <Plus size={14} /> Invite Client
            </button>
          </div>
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
