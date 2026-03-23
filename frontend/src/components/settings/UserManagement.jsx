import React, { useState, useEffect } from 'react'
import { useAuth } from '../../contexts/AuthContext.jsx'
import { authChangePassword, getBillingPlans, createCheckoutSession, createPortalSession } from '../../api.js'
import { KeyRound, CreditCard, Star, Check, AlertTriangle } from 'lucide-react'

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

function SubscriptionSection() {
  const { org, isPro, isAdmin } = useAuth()
  const [plans, setPlans] = useState([])
  const [billingCycle, setBillingCycle] = useState('monthly')
  const [loading, setLoading] = useState(false)

  const tier = org?.subscription_tier || 'free'
  const status = org?.subscription_status

  useEffect(() => {
    getBillingPlans().then(d => setPlans(d.plans || [])).catch(() => {})
  }, [])

  const proPlan = plans.find(p => p.tier === 'pro')
  const freePlan = plans.find(p => p.tier === 'free')

  const handleUpgrade = async () => {
    if (!proPlan) return
    setLoading(true)
    try {
      const priceId = billingCycle === 'annual' ? proPlan.price_id_annual : proPlan.price_id_monthly
      const data = await createCheckoutSession({
        price_id: priceId,
        success_url: window.location.origin + '/profile?success=1',
        cancel_url: window.location.origin + '/profile',
      })
      window.location.href = data.checkout_url
    } catch (e) {
      alert(e.message || 'Failed to start checkout')
    } finally {
      setLoading(false)
    }
  }

  const handleManage = async () => {
    setLoading(true)
    try {
      const data = await createPortalSession({
        return_url: window.location.origin + '/profile',
      })
      window.location.href = data.portal_url
    } catch (e) {
      alert(e.message || 'Failed to open billing portal')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{
      background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 10, padding: 20,
      marginTop: 16,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: isPro ? 0 : 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <CreditCard size={16} />
          <span style={{ fontSize: 14, fontWeight: 600 }}>Subscription</span>
          <span style={{
            display: 'inline-flex', alignItems: 'center', gap: 4,
            padding: '2px 8px', borderRadius: 999, fontSize: 11, fontWeight: 600,
            background: isPro ? 'rgba(37,99,235,0.1)' : 'var(--secondary)',
            color: isPro ? 'var(--primary)' : 'var(--muted)',
          }}>
            {isPro && <Star size={10} />}
            {isPro ? 'Pro' : 'Free'}
          </span>
        </div>
        {isPro && isAdmin && (
          <button onClick={handleManage} disabled={loading} style={{
            padding: '5px 12px', borderRadius: 6, border: '1px solid var(--border)',
            background: 'var(--bg-card)', fontSize: 12, cursor: 'pointer',
          }}>
            Manage Billing
          </button>
        )}
      </div>

      {status === 'past_due' && (
        <div style={{
          margin: '12px 0', padding: '10px 14px', borderRadius: 8,
          background: '#451a03', border: '1px solid #92400e',
          display: 'flex', alignItems: 'center', gap: 8, fontSize: 13,
        }}>
          <AlertTriangle size={14} color="#fdba74" />
          <span style={{ color: '#fdba74', flex: 1 }}>Payment failed. Update your payment method to avoid interruption.</span>
          {isAdmin && <button onClick={handleManage} style={{
            padding: '4px 10px', borderRadius: 5, border: 'none', background: '#92400e',
            color: '#fdba74', fontSize: 11, fontWeight: 600, cursor: 'pointer',
          }}>Fix Payment</button>}
        </div>
      )}

      {isPro && org?.current_period_end && (
        <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 8 }}>
          Next billing date: {new Date(org.current_period_end).toLocaleDateString()}
        </div>
      )}

      {/* Plan comparison — only show when on free tier */}
      {!isPro && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          {/* Free */}
          <div style={{
            border: '1px solid var(--border)', borderRadius: 8, padding: 16,
            background: 'var(--bg)',
          }}>
            <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 8 }}>Free</div>
            <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: 5 }}>
              {(freePlan?.features || ['Dashboard & reports', 'Findings & assets', '3 scans', '3 users', '3 campaigns', 'Integrations', 'Workflows']).map(f => (
                <li key={f} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--text)' }}>
                  <Check size={12} color="var(--muted)" /> {f}
                </li>
              ))}
            </ul>
          </div>

          {/* Pro */}
          <div style={{
            border: '1px solid var(--accent)', borderRadius: 8, padding: 16,
            background: 'var(--bg)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
              <Star size={14} color="#f59e0b" />
              <span style={{ fontSize: 14, fontWeight: 700 }}>Pro</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 4, marginBottom: 4 }}>
              <span style={{ fontSize: 22, fontWeight: 800 }}>${billingCycle === 'annual' ? '167' : '200'}</span>
              <span style={{ fontSize: 12, color: 'var(--muted)' }}>/mo</span>
            </div>
            <div style={{ display: 'flex', gap: 6, marginBottom: 10 }}>
              <button onClick={() => setBillingCycle('monthly')} style={{
                padding: '2px 8px', borderRadius: 4, border: '1px solid var(--border)',
                background: billingCycle === 'monthly' ? 'var(--accent)' : 'transparent',
                color: billingCycle === 'monthly' ? '#fff' : 'var(--muted)',
                fontSize: 10, fontWeight: 600, cursor: 'pointer',
              }}>Monthly</button>
              <button onClick={() => setBillingCycle('annual')} style={{
                padding: '2px 8px', borderRadius: 4, border: '1px solid var(--border)',
                background: billingCycle === 'annual' ? 'var(--accent)' : 'transparent',
                color: billingCycle === 'annual' ? '#fff' : 'var(--muted)',
                fontSize: 10, fontWeight: 600, cursor: 'pointer',
              }}>Annual</button>
              {billingCycle === 'annual' && (
                <span style={{ fontSize: 10, color: '#22c55e', fontWeight: 600 }}>Save $400</span>
              )}
            </div>
            <ul style={{ listStyle: 'none', padding: 0, margin: '0 0 12px', display: 'flex', flexDirection: 'column', gap: 5 }}>
              {(proPlan?.features || ['Everything in Free', 'Unlimited scans', 'Unlimited users', 'Unlimited campaigns', 'AI agents']).map(f => (
                <li key={f} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--text)' }}>
                  <Check size={12} color="#22c55e" /> {f}
                </li>
              ))}
            </ul>
            {isAdmin && (
              <button onClick={handleUpgrade} disabled={loading} style={{
                width: '100%', padding: '8px 0', borderRadius: 6, border: 'none',
                background: 'var(--accent)', color: '#fff', fontSize: 13, fontWeight: 600,
                cursor: loading ? 'wait' : 'pointer', opacity: loading ? 0.7 : 1,
              }}>
                {loading ? 'Redirecting...' : 'Upgrade to Pro'}
              </button>
            )}
          </div>
        </div>
      )}
    </div>
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

      <SubscriptionSection />
    </div>
  )
}
