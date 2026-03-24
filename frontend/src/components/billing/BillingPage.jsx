import React, { useState, useEffect } from 'react'
import { useAuth } from '../../contexts/AuthContext.jsx'
import { getBillingPlans, createCheckoutSession, createPortalSession } from '../../api.js'
import { CreditCard, Check, Star, AlertTriangle } from 'lucide-react'
import { useToast } from '../shared/ui.jsx'

const STATUS_COLORS = {
  active: { bg: '#052e16', text: '#86efac', border: '#166534' },
  trialing: { bg: '#1e1b4b', text: '#a5b4fc', border: '#4338ca' },
  past_due: { bg: '#451a03', text: '#fdba74', border: '#92400e' },
  canceled: { bg: '#1c1917', text: '#a8a29e', border: '#44403c' },
  free: { bg: '#0c1a2e', text: '#7dd3fc', border: '#0369a1' },
}

function StatusBadge({ status }) {
  const label = status || 'free'
  const c = STATUS_COLORS[label] || STATUS_COLORS.free
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      background: c.bg, color: c.text, border: `1px solid ${c.border}`,
      borderRadius: 4, padding: '2px 10px', fontSize: 11, fontWeight: 600,
      textTransform: 'uppercase', letterSpacing: '0.05em',
    }}>
      {label.replace('_', ' ')}
    </span>
  )
}

export default function BillingPage() {
  const { org, isAdmin } = useAuth()
  const toast = useToast()
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
        success_url: window.location.origin + '/billing?success=1',
        cancel_url: window.location.origin + '/billing',
      })
      window.location.href = data.checkout_url
    } catch (e) {
      toast.error(e.message || 'Failed to start checkout')
    } finally {
      setLoading(false)
    }
  }

  const handleManage = async () => {
    setLoading(true)
    try {
      const data = await createPortalSession({
        return_url: window.location.origin + '/billing',
      })
      window.location.href = data.portal_url
    } catch (e) {
      toast.error(e.message || 'Failed to open billing portal')
    } finally {
      setLoading(false)
    }
  }

  const isPro = tier === 'pro' && (status === 'active' || status === 'trialing')

  return (
    <div style={{ maxWidth: 900, margin: '0 auto' }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text)', margin: 0 }}>Billing</h1>
        <p style={{ fontSize: 13, color: 'var(--muted)', marginTop: 4 }}>
          Manage your subscription and billing details.
        </p>
      </div>

      {/* Current plan status */}
      <div style={{
        background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 10,
        padding: 20, marginBottom: 24,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
              <CreditCard size={18} color="var(--muted)" />
              <span style={{ fontSize: 15, fontWeight: 600, color: 'var(--text)' }}>
                {isPro ? 'Pro' : 'Free'} Plan
              </span>
              <StatusBadge status={isPro ? status : 'free'} />
            </div>
            {isPro && org?.current_period_end && (
              <div style={{ fontSize: 12, color: 'var(--muted)' }}>
                Next billing date: {new Date(org.current_period_end).toLocaleDateString()}
              </div>
            )}
          </div>
          {isPro && isAdmin && (
            <button
              onClick={handleManage}
              disabled={loading}
              style={{
                padding: '8px 16px', borderRadius: 6, border: '1px solid var(--border)',
                background: 'var(--bg)', color: 'var(--text)', fontSize: 13, fontWeight: 500,
                cursor: 'pointer',
              }}
            >
              Manage Billing
            </button>
          )}
        </div>

        {status === 'past_due' && (
          <div style={{
            marginTop: 14, padding: '10px 14px', borderRadius: 8,
            background: '#451a03', border: '1px solid #92400e',
            display: 'flex', alignItems: 'center', gap: 8,
          }}>
            <AlertTriangle size={16} color="#fdba74" />
            <span style={{ fontSize: 13, color: '#fdba74' }}>
              Your payment failed. Update your payment method to avoid service interruption.
            </span>
            {isAdmin && (
              <button
                onClick={handleManage}
                style={{
                  marginLeft: 'auto', padding: '5px 12px', borderRadius: 5,
                  background: '#92400e', color: '#fdba74', border: 'none',
                  fontSize: 12, fontWeight: 600, cursor: 'pointer',
                }}
              >
                Update Payment Method
              </button>
            )}
          </div>
        )}
      </div>

      {/* Plan cards */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        {/* Free tier */}
        <div style={{
          background: 'var(--bg)', border: `1px solid ${!isPro ? 'var(--accent)' : 'var(--border)'}`,
          borderRadius: 10, padding: 24, position: 'relative',
        }}>
          {!isPro && (
            <div style={{
              position: 'absolute', top: -10, right: 16, background: 'var(--accent)',
              color: '#fff', fontSize: 10, fontWeight: 700, padding: '2px 10px',
              borderRadius: 4, textTransform: 'uppercase',
            }}>
              Current
            </div>
          )}
          <h3 style={{ fontSize: 17, fontWeight: 700, color: 'var(--text)', margin: '0 0 4px' }}>Free</h3>
          <div style={{ fontSize: 28, fontWeight: 800, color: 'var(--text)', marginBottom: 16 }}>
            $0<span style={{ fontSize: 14, fontWeight: 400, color: 'var(--muted)' }}>/mo</span>
          </div>
          <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: 8 }}>
            {(freePlan?.features || ['Dashboard & reports', 'Findings & assets', '3 scans total', '3 users', '3 campaigns', 'Integrations', 'Workflows', 'SBOM & EASM', 'Threat intelligence', 'NLP search']).map(f => (
              <li key={f} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, color: 'var(--text)' }}>
                <Check size={14} color="var(--muted)" /> {f}
              </li>
            ))}
          </ul>
        </div>

        {/* Pro tier */}
        <div style={{
          background: 'var(--bg)', border: `1px solid ${isPro ? 'var(--accent)' : 'var(--border)'}`,
          borderRadius: 10, padding: 24, position: 'relative',
        }}>
          {isPro && (
            <div style={{
              position: 'absolute', top: -10, right: 16, background: 'var(--accent)',
              color: '#fff', fontSize: 10, fontWeight: 700, padding: '2px 10px',
              borderRadius: 4, textTransform: 'uppercase',
            }}>
              Current
            </div>
          )}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
            <Star size={16} color="#f59e0b" />
            <h3 style={{ fontSize: 17, fontWeight: 700, color: 'var(--text)', margin: 0 }}>Pro</h3>
          </div>

          {/* Billing cycle toggle */}
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginBottom: 4 }}>
            <div style={{ fontSize: 28, fontWeight: 800, color: 'var(--text)' }}>
              ${billingCycle === 'annual' ? '167' : '200'}
              <span style={{ fontSize: 14, fontWeight: 400, color: 'var(--muted)' }}>/mo</span>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
            <button
              onClick={() => setBillingCycle('monthly')}
              style={{
                padding: '3px 10px', borderRadius: 4, border: '1px solid var(--border)',
                background: billingCycle === 'monthly' ? 'var(--accent)' : 'transparent',
                color: billingCycle === 'monthly' ? '#fff' : 'var(--muted)',
                fontSize: 11, fontWeight: 600, cursor: 'pointer',
              }}
            >
              Monthly
            </button>
            <button
              onClick={() => setBillingCycle('annual')}
              style={{
                padding: '3px 10px', borderRadius: 4, border: '1px solid var(--border)',
                background: billingCycle === 'annual' ? 'var(--accent)' : 'transparent',
                color: billingCycle === 'annual' ? '#fff' : 'var(--muted)',
                fontSize: 11, fontWeight: 600, cursor: 'pointer',
              }}
            >
              Annual
            </button>
            {billingCycle === 'annual' && (
              <span style={{ fontSize: 11, color: '#22c55e', fontWeight: 600 }}>Save $400/yr</span>
            )}
          </div>

          <ul style={{ listStyle: 'none', padding: 0, margin: '0 0 20px', display: 'flex', flexDirection: 'column', gap: 8 }}>
            {(proPlan?.features || [
              'Everything in Free', 'Unlimited scans', 'Unlimited users',
              'Unlimited campaigns', 'AI agents',
            ]).map(f => (
              <li key={f} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, color: 'var(--text)' }}>
                <Check size={14} color="#22c55e" /> {f}
              </li>
            ))}
          </ul>

          {!isPro && isAdmin && (
            <button
              onClick={handleUpgrade}
              disabled={loading}
              style={{
                width: '100%', padding: '10px 0', borderRadius: 6, border: 'none',
                background: 'var(--accent)', color: '#fff', fontSize: 14, fontWeight: 600,
                cursor: loading ? 'wait' : 'pointer', opacity: loading ? 0.7 : 1,
              }}
            >
              {loading ? 'Redirecting...' : 'Upgrade to Pro'}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
