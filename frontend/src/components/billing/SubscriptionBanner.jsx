import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../../contexts/AuthContext.jsx'
import { AlertTriangle, X, Lock } from 'lucide-react'

export default function SubscriptionBanner() {
  const { org, isPro } = useAuth()
  const [dismissed, setDismissed] = useState(false)
  const navigate = useNavigate()

  if (dismissed) return null

  const status = org?.subscription_status
  const tier = org?.subscription_tier || 'free'

  // Past-due warning
  if (tier === 'pro' && status === 'past_due') {
    return (
      <div style={{
        margin: '0 0 12px', padding: '10px 16px', borderRadius: 8,
        background: '#451a03', border: '1px solid #92400e',
        display: 'flex', alignItems: 'center', gap: 10, fontSize: 13,
      }}>
        <AlertTriangle size={16} color="#fdba74" style={{ flexShrink: 0 }} />
        <span style={{ color: '#fdba74', flex: 1 }}>
          Your payment failed. Update your payment method to avoid service interruption.
        </span>
        <button
          onClick={() => navigate('/profile')}
          style={{
            padding: '4px 12px', borderRadius: 5, border: 'none',
            background: '#92400e', color: '#fdba74', fontSize: 12,
            fontWeight: 600, cursor: 'pointer', whiteSpace: 'nowrap',
          }}
        >
          Fix Payment
        </button>
        <button
          onClick={() => setDismissed(true)}
          style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 2 }}
        >
          <X size={14} color="#fdba74" />
        </button>
      </div>
    )
  }

  return null
}

/**
 * Inline upgrade prompt — use when a free user hits a quota limit.
 */
export function ProFeatureGate({ feature }) {
  const navigate = useNavigate()
  return (
    <div style={{
      display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
      minHeight: 300, gap: 12, color: 'var(--muted)',
    }}>
      <Lock size={32} />
      <span style={{ fontSize: 15, fontWeight: 600, color: 'var(--text)' }}>
        {feature || "You've reached your plan limit"}. Upgrade for higher quotas.
      </span>
      <button
        onClick={() => navigate('/profile')}
        style={{
          padding: '8px 20px', borderRadius: 6, border: 'none',
          background: 'var(--accent)', color: '#fff', fontSize: 13,
          fontWeight: 600, cursor: 'pointer', marginTop: 4,
        }}
      >
        Upgrade to Pro
      </button>
    </div>
  )
}
