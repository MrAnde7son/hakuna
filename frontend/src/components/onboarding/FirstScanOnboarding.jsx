import React, { useState, useEffect } from 'react'
import {
  CheckCircle, Target, Globe, Radar, ArrowRight, Loader,
  MonitorSmartphone, Activity,
} from 'lucide-react'
import { useAuth } from '../../contexts/AuthContext.jsx'
import { getEasmStatus } from '../../api.js'

// ── Discovery status card ──────────────────────────────────────────

function DiscoveryStatusCard({ domain, phase, stats }) {
  const phases = [
    { key: 'starting', icon: Radar, label: 'Starting discovery…', color: 'var(--accent)' },
    { key: 'discovering', icon: Globe, label: 'Discovering assets…', color: '#0ea5e9' },
    { key: 'scanning', icon: MonitorSmartphone, label: 'Scanning for vulnerabilities…', color: '#ec4899' },
    { key: 'complete', icon: CheckCircle, label: 'Discovery complete', color: '#16a34a' },
  ]

  const currentIdx = phases.findIndex(p => p.key === phase)

  return (
    <div style={{
      padding: '20px', borderRadius: 14,
      background: 'rgba(99,102,241,0.04)',
      border: '1px solid rgba(99,102,241,0.15)',
    }}>
      <div style={{ fontWeight: 700, fontSize: 14, marginBottom: 4 }}>
        Scanning <span style={{ color: 'var(--accent)' }}>{domain}</span>
      </div>
      <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 16, lineHeight: 1.6 }}>
        We're discovering your external attack surface and scanning for vulnerabilities.
        Results appear in your dashboard as they come in.
      </div>

      {/* Phase progress */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {phases.map((p, i) => {
          const Icon = p.icon
          const isActive = p.key === phase
          const isDone = i < currentIdx || phase === 'complete'
          const isPending = i > currentIdx && phase !== 'complete'

          return (
            <div key={p.key} style={{
              display: 'flex', alignItems: 'center', gap: 10,
              opacity: isPending ? 0.4 : 1,
              transition: 'opacity 0.3s',
            }}>
              <div style={{
                width: 28, height: 28, borderRadius: 8,
                background: isDone ? 'rgba(22,163,74,0.12)' : isActive ? 'rgba(99,102,241,0.12)' : 'var(--bg-secondary)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                flexShrink: 0,
              }}>
                {isDone && !isActive ? (
                  <CheckCircle size={14} color="#16a34a" />
                ) : isActive && phase !== 'complete' ? (
                  <><Loader size={14} color={p.color} style={{ animation: 'spin 1s linear infinite' }} />
                    <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
                  </>
                ) : (
                  <Icon size={14} color={isDone ? '#16a34a' : 'var(--text-muted)'} />
                )}
              </div>
              <div style={{ fontSize: 13, fontWeight: isActive ? 700 : 500, color: isActive ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                {p.label}
              </div>
            </div>
          )
        })}
      </div>

      {/* Live stats */}
      {stats && (stats.assets > 0 || stats.findings > 0) && (
        <div style={{
          marginTop: 14, padding: '10px 12px', borderRadius: 8,
          background: 'var(--bg-secondary)', border: '1px solid var(--border)',
          display: 'flex', gap: 16, fontSize: 12,
        }}>
          {stats.assets > 0 && (
            <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <Activity size={12} color="#0ea5e9" />
              <strong>{stats.assets}</strong> assets found
            </span>
          )}
          {stats.findings > 0 && (
            <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <Target size={12} color="#ec4899" />
              <strong>{stats.findings}</strong> findings so far
            </span>
          )}
        </div>
      )}
    </div>
  )
}

// ── Helpers ────────────────────────────────────────────────────────

const FREE_DOMAINS = new Set([
  'gmail.com','googlemail.com','yahoo.com','yahoo.co.uk','yahoo.fr','yahoo.de',
  'hotmail.com','hotmail.co.uk','outlook.com','live.com','msn.com',
  'icloud.com','me.com','mac.com','aol.com','protonmail.com','proton.me',
  'pm.me','zoho.com','tutanota.com','tuta.io','gmx.com','gmx.net','mail.com',
  'mail.ru','inbox.com','yandex.com','yandex.ru','fastmail.com','hey.com',
])

function deriveCorporateDomain(email) {
  if (!email || !email.includes('@')) return null
  const domain = email.split('@')[1].toLowerCase()
  return FREE_DOMAINS.has(domain) ? null : domain
}

// ── Main component ─────────────────────────────────────────────────

export default function FirstScanOnboarding({ onComplete }) {
  const { user } = useAuth()
  const [discoveryPhase, setDiscoveryPhase] = useState('starting')
  const [discoveryStats, setDiscoveryStats] = useState({ assets: 0, findings: 0 })
  const [discoveryStarted, setDiscoveryStarted] = useState(false)

  // Use stored domain, or derive from email as fallback
  const easmDomain = user?.org?.easm_domain || deriveCorporateDomain(user?.email)

  // Poll EASM status when domain exists
  useEffect(() => {
    if (!easmDomain) return
    setDiscoveryStarted(true)
    let cancelled = false

    const poll = async () => {
      try {
        const status = await getEasmStatus()
        if (cancelled) return

        if (status?.last_scan?.status === 'completed' || status?.last_scan?.status === 'complete') {
          setDiscoveryPhase('complete')
          setDiscoveryStats({
            assets: status.last_scan.asset_count || status.asset_count || 0,
            findings: status.last_scan.finding_count || status.finding_count || 0,
          })
        } else if (status?.last_scan?.status === 'running' || status?.last_scan?.status === 'scanning') {
          setDiscoveryPhase('scanning')
          setDiscoveryStats({
            assets: status.last_scan.asset_count || status.asset_count || 0,
            findings: status.last_scan.finding_count || 0,
          })
        } else if (status?.last_scan) {
          setDiscoveryPhase('discovering')
          setDiscoveryStats({
            assets: status.last_scan.asset_count || 0,
            findings: 0,
          })
        }
      } catch {
        // EASM not configured — that's fine, we'll just show the static card
      }
    }

    poll()
    const interval = setInterval(poll, 5000)
    return () => { cancelled = true; clearInterval(interval) }
  }, [easmDomain])

  return (
    <div style={{
      minHeight: '80vh', display: 'flex', flexDirection: 'column',
      alignItems: 'center', justifyContent: 'center',
      padding: '40px 24px',
    }}>
      {/* Hero */}
      <div style={{ textAlign: 'center', marginBottom: 36, maxWidth: 500 }}>
        <h1 style={{ fontSize: 26, fontWeight: 800, marginBottom: 10, color: 'var(--text-primary)' }}>
          Welcome to Hakuna
        </h1>
        <p style={{ fontSize: 15, color: 'var(--text-muted)', lineHeight: 1.6, margin: 0 }}>
          {easmDomain
            ? 'We\'re discovering your attack surface and scanning for vulnerabilities.'
            : 'Set up continuous scanning from Settings to get started, or go straight to your dashboard.'}
        </p>
      </div>

      <div style={{ width: '100%', maxWidth: 520, display: 'flex', flexDirection: 'column', gap: 16 }}>
        {/* Native discovery — primary path when domain exists */}
        {easmDomain && discoveryStarted && (
          <DiscoveryStatusCard
            domain={easmDomain}
            phase={discoveryPhase}
            stats={discoveryStats}
          />
        )}

        {/* Primary CTA */}
        <button
          onClick={onComplete}
          style={{
            display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
            width: '100%', padding: '12px 24px', borderRadius: 10, border: 'none',
            background: 'var(--accent)', color: '#fff', fontWeight: 700,
            fontSize: 14, cursor: 'pointer',
          }}
        >
          {easmDomain && discoveryPhase === 'complete' ? 'View results' : 'Go to dashboard'} <ArrowRight size={15} />
        </button>
      </div>
    </div>
  )
}
