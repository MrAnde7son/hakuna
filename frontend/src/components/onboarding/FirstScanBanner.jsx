import React, { useEffect, useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Radar, Globe, MonitorSmartphone, CheckCircle, Loader,
  ArrowRight, X, Activity, Target,
} from 'lucide-react'
import { getScans } from '../../api.js'

const DISMISS_KEY = 'hakuna_first_scan_banner_dismissed'
const SEEN_COMPLETE_KEY = 'hakuna_first_scan_banner_seen_complete'
const POLL_MS = 8000
const COMPLETE_WINDOW_MIN = 15

const PHASES = [
  { key: 'pending',     icon: Radar,              label: 'Queued',       color: 'var(--accent)' },
  { key: 'discovering', icon: Globe,              label: 'Discovering',  color: '#0ea5e9' },
  { key: 'scanning',    icon: MonitorSmartphone,  label: 'Scanning',     color: '#ec4899' },
  { key: 'complete',    icon: CheckCircle,        label: 'Complete',     color: '#16a34a' },
]

function pickActiveScan(scans) {
  if (!Array.isArray(scans) || scans.length === 0) return null
  const running = scans.find(s => s.status === 'running' || s.status === 'pending')
  if (running) return running
  const recent = [...scans]
    .filter(s => s.last_run_at)
    .sort((a, b) => new Date(b.last_run_at) - new Date(a.last_run_at))[0]
  if (!recent) return null
  const minsAgo = (Date.now() - new Date(recent.last_run_at).getTime()) / 60000
  return minsAgo <= COMPLETE_WINDOW_MIN ? recent : null
}

function inferPhase(scan) {
  if (!scan) return 'pending'
  if (scan.status === 'completed') return 'complete'
  if (scan.status === 'failed') return 'complete'
  if ((scan.finding_count || 0) > 0) return 'scanning'
  if ((scan.asset_count || 0) > 0) return 'discovering'
  return 'pending'
}

function PhasePill({ phase, active, done }) {
  const Icon = phase.icon
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 6,
      padding: '4px 10px', borderRadius: 999,
      background: done
        ? 'rgba(22,163,74,0.10)'
        : active
          ? 'rgba(99,102,241,0.12)'
          : 'var(--bg-secondary)',
      border: `1px solid ${done ? 'rgba(22,163,74,0.25)' : active ? 'rgba(99,102,241,0.25)' : 'var(--border)'}`,
      opacity: !active && !done ? 0.55 : 1,
      transition: 'opacity 0.2s',
      fontSize: 12, fontWeight: active ? 700 : 500,
      color: done ? '#16a34a' : active ? 'var(--text-primary)' : 'var(--text-muted)',
      whiteSpace: 'nowrap',
    }}>
      {done ? (
        <CheckCircle size={12} color="#16a34a" />
      ) : active ? (
        <>
          <Loader size={12} color={phase.color} style={{ animation: 'first-scan-spin 1s linear infinite' }} />
          <style>{`@keyframes first-scan-spin{to{transform:rotate(360deg)}}`}</style>
        </>
      ) : (
        <Icon size={12} color="var(--text-muted)" />
      )}
      {phase.label}
    </div>
  )
}

export default function FirstScanBanner() {
  const navigate = useNavigate()
  const [dismissed, setDismissed] = useState(() => {
    try { return localStorage.getItem(DISMISS_KEY) === 'true' } catch { return false }
  })
  const [scan, setScan] = useState(null)
  const [failedLoad, setFailedLoad] = useState(false)
  const timerRef = useRef(null)

  useEffect(() => {
    if (dismissed) return
    let cancelled = false

    const poll = async () => {
      try {
        const scans = await getScans()
        if (cancelled) return
        const active = pickActiveScan(scans)
        setScan(active)
        setFailedLoad(false)
      } catch {
        if (!cancelled) setFailedLoad(true)
      }
    }

    poll()
    timerRef.current = setInterval(poll, POLL_MS)
    return () => {
      cancelled = true
      if (timerRef.current) clearInterval(timerRef.current)
    }
  }, [dismissed])

  if (dismissed || failedLoad || !scan) return null

  const phase = inferPhase(scan)
  const isComplete = phase === 'complete'

  // If the scan is already complete, only show once — don't nag the user forever.
  if (isComplete) {
    try {
      const seen = localStorage.getItem(SEEN_COMPLETE_KEY)
      if (seen && String(seen) === String(scan.id)) return null
    } catch { /* empty */ }
  }

  const phaseIdx = PHASES.findIndex(p => p.key === phase)
  const domain = scan?.raw_metadata?.domain
  const sourceLabel = scan.source_type === 'easm'
    ? `External scan${domain ? ` — ${domain}` : ''}`
    : (scan.scan_name || scan.filename || 'First scan')

  const handleDismiss = () => {
    try {
      localStorage.setItem(DISMISS_KEY, 'true')
      if (isComplete) localStorage.setItem(SEEN_COMPLETE_KEY, String(scan.id))
    } catch { /* empty */ }
    setDismissed(true)
  }

  const handleView = () => {
    try {
      if (isComplete) localStorage.setItem(SEEN_COMPLETE_KEY, String(scan.id))
    } catch { /* empty */ }
    navigate(isComplete ? '/' : '/scans')
    if (isComplete) {
      // Landing report needs a fresh fetch once data has arrived.
      setTimeout(() => window.location.reload(), 50)
    }
  }

  return (
    <div style={{
      position: 'sticky',
      top: 0,
      zIndex: 49,
      margin: '-18px -18px 16px -18px',
      padding: '10px 18px',
      borderBottom: `1px solid ${isComplete ? 'rgba(22,163,74,0.25)' : 'rgba(99,102,241,0.25)'}`,
      background: isComplete
        ? 'linear-gradient(135deg, rgba(22,163,74,0.10), rgba(22,163,74,0.04))'
        : 'linear-gradient(135deg, rgba(99,102,241,0.10), rgba(124,58,237,0.04))',
      backdropFilter: 'blur(6px)',
      boxShadow: '0 2px 12px rgba(0,0,0,0.08)',
      display: 'flex',
      flexDirection: 'column',
      gap: 8,
    }}>
      {/* Top row: title + actions */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <div style={{
          width: 36, height: 36, borderRadius: 10, flexShrink: 0,
          background: isComplete ? 'rgba(22,163,74,0.12)' : 'rgba(99,102,241,0.12)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          {isComplete
            ? <CheckCircle size={18} color="#16a34a" />
            : <Loader size={18} color="var(--accent)" style={{ animation: 'first-scan-spin 1s linear infinite' }} />
          }
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>
            {isComplete ? 'First scan complete' : 'First scan in progress'}
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
            {isComplete
              ? 'Your dashboard is ready — results have arrived.'
              : `Hakuna is ${phase === 'scanning' ? 'scanning for vulnerabilities' : phase === 'discovering' ? 'discovering assets' : 'warming up your first scan'}. Data will appear here as it comes in.`}
            {sourceLabel && (
              <> <span style={{ color: 'var(--text-muted)', opacity: 0.7 }}>· {sourceLabel}</span></>
            )}
          </div>
        </div>
        <button
          onClick={handleView}
          style={{
            display: 'inline-flex', alignItems: 'center', gap: 4,
            padding: '6px 12px', borderRadius: 8,
            background: 'var(--accent)', color: '#fff',
            border: 'none', cursor: 'pointer',
            fontSize: 12, fontWeight: 700, whiteSpace: 'nowrap',
          }}
        >
          {isComplete ? 'View results' : 'View scan'} <ArrowRight size={12} />
        </button>
        <button
          onClick={handleDismiss}
          title="Dismiss"
          style={{
            background: 'transparent', border: 'none', cursor: 'pointer',
            padding: 4, display: 'flex', alignItems: 'center',
            color: 'var(--text-muted)',
          }}
        >
          <X size={16} />
        </button>
      </div>

      {/* Phase timeline */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 6,
        flexWrap: 'wrap',
      }}>
        {PHASES.map((p, i) => (
          <React.Fragment key={p.key}>
            <PhasePill
              phase={p}
              active={i === phaseIdx && !isComplete}
              done={i < phaseIdx || (isComplete && p.key === 'complete')}
            />
            {i < PHASES.length - 1 && (
              <div style={{
                width: 14, height: 1,
                background: i < phaseIdx ? 'rgba(22,163,74,0.35)' : 'var(--border)',
              }} />
            )}
          </React.Fragment>
        ))}

        {/* Live stats inline */}
        {(scan.asset_count > 0 || scan.finding_count > 0) && (
          <div style={{
            marginLeft: 'auto',
            display: 'flex', gap: 12, fontSize: 12,
            color: 'var(--text-muted)',
          }}>
            {scan.asset_count > 0 && (
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                <Activity size={12} color="#0ea5e9" />
                <strong style={{ color: 'var(--text-primary)' }}>{scan.asset_count}</strong> assets
              </span>
            )}
            {scan.finding_count > 0 && (
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                <Target size={12} color="#ec4899" />
                <strong style={{ color: 'var(--text-primary)' }}>{scan.finding_count}</strong> findings
              </span>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
