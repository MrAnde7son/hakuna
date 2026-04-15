/**
 * Shared UI primitives
 */
import React, { useState, useEffect, useRef, useCallback, Fragment, Component, createContext, useContext } from 'react'
import { createPortal } from 'react-dom'
import { useTranslation } from 'react-i18next'
import { getTags, createCampaign, createAutoTagRule, getSources } from '../../api.js'

// ─────────────────────────────────────────────────────────
// Toast Notification System
// ─────────────────────────────────────────────────────────

const ToastContext = createContext(null)

export function useToast() {
  const ctx = useContext(ToastContext)
  if (!ctx) throw new Error('useToast must be used within ToastProvider')
  return ctx
}

let toastId = 0

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([])

  const add = useCallback((type, message, duration = 4000) => {
    const id = ++toastId
    setToasts(prev => [...prev, { id, type, message }])
    if (duration > 0) setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), duration)
    return id
  }, [])

  const dismiss = useCallback((id) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

  const toast = useCallback(Object.assign(
    (message) => add('info', message),
    {
      success: (message, duration) => add('success', message, duration),
      error: (message, duration) => add('error', message, duration ?? 6000),
      info: (message, duration) => add('info', message, duration),
      warning: (message, duration) => add('warning', message, duration),
      dismiss,
    }
  ), [add, dismiss])

  return (
    <ToastContext.Provider value={toast}>
      {children}
      {createPortal(<ToastContainer toasts={toasts} onDismiss={dismiss} />, document.body)}
    </ToastContext.Provider>
  )
}

const TOAST_STYLES = {
  success: { bg: 'var(--success-subtle)', border: 'var(--success)', icon: '\u2713', color: 'var(--success)' },
  error: { bg: 'var(--danger-subtle)', border: 'var(--danger)', icon: '\u2716', color: 'var(--danger)' },
  warning: { bg: 'var(--warning-subtle)', border: 'var(--warning)', icon: '\u26A0', color: 'var(--warning)' },
  info: { bg: 'var(--secondary)', border: 'var(--primary)', icon: '\u2139', color: 'var(--primary)' },
}

function ToastContainer({ toasts, onDismiss }) {
  if (!toasts.length) return null
  return (
    <div style={{
      position: 'fixed', bottom: 16, right: 16, zIndex: 99999,
      display: 'flex', flexDirection: 'column-reverse', gap: 8,
      maxWidth: 400, pointerEvents: 'none',
    }}>
      {toasts.map(t => {
        const s = TOAST_STYLES[t.type] || TOAST_STYLES.info
        return (
          <div key={t.id} style={{
            display: 'flex', alignItems: 'flex-start', gap: 10,
            padding: '10px 14px', borderRadius: 8,
            background: s.bg, border: `1px solid ${s.border}`,
            color: 'var(--text)', fontSize: 13, lineHeight: 1.5,
            boxShadow: 'var(--shadow)', pointerEvents: 'auto',
            animation: 'toast-in 0.2s ease-out',
          }}>
            <span style={{ color: s.color, fontSize: 14, flexShrink: 0, marginTop: 1 }}>{s.icon}</span>
            <span style={{ flex: 1, wordBreak: 'break-word' }}>{t.message}</span>
            <button onClick={() => onDismiss(t.id)} style={{
              background: 'none', border: 'none', color: 'var(--muted)',
              cursor: 'pointer', fontSize: 15, lineHeight: 1, padding: 0, flexShrink: 0,
            }}>&times;</button>
          </div>
        )
      })}
      <style>{`@keyframes toast-in { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }`}</style>
    </div>
  )
}

// ─────────────────────────────────────────────────────────
// Confirm Dialog (replaces window.confirm)
// ─────────────────────────────────────────────────────────

const ConfirmContext = createContext(null)

export function useConfirm() {
  const ctx = useContext(ConfirmContext)
  if (!ctx) throw new Error('useConfirm must be used within ConfirmProvider')
  return ctx
}

export function ConfirmProvider({ children }) {
  const [state, setState] = useState(null)

  const confirm = useCallback((message, opts = {}) => {
    return new Promise((resolve) => {
      setState({ message, opts, resolve })
    })
  }, [])

  const handleClose = useCallback((result) => {
    state?.resolve(result)
    setState(null)
  }, [state])

  return (
    <ConfirmContext.Provider value={confirm}>
      {children}
      {state && createPortal(
        <ConfirmDialog
          message={state.message}
          title={state.opts.title}
          confirmLabel={state.opts.confirmLabel}
          cancelLabel={state.opts.cancelLabel}
          destructive={state.opts.destructive !== false}
          onConfirm={() => handleClose(true)}
          onCancel={() => handleClose(false)}
        />,
        document.body
      )}
    </ConfirmContext.Provider>
  )
}

function ConfirmDialog({ message, title, confirmLabel, cancelLabel, destructive, onConfirm, onCancel }) {
  useEffect(() => {
    const h = (e) => { if (e.key === 'Escape') onCancel() }
    document.addEventListener('keydown', h)
    return () => document.removeEventListener('keydown', h)
  }, [onCancel])

  return (
    <div onClick={onCancel} style={{
      position: 'fixed', inset: 0, zIndex: 99998,
      background: 'rgba(0,0,0,0.45)', display: 'flex',
      alignItems: 'center', justifyContent: 'center',
    }}>
      <div onClick={e => e.stopPropagation()} style={{
        background: 'var(--card)', borderRadius: 12,
        border: '1px solid var(--border)', boxShadow: 'var(--shadow)',
        padding: 24, maxWidth: 420, width: '90%',
      }}>
        {title && <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 8, color: 'var(--text)' }}>{title}</div>}
        <div style={{ fontSize: 13, lineHeight: 1.6, color: 'var(--text-secondary)', marginBottom: 20 }}>{message}</div>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
          <button onClick={onCancel} style={{
            padding: '7px 16px', borderRadius: 6, fontSize: 13, fontWeight: 500,
            border: '1px solid var(--border)', background: 'var(--secondary)',
            color: 'var(--text)', cursor: 'pointer',
          }}>{cancelLabel || 'Cancel'}</button>
          <button onClick={onConfirm} autoFocus style={{
            padding: '7px 16px', borderRadius: 6, fontSize: 13, fontWeight: 500,
            border: 'none', cursor: 'pointer',
            background: destructive ? 'var(--danger)' : 'var(--primary)',
            color: destructive ? '#fff' : 'var(--primary-foreground)',
          }}>{confirmLabel || (destructive ? 'Delete' : 'Confirm')}</button>
        </div>
      </div>
    </div>
  )
}

export function SeverityBadge({ severity, label }) {
  const { t } = useTranslation()
  const SEV_VARS = {
    4: { bg: 'var(--sev-critical-bg)', text: 'var(--sev-critical-text)', border: 'var(--sev-critical-border)' },
    3: { bg: 'var(--sev-high-bg)', text: 'var(--sev-high-text)', border: 'var(--sev-high-border)' },
    2: { bg: 'var(--sev-medium-bg)', text: 'var(--sev-medium-text)', border: 'var(--sev-medium-border)' },
    1: { bg: 'var(--sev-low-bg)', text: 'var(--sev-low-text)', border: 'var(--sev-low-border)' },
    0: { bg: 'var(--sev-info-bg)', text: 'var(--sev-info-text)', border: 'var(--sev-info-border)' },
  }
  const c = SEV_VARS[severity] || SEV_VARS[0]
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      background: c.bg, color: c.text, border: `1px solid ${c.border}`,
      borderRadius: 4, padding: '2px 8px', fontSize: 11, fontWeight: 600,
      textTransform: 'uppercase', letterSpacing: '0.05em', whiteSpace: 'nowrap',
    }}>
      {label || [t('severity.info'), t('severity.low'), t('severity.medium'), t('severity.high'), t('severity.critical')][severity] || t('severity.info')}
    </span>
  )
}

export function ScoreBar({ score, max = 10, color, breakdown }) {
  const pct = Math.min((score / max) * 100, 100)
  const c = color || (score >= 8 ? 'var(--critical)' : score >= 6 ? 'var(--high)' : score >= 4 ? 'var(--medium)' : 'var(--low)')
  const [tipOpen, setTipOpen] = useState(false)
  const [tipPos, setTipPos] = useState({ x: 0, y: 0 })
  const barRef = useRef(null)

  const showTip = () => {
    if (!breakdown) return
    const rect = barRef.current?.getBoundingClientRect()
    if (rect) setTipPos({ x: rect.left, y: rect.bottom + 6 })
    setTipOpen(true)
  }

  return (
    <div
      ref={barRef}
      onMouseEnter={showTip}
      onMouseLeave={() => setTipOpen(false)}
      style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: breakdown ? 'help' : 'default' }}
    >
      <div style={{ flex: 1, height: 6, background: 'var(--border)', borderRadius: 3, overflow: 'hidden' }}>
        <div style={{ width: `${pct}%`, height: '100%', background: c, borderRadius: 3, transition: 'width 0.3s' }} />
      </div>
      <span style={{ fontSize: 12, color: c, fontWeight: 600, minWidth: 28 }}>{score?.toFixed(1)}</span>
      {tipOpen && breakdown && createPortal(
        <ScoreBreakdownTooltip breakdown={breakdown} pos={tipPos} />,
        document.body
      )}
    </div>
  )
}

function ScoreBreakdownTooltip({ breakdown, pos }) {
  const factors = breakdown.factors || []
  return (
    <div style={{
      position: 'fixed', left: Math.min(pos.x, window.innerWidth - 310), top: pos.y,
      zIndex: 99996, width: 290, padding: '10px 12px',
      background: 'var(--card)', border: '1px solid var(--border)',
      borderRadius: 8, boxShadow: '0 8px 24px rgba(0,0,0,0.18)',
      animation: 'toast-in 0.15s ease-out',
    }}>
      <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>
        {breakdown.title || 'Score Breakdown'}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
        {factors.map(f => (
          <div key={f.label} style={{ display: 'grid', gridTemplateColumns: '90px 1fr 70px', gap: 6, alignItems: 'center' }}>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)', display: 'flex', justifyContent: 'space-between' }}>
              <span>{f.label}</span>
              <span style={{ color: 'var(--muted)' }}>{Math.round(f.weight * 100)}%</span>
            </div>
            <div style={{ height: 4, background: 'var(--border)', borderRadius: 2, overflow: 'hidden' }}>
              <div style={{ width: `${Math.min(f.value * 100, 100)}%`, height: '100%', background: f.color, borderRadius: 2 }} />
            </div>
            <div style={{ fontSize: 10, color: 'var(--muted)', textAlign: 'right', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }} title={f.detail}>
              {f.detail}
            </div>
          </div>
        ))}
      </div>
      {breakdown.total != null && (
        <div style={{ marginTop: 6, paddingTop: 6, borderTop: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--muted)' }}>
          <span>Weighted total</span>
          <span style={{ fontWeight: 600, color: 'var(--text)' }}>{breakdown.total.toFixed(1)} / 10</span>
        </div>
      )}
    </div>
  )
}

// ─────────────────────────────────────────────────────────
// Score Breakdown Helpers
// ─────────────────────────────────────────────────────────

const DEFAULT_FINDING_WEIGHTS = {
  severity: 0.25, intel: 0.25, exploitability: 0.20,
  criticality: 0.10, family: 0.10, controls: 0.05, reachability: 0.05,
}

const DEFAULT_ASSET_WEIGHTS = {
  severity: 0.35, exploitability: 0.25, intel: 0.15,
  criticality: 0.15, controls: 0.05, reachability: 0.05,
}

let _cachedRiskWeights = null
let _cachedAssetWeights = null

export function useRiskWeights() {
  const [weights, setWeights] = useState(_cachedRiskWeights)
  useEffect(() => {
    if (_cachedRiskWeights) return
    import('../../api.js').then(api => api.getRiskConfig()).then(cfg => {
      _cachedRiskWeights = {
        ...(cfg?.finding_formula_weights || DEFAULT_FINDING_WEIGHTS),
        severity_source: cfg?.severity_source || 'cvss_best',
      }
      setWeights(_cachedRiskWeights)
    }).catch(() => {
      _cachedRiskWeights = DEFAULT_FINDING_WEIGHTS
      setWeights(DEFAULT_FINDING_WEIGHTS)
    })
  }, [])
  return weights || DEFAULT_FINDING_WEIGHTS
}

export function useAssetRiskWeights() {
  const [weights, setWeights] = useState(_cachedAssetWeights)
  useEffect(() => {
    if (_cachedAssetWeights) return
    import('../../api.js').then(api => api.getRiskConfig()).then(cfg => {
      _cachedAssetWeights = cfg?.formula_weights || DEFAULT_ASSET_WEIGHTS
      setWeights(_cachedAssetWeights)
    }).catch(() => {
      _cachedAssetWeights = DEFAULT_ASSET_WEIGHTS
      setWeights(DEFAULT_ASSET_WEIGHTS)
    })
  }, [])
  return weights || DEFAULT_ASSET_WEIGHTS
}

export function buildFindingBreakdown(finding, riskWeights) {
  const w = riskWeights || DEFAULT_FINDING_WEIGHTS
  const sevSource = w.severity_source || 'cvss_best'
  let sevRaw, sevNorm, sevDetail
  if (sevSource === 'epss') {
    sevRaw = finding.epss_score || 0
    sevNorm = Math.min(sevRaw, 1.0)
    sevDetail = sevRaw ? `EPSS ${(sevRaw * 100).toFixed(1)}%` : 'N/A'
  } else if (sevSource === 'vpr') {
    sevRaw = finding.vpr_score || 0
    sevNorm = sevRaw / 10
    sevDetail = sevRaw ? `VPR ${sevRaw.toFixed(1)}` : 'N/A'
  } else if (sevSource === 'cvss2') {
    sevRaw = finding.cvss2_score || 0
    sevNorm = sevRaw / 10
    sevDetail = sevRaw ? `CVSS2 ${sevRaw.toFixed(1)}` : 'N/A'
  } else if (sevSource === 'cvss3') {
    sevRaw = finding.cvss3_score || 0
    sevNorm = sevRaw / 10
    sevDetail = sevRaw ? `CVSS3 ${sevRaw.toFixed(1)}` : 'N/A'
  } else if (sevSource === 'cvss4') {
    sevRaw = finding.cvss4_score || 0
    sevNorm = sevRaw / 10
    sevDetail = sevRaw ? `CVSS4 ${sevRaw.toFixed(1)}` : 'N/A'
  } else { // cvss_best
    sevRaw = finding.cvss4_score || finding.cvss3_score || finding.cvss2_score || 0
    sevNorm = sevRaw / 10
    sevDetail = sevRaw ? `CVSS ${sevRaw.toFixed(1)}` : 'N/A'
  }
  let exploitBonus = 0
  if (finding.zero_day) exploitBonus = 1.0
  else if (finding.exploit_maturity) {
    const m = { weaponized: 0.9, functional: 0.7, poc: 0.5, unproven: 0.2 }
    exploitBonus = m[finding.exploit_maturity.toLowerCase()] || 0.2
  } else if (finding.exploit_available) exploitBonus = 0.5
  const signals = []
  if (finding.is_kev) signals.push(0.9)
  if (finding.epss_score > 0) signals.push(Math.min(finding.epss_score * 1.5, 1.0))
  if (finding.ransomware_linked) signals.push(1.0)
  if (finding.trending_in_news) signals.push(0.6)
  if (finding.vpr_score > 0) signals.push(finding.vpr_score / 10)
  const intelFactor = signals.length ? Math.max(...signals) : 0
  const critRaw = finding.asset_criticality || 5
  const critNorm = (critRaw - 1) / 9
  // All 7 factors matching Settings > Risk > Finding Formula Weights
  const allFactors = [
    { key: 'severity', label: 'Severity', value: sevNorm, detail: sevDetail, color: 'var(--critical)' },
    { key: 'exploitability', label: 'Exploitability', value: exploitBonus,
      detail: finding.zero_day ? 'Zero-day' : finding.exploit_maturity || (finding.exploit_available ? 'Known exploit' : 'None'),
      color: 'var(--medium)' },
    { key: 'intel', label: 'Threat Intel', value: intelFactor,
      detail: [finding.is_kev && 'KEV', finding.ransomware_linked && 'Ransomware', finding.trending_in_news && 'Trending', finding.epss_score > 0 && `EPSS ${(finding.epss_score * 100).toFixed(1)}%`, finding.vpr_score > 0 && `VPR ${finding.vpr_score}`].filter(Boolean).join(', ') || 'None',
      color: 'var(--high)' },
    { key: 'criticality', label: 'Asset Crit.', value: critNorm, detail: `${critRaw}/10`, color: 'var(--info)' },
    { key: 'family', label: 'Family', value: 0.5, detail: finding.plugin_family || 'General', color: 'var(--low)' },
    { key: 'controls', label: 'Controls', value: 0.5, detail: 'N/A', color: 'var(--muted)' },
    { key: 'reachability', label: 'Reachability', value: 0.5, detail: 'N/A', color: 'var(--muted)' },
  ]
  // Only show factors that have weight > 0
  const factors = allFactors
    .filter(f => (w[f.key] || 0) > 0)
    .map(f => ({ ...f, weight: w[f.key] }))
  // Use actual priority_score from backend (already has severity floors + cap)
  const actual = finding.priority_score
  return { title: 'Priority Score Breakdown', factors, total: actual != null ? actual : Math.min(factors.reduce((s, f) => s + f.value * f.weight, 0) * 10, 10) }
}

export function buildAssetBreakdown(asset, weights, components) {
  const w = weights || DEFAULT_ASSET_WEIGHTS
  const cc = asset.critical_count || 0, hc = asset.high_count || 0
  const mc = asset.medium_count || 0, lc = asset.low_count || 0
  const nonInfo = cc + hc + mc + lc

  // Severity: use backend component if available, otherwise approximate from counts
  let severityValue, severityDetail
  if (components) {
    severityValue = components.severity
    const parts = []
    if (cc) parts.push(`${cc}C`)
    if (hc) parts.push(`${hc}H`)
    if (mc) parts.push(`${mc}M`)
    if (lc) parts.push(`${lc}L`)
    severityDetail = parts.join(' / ') || 'No findings'
  } else {
    severityValue = 0
    severityDetail = 'No findings'
    if (nonInfo > 0) {
      const quality = (cc * 10 + hc * 7 + mc * 4 + lc * 1.5) / (nonInfo * 10)
      const volume = Math.min(cc * 0.5 + hc * 0.25 + mc * 0.05, 10) / 10
      severityValue = Math.min(0.70 * quality + 0.30 * volume, 1)
      const parts = []
      if (cc) parts.push(`${cc}C`)
      if (hc) parts.push(`${hc}H`)
      if (mc) parts.push(`${mc}M`)
      if (lc) parts.push(`${lc}L`)
      severityDetail = parts.join(' / ')
    }
  }

  const crit = asset.criticality || 5
  const critValue = components ? components.criticality : (crit - 1) / 9

  const allFactors = [
    { key: 'severity',       label: 'Tech. Severity', value: severityValue,
      detail: severityDetail, color: 'var(--critical)' },
    { key: 'exploitability', label: 'Exploitability',
      value: components ? components.exploitability : null,
      detail: components ? (components.exploitability > 0 ? `${(components.exploitability * 100).toFixed(0)}% score` : 'No exploits') : 'N/A',
      color: 'var(--medium)' },
    { key: 'intel',          label: 'Threat Intel',
      value: components ? components.intel : null,
      detail: components ? (components.intel > 0 ? `${(components.intel * 100).toFixed(0)}% signal` : 'No signals') : 'N/A',
      color: 'var(--high)' },
    { key: 'criticality',    label: 'Asset Crit.',    value: critValue,
      detail: `${crit}/10`, color: 'var(--info)' },
    { key: 'controls',       label: 'Controls',
      value: components ? components.controls : null,
      detail: components ? (components.controls_detail || (components.controls > 0 ? 'No controls' : 'Controls present')) : 'N/A',
      color: components && components.controls > 0 ? 'var(--critical)' : 'var(--low)' },
    { key: 'reachability',   label: 'Reachability',
      value: components ? components.reachability : null,
      detail: components ? (components.reachability_detail || `${(components.reachability * 100).toFixed(0)}%`) : 'N/A',
      color: 'var(--muted)' },
  ]

  const factors = allFactors
    .filter(f => (w[f.key] || 0) > 0)
    .map(f => ({ ...f, weight: w[f.key], value: f.value ?? 0 }))

  return { title: 'Risk Score Breakdown', factors, total: asset.risk_score ?? null }
}

export function Card({ children, style = {}, onClick, activeBorderColor, active, activeColor }) {
  const borderColor = active ? (activeColor || 'var(--accent)') : 'var(--border)'
  const bgTint = active && activeColor ? activeColor + '12' : undefined
  return (
    <div
      onClick={onClick}
      style={{
        background: bgTint || 'var(--bg-card)', border: `2px solid ${borderColor}`,
        borderRadius: 10, padding: 20, ...style,
        ...(onClick && { cursor: 'pointer', transition: 'border-color 0.15s, background 0.15s, box-shadow 0.15s' }),
        ...(active && { boxShadow: `0 0 0 1px ${activeColor || 'var(--accent)'}30` }),
      }}
      onMouseEnter={onClick ? e => {
        e.currentTarget.style.borderColor = activeColor || 'var(--accent)'
      } : undefined}
      onMouseLeave={onClick ? e => {
        e.currentTarget.style.borderColor = active ? (activeColor || 'var(--accent)') : (activeBorderColor || 'var(--border)')
      } : undefined}
    >
      {children}
    </div>
  )
}

export function StatCard({ label, value, sub, color, icon: Icon, onClick, active }) {
  return (
    <Card
      style={{ display: 'flex', flexDirection: 'column', gap: 8 }}
      onClick={onClick}
      activeBorderColor={active ? (color || 'var(--accent)') : undefined}
      active={active}
      activeColor={color}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div style={{ fontSize: 12, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{label}</div>
        {Icon && <Icon size={16} color={color || 'var(--text-muted)'} />}
      </div>
      <div style={{ fontSize: 32, fontWeight: 700, color: color || 'var(--text-primary)' }}>{value}</div>
      {sub && <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>{sub}</div>}
    </Card>
  )
}

export function Table({ columns, rows, onRowClick, onSort, sortBy, sortOrder, emptyMessage = 'No data', renderRowExtra }) {
  return (
    <div style={{ overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
        <thead>
          <tr style={{ borderBottom: '1px solid var(--border)' }}>
            {columns.map(col => {
              const isSorted = sortBy === col.key
              const canSort = col.sortable && onSort
              return (
                <th
                  key={col.key}
                  onClick={canSort ? () => onSort(col.key) : undefined}
                  style={{
                    padding: '10px 12px', textAlign: 'left', fontWeight: 600,
                    color: isSorted ? 'var(--text-primary)' : 'var(--text-muted)',
                    fontSize: 11, textTransform: 'uppercase',
                    letterSpacing: '0.05em', whiteSpace: 'nowrap',
                    width: col.width,
                    cursor: canSort ? 'pointer' : 'default',
                    userSelect: 'none',
                  }}
                >
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                    {col.label}
                    {canSort && (
                      <span style={{ fontSize: 10, opacity: isSorted ? 1 : 0.3 }}>
                        {isSorted ? (sortOrder === 'asc' ? '▲' : '▼') : '⇅'}
                      </span>
                    )}
                  </span>
                </th>
              )
            })}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr><td colSpan={columns.length} style={{ padding: '32px 12px', textAlign: 'center', color: 'var(--text-muted)' }}>{emptyMessage}</td></tr>
          ) : rows.map((row, i) => {
            const extra = renderRowExtra && renderRowExtra(row, i)
            return (
              <Fragment key={i}>
                <tr
                  onClick={() => onRowClick && onRowClick(row)}
                  style={{
                    borderBottom: extra ? 'none' : '1px solid var(--border)',
                    cursor: onRowClick ? 'pointer' : 'default',
                    transition: 'background 0.1s',
                  }}
                  onMouseEnter={e => onRowClick && (e.currentTarget.style.background = 'var(--bg-hover)')}
                  onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                >
                  {columns.map(col => (
                    <td key={col.key} style={{ padding: '10px 12px', color: 'var(--text-primary)', verticalAlign: 'middle' }}>
                      {col.render ? col.render(row[col.key], row) : row[col.key]}
                    </td>
                  ))}
                </tr>
                {extra && (
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    <td colSpan={columns.length} style={{ padding: 0 }}>
                      {extra}
                    </td>
                  </tr>
                )}
              </Fragment>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

export function FilterBar({ children }) {
  return (
    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 16 }}>
      {children}
    </div>
  )
}

export function Select({ value, onChange, options, placeholder }) {
  return (
    <select
      value={value || ''}
      onChange={e => onChange(e.target.value || null)}
      style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)',
        color: value ? 'var(--text-primary)' : 'var(--text-muted)',
        borderRadius: 6, padding: '7px 12px', fontSize: 13, cursor: 'pointer',
        outline: 'none',
      }}
    >
      {placeholder && <option value="">{placeholder}</option>}
      {options.map(o => (
        <option key={o.value} value={o.value}>{o.label}</option>
      ))}
    </select>
  )
}

/**
 * MultiSelect – dropdown with checkboxes for selecting multiple values.
 * Props: values (array of selected strings), onChange(newValues[]), options [{value,label,color?}], placeholder
 */
export function MultiSelect({ values = [], onChange, options, placeholder }) {
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

  useEffect(() => {
    const handler = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const toggle = (val) => {
    onChange(values.includes(val) ? values.filter(v => v !== val) : [...values, val])
  }

  const label = values.length === 0
    ? placeholder
    : values.length === options.length
      ? placeholder  // all selected = same as no filter
      : options.filter(o => values.includes(o.value)).map(o => o.label).join(', ')

  return (
    <div ref={ref} style={{ position: 'relative', display: 'inline-block' }}>
      <button
        type="button"
        onClick={() => setOpen(!open)}
        style={{
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          color: values.length ? 'var(--text-primary)' : 'var(--text-muted)',
          borderRadius: 6, padding: '7px 12px', fontSize: 13, cursor: 'pointer',
          outline: 'none', display: 'flex', alignItems: 'center', gap: 6,
          minWidth: 130, justifyContent: 'space-between', whiteSpace: 'nowrap',
        }}
      >
        <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 160 }}>{label}</span>
        <span style={{ fontSize: 10, opacity: 0.5 }}>▾</span>
      </button>
      {open && (
        <div style={{
          position: 'absolute', top: '100%', left: 0, zIndex: 200, minWidth: 180,
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: 8, marginTop: 4, boxShadow: '0 4px 16px rgba(0,0,0,0.18)',
          padding: '4px 0',
        }}>
          {options.map(o => (
            <label
              key={o.value}
              style={{
                display: 'flex', alignItems: 'center', gap: 8,
                padding: '6px 12px', cursor: 'pointer', fontSize: 13,
                color: 'var(--text-primary)',
              }}
              onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-hover)'}
              onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
            >
              <input
                type="checkbox"
                checked={values.includes(o.value)}
                onChange={() => toggle(o.value)}
                style={{ accentColor: o.color || 'var(--accent)' }}
              />
              {o.label}
            </label>
          ))}
        </div>
      )}
    </div>
  )
}

export function Input({ value, onChange, placeholder, style = {} }) {
  return (
    <input
      value={value}
      onChange={e => onChange(e.target.value)}
      placeholder={placeholder}
      style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)',
        color: 'var(--text-primary)', borderRadius: 6, padding: '7px 12px',
        fontSize: 13, outline: 'none', ...style
      }}
    />
  )
}

export function Button({ children, onClick, variant = 'primary', size = 'md', disabled, style = {} }) {
  const base = {
    display: 'inline-flex', alignItems: 'center', gap: 6,
    border: 'none', borderRadius: 6, cursor: disabled ? 'not-allowed' : 'pointer',
    fontWeight: 600, transition: 'all 0.15s', fontSize: size === 'sm' ? 12 : 13,
    padding: size === 'sm' ? '5px 10px' : '8px 16px',
    opacity: disabled ? 0.5 : 1, ...style
  }
  const variants = {
    primary: { background: 'var(--accent)', color: 'var(--primary-foreground)' },
    danger: { background: 'var(--danger)', color: '#fff' },
    ghost: { background: 'transparent', color: 'var(--text-secondary)', border: '1px solid var(--border)' },
    success: { background: 'var(--success)', color: '#fff' },
    warning: { background: 'var(--warning)', color: '#fff' },
  }
  return (
    <button onClick={disabled ? undefined : onClick} style={{ ...base, ...variants[variant] }}>
      {children}
    </button>
  )
}

export function Pill({ label, color = 'var(--text-muted)', children }) {
  return (
    <span style={{
      display: 'inline-block', padding: '2px 8px', borderRadius: 999,
      background: `${color}22`, color, border: `1px solid ${color}44`,
      fontSize: 11, fontWeight: 600,
    }}>{label || children}</span>
  )
}

export function PageHeader({ title, subtitle, action }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 24 }}>
      <div>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary)' }}>{title}</h1>
        {subtitle && <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 4 }}>{subtitle}</div>}
      </div>
      {action}
    </div>
  )
}

export function EmptyState({ icon: Icon, title, sub, children }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '64px 24px', gap: 12 }}>
      {Icon && <Icon size={40} color="var(--text-muted)" />}
      <div style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-secondary)' }}>{title}</div>
      {sub && <div style={{ fontSize: 13, color: 'var(--text-muted)', textAlign: 'center', maxWidth: 320 }}>{sub}</div>}
      {children}
    </div>
  )
}

export function EffortBadge({ effort }) {
  const MAP = {
    quick_win: { label: 'Quick Win', color: 'var(--success)' },
    medium: { label: 'Medium', color: 'var(--warning)' },
    complex: { label: 'Complex', color: 'var(--danger)' },
  }
  const c = MAP[effort] || { label: effort || '—', color: 'var(--text-muted)' }
  return <Pill label={c.label} color={c.color} />
}

/**
 * Patch reliability badge — shows whether a patch is safe to deploy based
 * on vendor known-issue signals, internal rollbacks, and recalls.
 *
 * Accepts the `reliability` block from the backend patch_reliability scorer:
 *   { score, status, recalled_at, recall_reason, known_issues, signal_count, ... }
 * The scorer always returns a well-formed object, but we handle null/undefined
 * defensively for callers that pass patches from older cached responses.
 */
export function PatchReliabilityBadge({ reliability, size = 'md' }) {
  const STATUS_MAP = {
    stable:        { label: 'Stable',        color: '#10b981' },
    known_issues:  { label: 'Known Issues',  color: '#f59e0b' },
    recalled:      { label: 'Recalled',      color: '#dc2626' },
    superseded:    { label: 'Superseded',    color: '#6b7280' },
    unknown:       { label: 'Unverified',    color: '#6b7280' },
  }

  const r = reliability || {}
  const status = r.status || 'unknown'
  const cfg = STATUS_MAP[status] || STATUS_MAP.unknown

  // Build a tooltip that explains the status. For recalled/known_issues we
  // surface the actual reasons so the user doesn't have to click through.
  const tooltipLines = []
  if (status === 'recalled' && r.recall_reason) {
    tooltipLines.push(`Recalled: ${r.recall_reason}`)
  }
  if (status === 'unknown') {
    tooltipLines.push('No reliability signals observed yet')
  }
  if (Array.isArray(r.known_issues) && r.known_issues.length > 0) {
    tooltipLines.push(...r.known_issues.slice(0, 3).map(i => `• ${i.title || 'Issue'}`))
    if (r.known_issues.length > 3) tooltipLines.push(`+${r.known_issues.length - 3} more`)
  }
  if (typeof r.score === 'number') {
    tooltipLines.push(`Score ${r.score.toFixed(2)} · ${r.signal_count || 0} signals`)
  }

  const small = size === 'sm'
  return (
    <span
      title={tooltipLines.join('\n') || cfg.label}
      style={{
        display: 'inline-flex', alignItems: 'center', gap: 4,
        padding: small ? '1px 6px' : '2px 8px',
        borderRadius: 999,
        background: `${cfg.color}22`,
        color: cfg.color,
        border: `1px solid ${cfg.color}44`,
        fontSize: small ? 10 : 11,
        fontWeight: 600,
        whiteSpace: 'nowrap',
        cursor: tooltipLines.length > 0 ? 'help' : 'default',
      }}
    >
      <span style={{
        width: small ? 5 : 6, height: small ? 5 : 6, borderRadius: '50%',
        background: cfg.color, display: 'inline-block',
      }} />
      {cfg.label}
    </span>
  )
}

// Canonical ownership role → color map. Keep in sync with OWNERSHIP_ROLE_OPTIONS below.
export const OWNERSHIP_ROLE_COLORS = {
  // Infrastructure & Ops
  IT:         '#0ea5e9',
  HelpDesk:   '#38bdf8',
  DevOps:     '#8b5cf6',
  SRE:        '#a78bfa',
  Platform:   '#7c3aed',
  Networking: '#14b8a6',
  CloudOps:   '#3b82f6',
  DBA:        '#06b6d4',
  // Security
  SecOps:     '#dc2626',
  SOC:        '#ef4444',
  AppSec:     '#f59e0b',
  CloudSec:   '#fb923c',
  IAM:        '#d946ef',
  GRC:        '#a855f7',
  // Engineering
  Engineering:'#22c55e',
  Mobile:     '#10b981',
  Data:       '#84cc16',
}

export function OwnerBadge({ owner }) {
  return <Pill label={owner || '—'} color={OWNERSHIP_ROLE_COLORS[owner] || 'var(--text-muted)'} />
}

const SOURCE_LABELS = {
  manual_finding: 'Manual',
  manual_asset: 'Asset',
  inferred_service: 'Auto',
  inferred_user: 'Auto',
  plugin_family: 'Default',
  pentest_report: 'Pentest',
}
const SOURCE_COLORS = {
  manual_finding: '#22c55e',
  manual_asset: '#22c55e',
  inferred_service: '#60a5fa',
  inferred_user: '#60a5fa',
  plugin_family: 'var(--text-muted)',
  pentest_report: '#e879f9',
}

export function ResolvedOwnerBadge({ resolved }) {
  if (!resolved) return <OwnerBadge owner={null} />
  const role = resolved.owner_role || '—'
  const name = resolved.owner_name
  const src = SOURCE_LABELS[resolved.source] || 'Default'
  const srcColor = SOURCE_COLORS[resolved.source] || 'var(--text-muted)'
  const roleColor = OWNERSHIP_ROLE_COLORS[role] || 'var(--text-muted)'

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
        <Pill label={role} color={roleColor} />
        <span style={{ fontSize: 9, color: srcColor, fontWeight: 600, textTransform: 'uppercase' }}>{src}</span>
      </div>
      {name && name !== role && (
        <span style={{ fontSize: 11, color: 'var(--text-secondary)', maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
              title={name}>
          {name}
        </span>
      )}
    </div>
  )
}

// Canonical ownership role / team-type list.
// Grouped: Infrastructure & Ops → Security → Engineering. Exported for reuse across pages.
export const OWNERSHIP_ROLE_OPTIONS = [
  // Infrastructure & Operations (fixers)
  'IT', 'HelpDesk', 'DevOps', 'SRE', 'Platform', 'Networking', 'CloudOps', 'DBA',
  // Security (finders & fixers)
  'SecOps', 'SOC', 'AppSec', 'CloudSec', 'IAM', 'GRC',
  // Engineering (fixers)
  'Engineering', 'Mobile', 'Data',
  // Escape hatch
  'Custom',
]

const ROLE_OPTIONS = ['', ...OWNERSHIP_ROLE_OPTIONS.filter(r => r !== 'Custom')]

export function OwnershipEditPopover({ current, onSave, onClose }) {
  const [form, setForm] = useState(() => ({
    owner_name:  current?.owner_name  || '',
    owner_email: current?.owner_email || '',
    owner_role:  current?.owner_role  || '',
    team:        current?.team  || current?.owner_team || '',
    notes:       current?.notes       || '',
  }))
  const [saving, setSaving] = useState(false)
  const ref = useRef(null)

  useEffect(() => {
    if (current) {
      setForm({
        owner_name:  current.owner_name  || '',
        owner_email: current.owner_email || '',
        owner_role:  current.owner_role  || '',
        team:        current.team  || current.owner_team || '',
        notes:       current.notes       || '',
      })
    }
  }, [current])

  useEffect(() => {
    const handler = (e) => { if (ref.current && !ref.current.contains(e.target)) onClose() }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [onClose])

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }))

  const handleSave = async () => {
    setSaving(true)
    try { await onSave(form) } finally { setSaving(false) }
  }

  const fieldStyle = {
    background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 6,
    color: 'var(--text-primary)', fontSize: 12, padding: '5px 8px', width: '100%', outline: 'none',
  }

  return (
    <div ref={ref} onClick={e => e.stopPropagation()} style={{
      position: 'absolute', zIndex: 1000, background: 'var(--bg-card)',
      border: '1px solid var(--border)', borderRadius: 10, boxShadow: '0 8px 24px rgba(0,0,0,0.4)',
      padding: 14, width: 260, display: 'flex', flexDirection: 'column', gap: 8,
    }}>
      <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 2 }}>Edit Ownership</div>
      {[
        { key: 'owner_name',  label: 'Name' },
        { key: 'owner_email', label: 'Email' },
        { key: 'team',        label: 'Team' },
        { key: 'notes',       label: 'Notes' },
      ].map(({ key, label }) => (
        <div key={key}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 3 }}>{label}</div>
          <input value={form[key]} onChange={e => set(key, e.target.value)} style={fieldStyle} placeholder={label} />
        </div>
      ))}
      <div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 3 }}>Role</div>
        <select value={form.owner_role} onChange={e => set('owner_role', e.target.value)} style={fieldStyle}>
          {ROLE_OPTIONS.map(r => <option key={r} value={r}>{r || '— none —'}</option>)}
        </select>
      </div>
      <div style={{ display: 'flex', gap: 6, marginTop: 4 }}>
        <button onClick={handleSave} disabled={saving} style={{
          flex: 1, background: 'var(--accent)', color: '#fff', border: 'none', borderRadius: 6,
          fontSize: 12, fontWeight: 600, padding: '6px 0', cursor: 'pointer',
        }}>
          {saving ? 'Saving…' : 'Save'}
        </button>
        <button onClick={onClose} style={{
          flex: 1, background: 'var(--bg-hover)', color: 'var(--text-secondary)', border: '1px solid var(--border)',
          borderRadius: 6, fontSize: 12, padding: '6px 0', cursor: 'pointer',
        }}>
          Cancel
        </button>
      </div>
    </div>
  )
}

const ENV_OPTIONS = ['internal', 'external', 'dmz', 'production', 'development', 'test', 'staging', 'uat', 'qa', 'cloud', 'lab']
const BIZ_OPTIONS = [
  'Domain Controller', 'Active Directory', 'Identity Provider',
  'Web Server', 'Application Server', 'Database Server',
  'Mail Server', 'File Server', 'Backup Server',
  'Firewall', 'Proxy', 'VPN Gateway', 'Network Device', 'Load Balancer',
  'Terminal Server', 'Management Server', 'Print Server', 'DevOps Server', 'Workstation',
]

const REVENUE_OPTIONS = ['none', 'low', 'medium', 'high', 'critical']

export function ContextEditPopover({ field, currentValue, onSave, onConfirm, onClose, assetData }) {
  const [value, setValue] = useState(currentValue || '')
  const [numUsers, setNumUsers] = useState(assetData?.biz_num_users ?? '')
  const [revenueImpact, setRevenueImpact] = useState(assetData?.biz_revenue_impact || '')
  const [saving, setSaving] = useState(false)
  const ref = useRef(null)
  const anchorRef = useRef(null)
  const [pos, setPos] = useState(null)
  const isEnv = field === 'environment'
  const isBiz = field === 'business_context'

  useEffect(() => {
    if (anchorRef.current) {
      const parent = anchorRef.current.parentElement
      if (parent) {
        const rect = parent.getBoundingClientRect()
        const popW = field === 'business_context' ? 280 : 220
        const popH = field === 'business_context' ? 300 : 200
        let top = rect.bottom + 4
        let left = rect.left
        // Keep within viewport
        if (left + popW > window.innerWidth - 8) left = window.innerWidth - popW - 8
        if (left < 8) left = 8
        if (top + popH > window.innerHeight - 8) top = rect.top - popH - 4
        setPos({ top, left })
      }
    }
  }, [])

  useEffect(() => {
    const handler = (e) => {
      if (ref.current && !ref.current.contains(e.target) && anchorRef.current && !anchorRef.current.contains(e.target)) onClose()
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [onClose])

  const fieldStyle = {
    background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 6,
    color: 'var(--text-primary)', fontSize: 12, padding: '5px 8px', width: '100%', outline: 'none',
    boxSizing: 'border-box',
  }

  const handleSave = async () => {
    setSaving(true)
    try {
      if (isBiz) {
        await onSave(value, { biz_num_users: numUsers === '' ? null : parseInt(numUsers), biz_revenue_impact: revenueImpact || null })
      } else {
        await onSave(value)
      }
    } finally { setSaving(false) }
  }

  const handleConfirm = async () => {
    setSaving(true)
    try { await onConfirm() } finally { setSaving(false) }
  }

  const popoverContent = (
    <div ref={ref} onClick={e => e.stopPropagation()} style={{
      position: 'fixed', zIndex: 10000, background: 'var(--bg-card)',
      border: '1px solid var(--border)', borderRadius: 10, boxShadow: '0 8px 24px rgba(0,0,0,0.18)',
      padding: 14, width: isBiz ? 280 : 220, display: 'flex', flexDirection: 'column', gap: 8,
      ...(pos ? { top: pos.top, left: pos.left } : { top: 0, left: -9999 }),
    }}>
      <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 2 }}>
        {isEnv ? 'Environment' : 'Business Context'}
      </div>
      {isEnv ? (
        <select value={value} onChange={e => setValue(e.target.value)} style={fieldStyle}>
          <option value="">— none —</option>
          {ENV_OPTIONS.map(o => <option key={o} value={o}>{o}</option>)}
        </select>
      ) : (
        <>
          <div>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 3, textTransform: 'uppercase', fontWeight: 600 }}>Function</div>
            <select value={BIZ_OPTIONS.includes(value) ? value : ''} onChange={e => setValue(e.target.value)} style={fieldStyle}>
              <option value="">— custom —</option>
              {BIZ_OPTIONS.map(o => <option key={o} value={o}>{o}</option>)}
            </select>
            <input value={value} onChange={e => setValue(e.target.value)} style={{ ...fieldStyle, marginTop: 4 }} placeholder="Or type custom value…" />
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            <div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 3, textTransform: 'uppercase', fontWeight: 600 }}>No. of Users</div>
              <input type="number" min="0" value={numUsers} onChange={e => setNumUsers(e.target.value)} style={fieldStyle} placeholder="0" />
            </div>
            <div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 3, textTransform: 'uppercase', fontWeight: 600 }}>Revenue Impact</div>
              <select value={revenueImpact} onChange={e => setRevenueImpact(e.target.value)} style={fieldStyle}>
                <option value="">— not set —</option>
                {REVENUE_OPTIONS.map(o => <option key={o} value={o}>{o.charAt(0).toUpperCase() + o.slice(1)}</option>)}
              </select>
            </div>
          </div>
        </>
      )}
      <div style={{ display: 'flex', gap: 6, marginTop: 2 }}>
        {onConfirm && value === currentValue && (
          <button onClick={handleConfirm} disabled={saving} style={{
            flex: 1, background: '#16a34a22', color: '#22c55e', border: '1px solid #22c55e55',
            borderRadius: 6, fontSize: 11, fontWeight: 600, padding: '5px 0', cursor: 'pointer',
          }}>
            {saving ? '…' : 'Confirm'}
          </button>
        )}
        <button onClick={handleSave} disabled={saving} style={{
          flex: 1, background: 'var(--accent)', color: '#fff', border: 'none',
          borderRadius: 6, fontSize: 12, fontWeight: 600, padding: '6px 0', cursor: 'pointer',
        }}>
          {saving ? 'Saving…' : 'Save'}
        </button>
        <button onClick={onClose} style={{
          flex: 1, background: 'var(--bg-hover)', color: 'var(--text-secondary)', border: '1px solid var(--border)',
          borderRadius: 6, fontSize: 12, padding: '6px 0', cursor: 'pointer',
        }}>
          Cancel
        </button>
      </div>
    </div>
  )

  return (
    <>
      <span ref={anchorRef} style={{ position: 'absolute', top: 0, left: 0, width: 0, height: 0 }} />
      {createPortal(popoverContent, document.body)}
    </>
  )
}

export function ConfidenceDot({ confidence }) {
  const colors = { high: 'var(--success)', medium: 'var(--warning)', low: 'var(--muted)' }
  const c = colors[confidence] || colors.low
  return (
    <span title={`${confidence} confidence`} style={{
      display: 'inline-block', width: 8, height: 8, borderRadius: '50%',
      background: c, flexShrink: 0,
    }} />
  )
}

export function Spinner() {
  return (
    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', padding: 48 }}>
      <div style={{
        width: 32, height: 32, border: '3px solid var(--border)',
        borderTop: '3px solid var(--accent)', borderRadius: '50%',
        animation: 'spin 0.8s linear infinite',
      }} />
      <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
    </div>
  )
}

export function InlineSpinner({ size = 14 }) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', minHeight: '1.2em' }}>
      <div style={{
        width: size, height: size, border: '2px solid rgba(255,255,255,0.3)',
        borderTop: '2px solid #fff', borderRadius: '50%',
        animation: 'spin 0.8s linear infinite', flexShrink: 0,
      }} />
      <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
    </span>
  )
}

// ─────────────────────────────────────────────────────────
// Tag primitives
// ─────────────────────────────────────────────────────────

/**
 * TagPill – displays a single tag with its color dot.
 * onRemove: optional callback — renders an × button when provided.
 */
export function TagPill({ tag, onRemove, size = 'sm' }) {
  const color = tag.color || '#6366f1'
  const pad = size === 'xs' ? '1px 6px' : '2px 8px'
  const fs = size === 'xs' ? 10 : 11
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      background: `${color}18`, color, border: `1px solid ${color}44`,
      borderRadius: 999, padding: pad, fontSize: fs, fontWeight: 600,
      whiteSpace: 'nowrap', lineHeight: 1.4,
    }}>
      <span style={{
        width: size === 'xs' ? 5 : 6, height: size === 'xs' ? 5 : 6,
        borderRadius: '50%', background: color, flexShrink: 0,
      }} />
      {tag.label || `${tag.category}:${tag.value}`}
      {onRemove && (
        <button
          onClick={e => { e.stopPropagation(); onRemove(tag) }}
          style={{
            background: 'none', border: 'none', cursor: 'pointer',
            color, padding: 0, lineHeight: 1, fontSize: fs + 1, opacity: 0.7,
          }}
          title="Remove tag"
        >×</button>
      )}
    </span>
  )
}

/**
 * TagPicker – typeahead input for selecting/assigning tags.
 * Props:
 *   selectedTags: [{tag_id, label, category, value, color}]
 *   onChange(tags): called with updated selection
 *   placeholder: string
 *   multi: boolean (default true)
 */
export function TagPicker({ selectedTags = [], onChange, placeholder = 'Add tag…', multi = true }) {
  const [query, setQuery] = useState('')
  const [allTags, setAllTags] = useState([])
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

  useEffect(() => {
    getTags().then(setAllTags).catch(() => {})
  }, [])

  useEffect(() => {
    const handler = e => { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const selectedIds = new Set(selectedTags.map(t => t.tag_id))

  const filtered = allTags.filter(t => {
    if (selectedIds.has(t.id)) return false
    const q = query.toLowerCase()
    return !q || t.label.toLowerCase().includes(q) || t.category.toLowerCase().includes(q) || t.value.toLowerCase().includes(q)
  })

  // Group by category
  const grouped = {}
  for (const t of filtered) {
    if (!grouped[t.category]) grouped[t.category] = []
    grouped[t.category].push(t)
  }

  const select = (tag) => {
    const entry = { tag_id: tag.id, label: tag.label, category: tag.category, value: tag.value, color: tag.color }
    onChange(multi ? [...selectedTags, entry] : [entry])
    setQuery('')
    if (!multi) setOpen(false)
  }

  const remove = (tag) => onChange(selectedTags.filter(t => t.tag_id !== tag.tag_id))

  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <div
        style={{
          display: 'flex', flexWrap: 'wrap', gap: 4, alignItems: 'center',
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: 6, padding: '5px 8px', minHeight: 36, cursor: 'text',
        }}
        onClick={() => setOpen(true)}
      >
        {selectedTags.map(t => (
          <TagPill key={t.tag_id} tag={t} onRemove={remove} />
        ))}
        <input
          value={query}
          onChange={e => { setQuery(e.target.value); setOpen(true) }}
          onFocus={() => setOpen(true)}
          placeholder={selectedTags.length === 0 ? placeholder : ''}
          style={{
            flex: 1, minWidth: 80, border: 'none', background: 'transparent',
            outline: 'none', fontSize: 13, color: 'var(--text-primary)',
          }}
        />
      </div>
      {open && (
        <div style={{
          position: 'absolute', top: '100%', left: 0, right: 0, zIndex: 200,
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: 6, marginTop: 2, maxHeight: 280, overflowY: 'auto',
          boxShadow: '0 4px 16px rgba(0,0,0,0.18)',
        }}>
          {Object.keys(grouped).length === 0 ? (
            <div style={{ padding: '10px 14px', fontSize: 12, color: 'var(--text-muted)' }}>
              {allTags.length === 0 ? 'No tags defined yet' : 'No matching tags'}
            </div>
          ) : Object.entries(grouped).map(([cat, tags]) => (
            <div key={cat}>
              <div style={{
                padding: '6px 12px 2px', fontSize: 10, fontWeight: 700,
                color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em',
              }}>{cat}</div>
              {tags.map(t => (
                <div
                  key={t.id}
                  onClick={() => select(t)}
                  style={{
                    padding: '6px 12px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8,
                    fontSize: 13, color: 'var(--text-primary)',
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-hover)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <span style={{ width: 8, height: 8, borderRadius: '50%', background: t.color || '#6366f1', flexShrink: 0 }} />
                  {t.label}
                  {t.description && (
                    <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text-muted)', maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {t.description}
                    </span>
                  )}
                </div>
              ))}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

/**
 * ColumnSelector – dropdown menu to toggle column visibility.
 * Props:
 *   columns: [{key, label, defaultVisible?}] – all available columns
 *   visible: {key: bool} – current visibility state
 *   onChange(visible) – called with updated visibility map
 *   storageKey: string – localStorage key for persistence
 */
export function ColumnSelector({ columns, visible, onChange }) {
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

  useEffect(() => {
    const handler = e => { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const toggle = (key) => {
    const next = { ...visible, [key]: !visible[key] }
    onChange(next)
  }

  const toggleable = columns.filter(c => c.key !== '_select')

  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <button
        onClick={() => setOpen(!open)}
        style={{
          display: 'inline-flex', alignItems: 'center', gap: 5,
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: 6, padding: '6px 10px', fontSize: 12,
          color: 'var(--text-secondary)', cursor: 'pointer', fontWeight: 600,
          whiteSpace: 'nowrap',
        }}
        title="Show/Hide columns"
      >
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/>
          <rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/>
        </svg>
        Columns
      </button>
      {open && (
        <div style={{
          position: 'absolute', top: '100%', left: 0, zIndex: 200, minWidth: 200,
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: 8, marginTop: 4, maxHeight: 360, overflowY: 'auto',
          boxShadow: '0 4px 16px rgba(0,0,0,0.18)', padding: '6px 0',
        }}>
          {toggleable.map(col => (
            <label
              key={col.key}
              style={{
                display: 'flex', alignItems: 'center', gap: 8,
                padding: '6px 14px', cursor: 'pointer', fontSize: 13,
                color: 'var(--text-primary)',
              }}
              onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-hover)'}
              onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
            >
              <input
                type="checkbox"
                checked={visible[col.key] !== false}
                onChange={() => toggle(col.key)}
                style={{ accentColor: 'var(--accent)' }}
              />
              {typeof col.label === 'string' ? col.label : col.key}
            </label>
          ))}
        </div>
      )}
    </div>
  )
}


/**
 * TagFilterBar – compact multi-tag filter with AND/OR toggle.
 * Props: tags (array of tag objects with label/color), onChange, logic ('AND'|'OR'), onLogicChange
 */
export function TagFilterBar({ tags = [], onChange, logic = 'AND', onLogicChange }) {
  const [allTags, setAllTags] = useState([])
  const [query, setQuery] = useState('')
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

  useEffect(() => {
    getTags().then(setAllTags).catch(() => {})
  }, [])

  useEffect(() => {
    const handler = e => { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const selectedIds = new Set(tags.map(t => t.id || t.tag_id))
  const filtered = allTags.filter(t => {
    if (selectedIds.has(t.id)) return false
    const q = query.toLowerCase()
    return !q || t.label.toLowerCase().includes(q)
  })

  const add = (tag) => { onChange([...tags, tag]); setQuery(''); setOpen(false) }
  const remove = (tag) => onChange(tags.filter(t => (t.id || t.tag_id) !== (tag.id || tag.tag_id)))

  return (
    <div ref={ref} style={{ position: 'relative', display: 'flex', alignItems: 'center', gap: 4, flexWrap: 'wrap' }}>
      {tags.map((t, i) => (
        <span key={t.id || t.tag_id} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          {i > 0 && (
            <button
              onClick={() => onLogicChange && onLogicChange(logic === 'AND' ? 'OR' : 'AND')}
              style={{
                background: 'var(--bg-hover)', border: '1px solid var(--border)',
                borderRadius: 4, padding: '1px 6px', fontSize: 10, cursor: 'pointer',
                color: 'var(--text-muted)', fontWeight: 700,
              }}
              title="Click to toggle AND/OR"
            >{logic}</button>
          )}
          <TagPill tag={t} onRemove={() => remove(t)} size="sm" />
        </span>
      ))}
      <div style={{ position: 'relative' }}>
        <input
          value={query}
          onChange={e => { setQuery(e.target.value); setOpen(true) }}
          onFocus={() => setOpen(true)}
          placeholder={tags.length === 0 ? 'Filter by tag…' : '+tag'}
          style={{
            background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: 6, padding: '7px 12px', fontSize: 13,
            color: tags.length === 0 && !query ? 'var(--text-muted)' : 'var(--text-primary)',
            outline: 'none', width: tags.length === 0 ? 140 : 80, cursor: 'pointer',
          }}
        />
        {open && filtered.length > 0 && (
          <div style={{
            position: 'absolute', top: '100%', left: 0, zIndex: 200, minWidth: 200,
            background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: 6, marginTop: 2, maxHeight: 240, overflowY: 'auto',
            boxShadow: '0 4px 16px rgba(0,0,0,0.18)',
          }}>
            {filtered.map(t => (
              <div
                key={t.id}
                onClick={() => add(t)}
                style={{ padding: '7px 12px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}
                onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-hover)'}
                onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
              >
                <span style={{ width: 7, height: 7, borderRadius: '50%', background: t.color || '#6366f1' }} />
                {t.label}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}


/**
 * Export / Import buttons for config portability.
 *
 * Props:
 *   configType   — "risk_config" | "auto_tag_rules" | "report_template" | "campaign_workflow"
 *   exportFn     — async () => envelope JSON (if custom, e.g. with params). Falls back to exportConfig(configType).
 *   importFn     — async (file, conflict) => result. Falls back to importConfig(configType, file, conflict).
 *   onImported   — callback after successful import (e.g. to refresh data)
 *   label        — optional button label prefix (default: "Config")
 *   showConflict — show skip/overwrite dropdown (default: true)
 *   style        — wrapper style
 */
export function ExportImportButtons({
  configType, exportFn, importFn, onImported, label = 'Config',
  showConflict = true, style = {},
}) {
  const fileRef = useRef(null)
  const [conflict, setConflict] = useState('skip')
  const [status, setStatus] = useState(null) // {type: 'ok'|'error', msg: string}

  const handleExport = useCallback(async () => {
    try {
      setStatus(null)
      const data = exportFn ? await exportFn() : await (await import('../../api.js')).exportConfig(configType)
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${configType}-${new Date().toISOString().slice(0, 10)}.json`
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
      setStatus({ type: 'ok', msg: 'Exported' })
      setTimeout(() => setStatus(null), 2000)
    } catch (e) {
      setStatus({ type: 'error', msg: e.message || 'Export failed' })
    }
  }, [exportFn, configType])

  const handleImport = useCallback(async (e) => {
    const file = e.target.files?.[0]
    if (!file) return
    try {
      setStatus(null)
      const result = importFn
        ? await importFn(file, conflict)
        : await (await import('../../api.js')).importConfig(configType, file, conflict)
      const msg = result.message || `Imported${result.imported != null ? ` ${result.imported}` : ''}`
      setStatus({ type: 'ok', msg })
      onImported?.()
      setTimeout(() => setStatus(null), 3000)
    } catch (err) {
      setStatus({ type: 'error', msg: err.message || 'Import failed' })
    }
    // Reset file input so same file can be re-selected
    e.target.value = ''
  }, [importFn, configType, conflict, onImported])

  const btnStyle = {
    display: 'inline-flex', alignItems: 'center', gap: 5,
    padding: '5px 12px', borderRadius: 6, fontSize: 12, fontWeight: 600,
    cursor: 'pointer', border: '1px solid var(--border)',
    background: 'transparent', color: 'var(--text)',
  }

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', ...style }}>
      {exportFn !== null && (
        <button onClick={handleExport} style={btnStyle} title={`Export ${label}`}>
          <span style={{ fontSize: 13 }}>{'\u2B07'}</span> Export
        </button>
      )}
      <button onClick={() => fileRef.current?.click()} style={btnStyle} title={`Import ${label}`}>
        <span style={{ fontSize: 13 }}>{'\u2B06'}</span> Import
      </button>
      <input
        ref={fileRef} type="file" accept=".json"
        style={{ display: 'none' }}
        onChange={handleImport}
      />
      {showConflict && (
        <select
          value={conflict} onChange={e => setConflict(e.target.value)}
          style={{
            padding: '4px 8px', borderRadius: 6, fontSize: 11, border: '1px solid var(--border)',
            background: 'var(--bg-secondary)', color: 'var(--text)',
          }}
          title="Conflict resolution on import"
        >
          <option value="skip">Skip duplicates</option>
          <option value="overwrite">Overwrite</option>
        </select>
      )}
      {status && (
        <span style={{
          fontSize: 11, fontWeight: 600,
          color: status.type === 'ok' ? 'var(--success)' : 'var(--danger)',
        }}>
          {status.msg}
        </span>
      )}
    </div>
  )
}

// ─── Save as Campaign / Auto-tag Rule modal ───────────────────────────────────
// Converts a filter conditions array (from filtersToConditions) into a Campaign
// or Auto-tag Rule. Caller is responsible for navigation after creation.
export function SaveAsRuleModal({ conditions = [], scanId, onClose, onCreated }) {
  const [tab, setTab] = useState('campaign')
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(null)
  const [success, setSuccess] = useState(null)

  // Auto-tag specific
  const [selectedTag, setSelectedTag] = useState([])
  const [targetType, setTargetType] = useState('asset')

  const hasConditions = conditions.length > 0

  const handleCreateCampaign = async () => {
    if (!name.trim()) { setError('Name is required'); return }
    if (!hasConditions) { setError('No mappable filters — add at least one supported filter first'); return }
    setSaving(true); setError(null)
    try {
      const result = await createCampaign({
        name: name.trim(),
        description: description.trim() || null,
        scan_id: scanId || null,
        query: conditions,
        query_logic: 'AND',
        status: 'planned',
      })
      onCreated('campaign', result)
    } catch (e) {
      setError(e.message || 'Failed to create campaign')
    } finally {
      setSaving(false)
    }
  }

  const handleCreateRule = async () => {
    if (!name.trim()) { setError('Name is required'); return }
    if (!selectedTag.length) { setError('Select a tag to apply'); return }
    if (!hasConditions) { setError('No mappable filters — add at least one supported filter first'); return }
    setSaving(true); setError(null)
    try {
      const tagId = selectedTag[0]?.tag_id || selectedTag[0]?.id
      await createAutoTagRule({
        name: name.trim(),
        tag_id: Number(tagId),
        target_type: targetType,
        conditions,
        condition_logic: 'AND',
        is_enabled: true,
      })
      setSuccess('Rule created!')
      setTimeout(() => { onClose(); onCreated('autotag', null) }, 1500)
    } catch (e) {
      setError(e.message || 'Failed to create rule')
    } finally {
      setSaving(false)
    }
  }

  const tabStyle = (active) => ({
    flex: 1, padding: '8px 0', fontSize: 13, fontWeight: active ? 600 : 400,
    color: active ? 'var(--accent)' : 'var(--text-muted)',
    background: 'none', border: 'none', borderBottom: `2px solid ${active ? 'var(--accent)' : 'transparent'}`,
    cursor: 'pointer', marginBottom: -1,
  })

  const inp = {
    width: '100%', background: 'var(--bg)', border: '1px solid var(--border)',
    color: 'var(--text-primary)', borderRadius: 6, padding: '7px 10px',
    fontSize: 13, outline: 'none', boxSizing: 'border-box',
  }
  const lbl = { fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 1000,
      background: 'rgba(0,0,0,0.55)', display: 'flex', alignItems: 'center', justifyContent: 'center',
    }} onClick={e => { if (e.target === e.currentTarget) onClose() }}>
      <div style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 12,
        padding: 24, width: 460, maxWidth: '95vw', display: 'flex', flexDirection: 'column', gap: 16,
      }}>
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)' }}>Save as…</span>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', display: 'flex' }}>
            ✕
          </button>
        </div>

        {/* Conditions preview */}
        <div style={{
          fontSize: 12, color: 'var(--text-muted)', background: 'var(--bg-secondary)',
          borderRadius: 6, padding: '8px 12px', border: '1px solid var(--border)',
        }}>
          {hasConditions
            ? <><span style={{ color: 'var(--accent)', fontWeight: 600 }}>{conditions.length}</span> condition{conditions.length !== 1 ? 's' : ''} from your current filters will define the scope</>
            : <span style={{ color: 'var(--danger)' }}>No mappable filters active — set severity, family, hostname, etc. first</span>
          }
        </div>

        {/* Tab bar */}
        <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', marginBottom: -8 }}>
          <button style={tabStyle(tab === 'campaign')} onClick={() => { setTab('campaign'); setError(null) }}>Campaign</button>
          <button style={tabStyle(tab === 'autotag')} onClick={() => { setTab('autotag'); setError(null) }}>Auto-tag Rule</button>
        </div>

        {/* Campaign form */}
        {tab === 'campaign' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div>
              <label style={lbl}>Campaign name *</label>
              <input value={name} onChange={e => setName(e.target.value)} placeholder="e.g. Critical Windows — Q1 2026" style={inp} autoFocus />
            </div>
            <div>
              <label style={lbl}>Description</label>
              <textarea value={description} onChange={e => setDescription(e.target.value)} placeholder="Optional description" rows={2}
                style={{ ...inp, resize: 'vertical', fontFamily: 'inherit' }} />
            </div>
          </div>
        )}

        {/* Auto-tag rule form */}
        {tab === 'autotag' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div>
              <label style={lbl}>Rule name *</label>
              <input value={name} onChange={e => setName(e.target.value)} placeholder="e.g. Tag critical findings" style={inp} autoFocus />
            </div>
            <div>
              <label style={lbl}>Apply tag *</label>
              <TagPicker selectedTags={selectedTag} onChange={setSelectedTag} placeholder="Search tags…" multi={false} />
            </div>
            <div>
              <label style={lbl}>Applies to</label>
              <select value={targetType} onChange={e => setTargetType(e.target.value)} style={inp}>
                <option value="asset">Assets only</option>
                <option value="finding">Findings only</option>
                <option value="both">Assets + Findings</option>
              </select>
            </div>
          </div>
        )}

        {/* Error / success */}
        {error && <div style={{ fontSize: 12, color: 'var(--danger)', background: 'var(--danger-subtle)', borderRadius: 6, padding: '6px 10px' }}>{error}</div>}
        {success && <div style={{ fontSize: 12, color: 'var(--success)', background: 'var(--success-subtle)', borderRadius: 6, padding: '6px 10px' }}>✓ {success}</div>}

        {/* Footer */}
        {!success && (
          <div style={{ display: 'flex', gap: 8, paddingTop: 4 }}>
            <Button
              onClick={tab === 'campaign' ? handleCreateCampaign : handleCreateRule}
              disabled={saving || !hasConditions}
              style={{ flex: 1 }}
            >
              {saving ? 'Creating…' : tab === 'campaign' ? 'Create Campaign' : 'Create Rule'}
            </Button>
            <Button variant="ghost" onClick={onClose}>Cancel</Button>
          </div>
        )}
      </div>
    </div>
  )
}


// ── Source / Data-source helpers ──────────────────────────────────────

export const SOURCE_TYPES = {
  nessus:     { label: 'Nessus',   color: '#6366f1', bg: '#6366f122' },
  easm:       { label: 'EASM',     color: '#0ea5e9', bg: '#0ea5e922' },
  qualys:     { label: 'Qualys',   color: '#8b5cf6', bg: '#8b5cf622' },
  rapid7:     { label: 'Rapid7',   color: '#f97316', bg: '#f9731622' },
  openvas:    { label: 'OpenVAS',  color: '#22c55e', bg: '#22c55e22' },
  vm_scanner: { label: 'VM',       color: '#ec4899', bg: '#ec489922' },
}

export function getSourceMeta(type) {
  return SOURCE_TYPES[type] || { label: type || 'Unknown', color: '#71717a', bg: '#71717a22' }
}

export function SourceBadge({ source }) {
  const meta = getSourceMeta(source)
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      background: meta.bg, color: meta.color, border: `1px solid ${meta.color}44`,
      borderRadius: 5, padding: '1px 7px', fontSize: 11, fontWeight: 600,
      whiteSpace: 'nowrap',
    }}>
      {meta.label}
    </span>
  )
}

export function SourceDots({ sources = [] }) {
  const [hover, setHover] = useState(false)
  if (!sources.length) return null

  // Single source — show a compact labeled dot
  if (sources.length === 1) {
    const meta = getSourceMeta(sources[0])
    return (
      <span style={{
        display: 'inline-flex', alignItems: 'center', gap: 4,
        fontSize: 10, fontWeight: 600, color: meta.color, whiteSpace: 'nowrap',
      }}>
        <span style={{
          width: 8, height: 8, borderRadius: '50%', background: meta.color, flexShrink: 0,
        }} />
        {meta.label}
      </span>
    )
  }

  // Multi-source — overlapping colored dots with hover tooltip
  return (
    <span
      style={{ display: 'inline-flex', alignItems: 'center', position: 'relative', cursor: 'default' }}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
    >
      {/* Overlapping dots */}
      <span style={{ display: 'inline-flex' }}>
        {sources.map((s, i) => {
          const meta = getSourceMeta(s)
          return (
            <span key={s} style={{
              width: 10, height: 10, borderRadius: '50%',
              background: meta.color, border: '1.5px solid var(--bg-card)',
              marginLeft: i > 0 ? -4 : 0, zIndex: sources.length - i,
              position: 'relative',
            }} />
          )
        })}
      </span>
      <span style={{ fontSize: 10, color: 'var(--text-muted)', marginLeft: 4, fontWeight: 600 }}>
        {sources.length}
      </span>

      {/* Tooltip on hover */}
      {hover && (
        <span style={{
          position: 'absolute', bottom: '100%', left: 0,
          marginBottom: 6, padding: '6px 10px', borderRadius: 6,
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          boxShadow: '0 4px 12px rgba(0,0,0,.25)',
          zIndex: 999, whiteSpace: 'nowrap',
          display: 'flex', flexDirection: 'column', gap: 4,
        }}>
          {sources.map(s => {
            const meta = getSourceMeta(s)
            return (
              <span key={s} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11 }}>
                <span style={{
                  width: 8, height: 8, borderRadius: '50%', background: meta.color, flexShrink: 0,
                }} />
                <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{meta.label}</span>
              </span>
            )
          })}
        </span>
      )}
    </span>
  )
}

/** @deprecated Use SourceDots for compact display */
export function SourceBadges({ sources = [] }) {
  return <SourceDots sources={sources} />
}

export function SourceFilter({ value, onChange }) {
  const [sources, setSources] = useState([])
  useEffect(() => {
    getSources().then(d => setSources(d.sources || [])).catch(() => {})
  }, [])
  if (!sources.length) return null
  const options = sources.map(s => {
    const meta = getSourceMeta(s)
    return { value: s, label: meta.label }
  })
  return <Select value={value} onChange={onChange} placeholder="All Sources" options={options} />
}

// ─────────────────────────────────────────────────────────
// Error Boundary
// ─────────────────────────────────────────────────────────

export class ErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error }
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          display: 'flex', flexDirection: 'column', alignItems: 'center',
          justifyContent: 'center', padding: '64px 24px', gap: 16,
          minHeight: this.props.fullPage ? '60vh' : undefined,
        }}>
          <div style={{ fontSize: 40 }}>⚠</div>
          <div style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-secondary)' }}>
            {this.props.title || 'Something went wrong'}
          </div>
          <div style={{ fontSize: 13, color: 'var(--text-muted)', textAlign: 'center', maxWidth: 420 }}>
            {this.state.error?.message || 'An unexpected error occurred.'}
          </div>
          <button
            onClick={() => this.setState({ hasError: false, error: null })}
            style={{
              padding: '8px 20px', borderRadius: 6, border: '1px solid var(--border)',
              background: 'var(--bg)', color: 'var(--text)', cursor: 'pointer',
              fontSize: 13, fontWeight: 500,
            }}
          >
            Try again
          </button>
        </div>
      )
    }
    return this.props.children
  }
}

// ─────────────────────────────────────────────────────────
// Error Banner (for page-level fetch errors)
// ─────────────────────────────────────────────────────────

export function ErrorBanner({ error, onRetry, onDismiss }) {
  if (!error) return null
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 12,
      padding: '10px 16px', borderRadius: 8, marginBottom: 12,
      background: 'var(--danger-subtle, rgba(220,38,38,0.08))',
      border: '1px solid var(--danger, #dc2626)30',
      color: 'var(--danger, #dc2626)', fontSize: 13,
    }}>
      <span style={{ fontSize: 16, flexShrink: 0 }}>⚠</span>
      <span style={{ flex: 1 }}>
        {typeof error === 'string' ? error : 'Failed to load data. Please try again.'}
      </span>
      {onRetry && (
        <button
          onClick={onRetry}
          style={{
            padding: '4px 12px', borderRadius: 5, border: '1px solid var(--danger, #dc2626)40',
            background: 'transparent', color: 'var(--danger, #dc2626)',
            cursor: 'pointer', fontSize: 12, fontWeight: 600, whiteSpace: 'nowrap',
          }}
        >
          Retry
        </button>
      )}
      {onDismiss && (
        <button
          onClick={onDismiss}
          style={{
            padding: '2px 6px', borderRadius: 4, border: 'none',
            background: 'transparent', color: 'var(--danger, #dc2626)',
            cursor: 'pointer', fontSize: 16, lineHeight: 1,
          }}
        >
          ×
        </button>
      )}
    </div>
  )
}

// ─────────────────────────────────────────────────────────
// Skeleton Loaders
// ─────────────────────────────────────────────────────────

const skeletonKeyframes = `@keyframes shimmer {
  0% { background-position: -400px 0 }
  100% { background-position: 400px 0 }
}`

function SkeletonBase({ width, height, borderRadius = 4, style = {} }) {
  return (
    <>
      <div style={{
        width, height, borderRadius,
        background: 'linear-gradient(90deg, var(--border) 25%, var(--bg-hover, #f0f0f0) 50%, var(--border) 75%)',
        backgroundSize: '800px 100%',
        animation: 'shimmer 1.5s infinite linear',
        ...style,
      }} />
      <style>{skeletonKeyframes}</style>
    </>
  )
}

export function SkeletonRow({ columns = 5 }) {
  return (
    <div style={{ display: 'flex', gap: 16, padding: '12px 16px', borderBottom: '1px solid var(--border)' }}>
      {Array.from({ length: columns }).map((_, i) => (
        <SkeletonBase
          key={i}
          width={i === 0 ? '30%' : `${Math.floor(70 / (columns - 1))}%`}
          height={14}
        />
      ))}
    </div>
  )
}

export function SkeletonTable({ rows = 8, columns = 5 }) {
  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
      <div style={{ display: 'flex', gap: 16, padding: '12px 16px', background: 'var(--bg-secondary, var(--bg))' }}>
        {Array.from({ length: columns }).map((_, i) => (
          <SkeletonBase key={i} width={i === 0 ? '30%' : `${Math.floor(70 / (columns - 1))}%`} height={12} borderRadius={3} />
        ))}
      </div>
      {Array.from({ length: rows }).map((_, i) => (
        <SkeletonRow key={i} columns={columns} />
      ))}
    </div>
  )
}

export function SkeletonCard({ lines = 3 }) {
  return (
    <div style={{
      padding: 20, borderRadius: 8, border: '1px solid var(--border)',
      background: 'var(--bg)', display: 'flex', flexDirection: 'column', gap: 12,
    }}>
      <SkeletonBase width="40%" height={16} />
      {Array.from({ length: lines }).map((_, i) => (
        <SkeletonBase key={i} width={`${60 + Math.random() * 30}%`} height={12} />
      ))}
    </div>
  )
}

export function SkeletonDetail() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20, padding: 4 }}>
      <SkeletonBase width="50%" height={22} />
      <div style={{ display: 'flex', gap: 12 }}>
        <SkeletonBase width={80} height={24} borderRadius={12} />
        <SkeletonBase width={100} height={24} borderRadius={12} />
        <SkeletonBase width={60} height={24} borderRadius={12} />
      </div>
      <SkeletonCard lines={5} />
      <SkeletonCard lines={3} />
    </div>
  )
}
