import React, { useState, useEffect, useCallback, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { AlertTriangle, CheckCircle, XCircle, Clock, ChevronRight, Globe, Target, EyeOff, X } from 'lucide-react'
import { getAlerts, triageAlert, getAlert, createSuppressionRule } from '../../api'
import { PageHeader, EmptyState } from '../shared/ui'

const SEVERITY_COLORS = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#6b7280' }
const STATUS_ICONS = { open: AlertTriangle, triaged: Clock, closed: CheckCircle, false_positive: XCircle }

export default function AlertTriage() {
  const { t } = useTranslation()
  const [alerts, setAlerts] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [statusFilter, setStatusFilter] = useState('open')
  const [selectedAlert, setSelectedAlert] = useState(null)
  const [selectedIdx, setSelectedIdx] = useState(-1)
  const [page, setPage] = useState(1)
  const [showSuppressModal, setShowSuppressModal] = useState(false)
  const listRef = useRef(null)

  const loadAlerts = useCallback(async () => {
    setLoading(true)
    try {
      const params = { page, page_size: 50 }
      if (statusFilter) params.status = statusFilter
      const data = await getAlerts(params)
      setAlerts(data.items || [])
      setTotal(data.total || 0)
    } catch (e) { console.error(e) }
    finally { setLoading(false) }
  }, [statusFilter, page])

  useEffect(() => { loadAlerts() }, [loadAlerts])

  const handleTriage = async (alertId, status) => {
    await triageAlert(alertId, { status })
    loadAlerts()
    if (selectedAlert?.id === alertId) {
      setSelectedAlert(prev => ({ ...prev, status }))
    }
  }

  const handleSelect = async (alert, idx) => {
    setSelectedIdx(idx)
    try {
      const detail = await getAlert(alert.id)
      setSelectedAlert(detail)
    } catch { setSelectedAlert(alert) }
  }

  // Keyboard shortcuts
  useEffect(() => {
    const handler = (e) => {
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') return

      if (e.key === 'j' && alerts.length > 0) {
        e.preventDefault()
        const nextIdx = Math.min(selectedIdx + 1, alerts.length - 1)
        handleSelect(alerts[nextIdx], nextIdx)
      }
      if (e.key === 'k' && alerts.length > 0) {
        e.preventDefault()
        const prevIdx = Math.max(selectedIdx - 1, 0)
        handleSelect(alerts[prevIdx], prevIdx)
      }
      if (selectedAlert) {
        if (e.key === 't') { e.preventDefault(); handleTriage(selectedAlert.id, 'triaged') }
        if (e.key === 'f') { e.preventDefault(); handleTriage(selectedAlert.id, 'false_positive') }
        if (e.key === 's') { e.preventDefault(); setShowSuppressModal(true) }
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [alerts, selectedIdx, selectedAlert])

  return (
    <div>
      <PageHeader
        title={t('siem.alertTriage', 'Alert Triage')}
        subtitle={`${total} ${t('siem.alertsLabel', 'alerts')}`}
      />

      {/* Status filter tabs */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 16 }}>
        {['', 'open', 'triaged', 'closed', 'false_positive'].map(s => (
          <button key={s} onClick={() => { setStatusFilter(s); setPage(1) }}
                  style={{ padding: '6px 14px', borderRadius: 6, border: '1px solid var(--border)',
                           background: statusFilter === s ? 'var(--accent)' : 'var(--bg-secondary)',
                           color: statusFilter === s ? '#fff' : 'var(--text)', cursor: 'pointer', fontSize: 13 }}>
            {s || t('siem.all', 'All')}
          </button>
        ))}
        <div style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 8 }}>
          <kbd style={kbdStyle}>j/k</kbd> navigate
          <kbd style={kbdStyle}>t</kbd> triage
          <kbd style={kbdStyle}>f</kbd> FP
          <kbd style={kbdStyle}>s</kbd> suppress
        </div>
      </div>

      <div style={{ display: 'flex', gap: 16 }} ref={listRef}>
        {/* Alert list */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 6 }}>
          {loading ? <EmptyState icon={AlertTriangle} title={t('app.loading')} />
          : alerts.length === 0 ? <EmptyState icon={AlertTriangle} title={t('siem.noAlerts', 'No alerts')} sub={t('siem.noAlertsHint', 'Alerts will appear when detection rules are triggered by matching events.')} />
          : alerts.map((alert, idx) => (
            <div key={alert.id} onClick={() => handleSelect(alert, idx)}
                 style={{ padding: '12px 16px', borderRadius: 8, border: selectedIdx === idx ? '1px solid var(--accent)' : '1px solid var(--border)',
                          background: selectedAlert?.id === alert.id ? 'var(--bg-hover)' : 'var(--bg-secondary)',
                          cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 12, opacity: alert.suppressed ? 0.5 : 1 }}>
              <span style={{ width: 4, height: 36, borderRadius: 2, background: SEVERITY_COLORS[alert.severity] || '#6b7280' }} />
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 600, fontSize: 14, display: 'flex', alignItems: 'center', gap: 6 }}>
                  {alert.rule_name || `Rule #${alert.rule_id}`}
                  {alert.suppressed && <EyeOff size={12} style={{ color: '#6b7280' }} title="Suppressed" />}
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
                  {alert.event_count} events
                  {alert.entity_value && ` · ${alert.entity_type}: ${alert.entity_value}`}
                  {!alert.entity_value && alert.group_key && ` · ${alert.group_key}`}
                  {alert.fired_at && ` · ${new Date(alert.fired_at).toLocaleString()}`}
                </div>
              </div>
              <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600,
                background: (SEVERITY_COLORS[alert.severity] || '#6b7280') + '20', color: SEVERITY_COLORS[alert.severity] }}>
                {alert.severity}
              </span>
              <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase' }}>{alert.status}</span>
              <ChevronRight size={16} style={{ color: 'var(--text-muted)' }} />
            </div>
          ))}
        </div>

        {/* Detail panel */}
        {selectedAlert && (
          <div style={{ width: 420, padding: 20, borderRadius: 8, border: '1px solid var(--border)',
                        background: 'var(--bg-secondary)', overflowY: 'auto', maxHeight: 'calc(100vh - 200px)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12 }}>
              <h3 style={{ margin: 0, fontSize: 16 }}>{selectedAlert.rule_name || 'Alert Detail'}</h3>
              <button onClick={() => { setSelectedAlert(null); setSelectedIdx(-1) }}
                      style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}>
                <X size={16} />
              </button>
            </div>

            {/* Badges */}
            <div style={{ display: 'flex', gap: 6, marginBottom: 12, flexWrap: 'wrap' }}>
              <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600,
                background: (SEVERITY_COLORS[selectedAlert.severity] || '#6b7280') + '20', color: SEVERITY_COLORS[selectedAlert.severity] }}>
                {selectedAlert.severity}
              </span>
              <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 11, background: 'var(--bg)', color: 'var(--text-muted)' }}>
                {selectedAlert.status}
              </span>
              {selectedAlert.suppressed && (
                <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 11, background: '#6b728020', color: '#6b7280' }}>
                  <EyeOff size={10} style={{ verticalAlign: 'middle', marginRight: 3 }} /> Suppressed
                </span>
              )}
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 13 }}>
              <div><strong>{t('siem.eventCount', 'Events')}:</strong> {selectedAlert.event_count}</div>
              {selectedAlert.entity_value && (
                <div><strong>Entity:</strong> {selectedAlert.entity_type}: {selectedAlert.entity_value}</div>
              )}
              <div><strong>{t('siem.firedAt', 'Fired')}:</strong> {selectedAlert.fired_at ? new Date(selectedAlert.fired_at).toLocaleString() : '-'}</div>

              {/* Exposure context */}
              {selectedAlert.exposure_context && Object.keys(selectedAlert.exposure_context).length > 0 && (
                <div style={{ padding: 10, borderRadius: 8, background: 'var(--bg)', marginTop: 4 }}>
                  <div style={{ fontWeight: 600, marginBottom: 6, fontSize: 12, display: 'flex', alignItems: 'center', gap: 4 }}>
                    <Target size={12} /> Exposure Context
                  </div>
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', fontSize: 12 }}>
                    {selectedAlert.exposure_context.asset_name && (
                      <span>Asset: <strong>{selectedAlert.exposure_context.asset_name}</strong></span>
                    )}
                    {selectedAlert.asset_criticality != null && (
                      <span style={{ padding: '1px 6px', borderRadius: 3,
                        background: selectedAlert.asset_criticality >= 8 ? '#ef444420' : selectedAlert.asset_criticality >= 5 ? '#f9731620' : '#22c55e20',
                        color: selectedAlert.asset_criticality >= 8 ? '#ef4444' : selectedAlert.asset_criticality >= 5 ? '#f97316' : '#22c55e' }}>
                        Criticality {selectedAlert.asset_criticality}/10
                      </span>
                    )}
                    {selectedAlert.open_vulnerabilities > 0 && (
                      <span style={{ color: '#f97316' }}>{selectedAlert.open_vulnerabilities} crit+high vulns</span>
                    )}
                    {selectedAlert.internet_facing && (
                      <span style={{ display: 'flex', alignItems: 'center', gap: 2, color: '#ef4444' }}>
                        <Globe size={11} /> Internet-facing
                      </span>
                    )}
                  </div>
                </div>
              )}

              {/* Matching events */}
              {selectedAlert.context?.events_sample && (
                <div style={{ marginTop: 4 }}>
                  <div style={{ fontWeight: 600, marginBottom: 4 }}>{t('siem.matchingEvents', 'Matching Events')}</div>
                  {selectedAlert.context.events_sample.slice(0, 5).map((ev, i) => (
                    <div key={i} style={{ fontSize: 11, padding: '4px 8px', background: 'var(--bg)', borderRadius: 4, marginBottom: 4 }}>
                      <span style={{ color: 'var(--text-muted)' }}>{ev.event_time}</span> {ev.message}
                    </div>
                  ))}
                </div>
              )}

              {/* Action buttons */}
              <div style={{ display: 'flex', gap: 6, marginTop: 12 }}>
                <button onClick={() => handleTriage(selectedAlert.id, 'triaged')}
                        style={{ flex: 1, padding: '8px', borderRadius: 6, border: 'none', background: '#3b82f6', color: '#fff', cursor: 'pointer', fontSize: 12, fontWeight: 600 }}>
                  {t('siem.markTriaged', 'Triaged')}
                </button>
                <button onClick={() => handleTriage(selectedAlert.id, 'closed')}
                        style={{ flex: 1, padding: '8px', borderRadius: 6, border: 'none', background: '#22c55e', color: '#fff', cursor: 'pointer', fontSize: 12, fontWeight: 600 }}>
                  {t('siem.close', 'Close')}
                </button>
                <button onClick={() => handleTriage(selectedAlert.id, 'false_positive')}
                        style={{ flex: 1, padding: '8px', borderRadius: 6, border: 'none', background: '#6b7280', color: '#fff', cursor: 'pointer', fontSize: 12, fontWeight: 600 }}>
                  {t('siem.falsePositive', 'FP')}
                </button>
              </div>
              <div style={{ display: 'flex', gap: 6 }}>
                <button onClick={() => setShowSuppressModal(true)}
                        style={{ flex: 1, padding: '8px', borderRadius: 6, border: '1px solid var(--border)',
                                 background: 'transparent', color: 'var(--text)', cursor: 'pointer', fontSize: 12, fontWeight: 600,
                                 display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 4 }}>
                  <EyeOff size={12} /> Suppress
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Suppress modal */}
      {showSuppressModal && selectedAlert && (
        <SuppressModal alert={selectedAlert} onClose={() => setShowSuppressModal(false)} onCreated={() => { setShowSuppressModal(false); loadAlerts() }} />
      )}
    </div>
  )
}

const kbdStyle = {
  padding: '1px 5px', borderRadius: 3, border: '1px solid var(--border)',
  background: 'var(--bg)', fontFamily: 'monospace', fontSize: 10,
}


function SuppressModal({ alert, onClose, onCreated }) {
  const { t } = useTranslation()
  const [name, setName] = useState(`Suppress: ${alert.rule_name || 'Alert'}`)
  const [reason, setReason] = useState('')
  const [saving, setSaving] = useState(false)

  // Pre-fill conditions from alert's event data
  const conditions = []
  if (alert.entity_type === 'ip' && alert.entity_value) {
    conditions.push({ field: 'source_ip', op: 'eq', value: alert.entity_value })
  } else if (alert.entity_type === 'hostname' && alert.entity_value) {
    conditions.push({ field: 'host_name', op: 'eq', value: alert.entity_value })
  } else if (alert.entity_type === 'user' && alert.entity_value) {
    conditions.push({ field: 'user_name', op: 'eq', value: alert.entity_value })
  }

  const handleSubmit = async () => {
    if (!name.trim()) return
    setSaving(true)
    try {
      await createSuppressionRule({
        name: name.trim(),
        reason: reason.trim() || undefined,
        conditions,
        rule_id: alert.rule_id,
        enabled: true,
      })
      onCreated()
    } catch (e) { console.error(e) }
    finally { setSaving(false) }
  }

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', display: 'flex', alignItems: 'center',
                  justifyContent: 'center', zIndex: 1000 }}
         onClick={onClose}>
      <div style={{ background: 'var(--bg-secondary)', borderRadius: 12, padding: 24, width: 420,
                    border: '1px solid var(--border)' }}
           onClick={e => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <h3 style={{ margin: 0, fontSize: 16 }}>Create Suppression Rule</h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}><X size={16} /></button>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <input value={name} onChange={e => setName(e.target.value)} placeholder="Rule name"
                 style={{ padding: '8px 12px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', fontSize: 13 }} />
          <input value={reason} onChange={e => setReason(e.target.value)} placeholder="Reason (e.g., known scanner, maintenance)"
                 style={{ padding: '8px 12px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', fontSize: 13 }} />
          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            <div style={{ fontWeight: 600, marginBottom: 4 }}>Conditions (pre-filled from alert):</div>
            {conditions.length > 0 ? conditions.map((c, i) => (
              <div key={i} style={{ padding: '4px 8px', background: 'var(--bg)', borderRadius: 4, marginBottom: 2 }}>
                {c.field} {c.op} {c.value}
              </div>
            )) : <div>No conditions — will suppress all alerts from this rule</div>}
            {alert.rule_name && (
              <div style={{ marginTop: 4 }}>Scoped to rule: <strong>{alert.rule_name}</strong></div>
            )}
          </div>
          <button onClick={handleSubmit} disabled={saving || !name.trim()}
                  style={{ padding: '10px', borderRadius: 6, border: 'none', background: 'var(--accent)', color: '#fff',
                           cursor: 'pointer', fontSize: 13, fontWeight: 600, opacity: saving ? 0.6 : 1 }}>
            {saving ? 'Creating...' : 'Create Suppression Rule'}
          </button>
        </div>
      </div>
    </div>
  )
}
