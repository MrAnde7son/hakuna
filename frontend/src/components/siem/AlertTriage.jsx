import React, { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { AlertTriangle, CheckCircle, XCircle, User, Clock, ChevronRight } from 'lucide-react'
import { getAlerts, triageAlert, getAlert } from '../../api'

const SEVERITY_COLORS = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#6b7280' }
const STATUS_ICONS = { open: AlertTriangle, triaged: Clock, closed: CheckCircle, false_positive: XCircle }

export default function AlertTriage() {
  const { t } = useTranslation()
  const [alerts, setAlerts] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [statusFilter, setStatusFilter] = useState('open')
  const [selectedAlert, setSelectedAlert] = useState(null)
  const [page, setPage] = useState(1)

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

  const handleSelect = async (alert) => {
    try {
      const detail = await getAlert(alert.id)
      setSelectedAlert(detail)
    } catch { setSelectedAlert(alert) }
  }

  return (
    <div style={{ padding: '24px', maxWidth: 1400, margin: '0 auto' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 20 }}>
        <AlertTriangle size={24} style={{ color: '#f97316' }} />
        <h1 style={{ fontSize: 22, fontWeight: 700, margin: 0 }}>{t('siem.alertTriage', 'Alert Triage')}</h1>
        <span style={{ color: 'var(--text-muted)', fontSize: 14 }}>{total} {t('siem.alertsLabel', 'alerts')}</span>
      </div>

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
      </div>

      <div style={{ display: 'flex', gap: 16 }}>
        {/* Alert list */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 6 }}>
          {loading ? <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>{t('app.loading')}</div>
          : alerts.length === 0 ? <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>{t('siem.noAlerts', 'No alerts')}</div>
          : alerts.map(alert => (
            <div key={alert.id} onClick={() => handleSelect(alert)}
                 style={{ padding: '12px 16px', borderRadius: 8, border: '1px solid var(--border)',
                          background: selectedAlert?.id === alert.id ? 'var(--bg-hover)' : 'var(--bg-secondary)',
                          cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 12 }}>
              <span style={{ width: 4, height: 36, borderRadius: 2, background: SEVERITY_COLORS[alert.severity] || '#6b7280' }} />
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 600, fontSize: 14 }}>{alert.rule_name || `Rule #${alert.rule_id}`}</div>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
                  {alert.event_count} events · {alert.group_key || 'ungrouped'} · {alert.fired_at ? new Date(alert.fired_at).toLocaleString() : ''}
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
          <div style={{ width: 400, padding: 20, borderRadius: 8, border: '1px solid var(--border)', background: 'var(--bg-secondary)' }}>
            <h3 style={{ margin: '0 0 12px', fontSize: 16 }}>{selectedAlert.rule_name || 'Alert Detail'}</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 13 }}>
              <div><strong>{t('siem.severity', 'Severity')}:</strong> {selectedAlert.severity}</div>
              <div><strong>{t('siem.status', 'Status')}:</strong> {selectedAlert.status}</div>
              <div><strong>{t('siem.eventCount', 'Events')}:</strong> {selectedAlert.event_count}</div>
              <div><strong>{t('siem.groupKey', 'Group')}:</strong> {selectedAlert.group_key || '-'}</div>
              <div><strong>{t('siem.firedAt', 'Fired')}:</strong> {selectedAlert.fired_at ? new Date(selectedAlert.fired_at).toLocaleString() : '-'}</div>

              {selectedAlert.context?.events_sample && (
                <div style={{ marginTop: 8 }}>
                  <div style={{ fontWeight: 600, marginBottom: 4 }}>{t('siem.matchingEvents', 'Matching Events')}</div>
                  {selectedAlert.context.events_sample.slice(0, 5).map((ev, i) => (
                    <div key={i} style={{ fontSize: 11, padding: '4px 8px', background: 'var(--bg)', borderRadius: 4, marginBottom: 4 }}>
                      <span style={{ color: 'var(--text-muted)' }}>{ev.event_time}</span> {ev.message}
                    </div>
                  ))}
                </div>
              )}

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
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
