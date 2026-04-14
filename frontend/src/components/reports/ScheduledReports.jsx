import { useState, useEffect, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { Mail, Calendar, Clock, Play, Trash2, AlertCircle, CheckCircle, ExternalLink } from 'lucide-react'
import {
  listAllReportSchedules,
  getReportTemplates,
  deleteReportSchedule,
  runReportScheduleNow,
  updateReportSchedule,
} from '../../api.js'
import { useToast, useConfirm } from '../shared/ui.jsx'

const DAY_LABELS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

function formatDT(iso) {
  if (!iso) return '—'
  try { return new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) }
  catch { return iso }
}

export default function ScheduledReports() {
  const { t } = useTranslation()
  const toast = useToast()
  const confirm = useConfirm()
  const navigate = useNavigate()
  const [rows, setRows] = useState([])
  const [templates, setTemplates] = useState([])
  const [loading, setLoading] = useState(true)

  const templateMap = useMemo(() => {
    const m = new Map()
    for (const tpl of templates) m.set(tpl.id, tpl)
    return m
  }, [templates])

  useEffect(() => { reload() }, [])

  async function reload() {
    try {
      setLoading(true)
      const [s, tpls] = await Promise.all([
        listAllReportSchedules(),
        getReportTemplates(),
      ])
      setRows(s || [])
      setTemplates(tpls || [])
    } catch (e) {
      toast.error(e.message || 'Failed to load schedules')
    } finally {
      setLoading(false)
    }
  }

  async function toggle(row) {
    try {
      await updateReportSchedule(row.id, { is_enabled: !row.is_enabled })
      reload()
    } catch (e) { toast.error(e.message) }
  }

  async function remove(row) {
    const ok = await confirm(t('reports.scheduleDeleteConfirm'))
    if (!ok) return
    try {
      await deleteReportSchedule(row.id)
      toast.success(t('reports.scheduleDeleted'))
      reload()
    } catch (e) { toast.error(e.message) }
  }

  async function runNow(row) {
    try {
      await runReportScheduleNow(row.id)
      toast.success(t('reports.scheduleRunQueued'))
    } catch (e) { toast.error(e.message) }
  }

  if (loading) {
    return <div style={{ padding: 30, color: 'var(--text-muted)' }}>Loading…</div>
  }

  return (
    <div style={{ padding: 24, maxWidth: 1100, margin: '0 auto' }}>
      <div style={{ marginBottom: 16 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, margin: 0 }}>
          {t('reports.scheduleEmailTitle')}
        </h1>
        <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 4 }}>
          {t('reports.scheduleEmailSubtitle')}
        </div>
      </div>

      {rows.length === 0 ? (
        <div style={{
          padding: 32, border: '1px dashed var(--border)', borderRadius: 10,
          textAlign: 'center', color: 'var(--text-muted)', fontSize: 14,
        }}>
          {t('reports.scheduleNone')}
        </div>
      ) : (
        <div style={{
          border: '1px solid var(--border)', borderRadius: 10, overflow: 'hidden',
          background: 'var(--bg-card)',
        }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr style={{ background: 'var(--bg-secondary)', textAlign: 'left' }}>
                <th style={thStyle()}>Report</th>
                <th style={thStyle()}>{t('reports.scheduleRecipients')}</th>
                <th style={thStyle()}>{t('reports.scheduleFrequency')}</th>
                <th style={thStyle()}>{t('reports.scheduleLastRun')}</th>
                <th style={thStyle()}>{t('reports.scheduleNextRun')}</th>
                <th style={thStyle()}></th>
              </tr>
            </thead>
            <tbody>
              {rows.map(r => {
                const tpl = templateMap.get(r.report_template_id)
                const StatusIcon = r.last_status === 'error' ? AlertCircle
                  : r.last_status === 'success' ? CheckCircle : Clock
                const statusColor = r.last_status === 'error' ? '#ef4444'
                  : r.last_status === 'success' ? '#16a34a' : 'var(--text-muted)'
                const freqBits = []
                freqBits.push(r.frequency)
                if (r.frequency === 'weekly' && r.day_of_week != null) freqBits.push(DAY_LABELS[r.day_of_week])
                if (r.frequency === 'monthly' && r.day_of_month != null) freqBits.push(`day ${r.day_of_month}`)
                if (r.frequency !== 'custom') {
                  freqBits.push(`${String(r.hour).padStart(2, '0')}:${String(r.minute).padStart(2, '0')} ${r.timezone || 'UTC'}`)
                } else if (r.cron_expression) {
                  freqBits.push(r.cron_expression)
                }

                return (
                  <tr key={r.id} style={{
                    borderTop: '1px solid var(--border)',
                    opacity: r.is_enabled ? 1 : 0.6,
                  }}>
                    <td style={tdStyle()}>
                      <button
                        onClick={() => tpl && navigate(`/reports/${tpl.id}`)}
                        style={{
                          background: 'none', border: 'none', color: 'var(--accent)',
                          cursor: tpl ? 'pointer' : 'default', fontSize: 13, fontWeight: 600,
                          display: 'inline-flex', alignItems: 'center', gap: 4, padding: 0,
                        }}
                      >
                        {tpl?.name || `#${r.report_template_id}`}
                        {tpl && <ExternalLink size={12} />}
                      </button>
                    </td>
                    <td style={tdStyle()}>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                        <Mail size={12} color="var(--text-muted)" />
                        {r.recipients}
                      </span>
                    </td>
                    <td style={tdStyle()}>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                        <Calendar size={12} color="var(--text-muted)" />
                        {freqBits.join(' · ')}
                      </span>
                    </td>
                    <td style={{ ...tdStyle(), color: statusColor }}>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                        <StatusIcon size={12} />
                        {formatDT(r.last_run_at)}
                      </span>
                    </td>
                    <td style={tdStyle()}>{formatDT(r.next_run_at)}</td>
                    <td style={{ ...tdStyle(), textAlign: 'right', whiteSpace: 'nowrap' }}>
                      <button onClick={() => runNow(r)} style={iconBtn()} title={t('reports.scheduleRunNow')}>
                        <Play size={13} />
                      </button>
                      <button onClick={() => toggle(r)} style={iconBtn()} title={r.is_enabled ? t('reports.scheduleDisabled') : t('reports.scheduleEnabled')}>
                        {r.is_enabled ? '⏸' : '▶'}
                      </button>
                      <button onClick={() => remove(r)} style={iconBtn('#ef4444')} title="Delete">
                        <Trash2 size={13} />
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function thStyle() {
  return { padding: '10px 12px', fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)' }
}
function tdStyle() {
  return { padding: '12px', verticalAlign: 'middle', color: 'var(--text-primary)' }
}
function iconBtn(color) {
  return {
    padding: '6px 10px', background: 'transparent',
    border: '1px solid var(--border)', borderRadius: 6, cursor: 'pointer',
    color: color || 'var(--text-secondary)', marginLeft: 4, fontSize: 12,
    display: 'inline-flex', alignItems: 'center', gap: 4,
  }
}
