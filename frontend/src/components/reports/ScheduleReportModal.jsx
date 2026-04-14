import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { X, Calendar, Clock, Mail, Trash2, Plus, Play, AlertCircle, CheckCircle } from 'lucide-react'
import {
  listReportSchedulesForTemplate,
  createReportSchedule,
  updateReportSchedule,
  deleteReportSchedule,
  runReportScheduleNow,
} from '../../api.js'
import { useToast, useConfirm } from '../shared/ui.jsx'

const DAY_OF_WEEK_KEYS = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun']
const DAY_LABELS_EN = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

function formatDT(iso) {
  if (!iso) return '—'
  try {
    const d = new Date(iso)
    return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
  } catch { return iso }
}

function defaultForm() {
  return {
    recipients: '',
    frequency: 'weekly',
    day_of_week: 0,
    day_of_month: 1,
    hour: 8,
    minute: 0,
    cron_expression: '',
    timezone: 'UTC',
    subject_template: '',
    body_template: '',
    is_enabled: true,
    format: 'pdf',
  }
}

function rowStyle() {
  return { display: 'flex', flexDirection: 'column', gap: 6 }
}
function labelStyle() {
  return { fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)' }
}
function inputStyle() {
  return {
    padding: '8px 10px', background: 'var(--bg-primary)',
    border: '1px solid var(--border)', color: 'var(--text-primary)',
    borderRadius: 6, fontSize: 13, width: '100%',
  }
}

export default function ScheduleReportModal({ reportId, reportName, onClose }) {
  const { t } = useTranslation()
  const toast = useToast()
  const confirm = useConfirm()
  const [schedules, setSchedules] = useState([])
  const [loading, setLoading] = useState(true)
  const [editing, setEditing] = useState(null)    // schedule object being edited, or null
  const [form, setForm] = useState(defaultForm())
  const [saving, setSaving] = useState(false)

  useEffect(() => { reload() }, [reportId])

  async function reload() {
    if (!reportId) { setLoading(false); return }
    try {
      setLoading(true)
      const rows = await listReportSchedulesForTemplate(reportId)
      setSchedules(rows || [])
    } catch (e) {
      console.error('Failed to load schedules', e)
      toast.error(e.message || 'Failed to load schedules')
    } finally {
      setLoading(false)
    }
  }

  function startNew() {
    setEditing({ id: null })
    setForm(defaultForm())
  }

  function startEdit(s) {
    setEditing(s)
    setForm({
      recipients: s.recipients || '',
      frequency: s.frequency || 'weekly',
      day_of_week: s.day_of_week ?? 0,
      day_of_month: s.day_of_month ?? 1,
      hour: s.hour ?? 8,
      minute: s.minute ?? 0,
      cron_expression: s.cron_expression || '',
      timezone: s.timezone || 'UTC',
      subject_template: s.subject_template || '',
      body_template: s.body_template || '',
      is_enabled: !!s.is_enabled,
      format: s.format || 'pdf',
    })
  }

  async function save() {
    if (!form.recipients.trim()) {
      toast.error(t('reports.scheduleRecipientsRequired'))
      return
    }
    try {
      setSaving(true)
      const payload = { ...form }
      if (payload.frequency !== 'custom') payload.cron_expression = null
      if (editing?.id) {
        await updateReportSchedule(editing.id, payload)
      } else {
        await createReportSchedule(reportId, payload)
      }
      toast.success(t('reports.scheduleSaved'))
      setEditing(null)
      await reload()
    } catch (e) {
      toast.error(`${t('reports.scheduleSaveError')}: ${e.message || e}`)
    } finally {
      setSaving(false)
    }
  }

  async function remove(s) {
    const ok = await confirm(t('reports.scheduleDeleteConfirm'))
    if (!ok) return
    try {
      await deleteReportSchedule(s.id)
      toast.success(t('reports.scheduleDeleted'))
      reload()
    } catch (e) {
      toast.error(e.message || 'Failed to delete')
    }
  }

  async function runNow(s) {
    try {
      await runReportScheduleNow(s.id)
      toast.success(t('reports.scheduleRunQueued'))
    } catch (e) {
      toast.error(e.message || 'Failed to queue run')
    }
  }

  const overlay = {
    position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.55)',
    display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1100,
  }
  const panel = {
    background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 12,
    width: 'min(640px, 94vw)', maxHeight: '92vh', overflow: 'auto', padding: 0,
    boxShadow: '0 20px 60px rgba(0,0,0,0.55)',
  }
  const header = {
    display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between',
    padding: '16px 20px', borderBottom: '1px solid var(--border)',
  }

  return (
    <div style={overlay} onClick={onClose}>
      <div style={panel} onClick={e => e.stopPropagation()}>
        <div style={header}>
          <div>
            <div style={{ fontSize: 16, fontWeight: 700 }}>
              {t('reports.scheduleEmailTitle')}
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>
              {reportName} · {t('reports.scheduleEmailSubtitle')}
            </div>
          </div>
          <button
            onClick={onClose}
            style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
            aria-label="Close"
          >
            <X size={18} />
          </button>
        </div>

        <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
          {loading ? (
            <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>Loading…</div>
          ) : (
            <>
              {!editing && (
                <>
                  {schedules.length === 0 && (
                    <div style={{
                      padding: 20, border: '1px dashed var(--border)', borderRadius: 8,
                      textAlign: 'center', color: 'var(--text-muted)', fontSize: 13,
                    }}>
                      {t('reports.scheduleNone')}
                    </div>
                  )}
                  {schedules.map(s => (
                    <ScheduleCard key={s.id} schedule={s} onEdit={() => startEdit(s)}
                                  onDelete={() => remove(s)} onRun={() => runNow(s)} t={t} />
                  ))}
                  <button
                    onClick={startNew}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 6, justifyContent: 'center',
                      padding: '10px 14px', background: 'var(--accent)', color: '#fff',
                      border: 'none', borderRadius: 6, cursor: 'pointer', fontWeight: 600, fontSize: 13,
                    }}
                  >
                    <Plus size={14} /> {t('reports.scheduleNew')}
                  </button>
                </>
              )}

              {editing && (
                <ScheduleForm
                  form={form} setForm={setForm}
                  saving={saving}
                  onSave={save}
                  onCancel={() => setEditing(null)}
                  t={t}
                />
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}

function ScheduleCard({ schedule, onEdit, onDelete, onRun, t }) {
  const freqLabel = {
    daily: t('reports.scheduleFrequencyDaily'),
    weekly: t('reports.scheduleFrequencyWeekly'),
    monthly: t('reports.scheduleFrequencyMonthly'),
    custom: t('reports.scheduleFrequencyCustom'),
  }[schedule.frequency] || schedule.frequency

  const timePart = schedule.frequency === 'custom'
    ? schedule.cron_expression
    : `${String(schedule.hour).padStart(2, '0')}:${String(schedule.minute).padStart(2, '0')} ${schedule.timezone || 'UTC'}`

  const dayPart = schedule.frequency === 'weekly'
    ? DAY_LABELS_EN[schedule.day_of_week ?? 0]
    : schedule.frequency === 'monthly' ? `day ${schedule.day_of_month ?? 1}` : ''

  const StatusIcon = schedule.last_status === 'error' ? AlertCircle
    : schedule.last_status === 'success' ? CheckCircle : Clock
  const statusColor = schedule.last_status === 'error' ? '#ef4444'
    : schedule.last_status === 'success' ? '#16a34a' : 'var(--text-muted)'

  return (
    <div style={{
      border: '1px solid var(--border)', borderRadius: 8, padding: 12,
      display: 'flex', flexDirection: 'column', gap: 8,
      background: schedule.is_enabled ? 'var(--bg-primary)' : 'var(--bg-secondary)',
      opacity: schedule.is_enabled ? 1 : 0.75,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <Mail size={14} color="var(--text-secondary)" />
        <div style={{ flex: 1, fontSize: 13, fontWeight: 600, wordBreak: 'break-word' }}>
          {schedule.recipients}
        </div>
        {!schedule.is_enabled && (
          <span style={{
            fontSize: 11, color: 'var(--text-muted)', padding: '2px 6px',
            border: '1px solid var(--border)', borderRadius: 4,
          }}>{t('reports.scheduleDisabled')}</span>
        )}
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 14, fontSize: 12, color: 'var(--text-secondary)', flexWrap: 'wrap' }}>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
          <Calendar size={12} /> {freqLabel}{dayPart ? ` · ${dayPart}` : ''}
        </span>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
          <Clock size={12} /> {timePart}
        </span>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, color: statusColor }}>
          <StatusIcon size={12} /> {t('reports.scheduleLastRun')}: {formatDT(schedule.last_run_at)}
        </span>
        <span style={{ color: 'var(--text-muted)' }}>
          {t('reports.scheduleNextRun')}: {formatDT(schedule.next_run_at)}
        </span>
      </div>
      {schedule.last_status === 'error' && schedule.last_error && (
        <div style={{ fontSize: 11, color: '#ef4444', fontFamily: 'monospace' }}>
          {schedule.last_error}
        </div>
      )}
      <div style={{ display: 'flex', gap: 6 }}>
        <button onClick={onRun} style={btnStyle('ghost')}>
          <Play size={12} /> {t('reports.scheduleRunNow')}
        </button>
        <button onClick={onEdit} style={btnStyle('ghost')}>Edit</button>
        <div style={{ flex: 1 }} />
        <button onClick={onDelete} style={btnStyle('danger')}>
          <Trash2 size={12} />
        </button>
      </div>
    </div>
  )
}

function ScheduleForm({ form, setForm, saving, onSave, onCancel, t }) {
  const upd = (patch) => setForm(f => ({ ...f, ...patch }))

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={rowStyle()}>
        <label style={labelStyle()}>{t('reports.scheduleRecipients')}</label>
        <input
          value={form.recipients}
          onChange={e => upd({ recipients: e.target.value })}
          placeholder={t('reports.scheduleRecipientsPlaceholder')}
          style={inputStyle()}
        />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <div style={rowStyle()}>
          <label style={labelStyle()}>{t('reports.scheduleFrequency')}</label>
          <select
            value={form.frequency}
            onChange={e => upd({ frequency: e.target.value })}
            style={inputStyle()}
          >
            <option value="daily">{t('reports.scheduleFrequencyDaily')}</option>
            <option value="weekly">{t('reports.scheduleFrequencyWeekly')}</option>
            <option value="monthly">{t('reports.scheduleFrequencyMonthly')}</option>
            <option value="custom">{t('reports.scheduleFrequencyCustom')}</option>
          </select>
        </div>
        <div style={rowStyle()}>
          <label style={labelStyle()}>{t('reports.scheduleTimezone')}</label>
          <input
            value={form.timezone}
            onChange={e => upd({ timezone: e.target.value })}
            placeholder="UTC"
            style={inputStyle()}
          />
        </div>
      </div>

      {form.frequency === 'weekly' && (
        <div style={rowStyle()}>
          <label style={labelStyle()}>{t('reports.scheduleDayOfWeek')}</label>
          <select
            value={form.day_of_week}
            onChange={e => upd({ day_of_week: Number(e.target.value) })}
            style={inputStyle()}
          >
            {DAY_LABELS_EN.map((d, i) => <option key={i} value={i}>{d}</option>)}
          </select>
        </div>
      )}
      {form.frequency === 'monthly' && (
        <div style={rowStyle()}>
          <label style={labelStyle()}>{t('reports.scheduleDayOfMonth')}</label>
          <input
            type="number" min={1} max={28}
            value={form.day_of_month}
            onChange={e => upd({ day_of_month: Number(e.target.value) })}
            style={inputStyle()}
          />
        </div>
      )}

      {form.frequency === 'custom' ? (
        <div style={rowStyle()}>
          <label style={labelStyle()}>{t('reports.scheduleCron')}</label>
          <input
            value={form.cron_expression}
            onChange={e => upd({ cron_expression: e.target.value })}
            placeholder="0 8 * * 1"
            style={{ ...inputStyle(), fontFamily: 'monospace' }}
          />
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            {t('reports.scheduleCronHint')}
          </span>
        </div>
      ) : (
        <div style={rowStyle()}>
          <label style={labelStyle()}>{t('reports.scheduleTime')}</label>
          <input
            type="time"
            value={`${String(form.hour).padStart(2, '0')}:${String(form.minute).padStart(2, '0')}`}
            onChange={e => {
              const [h, m] = e.target.value.split(':')
              upd({ hour: Number(h), minute: Number(m) })
            }}
            style={inputStyle()}
          />
        </div>
      )}

      <div style={rowStyle()}>
        <label style={labelStyle()}>{t('reports.scheduleSubject')}</label>
        <input
          value={form.subject_template}
          onChange={e => upd({ subject_template: e.target.value })}
          placeholder={t('reports.scheduleSubjectPlaceholder')}
          style={inputStyle()}
        />
      </div>

      <div style={rowStyle()}>
        <label style={labelStyle()}>{t('reports.scheduleBody')}</label>
        <textarea
          value={form.body_template}
          onChange={e => upd({ body_template: e.target.value })}
          placeholder={t('reports.scheduleBodyPlaceholder')}
          rows={3}
          style={{ ...inputStyle(), resize: 'vertical', fontFamily: 'inherit' }}
        />
      </div>

      <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
        <input
          type="checkbox"
          checked={form.is_enabled}
          onChange={e => upd({ is_enabled: e.target.checked })}
        />
        {t('reports.scheduleEnabled')}
      </label>

      <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
        <button onClick={onCancel} disabled={saving} style={btnStyle('ghost')}>
          Cancel
        </button>
        <button onClick={onSave} disabled={saving} style={btnStyle('primary')}>
          {saving ? '…' : 'Save'}
        </button>
      </div>
    </div>
  )
}

function btnStyle(variant) {
  if (variant === 'primary') {
    return {
      padding: '8px 14px', background: 'var(--accent)', color: '#fff',
      border: 'none', borderRadius: 6, cursor: 'pointer', fontSize: 13, fontWeight: 600,
      display: 'inline-flex', alignItems: 'center', gap: 6,
    }
  }
  if (variant === 'danger') {
    return {
      padding: '6px 10px', background: 'transparent', color: '#ef4444',
      border: '1px solid var(--border)', borderRadius: 6, cursor: 'pointer', fontSize: 12,
      display: 'inline-flex', alignItems: 'center', gap: 6,
    }
  }
  return {
    padding: '6px 10px', background: 'transparent', color: 'var(--text-secondary)',
    border: '1px solid var(--border)', borderRadius: 6, cursor: 'pointer', fontSize: 12,
    display: 'inline-flex', alignItems: 'center', gap: 6,
  }
}
