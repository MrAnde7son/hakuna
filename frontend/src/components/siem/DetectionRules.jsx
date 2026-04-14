import React, { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { Shield, Plus, Trash2, Edit2, Play, Upload, ToggleLeft, ToggleRight } from 'lucide-react'
import { getDetectionRules, createDetectionRule, updateDetectionRule, deleteDetectionRule, testDetectionRule } from '../../api'
import { PageHeader, EmptyState, Button } from '../shared/ui'

const SEVERITY_COLORS = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#6b7280' }

export default function DetectionRules() {
  const { t } = useTranslation()
  const [rules, setRules] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [editRule, setEditRule] = useState(null)
  const [testResult, setTestResult] = useState(null)

  const loadRules = useCallback(async () => {
    setLoading(true)
    try {
      const data = await getDetectionRules({ page_size: 100 })
      setRules(data.items || [])
      setTotal(data.total || 0)
    } catch (e) { console.error(e) }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { loadRules() }, [loadRules])

  const handleToggle = async (rule) => {
    await updateDetectionRule(rule.id, { enabled: !rule.enabled })
    loadRules()
  }

  const handleDelete = async (id) => {
    if (!confirm(t('siem.confirmDeleteRule', 'Delete this detection rule?'))) return
    await deleteDetectionRule(id)
    loadRules()
  }

  const handleTest = async (rule) => {
    try {
      const result = await testDetectionRule({
        query: rule.query || {}, threshold: rule.threshold || 1,
        window_seconds: rule.window_seconds || 300, group_by: rule.group_by || [],
      })
      setTestResult({ rule: rule.name, ...result })
    } catch (e) { console.error(e) }
  }

  const handleCreate = async (data) => {
    await createDetectionRule(data)
    setShowCreate(false)
    loadRules()
  }

  return (
    <div>
      <PageHeader
        title={t('siem.detectionRules', 'Detection Rules')}
        subtitle={`${total} ${t('siem.rules', 'rules')}`}
        action={
          <Button onClick={() => setShowCreate(true)}>
            <Plus size={14} /> {t('siem.createRule', 'Create Rule')}
          </Button>
        }
      />

      {/* Test result banner */}
      {testResult && (
        <div style={{ padding: 16, marginBottom: 16, borderRadius: 8, background: testResult.would_fire ? '#ef444420' : '#22c55e20',
                       border: `1px solid ${testResult.would_fire ? '#ef4444' : '#22c55e'}` }}>
          <strong>{testResult.rule}</strong>: {testResult.would_fire ? 'Would FIRE' : 'Would NOT fire'} —
          {testResult.matching_events} events match (threshold: {testResult.threshold})
          <button onClick={() => setTestResult(null)} style={{ float: 'right', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}>×</button>
        </div>
      )}

      {/* Rules list */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {loading ? <EmptyState icon={Shield} title={t('app.loading')} />
        : rules.length === 0 ? <EmptyState icon={Shield} title={t('siem.noRules', 'No detection rules yet')} sub={t('siem.noRulesHint', 'Create a detection rule to automatically monitor events and trigger alerts.')} />
        : rules.map(rule => (
          <div key={rule.id} style={{ padding: '14px 18px', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--bg-secondary)',
                                       display: 'flex', alignItems: 'center', gap: 12, opacity: rule.enabled ? 1 : 0.6 }}>
            <button onClick={() => handleToggle(rule)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: rule.enabled ? 'var(--accent)' : 'var(--text-muted)' }}>
              {rule.enabled ? <ToggleRight size={20} /> : <ToggleLeft size={20} />}
            </button>
            <div style={{ flex: 1 }}>
              <div style={{ fontWeight: 600, fontSize: 14 }}>{rule.name}</div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
                {rule.source === 'sigma' && <span style={{ marginRight: 8, padding: '1px 6px', borderRadius: 4, background: '#8b5cf620', color: '#8b5cf6', fontSize: 10 }}>Sigma</span>}
                Threshold: {rule.threshold} in {rule.window_seconds}s
                {rule.mitre_techniques?.length > 0 && <> · {rule.mitre_techniques.join(', ')}</>}
              </div>
            </div>
            <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600,
              background: (SEVERITY_COLORS[rule.severity] || '#6b7280') + '20', color: SEVERITY_COLORS[rule.severity] }}>
              {rule.severity}
            </span>
            <button onClick={() => handleTest(rule)} title="Test rule" style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}><Play size={16} /></button>
            <button onClick={() => handleDelete(rule.id)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}><Trash2 size={16} /></button>
          </div>
        ))}
      </div>

      {/* Create modal */}
      {showCreate && <CreateRuleModal onClose={() => setShowCreate(false)} onCreate={handleCreate} t={t} />}
    </div>
  )
}

function CreateRuleModal({ onClose, onCreate, t }) {
  const [form, setForm] = useState({ name: '', severity: 'medium', threshold: 1, window_seconds: 300, query: {}, schedule_minutes: 5 })
  const [queryField, setQueryField] = useState('')
  const [queryValue, setQueryValue] = useState('')

  const addFilter = () => {
    if (queryField && queryValue) {
      setForm(f => ({ ...f, query: { ...f.query, [queryField]: queryValue } }))
      setQueryField('')
      setQueryValue('')
    }
  }

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ background: 'var(--bg)', borderRadius: 12, padding: 24, width: 480, maxHeight: '80vh', overflow: 'auto' }}>
        <h2 style={{ margin: '0 0 16px', fontSize: 18 }}>{t('siem.createRule', 'Create Detection Rule')}</h2>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <input placeholder="Rule name" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                 style={{ padding: 8, borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text)' }} />
          <select value={form.severity} onChange={e => setForm(f => ({ ...f, severity: e.target.value }))}
                  style={{ padding: 8, borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text)' }}>
            {['critical', 'high', 'medium', 'low'].map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <div style={{ display: 'flex', gap: 8 }}>
            <input type="number" placeholder="Threshold" value={form.threshold} onChange={e => setForm(f => ({ ...f, threshold: parseInt(e.target.value) || 1 }))}
                   style={{ flex: 1, padding: 8, borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text)' }} />
            <input type="number" placeholder="Window (sec)" value={form.window_seconds} onChange={e => setForm(f => ({ ...f, window_seconds: parseInt(e.target.value) || 300 }))}
                   style={{ flex: 1, padding: 8, borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text)' }} />
          </div>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-muted)' }}>Filters</div>
          <div style={{ display: 'flex', gap: 4 }}>
            <select value={queryField} onChange={e => setQueryField(e.target.value)} style={{ flex: 1, padding: 6, borderRadius: 4, border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text)', fontSize: 12 }}>
              <option value="">Field...</option>
              {['event_type', 'source_system', 'severity', 'outcome', 'action', 'message_contains', 'source_ip', 'user_name'].map(f => <option key={f} value={f}>{f}</option>)}
            </select>
            <input placeholder="Value" value={queryValue} onChange={e => setQueryValue(e.target.value)}
                   style={{ flex: 1, padding: 6, borderRadius: 4, border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text)', fontSize: 12 }} />
            <button onClick={addFilter} style={{ padding: '6px 12px', borderRadius: 4, border: 'none', background: 'var(--accent)', color: '#fff', cursor: 'pointer', fontSize: 12 }}>+</button>
          </div>
          {Object.entries(form.query).map(([k, v]) => (
            <div key={k} style={{ fontSize: 12, padding: '4px 8px', background: 'var(--bg-hover)', borderRadius: 4 }}>{k} = {v}</div>
          ))}
        </div>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 16 }}>
          <button onClick={onClose} style={{ padding: '8px 16px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text)', cursor: 'pointer' }}>
            {t('common.cancel', 'Cancel')}
          </button>
          <button onClick={() => onCreate(form)} disabled={!form.name}
                  style={{ padding: '8px 16px', borderRadius: 6, border: 'none', background: 'var(--accent)', color: '#fff', fontWeight: 600, cursor: 'pointer' }}>
            {t('common.create', 'Create')}
          </button>
        </div>
      </div>
    </div>
  )
}
