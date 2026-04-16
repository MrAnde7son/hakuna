import React, { useState, useEffect, useCallback, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { Shield, Plus, Trash2, Edit2, Play, Upload, ToggleLeft, ToggleRight, EyeOff, BookOpen, Search, Check } from 'lucide-react'
import { getDetectionRules, createDetectionRule, updateDetectionRule, deleteDetectionRule, testDetectionRule, getSuppressionRules, updateSuppressionRule, deleteSuppressionRule } from '../../api'
import { PageHeader, EmptyState, Button } from '../shared/ui'
import { useIsMobile } from '../../App'
import { DETECTION_RULE_TEMPLATES, MITRE_TACTICS, templateToRulePayload } from '../../data/detectionRuleLibrary'

const SEVERITY_COLORS = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#6b7280' }

export default function DetectionRules() {
  const { t } = useTranslation()
  const [tab, setTab] = useState('rules') // rules | suppression
  const [rules, setRules] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [showLibrary, setShowLibrary] = useState(false)
  const [editRule, setEditRule] = useState(null)
  const [testResult, setTestResult] = useState(null)
  const isMobile = useIsMobile()

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

  const handleInstallTemplates = async (templates) => {
    const results = await Promise.allSettled(
      templates.map(tpl => createDetectionRule(templateToRulePayload(tpl)))
    )
    const failed = results.filter(r => r.status === 'rejected').length
    if (failed) console.error(`${failed} template(s) failed to install`)
    setShowLibrary(false)
    loadRules()
  }

  const handleUpdate = async (data) => {
    await updateDetectionRule(editRule.id, data)
    setEditRule(null)
    loadRules()
  }

  return (
    <div>
      <PageHeader
        title={t('siem.detectionRules', 'Detection Rules')}
        subtitle={`${total} ${t('siem.rules', 'rules')}`}
        action={tab === 'rules' ? (
          <div style={{ display: 'flex', gap: 8 }}>
            <Button onClick={() => setShowLibrary(true)} variant="ghost">
              <BookOpen size={14} /> {t('siem.browseLibrary', 'Browse Library')}
            </Button>
            <Button onClick={() => setShowCreate(true)}>
              <Plus size={14} /> {t('siem.createRule', 'Create Rule')}
            </Button>
          </div>
        ) : null}
      />

      {/* Tab toggle */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 16 }}>
        <button onClick={() => setTab('rules')}
                style={{ padding: '6px 14px', borderRadius: 6, border: '1px solid var(--border)',
                         background: tab === 'rules' ? 'var(--accent)' : 'var(--bg-secondary)',
                         color: tab === 'rules' ? '#fff' : 'var(--text)', cursor: 'pointer', fontSize: 13,
                         display: 'flex', alignItems: 'center', gap: 4 }}>
          <Shield size={13} /> Detection Rules
        </button>
        <button onClick={() => setTab('suppression')}
                style={{ padding: '6px 14px', borderRadius: 6, border: '1px solid var(--border)',
                         background: tab === 'suppression' ? 'var(--accent)' : 'var(--bg-secondary)',
                         color: tab === 'suppression' ? '#fff' : 'var(--text)', cursor: 'pointer', fontSize: 13,
                         display: 'flex', alignItems: 'center', gap: 4 }}>
          <EyeOff size={13} /> Suppression Rules
        </button>
      </div>

      {tab === 'suppression' ? <SuppressionTab /> : <>

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
          <div key={rule.id} style={{ padding: isMobile ? '12px 14px' : '14px 18px', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--bg-secondary)',
                                       display: 'flex', alignItems: 'center', gap: isMobile ? 8 : 12, opacity: rule.enabled ? 1 : 0.6, flexWrap: isMobile ? 'wrap' : 'nowrap' }}>
            <button onClick={() => handleToggle(rule)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: rule.enabled ? 'var(--accent)' : 'var(--text-muted)' }}>
              {rule.enabled ? <ToggleRight size={20} /> : <ToggleLeft size={20} />}
            </button>
            <div style={{ flex: '1 1 0', minWidth: 0 }}>
              <div style={{ fontWeight: 600, fontSize: 14, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{rule.name}</div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {rule.source === 'sigma' && <span style={{ marginRight: 8, padding: '1px 6px', borderRadius: 4, background: '#8b5cf620', color: '#8b5cf6', fontSize: 10 }}>Sigma</span>}
                Threshold: {rule.threshold} in {rule.window_seconds}s
                {rule.mitre_techniques?.length > 0 && <> · {rule.mitre_techniques.join(', ')}</>}
                {rule.asset_filter && Object.keys(rule.asset_filter).length > 0 && (
                  <span style={{ marginLeft: 8, padding: '1px 6px', borderRadius: 4, background: '#0ea5e920', color: '#0ea5e9', fontSize: 10, fontWeight: 600 }}>
                    Asset Filter
                  </span>
                )}
              </div>
            </div>
            <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600,
              background: (SEVERITY_COLORS[rule.severity] || '#6b7280') + '20', color: SEVERITY_COLORS[rule.severity] }}>
              {rule.severity}
            </span>
            <button onClick={() => handleTest(rule)} title="Test rule" style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}><Play size={16} /></button>
            <button onClick={() => setEditRule(rule)} title="Edit rule" style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}><Edit2 size={16} /></button>
            <button onClick={() => handleDelete(rule.id)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}><Trash2 size={16} /></button>
          </div>
        ))}
      </div>

      {/* Create / Edit modal */}
      {showCreate && <RuleModal onClose={() => setShowCreate(false)} onSave={handleCreate} t={t} />}
      {editRule && <RuleModal rule={editRule} onClose={() => setEditRule(null)} onSave={handleUpdate} t={t} />}
      {showLibrary && (
        <RuleLibraryModal
          existingRules={rules}
          onClose={() => setShowLibrary(false)}
          onInstall={handleInstallTemplates}
          t={t}
        />
      )}

      </>}
    </div>
  )
}


function SuppressionTab() {
  const { t } = useTranslation()
  const [rules, setRules] = useState([])
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await getSuppressionRules({ page_size: 100 })
      setRules(data.items || [])
    } catch (e) { console.error(e) }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { load() }, [load])

  const handleToggle = async (rule) => {
    await updateSuppressionRule(rule.id, { enabled: !rule.enabled })
    load()
  }

  const handleDelete = async (id) => {
    if (!confirm('Delete this suppression rule?')) return
    await deleteSuppressionRule(id)
    load()
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {loading ? <EmptyState icon={EyeOff} title={t('app.loading')} />
      : rules.length === 0 ? <EmptyState icon={EyeOff} title="No suppression rules" sub="Suppression rules prevent known-good activity from creating alerts. Create them from the Alert Triage page." />
      : rules.map(rule => (
        <div key={rule.id} style={{ padding: '14px 18px', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--bg-secondary)',
                                     display: 'flex', alignItems: 'center', gap: 12, opacity: rule.enabled ? 1 : 0.5 }}>
          <button onClick={() => handleToggle(rule)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: rule.enabled ? 'var(--accent)' : 'var(--text-muted)' }}>
            {rule.enabled ? <ToggleRight size={20} /> : <ToggleLeft size={20} />}
          </button>
          <div style={{ flex: 1 }}>
            <div style={{ fontWeight: 600, fontSize: 14 }}>{rule.name}</div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
              {rule.reason && <span>{rule.reason} · </span>}
              {(rule.conditions || []).length} conditions
              {rule.expires_at && <> · expires {new Date(rule.expires_at).toLocaleDateString()}</>}
              {rule.suppressed_count > 0 && <> · suppressed {rule.suppressed_count} alerts</>}
            </div>
          </div>
          <button onClick={() => handleDelete(rule.id)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}>
            <Trash2 size={16} />
          </button>
        </div>
      ))}
    </div>
  )
}

function RuleModal({ rule, onClose, onSave, t }) {
  const isEdit = !!rule
  const [form, setForm] = useState({
    name: rule?.name || '', severity: rule?.severity || 'medium',
    threshold: rule?.threshold || 1, window_seconds: rule?.window_seconds || 300,
    query: rule?.query || {}, schedule_minutes: rule?.schedule_minutes || 5,
    asset_filter: rule?.asset_filter || {},
  })
  const [showAssetFilter, setShowAssetFilter] = useState(Object.keys(rule?.asset_filter || {}).length > 0)
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
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}>
      <div style={{ background: 'var(--bg)', borderRadius: 12, padding: 24, width: '100%', maxWidth: 480, maxHeight: '80vh', overflow: 'auto' }}>
        <h2 style={{ margin: '0 0 16px', fontSize: 18 }}>{isEdit ? t('siem.editRule', 'Edit Detection Rule') : t('siem.createRule', 'Create Detection Rule')}</h2>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <input placeholder="Rule name" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                 style={{ padding: 8, borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text)' }} />
          <select value={form.severity} onChange={e => setForm(f => ({ ...f, severity: e.target.value }))}
                  style={{ padding: 8, borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text)' }}>
            {['critical', 'high', 'medium', 'low'].map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <div style={{ display: 'flex', gap: 8 }}>
            <div style={{ flex: 1 }}>
              <label style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-muted)', marginBottom: 4, display: 'block' }}>Threshold (count)</label>
              <input type="number" value={form.threshold} onChange={e => setForm(f => ({ ...f, threshold: parseInt(e.target.value) || 1 }))}
                     style={{ width: '100%', padding: 8, borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text)', boxSizing: 'border-box' }} />
            </div>
            <div style={{ flex: 1 }}>
              <label style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-muted)', marginBottom: 4, display: 'block' }}>Window (seconds)</label>
              <input type="number" value={form.window_seconds} onChange={e => setForm(f => ({ ...f, window_seconds: parseInt(e.target.value) || 300 }))}
                     style={{ width: '100%', padding: 8, borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text)', boxSizing: 'border-box' }} />
            </div>
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
            <div key={k} style={{ fontSize: 12, padding: '4px 8px', background: 'var(--bg-hover)', borderRadius: 4, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span>{k} = {v}</span>
              <button onClick={() => setForm(f => { const q = { ...f.query }; delete q[k]; return { ...f, query: q } })}
                      style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', fontSize: 14, padding: 0, lineHeight: 1 }}>×</button>
            </div>
          ))}

          {/* Asset Context Filter */}
          <div style={{ marginTop: 8 }}>
            <button onClick={() => setShowAssetFilter(!showAssetFilter)} style={{
              background: 'none', border: 'none', cursor: 'pointer', fontSize: 13, fontWeight: 600,
              color: 'var(--accent)', padding: 0, display: 'flex', alignItems: 'center', gap: 4,
            }}>
              {showAssetFilter ? '▾' : '▸'} Asset Context Filter
              {Object.keys(form.asset_filter).length > 0 && (
                <span style={{ fontSize: 10, background: 'var(--accent)', color: '#fff', borderRadius: 10, padding: '1px 6px', fontWeight: 700 }}>
                  {Object.keys(form.asset_filter).length}
                </span>
              )}
            </button>
            {showAssetFilter && (
              <div style={{ marginTop: 8, padding: 12, background: 'var(--bg-hover)', borderRadius: 8, display: 'flex', flexDirection: 'column', gap: 8 }}>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Only fire alerts when the linked asset matches these criteria</div>
                <div style={{ display: 'flex', gap: 8 }}>
                  <div style={{ flex: 1 }}>
                    <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 3 }}>Min Criticality</label>
                    <select value={form.asset_filter.min_criticality || ''} onChange={e => {
                      const v = e.target.value ? parseInt(e.target.value) : undefined
                      setForm(f => {
                        const af = { ...f.asset_filter }
                        if (v) af.min_criticality = v; else delete af.min_criticality
                        return { ...f, asset_filter: af }
                      })
                    }} style={{ width: '100%', padding: 6, borderRadius: 4, border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text)', fontSize: 12 }}>
                      <option value="">Any</option>
                      {[1,2,3,4,5,6,7,8,9,10].map(n => <option key={n} value={n}>{n}{n >= 8 ? ' (High)' : n >= 5 ? ' (Medium)' : ' (Low)'}</option>)}
                    </select>
                  </div>
                  <div style={{ flex: 1 }}>
                    <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 3 }}>Environment</label>
                    <select value={form.asset_filter.environment || ''} onChange={e => {
                      setForm(f => {
                        const af = { ...f.asset_filter }
                        if (e.target.value) af.environment = e.target.value; else delete af.environment
                        return { ...f, asset_filter: af }
                      })
                    }} style={{ width: '100%', padding: 6, borderRadius: 4, border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text)', fontSize: 12 }}>
                      <option value="">Any</option>
                      {['production', 'staging', 'development', 'dmz', 'cloud', 'internal', 'external'].map(e => <option key={e} value={e}>{e}</option>)}
                    </select>
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                  {[
                    { key: 'internet_facing', label: 'Internet-facing only' },
                    { key: 'has_critical_vulns', label: 'Has critical vulns' },
                    { key: 'has_high_vulns', label: 'Has high+ vulns' },
                  ].map(({ key, label }) => (
                    <label key={key} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, cursor: 'pointer' }}>
                      <input type="checkbox" checked={!!form.asset_filter[key]} onChange={e => {
                        setForm(f => {
                          const af = { ...f.asset_filter }
                          if (e.target.checked) af[key] = true; else delete af[key]
                          return { ...f, asset_filter: af }
                        })
                      }} />
                      {label}
                    </label>
                  ))}
                </div>
                <div>
                  <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 3 }}>Asset Type</label>
                  <select value={form.asset_filter.asset_type || ''} onChange={e => {
                    setForm(f => {
                      const af = { ...f.asset_filter }
                      if (e.target.value) af.asset_type = e.target.value; else delete af.asset_type
                      return { ...f, asset_filter: af }
                    })
                  }} style={{ width: '100%', padding: 6, borderRadius: 4, border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text)', fontSize: 12 }}>
                    <option value="">Any</option>
                    {['server', 'workstation', 'network_device', 'iot', 'cloud_instance', 'container', 'database', 'web_application'].map(t => <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>)}
                  </select>
                </div>
              </div>
            )}
          </div>
        </div>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 16 }}>
          <button onClick={onClose} style={{ padding: '8px 16px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text)', cursor: 'pointer' }}>
            {t('common.cancel', 'Cancel')}
          </button>
          <button onClick={() => {
            const payload = { ...form }
            if (Object.keys(payload.asset_filter).length === 0) payload.asset_filter = null
            onSave(payload)
          }} disabled={!form.name}
                  style={{ padding: '8px 16px', borderRadius: 6, border: 'none', background: 'var(--accent)', color: '#fff', fontWeight: 600, cursor: 'pointer' }}>
            {isEdit ? t('common.save', 'Save') : t('common.create', 'Create')}
          </button>
        </div>
      </div>
    </div>
  )
}


const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

function RuleLibraryModal({ existingRules, onClose, onInstall, t }) {
  const [search, setSearch] = useState('')
  const [activeCategory, setActiveCategory] = useState('all')
  const [selected, setSelected] = useState(() => new Set())
  const [installing, setInstalling] = useState(false)

  // Mark any template whose name matches an existing rule so we don't re-install duplicates
  const existingNames = useMemo(() => new Set((existingRules || []).map(r => r.name)), [existingRules])

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return DETECTION_RULE_TEMPLATES
      .filter(tpl => activeCategory === 'all' || tpl.category === activeCategory)
      .filter(tpl => !q || (
        tpl.name.toLowerCase().includes(q) ||
        tpl.description.toLowerCase().includes(q) ||
        (tpl.mitre_techniques || []).some(m => m.toLowerCase().includes(q)) ||
        (tpl.attribution || '').toLowerCase().includes(q)
      ))
      .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9))
  }, [search, activeCategory])

  const counts = useMemo(() => {
    const c = { all: DETECTION_RULE_TEMPLATES.length }
    for (const tpl of DETECTION_RULE_TEMPLATES) c[tpl.category] = (c[tpl.category] || 0) + 1
    return c
  }, [])

  const toggle = (id) => {
    setSelected(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id); else next.add(id)
      return next
    })
  }

  const selectAllVisible = () => {
    setSelected(prev => {
      const next = new Set(prev)
      for (const tpl of filtered) if (!existingNames.has(tpl.name)) next.add(tpl.id)
      return next
    })
  }

  const handleInstall = async (ids) => {
    const templates = DETECTION_RULE_TEMPLATES.filter(tpl => ids.includes(tpl.id))
    if (!templates.length) return
    setInstalling(true)
    try { await onInstall(templates) } finally { setInstalling(false) }
  }

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}>
      <div style={{ background: 'var(--bg)', borderRadius: 12, width: '100%', maxWidth: 960, maxHeight: '85vh', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        {/* Header */}
        <div style={{ padding: '20px 24px 12px', borderBottom: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
            <h2 style={{ margin: 0, fontSize: 18, display: 'flex', alignItems: 'center', gap: 8 }}>
              <BookOpen size={18} /> {t('siem.ruleLibrary', 'Detection Rule Library')}
            </h2>
            <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', fontSize: 22, lineHeight: 1 }}>×</button>
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            {t('siem.ruleLibrarySub', 'Curated detections for common attacks, mapped to MITRE ATT&CK tactics and recent CVEs. Pick templates to install — each becomes an editable detection rule.')}
          </div>
          {/* Search */}
          <div style={{ marginTop: 12, position: 'relative' }}>
            <Search size={14} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
            <input
              autoFocus
              placeholder={t('siem.searchLibrary', 'Search by name, MITRE ID (e.g. T1110), CVE, or actor…')}
              value={search}
              onChange={e => setSearch(e.target.value)}
              style={{ width: '100%', padding: '8px 10px 8px 32px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text)', fontSize: 13, boxSizing: 'border-box' }}
            />
          </div>
        </div>

        {/* Body: sidebar + list */}
        <div style={{ display: 'flex', flex: 1, minHeight: 0 }}>
          {/* Category sidebar */}
          <div style={{ width: 200, borderRight: '1px solid var(--border)', padding: '12px 8px', overflowY: 'auto', background: 'var(--bg-secondary)' }}>
            {[{ id: 'all', name: 'All Templates', tacticId: null }, ...MITRE_TACTICS].map(cat => {
              const active = activeCategory === cat.id
              return (
                <button
                  key={cat.id}
                  onClick={() => setActiveCategory(cat.id)}
                  style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%',
                    padding: '7px 10px', marginBottom: 2, borderRadius: 6, border: 'none',
                    background: active ? 'var(--accent)' : 'transparent',
                    color: active ? '#fff' : 'var(--text)', cursor: 'pointer', fontSize: 12, textAlign: 'left',
                  }}
                >
                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {cat.name}
                    {cat.tacticId && <span style={{ marginLeft: 4, opacity: 0.6, fontSize: 10 }}>{cat.tacticId}</span>}
                  </span>
                  <span style={{ opacity: 0.7, fontSize: 10 }}>{counts[cat.id] || 0}</span>
                </button>
              )
            })}
          </div>

          {/* Templates list */}
          <div style={{ flex: 1, overflowY: 'auto', padding: '12px 16px' }}>
            {filtered.length === 0 ? (
              <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
                {t('siem.noTemplatesFound', 'No templates match your search.')}
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {filtered.map(tpl => {
                  const alreadyInstalled = existingNames.has(tpl.name)
                  const isSelected = selected.has(tpl.id)
                  return (
                    <div
                      key={tpl.id}
                      onClick={() => !alreadyInstalled && toggle(tpl.id)}
                      style={{
                        padding: '12px 14px', borderRadius: 8,
                        border: `1px solid ${isSelected ? 'var(--accent)' : 'var(--border)'}`,
                        background: isSelected ? 'var(--accent)10' : 'var(--bg-secondary)',
                        cursor: alreadyInstalled ? 'not-allowed' : 'pointer',
                        opacity: alreadyInstalled ? 0.5 : 1,
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                        <div style={{
                          width: 18, height: 18, marginTop: 2, flexShrink: 0,
                          borderRadius: 4, border: `1.5px solid ${isSelected ? 'var(--accent)' : 'var(--border)'}`,
                          background: isSelected ? 'var(--accent)' : 'transparent',
                          display: 'flex', alignItems: 'center', justifyContent: 'center',
                        }}>
                          {isSelected && <Check size={12} color="#fff" strokeWidth={3} />}
                        </div>
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                            <span style={{ fontWeight: 600, fontSize: 14 }}>{tpl.name}</span>
                            <span style={{
                              padding: '1px 7px', borderRadius: 4, fontSize: 10, fontWeight: 700,
                              background: (SEVERITY_COLORS[tpl.severity] || '#6b7280') + '20',
                              color: SEVERITY_COLORS[tpl.severity],
                            }}>{tpl.severity}</span>
                            {alreadyInstalled && (
                              <span style={{ padding: '1px 7px', borderRadius: 4, fontSize: 10, fontWeight: 600, background: '#22c55e20', color: '#22c55e' }}>
                                installed
                              </span>
                            )}
                          </div>
                          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4, lineHeight: 1.4 }}>
                            {tpl.description}
                          </div>
                          <div style={{ display: 'flex', gap: 6, marginTop: 6, flexWrap: 'wrap' }}>
                            {(tpl.mitre_techniques || []).map(tid => (
                              <span key={tid} style={{ padding: '1px 6px', borderRadius: 4, fontSize: 10, fontWeight: 600, background: '#8b5cf620', color: '#8b5cf6' }}>
                                {tid}
                              </span>
                            ))}
                            <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                              threshold {tpl.threshold} in {tpl.window_seconds}s
                              {tpl.group_by?.length ? ` · by ${tpl.group_by.join(', ')}` : ''}
                            </span>
                          </div>
                          {tpl.attribution && (
                            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4, fontStyle: 'italic' }}>
                              Seen in: {tpl.attribution}
                            </div>
                          )}
                          {tpl.note && (
                            <div style={{ fontSize: 11, color: '#f59e0b', marginTop: 4 }}>
                              Tuning note: {tpl.note}
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div style={{ padding: '12px 16px', borderTop: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', gap: 12, fontSize: 12, color: 'var(--text-muted)', alignItems: 'center' }}>
            <span>{selected.size} {t('siem.selected', 'selected')}</span>
            <button onClick={selectAllVisible} style={{ background: 'none', border: 'none', color: 'var(--accent)', cursor: 'pointer', fontSize: 12, padding: 0 }}>
              {t('siem.selectAllVisible', 'Select all visible')}
            </button>
            {selected.size > 0 && (
              <button onClick={() => setSelected(new Set())} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 12, padding: 0 }}>
                {t('common.clear', 'Clear')}
              </button>
            )}
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={onClose} style={{ padding: '8px 16px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text)', cursor: 'pointer' }}>
              {t('common.cancel', 'Cancel')}
            </button>
            <button
              onClick={() => handleInstall(Array.from(selected))}
              disabled={selected.size === 0 || installing}
              style={{
                padding: '8px 16px', borderRadius: 6, border: 'none',
                background: selected.size === 0 || installing ? 'var(--bg-hover)' : 'var(--accent)',
                color: '#fff', fontWeight: 600, cursor: selected.size === 0 || installing ? 'not-allowed' : 'pointer',
              }}
            >
              {installing
                ? t('siem.installing', 'Installing…')
                : t('siem.installSelected', `Install ${selected.size || ''} selected`.trim())}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
