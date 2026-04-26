import React, { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { ShieldCheck, FileDown, Plus, Settings, Activity, AlertTriangle, CheckCircle2 } from 'lucide-react'
import {
  PageHeader, Card, StatCard, Table, Button, Pill, EmptyState, ErrorBanner,
  SkeletonTable, Spinner, useToast, useConfirm, Input,
} from '../shared/ui.jsx'
import {
  getComplianceFrameworks, subscribeFramework, unsubscribeFramework,
  updateFrameworkScope, getComplianceControls,
  createComplianceReport, listComplianceReports, downloadComplianceReport,
  getTags,
} from '../../api.js'

// ────────────────────────────────────────────────────────────────
// State → color/label
// ────────────────────────────────────────────────────────────────

function stateColor(state) {
  switch (state) {
    case 'passing':              return 'var(--success, #16a34a)'
    case 'failing':              return 'var(--critical, #dc2626)'
    case 'partial':              return 'var(--high, #ea580c)'
    case 'compensating_control': return 'var(--medium, #d97706)'
    case 'not_applicable':       return 'var(--text-muted)'
    case 'not_evaluated':        return 'var(--text-muted)'
    default:                     return 'var(--text-muted)'
  }
}

function StateBadge({ state, t }) {
  const label = t(`compliance.states.${state}`, state)
  return <Pill label={label} color={stateColor(state)} />
}

// ────────────────────────────────────────────────────────────────
// TabBar — accent-underline pattern matching ThreatIntelCenter
// ────────────────────────────────────────────────────────────────

function TabBar({ tabs, active, onChange }) {
  return (
    <div style={{ display: 'flex', gap: 0, borderBottom: '1px solid var(--border)', marginBottom: 16 }}>
      {tabs.map(tab => (
        <button
          key={tab.key}
          onClick={() => onChange(tab.key)}
          style={{
            background: 'none',
            border: 'none',
            padding: '10px 16px',
            fontSize: 13,
            fontWeight: active === tab.key ? 700 : 500,
            color: active === tab.key ? 'var(--accent)' : 'var(--text-secondary)',
            borderBottom: `2px solid ${active === tab.key ? 'var(--accent)' : 'transparent'}`,
            marginBottom: -1,
            cursor: 'pointer',
            display: 'inline-flex',
            alignItems: 'center',
            gap: 6,
          }}
        >
          {tab.icon ? <tab.icon size={14} /> : null}
          {tab.label}
          {tab.count != null && (
            <span style={{
              fontSize: 11, fontWeight: 600,
              padding: '1px 6px', borderRadius: 8,
              background: 'var(--bg-subtle)', color: 'var(--text-muted)',
            }}>{tab.count}</span>
          )}
        </button>
      ))}
    </div>
  )
}

// ────────────────────────────────────────────────────────────────
// Framework picker (root /compliance)
// ────────────────────────────────────────────────────────────────

function FrameworkPicker({ frameworks, onPick, onSubscribe, onUnsubscribe, t, toast }) {
  if (!frameworks || frameworks.length === 0) {
    return (
      <EmptyState
        icon={ShieldCheck}
        title={t('compliance.noFrameworks')}
        sub=""
      />
    )
  }
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: 12 }}>
      {frameworks.map(fw => (
        <Card key={fw.slug} onClick={() => onPick(fw.slug)}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12 }}>
            <div style={{ minWidth: 0 }}>
              <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)' }}>{fw.name}</div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
                {fw.authority} · {t('compliance.version')} {fw.version}
              </div>
              {fw.description && (
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 8, lineHeight: 1.5 }}>
                  {fw.description.slice(0, 140)}{fw.description.length > 140 ? '…' : ''}
                </div>
              )}
            </div>
            <div onClick={e => e.stopPropagation()}>
              {fw.subscribed
                ? <Pill label={t('compliance.subscribed')} color="var(--success, #16a34a)" />
                : <Pill label={t('compliance.notSubscribed')} color="var(--text-muted)" />
              }
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, marginTop: 14 }} onClick={e => e.stopPropagation()}>
            {fw.subscribed ? (
              <Button
                variant="ghost"
                size="sm"
                onClick={async () => {
                  await onUnsubscribe(fw.slug)
                  toast(t('compliance.unsubscribed_toast', { framework: fw.name }))
                }}
              >
                {t('compliance.unsubscribe')}
              </Button>
            ) : (
              <Button
                variant="primary"
                size="sm"
                onClick={async () => {
                  await onSubscribe(fw.slug)
                  toast(t('compliance.subscribed_toast', { framework: fw.name }))
                }}
              >
                <Plus size={13} /> {t('compliance.subscribe')}
              </Button>
            )}
            <Button variant="ghost" size="sm" onClick={() => onPick(fw.slug)}>
              {t('compliance.controls')} →
            </Button>
          </div>
        </Card>
      ))}
    </div>
  )
}

// ────────────────────────────────────────────────────────────────
// Stats bar — rollup of control states across the framework
// ────────────────────────────────────────────────────────────────

function StatsBar({ controls, t }) {
  const counts = useMemo(() => {
    const out = {
      total: controls.length,
      passing: 0, failing: 0, partial: 0,
      compensating_control: 0, not_applicable: 0,
      failingFindings: 0, failingAssets: 0,
    }
    for (const c of controls) {
      if (c.state in out) out[c.state]++
      if (c.failing_finding_count) out.failingFindings += c.failing_finding_count
      if (c.failing_asset_count) out.failingAssets += c.failing_asset_count
    }
    return out
  }, [controls])

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 8, marginBottom: 16 }}>
      <StatCard label={t('compliance.stats.totalControls')} value={counts.total} icon={ShieldCheck} />
      <StatCard label={t('compliance.stats.passing')}     value={counts.passing}              color="var(--success, #16a34a)"  icon={CheckCircle2} />
      <StatCard label={t('compliance.stats.failing')}     value={counts.failing}              color="var(--critical, #dc2626)" icon={AlertTriangle} />
      <StatCard label={t('compliance.stats.partial')}     value={counts.partial}              color="var(--high, #ea580c)" />
      <StatCard label={t('compliance.stats.compensating')}value={counts.compensating_control} color="var(--medium, #d97706)" />
      <StatCard label={t('compliance.stats.notApplicable')} value={counts.not_applicable}     color="var(--text-muted)" />
      <StatCard label={t('compliance.stats.failingFindings')} value={counts.failingFindings}  color="var(--critical, #dc2626)" icon={Activity} />
      <StatCard label={t('compliance.stats.failingAssets')}   value={counts.failingAssets}    color="var(--high, #ea580c)" />
    </div>
  )
}

// ────────────────────────────────────────────────────────────────
// Controls tab — table of controls with state + counts
// ────────────────────────────────────────────────────────────────

function ControlsTab({ slug, controls, loading, error, onRetry, onPickControl, t }) {
  if (loading) return <SkeletonTable rows={10} columns={5} />
  if (error) return <ErrorBanner error={error} onRetry={onRetry} />
  if (!controls || controls.length === 0) {
    return <EmptyState icon={ShieldCheck} title={t('compliance.subscribeFirst')} sub="" />
  }

  const columns = [
    { key: 'ref', label: t('compliance.ref'), width: '110px', sortable: false },
    { key: 'title', label: t('compliance.control'), sortable: false },
    { key: 'domain', label: t('compliance.domain'), width: '180px',
      render: (v) => v ? <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{v}</span> :
                          <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span> },
    { key: 'state', label: t('compliance.state'), width: '140px',
      render: (v) => <StateBadge state={v} t={t} /> },
    { key: 'failing_finding_count', label: t('compliance.stats.failingFindings'), width: '120px',
      render: (v) => v > 0
        ? <span style={{ fontWeight: 700, color: 'var(--critical, #dc2626)' }}>{v}</span>
        : <span style={{ color: 'var(--text-muted)' }}>0</span>
    },
    { key: 'mapping_count', label: 'Mappings', width: '90px',
      render: (v) => <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{v ?? 0}</span> },
  ]

  return (
    <Card style={{ padding: 0 }}>
      <Table
        columns={columns}
        rows={controls}
        onRowClick={(row) => onPickControl(row.id)}
        emptyMessage={t('compliance.subscribeFirst')}
      />
    </Card>
  )
}

// ────────────────────────────────────────────────────────────────
// Scope tab — simple tag-expr editor + JSON rule view
// ────────────────────────────────────────────────────────────────

function ScopeTab({ slug, framework, onSave, t, toast }) {
  const [tagExpr, setTagExpr] = useState(framework?.scope_tag_expr || '')
  const [saving, setSaving] = useState(false)
  const [allTags, setAllTags] = useState([])
  const [open, setOpen] = useState(false)
  const [highlight, setHighlight] = useState(0)
  const wrapRef = useRef(null)
  const inputRef = useRef(null)

  useEffect(() => {
    getTags().then(setAllTags).catch(() => {})
  }, [])

  useEffect(() => {
    const onClick = e => { if (wrapRef.current && !wrapRef.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', onClick)
    return () => document.removeEventListener('mousedown', onClick)
  }, [])

  // Comma-separated tokens; suggestions operate on the trailing one.
  const parts = tagExpr.split(',')
  const currentToken = (parts[parts.length - 1] || '').trim().toLowerCase()
  const usedTokens = new Set(
    parts.slice(0, -1).map(s => s.trim().toLowerCase()).filter(Boolean)
  )
  const suggestions = useMemo(() => {
    return allTags
      .filter(tg => {
        const cv = `${tg.category}:${tg.value}`.toLowerCase()
        if (usedTokens.has(cv)) return false
        if (!currentToken) return true
        return cv.includes(currentToken) || (tg.label || '').toLowerCase().includes(currentToken)
      })
      .slice(0, 50)
  }, [allTags, currentToken, tagExpr])

  // Reset highlight when suggestions change.
  useEffect(() => { setHighlight(0) }, [suggestions.length, currentToken])

  const insertSuggestion = (tg) => {
    const cv = `${tg.category}:${tg.value}`
    const head = parts.slice(0, -1).map(s => s.trim()).filter(Boolean)
    const next = [...head, cv].join(',') + ','
    setTagExpr(next)
    setOpen(true)
    inputRef.current?.focus()
  }

  const onKeyDown = (e) => {
    if (!open || suggestions.length === 0) return
    if (e.key === 'ArrowDown') { e.preventDefault(); setHighlight(h => Math.min(h + 1, suggestions.length - 1)) }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setHighlight(h => Math.max(h - 1, 0)) }
    else if (e.key === 'Enter' && suggestions[highlight]) { e.preventDefault(); insertSuggestion(suggestions[highlight]) }
    else if (e.key === 'Escape') { setOpen(false) }
  }

  // Group suggestions by category.
  const grouped = useMemo(() => {
    const g = {}
    for (const tg of suggestions) {
      if (!g[tg.category]) g[tg.category] = []
      g[tg.category].push(tg)
    }
    return g
  }, [suggestions])

  const inputStyle = {
    flex: 1, background: 'var(--bg-card)', border: '1px solid var(--border)',
    color: 'var(--text-primary)', borderRadius: 6, padding: '7px 12px',
    fontSize: 13, outline: 'none',
  }

  return (
    <Card>
      <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 4 }}>
        {t('compliance.scope')}
      </div>
      <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 16 }}>
        {t('compliance.scopeHint')}
      </div>
      <div ref={wrapRef} style={{ position: 'relative', marginBottom: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Settings size={14} style={{ color: 'var(--text-muted)' }} />
          <input
            ref={inputRef}
            value={tagExpr}
            onChange={e => { setTagExpr(e.target.value); setOpen(true) }}
            onFocus={() => setOpen(true)}
            onKeyDown={onKeyDown}
            placeholder={t('compliance.scopePlaceholder')}
            style={inputStyle}
          />
        </div>
        {open && suggestions.length > 0 && (
          <div style={{
            position: 'absolute', top: '100%', left: 22, right: 0, zIndex: 200,
            background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: 6, marginTop: 2, maxHeight: 280, overflowY: 'auto',
            boxShadow: '0 4px 16px rgba(0,0,0,0.18)',
          }}>
            {Object.entries(grouped).map(([cat, tags]) => (
              <div key={cat}>
                <div style={{
                  padding: '6px 12px 2px', fontSize: 10, fontWeight: 700,
                  color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em',
                }}>{cat}</div>
                {tags.map(tg => {
                  const idx = suggestions.indexOf(tg)
                  const active = idx === highlight
                  return (
                    <div
                      key={tg.id}
                      onMouseDown={e => { e.preventDefault(); insertSuggestion(tg) }}
                      onMouseEnter={() => setHighlight(idx)}
                      style={{
                        padding: '6px 12px', cursor: 'pointer', display: 'flex', gap: 8,
                        alignItems: 'center', fontSize: 13,
                        background: active ? 'var(--bg-subtle)' : 'transparent',
                        color: 'var(--text-primary)',
                      }}
                    >
                      <span style={{
                        width: 6, height: 6, borderRadius: '50%',
                        background: tg.color || 'var(--accent)', flexShrink: 0,
                      }} />
                      <code style={{ fontSize: 12 }}>{tg.category}:{tg.value}</code>
                      {tg.label && tg.label !== `${tg.category}:${tg.value}` && (
                        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{tg.label}</span>
                      )}
                    </div>
                  )
                })}
              </div>
            ))}
          </div>
        )}
      </div>
      <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 14 }}>
        {tagExpr
          ? <>Will scope to assets matching: <code>{tagExpr}</code></>
          : <>{t('compliance.scopeAllAssets')}</>}
      </div>
      <Button
        variant="primary"
        size="sm"
        disabled={saving}
        onClick={async () => {
          setSaving(true)
          try {
            const trimmed = tagExpr.split(',').map(s => s.trim()).filter(Boolean).join(',')
            await onSave({ scope_tag_expr: trimmed || null })
            toast(t('compliance.scopeUpdated'))
          } finally {
            setSaving(false)
          }
        }}
      >
        {saving ? <Spinner /> : t('compliance.saveScope')}
      </Button>
    </Card>
  )
}

// ────────────────────────────────────────────────────────────────
// Reports tab — list + generate
// ────────────────────────────────────────────────────────────────

function ReportsTab({ slug, framework, t, toast }) {
  const [runs, setRuns] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const [fmt, setFmt] = useState('csv')

  const load = async () => {
    setLoading(true); setError(null)
    try {
      const data = await listComplianceReports({ framework_slug: slug })
      setRuns(data)
    } catch (e) {
      setError(e.message || 'Failed to load reports')
    } finally {
      setLoading(false)
    }
  }
  useEffect(() => { load() }, [slug])

  const generate = async () => {
    setBusy(true)
    try {
      await createComplianceReport({ framework_slug: slug, format: fmt })
      toast(t('compliance.reportGenerated'))
      await load()
    } catch (e) {
      setError(e.message || 'Generate failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div>
      <Card style={{ marginBottom: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, justifyContent: 'space-between', flexWrap: 'wrap' }}>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
            {t('compliance.reportRuns.ofFramework', { framework: framework?.name || slug })}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <select
              value={fmt}
              onChange={e => setFmt(e.target.value)}
              style={{
                fontSize: 12, padding: '6px 8px',
                border: '1px solid var(--border)', borderRadius: 6,
                background: 'var(--bg-card)', color: 'var(--text-primary)',
              }}
            >
              <option value="csv">CSV</option>
              <option value="json">JSON</option>
            </select>
            <Button variant="primary" size="sm" disabled={busy} onClick={generate}>
              {busy ? <Spinner /> : <><FileDown size={13} /> {t('compliance.reportRuns.generate')}</>}
            </Button>
          </div>
        </div>
      </Card>

      {error && <ErrorBanner error={error} onRetry={load} onDismiss={() => setError(null)} />}

      {loading
        ? <SkeletonTable rows={5} columns={4} />
        : runs.length === 0
          ? <EmptyState icon={FileDown} title={t('compliance.reportRuns.noReports')} sub="" />
          : (
            <Card style={{ padding: 0 }}>
              <Table
                columns={[
                  { key: 'created_at', label: t('compliance.reportRuns.createdAt'),
                    render: (v) => v ? new Date(v).toLocaleString() : '—' },
                  { key: 'format', label: t('compliance.reportRuns.format'), width: '90px',
                    render: (v) => <Pill label={(v || '').toUpperCase()} color="var(--accent)" /> },
                  { key: 'rollup', label: t('compliance.stats.failing'), width: '120px',
                    render: (v) => v
                      ? <span>{v.failing} / {v.total_controls}</span>
                      : <span style={{ color: 'var(--text-muted)' }}>—</span> },
                  { key: 'sha256', label: 'SHA256', width: '160px',
                    render: (v) => v
                      ? <code style={{ fontSize: 11, color: 'var(--text-muted)' }}>{v.slice(0, 16)}…</code>
                      : '—' },
                  { key: '_actions', label: '',
                    render: (_, row) => (
                      <Button variant="ghost" size="sm" onClick={(e) => {
                        e.stopPropagation()
                        downloadComplianceReport(row.id, row.framework_slug || slug, row.format)
                      }}>
                        <FileDown size={13} /> {t('compliance.reportRuns.download')}
                      </Button>
                    )
                  },
                ]}
                rows={runs}
              />
            </Card>
          )
      }
    </div>
  )
}

// ────────────────────────────────────────────────────────────────
// Framework overview (controls/scope/reports tabs for one framework)
// ────────────────────────────────────────────────────────────────

function FrameworkOverview({ slug, frameworks, onUpdateScope, t, toast }) {
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const tab = searchParams.get('tab') || 'controls'

  const framework = frameworks.find(f => f.slug === slug)

  const [controls, setControls] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const load = async () => {
    setLoading(true); setError(null)
    try {
      const data = await getComplianceControls(slug, { page_size: 500 })
      setControls(data.items || [])
    } catch (e) {
      setError(e.message || 'Failed to load controls')
    } finally {
      setLoading(false)
    }
  }
  useEffect(() => { load() }, [slug])

  if (!framework) {
    return (
      <EmptyState
        icon={ShieldCheck}
        title="Framework not found"
        sub={<Button variant="ghost" size="sm" onClick={() => navigate('/compliance')}>← {t('compliance.frameworks')}</Button>}
      />
    )
  }

  if (!framework.subscribed) {
    return (
      <Card>
        <div style={{ fontSize: 14, marginBottom: 10 }}>{t('compliance.subscribeFirst')}</div>
        <Button variant="primary" size="sm" onClick={async () => {
          await subscribeFramework(slug)
          toast(t('compliance.subscribed_toast', { framework: framework.name }))
          window.location.reload()
        }}>
          <Plus size={13} /> {t('compliance.subscribe')}
        </Button>
      </Card>
    )
  }

  const tabs = [
    { key: 'controls', label: t('compliance.controls'), icon: ShieldCheck, count: controls.length },
    { key: 'scope',    label: t('compliance.scope'),    icon: Settings },
    { key: 'reports',  label: t('compliance.reports'),  icon: FileDown },
  ]

  return (
    <>
      {tab === 'controls' && <StatsBar controls={controls} t={t} />}

      <TabBar
        tabs={tabs}
        active={tab}
        onChange={(k) => setSearchParams({ tab: k })}
      />

      {tab === 'controls' && (
        <ControlsTab
          slug={slug}
          controls={controls}
          loading={loading}
          error={error}
          onRetry={load}
          onPickControl={(cid) => navigate(`/compliance/${slug}/control/${cid}`)}
          t={t}
        />
      )}
      {tab === 'scope' && (
        <ScopeTab
          slug={slug}
          framework={framework}
          onSave={(body) => onUpdateScope(slug, body)}
          t={t}
          toast={toast}
        />
      )}
      {tab === 'reports' && (
        <ReportsTab slug={slug} framework={framework} t={t} toast={toast} />
      )}
    </>
  )
}

// ────────────────────────────────────────────────────────────────
// Top-level page
// ────────────────────────────────────────────────────────────────

export default function Compliance() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const { slug } = useParams()
  const toast = useToast()

  const [frameworks, setFrameworks] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const load = async () => {
    setLoading(true); setError(null)
    try {
      const data = await getComplianceFrameworks()
      setFrameworks(data || [])
    } catch (e) {
      setError(e.message || 'Failed to load frameworks')
    } finally {
      setLoading(false)
    }
  }
  useEffect(() => { load() }, [])

  const handleSubscribe = async (s) => { await subscribeFramework(s); await load() }
  const handleUnsubscribe = async (s) => { await unsubscribeFramework(s); await load() }
  const handleUpdateScope = async (s, body) => {
    await updateFrameworkScope(s, body)
    await load()
  }

  return (
    <div>
      <PageHeader
        title={t('compliance.title')}
        subtitle={slug
          ? <Button variant="ghost" size="sm" onClick={() => navigate('/compliance')}>← {t('compliance.frameworks')}</Button>
          : t('compliance.subtitle')
        }
      />

      {error && <ErrorBanner error={error} onRetry={load} onDismiss={() => setError(null)} />}

      {loading
        ? <SkeletonTable rows={6} columns={3} />
        : slug
          ? (
            <FrameworkOverview
              slug={slug}
              frameworks={frameworks}
              onUpdateScope={handleUpdateScope}
              t={t}
              toast={toast}
            />
          )
          : (
            <FrameworkPicker
              frameworks={frameworks}
              onPick={(s) => navigate(`/compliance/${s}`)}
              onSubscribe={handleSubscribe}
              onUnsubscribe={handleUnsubscribe}
              t={t}
              toast={toast}
            />
          )
      }
    </div>
  )
}
