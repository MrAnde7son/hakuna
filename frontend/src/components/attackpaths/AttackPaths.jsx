import React, { useEffect, useMemo, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Network, RefreshCw, ChevronRight, Sparkles, ShieldCheck, ExternalLink } from 'lucide-react'
import { listAttackPaths, runCorrelation } from '../../api.js'
import {
  Card, PageHeader, EmptyState, SeverityBadge, Button, Pill,
  ErrorBanner, SkeletonCard,
} from '../shared/ui.jsx'

function SeverityPillForLabel({ label }) {
  const map = { Critical: 4, High: 3, Medium: 2, Low: 1 }
  const sev = map[label] ?? 0
  return <SeverityBadge severity={sev} label={label} />
}

function StepChain({ steps = [] }) {
  if (!steps.length) return <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>No steps</span>
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
      {steps.map((step, idx) => (
        <React.Fragment key={`${step.asset_id}-${step.finding_id}-${idx}`}>
          <div style={{
            display: 'inline-flex', flexDirection: 'column', gap: 2,
            padding: '6px 10px', borderRadius: 8,
            background: 'var(--bg-secondary)', border: '1px solid var(--border)',
            maxWidth: 260,
          }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {step.hostname || 'unknown'}
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {step.finding_name || step.plugin_name || `Finding #${step.finding_id}`}
            </div>
          </div>
          {idx < steps.length - 1 && <ChevronRight size={14} color="var(--text-muted)" />}
        </React.Fragment>
      ))}
    </div>
  )
}

function AttackPathCard({ path, onClick }) {
  return (
    <Card style={{ marginBottom: 12, cursor: 'pointer' }} onClick={onClick}>
      <div style={{ padding: '14px 16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, marginBottom: 10 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <SeverityPillForLabel label={path.severity} />
            <Pill label={`${path.chain_length} step${path.chain_length === 1 ? '' : 's'}`} color="var(--text-secondary)" />
            {path.narrative && <Pill label="Narrated" color="#7c3aed" />}
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            {path.created_at ? new Date(path.created_at).toLocaleString() : ''}
          </div>
        </div>
        <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 10, lineHeight: 1.5 }}>
          <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{path.entry_hostname || 'Entry'}</span>
          {' → '}
          <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{path.target_hostname || 'Target'}</span>
        </div>
        <StepChain steps={path.steps} />
      </div>
    </Card>
  )
}

function AttackPathDetail({ path, onClose }) {
  if (!path) return null
  const mitigations = path.recommended_mitigations || []
  return (
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 200,
      display: 'flex', alignItems: 'flex-start', justifyContent: 'center', padding: 32, overflow: 'auto',
    }}
      onClick={onClose}
    >
      <Card
        style={{ maxWidth: 820, width: '100%', background: 'var(--bg-card)', cursor: 'default' }}
        onClick={(e) => e?.stopPropagation?.()}
      >
        <div style={{ padding: '18px 22px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <Network size={18} color="var(--text-muted)" />
              <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)' }}>
                Attack Path #{path.id}
              </div>
              <SeverityPillForLabel label={path.severity} />
            </div>
            <Button variant="ghost" size="sm" onClick={onClose}>Close</Button>
          </div>

          <div style={{ marginBottom: 18 }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: 0.04 }}>
              Chain
            </div>
            <StepChain steps={path.steps} />
          </div>

          {path.narrative ? (
            <div style={{ marginBottom: 18, padding: '14px 16px', background: '#7c3aed10', border: '1px solid #7c3aed40', borderRadius: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
                <Sparkles size={14} color="#7c3aed" />
                <span style={{ fontSize: 11, fontWeight: 700, color: '#7c3aed', letterSpacing: 0.05, textTransform: 'uppercase' }}>
                  LLM Narrative
                </span>
              </div>
              <div style={{ fontSize: 13, lineHeight: 1.65, color: 'var(--text-secondary)', whiteSpace: 'pre-wrap' }}>
                {path.narrative}
              </div>
            </div>
          ) : (
            <div style={{ marginBottom: 18, padding: '12px 14px', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12, color: 'var(--text-muted)' }}>
              No narrative generated yet. Narratives are produced by the cross-finding correlator when an LLM provider is configured.
            </div>
          )}

          <div>
            <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: 0.04 }}>
              Recommended Mitigations
            </div>
            {mitigations.length === 0 ? (
              <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>None ranked.</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {mitigations.map((m, idx) => (
                  <div key={`${m.finding_id}-${idx}`} style={{
                    display: 'flex', alignItems: 'center', gap: 10,
                    padding: '8px 12px', background: 'var(--bg-secondary)',
                    border: '1px solid var(--border)', borderRadius: 8,
                  }}>
                    <ShieldCheck size={14} color="var(--accent)" />
                    <div style={{ flex: 1, fontSize: 13, color: 'var(--text-primary)' }}>
                      <div style={{ fontWeight: 600 }}>{m.finding_name || `Finding #${m.finding_id}`}</div>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                        Breaks {m.chains_broken} chain{m.chains_broken === 1 ? '' : 's'}
                      </div>
                    </div>
                    <Pill label={`#${idx + 1}`} color="var(--accent)" />
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </Card>
    </div>
  )
}

export default function AttackPaths() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const severity = searchParams.get('severity') || ''

  const [paths, setPaths] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [selectedId, setSelectedId] = useState(null)
  const [rebuilding, setRebuilding] = useState(false)

  const selected = useMemo(
    () => (paths || []).find(p => p.id === selectedId) || null,
    [paths, selectedId],
  )

  async function reload() {
    setLoading(true)
    setError(null)
    try {
      const res = await listAttackPaths({ ...(severity ? { severity } : {}), page_size: 100 })
      setPaths(res?.items || [])
    } catch (e) {
      setError(e?.message || 'Failed to load attack paths')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { reload() }, [severity])

  async function onRebuild() {
    setRebuilding(true)
    try {
      await runCorrelation()
      await reload()
    } catch (e) {
      setError(e?.message || 'Failed to rebuild correlations')
    } finally {
      setRebuilding(false)
    }
  }

  function setSeverity(next) {
    const nextParams = new URLSearchParams(searchParams)
    if (!next) nextParams.delete('severity')
    else nextParams.set('severity', next)
    setSearchParams(nextParams, { replace: true })
  }

  return (
    <div style={{ padding: 24, maxWidth: 1200, margin: '0 auto' }}>
      <PageHeader
        title={t('attackPaths.title', 'Attack Paths')}
        subtitle={t('attackPaths.subtitle', 'LLM-narrated exploitation chains inferred from findings + knowledge graph')}
        action={
          <div style={{ display: 'flex', gap: 6 }}>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => navigate('/findings?corroborated=true')}
              title={t('attackPaths.viewCorroboratedTooltip', 'Findings confirmed by ≥ 2 scanners')}
            >
              <ShieldCheck size={14} style={{ marginRight: 4 }} />
              {t('attackPaths.viewCorroborated', 'View corroborated findings')}
              <ExternalLink size={12} style={{ marginLeft: 4 }} />
            </Button>
            <Button onClick={onRebuild} variant="ghost" size="sm" disabled={rebuilding}>
              <RefreshCw size={14} style={{ marginRight: 4 }} />
              {rebuilding ? t('attackPaths.rebuilding', 'Rebuilding…') : t('attackPaths.rebuild', 'Rebuild')}
            </Button>
          </div>
        }
      />

      <div style={{ display: 'flex', gap: 6, marginBottom: 14, flexWrap: 'wrap' }}>
        {['', 'Critical', 'High', 'Medium'].map(s => (
          <button
            key={s || 'all'}
            onClick={() => setSeverity(s)}
            style={{
              padding: '4px 10px', borderRadius: 999, fontSize: 12, fontWeight: 600,
              background: severity === s ? 'var(--accent)' : 'var(--bg-secondary)',
              color: severity === s ? 'var(--primary-foreground)' : 'var(--text-secondary)',
              border: severity === s ? '1px solid var(--accent)' : '1px solid var(--border)',
              cursor: 'pointer',
            }}
          >
            {s || t('attackPaths.all', 'All')}
          </button>
        ))}
      </div>

      {error && <ErrorBanner message={error} />}

      {loading && paths === null ? (
        <div>
          <SkeletonCard />
          <SkeletonCard />
          <SkeletonCard />
        </div>
      ) : (paths?.length ?? 0) === 0 ? (
        <EmptyState
          icon={Network}
          title={t('attackPaths.emptyTitle', 'No attack paths yet')}
          sub={t('attackPaths.emptySub', 'Paths are generated by the cross-finding correlator when internet-facing assets have critical/high findings that chain through related assets.')}
        />
      ) : (
        <div>
          {paths.map(p => (
            <AttackPathCard key={p.id} path={p} onClick={() => setSelectedId(p.id)} />
          ))}
        </div>
      )}

      {selected && <AttackPathDetail path={selected} onClose={() => setSelectedId(null)} />}
    </div>
  )
}
