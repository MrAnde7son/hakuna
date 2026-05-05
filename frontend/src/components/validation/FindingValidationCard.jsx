import React, { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ShieldCheck, Play, Sparkles, Bot, ExternalLink, ChevronRight, ChevronDown } from 'lucide-react'
import ReactMarkdown from 'react-markdown'
import { Card, Button, Pill, useToast } from '../shared/ui.jsx'
import { getValidationStatus, runValidation } from '../../api.js'

const VERDICT_STYLES = {
  true_positive: { color: 'var(--critical)', bg: 'var(--critical)10', border: 'var(--critical)40', label: 'True Positive' },
  false_positive: { color: 'var(--success)', bg: 'var(--success)10', border: 'var(--success)40', label: 'False Positive' },
  needs_review: { color: 'var(--warning)', bg: 'var(--warning)10', border: 'var(--warning)40', label: 'Needs Review' },
}

/**
 * Validation status + "Run validation" button for a single finding.
 * Shows LLM verdict (from services.llm_vuln_validator) and recent
 * validator agent runs (from services.validation_agent_scheduler).
 * Only renders when the finding is severity >= 3 (high/critical).
 */
export default function FindingValidationCard({ findingId, severity }) {
  const { t } = useTranslation()
  const toast = useToast()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [running, setRunning] = useState(false)
  const [expandedRuns, setExpandedRuns] = useState({})

  const eligible = (severity ?? 0) >= 3

  async function load() {
    if (!findingId || !eligible) return
    setLoading(true)
    try {
      const resp = await getValidationStatus(findingId)
      setData(resp)
    } catch (e) {
      // 404 = not applicable (non-vm_scanner finding etc.) — treat as no data
      setData(null)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [findingId])

  async function onRun() {
    setRunning(true)
    try {
      await runValidation(findingId)
      toast?.(t('validation.launched', 'Validation started for finding #{{id}}', { id: findingId }), 'success')
      setTimeout(load, 1500)
    } catch (e) {
      toast?.(e?.message || 'Failed to run validation', 'error')
    } finally {
      setRunning(false)
    }
  }

  if (!eligible) return null
  if (loading && data === null) return null
  if (!data && !eligible) return null

  const verdict = data?.verdict
  const style = verdict ? VERDICT_STYLES[verdict] : null
  const confidence = data?.confidence
  const reasoning = data?.reasoning
  const validator = data?.validator || 'llm'
  const validatedAt = data?.validated_at
  const recent = data?.recent_agent_runs || []

  function isExpanded(r, idx) {
    if (r.id in expandedRuns) return expandedRuns[r.id]
    return idx === 0 && !!r.output
  }
  function toggleRun(r, idx) {
    setExpandedRuns(prev => ({ ...prev, [r.id]: !isExpanded(r, idx) }))
  }

  return (
    <Card style={{
      marginBottom: 14,
      border: style ? `1px solid ${style.border}` : '1px solid var(--border)',
      background: style ? style.bg : 'var(--bg-card)',
    }}>
      <div style={{ padding: '14px 18px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10, gap: 8, flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <ShieldCheck size={16} color={style?.color || 'var(--text-muted)'} />
            <span style={{ fontSize: 11, fontWeight: 700, color: style?.color || 'var(--text-muted)', letterSpacing: 0.05, textTransform: 'uppercase' }}>
              {t('validation.sectionTitle', 'AI Validation')}
            </span>
            {verdict && (
              <span style={{
                padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 700,
                background: style.color + '20', color: style.color, border: `1px solid ${style.border}`,
              }}>
                {style.label}
              </span>
            )}
            {typeof confidence === 'number' && (
              <Pill label={`${Math.round(confidence * 100)}% ${t('validation.confidence', 'confidence')}`} color="var(--text-secondary)" />
            )}
            {validator && (
              <Pill label={validator === 'agent' ? t('validation.validatorAgent', 'agent') : t('validation.validatorLlm', 'llm')} color="var(--accent)" />
            )}
          </div>
          <Button variant="primary" size="sm" onClick={onRun} disabled={running}>
            <Play size={12} style={{ marginRight: 4 }} />
            {running ? t('validation.starting', 'Starting…') : t('validation.runAgent', 'Run validator agent')}
          </Button>
        </div>

        {reasoning && (
          <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.55, marginBottom: 10, whiteSpace: 'pre-wrap' }}>
            {reasoning}
          </div>
        )}

        {(data?.ctx_reachability || data?.ctx_exploitability) && (
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 10 }}>
            {data.ctx_reachability && (
              <Pill label={`${t('validation.reachability', 'reachability')}: ${data.ctx_reachability}`} color="var(--text-secondary)" />
            )}
            {data.ctx_exploitability && (
              <Pill label={`${t('validation.exploitability', 'exploitability')}: ${data.ctx_exploitability}`} color="var(--text-secondary)" />
            )}
          </div>
        )}

        {validatedAt && (
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: recent.length ? 10 : 0 }}>
            {t('validation.validatedAt', 'Validated')} {new Date(validatedAt).toLocaleString()}
          </div>
        )}

        {recent.length > 0 && (
          <div style={{ marginTop: 8, paddingTop: 10, borderTop: '1px solid var(--border)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
              <Bot size={12} color="var(--text-muted)" />
              <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', letterSpacing: 0.04, textTransform: 'uppercase' }}>
                {t('validation.recentRuns', 'Recent agent runs')}
              </span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {recent.map((r, idx) => {
                const expanded = isExpanded(r, idx)
                const hasOutput = !!r.output
                return (
                  <div key={r.id} style={{
                    borderRadius: 6,
                    background: 'var(--bg-secondary)',
                    fontSize: 11,
                    overflow: 'hidden',
                  }}>
                    <div
                      onClick={hasOutput ? () => toggleRun(r, idx) : undefined}
                      style={{
                        display: 'flex', alignItems: 'center', gap: 8,
                        padding: '6px 8px',
                        cursor: hasOutput ? 'pointer' : 'default',
                      }}
                    >
                      {hasOutput ? (
                        expanded ? <ChevronDown size={12} color="var(--text-muted)" /> : <ChevronRight size={12} color="var(--text-muted)" />
                      ) : (
                        <span style={{ width: 12 }} />
                      )}
                      <span style={{ color: 'var(--text-primary)' }}>#{r.id}</span>
                      <span style={{ color: 'var(--text-muted)' }}>{r.status}</span>
                      <span style={{ color: 'var(--text-muted)' }}>· {r.steps} step{r.steps === 1 ? '' : 's'}</span>
                      {r.created_at && (
                        <span style={{ color: 'var(--text-muted)', marginLeft: 'auto' }}>
                          {new Date(r.created_at).toLocaleString()}
                        </span>
                      )}
                    </div>
                    {expanded && hasOutput && (
                      <div style={{
                        padding: '8px 12px 10px 26px',
                        borderTop: '1px solid var(--border)',
                        fontSize: 12,
                        color: 'var(--text-secondary)',
                        lineHeight: 1.55,
                        background: 'var(--bg-card)',
                      }}>
                        <div className="markdown-body" style={{ whiteSpace: 'normal' }}>
                          <ReactMarkdown>{r.output}</ReactMarkdown>
                        </div>
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          </div>
        )}
      </div>
    </Card>
  )
}
