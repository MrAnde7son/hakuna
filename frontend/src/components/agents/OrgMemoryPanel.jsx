import React, { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { Brain, Trash2, RefreshCw, ChevronLeft, ArrowUpCircle, Plus } from 'lucide-react'
import { useAuth } from '../../contexts/AuthContext.jsx'
import {
  listOrgMemoryNamespaces,
  listOrgMemoryFacts,
  forgetOrgMemory,
  promoteOrgMemory,
  rememberOrgMemory,
} from '../../api.js'

const SUGGESTION_NAMESPACE = 'behavior_suggestions'

// Where to send a promoted suggestion based on its `kind`. The suggestion
// `value` payload always has a `kind`; default to `priority_rules` so an
// unknown kind still lands somewhere sensible.
const PROMOTE_TARGETS = {
  frequent_dismissal: 'priority_rules',
}

function formatDate(iso) {
  if (!iso) return ''
  try {
    return new Date(iso).toLocaleString()
  } catch {
    return iso
  }
}

function FactCard({ fact, namespace, onForget, onPromote, t }) {
  const [confirming, setConfirming] = useState(false)
  const [busy, setBusy] = useState(false)

  const value = fact.value
  const valueText = typeof value === 'string' ? value : JSON.stringify(value, null, 2)
  const isSuggestion = namespace === SUGGESTION_NAMESPACE
  const promoteTarget = (value && typeof value === 'object' && PROMOTE_TARGETS[value.kind]) || 'priority_rules'

  const handleForget = async () => {
    setBusy(true)
    try {
      await onForget(namespace, fact.key)
    } finally {
      setBusy(false)
      setConfirming(false)
    }
  }

  const handlePromote = async () => {
    setBusy(true)
    try {
      await onPromote(namespace, fact.key, promoteTarget)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div style={{
      border: '1px solid var(--border)',
      borderRadius: 8,
      background: 'var(--surface)',
      padding: 16,
      marginBottom: 12,
    }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
            <span style={{ fontWeight: 600, fontSize: 14 }}>{fact.key}</span>
            <span style={{
              fontSize: 11, padding: '1px 6px', borderRadius: 10,
              background: 'var(--muted-subtle, #f4f4f5)', color: 'var(--muted)',
            }}>
              {t('orgMemory.confidence')}: {Math.round((fact.confidence ?? 0) * 100)}%
            </span>
          </div>
          <pre style={{
            margin: 0, fontSize: 12, lineHeight: 1.5,
            background: 'var(--muted-subtle, #f9fafb)',
            color: 'var(--text)',
            padding: 8, borderRadius: 6,
            whiteSpace: 'pre-wrap', wordBreak: 'break-word',
            maxHeight: 200, overflow: 'auto',
          }}>{valueText}</pre>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, marginTop: 8, fontSize: 11, color: 'var(--muted)' }}>
            <span>{t('orgMemory.learnedOn')}: {formatDate(fact.created_at)}</span>
            {fact.source_agent_id != null && (
              <span>{t('orgMemory.sourceAgent')}: #{fact.source_agent_id}</span>
            )}
            {fact.expires_at && <span>{t('orgMemory.expiresAt')}: {formatDate(fact.expires_at)}</span>}
          </div>
          {fact.evidence && Object.keys(fact.evidence).length > 0 && (
            <details style={{ marginTop: 8 }}>
              <summary style={{ fontSize: 11, color: 'var(--muted)', cursor: 'pointer' }}>
                {t('orgMemory.evidence')}
              </summary>
              <pre style={{
                margin: '6px 0 0', fontSize: 11,
                background: 'var(--muted-subtle, #f9fafb)',
                padding: 6, borderRadius: 4,
                whiteSpace: 'pre-wrap', wordBreak: 'break-word',
              }}>{JSON.stringify(fact.evidence, null, 2)}</pre>
            </details>
          )}
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          {isSuggestion && !confirming && (
            <button
              onClick={handlePromote}
              disabled={busy}
              title={t('orgMemory.promoteHint', { target: promoteTarget })}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: 4,
                background: 'var(--success-subtle, #dcfce7)',
                color: 'var(--success, #16a34a)',
                border: '1px solid var(--success-border, #bbf7d0)',
                borderRadius: 6, padding: '4px 10px',
                cursor: busy ? 'not-allowed' : 'pointer',
                fontSize: 12, fontWeight: 600,
              }}
            >
              <ArrowUpCircle size={13} />
              {t('orgMemory.promote')}
            </button>
          )}
          {!confirming ? (
            <button
              onClick={() => setConfirming(true)}
              title={isSuggestion ? t('orgMemory.dismiss') : t('orgMemory.forget')}
              style={{
                background: 'transparent', border: '1px solid var(--border)',
                borderRadius: 6, padding: '4px 8px', cursor: 'pointer',
                color: 'var(--muted)',
              }}
            >
              <Trash2 size={14} />
            </button>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <button
                onClick={handleForget}
                disabled={busy}
                style={{
                  background: 'var(--danger)', color: '#fff',
                  border: 'none', borderRadius: 6, padding: '4px 8px',
                  cursor: busy ? 'not-allowed' : 'pointer', fontSize: 12,
                }}
              >
                {busy ? '…' : t('orgMemory.confirmForget')}
              </button>
              <button
                onClick={() => setConfirming(false)}
                style={{
                  background: 'transparent', color: 'var(--muted)',
                  border: '1px solid var(--border)', borderRadius: 6,
                  padding: '4px 8px', cursor: 'pointer', fontSize: 12,
                }}
              >
                {t('common.cancel')}
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function AddFactForm({ initialNamespace, namespaceOptions, onSave, onCancel, t }) {
  const [namespace, setNamespace] = useState(initialNamespace || '')
  const [key, setKey] = useState('')
  const [value, setValue] = useState('')
  const [isJson, setIsJson] = useState(false)
  const [confidence, setConfidence] = useState(0.85)
  const [submitting, setSubmitting] = useState(false)
  const [localError, setLocalError] = useState(null)

  const submit = async () => {
    setLocalError(null)
    if (!namespace.trim() || !key.trim()) {
      setLocalError(t('orgMemory.errMissingNsKey'))
      return
    }
    if (!value.trim()) {
      setLocalError(t('orgMemory.errMissingValue'))
      return
    }
    let parsedValue = value
    if (isJson) {
      try {
        parsedValue = JSON.parse(value)
      } catch {
        setLocalError(t('orgMemory.errInvalidJson'))
        return
      }
    }
    setSubmitting(true)
    try {
      await onSave({ namespace: namespace.trim(), key: key.trim(), value: parsedValue, confidence })
    } catch (e) {
      setLocalError(e?.message || 'Failed to save')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div style={{
      border: '1px solid var(--border)', borderRadius: 8, padding: 16,
      background: 'var(--surface)', marginBottom: 16,
    }}>
      <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 12, color: 'var(--text)' }}>
        {t('orgMemory.addFact')}
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 10 }}>
        <div>
          <label style={{ fontSize: 11, color: 'var(--muted)', display: 'block', marginBottom: 4 }}>
            {t('orgMemory.namespaceLabel')}
          </label>
          <input
            value={namespace}
            onChange={e => setNamespace(e.target.value)}
            list="org-memory-ns-options"
            placeholder="priority_rules"
            style={{
              width: '100%', padding: '6px 8px', borderRadius: 6, fontSize: 13,
              border: '1px solid var(--border)', background: 'var(--bg)',
              color: 'var(--text)',
            }}
          />
          <datalist id="org-memory-ns-options">
            {namespaceOptions.map(n => <option key={n} value={n} />)}
          </datalist>
        </div>
        <div>
          <label style={{ fontSize: 11, color: 'var(--muted)', display: 'block', marginBottom: 4 }}>
            {t('orgMemory.keyLabel')}
          </label>
          <input
            value={key}
            onChange={e => setKey(e.target.value)}
            placeholder="pci_assets_priority"
            style={{
              width: '100%', padding: '6px 8px', borderRadius: 6, fontSize: 13,
              border: '1px solid var(--border)', background: 'var(--bg)',
              color: 'var(--text)',
            }}
          />
        </div>
      </div>
      <div style={{ marginBottom: 10 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
          <label style={{ fontSize: 11, color: 'var(--muted)' }}>
            {t('orgMemory.valueLabel')}
          </label>
          <label style={{ fontSize: 11, color: 'var(--muted)', display: 'inline-flex', alignItems: 'center', gap: 4, cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={isJson}
              onChange={e => setIsJson(e.target.checked)}
              style={{ margin: 0 }}
            />
            {t('orgMemory.parseJson')}
          </label>
        </div>
        <textarea
          value={value}
          onChange={e => setValue(e.target.value)}
          rows={4}
          placeholder={isJson ? '{"priority": "critical", "applies_to": "pci"}' : t('orgMemory.valuePlaceholder')}
          style={{
            width: '100%', padding: '6px 8px', borderRadius: 6, fontSize: 13,
            border: '1px solid var(--border)', background: 'var(--bg)',
            color: 'var(--text)', fontFamily: isJson ? 'monospace' : 'inherit',
            resize: 'vertical',
          }}
        />
      </div>
      <div style={{ marginBottom: 12 }}>
        <label style={{ fontSize: 11, color: 'var(--muted)', display: 'block', marginBottom: 4 }}>
          {t('orgMemory.confidenceLabel')}: {Math.round(confidence * 100)}%
        </label>
        <input
          type="range"
          min={0} max={1} step={0.05}
          value={confidence}
          onChange={e => setConfidence(parseFloat(e.target.value))}
          style={{ width: '100%' }}
        />
      </div>
      {localError && (
        <div style={{
          fontSize: 12, color: 'var(--danger, #dc2626)',
          marginBottom: 10,
        }}>{localError}</div>
      )}
      <div style={{ display: 'flex', gap: 8 }}>
        <button
          onClick={submit}
          disabled={submitting}
          style={{
            background: 'var(--accent, #6366f1)', color: '#fff',
            border: 'none', borderRadius: 6, padding: '6px 14px',
            fontSize: 13, fontWeight: 600,
            cursor: submitting ? 'not-allowed' : 'pointer',
          }}
        >
          {submitting ? '…' : t('orgMemory.save')}
        </button>
        <button
          onClick={onCancel}
          disabled={submitting}
          style={{
            background: 'transparent', color: 'var(--muted)',
            border: '1px solid var(--border)', borderRadius: 6,
            padding: '6px 14px', fontSize: 13,
            cursor: submitting ? 'not-allowed' : 'pointer',
          }}
        >
          {t('common.cancel')}
        </button>
      </div>
    </div>
  )
}


export default function OrgMemoryPanel() {
  const { t } = useTranslation()
  const { isViewer, isCollaborator } = useAuth()
  const canEdit = !isViewer && !isCollaborator
  const [namespaces, setNamespaces] = useState([])
  const [activeNs, setActiveNs] = useState(null)
  const [facts, setFacts] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [adding, setAdding] = useState(false)

  const loadNamespaces = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await listOrgMemoryNamespaces()
      setNamespaces(data.namespaces || [])
    } catch (e) {
      setError(e?.message || 'Failed to load namespaces')
    } finally {
      setLoading(false)
    }
  }, [])

  const loadFacts = useCallback(async (ns) => {
    setLoading(true)
    setError(null)
    try {
      const data = await listOrgMemoryFacts(ns)
      setFacts(data.facts || [])
    } catch (e) {
      setError(e?.message || 'Failed to load facts')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { loadNamespaces() }, [loadNamespaces])
  useEffect(() => {
    if (activeNs) loadFacts(activeNs)
  }, [activeNs, loadFacts])

  const handleForget = async (namespace, key) => {
    try {
      await forgetOrgMemory(namespace, key)
      if (activeNs) await loadFacts(activeNs)
      await loadNamespaces()
    } catch (e) {
      setError(e?.message || 'Failed to forget fact')
    }
  }

  const handlePromote = async (namespace, key, targetNamespace) => {
    try {
      await promoteOrgMemory(namespace, key, {
        target_namespace: targetNamespace,
        confidence: 0.85,
      })
      if (activeNs) await loadFacts(activeNs)
      await loadNamespaces()
    } catch (e) {
      setError(e?.message || 'Failed to promote fact')
    }
  }

  const refresh = () => {
    if (activeNs) loadFacts(activeNs)
    else loadNamespaces()
  }

  const handleAdd = async ({ namespace, key, value, confidence }) => {
    await rememberOrgMemory({ namespace, key, value, confidence })
    setAdding(false)
    if (activeNs === namespace) await loadFacts(namespace)
    await loadNamespaces()
  }

  return (
    <div style={{ padding: '28px 32px', maxWidth: 920, margin: '0 auto' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <Brain size={22} color="var(--text)" />
          <div>
            <h1 style={{ margin: 0, fontSize: 22, color: 'var(--text)' }}>{t('orgMemory.title')}</h1>
            <p style={{ margin: '4px 0 0', color: 'var(--muted)', fontSize: 13 }}>
              {t('orgMemory.subtitle')}
            </p>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          {canEdit && !adding && (
            <button
              onClick={() => setAdding(true)}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: 6,
                background: 'var(--accent, #6366f1)', color: '#fff',
                border: 'none', borderRadius: 6, padding: '6px 12px',
                cursor: 'pointer', fontSize: 13, fontWeight: 600,
              }}
            >
              <Plus size={13} />
              {t('orgMemory.addFact')}
            </button>
          )}
          <button
            onClick={refresh}
            style={{
              display: 'inline-flex', alignItems: 'center', gap: 6,
              background: 'transparent', border: '1px solid var(--border)',
              borderRadius: 6, padding: '6px 10px', color: 'var(--text)',
              cursor: 'pointer', fontSize: 13,
            }}
          >
            <RefreshCw size={13} />
            {t('common.refresh')}
          </button>
        </div>
      </div>

      {adding && (
        <AddFactForm
          initialNamespace={activeNs || ''}
          namespaceOptions={namespaces.map(n => n.namespace)}
          onSave={handleAdd}
          onCancel={() => setAdding(false)}
          t={t}
        />
      )}

      {error && (
        <div style={{
          padding: 12, marginBottom: 16,
          border: '1px solid var(--danger-border, #fecaca)',
          background: 'var(--danger-subtle, #fee2e2)',
          color: 'var(--danger, #dc2626)',
          borderRadius: 6, fontSize: 13,
        }}>{error}</div>
      )}

      {!activeNs && (
        <div>
          {loading ? (
            <div style={{ color: 'var(--muted)', fontSize: 13 }}>{t('common.loading')}</div>
          ) : namespaces.length === 0 ? (
            <div style={{ color: 'var(--muted)', fontSize: 13 }}>{t('orgMemory.empty')}</div>
          ) : (
            namespaces.map(ns => (
              <button
                key={ns.namespace}
                onClick={() => setActiveNs(ns.namespace)}
                style={{
                  display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  width: '100%', padding: '14px 16px',
                  border: '1px solid var(--border)', borderRadius: 8,
                  background: 'var(--surface)', color: 'var(--text)',
                  cursor: 'pointer', marginBottom: 8, fontSize: 14,
                }}
              >
                <span style={{ fontWeight: 600 }}>{ns.namespace}</span>
                <span style={{
                  fontSize: 12, color: 'var(--muted)',
                  background: 'var(--muted-subtle, #f4f4f5)',
                  padding: '2px 8px', borderRadius: 10,
                }}>
                  {ns.count} {t('orgMemory.facts')}
                </span>
              </button>
            ))
          )}
        </div>
      )}

      {activeNs && (
        <div>
          <button
            onClick={() => { setActiveNs(null); setFacts([]) }}
            style={{
              display: 'inline-flex', alignItems: 'center', gap: 4,
              background: 'transparent', border: 'none', cursor: 'pointer',
              color: 'var(--muted)', fontSize: 13, marginBottom: 12, padding: 0,
            }}
          >
            <ChevronLeft size={14} />
            {t('orgMemory.backToNamespaces')}
          </button>
          <h2 style={{ margin: '0 0 16px', fontSize: 18, color: 'var(--text)' }}>{activeNs}</h2>
          {loading ? (
            <div style={{ color: 'var(--muted)', fontSize: 13 }}>{t('common.loading')}</div>
          ) : facts.length === 0 ? (
            <div style={{ color: 'var(--muted)', fontSize: 13 }}>{t('orgMemory.noFacts')}</div>
          ) : (
            facts.map(f => (
              <FactCard
                key={f.id}
                fact={f}
                namespace={activeNs}
                onForget={handleForget}
                onPromote={handlePromote}
                t={t}
              />
            ))
          )}
        </div>
      )}
    </div>
  )
}
