import { useEffect, useState, useCallback, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import {
  Bot, AlertTriangle, AlertCircle, Info, Check, X, ExternalLink,
  RefreshCw, Sparkles, Inbox, Send,
} from 'lucide-react'

import {
  getFeed, markFeedEntryRead, recordFeedEntryDecision, decideAgentApproval,
  getFeedChatContext, createCopilotConversation, getCopilotConversation,
  streamCopilotMessage,
} from '../../api.js'
import {
  Card, EmptyState, Button, Pill, SeverityBadge,
} from '../shared/ui.jsx'

// ── Markdown renderer (mirrors CopilotPanel's inline style) ─────────
const mdComponents = {
  h1: ({ children }) => <h1 style={{ fontSize: 15, fontWeight: 700, margin: '8px 0 4px', color: 'var(--text-primary)' }}>{children}</h1>,
  h2: ({ children }) => <h2 style={{ fontSize: 14, fontWeight: 700, margin: '8px 0 4px', color: 'var(--accent)' }}>{children}</h2>,
  h3: ({ children }) => <h3 style={{ fontSize: 13, fontWeight: 600, margin: '6px 0 3px', color: 'var(--text-primary)' }}>{children}</h3>,
  p: ({ children }) => <p style={{ margin: '6px 0', lineHeight: 1.55, color: 'var(--text-secondary)' }}>{children}</p>,
  ul: ({ children }) => <ul style={{ margin: '4px 0', paddingLeft: 18, color: 'var(--text-secondary)' }}>{children}</ul>,
  ol: ({ children }) => <ol style={{ margin: '4px 0', paddingLeft: 18, color: 'var(--text-secondary)' }}>{children}</ol>,
  li: ({ children }) => <li style={{ margin: '2px 0' }}>{children}</li>,
  strong: ({ children }) => <strong style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{children}</strong>,
  code: ({ children }) => (
    <code style={{ background: 'var(--bg-secondary)', padding: '1px 5px', borderRadius: 3, fontSize: 12, fontFamily: 'monospace', color: 'var(--text-primary)' }}>{children}</code>
  ),
  blockquote: ({ children }) => (
    <blockquote style={{ borderLeft: '3px solid var(--accent)', paddingLeft: 10, margin: '6px 0', color: 'var(--text-muted)' }}>{children}</blockquote>
  ),
  a: ({ children, href }) => (
    <a href={href} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent)' }}>{children}</a>
  ),
}

// ── Maps ──────────────────────────────────────────────────────────
// Translates the feed's severity strings to the numeric scale SeverityBadge expects.
const SEVERITY_TO_INT = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
const SEVERITY_ICON = {
  critical: AlertTriangle, high: AlertCircle, medium: AlertCircle, low: Info, info: Info,
}
const KIND_LABEL_KEY = {
  observation: 'feed.kind.observation',
  decision:    'feed.kind.decision',
  action:      'feed.kind.action',
  question:    'feed.kind.question',
  brief:       'feed.kind.brief',
}

// Color hint per kind — matches the system's pill convention (subtle tint).
const KIND_COLOR = {
  observation: 'var(--text-muted)',
  decision:    '#0d9488',
  action:      'var(--accent)',
  question:    '#d97706',
  brief:       '#7c3aed',
}

function relativeTime(t, iso) {
  if (!iso) return ''
  // Backend serializes naive UTC datetimes without a TZ suffix; browsers would
  // otherwise parse them as local time.
  const normalized = /[zZ]|[+-]\d{2}:?\d{2}$/.test(iso) ? iso : `${iso}Z`
  const d = new Date(normalized)
  const ms = Date.now() - d.getTime()
  const m = Math.round(ms / 60000)
  if (m < 1) return t('feed.justNow')
  if (m < 60) return t('feed.minutesAgo', { count: m })
  const h = Math.round(m / 60)
  if (h < 24) return t('feed.hoursAgo', { count: h })
  const days = Math.round(h / 24)
  return t('feed.daysAgo', { count: days })
}

// ── Inline action button ──────────────────────────────────────────
function ProposedAction({ entry, action, onActed }) {
  const { t } = useTranslation()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  const handleApprove = async () => {
    if (!action.approval_id) return
    setBusy(true); setError(null)
    try {
      await decideAgentApproval(action.approval_id, 'approve')
      await recordFeedEntryDecision(entry.id, 'acted')
      onActed?.(entry.id, 'acted')
    } catch (e) {
      setError(e.message || t('feed.actionFailed'))
    } finally { setBusy(false) }
  }

  const handleReject = async () => {
    if (!action.approval_id) return
    setBusy(true); setError(null)
    try {
      await decideAgentApproval(action.approval_id, 'reject', t('feed.rejectedFromFeed'))
      await recordFeedEntryDecision(entry.id, 'dismissed')
      onActed?.(entry.id, 'dismissed')
    } catch (e) {
      setError(e.message || t('feed.actionFailed'))
    } finally { setBusy(false) }
  }

  if (action.kind === 'approve_action' && action.approval_id) {
    return (
      <div style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}>
        <Button onClick={handleApprove} variant="primary" size="sm" disabled={busy}>
          <Check size={13} />
          {action.label || t('feed.approve')}
        </Button>
        <Button onClick={handleReject} variant="ghost" size="sm" disabled={busy}>
          <X size={13} />
          {t('feed.reject')}
        </Button>
        {error && <span style={{ color: 'var(--danger)', fontSize: 11 }}>{error}</span>}
      </div>
    )
  }

  if (action.kind === 'navigate' && action.href) {
    const isExternal = /^https?:\/\//i.test(action.href)
    if (isExternal) {
      return (
        <a
          href={action.href} target="_blank" rel="noopener noreferrer"
          style={{
            display: 'inline-flex', alignItems: 'center', gap: 6,
            padding: '5px 10px', borderRadius: 6, border: '1px solid var(--border)',
            background: 'transparent', color: 'var(--text-secondary)',
            fontSize: 12, fontWeight: 600, textDecoration: 'none',
          }}
        >
          <ExternalLink size={13} />
          {action.label || t('feed.open')}
        </a>
      )
    }
    return (
      <Link
        to={action.href}
        style={{
          display: 'inline-flex', alignItems: 'center', gap: 6,
          padding: '5px 10px', borderRadius: 6, border: '1px solid var(--border)',
          background: 'transparent', color: 'var(--text-secondary)',
          fontSize: 12, fontWeight: 600, textDecoration: 'none',
        }}
      >
        <ExternalLink size={13} />
        {action.label || t('feed.open')}
      </Link>
    )
  }

  return <Pill label={action.label || action.kind} color="var(--text-muted)" />
}

// ── Status filter (matches the system's filter chip pattern) ──────
function StatusFilter({ value, onChange }) {
  const { t } = useTranslation()
  const opts = [
    { v: 'open',      label: t('feed.filter.open') },
    { v: 'acted',     label: t('feed.filter.acted') },
    { v: 'dismissed', label: t('feed.filter.dismissed') },
    { v: '',          label: t('feed.filter.all') },
  ]
  return (
    <div
      className="feed-status-filter"
      style={{
        display: 'inline-flex', gap: 4, padding: 3,
        background: 'var(--bg-secondary)', borderRadius: 8,
        border: '1px solid var(--border)',
        maxWidth: '100%', overflowX: 'auto',
      }}
    >
      {opts.map(({ v, label }) => {
        const active = value === v
        return (
          <button
            key={v || 'all'}
            onClick={() => onChange(v)}
            style={{
              padding: '5px 12px', borderRadius: 5, border: 'none',
              background: active ? 'var(--bg-card)' : 'transparent',
              color: active ? 'var(--text-primary)' : 'var(--text-muted)',
              fontSize: 12, fontWeight: 600, cursor: 'pointer',
              boxShadow: active ? '0 1px 2px rgba(0,0,0,0.06)' : 'none',
              transition: 'all 0.15s',
              whiteSpace: 'nowrap',
            }}
          >
            {label}
          </button>
        )
      })}
    </div>
  )
}

// ── One feed entry as a Card ──────────────────────────────────────
function FeedEntryCard({ entry, onActed, onMarkedRead }) {
  const { t } = useTranslation()
  const SevIcon = SEVERITY_ICON[entry.severity] || Info
  const severityInt = SEVERITY_TO_INT[entry.severity] ?? 0

  const handleHoverRead = async () => {
    if (entry.is_read) return
    try {
      await markFeedEntryRead(entry.id)
      onMarkedRead?.(entry.id)
    } catch { /* non-fatal */ }
  }

  return (
    <div onMouseEnter={handleHoverRead} className="feed-entry" style={{ marginBottom: 12, position: 'relative' }}>
      {/* Unread dot — outside the card so it doesn't fight the border */}
      {!entry.is_read && (
        <span
          title={t('feed.unread')}
          className="feed-entry-dot"
          style={{
            position: 'absolute', top: 14, left: -14, width: 8, height: 8,
            borderRadius: 4, background: 'var(--accent)',
          }}
        />
      )}
      <Card style={{ padding: 0, opacity: entry.status === 'dismissed' ? 0.6 : 1, transition: 'opacity 0.2s' }}>
        <div className="feed-entry-body" style={{ padding: 18 }}>
          {/* Header row: severity + kind + agent + time */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, marginBottom: 10, flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
              <SeverityBadge severity={severityInt} label={t(`feed.severity.${entry.severity}`)} />
              <Pill label={t(KIND_LABEL_KEY[entry.kind] || 'feed.kind.observation')} color={KIND_COLOR[entry.kind] || 'var(--text-muted)'} />
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, color: 'var(--text-muted)', fontSize: 12 }}>
                <Bot size={12} />
                {entry.agent_name || t('feed.unknownAgent')}
              </span>
            </div>
            <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8, fontSize: 11, color: 'var(--text-muted)' }}>
              <SevIcon size={12} />
              <time dateTime={entry.created_at}>{relativeTime(t, entry.created_at)}</time>
            </div>
          </div>

          {/* Headline */}
          <h3 style={{ fontSize: 15, fontWeight: 600, margin: '4px 0 8px', lineHeight: 1.4, color: 'var(--text-primary)' }}>
            {entry.headline}
          </h3>

          {/* Body */}
          {entry.body_md && (
            <div style={{ fontSize: 13 }}>
              <ReactMarkdown remarkPlugins={[remarkGfm]} components={mdComponents}>{entry.body_md}</ReactMarkdown>
            </div>
          )}

          {/* Inline actions */}
          {entry.proposed_actions?.length > 0 && (
            <div style={{ marginTop: 14, display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>
              {entry.proposed_actions.map((a, i) => (
                <ProposedAction key={`${entry.id}-${i}`} entry={entry} action={a} onActed={onActed} />
              ))}
            </div>
          )}

          {/* Footer: trace link + resolution note. Trace appears whenever
              we have an agent_run_id (set by the engine since agent_run_id
              plumbing). Click drops the user into AgentBuilder with the
              run pre-selected so they can read the LLM's reasoning. */}
          {(entry.status !== 'open' || (entry.agent_id && entry.agent_run_id)) && (
            <div style={{ marginTop: 10, paddingTop: 10, borderTop: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
              {entry.status !== 'open' ? (
                <span style={{ color: 'var(--text-muted)', fontSize: 12, fontStyle: 'italic' }}>
                  {t(`feed.status.${entry.status}`, entry.status)}
                </span>
              ) : <span />}
              {entry.agent_id && entry.agent_run_id && (
                <Link
                  to={`/agents?agent=${entry.agent_id}&run=${entry.agent_run_id}`}
                  style={{
                    color: 'var(--text-muted)', fontSize: 11,
                    display: 'inline-flex', alignItems: 'center', gap: 4,
                    textDecoration: 'none',
                  }}
                  onMouseEnter={e => e.currentTarget.style.color = 'var(--text-primary)'}
                  onMouseLeave={e => e.currentTarget.style.color = 'var(--text-muted)'}
                >
                  {t('feed.viewTrace')}
                </Link>
              )}
            </div>
          )}
        </div>
      </Card>
    </div>
  )
}

// ── Chat composer ─────────────────────────────────────────────────
// Page-level conversation that delegates to the Security Copilot. The
// recent-feed block is fetched from /feed/chat-context and passed via
// copilot's ``context`` field on each turn — same agent, same approvals
// queue, same persistence. The conversation id is cached in localStorage
// so the thread survives page reload.
const FEED_CONV_KEY = 'hakuna.feed.copilot_conv_id'

function FeedChat({ contextEntryCount }) {
  const { t } = useTranslation()
  const [messages, setMessages] = useState([])  // {role, content, error?}
  const [streamText, setStreamText] = useState('')
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const convIdRef = useRef(null)
  const threadRef = useRef(null)

  // Restore the cached conversation (if any) so the thread persists across
  // reload. A 404 means the conversation was deleted — drop the stale id
  // and we'll lazy-create on next send.
  useEffect(() => {
    const cached = Number(localStorage.getItem(FEED_CONV_KEY))
    if (!cached) return
    let cancelled = false
    getCopilotConversation(cached).then((conv) => {
      if (cancelled) return
      convIdRef.current = conv.id
      const hist = (conv.messages || [])
        .filter(m => m.role === 'user' || m.role === 'assistant')
        .map(m => ({ role: m.role, content: m.content }))
      setMessages(hist)
    }).catch(() => {
      localStorage.removeItem(FEED_CONV_KEY)
    })
    return () => { cancelled = true }
  }, [])

  useEffect(() => {
    if (!threadRef.current) return
    threadRef.current.scrollTop = threadRef.current.scrollHeight
  }, [messages, streamText, busy])

  const ensureConversation = async () => {
    if (convIdRef.current) return convIdRef.current
    const conv = await createCopilotConversation()
    convIdRef.current = conv.id
    localStorage.setItem(FEED_CONV_KEY, String(conv.id))
    return conv.id
  }

  const submit = useCallback(async () => {
    const text = input.trim()
    if (!text || busy) return
    setMessages(prev => [...prev, { role: 'user', content: text }])
    setInput('')
    setBusy(true)
    setStreamText('')
    try {
      const convId = await ensureConversation()
      let context = ''
      try {
        const ctx = await getFeedChatContext(contextEntryCount)
        context = ctx?.context || ''
      } catch { /* non-fatal — copilot can still answer without the block */ }

      let accum = ''
      const finalText = await streamCopilotMessage(convId, { message: text, context }, (ev) => {
        if (ev.type === 'text') {
          accum += ev.text || ''
          setStreamText(accum)
        } else if (ev.type === 'done') {
          accum = ev.output || accum
        }
      })
      setMessages(prev => [...prev, { role: 'assistant', content: finalText || accum }])
    } catch (e) {
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: e.message || t('feed.chat.failed'),
        error: true,
      }])
    } finally {
      setBusy(false)
      setStreamText('')
    }
  }, [input, busy, contextEntryCount, t])

  const onKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      submit()
    }
  }

  const clear = async () => {
    // Drop the local thread but keep the copilot conversation — the user
    // can find it later in /copilot if they want to revisit. If they want
    // a true reset they can clear it from there.
    setMessages([])
    setStreamText('')
    convIdRef.current = null
    localStorage.removeItem(FEED_CONV_KEY)
  }

  const showThread = messages.length > 0 || busy

  return (
    <Card style={{ padding: 0, marginBottom: 16, overflow: 'hidden' }}>
      <div>
        {showThread && (
          <div
            ref={threadRef}
            style={{
              maxHeight: 360, overflowY: 'auto',
              padding: '12px 16px',
              display: 'flex', flexDirection: 'column', gap: 10,
              background: 'var(--bg-secondary)',
            }}
          >
            {messages.map((m, i) => (
              <div
                key={i}
                style={{
                  alignSelf: m.role === 'user' ? 'flex-end' : 'flex-start',
                  maxWidth: '85%',
                  padding: '8px 12px',
                  borderRadius: 10,
                  background: m.role === 'user' ? 'var(--accent)' : 'var(--bg-card)',
                  color: m.role === 'user' ? '#fff' : 'var(--text-primary)',
                  border: m.role === 'user' ? 'none' : '1px solid var(--border)',
                  fontSize: 13, lineHeight: 1.5,
                }}
              >
                {m.role === 'assistant' ? (
                  <>
                    {m.error && (
                      <div style={{ color: 'var(--danger)', fontSize: 11, marginBottom: 4 }}>
                        {t('feed.chat.failed')}
                      </div>
                    )}
                    <ReactMarkdown remarkPlugins={[remarkGfm]} components={mdComponents}>
                      {m.content || ''}
                    </ReactMarkdown>
                  </>
                ) : (
                  <div style={{ whiteSpace: 'pre-wrap' }}>{m.content}</div>
                )}
              </div>
            ))}
            {busy && (streamText ? (
              <div style={{
                alignSelf: 'flex-start', maxWidth: '85%',
                padding: '8px 12px', borderRadius: 10,
                background: 'var(--bg-card)', color: 'var(--text-primary)',
                border: '1px solid var(--border)', fontSize: 13, lineHeight: 1.5,
              }}>
                <ReactMarkdown remarkPlugins={[remarkGfm]} components={mdComponents}>
                  {streamText}
                </ReactMarkdown>
              </div>
            ) : (
              <div style={{
                alignSelf: 'flex-start', fontSize: 12, color: 'var(--text-muted)',
                fontStyle: 'italic', padding: '4px 8px',
              }}>
                {t('feed.chat.thinking')}
              </div>
            ))}
          </div>
        )}

        <div style={{ display: 'flex', gap: 8, padding: 12, alignItems: 'center' }}>
          <input
            type="text"
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={onKeyDown}
            placeholder={t('feed.chat.placeholder')}
            disabled={busy}
            style={{
              flex: 1, height: 36,
              padding: '0 10px', borderRadius: 6,
              border: '1px solid var(--border)', background: 'var(--bg-card)',
              color: 'var(--text-primary)', fontSize: 13, fontFamily: 'inherit',
              outline: 'none',
            }}
          />
          <Button onClick={submit} variant="primary" size="sm" disabled={busy || !input.trim()}>
            <Send size={13} />
            {t('feed.chat.send')}
          </Button>
          {messages.length > 0 && (
            <Button onClick={clear} variant="ghost" size="sm" disabled={busy}>
              {t('feed.chat.clear')}
            </Button>
          )}
        </div>
      </div>
    </Card>
  )
}

// ── Page ──────────────────────────────────────────────────────────
export default function Feed() {
  const { t } = useTranslation()
  const [entries, setEntries] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [statusFilter, setStatusFilter] = useState('open')
  const reloadRef = useRef(0)
  // Adaptive polling state: ``fastPollUntil`` is the wall-clock deadline
  // until which we poll every 5s. Initial value puts us in fast mode for
  // 2 min after mount (post-onboarding warmup). Each time new entries
  // arrive the deadline gets pushed out, so a chain of narrators
  // (welcome → scan_started → scan_batch_complete → scan_complete) keeps
  // the cadence tight while activity is happening.
  const fastPollUntil = useRef(Date.now() + 2 * 60 * 1000)
  const prevEntryCount = useRef(0)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const rows = await getFeed({ status: statusFilter || undefined })
      setEntries(rows || [])
    } catch (e) {
      setError(e.message || t('feed.loadFailed'))
    } finally {
      setLoading(false)
    }
  }, [statusFilter, t])

  useEffect(() => { load() }, [load])

  // When entries grow, extend the fast-poll window. This catches the
  // common chain-of-events case during a scan run.
  useEffect(() => {
    if (entries.length > prevEntryCount.current) {
      fastPollUntil.current = Date.now() + 2 * 60 * 1000
    }
    prevEntryCount.current = entries.length
  }, [entries.length])

  // Adaptive polling. The interval fires every 5s but only triggers a
  // load() when enough time has elapsed since the last fire — fast (5s)
  // while in the warmup/active window, slow (60s) otherwise. Single
  // setInterval keeps the timer logic simple and the cleanup easy.
  // visibilitychange refreshes immediately on tab focus regardless of
  // window state, so a returning user doesn't wait for the next tick.
  useEffect(() => {
    const FAST_MS = 5_000
    const SLOW_MS = 60_000
    let lastFiredAt = Date.now()

    const onVisible = () => {
      if (document.visibilityState === 'visible') {
        load()
        lastFiredAt = Date.now()
      }
    }
    document.addEventListener('visibilitychange', onVisible)

    const tick = setInterval(() => {
      if (document.visibilityState !== 'visible') return
      const now = Date.now()
      const inFastWindow = now < fastPollUntil.current
      const minInterval = inFastWindow ? FAST_MS : SLOW_MS
      if (now - lastFiredAt >= minInterval) {
        load()
        lastFiredAt = now
      }
    }, FAST_MS)

    return () => {
      document.removeEventListener('visibilitychange', onVisible)
      clearInterval(tick)
    }
  }, [load])

  // Optimistic local updates so the user sees their click before the
  // next refresh round-trips.
  const handleActed = (entryId, newStatus) => {
    setEntries((prev) => prev.map((e) => e.id === entryId ? { ...e, status: newStatus, is_read: true } : e))
  }
  const handleMarkedRead = (entryId) => {
    setEntries((prev) => prev.map((e) => e.id === entryId ? { ...e, is_read: true } : e))
  }

  const empty = !loading && entries.length === 0

  return (
    <div className="feed-page">
      <style>{`
        @keyframes spin { to { transform: rotate(360deg) } }
        .feed-header {
          display: flex; justify-content: space-between; align-items: flex-start;
          gap: 16px; margin-bottom: 24px; flex-wrap: wrap;
        }
        .feed-header-actions {
          display: flex; gap: 8px; align-items: center; flex-wrap: wrap;
        }
        .feed-list { padding-left: 16px; }
        @media (max-width: 640px) {
          .feed-header { gap: 12px; margin-bottom: 16px; }
          .feed-header-title h1 { font-size: 18px !important; }
          .feed-header-actions { width: 100%; }
          .feed-status-filter { flex: 1; }
          .feed-list { padding-left: 12px; }
          .feed-entry-dot { left: -10px !important; }
          .feed-entry-body { padding: 14px !important; }
        }
      `}</style>
      <div className="feed-header">
        <div className="feed-header-title" style={{ minWidth: 0, flex: 1 }}>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary)', display: 'inline-flex', alignItems: 'center', gap: 8 }}>
            <Sparkles size={20} color="var(--accent)" />
            {t('feed.title')}
          </h1>
          <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 4 }}>{t('feed.subtitle')}</div>
        </div>
        <div className="feed-header-actions">
          <StatusFilter value={statusFilter} onChange={setStatusFilter} />
          <Button onClick={() => { reloadRef.current++; load() }} variant="ghost" size="sm" disabled={loading}>
            <RefreshCw size={14} style={{ animation: loading ? 'spin 1.2s linear infinite' : 'none' }} />
            {t('feed.refresh')}
          </Button>
        </div>
      </div>

      <FeedChat contextEntryCount={5} />

      {error && (
        <div style={{
          background: 'var(--danger)15', color: 'var(--danger)',
          border: '1px solid var(--danger)40', borderRadius: 8,
          padding: '10px 14px', marginBottom: 12, fontSize: 13,
        }}>
          {error}
        </div>
      )}

      {loading && entries.length === 0 && !error && (
        <div style={{ padding: '64px 0', textAlign: 'center', color: 'var(--text-muted)' }}>
          {t('feed.loading')}
        </div>
      )}

      {empty && !error && (
        <EmptyState
          icon={Inbox}
          title={t('feed.empty.title')}
          sub={t('feed.empty.body')}
        />
      )}

      {entries.length > 0 && (
        <div className="feed-list">{/* leave room for the unread dot */}
          {entries.map((entry) => (
            <FeedEntryCard
              key={entry.id}
              entry={entry}
              onActed={handleActed}
              onMarkedRead={handleMarkedRead}
            />
          ))}
        </div>
      )}
    </div>
  )
}
