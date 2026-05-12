import { useEffect, useState, useCallback, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import {
  Bot, AlertTriangle, AlertCircle, Info, Check, X, ExternalLink,
  RefreshCw, Sparkles, Inbox, Send, Plug, Wand2, Trash2,
} from 'lucide-react'

import {
  getFeed, markFeedEntryRead, recordFeedEntryDecision, decideAgentApproval,
  getFeedChatContext, createCopilotConversation, getCopilotConversation,
  streamCopilotMessage,
  assignTags, unassignTags,
  setAssetOwnership, setFindingOwnership, confirmAssetOwner,
  downloadComplianceReport, runReportScheduleNow,
  syncFindingTickets, triggerTicketSync, createCampaignSlackChannel,
} from '../../api.js'

// Whitelist of mutations a narrator can request inline. Keeps the
// agent → user contract narrow: anything not in this map degrades to a
// muted pill so a stale or hallucinated op can't trigger arbitrary
// requests.
//
// Tagging / ownership are SOFT_WRITE and trivially reversible. Report
// ops are read-shaped (download) or low-impact triggers (re-run a
// scheduled run). Ticket-sync ops touch external systems but are
// idempotent reconciliations against existing tickets — not net-new
// tickets/messages, which keep flowing through approve_action.
const APPLY_INLINE_OPS = {
  assign_tags:                  ({ args }) => assignTags(args),
  unassign_tags:                ({ args }) => unassignTags(args),
  set_asset_ownership:          ({ args }) => setAssetOwnership(args.asset_id, args),
  set_finding_ownership:        ({ args }) => setFindingOwnership(args.finding_id, args),
  confirm_asset_owner:          ({ args }) => confirmAssetOwner(args.asset_id),
  download_report:              ({ args }) => downloadComplianceReport(args.run_id, args.framework_slug, args.fmt),
  run_report:                   ({ args }) => runReportScheduleNow(args.schedule_id),
  sync_finding_tickets:         ({ args }) => syncFindingTickets(args.finding_id),
  trigger_ticket_sync:          () => triggerTicketSync(),
  create_campaign_slack_channel: ({ args }) => createCampaignSlackChannel(args.campaign_id),
}
import {
  Card, EmptyState, Button, Pill, SeverityBadge,
} from '../shared/ui.jsx'
import { tryRenderRichBlock } from '../copilot/RichBlockRenderer.jsx'

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
  // Mirror CopilotPanel: passthrough `pre` so the `code` handler owns the
  // block wrapper and can swap fenced JSON for a rich block (stat_cards,
  // finding_list, charts, …) instead of dumping raw JSON.
  pre: ({ children }) => <>{children}</>,
  code: ({ className, children }) => {
    const match = /language-(\w+)/.exec(className || '')
    const raw = String(children).replace(/\n$/, '')
    const isBlock = !!match || raw.includes('\n')
    if (!isBlock) {
      return <code style={{ background: 'var(--bg-secondary)', padding: '1px 5px', borderRadius: 3, fontSize: 12, fontFamily: 'monospace', color: 'var(--text-primary)' }}>{children}</code>
    }
    const lang = match ? match[1] : ''
    const rich = tryRenderRichBlock(lang, raw)
    if (rich) return rich
    return (
      <pre style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 6, padding: 8, overflowX: 'auto', fontSize: 12, fontFamily: 'monospace', margin: '6px 0', color: 'var(--text-primary)' }}>
        <code>{children}</code>
      </pre>
    )
  },
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
  // For apply_inline ops with confirm_text: stage the confirmation
  // inline rather than popping a modal (modals fight the feed's
  // compact, scannable layout).
  const [confirming, setConfirming] = useState(false)
  const [done, setDone] = useState(false)

  const handleApprove = async () => {
    if (!action.approval_id) return
    setBusy(true); setError(null)
    try {
      await decideAgentApproval(action.approval_id, 'approved')
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
      await decideAgentApproval(action.approval_id, 'rejected', t('feed.rejectedFromFeed'))
      await recordFeedEntryDecision(entry.id, 'dismissed')
      onActed?.(entry.id, 'dismissed')
    } catch (e) {
      setError(e.message || t('feed.actionFailed'))
    } finally { setBusy(false) }
  }

  const handleApplyInline = async () => {
    const handler = APPLY_INLINE_OPS[action.op]
    if (!handler) return
    setBusy(true); setError(null)
    try {
      await handler(action)
      // Mirror the approve flow: an apply that mutates state should
      // close the entry as "acted" so it leaves the open queue.
      await recordFeedEntryDecision(entry.id, 'acted')
      setDone(true)
      onActed?.(entry.id, 'acted')
    } catch (e) {
      setError(e.message || t('feed.actionFailed'))
    } finally {
      setBusy(false)
      setConfirming(false)
    }
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

  if (action.kind === 'apply_inline') {
    const handler = APPLY_INLINE_OPS[action.op]
    if (!handler) {
      return <Pill label={action.label || t('feed.unsupportedOp')} color="var(--text-muted)" />
    }
    if (done) {
      return <Pill label={action.success_label || t('feed.applied')} color="var(--success, #16a34a)" />
    }
    if (action.confirm_text && confirming) {
      return (
        <div style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}>
          <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{action.confirm_text}</span>
          <Button onClick={handleApplyInline} variant="primary" size="sm" disabled={busy}>
            <Check size={13} />{t('feed.confirm')}
          </Button>
          <Button onClick={() => setConfirming(false)} variant="ghost" size="sm" disabled={busy}>
            {t('feed.cancel')}
          </Button>
          {error && <span style={{ color: 'var(--danger)', fontSize: 11 }}>{error}</span>}
        </div>
      )
    }
    return (
      <div style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}>
        <Button
          onClick={action.confirm_text ? () => setConfirming(true) : handleApplyInline}
          variant="primary" size="sm" disabled={busy}
        >
          <Wand2 size={13} />
          {action.label || t('feed.apply')}
        </Button>
        {error && <span style={{ color: 'var(--danger)', fontSize: 11 }}>{error}</span>}
      </div>
    )
  }

  if (action.kind === 'navigate' && action.href) {
    const isExternal = /^https?:\/\//i.test(action.href)
    const isIntegrate = action.intent === 'integrate'
    const Icon = isIntegrate ? Plug : ExternalLink
    const label = action.label || (isIntegrate ? t('feed.connect') : t('feed.open'))
    const linkStyle = {
      display: 'inline-flex', alignItems: 'center', gap: 6,
      padding: '5px 10px', borderRadius: 6,
      border: `1px solid ${isIntegrate ? 'var(--accent)' : 'var(--border)'}`,
      background: isIntegrate ? 'var(--accent)15' : 'transparent',
      color: isIntegrate ? 'var(--accent)' : 'var(--text-secondary)',
      fontSize: 12, fontWeight: 600, textDecoration: 'none',
    }
    if (isExternal) {
      return (
        <a href={action.href} target="_blank" rel="noopener noreferrer" style={linkStyle}>
          <Icon size={13} />
          {label}
        </a>
      )
    }
    return (
      <Link to={action.href} style={linkStyle}>
        <Icon size={13} />
        {label}
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

// Build the suggested starter prompts shown when the thread is empty.
// When the feed has recent high/critical entries, replace one generic
// suggestion with a contextual one that references the entry by its
// feed id — the copilot's chat-context block resolves "#N" to a real
// entry, so this teaches the user the reference syntax while showing
// an answer they actually want.
function buildChatSuggestions(entries, t) {
  const base = [
    t('feed.chat.suggestions.summarize'),
    t('feed.chat.suggestions.lastScan'),
    t('feed.chat.suggestions.draftCampaign'),
  ]
  const topRisk = (entries || []).find(e =>
    e.status === 'open' && (e.severity === 'critical' || e.severity === 'high')
  )
  if (topRisk) {
    return [
      t('feed.chat.suggestions.explainEntry', { id: topRisk.id }),
      base[0],
      t('feed.chat.suggestions.draftRemediation'),
    ]
  }
  return base
}

// Three-dot bouncing indicator shown while the assistant is generating.
function ThinkingDots() {
  return (
    <div
      aria-label="Thinking"
      style={{
        display: 'inline-flex', alignItems: 'center', gap: 4,
        padding: '10px 14px', borderRadius: 14,
        background: 'var(--bg-card)', border: '1px solid var(--border)',
      }}
    >
      {[0, 1, 2].map(i => (
        <span
          key={i}
          style={{
            width: 6, height: 6, borderRadius: 3,
            background: 'var(--text-muted)',
            animation: `feedchat-bounce 1.2s ${i * 0.15}s infinite ease-in-out`,
          }}
        />
      ))}
    </div>
  )
}

function FeedChat({ contextEntryCount, entries }) {
  const { t } = useTranslation()
  const [messages, setMessages] = useState([])  // {role, content, error?}
  const [streamText, setStreamText] = useState('')
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [focused, setFocused] = useState(false)
  const convIdRef = useRef(null)
  const threadRef = useRef(null)
  const inputRef = useRef(null)

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

  const submit = useCallback(async (override) => {
    const text = (typeof override === 'string' ? override : input).trim()
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
    inputRef.current?.focus()
  }

  const showThread = messages.length > 0 || busy
  const canSend = input.trim() && !busy

  return (
    <Card style={{ padding: 0, marginBottom: 16, overflow: 'hidden' }}>
      <style>{`
        @keyframes feedchat-bounce {
          0%, 80%, 100% { transform: translateY(0); opacity: 0.4 }
          40% { transform: translateY(-4px); opacity: 1 }
        }
        .feedchat-suggest {
          padding: 6px 12px; border-radius: 999px;
          background: var(--bg-card); border: 1px solid var(--border);
          color: var(--text-secondary); font-size: 12px; font-weight: 500;
          cursor: pointer; transition: all 0.15s;
          display: inline-flex; align-items: center; gap: 6px;
        }
        .feedchat-suggest:hover {
          border-color: var(--accent); color: var(--accent);
          background: var(--accent)10;
        }
        .feedchat-clear {
          display: inline-flex; align-items: center; gap: 4px;
          background: transparent; border: none; cursor: pointer;
          color: var(--text-muted); font-size: 11px; font-weight: 500;
          padding: 4px 8px; border-radius: 5px; transition: all 0.15s;
        }
        .feedchat-clear:hover { color: var(--text-primary); background: var(--bg-hover) }
        .feedchat-clear:disabled { opacity: 0.5; cursor: default }
      `}</style>

      {/* Header strip */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        gap: 12, padding: '12px 16px',
        background: 'linear-gradient(180deg, var(--bg-secondary) 0%, var(--bg-card) 100%)',
        borderBottom: showThread ? '1px solid var(--border)' : 'none',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0 }}>
          <div style={{
            width: 28, height: 28, borderRadius: 14, flexShrink: 0,
            background: 'var(--accent)15',
            display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <Sparkles size={14} color="var(--accent)" />
          </div>
          <div style={{ minWidth: 0 }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', lineHeight: 1.2 }}>
              {t('feed.chat.title')}
            </div>
            <div style={{
              fontSize: 11, color: 'var(--text-muted)', marginTop: 2,
              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
            }}>
              {t('feed.chat.subtitle')}
            </div>
          </div>
        </div>
        {messages.length > 0 && (
          <button onClick={clear} disabled={busy} className="feedchat-clear" title={t('feed.chat.clear')}>
            <Trash2 size={11} />
            {t('feed.chat.clear')}
          </button>
        )}
      </div>

      {/* Thread */}
      {showThread && (
        <div
          ref={threadRef}
          style={{
            maxHeight: 380, overflowY: 'auto',
            padding: '16px 16px 8px',
            display: 'flex', flexDirection: 'column', gap: 12,
            background: 'var(--bg-secondary)',
          }}
        >
          {messages.map((m, i) => (
            m.role === 'user' ? (
              <div
                key={i}
                style={{
                  alignSelf: 'flex-end', maxWidth: '78%',
                  padding: '9px 13px',
                  borderRadius: '14px 14px 4px 14px',
                  background: 'var(--accent)',
                  color: '#fff',
                  fontSize: 13, lineHeight: 1.5,
                  whiteSpace: 'pre-wrap',
                  boxShadow: '0 1px 2px rgba(0,0,0,0.06)',
                }}
              >
                {m.content}
              </div>
            ) : (
              <div key={i} style={{
                alignSelf: 'flex-start', maxWidth: '88%',
                display: 'flex', gap: 8, alignItems: 'flex-start',
              }}>
                <div style={{
                  width: 24, height: 24, borderRadius: 12, flexShrink: 0,
                  background: 'var(--bg-card)', border: '1px solid var(--border)',
                  display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                  marginTop: 2,
                }}>
                  <Bot size={13} color="var(--accent)" />
                </div>
                <div style={{
                  padding: '8px 13px',
                  borderRadius: '14px 14px 14px 4px',
                  background: 'var(--bg-card)',
                  color: 'var(--text-primary)',
                  border: `1px solid ${m.error ? 'var(--danger)40' : 'var(--border)'}`,
                  fontSize: 13, lineHeight: 1.5,
                  flex: 1, minWidth: 0,
                }}>
                  {m.error && (
                    <div style={{ color: 'var(--danger)', fontSize: 11, fontWeight: 600, marginBottom: 4 }}>
                      {t('feed.chat.failed')}
                    </div>
                  )}
                  <ReactMarkdown remarkPlugins={[remarkGfm]} components={mdComponents}>
                    {m.content || ''}
                  </ReactMarkdown>
                </div>
              </div>
            )
          ))}
          {busy && (streamText ? (
            <div style={{
              alignSelf: 'flex-start', maxWidth: '88%',
              display: 'flex', gap: 8, alignItems: 'flex-start',
            }}>
              <div style={{
                width: 24, height: 24, borderRadius: 12, flexShrink: 0,
                background: 'var(--bg-card)', border: '1px solid var(--border)',
                display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                marginTop: 2,
              }}>
                <Bot size={13} color="var(--accent)" />
              </div>
              <div style={{
                padding: '8px 13px',
                borderRadius: '14px 14px 14px 4px',
                background: 'var(--bg-card)', color: 'var(--text-primary)',
                border: '1px solid var(--border)',
                fontSize: 13, lineHeight: 1.5, flex: 1, minWidth: 0,
              }}>
                <ReactMarkdown remarkPlugins={[remarkGfm]} components={mdComponents}>
                  {streamText}
                </ReactMarkdown>
              </div>
            </div>
          ) : (
            <div style={{ alignSelf: 'flex-start', display: 'flex', gap: 8, alignItems: 'flex-start' }}>
              <div style={{
                width: 24, height: 24, borderRadius: 12, flexShrink: 0,
                background: 'var(--bg-card)', border: '1px solid var(--border)',
                display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                marginTop: 2,
              }}>
                <Bot size={13} color="var(--accent)" />
              </div>
              <ThinkingDots />
            </div>
          ))}
        </div>
      )}

      {/* Suggested prompts — only on the empty state */}
      {!showThread && (
        <div style={{
          padding: '4px 16px 0',
          display: 'flex', flexWrap: 'wrap', gap: 6,
        }}>
          {buildChatSuggestions(entries, t).map((s) => (
            <button
              key={s}
              type="button"
              className="feedchat-suggest"
              onClick={() => submit(s)}
              disabled={busy}
            >
              <Sparkles size={11} />
              {s}
            </button>
          ))}
        </div>
      )}

      {/* Composer */}
      <div style={{ padding: 12 }}>
        <div style={{
          display: 'flex', gap: 8, alignItems: 'center',
          padding: '4px 4px 4px 14px',
          background: 'var(--bg-card)',
          border: `1px solid ${focused ? 'var(--accent)' : 'var(--border)'}`,
          borderRadius: 999,
          transition: 'border-color 0.15s, box-shadow 0.15s',
          boxShadow: focused ? '0 0 0 3px var(--accent)15' : 'none',
        }}>
          <input
            ref={inputRef}
            type="text"
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={onKeyDown}
            onFocus={() => setFocused(true)}
            onBlur={() => setFocused(false)}
            placeholder={t('feed.chat.placeholder')}
            disabled={busy}
            style={{
              flex: 1, height: 34,
              padding: 0,
              border: 'none', background: 'transparent',
              color: 'var(--text-primary)', fontSize: 13, fontFamily: 'inherit',
              outline: 'none', minWidth: 0,
            }}
          />
          <button
            type="button"
            onClick={() => submit()}
            disabled={!canSend}
            aria-label={t('feed.chat.send')}
            title={t('feed.chat.send')}
            style={{
              width: 32, height: 32, borderRadius: 16, border: 'none',
              background: canSend ? 'var(--accent)' : 'var(--bg-secondary)',
              color: canSend ? '#fff' : 'var(--text-muted)',
              cursor: canSend ? 'pointer' : 'default',
              display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
              flexShrink: 0, transition: 'background 0.15s, color 0.15s',
            }}
          >
            <Send size={14} />
          </button>
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
  const [hasLoadedOnce, setHasLoadedOnce] = useState(false)
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
      setHasLoadedOnce(true)
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

  const empty = hasLoadedOnce && entries.length === 0

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

      <FeedChat contextEntryCount={5} entries={entries} />

      {error && (
        <div style={{
          background: 'var(--danger)15', color: 'var(--danger)',
          border: '1px solid var(--danger)40', borderRadius: 8,
          padding: '10px 14px', marginBottom: 12, fontSize: 13,
        }}>
          {error}
        </div>
      )}

      {loading && !hasLoadedOnce && entries.length === 0 && !error && (
        <div style={{ padding: '64px 0', textAlign: 'center', color: 'var(--text-muted)' }}>
          {t('feed.loading')}
        </div>
      )}

      {empty && !error && (
        <EmptyState
          icon={Inbox}
          title={t('feed.empty.title')}
          sub={t('feed.empty.body')}
        >
          <div style={{
            marginTop: 8, maxWidth: 480, width: '100%',
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border)',
            borderRadius: 8, padding: '14px 16px',
            textAlign: 'left',
          }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 8 }}>
              {t('feed.empty.whatToExpect')}
            </div>
            <ul style={{ margin: 0, paddingLeft: 18, color: 'var(--text-secondary)', fontSize: 12, lineHeight: 1.6 }}>
              <li>{t('feed.empty.bullet1')}</li>
              <li>{t('feed.empty.bullet2')}</li>
              <li>{t('feed.empty.bullet3')}</li>
            </ul>
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', justifyContent: 'center', marginTop: 4 }}>
            <Link
              to="/settings"
              style={{
                display: 'inline-flex', alignItems: 'center', gap: 6,
                padding: '7px 14px', borderRadius: 6,
                border: '1px solid var(--accent)',
                background: 'var(--accent)',
                color: '#fff', fontSize: 12, fontWeight: 600, textDecoration: 'none',
              }}
            >
              <Plug size={13} />
              {t('feed.empty.cta.integrate')}
            </Link>
            <Link
              to="/agents"
              style={{
                display: 'inline-flex', alignItems: 'center', gap: 6,
                padding: '7px 14px', borderRadius: 6,
                border: '1px solid var(--border)',
                background: 'transparent',
                color: 'var(--text-secondary)', fontSize: 12, fontWeight: 600, textDecoration: 'none',
              }}
            >
              <Bot size={13} />
              {t('feed.empty.cta.agents')}
            </Link>
          </div>
        </EmptyState>
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
