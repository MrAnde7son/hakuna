import React, { useState, useEffect, useRef, useCallback } from 'react'
import ReactMarkdown from 'react-markdown'
import { useTranslation } from 'react-i18next'
import {
  X, Send, Plus, Trash2, MessageSquare, Bot, Loader2,
  ChevronDown, ChevronRight, Wrench, ShieldAlert, Zap,
  Clock, Globe, Bug, Target, Briefcase, Clipboard,
} from 'lucide-react'
import {
  getCopilotConversations,
  createCopilotConversation,
  getCopilotConversation,
  deleteCopilotConversation,
  getCopilotSuggestedPrompts,
  decideAgentApproval,
  getStoredToken,
  getOrgContext,
} from '../../api.js'

const API_ORIGIN = import.meta.env.VITE_API_URL || ''

const ICON_MAP = {
  'shield-alert': ShieldAlert,
  'alarm': Clock,
  'zap': Zap,
  'clipboard': Clipboard,
  'globe': Globe,
  'bug': Bug,
  'target': Target,
  'briefcase': Briefcase,
}

// ── Context-aware suggested prompts by page ────────────────────────
const CONTEXTUAL_PROMPTS = {
  '/findings': [
    { text: 'Show me the most critical unresolved findings', icon: 'shield-alert' },
    { text: 'Which findings have known exploits in the wild?', icon: 'bug' },
    { text: 'Find findings that are past their SLA deadline', icon: 'alarm' },
    { text: 'Group findings by solution and show quick wins', icon: 'zap' },
  ],
  '/findings/': [
    { text: 'Explain this finding and its impact', icon: 'shield-alert' },
    { text: 'What is the recommended remediation for this?', icon: 'target' },
    { text: 'Are there other assets affected by this same vulnerability?', icon: 'globe' },
    { text: 'Create a campaign to fix this finding across all affected assets', icon: 'zap' },
  ],
  '/assets': [
    { text: 'Which assets have the most critical vulnerabilities?', icon: 'shield-alert' },
    { text: 'Find internet-facing assets with open critical findings', icon: 'globe' },
    { text: 'Show assets that haven\'t been scanned in over 30 days', icon: 'alarm' },
    { text: 'List assets with the highest risk scores', icon: 'target' },
  ],
  '/assets/': [
    { text: 'Summarize the risk posture of this asset', icon: 'shield-alert' },
    { text: 'What are the open findings on this asset?', icon: 'bug' },
    { text: 'Has this asset been scanned recently?', icon: 'alarm' },
    { text: 'Create a remediation campaign for this asset\'s critical findings', icon: 'target' },
  ],
  '/campaigns': [
    { text: 'Which campaigns are falling behind schedule?', icon: 'alarm' },
    { text: 'Create a new campaign for all critical unresolved findings', icon: 'target' },
    { text: 'Show campaign completion rates across teams', icon: 'briefcase' },
    { text: 'Find findings not covered by any campaign', icon: 'shield-alert' },
  ],
  '/campaigns/': [
    { text: 'How is this campaign progressing?', icon: 'clipboard' },
    { text: 'Which findings in this campaign are still open?', icon: 'bug' },
    { text: 'Notify the team about overdue items in this campaign', icon: 'alarm' },
    { text: 'Suggest additional findings that should be in this campaign', icon: 'zap' },
  ],
  '/': [
    { text: 'Give me an executive summary of our security posture', icon: 'briefcase' },
    { text: 'What changed since the last scan?', icon: 'clipboard' },
    { text: 'Find the top 10 risks I should focus on today', icon: 'shield-alert' },
    { text: 'Check for SLA breaches and escalate overdue findings', icon: 'alarm' },
  ],
  '/inventory': [
    { text: 'Which software has known CVEs?', icon: 'bug' },
    { text: 'Show end-of-life software still running in the environment', icon: 'alarm' },
    { text: 'List the most common software across all assets', icon: 'clipboard' },
    { text: 'Find assets running outdated versions of critical software', icon: 'shield-alert' },
  ],
  '/threat-intel': [
    { text: 'Are any of my findings linked to active threat campaigns?', icon: 'shield-alert' },
    { text: 'Show findings that match CISA KEV entries', icon: 'bug' },
    { text: 'Map my top risks to MITRE ATT&CK techniques', icon: 'target' },
    { text: 'Which exploitable findings should I prioritize?', icon: 'zap' },
  ],
  '/aggregated-solutions': [
    { text: 'Which solution would fix the most findings?', icon: 'zap' },
    { text: 'Create a campaign from the top solution group', icon: 'target' },
    { text: 'Show solutions grouped by effort vs impact', icon: 'briefcase' },
    { text: 'How many findings would be resolved by patching the top 5 solutions?', icon: 'clipboard' },
  ],
  '/tags': [
    { text: 'Show tag distribution across assets', icon: 'clipboard' },
    { text: 'Which tags have the most critical findings?', icon: 'shield-alert' },
    { text: 'Suggest auto-tag rules based on current asset patterns', icon: 'zap' },
  ],
  '/settings': [
    { text: 'Analyze my latest scan upload and summarize what changed', icon: 'clipboard' },
    { text: 'How many scans have been uploaded this month?', icon: 'briefcase' },
  ],
}

// Get the page label for context injection
const PAGE_LABELS = {
  '/': 'Dashboard / Reports',
  '/findings': 'Findings list',
  '/assets': 'Asset Inventory',
  '/campaigns': 'Campaigns',
  '/inventory': 'Software Inventory',
  '/threat-intel': 'Threat Intelligence',
  '/aggregated-solutions': 'Aggregated Solutions',
  '/tags': 'Tag Manager',
  '/agents': 'AI Agents',
  '/settings': 'Settings',
  '/profile': 'User Profile',
  '/docs': 'Documentation',
}

function getContextualPrompts(path) {
  if (!path) return null
  // Exact match first (e.g., /findings, /assets, /campaigns)
  if (CONTEXTUAL_PROMPTS[path]) return CONTEXTUAL_PROMPTS[path]
  // Detail page match (e.g., /findings/123 → /findings/)
  for (const key of Object.keys(CONTEXTUAL_PROMPTS)) {
    if (key.endsWith('/') && path.startsWith(key)) return CONTEXTUAL_PROMPTS[key]
  }
  return null
}

function getPageLabel(path) {
  if (!path) return null
  if (PAGE_LABELS[path]) return PAGE_LABELS[path]
  // Detail pages
  if (path.startsWith('/findings/')) return 'Finding detail'
  if (path.startsWith('/assets/')) return 'Asset detail'
  if (path.startsWith('/campaigns/')) return 'Campaign detail'
  if (path.startsWith('/workflows/')) return 'Workflow builder'
  if (path.startsWith('/reports/')) return 'Report detail'
  if (path.startsWith('/threat-intel')) return 'Threat Intelligence'
  return null
}

// ── Markdown components (matches AgentBuilder pattern) ──────────────

const mdComponents = {
  h1: ({ children }) => <h1 style={{ fontSize: 16, fontWeight: 700, margin: '12px 0 6px', borderBottom: '1px solid var(--border)', paddingBottom: 4 }}>{children}</h1>,
  h2: ({ children }) => <h2 style={{ fontSize: 14, fontWeight: 700, margin: '10px 0 4px', color: 'var(--accent)' }}>{children}</h2>,
  h3: ({ children }) => <h3 style={{ fontSize: 13, fontWeight: 600, margin: '8px 0 3px' }}>{children}</h3>,
  p: ({ children }) => <p style={{ margin: '4px 0' }}>{children}</p>,
  ul: ({ children }) => <ul style={{ margin: '3px 0', paddingLeft: 18 }}>{children}</ul>,
  ol: ({ children }) => <ol style={{ margin: '3px 0', paddingLeft: 18 }}>{children}</ol>,
  li: ({ children }) => <li style={{ margin: '1px 0' }}>{children}</li>,
  strong: ({ children }) => <strong style={{ fontWeight: 700, color: 'var(--text)' }}>{children}</strong>,
  code: ({ inline, children }) => inline
    ? <code style={{ background: 'var(--bg-secondary)', padding: '1px 4px', borderRadius: 3, fontSize: 11, fontFamily: 'monospace' }}>{children}</code>
    : <pre style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 6, padding: 8, overflowX: 'auto', fontSize: 11, fontFamily: 'monospace', margin: '6px 0' }}><code>{children}</code></pre>,
  table: ({ children }) => <div style={{ overflowX: 'auto' }}><table style={{ borderCollapse: 'collapse', width: '100%', margin: '6px 0', fontSize: 11 }}>{children}</table></div>,
  th: ({ children }) => <th style={{ border: '1px solid var(--border)', padding: '4px 8px', background: 'var(--bg-secondary)', fontWeight: 600, textAlign: 'left' }}>{children}</th>,
  td: ({ children }) => <td style={{ border: '1px solid var(--border)', padding: '3px 8px' }}>{children}</td>,
  hr: () => <hr style={{ border: 'none', borderTop: '1px solid var(--border)', margin: '8px 0' }} />,
  blockquote: ({ children }) => <blockquote style={{ borderLeft: '3px solid var(--accent)', paddingLeft: 10, margin: '6px 0', color: 'var(--text-muted)', fontStyle: 'italic' }}>{children}</blockquote>,
}


// ── Tool call display ───────────────────────────────────────────────

function ToolCallEvent({ event }) {
  const [expanded, setExpanded] = useState(false)
  const hasResult = !!event.result
  const Icon = expanded ? ChevronDown : ChevronRight
  return (
    <div style={{
      margin: '4px 0', padding: '6px 10px', borderRadius: 6,
      background: 'var(--bg-secondary)', border: '1px solid var(--border)',
      fontSize: 11,
    }}>
      <div
        onClick={() => setExpanded(!expanded)}
        style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', color: 'var(--text-muted)' }}
      >
        {hasResult ? (
          <Wrench size={12} style={{ color: '#22c55e' }} />
        ) : (
          <Loader2 size={12} style={{ animation: 'spin 1s linear infinite', color: 'var(--accent)' }} />
        )}
        <span style={{ fontFamily: 'monospace', fontWeight: 600 }}>{event.name}</span>
        {!hasResult && <span style={{ color: 'var(--accent)', fontSize: 10 }}>running...</span>}
        <Icon size={12} style={{ marginLeft: 'auto' }} />
      </div>
      {expanded && event.input && (
        <pre style={{
          marginTop: 6, padding: 6, borderRadius: 4,
          background: '#0f172a', color: '#94a3b8',
          fontSize: 10, fontFamily: 'monospace', overflowX: 'auto',
          maxHeight: 120,
        }}>
          {JSON.stringify(event.input, null, 2)}
        </pre>
      )}
      {expanded && event.result && (
        <pre style={{
          marginTop: 4, padding: 6, borderRadius: 4,
          background: '#0f172a', color: '#6ee7b7',
          fontSize: 10, fontFamily: 'monospace', overflowX: 'auto',
          maxHeight: 150,
        }}>
          {typeof event.result === 'string' ? event.result.slice(0, 1500) : JSON.stringify(event.result, null, 2).slice(0, 1500)}
        </pre>
      )}
    </div>
  )
}


// ── Approval inline ─────────────────────────────────────────────────

function ApprovalEvent({ event, onDecide }) {
  const [deciding, setDeciding] = useState(false)
  const [decided, setDecided] = useState(null)

  const handleDecide = async (decision) => {
    setDeciding(true)
    try {
      await decideAgentApproval(event.approval_id, decision)
      setDecided(decision)
    } catch (e) {
      console.error('Approval failed:', e)
    } finally {
      setDeciding(false)
    }
  }

  return (
    <div style={{
      margin: '6px 0', padding: '10px 12px', borderRadius: 8,
      background: decided ? 'var(--bg-secondary)' : 'rgba(251, 191, 36, 0.1)',
      border: `1px solid ${decided ? 'var(--border)' : 'rgba(251, 191, 36, 0.3)'}`,
      fontSize: 12,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
        <ShieldAlert size={14} style={{ color: '#f59e0b' }} />
        <span style={{ fontWeight: 600 }}>Approval required: </span>
        <code style={{ fontFamily: 'monospace', fontSize: 11, background: 'var(--bg-secondary)', padding: '1px 4px', borderRadius: 3 }}>{event.tool_name}</code>
      </div>
      {decided ? (
        <div style={{ color: decided === 'approved' ? '#22c55e' : '#ef4444', fontWeight: 500, fontSize: 11 }}>
          {decided === 'approved' ? 'Approved' : 'Rejected'}
        </div>
      ) : (
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            onClick={() => handleDecide('approved')}
            disabled={deciding}
            style={{
              padding: '4px 14px', borderRadius: 5, border: 'none', cursor: 'pointer',
              background: '#22c55e', color: '#fff', fontSize: 11, fontWeight: 600,
              opacity: deciding ? 0.6 : 1,
            }}
          >
            Approve
          </button>
          <button
            onClick={() => handleDecide('rejected')}
            disabled={deciding}
            style={{
              padding: '4px 14px', borderRadius: 5, border: '1px solid var(--border)', cursor: 'pointer',
              background: 'var(--bg)', color: 'var(--text)', fontSize: 11, fontWeight: 500,
              opacity: deciding ? 0.6 : 1,
            }}
          >
            Reject
          </button>
        </div>
      )}
    </div>
  )
}


// ── Thinking indicator ──────────────────────────────────────────────

function ThinkingIndicator({ step }) {
  const labels = [
    'Analyzing your request...',
    'Querying data...',
    'Processing results...',
    'Analyzing findings...',
    'Preparing response...',
  ]
  const label = step < labels.length ? labels[step] : `Working (step ${step + 1})...`
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px',
      color: 'var(--text-muted)', fontSize: 12, marginTop: 4,
    }}>
      <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} />
      <span>{label}</span>
      <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
    </div>
  )
}


// ── Main Panel ──────────────────────────────────────────────────────

export default function CopilotPanel({ open, onClose, currentPath }) {
  const { t } = useTranslation()
  const [conversations, setConversations] = useState([])
  const [activeConv, setActiveConv] = useState(null)
  const [messages, setMessages] = useState([])
  const [input, setInput] = useState('')
  const [streaming, setStreaming] = useState(false)
  const [streamEvents, setStreamEvents] = useState([])
  const [streamText, setStreamText] = useState('')
  const [suggestedPrompts, setSuggestedPrompts] = useState([])
  const [showHistory, setShowHistory] = useState(false)
  const [thinkingStep, setThinkingStep] = useState(-1)
  const messagesEndRef = useRef(null)
  const textareaRef = useRef(null)
  const abortRef = useRef(null)

  // Load conversations and suggested prompts on open
  useEffect(() => {
    if (open) {
      getCopilotConversations().then(setConversations).catch(() => {})
      getCopilotSuggestedPrompts().then(setSuggestedPrompts).catch(() => {})
    }
  }, [open])

  // Auto-scroll to bottom
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, streamText, streamEvents])

  // Focus textarea when panel opens
  useEffect(() => {
    if (open && textareaRef.current) {
      setTimeout(() => textareaRef.current?.focus(), 300)
    }
  }, [open, activeConv])

  const startNewConversation = useCallback(async () => {
    try {
      const conv = await createCopilotConversation()
      setActiveConv(conv)
      setMessages([])
      setStreamEvents([])
      setStreamText('')
      setShowHistory(false)
      setConversations(prev => [conv, ...prev])
    } catch (e) {
      console.error('Failed to create conversation:', e)
    }
  }, [])

  const loadConversation = useCallback(async (conv) => {
    try {
      const full = await getCopilotConversation(conv.id)
      setActiveConv(full)
      setMessages(full.messages || [])
      setStreamEvents([])
      setStreamText('')
      setShowHistory(false)
    } catch (e) {
      console.error('Failed to load conversation:', e)
    }
  }, [])

  const deleteConv = useCallback(async (convId, e) => {
    e.stopPropagation()
    try {
      await deleteCopilotConversation(convId)
      setConversations(prev => prev.filter(c => c.id !== convId))
      if (activeConv?.id === convId) {
        setActiveConv(null)
        setMessages([])
      }
    } catch (err) {
      console.error('Failed to delete conversation:', err)
    }
  }, [activeConv])

  const sendMessage = useCallback(async (text) => {
    const msg = (text || input).trim()
    if (!msg || streaming) return

    // Auto-create conversation if none active
    let conv = activeConv
    if (!conv) {
      try {
        conv = await createCopilotConversation()
        setActiveConv(conv)
        setConversations(prev => [conv, ...prev])
      } catch (e) {
        console.error('Failed to create conversation:', e)
        return
      }
    }

    setInput('')
    setStreaming(true)
    setStreamText('')
    setStreamEvents([])
    setThinkingStep(0)

    // Add user message to local state (show original text in chat bubble)
    const userMsg = { role: 'user', content: msg, timestamp: new Date().toISOString() }
    setMessages(prev => [...prev, userMsg])

    // Build context-enriched message for the backend
    const pageLabel = getPageLabel(currentPath)
    const contextPrefix = pageLabel ? `[User is currently viewing: ${pageLabel}${currentPath?.match(/\/.+\/(.+)/) ? ` (ID: ${currentPath.match(/\/.+\/(.+)/)[1]})` : ''}]\n\n` : ''
    const enrichedMsg = contextPrefix + msg

    try {
      const token = getStoredToken()
      const orgContext = getOrgContext()
      const headers = { 'Content-Type': 'application/json' }
      if (token) headers['Authorization'] = `Bearer ${token}`
      if (orgContext) headers['X-Org-Context'] = orgContext

      const abortController = new AbortController()
      abortRef.current = abortController

      const resp = await fetch(`${API_ORIGIN}/api/copilot/conversations/${conv.id}/message`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ message: enrichedMsg }),
        signal: abortController.signal,
      })

      if (!resp.ok || !resp.body) {
        let errMsg = `Request failed: ${resp.status}`
        try {
          const errBody = await resp.json()
          errMsg = errBody.detail || errBody.message || errMsg
        } catch {}
        throw new Error(errMsg)
      }

      const reader = resp.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''
      let textAccum = ''
      const events = []

      while (true) {
        const { done, value } = await reader.read()
        if (done) break

        buffer += decoder.decode(value, { stream: true })
        const lines = buffer.split('\n')
        buffer = lines.pop()

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue
          const payload = line.slice(6).trim()
          if (payload === '[DONE]') continue

          try {
            const event = JSON.parse(payload)
            events.push(event)
            setStreamEvents([...events])

            if (event.type === 'text') {
              textAccum += event.text
              setStreamText(textAccum)
              setThinkingStep(-1)
            } else if (event.type === 'thinking') {
              setThinkingStep(event.step)
            } else if (event.type === 'tool_call') {
              // Show the tool call with spinner, hide thinking
              setThinkingStep(-1)
            } else if (event.type === 'tool_result') {
              // Tool finished — update events so spinner becomes checkmark
              setStreamEvents([...events])
            } else if (event.type === 'done') {
              setStreamText('')
              setMessages(prev => [...prev, {
                role: 'assistant',
                content: event.output || textAccum,
                timestamp: new Date().toISOString(),
              }])
            } else if (event.type === 'error') {
              setMessages(prev => [...prev, {
                role: 'error',
                content: event.error,
                timestamp: new Date().toISOString(),
              }])
            }
          } catch {}
        }
      }

      // If stream ended without done event, use accumulated text
      if (textAccum && !events.some(e => e.type === 'done')) {
        setStreamText('')
        setMessages(prev => [...prev, {
          role: 'assistant',
          content: textAccum,
          timestamp: new Date().toISOString(),
        }])
      }

      // Update conversation title in sidebar
      if (conv.title === 'New conversation') {
        setConversations(prev => prev.map(c =>
          c.id === conv.id ? { ...c, title: msg.slice(0, 80) } : c
        ))
      }
    } catch (e) {
      if (e.name !== 'AbortError') {
        setMessages(prev => [...prev, {
          role: 'error',
          content: e.message,
          timestamp: new Date().toISOString(),
        }])
      }
    } finally {
      setStreaming(false)
      setThinkingStep(-1)
      abortRef.current = null
    }
  }, [input, streaming, activeConv])

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      sendMessage()
    }
  }

  const handleStop = () => {
    abortRef.current?.abort()
    setStreaming(false)
    setThinkingStep(-1)
  }

  if (!open) return null

  return (
    <>
      {/* Backdrop */}
      <div
        onClick={onClose}
        style={{
          position: 'fixed', inset: 0, zIndex: 199,
          background: 'rgba(0,0,0,0.3)',
          opacity: open ? 1 : 0,
          transition: 'opacity 0.2s ease',
        }}
      />

      {/* Panel */}
      <div style={{
        position: 'fixed', top: 0, right: 0, bottom: 0,
        width: Math.min(480, window.innerWidth - 20),
        zIndex: 200,
        background: 'var(--bg)',
        borderLeft: '1px solid var(--border)',
        display: 'flex', flexDirection: 'column',
        boxShadow: '-4px 0 24px rgba(0,0,0,0.15)',
        transform: open ? 'translateX(0)' : 'translateX(100%)',
        transition: 'transform 0.25s ease',
      }}>

        {/* Header */}
        <div style={{
          padding: '12px 16px', borderBottom: '1px solid var(--border)',
          display: 'flex', alignItems: 'center', gap: 10,
          background: 'var(--bg-secondary)',
        }}>
          <Bot size={20} style={{ color: 'var(--accent)' }} />
          <div style={{ flex: 1, display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontWeight: 700, fontSize: 15 }}>Security Copilot</span>
            <span style={{
              fontSize: 9, color: 'var(--accent)', fontWeight: 700, letterSpacing: 0.5,
              background: 'rgba(var(--accent-rgb, 99,102,241), 0.1)',
              padding: '2px 6px', borderRadius: 4, textTransform: 'uppercase',
            }}>Agent</span>
          </div>
          <button
            onClick={() => setShowHistory(!showHistory)}
            title="Conversation history"
            style={{
              background: 'none', border: 'none', cursor: 'pointer',
              color: 'var(--text-muted)', padding: 4, borderRadius: 4,
            }}
          >
            <MessageSquare size={16} />
          </button>
          <button
            onClick={startNewConversation}
            title="New conversation"
            style={{
              background: 'none', border: 'none', cursor: 'pointer',
              color: 'var(--text-muted)', padding: 4, borderRadius: 4,
            }}
          >
            <Plus size={16} />
          </button>
          <button
            onClick={onClose}
            style={{
              background: 'none', border: 'none', cursor: 'pointer',
              color: 'var(--text-muted)', padding: 4, borderRadius: 4,
            }}
          >
            <X size={16} />
          </button>
        </div>

        {/* Conversation history dropdown */}
        {showHistory && (
          <div style={{
            borderBottom: '1px solid var(--border)', maxHeight: 250, overflowY: 'auto',
            background: 'var(--bg-secondary)',
          }}>
            {conversations.length === 0 ? (
              <div style={{ padding: 16, color: 'var(--text-muted)', fontSize: 12, textAlign: 'center' }}>
                No conversations yet
              </div>
            ) : conversations.map(conv => (
              <div
                key={conv.id}
                onClick={() => loadConversation(conv)}
                style={{
                  padding: '8px 16px', cursor: 'pointer', fontSize: 12,
                  display: 'flex', alignItems: 'center', gap: 8,
                  background: activeConv?.id === conv.id ? 'var(--bg)' : 'transparent',
                  borderBottom: '1px solid var(--border)',
                }}
              >
                <MessageSquare size={12} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
                <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {conv.title || 'New conversation'}
                </span>
                <span style={{ color: 'var(--text-muted)', fontSize: 10, flexShrink: 0 }}>
                  {conv.message_count || 0} msgs
                </span>
                <button
                  onClick={(e) => deleteConv(conv.id, e)}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 2 }}
                >
                  <Trash2 size={12} />
                </button>
              </div>
            ))}
          </div>
        )}

        {/* Messages area */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '12px 16px' }}>
          {/* Empty state with suggested prompts */}
          {messages.length === 0 && !streaming && (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '40px 10px', gap: 20 }}>
              <div style={{
                width: 56, height: 56, borderRadius: '50%',
                background: 'var(--bg-secondary)', border: '2px solid var(--border)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                <Bot size={28} style={{ color: 'var(--accent)' }} />
              </div>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontWeight: 700, fontSize: 16, marginBottom: 6 }}>Security Copilot</div>
                <div style={{ color: 'var(--text-muted)', fontSize: 12, lineHeight: 1.5, maxWidth: 320 }}>
                  {getPageLabel(currentPath)
                    ? <>You're on <strong style={{ color: 'var(--text)' }}>{getPageLabel(currentPath)}</strong>. Ask me anything about what you see, or try a suggestion below.</>
                    : 'Your autonomous security agent. It queries your scan data, analyzes risk, creates campaigns, opens tickets, and notifies your team — all in one conversation.'
                  }
                </div>
              </div>

              {/* Capability badges */}
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', justifyContent: 'center', maxWidth: 360 }}>
                {['Discover risks', 'Triage & prioritize', 'Create campaigns', 'Open tickets', 'Notify teams'].map(cap => (
                  <span key={cap} style={{
                    padding: '3px 10px', borderRadius: 20, fontSize: 10, fontWeight: 600,
                    background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                    color: 'var(--text-muted)', letterSpacing: 0.3,
                  }}>
                    {cap}
                  </span>
                ))}
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, justifyContent: 'center', maxWidth: 380 }}>
                {(getContextualPrompts(currentPath) || suggestedPrompts).map((p, i) => {
                  const SIcon = ICON_MAP[p.icon] || ShieldAlert
                  return (
                    <button
                      key={i}
                      onClick={() => sendMessage(p.text)}
                      style={{
                        padding: '8px 12px', borderRadius: 8, fontSize: 11,
                        border: '1px solid var(--border)', background: 'var(--bg-secondary)',
                        color: 'var(--text)', cursor: 'pointer',
                        display: 'flex', alignItems: 'center', gap: 6,
                        transition: 'border-color 0.15s ease, background 0.15s ease',
                        textAlign: 'left', lineHeight: 1.3,
                      }}
                      onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent)'; e.currentTarget.style.background = 'var(--bg)' }}
                      onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.background = 'var(--bg-secondary)' }}
                    >
                      <SIcon size={13} style={{ color: 'var(--accent)', flexShrink: 0 }} />
                      {p.text}
                    </button>
                  )
                })}
              </div>
            </div>
          )}

          {/* Rendered messages */}
          {messages.map((msg, i) => (
            <div key={i} style={{ marginBottom: 12 }}>
              {msg.role === 'user' ? (
                <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                  <div style={{
                    maxWidth: '85%', padding: '8px 14px', borderRadius: '14px 14px 4px 14px',
                    background: 'var(--accent)', color: '#fff', fontSize: 13, lineHeight: 1.5,
                    whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                  }}>
                    {msg.content}
                  </div>
                </div>
              ) : msg.role === 'error' ? (
                <div style={{
                  padding: '8px 12px', borderRadius: 8,
                  background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.2)',
                  color: '#ef4444', fontSize: 12,
                }}>
                  Error: {msg.content}
                </div>
              ) : (
                <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start' }}>
                  <div style={{
                    width: 26, height: 26, borderRadius: '50%', flexShrink: 0,
                    background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    marginTop: 2,
                  }}>
                    <Bot size={14} style={{ color: 'var(--accent)' }} />
                  </div>
                  <div style={{
                    flex: 1, minWidth: 0, fontSize: 13, lineHeight: 1.6,
                    color: 'var(--text)',
                  }}>
                    <ReactMarkdown components={mdComponents}>{msg.content}</ReactMarkdown>
                  </div>
                </div>
              )}
            </div>
          ))}

          {/* Live streaming activity — interleaved tool calls, results, text, approvals */}
          {streaming && (
            <div style={{ marginBottom: 12 }}>
              {/* Tool calls and results in order */}
              {streamEvents.filter(e =>
                e.type === 'tool_call' || e.type === 'tool_result' || e.type === 'approval_required'
              ).map((event, i) => (
                event.type === 'approval_required' ? (
                  <ApprovalEvent key={`evt-${i}`} event={event} />
                ) : event.type === 'tool_call' ? (
                  <ToolCallEvent
                    key={`evt-${i}`}
                    event={{
                      ...event,
                      // Attach result if we have one for this tool
                      result: streamEvents.find(
                        e => e.type === 'tool_result' && e.name === event.name && e.step === event.step
                      )?.result,
                    }}
                  />
                ) : null
              ))}

              {/* Streaming text output */}
              {streamText && (
                <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start', marginTop: 8 }}>
                  <div style={{
                    width: 26, height: 26, borderRadius: '50%', flexShrink: 0,
                    background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    marginTop: 2,
                  }}>
                    <Bot size={14} style={{ color: 'var(--accent)' }} />
                  </div>
                  <div style={{ flex: 1, minWidth: 0, fontSize: 13, lineHeight: 1.6 }}>
                    <ReactMarkdown components={mdComponents}>{streamText}</ReactMarkdown>
                  </div>
                </div>
              )}

              {/* Thinking indicator — shown when waiting for LLM or between tool calls */}
              {thinkingStep >= 0 && (
                <ThinkingIndicator step={thinkingStep} />
              )}
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Input area */}
        <div style={{
          padding: '12px 16px', borderTop: '1px solid var(--border)',
          background: 'var(--bg-secondary)',
        }}>
          <div style={{
            display: 'flex', gap: 8, alignItems: 'flex-end',
            background: 'var(--bg)', border: '1px solid var(--border)',
            borderRadius: 12, padding: '6px 6px 6px 14px',
          }}>
            <textarea
              ref={textareaRef}
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Tell the agent what to do..."
              rows={1}
              style={{
                flex: 1, border: 'none', outline: 'none', resize: 'none',
                background: 'transparent', color: 'var(--text)',
                fontSize: 13, lineHeight: 1.5, fontFamily: 'inherit',
                maxHeight: 100, minHeight: 20,
              }}
              onInput={e => {
                e.target.style.height = '20px'
                e.target.style.height = Math.min(e.target.scrollHeight, 100) + 'px'
              }}
            />
            {streaming ? (
              <button
                onClick={handleStop}
                style={{
                  width: 32, height: 32, borderRadius: 8, border: 'none',
                  background: '#ef4444', color: '#fff', cursor: 'pointer',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  flexShrink: 0,
                }}
                title="Stop"
              >
                <X size={16} />
              </button>
            ) : (
              <button
                onClick={() => sendMessage()}
                disabled={!input.trim()}
                style={{
                  width: 32, height: 32, borderRadius: 8, border: 'none',
                  background: input.trim() ? 'var(--accent)' : 'var(--bg-secondary)',
                  color: input.trim() ? '#fff' : 'var(--text-muted)',
                  cursor: input.trim() ? 'pointer' : 'default',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  flexShrink: 0,
                  transition: 'background 0.15s ease',
                }}
                title="Send"
              >
                <Send size={15} />
              </button>
            )}
          </div>
        </div>
      </div>
    </>
  )
}
