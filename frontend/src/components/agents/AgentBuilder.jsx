/**
 * Mini Agent Builder — create, configure, and run user-defined agents.
 * Features: templates gallery, streaming output, cron schedules.
 */
import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { Card, ErrorBanner, useToast, useConfirm } from '../shared/ui.jsx'
import { useNavigate, useSearchParams } from 'react-router-dom'
import {
  Bot, Plus, Trash2, Play, ChevronDown, ChevronRight, Clock, CheckCircle,
  XCircle, Loader2, Settings2, MessageSquare, Wrench, Shield, Brain,
  Zap, Calendar, Copy, Clipboard, Briefcase, Target, Ticket, Radio, AlarmClock,
  Download, Upload, Tag, AlertCircle, FileText, Paperclip, ExternalLink, Search,
  Activity, Timer, Hash,
} from 'lucide-react'
import { tryRenderRichBlock } from '../copilot/RichBlockRenderer.jsx'
import {
  getAgents, createAgent, updateAgent, deleteAgent,
  runAgent, getAgentRuns, getAgentRun, getAgentToolCatalog,
  getAgentTemplates, createAgentFromTemplate,
  getAgentSchedules, createAgentSchedule, updateAgentSchedule, deleteAgentSchedule,
  exportAgent, importAgent,
  getAgentDocuments, uploadAgentDocument, deleteAgentDocument,
  getAvailableModels, getAgentApprovals,
  getBillingUsage,
} from '../../api.js'
import AgentApprovalQueue from './AgentApprovalQueue.jsx'
import { capture } from '../../utils/analytics.js'

const MODELS = [
  // Anthropic
  { value: 'claude-sonnet-4-6', label: 'Claude Sonnet 4.6', group: 'Anthropic' },
  { value: 'claude-haiku-4-5-20251001', label: 'Claude Haiku 4.5', group: 'Anthropic' },
  { value: 'claude-opus-4-6', label: 'Claude Opus 4.6', group: 'Anthropic' },
  // OpenAI
  { value: 'gpt-4o', label: 'GPT-4o', group: 'OpenAI' },
  { value: 'gpt-4o-mini', label: 'GPT-4o Mini', group: 'OpenAI' },
  { value: 'gpt-4.1', label: 'GPT-4.1', group: 'OpenAI' },
  { value: 'gpt-4.1-mini', label: 'GPT-4.1 Mini', group: 'OpenAI' },
  { value: 'o3-mini', label: 'o3-mini', group: 'OpenAI' },
  // Google Gemini (direct API key)
  { value: 'gemini-2.5-flash', label: 'Gemini 2.5 Flash', group: 'Google' },
  { value: 'gemini-2.5-pro', label: 'Gemini 2.5 Pro', group: 'Google' },
  { value: 'gemini-2.0-flash', label: 'Gemini 2.0 Flash', group: 'Google' },
  // Google Vertex AI (GCP-billed)
  { value: 'vertex/gemini-2.5-pro', label: 'Gemini 2.5 Pro (Vertex)', group: 'Vertex AI' },
  { value: 'vertex/gemini-2.5-flash', label: 'Gemini 2.5 Flash (Vertex)', group: 'Vertex AI' },
  { value: 'vertex/gemini-2.0-flash', label: 'Gemini 2.0 Flash (Vertex)', group: 'Vertex AI' },
  { value: 'vertex/claude-sonnet-4-5@20250929', label: 'Claude Sonnet 4.5 (Vertex)', group: 'Vertex AI' },
  { value: 'vertex/claude-haiku-4-5@20251001', label: 'Claude Haiku 4.5 (Vertex)', group: 'Vertex AI' },
  // Groq
  { value: 'llama-3.3-70b-versatile', label: 'Llama 3.3 70B', group: 'Groq' },
  { value: 'llama-3.1-8b-instant', label: 'Llama 3.1 8B', group: 'Groq' },
  { value: 'mixtral-8x7b-32768', label: 'Mixtral 8x7B', group: 'Groq' },
  { value: 'deepseek-r1-distill-llama-70b', label: 'DeepSeek R1 70B', group: 'Groq' },
]

const STATUS_ICON = {
  done: { Icon: CheckCircle, color: '#22c55e' },
  failed: { Icon: XCircle, color: '#ef4444' },
  running: { Icon: Loader2, color: '#3b82f6' },
  pending: { Icon: Clock, color: '#a3a3a3' },
}

const TEMPLATE_ICONS = {
  clipboard: Clipboard, calendar: Calendar, briefcase: Briefcase,
  alarm: AlarmClock, radar: Radio, ticket: Ticket, target: Target, tag: Tag,
  shield: Shield, alert: AlertCircle, file: FileText, brain: Brain,
  zap: Zap, check: CheckCircle, settings: Settings2,
}

const AGENT_COLORS = [
  '#3b82f6', '#8b5cf6', '#ec4899', '#f59e0b', '#10b981', '#06b6d4', '#ef4444', '#6366f1',
]
function agentColor(name) {
  let h = 0
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) | 0
  return AGENT_COLORS[Math.abs(h) % AGENT_COLORS.length]
}

function timeAgo(iso) {
  if (!iso) return null
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000)
  if (s < 60) return 'just now'
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  if (s < 604800) return `${Math.floor(s / 86400)}d ago`
  return new Date(iso).toLocaleDateString()
}

export default function AgentBuilder() {
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const toast = useToast()
  const confirm = useConfirm()
  const [agents, setAgents] = useState([])
  const [toolCatalog, setToolCatalog] = useState([])
  const [availableModels, setAvailableModels] = useState(null) // { providers, default_model }
  const [templates, setTemplates] = useState([])
  const [selected, setSelected] = useState(null)
  const [editing, setEditing] = useState(null)
  const [runs, setRuns] = useState([])
  const [activeRun, setActiveRun] = useState(null)
  const [streamEvents, setStreamEvents] = useState([])
  const [runInput, setRunInput] = useState('')
  const [running, setRunning] = useState(false)
  const [tab, setTab] = useState('runs') // config | runs | schedule
  const [saving, setSaving] = useState(false)
  const [showTemplates, setShowTemplates] = useState(false)
  const [showApprovals, setShowApprovals] = useState(false)
  const [pendingApprovalCount, setPendingApprovalCount] = useState(0)
  // Deep-link from notification bell / scan rows: ?approvals=1[&run=<id>]
  // opens the approval queue and (optionally) filters to a single agent run.
  const approvalRunFilter = searchParams.get('run')
  const approvalsFromQuery = searchParams.get('approvals') === '1'
  const [schedules, setSchedules] = useState([])
  const [documents, setDocuments] = useState([])
  const [agentSearch, setAgentSearch] = useState('')
  const inputRef = useRef()
  const importRef = useRef()
  const streamRef = useRef(null) // for aborting streams
  const [fetchError, setFetchError] = useState(null)
  const [tokenUsage, setTokenUsage] = useState(null)

  const refreshUsage = () => getBillingUsage().then(setTokenUsage).catch(() => {})

  const refresh = () => {
    setFetchError(null)
    return getAgents().then(setAgents).catch(() => setFetchError('Failed to load agents.'))
  }

  useEffect(() => {
    refresh()
    getAgentToolCatalog().then(setToolCatalog).catch(() => {})
    getAgentTemplates().then(setTemplates).catch(() => {})
    getAvailableModels().then(setAvailableModels).catch(() => {})
    getAgentSchedules().then(setSchedules).catch(() => {})
    getAgentApprovals('pending').then(a => setPendingApprovalCount(a.length)).catch(() => {})
    refreshUsage()
  }, [])

  // Keep the "Approval Queue" badge live without requiring a refresh. The
  // panel-mounted AgentApprovalQueue already polls for itself, but when the
  // user is on a different tab (config/runs/schedule) the count would only
  // ever reflect the initial mount fetch above. Poll the same endpoint here
  // so a freshly-queued approval surfaces in the badge within ~10s.
  useEffect(() => {
    const tick = () => {
      if (document.visibilityState !== 'visible') return
      // Skip while the panel is open — it owns the count via onPendingCount
      // and refetching here would race with its silent reloads.
      if (showApprovals) return
      getAgentApprovals('pending')
        .then(a => setPendingApprovalCount(a.length))
        .catch(() => {})
    }
    const id = setInterval(tick, 10_000)
    return () => clearInterval(id)
  }, [showApprovals])

  // Auto-open the approval queue when the user lands here via deep-link
  // (notification bell / "Review action" button on a scan row). Runs once
  // per query-param transition so the user can still close the panel.
  useEffect(() => {
    if (approvalsFromQuery) {
      setShowApprovals(true)
      setShowTemplates(false)
      setSelected(null)
      setEditing(null)
    }
  }, [approvalsFromQuery])

  const selectAgent = (agent) => {
    setSelected(agent)
    setEditing({ ...agent })
    setTab('runs')
    setActiveRun(null)
    setStreamEvents([])
    setShowTemplates(false)
    setShowApprovals(false)
    getAgentRuns(agent.id).then(setRuns).catch(() => setRuns([]))
    getAgentSchedules().then(setSchedules).catch(() => {})
    getAgentDocuments(agent.id).then(setDocuments).catch(() => setDocuments([]))
  }

  const handleNew = async () => {
    const agent = await createAgent({
      name: 'New Agent',
      system_prompt: 'You are a helpful security analyst assistant. Analyze vulnerability scan data and provide actionable insights.',
      tools: [],
      guardrails: { max_steps: 10, read_only: true },
    })
    capture('agent_created', { agent_id: agent.id, from_template: false })
    await refresh()
    selectAgent(agent)
  }

  const handleFromTemplate = async (template) => {
    setShowTemplates(false)
    const agent = await createAgentFromTemplate({ template_id: template.id })
    capture('agent_created', {
      agent_id: agent.id,
      from_template: true,
      template_id: template.id,
      template_name: template.name,
    })
    await refresh()
    selectAgent(agent)
  }

  const handleExport = async () => {
    if (!selected) return
    try {
      const config = await exportAgent(selected.id)
      const blob = new Blob([JSON.stringify(config, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${selected.name.replace(/[^a-zA-Z0-9_-]/g, '_').toLowerCase()}.agent.json`
      a.click()
      URL.revokeObjectURL(url)
      toast.success('Agent exported')
    } catch (e) {
      toast.error('Export failed: ' + e.message)
    }
  }

  const handleImportFile = async (e) => {
    const file = e.target.files?.[0]
    if (!file) return
    try {
      const text = await file.text()
      const config = JSON.parse(text)
      if (!config.name || !config.system_prompt) {
        toast.error('Invalid agent file: must contain "name" and "system_prompt".')
        return
      }
      const agent = await importAgent(config)
      await refresh()
      selectAgent(agent)
      toast.success('Agent imported')
    } catch (err) {
      toast.error('Import failed: ' + err.message)
    } finally {
      e.target.value = '' // reset so same file can be re-imported
    }
  }

  const handleSave = async () => {
    if (!editing || !selected) return
    setSaving(true)
    try {
      const updated = await updateAgent(selected.id, {
        name: editing.name,
        description: editing.description,
        system_prompt: editing.system_prompt,
        tools: editing.tools,
        guardrails: editing.guardrails,
        model: editing.model,
      })
      setSelected(updated)
      setEditing({ ...updated })
      refresh()
      toast.success('Agent saved')
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async () => {
    if (!selected) return
    if (!await confirm(`Delete agent "${selected.name}"?`)) return
    await deleteAgent(selected.id)
    setSelected(null)
    setEditing(null)
    refresh()
    toast.success('Agent deleted')
  }

  // ── Streaming run ────────────────────────────────────────────────
  const handleRun = async (overrideAgent, overrideInput) => {
    const agent = overrideAgent || selected
    const rawInput = overrideInput || runInput
    if (!agent || !rawInput.trim() || running) return
    if (!overrideAgent && !selected) return
    setRunning(true)
    setTab('runs')
    setActiveRun({ status: 'running', output: '', trace: [] })
    setStreamEvents([])

    const input = rawInput.trim()
    setRunInput('')

    capture('agent_executed', {
      agent_id: agent.id,
      agent_name: agent.name,
      model: agent.model,
      input_length: input.length,
    })

    try {
      // Try streaming first
      const resp = await fetch(`/api/agents/${agent.id}/run/stream`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input }),
      })

      if (!resp.ok || !resp.body) {
        // Fall back to non-streaming
        const result = await runAgent(agent.id, input)
        setActiveRun(result)
        getAgentRuns(agent.id).then(setRuns).catch(() => {})
        setRunning(false)
        return
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
        buffer = lines.pop() // keep incomplete line

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
              setActiveRun(prev => ({ ...prev, output: textAccum, status: 'running' }))
            } else if (event.type === 'tool_call') {
              setActiveRun(prev => ({ ...prev, status: 'running' }))
            } else if (event.type === 'done') {
              setActiveRun(prev => ({
                ...prev,
                output: event.output || textAccum,
                status: 'done',
                steps_used: event.steps_used,
                id: event.run_id,
              }))
            } else if (event.type === 'error') {
              setActiveRun(prev => ({ ...prev, status: 'failed', error: event.error }))
            }
          } catch {}
        }
      }

      getAgentRuns(agent.id).then(setRuns).catch(() => {})
    } catch (e) {
      setActiveRun({ status: 'failed', error: e.message, trace: [] })
    } finally {
      setRunning(false)
      refreshUsage()
    }
  }

  const toggleTool = (toolName) => {
    if (!editing) return
    const tools = editing.tools || []
    const next = tools.includes(toolName)
      ? tools.filter(t => t !== toolName)
      : [...tools, toolName]
    setEditing({ ...editing, tools: next })
  }

  const updateGuardrail = (key, value) => {
    setEditing({
      ...editing,
      guardrails: { ...editing.guardrails, [key]: value },
    })
  }

  return (
    <div>
      <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
      <ErrorBanner error={fetchError} onRetry={refresh} onDismiss={() => setFetchError(null)} />
    <div style={{ display: 'flex', gap: 18, height: 'calc(100vh - 72px)' }}>
      {/* Left panel — agent list */}
      <div style={{ width: 300, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 8 }}>
        <div style={{ marginBottom: 4 }}>
          <h2 style={{ fontSize: 18, fontWeight: 700, marginBottom: 8 }}>Agents</h2>
          {tokenUsage && tokenUsage.tier === 'pro' && (
            <div style={{ marginBottom: 8, fontSize: 11, color: 'var(--text-muted)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                <span>AI tokens</span>
                <span style={{ color: tokenUsage.exceeded ? '#ef4444' : tokenUsage.warning ? '#f59e0b' : 'var(--text-muted)' }}>
                  {tokenUsage.used >= 1_000_000 ? `${(tokenUsage.used / 1_000_000).toFixed(1)}M` : tokenUsage.used >= 1_000 ? `${(tokenUsage.used / 1_000).toFixed(0)}K` : tokenUsage.used} / {tokenUsage.limit >= 1_000_000 ? `${(tokenUsage.limit / 1_000_000).toFixed(0)}M` : tokenUsage.limit}
                </span>
              </div>
              <div style={{ height: 4, borderRadius: 2, background: 'var(--border)', overflow: 'hidden' }}>
                <div style={{ height: '100%', width: `${Math.min(tokenUsage.percentage, 100)}%`, background: tokenUsage.exceeded ? '#ef4444' : tokenUsage.warning ? '#f59e0b' : 'var(--accent)', borderRadius: 2, transition: 'width 0.3s ease' }} />
              </div>
              {tokenUsage.exceeded && <div style={{ color: '#ef4444', fontSize: 10, marginTop: 2 }}>Monthly quota exceeded</div>}
            </div>
          )}
          <div style={{ display: 'flex', gap: 4 }}>
            <button
              onClick={() => { setShowTemplates(v => !v); setShowApprovals(false); setSelected(null); setEditing(null) }}
              title="Create from template"
              style={{
                display: 'flex', alignItems: 'center', gap: 4, flex: 1, justifyContent: 'center',
                background: 'transparent', color: 'var(--accent)', border: '1px solid var(--accent)',
                borderRadius: 6, padding: '5px 0', fontSize: 11, fontWeight: 600, cursor: 'pointer',
              }}
            >
              <Zap size={12} /> Templates
            </button>
            <button
              onClick={() => importRef.current?.click()}
              title="Import agent from file"
              style={{
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                background: 'transparent', color: 'var(--text-muted)', border: '1px solid var(--border)',
                borderRadius: 6, padding: '5px 8px', fontSize: 11, cursor: 'pointer',
              }}
            >
              <Upload size={12} />
            </button>
            <input ref={importRef} type="file" accept=".json,.agent.json" onChange={handleImportFile} style={{ display: 'none' }} />
            <button
              onClick={handleNew}
              style={{
                display: 'flex', alignItems: 'center', gap: 4, flex: 1, justifyContent: 'center',
                background: 'var(--accent)', color: '#fff', border: 'none',
                borderRadius: 6, padding: '5px 0', fontSize: 11, fontWeight: 600, cursor: 'pointer',
              }}
            >
              <Plus size={12} /> New
            </button>
          </div>
        </div>

        {/* Search */}
        {agents.length > 0 && (
          <div style={{ position: 'relative' }}>
            <Search size={13} style={{ position: 'absolute', left: 8, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
            <input
              type="text"
              placeholder="Filter agents..."
              value={agentSearch}
              onChange={e => setAgentSearch(e.target.value)}
              style={{
                width: '100%', padding: '6px 10px 6px 28px', borderRadius: 6,
                border: '1px solid var(--border)', background: 'var(--bg)',
                fontSize: 12, color: 'var(--text-primary)', outline: 'none', boxSizing: 'border-box',
              }}
            />
          </div>
        )}

        <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 4 }}>
          {(() => {
            const filtered = agents.filter(a => {
              if (!agentSearch.trim()) return true
              const q = agentSearch.toLowerCase()
              return a.name.toLowerCase().includes(q) || (a.description || '').toLowerCase().includes(q)
            })
            const scheduled = filtered.filter(a => a.schedules?.length > 0)
            const manual = filtered.filter(a => !a.schedules?.length)

            const renderCard = (a) => {
              const color = agentColor(a.name)
              const lr = a.last_run
              const statusDot = lr ? (STATUS_ICON[lr.status]?.color || '#a3a3a3') : '#a3a3a3'
              const dupeCount = agents.filter(x => x.name === a.name).length
              return (
                <Card
                  key={a.id}
                  onClick={() => selectAgent(a)}
                  style={{
                    padding: '10px 12px', cursor: 'pointer',
                    borderTopColor: selected?.id === a.id ? 'var(--accent)' : 'var(--border)',
                    borderRightColor: selected?.id === a.id ? 'var(--accent)' : 'var(--border)',
                    borderBottomColor: selected?.id === a.id ? 'var(--accent)' : 'var(--border)',
                    background: selected?.id === a.id ? 'var(--bg)' : 'var(--bg-card)',
                    borderLeft: `3px solid ${color}`,
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
                    <div style={{
                      width: 32, height: 32, borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center',
                      background: `${color}18`, flexShrink: 0, marginTop: 1,
                    }}>
                      <Bot size={16} color={color} />
                    </div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <div style={{ fontSize: 13, fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>
                          {a.name}
                        </div>
                        {/* Status dot */}
                        <div style={{ width: 7, height: 7, borderRadius: '50%', background: statusDot, flexShrink: 0 }} title={lr ? `Last run: ${lr.status}` : 'Never run'} />
                      </div>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {a.description || 'No description'}
                      </div>
                      {/* Metadata row */}
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 4, fontSize: 10, color: 'var(--text-muted)' }}>
                        {lr ? (
                          <span style={{ display: 'flex', alignItems: 'center', gap: 3 }}>
                            <Timer size={10} /> {timeAgo(lr.created_at)}
                          </span>
                        ) : (
                          <span style={{ display: 'flex', alignItems: 'center', gap: 3 }}>
                            <Timer size={10} /> Never run
                          </span>
                        )}
                        {a.run_count > 0 && (
                          <span style={{ display: 'flex', alignItems: 'center', gap: 3 }}>
                            <Hash size={10} /> {a.run_count} runs
                          </span>
                        )}
                        {a.schedules?.length > 0 && (
                          <span style={{ display: 'flex', alignItems: 'center', gap: 3, color: 'var(--accent)' }}>
                            <Calendar size={10} /> Scheduled
                          </span>
                        )}
                        {dupeCount > 1 && (
                          <span style={{ opacity: 0.7 }}>
                            #{agents.filter(x => x.name === a.name).indexOf(a) + 1}
                          </span>
                        )}
                      </div>
                    </div>
                    {/* Quick run button */}
                    {lr && (
                      <button
                        onClick={e => {
                          e.stopPropagation()
                          selectAgent(a)
                          const lastInput = lr.input || ''
                          if (lastInput.trim()) {
                            handleRun(a, lastInput)
                          } else {
                            setRunInput('')
                            setTimeout(() => inputRef.current?.focus(), 100)
                          }
                        }}
                        title="Re-run last prompt"
                        style={{
                          background: 'transparent', border: '1px solid var(--border)', borderRadius: 6,
                          padding: '4px 6px', cursor: 'pointer', color: 'var(--text-muted)', display: 'flex',
                          alignItems: 'center', flexShrink: 0, marginTop: 1,
                        }}
                        onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent)'; e.currentTarget.style.color = 'var(--accent)' }}
                        onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-muted)' }}
                      >
                        <Play size={12} />
                      </button>
                    )}
                  </div>
                </Card>
              )
            }

            if (filtered.length === 0 && agentSearch) {
              return (
                <div style={{ textAlign: 'center', padding: '24px 16px', color: 'var(--text-muted)', fontSize: 12 }}>
                  No agents match "{agentSearch}"
                </div>
              )
            }

            // Show groups only when there are both scheduled and manual agents
            if (scheduled.length > 0 && manual.length > 0) {
              return (
                <>
                  <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--text-muted)', padding: '6px 4px 2px' }}>
                    Scheduled ({scheduled.length})
                  </div>
                  {scheduled.map(renderCard)}
                  <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--text-muted)', padding: '10px 4px 2px' }}>
                    Manual ({manual.length})
                  </div>
                  {manual.map(renderCard)}
                </>
              )
            }
            return filtered.map(renderCard)
          })()}
          {agents.length === 0 && !showTemplates && (
            <div style={{ textAlign: 'center', padding: '32px 16px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12 }}>
              <div style={{
                width: 48, height: 48, borderRadius: 12, display: 'flex', alignItems: 'center', justifyContent: 'center',
                background: 'color-mix(in srgb, var(--accent) 10%, transparent)',
              }}>
                <Bot size={24} color="var(--accent)" />
              </div>
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>No agents yet</div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.5 }}>
                Pick a template from the gallery to get started quickly.
              </div>
            </div>
          )}
        </div>

        {/* Approvals button */}
        <button
          onClick={() => { setShowApprovals(v => !v); setShowTemplates(false); setSelected(null); setEditing(null) }}
          style={{
            display: 'flex', alignItems: 'center', gap: 6, marginTop: 8,
            width: '100%', padding: '7px 10px', borderRadius: 6,
            border: '1px solid var(--border)',
            background: showApprovals ? 'var(--nav-active-bg)' : 'transparent',
            color: showApprovals ? 'var(--nav-active-text)' : 'var(--muted)',
            cursor: 'pointer', fontSize: 12, fontWeight: 600, textAlign: 'left',
          }}
        >
          <CheckCircle size={13} />
          Approval Queue
          {pendingApprovalCount > 0 && (
            <span style={{
              marginLeft: 'auto', padding: '1px 6px', borderRadius: 10,
              background: '#f59e0b', color: '#fff', fontSize: 10, fontWeight: 700,
            }}>
              {pendingApprovalCount}
            </span>
          )}
        </button>
      </div>

      {/* Right panel — templates gallery / approval queue / config + runner */}
      {showTemplates ? (
        <TemplateGallery templates={templates} onCreate={handleFromTemplate} onClose={() => setShowTemplates(false)} />
      ) : showApprovals ? (
        <div style={{ flex: 1, overflow: 'auto', padding: '0 4px' }}>
          <AgentApprovalQueue
            panel
            runFilter={approvalRunFilter ? Number(approvalRunFilter) : null}
            onPendingCount={setPendingApprovalCount}
            onClearRunFilter={() => {
              const next = new URLSearchParams(searchParams)
              next.delete('run')
              next.delete('approvals')
              setSearchParams(next, { replace: true })
            }}
          />
        </div>
      ) : selected && editing ? (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 12, minWidth: 0, overflow: 'hidden' }}>
          {/* Header */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <input
              value={editing.name}
              onChange={e => setEditing({ ...editing, name: e.target.value })}
              style={{
                fontSize: 20, fontWeight: 700, background: 'var(--bg)', border: '1px solid var(--border)',
                borderRadius: 8, padding: '6px 12px',
                color: 'var(--text-primary)', outline: 'none', flex: 1,
              }}
              placeholder="Agent name"
            />
            <div style={{ display: 'flex', gap: 8 }}>
              <button
                onClick={handleExport}
                title="Export agent as JSON"
                style={{
                  padding: '6px 10px', borderRadius: 6, border: '1px solid var(--border)',
                  background: 'transparent', color: 'var(--text-muted)', cursor: 'pointer',
                  display: 'flex', alignItems: 'center', gap: 4, fontSize: 12,
                }}
              >
                <Download size={14} /> Export
              </button>
              <button
                onClick={handleSave}
                disabled={saving}
                style={{
                  padding: '6px 16px', borderRadius: 6, border: 'none', fontSize: 12, fontWeight: 600,
                  background: 'var(--accent)', color: '#fff', cursor: 'pointer', opacity: saving ? 0.6 : 1,
                }}
              >
                {saving ? 'Saving...' : 'Save'}
              </button>
              <button
                onClick={handleDelete}
                style={{
                  padding: '6px 10px', borderRadius: 6, border: '1px solid var(--border)',
                  background: 'transparent', color: '#ef4444', cursor: 'pointer', display: 'flex', alignItems: 'center',
                }}
              >
                <Trash2 size={14} />
              </button>
            </div>
          </div>

          <input
            value={editing.description || ''}
            onChange={e => setEditing({ ...editing, description: e.target.value })}
            placeholder="Short description..."
            style={{
              fontSize: 13, background: 'var(--bg)', border: '1px solid var(--border)',
              borderRadius: 6, padding: '6px 10px', color: 'var(--text-primary)', outline: 'none',
            }}
          />

          {/* Tabs */}
          <div style={{ display: 'flex', gap: 0, borderBottom: '1px solid var(--border)' }}>
            {[
              { key: 'runs', label: 'Runs', icon: Clock },
              { key: 'config', label: 'Configure', icon: Settings2 },
              { key: 'schedule', label: 'Schedule', icon: Calendar },
            ].map(t => (
              <button
                key={t.key}
                onClick={() => setTab(t.key)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 6,
                  padding: '8px 16px', border: 'none', background: 'transparent', cursor: 'pointer',
                  fontSize: 13, fontWeight: 600,
                  color: tab === t.key ? 'var(--accent)' : 'var(--text-muted)',
                  borderBottom: tab === t.key ? '2px solid var(--accent)' : '2px solid transparent',
                }}
              >
                <t.icon size={14} /> {t.label}
              </button>
            ))}
          </div>

          {/* Tab content */}
          <div style={{ flex: 1, overflowY: 'auto', overflowX: 'hidden', minWidth: 0 }}>
            {tab === 'config' ? (
              <ConfigPanel
                editing={editing}
                setEditing={setEditing}
                toolCatalog={toolCatalog}
                toggleTool={toggleTool}
                updateGuardrail={updateGuardrail}
                agentId={selected.id}
                documents={documents}
                onDocumentsChange={() => getAgentDocuments(selected.id).then(setDocuments).catch(() => {})}
                availableModels={availableModels}
                navigate={navigate}
              />
            ) : tab === 'runs' ? (
              <RunsPanel
                runs={runs}
                activeRun={activeRun}
                setActiveRun={setActiveRun}
                selected={selected}
                streamEvents={streamEvents}
                running={running}
                navigate={navigate}
                onRerun={(input) => handleRun(selected, input)}
              />
            ) : (
              <SchedulePanel
                agentId={selected.id}
                agent={selected}
                templates={templates}
                schedules={schedules.filter(s => s.agent_id === selected.id)}
                onRefresh={() => getAgentSchedules().then(setSchedules).catch(() => {})}
              />
            )}
          </div>

          {/* Run input */}
          <div style={{
            display: 'flex', gap: 8, padding: '12px 0 0',
            borderTop: '1px solid var(--border)',
          }}>
            <input
              ref={inputRef}
              value={runInput}
              onChange={e => setRunInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleRun()}
              placeholder="Ask this agent something..."
              style={{
                flex: 1, padding: '10px 14px', borderRadius: 8,
                border: '1px solid var(--border)', background: 'var(--bg)',
                color: 'var(--text-primary)', fontSize: 13, outline: 'none',
              }}
            />
            <button
              onClick={handleRun}
              disabled={running || !runInput.trim()}
              style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '10px 20px', borderRadius: 8, border: 'none',
                background: running ? 'var(--border)' : 'var(--accent)',
                color: '#fff', fontSize: 13, fontWeight: 600, cursor: running ? 'not-allowed' : 'pointer',
              }}
            >
              {running ? <><Loader2 size={14} className="spin" /> Running...</> : <><Play size={14} /> Run</>}
            </button>
          </div>
        </div>
      ) : agents.length === 0 ? (
        <TemplateGallery templates={templates} onCreate={handleFromTemplate} onClose={() => {}} hideClose />
      ) : (
        <AgentDashboard agents={agents} schedules={schedules} onSelect={selectAgent} onNew={() => setShowTemplates(true)} />
      )}
    </div>
    </div>
  )
}


// ── Template Gallery ──────────────────────────────────────────────────

function TemplateGallery({ templates, onCreate, onClose, hideClose }) {
  const [search, setSearch] = useState('')
  const CATEGORY_COLORS = {
    read_only: { bg: '#dbeafe', text: '#1d4ed8', label: 'Read-only' },
    write: { bg: '#fef3c7', text: '#92400e', label: 'Write actions' },
  }

  const filtered = templates.filter(t => {
    if (!search.trim()) return true
    const q = search.toLowerCase()
    return t.name.toLowerCase().includes(q)
      || t.description.toLowerCase().includes(q)
      || (t.tools || []).some(tool => tool.toLowerCase().includes(q))
  })

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0, overflowY: 'auto' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <div>
          <h2 style={{ fontSize: 20, fontWeight: 700, margin: 0 }}>Agent Templates</h2>
          <p style={{ fontSize: 13, color: 'var(--text-muted)', margin: '4px 0 0' }}>
            Choose a template to create a pre-configured agent. Click any card to get started.
          </p>
        </div>
        {!hideClose && (
          <button
            onClick={onClose}
            style={{
              background: 'transparent', border: '1px solid var(--border)', borderRadius: 6,
              padding: '6px 14px', cursor: 'pointer', color: 'var(--text-muted)', fontSize: 12, fontWeight: 600,
            }}
          >
            Close
          </button>
        )}
      </div>

      <div style={{ position: 'relative', marginBottom: 14 }}>
        <Search size={15} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
        <input
          type="text"
          placeholder="Search templates by name, description, or tool..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{
            width: '100%', padding: '9px 12px 9px 32px', borderRadius: 8,
            border: '1px solid var(--border)', background: 'var(--bg-secondary)',
            fontSize: 13, color: 'var(--text)', outline: 'none', boxSizing: 'border-box',
          }}
        />
      </div>

      {filtered.length === 0 && (
        <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--text-muted)', fontSize: 13 }}>
          {search ? `No templates match "${search}"` : 'No templates available.'}
        </div>
      )}

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))',
        gap: 14,
      }}>
        {filtered.map(t => {
          const TIcon = TEMPLATE_ICONS[t.icon] || Bot
          const mode = t.guardrails?.read_only ? 'read_only' : 'write'
          const modeStyle = CATEGORY_COLORS[mode]
          return (
            <Card
              key={t.id}
              onClick={() => onCreate(t)}
              style={{
                padding: 0, cursor: 'pointer', transition: 'border-color 0.15s, box-shadow 0.15s',
                overflow: 'hidden', display: 'flex', flexDirection: 'column',
              }}
              onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent)'; e.currentTarget.style.boxShadow = '0 0 0 1px var(--accent)' }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.boxShadow = 'none' }}
            >
              {/* Header stripe */}
              <div style={{
                padding: '14px 16px 12px', display: 'flex', alignItems: 'center', gap: 12,
                background: 'color-mix(in srgb, var(--accent) 6%, transparent)',
                borderBottom: '1px solid var(--border)',
              }}>
                <div style={{
                  width: 38, height: 38, borderRadius: 10, display: 'flex', alignItems: 'center', justifyContent: 'center',
                  background: 'color-mix(in srgb, var(--accent) 15%, transparent)',
                }}>
                  <TIcon size={20} color="var(--accent)" />
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 14, fontWeight: 700 }}>{t.name}</div>
                  <span style={{
                    fontSize: 10, fontWeight: 600, padding: '2px 7px', borderRadius: 4,
                    background: modeStyle.bg, color: modeStyle.text,
                  }}>
                    {modeStyle.label}
                  </span>
                </div>
              </div>

              {/* Body */}
              <div style={{ padding: '12px 16px 14px', flex: 1, display: 'flex', flexDirection: 'column', gap: 10 }}>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.5, flex: 1 }}>
                  {t.description}
                </div>

                {/* Tools */}
                <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
                  {(t.tools || []).slice(0, 5).map(tool => (
                    <span key={tool} style={{
                      fontSize: 10, padding: '3px 7px', borderRadius: 4, fontWeight: 500,
                      background: 'color-mix(in srgb, var(--accent) 12%, transparent)',
                      color: 'var(--accent)',
                    }}>
                      {tool}
                    </span>
                  ))}
                  {(t.tools || []).length > 5 && (
                    <span style={{ fontSize: 10, color: 'var(--text-muted)', alignSelf: 'center' }}>
                      +{t.tools.length - 5} more
                    </span>
                  )}
                </div>

                {/* Suggested input */}
                {t.suggested_input && (
                  <div style={{
                    fontSize: 11, color: 'var(--text-muted)', fontStyle: 'italic',
                    padding: '8px 10px', borderRadius: 6, background: 'var(--bg)',
                    borderLeft: '3px solid var(--border)',
                  }}>
                    "{t.suggested_input}"
                  </div>
                )}
              </div>
            </Card>
          )
        })}
      </div>
    </div>
  )
}


// ── Agent Dashboard (empty-state replacement) ─────────────────────────

function AgentDashboard({ agents, schedules, onSelect, onNew }) {
  // Collect recent runs from all agents (already included via list_agents enrichment)
  const recentRuns = agents
    .filter(a => a.last_run)
    .map(a => ({ ...a.last_run, agent_name: a.name, agent: a }))
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
    .slice(0, 8)

  const failedAgents = agents.filter(a => a.last_run?.status === 'failed')
  const scheduledAgents = agents.filter(a => a.schedules?.length > 0)
  const totalRuns = agents.reduce((sum, a) => sum + (a.run_count || 0), 0)

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: '0 4px' }}>
      <h2 style={{ fontSize: 20, fontWeight: 700, marginBottom: 4 }}>Agent Overview</h2>
      <p style={{ fontSize: 13, color: 'var(--text-muted)', margin: '0 0 20px' }}>
        Select an agent from the sidebar, or get a quick look at recent activity below.
      </p>

      {/* Stats row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 12, marginBottom: 20 }}>
        {[
          { label: 'Total Agents', value: agents.length, icon: Bot, color: '#3b82f6' },
          { label: 'Total Runs', value: totalRuns, icon: Activity, color: '#8b5cf6' },
          { label: 'Scheduled', value: scheduledAgents.length, icon: Calendar, color: '#10b981' },
          { label: 'Needs Attention', value: failedAgents.length, icon: AlertCircle, color: failedAgents.length > 0 ? '#ef4444' : '#a3a3a3' },
        ].map(s => (
          <Card key={s.label} style={{ padding: '14px 16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{
                width: 36, height: 36, borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center',
                background: `${s.color}15`,
              }}>
                <s.icon size={18} color={s.color} />
              </div>
              <div>
                <div style={{ fontSize: 20, fontWeight: 700, lineHeight: 1 }}>{s.value}</div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{s.label}</div>
              </div>
            </div>
          </Card>
        ))}
      </div>

      {/* Failed agents - needs attention */}
      {failedAgents.length > 0 && (
        <div style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6, color: '#ef4444' }}>
            <AlertCircle size={14} /> Needs Attention
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {failedAgents.map(a => (
              <Card key={a.id} onClick={() => onSelect(a)} style={{ padding: '10px 14px', cursor: 'pointer', borderLeft: '3px solid #ef4444' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <XCircle size={14} color="#ef4444" />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 13, fontWeight: 600 }}>{a.name}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      Last run failed {timeAgo(a.last_run.created_at)}
                    </div>
                  </div>
                  <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>View</span>
                </div>
              </Card>
            ))}
          </div>
        </div>
      )}

      {/* Recent runs */}
      {recentRuns.length > 0 && (
        <div style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6, color: 'var(--text-secondary)' }}>
            <Clock size={14} /> Recent Activity
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {recentRuns.map((r, i) => {
              const si = STATUS_ICON[r.status] || STATUS_ICON.pending
              return (
                <Card key={i} onClick={() => onSelect(r.agent)} style={{ padding: '8px 12px', cursor: 'pointer' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
                    <si.Icon size={13} color={si.color} />
                    <span style={{ fontSize: 12, fontWeight: 600, flexShrink: 0 }}>{r.agent_name}</span>
                    <span style={{ fontSize: 12, color: 'var(--text-muted)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {r.input}
                    </span>
                    <span style={{ fontSize: 11, color: 'var(--text-muted)', flexShrink: 0 }}>
                      {timeAgo(r.created_at)}
                    </span>
                  </div>
                </Card>
              )
            })}
          </div>
        </div>
      )}

      {/* Upcoming scheduled runs */}
      {scheduledAgents.length > 0 && (
        <div style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6, color: 'var(--text-secondary)' }}>
            <Calendar size={14} /> Upcoming Scheduled Runs
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {scheduledAgents.map(a => (
              <Card key={a.id} onClick={() => onSelect(a)} style={{ padding: '8px 12px', cursor: 'pointer' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Calendar size={13} color="var(--accent)" />
                  <span style={{ fontSize: 12, fontWeight: 600 }}>{a.name}</span>
                  <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                    {a.schedules[0].cron_expression}
                  </span>
                  {a.schedules[0].next_run_at && (
                    <span style={{ fontSize: 11, color: 'var(--text-muted)', marginLeft: 'auto' }}>
                      Next: {new Date(a.schedules[0].next_run_at).toLocaleString()}
                    </span>
                  )}
                </div>
              </Card>
            ))}
          </div>
        </div>
      )}

      {/* Quick create CTA */}
      {agents.length < 3 && (
        <Card style={{ padding: '20px 24px', textAlign: 'center', borderStyle: 'dashed' }}>
          <Bot size={24} color="var(--accent)" style={{ marginBottom: 8 }} />
          <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 4 }}>Create more agents</div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 12 }}>
            Automate patch analysis, daily triage, executive summaries, and more.
          </div>
          <button
            onClick={onNew}
            style={{
              padding: '7px 20px', borderRadius: 6, border: 'none',
              background: 'var(--accent)', color: '#fff', fontSize: 12, fontWeight: 600, cursor: 'pointer',
            }}
          >
            Browse Templates
          </button>
        </Card>
      )}
    </div>
  )
}


// ── Config Panel ──────────────────────────────────────────────────────

function ConfigPanel({ editing, setEditing, toolCatalog, toggleTool, updateGuardrail, agentId, documents, onDocumentsChange, availableModels, navigate }) {
  const toast = useToast()
  const confirm = useConfirm()
  const docInputRef = useRef()
  const [uploading, setUploading] = useState(false)

  const handleDocUpload = async (e) => {
    const file = e.target.files?.[0]
    if (!file) return
    setUploading(true)
    try {
      await uploadAgentDocument(agentId, file)
      onDocumentsChange()
      toast.success('Document uploaded')
    } catch (err) {
      toast.error('Upload failed: ' + err.message)
    } finally {
      setUploading(false)
      e.target.value = ''
    }
  }

  const handleDocDelete = async (docId) => {
    if (!await confirm('Remove this document?')) return
    try {
      await deleteAgentDocument(agentId, docId)
      onDocumentsChange()
      toast.success('Document removed')
    } catch (err) {
      toast.error('Delete failed: ' + err.message)
    }
  }

  const formatSize = (bytes) => {
    if (bytes < 1024) return bytes + ' B'
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB'
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16, paddingTop: 8 }}>
      {/* System Prompt */}
      <Section icon={MessageSquare} title="Instructions">
        <textarea
          value={editing.system_prompt}
          onChange={e => setEditing({ ...editing, system_prompt: e.target.value })}
          rows={6}
          style={{
            width: '100%', padding: 10, borderRadius: 8, border: '1px solid var(--border)',
            background: 'var(--bg)', color: 'var(--text-primary)', fontSize: 13,
            fontFamily: 'monospace', resize: 'vertical', outline: 'none',
          }}
          placeholder="System prompt — tell the agent who it is and what it should do..."
        />
      </Section>

      {/* Tools */}
      <Section icon={Wrench} title={`Tools (${(editing.tools || []).length} selected)`}>
        <ToolSelector tools={editing.tools || []} toolCatalog={toolCatalog} toggleTool={toggleTool} setEditing={setEditing} editing={editing} />
      </Section>

      {/* Guardrails */}
      <Section icon={Shield} title="Guardrails">
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
            <input
              type="checkbox"
              checked={editing.guardrails?.read_only ?? true}
              onChange={e => updateGuardrail('read_only', e.target.checked)}
            />
            Read-only mode (blocks write operations like ticketing, tagging)
          </label>
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
            Max steps:
            <input
              type="number"
              min={1} max={50}
              value={editing.guardrails?.max_steps ?? 10}
              onChange={e => updateGuardrail('max_steps', parseInt(e.target.value) || 10)}
              style={{
                width: 60, padding: '4px 8px', borderRadius: 4,
                border: '1px solid var(--border)', background: 'var(--bg)',
                color: 'var(--text-primary)', fontSize: 13, outline: 'none',
              }}
            />
          </label>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 4 }}>
            <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-primary)' }}>Execution mode</span>
            <div style={{ display: 'flex', gap: 8 }}>
              {[
                { value: 'auto', label: 'Fully Autonomous', icon: Zap, desc: 'Executes all tools without pausing' },
                { value: 'hitl', label: 'Human-in-the-Loop', icon: Shield, desc: 'Pauses for approval before write actions' },
              ].map(mode => {
                const selected = (editing.guardrails?.approval_mode ?? 'auto') === mode.value
                return (
                  <button
                    key={mode.value}
                    onClick={() => updateGuardrail('approval_mode', mode.value)}
                    style={{
                      flex: 1, display: 'flex', flexDirection: 'column', gap: 4,
                      padding: '10px 12px', borderRadius: 8, cursor: 'pointer',
                      border: selected ? '2px solid #3b82f6' : '1px solid var(--border)',
                      background: selected ? 'rgba(59,130,246,0.08)' : 'var(--bg)',
                      color: 'var(--text-primary)', textAlign: 'left',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <mode.icon size={14} color={selected ? '#3b82f6' : 'var(--text-muted)'} />
                      <span style={{ fontSize: 13, fontWeight: 600, color: selected ? '#3b82f6' : 'var(--text-primary)' }}>
                        {mode.label}
                      </span>
                    </div>
                    <span style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.4 }}>
                      {mode.desc}
                    </span>
                  </button>
                )
              })}
            </div>
            {(editing.guardrails?.approval_mode ?? 'auto') === 'hitl' && (
              <p style={{ fontSize: 11, color: 'var(--text-muted)', margin: '2px 0 0', lineHeight: 1.5 }}>
                Write tools (Jira, Slack, email, campaigns, tagging) will require your approval before executing. View pending approvals in the Runs tab.
              </p>
            )}
          </div>
        </div>
      </Section>

      {/* Model */}
      <Section icon={Brain} title="Model">
        {availableModels && availableModels.providers.length === 0 ? (
          <div style={{
            display: 'flex', flexDirection: 'column', gap: 10, padding: '12px 14px',
            background: 'var(--bg)', borderRadius: 8, border: '1px solid var(--border)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: '#f59e0b' }}>
              <AlertCircle size={16} />
              <span style={{ fontSize: 13, fontWeight: 500 }}>No AI provider configured</span>
            </div>
            <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: 0, lineHeight: 1.5 }}>
              Connect at least one AI provider (Anthropic, OpenAI, Groq, or Google) to run agents.
            </p>
            <button
              onClick={() => navigate('/settings')}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: 6,
                padding: '6px 14px', borderRadius: 6, border: 'none', cursor: 'pointer',
                background: '#3b82f6', color: '#fff', fontSize: 12, fontWeight: 500,
                alignSelf: 'flex-start',
              }}
            >
              <ExternalLink size={13} /> Go to Settings &rarr; Integrations
            </button>
          </div>
        ) : (
          <>
            <select
              value={editing.model || availableModels?.default_model || 'vertex/gemini-2.5-pro'}
              onChange={e => setEditing({ ...editing, model: e.target.value })}
              style={{
                padding: '6px 10px', borderRadius: 6, border: '1px solid var(--border)',
                background: 'var(--bg)', color: 'var(--text-primary)', fontSize: 13, outline: 'none',
              }}
            >
              {availableModels ? (
                availableModels.providers.map(p => (
                  <optgroup key={p.provider} label={`${p.display} ✓`}>
                    {p.models.map(m => {
                      const info = MODELS.find(x => x.value === m)
                      return <option key={m} value={m}>{info?.label || m}</option>
                    })}
                  </optgroup>
                ))
              ) : (
                [...new Set(MODELS.map(m => m.group))].map(group => (
                  <optgroup key={group} label={group}>
                    {MODELS.filter(m => m.group === group).map(m => (
                      <option key={m.value} value={m.value}>{m.label}</option>
                    ))}
                  </optgroup>
                ))
              )}
            </select>
            {availableModels && (
              <span style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4, marginLeft: 8 }}>
                Showing only connected providers. <a href="#" onClick={e => { e.preventDefault(); navigate('/settings') }} style={{ color: '#3b82f6' }}>Manage integrations</a>
              </span>
            )}
          </>
        )}
      </Section>

      {/* Knowledge Base (RAG Documents) */}
      <Section icon={FileText} title={`Knowledge Base (${documents.length} files)`}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.5 }}>
            Upload reference documents (policies, runbooks, configs, reports) so the agent can search them during runs.
            Add the <code style={{ background: 'var(--bg)', padding: '1px 5px', borderRadius: 3, fontSize: 11 }}>search_documents</code> tool to enable retrieval.
          </div>

          {/* Upload button */}
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <button
              onClick={() => docInputRef.current?.click()}
              disabled={uploading}
              style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '6px 14px', borderRadius: 6, fontSize: 12, fontWeight: 600,
                border: '1px dashed var(--border)', background: 'transparent',
                color: 'var(--accent)', cursor: uploading ? 'wait' : 'pointer',
                opacity: uploading ? 0.6 : 1,
              }}
            >
              {uploading ? <Loader2 size={13} className="spin" /> : <Paperclip size={13} />}
              {uploading ? 'Uploading...' : 'Upload File'}
            </button>
            <input
              ref={docInputRef}
              type="file"
              accept=".txt,.md,.csv,.json,.xml,.html,.htm,.log,.yaml,.yml,.nessus,.pdf,.py,.js,.ts,.conf,.cfg,.ini,.toml"
              onChange={handleDocUpload}
              style={{ display: 'none' }}
            />
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
              Max 10 MB &middot; .txt, .md, .csv, .json, .xml, .yaml, .log, .nessus, .pdf, etc.
            </span>
          </div>

          {/* Document list */}
          {documents.length > 0 && (
            <div style={{
              display: 'flex', flexDirection: 'column', gap: 4,
              padding: 8, borderRadius: 6, background: 'var(--bg)', border: '1px solid var(--border)',
            }}>
              {documents.map(doc => (
                <div key={doc.id} style={{
                  display: 'flex', alignItems: 'center', gap: 8,
                  padding: '6px 8px', borderRadius: 4,
                  background: 'var(--bg-card)',
                }}>
                  <FileText size={14} color="var(--accent)" style={{ flexShrink: 0 }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{
                      fontSize: 12, fontWeight: 600, overflow: 'hidden',
                      textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                    }}>
                      {doc.filename}
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                      {formatSize(doc.size_bytes)} &middot; {doc.chunk_count} chunks
                    </div>
                  </div>
                  <button
                    onClick={() => handleDocDelete(doc.id)}
                    title="Remove document"
                    style={{
                      background: 'transparent', border: 'none', cursor: 'pointer',
                      color: 'var(--text-muted)', padding: 4, borderRadius: 4,
                      display: 'flex', alignItems: 'center',
                    }}
                    onMouseEnter={e => e.currentTarget.style.color = '#ef4444'}
                    onMouseLeave={e => e.currentTarget.style.color = 'var(--text-muted)'}
                  >
                    <Trash2 size={13} />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </Section>

      {/* Memory (read-only view) */}
      {editing.memory && Object.keys(editing.memory).length > 0 && (
        <Section icon={Brain} title="Memory">
          <pre style={{
            fontSize: 12, padding: 10, borderRadius: 6, background: 'var(--bg)',
            border: '1px solid var(--border)', overflow: 'auto', maxHeight: 200,
            color: 'var(--text-secondary)',
          }}>
            {JSON.stringify(editing.memory, null, 2)}
          </pre>
        </Section>
      )}
    </div>
  )
}


// ── Runs Panel (with streaming) ──────────────────────────────────────

function RunsPanel({ runs, activeRun, setActiveRun, selected, streamEvents, running, navigate, onRerun }) {
  const loadRun = async (run) => {
    try {
      const full = await getAgentRun(selected.id, run.id)
      setActiveRun(full)
    } catch { setActiveRun(run) }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, paddingTop: 8, minWidth: 0, overflow: 'hidden' }}>
      {/* Active run output */}
      {activeRun && (
        <Card style={{ padding: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
            <StatusBadge status={activeRun.status} />
            <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              {activeRun.steps_used ?? 0} steps
            </span>
            {!running && activeRun.input && (
              <button
                onClick={() => onRerun(activeRun.input)}
                title="Re-run with same input"
                style={{
                  marginLeft: 'auto', display: 'inline-flex', alignItems: 'center', gap: 4,
                  padding: '3px 10px', borderRadius: 5, border: '1px solid var(--border)',
                  background: 'transparent', color: 'var(--accent)', fontSize: 11,
                  cursor: 'pointer', fontWeight: 500,
                }}
              >
                <Play size={11} /> Re-run
              </button>
            )}
          </div>

          {/* Streaming events (live tool call feed) */}
          {running && streamEvents.length > 0 && (
            <div style={{
              marginBottom: 12, padding: 10, borderRadius: 6,
              background: 'var(--bg-secondary)', border: '1px solid var(--border)',
              maxHeight: 150, overflowY: 'auto', fontSize: 12, fontFamily: 'monospace',
            }}>
              {streamEvents.map((ev, i) => (
                <div key={i} style={{ color: ev.type === 'tool_call' ? '#818cf8' : ev.type === 'tool_result' ? '#22c55e' : ev.type === 'thinking' ? '#64748b' : '#e2e8f0', marginBottom: 2 }}>
                  {ev.type === 'thinking' && `[step ${ev.step}] Thinking...`}
                  {ev.type === 'tool_call' && `[step ${ev.step}] Calling ${ev.name}...`}
                  {ev.type === 'tool_result' && `[step ${ev.step}] ${ev.name} done`}
                  {ev.type === 'text' && `[step ${ev.step}] Writing response...`}
                </div>
              ))}
            </div>
          )}

          {activeRun.error && (
            <div style={{
              display: 'flex', alignItems: 'flex-start', gap: 10,
              padding: '12px 14px', borderRadius: 8, marginBottom: 12,
              background: '#dc262610', border: '1px solid #dc262635',
            }}>
              <AlertCircle size={15} color="#ef4444" style={{ marginTop: 1, flexShrink: 0 }} />
              <div style={{ minWidth: 0 }}>
                <div style={{ fontSize: 12, fontWeight: 600, color: '#ef4444', marginBottom: 2 }}>
                  Agent run failed
                </div>
                <div style={{ fontSize: 12, color: '#fca5a5', lineHeight: 1.5, wordBreak: 'break-word', overflowWrap: 'anywhere' }}>
                  {activeRun.error}
                  {activeRun.error?.includes('API key not configured') && (
                    <button
                      onClick={() => navigate('/settings')}
                      style={{
                        display: 'inline-flex', alignItems: 'center', gap: 4,
                        marginTop: 6, padding: '4px 10px', borderRadius: 4, border: 'none',
                        cursor: 'pointer', background: '#3b82f6', color: '#fff', fontSize: 11,
                      }}
                    >
                      <ExternalLink size={11} /> Go to Integrations
                    </button>
                  )}
                </div>
              </div>
            </div>
          )}
          {activeRun.output && (
            <div className="agent-markdown-output" style={{
              padding: '12px 16px', borderRadius: 6, background: 'var(--bg)',
              border: '1px solid var(--border)', fontSize: 13, lineHeight: 1.7,
              maxHeight: 500, overflowY: 'auto',
            }}>
              <ReactMarkdown
                remarkPlugins={[remarkGfm]}
                components={{
                  h1: ({ children }) => <h1 style={{ fontSize: 18, fontWeight: 700, margin: '16px 0 8px', borderBottom: '1px solid var(--border)', paddingBottom: 6 }}>{children}</h1>,
                  h2: ({ children }) => <h2 style={{ fontSize: 16, fontWeight: 700, margin: '14px 0 6px', color: 'var(--accent)' }}>{children}</h2>,
                  h3: ({ children }) => <h3 style={{ fontSize: 14, fontWeight: 600, margin: '12px 0 4px' }}>{children}</h3>,
                  p: ({ children }) => <p style={{ margin: '6px 0' }}>{children}</p>,
                  ul: ({ children }) => <ul style={{ margin: '4px 0', paddingLeft: 20 }}>{children}</ul>,
                  ol: ({ children }) => <ol style={{ margin: '4px 0', paddingLeft: 20 }}>{children}</ol>,
                  li: ({ children }) => <li style={{ margin: '2px 0' }}>{children}</li>,
                  strong: ({ children }) => <strong style={{ fontWeight: 700, color: 'var(--text)' }}>{children}</strong>,
                  // react-markdown v10 removed the `inline` prop — block code
                  // always has a `language-*` class and is wrapped in `<pre>`.
                  // Passthrough `pre` so our `code` handler owns the block
                  // wrapper (no double `<pre>`) and rich blocks aren't nested
                  // inside a real `<pre>`.
                  pre: ({ children }) => <>{children}</>,
                  code: ({ className, children }) => {
                    const match = /language-(\w+)/.exec(className || '')
                    const raw = String(children).replace(/\n$/, '')
                    const isBlock = !!match || raw.includes('\n')
                    if (!isBlock) {
                      return <code style={{ background: 'var(--bg-secondary)', padding: '1px 5px', borderRadius: 3, fontSize: 12, fontFamily: 'monospace' }}>{children}</code>
                    }
                    const lang = match ? match[1] : ''
                    const rich = tryRenderRichBlock(lang, raw)
                    if (rich) return rich
                    return <pre style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 6, padding: 10, overflowX: 'auto', fontSize: 12, fontFamily: 'monospace', margin: '8px 0', color: 'var(--text)' }}><code>{children}</code></pre>
                  },
                  table: ({ children }) => <table style={{ borderCollapse: 'collapse', width: '100%', margin: '8px 0', fontSize: 12 }}>{children}</table>,
                  th: ({ children }) => <th style={{ border: '1px solid var(--border)', padding: '6px 10px', background: 'var(--bg-secondary)', fontWeight: 600, textAlign: 'left' }}>{children}</th>,
                  td: ({ children }) => <td style={{ border: '1px solid var(--border)', padding: '5px 10px' }}>{children}</td>,
                  hr: () => <hr style={{ border: 'none', borderTop: '1px solid var(--border)', margin: '12px 0' }} />,
                  blockquote: ({ children }) => <blockquote style={{ borderLeft: '3px solid var(--accent)', paddingLeft: 12, margin: '8px 0', color: 'var(--text-muted)', fontStyle: 'italic' }}>{children}</blockquote>,
                }}
              >
                {activeRun.output}
              </ReactMarkdown>
            </div>
          )}
          {/* Trace accordion */}
          {activeRun.trace && activeRun.trace.length > 0 && (
            <TraceView trace={activeRun.trace} />
          )}
        </Card>
      )}

      {/* Run history */}
      <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-muted)' }}>History</div>
      {runs.map(r => (
        <Card
          key={r.id}
          onClick={() => loadRun(r)}
          style={{
            padding: '8px 12px', cursor: 'pointer', overflow: 'hidden',
            borderColor: activeRun?.id === r.id ? 'var(--accent)' : 'var(--border)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0, overflow: 'hidden' }}>
            <StatusBadge status={r.status} />
            <div style={{ flex: 1, minWidth: 0, fontSize: 12, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {r.input}
            </div>
            {!running && r.input && (
              <button
                onClick={e => { e.stopPropagation(); onRerun(r.input) }}
                title="Re-run with same input"
                style={{
                  display: 'flex', alignItems: 'center', padding: '2px 5px', borderRadius: 4,
                  border: '1px solid var(--border)', background: 'transparent',
                  color: 'var(--text-muted)', cursor: 'pointer', flexShrink: 0,
                }}
              >
                <Play size={11} />
              </button>
            )}
            <span style={{ fontSize: 11, color: 'var(--text-muted)', flexShrink: 0 }}>
              {r.created_at ? new Date(r.created_at).toLocaleString() : ''}
            </span>
          </div>
        </Card>
      ))}
      {runs.length === 0 && !activeRun && (
        <div style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: 13, padding: 24 }}>
          No runs yet. Type a message below and hit Run.
        </div>
      )}
    </div>
  )
}


// ── Schedule Panel ────────────────────────────────────────────────────

const CRON_PRESETS = [
  { label: 'Every weekday 8 AM', cron: '0 8 * * 1-5' },
  { label: 'Every Monday 9 AM', cron: '0 9 * * 1' },
  { label: 'Every day 7 AM', cron: '0 7 * * *' },
  { label: 'Every 6 hours', cron: '0 */6 * * *' },
  { label: 'First of month 9 AM', cron: '0 9 1 * *' },
]

function SchedulePanel({ agentId, agent, templates, schedules, onRefresh }) {
  const toast = useToast()
  const confirm = useConfirm()
  const [cronExpr, setCronExpr] = useState('0 8 * * 1-5')

  // Derive a default message from the matching template's suggested_input, or from the agent name
  const defaultMessage = useMemo(() => {
    if (templates && agent) {
      const match = templates.find(t => t.name === agent.name)
      if (match?.suggested_input) return match.suggested_input
    }
    if (agent?.name) return `Run ${agent.name} for the latest scan.`
    return 'Run the agent for the latest scan.'
  }, [agent, templates])

  const [schedInput, setSchedInput] = useState(defaultMessage)
  const [creating, setCreating] = useState(false)

  // Reset the input when switching agents
  useEffect(() => { setSchedInput(defaultMessage) }, [defaultMessage])

  const handleCreate = async () => {
    if (!cronExpr || !schedInput.trim()) return
    setCreating(true)
    try {
      await createAgentSchedule({
        agent_id: agentId,
        cron_expression: cronExpr,
        input: schedInput.trim(),
      })
      capture('agent_scheduled', {
        agent_id: agentId,
        cron_expression: cronExpr,
      })
      onRefresh()
      toast.success('Schedule created')
    } catch (e) {
      toast.error(e.message)
    } finally {
      setCreating(false)
    }
  }

  const handleToggle = async (sched) => {
    await updateAgentSchedule(sched.id, { is_enabled: !sched.is_enabled })
    onRefresh()
  }

  const handleDelete = async (sched) => {
    if (!await confirm('Delete this schedule?')) return
    await deleteAgentSchedule(sched.id)
    onRefresh()
    toast.success('Schedule deleted')
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16, paddingTop: 8 }}>
      <Section icon={Calendar} title="Scheduled Runs">
        <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 8 }}>
          Set up this agent to run automatically on a cron schedule.
        </div>

        {/* Existing schedules */}
        {schedules.length > 0 && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 16 }}>
            {schedules.map(s => (
              <Card key={s.id} style={{ padding: '10px 12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <button
                    onClick={() => handleToggle(s)}
                    style={{
                      width: 36, height: 20, borderRadius: 10, border: 'none', cursor: 'pointer',
                      background: s.is_enabled ? 'var(--accent)' : 'var(--border)',
                      position: 'relative', transition: 'background 0.2s',
                    }}
                  >
                    <div style={{
                      width: 16, height: 16, borderRadius: 8, background: '#fff',
                      position: 'absolute', top: 2,
                      left: s.is_enabled ? 18 : 2, transition: 'left 0.2s',
                    }} />
                  </button>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 12, fontFamily: 'monospace', fontWeight: 600 }}>{s.cron_expression}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {s.input}
                    </div>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
                      {s.last_run_at ? `Last: ${new Date(s.last_run_at).toLocaleString()}` : 'Never run'}
                      {s.next_run_at && ` | Next: ${new Date(s.next_run_at).toLocaleString()}`}
                    </div>
                  </div>
                  <button
                    onClick={() => handleDelete(s)}
                    style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#ef4444' }}
                  >
                    <Trash2 size={14} />
                  </button>
                </div>
              </Card>
            ))}
          </div>
        )}

        {/* New schedule form */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10, padding: 12, borderRadius: 8, border: '1px solid var(--border)', background: 'var(--bg)' }}>
          <div style={{ fontSize: 12, fontWeight: 600 }}>Add Schedule</div>

          {/* Cron presets */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
            {CRON_PRESETS.map(p => (
              <button
                key={p.cron}
                onClick={() => setCronExpr(p.cron)}
                style={{
                  padding: '4px 8px', borderRadius: 4, fontSize: 11,
                  border: cronExpr === p.cron ? '1px solid var(--accent)' : '1px solid var(--border)',
                  background: cronExpr === p.cron ? 'color-mix(in srgb, var(--accent) 15%, transparent)' : 'transparent',
                  color: cronExpr === p.cron ? 'var(--accent)' : 'var(--text-muted)',
                  cursor: 'pointer',
                }}
              >
                {p.label}
              </button>
            ))}
          </div>

          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <label style={{ fontSize: 12, color: 'var(--text-secondary)', flexShrink: 0 }}>Cron:</label>
            <input
              value={cronExpr}
              onChange={e => setCronExpr(e.target.value)}
              placeholder="0 8 * * 1-5"
              style={{
                flex: 1, padding: '6px 10px', borderRadius: 6, border: '1px solid var(--border)',
                background: 'var(--bg-card)', color: 'var(--text-primary)', fontSize: 12, fontFamily: 'monospace', outline: 'none',
              }}
            />
          </div>

          <textarea
            value={schedInput}
            onChange={e => setSchedInput(e.target.value)}
            rows={2}
            placeholder="What should the agent do each time?"
            style={{
              padding: '8px 10px', borderRadius: 6, border: '1px solid var(--border)',
              background: 'var(--bg-card)', color: 'var(--text-primary)', fontSize: 12, resize: 'vertical', outline: 'none',
            }}
          />

          <button
            onClick={handleCreate}
            disabled={creating || !cronExpr || !schedInput.trim()}
            style={{
              padding: '8px 16px', borderRadius: 6, border: 'none',
              background: 'var(--accent)', color: '#fff', fontSize: 12, fontWeight: 600,
              cursor: creating ? 'not-allowed' : 'pointer', opacity: creating ? 0.6 : 1,
              alignSelf: 'flex-start',
            }}
          >
            {creating ? 'Creating...' : 'Create Schedule'}
          </button>
        </div>
      </Section>
    </div>
  )
}




// ── Shared components ─────────────────────────────────────────────────

function TraceView({ trace }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div style={{ marginTop: 12 }}>
      <button
        onClick={() => setExpanded(!expanded)}
        style={{
          display: 'flex', alignItems: 'center', gap: 4,
          background: 'transparent', border: 'none', cursor: 'pointer',
          color: 'var(--text-muted)', fontSize: 12, fontWeight: 600, padding: 0,
        }}
      >
        {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        Trace ({trace.length} entries)
      </button>
      {expanded && (
        <div style={{
          marginTop: 8, display: 'flex', flexDirection: 'column', gap: 6,
          maxHeight: 400, overflowY: 'auto',
        }}>
          {trace.map((entry, i) => (
            <div
              key={i}
              style={{
                padding: 8, borderRadius: 6, fontSize: 12, fontFamily: 'monospace',
                background: entry.role === 'tool' ? '#1a1a2e' : 'var(--bg)',
                border: '1px solid var(--border)',
              }}
            >
              <div style={{ fontWeight: 600, color: entry.role === 'tool' ? '#818cf8' : 'var(--accent)', marginBottom: 4 }}>
                {entry.role === 'tool' ? `tool: ${entry.tool_name}` : `assistant (step ${entry.step})`}
              </div>
              <pre style={{
                margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                color: 'var(--text-secondary)', maxHeight: 200, overflow: 'auto',
              }}>
                {entry.role === 'tool'
                  ? (typeof entry.output === 'string' ? entry.output : JSON.stringify(entry.output, null, 2))
                  : entry.content?.map(b => b.type === 'text' ? b.text : `[tool_use: ${b.name}(${JSON.stringify(b.input)})]`).join('\n')
                }
              </pre>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}


// ── Tool Categories ──────────────────────────────────────────────────
const TOOL_CATEGORIES = [
  { id: 'findings', label: 'Findings & Vulnerabilities', match: ['query_findings', 'get_finding_detail', 'get_exploit_findings', 'get_regression_findings', 'get_quick_wins', 'get_plugin_family_stats', 'update_finding_status', 'correlate_cves_with_findings', 'get_blast_radius'] },
  { id: 'assets', label: 'Assets & Inventory', match: ['query_assets', 'get_asset_profile', 'get_top_risky_assets', 'tag_assets', 'get_inventory_users', 'get_inventory_services', 'get_network_connections', 'get_missing_patches', 'get_installed_software', 'get_certificates', 'get_writeable_shares', 'get_os_breakdown', 'get_internet_facing_risk', 'get_security_controls'] },
  { id: 'scans', label: 'Scans & EASM', match: ['list_scans', 'get_scan_summary', 'compare_scans', 'delete_scan', 'rename_scan', 'trigger_easm_scan', 'check_easm_scan_status', 'list_easm_domains'] },
  { id: 'tags', label: 'Tags & Auto-Tag Rules', match: ['list_tags', 'get_tag_stats', 'create_tag', 'manage_tag', 'bulk_tag_findings', 'create_auto_tag_rule', 'manage_auto_tag_rule', 'run_auto_tag_rules'] },
  { id: 'campaigns', label: 'Campaigns & SLA', match: ['create_campaign', 'list_campaigns', 'get_campaign', 'get_remediation_grouping', 'get_sla_status', 'get_sla_config', 'update_sla_config', 'recalculate_sla', 'get_owner_workload'] },
  { id: 'exceptions', label: 'Exceptions', match: ['create_exception', 'list_exceptions', 'manage_exception'] },
  { id: 'risk', label: 'Risk & Prioritization', match: ['get_risk_config', 'update_risk_config', 'manage_criticality_rules', 'recalculate_risk_scores', 'analyze_attack_surface', 'get_dedup_config', 'update_dedup_config', 'run_dedup'] },
  { id: 'threat', label: 'Threat Intelligence', match: ['get_threat_groups', 'get_threat_cves', 'get_threat_campaigns', 'get_ttps'] },
  { id: 'integrations', label: 'Integrations', match: ['list_integrations', 'call_integration_fetch', 'call_integration_push', 'create_jira_ticket', 'create_servicenow_ticket', 'list_integration_builder_connectors', 'get_integration_builder_connector_detail', 'get_integration_builder_targets', 'list_integration_credentials', 'create_integration_credential', 'create_integration', 'update_integration', 'get_integration_detail', 'manage_integration', 'get_integration_runs', 'suggest_field_mapping'] },
  { id: 'notifications', label: 'Notifications', match: ['send_slack_message', 'send_teams_message', 'send_email_alert', 'send_webhook'] },
  { id: 'workflows', label: 'Workflows', match: ['list_workflows', 'get_workflow_detail', 'get_workflow_execution', 'create_campaign_workflow', 'create_workflow_from_template', 'list_workflow_templates', 'run_workflow', 'toggle_workflow', 'get_workflow_status_summary'] },
  { id: 'agents', label: 'Agents', match: ['list_agents', 'get_agent_run', 'recommend_agents', 'create_agent', 'create_agent_schedule'] },
  { id: 'ownership', label: 'Ownership & Roles', match: ['list_ownership_rules', 'manage_ownership_rule', 'run_ownership_rules', 'list_custom_roles', 'manage_custom_role'] },
  { id: 'reports', label: 'Reports & Documents', match: ['build_report', 'search_documents', 'suggest_tagging_schema'] },
  { id: 'siem', label: 'SIEM & Alerts', match: ['query_events', 'get_event_context', 'list_alerts', 'get_alert_with_events', 'update_alert_status', 'run_detection_rule_now', 'triage_alert', 'query_siem_events', 'get_exposure_context'] },
  { id: 'utility', label: 'Utility', match: ['read_scratchpad', 'write_scratchpad', 'clear_scratchpad', 'request_clarification', 'search_web', 'fetch_url', 'run_sql_query'] },
]

function categorizeTools(toolCatalog) {
  const assigned = new Set()
  const categories = TOOL_CATEGORIES.map(cat => {
    const tools = toolCatalog.filter(t => cat.match.includes(t.name))
    tools.forEach(t => assigned.add(t.name))
    return { ...cat, tools }
  })
  const uncategorized = toolCatalog.filter(t => !assigned.has(t.name))
  if (uncategorized.length > 0) {
    categories.push({ id: 'other', label: 'Other', tools: uncategorized, match: [] })
  }
  return categories.filter(c => c.tools.length > 0)
}

function ToolSelector({ tools, toolCatalog, toggleTool, setEditing, editing }) {
  const [search, setSearch] = useState('')
  const [collapsed, setCollapsed] = useState({})
  const [showSelected, setShowSelected] = useState(false)

  const categories = useMemo(() => categorizeTools(toolCatalog), [toolCatalog])

  const filtered = useMemo(() => {
    const q = search.toLowerCase()
    return categories.map(cat => {
      let catTools = cat.tools
      if (q) catTools = catTools.filter(t => t.name.includes(q) || t.description?.toLowerCase().includes(q))
      if (showSelected) catTools = catTools.filter(t => tools.includes(t.name))
      return { ...cat, tools: catTools }
    }).filter(c => c.tools.length > 0)
  }, [categories, search, showSelected, tools])

  const toggleCategory = (catTools) => {
    const catNames = catTools.map(t => t.name)
    const allSelected = catNames.every(n => tools.includes(n))
    const next = allSelected
      ? tools.filter(n => !catNames.includes(n))
      : [...new Set([...tools, ...catNames])]
    setEditing({ ...editing, tools: next })
  }

  const selectAll = () => setEditing({ ...editing, tools: toolCatalog.map(t => t.name) })
  const selectNone = () => setEditing({ ...editing, tools: [] })

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {/* Search + filters row */}
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <div style={{ position: 'relative', flex: 1, minWidth: 180 }}>
          <Search size={14} style={{ position: 'absolute', left: 8, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', pointerEvents: 'none' }} />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search tools..."
            style={{
              width: '100%', padding: '6px 10px 6px 28px', borderRadius: 6, fontSize: 12,
              border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text-primary)', outline: 'none',
            }}
          />
        </div>
        <button onClick={() => setShowSelected(!showSelected)} style={{
          padding: '5px 10px', borderRadius: 6, fontSize: 11, fontWeight: 600, cursor: 'pointer',
          border: `1px solid ${showSelected ? 'var(--accent)' : 'var(--border)'}`,
          background: showSelected ? 'color-mix(in srgb, var(--accent) 15%, transparent)' : 'transparent',
          color: showSelected ? 'var(--accent)' : 'var(--text-muted)',
        }}>
          Selected ({tools.length})
        </button>
        <button onClick={selectAll} style={{ padding: '5px 8px', borderRadius: 6, fontSize: 11, cursor: 'pointer', border: '1px solid var(--border)', background: 'transparent', color: 'var(--text-muted)' }}>
          All
        </button>
        <button onClick={selectNone} style={{ padding: '5px 8px', borderRadius: 6, fontSize: 11, cursor: 'pointer', border: '1px solid var(--border)', background: 'transparent', color: 'var(--text-muted)' }}>
          None
        </button>
      </div>

      {/* Categories */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
        {filtered.map(cat => {
          const isCollapsed = collapsed[cat.id]
          const selectedCount = cat.tools.filter(t => tools.includes(t.name)).length
          const allSelected = cat.tools.length > 0 && selectedCount === cat.tools.length
          return (
            <div key={cat.id}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 4px', cursor: 'pointer', userSelect: 'none' }}>
                <div onClick={() => setCollapsed(p => ({ ...p, [cat.id]: !isCollapsed }))} style={{ display: 'flex', alignItems: 'center', gap: 6, flex: 1 }}>
                  {isCollapsed ? <ChevronRight size={12} color="var(--text-muted)" /> : <ChevronDown size={12} color="var(--text-muted)" />}
                  <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)' }}>{cat.label}</span>
                  <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                    {selectedCount > 0 ? `${selectedCount}/${cat.tools.length}` : cat.tools.length}
                  </span>
                </div>
                <button
                  onClick={() => toggleCategory(cat.tools)}
                  style={{
                    padding: '2px 6px', borderRadius: 4, fontSize: 10, fontWeight: 600, cursor: 'pointer',
                    border: '1px solid var(--border)', background: allSelected ? 'color-mix(in srgb, var(--accent) 12%, transparent)' : 'transparent',
                    color: allSelected ? 'var(--accent)' : 'var(--text-muted)',
                  }}
                >
                  {allSelected ? '✓ all' : 'select all'}
                </button>
              </div>
              {!isCollapsed && (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, padding: '2px 0 8px 20px' }}>
                  {cat.tools.map(tool => {
                    const active = tools.includes(tool.name)
                    return (
                      <button
                        key={tool.name}
                        onClick={() => toggleTool(tool.name)}
                        title={tool.description}
                        style={{
                          padding: '4px 9px', borderRadius: 6, fontSize: 11, fontWeight: 500,
                          cursor: 'pointer', transition: 'all 0.15s',
                          border: `1px solid ${active ? 'var(--accent)' : 'var(--border)'}`,
                          background: active ? 'color-mix(in srgb, var(--accent) 15%, transparent)' : 'transparent',
                          color: active ? 'var(--accent)' : 'var(--text-muted)',
                        }}
                      >
                        {tool.name}
                      </button>
                    )
                  })}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}


function Section({ icon: Icon, title, children }) {
  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8, fontSize: 13, fontWeight: 600, color: 'var(--text-secondary)' }}>
        <Icon size={14} /> {title}
      </div>
      {children}
    </div>
  )
}


function StatusBadge({ status }) {
  const { Icon, color } = STATUS_ICON[status] || STATUS_ICON.pending
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, color, fontSize: 12, fontWeight: 600 }}>
      <Icon size={14} style={status === 'running' ? { animation: 'spin 1s linear infinite' } : undefined} /> {status}
    </span>
  )
}
