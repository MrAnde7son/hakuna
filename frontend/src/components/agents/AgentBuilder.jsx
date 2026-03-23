/**
 * Mini Agent Builder — create, configure, and run user-defined agents.
 * Features: templates gallery, streaming output, cron schedules.
 */
import { useState, useEffect, useRef, useCallback } from 'react'
import ReactMarkdown from 'react-markdown'
import { Card, ErrorBanner } from '../shared/ui.jsx'
import { useNavigate } from 'react-router-dom'
import {
  Bot, Plus, Trash2, Play, ChevronDown, ChevronRight, Clock, CheckCircle,
  XCircle, Loader2, Settings2, MessageSquare, Wrench, Shield, Brain,
  Zap, Calendar, Copy, Clipboard, Briefcase, Target, Ticket, Radio, AlarmClock,
  Download, Upload, Tag, AlertCircle, FileText, Paperclip, ExternalLink, Search,
} from 'lucide-react'
import {
  getAgents, createAgent, updateAgent, deleteAgent,
  runAgent, getAgentRuns, getAgentRun, getAgentToolCatalog,
  getAgentTemplates, createAgentFromTemplate,
  getAgentSchedules, createAgentSchedule, updateAgentSchedule, deleteAgentSchedule,
  exportAgent, importAgent,
  getAgentDocuments, uploadAgentDocument, deleteAgentDocument,
  getAvailableModels, getAgentApprovals,
} from '../../api.js'
import AgentApprovalQueue from './AgentApprovalQueue.jsx'

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
  // Google Gemini
  { value: 'gemini-2.5-flash', label: 'Gemini 2.5 Flash', group: 'Google' },
  { value: 'gemini-2.5-pro', label: 'Gemini 2.5 Pro', group: 'Google' },
  { value: 'gemini-2.0-flash', label: 'Gemini 2.0 Flash', group: 'Google' },
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

export default function AgentBuilder() {
  const navigate = useNavigate()
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
  const [schedules, setSchedules] = useState([])
  const [documents, setDocuments] = useState([])
  const inputRef = useRef()
  const importRef = useRef()
  const streamRef = useRef(null) // for aborting streams
  const [fetchError, setFetchError] = useState(null)

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
  }, [])

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
    await refresh()
    selectAgent(agent)
  }

  const handleFromTemplate = async (template) => {
    setShowTemplates(false)
    const agent = await createAgentFromTemplate({ template_id: template.id })
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
    } catch (e) {
      alert('Export failed: ' + e.message)
    }
  }

  const handleImportFile = async (e) => {
    const file = e.target.files?.[0]
    if (!file) return
    try {
      const text = await file.text()
      const config = JSON.parse(text)
      if (!config.name || !config.system_prompt) {
        alert('Invalid agent file: must contain "name" and "system_prompt".')
        return
      }
      const agent = await importAgent(config)
      await refresh()
      selectAgent(agent)
    } catch (err) {
      alert('Import failed: ' + err.message)
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
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async () => {
    if (!selected) return
    if (!confirm(`Delete agent "${selected.name}"?`)) return
    await deleteAgent(selected.id)
    setSelected(null)
    setEditing(null)
    refresh()
  }

  // ── Streaming run ────────────────────────────────────────────────
  const handleRun = async () => {
    if (!selected || !runInput.trim() || running) return
    setRunning(true)
    setTab('runs')
    setActiveRun({ status: 'running', output: '', trace: [] })
    setStreamEvents([])

    const input = runInput.trim()
    setRunInput('')

    try {
      // Try streaming first
      const resp = await fetch(`/api/agents/${selected.id}/run/stream`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input }),
      })

      if (!resp.ok || !resp.body) {
        // Fall back to non-streaming
        const result = await runAgent(selected.id, input)
        setActiveRun(result)
        getAgentRuns(selected.id).then(setRuns).catch(() => {})
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

      getAgentRuns(selected.id).then(setRuns).catch(() => {})
    } catch (e) {
      setActiveRun({ status: 'failed', error: e.message, trace: [] })
    } finally {
      setRunning(false)
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
      <ErrorBanner error={fetchError} onRetry={refresh} onDismiss={() => setFetchError(null)} />
    <div style={{ display: 'flex', gap: 18, height: 'calc(100vh - 72px)' }}>
      {/* Left panel — agent list */}
      <div style={{ width: 260, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 8 }}>
        <div style={{ marginBottom: 4 }}>
          <h2 style={{ fontSize: 18, fontWeight: 700, marginBottom: 8 }}>Agents</h2>
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

        <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 4 }}>
          {agents.map(a => (
            <Card
              key={a.id}
              onClick={() => selectAgent(a)}
              style={{
                padding: '10px 12px', cursor: 'pointer',
                borderColor: selected?.id === a.id ? 'var(--accent)' : 'var(--border)',
                background: selected?.id === a.id ? 'var(--bg)' : 'var(--bg-card)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Bot size={16} color="var(--accent)" />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 13, fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.name}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {a.description || 'No description'}
                  </div>
                </div>
              </div>
            </Card>
          ))}
          {agents.length === 0 && !showTemplates && (
            <div style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: 13, padding: 24 }}>
              No agents yet. Click "Templates" for presets or "New" for a blank agent.
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
            onPendingCount={setPendingApprovalCount}
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
              />
            ) : (
              <SchedulePanel
                agentId={selected.id}
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
      ) : (
        <div style={{
          flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
          color: 'var(--text-muted)', fontSize: 14,
        }}>
          Select an agent or create a new one to get started.
        </div>
      )}
    </div>
    </div>
  )
}


// ── Template Gallery ──────────────────────────────────────────────────

function TemplateGallery({ templates, onCreate, onClose }) {
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
        <button
          onClick={onClose}
          style={{
            background: 'transparent', border: '1px solid var(--border)', borderRadius: 6,
            padding: '6px 14px', cursor: 'pointer', color: 'var(--text-muted)', fontSize: 12, fontWeight: 600,
          }}
        >
          Close
        </button>
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
          No templates match "{search}"
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


// ── Config Panel ──────────────────────────────────────────────────────

function ConfigPanel({ editing, setEditing, toolCatalog, toggleTool, updateGuardrail, agentId, documents, onDocumentsChange, availableModels, navigate }) {
  const docInputRef = useRef()
  const [uploading, setUploading] = useState(false)

  const handleDocUpload = async (e) => {
    const file = e.target.files?.[0]
    if (!file) return
    setUploading(true)
    try {
      await uploadAgentDocument(agentId, file)
      onDocumentsChange()
    } catch (err) {
      alert('Upload failed: ' + err.message)
    } finally {
      setUploading(false)
      e.target.value = ''
    }
  }

  const handleDocDelete = async (docId) => {
    if (!confirm('Remove this document?')) return
    try {
      await deleteAgentDocument(agentId, docId)
      onDocumentsChange()
    } catch (err) {
      alert('Delete failed: ' + err.message)
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
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
          {toolCatalog.map(tool => {
            const active = (editing.tools || []).includes(tool.name)
            return (
              <button
                key={tool.name}
                onClick={() => toggleTool(tool.name)}
                title={tool.description}
                style={{
                  padding: '5px 10px', borderRadius: 6, fontSize: 12, fontWeight: 500,
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
              value={editing.model || availableModels?.default_model || 'claude-sonnet-4-6'}
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

function RunsPanel({ runs, activeRun, setActiveRun, selected, streamEvents, running, navigate }) {
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
          </div>

          {/* Streaming events (live tool call feed) */}
          {running && streamEvents.length > 0 && (
            <div style={{
              marginBottom: 12, padding: 10, borderRadius: 6,
              background: '#0f172a', border: '1px solid #1e293b',
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
                components={{
                  h1: ({ children }) => <h1 style={{ fontSize: 18, fontWeight: 700, margin: '16px 0 8px', borderBottom: '1px solid var(--border)', paddingBottom: 6 }}>{children}</h1>,
                  h2: ({ children }) => <h2 style={{ fontSize: 16, fontWeight: 700, margin: '14px 0 6px', color: 'var(--accent)' }}>{children}</h2>,
                  h3: ({ children }) => <h3 style={{ fontSize: 14, fontWeight: 600, margin: '12px 0 4px' }}>{children}</h3>,
                  p: ({ children }) => <p style={{ margin: '6px 0' }}>{children}</p>,
                  ul: ({ children }) => <ul style={{ margin: '4px 0', paddingLeft: 20 }}>{children}</ul>,
                  ol: ({ children }) => <ol style={{ margin: '4px 0', paddingLeft: 20 }}>{children}</ol>,
                  li: ({ children }) => <li style={{ margin: '2px 0' }}>{children}</li>,
                  strong: ({ children }) => <strong style={{ fontWeight: 700, color: 'var(--text)' }}>{children}</strong>,
                  code: ({ inline, children }) => inline
                    ? <code style={{ background: 'var(--bg-secondary)', padding: '1px 5px', borderRadius: 3, fontSize: 12, fontFamily: 'monospace' }}>{children}</code>
                    : <pre style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 6, padding: 10, overflowX: 'auto', fontSize: 12, fontFamily: 'monospace', margin: '8px 0' }}><code>{children}</code></pre>,
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

function SchedulePanel({ agentId, schedules, onRefresh }) {
  const [cronExpr, setCronExpr] = useState('0 8 * * 1-5')
  const [schedInput, setSchedInput] = useState('Run the daily triage for the latest scan.')
  const [creating, setCreating] = useState(false)

  const handleCreate = async () => {
    if (!cronExpr || !schedInput.trim()) return
    setCreating(true)
    try {
      await createAgentSchedule({
        agent_id: agentId,
        cron_expression: cronExpr,
        input: schedInput.trim(),
      })
      onRefresh()
    } catch (e) {
      alert(e.message)
    } finally {
      setCreating(false)
    }
  }

  const handleToggle = async (sched) => {
    await updateAgentSchedule(sched.id, { is_enabled: !sched.is_enabled })
    onRefresh()
  }

  const handleDelete = async (sched) => {
    if (!confirm('Delete this schedule?')) return
    await deleteAgentSchedule(sched.id)
    onRefresh()
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
      <Icon size={14} /> {status}
    </span>
  )
}
