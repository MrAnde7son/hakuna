import React, { useEffect, useMemo, useState, useCallback } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import {
  Check, ChevronLeft, ChevronRight, X, Plus, Copy, Mail,
  Users, Bot, GitBranch, Shield, Clock, Rocket, Link as LinkIcon,
  AlertCircle,
} from 'lucide-react'
import {
  Card, Button, Pill, Spinner, useToast, PageHeader,
} from '../shared/ui.jsx'
import {
  getAggregatedSolution, createCampaign,
  inviteCampaignCollaborator, authListUsers, getAgents,
  getWorkflowTemplates,
} from '../../api.js'

// Generates a random URL-safe token (~43 chars) for demo share links when
// the backend's collaborator endpoint isn't available.
function cryptoRandomToken() {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return (crypto.randomUUID() + crypto.randomUUID()).replace(/-/g, '').slice(0, 43)
  }
  // Very-old-browser fallback (not used in practice).
  return Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2)
}

// 6-digit numeric passcode.
function cryptoRandomPasscode() {
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    const buf = new Uint32Array(1)
    crypto.getRandomValues(buf)
    return String(buf[0] % 1_000_000).padStart(6, '0')
  }
  return String(Math.floor(Math.random() * 1_000_000)).padStart(6, '0')
}

// API responses aren't uniform — some endpoints return `{agents: [...]}`,
// others return bare arrays, others `{templates: [...]}`. Coerce to array so
// list renderers don't blow up on a wrapper object.
function asArray(value, wrapperKeys = []) {
  if (Array.isArray(value)) return value
  if (value && typeof value === 'object') {
    for (const key of wrapperKeys) {
      if (Array.isArray(value[key])) return value[key]
    }
    // Last resort: find first array-valued property.
    for (const v of Object.values(value)) {
      if (Array.isArray(v)) return v
    }
  }
  return []
}

// Compute a cheap relevance score between an agent/workflow and the
// aggregated solution the user is launching a campaign for. Used to pre-check
// and surface "Recommended" items at the top of the list.
//
// Heuristic only — no ML. Keyword match on the item's name+description against
// words derived from the solution's component, root_cause_type, and action_type.
const GENERIC_REMEDIATION_TERMS = [
  'patch', 'upgrade', 'remediation', 'vulnerability', 'cve', 'migrate', 'fix',
]

function computeRelevance(item, solution) {
  if (!item || !solution) return 0
  const text = `${item.name || ''} ${item.description || ''}`.toLowerCase()
  const kw = [
    solution.affected_component,
    solution.target_version,
    (solution.root_cause_type || '').replace(/_/g, ' '),
    (solution.action_type || '').replace(/_/g, ' '),
  ].filter(Boolean).map(s => String(s).toLowerCase())
  let score = 0
  for (const k of kw) if (k && text.includes(k)) score += 3
  for (const g of GENERIC_REMEDIATION_TERMS) if (text.includes(g)) score += 1
  return score
}

const RECOMMENDED_THRESHOLD = 2

function rankAndTag(items, solution) {
  // Returns items sorted by relevance descending, with { __score, __recommended } tags.
  return [...items]
    .map(it => {
      const score = computeRelevance(it, solution)
      return { ...it, __score: score, __recommended: score >= RECOMMENDED_THRESHOLD }
    })
    .sort((a, b) => (b.__score - a.__score) || String(a.name).localeCompare(String(b.name)))
}

// ─── Small primitives (styled to match OnboardingWizard conventions) ──────

function StepIndicator({ steps, current }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: 32 }}>
      {steps.map((s, i) => {
        const done = i < current
        const active = i === current
        return (
          <React.Fragment key={s.id}>
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6, minWidth: 84 }}>
              <div style={{
                width: 32, height: 32, borderRadius: '50%',
                display: 'grid', placeItems: 'center',
                fontSize: 13, fontWeight: 700,
                background: done ? 'var(--success)' : active ? 'var(--accent)' : 'var(--bg-secondary)',
                color: done || active ? '#fff' : 'var(--text-muted)',
                transition: 'all 0.2s',
              }}>
                {done ? <Check size={15} /> : i + 1}
              </div>
              <span style={{
                fontSize: 11, fontWeight: active ? 700 : 500,
                color: active ? 'var(--text)' : 'var(--text-muted)',
                textAlign: 'center',
              }}>
                {s.label}
              </span>
            </div>
            {i < steps.length - 1 && (
              <div style={{
                flex: 1, height: 2, maxWidth: 56,
                background: done ? 'var(--success)' : 'var(--border)',
                marginBottom: 22,
                transition: 'background 0.2s',
              }} />
            )}
          </React.Fragment>
        )
      })}
    </div>
  )
}

function SectionHeading({ title, sub }) {
  return (
    <div style={{ marginBottom: 20 }}>
      <h2 style={{ fontSize: 20, fontWeight: 700, color: 'var(--text)', margin: 0 }}>
        {title}
      </h2>
      {sub && (
        <p style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 4, marginBottom: 0 }}>
          {sub}
        </p>
      )}
    </div>
  )
}

const inputStyle = {
  width: '100%',
  padding: '10px 12px',
  borderRadius: 8,
  border: '1px solid var(--border)',
  background: 'var(--bg-card)',
  color: 'var(--text)',
  fontSize: 14,
  outline: 'none',
  boxSizing: 'border-box',
}

function TextField({ label, value, onChange, placeholder, type = 'text', multiline }) {
  const Tag = multiline ? 'textarea' : 'input'
  return (
    <label style={{ display: 'block', marginBottom: 16 }}>
      <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text)', marginBottom: 6 }}>
        {label}
      </div>
      <Tag
        type={type}
        value={value || ''}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        rows={multiline ? 3 : undefined}
        style={{ ...inputStyle, resize: multiline ? 'vertical' : undefined, fontFamily: 'inherit' }}
      />
    </label>
  )
}

function ToggleRow({ selected, onToggle, children }) {
  return (
    <div
      onClick={onToggle}
      style={{
        border: `2px solid ${selected ? 'var(--primary)' : 'var(--border)'}`,
        background: selected ? 'color-mix(in srgb, var(--primary) 7%, var(--bg-card))' : 'var(--bg-card)',
        borderRadius: 8,
        padding: '10px 14px',
        cursor: 'pointer',
        marginBottom: 8,
        display: 'flex', alignItems: 'center', gap: 10,
        transition: 'all 0.15s',
      }}
    >
      <div style={{
        width: 18, height: 18, borderRadius: 4,
        border: `2px solid ${selected ? 'var(--primary)' : 'var(--border)'}`,
        background: selected ? 'var(--primary)' : 'transparent',
        display: 'grid', placeItems: 'center', flexShrink: 0,
      }}>
        {selected && <Check size={11} color="#fff" />}
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        {children}
      </div>
    </div>
  )
}

// ─── Step 1: Review ───────────────────────────────────────────────────────

function StepReview({ state, setState, preview }) {
  return (
    <div>
      <SectionHeading
        title="Review campaign"
        sub="Name, describe, and scope. The finding count updates as you edit."
      />
      <TextField label="Name" value={state.name}
        onChange={v => setState(s => ({ ...s, name: v }))} />
      <TextField label="Description" value={state.description}
        onChange={v => setState(s => ({ ...s, description: v }))} multiline />
      <Card style={{ padding: 16, background: 'var(--bg-muted)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, fontSize: 13 }}>
          <div>
            <div style={{ color: 'var(--text-muted)', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Findings
            </div>
            <div style={{ fontWeight: 700, fontSize: 20, color: 'var(--text)' }}>
              {preview?.finding_count?.toLocaleString() ?? '—'}
            </div>
          </div>
          <div>
            <div style={{ color: 'var(--text-muted)', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Assets
            </div>
            <div style={{ fontWeight: 700, fontSize: 20, color: 'var(--text)' }}>
              {preview?.asset_count?.toLocaleString() ?? '—'}
            </div>
          </div>
          <div style={{ flex: 1 }} />
          {preview?.loading && <Spinner />}
        </div>
      </Card>
    </div>
  )
}

// ─── Steps 2 & 3: Automations (Agents + Workflows, split) ────────────────

// One row with optional "Recommended" pill, used in both StepAgents and StepWorkflows.
function AutomationRow({ item, selected, onToggle }) {
  return (
    <ToggleRow selected={selected} onToggle={onToggle}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text)' }}>
          {item.name}
        </div>
        {item.__recommended && (
          <span style={{
            display: 'inline-flex', alignItems: 'center', gap: 4,
            fontSize: 10, fontWeight: 700, letterSpacing: '0.04em',
            color: 'var(--primary)',
            background: 'color-mix(in srgb, var(--primary) 12%, transparent)',
            border: '1px solid var(--primary)',
            borderRadius: 999, padding: '1px 7px',
            textTransform: 'uppercase',
          }}>
            <Check size={9} /> Recommended
          </span>
        )}
      </div>
      {item.description && (
        <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
          {String(item.description).slice(0, 160)}
        </div>
      )}
    </ToggleRow>
  )
}

// Shared list renderer — recommended items group up top, visually separated
// from the rest with a thin label so users can see what's been pre-picked.
function AutomationList({ items, selectedIds, onToggle, emptyText, icon: Icon }) {
  if (!items) return <Spinner />
  if (items.length === 0) {
    return (
      <div style={{ fontSize: 13, color: 'var(--text-muted)', padding: '12px 0' }}>
        {emptyText}
      </div>
    )
  }
  const recommended = items.filter(i => i.__recommended)
  const rest = items.filter(i => !i.__recommended)
  const labelStyle = {
    fontSize: 11, fontWeight: 600, textTransform: 'uppercase',
    letterSpacing: '0.05em', color: 'var(--text-muted)',
    margin: '8px 0 6px',
  }
  return (
    <>
      {recommended.length > 0 && (
        <>
          <div style={labelStyle}>Recommended for this campaign</div>
          {recommended.map(it => (
            <AutomationRow
              key={it.id}
              item={it}
              selected={selectedIds.includes(it.id)}
              onToggle={() => onToggle(it.id)}
            />
          ))}
        </>
      )}
      {rest.length > 0 && (
        <>
          {recommended.length > 0 && <div style={labelStyle}>Others</div>}
          {rest.map(it => (
            <AutomationRow
              key={it.id}
              item={it}
              selected={selectedIds.includes(it.id)}
              onToggle={() => onToggle(it.id)}
            />
          ))}
        </>
      )}
    </>
  )
}

function StepAgents({ state, setState, agents }) {
  const toggle = (id) => setState(s => {
    const cur = new Set(s.selectedAgentIds)
    if (cur.has(id)) cur.delete(id); else cur.add(id)
    return { ...s, selectedAgentIds: Array.from(cur) }
  })
  return (
    <div>
      <SectionHeading
        title="Attach agents"
        sub="AI agents run against the campaign context — e.g. triage, explain, escalate. Recommended ones are pre-selected."
      />
      <div style={{
        fontSize: 12, fontWeight: 600, color: 'var(--text)',
        display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8,
      }}>
        <Bot size={14} /> Agents
      </div>
      <AutomationList
        items={agents}
        selectedIds={state.selectedAgentIds}
        onToggle={toggle}
        emptyText="No agents configured yet. Skip this step or add agents from the sidebar."
      />
    </div>
  )
}

function StepWorkflows({ state, setState, workflows }) {
  const toggle = (id) => setState(s => {
    const cur = new Set(s.selectedWorkflowIds)
    if (cur.has(id)) cur.delete(id); else cur.add(id)
    return { ...s, selectedWorkflowIds: Array.from(cur) }
  })
  return (
    <div>
      <SectionHeading
        title="Attach workflows"
        sub="Automation workflows fire on campaign events (ticket creation, SLA breach, etc.). Recommended ones are pre-selected."
      />
      <div style={{
        fontSize: 12, fontWeight: 600, color: 'var(--text)',
        display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8,
      }}>
        <GitBranch size={14} /> Workflows
      </div>
      <AutomationList
        items={workflows}
        selectedIds={state.selectedWorkflowIds}
        onToggle={toggle}
        emptyText="No workflow templates available yet. This step is optional."
      />
    </div>
  )
}

// ─── Step 3: Collaborators ────────────────────────────────────────────────

function StepCollaborators({ state, setState, users }) {
  const toggleUser = (id) => {
    setState(s => {
      const cur = new Set(s.internalUserIds)
      if (cur.has(id)) cur.delete(id); else cur.add(id)
      return { ...s, internalUserIds: Array.from(cur) }
    })
  }
  const updateExternal = (i, patch) => {
    setState(s => ({
      ...s,
      externalInvitees: s.externalInvitees.map((e, idx) => idx === i ? { ...e, ...patch } : e),
    }))
  }
  const addExternal = () => setState(s => ({
    ...s, externalInvitees: [...s.externalInvitees, { email: '', name: '' }],
  }))
  const removeExternal = (i) => setState(s => ({
    ...s, externalInvitees: s.externalInvitees.filter((_, idx) => idx !== i),
  }))

  return (
    <div>
      <SectionHeading
        title="Invite collaborators"
        sub="Internal teammates get direct access. External owners get a passcode-gated link by email."
      />

      <div style={{ marginBottom: 24 }}>
        <div style={{
          fontSize: 12, fontWeight: 600, color: 'var(--text)',
          display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8,
        }}>
          <Users size={14} /> Internal teammates
        </div>
        {!users ? <Spinner /> : users.length === 0 ? (
          <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>No other users in this org.</div>
        ) : users.slice(0, 30).map(u => (
          <ToggleRow key={u.id}
            selected={state.internalUserIds.includes(u.id)}
            onToggle={() => toggleUser(u.id)}
          >
            <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text)' }}>
              {u.display_name || u.email}
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
              {u.email} · {u.role}
            </div>
          </ToggleRow>
        ))}
      </div>

      <div>
        <div style={{
          fontSize: 12, fontWeight: 600, color: 'var(--text)',
          display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8,
        }}>
          <Mail size={14} /> External owners (passcode-gated)
        </div>

        {state.externalInvitees.map((ext, i) => (
          <div key={i} style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
            <input
              type="email" placeholder="email@example.com"
              value={ext.email}
              onChange={e => updateExternal(i, { email: e.target.value })}
              style={{ ...inputStyle, flex: 2 }}
            />
            <input
              type="text" placeholder="Name (optional)"
              value={ext.name}
              onChange={e => updateExternal(i, { name: e.target.value })}
              style={{ ...inputStyle, flex: 1 }}
            />
            <button onClick={() => removeExternal(i)}
              title="Remove"
              style={{
                background: 'transparent', border: '1px solid var(--border)',
                borderRadius: 8, padding: '0 10px', color: 'var(--text-muted)',
                cursor: 'pointer',
              }}>
              <X size={14} />
            </button>
          </div>
        ))}

        <Button variant="ghost" onClick={addExternal}>
          <Plus size={12} /> Add external owner
        </Button>
      </div>
    </div>
  )
}

// ─── Step 4: Schedule (minimal — phase-1) ─────────────────────────────────

function StepSchedule({ state, setState }) {
  return (
    <div>
      <SectionHeading
        title="Schedule"
        sub="Phase 1 launches the campaign immediately in draft status. Scheduling comes next."
      />

      <ToggleRow
        selected={state.runImmediately}
        onToggle={() => setState(s => ({ ...s, runImmediately: !s.runImmediately }))}
      >
        <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text)' }}>
          Run campaign query immediately after creation
        </div>
        <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
          Attaches matching findings right away. Uncheck to leave in draft for later review.
        </div>
      </ToggleRow>
    </div>
  )
}

// ─── Step 5: Confirm & Launch ────────────────────────────────────────────

function CopyField({ label, value }) {
  const [copied, setCopied] = useState(false)
  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch { /* ignore */ }
  }
  return (
    <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
      <div style={{
        flex: 1, fontFamily: 'var(--mono, monospace)', fontSize: 12,
        padding: '6px 10px', background: 'var(--bg-muted)',
        border: '1px solid var(--border)', borderRadius: 6,
        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        color: 'var(--text)',
      }} title={value}>
        {value}
      </div>
      <button onClick={onCopy}
        title={copied ? 'Copied!' : `Copy ${label}`}
        style={{
          background: copied ? 'var(--success-subtle)' : 'var(--bg-card)',
          color: copied ? 'var(--success)' : 'var(--text-muted)',
          border: '1px solid var(--border)',
          borderRadius: 6, padding: '6px 10px', cursor: 'pointer',
          fontSize: 12, fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: 4,
        }}>
        {copied ? <><Check size={12} /> Copied</> : <><Copy size={12} /> Copy</>}
      </button>
    </div>
  )
}

function StepConfirm({ state, createdLinks, demoMode, creating, error, onLaunch }) {
  if (createdLinks) {
    return (
      <div>
        <SectionHeading
          title="Campaign launched"
          sub="Share these link+passcode pairs with your external collaborators. Passcodes are shown only once."
        />

        {demoMode && (
          <Card style={{
            padding: 12, marginBottom: 12,
            background: 'var(--warning-subtle)',
            border: '1px solid var(--warning)',
          }}>
            <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start', color: 'var(--warning)', fontSize: 12.5 }}>
              <AlertCircle size={14} style={{ marginTop: 2, flexShrink: 0 }} />
              <div>
                <strong>Demo invites.</strong> The collaboration backend isn't
                deployed against this API, so the links + passcodes below were
                generated client-side and nothing was persisted or emailed.
                Useful for walking through the flow — deploy the backend (or
                run it locally) for real invites.
              </div>
            </div>
          </Card>
        )}

        {createdLinks.length === 0 && (
          <Card style={{ padding: 16 }}>
            <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
              No external collaborators invited. Internal users (if any) already have access.
            </div>
          </Card>
        )}
        {createdLinks.map((l, i) => (
          <Card key={i} style={{ padding: 16, marginBottom: 10 }}>
            <div style={{
              fontSize: 13, fontWeight: 600, marginBottom: 8, color: 'var(--text)',
              display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap',
            }}>
              <span><Mail size={14} style={{ display: 'inline', marginRight: 6, verticalAlign: 'middle' }} />
              {l.external_email}</span>
              {l.demo ? (
                <Pill label="demo (not sent)" color="var(--warning)" />
              ) : l.email?.status === 'sent' ? (
                <Pill label="emailed" color="var(--success)" />
              ) : (
                <Pill label={l.email ? 'email failed' : 'not emailed'} color="var(--warning)" />
              )}
            </div>
            <div style={{ marginBottom: 6 }}>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Share URL</div>
              <CopyField label="URL" value={l.share_url} />
            </div>
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Passcode</div>
              <CopyField label="passcode" value={l.share_link.passcode} />
            </div>
          </Card>
        ))}
      </div>
    )
  }

  return (
    <div>
      <SectionHeading
        title="Review & launch"
        sub="Confirm the details, then launch."
      />
      <Card style={{ padding: 16, marginBottom: 12 }}>
        <div style={{ fontSize: 13, color: 'var(--text)', marginBottom: 8 }}>
          <strong>{state.name || '(untitled)'}</strong>
        </div>
        {state.description && (
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 12 }}>
            {state.description}
          </div>
        )}
        <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap', fontSize: 12 }}>
          <div><strong>{state.selectedAgentIds.length}</strong> agent(s)</div>
          <div><strong>{state.selectedWorkflowIds.length}</strong> workflow(s)</div>
          <div><strong>{state.internalUserIds.length}</strong> internal</div>
          <div>
            <strong>{state.externalInvitees.filter(e => e.email.trim()).length}</strong> external
          </div>
        </div>
      </Card>

      {error && (
        <Card style={{ padding: 12, marginBottom: 12, border: '1px solid var(--danger)' }}>
          <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start', color: 'var(--danger)', fontSize: 13 }}>
            <AlertCircle size={14} style={{ marginTop: 2, flexShrink: 0 }} />
            <div>{error}</div>
          </div>
        </Card>
      )}

      <Button onClick={onLaunch} disabled={creating}>
        {creating ? <><Spinner /> Launching…</> : <><Rocket size={12} /> Launch campaign</>}
      </Button>
    </div>
  )
}

// ─── Main wizard ──────────────────────────────────────────────────────────

const STEPS = [
  { id: 'review',     label: 'Review' },
  { id: 'agents',     label: 'Agents' },
  { id: 'workflows',  label: 'Workflows' },
  { id: 'collabs',    label: 'Collaborators' },
  { id: 'schedule',   label: 'Schedule' },
  { id: 'confirm',    label: 'Launch' },
]

export default function LaunchWizard() {
  const navigate = useNavigate()
  const toast = useToast()
  const { suggestionId } = useParams()

  const [step, setStep] = useState(0)
  const [solution, setSolution] = useState(null)
  const [loadError, setLoadError] = useState(null)

  const [state, setState] = useState({
    name: '',
    description: '',
    selectedAgentIds: [],
    selectedWorkflowIds: [],
    internalUserIds: [],
    externalInvitees: [],
    runImmediately: true,
  })

  const [agents, setAgents] = useState(null)       // ranked + tagged array
  const [workflows, setWorkflows] = useState(null) // ranked + tagged array
  const [users, setUsers] = useState(null)

  // Finding / asset counts come straight from the aggregated solution — no
  // /campaigns/preview roundtrip required (and that endpoint's query engine
  // doesn't support `finding.id in [...]` anyway, which was giving 0/0).
  const preview = useMemo(() => ({
    loading: !solution,
    finding_count: solution?.finding_count ?? null,
    asset_count: solution?.asset_count ?? null,
  }), [solution])

  const [creating, setCreating] = useState(false)
  const [createError, setCreateError] = useState(null)
  const [createdLinks, setCreatedLinks] = useState(null)
  const [createdCampaignId, setCreatedCampaignId] = useState(null)
  const [demoMode, setDemoMode] = useState(false)

  // Load aggregated solution → seed name, description.
  useEffect(() => {
    let alive = true
    getAggregatedSolution(suggestionId)
      .then(s => {
        if (!alive) return
        setSolution(s)
        setState(prev => ({
          ...prev,
          name: s.title || `Campaign for ${s.affected_component || 'component'}`,
          description: s.description || '',
        }))
      })
      .catch(err => setLoadError(err?.message || 'Failed to load suggestion'))
    return () => { alive = false }
  }, [suggestionId])

  // Lazy-load step data as user advances. Once loaded, we rank each item by
  // relevance to the current solution and auto-check the recommended ones
  // (only on first load — user's subsequent toggles are preserved).
  useEffect(() => {
    if ((step === 1 || step === 2) && agents === null && solution) {
      Promise.all([
        getAgents().catch(() => []),
        getWorkflowTemplates().catch(() => []),
      ]).then(([agentsRes, templatesRes]) => {
        const rankedAgents = rankAndTag(asArray(agentsRes, ['agents']), solution)
        const rankedWorkflows = rankAndTag(asArray(templatesRes, ['templates', 'workflows']), solution)
        setAgents(rankedAgents)
        setWorkflows(rankedWorkflows)
        setState(prev => ({
          ...prev,
          selectedAgentIds: prev.selectedAgentIds.length
            ? prev.selectedAgentIds
            : rankedAgents.filter(a => a.__recommended).map(a => a.id),
          selectedWorkflowIds: prev.selectedWorkflowIds.length
            ? prev.selectedWorkflowIds
            : rankedWorkflows.filter(w => w.__recommended).map(w => w.id),
        }))
      })
    }
    if (step === 3 && users === null) {
      authListUsers()
        .then(r => setUsers(asArray(r, ['users'])))
        .catch(() => setUsers([]))
    }
  }, [step, agents, users, solution])

  const canNext = useMemo(() => {
    if (step === 0) return !!state.name.trim()
    if (step === 2) return true // collaborators optional
    return true
  }, [step, state.name])

  const handleLaunch = useCallback(async () => {
    if (!solution) return
    setCreating(true)
    setCreateError(null)
    try {
      const payload = {
        name: state.name,
        description: state.description,
        scan_id: solution.scan_id,
        query: [{ field: 'finding.id', op: 'in', value: solution.finding_ids || [] }],
        query_logic: 'AND',
        automations_config: {
          agent_ids: state.selectedAgentIds,
          workflow_ids: state.selectedWorkflowIds,
        },
      }
      const campaign = await createCampaign(payload)
      setCreatedCampaignId(campaign.id)

      // Invite internal users — no share link, no email, just registers them.
      for (const uid of state.internalUserIds) {
        try {
          await inviteCampaignCollaborator(campaign.id, {
            user_id: uid,
            role: 'internal_owner',
            send_email: false,
          })
        } catch (e) {
          console.warn('Internal invite failed:', e)
        }
      }

      // Invite externals — each returns {share_link: {share_token, passcode}, email: {...}}
      // If the backend doesn't have the collaborator endpoint deployed yet
      // (404), fall back to generating a demo share link + passcode client-
      // side so the wizard's final step still has something to show. Demo
      // links are clearly marked — no email is actually sent and nothing
      // persists beyond the current view.
      const links = []
      const validExternals = state.externalInvitees.filter(e => e.email.trim())
      const origin = window.location.origin
      let anyDemo = false
      for (const ext of validExternals) {
        try {
          const res = await inviteCampaignCollaborator(campaign.id, {
            external_email: ext.email.trim(),
            external_name: ext.name?.trim() || null,
            role: 'external_owner',
            send_email: true,
          })
          if (res.share_link) {
            links.push({
              ...res,
              share_url: `${origin}/c/${res.share_link.share_token}`,
            })
          }
        } catch (e) {
          console.warn('External invite failed:', e)
          if (e.status === 404 || /not found/i.test(String(e.message))) {
            anyDemo = true
            const token = cryptoRandomToken()
            const passcode = cryptoRandomPasscode()
            links.push({
              demo: true,
              external_email: ext.email.trim(),
              external_name: ext.name?.trim() || null,
              share_link: { share_token: token, passcode },
              share_url: `${origin}/c/${token}`,
              email: { status: 'not_sent', error: 'demo' },
            })
          }
        }
      }

      setCreatedLinks(links)
      setDemoMode(anyDemo)
      toast.success(anyDemo ? 'Campaign created (demo invites)' : 'Campaign created')
    } catch (err) {
      setCreateError(err?.message || 'Failed to create campaign')
    } finally {
      setCreating(false)
    }
  }, [solution, state, toast])

  if (loadError) {
    return (
      <div style={{ maxWidth: 720, margin: '0 auto', padding: '40px 20px' }}>
        <PageHeader title="Launch Campaign" subtitle={loadError} />
        <Button variant="ghost" onClick={() => navigate('/campaigns-v2')}>
          <ChevronLeft size={14} /> Back to suggestions
        </Button>
      </div>
    )
  }

  if (!solution) {
    return (
      <div style={{ display: 'grid', placeItems: 'center', padding: 80 }}>
        <Spinner />
      </div>
    )
  }

  return (
    <div style={{ maxWidth: 760, margin: '0 auto', padding: '24px 20px' }}>
      <div style={{ marginBottom: 16 }}>
        <Button variant="ghost" onClick={() => navigate('/campaigns-v2')}>
          <ChevronLeft size={14} /> Back to suggestions
        </Button>
      </div>

      <StepIndicator steps={STEPS} current={step} />

      <Card style={{ padding: 24 }}>
        {step === 0 && <StepReview state={state} setState={setState} preview={preview} />}
        {step === 1 && <StepAgents state={state} setState={setState} agents={agents} />}
        {step === 2 && <StepWorkflows state={state} setState={setState} workflows={workflows} />}
        {step === 3 && <StepCollaborators state={state} setState={setState} users={users} />}
        {step === 4 && <StepSchedule state={state} setState={setState} />}
        {step === 5 && (
          <StepConfirm
            state={state}
            createdLinks={createdLinks}
            demoMode={demoMode}
            creating={creating}
            error={createError}
            onLaunch={handleLaunch}
          />
        )}

        {/* Navigation footer */}
        <div style={{
          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          marginTop: 24, paddingTop: 16, borderTop: '1px solid var(--border)',
        }}>
          {createdLinks ? (
            <>
              <span />
              <Button onClick={() => navigate(`/campaigns/${createdCampaignId}`)}>
                Go to campaign <ChevronRight size={14} />
              </Button>
            </>
          ) : (
            <>
              <Button
                variant="ghost"
                disabled={step === 0}
                onClick={() => setStep(s => Math.max(0, s - 1))}
              >
                <ChevronLeft size={14} /> Back
              </Button>
              {step < STEPS.length - 1 ? (
                <Button disabled={!canNext} onClick={() => setStep(s => Math.min(STEPS.length - 1, s + 1))}>
                  Next <ChevronRight size={14} />
                </Button>
              ) : (
                <span />
              )}
            </>
          )}
        </div>
      </Card>
    </div>
  )
}
