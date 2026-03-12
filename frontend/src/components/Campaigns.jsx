import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Target, Plus, Play, Trash2, Clock, AlertTriangle, CheckCircle, PauseCircle,
  ChevronRight, GitBranch, Zap, Settings, Download,
} from 'lucide-react'
import { useScan } from '../App.jsx'
import { getCampaigns, createCampaign, deleteCampaign, runCampaign, getWorkflows, createWorkflow, deleteWorkflow, getWorkflowTemplates, createWorkflowFromTemplate, exportConfig, importConfig } from '../api.js'
import { Card, PageHeader, Button, Spinner, EmptyState, Pill, ExportImportButtons } from './ui.jsx'

const STATUS_META = {
  draft:     { label: 'Draft',     color: 'var(--muted)',   bg: 'rgba(100,116,139,0.1)', border: 'rgba(100,116,139,0.25)', icon: Clock },
  active:    { label: 'Active',    color: 'var(--primary)', bg: 'rgba(37,99,235,0.1)',   border: 'rgba(37,99,235,0.25)',   icon: Play },
  completed: { label: 'Completed', color: 'var(--success)', bg: 'rgba(34,197,94,0.1)',   border: 'rgba(34,197,94,0.25)',   icon: CheckCircle },
  paused:    { label: 'Paused',    color: 'var(--warning)', bg: 'rgba(245,158,11,0.1)',  border: 'rgba(245,158,11,0.25)',  icon: PauseCircle },
}

function StatusBadge({ status }) {
  const m = STATUS_META[status] || STATUS_META.draft
  const Icon = m.icon
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      background: m.bg, color: m.color, border: `1px solid ${m.border}`,
      borderRadius: 4, padding: '2px 8px', fontSize: 11, fontWeight: 600,
      textTransform: 'uppercase', letterSpacing: '0.04em',
    }}>
      <Icon size={10} />
      {m.label}
    </span>
  )
}

function CreateCampaignModal({ scanId, onClose, onCreate }) {
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [saving, setSaving] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!name.trim()) return
    setSaving(true)
    try {
      const c = await createCampaign({ name: name.trim(), description, scan_id: scanId, query: [], query_logic: 'AND' })
      onCreate(c)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div style={{
      position: 'fixed', inset: 0, background: '#000a', zIndex: 200,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }} onClick={onClose}>
      <div style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 14,
        padding: 28, minWidth: 440, maxWidth: 540,
      }} onClick={e => e.stopPropagation()}>
        <div style={{ fontWeight: 700, fontSize: 16, marginBottom: 20 }}>New Remediation Campaign</div>

        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: 16 }}>
            <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 6 }}>
              Campaign Name *
            </label>
            <input
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder='e.g. Patch Tuesday March 2026, React2Shell, Critical CVE Blitz…'
              autoFocus
              style={{
                width: '100%', padding: '8px 12px', background: 'var(--bg-secondary)',
                border: '1px solid var(--border)', borderRadius: 8, fontSize: 13,
                color: 'var(--text-primary)', boxSizing: 'border-box',
              }}
            />
          </div>

          <div style={{ marginBottom: 24 }}>
            <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 6 }}>
              Description
            </label>
            <textarea
              value={description}
              onChange={e => setDescription(e.target.value)}
              placeholder='Describe the goal and scope of this campaign…'
              rows={3}
              style={{
                width: '100%', padding: '8px 12px', background: 'var(--bg-secondary)',
                border: '1px solid var(--border)', borderRadius: 8, fontSize: 13,
                color: 'var(--text-primary)', resize: 'vertical', boxSizing: 'border-box',
                fontFamily: 'inherit',
              }}
            />
          </div>

          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
            <Button variant='ghost' onClick={onClose} type='button'>Cancel</Button>
            <Button type='submit' disabled={!name.trim() || saving}>
              {saving ? 'Creating…' : 'Create Campaign'}
            </Button>
          </div>
        </form>
      </div>
    </div>
  )
}

function CampaignCard({ campaign, onDelete, onRun }) {
  const navigate = useNavigate()
  const [running, setRunning] = useState(false)
  const [confirming, setConfirming] = useState(false)

  const handleRun = async (e) => {
    e.stopPropagation()
    setRunning(true)
    try {
      await onRun(campaign.id)
    } finally {
      setRunning(false)
    }
  }

  const conditionCount = (campaign.query || []).length

  return (
    <div
      onClick={() => navigate(`/campaigns/${campaign.id}`)}
      style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 10,
        padding: '16px 20px', cursor: 'pointer', display: 'flex', gap: 16, alignItems: 'center',
        transition: 'border-color 0.15s',
      }}
      onMouseEnter={e => e.currentTarget.style.borderColor = 'var(--accent)'}
      onMouseLeave={e => e.currentTarget.style.borderColor = 'var(--border)'}
    >
      {/* Icon */}
      <div style={{
        width: 40, height: 40, borderRadius: 10, background: 'rgba(37,99,235,0.12)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
      }}>
        <Target size={18} color='var(--accent)' />
      </div>

      {/* Info */}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 4 }}>
          <span style={{ fontWeight: 600, fontSize: 14, color: 'var(--text-primary)' }}>
            {campaign.name}
          </span>
          <StatusBadge status={campaign.status} />
        </div>
        {campaign.description && (
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 6, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {campaign.description}
          </div>
        )}
        <div style={{ display: 'flex', gap: 16, fontSize: 11, color: 'var(--text-muted)' }}>
          <span>{conditionCount} condition{conditionCount !== 1 ? 's' : ''}</span>
          {campaign.finding_count > 0 && (
            <span style={{ color: '#f87171' }}>{campaign.finding_count} findings</span>
          )}
          {campaign.last_run_at && (
            <span>Last run: {new Date(campaign.last_run_at).toLocaleDateString()}</span>
          )}
          {!campaign.last_run_at && <span style={{ color: '#f59e0b' }}>Never run</span>}
        </div>
      </div>

      {/* Actions */}
      <div style={{ display: 'flex', gap: 8, flexShrink: 0 }} onClick={e => e.stopPropagation()}>
        <button
          onClick={handleRun}
          disabled={running || conditionCount === 0}
          title={conditionCount === 0 ? 'Add conditions first' : 'Run query now'}
          style={{
            display: 'flex', alignItems: 'center', gap: 5,
            padding: '6px 12px', borderRadius: 6, border: '1px solid #1e3a5f66',
            background: '#1e3a5f22', color: '#60a5fa', fontSize: 12, fontWeight: 600,
            cursor: conditionCount === 0 ? 'not-allowed' : 'pointer', opacity: conditionCount === 0 ? 0.5 : 1,
          }}
        >
          <Play size={12} />
          {running ? 'Running…' : 'Run'}
        </button>

        <button
          onClick={async (e) => {
            e.stopPropagation()
            try {
              const data = await exportConfig('campaign_workflow', { campaign_id: campaign.id })
              const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
              const url = URL.createObjectURL(blob)
              const a = document.createElement('a')
              a.href = url
              a.download = `campaign-${campaign.name.replace(/\s+/g, '-').toLowerCase()}.json`
              document.body.appendChild(a)
              a.click()
              a.remove()
              URL.revokeObjectURL(url)
            } catch (err) { console.error('Export failed', err) }
          }}
          title="Export campaign template"
          style={{ padding: '6px 8px', borderRadius: 6, border: '1px solid var(--border)', background: 'transparent', color: 'var(--text-muted)', cursor: 'pointer', display: 'flex' }}
        >
          <Download size={14} />
        </button>

        {confirming ? (
          <>
            <button onClick={() => { onDelete(campaign.id); setConfirming(false) }}
              style={{ padding: '6px 10px', borderRadius: 6, border: '1px solid #991b1b', background: '#dc262622', color: '#f87171', fontSize: 12, cursor: 'pointer' }}>
              Confirm
            </button>
            <button onClick={() => setConfirming(false)}
              style={{ padding: '6px 10px', borderRadius: 6, border: '1px solid var(--border)', background: 'transparent', color: 'var(--text-muted)', fontSize: 12, cursor: 'pointer' }}>
              Cancel
            </button>
          </>
        ) : (
          <button onClick={() => setConfirming(true)}
            title='Delete campaign'
            style={{ padding: '6px 8px', borderRadius: 6, border: '1px solid var(--border)', background: 'transparent', color: 'var(--text-muted)', cursor: 'pointer', display: 'flex' }}>
            <Trash2 size={14} />
          </button>
        )}
      </div>

      <ChevronRight size={16} color='var(--text-muted)' />
    </div>
  )
}

// ─── Workflow cards ─────────────────────────
function WorkflowCard({ workflow, onDelete }) {
  const navigate = useNavigate()
  const [confirming, setConfirming] = useState(false)

  return (
    <div
      onClick={() => navigate(`/workflows/${workflow.id}`)}
      style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 10,
        padding: '16px 20px', cursor: 'pointer', display: 'flex', gap: 16, alignItems: 'center',
        transition: 'border-color 0.15s',
      }}
      onMouseEnter={e => e.currentTarget.style.borderColor = '#818cf866'}
      onMouseLeave={e => e.currentTarget.style.borderColor = 'var(--border)'}
    >
      <div style={{
        width: 40, height: 40, borderRadius: 10, background: '#312e8133',
        display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
      }}>
        <GitBranch size={18} color='#818cf8' />
      </div>

      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 4 }}>
          <span style={{ fontWeight: 600, fontSize: 14 }}>{workflow.name}</span>
          <Pill color={workflow.status === 'active' ? '#22c55e' : '#71717a'}>
            {workflow.status}
          </Pill>
        </div>
        {workflow.description && (
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 4, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {workflow.description}
          </div>
        )}
        <div style={{ display: 'flex', gap: 16, fontSize: 11, color: 'var(--text-muted)' }}>
          <span>{workflow.node_count || 0} nodes</span>
          <span>{workflow.run_count || 0} runs</span>
          {workflow.last_run_at && (
            <span>Last run: {new Date(workflow.last_run_at).toLocaleDateString()}</span>
          )}
        </div>
      </div>

      <div style={{ display: 'flex', gap: 8, flexShrink: 0 }} onClick={e => e.stopPropagation()}>
        {confirming ? (
          <>
            <button onClick={() => { onDelete(workflow.id); setConfirming(false) }}
              style={{ padding: '6px 10px', borderRadius: 6, border: '1px solid #991b1b', background: '#dc262622', color: '#f87171', fontSize: 12, cursor: 'pointer' }}>
              Confirm
            </button>
            <button onClick={() => setConfirming(false)}
              style={{ padding: '6px 10px', borderRadius: 6, border: '1px solid var(--border)', background: 'transparent', color: 'var(--text-muted)', fontSize: 12, cursor: 'pointer' }}>
              Cancel
            </button>
          </>
        ) : (
          <button onClick={() => setConfirming(true)} title='Delete workflow'
            style={{ padding: '6px 8px', borderRadius: 6, border: '1px solid var(--border)', background: 'transparent', color: 'var(--text-muted)', cursor: 'pointer', display: 'flex' }}>
            <Trash2 size={14} />
          </button>
        )}
      </div>

      <ChevronRight size={16} color='var(--text-muted)' />
    </div>
  )
}

function CreateWorkflowModal({ onClose, onCreate }) {
  const [mode, setMode] = useState('template') // 'template' | 'custom'
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [saving, setSaving] = useState(false)
  const [templates, setTemplates] = useState([])
  const [categories, setCategories] = useState([])
  const [loadingTpl, setLoadingTpl] = useState(true)

  useEffect(() => {
    getWorkflowTemplates().then(data => {
      setTemplates(data.templates || [])
      setCategories(data.categories || [])
    }).finally(() => setLoadingTpl(false))
  }, [])

  const handleCreateCustom = async (e) => {
    e.preventDefault()
    if (!name.trim()) return
    setSaving(true)
    try {
      const wf = await createWorkflow({ name: name.trim(), description })
      onCreate(wf)
    } finally { setSaving(false) }
  }

  const handleUseTemplate = async (tpl) => {
    setSaving(true)
    try {
      const wf = await createWorkflowFromTemplate({ template_id: tpl.id })
      onCreate(wf)
    } finally { setSaving(false) }
  }

  const CATEGORY_ICONS = { triage: GitBranch, patching: Settings, incident: Zap, integration: Settings }

  return (
    <div style={{
      position: 'fixed', inset: 0, background: '#000a', zIndex: 200,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }} onClick={onClose}>
      <div style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 14,
        padding: 28, minWidth: 560, maxWidth: 640, maxHeight: '80vh', overflow: 'auto',
      }} onClick={e => e.stopPropagation()}>
        <div style={{ fontWeight: 700, fontSize: 16, marginBottom: 16 }}>New Automation Workflow</div>

        {/* Mode tabs */}
        <div style={{ display: 'flex', gap: 0, marginBottom: 20, borderBottom: '1px solid var(--border)' }}>
          {[
            { key: 'template', label: 'Use Template' },
            { key: 'custom', label: 'Start from Scratch' },
          ].map(t => (
            <button key={t.key} onClick={() => setMode(t.key)} style={{
              padding: '8px 16px', fontSize: 13, fontWeight: 600,
              background: 'none', border: 'none', cursor: 'pointer',
              color: mode === t.key ? 'var(--text)' : 'var(--muted-2)',
              borderBottom: mode === t.key ? '2px solid var(--text)' : '2px solid transparent',
              marginBottom: -1,
            }}>{t.label}</button>
          ))}
        </div>

        {mode === 'template' ? (
          <div>
            {loadingTpl ? <Spinner /> : templates.length === 0 ? (
              <div style={{ textAlign: 'center', padding: 20, color: '#94a3b8' }}>No templates available</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {templates.map(tpl => (
                  <button key={tpl.id} onClick={() => handleUseTemplate(tpl)}
                    disabled={saving}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 12,
                      padding: '14px 16px', borderRadius: 10,
                      border: '1px solid var(--border)', background: 'var(--card)',
                      cursor: 'pointer', textAlign: 'left', width: '100%',
                      transition: 'border-color 0.15s',
                    }}
                    onMouseEnter={e => e.currentTarget.style.borderColor = '#818cf8'}
                    onMouseLeave={e => e.currentTarget.style.borderColor = 'var(--border)'}
                  >
                    <div style={{
                      width: 40, height: 40, borderRadius: 10, background: '#312e8133',
                      display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                    }}>
                      <GitBranch size={18} color='#818cf8' />
                    </div>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 2 }}>{tpl.name}</div>
                      <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>{tpl.description}</div>
                      <div style={{ display: 'flex', gap: 6, marginTop: 4 }}>
                        <Pill color="#818cf8">{tpl.category}</Pill>
                        <Pill color="#94a3b8">{tpl.nodes?.length || 0} nodes</Pill>
                      </div>
                    </div>
                    <ChevronRight size={16} color='var(--text-muted)' />
                  </button>
                ))}
              </div>
            )}
          </div>
        ) : (
          <form onSubmit={handleCreateCustom}>
            <div style={{ marginBottom: 16 }}>
              <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 6 }}>
                Workflow Name *
              </label>
              <input value={name} onChange={e => setName(e.target.value)}
                placeholder='e.g. Auto-assign critical findings, Tag exploitable assets…'
                autoFocus
                style={{
                  width: '100%', padding: '8px 12px', background: 'var(--bg-secondary)',
                  border: '1px solid var(--border)', borderRadius: 8, fontSize: 13,
                  color: 'var(--text-primary)', boxSizing: 'border-box',
                }}
              />
            </div>
            <div style={{ marginBottom: 24 }}>
              <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 6 }}>
                Description
              </label>
              <textarea value={description} onChange={e => setDescription(e.target.value)}
                placeholder='Describe what this workflow automates…' rows={3}
                style={{
                  width: '100%', padding: '8px 12px', background: 'var(--bg-secondary)',
                  border: '1px solid var(--border)', borderRadius: 8, fontSize: 13,
                  color: 'var(--text-primary)', resize: 'vertical', boxSizing: 'border-box',
                  fontFamily: 'inherit',
                }}
              />
            </div>
            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
              <Button variant='ghost' onClick={onClose} type='button'>Cancel</Button>
              <Button type='submit' disabled={!name.trim() || saving}>
                {saving ? 'Creating…' : 'Create Workflow'}
              </Button>
            </div>
          </form>
        )}
      </div>
    </div>
  )
}

export default function Campaigns() {
  const { activeScanId } = useScan()
  const navigate = useNavigate()
  const [campaigns, setCampaigns] = useState([])
  const [workflows, setWorkflows] = useState([])
  const [loading, setLoading] = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [showCreateWf, setShowCreateWf] = useState(false)
  const [tab, setTab] = useState('campaigns')

  const load = () => {
    setLoading(true)
    Promise.all([
      getCampaigns(activeScanId),
      getWorkflows(),
    ]).then(([c, w]) => {
      setCampaigns(c)
      setWorkflows(w)
    }).finally(() => setLoading(false))
  }

  useEffect(load, [activeScanId])

  const handleCreate = (c) => {
    setShowCreate(false)
    navigate(`/campaigns/${c.id}`)
  }

  const handleCreateWf = (wf) => {
    setShowCreateWf(false)
    navigate(`/workflows/${wf.id}`)
  }

  const handleDelete = async (id) => {
    await deleteCampaign(id)
    setCampaigns(prev => prev.filter(c => c.id !== id))
  }

  const handleDeleteWf = async (id) => {
    await deleteWorkflow(id)
    setWorkflows(prev => prev.filter(w => w.id !== id))
  }

  const handleRun = async (id) => {
    await runCampaign(id)
    load()
  }

  const byStatus = (s) => campaigns.filter(c => c.status === s)
  const draft = byStatus('draft')
  const active = byStatus('active')
  const completed = byStatus('completed')
  const paused = byStatus('paused')
  const ordered = [...active, ...draft, ...paused, ...completed]

  return (
    <div>
      <PageHeader
        title="Campaigns & Workflows"
        subtitle="Targeted remediation campaigns and automated workflows"
        action={
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <ExportImportButtons
              configType="campaign_workflow"
              exportFn={null}
              importFn={(file, conflict) => importConfig('campaign_workflow', file, conflict)}
              onImported={load}
              label="Campaign Template"
              showConflict={true}
            />
            <Button variant="ghost" onClick={() => setShowCreateWf(true)}>
              <GitBranch size={14} /> New Workflow
            </Button>
            <Button onClick={() => setShowCreate(true)}>
              <Plus size={14} /> New Campaign
            </Button>
          </div>
        }
      />

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 0, marginBottom: 16, borderBottom: '1px solid var(--border)' }}>
        {[
          { key: 'campaigns', label: 'Campaigns', count: campaigns.length, icon: Target },
          { key: 'workflows', label: 'Workflows', count: workflows.length, icon: GitBranch },
        ].map(t => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              padding: '10px 18px', fontSize: 13, fontWeight: 600,
              background: 'none', border: 'none', cursor: 'pointer',
              color: tab === t.key ? 'var(--text)' : '#94a3b8',
              borderBottom: tab === t.key ? '2px solid var(--text)' : '2px solid transparent',
              marginBottom: -1,
            }}
          >
            <t.icon size={14} />
            {t.label}
            <span style={{
              fontSize: 11, padding: '1px 6px', borderRadius: 10,
              background: tab === t.key ? 'var(--text)' : 'var(--secondary)',
              color: tab === t.key ? 'var(--bg)' : 'var(--muted)',
            }}>{t.count}</span>
          </button>
        ))}
      </div>

      {loading ? <Spinner /> : tab === 'campaigns' ? (
        ordered.length === 0 ? (
          <EmptyState
            icon={Target}
            title="No campaigns yet"
            sub="Create a campaign to build targeted remediation workflows with smart search queries and ownership assignments."
          >
            <Button onClick={() => setShowCreate(true)}><Plus size={14} /> Create First Campaign</Button>
          </EmptyState>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {ordered.map(c => (
              <CampaignCard key={c.id} campaign={c} onDelete={handleDelete} onRun={handleRun} />
            ))}
          </div>
        )
      ) : (
        workflows.length === 0 ? (
          <EmptyState
            icon={GitBranch}
            title="No workflows yet"
            sub="Create an automation workflow with triggers, conditions, and actions to streamline your remediation process."
          >
            <Button onClick={() => setShowCreateWf(true)}><GitBranch size={14} /> Create First Workflow</Button>
          </EmptyState>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {workflows.map(w => (
              <WorkflowCard key={w.id} workflow={w} onDelete={handleDeleteWf} />
            ))}
          </div>
        )
      )}

      {showCreate && (
        <CreateCampaignModal
          scanId={activeScanId}
          onClose={() => setShowCreate(false)}
          onCreate={handleCreate}
        />
      )}
      {showCreateWf && (
        <CreateWorkflowModal
          onClose={() => setShowCreateWf(false)}
          onCreate={handleCreateWf}
        />
      )}
    </div>
  )
}
