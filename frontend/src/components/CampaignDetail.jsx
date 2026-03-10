import React, { useState, useEffect, useCallback } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  Target, Play, Plus, X, ChevronDown, ChevronRight, ChevronLeft,
  User, Users, Zap, AlertTriangle, CheckCircle, Edit2, Save, Eye,
  RefreshCw, Layers, GitBranch, Trash2,
} from 'lucide-react'
import { useScan } from '../App.jsx'
import {
  getCampaign, updateCampaign, runCampaign,
  previewCampaignQuery, updateCampaignFinding,
  getWorkflows, createWorkflowFromTemplate, createWorkflow, deleteWorkflow,
  executeWorkflow, getWorkflowTemplates,
} from '../api.js'
import { SeverityBadge, ScoreBar, Button, Spinner, EmptyState, Card, Pill } from './ui.jsx'
import RuleBuilder from './RuleBuilder.jsx'

// ─── Condition chip colors ───────────────────────────────
const GROUP_COLORS = {
  'Vulnerability':      { bg: '#450a0a22', border: '#991b1b44', text: '#fca5a5' },
  'Environment':        { bg: '#1a2e0522', border: '#16653344', text: '#86efac' },
  'Identity & Access':  { bg: '#1e1a4222', border: '#4f46e544', text: '#a5b4fc' },
  'Security Controls':  { bg: '#1c111322', border: '#92400e44', text: '#fcd34d' },
  'Remediation':        { bg: '#0c1a2e22', border: '#036910a144', text: '#7dd3fc' },
}

const SEV_COLORS = ['#0ea5e9', '#65a30d', '#d97706', '#ea580c', '#dc2626']

const OWNER_ROLE_COLORS = {
  IT:      { bg: '#1e3a5f22', border: '#1e3a5f55', text: '#60a5fa' },
  DevOps:  { bg: '#14532d22', border: '#14532d55', text: '#4ade80' },
  SecOps:  { bg: '#450a0a22', border: '#991b1b55', text: '#fca5a5' },
  AppSec:  { bg: '#1a1a2e22', border: '#4f46e555', text: '#a5b4fc' },
  Unassigned: { bg: '#27272a22', border: '#27272a55', text: '#a1a1aa' },
}

function getOwnerColors(role) {
  return OWNER_ROLE_COLORS[role] || OWNER_ROLE_COLORS.Unassigned
}

// ─── Query Builder ────────────────────────────────────────
function QueryBuilder({ query, queryLogic, onChange, onLogicChange, onPreview, previewing, previewResult }) {
  return (
    <Card style={{ marginBottom: 20 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
        <div>
          <div style={{ fontWeight: 700, fontSize: 14, marginBottom: 2 }}>Search Query</div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            Build conditions to find assets for this campaign.
          </div>
        </div>
      </div>

      {query.length === 0 && (
        <div style={{
          padding: '12px', textAlign: 'center', background: 'var(--bg-secondary)',
          borderRadius: 8, border: '1px dashed var(--border)',
          fontSize: 12, color: 'var(--text-muted)', marginBottom: 10,
        }}>
          No conditions yet — use "Add Condition" below to define which assets are included.
        </div>
      )}

      <RuleBuilder
        conditions={query}
        logic={queryLogic}
        onChange={(conds, lgc) => { onChange(conds); onLogicChange(lgc) }}
        showLogic
        addLabel="Add Condition"
      />

      {/* Preview */}
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 12 }}>
        <button
          onClick={onPreview}
          disabled={query.length === 0 || previewing}
          style={{
            display: 'flex', alignItems: 'center', gap: 5,
            padding: '6px 14px', borderRadius: 6, fontSize: 12, fontWeight: 600,
            border: '1px solid #36456644', background: '#36456622', color: '#7dd3fc',
            cursor: query.length === 0 ? 'not-allowed' : 'pointer',
            opacity: query.length === 0 ? 0.5 : 1,
          }}
        >
          <Eye size={13} />
          {previewing ? 'Previewing…' : 'Preview'}
        </button>
        {previewResult && (
          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            → <span style={{ color: '#60a5fa', fontWeight: 600 }}>{previewResult.asset_count} assets</span>
            {' · '}
            <span style={{ color: '#f87171', fontWeight: 600 }}>{previewResult.finding_count} findings</span>
          </div>
        )}
      </div>
    </Card>
  )
}

// ─── Ownership Editor ─────────────────────────────────────
const OWNER_ROLES = ['IT', 'DevOps', 'SecOps', 'AppSec', 'Custom']

function OwnershipEditor({ current, onSave, onCancel }) {
  const [ownerName, setOwnerName] = useState(current?.owner_name || '')
  const [ownerEmail, setOwnerEmail] = useState(current?.owner_email || '')
  const [ownerRole, setOwnerRole] = useState(current?.owner_role || '')
  const [team, setTeam] = useState(current?.team || '')
  const [notes, setNotes] = useState(current?.notes || '')

  const inp = (val, set, placeholder) => (
    <input
      value={val}
      onChange={e => set(e.target.value)}
      placeholder={placeholder}
      style={{
        flex: 1, padding: '5px 8px', background: 'var(--bg-secondary)',
        border: '1px solid var(--border)', borderRadius: 6, fontSize: 12,
        color: 'var(--text-primary)',
      }}
    />
  )

  return (
    <div style={{
      background: 'var(--bg-card)', border: '1px solid var(--border)',
      borderRadius: 10, padding: 16, display: 'flex', flexDirection: 'column', gap: 10,
    }}>
      <div style={{ display: 'flex', gap: 8 }}>
        {inp(ownerName, setOwnerName, 'Owner name')}
        {inp(ownerEmail, setOwnerEmail, 'Email')}
        <select
          value={ownerRole}
          onChange={e => setOwnerRole(e.target.value)}
          style={{
            padding: '5px 8px', background: 'var(--bg-secondary)',
            border: '1px solid var(--border)', borderRadius: 6, fontSize: 12,
            color: 'var(--text-primary)', minWidth: 90,
          }}
        >
          <option value=''>Role…</option>
          {OWNER_ROLES.map(r => <option key={r} value={r}>{r}</option>)}
        </select>
      </div>
      <div style={{ display: 'flex', gap: 8 }}>
        {inp(team, setTeam, 'Team / squad')}
        {inp(notes, setNotes, 'Notes')}
      </div>
      <div style={{ display: 'flex', gap: 8 }}>
        <Button size='sm' onClick={() => onSave({ owner_name: ownerName, owner_email: ownerEmail, owner_role: ownerRole, team, notes })}>
          <Save size={12} /> Save
        </Button>
        <Button variant='ghost' size='sm' onClick={onCancel}>Cancel</Button>
      </div>
    </div>
  )
}

function OwnerChip({ role, name, team, editable, onEdit }) {
  const c = getOwnerColors(role)
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      <span style={{
        display: 'inline-flex', alignItems: 'center', gap: 4,
        background: c.bg, color: c.text, border: `1px solid ${c.border}`,
        borderRadius: 6, padding: '3px 10px', fontSize: 11, fontWeight: 600,
      }}>
        <User size={10} />
        {name || role || 'Unassigned'}
        {team && <span style={{ opacity: 0.7 }}>· {team}</span>}
      </span>
      {editable && (
        <button onClick={onEdit} style={{ padding: 2, background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', display: 'flex' }}>
          <Edit2 size={11} />
        </button>
      )}
    </div>
  )
}

// ─── Finding Card (campaign context) ─────────────────────
function CampaignFindingCard({ finding, campaignId, onOwnerUpdate }) {
  const navigate = useNavigate()
  const [expanded, setExpanded] = useState(false)
  const [editingOwner, setEditingOwner] = useState(false)
  const [status, setStatus] = useState(finding.campaign_status || 'open')

  const sevColor = SEV_COLORS[finding.severity] || SEV_COLORS[0]

  const handleOwnerSave = async (data) => {
    await updateCampaignFinding(campaignId, finding.campaign_finding_id, {
      ...data, owner_role: data.owner_role || data.owner_name,
    })
    setEditingOwner(false)
    onOwnerUpdate()
  }

  const handleStatusChange = async (newStatus) => {
    setStatus(newStatus)
    await updateCampaignFinding(campaignId, finding.campaign_finding_id, { status: newStatus })
  }

  const STATUS_COLORS = {
    open:        { bg: '#27272a22', text: '#a1a1aa', border: '#27272a55' },
    in_progress: { bg: '#1e3a5f22', text: '#60a5fa', border: '#1e3a5f55' },
    resolved:    { bg: '#14532d22', text: '#4ade80', border: '#14532d55' },
    wont_fix:    { bg: '#450a0a22', text: '#fca5a5', border: '#991b1b55' },
  }
  const sc = STATUS_COLORS[status] || STATUS_COLORS.open

  return (
    <div style={{
      background: 'var(--bg-secondary)', border: '1px solid var(--border)',
      borderRadius: 8, overflow: 'hidden',
      borderLeft: `3px solid ${sevColor}`,
    }}>
      {/* Header */}
      <div
        style={{ padding: '10px 14px', cursor: 'pointer', display: 'flex', gap: 10, alignItems: 'flex-start' }}
        onClick={() => setExpanded(e => !e)}
      >
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center', marginBottom: 4 }}>
            <SeverityBadge severity={finding.severity} label={finding.severity_label} />
            {finding.exploit_available && (
              <span style={{ fontSize: 10, fontWeight: 700, color: '#ea580c', background: '#431407', border: '1px solid #9a3412', borderRadius: 4, padding: '1px 6px' }}>
                EXPLOIT
              </span>
            )}
            {finding.zero_day && (
              <span style={{ fontSize: 10, fontWeight: 700, color: '#dc2626', background: '#450a0a', border: '1px solid #991b1b', borderRadius: 4, padding: '1px 6px' }}>
                0-DAY
              </span>
            )}
            {/* Status badge */}
            <select
              value={status}
              onChange={e => { e.stopPropagation(); handleStatusChange(e.target.value) }}
              onClick={e => e.stopPropagation()}
              style={{
                background: sc.bg, color: sc.text, border: `1px solid ${sc.border}`,
                borderRadius: 4, fontSize: 10, fontWeight: 700, padding: '1px 6px',
                textTransform: 'uppercase', letterSpacing: '0.04em', cursor: 'pointer',
              }}
            >
              <option value='open'>Open</option>
              <option value='in_progress'>In Progress</option>
              <option value='resolved'>Resolved</option>
              <option value='wont_fix'>Won't Fix</option>
            </select>
          </div>
          <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-primary)', marginBottom: 2 }}>
            {finding.plugin_name}
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            {finding.asset_hostname || finding.asset_ip}
            {finding.plugin_family && ` · ${finding.plugin_family}`}
            {finding.port && ` · :${finding.port}`}
          </div>
        </div>

        <div style={{ textAlign: 'right', flexShrink: 0, minWidth: 80 }}>
          <ScoreBar score={finding.priority_score} />
          {(finding.cvss3_score || finding.cvss2_score) && (
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
              CVSS {(finding.cvss3_score || finding.cvss2_score)?.toFixed(1)}
            </div>
          )}
        </div>

        {expanded ? <ChevronDown size={14} color='var(--text-muted)' /> : <ChevronRight size={14} color='var(--text-muted)' />}
      </div>

      {expanded && (
        <div style={{ padding: '0 14px 14px', borderTop: '1px solid var(--border)' }}>
          {finding.synopsis && (
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 10, lineHeight: 1.6 }}>
              {finding.synopsis}
            </div>
          )}

          {finding.remediation_steps && (
            <div style={{ marginTop: 10, padding: '10px 12px', background: '#14532d11', border: '1px solid #14532d33', borderRadius: 8 }}>
              <div style={{ fontSize: 10, fontWeight: 700, color: '#4ade80', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 4 }}>
                Recommended Steps
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                {finding.remediation_steps}
              </div>
            </div>
          )}

          {finding.cves?.length > 0 && (
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 10 }}>
              {finding.cves.map(cve => (
                <span key={cve} style={{ fontSize: 10, fontWeight: 600, color: '#fbbf24', background: '#78350f22', border: '1px solid #78350f44', borderRadius: 4, padding: '2px 6px' }}>
                  {cve}
                </span>
              ))}
            </div>
          )}

          {/* Ownership editor */}
          <div style={{ marginTop: 12 }}>
            {editingOwner ? (
              <OwnershipEditor
                current={finding.campaign_owner}
                onSave={handleOwnerSave}
                onCancel={() => setEditingOwner(false)}
              />
            ) : (
              <OwnerChip
                role={finding.campaign_owner?.owner_role || finding.owner_suggestion}
                name={finding.campaign_owner?.owner_name}
                team={finding.campaign_owner?.team}
                editable
                onEdit={() => setEditingOwner(true)}
              />
            )}
          </div>

          <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
            <Button variant='ghost' size='sm' onClick={() => navigate(`/findings/${finding.id}`)}>
              View Details <ChevronRight size={12} />
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Owner Group Section ──────────────────────────────────
function OwnerGroup({ group, campaignId, onOwnerUpdate, defaultExpanded = true }) {
  const [expanded, setExpanded] = useState(defaultExpanded)
  const [editingGroup, setEditingGroup] = useState(false)
  const c = getOwnerColors(group.owner_role)

  return (
    <div style={{
      background: 'var(--bg-card)', border: `1px solid ${c.border}`,
      borderRadius: 12, overflow: 'hidden', marginBottom: 16,
    }}>
      {/* Group header */}
      <div
        onClick={() => setExpanded(e => !e)}
        style={{
          padding: '14px 18px', cursor: 'pointer', display: 'flex', gap: 12, alignItems: 'center',
          background: c.bg, borderBottom: expanded ? `1px solid ${c.border}` : 'none',
        }}
      >
        <div style={{
          width: 36, height: 36, borderRadius: 8, background: c.bg,
          border: `1px solid ${c.border}`, display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <Users size={16} color={c.text} />
        </div>

        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 700, fontSize: 15, color: c.text }}>
            {group.owner_name || group.owner_role || 'Unassigned'}
          </div>
          {group.team && (
            <div style={{ fontSize: 11, color: c.text, opacity: 0.7 }}>
              {group.team}
            </div>
          )}
        </div>

        {/* Stats */}
        <div style={{ display: 'flex', gap: 14, fontSize: 12 }}>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{group.findings.length}</div>
            <div style={{ color: 'var(--text-muted)', fontSize: 10 }}>Findings</div>
          </div>
          {group.critical_count > 0 && (
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontWeight: 700, color: '#fca5a5' }}>{group.critical_count}</div>
              <div style={{ color: 'var(--text-muted)', fontSize: 10 }}>Critical</div>
            </div>
          )}
          {group.exploit_count > 0 && (
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontWeight: 700, color: '#fb923c' }}>{group.exploit_count}</div>
              <div style={{ color: 'var(--text-muted)', fontSize: 10 }}>Exploits</div>
            </div>
          )}
        </div>

        {expanded ? <ChevronDown size={16} color={c.text} /> : <ChevronRight size={16} color={c.text} />}
      </div>

      {expanded && (
        <div style={{ padding: '14px 18px', display: 'flex', flexDirection: 'column', gap: 8 }}>
          {group.findings.map(f => (
            <CampaignFindingCard
              key={f.campaign_finding_id}
              finding={f}
              campaignId={campaignId}
              onOwnerUpdate={onOwnerUpdate}
            />
          ))}
        </div>
      )}
    </div>
  )
}

// ─── Main Component ───────────────────────────────────────
const STATUS_OPTIONS = ['draft', 'active', 'paused', 'completed']

export default function CampaignDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const { activeScanId } = useScan()

  const [campaign, setCampaign] = useState(null)
  const [loading, setLoading] = useState(true)
  const [query, setQuery] = useState([])
  const [queryLogic, setQueryLogic] = useState('AND')
  const [queryDirty, setQueryDirty] = useState(false)
  const [saving, setSaving] = useState(false)
  const [running, setRunning] = useState(false)
  const [previewing, setPreviewing] = useState(false)
  const [previewResult, setPreviewResult] = useState(null)
  const [editingName, setEditingName] = useState(false)
  const [nameVal, setNameVal] = useState('')
  const [descVal, setDescVal] = useState('')
  const [activeTab, setActiveTab] = useState('results') // 'query' | 'results'

  const load = useCallback(() => {
    setLoading(true)
    getCampaign(id)
      .then(data => {
        setCampaign(data)
        setQuery(data.query || [])
        setQueryLogic(data.query_logic || 'AND')
        setNameVal(data.name || '')
        setDescVal(data.description || '')
      })
      .finally(() => setLoading(false))
  }, [id])

  useEffect(load, [load])

  const handleQueryChange = (newQ) => {
    setQuery(newQ)
    setQueryDirty(true)
    setPreviewResult(null)
  }

  const handleLogicChange = (l) => {
    setQueryLogic(l)
    setQueryDirty(true)
    setPreviewResult(null)
  }

  const handleSaveQuery = async () => {
    setSaving(true)
    await updateCampaign(id, { query, query_logic: queryLogic })
    setQueryDirty(false)
    setSaving(false)
  }

  const handleRun = async () => {
    if (queryDirty) await handleSaveQuery()
    setRunning(true)
    try {
      await runCampaign(id)
      await load()
      setActiveTab('results')
    } finally {
      setRunning(false)
    }
  }

  const handlePreview = async () => {
    setPreviewing(true)
    try {
      const res = await previewCampaignQuery({
        query,
        query_logic: queryLogic,
        scan_id: campaign?.scan_id || activeScanId,
      })
      setPreviewResult(res)
    } finally {
      setPreviewing(false)
    }
  }

  const handleSaveName = async () => {
    await updateCampaign(id, { name: nameVal, description: descVal })
    setCampaign(c => ({ ...c, name: nameVal, description: descVal }))
    setEditingName(false)
  }

  const handleStatusChange = async (status) => {
    await updateCampaign(id, { status })
    setCampaign(c => ({ ...c, status }))
  }

  if (loading) return <Spinner />
  if (!campaign) return <EmptyState icon={Target} title='Campaign not found' />

  const hasResults = campaign.owner_groups?.length > 0
  const totalFindings = campaign.finding_count || 0

  return (
    <div>
      {/* Breadcrumb */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16, fontSize: 13 }}>
        <button onClick={() => navigate('/campaigns')}
          style={{ display: 'flex', alignItems: 'center', gap: 4, background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 0 }}>
          <ChevronLeft size={14} /> Campaigns
        </button>
        <span style={{ color: 'var(--text-muted)' }}>/</span>
        <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{campaign.name}</span>
      </div>

      {/* Header */}
      <div style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)',
        borderRadius: 12, padding: '20px 24px', marginBottom: 20,
      }}>
        {editingName ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <input
              value={nameVal}
              onChange={e => setNameVal(e.target.value)}
              style={{
                fontSize: 18, fontWeight: 700, background: 'var(--bg-secondary)',
                border: '1px solid var(--border)', borderRadius: 8, padding: '6px 10px',
                color: 'var(--text-primary)',
              }}
            />
            <textarea
              value={descVal}
              onChange={e => setDescVal(e.target.value)}
              placeholder='Campaign description…'
              rows={2}
              style={{
                fontSize: 13, background: 'var(--bg-secondary)',
                border: '1px solid var(--border)', borderRadius: 8, padding: '6px 10px',
                color: 'var(--text-primary)', resize: 'none', fontFamily: 'inherit',
              }}
            />
            <div style={{ display: 'flex', gap: 8 }}>
              <Button size='sm' onClick={handleSaveName}><Save size={12} /> Save</Button>
              <Button variant='ghost' size='sm' onClick={() => setEditingName(false)}>Cancel</Button>
            </div>
          </div>
        ) : (
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 16 }}>
            <div style={{ flex: 1 }}>
              <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 4 }}>
                <div style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-primary)' }}>
                  {campaign.name}
                </div>
                <button onClick={() => setEditingName(true)}
                  style={{ padding: 4, background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', display: 'flex' }}>
                  <Edit2 size={13} />
                </button>
              </div>
              {campaign.description && (
                <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 8 }}>{campaign.description}</div>
              )}
              <div style={{ display: 'flex', gap: 16, fontSize: 12, color: 'var(--text-muted)' }}>
                {totalFindings > 0 && <span style={{ color: '#f87171', fontWeight: 600 }}>{totalFindings} findings</span>}
                {campaign.critical_count > 0 && <span style={{ color: '#fca5a5' }}>{campaign.critical_count} critical</span>}
                {campaign.exploit_count > 0 && <span style={{ color: '#fb923c' }}>{campaign.exploit_count} with exploits</span>}
                {campaign.last_run_at && <span>Last run {new Date(campaign.last_run_at).toLocaleString()}</span>}
              </div>
            </div>

            {/* Status + Run */}
            <div style={{ display: 'flex', gap: 8, flexShrink: 0, alignItems: 'center' }}>
              <select
                value={campaign.status}
                onChange={e => handleStatusChange(e.target.value)}
                style={{
                  padding: '6px 10px', background: 'var(--bg-secondary)',
                  border: '1px solid var(--border)', borderRadius: 8,
                  fontSize: 12, color: 'var(--text-primary)', cursor: 'pointer',
                }}
              >
                {STATUS_OPTIONS.map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
              </select>

              {queryDirty && (
                <Button variant='ghost' size='sm' onClick={handleSaveQuery} disabled={saving}>
                  <Save size={12} /> {saving ? 'Saving…' : 'Save Query'}
                </Button>
              )}

              <button
                onClick={handleRun}
                disabled={running || query.length === 0}
                style={{
                  display: 'flex', alignItems: 'center', gap: 6,
                  padding: '8px 18px', borderRadius: 8, fontSize: 13, fontWeight: 700,
                  border: 'none', background: '#1d4ed8', color: '#fff',
                  cursor: query.length === 0 ? 'not-allowed' : 'pointer',
                  opacity: query.length === 0 ? 0.5 : 1,
                }}
              >
                {running ? <RefreshCw size={14} className='spin' /> : <Play size={14} />}
                {running ? 'Running…' : 'Run Campaign'}
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 0, marginBottom: 20, borderBottom: '1px solid var(--border)' }}>
        {[
          { key: 'query', label: 'Query Builder', icon: Target },
          { key: 'results', label: `Results${totalFindings > 0 ? ` (${totalFindings})` : ''}`, icon: Layers },
          { key: 'workflows', label: 'Workflows', icon: GitBranch },
        ].map(({ key, label, icon: Icon }) => (
          <button
            key={key}
            onClick={() => setActiveTab(key)}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              padding: '10px 18px', background: 'none', border: 'none',
              borderBottom: activeTab === key ? '2px solid #60a5fa' : '2px solid transparent',
              color: activeTab === key ? '#60a5fa' : 'var(--text-muted)',
              fontSize: 13, fontWeight: 600, cursor: 'pointer', transition: 'color 0.15s',
            }}
          >
            <Icon size={14} />
            {label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {activeTab === 'query' && (
        <QueryBuilder
          query={query}
          queryLogic={queryLogic}
          onChange={handleQueryChange}
          onLogicChange={handleLogicChange}
          onPreview={handlePreview}
          previewing={previewing}
          previewResult={previewResult}
        />
      )}

      {activeTab === 'results' && (
        <div>
          {!hasResults ? (
            <EmptyState
              icon={Play}
              title={query.length === 0 ? 'Build your query first' : 'Run the campaign to see results'}
              sub={query.length === 0
                ? 'Switch to the Query Builder tab and add conditions to define which assets to target.'
                : 'Click "Run Campaign" to execute the query and populate findings with owner assignments.'}
            >
              {query.length > 0 && (
                <button onClick={handleRun} disabled={running}
                  style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '10px 20px', borderRadius: 8, fontSize: 13, fontWeight: 700, border: 'none', background: '#1d4ed8', color: '#fff', cursor: 'pointer' }}>
                  <Play size={14} /> Run Now
                </button>
              )}
            </EmptyState>
          ) : (
            <>
              {/* Summary bar */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 12, marginBottom: 20 }}>
                <div style={{ background: '#dc262622', border: '1px solid #dc262644', borderRadius: 10, padding: '12px 16px' }}>
                  <div style={{ fontSize: 11, color: '#fca5a5', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>Critical</div>
                  <div style={{ fontSize: 26, fontWeight: 700, color: '#fca5a5' }}>{campaign.critical_count}</div>
                </div>
                <div style={{ background: '#78350f22', border: '1px solid #78350f44', borderRadius: 10, padding: '12px 16px' }}>
                  <div style={{ fontSize: 11, color: '#fcd34d', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>With Exploits</div>
                  <div style={{ fontSize: 26, fontWeight: 700, color: '#fcd34d' }}>{campaign.exploit_count}</div>
                </div>
                <div style={{ background: '#1e3a5f22', border: '1px solid #1e3a5f44', borderRadius: 10, padding: '12px 16px' }}>
                  <div style={{ fontSize: 11, color: '#60a5fa', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>Owner Groups</div>
                  <div style={{ fontSize: 26, fontWeight: 700, color: '#60a5fa' }}>{campaign.owner_groups?.length}</div>
                </div>
                <div style={{ background: '#14532d22', border: '1px solid #14532d44', borderRadius: 10, padding: '12px 16px' }}>
                  <div style={{ fontSize: 11, color: '#4ade80', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>Total Findings</div>
                  <div style={{ fontSize: 26, fontWeight: 700, color: '#4ade80' }}>{totalFindings}</div>
                </div>
              </div>

              {/* Owner groups */}
              {campaign.owner_groups.map((group, idx) => (
                <OwnerGroup
                  key={group.owner_key}
                  group={group}
                  campaignId={campaign.id}
                  onOwnerUpdate={load}
                  defaultExpanded={idx === 0}
                />
              ))}
            </>
          )}
        </div>
      )}

      {activeTab === 'workflows' && (
        <CampaignWorkflows campaignId={campaign.id} hasResults={hasResults} />
      )}
    </div>
  )
}

// ─── Campaign Workflows Tab ──────────────────────
function CampaignWorkflows({ campaignId, hasResults }) {
  const navigate = useNavigate()
  const [workflows, setWorkflows] = useState([])
  const [templates, setTemplates] = useState([])
  const [loading, setLoading] = useState(true)
  const [showAdd, setShowAdd] = useState(false)
  const [executing, setExecuting] = useState(null)
  const [execResults, setExecResults] = useState({})

  useEffect(() => {
    Promise.all([
      getWorkflows(campaignId),
      getWorkflowTemplates(),
    ]).then(([wfs, tplData]) => {
      setWorkflows(wfs)
      setTemplates(tplData.templates || [])
    }).finally(() => setLoading(false))
  }, [campaignId])

  const handleCreateFromTemplate = async (tpl) => {
    const wf = await createWorkflowFromTemplate({
      template_id: tpl.id,
      campaign_id: campaignId,
    })
    setWorkflows(prev => [wf, ...prev])
    setShowAdd(false)
  }

  const handleCreateCustom = async () => {
    const wf = await createWorkflow({
      name: 'Custom Workflow',
      campaign_id: campaignId,
    })
    navigate(`/workflows/${wf.id}`)
  }

  const handleDelete = async (wfId) => {
    await deleteWorkflow(wfId)
    setWorkflows(prev => prev.filter(w => w.id !== wfId))
  }

  const handleRun = async (wfId) => {
    setExecuting(wfId)
    try {
      const result = await executeWorkflow(wfId)
      setExecResults(prev => ({ ...prev, [wfId]: result }))
      // Refresh workflow data
      const updated = await getWorkflows(campaignId)
      setWorkflows(updated)
    } catch (e) {
      setExecResults(prev => ({ ...prev, [wfId]: { status: 'failed', error: e.message } }))
    }
    setExecuting(null)
  }

  if (loading) return <Spinner />

  return (
    <div>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <div>
          <div style={{ fontWeight: 700, fontSize: 14, marginBottom: 2 }}>Automation Workflows</div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            Attach workflows to automate actions on campaign results
          </div>
        </div>
        <Button size="sm" onClick={() => setShowAdd(true)}>
          <Plus size={14} /> Add Workflow
        </Button>
      </div>

      {!hasResults && (
        <div style={{
          padding: '12px 16px', marginBottom: 16, borderRadius: 8,
          background: '#78350f11', border: '1px solid #78350f33',
          fontSize: 12, color: '#f59e0b',
        }}>
          Run the campaign first to populate findings. Workflows will process the campaign results.
        </div>
      )}

      {/* Workflow list */}
      {workflows.length === 0 ? (
          <EmptyState
            icon={GitBranch}
            title="No workflows attached"
            sub="Add a workflow from a template or create a custom one to automate remediation actions."
          >
            <Button onClick={() => setShowAdd(true)}><GitBranch size={14} /> Add Workflow</Button>
          </EmptyState>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {workflows.map(wf => {
              const result = execResults[wf.id]
              return (
                <Card key={wf.id} style={{ padding: '14px 18px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                    <div style={{
                      width: 38, height: 38, borderRadius: 10, background: '#312e8133',
                      display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                    }}>
                      <GitBranch size={16} color='#818cf8' />
                    </div>

                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginBottom: 2 }}>
                        <span style={{ fontWeight: 600, fontSize: 14 }}>{wf.name}</span>
                        <Pill color={wf.status === 'active' ? '#22c55e' : '#71717a'}>{wf.status}</Pill>
                      </div>
                      {wf.description && (
                        <div style={{ fontSize: 12, color: 'var(--text-muted)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {wf.description}
                        </div>
                      )}
                      <div style={{ display: 'flex', gap: 12, fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                        <span>{wf.node_count || 0} nodes</span>
                        <span>{wf.run_count || 0} runs</span>
                        {wf.last_run_at && <span>Last: {new Date(wf.last_run_at).toLocaleString()}</span>}
                      </div>
                      {result && (
                        <div style={{ marginTop: 6 }}>
                          <Pill color={result.status === 'completed' ? '#22c55e' : '#ef4444'}>
                            {result.status === 'completed'
                              ? `Completed - ${result.items_processed} items processed`
                              : `Failed: ${result.error || 'Unknown error'}`}
                          </Pill>
                        </div>
                      )}
                    </div>

                    <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
                      <Button size="sm" variant="ghost"
                        onClick={() => navigate(`/workflows/${wf.id}`)}>
                        <Edit2 size={12} /> Edit
                      </Button>
                      <Button size="sm" variant="primary"
                        onClick={() => handleRun(wf.id)}
                        disabled={executing === wf.id || !hasResults}>
                        <Play size={12} /> {executing === wf.id ? 'Running...' : 'Run'}
                      </Button>
                      <button onClick={() => handleDelete(wf.id)}
                        style={{ padding: '4px 6px', borderRadius: 6, border: '1px solid var(--border)', background: 'transparent', color: 'var(--text-muted)', cursor: 'pointer', display: 'flex' }}>
                        <Trash2 size={14} />
                      </button>
                    </div>
                  </div>
                </Card>
              )
            })}
          </div>
        )
      }

      {/* Add workflow modal */}
      {showAdd && (
        <div style={{
          position: 'fixed', inset: 0, background: '#000a', zIndex: 200,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }} onClick={() => setShowAdd(false)}>
          <div style={{
            background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 14,
            padding: 28, minWidth: 520, maxWidth: 600, maxHeight: '80vh', overflow: 'auto',
          }} onClick={e => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
              <div style={{ fontWeight: 700, fontSize: 16 }}>Add Workflow to Campaign</div>
              <button onClick={() => setShowAdd(false)}
                style={{ background: 'none', border: 'none', cursor: 'pointer' }}><X size={18} /></button>
            </div>

            {/* Templates */}
            <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', color: '#818cf8', marginBottom: 8, letterSpacing: '0.05em' }}>
              From Template
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 20 }}>
              {templates.map(tpl => (
                <button key={tpl.id} onClick={() => handleCreateFromTemplate(tpl)}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 12,
                    padding: '12px 14px', borderRadius: 10,
                    border: '1px solid var(--border)', background: '#fff',
                    cursor: 'pointer', textAlign: 'left', width: '100%',
                    transition: 'border-color 0.15s',
                  }}
                  onMouseEnter={e => e.currentTarget.style.borderColor = '#818cf8'}
                  onMouseLeave={e => e.currentTarget.style.borderColor = 'var(--border)'}
                >
                  <div style={{
                    width: 36, height: 36, borderRadius: 8, background: '#312e8122',
                    display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                  }}>
                    <GitBranch size={16} color='#818cf8' />
                  </div>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontWeight: 600, fontSize: 13 }}>{tpl.name}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{tpl.description}</div>
                  </div>
                  <Pill color="#94a3b8">{tpl.nodes?.length || 0} nodes</Pill>
                </button>
              ))}
            </div>

            {/* Custom */}
            <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', color: '#64748b', marginBottom: 8, letterSpacing: '0.05em' }}>
              Or
            </div>
            <button onClick={handleCreateCustom}
              style={{
                display: 'flex', alignItems: 'center', gap: 12, width: '100%',
                padding: '12px 14px', borderRadius: 10,
                border: '1px dashed var(--border)', background: '#f8fafc',
                cursor: 'pointer', textAlign: 'left',
              }}>
              <Plus size={18} color='#94a3b8' />
              <div>
                <div style={{ fontWeight: 600, fontSize: 13 }}>Create Custom Workflow</div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Build from scratch in the visual editor</div>
              </div>
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
