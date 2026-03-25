import React, { useState, useEffect, useCallback } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import {
  Target, Play, Plus, X, ChevronDown, ChevronRight, ChevronLeft,
  User, Users, Zap, AlertTriangle, CheckCircle, Edit2, Save, Eye,
  RefreshCw, GitBranch, Trash2, Ticket, ExternalLink, Hash,
} from 'lucide-react'
import { useScan } from '../../App.jsx'
import {
  getCampaign, updateCampaign, runCampaign,
  previewCampaignQuery, updateCampaignFinding,
  getWorkflows, createWorkflowFromTemplate, createWorkflow, deleteWorkflow,
  executeWorkflow, getWorkflowTemplates, authListUsers,
  getCampaignTickets, syncFindingTickets, createCampaignSlackChannel,
} from '../../api.js'
import { SeverityBadge, ScoreBar, Button, Spinner, EmptyState, Card, Pill, ErrorBanner, SkeletonDetail, Table, buildFindingBreakdown, useRiskWeights } from '../shared/ui.jsx'
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

// ─── Ownership Editor ─────────────────────────────────────
const OWNER_ROLES = ['IT', 'DevOps', 'SecOps', 'AppSec', 'Custom']

function OwnershipEditor({ current, onSave, onCancel }) {
  const { t } = useTranslation()
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
        {inp(ownerName, setOwnerName, t('campaigns.ownerName'))}
        {inp(ownerEmail, setOwnerEmail, t('campaigns.email'))}
        <select
          value={ownerRole}
          onChange={e => setOwnerRole(e.target.value)}
          style={{
            padding: '5px 8px', background: 'var(--bg-secondary)',
            border: '1px solid var(--border)', borderRadius: 6, fontSize: 12,
            color: 'var(--text-primary)', minWidth: 90,
          }}
        >
          <option value=''>{t('campaigns.role')}</option>
          {OWNER_ROLES.map(r => <option key={r} value={r}>{r}</option>)}
        </select>
      </div>
      <div style={{ display: 'flex', gap: 8 }}>
        {inp(team, setTeam, t('campaigns.teamSquad'))}
        {inp(notes, setNotes, t('campaigns.notes'))}
      </div>
      <div style={{ display: 'flex', gap: 8 }}>
        <Button size='sm' onClick={() => onSave({ owner_name: ownerName, owner_email: ownerEmail, owner_role: ownerRole, team, notes })}>
          <Save size={12} /> {t('common.save')}
        </Button>
        <Button variant='ghost' size='sm' onClick={onCancel}>{t('common.cancel')}</Button>
      </div>
    </div>
  )
}

function OwnerChip({ role, name, team, editable, onEdit }) {
  const { t } = useTranslation()
  const c = getOwnerColors(role)
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      <span style={{
        display: 'inline-flex', alignItems: 'center', gap: 4,
        background: c.bg, color: c.text, border: `1px solid ${c.border}`,
        borderRadius: 6, padding: '3px 10px', fontSize: 11, fontWeight: 600,
      }}>
        <User size={10} />
        {name || role || t('campaigns.unassigned')}
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
function CampaignFindingCard({ finding, campaignId, onOwnerUpdate, riskWeights }) {
  const { t } = useTranslation()
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
                {t('campaigns.exploit')}
              </span>
            )}
            {finding.zero_day && (
              <span style={{ fontSize: 10, fontWeight: 700, color: '#dc2626', background: '#450a0a', border: '1px solid #991b1b', borderRadius: 4, padding: '1px 6px' }}>
                {t('campaigns.zeroDay')}
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
              <option value='open'>{t('campaigns.open')}</option>
              <option value='in_progress'>{t('campaigns.inProgress')}</option>
              <option value='resolved'>{t('campaigns.resolved')}</option>
              <option value='wont_fix'>{t('campaigns.wontFix')}</option>
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
          <ScoreBar score={finding.priority_score} breakdown={buildFindingBreakdown(finding, riskWeights)} />
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
                {t('campaigns.recommendedSteps')}
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
              {t('campaigns.viewDetails')} <ChevronRight size={12} />
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Owner Group Section ──────────────────────────────────
function OwnerGroup({ group, campaignId, onOwnerUpdate, riskWeights, defaultExpanded = true }) {
  const { t } = useTranslation()
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
            {group.owner_name || group.owner_role || t('campaigns.unassigned')}
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
            <div style={{ color: 'var(--text-muted)', fontSize: 10 }}>{t('findings.title')}</div>
          </div>
          {group.critical_count > 0 && (
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontWeight: 700, color: '#fca5a5' }}>{group.critical_count}</div>
              <div style={{ color: 'var(--text-muted)', fontSize: 10 }}>{t('severity.critical')}</div>
            </div>
          )}
          {group.exploit_count > 0 && (
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontWeight: 700, color: '#fb923c' }}>{group.exploit_count}</div>
              <div style={{ color: 'var(--text-muted)', fontSize: 10 }}>{t('findings.exploit')}</div>
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
              riskWeights={riskWeights}
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
  const { t } = useTranslation()
  const { id } = useParams()
  const navigate = useNavigate()
  const { activeScanId } = useScan()
  const riskWeights = useRiskWeights()

  const [campaign, setCampaign] = useState(null)
  const [loading, setLoading] = useState(true)
  const [fetchError, setFetchError] = useState(null)
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
  const [activeTab, setActiveTab] = useState('campaign') // 'campaign' | 'workflows' | 'tickets'
  const [queryExpanded, setQueryExpanded] = useState(false) // collapsed by default when results exist
  const [users, setUsers] = useState([])
  const [campaignTickets, setCampaignTickets] = useState([])
  const [ticketsLoading, setTicketsLoading] = useState(false)
  const [creatingSlackChannel, setCreatingSlackChannel] = useState(false)
  const [slackChannelError, setSlackChannelError] = useState(null)

  useEffect(() => {
    authListUsers().then(data => setUsers(data.users || data || [])).catch(() => {})
  }, [])

  const handleOwnerChange = async (newOwnerId) => {
    const oid = newOwnerId ? Number(newOwnerId) : null
    await updateCampaign(id, { owner_id: oid })
    const u = users.find(u => u.id === oid)
    setCampaign(c => ({ ...c, owner_id: oid, owner_name: u ? (u.display_name || u.email) : null }))
  }

  const statusLabel = (s) => {
    const map = { draft: t('campaigns.draft'), active: t('campaigns.active'), paused: t('campaigns.paused'), completed: t('campaigns.completed') }
    return map[s] || s.charAt(0).toUpperCase() + s.slice(1)
  }

  const load = useCallback((autoRun = false) => {
    setLoading(true)
    setFetchError(null)
    getCampaign(id)
      .then(data => {
        setCampaign(data)
        setQuery(data.query || [])
        setQueryLogic(data.query_logic || 'AND')
        setNameVal(data.name || '')
        setDescVal(data.description || '')
        if (autoRun && !(data.owner_groups?.length > 0)) {
          setRunning(true)
          runCampaign(id)
            .then(() => getCampaign(id))
            .then(fresh => {
              setCampaign(fresh)
              setQuery(fresh.query || [])
              setQueryLogic(fresh.query_logic || 'AND')
            })
            .finally(() => setRunning(false))
        }
      })
      .catch(() => setFetchError('Failed to load campaign.'))
      .finally(() => setLoading(false))
  }, [id])

  useEffect(() => { load(true) }, [load])

  // Load campaign tickets
  const loadTickets = useCallback(() => {
    if (!id) return
    setTicketsLoading(true)
    getCampaignTickets(id)
      .then(data => setCampaignTickets(data.tickets || []))
      .catch(() => setCampaignTickets([]))
      .finally(() => setTicketsLoading(false))
  }, [id])

  useEffect(() => {
    if (campaign && campaign.owner_groups?.length > 0) loadTickets()
  }, [campaign?.id, campaign?.owner_groups?.length])

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
      load()
      setQueryExpanded(false) // collapse query builder to show results
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

  const handleCreateSlackChannel = async () => {
    setCreatingSlackChannel(true)
    setSlackChannelError(null)
    try {
      const result = await createCampaignSlackChannel(id)
      setCampaign(c => ({ ...c, slack_channel_id: result.channel_id, slack_channel_name: result.channel_name }))
    } catch (e) {
      setSlackChannelError(e.message || 'Failed to create Slack channel')
    } finally {
      setCreatingSlackChannel(false)
    }
  }

  if (loading) return <SkeletonDetail />
  if (fetchError) return <ErrorBanner error={fetchError} onRetry={() => load(false)} />
  if (!campaign) return <EmptyState icon={Target} title={t('campaigns.notFound')} />

  const hasResults = campaign.owner_groups?.length > 0
  const totalFindings = campaign.finding_count || 0

  return (
    <div>
      {/* Breadcrumb */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16, fontSize: 13 }}>
        <button onClick={() => navigate('/campaigns')}
          style={{ display: 'flex', alignItems: 'center', gap: 4, background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 0 }}>
          <ChevronLeft size={14} /> {t('campaigns.title')}
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
              placeholder={t('campaigns.campaignDescription')}
              rows={2}
              style={{
                fontSize: 13, background: 'var(--bg-secondary)',
                border: '1px solid var(--border)', borderRadius: 8, padding: '6px 10px',
                color: 'var(--text-primary)', resize: 'none', fontFamily: 'inherit',
              }}
            />
            <div style={{ display: 'flex', gap: 8 }}>
              <Button size='sm' onClick={handleSaveName}><Save size={12} /> {t('common.save')}</Button>
              <Button variant='ghost' size='sm' onClick={() => setEditingName(false)}>{t('common.cancel')}</Button>
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
                {totalFindings > 0 && <span style={{ color: '#f87171', fontWeight: 600 }}>{t('campaigns.findingsCount', { count: totalFindings })}</span>}
                {campaign.critical_count > 0 && <span style={{ color: '#fca5a5' }}>{campaign.critical_count} {t('severity.critical').toLowerCase()}</span>}
                {campaign.exploit_count > 0 && <span style={{ color: '#fb923c' }}>{campaign.exploit_count} {t('campaigns.withExploits').toLowerCase()}</span>}
                {campaign.last_run_at && <span>{t('campaigns.lastRunAt', { date: new Date(campaign.last_run_at).toLocaleString() })}</span>}
              </div>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 8, fontSize: 12 }}>
                <User size={12} color="var(--text-muted)" />
                <span style={{ color: 'var(--text-muted)' }}>Owner:</span>
                <select
                  value={campaign.owner_id || ''}
                  onChange={e => handleOwnerChange(e.target.value)}
                  style={{
                    padding: '3px 8px', background: 'var(--bg-secondary)',
                    border: '1px solid var(--border)', borderRadius: 6,
                    fontSize: 12, color: 'var(--text-primary)', cursor: 'pointer',
                  }}
                >
                  <option value="">Unassigned</option>
                  {users.map(u => (
                    <option key={u.id} value={u.id}>
                      {u.display_name || u.email}{u.display_name ? ` (${u.email})` : ''}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Status + Run */}
            <div style={{ display: 'flex', gap: 8, flexShrink: 0, alignItems: 'center', flexWrap: 'wrap', justifyContent: 'flex-end' }}>
              <select
                value={campaign.status}
                onChange={e => handleStatusChange(e.target.value)}
                style={{
                  padding: '6px 10px', background: 'var(--bg-secondary)',
                  border: '1px solid var(--border)', borderRadius: 8,
                  fontSize: 12, color: 'var(--text-primary)', cursor: 'pointer',
                }}
              >
                {STATUS_OPTIONS.map(s => <option key={s} value={s}>{statusLabel(s)}</option>)}
              </select>

              {queryDirty && (
                <Button variant='ghost' size='sm' onClick={handleSaveQuery} disabled={saving}>
                  <Save size={12} /> {saving ? t('campaigns.savingQuery') : t('campaigns.saveQuery')}
                </Button>
              )}

              {/* Slack channel */}
              {campaign.slack_channel_name ? (
                <div style={{
                  display: 'flex', alignItems: 'center', gap: 5,
                  padding: '6px 12px', borderRadius: 8, fontSize: 12, fontWeight: 600,
                  background: '#1a1a2e', border: '1px solid #4a154b55', color: '#e01e5a',
                }}>
                  <Hash size={12} />
                  {campaign.slack_channel_name}
                </div>
              ) : (
                <button
                  onClick={handleCreateSlackChannel}
                  disabled={creatingSlackChannel || !hasResults}
                  title={!hasResults ? 'Run campaign first to identify collaborators' : 'Create a Slack channel and invite all collaborators'}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 6,
                    padding: '7px 14px', borderRadius: 8, fontSize: 12, fontWeight: 600,
                    border: '1px solid #4a154b66', background: '#4a154b22', color: '#e01e5a',
                    cursor: (!hasResults || creatingSlackChannel) ? 'not-allowed' : 'pointer',
                    opacity: !hasResults ? 0.5 : 1,
                  }}
                >
                  <Hash size={13} />
                  {creatingSlackChannel ? 'Creating…' : 'Create Slack Channel'}
                </button>
              )}
              {slackChannelError && (
                <div style={{ fontSize: 11, color: '#f87171', maxWidth: 200 }}>{slackChannelError}</div>
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
                {running ? t('campaigns.running') : t('campaigns.runCampaign')}
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 0, marginBottom: 20, borderBottom: '1px solid var(--border)' }}>
        {[
          { key: 'campaign', label: totalFindings > 0 ? `Campaign (${totalFindings})` : 'Campaign', icon: Target },
          { key: 'workflows', label: t('campaigns.workflows'), icon: GitBranch },
          ...(campaignTickets.length > 0 ? [{ key: 'tickets', label: `Tickets (${campaignTickets.length})`, icon: Ticket }] : []),
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
      {activeTab === 'campaign' && (
        <div>
          {/* Query Builder — collapsible, auto-expanded when no results */}
          <Card style={{ marginBottom: 20 }}>
            <button
              onClick={() => setQueryExpanded(e => !e)}
              style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                width: '100%', background: 'none', border: 'none', cursor: 'pointer',
                padding: 0, color: 'var(--text-primary)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                {(queryExpanded || !hasResults) ? <ChevronDown size={14} color='var(--text-muted)' /> : <ChevronRight size={14} color='var(--text-muted)' />}
                <span style={{ fontWeight: 700, fontSize: 14 }}>{t('campaigns.searchQuery')}</span>
                <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                  {query.length} condition{query.length !== 1 ? 's' : ''}
                </span>
                {queryDirty && (
                  <span style={{ fontSize: 10, fontWeight: 700, color: '#f59e0b', background: '#78350f22', border: '1px solid #78350f44', borderRadius: 4, padding: '1px 6px' }}>
                    Unsaved
                  </span>
                )}
              </div>
              {!queryExpanded && hasResults && query.length > 0 && (
                <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Click to edit conditions</span>
              )}
            </button>

            {(queryExpanded || !hasResults) && (
              <div style={{ marginTop: 14 }}>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 10 }}>
                  {t('campaigns.searchQueryDesc')}
                </div>

                {query.length === 0 && (
                  <div style={{
                    padding: '12px', textAlign: 'center', background: 'var(--bg-secondary)',
                    borderRadius: 8, border: '1px dashed var(--border)',
                    fontSize: 12, color: 'var(--text-muted)', marginBottom: 10,
                  }}>
                    {t('campaigns.noConditions')}
                  </div>
                )}

                <RuleBuilder
                  conditions={query}
                  logic={queryLogic}
                  onChange={(conds, lgc) => { handleQueryChange(conds); handleLogicChange(lgc) }}
                  showLogic
                  addLabel={t('campaigns.addCondition')}
                />

                {/* Preview + Save + Run */}
                <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 12, flexWrap: 'wrap' }}>
                  <button
                    onClick={handlePreview}
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
                    {previewing ? t('campaigns.previewing') : t('campaigns.preview')}
                  </button>
                  {previewResult && (
                    <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                      → <span style={{ color: '#60a5fa', fontWeight: 600 }}>{t('campaigns.assetsFound', { count: previewResult.asset_count })}</span>
                      {' · '}
                      <span style={{ color: '#f87171', fontWeight: 600 }}>{t('campaigns.findingsFound', { count: previewResult.finding_count })}</span>
                    </div>
                  )}
                </div>
              </div>
            )}
          </Card>

          {/* Results */}
          {!hasResults ? (
            query.length > 0 && (
              <EmptyState
                icon={Play}
                title={t('campaigns.runToSeeResults')}
                sub={t('campaigns.runToSeeResultsDesc')}
              >
                <button onClick={handleRun} disabled={running}
                  style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '10px 20px', borderRadius: 8, fontSize: 13, fontWeight: 700, border: 'none', background: '#1d4ed8', color: '#fff', cursor: 'pointer' }}>
                  <Play size={14} /> {t('campaigns.runNow')}
                </button>
              </EmptyState>
            )
          ) : (
            <>
              {/* Summary bar */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 12, marginBottom: 20 }}>
                <div style={{ background: '#dc262622', border: '1px solid #dc262644', borderRadius: 10, padding: '12px 16px' }}>
                  <div style={{ fontSize: 11, color: '#fca5a5', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>{t('campaigns.critical')}</div>
                  <div style={{ fontSize: 26, fontWeight: 700, color: '#fca5a5' }}>{campaign.critical_count}</div>
                </div>
                <div style={{ background: '#78350f22', border: '1px solid #78350f44', borderRadius: 10, padding: '12px 16px' }}>
                  <div style={{ fontSize: 11, color: '#fcd34d', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>{t('campaigns.withExploits')}</div>
                  <div style={{ fontSize: 26, fontWeight: 700, color: '#fcd34d' }}>{campaign.exploit_count}</div>
                </div>
                <div style={{ background: '#1e3a5f22', border: '1px solid #1e3a5f44', borderRadius: 10, padding: '12px 16px' }}>
                  <div style={{ fontSize: 11, color: '#60a5fa', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>{t('campaigns.ownerGroups')}</div>
                  <div style={{ fontSize: 26, fontWeight: 700, color: '#60a5fa' }}>{campaign.owner_groups?.length}</div>
                </div>
                <div style={{ background: '#14532d22', border: '1px solid #14532d44', borderRadius: 10, padding: '12px 16px' }}>
                  <div style={{ fontSize: 11, color: '#4ade80', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>{t('campaigns.totalFindings')}</div>
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
                  riskWeights={riskWeights}
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

      {activeTab === 'tickets' && (
        <Card style={{ padding: 0 }}>
          {ticketsLoading ? (
            <div style={{ padding: 32, textAlign: 'center' }}><Spinner /></div>
          ) : (
            <Table
              columns={[
                {
                  key: 'ticket_system', label: 'System', width: '90px',
                  render: (v) => <span style={{ textTransform: 'capitalize', fontWeight: 500, fontSize: 12 }}>{v}</span>
                },
                {
                  key: 'ticket_key', label: 'Ticket', width: '140px',
                  render: (v, row) => (
                    <a href={row.ticket_url} target="_blank" rel="noopener noreferrer"
                      onClick={e => e.stopPropagation()}
                      style={{ color: 'var(--accent)', fontWeight: 600, fontSize: 13, display: 'flex', alignItems: 'center', gap: 4 }}>
                      {v} <ExternalLink size={10} />
                    </a>
                  )
                },
                {
                  key: 'external_status', label: 'External Status',
                  render: (v, row) => v
                    ? <Pill label={v} color={row.mapped_status === 'resolved' ? '#22c55e' : row.mapped_status === 'in_progress' ? '#3b82f6' : '#6b7280'} />
                    : <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>Not synced</span>
                },
                {
                  key: 'mapped_status', label: 'Mapped Status',
                  render: (v) => v
                    ? <Pill label={v.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())} color={v === 'resolved' ? '#22c55e' : v === 'in_progress' ? '#3b82f6' : '#6b7280'} />
                    : <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
                },
                {
                  key: 'finding_plugin_name', label: 'Finding',
                  render: (v, row) => (
                    <div>
                      <div style={{ fontSize: 12, fontWeight: 500 }}>{v || '—'}</div>
                      {row.finding_severity_label && <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>{row.finding_severity_label}</span>}
                    </div>
                  )
                },
                {
                  key: 'last_synced_at', label: 'Last Synced', width: '150px',
                  render: (v) => v
                    ? <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{new Date(v).toLocaleString()}</span>
                    : <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>Never</span>
                },
              ]}
              rows={campaignTickets}
              onRowClick={(row) => navigate(`/findings/${row.finding_id}`)}
              emptyMessage="No tickets linked to this campaign's findings"
            />
          )}
        </Card>
      )}
    </div>
  )
}

// ─── Campaign Workflows Tab ──────────────────────
function CampaignWorkflows({ campaignId, hasResults }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [workflows, setWorkflows] = useState([])
  const [templates, setTemplates] = useState([])
  const [loading, setLoading] = useState(true)
  const [wfError, setWfError] = useState(null)
  const [showAdd, setShowAdd] = useState(false)
  const [executing, setExecuting] = useState(null)
  const [execResults, setExecResults] = useState({})

  const loadWorkflows = () => {
    setLoading(true)
    setWfError(null)
    Promise.all([
      getWorkflows(campaignId),
      getWorkflowTemplates(),
    ]).then(([wfs, tplData]) => {
      setWorkflows(wfs)
      setTemplates(tplData.templates || [])
    }).catch(() => setWfError('Failed to load workflows.'))
      .finally(() => setLoading(false))
  }

  useEffect(() => { loadWorkflows() }, [campaignId])

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
  if (wfError) return <ErrorBanner error={wfError} onRetry={loadWorkflows} />

  return (
    <div>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <div>
          <div style={{ fontWeight: 700, fontSize: 14, marginBottom: 2 }}>{t('campaigns.automationWorkflows')}</div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            {t('campaigns.automationWorkflowsDesc')}
          </div>
        </div>
        <Button size="sm" onClick={() => setShowAdd(true)}>
          <Plus size={14} /> {t('campaigns.addWorkflow')}
        </Button>
      </div>

      {!hasResults && (
        <div style={{
          padding: '12px 16px', marginBottom: 16, borderRadius: 8,
          background: '#78350f11', border: '1px solid #78350f33',
          fontSize: 12, color: '#f59e0b',
        }}>
          {t('campaigns.runCampaignFirst')}
        </div>
      )}

      {/* Workflow list */}
      {workflows.length === 0 ? (
          <EmptyState
            icon={GitBranch}
            title={t('campaigns.noWorkflowsAttached')}
            sub={t('campaigns.noWorkflowsAttachedDesc')}
          >
            <Button onClick={() => setShowAdd(true)}><GitBranch size={14} /> {t('campaigns.addWorkflow')}</Button>
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
                        <span>{t('campaigns.nodes', { count: wf.node_count || 0 })}</span>
                        <span>{t('campaigns.runs', { count: wf.run_count || 0 })}</span>
                        {wf.last_run_at && <span>{t('campaigns.lastRunDate', { date: new Date(wf.last_run_at).toLocaleString() })}</span>}
                      </div>
                      {result && (
                        <div style={{ marginTop: 6 }}>
                          <Pill color={result.status === 'completed' ? '#22c55e' : '#ef4444'}>
                            {result.status === 'completed'
                              ? t('campaigns.completedItems', { count: result.items_processed })
                              : t('campaigns.failedError', { error: result.error || t('campaigns.unknownError') })}
                          </Pill>
                        </div>
                      )}
                    </div>

                    <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
                      <Button size="sm" variant="ghost"
                        onClick={() => navigate(`/workflows/${wf.id}`)}>
                        <Edit2 size={12} /> {t('common.edit')}
                      </Button>
                      <Button size="sm" variant="primary"
                        onClick={() => handleRun(wf.id)}
                        disabled={executing === wf.id || !hasResults}>
                        <Play size={12} /> {executing === wf.id ? t('campaigns.running') : t('campaigns.run')}
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
              <div style={{ fontWeight: 700, fontSize: 16 }}>{t('campaigns.addWorkflowToCampaign')}</div>
              <button onClick={() => setShowAdd(false)}
                style={{ background: 'none', border: 'none', cursor: 'pointer' }}><X size={18} /></button>
            </div>

            {/* Templates */}
            <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', color: '#818cf8', marginBottom: 8, letterSpacing: '0.05em' }}>
              {t('campaigns.fromTemplate')}
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
                  <Pill color="#94a3b8">{t('campaigns.nodes', { count: tpl.nodes?.length || 0 })}</Pill>
                </button>
              ))}
            </div>

            {/* Custom */}
            <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', color: '#64748b', marginBottom: 8, letterSpacing: '0.05em' }}>
              {t('campaigns.or')}
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
                <div style={{ fontWeight: 600, fontSize: 13 }}>{t('campaigns.createCustomWorkflow')}</div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{t('campaigns.buildFromScratch')}</div>
              </div>
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
