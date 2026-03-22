import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import {
  Target, Plus, Play, Trash2, Clock, AlertTriangle, CheckCircle, PauseCircle,
  ChevronRight, GitBranch, Zap, Settings, Download, Search,
  Flame, Shield, Timer, Wrench, Globe, Sparkles, FileText, CalendarClock, Siren,
} from 'lucide-react'
import { useScan } from '../../App.jsx'
import { getCampaigns, createCampaign, deleteCampaign, runCampaign, getWorkflows, createWorkflow, deleteWorkflow, getWorkflowTemplates, createWorkflowFromTemplate, exportConfig, importConfig, authListUsers } from '../../api.js'
import { Card, PageHeader, Button, Spinner, EmptyState, Pill, ExportImportButtons, ErrorBanner, SkeletonCard } from '../shared/ui.jsx'

const STATUS_KEYS = {
  draft:     { key: 'campaigns.draft',     color: 'var(--muted)',   bg: 'rgba(100,116,139,0.1)', border: 'rgba(100,116,139,0.25)', icon: Clock },
  active:    { key: 'campaigns.active',    color: 'var(--primary)', bg: 'rgba(37,99,235,0.1)',   border: 'rgba(37,99,235,0.25)',   icon: Play },
  completed: { key: 'campaigns.completed', color: 'var(--success)', bg: 'rgba(34,197,94,0.1)',   border: 'rgba(34,197,94,0.25)',   icon: CheckCircle },
  paused:    { key: 'campaigns.paused',    color: 'var(--warning)', bg: 'rgba(245,158,11,0.1)',  border: 'rgba(245,158,11,0.25)',  icon: PauseCircle },
}

function StatusBadge({ status }) {
  const { t } = useTranslation()
  const m = STATUS_KEYS[status] || STATUS_KEYS.draft
  const Icon = m.icon
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      background: m.bg, color: m.color, border: `1px solid ${m.border}`,
      borderRadius: 4, padding: '2px 8px', fontSize: 11, fontWeight: 600,
      textTransform: 'uppercase', letterSpacing: '0.04em',
    }}>
      <Icon size={10} />
      {t(m.key)}
    </span>
  )
}

// ─── Campaign Templates ──────────────────────────────────────────────────────
const CAMPAIGN_TEMPLATES = [
  {
    id: 'exploitable_now',
    icon: Flame,
    color: '#ef4444',
    bg: 'rgba(239,68,68,0.10)',
    border: 'rgba(239,68,68,0.25)',
    badge: 'Immediate Action',
    badgeColor: '#ef4444',
    name: 'Exploitable Now',
    description: 'Critical & High findings with a known weaponized or functional exploit — the highest-risk items demanding immediate remediation.',
    query: [
      { field: 'finding.severity', op: 'gte', value: 3 },
      { field: 'finding.exploit', op: 'is_true', value: true },
      { field: 'finding.exploit_maturity', op: 'eq', value: 'weaponized' },
    ],
    query_logic: 'AND',
  },
  {
    id: 'patch_tuesday',
    icon: CalendarClock,
    color: '#6366f1',
    bg: 'rgba(99,102,241,0.10)',
    border: 'rgba(99,102,241,0.25)',
    badge: 'Monthly Routine',
    badgeColor: '#6366f1',
    name: `Patch Tuesday — ${new Date().toLocaleString('default', { month: 'long', year: 'numeric' })}`,
    description: 'Critical and High severity findings with missing patches. Run this every Patch Tuesday to scope your monthly patching effort.',
    query: [
      { field: 'finding.severity', op: 'gte', value: 3 },
      { field: 'finding.missing_patches', op: 'is_true', value: true },
    ],
    query_logic: 'AND',
  },
  {
    id: 'sla_breached',
    icon: Siren,
    color: '#f59e0b',
    bg: 'rgba(245,158,11,0.10)',
    border: 'rgba(245,158,11,0.25)',
    badge: 'SLA Compliance',
    badgeColor: '#f59e0b',
    name: 'SLA Breached Findings',
    description: 'All findings that have already breached their SLA deadline. Prioritize these for escalation or remediation.',
    query: [
      { field: 'finding.sla_status', op: 'eq', value: 'breached' },
    ],
    query_logic: 'AND',
  },
  {
    id: 'internet_facing',
    icon: Globe,
    color: '#0ea5e9',
    bg: 'rgba(14,165,233,0.10)',
    border: 'rgba(14,165,233,0.25)',
    badge: 'Attack Surface',
    badgeColor: '#0ea5e9',
    name: 'Internet-Facing Critical Risk',
    description: 'High and Critical findings on internet-facing assets. These represent your most exposed attack surface.',
    query: [
      { field: 'inventory.is_internet_facing', op: 'is_true', value: true },
      { field: 'finding.severity', op: 'gte', value: 3 },
    ],
    query_logic: 'AND',
  },
  {
    id: 'quick_wins',
    icon: Wrench,
    color: '#22c55e',
    bg: 'rgba(34,197,94,0.10)',
    border: 'rgba(34,197,94,0.25)',
    badge: 'Easy Impact',
    badgeColor: '#22c55e',
    name: 'Quick Wins',
    description: 'High/Critical findings where the estimated remediation effort is low — maximum security impact with minimal engineering effort.',
    query: [
      { field: 'finding.severity', op: 'gte', value: 3 },
      { field: 'finding.effort', op: 'eq', value: 'quick_win' },
    ],
    query_logic: 'AND',
  },
  {
    id: 'new_this_scan',
    icon: Sparkles,
    color: '#a855f7',
    bg: 'rgba(168,85,247,0.10)',
    border: 'rgba(168,85,247,0.25)',
    badge: 'New Exposure',
    badgeColor: '#a855f7',
    name: 'New Vulnerabilities',
    description: 'Findings first seen in the latest scan — helps the team focus on newly introduced risk before it spreads.',
    query: [
      { field: 'finding.vulnerability_state', op: 'eq', value: 'New' },
    ],
    query_logic: 'AND',
  },
  {
    id: 'resurfaced',
    icon: Timer,
    color: '#f97316',
    bg: 'rgba(249,115,22,0.10)',
    border: 'rgba(249,115,22,0.25)',
    badge: 'Regression',
    badgeColor: '#f97316',
    name: 'Resurfaced & Regressions',
    description: 'Previously resolved findings that have come back. These often indicate incomplete fixes or re-introduced code.',
    query: [
      { field: 'finding.vulnerability_state', op: 'eq', value: 'Resurfaced' },
    ],
    query_logic: 'OR',
  },
  {
    id: 'zero_days',
    icon: Shield,
    color: '#dc2626',
    bg: 'rgba(220,38,38,0.10)',
    border: 'rgba(220,38,38,0.25)',
    badge: 'Critical Threat',
    badgeColor: '#dc2626',
    name: 'Zero-Day Exposure',
    description: 'Assets affected by zero-day vulnerabilities with no vendor patch available yet. Requires compensating controls.',
    query: [
      { field: 'finding.zero_day', op: 'is_true', value: true },
    ],
    query_logic: 'AND',
  },
  {
    id: 'ransomware',
    icon: Flame,
    color: '#b91c1c',
    bg: 'rgba(185,28,28,0.10)',
    border: 'rgba(185,28,28,0.30)',
    badge: 'Ransomware Risk',
    badgeColor: '#b91c1c',
    name: 'Ransomware Exposure',
    description: 'High/Critical findings with a known exploit and high EPSS probability — the vulnerabilities ransomware operators actively target for initial access.',
    query: [
      { field: 'finding.severity', op: 'gte', value: 3 },
      { field: 'finding.exploit', op: 'is_true', value: true },
      { field: 'finding.epss_score', op: 'gte', value: 0.5 },
    ],
    query_logic: 'AND',
  },
  {
    id: 'blank',
    icon: FileText,
    color: 'var(--text-muted)',
    bg: 'var(--bg-secondary)',
    border: 'var(--border)',
    badge: null,
    name: '',
    description: 'Start with an empty campaign and build your own conditions from scratch.',
    query: [],
    query_logic: 'AND',
  },
]

function TemplateBadge({ label, color }) {
  return (
    <span style={{
      fontSize: 10, fontWeight: 700, letterSpacing: '0.05em', textTransform: 'uppercase',
      padding: '2px 6px', borderRadius: 4,
      background: color + '22', color, border: `1px solid ${color}44`,
    }}>{label}</span>
  )
}

function CreateCampaignModal({ scanId, onClose, onCreate }) {
  const { t } = useTranslation()
  const [step, setStep] = useState('templates') // 'templates' | 'details'
  const [selectedTemplate, setSelectedTemplate] = useState(null)
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [saving, setSaving] = useState(false)
  const [users, setUsers] = useState([])
  const [ownerId, setOwnerId] = useState('')

  useEffect(() => {
    authListUsers().then(data => setUsers(data.users || data || [])).catch(() => {})
  }, [])

  const handleSelectTemplate = (tpl) => {
    setSelectedTemplate(tpl)
    setName(tpl.name)
    setDescription(tpl.description)
    setStep('details')
  }

  const handleBack = () => {
    setStep('templates')
    setSelectedTemplate(null)
    setName('')
    setDescription('')
    setOwnerId('')
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!name.trim()) return
    setSaving(true)
    try {
      const tpl = selectedTemplate || CAMPAIGN_TEMPLATES.find(t => t.id === 'blank')
      const c = await createCampaign({
        name: name.trim(),
        description,
        scan_id: scanId,
        query: tpl.query || [],
        query_logic: tpl.query_logic || 'AND',
        owner_id: ownerId ? Number(ownerId) : null,
      })
      onCreate(c)
    } finally {
      setSaving(false)
    }
  }

  const TplIcon = selectedTemplate?.icon || FileText

  return (
    <div style={{
      position: 'fixed', inset: 0, background: '#000b', zIndex: 200,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }} onClick={onClose}>
      <div style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 14,
        width: step === 'templates' ? 740 : 520,
        maxHeight: '85vh', overflow: 'hidden',
        display: 'flex', flexDirection: 'column',
        transition: 'width 0.2s',
      }} onClick={e => e.stopPropagation()}>

        {/* Header */}
        <div style={{ padding: '22px 24px 16px', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
          <div style={{ fontWeight: 700, fontSize: 16 }}>
            {step === 'templates' ? 'New Remediation Campaign' : 'Configure Campaign'}
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>
            {step === 'templates'
              ? 'Choose a template to get started quickly, or build from scratch.'
              : selectedTemplate?.id !== 'blank'
                ? `Based on: ${selectedTemplate?.name}`
                : 'Blank campaign — add conditions after creation.'}
          </div>
        </div>

        {step === 'templates' ? (
          /* ── Template grid ── */
          <div style={{ overflowY: 'auto', padding: 20 }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10 }}>
              {CAMPAIGN_TEMPLATES.map(tpl => {
                const Icon = tpl.icon
                return (
                  <button
                    key={tpl.id}
                    onClick={() => handleSelectTemplate(tpl)}
                    style={{
                      background: 'var(--bg-secondary)', border: `1px solid var(--border)`,
                      borderRadius: 10, padding: '14px 14px 12px',
                      textAlign: 'left', cursor: 'pointer',
                      display: 'flex', flexDirection: 'column', gap: 8,
                      transition: 'border-color 0.15s, background 0.15s',
                    }}
                    onMouseEnter={e => {
                      e.currentTarget.style.borderColor = tpl.color
                      e.currentTarget.style.background = tpl.bg
                    }}
                    onMouseLeave={e => {
                      e.currentTarget.style.borderColor = 'var(--border)'
                      e.currentTarget.style.background = 'var(--bg-secondary)'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                      <div style={{
                        width: 34, height: 34, borderRadius: 8,
                        background: tpl.bg, border: `1px solid ${tpl.border}`,
                        display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                      }}>
                        <Icon size={16} color={tpl.color} />
                      </div>
                      {tpl.badge && <TemplateBadge label={tpl.badge} color={tpl.badgeColor} />}
                    </div>

                    <div>
                      <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-primary)', marginBottom: 4 }}>
                        {tpl.id === 'blank' ? 'Blank Campaign' : tpl.name}
                      </div>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.5 }}>
                        {tpl.description}
                      </div>
                    </div>

                    {tpl.query.length > 0 && (
                      <div style={{ fontSize: 10, color: tpl.color, fontWeight: 600 }}>
                        {tpl.query.length} pre-built condition{tpl.query.length > 1 ? 's' : ''}
                      </div>
                    )}
                  </button>
                )
              })}
            </div>
          </div>
        ) : (
          /* ── Details form ── */
          <div style={{ padding: '20px 24px 24px', overflowY: 'auto' }}>
            {/* Template preview chip */}
            {selectedTemplate?.id !== 'blank' && (
              <div style={{
                display: 'flex', alignItems: 'center', gap: 8, marginBottom: 20,
                padding: '10px 12px', borderRadius: 8,
                background: selectedTemplate.bg, border: `1px solid ${selectedTemplate.border}`,
              }}>
                <TplIcon size={14} color={selectedTemplate.color} />
                <span style={{ fontSize: 12, color: selectedTemplate.color, fontWeight: 600 }}>
                  {selectedTemplate.query.length} pre-built conditions
                </span>
                <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                  · You can customize them after creation
                </span>
              </div>
            )}

            <form onSubmit={handleSubmit}>
              <div style={{ marginBottom: 16 }}>
                <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 6 }}>
                  Campaign Name <span style={{ color: 'var(--accent)' }}>*</span>
                </label>
                <input
                  value={name}
                  onChange={e => setName(e.target.value)}
                  placeholder={t('campaigns.campaignNamePlaceholder')}
                  autoFocus
                  style={{
                    width: '100%', padding: '8px 12px', background: 'var(--bg-secondary)',
                    border: '1px solid var(--border)', borderRadius: 8, fontSize: 13,
                    color: 'var(--text-primary)', boxSizing: 'border-box',
                  }}
                />
              </div>

              <div style={{ marginBottom: 16 }}>
                <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 6 }}>
                  {t('campaigns.descriptionLabel')}
                </label>
                <textarea
                  value={description}
                  onChange={e => setDescription(e.target.value)}
                  placeholder={t('campaigns.descriptionPlaceholder')}
                  rows={3}
                  style={{
                    width: '100%', padding: '8px 12px', background: 'var(--bg-secondary)',
                    border: '1px solid var(--border)', borderRadius: 8, fontSize: 13,
                    color: 'var(--text-primary)', resize: 'vertical', boxSizing: 'border-box',
                    fontFamily: 'inherit',
                  }}
                />
              </div>

              <div style={{ marginBottom: 24 }}>
                <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 6 }}>
                  Campaign Owner
                </label>
                <select
                  value={ownerId}
                  onChange={e => setOwnerId(e.target.value)}
                  style={{
                    width: '100%', padding: '8px 12px', background: 'var(--bg-secondary)',
                    border: '1px solid var(--border)', borderRadius: 8, fontSize: 13,
                    color: 'var(--text-primary)', boxSizing: 'border-box',
                    appearance: 'auto',
                  }}
                >
                  <option value="">No owner</option>
                  {users.map(u => (
                    <option key={u.id} value={u.id}>
                      {u.display_name || u.email}{u.display_name ? ` (${u.email})` : ''}
                    </option>
                  ))}
                </select>
              </div>

              <div style={{ display: 'flex', gap: 8, justifyContent: 'space-between' }}>
                <Button variant='ghost' onClick={handleBack} type='button'>← Back</Button>
                <div style={{ display: 'flex', gap: 8 }}>
                  <Button variant='ghost' onClick={onClose} type='button'>{t('common.cancel')}</Button>
                  <Button type='submit' disabled={!name.trim() || saving}>
                    {saving ? t('campaigns.creating') : t('campaigns.create')}
                  </Button>
                </div>
              </div>
            </form>
          </div>
        )}
      </div>
    </div>
  )
}

function CampaignCard({ campaign, onDelete, onRun }) {
  const { t } = useTranslation()
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
          <span>{t('campaigns.conditions', { count: conditionCount })}</span>
          {campaign.finding_count > 0 && (
            <span style={{ color: '#f87171' }}>{t('campaigns.findingsCount', { count: campaign.finding_count })}</span>
          )}
          {campaign.last_run_at && (
            <span>{t('campaigns.lastRun', { date: new Date(campaign.last_run_at).toLocaleDateString() })}</span>
          )}
          {!campaign.last_run_at && <span style={{ color: '#f59e0b' }}>{t('campaigns.neverRun')}</span>}
          {campaign.owner_name && <span>Owner: {campaign.owner_name}</span>}
        </div>
      </div>

      {/* Actions */}
      <div style={{ display: 'flex', gap: 8, flexShrink: 0 }} onClick={e => e.stopPropagation()}>
        <button
          onClick={handleRun}
          disabled={running || conditionCount === 0}
          title={conditionCount === 0 ? t('campaigns.addConditionsFirst') : t('campaigns.runQueryNow')}
          style={{
            display: 'flex', alignItems: 'center', gap: 5,
            padding: '6px 12px', borderRadius: 6, border: '1px solid #1e3a5f66',
            background: '#1e3a5f22', color: '#60a5fa', fontSize: 12, fontWeight: 600,
            cursor: conditionCount === 0 ? 'not-allowed' : 'pointer', opacity: conditionCount === 0 ? 0.5 : 1,
          }}
        >
          <Play size={12} />
          {running ? t('campaigns.running') : t('campaigns.run')}
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
          title={t('campaigns.exportTemplate')}
          style={{ padding: '6px 8px', borderRadius: 6, border: '1px solid var(--border)', background: 'transparent', color: 'var(--text-muted)', cursor: 'pointer', display: 'flex' }}
        >
          <Download size={14} />
        </button>

        {confirming ? (
          <>
            <button onClick={() => { onDelete(campaign.id); setConfirming(false) }}
              style={{ padding: '6px 10px', borderRadius: 6, border: '1px solid #991b1b', background: '#dc262622', color: '#f87171', fontSize: 12, cursor: 'pointer' }}>
              {t('common.confirm')}
            </button>
            <button onClick={() => setConfirming(false)}
              style={{ padding: '6px 10px', borderRadius: 6, border: '1px solid var(--border)', background: 'transparent', color: 'var(--text-muted)', fontSize: 12, cursor: 'pointer' }}>
              {t('common.cancel')}
            </button>
          </>
        ) : (
          <button onClick={() => setConfirming(true)}
            title={t('campaigns.deleteCampaign')}
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
  const { t } = useTranslation()
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
          <span>{t('campaigns.nodes', { count: workflow.node_count || 0 })}</span>
          <span>{t('campaigns.runs', { count: workflow.run_count || 0 })}</span>
          {workflow.last_run_at && (
            <span>{t('campaigns.lastRun', { date: new Date(workflow.last_run_at).toLocaleDateString() })}</span>
          )}
        </div>
      </div>

      <div style={{ display: 'flex', gap: 8, flexShrink: 0 }} onClick={e => e.stopPropagation()}>
        {confirming ? (
          <>
            <button onClick={() => { onDelete(workflow.id); setConfirming(false) }}
              style={{ padding: '6px 10px', borderRadius: 6, border: '1px solid #991b1b', background: '#dc262622', color: '#f87171', fontSize: 12, cursor: 'pointer' }}>
              {t('common.confirm')}
            </button>
            <button onClick={() => setConfirming(false)}
              style={{ padding: '6px 10px', borderRadius: 6, border: '1px solid var(--border)', background: 'transparent', color: 'var(--text-muted)', fontSize: 12, cursor: 'pointer' }}>
              {t('common.cancel')}
            </button>
          </>
        ) : (
          <button onClick={() => setConfirming(true)} title={t('campaigns.deleteWorkflow')}
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
  const { t } = useTranslation()
  const [mode, setMode] = useState('template') // 'template' | 'custom'
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [saving, setSaving] = useState(false)
  const [templates, setTemplates] = useState([])
  const [categories, setCategories] = useState([])
  const [loadingTpl, setLoadingTpl] = useState(true)
  const [tplSearch, setTplSearch] = useState('')

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

  const modeTabs = [
    { key: 'template', label: t('campaigns.useTemplate') },
    { key: 'custom', label: t('campaigns.startFromScratch') },
  ]

  return (
    <div style={{
      position: 'fixed', inset: 0, background: '#000a', zIndex: 200,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }} onClick={onClose}>
      <div style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 14,
        padding: 28, minWidth: 560, maxWidth: 640, maxHeight: '80vh', overflow: 'auto',
      }} onClick={e => e.stopPropagation()}>
        <div style={{ fontWeight: 700, fontSize: 16, marginBottom: 16 }}>{t('campaigns.newAutomationWorkflow')}</div>

        {/* Mode tabs */}
        <div style={{ display: 'flex', gap: 0, marginBottom: 20, borderBottom: '1px solid var(--border)' }}>
          {modeTabs.map(tab => (
            <button key={tab.key} onClick={() => setMode(tab.key)} style={{
              padding: '8px 16px', fontSize: 13, fontWeight: 600,
              background: 'none', border: 'none', cursor: 'pointer',
              color: mode === tab.key ? 'var(--text)' : 'var(--muted-2)',
              borderBottom: mode === tab.key ? '2px solid var(--text)' : '2px solid transparent',
              marginBottom: -1,
            }}>{tab.label}</button>
          ))}
        </div>

        {mode === 'template' ? (
          <div>
            {loadingTpl ? <Spinner /> : templates.length === 0 ? (
              <div style={{ textAlign: 'center', padding: 20, color: '#94a3b8' }}>{t('campaigns.noTemplatesAvailable')}</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                <div style={{ position: 'relative', marginBottom: 4 }}>
                  <Search size={14} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
                  <input
                    value={tplSearch}
                    onChange={e => setTplSearch(e.target.value)}
                    placeholder={t('campaigns.searchTemplates')}
                    style={{
                      width: '100%', padding: '8px 12px 8px 32px', background: 'var(--bg-secondary)',
                      border: '1px solid var(--border)', borderRadius: 8, fontSize: 13,
                      color: 'var(--text-primary)', boxSizing: 'border-box',
                    }}
                  />
                </div>
                {templates.filter(tpl => {
                  if (!tplSearch.trim()) return true
                  const q = tplSearch.toLowerCase()
                  return tpl.name?.toLowerCase().includes(q) || tpl.description?.toLowerCase().includes(q) || tpl.category?.toLowerCase().includes(q)
                }).map(tpl => (
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
                        <Pill color="#94a3b8">{t('campaigns.nodes', { count: tpl.nodes?.length || 0 })}</Pill>
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
                {t('campaigns.workflowName')}
              </label>
              <input value={name} onChange={e => setName(e.target.value)}
                placeholder={t('campaigns.workflowNamePlaceholder')}
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
                {t('campaigns.descriptionLabel')}
              </label>
              <textarea value={description} onChange={e => setDescription(e.target.value)}
                placeholder={t('campaigns.workflowDescPlaceholder')} rows={3}
                style={{
                  width: '100%', padding: '8px 12px', background: 'var(--bg-secondary)',
                  border: '1px solid var(--border)', borderRadius: 8, fontSize: 13,
                  color: 'var(--text-primary)', resize: 'vertical', boxSizing: 'border-box',
                  fontFamily: 'inherit',
                }}
              />
            </div>
            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
              <Button variant='ghost' onClick={onClose} type='button'>{t('common.cancel')}</Button>
              <Button type='submit' disabled={!name.trim() || saving}>
                {saving ? t('campaigns.creating') : t('campaigns.createWorkflow')}
              </Button>
            </div>
          </form>
        )}
      </div>
    </div>
  )
}

export default function Campaigns() {
  const { t } = useTranslation()
  const { activeScanId } = useScan()
  const navigate = useNavigate()
  const [campaigns, setCampaigns] = useState([])
  const [workflows, setWorkflows] = useState([])
  const [loading, setLoading] = useState(true)
  const [fetchError, setFetchError] = useState(null)
  const [showCreate, setShowCreate] = useState(false)
  const [showCreateWf, setShowCreateWf] = useState(false)
  const [tab, setTab] = useState('campaigns')
  const [wfSearch, setWfSearch] = useState('')
  const [campSearch, setCampSearch] = useState('')
  const [ownerFilter, setOwnerFilter] = useState('')

  const load = () => {
    setLoading(true)
    setFetchError(null)
    Promise.all([
      getCampaigns(activeScanId),
      getWorkflows(),
    ]).then(([c, w]) => {
      setCampaigns(c)
      setWorkflows(w)
    }).catch(() => setFetchError('Failed to load campaigns.'))
      .finally(() => setLoading(false))
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
        title={t('campaigns.campaignsAndWorkflows')}
        subtitle={t('campaigns.subtitle')}
        action={
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <ExportImportButtons
              configType="campaign_workflow"
              exportFn={null}
              importFn={(file, conflict) => importConfig('campaign_workflow', file, conflict)}
              onImported={load}
              label={t('campaigns.campaignTemplate')}
              showConflict={true}
            />
            <Button variant="ghost" onClick={() => setShowCreateWf(true)}>
              <GitBranch size={14} /> {t('campaigns.newWorkflow')}
            </Button>
            <Button onClick={() => setShowCreate(true)}>
              <Plus size={14} /> {t('campaigns.newCampaign')}
            </Button>
          </div>
        }
      />

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 0, marginBottom: 16, borderBottom: '1px solid var(--border)' }}>
        {[
          { key: 'campaigns', label: t('campaigns.title'), count: campaigns.length, icon: Target },
          { key: 'workflows', label: t('workflows.title'), count: workflows.length, icon: GitBranch },
        ].map(tb => (
          <button
            key={tb.key}
            onClick={() => setTab(tb.key)}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              padding: '10px 18px', fontSize: 13, fontWeight: 600,
              background: 'none', border: 'none', cursor: 'pointer',
              color: tab === tb.key ? 'var(--text)' : '#94a3b8',
              borderBottom: tab === tb.key ? '2px solid var(--text)' : '2px solid transparent',
              marginBottom: -1,
            }}
          >
            <tb.icon size={14} />
            {tb.label}
            <span style={{
              fontSize: 11, padding: '1px 6px', borderRadius: 10,
              background: tab === tb.key ? 'var(--text)' : 'var(--secondary)',
              color: tab === tb.key ? 'var(--bg)' : 'var(--muted)',
            }}>{tb.count}</span>
          </button>
        ))}
      </div>

      <ErrorBanner error={fetchError} onRetry={load} onDismiss={() => setFetchError(null)} />
      {loading ? <><SkeletonCard /><SkeletonCard /><SkeletonCard /></> : tab === 'campaigns' ? (
        ordered.length === 0 ? (
          <EmptyState
            icon={Target}
            title={t('campaigns.noCampaignsYet')}
            sub={t('campaigns.noCampaignsDesc')}
          >
            <Button onClick={() => setShowCreate(true)}><Plus size={14} /> {t('campaigns.createFirstCampaign')}</Button>
          </EmptyState>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <div style={{ position: 'relative', maxWidth: 320, flex: 1 }}>
                <Search size={14} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
                <input
                  value={campSearch}
                  onChange={e => setCampSearch(e.target.value)}
                  placeholder="Search campaigns..."
                  style={{
                    width: '100%', padding: '8px 12px 8px 32px', background: 'var(--bg-secondary)',
                    border: '1px solid var(--border)', borderRadius: 8, fontSize: 13,
                    color: 'var(--text-primary)', boxSizing: 'border-box',
                  }}
                />
              </div>
              <select
                value={ownerFilter}
                onChange={e => setOwnerFilter(e.target.value)}
                style={{
                  padding: '8px 12px', background: 'var(--bg-secondary)',
                  border: '1px solid var(--border)', borderRadius: 8, fontSize: 13,
                  color: 'var(--text-primary)', cursor: 'pointer',
                }}
              >
                <option value="">All owners</option>
                <option value="__unassigned__">Unassigned</option>
                {[...new Map(campaigns.filter(c => c.owner_name).map(c => [c.owner_id, c.owner_name])).entries()].map(([oid, name]) => (
                  <option key={oid} value={oid}>{name}</option>
                ))}
              </select>
            </div>
            {ordered.filter(c => {
              if (ownerFilter === '__unassigned__' && c.owner_id) return false
              if (ownerFilter && ownerFilter !== '__unassigned__' && String(c.owner_id) !== ownerFilter) return false
              if (!campSearch.trim()) return true
              const q = campSearch.toLowerCase()
              return c.name?.toLowerCase().includes(q) || c.description?.toLowerCase().includes(q)
            }).map(c => (
              <CampaignCard key={c.id} campaign={c} onDelete={handleDelete} onRun={handleRun} />
            ))}
          </div>
        )
      ) : (
        workflows.length === 0 ? (
          <EmptyState
            icon={GitBranch}
            title={t('campaigns.noWorkflowsYet')}
            sub={t('campaigns.noWorkflowsDesc')}
          >
            <Button onClick={() => setShowCreateWf(true)}><GitBranch size={14} /> {t('campaigns.createFirstWorkflow')}</Button>
          </EmptyState>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div style={{ position: 'relative', maxWidth: 320 }}>
              <Search size={14} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              <input
                value={wfSearch}
                onChange={e => setWfSearch(e.target.value)}
                placeholder={t('campaigns.searchWorkflows')}
                style={{
                  width: '100%', padding: '8px 12px 8px 32px', background: 'var(--bg-secondary)',
                  border: '1px solid var(--border)', borderRadius: 8, fontSize: 13,
                  color: 'var(--text-primary)', boxSizing: 'border-box',
                }}
              />
            </div>
            {workflows.filter(w => {
              if (!wfSearch.trim()) return true
              const q = wfSearch.toLowerCase()
              return w.name?.toLowerCase().includes(q) || w.description?.toLowerCase().includes(q)
            }).map(w => (
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
