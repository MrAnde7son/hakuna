import React, { useState, useEffect, useCallback } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import {
  Target, Play, Plus, X, ChevronDown, ChevronRight, ChevronLeft,
  User, Users, Zap, AlertTriangle, CheckCircle, Edit2, Save, Eye,
  RefreshCw, GitBranch, Trash2, Ticket, ExternalLink, Hash, ShieldOff,
  Search, ListChecks,
} from 'lucide-react'
import { useScan } from '../../App.jsx'
import { getFindingAssetDisplay } from '../../utils/assetDisplay.js'
import {
  getCampaign, updateCampaign, runCampaign,
  previewCampaignQuery, updateCampaignFinding,
  getWorkflows, createWorkflowFromTemplate, createWorkflow, deleteWorkflow,
  getWorkflowTemplates, authListUsers,
  getCampaignTickets, syncFindingTickets, createCampaignSlackChannel,
  createException,
  listCampaignCollaborators, inviteCampaignCollaborator,
  revokeCampaignCollaborator, resendCampaignCollaborator,
  isCollaboratorMode,
} from '../../api.js'
import { SeverityBadge, ScoreBar, Button, Spinner, EmptyState, Card, Pill, ErrorBanner, SkeletonDetail, Table, buildFindingBreakdown, useRiskWeights, OWNERSHIP_ROLE_OPTIONS, OWNERSHIP_ROLE_COLORS } from '../shared/ui.jsx'
import RuleBuilder from './RuleBuilder.jsx'
import NewSinceBanner from '../notifications/NewSinceBanner.jsx'

// ─── Condition chip colors ───────────────────────────────
const GROUP_COLORS = {
  'Vulnerability':      { bg: '#450a0a22', border: '#991b1b44', text: '#fca5a5' },
  'Environment':        { bg: '#1a2e0522', border: '#16653344', text: '#86efac' },
  'Identity & Access':  { bg: '#1e1a4222', border: '#4f46e544', text: '#a5b4fc' },
  'Security Controls':  { bg: '#1c111322', border: '#92400e44', text: '#fcd34d' },
  'Remediation':        { bg: '#0c1a2e22', border: '#036910a144', text: '#7dd3fc' },
}

const SEV_COLORS = ['#0ea5e9', '#65a30d', '#d97706', '#ea580c', '#dc2626']

// Tri-color chip (bg/border/text) derived from the canonical OWNERSHIP_ROLE_COLORS hex map.
// Keeps all role-specific styling in one place: add a new role to OWNERSHIP_ROLE_OPTIONS
// with a color in OWNERSHIP_ROLE_COLORS and it automatically gets a chip here.
const UNASSIGNED_COLORS = { bg: '#27272a22', border: '#27272a55', text: '#a1a1aa' }

function getOwnerColors(role) {
  const hex = OWNERSHIP_ROLE_COLORS[role]
  if (!hex) return UNASSIGNED_COLORS
  return { bg: `${hex}22`, border: `${hex}55`, text: hex }
}

// ─── Ownership Editor ─────────────────────────────────────
const OWNER_ROLES = OWNERSHIP_ROLE_OPTIONS

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

// ─── Campaign Progress Bar ───────────────────────────────
function CampaignProgressBar({ statusCounts, total }) {
  const { t } = useTranslation()
  if (!total) return null

  const segments = [
    { key: 'resolved', count: statusCounts?.resolved || 0, color: '#4ade80', label: t('campaigns.resolved') },
    { key: 'wont_fix', count: statusCounts?.wont_fix || 0, color: '#fca5a5', label: t('campaigns.wontFix') },
    { key: 'in_progress', count: statusCounts?.in_progress || 0, color: '#60a5fa', label: t('campaigns.inProgress') },
    { key: 'open', count: statusCounts?.open || 0, color: '#a1a1aa', label: t('campaigns.open') },
  ]

  const completedCount = (statusCounts?.resolved || 0) + (statusCounts?.wont_fix || 0)
  const pct = Math.round((completedCount / total) * 100)

  return (
    <div style={{ marginBottom: 20 }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 8 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>
          {t('campaigns.progress')}
        </div>
        <div style={{ fontSize: 22, fontWeight: 700, color: pct === 100 ? '#4ade80' : 'var(--text-primary)' }}>
          {pct}%
        </div>
      </div>
      {/* Segmented bar */}
      <div style={{
        display: 'flex', height: 10, borderRadius: 6, overflow: 'hidden',
        background: 'var(--bg-secondary)', border: '1px solid var(--border)',
      }}>
        {segments.map(seg => {
          const w = (seg.count / total) * 100
          if (w === 0) return null
          return (
            <div
              key={seg.key}
              title={`${seg.label}: ${seg.count}`}
              style={{ width: `${w}%`, background: seg.color, transition: 'width 0.3s ease' }}
            />
          )
        })}
      </div>
      {/* Legend */}
      <div style={{ display: 'flex', gap: 16, marginTop: 8, flexWrap: 'wrap' }}>
        {segments.map(seg => (
          seg.count > 0 && (
            <div key={seg.key} style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11 }}>
              <div style={{ width: 8, height: 8, borderRadius: 2, background: seg.color }} />
              <span style={{ color: 'var(--text-muted)' }}>{seg.label}</span>
              <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{seg.count}</span>
            </div>
          )
        ))}
      </div>
    </div>
  )
}

// ─── Compliance Control Chips ────────────────────────────
function ComplianceControlChips({ controls }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  return (
    <Card style={{ marginBottom: 20 }}>
      <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', marginBottom: 10, gap: 8 }}>
        <div style={{ fontSize: 13, fontWeight: 700 }}>
          {t('campaigns.complianceControls', { defaultValue: 'Compliance controls' })}
        </div>
        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
          {t('campaigns.complianceControlsHelp', { defaultValue: 'Findings remediated also satisfy these controls' })}
        </span>
      </div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
        {controls.map(ctrl => {
          const total = ctrl.total || 0
          const resolved = ctrl.resolved || 0
          const pct = total > 0 ? Math.round((resolved / total) * 100) : 0
          const done = total > 0 && resolved === total
          return (
            <div
              key={ctrl.control_id}
              onClick={() => ctrl.framework_slug && navigate(`/compliance/${ctrl.framework_slug}/control/${ctrl.control_id}`)}
              style={{
                cursor: ctrl.framework_slug ? 'pointer' : 'default',
                border: '1px solid var(--border)',
                borderRadius: 8,
                padding: '8px 12px',
                minWidth: 220,
                background: 'var(--bg-card)',
              }}
              title={ctrl.title}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                <code style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)' }}>
                  {ctrl.ref}
                </code>
                <Pill
                  label={total > 0 ? `${resolved}/${total}` : '—'}
                  color={done ? 'var(--success, #16a34a)' : 'var(--text-muted)'}
                />
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 240 }}>
                {ctrl.framework_name}
              </div>
              {total > 0 && (
                <div style={{ marginTop: 6, height: 4, background: 'var(--bg-subtle)', borderRadius: 2, overflow: 'hidden' }}>
                  <div style={{
                    width: `${pct}%`, height: '100%',
                    background: done ? 'var(--success, #16a34a)' : 'var(--accent)',
                    transition: 'width 200ms ease',
                  }} />
                </div>
              )}
            </div>
          )
        })}
      </div>
    </Card>
  )
}

// ─── Exception Reason Dialog ─────────────────────────────
function ExceptionDialog({ finding, onConfirm, onCancel }) {
  const { t } = useTranslation()
  const [exceptionType, setExceptionType] = useState('accepted_risk')
  const [reason, setReason] = useState('')
  const [createGlobal, setCreateGlobal] = useState(false)

  const EXCEPTION_TYPES = [
    { value: 'accepted_risk', label: t('campaigns.acceptedRisk', 'Accepted Risk'), desc: t('campaigns.acceptedRiskDesc', 'Risk acknowledged and accepted by stakeholder') },
    { value: 'false_positive', label: t('campaigns.falsePositive', 'False Positive'), desc: t('campaigns.falsePositiveDesc', 'Finding is incorrect or not applicable') },
    { value: 'compensating_control', label: t('campaigns.compensatingControl', 'Compensating Control'), desc: t('campaigns.compensatingControlDesc', 'Risk mitigated by an existing control') },
  ]

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 9999,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(4px)',
    }} onClick={onCancel}>
      <div
        onClick={e => e.stopPropagation()}
        style={{
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: 14, padding: 24, width: 420, maxWidth: '90vw',
          boxShadow: '0 20px 60px rgba(0,0,0,0.4)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
          <div style={{
            width: 36, height: 36, borderRadius: 8, background: '#450a0a44',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <ShieldOff size={18} color="#fca5a5" />
          </div>
          <div>
            <div style={{ fontWeight: 700, fontSize: 15, color: 'var(--text-primary)' }}>
              {t('campaigns.markWontFix', "Mark as Won't Fix")}
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 1 }}>
              {finding?.plugin_name}
            </div>
          </div>
        </div>

        {/* Exception type */}
        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 6 }}>
            {t('campaigns.exceptionReason', 'Reason')}
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {EXCEPTION_TYPES.map(et => (
              <label
                key={et.value}
                style={{
                  display: 'flex', alignItems: 'flex-start', gap: 8, padding: '8px 10px',
                  background: exceptionType === et.value ? '#450a0a22' : 'var(--bg-secondary)',
                  border: `1px solid ${exceptionType === et.value ? '#991b1b55' : 'var(--border)'}`,
                  borderRadius: 8, cursor: 'pointer', transition: 'all 0.15s',
                }}
              >
                <input
                  type="radio" name="exception_type" value={et.value}
                  checked={exceptionType === et.value}
                  onChange={() => setExceptionType(et.value)}
                  style={{ marginTop: 2 }}
                />
                <div>
                  <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>{et.label}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 1 }}>{et.desc}</div>
                </div>
              </label>
            ))}
          </div>
        </div>

        {/* Justification */}
        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 6 }}>
            {t('campaigns.justification', 'Justification')}
          </div>
          <textarea
            value={reason}
            onChange={e => setReason(e.target.value)}
            placeholder={t('campaigns.justificationPlaceholder', 'Why is this finding being dismissed?')}
            rows={2}
            style={{
              width: '100%', padding: '8px 10px', background: 'var(--bg-secondary)',
              border: '1px solid var(--border)', borderRadius: 8, fontSize: 12,
              color: 'var(--text-primary)', resize: 'vertical', boxSizing: 'border-box',
            }}
          />
        </div>

        {/* Create global exception */}
        <label style={{
          display: 'flex', alignItems: 'center', gap: 8, marginBottom: 18,
          padding: '8px 10px', background: 'var(--bg-secondary)',
          border: '1px solid var(--border)', borderRadius: 8, cursor: 'pointer',
        }}>
          <input
            type="checkbox" checked={createGlobal}
            onChange={e => setCreateGlobal(e.target.checked)}
          />
          <div>
            <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)' }}>
              {t('campaigns.createGlobalException', 'Create global exception rule')}
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
              {t('campaigns.globalExceptionDesc', 'Auto-applies to all matching findings across scans')}
            </div>
          </div>
        </label>

        {/* Actions */}
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <Button variant="ghost" size="sm" onClick={onCancel}>
            {t('common.cancel')}
          </Button>
          <Button size="sm" onClick={() => onConfirm({ exceptionType, reason, createGlobal })}
            style={{ background: '#991b1b', borderColor: '#991b1b' }}>
            {t('campaigns.confirmWontFix', "Confirm Won't Fix")}
          </Button>
        </div>
      </div>
    </div>
  )
}

// ─── Finding Card (campaign context) ─────────────────────
function CampaignFindingCard({ finding, campaignId, onOwnerUpdate, onStatusChange, riskWeights }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [expanded, setExpanded] = useState(false)
  const [editingOwner, setEditingOwner] = useState(false)
  const [status, setStatus] = useState(finding.campaign_status || 'open')
  const [showExceptionDialog, setShowExceptionDialog] = useState(false)

  const sevColor = SEV_COLORS[finding.severity] || SEV_COLORS[0]

  const handleOwnerSave = async (data) => {
    await updateCampaignFinding(campaignId, finding.campaign_finding_id, {
      ...data, owner_role: data.owner_role || data.owner_name,
    })
    setEditingOwner(false)
    onOwnerUpdate()
  }

  const handleStatusChange = async (newStatus) => {
    if (newStatus === 'wont_fix') {
      setShowExceptionDialog(true)
      return
    }
    setStatus(newStatus)
    await updateCampaignFinding(campaignId, finding.campaign_finding_id, { status: newStatus })
    onStatusChange?.()
  }

  const handleExceptionConfirm = async ({ exceptionType, reason, createGlobal }) => {
    setStatus('wont_fix')
    setShowExceptionDialog(false)
    await updateCampaignFinding(campaignId, finding.campaign_finding_id, {
      status: 'wont_fix',
      exception_type: exceptionType,
    })
    if (createGlobal) {
      await createException({
        plugin_id: finding.plugin_id,
        plugin_name: finding.plugin_name,
        exception_type: exceptionType,
        reason,
        exclude_from_reports: true,
      }).catch(() => {}) // best-effort
    }
    onStatusChange?.()
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
            {getFindingAssetDisplay(finding)}
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

      {showExceptionDialog && (
        <ExceptionDialog
          finding={finding}
          onConfirm={handleExceptionConfirm}
          onCancel={() => setShowExceptionDialog(false)}
        />
      )}
    </div>
  )
}

// ─── Owner Group Section ──────────────────────────────────
function OwnerGroup({ group, campaignId, onOwnerUpdate, onStatusChange, riskWeights, defaultExpanded = true }) {
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
              onStatusChange={onStatusChange}
              riskWeights={riskWeights}
            />
          ))}
        </div>
      )}
    </div>
  )
}

// ─── Pipeline Strip ───────────────────────────────────────
// Three connected summary cards: Match → Automate → Results.
// Click a card to scroll to its editor section below.
function PipelineStrip({ query, queryDirty, hasResults, totalFindings, criticalCount, lastRunAt, workflows, onScrollTo, t }) {
  const stepCount = workflows?.length || 0
  const stepNames = (workflows || []).slice(0, 3).map(w => w.name).filter(Boolean)
  const moreSteps = stepCount > 3 ? stepCount - 3 : 0

  const matchSummary = query.length === 0
    ? t('campaigns.pipeline.noConditions', 'No conditions yet')
    : t('campaigns.pipeline.conditions', { count: query.length, defaultValue: '{{count}} condition' })

  const automateSummary = stepCount === 0
    ? t('campaigns.pipeline.noAutomation', 'No automation — add a step')
    : stepNames.join(' → ') + (moreSteps ? ` +${moreSteps}` : '')

  const resultsSummary = !hasResults
    ? t('campaigns.pipeline.notRun', 'Not yet run')
    : `${totalFindings} ${t('campaigns.pipeline.findings', 'findings')}${criticalCount ? ` · ${criticalCount} ${t('campaigns.pipeline.critical', 'critical')}` : ''}`

  const cards = [
    {
      key: 'match',
      number: '1',
      icon: Search,
      title: t('campaigns.pipeline.match', 'Match'),
      summary: matchSummary,
      tone: query.length === 0 ? 'muted' : 'info',
      dirty: queryDirty,
    },
    {
      key: 'automate',
      number: '2',
      icon: Zap,
      title: t('campaigns.pipeline.automate', 'Automate'),
      summary: automateSummary,
      tone: stepCount === 0 ? 'muted' : 'accent',
    },
    {
      key: 'results',
      number: '3',
      icon: ListChecks,
      title: t('campaigns.pipeline.results', 'Results'),
      summary: resultsSummary,
      tone: !hasResults ? 'muted' : 'success',
      meta: lastRunAt ? `${t('campaigns.pipeline.lastRun', 'Last run')} ${new Date(lastRunAt).toLocaleString()}` : null,
    },
  ]

  const TONE = {
    muted:   { bg: 'var(--bg-secondary)', border: 'var(--border)', icon: 'var(--text-muted)' },
    info:    { bg: 'rgba(96,165,250,0.08)', border: 'rgba(96,165,250,0.30)', icon: '#60a5fa' },
    accent:  { bg: 'rgba(129,140,248,0.10)', border: 'rgba(129,140,248,0.35)', icon: '#818cf8' },
    success: { bg: 'rgba(74,222,128,0.10)', border: 'rgba(74,222,128,0.35)', icon: '#4ade80' },
  }

  return (
    <div style={{
      display: 'flex',
      alignItems: 'stretch',
      gap: 0,
      marginBottom: 24,
      flexWrap: 'wrap',
    }}>
      {cards.map((c, i) => {
        const Icon = c.icon
        const tone = TONE[c.tone]
        return (
          <React.Fragment key={c.key}>
            <button
              onClick={() => onScrollTo(c.key)}
              style={{
                display: 'flex', alignItems: 'center', gap: 12,
                background: tone.bg, border: `1px solid ${tone.border}`,
                borderRadius: 12, padding: '14px 16px',
                cursor: 'pointer', textAlign: 'left',
                color: 'var(--text-primary)',
                transition: 'transform 0.1s, box-shadow 0.1s',
                minWidth: 0, flex: '1 1 240px',
              }}
              onMouseEnter={e => { e.currentTarget.style.boxShadow = '0 2px 8px rgba(0,0,0,0.08)' }}
              onMouseLeave={e => { e.currentTarget.style.boxShadow = 'none' }}
            >
              <div style={{
                width: 32, height: 32, borderRadius: 10,
                background: tone.icon + '22', color: tone.icon,
                fontWeight: 700, fontSize: 13,
                display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
              }}>
                <Icon size={16} />
              </div>
              <div style={{ minWidth: 0, flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2 }}>
                  <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', letterSpacing: '0.05em' }}>
                    {c.number}
                  </span>
                  <span style={{ fontSize: 13, fontWeight: 700 }}>{c.title}</span>
                  {c.dirty && (
                    <span style={{ fontSize: 9, fontWeight: 700, color: '#f59e0b', background: '#78350f22', border: '1px solid #78350f44', borderRadius: 3, padding: '0 5px' }}>
                      {t('campaigns.pipeline.unsaved', 'Unsaved')}
                    </span>
                  )}
                </div>
                <div style={{
                  fontSize: 12, color: 'var(--text-muted)',
                  whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
                }}>
                  {c.summary}
                </div>
                {c.meta && (
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2,
                    whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {c.meta}
                  </div>
                )}
              </div>
            </button>
            {i < cards.length - 1 && (
              <div style={{
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                color: 'var(--text-muted)', flexShrink: 0, padding: '0 4px',
              }}>
                <ChevronRight size={16} />
              </div>
            )}
          </React.Fragment>
        )
      })}
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
  const [activeTab, setActiveTab] = useState('campaign') // 'campaign' | 'tickets' | 'collaborators'
  const [queryExpanded, setQueryExpanded] = useState(false) // collapsed by default when results exist
  const [users, setUsers] = useState([])
  const [campaignTickets, setCampaignTickets] = useState([])
  const [ticketsLoading, setTicketsLoading] = useState(false)
  const [workflowSummary, setWorkflowSummary] = useState([])
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
        // Only auto-run on the very first visit (never run before) to avoid
        // silently mutating last_run_at on every detail-page open.
        if (autoRun && !data.last_run_at && !(data.owner_groups?.length > 0)) {
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

      <NewSinceBanner pageKey={`campaigns:${id}`} labelKey="notifications.newCampaignFindings" />

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
          ...(campaignTickets.length > 0 ? [{ key: 'tickets', label: `Tickets (${campaignTickets.length})`, icon: Ticket }] : []),
          ...(isCollaboratorMode() ? [] : [{ key: 'collaborators', label: 'Collaborators', icon: Users }]),
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
          {/* Pipeline strip — Match → Automate → Results, always visible */}
          <PipelineStrip
            t={t}
            query={query}
            queryDirty={queryDirty}
            hasResults={hasResults}
            totalFindings={totalFindings}
            criticalCount={campaign.critical_count || 0}
            lastRunAt={campaign.last_run_at}
            workflows={workflowSummary}
            onScrollTo={(key) => {
              const el = document.getElementById(`section-${key}`)
              if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' })
            }}
          />

          {/* Section 1: Match — query builder */}
          <div id="section-match" style={{ scrollMarginTop: 80 }}>
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
          </div>

          {/* Section 2: Automate — workflows that run against matched findings */}
          <div id="section-automate" style={{ scrollMarginTop: 80, marginBottom: 20 }}>
            <CampaignWorkflows
              campaignId={campaign.id}
              hasResults={hasResults}
              onWorkflowsChange={setWorkflowSummary}
            />
          </div>

          {/* Section 3: Results — matched findings grouped by owner */}
          <div id="section-results" style={{ scrollMarginTop: 80 }}>
            {!hasResults ? (
              <Card style={{ padding: 24, textAlign: 'center' }}>
                <Play size={20} color='var(--text-muted)' style={{ marginBottom: 8 }} />
                <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 4 }}>
                  {query.length === 0
                    ? t('campaigns.pipeline.addQueryFirst', 'Add a condition above to start matching findings.')
                    : t('campaigns.runToSeeResults')}
                </div>
                {query.length > 0 && (
                  <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                    {t('campaigns.pipeline.runFromHeader', 'Use Run Campaign in the header to execute the query and trigger automation.')}
                  </div>
                )}
              </Card>
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

                {/* Progress bar */}
                <CampaignProgressBar statusCounts={campaign.status_counts} total={totalFindings} />

                {/* Compliance controls this campaign remediates */}
                {campaign.compliance_controls?.length > 0 && (
                  <ComplianceControlChips controls={campaign.compliance_controls} />
                )}

                {/* Owner groups */}
                {campaign.owner_groups.map((group, idx) => (
                  <OwnerGroup
                    key={group.owner_key}
                    group={group}
                    campaignId={campaign.id}
                    onOwnerUpdate={load}
                    onStatusChange={load}
                    riskWeights={riskWeights}
                    defaultExpanded={idx === 0}
                  />
                ))}
              </>
            )}
          </div>
        </div>
      )}

      {activeTab === 'collaborators' && (
        <CollaboratorsPanel campaignId={campaign.id} />
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
function CampaignWorkflows({ campaignId, hasResults, onWorkflowsChange }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [workflows, setWorkflows] = useState([])
  const [templates, setTemplates] = useState([])
  const [loading, setLoading] = useState(true)
  const [wfError, setWfError] = useState(null)
  const [showAdd, setShowAdd] = useState(false)

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

  useEffect(() => {
    if (onWorkflowsChange) onWorkflowsChange(workflows)
  }, [workflows, onWorkflowsChange])

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

      {/* Workflow list */}
      {workflows.length === 0 ? (
          <EmptyState
            icon={GitBranch}
            title={t('campaigns.noWorkflowsAttached')}
            sub={t('campaigns.noWorkflowsAttachedDesc')}
          >
            <SuggestedWorkflows
              templates={templates}
              onPick={handleCreateFromTemplate}
            />
            <div style={{ marginTop: 14 }}>
              <Button onClick={() => setShowAdd(true)}><GitBranch size={14} /> {t('campaigns.browseAllWorkflows')}</Button>
            </div>
          </EmptyState>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {workflows.map(wf => {
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
                    </div>

                    <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
                      <Button size="sm" variant="ghost"
                        onClick={() => navigate(`/workflows/${wf.id}`)}>
                        <Edit2 size={12} /> {t('common.edit')}
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


// ─── Suggested Workflows (empty-state quick picks) ────────
// Curated shortlist that fits most remediation campaigns: triage routing
// first, owner-routing second, plain email as a credential-free fallback.
// Falls back to whatever's first in the catalog if these IDs are missing
// so the empty state never collapses to zero suggestions.
const SUGGESTED_TEMPLATE_IDS = ['critical_triage', 'owner_routing', 'email_notification']

function SuggestedWorkflows({ templates, onPick }) {
  const { t } = useTranslation()
  if (!templates || templates.length === 0) return null

  const byId = new Map(templates.map(tpl => [tpl.id, tpl]))
  const picked = []
  for (const id of SUGGESTED_TEMPLATE_IDS) {
    const tpl = byId.get(id)
    if (tpl) picked.push(tpl)
  }
  // Top-up to 3 from the catalog head if curated IDs aren't all present.
  for (const tpl of templates) {
    if (picked.length >= 3) break
    if (!picked.includes(tpl)) picked.push(tpl)
  }

  const [busy, setBusy] = useState(null)
  const handleClick = async (tpl) => {
    if (busy) return
    setBusy(tpl.id)
    try {
      await onPick(tpl)
    } finally {
      setBusy(null)
    }
  }

  return (
    <div style={{ marginTop: 18, width: '100%', maxWidth: 540 }}>
      <div style={{
        fontSize: 11, fontWeight: 700, textTransform: 'uppercase',
        color: '#818cf8', letterSpacing: '0.05em', marginBottom: 8, textAlign: 'left',
      }}>
        {t('campaigns.suggestedWorkflows')}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {picked.map(tpl => (
          <button
            key={tpl.id}
            onClick={() => handleClick(tpl)}
            disabled={busy != null}
            style={{
              display: 'flex', alignItems: 'center', gap: 12,
              padding: '12px 14px', borderRadius: 10,
              border: '1px solid var(--border)', background: 'var(--bg-card)',
              cursor: busy ? 'wait' : 'pointer', textAlign: 'left', width: '100%',
              opacity: busy && busy !== tpl.id ? 0.55 : 1,
              transition: 'border-color 0.15s',
            }}
            onMouseEnter={e => { if (!busy) e.currentTarget.style.borderColor = '#818cf8' }}
            onMouseLeave={e => e.currentTarget.style.borderColor = 'var(--border)'}
          >
            <div style={{
              width: 36, height: 36, borderRadius: 8, background: '#312e8122',
              display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
            }}>
              <GitBranch size={16} color='#818cf8' />
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontWeight: 600, fontSize: 13 }}>{tpl.name}</div>
              {tpl.description && (
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{tpl.description}</div>
              )}
            </div>
            <Plus size={14} color='#94a3b8' />
          </button>
        ))}
      </div>
    </div>
  )
}


// ─── External Collaborators ────────────────────────────────
function CollaboratorsPanel({ campaignId }) {
  const [rows, setRows] = useState([])
  const [loading, setLoading] = useState(true)
  const [email, setEmail] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')
  const [lastInviteUrl, setLastInviteUrl] = useState('')

  const refresh = useCallback(() => {
    setLoading(true)
    listCampaignCollaborators(campaignId)
      .then(d => setRows(d.collaborators || []))
      .catch(err => setError(err.message || 'Failed to load collaborators'))
      .finally(() => setLoading(false))
  }, [campaignId])

  useEffect(() => { refresh() }, [refresh])

  const handleInvite = async (e) => {
    e.preventDefault()
    setError('')
    setLastInviteUrl('')
    setSubmitting(true)
    try {
      const r = await inviteCampaignCollaborator(campaignId, email.trim())
      setEmail('')
      // If email delivery isn't configured, surface the link so the user can
      // share it manually. Always shown once on invite for convenience.
      setLastInviteUrl(r.accept_url || '')
      refresh()
    } catch (err) {
      setError(err.message || 'Invite failed')
    } finally {
      setSubmitting(false)
    }
  }

  const handleRevoke = async (id) => {
    if (!window.confirm('Revoke this collaborator? Their access stops immediately.')) return
    try {
      await revokeCampaignCollaborator(campaignId, id)
      refresh()
    } catch (err) {
      setError(err.message || 'Revoke failed')
    }
  }

  const handleResend = async (id) => {
    try {
      const r = await resendCampaignCollaborator(campaignId, id)
      setLastInviteUrl(r.accept_url || '')
      refresh()
    } catch (err) {
      setError(err.message || 'Resend failed')
    }
  }

  const statusColor = {
    pending: '#f59e0b',
    active: '#10b981',
    expired: '#71717a',
    revoked: '#dc2626',
  }

  return (
    <Card>
      <div style={{ marginBottom: 16 }}>
        <h3 style={{ fontSize: 15, fontWeight: 600, margin: '0 0 4px' }}>External collaborators</h3>
        <p style={{ fontSize: 13, color: 'var(--text-muted)', margin: 0 }}>
          Invite someone outside Hakuna to view findings, build workflows, and connect integrations
          for this campaign only. They get a magic-link — no account creation needed.
        </p>
      </div>

      <form onSubmit={handleInvite} style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        <input
          type="email"
          value={email}
          onChange={e => setEmail(e.target.value)}
          required
          placeholder="email@partner.com"
          style={{
            flex: 1, padding: '8px 12px', borderRadius: 6,
            border: '1px solid var(--border)', background: 'var(--bg-card)',
            color: 'var(--text-primary)', fontSize: 13,
          }}
        />
        <Button type="submit" disabled={submitting}>
          {submitting ? 'Inviting…' : 'Invite'}
        </Button>
      </form>

      {error && <ErrorBanner message={error} onDismiss={() => setError('')} />}

      {lastInviteUrl && (
        <div style={{
          marginBottom: 16, padding: 10, borderRadius: 6,
          background: 'var(--bg-muted)', border: '1px solid var(--border)',
          fontSize: 12, color: 'var(--text-secondary)',
          wordBreak: 'break-all',
        }}>
          <div style={{ fontWeight: 600, marginBottom: 4 }}>Invite link (share if email delivery isn't set up):</div>
          <a href={lastInviteUrl} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent)' }}>
            {lastInviteUrl}
          </a>
        </div>
      )}

      {loading ? (
        <Spinner />
      ) : rows.length === 0 ? (
        <EmptyState
          icon={Users}
          title="No collaborators yet"
          subtitle="Invite a vendor, contractor, or partner to help triage this campaign."
        />
      ) : (
        <Table
          columns={[
            { key: 'email', label: 'Email', render: v => <span style={{ fontSize: 13 }}>{v}</span> },
            {
              key: 'status', label: 'Status', width: '100px',
              render: v => (
                <Pill style={{ background: `${statusColor[v] || '#71717a'}22`, color: statusColor[v] || '#71717a' }}>
                  {v}
                </Pill>
              )
            },
            { key: 'invited_at', label: 'Invited', width: '160px', render: v => v ? new Date(v).toLocaleDateString() : '—' },
            { key: 'expires_at', label: 'Expires', width: '160px', render: v => v ? new Date(v).toLocaleDateString() : '—' },
            { key: 'last_seen_at', label: 'Last seen', width: '160px', render: v => v ? new Date(v).toLocaleDateString() : '—' },
            {
              key: 'id', label: '', width: '160px',
              render: (_v, row) => (
                <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
                  {row.status === 'pending' && (
                    <button
                      onClick={() => handleResend(row.id)}
                      style={{
                        background: 'transparent', border: '1px solid var(--border)',
                        borderRadius: 4, padding: '4px 8px', fontSize: 12, cursor: 'pointer',
                        color: 'var(--text-primary)',
                      }}
                    >Resend</button>
                  )}
                  {row.status !== 'revoked' && (
                    <button
                      onClick={() => handleRevoke(row.id)}
                      style={{
                        background: 'transparent', border: '1px solid var(--danger)',
                        borderRadius: 4, padding: '4px 8px', fontSize: 12, cursor: 'pointer',
                        color: 'var(--danger)',
                      }}
                    >Revoke</button>
                  )}
                </div>
              )
            },
          ]}
          rows={rows}
        />
      )}
    </Card>
  )
}
