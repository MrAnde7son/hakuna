import React, { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { CheckCircle, XCircle, Clock, AlertTriangle, RefreshCw, ChevronDown, ChevronUp } from 'lucide-react'
import { getAgentApprovals, decideAgentApproval } from '../../api.js'

const STATUS_COLORS = {
  pending:  { bg: 'var(--warning-subtle, #fef9c3)',  text: 'var(--warning,  #ca8a04)',  border: 'var(--warning-border, #fde68a)' },
  approved: { bg: 'var(--success-subtle, #dcfce7)',  text: 'var(--success,  #16a34a)',  border: 'var(--success-border, #bbf7d0)' },
  rejected: { bg: 'var(--danger-subtle,  #fee2e2)',  text: 'var(--danger,   #dc2626)',  border: 'var(--danger-border,  #fecaca)' },
  expired:  { bg: 'var(--muted-subtle,   #f4f4f5)',  text: 'var(--muted,    #71717a)',  border: 'var(--border, #e4e4e7)' },
}

const TOOL_LABELS = {
  create_jira_ticket: 'Create Jira Ticket',
  create_servicenow_ticket: 'Create ServiceNow Ticket',
  send_slack_message: 'Send Slack Message',
  send_teams_message: 'Send Teams Message',
  send_email_alert: 'Send Email Alert',
  create_campaign: 'Create Campaign',
  send_webhook: 'Send Webhook',
  update_finding_status: 'Update Finding Status',
  create_exception: 'Create Exception',
  tag_assets: 'Tag Assets',
  bulk_tag_findings: 'Bulk Tag Findings',
  create_tag: 'Create Tag',
  run_auto_tag_rules: 'Run Auto-Tag Rules',
}

function StatusBadge({ status }) {
  const c = STATUS_COLORS[status] || STATUS_COLORS.expired
  const icons = { pending: Clock, approved: CheckCircle, rejected: XCircle, expired: AlertTriangle }
  const Icon = icons[status] || Clock
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      padding: '2px 8px', borderRadius: 12, fontSize: 11, fontWeight: 600,
      background: c.bg, color: c.text, border: `1px solid ${c.border}`,
    }}>
      <Icon size={11} />
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  )
}

function ToolInputPreview({ toolName, toolInput }) {
  const [expanded, setExpanded] = useState(false)
  if (!toolInput || Object.keys(toolInput).length === 0) return null

  const safeInput = { ...toolInput }
  delete safeInput.confirmed  // don't show internal flag

  const preview = Object.entries(safeInput)
    .slice(0, 3)
    .map(([k, v]) => `${k}: ${typeof v === 'string' ? v.slice(0, 60) : JSON.stringify(v).slice(0, 60)}`)
    .join(' · ')

  return (
    <div style={{ marginTop: 6 }}>
      <button
        onClick={() => setExpanded(e => !e)}
        style={{
          display: 'flex', alignItems: 'center', gap: 4,
          background: 'none', border: 'none', cursor: 'pointer',
          padding: 0, color: 'var(--muted)', fontSize: 12,
        }}
      >
        {expanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
        {expanded ? 'Hide parameters' : 'Show parameters'}
      </button>
      {!expanded && (
        <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2, fontFamily: 'monospace' }}>
          {preview}
        </div>
      )}
      {expanded && (
        <pre style={{
          marginTop: 6, padding: '8px 10px', borderRadius: 6,
          background: 'var(--bg-subtle, #f9fafb)', border: '1px solid var(--border)',
          fontSize: 11, fontFamily: 'monospace', whiteSpace: 'pre-wrap',
          maxHeight: 200, overflowY: 'auto', color: 'var(--text)',
        }}>
          {JSON.stringify(safeInput, null, 2)}
        </pre>
      )}
    </div>
  )
}

function ApprovalCard({ approval, onDecide }) {
  const [rejectReason, setRejectReason] = useState('')
  const [showReject, setShowReject] = useState(false)
  const [loading, setLoading] = useState(false)

  const isPending = approval.status === 'pending'
  const toolLabel = TOOL_LABELS[approval.tool_name] || approval.tool_name
  const alreadyGranted = (approval.run_auto_approved_tools || []).includes(approval.tool_name)

  const handleDecide = async (decision, opts = {}) => {
    if (decision === 'rejected' && !showReject) {
      setShowReject(true)
      return
    }
    setLoading(true)
    try {
      await onDecide(approval.id, decision, rejectReason || undefined, opts)
    } finally {
      setLoading(false)
      setShowReject(false)
    }
  }

  return (
    <div style={{
      border: '1px solid var(--border)',
      borderRadius: 8,
      padding: '14px 16px',
      background: 'var(--bg)',
      display: 'flex',
      flexDirection: 'column',
      gap: 8,
    }}>
      {/* Header row */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span style={{ fontWeight: 600, fontSize: 14 }}>{toolLabel}</span>
            <StatusBadge status={approval.status} />
          </div>
          <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 3 }}>
            Run #{approval.agent_run_id}
            {' · '}
            Step {approval.current_step + 1}
            {' · '}
            {new Date(approval.requested_at).toLocaleString()}
          </div>
        </div>
      </div>

      {/* Tool input */}
      <ToolInputPreview toolName={approval.tool_name} toolInput={approval.tool_input} />

      {/* Rejection reason (decided) */}
      {approval.rejection_reason && (
        <div style={{ fontSize: 12, color: 'var(--danger)', padding: '4px 8px', background: 'var(--danger-subtle)', borderRadius: 4 }}>
          Rejected: {approval.rejection_reason}
        </div>
      )}

      {/* Reject reason input */}
      {showReject && isPending && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          <input
            autoFocus
            placeholder="Reason for rejection (optional)"
            value={rejectReason}
            onChange={e => setRejectReason(e.target.value)}
            style={{
              padding: '7px 10px', borderRadius: 6, border: '1px solid var(--border)',
              background: 'var(--bg)', color: 'var(--text)', fontSize: 13,
            }}
            onKeyDown={e => e.key === 'Enter' && handleDecide('rejected')}
          />
          <div style={{ display: 'flex', gap: 6 }}>
            <button
              onClick={() => handleDecide('rejected')}
              disabled={loading}
              style={{
                padding: '6px 14px', borderRadius: 6, border: 'none',
                background: 'var(--danger)', color: '#fff',
                cursor: loading ? 'not-allowed' : 'pointer', fontSize: 13, fontWeight: 600,
              }}
            >
              {loading ? 'Rejecting…' : 'Confirm Reject'}
            </button>
            <button
              onClick={() => { setShowReject(false); setRejectReason('') }}
              style={{
                padding: '6px 14px', borderRadius: 6, border: '1px solid var(--border)',
                background: 'transparent', color: 'var(--text)',
                cursor: 'pointer', fontSize: 13,
              }}
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Approve / Reject buttons */}
      {isPending && !showReject && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 2 }}>
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              onClick={() => handleDecide('approved')}
              disabled={loading}
              style={{
                flex: 1, padding: '7px 0', borderRadius: 6, border: 'none',
                background: 'var(--success, #16a34a)', color: '#fff',
                cursor: loading ? 'not-allowed' : 'pointer', fontSize: 13, fontWeight: 600,
                display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
              }}
            >
              <CheckCircle size={14} />
              {loading ? 'Approving…' : 'Approve'}
            </button>
            <button
              onClick={() => handleDecide('rejected')}
              disabled={loading}
              style={{
                flex: 1, padding: '7px 0', borderRadius: 6,
                border: '1px solid var(--danger)', background: 'transparent',
                color: 'var(--danger)', cursor: loading ? 'not-allowed' : 'pointer',
                fontSize: 13, fontWeight: 600,
                display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
              }}
            >
              <XCircle size={14} />
              Reject
            </button>
          </div>
          {!alreadyGranted && (
            <button
              onClick={() => handleDecide('approved', { grantScope: 'run' })}
              disabled={loading}
              title={`Skip future ${toolLabel} approvals for this agent run`}
              style={{
                padding: '6px 0', borderRadius: 6,
                border: '1px solid var(--success-border, #bbf7d0)',
                background: 'var(--success-subtle, #dcfce7)',
                color: 'var(--success, #16a34a)',
                cursor: loading ? 'not-allowed' : 'pointer',
                fontSize: 12, fontWeight: 600,
              }}
            >
              Approve all {toolLabel} for this run
            </button>
          )}
          {alreadyGranted && (
            <div style={{ fontSize: 11, color: 'var(--muted)', textAlign: 'center' }}>
              {toolLabel} is auto-approved for this run
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default function AgentApprovalQueue({ panel = false, onPendingCount, runFilter = null, onClearRunFilter } = {}) {
  const { t } = useTranslation()
  const [approvals, setApprovals] = useState([])
  const [filter, setFilter] = useState('pending')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [decideMessage, setDecideMessage] = useState(null)

  const load = useCallback(async ({ silent = false } = {}) => {
    if (!silent) setLoading(true)
    setError(null)
    try {
      const data = await getAgentApprovals(filter || undefined)
      setApprovals(data)
      if (onPendingCount) {
        // Always count pending separately so badge stays accurate across filter changes
        const pending = filter === 'pending' ? data.filter(a => a.status === 'pending').length : null
        if (pending !== null) onPendingCount(pending)
      }
    } catch (e) {
      const msg = typeof e?.message === 'string' ? e.message : JSON.stringify(e?.message ?? e)
      if (!silent) setError(msg || 'Failed to load approvals')
    } finally {
      if (!silent) setLoading(false)
    }
  }, [filter, onPendingCount])

  // When deep-linked from a scan / notification, narrow the visible list to
  // approvals that belong to a specific agent run. The full list still loads
  // (so counts stay accurate) — we just filter for display.
  const visibleApprovals = runFilter
    ? approvals.filter(a => a.agent_run_id === runFilter)
    : approvals

  useEffect(() => { load() }, [load])

  // Poll while the queue is visible so newly-queued approvals show up
  // without a manual refresh. Pending is the hot view; other filters
  // change less often, so we poll them less aggressively.
  useEffect(() => {
    const intervalMs = filter === 'pending' ? 10_000 : 30_000
    const id = setInterval(() => {
      if (document.visibilityState === 'visible') load({ silent: true })
    }, intervalMs)
    return () => clearInterval(id)
  }, [filter, load])

  const handleDecide = async (approvalId, decision, reason, opts = {}) => {
    try {
      await decideAgentApproval(approvalId, decision, reason, opts)
      setDecideMessage(null)
    } catch (e) {
      if (e?.status === 404) {
        setDecideMessage({ kind: 'info', text: 'That approval was already decided elsewhere — refreshing the list.' })
      } else {
        const msg = typeof e?.message === 'string' ? e.message : 'Failed to record decision'
        setDecideMessage({ kind: 'error', text: msg })
      }
    } finally {
      load({ silent: true })
    }
  }

  const pendingCount = approvals.filter(a => a.status === 'pending').length

  return (
    <div style={panel ? { display: 'flex', flexDirection: 'column', height: '100%' } : { padding: '28px 32px', maxWidth: 820, margin: '0 auto' }}>
      {/* Header — only shown in full-page mode */}
      {!panel && (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, margin: 0 }}>Agent Approval Queue</h1>
          <p style={{ margin: '4px 0 0', fontSize: 13, color: 'var(--muted)' }}>
            Review and approve or reject write actions queued by agents running in HITL mode.
            {pendingCount > 0 && filter === 'pending' && (
              <span style={{
                marginLeft: 8, padding: '1px 7px', borderRadius: 10,
                background: 'var(--warning-subtle, #fef9c3)',
                color: 'var(--warning, #ca8a04)',
                fontWeight: 700, fontSize: 12,
              }}>
                {pendingCount} pending
              </span>
            )}
          </p>
        </div>
        <button
          onClick={load}
          style={{
            display: 'flex', alignItems: 'center', gap: 6,
            padding: '7px 14px', borderRadius: 6, border: '1px solid var(--border)',
            background: 'var(--bg)', color: 'var(--text)', cursor: 'pointer', fontSize: 13,
          }}
        >
          <RefreshCw size={14} />
          Refresh
        </button>
      </div>
      )}

      {/* Filter tabs */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 20 }}>
        {['pending', 'approved', 'rejected', ''].map(s => (
          <button
            key={s}
            onClick={() => setFilter(s)}
            style={{
              padding: '5px 14px', borderRadius: 6, border: '1px solid var(--border)',
              background: filter === s ? 'var(--nav-active-bg)' : 'transparent',
              color: filter === s ? 'var(--nav-active-text)' : 'var(--muted)',
              cursor: 'pointer', fontSize: 13, fontWeight: filter === s ? 600 : 400,
            }}
          >
            {s === '' ? 'All' : s.charAt(0).toUpperCase() + s.slice(1)}
          </button>
        ))}
      </div>

      {/* Content */}
      {loading && (
        <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--muted)', fontSize: 13 }}>
          Loading…
        </div>
      )}

      {!loading && error && (
        <div style={{
          padding: '14px 16px', borderRadius: 8,
          background: 'var(--danger-subtle)', color: 'var(--danger)',
          border: '1px solid var(--danger-border)', fontSize: 13,
        }}>
          {error}
        </div>
      )}

      {!loading && decideMessage && (
        <div style={{
          padding: '10px 14px', borderRadius: 8, marginBottom: 12,
          background: decideMessage.kind === 'error' ? 'var(--danger-subtle)' : 'var(--warning-subtle, #fef9c3)',
          color: decideMessage.kind === 'error' ? 'var(--danger)' : 'var(--warning, #92400e)',
          border: `1px solid ${decideMessage.kind === 'error' ? 'var(--danger-border)' : 'var(--warning-border, #fde68a)'}`,
          fontSize: 13, display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12,
        }}>
          <span>{decideMessage.text}</span>
          <button
            onClick={() => setDecideMessage(null)}
            style={{
              background: 'transparent', border: 'none', color: 'inherit',
              cursor: 'pointer', fontSize: 16, lineHeight: 1, padding: 0,
            }}
            aria-label="Dismiss"
          >
            ×
          </button>
        </div>
      )}

      {/* Run filter banner — shown when deep-linked from a specific scan */}
      {runFilter && !loading && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 10,
          padding: '8px 12px', marginBottom: 12, borderRadius: 6,
          background: 'var(--warning-subtle, #fef9c3)',
          color: 'var(--warning, #92400e)',
          fontSize: 12,
        }}>
          <span style={{ flex: 1 }}>
            Showing approvals for run #{runFilter} only.
          </span>
          {onClearRunFilter && (
            <button
              onClick={onClearRunFilter}
              style={{
                background: 'transparent', border: '1px solid currentColor',
                color: 'inherit', borderRadius: 4, padding: '2px 8px',
                fontSize: 11, cursor: 'pointer', fontWeight: 600,
              }}
            >
              Show all
            </button>
          )}
        </div>
      )}

      {!loading && !error && visibleApprovals.length === 0 && (
        <div style={{ textAlign: 'center', padding: '48px 0', color: 'var(--muted)' }}>
          <CheckCircle size={40} style={{ opacity: 0.25, marginBottom: 12 }} />
          <div style={{ fontSize: 15, fontWeight: 600 }}>
            {runFilter
              ? `No ${filter || ''} approvals for run #${runFilter}`.trim()
              : (filter === 'pending' ? 'No pending approvals' : 'No approvals found')}
          </div>
          <div style={{ fontSize: 13, marginTop: 4 }}>
            {filter === 'pending'
              ? 'Agents with approval_mode: "hitl" will queue actions here before executing them.'
              : 'Try a different filter.'}
          </div>
        </div>
      )}

      {!loading && !error && visibleApprovals.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {visibleApprovals.map(a => (
            <ApprovalCard key={a.id} approval={a} onDecide={handleDecide} />
          ))}
        </div>
      )}

      {/* How it works — full-page only */}
      {!panel && (
      <div style={{
        marginTop: 40, padding: '16px 18px', borderRadius: 8,
        border: '1px solid var(--border)', background: 'var(--bg-subtle, #f9fafb)',
      }}>
        <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8 }}>How HITL mode works</div>
        <ol style={{ margin: 0, paddingLeft: 18, fontSize: 12, color: 'var(--muted)', lineHeight: 1.7 }}>
          <li>Set <code style={{ fontFamily: 'monospace' }}>approval_mode: "hitl"</code> in an agent's guardrails.</li>
          <li>When the agent calls a write tool (Jira, Slack, campaigns, etc.), it pauses and queues a request here.</li>
          <li>Approve to let it proceed, or reject with an optional reason — the agent resumes and adapts accordingly.</li>
          <li>Use <code style={{ fontFamily: 'monospace' }}>approval_mode: "auto"</code> (default) to run fully autonomously without approval gates.</li>
        </ol>
      </div>
      )}
    </div>
  )
}
