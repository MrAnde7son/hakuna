import React, { useState, useEffect, useCallback } from 'react'
import { ClipboardList, ChevronDown, ChevronRight, RefreshCw, Search } from 'lucide-react'
import { Card, PageHeader, Button, Input, Spinner, EmptyState } from '../shared/ui.jsx'
import { getStoredToken, getOrgContext } from '../../api.js'
import useURLFilters from '../../hooks/useURLFilters.js'

const SELECT_STYLE = {
  background: 'var(--bg-card)',
  border: '1px solid var(--border)',
  borderRadius: 6,
  padding: '7px 10px',
  fontSize: 13,
  color: 'var(--text)',
  cursor: 'pointer',
  outline: 'none',
  width: '100%',
}

async function fetchAuditLog(params = {}) {
  const q = new URLSearchParams()
  Object.entries(params).forEach(([k, v]) => { if (v !== '' && v != null) q.set(k, v) })
  const headers = {}
  const token = getStoredToken()
  if (token) headers['Authorization'] = `Bearer ${token}`
  const orgContext = getOrgContext()
  if (orgContext) headers['X-Org-Context'] = orgContext
  const res = await fetch(`/api/audit-log?${q}`, { headers })
  if (!res.ok) throw new Error('Failed to fetch audit log')
  return res.json()
}

// ─── Action badge ─────────────────────────────────────────
const ACTION_COLOR = {
  create: '#22c55e',
  update: '#3b82f6',
  delete: '#ef4444',
  enable: '#8b5cf6',
  disable: '#f97316',
  assign: '#06b6d4',
  start: '#10b981',
  run: '#06b6d4',
  cancel: '#f97316',
}

function ActionBadge({ action }) {
  const color = ACTION_COLOR[action] || '#71717a'
  return (
    <span style={{
      display: 'inline-block',
      padding: '2px 8px',
      borderRadius: 99,
      fontSize: 11,
      fontWeight: 700,
      letterSpacing: '0.04em',
      textTransform: 'uppercase',
      background: `${color}18`,
      color,
      border: `1px solid ${color}44`,
      minWidth: 52,
      textAlign: 'center',
    }}>
      {action}
    </span>
  )
}

// ─── Entity type label ────────────────────────────────────
const ENTITY_LABEL = {
  exception: 'Exception',
  sla_config: 'SLA Config',
  campaign: 'Campaign',
  workflow: 'Workflow',
  asset_ownership: 'Asset Ownership',
  finding_ownership: 'Finding Ownership',
  finding_status: 'Finding Status',
  tag: 'Tag',
  auto_tag_rule: 'Auto-Tag Rule',
  scan: 'Scan',
  integration: 'Integration',
  user: 'User',
  organization: 'Organization',
  role: 'Role',
  role_assignment: 'Role Assignment',
  alert: 'Alert',
  ingest_endpoint: 'Ingest Endpoint',
  siem_event: 'SIEM Event',
  asset_type_rule: 'Asset Type Rule',
  finding_context: 'Finding Context',
}

function EntityTypePill({ type }) {
  return (
    <span style={{
      display: 'inline-block',
      padding: '2px 7px',
      borderRadius: 6,
      fontSize: 11,
      background: 'var(--bg-muted)',
      color: 'var(--muted)',
      border: '1px solid var(--border)',
      whiteSpace: 'nowrap',
    }}>
      {ENTITY_LABEL[type] || type}
    </span>
  )
}

// ─── Change diff viewer ───────────────────────────────────
function ChangeDiff({ changes }) {
  const [open, setOpen] = useState(false)
  if (!changes || Object.keys(changes).length === 0) return <span style={{ color: 'var(--muted)', fontSize: 12 }}>—</span>
  const fields = Object.keys(changes)
  return (
    <div>
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          display: 'flex', alignItems: 'center', gap: 4,
          background: 'none', border: 'none', cursor: 'pointer',
          color: 'var(--muted)', fontSize: 12, padding: 0,
        }}
      >
        {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        {fields.length} field{fields.length !== 1 ? 's' : ''} changed
      </button>
      {open && (
        <div style={{
          marginTop: 6,
          display: 'flex',
          flexDirection: 'column',
          gap: 4,
          paddingLeft: 12,
          borderLeft: '2px solid var(--border)',
        }}>
          {fields.map(f => {
            const { old: oldVal, new: newVal } = changes[f]
            return (
              <div key={f} style={{ fontSize: 11 }}>
                <span style={{ color: 'var(--muted)', fontWeight: 500 }}>{f}: </span>
                <span style={{ color: '#ef4444' }}>{formatVal(oldVal)}</span>
                <span style={{ color: 'var(--muted)' }}> → </span>
                <span style={{ color: '#22c55e' }}>{formatVal(newVal)}</span>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

function formatVal(v) {
  if (v === null || v === undefined) return '—'
  if (typeof v === 'boolean') return v ? 'true' : 'false'
  if (Array.isArray(v)) return v.length ? v.join(', ') : '[]'
  return String(v)
}

// ─── Time formatter ───────────────────────────────────────
function relativeTime(isoStr) {
  if (!isoStr) return '—'
  const d = new Date(isoStr)
  const now = new Date()
  const diff = Math.floor((now - d) / 1000)
  if (diff < 60) return `${diff}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
}

function fullTime(isoStr) {
  if (!isoStr) return ''
  return new Date(isoStr).toLocaleString()
}

// ─── Main component ───────────────────────────────────────
export default function AuditLog() {
  const { filters, setFilter, clearFilters } = useURLFilters({
    entity_type: { default: '' },
    action: { default: '' },
    actor: { default: '' },
    date_from: { default: '' },
    date_to: { default: '' },
    audit_page: { default: 1, type: 'number' },
  }, { pageKey: 'audit_page' })
  const filterEntityType = filters.entity_type
  const filterAction = filters.action
  const filterActor = filters.actor
  const filterDateFrom = filters.date_from
  const filterDateTo = filters.date_to
  const page = filters.audit_page || 1

  const [entries, setEntries] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [entityTypes, setEntityTypes] = useState([])
  const [actions, setActions] = useState([])

  const PAGE_SIZE = 50

  const load = useCallback(async (pg) => {
    const loadPage = pg ?? page
    setLoading(true)
    setError(null)
    try {
      const data = await fetchAuditLog({
        entity_type: filterEntityType,
        action: filterAction,
        actor_email: filterActor,
        date_from: filterDateFrom,
        date_to: filterDateTo,
        page: loadPage,
        page_size: PAGE_SIZE,
      })
      setEntries(data.entries)
      setTotal(data.total)
      if (data.entity_types?.length) setEntityTypes(data.entity_types.filter(Boolean))
      if (data.actions?.length) setActions(data.actions.filter(Boolean))
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [filterEntityType, filterAction, filterActor, filterDateFrom, filterDateTo, page])

  useEffect(() => { load() }, [load])

  const totalPages = Math.ceil(total / PAGE_SIZE)

  return (
    <div>
      <PageHeader
        title="Audit Log"
        subtitle={`${total.toLocaleString()} event${total !== 1 ? 's' : ''} recorded`}
        icon={<ClipboardList size={20} />}
        actions={
          <Button variant="ghost" onClick={() => load(page)} title="Refresh">
            <RefreshCw size={14} />
          </Button>
        }
      />

      {/* Filters */}
      <Card style={{ marginBottom: 16, padding: '14px 16px' }}>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: '1 1 140px', minWidth: 120 }}>
            <label style={{ fontSize: 11, color: 'var(--muted)', fontWeight: 500 }}>Entity Type</label>
            <select style={SELECT_STYLE} value={filterEntityType} onChange={e => setFilter('entity_type', e.target.value)}>
              <option value="">All types</option>
              {entityTypes.map(t => (
                <option key={t} value={t}>{ENTITY_LABEL[t] || t}</option>
              ))}
            </select>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: '1 1 120px', minWidth: 100 }}>
            <label style={{ fontSize: 11, color: 'var(--muted)', fontWeight: 500 }}>Action</label>
            <select style={SELECT_STYLE} value={filterAction} onChange={e => setFilter('action', e.target.value)}>
              <option value="">All actions</option>
              {actions.map(a => (
                <option key={a} value={a}>{a}</option>
              ))}
            </select>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: '2 1 180px', minWidth: 140 }}>
            <label style={{ fontSize: 11, color: 'var(--muted)', fontWeight: 500 }}>Actor (email)</label>
            <div style={{ position: 'relative' }}>
              <Search size={12} style={{ position: 'absolute', left: 8, top: '50%', transform: 'translateY(-50%)', color: 'var(--muted)' }} />
              <Input
                value={filterActor}
                onChange={e => setFilter('actor', e.target.value)}
                placeholder="Filter by user..."
                style={{ paddingLeft: 26 }}
              />
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: '1 1 140px', minWidth: 120 }}>
            <label style={{ fontSize: 11, color: 'var(--muted)', fontWeight: 500 }}>From</label>
            <input
              type="date"
              value={filterDateFrom}
              onChange={e => setFilter('date_from', e.target.value)}
              style={{
                background: 'var(--bg)',
                border: '1px solid var(--border)',
                borderRadius: 6,
                padding: '6px 10px',
                fontSize: 12,
                color: 'var(--text)',
              }}
            />
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: '1 1 140px', minWidth: 120 }}>
            <label style={{ fontSize: 11, color: 'var(--muted)', fontWeight: 500 }}>To</label>
            <input
              type="date"
              value={filterDateTo}
              onChange={e => setFilter('date_to', e.target.value)}
              style={{
                background: 'var(--bg)',
                border: '1px solid var(--border)',
                borderRadius: 6,
                padding: '6px 10px',
                fontSize: 12,
                color: 'var(--text)',
              }}
            />
          </div>

          <Button
            variant="ghost"
            onClick={() => clearFilters()}
            style={{ alignSelf: 'flex-end' }}
          >
            Clear
          </Button>
        </div>
      </Card>

      {/* Table */}
      <Card style={{ padding: 0, overflow: 'hidden' }}>
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}>
            <Spinner />
          </div>
        ) : error ? (
          <div style={{ padding: 24, color: '#ef4444', textAlign: 'center', fontSize: 13 }}>{error}</div>
        ) : entries.length === 0 ? (
          <EmptyState icon={ClipboardList} title="No events recorded" sub="Changes to scans, integrations, exceptions, SLA, campaigns, workflows, ownership, and tags will appear here." />
        ) : (
          <>
            <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: 860 }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  {['Time', 'Action', 'Entity Type', 'Entity', 'Actor', 'Changes'].map(h => (
                    <th key={h} style={{
                      padding: '10px 14px',
                      textAlign: 'left',
                      fontSize: 11,
                      fontWeight: 600,
                      color: 'var(--muted)',
                      textTransform: 'uppercase',
                      letterSpacing: '0.05em',
                      whiteSpace: 'nowrap',
                    }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {entries.map((e, i) => (
                  <tr
                    key={e.id}
                    style={{
                      borderBottom: '1px solid var(--border)',
                      background: i % 2 === 0 ? 'transparent' : 'var(--bg-muted)',
                    }}
                  >
                    <td style={{ padding: '10px 14px', whiteSpace: 'nowrap' }}>
                      <div
                        title={fullTime(e.created_at)}
                        style={{ fontSize: 12, color: 'var(--muted)', cursor: 'default' }}
                      >
                        {relativeTime(e.created_at)}
                      </div>
                      <div style={{ fontSize: 10, color: 'var(--muted)', opacity: 0.7 }}>
                        {e.created_at ? new Date(e.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : ''}
                      </div>
                    </td>
                    <td style={{ padding: '10px 14px' }}>
                      <ActionBadge action={e.action} />
                    </td>
                    <td style={{ padding: '10px 14px' }}>
                      <EntityTypePill type={e.entity_type} />
                    </td>
                    <td style={{ padding: '10px 14px', maxWidth: 200 }}>
                      <div style={{ fontSize: 13, fontWeight: 500, color: 'var(--text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {e.entity_name || <span style={{ color: 'var(--muted)' }}>—</span>}
                      </div>
                      {e.entity_id && (
                        <div style={{ fontSize: 10, color: 'var(--muted)' }}>id #{e.entity_id}</div>
                      )}
                    </td>
                    <td style={{ padding: '10px 14px', whiteSpace: 'nowrap' }}>
                      {e.actor_email ? (
                        <div>
                          <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text)' }}>
                            {e.actor_display_name || e.actor_email}
                          </div>
                          {e.actor_display_name && (
                            <div style={{ fontSize: 10, color: 'var(--muted)' }}>{e.actor_email}</div>
                          )}
                        </div>
                      ) : (
                        <span style={{ fontSize: 12, color: 'var(--muted)' }}>System</span>
                      )}
                    </td>
                    <td style={{ padding: '10px 14px', maxWidth: 280 }}>
                      <ChangeDiff changes={e.changes} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '12px 16px',
                borderTop: '1px solid var(--border)',
                fontSize: 12,
                color: 'var(--muted)',
              }}>
                <span>
                  Showing {(page - 1) * PAGE_SIZE + 1}–{Math.min(page * PAGE_SIZE, total)} of {total.toLocaleString()}
                </span>
                <div style={{ display: 'flex', gap: 6 }}>
                  <Button
                    variant="ghost"
                    onClick={() => setFilter('audit_page', page - 1)}
                    disabled={page === 1}
                    style={{ padding: '4px 10px', fontSize: 12 }}
                  >
                    Previous
                  </Button>
                  <Button
                    variant="ghost"
                    onClick={() => setFilter('audit_page', page + 1)}
                    disabled={page >= totalPages}
                    style={{ padding: '4px 10px', fontSize: 12 }}
                  >
                    Next
                  </Button>
                </div>
              </div>
            )}
          </>
        )}
      </Card>
    </div>
  )
}
