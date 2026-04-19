import React, { useEffect, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import {
  Network, RefreshCw, ChevronRight, ChevronLeft, Sparkles, ShieldCheck,
  LogIn, Target, HelpCircle, X as XIcon, Search as SearchIcon,
} from 'lucide-react'
import {
  getJobStatus, getOrgContext, listAttackPaths, runCorrelation,
} from '../../api.js'
import { useScan } from '../../App.jsx'
import AttackPathGraph from './AttackPathGraph.jsx'
import {
  Card, PageHeader, EmptyState, SeverityBadge, Button, Pill,
  ErrorBanner, SkeletonCard,
} from '../shared/ui.jsx'

function SeverityPillForLabel({ label }) {
  const map = { Critical: 4, High: 3, Medium: 2, Low: 1 }
  const sev = map[label] ?? 0
  return <SeverityBadge severity={sev} label={label} />
}

// Human-readable labels for the reason codes emitted by the backend. Keeps
// the UI decoupled from machine strings — if a new code appears we fall
// back to a title-cased version so nothing is invisible.
const ENTRY_REASON_LABELS = {
  critical_finding: 'Critical finding',
  high_finding: 'High finding',
  medium_finding: 'Medium finding',
  internet_facing: 'Internet-facing',
  has_exploit: 'Public exploit',
}

const TARGET_REASON_LABELS = {
  domain_controller: 'Domain controller',
  internet_facing_target: 'Internet-facing',
  has_critical_finding: 'Hosts critical finding',
}

// Defensive JSON-string parse. Older backends (pre-_jsonify) return JSON
// columns as strings on SQLite — rather than depend on a server restart,
// normalize here so the component never crashes on .map/.bonuses access.
function safeJson(value) {
  if (value == null || typeof value === 'object') return value
  if (typeof value === 'string') {
    try { return JSON.parse(value) } catch { return null }
  }
  return value
}

function normalizePath(p) {
  if (!p) return p
  return {
    ...p,
    steps: safeJson(p.steps) || [],
    score_breakdown: safeJson(p.score_breakdown),
    recommended_mitigations: safeJson(p.recommended_mitigations) || [],
  }
}

// Tone for per-step pivot quality. Green = real service exposure, yellow =
// reachability only (ephemeral port, not a proven pivot), blue = identity
// primitive, grey = inference-only signal.
const PIVOT_QUALITY_STYLES = {
  exploit_path_verified: { bg: '#15803d20', border: '#15803d80', fg: '#14532d', label: 'exploit path verified' },
  service_exposed: { bg: '#16a34a15', border: '#16a34a60', fg: '#15803d', label: 'service exposed' },
  port_mismatch:   { bg: '#ea580c15', border: '#ea580c60', fg: '#9a3412', label: 'port mismatch' },
  reachability:    { bg: '#f59e0b15', border: '#f59e0b60', fg: '#b45309', label: 'reachability only' },
  identity:        { bg: '#2563eb15', border: '#2563eb60', fg: '#1d4ed8', label: 'identity' },
  inference:       { bg: '#94a3b815', border: '#94a3b860', fg: '#475569', label: 'inference' },
  entry:           { bg: '#7c3aed15', border: '#7c3aed60', fg: '#6d28d9', label: 'entry' },
}

function PivotQualityBadge({ quality }) {
  if (!quality) return null
  const s = PIVOT_QUALITY_STYLES[quality]
  if (!s) return null
  return (
    <span
      title={
        quality === 'exploit_path_verified'
          ? 'Observed network connection hits the exact port the target\'s finding sits on — strongest signal we emit.'
          : quality === 'port_mismatch'
            ? 'Observed traffic and the target\'s vulnerable service are on different ports — not a proven exploit path.'
            : quality === 'reachability'
              ? 'Hosts can talk, but the observed port does not prove the target\'s finding is exploitable through this flow.'
              : quality === 'service_exposed'
                ? 'Target exposes a recognised service port — a real pivot primitive.'
                : quality === 'identity'
                  ? 'Credential / AD primitive — the attacker inherits access via shared identity.'
                  : 'Weaker signal (shared cert, JARM, or same IP) — possible same infrastructure, not proven reachability.'
      }
      style={{
        marginLeft: 6, padding: '1px 6px', fontSize: 10,
        background: s.bg, border: `1px solid ${s.border}`,
        borderRadius: 4, color: s.fg, fontWeight: 600,
        textTransform: 'lowercase',
      }}
    >
      {s.label}
    </span>
  )
}

function humanizeCode(code) {
  if (!code) return ''
  return code
    .replace(/_/g, ' ')
    .replace(/^([a-z])/, m => m.toUpperCase())
}

// Minimal native <select> wrapped with the app's pill aesthetic. Keeps
// styling consistent without pulling in a combobox dependency.
function FilterSelect({ value, onChange, options, compact = false }) {
  return (
    <select
      value={value || ''}
      onChange={e => onChange(e.target.value)}
      style={{
        padding: compact ? '4px 8px' : '6px 10px',
        fontSize: 12, fontWeight: 600,
        background: 'var(--bg-secondary)',
        border: '1px solid var(--border)',
        borderRadius: 8,
        color: value ? 'var(--text-primary)' : 'var(--text-secondary)',
        cursor: 'pointer', outline: 'none',
      }}
    >
      {options.map(o => (
        <option key={o.value} value={o.value}>{o.label}</option>
      ))}
    </select>
  )
}

function EntryReasonPills({ reason }) {
  if (!reason) return null
  const parts = String(reason).split('+').map(p => p.trim()).filter(Boolean)
  return (
    <div style={{ display: 'inline-flex', gap: 4, flexWrap: 'wrap' }}>
      {parts.map(p => (
        <Pill
          key={p}
          label={ENTRY_REASON_LABELS[p] || humanizeCode(p)}
          color="#2563eb"
        />
      ))}
    </div>
  )
}

function TargetReasonPill({ reason }) {
  if (!reason) return null
  // target_reason can be 'high_criticality=9' — split on '=' for display.
  const [code, value] = String(reason).split('=')
  const label = TARGET_REASON_LABELS[code] || humanizeCode(code || reason)
  const display = value ? `${label} (${value})` : label
  return <Pill label={display} color="#db2777" />
}

function ScoreBreakdown({ score, breakdown }) {
  if (score == null && !breakdown) return null
  const b = breakdown || {}
  return (
    <div style={{
      padding: '12px 14px', background: 'var(--bg-secondary)',
      border: '1px solid var(--border)', borderRadius: 8, fontSize: 12, lineHeight: 1.6,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
        <HelpCircle size={13} color="var(--text-muted)" />
        <span style={{ fontWeight: 700, color: 'var(--text-primary)' }}>
          Score: {score != null ? Number(score).toFixed(1) : '—'} / 100
        </span>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, color: 'var(--text-secondary)' }}>
        {b.entry_severity != null && <div>Entry severity: <b>{b.entry_severity}</b> × 6 = {b.entry_severity * 6}</div>}
        {b.target_criticality != null && <div>Target criticality: <b>{b.target_criticality}</b> × 4 = {b.target_criticality * 4}</div>}
        {b.chain_length != null && <div>Chain length: <b>{b.chain_length}</b> (+{b.length_bonus})</div>}
        {b.confidence_factor != null && <div>Edge confidence: <b>×{b.confidence_factor}</b></div>}
      </div>
      {Array.isArray(b.bonuses) && b.bonuses.length > 0 && (
        <div style={{ marginTop: 8, color: 'var(--text-secondary)' }}>
          Bonuses: {b.bonuses.map(x => `${humanizeCode(x.label)} (+${x.value})`).join(', ')}
        </div>
      )}
      {b.formula && (
        <div style={{ marginTop: 8, fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono, monospace)' }}>
          {b.formula}
        </div>
      )}
    </div>
  )
}

// Active correlation job id — scoped by org so navigating back + multi-org
// users don't attach to a stale job from another org.
const JOB_STORAGE_KEY = (orgId) => `attack_paths_active_job_${orgId || 'none'}`
const JOB_POLL_INTERVAL_MS = 3000

// Help icon in the header that reveals the methodology on hover/focus.
// Replaces the dismissable banner: less visual weight, same discoverability,
// no localStorage state to manage.
function MethodologyHelp() {
  const [open, setOpen] = useState(false)
  return (
    <span
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
      style={{ position: 'relative', display: 'inline-flex' }}
    >
      <button
        type="button"
        aria-label="How attack paths are built"
        onClick={() => setOpen(o => !o)}
        style={{
          background: 'none', border: 'none', cursor: 'help',
          padding: 2, color: 'var(--text-muted)', display: 'inline-flex',
        }}
      >
        <HelpCircle size={16} />
      </button>
      {open && (
        <div
          role="tooltip"
          style={{
            position: 'absolute', top: '100%', left: 0, marginTop: 6,
            width: 360, maxWidth: '90vw', zIndex: 50,
            padding: '12px 14px', borderRadius: 10,
            background: 'var(--bg-card)',
            border: '1px solid var(--border)',
            boxShadow: '0 8px 24px rgba(0,0,0,0.12)',
            fontSize: 12, lineHeight: 1.55, color: 'var(--text-secondary)',
          }}
        >
          <div style={{ fontWeight: 700, color: 'var(--text-primary)', marginBottom: 6, fontSize: 13 }}>
            How attack paths are built
          </div>
          <div style={{ marginBottom: 6 }}>
            We take an <b>assume-breach</b> view: any asset with a live severity ≥ High
            finding is a candidate <b>entry point</b>. We then BFS through the asset
            relationship graph (netconn traffic, AD trusts, shared sessions, runs-as
            principals, DNS / cloud edges) until we reach a <b>target</b> — a domain
            controller, a high-criticality asset, or an internet-facing egress.
          </div>
          <div style={{ marginBottom: 6 }}>
            Each path carries an explainable score:{' '}
            <code style={{ fontSize: 11 }}>
              (entry_sev × 6 + target_crit × 4 + length bonus + bonuses) × edge_confidence
            </code>.
            Expand any path to see step-by-step reasoning.
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            If you're seeing few paths, the graph is likely sparse — check the inventory
            edge extractor is populating netconn / AD / identity relationships.
          </div>
        </div>
      )}
    </span>
  )
}

function StepChain({ steps = [], detailed = false }) {
  if (!steps.length) return <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>No steps</span>

  if (!detailed) {
    // Compact card view — one-line hostname + finding name per hop.
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
        {steps.map((step, idx) => (
          <React.Fragment key={`${step.asset_id}-${step.finding_id}-${idx}`}>
            <div style={{
              display: 'inline-flex', flexDirection: 'column', gap: 2,
              padding: '6px 10px', borderRadius: 8,
              background: 'var(--bg-secondary)', border: '1px solid var(--border)',
              maxWidth: 260,
            }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {step.hostname || 'unknown'}
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {step.finding_name || step.plugin_name || `Finding #${step.finding_id}`}
              </div>
            </div>
            {idx < steps.length - 1 && <ChevronRight size={14} color="var(--text-muted)" />}
          </React.Fragment>
        ))}
      </div>
    )
  }

  // Detailed view — per-step why_reachable + what_enables reasoning.
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {steps.map((step, idx) => {
        const isEntry = step.edge_type === 'entry' || idx === 0
        return (
          <div key={`${step.asset_id}-${step.finding_id}-${idx}`} style={{
            display: 'flex', alignItems: 'flex-start', gap: 10,
          }}>
            <div style={{
              minWidth: 24, height: 24, borderRadius: 12,
              background: isEntry ? '#2563eb' : 'var(--bg-secondary)',
              color: isEntry ? 'white' : 'var(--text-secondary)',
              border: '1px solid var(--border)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 11, fontWeight: 700, flexShrink: 0,
            }}>
              {idx + 1}
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 2 }}>
                {step.hostname || 'unknown'}
                {step.edge_type && step.edge_type !== 'entry' && (
                  <span style={{
                    marginLeft: 8, padding: '1px 6px', fontSize: 10,
                    background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                    borderRadius: 4, color: 'var(--text-muted)', fontWeight: 500,
                    textTransform: 'lowercase',
                  }}>
                    via {step.edge_type}
                    {step.edge_confidence ? ` · ${step.edge_confidence}` : ''}
                  </span>
                )}
                <PivotQualityBadge quality={step.pivot_quality} />
              </div>
              {step.why_reachable && (
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 3 }}>
                  <b>Why reachable:</b> {step.why_reachable}
                </div>
              )}
              {step.what_enables && (
                <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                  <b>What this enables:</b> {step.what_enables}
                </div>
              )}
            </div>
          </div>
        )
      })}
    </div>
  )
}

function AttackPathCard({ path, onClick }) {
  return (
    <Card style={{ marginBottom: 12, cursor: 'pointer' }} onClick={onClick}>
      <div style={{ padding: '14px 16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, marginBottom: 10 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <SeverityPillForLabel label={path.severity} />
            {path.score != null && (
              <Pill label={`Score ${Number(path.score).toFixed(1)}`} color="var(--accent)" />
            )}
            <Pill label={`${path.chain_length} step${path.chain_length === 1 ? '' : 's'}`} color="var(--text-secondary)" />
            {path.narrative && <Pill label="Narrated" color="#7c3aed" />}
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            {path.created_at ? new Date(path.created_at).toLocaleString() : ''}
          </div>
        </div>

        {/* Why this path exists — entry + target reasons */}
        {(path.entry_reason || path.target_reason) && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10, flexWrap: 'wrap', fontSize: 12, color: 'var(--text-secondary)' }}>
            {path.entry_reason && (
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                <LogIn size={12} color="#2563eb" /> <EntryReasonPills reason={path.entry_reason} />
              </span>
            )}
            {path.target_reason && (
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                <Target size={12} color="#db2777" /> <TargetReasonPill reason={path.target_reason} />
              </span>
            )}
          </div>
        )}

        <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 10, lineHeight: 1.5 }}>
          <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{path.entry_hostname || 'Entry'}</span>
          {' → '}
          <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{path.target_hostname || 'Target'}</span>
        </div>
        <StepChain steps={path.steps} />
      </div>
    </Card>
  )
}

function AttackPathDetail({ path, onClose }) {
  const { t } = useTranslation()
  if (!path) return null
  const mitigations = path.recommended_mitigations || []
  return (
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 200,
      display: 'flex', alignItems: 'flex-start', justifyContent: 'center', padding: 32, overflow: 'auto',
    }}
      onClick={onClose}
    >
      <Card
        style={{ maxWidth: 820, width: '100%', background: 'var(--bg-card)', cursor: 'default' }}
        onClick={(e) => e?.stopPropagation?.()}
      >
        <div style={{ padding: '18px 22px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <Network size={18} color="var(--text-muted)" />
              <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)' }}>
                Attack Path #{path.id}
              </div>
              <SeverityPillForLabel label={path.severity} />
            </div>
            <Button variant="ghost" size="sm" onClick={onClose}>Close</Button>
          </div>

          {/* Entry + target summary */}
          {(path.entry_reason || path.target_reason) && (
            <div style={{
              marginBottom: 14, padding: '10px 12px',
              background: 'var(--bg-secondary)', border: '1px solid var(--border)',
              borderRadius: 8, fontSize: 12, display: 'grid',
              gridTemplateColumns: '1fr 1fr', gap: 10, alignItems: 'start',
            }}>
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 4 }}>
                  <LogIn size={11} /> Entry
                </div>
                <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>
                  {path.entry_hostname || '—'}
                </div>
                <EntryReasonPills reason={path.entry_reason} />
              </div>
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 4 }}>
                  <Target size={11} /> Target
                </div>
                <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>
                  {path.target_hostname || '—'}
                </div>
                <TargetReasonPill reason={path.target_reason} />
              </div>
            </div>
          )}

          {Array.isArray(path.steps) && path.steps.length >= 2 && (
            <div style={{ marginBottom: 18 }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: 0.04 }}>
                Graph
              </div>
              <AttackPathGraph
                steps={path.steps}
                targetReason={(path.target_reason || '').split('=')[0]}
              />
            </div>
          )}

          <div style={{ marginBottom: 18 }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: 0.04 }}>
              Reasoning — step by step
            </div>
            <StepChain steps={path.steps} detailed />
          </div>

          {path.score != null && (
            <div style={{ marginBottom: 18 }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: 0.04 }}>
                Why this is prioritized
              </div>
              <ScoreBreakdown score={path.score} breakdown={path.score_breakdown} />
            </div>
          )}

          {path.narrative ? (
            <div style={{ marginBottom: 18, padding: '14px 16px', background: '#7c3aed10', border: '1px solid #7c3aed40', borderRadius: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
                <Sparkles size={14} color="#7c3aed" />
                <span style={{ fontSize: 11, fontWeight: 700, color: '#7c3aed', letterSpacing: 0.05, textTransform: 'uppercase' }}>
                  LLM Narrative
                </span>
              </div>
              <div style={{ fontSize: 13, lineHeight: 1.65, color: 'var(--text-secondary)', whiteSpace: 'pre-wrap' }}>
                {path.narrative}
              </div>
            </div>
          ) : (
            <div style={{ marginBottom: 18, padding: '12px 14px', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12, color: 'var(--text-muted)' }}>
              No narrative generated yet. Narratives are produced by the cross-finding correlator when an LLM provider is configured.
            </div>
          )}

          <div>
            <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: 0.04 }}>
              Recommended Mitigations
            </div>
            {mitigations.length === 0 ? (
              <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>None ranked.</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {mitigations.map((m, idx) => {
                  const row = (
                    <>
                      <ShieldCheck size={14} color="var(--accent)" style={{ flexShrink: 0 }} />
                      <div style={{ flex: 1, fontSize: 13, color: 'var(--text-primary)', minWidth: 0 }}>
                        <div style={{ fontWeight: 600, textDecoration: m.finding_id ? 'underline' : 'none' }}>
                          {m.finding_name || `Finding #${m.finding_id}`}
                        </div>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                          Breaks {m.chains_broken} chain{m.chains_broken === 1 ? '' : 's'}
                        </div>
                      </div>
                      <Pill label={`#${idx + 1}`} color="var(--accent)" />
                    </>
                  )
                  const rowStyle = {
                    display: 'flex', alignItems: 'center', gap: 10,
                    padding: '8px 12px', background: 'var(--bg-secondary)',
                    border: '1px solid var(--border)', borderRadius: 8,
                    textDecoration: 'none', color: 'inherit',
                    cursor: m.finding_id ? 'pointer' : 'default',
                  }
                  if (m.finding_id) {
                    return (
                      <Link
                        key={`${m.finding_id}-${idx}`}
                        to={`/findings/${m.finding_id}`}
                        style={rowStyle}
                        title={t('attackPaths.openFinding', 'Open finding')}
                      >
                        {row}
                      </Link>
                    )
                  }
                  return (
                    <div key={`no-id-${idx}`} style={rowStyle}>
                      {row}
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        </div>
      </Card>
    </div>
  )
}

// Source of truth for every server-driven filter lives in the URL so state
// survives refresh, can be bookmarked, and is easy to share. `reload` reads
// this dict directly and forwards every non-empty value to the backend.
function readFiltersFromUrl(searchParams) {
  const get = (k, d = '') => searchParams.get(k) ?? d
  return {
    search: get('search'),
    severity: get('severity'),
    entry_reason: get('entry_reason'),
    target_reason: get('target_reason'),
    min_score: get('min_score'),
    narrated: get('narrated'),
    sort_by: get('sort_by', 'score'),
    order: get('order', 'desc'),
    page: parseInt(get('page', '1'), 10) || 1,
    page_size: parseInt(get('page_size', '25'), 10) || 25,
  }
}

const DEFAULT_PAGE_SIZE = 25
const PAGE_SIZE_OPTIONS = [10, 25, 50, 100]
const ENTRY_REASON_OPTIONS = [
  { value: '', label: 'Any entry reason' },
  { value: 'critical_finding', label: 'Critical finding' },
  { value: 'high_finding', label: 'High finding' },
  { value: 'internet_facing', label: 'Internet-facing' },
  { value: 'has_exploit', label: 'Public exploit' },
]
const TARGET_REASON_OPTIONS = [
  { value: '', label: 'Any target reason' },
  { value: 'domain_controller', label: 'Domain controller' },
  { value: 'high_criticality', label: 'High criticality' },
  { value: 'internet_facing_target', label: 'Internet-facing' },
  { value: 'has_critical_finding', label: 'Hosts critical finding' },
]
const SORT_OPTIONS = [
  { value: 'score', label: 'Score' },
  { value: 'severity', label: 'Severity' },
  { value: 'chain_length', label: 'Chain length' },
  { value: 'created_at', label: 'Created' },
]

export default function AttackPaths() {
  const { t } = useTranslation()
  const [searchParams, setSearchParams] = useSearchParams()
  const filters = useMemo(() => readFiltersFromUrl(searchParams), [searchParams])
  // Sidebar scan picker — when set, restrict to paths involving findings from
  // that scan. null/undefined means "all scans" so we omit the param.
  const { activeScanId } = useScan()

  // Local, immediate value for the search input — debounced into the URL so
  // we don't fire a request on every keystroke.
  const [searchInput, setSearchInput] = useState(filters.search)
  useEffect(() => { setSearchInput(filters.search) }, [filters.search])
  useEffect(() => {
    if (searchInput === filters.search) return
    const timer = setTimeout(() => {
      setFilter({ search: searchInput, page: 1 })
    }, 400)
    return () => clearTimeout(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchInput])

  function setFilter(patch) {
    const next = new URLSearchParams(searchParams)
    for (const [k, v] of Object.entries(patch)) {
      if (v === '' || v == null || v === false) next.delete(k)
      else next.set(k, String(v))
    }
    // Reset to page 1 whenever a filter (not page/page_size) changes.
    const resetsPage = Object.keys(patch).some(
      k => !['page', 'page_size'].includes(k),
    )
    if (resetsPage && !('page' in patch)) next.delete('page')
    setSearchParams(next, { replace: true })
  }

  const [paths, setPaths] = useState(null)
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [selectedId, setSelectedId] = useState(null)
  const [orgContext, setLocalOrgContext] = useState(() => getOrgContext())
  // Active job: { id, status, startedAt, lastStatusAt, progress? }
  const [activeJob, setActiveJob] = useState(() => {
    const raw = localStorage.getItem(JOB_STORAGE_KEY(getOrgContext()))
    if (!raw) return null
    try { return JSON.parse(raw) } catch { return null }
  })

  function persistActiveJob(job) {
    const key = JOB_STORAGE_KEY(getOrgContext())
    if (job) localStorage.setItem(key, JSON.stringify(job))
    else localStorage.removeItem(key)
    setActiveJob(job)
  }

  // Keep org-context state in sync with localStorage changes made elsewhere
  // (org switcher in the nav, another tab logging out, etc.).
  useEffect(() => {
    function sync() { setLocalOrgContext(getOrgContext()) }
    window.addEventListener('storage', sync)
    window.addEventListener('focus', sync)
    return () => {
      window.removeEventListener('storage', sync)
      window.removeEventListener('focus', sync)
    }
  }, [])

  const selected = useMemo(
    () => (paths || []).find(p => p.id === selectedId) || null,
    [paths, selectedId],
  )

  async function reload() {
    setLoading(true)
    setError(null)
    try {
      // Forward every non-empty filter; URLSearchParams strips empty values.
      const params = {}
      for (const [k, v] of Object.entries(filters)) {
        if (v === '' || v == null) continue
        params[k] = v
      }
      if (activeScanId) params.scan_id = activeScanId
      const res = await listAttackPaths(params)
      setPaths((res?.items || []).map(normalizePath))
      setTotal(res?.total || 0)
    } catch (e) {
      setError(e?.message || 'Failed to load attack paths')
    } finally {
      setLoading(false)
    }
  }

  // Clear results when the sidebar scan changes so the skeleton (gated on
  // `paths === null`) re-shows during the refetch — otherwise stale rows from
  // the previous scan linger silently. We deliberately don't do this for
  // ordinary filter changes to avoid a flash on every keystroke.
  useEffect(() => {
    setPaths(null)
    setSelectedId(null)
  }, [activeScanId])

  useEffect(() => { reload() }, [
    filters.search, filters.severity, filters.entry_reason,
    filters.target_reason, filters.min_score, filters.narrated,
    filters.sort_by, filters.order, filters.page, filters.page_size,
    activeScanId,
  ])

  // Poll the active job's status while running. Stops cleanly when the job
  // finishes, fails, or is cleared. Survives navigation: if you come back,
  // the job_id is read from localStorage and polling resumes.
  useEffect(() => {
    if (!activeJob || !['pending', 'running'].includes(activeJob.status)) return

    let cancelled = false
    async function tick() {
      try {
        const status = await getJobStatus(activeJob.id)
        if (cancelled) return
        if (status.status === 'completed') {
          persistActiveJob(null)
          await reload()
        } else if (status.status === 'failed') {
          setError(status.error || t(
            'attackPaths.rebuildFailed', 'Rebuild failed. Check server logs.',
          ))
          persistActiveJob(null)
        } else {
          // Still running — update lastStatusAt so UI can show elapsed time.
          persistActiveJob({ ...activeJob, status: status.status, lastStatusAt: Date.now() })
        }
      } catch (e) {
        // 'Job not found' means the server evicted it from the in-memory
        // registry (2h TTL or process restart). Drop the local record so
        // the Rebuild button re-enables.
        const msg = String(e?.message || '').toLowerCase()
        if (msg.includes('job not found') || msg.includes('not found')) {
          persistActiveJob(null)
        }
        // Other transient errors (network, 5xx): ignore — next tick retries.
      }
    }

    // Immediate tick, then interval.
    tick()
    const id = setInterval(tick, JOB_POLL_INTERVAL_MS)
    return () => { cancelled = true; clearInterval(id) }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeJob?.id, activeJob?.status])

  const isRebuilding = !!activeJob && ['pending', 'running'].includes(activeJob.status)
  const rebuildElapsedSeconds = activeJob?.startedAt
    ? Math.max(0, Math.round((Date.now() - activeJob.startedAt) / 1000))
    : 0

  async function onRebuild() {
    // Re-check at click time so a fresh org pick doesn't require a remount.
    if (!getOrgContext()) {
      setLocalOrgContext(null)
      setError(t(
        'attackPaths.selectOrgError',
        'Select an organization to rebuild correlations.',
      ))
      return
    }
    if (isRebuilding) return  // Button already disabled, belt-and-suspenders.

    setError(null)
    try {
      const res = await runCorrelation()
      if (!res?.job_id) throw new Error('Server did not return a job_id')
      persistActiveJob({
        id: res.job_id,
        status: res.status || 'pending',
        startedAt: Date.now(),
        lastStatusAt: Date.now(),
      })
    } catch (e) {
      setError(e?.message || 'Failed to start rebuild')
    }
  }

  const totalPages = Math.max(1, Math.ceil(total / filters.page_size))
  const rangeStart = total === 0 ? 0 : (filters.page - 1) * filters.page_size + 1
  const rangeEnd = Math.min(filters.page * filters.page_size, total)
  const hasActiveFilters = !!(
    filters.search || filters.severity || filters.entry_reason ||
    filters.target_reason || filters.min_score || filters.narrated
  )

  return (
    <div style={{ padding: 24, maxWidth: 1200, margin: '0 auto' }}>
      <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
      <PageHeader
        title={t('attackPaths.title', 'Attack Paths')}
        subtitle={t('attackPaths.subtitle', 'Assume-breach chains from exploitable entry points to crown-jewel targets, ranked by an explainable score')}
        action={
          <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            <MethodologyHelp />
            <Button
              onClick={onRebuild}
              variant="ghost"
              size="sm"
              disabled={isRebuilding || !orgContext}
              title={
                !orgContext
                  ? t('attackPaths.selectOrgTooltip', 'Select an organization to rebuild')
                  : isRebuilding
                    ? t('attackPaths.rebuildingTooltip', 'Running in the background — safe to navigate away')
                    : undefined
              }
            >
              <RefreshCw
                size={14}
                style={{
                  marginRight: 4,
                  animation: isRebuilding ? 'spin 1.2s linear infinite' : 'none',
                }}
              />
              {!orgContext
                ? t('attackPaths.selectOrg', 'Select an organization to rebuild')
                : isRebuilding
                  ? t('attackPaths.rebuilding', 'Rebuilding… ({{sec}}s)', { sec: rebuildElapsedSeconds })
                  : t('attackPaths.rebuild', 'Rebuild')}
            </Button>
          </div>
        }
      />

      {isRebuilding && (
        <div style={{
          marginBottom: 12, padding: '10px 14px',
          background: '#7c3aed15', border: '1px solid #7c3aed40',
          borderRadius: 8, fontSize: 13, display: 'flex',
          alignItems: 'center', gap: 10, color: 'var(--text-secondary)',
        }}>
          <RefreshCw
            size={14}
            color="#7c3aed"
            style={{ animation: 'spin 1.2s linear infinite' }}
          />
          <span>
            {t(
              'attackPaths.rebuildingBanner',
              'Rebuilding correlations in the background ({{sec}}s elapsed). You can navigate away — we\'ll refresh when it finishes.',
              { sec: rebuildElapsedSeconds },
            )}
          </span>
        </div>
      )}

      {/* Filter bar — search + severity + reason dropdowns + min score + narrated toggle + sort */}
      <div style={{
        display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 10,
        alignItems: 'center',
      }}>
        <div style={{
          display: 'inline-flex', alignItems: 'center', gap: 6,
          padding: '6px 10px', background: 'var(--bg-secondary)',
          border: '1px solid var(--border)', borderRadius: 8, flex: '1 1 260px',
          minWidth: 200, maxWidth: 420,
        }}>
          <SearchIcon size={14} color="var(--text-muted)" />
          <input
            value={searchInput}
            onChange={e => setSearchInput(e.target.value)}
            placeholder={t('attackPaths.searchPlaceholder', 'Search host, title…')}
            style={{
              flex: 1, border: 'none', background: 'transparent', outline: 'none',
              fontSize: 13, color: 'var(--text-primary)', minWidth: 0,
            }}
          />
          {searchInput && (
            <button
              onClick={() => setSearchInput('')}
              style={{ border: 'none', background: 'none', cursor: 'pointer', padding: 0, color: 'var(--text-muted)' }}
              title={t('common.clear', 'Clear')}
            >
              <XIcon size={12} />
            </button>
          )}
        </div>

        <FilterSelect
          value={filters.severity}
          onChange={v => setFilter({ severity: v })}
          options={[
            { value: '', label: t('attackPaths.allSeverities', 'All severities') },
            { value: 'Critical', label: 'Critical' },
            { value: 'High', label: 'High' },
            { value: 'Medium', label: 'Medium' },
          ]}
        />
        <FilterSelect
          value={filters.entry_reason}
          onChange={v => setFilter({ entry_reason: v })}
          options={ENTRY_REASON_OPTIONS}
        />
        <FilterSelect
          value={filters.target_reason}
          onChange={v => setFilter({ target_reason: v })}
          options={TARGET_REASON_OPTIONS}
        />

        <label style={{
          display: 'inline-flex', alignItems: 'center', gap: 6,
          padding: '6px 10px', background: 'var(--bg-secondary)',
          border: '1px solid var(--border)', borderRadius: 8,
          fontSize: 12, color: 'var(--text-secondary)',
        }}>
          {t('attackPaths.minScore', 'Min score')}
          <input
            type="number"
            min={0} max={100}
            value={filters.min_score}
            onChange={e => setFilter({ min_score: e.target.value })}
            style={{
              width: 50, border: 'none', background: 'transparent',
              outline: 'none', fontSize: 12, color: 'var(--text-primary)',
            }}
          />
        </label>

        <label style={{
          display: 'inline-flex', alignItems: 'center', gap: 6,
          padding: '6px 10px', background: 'var(--bg-secondary)',
          border: '1px solid var(--border)', borderRadius: 8,
          fontSize: 12, color: 'var(--text-secondary)', cursor: 'pointer',
        }}>
          <input
            type="checkbox"
            checked={filters.narrated === 'true'}
            onChange={e => setFilter({ narrated: e.target.checked ? 'true' : '' })}
            style={{ margin: 0 }}
          />
          {t('attackPaths.narratedOnly', 'Narrated only')}
        </label>

        {hasActiveFilters && (
          <button
            onClick={() => setSearchParams(new URLSearchParams(), { replace: true })}
            style={{
              padding: '6px 10px', fontSize: 12, fontWeight: 600,
              background: 'transparent', border: '1px solid var(--border)',
              borderRadius: 8, color: 'var(--text-secondary)', cursor: 'pointer',
            }}
          >
            {t('attackPaths.clearFilters', 'Clear filters')}
          </button>
        )}
      </div>

      {/* Result count + sort — same line, separated so they're glanceable */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        gap: 10, marginBottom: 14, fontSize: 12, color: 'var(--text-muted)',
        flexWrap: 'wrap',
      }}>
        <div>
          {total > 0
            ? t('attackPaths.resultCount', 'Showing {{start}}–{{end}} of {{total}}', {
                start: rangeStart, end: rangeEnd, total,
              })
            : loading
              ? t('attackPaths.loading', 'Loading…')
              : t('attackPaths.noResults', 'No attack paths match these filters')}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span>{t('attackPaths.sortBy', 'Sort by')}</span>
          <FilterSelect
            value={filters.sort_by}
            onChange={v => setFilter({ sort_by: v })}
            options={SORT_OPTIONS}
            compact
          />
          <button
            onClick={() => setFilter({ order: filters.order === 'asc' ? 'desc' : 'asc' })}
            title={filters.order === 'asc' ? 'Ascending — click to flip' : 'Descending — click to flip'}
            style={{
              padding: '6px 10px', fontSize: 12, fontWeight: 600,
              background: 'var(--bg-secondary)', border: '1px solid var(--border)',
              borderRadius: 8, color: 'var(--text-secondary)', cursor: 'pointer',
            }}
          >
            {filters.order === 'asc' ? '↑' : '↓'}
          </button>
        </div>
      </div>

      {error && <ErrorBanner message={error} />}

      {loading && paths === null ? (
        <div>
          <SkeletonCard />
          <SkeletonCard />
          <SkeletonCard />
        </div>
      ) : (paths?.length ?? 0) === 0 ? (
        <EmptyState
          icon={Network}
          title={t('attackPaths.emptyTitle', 'No attack paths yet')}
          sub={t('attackPaths.emptySub', 'Paths appear when any asset with a live high/critical finding can chain through the relationship graph to a crown-jewel target (domain controller, high-criticality asset, or internet-facing egress). If your graph is sparse, the inventory edge extractor may not have enough netconn/AD/identity data yet.')}
        />
      ) : (
        <div>
          {paths.map(p => (
            <AttackPathCard key={p.id} path={p} onClick={() => setSelectedId(p.id)} />
          ))}
        </div>
      )}

      {/* Pagination — hidden when all results fit on one page. Page size
          selector always visible so users can widen without filter churn. */}
      {total > 0 && (
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          marginTop: 14, gap: 12, flexWrap: 'wrap',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--text-muted)' }}>
            <span>{t('attackPaths.perPage', 'Per page')}</span>
            <FilterSelect
              compact
              value={String(filters.page_size)}
              onChange={v => setFilter({ page_size: v, page: 1 })}
              options={PAGE_SIZE_OPTIONS.map(n => ({ value: String(n), label: String(n) }))}
            />
          </div>
          {totalPages > 1 && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Button
                variant="ghost" size="sm"
                disabled={filters.page <= 1}
                onClick={() => setFilter({ page: filters.page - 1 })}
              >
                <ChevronLeft size={14} /> {t('common.prev', 'Prev')}
              </Button>
              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                {t('attackPaths.pageOf', 'Page {{page}} of {{total}}', {
                  page: filters.page, total: totalPages,
                })}
              </span>
              <Button
                variant="ghost" size="sm"
                disabled={filters.page >= totalPages}
                onClick={() => setFilter({ page: filters.page + 1 })}
              >
                {t('common.next', 'Next')} <ChevronRight size={14} />
              </Button>
            </div>
          )}
        </div>
      )}

      {selected && <AttackPathDetail path={selected} onClose={() => setSelectedId(null)} />}
    </div>
  )
}
