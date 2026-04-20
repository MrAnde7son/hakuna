import React, { useMemo, useState, useCallback, useEffect } from 'react'
import { ResponsiveContainer, Sankey } from 'recharts'
import {
  AlertTriangle, Bug, Shield, Lock, Server, Target, Play, TrendingUp,
  Package, FileText, Wrench, GitBranch, X, LayoutGrid, List,
} from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { useScan } from '../../App.jsx'
import { getAggregatedSolutions } from '../../api.js'
import {
  PageHeader, Card, Button, Pill, Spinner, EmptyState, ErrorBanner,
  SeverityBadge, useToast,
} from '../shared/ui.jsx'

// ─── Chart config ───────────────────────────────────────────────────────────
const CHART_HEIGHT = 240
const MARGIN = { top: 8, right: 220, bottom: 8, left: 200 }
const RIGHT_SQUASH = 0.42
const PLOT_CENTER_Y = (CHART_HEIGHT - MARGIN.top - MARGIN.bottom) / 2 + MARGIN.top

// Log10 scaling for link values. Raw finding counts span ~3 orders of magnitude
// (4 → 1058), which collapses small buckets to sub-pixel slivers. We store the
// real count on the node/link for label display but let Sankey compute layout
// from log-scaled values so even 4-finding categories stay visible + clickable.
const logScale = (v) => Math.log10(Math.max(0, v) + 1)

function squashY(y, h) {
  const center = y + h / 2
  const newH = h * RIGHT_SQUASH
  const newCenter = PLOT_CENTER_Y + (center - PLOT_CENTER_Y) * RIGHT_SQUASH
  return { y: newCenter - newH / 2, height: newH }
}

const squashPoint = (y) => PLOT_CENTER_Y + (y - PLOT_CENTER_Y) * RIGHT_SQUASH

function ribbonPath(sx, sy, tx, ty, scx, tcx, wSrc, wTgt) {
  const sTop = sy - wSrc / 2, sBot = sy + wSrc / 2
  const tTop = ty - wTgt / 2, tBot = ty + wTgt / 2
  return [
    `M${sx},${sTop}`,
    `C${scx},${sTop} ${tcx},${tTop} ${tx},${tTop}`,
    `L${tx},${tBot}`,
    `C${tcx},${tBot} ${scx},${sBot} ${sx},${sBot}`,
    'Z',
  ].join(' ')
}

// ─── Taxonomy ───────────────────────────────────────────────────────────────
// Maps backend `root_cause_type` values (from solution_aggregator.py) to UI meta.
const ROOT_CAUSE_META = {
  outdated_version:    { label: 'Outdated versions',     icon: Package,        color: 'var(--high)' },
  eol_software:        { label: 'EOL software',          icon: Server,         color: 'var(--medium)' },
  missing_patch:       { label: 'Missing patches',       icon: AlertTriangle,  color: 'var(--critical)' },
  deprecated_protocol: { label: 'Deprecated protocols',  icon: Lock,           color: 'var(--info)' },
  misconfiguration:    { label: 'Misconfigurations',     icon: Shield,         color: 'var(--warning)' },
}
const DEFAULT_META = { label: 'Other', icon: Target, color: 'var(--muted)' }
const metaFor = (rct) => ROOT_CAUSE_META[rct] || DEFAULT_META

// Right-side Sankey nodes aggregate every campaign into one of these action
// types (from solution_aggregator._determine_action_type). Monochrome on the
// right so the funnel visually converges into "the action space".
const ACTION_TYPE_META = {
  upgrade_component:    { label: 'Upgrade component', icon: Package },
  apply_patch:          { label: 'Apply patches',     icon: Wrench },
  migrate_to_supported: { label: 'Migrate off EOL',   icon: GitBranch },
  disable_protocol:     { label: 'Disable protocol',  icon: Lock },
  remediate_config:     { label: 'Fix configuration', icon: Shield },
}
const actionMetaFor = (at) => ACTION_TYPE_META[at] || { label: at || 'Other action', icon: Target }

// Posture-impact estimate: `risk_reduction` on aggregated-solutions is already
// expressed as a percentage (0–100) per backend scoring. We clamp low counts
// so tiny solutions don't look like meaningless zeros.
const postureImpact = (s) => Math.max(Number(s.risk_reduction || 0), 0)

function truncate(text, max = 150) {
  if (!text) return ''
  return text.length > max ? text.slice(0, max - 1).trimEnd() + '…' : text
}

// ─── Sankey shape ───────────────────────────────────────────────────────────
// Left column = one node per root_cause_type.
// Right column = one node per action_type (aggregates all campaigns).
// Links = (root_cause_type, action_type) pairs with total finding_count.
function buildSankey(suggestions) {
  const rctTotals = new Map()      // rct -> total findings
  const actionTotals = new Map()   // action -> { findings, campaigns }
  const pairTotals = new Map()     // "rct|action" -> findings

  suggestions.forEach(s => {
    if (!s.findingCount) return
    rctTotals.set(s.rootCauseType, (rctTotals.get(s.rootCauseType) || 0) + s.findingCount)
    const cur = actionTotals.get(s.actionType) || { findings: 0, campaigns: 0 }
    cur.findings += s.findingCount
    cur.campaigns += 1
    actionTotals.set(s.actionType, cur)
    const key = `${s.rootCauseType}|${s.actionType}`
    pairTotals.set(key, (pairTotals.get(key) || 0) + s.findingCount)
  })

  const issueNodes = Array.from(rctTotals.entries()).map(([rct, count]) => ({
    name: `${metaFor(rct).label} · ${count.toLocaleString()}`,
    kind: 'issue',
    issueType: rct,
    color: metaFor(rct).color,
  }))
  const actionNodes = Array.from(actionTotals.entries()).map(([at, agg]) => ({
    name: `${actionMetaFor(at).label} · ${agg.campaigns} campaign${agg.campaigns === 1 ? '' : 's'}`,
    kind: 'action',
    actionType: at,
    color: 'var(--primary)',
  }))
  const issueIndex = Object.fromEntries(issueNodes.map((n, i) => [n.issueType, i]))
  const actionIndex = Object.fromEntries(
    actionNodes.map((n, i) => [n.actionType, issueNodes.length + i])
  )

  const links = []
  pairTotals.forEach((raw, key) => {
    const [rct, at] = key.split('|')
    links.push({
      source: issueIndex[rct],
      target: actionIndex[at],
      // Layout uses log-scaled value so low-volume buckets stay visible;
      // rawValue is preserved for future tooltips / labels.
      value: logScale(raw),
      rawValue: raw,
      issueType: rct,
      actionType: at,
    })
  })

  return { nodes: [...issueNodes, ...actionNodes], links }
}

// ─── Sankey renderers ───────────────────────────────────────────────────────
function SankeyNodeRenderer(props) {
  const { x, y, width, height, payload, onHover, onSelect, hover, filter } = props
  const isIssue = payload.kind === 'issue'
  const id = isIssue ? payload.issueType : payload.actionType
  const side = isIssue ? 'issues' : 'campaigns'
  const hovered =
    (hover.side === side && hover.id === id) ||
    (hover.side === 'card' && (
      (isIssue && hover.rct === id) ||
      (!isIssue && hover.actionType === id)
    ))
  const selected = filter && filter.side === side && filter.id === id
  const lit = hovered || selected

  const pos = isIssue ? { y, height } : squashY(y, height)
  const labelX = isIssue ? x - 8 : x + width + 8

  const MAX_CHARS = 30
  const text = truncate(payload.name, MAX_CHARS)

  return (
    <g
      onMouseEnter={() => onHover(side, id)}
      onMouseLeave={() => onHover(null, null)}
      onClick={(e) => { e.stopPropagation(); onSelect(side, id) }}
      style={{ cursor: 'pointer' }}
    >
      <rect
        x={x}
        y={pos.y}
        width={width}
        height={pos.height}
        fill={payload.color}
        fillOpacity={lit ? 1 : 0.85}
        rx={2}
        stroke={selected ? payload.color : 'none'}
        strokeWidth={selected ? 2 : 0}
        style={{
          filter: lit ? `drop-shadow(0 0 8px ${payload.color})` : 'none',
          transition: 'fill-opacity 160ms ease, filter 160ms ease',
        }}
      />
      <text
        x={labelX}
        y={pos.y + pos.height / 2}
        dy={4}
        textAnchor={isIssue ? 'end' : 'start'}
        fontSize={11}
        fill="var(--text)"
        fontWeight={lit ? 600 : 500}
        pointerEvents="none"
      >
        {text}
      </text>
    </g>
  )
}

function SankeyLinkRenderer(props) {
  const {
    sourceX, sourceY, targetX, targetY, sourceControlX, targetControlX,
    linkWidth, payload, hover, filter,
  } = props
  const hovered =
    (hover.side === 'issues' && hover.id === payload.issueType) ||
    (hover.side === 'campaigns' && hover.id === payload.actionType) ||
    (hover.side === 'card' &&
      hover.rct === payload.issueType &&
      hover.actionType === payload.actionType)
  const selected = filter && (
    (filter.side === 'issues' && filter.id === payload.issueType) ||
    (filter.side === 'campaigns' && filter.id === payload.actionType)
  )
  const lit = hovered || selected

  const newTargetY = squashPoint(targetY)
  const targetWidth = Math.max(1, linkWidth * RIGHT_SQUASH)
  const d = ribbonPath(
    sourceX, sourceY, targetX, newTargetY,
    sourceControlX, targetControlX,
    linkWidth, targetWidth
  )
  return (
    <path
      d={d}
      stroke="none"
      fill={lit ? 'var(--primary)' : 'var(--muted)'}
      fillOpacity={lit ? 0.5 : 0.16}
      style={{ transition: 'fill 160ms ease, fill-opacity 160ms ease' }}
    />
  )
}

// ─── Card ───────────────────────────────────────────────────────────────────
function SuggestionCard({ suggestion, hover, onHover, onLaunch, index = 0 }) {
  const cardHovered = hover.side === 'card' && hover.id === suggestion.id
  const leftLit =
    cardHovered ||
    (hover.side === 'issues' && hover.id === suggestion.rootCauseType)
  const rightLit =
    cardHovered ||
    (hover.side === 'campaigns' && hover.id === suggestion.actionType)

  let boxShadow = 'var(--shadow)'
  let borderColor = 'var(--border)'
  if (cardHovered) {
    boxShadow = '0 0 0 1px var(--primary), 0 0 24px var(--ring)'
    borderColor = 'transparent'
  } else if (leftLit && rightLit) {
    boxShadow = '0 0 20px var(--ring)'
  } else if (leftLit) {
    boxShadow = '-2px 0 0 var(--primary), -10px 0 24px var(--ring)'
  } else if (rightLit) {
    boxShadow = '2px 0 0 var(--primary), 10px 0 24px var(--ring)'
  }

  const sectionLabel = {
    fontSize: 11,
    textTransform: 'uppercase',
    letterSpacing: '0.05em',
    color: 'var(--text-muted)',
    marginBottom: 12,
    fontWeight: 600,
  }

  const meta = metaFor(suggestion.rootCauseType)

  // Counters driven by real solution fields.
  const counters = [
    { icon: Bug,     label: 'Findings',       value: suggestion.findingCount, color: meta.color },
    { icon: FileText, label: 'CVEs',          value: suggestion.cveCount,     color: 'var(--critical)' },
    { icon: Server,  label: 'Assets affected', value: suggestion.assetCount,  color: 'var(--info)' },
  ].filter(c => c.value > 0)

  return (
    <div
      className="campV2-card-enter"
      onMouseEnter={() => onHover('card', suggestion.id, {
        rct: suggestion.rootCauseType,
        actionType: suggestion.actionType,
      })}
      onMouseLeave={() => onHover(null, null)}
      style={{
        display: 'grid',
        gridTemplateColumns: '1fr 1fr',
        background: 'var(--bg-card)',
        border: `2px solid ${borderColor}`,
        borderRadius: 10,
        boxShadow,
        transition: 'box-shadow 180ms ease, border-color 180ms ease',
        overflow: 'hidden',
        animationDelay: staggerDelay(index),
      }}
    >
      {/* LEFT: what it fixes */}
      <div
        style={{
          padding: 20,
          borderRight: '1px solid var(--border)',
          background: leftLit
            ? 'color-mix(in srgb, var(--primary) 7%, var(--bg-card))'
            : 'transparent',
          transition: 'background 180ms ease',
        }}
      >
        <div style={sectionLabel}>What it fixes</div>

        {/* root-cause label chip + severity */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
          <div
            style={{
              position: 'relative',
              width: 28, height: 28, borderRadius: 6,
              color: meta.color,
              display: 'grid', placeItems: 'center',
              flexShrink: 0,
            }}
          >
            <div style={{ position: 'absolute', inset: 0, background: meta.color, opacity: 0.12, borderRadius: 6 }} />
            <meta.icon size={15} style={{ position: 'relative' }} />
          </div>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)' }}>
            {meta.label}
          </div>
          {suggestion.severityMax != null && (
            <div style={{ marginLeft: 'auto' }}>
              <SeverityBadge severity={suggestion.severityMax} />
            </div>
          )}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          {counters.map(c => {
            const Icon = c.icon
            return (
              <div
                key={c.label}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                  padding: '6px 8px',
                  borderRadius: 6,
                  background: leftLit ? 'var(--bg-hover)' : 'transparent',
                  transition: 'background 160ms ease',
                }}
              >
                <div
                  style={{
                    position: 'relative',
                    width: 28, height: 28, borderRadius: 6,
                    color: c.color,
                    display: 'grid', placeItems: 'center',
                    flexShrink: 0,
                  }}
                >
                  <div style={{ position: 'absolute', inset: 0, background: c.color, opacity: 0.12, borderRadius: 6 }} />
                  <Icon size={15} style={{ position: 'relative' }} />
                </div>
                <div style={{ fontSize: 13, color: 'var(--text)' }}>{c.label}</div>
                <div
                  style={{
                    marginLeft: 'auto',
                    fontVariantNumeric: 'tabular-nums',
                    fontWeight: 700,
                    fontSize: 14,
                    color: 'var(--text)',
                  }}
                >
                  {c.value.toLocaleString()}
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* RIGHT: the campaign */}
      <div
        style={{
          padding: 20,
          display: 'flex',
          flexDirection: 'column',
          background: rightLit
            ? 'color-mix(in srgb, var(--primary) 7%, var(--bg-card))'
            : 'transparent',
          transition: 'background 180ms ease',
        }}
      >
        <div style={sectionLabel}>Campaign</div>
        <div
          title={suggestion.name}
          style={{ fontWeight: 600, fontSize: 15, color: 'var(--text)', marginBottom: 6 }}
        >
          {truncate(suggestion.name, 120)}
        </div>
        {suggestion.description && (
          <div
            title={suggestion.description}
            style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.5, flex: 1 }}
          >
            {truncate(suggestion.description, 150)}
          </div>
        )}
        {!suggestion.description && <div style={{ flex: 1 }} />}

        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 14, flexWrap: 'wrap' }}>
          {suggestion.postureImpact > 0 && (
            <div
              style={{
                display: 'inline-flex', alignItems: 'center', gap: 6,
                padding: '6px 10px',
                background: 'var(--success-subtle)',
                border: '1px solid var(--success)',
                borderRadius: 999,
              }}
            >
              <TrendingUp size={12} color="var(--success)" />
              <span style={{ fontSize: 12, color: 'var(--success)', fontWeight: 600 }}>
                +{suggestion.postureImpact.toFixed(1)}% posture
              </span>
            </div>
          )}
          {suggestion.effortLevel && (
            <Pill
              label={suggestion.effortLevel.replace('_', ' ')}
              color={
                suggestion.effortLevel === 'quick_win' ? 'var(--success)' :
                suggestion.effortLevel === 'complex'   ? 'var(--danger)'  :
                'var(--warning)'
              }
            />
          )}
        </div>

        <div style={{ display: 'flex', gap: 8, marginTop: 14 }}>
          <Button onClick={() => onLaunch(suggestion)}>
            <Play size={12} /> Launch campaign
          </Button>
        </div>
      </div>
    </div>
  )
}

// ─── Motion primitives ──────────────────────────────────────────────────────
// Inline keyframes (scoped by `campV2-` prefix to avoid clobbering globals).
// React stably dedupes this <style> tag across re-renders since its content
// is constant.
const MOTION_CSS = `
  @keyframes campV2-cardIn {
    from { opacity: 0; transform: translateY(6px) scale(0.985); }
    to   { opacity: 1; transform: translateY(0)  scale(1); }
  }
  @keyframes campV2-chipIn {
    from { opacity: 0; transform: translateX(-4px); }
    to   { opacity: 1; transform: translateX(0); }
  }
  @keyframes campV2-fadeIn {
    from { opacity: 0; }
    to   { opacity: 1; }
  }
  .campV2-card-enter {
    animation: campV2-cardIn 260ms cubic-bezier(0.2, 0.8, 0.2, 1) both;
  }
  .campV2-fade-enter {
    animation: campV2-fadeIn 280ms ease-out both;
  }
  .campV2-chip-enter {
    animation: campV2-chipIn 200ms cubic-bezier(0.2, 0.8, 0.2, 1) both;
  }
  @media (prefers-reduced-motion: reduce) {
    .campV2-card-enter, .campV2-fade-enter, .campV2-chip-enter { animation: none; }
  }
`

// Capped stagger so big lists don't cascade for seconds.
const staggerDelay = (i) => `${Math.min(i, 14) * 20}ms`

// ─── Compact card (grid mode) ───────────────────────────────────────────────
// Whole-card highlight only (no left/right split — halves would be unreadable
// at this size). Small `Launch` icon button in the top-right prevents
// accidental launches from body clicks.
function CompactCard({ suggestion, hover, onHover, onLaunch, index = 0 }) {
  const cardHovered = hover.side === 'card' && hover.id === suggestion.id
  const linked =
    (hover.side === 'issues' && hover.id === suggestion.rootCauseType) ||
    (hover.side === 'campaigns' && hover.id === suggestion.actionType)
  const lit = cardHovered || linked

  let boxShadow = 'var(--shadow)'
  let borderColor = 'var(--border)'
  if (cardHovered) {
    boxShadow = '0 0 0 1px var(--primary), 0 0 16px var(--ring)'
    borderColor = 'transparent'
  } else if (lit) {
    boxShadow = '0 0 12px var(--ring)'
  }

  const meta = metaFor(suggestion.rootCauseType)
  const actionMeta = actionMetaFor(suggestion.actionType)

  return (
    <div
      className="campV2-card-enter"
      onMouseEnter={() => onHover('card', suggestion.id, {
        rct: suggestion.rootCauseType,
        actionType: suggestion.actionType,
      })}
      onMouseLeave={() => onHover(null, null)}
      style={{
        background: lit
          ? 'color-mix(in srgb, var(--primary) 7%, var(--bg-card))'
          : 'var(--bg-card)',
        border: `2px solid ${borderColor}`,
        borderRadius: 10,
        boxShadow,
        padding: '12px 14px 12px 16px',
        display: 'flex',
        flexDirection: 'column',
        gap: 8,
        transition: 'box-shadow 180ms ease, border-color 180ms ease, background 180ms ease',
        minHeight: 108,
        position: 'relative',
        overflow: 'hidden',
        animationDelay: staggerDelay(index),
      }}
    >
      {/* Left accent stripe (root-cause color) */}
      <div style={{
        position: 'absolute', left: 0, top: 0, bottom: 0, width: 3,
        background: meta.color,
      }} />

      {/* Launch icon (top-right) */}
      <button
        onClick={(e) => { e.stopPropagation(); onLaunch(suggestion) }}
        title="Launch campaign"
        style={{
          position: 'absolute', top: 8, right: 8,
          width: 24, height: 24, borderRadius: 5,
          background: 'transparent', border: 'none', cursor: 'pointer',
          color: 'var(--text-muted)',
          display: 'grid', placeItems: 'center',
          transition: 'background 120ms, color 120ms',
        }}
        onMouseEnter={e => {
          e.currentTarget.style.background = 'var(--bg-hover)'
          e.currentTarget.style.color = 'var(--primary)'
        }}
        onMouseLeave={e => {
          e.currentTarget.style.background = 'transparent'
          e.currentTarget.style.color = 'var(--text-muted)'
        }}
      >
        <Play size={12} />
      </button>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8, paddingRight: 24 }}>
        <div style={{
          position: 'relative',
          width: 24, height: 24, borderRadius: 5,
          color: meta.color,
          display: 'grid', placeItems: 'center', flexShrink: 0, marginTop: 1,
        }}>
          <div style={{ position: 'absolute', inset: 0, background: meta.color, opacity: 0.14, borderRadius: 5 }} />
          <meta.icon size={13} style={{ position: 'relative' }} />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div
            title={suggestion.name}
            style={{
              fontSize: 13, fontWeight: 600, color: 'var(--text)',
              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
              lineHeight: 1.35,
            }}
          >
            {suggestion.name}
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
            {actionMeta.label}
          </div>
        </div>
      </div>

      {/* Metrics row */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 8,
        fontSize: 11,
        marginTop: 'auto',
        fontVariantNumeric: 'tabular-nums',
      }}>
        <span style={{ color: 'var(--text-secondary)' }}>
          <strong style={{ color: 'var(--text)' }}>
            {suggestion.findingCount.toLocaleString()}
          </strong> finding{suggestion.findingCount === 1 ? '' : 's'}
          {suggestion.assetCount > 0 && (
            <>  · <strong style={{ color: 'var(--text)' }}>{suggestion.assetCount}</strong> host{suggestion.assetCount === 1 ? '' : 's'}</>
          )}
        </span>
        {suggestion.postureImpact > 0 && (
          <span style={{
            marginLeft: 'auto',
            color: 'var(--success)', fontWeight: 700,
          }}>
            +{suggestion.postureImpact.toFixed(1)}%
          </span>
        )}
      </div>
    </div>
  )
}

// ─── View-mode toggle ───────────────────────────────────────────────────────
function ViewModeToggle({ mode, onChange }) {
  const opts = [
    { value: 'grid', icon: LayoutGrid, label: 'Grid' },
    { value: 'list', icon: List,       label: 'List' },
  ]
  return (
    <div style={{
      display: 'inline-flex',
      border: '1px solid var(--border)',
      borderRadius: 6,
      background: 'var(--bg-card)',
      padding: 2,
    }}>
      {opts.map(o => {
        const active = mode === o.value
        const Icon = o.icon
        return (
          <button
            key={o.value}
            onClick={() => onChange(o.value)}
            aria-pressed={active}
            style={{
              display: 'inline-flex', alignItems: 'center', gap: 6,
              padding: '5px 10px',
              background: active ? 'var(--secondary)' : 'transparent',
              color: active ? 'var(--text)' : 'var(--text-secondary)',
              border: 'none', borderRadius: 4,
              cursor: 'pointer',
              fontSize: 12, fontWeight: 600,
              transition: 'background 120ms, color 120ms',
            }}
          >
            <Icon size={13} /> {o.label}
          </button>
        )
      })}
    </div>
  )
}

// ─── Page ───────────────────────────────────────────────────────────────────
export default function CampaignsV2() {
  const navigate = useNavigate()
  const toast = useToast()
  const { activeScanId } = useScan()
  const [hover, setHover] = useState({ side: null, id: null, rct: null, actionType: null })
  const onHover = useCallback((side, id, extra = {}) => {
    setHover({ side, id, rct: extra.rct ?? null, actionType: extra.actionType ?? null })
  }, [])

  // Click-to-filter. Clicking the same node again clears the filter.
  const [filter, setFilter] = useState(null)
  const onSelectNode = useCallback((side, id) => {
    setFilter(prev => (prev && prev.side === side && prev.id === id ? null : { side, id }))
  }, [])
  const clearFilter = useCallback(() => setFilter(null), [])

  // View mode — grid (compact) or list (full-width 50/50). Persist across reloads.
  const [viewMode, setViewMode] = useState(
    () => localStorage.getItem('campaignsV2.viewMode') || 'grid'
  )
  useEffect(() => {
    localStorage.setItem('campaignsV2.viewMode', viewMode)
  }, [viewMode])

  const [solutions, setSolutions] = useState([])
  const [totalScanRisk, setTotalScanRisk] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    const params = {}
    if (activeScanId) params.scan_id = activeScanId
    getAggregatedSolutions(params)
      .then(data => {
        setSolutions(data.solutions || [])
        setTotalScanRisk(data.total_scan_risk || 0)
      })
      .catch(err => setError(err?.message || 'Failed to load campaign suggestions.'))
      .finally(() => setLoading(false))
  }, [activeScanId])

  useEffect(() => { load() }, [load])

  // Map backend solutions to the shape the UI consumes.
  const suggestions = useMemo(
    () => solutions.map(s => ({
      id: String(s.id),
      name: s.title || `Remediate ${s.affected_component || 'component'}`,
      description: s.description || null,
      rootCauseType: s.root_cause_type,
      actionType: s.action_type || 'upgrade_component',
      findingCount: Number(s.finding_count || 0),
      cveCount: Number(s.cve_count || 0),
      assetCount: Number(s.asset_count || 0),
      severityMax: s.severity_max,
      effortLevel: s.effort_level,
      postureImpact: postureImpact(s),
      raw: s,
    })),
    [solutions]
  )

  const sankey = useMemo(() => buildSankey(suggestions), [suggestions])

  // Sankey always renders the full flow; the filter only narrows the cards.
  const visibleSuggestions = useMemo(() => {
    if (!filter) return suggestions
    if (filter.side === 'issues')    return suggestions.filter(s => s.rootCauseType === filter.id)
    if (filter.side === 'campaigns') return suggestions.filter(s => s.actionType === filter.id)
    return suggestions
  }, [suggestions, filter])

  const filterLabel = filter
    ? (filter.side === 'issues' ? metaFor(filter.id).label : actionMetaFor(filter.id).label)
    : null

  const totalFindings = suggestions.reduce((sum, s) => sum + s.findingCount, 0)
  const totalPosture = suggestions.reduce((s, x) => s + x.postureImpact, 0)

  const handleLaunch = useCallback((suggestion) => {
    // Open the launch wizard scoped to this aggregated solution.
    // The wizard handles campaign creation + collaborator invites in a
    // multi-step flow with share-link + passcode generation for externals.
    navigate(`/campaigns-v2/launch/${encodeURIComponent(suggestion.id)}`)
  }, [navigate])

  // ─── Render branches ──────────────────────────────────────────────────────
  const Header = (
    <PageHeader
      title={
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 10 }}>
          Campaign Suggestions
          <Pill label="V2" color="var(--primary)" />
        </span>
      }
      subtitle={
        loading ? 'Loading recommended campaigns…' :
        suggestions.length === 0 ? 'No campaign suggestions available yet.' :
        <>
          {totalFindings.toLocaleString()} findings converge into {suggestions.length} recommended
          campaigns — executing all lifts posture by{' '}
          <strong style={{ color: 'var(--success)' }}>+{totalPosture.toFixed(1)}%</strong>.
        </>
      }
    />
  )

  if (loading) {
    return (
      <div>
        {Header}
        <Card style={{ padding: 64, display: 'grid', placeItems: 'center' }}>
          <Spinner />
        </Card>
      </div>
    )
  }

  if (error) {
    return (
      <div>
        {Header}
        <ErrorBanner error={error} onRetry={load} onDismiss={() => setError(null)} />
      </div>
    )
  }

  if (suggestions.length === 0) {
    return (
      <div>
        {Header}
        <Card>
          <EmptyState
            icon={Wrench}
            title="No campaign suggestions yet"
            sub="Run a scan — the platform will group findings by root cause and surface remediation campaigns here."
          >
            <Button onClick={() => navigate('/scans')} style={{ marginTop: 16 }}>
              Go to Scan Management
            </Button>
          </EmptyState>
        </Card>
      </div>
    )
  }

  return (
    <div style={{ padding: 24, maxWidth: 1400, margin: '0 auto' }}>
      <style>{MOTION_CSS}</style>
      {Header}

      {/* Sankey */}
      <Card style={{ padding: 16, marginBottom: 20 }}>
        <div style={{ width: '100%', height: CHART_HEIGHT }}>
          <ResponsiveContainer width="100%" height="100%">
            <Sankey
              data={sankey}
              node={
                <SankeyNodeRenderer
                  onHover={onHover}
                  onSelect={onSelectNode}
                  hover={hover}
                  filter={filter}
                />
              }
              link={<SankeyLinkRenderer hover={hover} filter={filter} />}
              nodePadding={10}
              nodeWidth={10}
              margin={MARGIN}
            />
          </ResponsiveContainer>
        </div>
      </Card>

      {/* Toolbar — filter chip (left) + view-mode toggle (right) */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        gap: 12, marginBottom: 14, minHeight: 32,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          {filter ? (
            <div
              key={`chip-${filter.side}-${filter.id}`}
              className="campV2-chip-enter"
              style={{ display: 'inline-flex', alignItems: 'center', gap: 10 }}
            >
              <span style={{ fontSize: 13, color: 'var(--text-secondary)' }}>Filtered by:</span>
              <button
                onClick={clearFilter}
                title="Clear filter"
                style={{
                  display: 'inline-flex', alignItems: 'center', gap: 6,
                  padding: '4px 8px 4px 10px',
                  background: 'color-mix(in srgb, var(--primary) 10%, transparent)',
                  border: '1px solid var(--primary)',
                  borderRadius: 999,
                  color: 'var(--primary)',
                  fontSize: 12,
                  fontWeight: 600,
                  cursor: 'pointer',
                  transition: 'background 160ms ease',
                }}
              >
                {filterLabel}
                <X size={12} />
              </button>
              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                {visibleSuggestions.length} of {suggestions.length} campaigns
              </span>
            </div>
          ) : (
            <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              {suggestions.length} campaign{suggestions.length === 1 ? '' : 's'}
            </span>
          )}
        </div>
        <ViewModeToggle mode={viewMode} onChange={setViewMode} />
      </div>

      {/* Cards — grid (compact) or list (full-width 50/50). The keyed wrapper
          causes a full remount when view mode OR the filter changes, which
          triggers the staggered card entrance animation — acts as a cross-
          fade between layouts. */}
      <div
        key={`cards-${viewMode}-${filter ? filter.side + ':' + filter.id : 'all'}`}
        className="campV2-fade-enter"
        style={{
          display: 'grid',
          gridTemplateColumns: viewMode === 'grid'
            ? 'repeat(auto-fill, minmax(240px, 1fr))'
            : '1fr',
          gap: viewMode === 'grid' ? 12 : 16,
        }}
      >
        {visibleSuggestions.map((s, i) =>
          viewMode === 'grid' ? (
            <CompactCard
              key={s.id}
              index={i}
              suggestion={s}
              hover={hover}
              onHover={onHover}
              onLaunch={handleLaunch}
            />
          ) : (
            <SuggestionCard
              key={s.id}
              index={i}
              suggestion={s}
              hover={hover}
              onHover={onHover}
              onLaunch={handleLaunch}
            />
          )
        )}
      </div>
    </div>
  )
}
