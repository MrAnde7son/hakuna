/**
 * AttackPathGraph — graph visualization of a single attack path.
 *
 * Renders `steps[]` (as emitted by finding_correlator) as a left-to-right
 * ReactFlow graph. Visual DNA matches BlastRadiusPanel: circular icon
 * nodes with severity-ringed borders, colored edges labelled by the
 * relationship type, badges for START / TARGET / DC / CRIT, and a
 * fullscreen toggle.
 *
 * Deliberately narrower in scope than BlastRadiusPanel: an attack path is
 * a linear chain (one hop per step), so no branching, legend filters, or
 * collapse logic — just the chain itself, clearly drawn.
 *
 * Props:
 *   steps         {Array}   path.steps from the attack-paths API
 *   entryReason   {string}  path.entry_reason (codes joined with '+')
 *   targetReason  {string}  path.target_reason
 */
import React, { useMemo, useState } from 'react'
import {
  ReactFlow,
  ReactFlowProvider,
  Background,
  Controls,
  Handle,
  Position,
  MarkerType,
  Panel,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import dagre from '@dagrejs/dagre'
import {
  Server, Database, Globe, ShieldAlert, LogIn, Target as TargetIcon,
  Maximize2, Minimize2,
} from 'lucide-react'

// ── Colour palette — mirrors the pivot_quality badges + step severity ─────
const PIVOT_STYLE = {
  exploit_path_verified: { color: '#15803d', label: 'exploit path verified' },
  service_exposed:       { color: '#16a34a', label: 'service exposed' },
  port_mismatch:         { color: '#ea580c', label: 'port mismatch', dash: '4 2' },
  reachability:          { color: '#f59e0b', label: 'reachability', dash: '6 3' },
  identity:              { color: '#2563eb', label: 'identity' },
  inference:             { color: '#94a3b8', label: 'inference', dash: '4 2' },
  entry:                 { color: '#7c3aed', label: 'entry' },
}

const SEV_RING = {
  4: '#ef4444',  // Critical
  3: '#f59e0b',  // High
  2: '#3b82f6',  // Medium
  1: '#64748b',  // Low
}

const CIRCLE_SIZE = 48
const handleStyle = { background: 'transparent', border: 'none', width: 1, height: 1 }

// ── Custom node ───────────────────────────────────────────────────────────
function StepNode({ data }) {
  const isEntry = data.isEntry
  const isTarget = data.isTarget
  const isDC = data.targetReason === 'domain_controller'

  // Primary fill: green for entry, DC orange / red for target, slate for middle.
  const fillColor = isEntry
    ? '#22c55e'
    : isTarget
      ? (isDC ? '#ea580c' : '#dc2626')
      : '#64748b'

  // Ring: highlight severity of the finding attached to this step.
  const ringColor = SEV_RING[data.severity] || '#cbd5e1'

  const Icon = isTarget
    ? (isDC ? Database : TargetIcon)
    : isEntry
      ? LogIn
      : Server

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4, minWidth: 120, maxWidth: 180 }}>
      <Handle type="target" position={Position.Left} style={{ ...handleStyle, top: CIRCLE_SIZE / 2 }} />
      <Handle type="source" position={Position.Right} style={{ ...handleStyle, top: CIRCLE_SIZE / 2 }} />

      {/* Icon circle with severity ring */}
      <div style={{
        width: CIRCLE_SIZE, height: CIRCLE_SIZE, borderRadius: '50%',
        background: fillColor,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        boxShadow: `0 0 0 4px ${ringColor}30, 0 2px 8px rgba(0,0,0,0.15)`,
        border: `2px solid ${ringColor}`,
      }}
        title={data.why_reachable || data.hostname}
      >
        <Icon size={20} color="#fff" strokeWidth={2} />
      </div>

      {/* Step number pill that doubles as a visual anchor */}
      <div style={{
        marginTop: -6, padding: '1px 6px', fontSize: 10, fontWeight: 700,
        color: 'white', background: fillColor, borderRadius: 99,
      }}>
        {data.stepNumber}
      </div>

      {/* Hostname */}
      <div style={{
        fontSize: 12, fontWeight: 700, color: 'var(--text-primary)',
        textAlign: 'center', maxWidth: 160, overflow: 'hidden',
        textOverflow: 'ellipsis', whiteSpace: 'nowrap',
      }} title={data.hostname}>
        {data.hostname}
      </div>

      {/* Finding name */}
      {data.finding_name && (
        <div style={{
          fontSize: 10, color: 'var(--text-muted)', textAlign: 'center',
          maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis',
          whiteSpace: 'nowrap', lineHeight: 1.3,
        }} title={data.finding_name}>
          {data.finding_name}
        </div>
      )}

      {/* Badges */}
      <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap', justifyContent: 'center' }}>
        {isEntry && <MiniBadge bg="#22c55e18" fg="#22c55e" border="#22c55e">START</MiniBadge>}
        {isTarget && !isDC && <MiniBadge bg="#dc262618" fg="#dc2626" border="#dc2626">TARGET</MiniBadge>}
        {isTarget && isDC && <MiniBadge bg="#ea580c18" fg="#ea580c" border="#ea580c">DC</MiniBadge>}
        {data.severity === 4 && <MiniBadge bg="#ef444418" fg="#ef4444" border="#ef4444">CRIT</MiniBadge>}
        {data.severity === 3 && <MiniBadge bg="#f59e0b18" fg="#f59e0b" border="#f59e0b">HIGH</MiniBadge>}
      </div>
    </div>
  )
}

function MiniBadge({ bg, fg, border, children }) {
  return (
    <span style={{
      fontSize: 9, fontWeight: 700,
      background: bg, color: fg, border: `1px solid ${border}`,
      padding: '1px 4px', borderRadius: 3, whiteSpace: 'nowrap',
    }}>
      {children}
    </span>
  )
}

const nodeTypes = { attackStep: StepNode }

// ── Dagre layout (linear LR) ──────────────────────────────────────────────
function layoutChain(rawNodes, rawEdges) {
  const g = new dagre.graphlib.Graph()
  g.setDefaultEdgeLabel(() => ({}))

  // Linear chain → LR with generous horizontal spacing so edge labels fit.
  g.setGraph({
    rankdir: 'LR', ranksep: 110, nodesep: 40,
    marginx: 24, marginy: 24, ranker: 'network-simplex',
  })

  rawNodes.forEach(n => g.setNode(n.id, { width: 180, height: 140 }))
  rawEdges.forEach(e => g.setEdge(e.source, e.target))
  dagre.layout(g)

  return rawNodes.map(n => {
    const pos = g.node(n.id)
    return { ...n, position: { x: (pos?.x ?? 0) - 90, y: (pos?.y ?? 0) - 70 } }
  })
}

// ── Inner ReactFlow graph (expects provider from caller) ──────────────────
function ChainFlow({ steps, targetReason }) {
  const { nodes, edges } = useMemo(() => {
    const n = steps.map((s, idx) => ({
      id: `step-${idx}`,
      type: 'attackStep',
      data: {
        stepNumber: idx + 1,
        hostname: s.hostname,
        finding_name: s.finding_name,
        finding_id: s.finding_id,
        severity: s.severity,
        why_reachable: s.why_reachable,
        isEntry: idx === 0,
        isTarget: idx === steps.length - 1,
        targetReason,
      },
      position: { x: 0, y: 0 },
    }))

    const e = steps.slice(1).map((s, idx) => {
      const pq = PIVOT_STYLE[s.pivot_quality] || PIVOT_STYLE.reachability
      const edgeLabel = [s.edge_type, s.edge_confidence]
        .filter(Boolean).join(' · ')
      return {
        id: `edge-${idx}`,
        source: `step-${idx}`,
        target: `step-${idx + 1}`,
        label: edgeLabel || s.edge_type || 'reachable',
        labelStyle: { fontSize: 10, fill: pq.color, fontWeight: 600 },
        labelBgStyle: { fill: 'var(--bg-card)', fillOpacity: 0.95 },
        labelBgPadding: [3, 5],
        labelBgBorderRadius: 4,
        style: {
          stroke: pq.color, strokeWidth: 2,
          ...(pq.dash ? { strokeDasharray: pq.dash } : {}),
        },
        markerEnd: { type: MarkerType.ArrowClosed, color: pq.color, width: 14, height: 14 },
      }
    })
    return { nodes: n, edges: e }
  }, [steps, targetReason])

  const positioned = useMemo(() => layoutChain(nodes, edges), [nodes, edges])

  // Inline legend restricted to pivot qualities actually present in this path.
  const presentQualities = useMemo(() => {
    const set = new Set()
    steps.slice(1).forEach(s => { if (s.pivot_quality) set.add(s.pivot_quality) })
    return Array.from(set)
  }, [steps])

  return (
    <ReactFlow
      nodes={positioned}
      edges={edges}
      nodeTypes={nodeTypes}
      fitView
      fitViewOptions={{ padding: 0.15 }}
      colorMode="light"
      proOptions={{ hideAttribution: true }}
      nodesDraggable={true}
      nodesConnectable={false}
      elementsSelectable={true}
    >
      <Background color="#e5e7eb" gap={20} size={1} />
      <Controls
        showInteractive={false}
        style={{
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: 6, padding: 2,
        }}
      />
      {presentQualities.length > 0 && (
        <Panel position="top-left">
          <div style={{
            background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: 6, padding: '6px 10px', fontSize: 10,
            display: 'flex', flexDirection: 'column', gap: 3,
          }}>
            <div style={{ fontWeight: 700, color: 'var(--text-secondary)', marginBottom: 2 }}>
              Edge types
            </div>
            {presentQualities.map(q => {
              const s = PIVOT_STYLE[q] || PIVOT_STYLE.reachability
              return (
                <div key={q} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <div style={{
                    width: 16, height: 2, background: s.color, borderRadius: 1,
                    ...(s.dash ? { background: `repeating-linear-gradient(90deg, ${s.color} 0 4px, transparent 4px 7px)` } : {}),
                  }} />
                  <span style={{ color: '#475569' }}>{s.label}</span>
                </div>
              )
            })}
          </div>
        </Panel>
      )}
    </ReactFlow>
  )
}

// ── Public component ──────────────────────────────────────────────────────
export default function AttackPathGraph({ steps, targetReason, height = 280 }) {
  const [fullscreen, setFullscreen] = useState(false)

  // Guard: need at least an entry + one hop for a meaningful graph.
  if (!Array.isArray(steps) || steps.length < 2) return null

  const Inner = (
    <ReactFlowProvider>
      <ChainFlow steps={steps} targetReason={targetReason} />
    </ReactFlowProvider>
  )

  return (
    <>
      <div style={{
        position: 'relative', height, background: 'var(--bg-muted)',
        border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden',
      }}>
        {Inner}
        <button
          onClick={() => setFullscreen(true)}
          title="Fullscreen"
          style={{
            position: 'absolute', top: 8, right: 8, zIndex: 10,
            background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: 6, padding: '5px 8px', cursor: 'pointer',
            display: 'flex', alignItems: 'center', gap: 5,
            fontSize: 11, color: 'var(--text-secondary)',
          }}
        >
          <Maximize2 size={13} /> Fullscreen
        </button>
      </div>

      {fullscreen && (
        <div style={{
          position: 'fixed', inset: 0, zIndex: 9999,
          background: 'var(--bg-card)', display: 'flex', flexDirection: 'column',
        }}>
          <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            padding: '12px 20px', borderBottom: '1px solid var(--border)',
          }}>
            <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>
              Attack Path Graph
            </div>
            <button
              onClick={() => setFullscreen(false)}
              style={{
                background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                borderRadius: 6, padding: '6px 12px', cursor: 'pointer',
                display: 'flex', alignItems: 'center', gap: 6,
                fontSize: 12, color: 'var(--text-secondary)',
              }}
            >
              <Minimize2 size={14} /> Exit Fullscreen
            </button>
          </div>
          <div style={{ flex: 1 }}>{Inner}</div>
        </div>
      )}
    </>
  )
}
