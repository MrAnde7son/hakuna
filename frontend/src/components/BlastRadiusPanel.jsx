/**
 * BlastRadiusPanel — embeddable attack path visualization
 *
 * Props:
 *   scanId   {number}   scan to query
 *   assetId  {number}   focal asset
 *   compact  {boolean}  if true, show score badge only (no graph)
 */

import React, { useState, useEffect, useCallback, useMemo } from 'react'
import {
  ReactFlow,
  ReactFlowProvider,
  Background,
  Controls,
  useNodesState,
  useEdgesState,
  Handle,
  Position,
  MarkerType,
  Panel,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import dagre from '@dagrejs/dagre'
import { Server, Users, AlertTriangle, Network, Shield, ChevronDown, ChevronRight, Crosshair, Maximize2, Minimize2 } from 'lucide-react'
import { getBlastRadius } from '../api.js'

// ── Colours ─────────────────────────────────────────────────────────────
const EDGE_CFG = {
  local_admin:         { color: '#f59e0b', label: 'Local Admin' },
  domain_admin:        { color: '#ef4444', label: 'Domain Admin' },
  network_connection:  { color: '#3b82f6', label: 'Network' },
  credential_exposure: { color: '#a855f7', label: 'Cred Exposure' },
}

const SEV_COLOR = { critical: '#ef4444', high: '#f59e0b', medium: '#3b82f6', low: '#64748b' }

function scoreColor(s) {
  if (s >= 8) return '#ef4444'
  if (s >= 6) return '#f59e0b'
  if (s >= 4) return '#eab308'
  return '#22c55e'
}

function scoreLabel(s) {
  if (s >= 8) return 'Critical'
  if (s >= 6) return 'High'
  if (s >= 4) return 'Medium'
  return 'Low'
}

// ── Dagre layout ─────────────────────────────────────────────────────────
function layoutNodes(rawNodes, rawEdges) {
  const g = new dagre.graphlib.Graph()
  g.setDefaultEdgeLabel(() => ({}))
  g.setGraph({ rankdir: 'LR', ranksep: 180, nodesep: 50, marginx: 16, marginy: 16 })
  rawNodes.forEach(n => g.setNode(n.id, { width: 180, height: 72 }))
  rawEdges.forEach(e => { try { g.setEdge(e.source, e.target) } catch (_) {} })
  dagre.layout(g)
  return rawNodes.map(n => {
    const pos = g.node(n.id)
    return { ...n, position: { x: (pos?.x ?? 0) - 90, y: (pos?.y ?? 0) - 36 } }
  })
}

// ── Custom Nodes ──────────────────────────────────────────────────────────
function AssetNode({ data }) {
  const isStart = data._start
  const riskPct = Math.min((data.risk_score || 0) * 10, 100)
  const riskColor = riskPct > 70 ? '#ef4444' : riskPct > 50 ? '#f59e0b' : '#22c55e'

  const bg = isStart ? '#f0fdf4' : data.is_dc ? '#fff7ed' : '#ffffff'
  const borderColor = isStart ? '#16a34a' : data.is_dc ? '#ea580c' : '#cbd5e1'
  const shadow = isStart ? '0 0 0 3px #16a34a22, 0 2px 8px rgba(0,0,0,0.08)'
    : '0 1px 4px rgba(0,0,0,0.08), 0 0 0 1px rgba(0,0,0,0.04)'

  return (
    <div style={{
      background: bg, border: `2px solid ${borderColor}`,
      borderRadius: 8, padding: '6px 10px', minWidth: 160, maxWidth: 180,
      boxShadow: shadow,
    }}>
      <Handle type="target" position={Position.Left} style={{ background: '#94a3b8', width: 7, height: 7, border: '1.5px solid #fff' }} />
      <Handle type="source" position={Position.Right} style={{ background: '#94a3b8', width: 7, height: 7, border: '1.5px solid #fff' }} />
      <div style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 2 }}>
        <Server size={10} color={isStart ? '#16a34a' : data.is_dc ? '#ea580c' : '#64748b'} />
        {isStart && <NBadge bg="#dcfce7" fg="#15803d" border="#86efac">START</NBadge>}
        {data.is_dc && <NBadge bg="#ffedd5" fg="#c2410c" border="#fed7aa">DC</NBadge>}
        <span style={{ fontSize: 11, fontWeight: 700, color: '#0f172a', flex: 1,
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {data.label}
        </span>
      </div>
      <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap', marginBottom: 4 }}>
        {data.critical_count > 0 && <NBadge bg="#fee2e2" fg="#b91c1c" border="#fca5a5">{data.critical_count}C</NBadge>}
        {data.high_count > 0 && <NBadge bg="#fef3c7" fg="#b45309" border="#fde68a">{data.high_count}H</NBadge>}
        {!data.has_av && <NBadge bg="#fee2e2" fg="#dc2626" border="#fca5a5">NoAV</NBadge>}
        {data.has_writeable_share && <NBadge bg="#dbeafe" fg="#1d4ed8" border="#bfdbfe">Share</NBadge>}
      </div>
      <div style={{ height: 3, background: '#e2e8f0', borderRadius: 99 }}>
        <div style={{ width: `${riskPct}%`, height: '100%', background: riskColor, borderRadius: 99 }} />
      </div>
    </div>
  )
}

function UserNode({ data }) {
  const bc = data.is_domain_admin ? '#ef4444'
    : data.kerberoastable ? '#a855f7'
    : data.is_local_admin ? '#f59e0b'
    : '#3b82f6'
  const bg = data.is_domain_admin ? '#fef2f2'
    : data.kerberoastable ? '#faf5ff'
    : data.is_local_admin ? '#fffbeb'
    : '#eff6ff'
  return (
    <div style={{
      background: bg, border: `2px solid ${bc}`,
      borderRadius: 8, padding: '6px 10px', minWidth: 140, maxWidth: 170,
      boxShadow: '0 1px 4px rgba(0,0,0,0.08), 0 0 0 1px rgba(0,0,0,0.04)',
    }}>
      <Handle type="target" position={Position.Left} style={{ background: '#94a3b8', width: 7, height: 7, border: '1.5px solid #fff' }} />
      <Handle type="source" position={Position.Right} style={{ background: '#94a3b8', width: 7, height: 7, border: '1.5px solid #fff' }} />
      <div style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 3 }}>
        <Users size={10} color={bc} />
        <span style={{ fontSize: 11, fontWeight: 700, color: '#0f172a', flex: 1,
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {data.label}
        </span>
      </div>
      <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
        {data.is_domain_admin && <NBadge bg="#fee2e2" fg="#b91c1c" border="#fca5a5">DA</NBadge>}
        {data.is_local_admin && !data.is_domain_admin && <NBadge bg="#fef3c7" fg="#92400e" border="#fde68a">LA</NBadge>}
        {data.kerberoastable && <NBadge bg="#f3e8ff" fg="#6d28d9" border="#ddd6fe">Kerb</NBadge>}
        {data.password_never_expires && <NBadge bg="#f1f5f9" fg="#475569" border="#cbd5e1">PNE</NBadge>}
        {data.user_type === 'service_account' && <NBadge bg="#dbeafe" fg="#1d4ed8" border="#bfdbfe">SVC</NBadge>}
      </div>
    </div>
  )
}

function NBadge({ bg, fg, border, children }) {
  return (
    <span style={{ fontSize: 9, background: bg, color: fg,
      border: `1px solid ${border || 'transparent'}`,
      padding: '1px 4px', borderRadius: 3, fontWeight: 700, whiteSpace: 'nowrap' }}>
      {children}
    </span>
  )
}

const nodeTypes = { asset: AssetNode, user: UserNode }

// ── Mini ReactFlow graph ──────────────────────────────────────────────────
function BlastRadiusFlow({ data }) {
  const [nodes, setNodes, onNodesChange] = useNodesState([])
  const [edges, setEdges, onEdgesChange] = useEdgesState([])
  const [blastNode, setBlastNode] = useState(null)

  const styledEdges = useMemo(() =>
    data.edges.map(e => ({
      ...e,
      animated: e.type === 'credential_exposure',
      style: { stroke: EDGE_CFG[e.type]?.color || '#475569', strokeWidth: 1.5 },
      markerEnd: { type: MarkerType.ArrowClosed, color: EDGE_CFG[e.type]?.color || '#475569', width: 12, height: 12 },
      label: e.data?.label,
      labelStyle: { fontSize: 9, fill: '#64748b' },
      labelBgStyle: { fill: '#f9fafb', fillOpacity: 0.95 },
      labelBgPadding: [2, 4],
      labelBgBorderRadius: 3,
    })),
  [data.edges])

  useEffect(() => {
    if (!data.nodes.length) return

    // Compute blast radius from selected node (or start)
    const focusId = blastNode || `asset-${data.asset_id}`
    const reachable = new Set([focusId])
    const q = [focusId]
    while (q.length) {
      const cur = q.shift()
      data.edges.forEach(e => {
        if (e.source === cur && !reachable.has(e.target)) {
          reachable.add(e.target); q.push(e.target)
        }
      })
    }
    const hasBlast = blastNode !== null

    const positioned = layoutNodes(data.nodes, data.edges)
    setNodes(positioned.map(n => ({
      ...n,
      data: {
        ...n.data,
        _dimmed: hasBlast && !reachable.has(n.id),
      },
      style: { opacity: hasBlast && !reachable.has(n.id) ? 0.2 : 1 },
    })))
    setEdges(styledEdges.map(e => ({
      ...e,
      style: {
        ...e.style,
        opacity: hasBlast && !(reachable.has(e.source) && reachable.has(e.target)) ? 0.08 : 1,
      },
    })))
  }, [data, blastNode, styledEdges])

  const onNodeClick = useCallback((_, node) => {
    setBlastNode(prev => prev === node.id ? null : node.id)
  }, [])

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      onNodeClick={onNodeClick}
      nodeTypes={nodeTypes}
      fitView
      fitViewOptions={{ padding: 0.15 }}
      colorMode="light"
      proOptions={{ hideAttribution: true }}
      nodesDraggable={false}
      nodesConnectable={false}
      elementsSelectable={true}
    >
      <Background color="#e5e7eb" gap={20} size={1} />
      <Controls showInteractive={false} style={{
        background: 'rgba(255,255,255,0.9)', border: '1px solid var(--border)', borderRadius: 6, padding: 2,
      }} />
      <Panel position="bottom-right">
        <div style={{ fontSize: 10, color: 'var(--text-muted)', background: 'rgba(255,255,255,0.9)',
          border: '1px solid var(--border)', borderRadius: 5, padding: '4px 8px' }}>
          {blastNode ? (
            <span style={{ color: '#f59e0b' }}>
              <Crosshair size={9} style={{ display: 'inline', marginRight: 4 }} />
              Click same node to clear
            </span>
          ) : 'Click node for blast radius'}
        </div>
      </Panel>
    </ReactFlow>
  )
}

// ── Score badge (compact mode) ────────────────────────────────────────────
export function BlastRadiusScore({ score, reachable, daExposed, dcReachable, onClick }) {
  if (score === null || score === undefined) {
    return (
      <span style={{ fontSize: 11, color: '#475569' }}>—</span>
    )
  }
  const c = scoreColor(score)
  return (
    <button
      onClick={e => { e.stopPropagation(); onClick && onClick() }}
      title="View blast radius"
      style={{
        display: 'inline-flex', alignItems: 'center', gap: 5,
        background: `${c}15`, border: `1px solid ${c}55`,
        borderRadius: 6, padding: '3px 8px', cursor: onClick ? 'pointer' : 'default',
        fontWeight: 700, fontSize: 12, color: c,
      }}
    >
      <Crosshair size={11} />
      {score.toFixed(1)}
      {reachable > 0 && (
        <span style={{ fontSize: 10, color: '#94a3b8', fontWeight: 400 }}>
          · {reachable} hosts
        </span>
      )}
      {daExposed && <span style={{ fontSize: 9, background: '#dc2626', color: '#fff', padding: '1px 4px', borderRadius: 3 }}>DA</span>}
      {dcReachable && <span style={{ fontSize: 9, background: '#ea580c', color: '#fff', padding: '1px 4px', borderRadius: 3 }}>DC</span>}
    </button>
  )
}

// ── Full panel ────────────────────────────────────────────────────────────
export default function BlastRadiusPanel({ scanId, assetId, defaultExpanded = false }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [expanded, setExpanded] = useState(defaultExpanded)
  const [fullscreen, setFullscreen] = useState(false)

  useEffect(() => {
    if (!scanId || !assetId) return
    setLoading(true)
    getBlastRadius(scanId, assetId)
      .then(setData)
      .catch(() => setData(null))
      .finally(() => setLoading(false))
  }, [scanId, assetId])

  const hasData = data && (data.nodes?.length > 1 || data.vectors?.length > 0)
  const sc = scoreColor(data?.score ?? 0)

  return (
    <div style={{
      border: `1px solid ${data ? sc + '44' : 'var(--border)'}`,
      borderRadius: 10,
      background: 'var(--bg-card)',
      overflow: 'hidden',
    }}>
      {/* Header row */}
      <button
        onClick={() => setExpanded(p => !p)}
        style={{
          width: '100%', display: 'flex', alignItems: 'center', gap: 10,
          padding: '12px 16px', background: 'none', border: 'none',
          cursor: 'pointer', textAlign: 'left',
        }}
      >
        <Crosshair size={15} color={data ? sc : '#64748b'} />
        <span style={{ flex: 1, fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
          Blast Radius
        </span>

        {loading && <span style={{ fontSize: 11, color: '#64748b' }}>Loading…</span>}

        {data && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            {/* Score pill */}
            <span style={{
              fontSize: 16, fontWeight: 800, color: sc,
              background: sc + '18', border: `1px solid ${sc}44`,
              borderRadius: 6, padding: '2px 10px',
            }}>
              {data.score.toFixed(1)}
            </span>
            <span style={{ fontSize: 11, color: sc, fontWeight: 600 }}>{scoreLabel(data.score)}</span>

            {/* Quick-fire indicators */}
            {data.dc_reachable && (
              <span style={{ fontSize: 10, background: '#fff7ed', color: '#ea580c',
                border: '1px solid #fed7aa', borderRadius: 4, padding: '2px 6px', fontWeight: 700 }}>
                DC
              </span>
            )}
            {data.da_exposed && (
              <span style={{ fontSize: 10, background: '#fef2f2', color: '#ef4444',
                border: '1px solid #fecaca', borderRadius: 4, padding: '2px 6px', fontWeight: 700 }}>
                DA
              </span>
            )}
            {data.kerberoastable_exposed && (
              <span style={{ fontSize: 10, background: '#faf5ff', color: '#a855f7',
                border: '1px solid #ddd6fe', borderRadius: 4, padding: '2px 6px', fontWeight: 700 }}>
                Kerb
              </span>
            )}
          </div>
        )}

        {!loading && !data && (
          <span style={{ fontSize: 11, color: '#64748b' }}>No inventory data</span>
        )}

        {expanded ? <ChevronDown size={14} color="#64748b" /> : <ChevronRight size={14} color="#64748b" />}
      </button>

      {/* Expanded content */}
      {expanded && data && (
        <div style={{ borderTop: '1px solid var(--border)' }}>

          {/* Stat strip */}
          <div style={{
            display: 'flex', gap: 0, borderBottom: '1px solid var(--border)',
          }}>
            {[
              { label: 'Reachable', value: data.reachable_assets, color: '#3b82f6' },
              { label: 'Priv Users', value: data.privileged_users, color: '#a855f7' },
              { label: 'Attack Vectors', value: data.vectors?.length || 0, color: '#f59e0b' },
            ].map(({ label, value, color }, i) => (
              <div key={i} style={{
                flex: 1, padding: '10px 14px', textAlign: 'center',
                borderRight: i < 2 ? '1px solid var(--border)' : 'none',
              }}>
                <div style={{ fontSize: 20, fontWeight: 800, color }}>{value}</div>
                <div style={{ fontSize: 10, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{label}</div>
              </div>
            ))}
          </div>

          {/* Attack vectors */}
          {data.vectors?.length > 0 && (
            <div style={{ padding: '12px 16px', borderBottom: hasData ? '1px solid var(--border)' : 'none' }}>
              <div style={{ fontSize: 11, color: '#64748b', marginBottom: 8,
                textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>
                Attack Vectors
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                {data.vectors.map((v, i) => (
                  <div key={i} style={{
                    display: 'flex', alignItems: 'center', gap: 8,
                    padding: '5px 8px', background: 'var(--bg-secondary)',
                    borderRadius: 6, fontSize: 12,
                  }}>
                    <div style={{
                      width: 7, height: 7, borderRadius: 99, flexShrink: 0,
                      background: SEV_COLOR[v.severity] || '#64748b',
                    }} />
                    <span style={{ color: 'var(--text-secondary)', flex: 1 }}>{v.label}</span>
                    <span style={{
                      fontSize: 10, color: SEV_COLOR[v.severity] || '#64748b',
                      textTransform: 'capitalize',
                    }}>{v.severity}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Graph */}
          {data.nodes?.length > 0 && (
            <>
              {fullscreen && (
                <div style={{
                  position: 'fixed', inset: 0, zIndex: 9999,
                  background: 'var(--bg-card)', display: 'flex', flexDirection: 'column',
                }}>
                  <div style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                    padding: '12px 20px', borderBottom: '1px solid var(--border)',
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <Crosshair size={15} color={sc} />
                      <span style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>Blast Radius</span>
                      <span style={{ fontSize: 16, fontWeight: 800, color: sc,
                        background: sc + '18', border: `1px solid ${sc}44`,
                        borderRadius: 6, padding: '2px 10px' }}>
                        {data.score.toFixed(1)}
                      </span>
                    </div>
                    <button onClick={() => setFullscreen(false)} style={{
                      background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                      borderRadius: 6, padding: '6px 12px', cursor: 'pointer',
                      display: 'flex', alignItems: 'center', gap: 6,
                      fontSize: 12, color: 'var(--text-secondary)',
                    }}>
                      <Minimize2 size={14} /> Exit Fullscreen
                    </button>
                  </div>
                  <div style={{ flex: 1 }}>
                    <ReactFlowProvider>
                      <BlastRadiusFlow data={data} />
                    </ReactFlowProvider>
                  </div>
                </div>
              )}
              <div style={{ height: 320, background: 'var(--bg-muted)', position: 'relative' }}>
                <ReactFlowProvider>
                  <BlastRadiusFlow data={data} />
                </ReactFlowProvider>
                <button
                  onClick={() => setFullscreen(true)}
                  title="Fullscreen"
                  style={{
                    position: 'absolute', top: 8, right: 8, zIndex: 10,
                    background: 'rgba(255,255,255,0.9)', border: '1px solid var(--border)',
                    borderRadius: 6, padding: '5px 8px', cursor: 'pointer',
                    display: 'flex', alignItems: 'center', gap: 5,
                    fontSize: 11, color: 'var(--text-secondary)',
                  }}
                >
                  <Maximize2 size={13} /> Fullscreen
                </button>
              </div>
            </>
          )}

          {!hasData && (
            <div style={{ padding: '20px 16px', textAlign: 'center', color: '#475569', fontSize: 13 }}>
              No lateral movement paths detected for this asset.
            </div>
          )}
        </div>
      )}
    </div>
  )
}
