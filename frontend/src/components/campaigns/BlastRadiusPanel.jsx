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
import {
  Server, User, Users, Monitor, Database,
  UserCheck, UserCog,
  ChevronDown, ChevronRight, Crosshair, Maximize2, Minimize2,
} from 'lucide-react'
import { getBlastRadius } from '../../api.js'

// ── Colours ─────────────────────────────────────────────────────────────
const EDGE_CFG = {
  local_admin:         { color: '#f59e0b', label: 'Local Admin' },
  domain_admin:        { color: '#ef4444', label: 'Domain Admin' },
  network_connection:  { color: '#3b82f6', label: 'Network' },
  credential_exposure: { color: '#a855f7', label: 'Cred Exposure' },
  rdp_access:          { color: '#0ea5e9', label: 'RDP Access' },
  dcom_access:         { color: '#06b6d4', label: 'DCOM Access' },
  power_user:          { color: '#d97706', label: 'Power User' },
  winrm_access:        { color: '#7c3aed', label: 'WinRM' },
  ssh_access:          { color: '#10b981', label: 'SSH Access' },
  sudo_access:         { color: '#dc2626', label: 'Sudo Access' },
  docker_access:       { color: '#1d4ed8', label: 'Docker' },
  admin_read:          { color: 'var(--text-secondary)', label: 'Admin Read' },
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
  const riskColor = riskPct > 70 ? 'var(--critical)' : riskPct > 50 ? 'var(--warning)' : 'var(--success)'

  const bg = isStart ? 'var(--success-subtle)' : data.is_dc ? 'var(--warning-subtle)' : 'var(--card)'
  const borderColor = isStart ? 'var(--success)' : data.is_dc ? 'var(--high)' : 'var(--border)'
  const iconColor = isStart ? 'var(--success)' : data.is_dc ? 'var(--high)' : 'var(--text-secondary)'
  const shadow = isStart ? '0 0 0 3px rgba(34,197,94,0.15), 0 2px 8px rgba(0,0,0,0.08)'
    : '0 1px 4px rgba(0,0,0,0.08), 0 0 0 1px rgba(0,0,0,0.04)'
  const AssetIcon = data.is_dc ? Database : Server

  return (
    <div style={{
      background: bg, border: `2px solid ${borderColor}`,
      borderRadius: 8, padding: '6px 10px', minWidth: 160, maxWidth: 180,
      boxShadow: shadow,
    }}>
      <Handle type="target" position={Position.Left} style={{ background: '#94a3b8', width: 7, height: 7, border: '1.5px solid #fff' }} />
      <Handle type="source" position={Position.Right} style={{ background: '#94a3b8', width: 7, height: 7, border: '1.5px solid #fff' }} />
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2 }}>
        <div style={{
          width: 22, height: 22, borderRadius: 5, background: iconColor + '18',
          display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
        }}>
          <AssetIcon size={13} color={iconColor} />
        </div>
        {isStart && <NBadge bg="var(--success-subtle)" fg="var(--success)" border="var(--success)">START</NBadge>}
        {data.is_dc && <NBadge bg="var(--warning-subtle)" fg="var(--high)" border="var(--high)">DC</NBadge>}
        <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-primary)', flex: 1,
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {data.label}
        </span>
      </div>
      <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap', marginBottom: 4 }}>
        {data.critical_count > 0 && <NBadge bg="var(--danger-subtle)" fg="var(--danger)" border="var(--danger)">{data.critical_count}C</NBadge>}
        {data.high_count > 0 && <NBadge bg="var(--warning-subtle)" fg="var(--warning)" border="var(--warning)">{data.high_count}H</NBadge>}
        {!data.has_av && <NBadge bg="var(--danger-subtle)" fg="var(--danger)" border="var(--danger)">NoAV</NBadge>}
        {data.has_writeable_share && <NBadge bg="rgba(37,99,235,0.1)" fg="var(--primary)" border="var(--primary)">Share</NBadge>}
      </div>
      <div style={{ height: 3, background: 'var(--border)', borderRadius: 99 }}>
        <div style={{ width: `${riskPct}%`, height: '100%', background: riskColor, borderRadius: 99 }} />
      </div>
    </div>
  )
}

// Map user_type → { icon, label, iconColor, iconBg }
const USER_TYPE_CFG = {
  domain_user:      { Icon: User,     label: 'Domain User',    iconColor: '#3b82f6', iconBg: '#eff6ff' },
  local_user:       { Icon: UserCheck,label: 'Local User',     iconColor: '#64748b', iconBg: '#f8fafc' },
  service_account:  { Icon: UserCog,  label: 'Service Acct',   iconColor: '#8b5cf6', iconBg: '#f5f3ff' },
  computer_account: { Icon: Monitor,  label: 'Computer',       iconColor: '#0ea5e9', iconBg: '#f0f9ff' },
  group:            { Icon: Users,    label: 'Group',          iconColor: '#10b981', iconBg: '#ecfdf5' },
}

function UserNode({ data }) {
  const bc = data.is_domain_admin ? 'var(--danger)'
    : data.kerberoastable ? '#a855f7'
    : data.is_local_admin ? 'var(--warning)'
    : 'var(--primary)'
  const bg = data.is_domain_admin ? 'var(--danger-subtle)'
    : data.kerberoastable ? 'rgba(168,85,247,0.08)'
    : data.is_local_admin ? 'var(--warning-subtle)'
    : 'var(--card)'

  const typeCfg = USER_TYPE_CFG[data.user_type] || USER_TYPE_CFG.domain_user
  const { Icon, iconColor, iconBg } = typeCfg

  return (
    <div style={{
      background: bg, border: `2px solid ${bc}`,
      borderRadius: 8, padding: '6px 10px', minWidth: 140, maxWidth: 170,
      boxShadow: '0 1px 4px rgba(0,0,0,0.08), 0 0 0 1px rgba(0,0,0,0.04)',
    }}>
      <Handle type="target" position={Position.Left} style={{ background: '#94a3b8', width: 7, height: 7, border: '1.5px solid #fff' }} />
      <Handle type="source" position={Position.Right} style={{ background: '#94a3b8', width: 7, height: 7, border: '1.5px solid #fff' }} />
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
        <div style={{
          width: 22, height: 22, borderRadius: 5, background: iconBg,
          border: `1px solid ${iconColor}33`,
          display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
        }}>
          <Icon size={13} color={iconColor} />
        </div>
        <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-primary)', flex: 1,
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {data.label}
        </span>
      </div>
      <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
        {data.is_domain_admin && <NBadge bg="var(--danger-subtle)" fg="var(--danger)" border="var(--danger)">DA</NBadge>}
        {data.is_local_admin && !data.is_domain_admin && <NBadge bg="var(--warning-subtle)" fg="var(--warning)" border="var(--warning)">LA</NBadge>}
        {data.kerberoastable && <NBadge bg="rgba(168,85,247,0.1)" fg="#a855f7" border="#a855f7">Kerb</NBadge>}
        {data.password_never_expires && <NBadge bg="var(--secondary)" fg="var(--text-secondary)" border="var(--border)">PNE</NBadge>}
        {data.user_type === 'service_account' && <NBadge bg="rgba(37,99,235,0.1)" fg="var(--primary)" border="var(--primary)">SVC</NBadge>}
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

// Maps legend node entries to a predicate over node data
const NODE_LEGEND = [
  { Icon: Server,    color: 'var(--text-secondary)', bg: '#f8fafc', label: 'Server',            match: n => n.type === 'asset' && !n.data.is_dc },
  { Icon: Database,  color: '#ea580c', bg: '#fff7ed', label: 'Domain Controller', match: n => n.type === 'asset' && n.data.is_dc },
  { Icon: User,      color: '#3b82f6', bg: '#eff6ff', label: 'Domain User',       match: n => n.type === 'user' && n.data.user_type === 'domain_user' },
  { Icon: UserCheck, color: 'var(--text-secondary)', bg: '#f8fafc', label: 'Local User',        match: n => n.type === 'user' && n.data.user_type === 'local_user' },
  { Icon: UserCog,   color: '#8b5cf6', bg: '#f5f3ff', label: 'Service Account',   match: n => n.type === 'user' && n.data.user_type === 'service_account' },
  { Icon: Monitor,   color: '#0ea5e9', bg: '#f0f9ff', label: 'Computer Account',  match: n => n.type === 'user' && n.data.user_type === 'computer_account' },
]

const EDGE_LEGEND = [
  { key: 'domain_admin',        color: '#ef4444', label: 'Domain Admin' },
  { key: 'local_admin',         color: '#f59e0b', label: 'Local Admin' },
  { key: 'rdp_access',          color: '#0ea5e9', label: 'RDP Access' },
  { key: 'dcom_access',         color: '#06b6d4', label: 'DCOM Access' },
  { key: 'winrm_access',        color: '#7c3aed', label: 'WinRM' },
  { key: 'ssh_access',          color: '#10b981', label: 'SSH Access' },
  { key: 'sudo_access',         color: '#dc2626', label: 'Sudo Access' },
  { key: 'docker_access',       color: '#1d4ed8', label: 'Docker' },
  { key: 'network_connection',  color: '#3b82f6', label: 'Network' },
  { key: 'credential_exposure', color: '#a855f7', label: 'Cred Exposure' },
]

// ── Mini ReactFlow graph ──────────────────────────────────────────────────
function BlastRadiusFlow({ data }) {
  const [nodes, setNodes, onNodesChange] = useNodesState([])
  const [edges, setEdges, onEdgesChange] = useEdgesState([])
  // blastNode: node-click mode; legendFilter: { kind: 'edge'|'node', value }
  const [blastNode, setBlastNode] = useState(null)
  const [legendFilter, setLegendFilter] = useState(null)

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

  const positioned = useMemo(() => layoutNodes(data.nodes, data.edges), [data.nodes, data.edges])

  useEffect(() => {
    if (!data.nodes.length) return

    // ── legend filter mode ───────────────────────────────────────────────
    if (legendFilter) {
      let litNodeIds = new Set()

      if (legendFilter.kind === 'edge') {
        // Highlight edges of this type + their connected nodes
        data.edges.forEach(e => {
          if (e.type === legendFilter.value) {
            litNodeIds.add(e.source)
            litNodeIds.add(e.target)
          }
        })
        setNodes(positioned.map(n => ({
          ...n,
          style: { opacity: litNodeIds.has(n.id) ? 1 : 0.12 },
        })))
        setEdges(styledEdges.map(e => ({
          ...e,
          style: {
            ...e.style,
            opacity: e.type === legendFilter.value ? 1 : 0.06,
            strokeWidth: e.type === legendFilter.value ? 2.5 : 1.5,
          },
        })))
      } else {
        // node-type filter: find matching nodes via predicate
        const entry = NODE_LEGEND.find(l => l.label === legendFilter.value)
        if (entry) {
          data.nodes.forEach(n => { if (entry.match(n)) litNodeIds.add(n.id) })
          // Also include edges that touch at least one lit node
          const litEdgeIds = new Set(
            data.edges.filter(e => litNodeIds.has(e.source) || litNodeIds.has(e.target)).map(e => e.id)
          )
          // Expand lit nodes to include the other end of those edges
          data.edges.forEach(e => {
            if (litNodeIds.has(e.source)) litNodeIds.add(e.target)
            if (litNodeIds.has(e.target)) litNodeIds.add(e.source)
          })
          setNodes(positioned.map(n => ({
            ...n,
            style: { opacity: litNodeIds.has(n.id) ? 1 : 0.12 },
          })))
          setEdges(styledEdges.map(e => ({
            ...e,
            style: {
              ...e.style,
              opacity: litEdgeIds.has(e.id) ? 1 : 0.06,
            },
          })))
        }
      }
      return
    }

    // ── node-click blast radius mode ────────────────────────────────────
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

    setNodes(positioned.map(n => ({
      ...n,
      style: { opacity: hasBlast && !reachable.has(n.id) ? 0.12 : 1 },
    })))
    setEdges(styledEdges.map(e => ({
      ...e,
      style: {
        ...e.style,
        opacity: hasBlast && !(reachable.has(e.source) && reachable.has(e.target)) ? 0.06 : 1,
      },
    })))
  }, [data, blastNode, legendFilter, styledEdges, positioned])

  const onNodeClick = useCallback((_, node) => {
    setLegendFilter(null)
    setBlastNode(prev => prev === node.id ? null : node.id)
  }, [])

  const onLegendEdgeClick = useCallback((key) => {
    setBlastNode(null)
    setLegendFilter(prev => prev?.kind === 'edge' && prev.value === key ? null : { kind: 'edge', value: key })
  }, [])

  const onLegendNodeClick = useCallback((label) => {
    setBlastNode(null)
    setLegendFilter(prev => prev?.kind === 'node' && prev.value === label ? null : { kind: 'node', value: label })
  }, [])

  const hint = legendFilter
    ? `Filtering: ${legendFilter.value.replace(/_/g, ' ')} — click again to clear`
    : blastNode
      ? 'Click same node to clear'
      : 'Click node or legend to highlight'

  const hintColor = legendFilter ? '#0ea5e9' : blastNode ? '#f59e0b' : undefined

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
        background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 6, padding: 2,
      }} />
      <Panel position="bottom-right">
        <div style={{ fontSize: 10, color: hintColor || 'var(--text-muted)',
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: 5, padding: '4px 8px' }}>
          {(legendFilter || blastNode) && <Crosshair size={9} style={{ display: 'inline', marginRight: 4 }} />}
          {hint}
        </div>
      </Panel>
      <Panel position="top-left">
        <div style={{
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: 6, padding: '6px 10px', fontSize: 10,
          display: 'flex', flexDirection: 'column', gap: 3,
          maxHeight: 'calc(100vh - 120px)', overflowY: 'auto',
        }}>
          {/* Node types */}
          {NODE_LEGEND.map(({ Icon, color, bg, label }) => {
            const active = legendFilter?.kind === 'node' && legendFilter.value === label
            return (
              <button key={label} onClick={() => onLegendNodeClick(label)} style={{
                display: 'flex', alignItems: 'center', gap: 6,
                background: active ? color + '18' : 'transparent',
                border: active ? `1px solid ${color}55` : '1px solid transparent',
                borderRadius: 4, padding: '2px 4px', cursor: 'pointer', textAlign: 'left',
              }}>
                <div style={{
                  width: 18, height: 18, borderRadius: 4,
                  background: active ? bg : bg,
                  border: `1px solid ${color}33`,
                  display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                }}>
                  <Icon size={11} color={color} />
                </div>
                <span style={{ color: active ? color : '#475569', fontWeight: active ? 700 : 400 }}>{label}</span>
              </button>
            )
          })}

          {/* Edge types */}
          <div style={{ borderTop: '1px solid var(--border)', marginTop: 2, paddingTop: 4, display: 'flex', flexDirection: 'column', gap: 2 }}>
            {EDGE_LEGEND.map(({ key, color, label }) => {
              // Only show edge types that actually appear in the data
              const exists = data.edges.some(e => e.type === key)
              if (!exists) return null
              const active = legendFilter?.kind === 'edge' && legendFilter.value === key
              return (
                <button key={key} onClick={() => onLegendEdgeClick(key)} style={{
                  display: 'flex', alignItems: 'center', gap: 6,
                  background: active ? color + '18' : 'transparent',
                  border: active ? `1px solid ${color}55` : '1px solid transparent',
                  borderRadius: 4, padding: '2px 4px', cursor: 'pointer', textAlign: 'left',
                }}>
                  <div style={{ width: 18, height: 2, background: color, borderRadius: 1, flexShrink: 0,
                    boxShadow: active ? `0 0 4px ${color}` : 'none' }} />
                  <span style={{ color: active ? color : '#475569', fontWeight: active ? 700 : 400 }}>{label}</span>
                </button>
              )
            })}
          </div>
        </div>
      </Panel>
    </ReactFlow>
  )
}

// ── Score badge (compact mode) ────────────────────────────────────────────
export function BlastRadiusScore({ score, reachable, daExposed, dcReachable, onClick }) {
  if (score === null || score === undefined) {
    return (
      <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>—</span>
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
        <span style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 400 }}>
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
        <Crosshair size={15} color={data ? sc : 'var(--text-secondary)'} />
        <span style={{ flex: 1, fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
          Blast Radius
        </span>

        {loading && <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Loading…</span>}

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
              <span style={{ fontSize: 10, background: 'var(--warning-subtle)', color: 'var(--high)',
                border: '1px solid var(--high)', borderRadius: 4, padding: '2px 6px', fontWeight: 700 }}>
                DC
              </span>
            )}
            {data.da_exposed && (
              <span style={{ fontSize: 10, background: 'var(--danger-subtle)', color: 'var(--danger)',
                border: '1px solid var(--danger)', borderRadius: 4, padding: '2px 6px', fontWeight: 700 }}>
                DA
              </span>
            )}
            {data.kerberoastable_exposed && (
              <span style={{ fontSize: 10, background: 'rgba(168,85,247,0.1)', color: '#a855f7',
                border: '1px solid #a855f7', borderRadius: 4, padding: '2px 6px', fontWeight: 700 }}>
                Kerb
              </span>
            )}
            {data.group_access_exposed && (
              <span style={{ fontSize: 10, background: 'rgba(14,165,233,0.1)', color: 'var(--info)',
                border: '1px solid var(--info)', borderRadius: 4, padding: '2px 6px', fontWeight: 700 }}>
                RDP/DCOM
              </span>
            )}
          </div>
        )}

        {!loading && !data && (
          <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>No inventory data</span>
        )}

        {expanded ? <ChevronDown size={14} color="var(--text-secondary)" /> : <ChevronRight size={14} color="var(--text-secondary)" />}
      </button>

      {/* Expanded content */}
      {expanded && data && (
        <div style={{ borderTop: '1px solid var(--border)' }}>

          {/* Stat strip */}
          <div style={{
            display: 'flex', gap: 0, borderBottom: '1px solid var(--border)',
          }}>
            {[
              { label: 'Reachable', value: data.reachable_assets, color: 'var(--primary)' },
              { label: 'Priv Users', value: data.privileged_users, color: '#a855f7' },
              { label: 'Attack Vectors', value: data.vectors?.length || 0, color: 'var(--warning)' },
            ].map(({ label, value, color }, i) => (
              <div key={i} style={{
                flex: 1, padding: '10px 14px', textAlign: 'center',
                borderRight: i < 2 ? '1px solid var(--border)' : 'none',
              }}>
                <div style={{ fontSize: 20, fontWeight: 800, color }}>{value}</div>
                <div style={{ fontSize: 10, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{label}</div>
              </div>
            ))}
          </div>

          {/* Attack vectors */}
          {data.vectors?.length > 0 && (
            <div style={{ padding: '12px 16px', borderBottom: hasData ? '1px solid var(--border)' : 'none' }}>
              <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 8,
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
                    background: 'var(--bg-card)', border: '1px solid var(--border)',
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
            <div style={{ padding: '20px 16px', textAlign: 'center', color: 'var(--text-secondary)', fontSize: 13 }}>
              No lateral movement paths detected for this asset.
            </div>
          )}
        </div>
      )}
    </div>
  )
}
