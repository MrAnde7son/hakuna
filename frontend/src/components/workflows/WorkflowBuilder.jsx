import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  Play, Save, ArrowLeft, Plus, Trash2, X,
  GitBranch, Zap, Target, Clock, Upload, Server,
  UserPlus, Tag, CheckCircle, AlertTriangle, Globe, Bell,
  BarChart2, ChevronRight, Filter, Mail, MessageSquare,
  Terminal, Ticket, History, Shield, Monitor, AlertCircle, Plug,
} from 'lucide-react'
import {
  getWorkflow, updateWorkflow, executeWorkflow, getWorkflowExecutions,
  getWorkflowExecution, getNodeCatalog, getIntegration,
} from '../../api.js'
import { Button, Spinner, EmptyState, Pill } from '../shared/ui.jsx'

// ─── Icon map ─────────────────────────────
const ICON_MAP = {
  Play, Target, Clock, Upload, GitBranch, BarChart2, Tag, Zap, Server,
  UserPlus, CheckCircle, AlertTriangle, Globe, Bell, Filter, Mail,
  MessageSquare, Terminal, Ticket, Shield, Monitor, AlertCircle, Plug,
}

const TYPE_COLORS = {
  trigger: { bg: '#312e81', border: '#6366f1', text: '#c7d2fe', accent: '#818cf8', headerBg: '#3730a3' },
  filter:  { bg: '#1a2e05', border: '#65a30d', text: '#d9f99d', accent: '#84cc16', headerBg: '#365314' },
  action:  { bg: '#450a0a', border: '#dc2626', text: '#fecaca', accent: '#f87171', headerBg: '#7f1d1d' },
}

const NODE_WIDTH = 240
const NODE_HEADER = 40
const NODE_HEIGHT = 86
const HANDLE_SIZE = 12

export default function WorkflowBuilder() {
  const { id } = useParams()
  const navigate = useNavigate()
  const canvasRef = useRef(null)

  const [workflow, setWorkflow] = useState(null)
  const [nodes, setNodes] = useState([])
  const [edges, setEdges] = useState([])
  const [catalog, setCatalog] = useState(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [executing, setExecuting] = useState(false)
  const [selectedNode, setSelectedNode] = useState(null)
  const [dragging, setDragging] = useState(null)
  const [connecting, setConnecting] = useState(null)
  const [pan, setPan] = useState({ x: 0, y: 0 })
  const [isPanning, setIsPanning] = useState(false)
  const [panStart, setPanStart] = useState(null)
  const [showNodePalette, setShowNodePalette] = useState(false)
  const [showExecutions, setShowExecutions] = useState(false)
  const [executions, setExecutions] = useState([])
  const [executionDetail, setExecutionDetail] = useState(null)
  const [dirty, setDirty] = useState(false)
  const [lastExecResult, setLastExecResult] = useState(null)
  const [showExecPanel, setShowExecPanel] = useState(false)
  const [execDetail, setExecDetail] = useState(null)
  const [smtpConfigured, setSmtpConfigured] = useState(null)
  const [nodeOutputOpen, setNodeOutputOpen] = useState(false)

  useEffect(() => {
    Promise.all([getWorkflow(id), getNodeCatalog()])
      .then(([wf, cat]) => {
        setWorkflow(wf)
        setNodes(wf.nodes || [])
        setEdges(wf.edges || [])
        setCatalog(cat)
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }, [id])

  const allNodeDefs = useMemo(() => {
    if (!catalog) return {}
    const map = {}
    for (const [type, defs] of Object.entries(catalog)) {
      for (const d of defs) {
        map[d.subtype] = { ...d, type: type.replace(/s$/, '') }
      }
    }
    return map
  }, [catalog])

  // Reset output panel when switching nodes
  useEffect(() => { setNodeOutputOpen(false) }, [selectedNode])

  // Fetch SMTP status when a send_email node is selected
  useEffect(() => {
    const node = nodes.find(n => n.node_id === selectedNode)
    if (node?.node_subtype === 'send_email') {
      setSmtpConfigured(null) // reset while loading
      getIntegration('email')
        .then(cfg => setSmtpConfigured(!!(cfg?.is_enabled)))
        .catch(() => setSmtpConfigured(false))
    }
  }, [selectedNode])

  // ─── Save ────────────────────────────────
  const handleSave = useCallback(async () => {
    setSaving(true)
    try {
      const data = {
        nodes: nodes.map(n => ({
          node_id: n.node_id, node_type: n.node_type, node_subtype: n.node_subtype,
          label: n.label, config: n.config || {},
          position_x: n.position_x, position_y: n.position_y,
        })),
        edges: edges.map(e => ({
          edge_id: e.edge_id, source_node_id: e.source_node_id, target_node_id: e.target_node_id,
          source_handle: e.source_handle || 'output', target_handle: e.target_handle || 'input',
          label: e.label,
        })),
      }
      const updated = await updateWorkflow(id, data)
      setWorkflow(updated)
      setDirty(false)
    } catch (e) { console.error(e) }
    setSaving(false)
  }, [id, nodes, edges])

  // ─── Validation ─────────────────────────
  const getValidationWarnings = useCallback(() => {
    const warnings = []
    if (nodes.length === 0) {
      warnings.push({ level: 'error', message: 'Workflow has no nodes' })
      return warnings
    }
    const triggers = nodes.filter(n => n.node_type === 'trigger')
    if (triggers.length === 0) warnings.push({ level: 'error', message: 'No trigger node — workflow cannot start' })

    // Check for disconnected nodes (no incoming edge and not a trigger)
    const nodesWithIncoming = new Set(edges.map(e => e.target_node_id))
    nodes.forEach(n => {
      if (n.node_type !== 'trigger' && !nodesWithIncoming.has(n.node_id))
        warnings.push({ level: 'warn', message: `"${n.label || n.node_subtype}" is disconnected — it won't receive any data` })
    })

    // Check for missing required config
    nodes.forEach(n => {
      const def = allNodeDefs[n.node_subtype]
      if (!def?.config_schema) return
      const config = n.config || {}
      if (n.node_subtype === 'send_webhook' && !config.url)
        warnings.push({ level: 'error', message: `"${n.label || 'Send Webhook'}" is missing a Webhook URL` })
      if (n.node_subtype === 'send_email' && !config.to)
        warnings.push({ level: 'warn', message: `"${n.label || 'Send Email'}" has no recipient email` })
      if (n.node_subtype === 'slack_notify' && !config.webhook_url)
        warnings.push({ level: 'warn', message: `"${n.label || 'Slack'}" has no webhook URL` })
      if (n.node_subtype === 'teams_notify' && !config.webhook_url)
        warnings.push({ level: 'warn', message: `"${n.label || 'Teams'}" has no webhook URL` })
      if (n.node_subtype === 'create_ticket' && !config.integration)
        warnings.push({ level: 'warn', message: `"${n.label || 'Create Ticket'}" has no integration selected` })
    })

    // Check if workflow has data source
    if (triggers.length > 0 && !workflow?.campaign_id) {
      const triggerSubtypes = triggers.map(t => t.node_subtype)
      const dataDrivenTriggers = ['on_upload', 'on_new_finding', 'on_new_asset', 'on_new_threat_intel', 'on_integration_execution']
      const hasDataTrigger = triggerSubtypes.some(s => dataDrivenTriggers.includes(s))
      if (!hasDataTrigger && (triggerSubtypes.includes('manual') || triggerSubtypes.includes('on_campaign_run')))
        warnings.push({ level: 'info', message: 'Workflow is not linked to a campaign — it will run with 0 findings unless triggered with data' })
    }
    return warnings
  }, [nodes, edges, allNodeDefs, workflow])

  // ─── Execute ─────────────────────────────
  const handleExecute = useCallback(async () => {
    if (dirty) await handleSave()
    setExecuting(true)
    setExecDetail(null)
    try {
      const result = await executeWorkflow(id)
      setLastExecResult(result)
      // Auto-fetch detailed execution logs
      if (result.execution_id) {
        try {
          const detail = await getWorkflowExecution(result.execution_id)
          setExecDetail(detail)
        } catch (_) { /* detail fetch optional */ }
      }
      setShowExecPanel(true)
      const wf = await getWorkflow(id)
      setWorkflow(wf)
    } catch (e) {
      setLastExecResult({ status: 'failed', error: e.message })
      setShowExecPanel(true)
    }
    setExecuting(false)
  }, [id, dirty, handleSave])

  // ─── Add node ────────────────────────────
  const addNode = useCallback((type, def_) => {
    const nodeId = `node-${Date.now()}`

    // Find the best source node to auto-connect from:
    // 1. Currently selected node, or 2. Rightmost node with a free output handle
    const nodesWithFreeOutput = nodes.filter(n => {
      if (n.node_type === 'trigger' && type === 'trigger') return false
      return !edges.some(e => e.source_node_id === n.node_id && e.source_handle === 'output')
    })
    let sourceNode = null
    if (selectedNode && type !== 'trigger') {
      sourceNode = nodesWithFreeOutput.find(n => n.node_id === selectedNode)
    }
    if (!sourceNode && type !== 'trigger') {
      sourceNode = nodesWithFreeOutput.sort((a, b) => b.position_x - a.position_x)[0] || null
    }

    const x = sourceNode ? sourceNode.position_x + 300 : (nodes.length ? Math.max(...nodes.map(n => n.position_x)) + 300 : 100)
    const y = sourceNode ? sourceNode.position_y : 200
    setNodes(prev => [...prev, {
      node_id: nodeId, node_type: type, node_subtype: def_.subtype,
      label: def_.label, config: {}, position_x: x - pan.x, position_y: y - pan.y,
    }])
    if (sourceNode) {
      setEdges(prev => [...prev, {
        edge_id: `edge-${Date.now()}`,
        source_node_id: sourceNode.node_id,
        target_node_id: nodeId,
        source_handle: 'output',
        target_handle: 'input',
      }])
    }
    setShowNodePalette(false)
    setSelectedNode(nodeId)
    setDirty(true)
  }, [nodes, edges, pan, selectedNode])

  const deleteNode = useCallback((nodeId) => {
    setNodes(prev => prev.filter(n => n.node_id !== nodeId))
    setEdges(prev => prev.filter(e => e.source_node_id !== nodeId && e.target_node_id !== nodeId))
    if (selectedNode === nodeId) setSelectedNode(null)
    setDirty(true)
  }, [selectedNode])

  // ─── Dragging ────────────────────────────
  const handleMouseDown = useCallback((e, nodeId) => {
    if (e.button !== 0) return
    e.stopPropagation()
    const node = nodes.find(n => n.node_id === nodeId)
    if (!node) return
    setDragging({ nodeId, startX: e.clientX, startY: e.clientY, origX: node.position_x, origY: node.position_y })
    setSelectedNode(nodeId)
  }, [nodes])

  const handleMouseMove = useCallback((e) => {
    if (dragging) {
      const dx = e.clientX - dragging.startX
      const dy = e.clientY - dragging.startY
      setNodes(prev => prev.map(n =>
        n.node_id === dragging.nodeId
          ? { ...n, position_x: dragging.origX + dx, position_y: dragging.origY + dy }
          : n
      ))
    } else if (connecting) {
      setConnecting(prev => prev ? { ...prev, mouseX: e.clientX, mouseY: e.clientY } : null)
    } else if (isPanning && panStart) {
      const dx = e.clientX - panStart.x
      const dy = e.clientY - panStart.y
      setPan(prev => ({ x: prev.x + dx, y: prev.y + dy }))
      setPanStart({ x: e.clientX, y: e.clientY })
    }
  }, [dragging, connecting, isPanning, panStart])

  const handleMouseUp = useCallback(() => {
    if (dragging) setDirty(true)
    setDragging(null)
    setIsPanning(false)
    setPanStart(null)
    if (connecting) setConnecting(null)
  }, [dragging, connecting])

  const handleCanvasMouseDown = useCallback((e) => {
    if (e.button === 0 && e.target === canvasRef.current) {
      setSelectedNode(null)
      setIsPanning(true)
      setPanStart({ x: e.clientX, y: e.clientY })
    }
  }, [])

  // ─── Connections ─────────────────────────
  const handleHandleMouseDown = useCallback((e, nodeId, handleType) => {
    e.stopPropagation()
    setConnecting({ sourceNodeId: nodeId, sourceHandle: handleType, mouseX: e.clientX, mouseY: e.clientY })
  }, [])

  const handleNodeDrop = useCallback((targetNodeId) => {
    if (!connecting || connecting.sourceNodeId === targetNodeId) {
      setConnecting(null)
      return
    }
    const exists = edges.some(
      e => e.source_node_id === connecting.sourceNodeId && e.target_node_id === targetNodeId
        && e.source_handle === connecting.sourceHandle
    )
    if (!exists) {
      const label = connecting.sourceHandle === 'remainder' ? 'No match' : undefined
      setEdges(prev => [...prev, {
        edge_id: `edge-${Date.now()}`,
        source_node_id: connecting.sourceNodeId,
        target_node_id: targetNodeId,
        source_handle: connecting.sourceHandle || 'output',
        target_handle: 'input',
        label,
      }])
      setDirty(true)
    }
    setConnecting(null)
  }, [connecting, edges])

  const deleteEdge = useCallback((edgeId) => {
    setEdges(prev => prev.filter(e => e.edge_id !== edgeId))
    setDirty(true)
  }, [])

  // ─── Handle positions ───────────────────
  const getHandlePos = useCallback((nodeId, handle) => {
    const node = nodes.find(n => n.node_id === nodeId)
    if (!node) return { x: 0, y: 0 }
    const x = node.position_x + pan.x
    const y = node.position_y + pan.y
    if (handle === 'input') return { x, y: y + NODE_HEADER }
    if (handle === 'remainder') return { x: x + NODE_WIDTH, y: y + NODE_HEIGHT * 0.78 }
    return { x: x + NODE_WIDTH, y: y + NODE_HEIGHT * 0.4 }
  }, [nodes, pan])

  const updateNodeConfig = useCallback((nodeId, key, value) => {
    setNodes(prev => prev.map(n =>
      n.node_id === nodeId ? { ...n, config: { ...n.config, [key]: value } } : n
    ))
    setDirty(true)
  }, [])

  const updateNodeLabel = useCallback((nodeId, label) => {
    setNodes(prev => prev.map(n => n.node_id === nodeId ? { ...n, label } : n))
    setDirty(true)
  }, [])

  const loadExecutions = useCallback(async () => {
    try {
      const execs = await getWorkflowExecutions(id)
      setExecutions(execs)
      setShowExecutions(true)
    } catch (e) { console.error(e) }
  }, [id])

  const validationWarnings = useMemo(() => getValidationWarnings(), [getValidationWarnings])
  const hasErrors = validationWarnings.some(w => w.level === 'error')

  // Map node_id → full log entry from last execution
  const nodeResults = useMemo(() => {
    const map = {}
    if (execDetail?.logs) {
      for (const log of execDetail.logs) map[log.node_id] = log
    }
    return map
  }, [execDetail])

  // Keep backward-compat alias used for canvas border/shadow styling
  const nodeErrors = useMemo(() => {
    const map = {}
    for (const [nid, log] of Object.entries(nodeResults)) {
      if (log.status === 'failed') map[nid] = log.output_data?.error || log.error || 'Failed'
      else if (log.status === 'success' && log.items_in === 0) map[nid] = 'empty'
    }
    return map
  }, [nodeResults])

  if (loading) return <div style={{ padding: 40, textAlign: 'center' }}><Spinner /> Loading workflow...</div>
  if (!workflow) return <EmptyState icon={AlertTriangle} title="Workflow not found" />

  const selectedNodeData = nodes.find(n => n.node_id === selectedNode)
  const selectedDef = selectedNodeData ? allNodeDefs[selectedNodeData.node_subtype] : null

  return (
    <div style={{ height: 'calc(100vh - 36px)', display: 'flex', flexDirection: 'column' }}>
      {/* Toolbar */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 10, padding: '10px 16px',
        background: 'var(--card)', borderBottom: '1px solid var(--border)', flexShrink: 0,
      }}>
        <button onClick={() => navigate('/campaigns')}
          style={{ display: 'flex', alignItems: 'center', gap: 4, background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', fontSize: 13 }}>
          <ArrowLeft size={16} /> Back
        </button>
        <div style={{ width: 1, height: 24, background: 'var(--border)' }} />
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 700, fontSize: 15 }}>{workflow.name}</div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            {workflow.description || 'Custom workflow'}
            {workflow.campaign_id && <span> · Linked to campaign #{workflow.campaign_id}</span>}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          {dirty && <span style={{ fontSize: 11, color: 'var(--warning)', fontWeight: 600 }}>Unsaved</span>}
          {lastExecResult && (
            <button onClick={() => setShowExecPanel(p => !p)}
              style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>
              <Pill color={lastExecResult.status === 'completed' ? 'var(--success)' : 'var(--danger)'}>
                {lastExecResult.status === 'completed'
                  ? `Done — ${lastExecResult.items_processed} items`
                  : 'Failed'}{' '}
                <span style={{ fontSize: 9, opacity: 0.8 }}>▾ details</span>
              </Pill>
            </button>
          )}
          <Button size="sm" variant="ghost" onClick={() => setShowNodePalette(true)}>
            <Plus size={14} /> Add Node
          </Button>
          <Button size="sm" variant="ghost" onClick={loadExecutions}>
            <History size={14} /> History
          </Button>
          <Button size="sm" onClick={handleSave} disabled={saving || !dirty}>
            <Save size={14} /> {saving ? 'Saving...' : 'Save'}
          </Button>
          <Button size="sm" variant="primary" onClick={handleExecute} disabled={executing || hasErrors}
            title={hasErrors ? validationWarnings.filter(w => w.level === 'error').map(w => w.message).join('; ') : ''}>
            <Play size={14} /> {executing ? 'Running...' : 'Run'}
          </Button>
        </div>
      </div>

      {/* Validation warnings */}
      {validationWarnings.length > 0 && (
        <div style={{
          display: 'flex', flexWrap: 'wrap', gap: 6, padding: '6px 16px',
          background: hasErrors ? 'var(--danger-subtle)' : 'var(--warning-subtle)', borderBottom: '1px solid var(--border)', flexShrink: 0,
        }}>
          {validationWarnings.map((w, i) => (
            <span key={i} style={{
              display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 11, fontWeight: 500,
              color: w.level === 'error' ? 'var(--danger)' : w.level === 'warn' ? 'var(--warning)' : 'var(--muted)',
              padding: '2px 8px', borderRadius: 6,
              background: w.level === 'error' ? 'var(--danger-subtle)' : w.level === 'warn' ? 'var(--warning-subtle)' : 'var(--secondary)',
            }}>
              {w.level === 'error' ? <AlertTriangle size={11} /> : w.level === 'warn' ? <AlertTriangle size={11} /> : <Zap size={11} />}
              {w.message}
            </span>
          ))}
        </div>
      )}

      {/* Execution result panel */}
      {showExecPanel && lastExecResult && (
        <div style={{
          flexShrink: 0, borderBottom: '1px solid var(--border)',
          background: lastExecResult.status === 'completed' ? 'var(--success-subtle)' : 'var(--danger-subtle)',
          maxHeight: 220, overflow: 'auto',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 16px' }}>
            {lastExecResult.status === 'completed'
              ? <CheckCircle size={16} color="var(--success)" />
              : <AlertTriangle size={16} color="var(--danger)" />}
            <span style={{
              fontWeight: 700, fontSize: 13,
              color: lastExecResult.status === 'completed' ? 'var(--success)' : 'var(--danger)',
            }}>
              {lastExecResult.status === 'completed' ? 'Workflow completed' : 'Workflow failed'}
            </span>
            <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
              {lastExecResult.items_processed ?? 0} items processed
              {lastExecResult.summary && ` · ${lastExecResult.summary.nodes_executed} nodes · ${lastExecResult.summary.actions_taken} actions`}
            </span>
            <button onClick={() => setShowExecPanel(false)}
              style={{ marginLeft: 'auto', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 4 }}>
              <X size={14} />
            </button>
          </div>

          {/* Top-level error */}
          {lastExecResult.error && !execDetail && (
            <div style={{ margin: '0 16px 8px', padding: '8px 12px', background: 'var(--danger-subtle)', borderRadius: 8, fontSize: 12, color: 'var(--danger)' }}>
              {lastExecResult.error}
            </div>
          )}

          {/* Per-node execution logs */}
          {execDetail?.logs && execDetail.logs.length > 0 && (
            <div style={{ padding: '0 16px 10px' }}>
              {execDetail.logs.map((log, i) => {
                const isFail = log.status === 'failed'
                const isEmpty = log.status === 'success' && log.items_in === 0 && log.node_type !== 'trigger'
                return (
                  <div key={i} style={{
                    display: 'flex', alignItems: 'flex-start', gap: 8,
                    padding: '6px 10px', borderRadius: 6, marginBottom: 3, fontSize: 12,
                    background: isFail ? 'var(--danger-subtle)' : isEmpty ? 'var(--warning-subtle)' : 'var(--card)',
                    border: `1px solid ${isFail ? 'var(--danger)' : isEmpty ? 'var(--warning)' : 'var(--border)'}`,
                  }}>
                    <span style={{
                      display: 'inline-flex', alignItems: 'center', gap: 3, fontWeight: 600, minWidth: 60,
                      color: isFail ? 'var(--danger)' : isEmpty ? 'var(--warning)' : 'var(--success)',
                    }}>
                      {isFail ? <X size={11} /> : isEmpty ? <AlertTriangle size={11} /> : <CheckCircle size={11} />}
                      {isFail ? 'FAIL' : isEmpty ? 'EMPTY' : 'OK'}
                    </span>
                    <span style={{ fontWeight: 600, color: 'var(--text-primary)', minWidth: 100 }}>{log.node_subtype}</span>
                    <span style={{ color: 'var(--text-secondary)' }}>{log.items_in} in → {log.items_out} out</span>
                    {log.output_data?.affected != null && (
                      <span style={{ color: 'var(--accent)' }}>{log.output_data.affected} affected</span>
                    )}
                    {isFail && (log.output_data?.error || log.error) && (
                      <span style={{ color: 'var(--danger)', flex: 1 }}>
                        {log.output_data?.error || log.error}
                      </span>
                    )}
                    {isEmpty && (
                      <span style={{ color: 'var(--warning)', fontStyle: 'italic' }}>
                        No items reached this node
                      </span>
                    )}
                  </div>
                )
              })}
            </div>
          )}

          {/* Errors summary from result */}
          {lastExecResult.summary?.errors?.length > 0 && !execDetail && (
            <div style={{ padding: '0 16px 10px' }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--danger)', marginBottom: 4 }}>Errors:</div>
              {lastExecResult.summary.errors.map((err, i) => (
                <div key={i} style={{
                  padding: '6px 10px', background: 'var(--danger-subtle)', borderRadius: 6,
                  fontSize: 12, color: 'var(--danger)', marginBottom: 3,
                  border: '1px solid var(--danger)',
                }}>
                  <span style={{ fontWeight: 600 }}>{err.node_id}:</span> {err.error}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        {/* Canvas */}
        <div
          ref={canvasRef}
          onMouseDown={handleCanvasMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseUp}
          style={{
            flex: 1, position: 'relative', overflow: 'hidden',
            background: 'var(--bg-muted)',
            backgroundImage: 'radial-gradient(circle, var(--border) 1px, transparent 1px)',
            backgroundSize: '20px 20px',
            backgroundPosition: `${pan.x % 20}px ${pan.y % 20}px`,
            cursor: isPanning ? 'grabbing' : dragging ? 'grabbing' : 'default',
          }}
        >
          {/* SVG Edges */}
          <svg style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%', pointerEvents: 'none' }}>
            <defs>
              <marker id="arr" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
                <polygon points="0 0, 10 3.5, 0 7" fill="#94a3b8" />
              </marker>
              <marker id="arr-g" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
                <polygon points="0 0, 10 3.5, 0 7" fill="#22c55e" />
              </marker>
              <marker id="arr-o" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
                <polygon points="0 0, 10 3.5, 0 7" fill="#f59e0b" />
              </marker>
            </defs>
            {edges.map(edge => {
              const from = getHandlePos(edge.source_node_id, edge.source_handle || 'output')
              const to = getHandlePos(edge.target_node_id, 'input')
              const midX = (from.x + to.x) / 2
              const isRemainder = edge.source_handle === 'remainder'
              const color = isRemainder ? '#f59e0b' : '#94a3b8'
              const marker = isRemainder ? 'url(#arr-o)' : 'url(#arr)'
              return (
                <g key={edge.edge_id} style={{ pointerEvents: 'auto', cursor: 'pointer' }}
                   onClick={() => deleteEdge(edge.edge_id)}>
                  <path d={`M${from.x},${from.y} C${midX},${from.y} ${midX},${to.y} ${to.x},${to.y}`}
                    fill="none" stroke="transparent" strokeWidth={16} />
                  <path d={`M${from.x},${from.y} C${midX},${from.y} ${midX},${to.y} ${to.x},${to.y}`}
                    fill="none" stroke={color} strokeWidth={2}
                    strokeDasharray={isRemainder ? '6,4' : 'none'} markerEnd={marker} />
                  {edge.label && (
                    <text x={midX} y={(from.y + to.y) / 2 - 8}
                      textAnchor="middle" fill={color} style={{ fontSize: 11, fontWeight: 600 }}>
                      {edge.label}
                    </text>
                  )}
                </g>
              )
            })}
            {connecting && canvasRef.current && (() => {
              const rect = canvasRef.current.getBoundingClientRect()
              const from = getHandlePos(connecting.sourceNodeId, connecting.sourceHandle || 'output')
              const toX = connecting.mouseX - rect.left
              const toY = connecting.mouseY - rect.top
              const midX = (from.x + toX) / 2
              return (
                <path d={`M${from.x},${from.y} C${midX},${from.y} ${midX},${toY} ${toX},${toY}`}
                  fill="none" stroke="#6366f1" strokeWidth={2} strokeDasharray="6,3"
                  style={{ pointerEvents: 'none' }} />
              )
            })()}
          </svg>

          {/* Nodes */}
          {nodes.map(node => {
            const colors = TYPE_COLORS[node.node_type] || TYPE_COLORS.action
            const def = allNodeDefs[node.node_subtype]
            const Icon = def ? (ICON_MAP[def.icon] || Zap) : Zap
            const isSelected = selectedNode === node.node_id
            const isFilter = node.node_type === 'filter'
            const x = node.position_x + pan.x
            const y = node.position_y + pan.y
            const nodeErr = nodeErrors[node.node_id]
            const isFailed = nodeErr && nodeErr !== 'empty'
            const isEmpty = nodeErr === 'empty'

            return (
              <div
                key={node.node_id}
                onMouseDown={(e) => handleMouseDown(e, node.node_id)}
                onMouseUp={() => connecting && handleNodeDrop(node.node_id)}
                style={{
                  position: 'absolute', left: x, top: y,
                  width: NODE_WIDTH, minHeight: NODE_HEIGHT,
                  background: isFailed ? 'var(--danger-subtle)' : isEmpty ? 'var(--warning-subtle)' : 'var(--card)',
                  border: `2px solid ${isFailed ? 'var(--danger)' : isEmpty ? 'var(--warning)' : isSelected ? colors.accent : 'var(--border)'}`,
                  borderRadius: 12,
                  boxShadow: isFailed
                    ? '0 0 0 3px rgba(239,68,68,0.15), 0 4px 12px rgba(0,0,0,0.1)'
                    : isSelected
                    ? `0 0 0 3px ${colors.accent}33, 0 4px 12px rgba(0,0,0,0.1)`
                    : '0 2px 8px rgba(0,0,0,0.06)',
                  cursor: 'grab', userSelect: 'none', overflow: 'hidden',
                  transition: dragging?.nodeId === node.node_id ? 'none' : 'box-shadow 0.15s',
                }}
              >
                {/* Header */}
                <div style={{
                  display: 'flex', alignItems: 'center', gap: 6,
                  padding: '8px 10px', background: colors.headerBg,
                  color: colors.text, fontSize: 12, fontWeight: 700,
                }}>
                  <Icon size={14} style={{ opacity: 0.9 }} />
                  <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {node.label || def?.label || node.node_subtype}
                  </span>
                  <span style={{
                    fontSize: 9, textTransform: 'uppercase', opacity: 0.7,
                    padding: '1px 5px', background: 'rgba(255,255,255,0.1)', borderRadius: 4,
                  }}>
                    {node.node_type}
                  </span>
                </div>
                {/* Body */}
                <div style={{ padding: '8px 10px', fontSize: 11, color: 'var(--muted)' }}>
                  {def?.description || node.node_subtype}
                  {node.config && Object.keys(node.config).length > 0 && (
                    <div style={{ marginTop: 4, display: 'flex', flexWrap: 'wrap', gap: 3 }}>
                      {Object.entries(node.config).slice(0, 3).map(([k, v]) =>
                        v ? (
                          <span key={k} style={{
                            fontSize: 10, padding: '1px 5px', background: 'var(--secondary)',
                            borderRadius: 4, color: 'var(--muted)',
                          }}>
                            {k}: {String(v).slice(0, 15)}
                          </span>
                        ) : null
                      )}
                    </div>
                  )}
                </div>

                {/* Per-node execution status footer */}
                {nodeResults[node.node_id] && (() => {
                  const res = nodeResults[node.node_id]
                  const isOk = res.status === 'success'
                  const color = isOk ? '#22c55e' : '#ef4444'
                  const bg = isOk ? 'rgba(34,197,94,0.12)' : 'rgba(239,68,68,0.12)'
                  return (
                    <div style={{
                      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                      padding: '4px 10px', borderTop: `1px solid ${color}33`,
                      background: bg, fontSize: 10, color: color, fontWeight: 600,
                      gap: 4,
                    }}>
                      <span style={{ display: 'flex', alignItems: 'center', gap: 3 }}>
                        {isOk
                          ? <CheckCircle size={10} />
                          : <X size={10} strokeWidth={3} />}
                        {isOk ? 'OK' : 'FAILED'}
                      </span>
                      <span style={{ color: 'var(--muted)', fontWeight: 400 }}>
                        {res.items_in} in → {res.items_out} out
                      </span>
                    </div>
                  )
                })()}

                {/* Error/warning badge */}
                {isFailed && (
                  <div title={nodeErr} style={{
                    position: 'absolute', top: -8, right: -8, width: 20, height: 20,
                    borderRadius: '50%', background: '#ef4444', display: 'flex', alignItems: 'center',
                    justifyContent: 'center', zIndex: 3, border: '2px solid #fff',
                  }}>
                    <X size={10} color="#fff" strokeWidth={3} />
                  </div>
                )}
                {isEmpty && (
                  <div title="No items reached this node" style={{
                    position: 'absolute', top: -8, right: -8, width: 20, height: 20,
                    borderRadius: '50%', background: '#eab308', display: 'flex', alignItems: 'center',
                    justifyContent: 'center', zIndex: 3, border: '2px solid #fff',
                  }}>
                    <AlertTriangle size={10} color="#fff" strokeWidth={3} />
                  </div>
                )}

                {/* Input handle (left) */}
                {node.node_type !== 'trigger' && (
                  <div
                    onMouseUp={(e) => { e.stopPropagation(); connecting && handleNodeDrop(node.node_id) }}
                    style={{
                      position: 'absolute', left: -HANDLE_SIZE / 2, top: NODE_HEADER,
                      width: HANDLE_SIZE, height: HANDLE_SIZE, borderRadius: '50%',
                      background: 'var(--card)', border: '2px solid #94a3b8', cursor: 'crosshair', zIndex: 2,
                    }}
                  />
                )}

                {/* Output handle(s) */}
                <div
                  onMouseDown={(e) => handleHandleMouseDown(e, node.node_id, 'output')}
                  style={{
                    position: 'absolute', right: -HANDLE_SIZE / 2,
                    top: isFilter ? NODE_HEIGHT * 0.4 - HANDLE_SIZE / 2 : NODE_HEIGHT / 2 - HANDLE_SIZE / 2,
                    width: HANDLE_SIZE, height: HANDLE_SIZE, borderRadius: '50%',
                    background: isFilter ? '#22c55e' : 'var(--card)',
                    border: `2px solid ${isFilter ? '#16a34a' : '#94a3b8'}`,
                    cursor: 'crosshair', zIndex: 2,
                  }}
                  title={isFilter ? 'Matched items' : 'Output'}
                />
                {isFilter && (
                  <div style={{
                    position: 'absolute', right: HANDLE_SIZE + 2,
                    top: NODE_HEIGHT * 0.4 - 6, fontSize: 9, color: '#22c55e', fontWeight: 700,
                  }}>Match</div>
                )}

                {/* Remainder handle for filters */}
                {isFilter && (
                  <>
                    <div
                      onMouseDown={(e) => handleHandleMouseDown(e, node.node_id, 'remainder')}
                      style={{
                        position: 'absolute', right: -HANDLE_SIZE / 2,
                        top: NODE_HEIGHT * 0.78 - HANDLE_SIZE / 2,
                        width: HANDLE_SIZE, height: HANDLE_SIZE, borderRadius: '50%',
                        background: '#f59e0b', border: '2px solid #d97706',
                        cursor: 'crosshair', zIndex: 2,
                      }}
                      title="Remainder (non-matching items)"
                    />
                    <div style={{
                      position: 'absolute', right: HANDLE_SIZE + 2,
                      top: NODE_HEIGHT * 0.78 - 6, fontSize: 9, color: '#f59e0b', fontWeight: 700,
                    }}>Rest</div>
                  </>
                )}
              </div>
            )
          })}

          {/* Empty state */}
          {nodes.length === 0 && (
            <div style={{
              position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)',
              textAlign: 'center', color: '#94a3b8',
            }}>
              <GitBranch size={40} style={{ marginBottom: 12, opacity: 0.5 }} />
              <div style={{ fontSize: 16, fontWeight: 600, marginBottom: 6 }}>Empty Workflow</div>
              <div style={{ fontSize: 13, marginBottom: 16 }}>Start by adding a trigger node</div>
              <Button size="sm" variant="primary" onClick={() => setShowNodePalette(true)}>
                <Plus size={14} /> Add Node
              </Button>
            </div>
          )}
        </div>

        {/* Config Panel */}
        {selectedNodeData && (
          <div style={{
            width: 320, flexShrink: 0, background: 'var(--card)', borderLeft: '1px solid var(--border)',
            overflow: 'auto', display: 'flex', flexDirection: 'column',
          }}>
            <div style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              padding: '12px 14px', borderBottom: '1px solid var(--border)',
            }}>
              <div style={{ fontWeight: 700, fontSize: 14 }}>Node Settings</div>
              <div style={{ display: 'flex', gap: 4 }}>
                <button onClick={() => deleteNode(selectedNode)}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#ef4444', padding: 4, borderRadius: 4 }}
                  title="Delete node"><Trash2 size={14} /></button>
                <button onClick={() => setSelectedNode(null)}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#94a3b8', padding: 4 }}>
                  <X size={14} /></button>
              </div>
            </div>
            <div style={{ padding: 14, flex: 1 }}>
              <div style={{ marginBottom: 14 }}>
                <label style={{ fontSize: 11, fontWeight: 600, color: 'var(--muted)', display: 'block', marginBottom: 4 }}>Label</label>
                <input value={selectedNodeData.label || ''}
                  onChange={e => updateNodeLabel(selectedNode, e.target.value)}
                  style={{ width: '100%', padding: '6px 10px', borderRadius: 6, border: '1px solid var(--border)', fontSize: 13, boxSizing: 'border-box', background: 'var(--bg)', color: 'var(--text)' }}
                />
              </div>
              <div style={{ marginBottom: 14, display: 'flex', gap: 6 }}>
                <Pill label={selectedNodeData.node_type} color={TYPE_COLORS[selectedNodeData.node_type]?.accent || '#94a3b8'} />
                <Pill label={selectedNodeData.node_subtype} color="#64748b" />
              </div>

              {/* SMTP not configured banner */}
              {selectedNodeData.node_subtype === 'send_email' && smtpConfigured === false && (
                <div style={{
                  marginBottom: 14, padding: '10px 12px', borderRadius: 8,
                  background: '#431407', border: '1px solid #c2410c',
                  fontSize: 12, color: '#fed7aa',
                  display: 'flex', flexDirection: 'column', gap: 6,
                }}>
                  <div style={{ fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6 }}>
                    <AlertTriangle size={13} style={{ color: '#fb923c', flexShrink: 0 }} />
                    Email (SMTP) not configured
                  </div>
                  <div style={{ lineHeight: 1.4 }}>
                    This action requires an SMTP integration to send emails.
                  </div>
                  <button
                    onClick={() => navigate('/settings?tab=integrations')}
                    style={{
                      alignSelf: 'flex-start', marginTop: 2,
                      padding: '5px 10px', borderRadius: 6, border: 'none',
                      background: '#ea580c', color: '#fff',
                      fontSize: 11, fontWeight: 600, cursor: 'pointer',
                    }}
                  >
                    Configure SMTP →
                  </button>
                </div>
              )}

              {/* Config fields from schema */}
              {selectedDef?.config_schema && Object.entries(selectedDef.config_schema).map(([key, schema]) => {
                // Conditional visibility: hide fields whose visible_when condition isn't met
                if (schema.visible_when) {
                  const ok = Object.entries(schema.visible_when).every(([k, v]) => (selectedNodeData.config?.[k] || '') === v)
                  if (!ok) return null
                }
                return (
                <div key={key} style={{ marginBottom: 12 }}>
                  <label style={{ fontSize: 11, fontWeight: 600, color: 'var(--muted)', display: 'block', marginBottom: 4 }}>
                    {schema.label || key}
                  </label>
                  {schema.type === 'enum' ? (
                    <select
                      value={selectedNodeData.config?.[key] || ''}
                      onChange={e => updateNodeConfig(selectedNode, key, e.target.value)}
                      style={{ width: '100%', padding: '6px 10px', borderRadius: 6, border: '1px solid var(--border)', fontSize: 13, boxSizing: 'border-box', background: 'var(--bg)', color: 'var(--text)' }}
                    >
                      <option value="">Select...</option>
                      {(schema.options || []).map(opt => {
                        const val = typeof opt === 'object' ? opt.value : opt
                        const label = typeof opt === 'object' ? opt.label : opt
                        return <option key={val} value={val}>{label}</option>
                      })}
                    </select>
                  ) : schema.type === 'multi_enum' ? (
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                      {(schema.options || []).map(opt => {
                        const val = typeof opt === 'object' ? opt.value : opt
                        const label = typeof opt === 'object' ? opt.label : opt
                        const selected = (selectedNodeData.config?.[key] || schema.default || [])
                        const isSelected = Array.isArray(selected) && selected.includes(val)
                        return (
                          <button key={val} type="button"
                            onClick={() => {
                              const cur = Array.isArray(selectedNodeData.config?.[key]) ? [...selectedNodeData.config[key]] : [...(schema.default || [])]
                              const next = isSelected ? cur.filter(v => v !== val) : [...cur, val]
                              updateNodeConfig(selectedNode, key, next)
                            }}
                            style={{
                              padding: '4px 10px', borderRadius: 6, fontSize: 12, fontWeight: 500, cursor: 'pointer',
                              border: isSelected ? '1px solid var(--accent)' : '1px solid var(--border)',
                              background: isSelected ? 'color-mix(in srgb, var(--accent) 15%, transparent)' : 'transparent',
                              color: isSelected ? 'var(--accent)' : 'var(--text-muted)',
                            }}
                          >{label}</button>
                        )
                      })}
                    </div>
                  ) : schema.type === 'boolean' ? (
                    <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
                      <input type="checkbox" checked={selectedNodeData.config?.[key] ?? schema.default ?? false}
                        onChange={e => updateNodeConfig(selectedNode, key, e.target.checked)} />
                      {schema.label}
                    </label>
                  ) : (
                    <input
                      type={schema.type === 'number' ? 'number' : 'text'}
                      value={selectedNodeData.config?.[key] || ''}
                      onChange={e => updateNodeConfig(selectedNode, key, e.target.value)}
                      placeholder={schema.placeholder || schema.label}
                      style={{ width: '100%', padding: '6px 10px', borderRadius: 6, border: '1px solid var(--border)', fontSize: 13, boxSizing: 'border-box', background: 'var(--bg)', color: 'var(--text)' }}
                    />
                  )}
                </div>
                )
              })}

              {/* Last run output */}
              {nodeResults[selectedNode] && (() => {
                const res = nodeResults[selectedNode]
                const isOk = res.status === 'success'
                return (
                  <div style={{ marginTop: 16, paddingTop: 14, borderTop: '1px solid var(--border)' }}>
                    <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--muted)', marginBottom: 8 }}>Last Run</div>
                    <div style={{
                      padding: '8px 10px', borderRadius: 8,
                      background: isOk ? 'rgba(34,197,94,0.08)' : 'rgba(239,68,68,0.08)',
                      border: `1px solid ${isOk ? 'rgba(34,197,94,0.3)' : 'rgba(239,68,68,0.3)'}`,
                      fontSize: 12,
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                        {isOk
                          ? <CheckCircle size={12} color="#22c55e" />
                          : <X size={12} color="#ef4444" strokeWidth={3} />}
                        <span style={{ fontWeight: 600, color: isOk ? '#22c55e' : '#ef4444' }}>
                          {isOk ? 'Success' : 'Failed'}
                        </span>
                        <span style={{ color: 'var(--muted)', marginLeft: 'auto' }}>
                          {res.items_in} in → {res.items_out} out
                        </span>
                      </div>
                      {res.error && (
                        <div style={{ color: '#ef4444', fontSize: 11, marginTop: 4, wordBreak: 'break-word' }}>
                          {res.error}
                        </div>
                      )}
                      {res.output_data && Object.keys(res.output_data).length > 0 && (
                        <div>
                          <button
                            onClick={() => setNodeOutputOpen(o => !o)}
                            style={{
                              marginTop: 6, background: 'none', border: 'none', cursor: 'pointer',
                              fontSize: 11, color: 'var(--muted)', padding: 0, display: 'flex', alignItems: 'center', gap: 3,
                            }}
                          >
                            <ChevronRight size={10} style={{ transform: nodeOutputOpen ? 'rotate(90deg)' : 'none', transition: 'transform 0.15s' }} />
                            Output data
                          </button>
                          {nodeOutputOpen && (
                            <pre style={{
                              marginTop: 6, padding: '6px 8px', borderRadius: 6,
                              background: 'var(--secondary)', fontSize: 10,
                              color: 'var(--text)', overflowX: 'auto', whiteSpace: 'pre-wrap',
                              wordBreak: 'break-word', maxHeight: 200, overflow: 'auto',
                            }}>
                              {JSON.stringify(res.output_data, null, 2)}
                            </pre>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                )
              })()}

              {/* Connections */}
              <div style={{ marginTop: 20, paddingTop: 14, borderTop: '1px solid var(--border)' }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--muted)', marginBottom: 8 }}>Connections</div>
                {edges.filter(e => e.source_node_id === selectedNode || e.target_node_id === selectedNode).map(e => {
                  const isSource = e.source_node_id === selectedNode
                  const otherNode = nodes.find(n => n.node_id === (isSource ? e.target_node_id : e.source_node_id))
                  return (
                    <div key={e.edge_id} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--muted)', marginBottom: 4 }}>
                      <ChevronRight size={12} />
                      <span>{isSource ? 'To' : 'From'}: {otherNode?.label || '?'}</span>
                      {e.source_handle === 'remainder' && <Pill color="#f59e0b">remainder</Pill>}
                      {e.label && <Pill color="#94a3b8">{e.label}</Pill>}
                      <button onClick={() => deleteEdge(e.edge_id)}
                        style={{ marginLeft: 'auto', background: 'none', border: 'none', cursor: 'pointer', color: '#ef4444' }}>
                        <X size={12} />
                      </button>
                    </div>
                  )
                })}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Node palette */}
      {showNodePalette && catalog && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.4)', zIndex: 100,
          display: 'flex', alignItems: 'center', justifyContent: 'center' }}
          onClick={() => setShowNodePalette(false)}>
          <div onClick={e => e.stopPropagation()}
            style={{ background: 'var(--card)', borderRadius: 16, width: 580, maxHeight: '75vh',
              overflow: 'auto', boxShadow: '0 20px 60px rgba(0,0,0,0.2)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center',
              padding: '16px 20px', borderBottom: '1px solid var(--border)' }}>
              <div style={{ fontWeight: 700, fontSize: 16 }}>Add Node</div>
              <button onClick={() => setShowNodePalette(false)}
                style={{ background: 'none', border: 'none', cursor: 'pointer' }}><X size={18} /></button>
            </div>
            <div style={{ padding: '12px 20px' }}>
              {Object.entries(catalog).map(([type, defs]) => {
                const nodeType = type.replace(/s$/, '')
                const colors = TYPE_COLORS[nodeType]
                return (
                  <div key={type} style={{ marginBottom: 16 }}>
                    <div style={{
                      fontSize: 11, fontWeight: 700, textTransform: 'uppercase',
                      color: colors?.accent || '#64748b', marginBottom: 8, letterSpacing: '0.05em',
                    }}>{type}</div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                      {defs.map(def => {
                        const Icon = ICON_MAP[def.icon] || Zap
                        return (
                          <button key={def.subtype} onClick={() => addNode(nodeType, def)}
                            style={{
                              display: 'flex', alignItems: 'center', gap: 10,
                              padding: '10px 12px', borderRadius: 10,
                              border: '1px solid var(--border)', background: 'var(--card)',
                              cursor: 'pointer', textAlign: 'left', transition: 'all 0.15s',
                            }}
                            onMouseEnter={e => { e.currentTarget.style.borderColor = colors?.accent || '#94a3b8'; e.currentTarget.style.background = 'var(--bg-hover)' }}
                            onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.background = 'var(--card)' }}
                          >
                            <div style={{
                              width: 36, height: 36, borderRadius: 8,
                              background: colors?.headerBg || '#374151',
                              display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                            }}>
                              <Icon size={16} color={colors?.text || '#fff'} />
                            </div>
                            <div>
                              <div style={{ fontSize: 13, fontWeight: 600 }}>{def.label}</div>
                              <div style={{ fontSize: 11, color: 'var(--muted-2)' }}>{def.description}</div>
                            </div>
                          </button>
                        )
                      })}
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      )}

      {/* Execution history modal */}
      {showExecutions && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.4)', zIndex: 100,
          display: 'flex', alignItems: 'center', justifyContent: 'center' }}
          onClick={() => { setShowExecutions(false); setExecutionDetail(null) }}>
          <div onClick={e => e.stopPropagation()}
            style={{ background: 'var(--card)', borderRadius: 16, width: 600, maxHeight: '70vh',
              overflow: 'auto', boxShadow: '0 20px 60px rgba(0,0,0,0.2)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center',
              padding: '16px 20px', borderBottom: '1px solid var(--border)' }}>
              <div style={{ fontWeight: 700, fontSize: 16 }}>
                {executionDetail ? `Execution #${executionDetail.id}` : 'Execution History'}
              </div>
              <button onClick={() => { setShowExecutions(false); setExecutionDetail(null) }}
                style={{ background: 'none', border: 'none', cursor: 'pointer' }}><X size={18} /></button>
            </div>
            <div style={{ padding: '12px 20px' }}>
              {executionDetail ? (
                <div>
                  <div style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap' }}>
                    <Pill color={executionDetail.status === 'completed' ? '#22c55e' : '#ef4444'}>{executionDetail.status}</Pill>
                    <Pill color="#64748b">{executionDetail.items_processed} items</Pill>
                    <Pill color="#6366f1">{executionDetail.trigger_type}</Pill>
                  </div>
                  {executionDetail.error && (
                    <div style={{ padding: 10, background: 'var(--danger-subtle)', borderRadius: 8, color: 'var(--danger)', fontSize: 12, marginBottom: 12 }}>{executionDetail.error}</div>
                  )}
                  <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 8, color: 'var(--muted)' }}>Node Logs</div>
                  {(executionDetail.logs || []).map((log, i) => (
                    <div key={i} style={{
                      display: 'flex', alignItems: 'center', gap: 8,
                      padding: '8px 10px', borderRadius: 6,
                      background: log.status === 'failed' ? 'var(--danger-subtle)' : 'var(--secondary)',
                      marginBottom: 4, fontSize: 12,
                    }}>
                      <Pill color={log.status === 'success' ? '#22c55e' : '#ef4444'}>{log.status}</Pill>
                      <span style={{ fontWeight: 600 }}>{log.node_subtype}</span>
                      <span style={{ color: '#94a3b8' }}>{log.items_in} in / {log.items_out} out</span>
                      {log.output_data?.affected != null && <span style={{ color: '#6366f1' }}>{log.output_data.affected} affected</span>}
                    </div>
                  ))}
                  <button onClick={() => setExecutionDetail(null)}
                    style={{ marginTop: 12, fontSize: 12, color: '#6366f1', background: 'none', border: 'none', cursor: 'pointer' }}>
                    <ArrowLeft size={12} style={{ verticalAlign: 'middle' }} /> Back to list
                  </button>
                </div>
              ) : (
                <div>
                  {executions.length === 0 && (
                    <div style={{ textAlign: 'center', padding: 30, color: '#94a3b8', fontSize: 13 }}>No executions yet</div>
                  )}
                  {executions.map(ex => (
                    <button key={ex.id}
                      onClick={async () => { const d = await getWorkflowExecution(ex.id); setExecutionDetail(d) }}
                      style={{
                        display: 'flex', alignItems: 'center', gap: 8, width: '100%',
                        padding: '10px 12px', borderRadius: 8, marginBottom: 4,
                        border: '1px solid var(--border)', background: 'var(--card)',
                        cursor: 'pointer', textAlign: 'left', fontSize: 12,
                      }}>
                      <Pill color={ex.status === 'completed' ? '#22c55e' : '#ef4444'}>{ex.status}</Pill>
                      <span>{ex.items_processed} items</span>
                      <span style={{ color: '#94a3b8', marginLeft: 'auto' }}>
                        {ex.started_at ? new Date(ex.started_at).toLocaleString() : ''}
                      </span>
                      <ChevronRight size={14} color="#94a3b8" />
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
