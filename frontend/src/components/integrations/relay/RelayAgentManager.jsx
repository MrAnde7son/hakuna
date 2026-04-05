/**
 * Relay Agent Manager — CRUD for on-prem relay agents.
 * Shows agent list, create dialog, setup guide, and status.
 */
import { useState, useEffect, useCallback } from 'react'
import { Plus, Trash2, RotateCcw, Copy, Check, Wifi, WifiOff, ChevronDown, ChevronRight, Server, Shield, Clock, ExternalLink, RefreshCw } from 'lucide-react'
import { Card, Button, useToast } from '../../shared/ui.jsx'
import { getRelayAgents, createRelayAgent, deleteRelayAgent, rotateAgentToken, getAgentSetup } from '../../../api.js'
import RelayAgentSetupGuide from './RelayAgentSetupGuide.jsx'

export default function RelayAgentManager() {
  const toast = useToast()
  const [agents, setAgents] = useState([])
  const [loading, setLoading] = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [createName, setCreateName] = useState('')
  const [createMode, setCreateMode] = useState('agent_local')
  const [creating, setCreating] = useState(false)
  const [newToken, setNewToken] = useState(null)    // shown once after create
  const [tokenCopied, setTokenCopied] = useState(false)
  const [setupAgent, setSetupAgent] = useState(null) // agent to show setup for
  const [expandedAgent, setExpandedAgent] = useState(null)

  const refresh = useCallback(async () => {
    try {
      setLoading(true)
      const data = await getRelayAgents()
      setAgents(data)
    } catch (e) {
      toast.error('Failed to load agents: ' + e.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { refresh() }, [refresh])

  const handleCreate = async () => {
    if (!createName.trim()) return
    setCreating(true)
    try {
      const result = await createRelayAgent({
        name: createName.trim(),
        credentials_mode: createMode,
      })
      setNewToken(result.token)
      setCreateName('')
      setShowCreate(false)
      await refresh()
      toast.success('Agent created. Copy the token below — it will only be shown once.')
    } catch (e) {
      toast.error('Failed to create agent: ' + e.message)
    } finally {
      setCreating(false)
    }
  }

  const handleDelete = async (agent) => {
    if (!confirm(`Delete agent "${agent.name}"? This cannot be undone.`)) return
    try {
      await deleteRelayAgent(agent.id)
      await refresh()
      toast.success('Agent deleted')
    } catch (e) {
      toast.error(e.message)
    }
  }

  const handleRotateToken = async (agent) => {
    if (!confirm(`Rotate token for "${agent.name}"? The current token will stop working immediately.`)) return
    try {
      const result = await rotateAgentToken(agent.id)
      setNewToken(result.token)
      await refresh()
      toast.success('Token rotated. Copy the new token below.')
    } catch (e) {
      toast.error(e.message)
    }
  }

  const copyToken = () => {
    if (newToken) {
      navigator.clipboard.writeText(newToken)
      setTokenCopied(true)
      setTimeout(() => setTokenCopied(false), 2000)
    }
  }

  if (setupAgent) {
    return <RelayAgentSetupGuide agent={setupAgent} onBack={() => setSetupAgent(null)} />
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div>
          <h2 style={{ fontSize: 18, fontWeight: 600, margin: 0, color: 'var(--text)' }}>Relay Agents</h2>
          <p style={{ fontSize: 13, color: 'var(--text-muted)', margin: '4px 0 0' }}>
            Deploy agents in your network to connect on-prem tools (Jira Server, ServiceNow, CrowdStrike, etc.)
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <Button size="sm" variant="ghost" onClick={refresh} title="Refresh">
            <RefreshCw size={14} />
          </Button>
          <Button size="sm" onClick={() => setShowCreate(true)}>
            <Plus size={14} /> New Agent
          </Button>
        </div>
      </div>

      {/* Token display (shown once after create/rotate) */}
      {newToken && (
        <div style={{
          background: 'var(--warning-bg, #fef3c7)', border: '1px solid var(--warning-border, #f59e0b)',
          borderRadius: 10, padding: 16, marginBottom: 16,
        }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--warning-text, #92400e)', marginBottom: 8 }}>
            Agent Token (copy now — it won't be shown again)
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <code style={{
              flex: 1, fontSize: 12, padding: '8px 12px', borderRadius: 6,
              background: 'var(--bg)', border: '1px solid var(--border)',
              wordBreak: 'break-all', color: 'var(--text)',
            }}>
              {newToken}
            </code>
            <Button size="sm" onClick={copyToken}>
              {tokenCopied ? <><Check size={14} /> Copied</> : <><Copy size={14} /> Copy</>}
            </Button>
          </div>
          <button
            onClick={() => setNewToken(null)}
            style={{ marginTop: 8, fontSize: 12, color: 'var(--text-muted)', background: 'none', border: 'none', cursor: 'pointer', textDecoration: 'underline' }}
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Create dialog */}
      {showCreate && (
        <Card style={{ marginBottom: 16, padding: 20 }}>
          <h3 style={{ fontSize: 14, fontWeight: 600, margin: '0 0 12px', color: 'var(--text)' }}>Create Relay Agent</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div>
              <label style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Agent Name</label>
              <input
                type="text"
                value={createName}
                onChange={e => setCreateName(e.target.value)}
                placeholder="e.g. NYC Office Agent"
                style={{
                  width: '100%', padding: '8px 12px', borderRadius: 8, fontSize: 13,
                  border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)',
                }}
                autoFocus
                onKeyDown={e => e.key === 'Enter' && handleCreate()}
              />
            </div>
            <div>
              <label style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Credential Mode</label>
              <div style={{ display: 'flex', gap: 8 }}>
                {[
                  { value: 'agent_local', label: 'Agent-Local', desc: 'Credentials stored on the agent (more secure)' },
                  { value: 'cloud_managed', label: 'Cloud-Managed', desc: 'Credentials stored in Hakuna (more convenient)' },
                ].map(opt => (
                  <button
                    key={opt.value}
                    onClick={() => setCreateMode(opt.value)}
                    style={{
                      flex: 1, padding: '10px 12px', borderRadius: 8, cursor: 'pointer',
                      border: createMode === opt.value ? '2px solid var(--accent)' : '1px solid var(--border)',
                      background: createMode === opt.value ? 'rgba(99,102,241,0.06)' : 'var(--bg)',
                      textAlign: 'left',
                    }}
                  >
                    <div style={{ fontSize: 13, fontWeight: 500, color: 'var(--text)' }}>{opt.label}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{opt.desc}</div>
                  </button>
                ))}
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
              <Button size="sm" variant="ghost" onClick={() => setShowCreate(false)}>Cancel</Button>
              <Button size="sm" onClick={handleCreate} disabled={creating || !createName.trim()}>
                {creating ? 'Creating...' : 'Create Agent'}
              </Button>
            </div>
          </div>
        </Card>
      )}

      {/* Agent list */}
      {loading && agents.length === 0 ? (
        <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>Loading...</div>
      ) : agents.length === 0 ? (
        <Card style={{ padding: 40, textAlign: 'center' }}>
          <Server size={32} style={{ color: 'var(--text-muted)', margin: '0 auto 12px' }} />
          <div style={{ fontSize: 15, fontWeight: 500, color: 'var(--text)', marginBottom: 4 }}>No relay agents yet</div>
          <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 16 }}>
            Deploy a relay agent in your network to connect on-prem tools like Jira Server, ServiceNow, or CrowdStrike.
          </div>
          <Button size="sm" onClick={() => setShowCreate(true)}>
            <Plus size={14} /> Create Your First Agent
          </Button>
        </Card>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {agents.map(agent => {
            const isConnected = agent.status === 'connected'
            const isExpanded = expandedAgent === agent.id
            return (
              <Card key={agent.id} style={{ padding: 0, overflow: 'hidden' }}>
                <button
                  onClick={() => setExpandedAgent(isExpanded ? null : agent.id)}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 12, width: '100%',
                    padding: '14px 16px', border: 'none', background: 'transparent',
                    cursor: 'pointer', textAlign: 'left',
                  }}
                >
                  {isExpanded ? <ChevronDown size={14} color="var(--text-muted)" /> : <ChevronRight size={14} color="var(--text-muted)" />}

                  {/* Status indicator */}
                  <div style={{
                    width: 8, height: 8, borderRadius: '50%', flexShrink: 0,
                    background: isConnected ? '#22c55e' : 'var(--text-muted)',
                  }} />

                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 14, fontWeight: 500, color: 'var(--text)' }}>{agent.name}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', display: 'flex', gap: 12, marginTop: 2 }}>
                      <span>{isConnected ? 'Connected' : 'Disconnected'}</span>
                      {agent.agent_version && <span>v{agent.agent_version}</span>}
                      {agent.ip_address && <span>{agent.ip_address}</span>}
                      <span>{agent.integration_count} integration{agent.integration_count !== 1 ? 's' : ''}</span>
                    </div>
                  </div>

                  <div style={{ display: 'flex', gap: 4 }} onClick={e => e.stopPropagation()}>
                    <Button size="xs" variant="ghost" title="Setup Guide" onClick={() => setSetupAgent(agent)}>
                      <ExternalLink size={13} />
                    </Button>
                    <Button size="xs" variant="ghost" title="Rotate Token" onClick={() => handleRotateToken(agent)}>
                      <RotateCcw size={13} />
                    </Button>
                    <Button size="xs" variant="ghost" title="Delete" onClick={() => handleDelete(agent)} style={{ color: 'var(--danger, #ef4444)' }}>
                      <Trash2 size={13} />
                    </Button>
                  </div>
                </button>

                {isExpanded && (
                  <div style={{ padding: '0 16px 14px 44px', fontSize: 12, color: 'var(--text-muted)' }}>
                    <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '4px 16px' }}>
                      <span style={{ fontWeight: 500 }}>ID:</span>
                      <code style={{ fontSize: 11 }}>{agent.id}</code>
                      <span style={{ fontWeight: 500 }}>Token:</span>
                      <code style={{ fontSize: 11 }}>{agent.token_prefix}</code>
                      <span style={{ fontWeight: 500 }}>Mode:</span>
                      <span>{agent.credentials_mode === 'agent_local' ? 'Agent-Local (credentials on agent)' : 'Cloud-Managed (credentials in Hakuna)'}</span>
                      <span style={{ fontWeight: 500 }}>Created:</span>
                      <span>{agent.created_at ? new Date(agent.created_at).toLocaleString() : '—'}</span>
                      <span style={{ fontWeight: 500 }}>Last Seen:</span>
                      <span>{agent.last_seen_at ? new Date(agent.last_seen_at).toLocaleString() : 'Never'}</span>
                      {agent.allowed_hosts?.length > 0 && <>
                        <span style={{ fontWeight: 500 }}>Allowed Hosts:</span>
                        <span>{agent.allowed_hosts.join(', ')}</span>
                      </>}
                    </div>
                    <div style={{ marginTop: 8 }}>
                      <Button size="xs" variant="ghost" onClick={() => setSetupAgent(agent)}>
                        View Setup Guide
                      </Button>
                    </div>
                  </div>
                )}
              </Card>
            )
          })}
        </div>
      )}
    </div>
  )
}
