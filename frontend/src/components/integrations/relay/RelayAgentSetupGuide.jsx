/**
 * Relay Agent Setup Guide — step-by-step deployment instructions.
 * Fetches setup data from the backend and renders Docker commands,
 * env var references, and per-product credential examples.
 */
import { useState, useEffect } from 'react'
import { ArrowLeft, Copy, Check, Terminal, Server, Shield, ChevronDown, ChevronRight } from 'lucide-react'
import { Card, Button, useToast } from '../../shared/ui.jsx'
import { getAgentSetup } from '../../../api.js'

function CodeBlock({ code, label }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard.writeText(code)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return (
    <div style={{ position: 'relative', marginBottom: 12 }}>
      {label && <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.05em' }}>{label}</div>}
      <div style={{ position: 'relative' }}>
        <pre style={{
          background: 'var(--code-bg, #1e1e2e)', color: 'var(--code-text, #cdd6f4)',
          padding: '14px 16px', borderRadius: 8, fontSize: 12, lineHeight: 1.6,
          overflow: 'auto', margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all',
        }}>
          {code}
        </pre>
        <button
          onClick={copy}
          style={{
            position: 'absolute', top: 8, right: 8, background: 'rgba(255,255,255,0.1)',
            border: 'none', borderRadius: 6, padding: '4px 8px', cursor: 'pointer',
            color: 'var(--code-text, #cdd6f4)', fontSize: 11, display: 'flex', alignItems: 'center', gap: 4,
          }}
        >
          {copied ? <><Check size={12} /> Copied</> : <><Copy size={12} /> Copy</>}
        </button>
      </div>
    </div>
  )
}

export default function RelayAgentSetupGuide({ agent, onBack }) {
  const toast = useToast()
  const [setup, setSetup] = useState(null)
  const [loading, setLoading] = useState(true)
  const [expandedProduct, setExpandedProduct] = useState(null)
  const [activeTab, setActiveTab] = useState('docker-run') // docker-run | docker-compose

  useEffect(() => {
    setLoading(true)
    getAgentSetup(agent.id)
      .then(setSetup)
      .catch(e => toast.error('Failed to load setup: ' + e.message))
      .finally(() => setLoading(false))
  }, [agent.id])

  if (loading) {
    return <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>Loading setup guide...</div>
  }

  if (!setup) return null

  return (
    <div style={{ maxWidth: 760 }}>
      <button
        onClick={onBack}
        style={{
          display: 'flex', alignItems: 'center', gap: 6, background: 'none', border: 'none',
          cursor: 'pointer', color: 'var(--text-muted)', fontSize: 13, marginBottom: 16, padding: 0,
        }}
      >
        <ArrowLeft size={14} /> Back to Agents
      </button>

      <h2 style={{ fontSize: 18, fontWeight: 600, margin: '0 0 4px', color: 'var(--text)' }}>
        Deploy "{agent.name}"
      </h2>
      <p style={{ fontSize: 13, color: 'var(--text-muted)', margin: '0 0 24px' }}>
        Follow these steps to deploy the relay agent in your network.
      </p>

      {/* Step 1: Prerequisites */}
      <Card style={{ padding: 20, marginBottom: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
          <div style={{
            width: 24, height: 24, borderRadius: '50%', background: 'var(--accent)',
            color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 12, fontWeight: 700, flexShrink: 0,
          }}>1</div>
          <h3 style={{ fontSize: 14, fontWeight: 600, margin: 0, color: 'var(--text)' }}>Prerequisites</h3>
        </div>
        <ul style={{ fontSize: 13, color: 'var(--text-muted)', margin: 0, paddingLeft: 56, lineHeight: 1.8 }}>
          <li>Docker or Docker Compose installed on a server in your network</li>
          <li>Outbound HTTPS/WSS access to your Hakuna instance</li>
          <li>Network access to the on-prem services you want to connect (Jira, ServiceNow, etc.)</li>
          <li>The agent token from the creation step (shown once)</li>
        </ul>
      </Card>

      {/* Step 2: Deploy */}
      <Card style={{ padding: 20, marginBottom: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
          <div style={{
            width: 24, height: 24, borderRadius: '50%', background: 'var(--accent)',
            color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 12, fontWeight: 700, flexShrink: 0,
          }}>2</div>
          <h3 style={{ fontSize: 14, fontWeight: 600, margin: 0, color: 'var(--text)' }}>Deploy the Agent</h3>
        </div>

        {/* Tabs */}
        <div style={{ display: 'flex', gap: 0, marginBottom: 12, marginLeft: 32 }}>
          {[
            { id: 'docker-run', label: 'Docker Run' },
            { id: 'docker-compose', label: 'Docker Compose' },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              style={{
                padding: '6px 14px', fontSize: 12, fontWeight: 500, cursor: 'pointer',
                border: '1px solid var(--border)', borderBottom: activeTab === tab.id ? '2px solid var(--accent)' : '1px solid var(--border)',
                background: activeTab === tab.id ? 'var(--bg)' : 'transparent',
                color: activeTab === tab.id ? 'var(--accent)' : 'var(--text-muted)',
                borderRadius: tab.id === 'docker-run' ? '6px 0 0 0' : '0 6px 0 0',
              }}
            >
              {tab.label}
            </button>
          ))}
        </div>

        <div style={{ marginLeft: 32 }}>
          {activeTab === 'docker-run' && (
            <CodeBlock code={setup.docker_run} />
          )}
          {activeTab === 'docker-compose' && (
            <CodeBlock code={setup.docker_compose} />
          )}
          <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: '8px 0 0' }}>
            Replace <code>&lt;your-agent-token&gt;</code> with the token from step 1, and <code>&lt;your-hakuna-host&gt;</code> with your Hakuna domain.
          </p>
        </div>
      </Card>

      {/* Step 3: Configure Credentials */}
      {setup.credentials_mode === 'agent_local' && (
        <Card style={{ padding: 20, marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
            <div style={{
              width: 24, height: 24, borderRadius: '50%', background: 'var(--accent)',
              color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 12, fontWeight: 700, flexShrink: 0,
            }}>3</div>
            <h3 style={{ fontSize: 14, fontWeight: 600, margin: 0, color: 'var(--text)' }}>Configure On-Prem Credentials</h3>
          </div>
          <p style={{ fontSize: 13, color: 'var(--text-muted)', margin: '0 0 12px 32px' }}>
            Add environment variables for each on-prem product. Credentials stay on the agent and are never sent to Hakuna cloud.
          </p>

          <div style={{ marginLeft: 32, display: 'flex', flexDirection: 'column', gap: 4 }}>
            {(setup.product_examples || []).map(product => {
              const isOpen = expandedProduct === product.product
              return (
                <div key={product.product} style={{ border: '1px solid var(--border)', borderRadius: 8 }}>
                  <button
                    onClick={() => setExpandedProduct(isOpen ? null : product.product)}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 8, width: '100%',
                      padding: '10px 12px', border: 'none', background: 'transparent',
                      cursor: 'pointer', textAlign: 'left',
                    }}
                  >
                    {isOpen ? <ChevronDown size={14} color="var(--text-muted)" /> : <ChevronRight size={14} color="var(--text-muted)" />}
                    <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--text)' }}>{product.product}</span>
                  </button>
                  {isOpen && (
                    <div style={{ padding: '0 12px 12px 34px' }}>
                      <CodeBlock code={product.vars.map(v => `${v.name}=${v.example}`).join('\n')} />
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </Card>
      )}

      {/* Step 4: Verify */}
      <Card style={{ padding: 20, marginBottom: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
          <div style={{
            width: 24, height: 24, borderRadius: '50%', background: 'var(--accent)',
            color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 12, fontWeight: 700, flexShrink: 0,
          }}>{setup.credentials_mode === 'agent_local' ? '4' : '3'}</div>
          <h3 style={{ fontSize: 14, fontWeight: 600, margin: 0, color: 'var(--text)' }}>Verify Connection</h3>
        </div>
        <div style={{ marginLeft: 32, fontSize: 13, color: 'var(--text-muted)', lineHeight: 1.8 }}>
          <p style={{ margin: '0 0 8px' }}>
            Once the container starts, it will connect to Hakuna automatically. Check the agent status:
          </p>
          <ul style={{ margin: 0, paddingLeft: 20 }}>
            <li>The agent should show as <span style={{ color: '#22c55e', fontWeight: 600 }}>Connected</span> in the list above</li>
            <li>Check container logs: <code style={{ fontSize: 11 }}>docker logs hakuna-relay-agent</code></li>
            <li>Create an integration in the Integration Builder and select this relay agent</li>
          </ul>
        </div>
      </Card>

      {/* Env var reference */}
      <Card style={{ padding: 20, marginBottom: 16 }}>
        <h3 style={{ fontSize: 14, fontWeight: 600, margin: '0 0 12px', color: 'var(--text)' }}>Environment Variable Reference</h3>
        <div style={{ overflow: 'auto' }}>
          <table style={{ width: '100%', fontSize: 12, borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                <th style={{ textAlign: 'left', padding: '6px 8px', color: 'var(--text-muted)', fontWeight: 600 }}>Variable</th>
                <th style={{ textAlign: 'left', padding: '6px 8px', color: 'var(--text-muted)', fontWeight: 600 }}>Required</th>
                <th style={{ textAlign: 'left', padding: '6px 8px', color: 'var(--text-muted)', fontWeight: 600 }}>Description</th>
              </tr>
            </thead>
            <tbody>
              {(setup.env_vars || []).map(v => (
                <tr key={v.name} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '6px 8px' }}><code style={{ fontSize: 11 }}>{v.name}</code></td>
                  <td style={{ padding: '6px 8px', color: v.required ? 'var(--danger, #ef4444)' : 'var(--text-muted)' }}>{v.required ? 'Yes' : 'No'}</td>
                  <td style={{ padding: '6px 8px', color: 'var(--text-muted)' }}>{v.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  )
}
