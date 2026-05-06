import React, { useEffect, useState } from 'react'
import { Key, Copy, Check, Trash2, Plus, X } from 'lucide-react'
import { listApiTokens, createApiToken, revokeApiToken } from '../../api.js'

const SCOPE_OPTIONS = [
  { value: 'mcp:read',  label: 'MCP read',   help: 'Read findings, assets, campaigns via MCP' },
  { value: 'mcp:write', label: 'MCP write',  help: 'Reserved for future write tools (currently no-op)' },
  { value: 'api:read',  label: 'REST read',  help: 'Read access to /api/* endpoints' },
  { value: 'api:write', label: 'REST write', help: 'Write access to /api/* endpoints' },
]

const fmtDate = (iso) => iso ? new Date(iso).toLocaleString() : '—'

function CopyBox({ value, label }) {
  const [copied, setCopied] = useState(false)
  return (
    <div style={{ display: 'flex', alignItems: 'stretch', border: '1px solid var(--border)', borderRadius: 6, overflow: 'hidden' }}>
      <pre style={{
        flex: 1, margin: 0, padding: '10px 12px', fontSize: 12, lineHeight: 1.5,
        fontFamily: 'ui-monospace, SFMono-Regular, monospace', background: 'var(--bg-subtle)',
        color: 'var(--text)', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
      }}>
        {value}
      </pre>
      <button
        onClick={async () => {
          await navigator.clipboard.writeText(value)
          setCopied(true)
          setTimeout(() => setCopied(false), 1500)
        }}
        title={`Copy ${label || ''}`.trim()}
        style={{
          padding: '0 14px', border: 'none', borderLeft: '1px solid var(--border)',
          background: 'var(--bg)', color: copied ? 'var(--success, #10b981)' : 'var(--text-muted)',
          cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4, fontSize: 12,
        }}
      >
        {copied ? <Check size={14} /> : <Copy size={14} />} {copied ? 'Copied' : 'Copy'}
      </button>
    </div>
  )
}

function CreatedTokenView({ created, orgId, baseUrl, onClose }) {
  const mcpConfig = JSON.stringify({
    mcpServers: {
      hakuna: {
        url: `${baseUrl}/api/mcp`,
        headers: {
          Authorization: `Bearer ${created.token}`,
          'X-Org-Context': String(orgId),
        },
      },
    },
  }, null, 2)

  return (
    <div style={{
      border: '1px solid rgba(16,185,129,0.4)', background: 'rgba(16,185,129,0.06)',
      borderRadius: 8, padding: 16, marginBottom: 16,
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
        <strong style={{ fontSize: 14, color: 'var(--text)' }}>Token created — copy it now</strong>
        <button onClick={onClose} style={{ border: 'none', background: 'transparent', cursor: 'pointer', color: 'var(--text-muted)' }}>
          <X size={16} />
        </button>
      </div>
      <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: '0 0 12px' }}>
        This is the only time you'll see the plaintext. Store it in a secret manager.
      </p>

      <div style={{ marginBottom: 12 }}>
        <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 6 }}>
          Token
        </div>
        <CopyBox value={created.token} label="token" />
      </div>

      <div>
        <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 6 }}>
          MCP client config (Claude Desktop, Cursor, etc.)
        </div>
        <CopyBox value={mcpConfig} label="MCP config" />
      </div>
    </div>
  )
}

function CreateTokenForm({ onCreated, onCancel }) {
  const [name, setName] = useState('')
  const [scopes, setScopes] = useState(['mcp:read'])
  const [expiresInDays, setExpiresInDays] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)

  const toggle = (scope) => {
    setScopes(prev => prev.includes(scope) ? prev.filter(s => s !== scope) : [...prev, scope])
  }

  const submit = async () => {
    setError(null)
    if (!name.trim()) { setError('Name is required'); return }
    if (scopes.length === 0) { setError('Pick at least one scope'); return }
    setSubmitting(true)
    try {
      const body = { name: name.trim(), scopes }
      if (expiresInDays) body.expires_in_days = Number(expiresInDays)
      const created = await createApiToken(body)
      onCreated(created)
    } catch (e) {
      setError(e.message || 'Failed to create token')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 8, padding: 16, marginBottom: 16, background: 'var(--bg)' }}>
      <strong style={{ fontSize: 14, color: 'var(--text)' }}>New API token</strong>
      <div style={{ marginTop: 12 }}>
        <label style={{ display: 'block', fontSize: 12, color: 'var(--text-muted)', marginBottom: 4 }}>Name</label>
        <input
          value={name}
          onChange={e => setName(e.target.value)}
          placeholder="claude-desktop, ci-runner, …"
          style={{
            width: '100%', padding: '7px 10px', border: '1px solid var(--border)',
            borderRadius: 6, fontSize: 13, background: 'var(--bg)', color: 'var(--text)',
          }}
        />
      </div>
      <div style={{ marginTop: 12 }}>
        <label style={{ display: 'block', fontSize: 12, color: 'var(--text-muted)', marginBottom: 4 }}>Scopes</label>
        {SCOPE_OPTIONS.map(opt => (
          <label key={opt.value} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 0', fontSize: 13, color: 'var(--text)', cursor: 'pointer' }}>
            <input type="checkbox" checked={scopes.includes(opt.value)} onChange={() => toggle(opt.value)} />
            <span style={{ fontFamily: 'ui-monospace, monospace', fontSize: 12 }}>{opt.value}</span>
            <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>— {opt.help}</span>
          </label>
        ))}
      </div>
      <div style={{ marginTop: 12 }}>
        <label style={{ display: 'block', fontSize: 12, color: 'var(--text-muted)', marginBottom: 4 }}>Expires in (days, optional)</label>
        <input
          type="number" min="1" max="1825"
          value={expiresInDays}
          onChange={e => setExpiresInDays(e.target.value)}
          placeholder="leave blank for no expiry"
          style={{
            width: 240, padding: '7px 10px', border: '1px solid var(--border)',
            borderRadius: 6, fontSize: 13, background: 'var(--bg)', color: 'var(--text)',
          }}
        />
      </div>
      {error && <div style={{ marginTop: 12, color: 'var(--danger, #ef4444)', fontSize: 12 }}>{error}</div>}
      <div style={{ marginTop: 16, display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
        <button
          onClick={onCancel}
          disabled={submitting}
          style={{
            padding: '7px 14px', borderRadius: 6, fontSize: 13,
            border: '1px solid var(--border)', background: 'transparent',
            color: 'var(--text-muted)', cursor: submitting ? 'not-allowed' : 'pointer',
          }}
        >
          Cancel
        </button>
        <button
          onClick={submit}
          disabled={submitting}
          style={{
            padding: '7px 14px', borderRadius: 6, fontSize: 13, fontWeight: 500,
            border: 'none', background: 'var(--accent)', color: 'white',
            cursor: submitting ? 'not-allowed' : 'pointer',
          }}
        >
          {submitting ? 'Creating…' : 'Create token'}
        </button>
      </div>
    </div>
  )
}

export default function ApiTokensPanel() {
  const [tokens, setTokens] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [showForm, setShowForm] = useState(false)
  const [created, setCreated] = useState(null)

  const orgId = (() => {
    try { return localStorage.getItem('org_context') || '' } catch { return '' }
  })()
  const baseUrl = typeof window !== 'undefined' ? window.location.origin : ''

  const reload = () => {
    setLoading(true)
    listApiTokens()
      .then(data => setTokens(data.tokens || []))
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }

  useEffect(reload, [])

  const onRevoke = async (id) => {
    if (!window.confirm('Revoke this token? Any clients using it will fail to authenticate.')) return
    try {
      await revokeApiToken(id)
      reload()
    } catch (e) {
      alert(`Failed to revoke: ${e.message}`)
    }
  }

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Key size={16} color="var(--accent)" />
          <span style={{ fontSize: 15, fontWeight: 600, color: 'var(--text)' }}>API Tokens</span>
        </div>
        {!showForm && !created && (
          <button
            onClick={() => setShowForm(true)}
            style={{
              display: 'inline-flex', alignItems: 'center', gap: 6, padding: '7px 14px',
              borderRadius: 6, fontSize: 13, fontWeight: 500, border: 'none',
              background: 'var(--accent)', color: 'white', cursor: 'pointer',
            }}
          >
            <Plus size={13} /> New token
          </button>
        )}
      </div>

      <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: '0 0 16px', maxWidth: 640 }}>
        Long-lived bearer credentials for programmatic access. Use these to connect MCP clients
        (Claude Desktop, Cursor) or scripts that call the REST API. Tokens inherit your role and org context.
      </p>

      {created && (
        <CreatedTokenView
          created={created}
          orgId={orgId}
          baseUrl={baseUrl}
          onClose={() => { setCreated(null); reload() }}
        />
      )}

      {showForm && (
        <CreateTokenForm
          onCreated={(c) => { setShowForm(false); setCreated(c) }}
          onCancel={() => setShowForm(false)}
        />
      )}

      {error && <div style={{ color: 'var(--danger, #ef4444)', fontSize: 12, marginBottom: 12 }}>{error}</div>}

      {loading ? (
        <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>Loading…</div>
      ) : tokens.length === 0 ? (
        <div style={{
          padding: 32, textAlign: 'center', border: '1px dashed var(--border)',
          borderRadius: 8, color: 'var(--text-muted)', fontSize: 13,
        }}>
          No tokens yet.
        </div>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)', textAlign: 'left' }}>
              <th style={{ padding: '8px 4px', fontWeight: 600, color: 'var(--text-muted)' }}>Name</th>
              <th style={{ padding: '8px 4px', fontWeight: 600, color: 'var(--text-muted)' }}>Prefix</th>
              <th style={{ padding: '8px 4px', fontWeight: 600, color: 'var(--text-muted)' }}>Scopes</th>
              <th style={{ padding: '8px 4px', fontWeight: 600, color: 'var(--text-muted)' }}>Created</th>
              <th style={{ padding: '8px 4px', fontWeight: 600, color: 'var(--text-muted)' }}>Last used</th>
              <th style={{ padding: '8px 4px', fontWeight: 600, color: 'var(--text-muted)' }}>Expires</th>
              <th style={{ padding: '8px 4px', fontWeight: 600, color: 'var(--text-muted)' }}>Status</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {tokens.map(t => (
              <tr key={t.id} style={{ borderBottom: '1px solid var(--border)' }}>
                <td style={{ padding: '10px 4px', color: 'var(--text)' }}>{t.name}</td>
                <td style={{ padding: '10px 4px', fontFamily: 'ui-monospace, monospace', color: 'var(--text-muted)' }}>
                  {t.token_prefix}…
                </td>
                <td style={{ padding: '10px 4px', color: 'var(--text-muted)' }}>{(t.scopes || []).join(', ')}</td>
                <td style={{ padding: '10px 4px', color: 'var(--text-muted)' }}>{fmtDate(t.created_at)}</td>
                <td style={{ padding: '10px 4px', color: 'var(--text-muted)' }}>{fmtDate(t.last_used_at)}</td>
                <td style={{ padding: '10px 4px', color: 'var(--text-muted)' }}>{fmtDate(t.expires_at)}</td>
                <td style={{ padding: '10px 4px' }}>
                  {t.revoked_at ? (
                    <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>Revoked</span>
                  ) : (
                    <span style={{ color: 'var(--success, #10b981)', fontSize: 11 }}>Active</span>
                  )}
                </td>
                <td style={{ padding: '10px 4px', textAlign: 'right' }}>
                  {!t.revoked_at && (
                    <button
                      onClick={() => onRevoke(t.id)}
                      title="Revoke"
                      style={{ border: 'none', background: 'transparent', cursor: 'pointer', color: 'var(--text-muted)' }}
                    >
                      <Trash2 size={14} />
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
