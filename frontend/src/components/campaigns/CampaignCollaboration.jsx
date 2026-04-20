/**
 * Public, passcode-gated campaign collaboration page at /c/:shareToken.
 *
 * Lives OUTSIDE the authenticated MainShell — no sidebar, no org context,
 * no JWT. Uses only the `guest_session` HttpOnly cookie set by the backend's
 * /unlock endpoint.
 *
 * Flow:
 *   1. Load meta (campaign name + inviting org)
 *   2. Show unlock screen → user enters passcode
 *   3. On success, load full campaign payload + activity feed
 *   4. Poll activity every 10s; post comments via the activity endpoint
 */
import React, { useCallback, useEffect, useRef, useState } from 'react'
import { useParams } from 'react-router-dom'
import {
  Shield, Lock, AlertCircle, MessageCircle, Send, User,
  Bot, Clock,
} from 'lucide-react'
import {
  publicCampaignMeta, publicCampaignUnlock,
  publicCampaignGet, publicCampaignActivityList, publicCampaignActivityPost,
} from '../../api.js'

// Kept local to avoid pulling App.jsx into this route's bundle.
function HakunaLogo({ size = 22, style }) {
  const scale = size / 65
  return (
    <svg width={size} height={Math.round(44 * scale)} viewBox="0 0 65 44"
      fill="none" xmlns="http://www.w3.org/2000/svg" aria-label="Hakuna" style={style}>
      <path d="M30.7181 4.27637L26.7728 19H30.4495V25H25.1653L22.4788 35.0273C21.1397 40.0248 16.6106 43.5 11.4368 43.5C3.92067 43.4999 -1.54952 36.3704 0.395817 29.1104L0.671208 28.0791C2.10629 22.7237 6.95988 19 12.5042 19H20.5618L24.9232 2.72363L30.7181 4.27637ZM53.4612 0C60.9775 0 66.4486 7.1295 64.5032 14.3896L64.2269 15.4209C62.7918 20.7761 57.939 24.4998 52.3948 24.5H44.3372L39.9759 40.7764L34.18 39.2236L38.1253 24.5H34.4495V18.5H39.7327L42.4202 8.47266C43.7593 3.47531 48.2876 0.000201552 53.4612 0ZM12.5042 25C9.67544 25 7.19925 26.9004 6.46711 29.6328L6.19074 30.6631C5.26649 34.1124 7.86583 37.4999 11.4368 37.5C13.895 37.5 16.0467 35.849 16.6829 33.4746L18.9544 25H12.5042ZM53.4612 6C51.0033 6.0002 48.8524 7.65123 48.2161 10.0254L45.9446 18.5H52.3948C55.2235 18.4998 57.6998 16.5995 58.4319 13.8672L58.7073 12.8369C59.6316 9.38749 57.0324 6 53.4612 6Z"
        fill="currentColor" />
    </svg>
  )
}

// ─── Shared primitives (kept local — this page mounts without the shell) ─

const shellStyle = {
  minHeight: '100vh',
  background: 'var(--bg-muted)',
  color: 'var(--text)',
  display: 'flex',
  flexDirection: 'column',
}

const headerStyle = {
  display: 'flex', alignItems: 'center', gap: 12,
  padding: '14px 20px',
  borderBottom: '1px solid var(--border)',
  background: 'var(--bg-card)',
}

const Card = ({ children, style = {} }) => (
  <div style={{
    background: 'var(--bg-card)',
    border: '1px solid var(--border)',
    borderRadius: 10,
    padding: 20,
    ...style,
  }}>{children}</div>
)

const Button = ({ children, onClick, disabled, variant = 'primary', style = {}, type = 'button' }) => (
  <button
    type={type}
    onClick={disabled ? undefined : onClick}
    disabled={disabled}
    style={{
      display: 'inline-flex', alignItems: 'center', gap: 6,
      padding: '8px 16px', borderRadius: 6, fontSize: 13, fontWeight: 600,
      border: variant === 'ghost' ? '1px solid var(--border)' : 'none',
      background: variant === 'ghost' ? 'var(--bg-card)' : 'var(--primary)',
      color: variant === 'ghost' ? 'var(--text)' : 'var(--primary-foreground)',
      cursor: disabled ? 'not-allowed' : 'pointer',
      opacity: disabled ? 0.5 : 1,
      transition: 'all 0.15s',
      ...style,
    }}>
    {children}
  </button>
)

// ─── Brand header ────────────────────────────────────────────────────────

function BrandHeader({ campaignName, invitedByOrgName }) {
  return (
    <header style={headerStyle}>
      <HakunaLogo size={22} style={{ display: 'block', flexShrink: 0 }} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 13, fontWeight: 800 }}>
          {campaignName || 'Campaign collaboration'}
        </div>
        {invitedByOrgName && (
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            Invited by {invitedByOrgName} via Hakuna
          </div>
        )}
      </div>
      <Shield size={16} color="var(--text-muted)" title="Secure, passcode-gated" />
    </header>
  )
}

// ─── Unlock ─────────────────────────────────────────────────────────────

function Unlock({ token, meta, onUnlocked }) {
  const [passcode, setPasscode] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)

  const onSubmit = async (e) => {
    e.preventDefault()
    setSubmitting(true)
    setError(null)
    try {
      await publicCampaignUnlock(token, passcode.trim())
      onUnlocked()
    } catch (err) {
      setError(err?.message || 'Incorrect passcode')
      setPasscode('')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div style={{
      flex: 1, display: 'grid', placeItems: 'center', padding: 20,
    }}>
      <Card style={{ width: '100%', maxWidth: 440 }}>
        <div style={{ textAlign: 'center', marginBottom: 20 }}>
          <div style={{
            width: 48, height: 48, borderRadius: 12,
            background: 'color-mix(in srgb, var(--primary) 10%, transparent)',
            color: 'var(--primary)',
            display: 'grid', placeItems: 'center', margin: '0 auto 10px',
          }}>
            <Lock size={22} />
          </div>
          <h1 style={{ fontSize: 18, fontWeight: 700, margin: 0, color: 'var(--text)' }}>
            Enter passcode
          </h1>
          <p style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 6, marginBottom: 0 }}>
            {meta?.invited_by_org_name
              ? <>{meta.invited_by_org_name} invited you to collaborate on <strong>{meta.campaign_name}</strong>.</>
              : 'This page is passcode-protected.'}
          </p>
        </div>

        {meta?.locked_out && (
          <div style={{
            display: 'flex', gap: 8, alignItems: 'flex-start',
            padding: 10, borderRadius: 8,
            background: 'var(--warning-subtle)',
            border: '1px solid var(--warning)',
            color: 'var(--warning)',
            fontSize: 12, marginBottom: 14,
          }}>
            <AlertCircle size={14} style={{ flexShrink: 0, marginTop: 1 }} />
            <div>Too many failed attempts. Please wait a few minutes and try again.</div>
          </div>
        )}

        <form onSubmit={onSubmit}>
          <input
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            autoFocus
            value={passcode}
            onChange={e => setPasscode(e.target.value)}
            placeholder="6-digit passcode"
            style={{
              width: '100%',
              padding: '12px 14px',
              borderRadius: 8,
              border: '1px solid var(--border)',
              background: 'var(--bg-card)',
              color: 'var(--text)',
              fontSize: 18, letterSpacing: '0.18em', textAlign: 'center',
              fontFamily: 'var(--mono, monospace)',
              outline: 'none', boxSizing: 'border-box',
              marginBottom: 14,
            }}
          />
          {error && (
            <div style={{ color: 'var(--danger)', fontSize: 12, marginBottom: 12, textAlign: 'center' }}>
              {error}
            </div>
          )}
          <Button type="submit" disabled={submitting || !passcode.trim()} style={{ width: '100%', justifyContent: 'center' }}>
            {submitting ? 'Unlocking…' : 'Unlock'}
          </Button>
        </form>
      </Card>
    </div>
  )
}

// ─── Unlocked view ──────────────────────────────────────────────────────

function formatTime(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  const now = new Date()
  const sameDay = d.toDateString() === now.toDateString()
  if (sameDay) return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  return d.toLocaleDateString([], { month: 'short', day: 'numeric' }) +
         ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

function ActivityItem({ entry }) {
  const isExternal = entry.author_type === 'external'
  const isAgent = entry.author_type === 'agent'
  const isSystem = entry.author_type === 'system'
  const color = isSystem ? 'var(--text-muted)'
              : isAgent ? 'var(--primary)'
              : isExternal ? 'var(--success)'
              : 'var(--text)'
  const Icon = isAgent ? Bot : isSystem ? Clock : isExternal ? User : User
  return (
    <div style={{ padding: '10px 0', borderBottom: '1px solid var(--border)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
        <div style={{
          width: 22, height: 22, borderRadius: 4, color,
          display: 'grid', placeItems: 'center', flexShrink: 0,
          background: 'color-mix(in srgb, currentColor 12%, transparent)',
        }}>
          <Icon size={12} />
        </div>
        <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text)' }}>
          {entry.author_display_name || 'Unknown'}
        </div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
          {formatTime(entry.created_at)}
        </div>
      </div>
      <div style={{ fontSize: 13, color: 'var(--text)', whiteSpace: 'pre-wrap', paddingLeft: 30 }}>
        {entry.body}
      </div>
    </div>
  )
}

function UnlockedView({ token, payload }) {
  const [activity, setActivity] = useState([])
  const [input, setInput] = useState('')
  const [sending, setSending] = useState(false)
  const [error, setError] = useState(null)
  const scrollRef = useRef(null)

  const loadActivity = useCallback(async () => {
    try {
      const r = await publicCampaignActivityList(token)
      setActivity(r.activity || [])
    } catch (e) {
      // Non-fatal — older activity is cached
    }
  }, [token])

  useEffect(() => {
    loadActivity()
    const t = setInterval(loadActivity, 10_000)
    return () => clearInterval(t)
  }, [loadActivity])

  useEffect(() => {
    // Scroll to bottom on new activity
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [activity.length])

  const send = async (e) => {
    e.preventDefault()
    const body = input.trim()
    if (!body) return
    setSending(true)
    setError(null)
    try {
      const entry = await publicCampaignActivityPost(token, { body, kind: 'comment' })
      setActivity(cur => [...cur, entry])
      setInput('')
    } catch (err) {
      setError(err?.message || 'Failed to send')
    } finally {
      setSending(false)
    }
  }

  const findings = payload.findings || []
  const canComment = (payload.permissions || {}).comment !== false

  return (
    <div style={{
      flex: 1,
      display: 'grid',
      gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)',
      gap: 16, padding: 16,
    }}>
      {/* LEFT: campaign overview + findings */}
      <Card style={{ overflow: 'auto' }}>
        <div style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', marginBottom: 6 }}>
          Campaign
        </div>
        <h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text)', margin: '0 0 8px' }}>
          {payload.campaign.name}
        </h2>
        {payload.campaign.description && (
          <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.5, marginTop: 0 }}>
            {payload.campaign.description}
          </p>
        )}

        <div style={{ marginTop: 16 }}>
          <div style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', marginBottom: 10 }}>
            Findings ({findings.length})
          </div>
          {findings.length === 0 ? (
            <div style={{ fontSize: 13, color: 'var(--text-muted)', padding: '12px 0' }}>
              No findings scoped to this campaign yet.
            </div>
          ) : findings.slice(0, 50).map(f => (
            <div key={f.id} style={{
              padding: '8px 0',
              borderBottom: '1px solid var(--border)',
              fontSize: 13,
            }}>
              <div style={{ fontWeight: 600, color: 'var(--text)' }}>
                {f.plugin_name || '(untitled finding)'}
              </div>
              {f.severity_label && (
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                  Severity: {f.severity_label}
                </div>
              )}
            </div>
          ))}
        </div>
      </Card>

      {/* RIGHT: activity feed */}
      <Card style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden', padding: 0 }}>
        <div style={{
          padding: '12px 16px', borderBottom: '1px solid var(--border)',
          display: 'flex', alignItems: 'center', gap: 8,
        }}>
          <MessageCircle size={16} color="var(--text-muted)" />
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)' }}>
            Activity
          </div>
        </div>

        <div ref={scrollRef} style={{
          flex: 1, overflowY: 'auto', padding: '4px 16px', minHeight: 360,
        }}>
          {activity.length === 0 ? (
            <div style={{
              textAlign: 'center', color: 'var(--text-muted)', fontSize: 13,
              padding: '40px 20px',
            }}>
              No activity yet. Say hi!
            </div>
          ) : activity.map(a => <ActivityItem key={a.id} entry={a} />)}
        </div>

        {canComment && (
          <form onSubmit={send} style={{
            padding: 12, borderTop: '1px solid var(--border)',
            display: 'flex', gap: 8,
          }}>
            <input
              value={input}
              onChange={e => setInput(e.target.value)}
              placeholder="Write a comment…"
              disabled={sending}
              style={{
                flex: 1, padding: '10px 12px', borderRadius: 6,
                border: '1px solid var(--border)',
                background: 'var(--bg-card)',
                color: 'var(--text)', fontSize: 13,
                outline: 'none',
              }}
            />
            <Button type="submit" disabled={sending || !input.trim()}>
              <Send size={13} />
            </Button>
          </form>
        )}
        {error && (
          <div style={{
            padding: '6px 16px', color: 'var(--danger)', fontSize: 12,
          }}>
            {error}
          </div>
        )}
      </Card>
    </div>
  )
}

// ─── Page ──────────────────────────────────────────────────────────────

export default function CampaignCollaboration() {
  const { shareToken } = useParams()
  const [meta, setMeta] = useState(null)
  const [metaError, setMetaError] = useState(null)
  const [unlocked, setUnlocked] = useState(false)
  const [payload, setPayload] = useState(null)
  const [payloadError, setPayloadError] = useState(null)

  useEffect(() => {
    publicCampaignMeta(shareToken)
      .then(setMeta)
      .catch(err => setMetaError(err?.message || 'Invalid link'))
  }, [shareToken])

  // Optimistic: try to load the full payload — if we still have a valid guest
  // cookie from a previous visit, we skip the unlock screen.
  useEffect(() => {
    if (!meta) return
    publicCampaignGet(shareToken)
      .then(p => { setPayload(p); setUnlocked(true) })
      .catch(() => { /* expected before unlock */ })
  }, [meta, shareToken])

  const handleUnlocked = async () => {
    try {
      const p = await publicCampaignGet(shareToken)
      setPayload(p)
      setUnlocked(true)
    } catch (err) {
      setPayloadError(err?.message || 'Failed to load campaign after unlock')
    }
  }

  if (metaError) {
    return (
      <div style={shellStyle}>
        <BrandHeader />
        <div style={{ flex: 1, display: 'grid', placeItems: 'center', padding: 20 }}>
          <Card style={{ maxWidth: 400, textAlign: 'center' }}>
            <div style={{ fontSize: 16, fontWeight: 600, marginBottom: 8, color: 'var(--text)' }}>
              Link unavailable
            </div>
            <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
              {metaError}
            </div>
          </Card>
        </div>
      </div>
    )
  }

  if (!meta) {
    return (
      <div style={shellStyle}>
        <BrandHeader />
        <div style={{ flex: 1, display: 'grid', placeItems: 'center' }}>
          <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>Loading…</div>
        </div>
      </div>
    )
  }

  return (
    <div style={shellStyle}>
      <BrandHeader
        campaignName={unlocked && payload ? payload.campaign.name : meta.campaign_name}
        invitedByOrgName={meta.invited_by_org_name}
      />
      {unlocked && payload ? (
        <UnlockedView token={shareToken} payload={payload} />
      ) : (
        <Unlock token={shareToken} meta={meta} onUnlocked={handleUnlocked} />
      )}
      {payloadError && (
        <div style={{ padding: 20, color: 'var(--danger)', fontSize: 13, textAlign: 'center' }}>
          {payloadError}
        </div>
      )}
    </div>
  )
}
