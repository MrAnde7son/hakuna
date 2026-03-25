import React, { useState, useEffect } from 'react'
import { Link, useSearchParams, useNavigate } from 'react-router-dom'
import { getInviteInfo, acceptInvite, setStoredToken } from '../../api.js'

function HakunaLogo({ size = 40 }) {
  const scale = size / 65
  return (
    <svg width={size} height={Math.round(44 * scale)} viewBox="0 0 65 44" fill="none" xmlns="http://www.w3.org/2000/svg" aria-label="Hakuna">
      <path d="M30.7181 4.27637L26.7728 19H30.4495V25H25.1653L22.4788 35.0273C21.1397 40.0248 16.6106 43.5 11.4368 43.5C3.92067 43.4999 -1.54952 36.3704 0.395817 29.1104L0.671208 28.0791C2.10629 22.7237 6.95988 19 12.5042 19H20.5618L24.9232 2.72363L30.7181 4.27637ZM53.4612 0C60.9775 0 66.4486 7.1295 64.5032 14.3896L64.2269 15.4209C62.7918 20.7761 57.939 24.4998 52.3948 24.5H44.3372L39.9759 40.7764L34.18 39.2236L38.1253 24.5H34.4495V18.5H39.7327L42.4202 8.47266C43.7593 3.47531 48.2876 0.000201552 53.4612 0ZM12.5042 25C9.67544 25 7.19925 26.9004 6.46711 29.6328L6.19074 30.6631C5.26649 34.1124 7.86583 37.4999 11.4368 37.5C13.895 37.5 16.0467 35.849 16.6829 33.4746L18.9544 25H12.5042ZM53.4612 6C51.0033 6.0002 48.8524 7.65123 48.2161 10.0254L45.9446 18.5H52.3948C55.2235 18.4998 57.6998 16.5995 58.4319 13.8672L58.7073 12.8369C59.6316 9.38749 57.0324 6 53.4612 6Z" fill="#590202" />
    </svg>
  )
}

const inputStyle = {
  width: '100%',
  padding: '8px 12px',
  borderRadius: 8,
  border: '1px solid var(--border, #e4e4e7)',
  fontSize: 14,
  boxSizing: 'border-box',
  background: 'var(--bg-card, #fff)',
  color: 'var(--text-primary, #1a1a1a)',
}

export default function AcceptInvite() {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const token = searchParams.get('token') || ''

  const [invite, setInvite] = useState(null)
  const [loadError, setLoadError] = useState('')
  const [loading, setLoading] = useState(true)

  const [form, setForm] = useState({
    org_name: '',
    admin_name: '',
    admin_email: '',
    password: '',
    confirm: '',
  })
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!token) {
      setLoadError('Missing invite token.')
      setLoading(false)
      return
    }
    getInviteInfo(token)
      .then(data => {
        setInvite(data)
        setForm(prev => ({
          ...prev,
          org_name: data.client_org_name || '',
          admin_email: data.invited_email || '',
        }))
      })
      .catch(err => setLoadError(err.message || 'Invalid or expired invite link.'))
      .finally(() => setLoading(false))
  }, [token])

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')

    if (form.password.length < 8) {
      setError('Password must be at least 8 characters')
      return
    }
    if (form.password !== form.confirm) {
      setError('Passwords do not match')
      return
    }

    setSubmitting(true)
    try {
      const data = await acceptInvite({
        token,
        org_name: form.org_name,
        admin_name: form.admin_name,
        admin_email: form.admin_email,
        password: form.password,
      })
      setStoredToken(data.access_token)
      navigate('/')
    } catch (err) {
      setError(err.message || 'Something went wrong')
    } finally {
      setSubmitting(false)
    }
  }

  const card = {
    width: 440,
    maxWidth: '95vw',
    background: 'var(--bg-card, #fff)',
    borderRadius: 12,
    border: '1px solid var(--border, #e4e4e7)',
    padding: 32,
    boxShadow: '0 4px 24px rgba(0,0,0,0.06)',
  }

  const outer = {
    minHeight: '100vh',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    background: 'var(--bg-muted, #f4f4f5)',
    padding: 16,
  }

  if (loading) {
    return (
      <div style={outer}>
        <div style={{ ...card, textAlign: 'center', color: 'var(--text-secondary)' }}>
          Validating invite…
        </div>
      </div>
    )
  }

  if (loadError) {
    return (
      <div style={outer}>
        <div style={{ ...card, textAlign: 'center' }}>
          <HakunaLogo size={36} />
          <p style={{ color: 'var(--danger, #dc2626)', marginTop: 16, marginBottom: 16 }}>{loadError}</p>
          <Link to="/login" style={{ color: 'var(--text-primary)', fontWeight: 600, fontSize: 14 }}>
            Back to sign in
          </Link>
        </div>
      </div>
    )
  }

  return (
    <div style={outer}>
      <div style={card}>
        <div style={{ textAlign: 'center', marginBottom: 24 }}>
          <HakunaLogo size={40} />
          <h1 style={{ fontSize: 20, fontWeight: 700, margin: '12px 0 4px' }}>
            You've been invited
          </h1>
          <p style={{ fontSize: 14, color: 'var(--text-secondary, #71717a)', margin: 0 }}>
            <strong>{invite?.mssp_org_name}</strong> invited you to Hakuna.
            Set up your organization below.
          </p>
        </div>

        {error && (
          <div style={{
            background: 'var(--danger-subtle)',
            color: 'var(--danger)',
            padding: '8px 12px',
            borderRadius: 6,
            fontSize: 13,
            marginBottom: 16,
            border: '1px solid var(--danger)',
          }}>
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4 }}>
              Organization name
            </label>
            <input
              type="text"
              value={form.org_name}
              onChange={e => setForm(p => ({ ...p, org_name: e.target.value }))}
              required
              placeholder="Acme Corp"
              style={inputStyle}
              autoFocus
            />
          </div>

          <div style={{ display: 'flex', gap: 10 }}>
            <div style={{ flex: 1 }}>
              <label style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4 }}>
                Your name
              </label>
              <input
                type="text"
                value={form.admin_name}
                onChange={e => setForm(p => ({ ...p, admin_name: e.target.value }))}
                required
                placeholder="Jane Smith"
                style={inputStyle}
              />
            </div>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4 }}>
              Work email
            </label>
            <input
              type="email"
              value={form.admin_email}
              onChange={e => setForm(p => ({ ...p, admin_email: e.target.value }))}
              required
              placeholder="jane@acme.com"
              style={inputStyle}
              readOnly={!!invite?.invited_email}
            />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4 }}>
              Password
            </label>
            <input
              type="password"
              value={form.password}
              onChange={e => setForm(p => ({ ...p, password: e.target.value }))}
              required
              placeholder="Min. 8 characters"
              style={inputStyle}
            />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4 }}>
              Confirm password
            </label>
            <input
              type="password"
              value={form.confirm}
              onChange={e => setForm(p => ({ ...p, confirm: e.target.value }))}
              required
              placeholder="Repeat your password"
              style={inputStyle}
            />
          </div>

          <button
            type="submit"
            disabled={submitting}
            style={{
              marginTop: 6,
              width: '100%',
              padding: '10px 0',
              borderRadius: 8,
              border: 'none',
              background: 'var(--nav-active-bg, #590202)',
              color: 'var(--nav-active-text, #fff)',
              fontSize: 14,
              fontWeight: 600,
              cursor: submitting ? 'not-allowed' : 'pointer',
              opacity: submitting ? 0.6 : 1,
            }}
          >
            {submitting ? 'Creating account…' : 'Create account'}
          </button>
        </form>

        <div style={{ textAlign: 'center', marginTop: 16, fontSize: 13, color: 'var(--text-secondary, #71717a)' }}>
          Already have an account?{' '}
          <Link to="/login" style={{ color: 'var(--text-primary)', fontWeight: 600, textDecoration: 'none' }}>
            Sign in
          </Link>
        </div>
      </div>
    </div>
  )
}
