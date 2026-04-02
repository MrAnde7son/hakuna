import React, { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useAuth } from '../../contexts/AuthContext.jsx'
import GoogleSignInButton from './GoogleSignInButton.jsx'

function HakunaLogo({ size = 40 }) {
  const scale = size / 65
  return (
    <svg width={size} height={Math.round(44 * scale)} viewBox="0 0 65 44" fill="none" xmlns="http://www.w3.org/2000/svg" aria-label="Hakuna">
      <path d="M30.7181 4.27637L26.7728 19H30.4495V25H25.1653L22.4788 35.0273C21.1397 40.0248 16.6106 43.5 11.4368 43.5C3.92067 43.4999 -1.54952 36.3704 0.395817 29.1104L0.671208 28.0791C2.10629 22.7237 6.95988 19 12.5042 19H20.5618L24.9232 2.72363L30.7181 4.27637ZM53.4612 0C60.9775 0 66.4486 7.1295 64.5032 14.3896L64.2269 15.4209C62.7918 20.7761 57.939 24.4998 52.3948 24.5H44.3372L39.9759 40.7764L34.18 39.2236L38.1253 24.5H34.4495V18.5H39.7327L42.4202 8.47266C43.7593 3.47531 48.2876 0.000201552 53.4612 0ZM12.5042 25C9.67544 25 7.19925 26.9004 6.46711 29.6328L6.19074 30.6631C5.26649 34.1124 7.86583 37.4999 11.4368 37.5C13.895 37.5 16.0467 35.849 16.6829 33.4746L18.9544 25H12.5042ZM53.4612 6C51.0033 6.0002 48.8524 7.65123 48.2161 10.0254L45.9446 18.5H52.3948C55.2235 18.4998 57.6998 16.5995 58.4319 13.8672L58.7073 12.8369C59.6316 9.38749 57.0324 6 53.4612 6Z" fill="#590202" />
    </svg>
  )
}

export default function Register() {
  const [orgName, setOrgName] = useState('')
  const [email, setEmail] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const { register } = useAuth()
  const navigate = useNavigate()
  const { t } = useTranslation()

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    if (password !== confirmPassword) {
      setError(t('auth.passwordsMismatch'))
      return
    }
    if (password.length < 8) {
      setError(t('auth.passwordTooShort'))
      return
    }
    setLoading(true)
    try {
      const data = await register(orgName, email, password, displayName)
      if (data?.user?.email_verified === false) {
        navigate('/verify-email')
      } else {
        navigate('/onboarding')
      }
    } catch (err) {
      setError(err.message || t('auth.registrationFailed'))
    } finally {
      setLoading(false)
    }
  }

  const inputStyle = {
    width: '100%',
    padding: '8px 12px',
    borderRadius: 8,
    border: '1px solid var(--border)',
    fontSize: 14,
    boxSizing: 'border-box',
  }

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'var(--bg-muted, #f4f4f5)',
    }}>
      <div style={{
        width: 420,
        background: 'var(--bg-card)',
        borderRadius: 12,
        border: '1px solid var(--border)',
        padding: 32,
        boxShadow: '0 4px 24px rgba(0,0,0,0.06)',
      }}>
        <div style={{ textAlign: 'center', marginBottom: 24 }}>
          <HakunaLogo size={40} />
          <h1 style={{ fontSize: 20, fontWeight: 700, margin: 0 }}>{t('auth.createYourAccount')}</h1>
          <p style={{ fontSize: 13, color: 'var(--muted, #71717a)', marginTop: 4 }}>
            {t('auth.setupOrg')}
          </p>
        </div>

        <GoogleSignInButton />

        <div style={{
          display: 'flex', alignItems: 'center', gap: 12, margin: '16px 0',
          color: 'var(--muted, #71717a)', fontSize: 13,
        }}>
          <div style={{ flex: 1, height: 1, background: 'var(--border)' }} />
          or
          <div style={{ flex: 1, height: 1, background: 'var(--border)' }} />
        </div>

        <form onSubmit={handleSubmit}>
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

          <div style={{ marginBottom: 14 }}>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4 }}>{t('auth.orgName')}</label>
            <input
              type="text"
              value={orgName}
              onChange={e => setOrgName(e.target.value)}
              required
              autoFocus
              placeholder="Acme Corp"
              style={inputStyle}
            />
          </div>

          <div style={{ marginBottom: 14 }}>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4 }}>{t('auth.yourName')}</label>
            <input
              type="text"
              value={displayName}
              onChange={e => setDisplayName(e.target.value)}
              placeholder="Jane Smith"
              style={inputStyle}
            />
          </div>

          <div style={{ marginBottom: 14 }}>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4 }}>{t('auth.email')}</label>
            <input
              type="email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              required
              placeholder="you@example.com"
              style={inputStyle}
            />
          </div>

          <div style={{ marginBottom: 14 }}>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4 }}>{t('auth.password')}</label>
            <input
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              required
              placeholder={t('auth.minChars')}
              style={inputStyle}
            />
          </div>

          <div style={{ marginBottom: 20 }}>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4 }}>{t('auth.confirmPassword')}</label>
            <input
              type="password"
              value={confirmPassword}
              onChange={e => setConfirmPassword(e.target.value)}
              required
              style={inputStyle}
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            style={{
              width: '100%',
              padding: '10px 0',
              borderRadius: 8,
              border: 'none',
              background: 'var(--nav-active-bg)',
              color: 'var(--nav-active-text)',
              fontSize: 14,
              fontWeight: 600,
              cursor: loading ? 'not-allowed' : 'pointer',
              opacity: loading ? 0.6 : 1,
            }}
          >
            {loading ? t('auth.creatingAccount') : t('auth.createAccount')}
          </button>
        </form>

        <div style={{ textAlign: 'center', marginTop: 16, fontSize: 13, color: 'var(--muted, #71717a)' }}>
          {t('auth.hasAccount')}{' '}
          <Link to="/login" style={{ color: 'var(--text-primary)', fontWeight: 600, textDecoration: 'none' }}>
            {t('auth.signIn')}
          </Link>
        </div>
      </div>
    </div>
  )
}
