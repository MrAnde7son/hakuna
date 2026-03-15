import React, { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useAuth } from '../../contexts/AuthContext.jsx'

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
      await register(orgName, email, password, displayName)
      navigate('/')
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
          <img src="/logo-symbol.svg" alt="Logo" style={{ width: 40, height: 40, marginBottom: 12 }} />
          <h1 style={{ fontSize: 20, fontWeight: 700, margin: 0 }}>{t('auth.createYourAccount')}</h1>
          <p style={{ fontSize: 13, color: 'var(--muted, #71717a)', marginTop: 4 }}>
            {t('auth.setupOrg')}
          </p>
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
