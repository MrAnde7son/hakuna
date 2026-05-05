import React, { useState, useEffect } from 'react'
import { useNavigate, Link, useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useAuth } from '../../contexts/AuthContext.jsx'
import GoogleSignInButton from './GoogleSignInButton.jsx'
import { samlDiscover } from '../../api.js'

function HakunaLogo({ size = 40 }) {
  const scale = size / 65
  return (
    <svg width={size} height={Math.round(44 * scale)} viewBox="0 0 65 44" fill="none" xmlns="http://www.w3.org/2000/svg" aria-label="Hakuna">
      <path d="M30.7181 4.27637L26.7728 19H30.4495V25H25.1653L22.4788 35.0273C21.1397 40.0248 16.6106 43.5 11.4368 43.5C3.92067 43.4999 -1.54952 36.3704 0.395817 29.1104L0.671208 28.0791C2.10629 22.7237 6.95988 19 12.5042 19H20.5618L24.9232 2.72363L30.7181 4.27637ZM53.4612 0C60.9775 0 66.4486 7.1295 64.5032 14.3896L64.2269 15.4209C62.7918 20.7761 57.939 24.4998 52.3948 24.5H44.3372L39.9759 40.7764L34.18 39.2236L38.1253 24.5H34.4495V18.5H39.7327L42.4202 8.47266C43.7593 3.47531 48.2876 0.000201552 53.4612 0ZM12.5042 25C9.67544 25 7.19925 26.9004 6.46711 29.6328L6.19074 30.6631C5.26649 34.1124 7.86583 37.4999 11.4368 37.5C13.895 37.5 16.0467 35.849 16.6829 33.4746L18.9544 25H12.5042ZM53.4612 6C51.0033 6.0002 48.8524 7.65123 48.2161 10.0254L45.9446 18.5H52.3948C55.2235 18.4998 57.6998 16.5995 58.4319 13.8672L58.7073 12.8369C59.6316 9.38749 57.0324 6 53.4612 6Z" fill="#590202" />
    </svg>
  )
}

export default function Login() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [ssoInfo, setSsoInfo] = useState(null)
  const [ssoChecking, setSsoChecking] = useState(false)
  const { login } = useAuth()
  const navigate = useNavigate()
  const { t } = useTranslation()
  const [searchParams] = useSearchParams()

  // Show SSO error from redirect
  useEffect(() => {
    const ssoError = searchParams.get('sso_error')
    if (ssoError) {
      const messages = {
        saml_validation_failed: 'SSO authentication failed. Please contact your administrator.',
        not_authenticated: 'SSO authentication was not completed.',
        no_email_in_assertion: 'No email found in SSO response. Check IdP attribute mapping.',
        user_not_found: 'No account found for your SSO identity. Contact your administrator.',
        account_deactivated: 'Your account has been deactivated.',
        org_not_found: 'Organization not found.',
      }
      setError(messages[ssoError] || `SSO error: ${ssoError}`)
    }
  }, [searchParams])

  // Check for SSO when email changes (debounced)
  useEffect(() => {
    if (!email || !email.includes('@') || email.split('@')[1].length < 3) {
      setSsoInfo(null)
      return
    }
    const timer = setTimeout(async () => {
      setSsoChecking(true)
      try {
        const data = await samlDiscover(email)
        setSsoInfo(data.sso_enabled ? data : null)
      } catch {
        setSsoInfo(null)
      } finally {
        setSsoChecking(false)
      }
    }, 500)
    return () => clearTimeout(timer)
  }, [email])

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await login(email, password)
      navigate('/')
    } catch (err) {
      setError(err.message || t('auth.loginFailed'))
    } finally {
      setLoading(false)
    }
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
        width: 400,
        background: 'var(--bg-card)',
        borderRadius: 12,
        border: '1px solid var(--border)',
        padding: 32,
        boxShadow: '0 4px 24px rgba(0,0,0,0.06)',
      }}>
        <div style={{ textAlign: 'center', marginBottom: 24 }}>
          <HakunaLogo size={40} />
          <h1 style={{ fontSize: 20, fontWeight: 700, margin: 0 }}>{t('auth.signInTo')}</h1>
          <p style={{ fontSize: 13, color: 'var(--muted, #71717a)', marginTop: 4 }}>
            {t('app.tagline')}
          </p>
        </div>

        {import.meta.env.VITE_GOOGLE_CLIENT_ID && (
          <>
            <GoogleSignInButton />

            <div style={{
              display: 'flex', alignItems: 'center', gap: 12, margin: '16px 0',
              color: 'var(--muted, #71717a)', fontSize: 13,
            }}>
              <div style={{ flex: 1, height: 1, background: 'var(--border)' }} />
              or
              <div style={{ flex: 1, height: 1, background: 'var(--border)' }} />
            </div>
          </>
        )}

        {/* SSO discovery banner */}
        {ssoInfo && (
          <div style={{
            background: 'var(--accent-subtle, #eef2ff)', borderRadius: 8,
            padding: '12px 16px', marginBottom: 16,
            border: '1px solid var(--accent, #6366f1)',
          }}>
            <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 8 }}>
              SSO is available for {ssoInfo.org_name}
            </div>
            <a
              href={ssoInfo.login_url}
              style={{
                display: 'inline-block', padding: '8px 20px', borderRadius: 8,
                background: 'var(--accent)', color: '#fff', fontSize: 13,
                fontWeight: 600, textDecoration: 'none', textAlign: 'center',
              }}
            >
              Sign in with SSO
            </a>
            {ssoInfo.force_sso && (
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 6 }}>
                Your organization requires SSO. Password login is disabled.
              </div>
            )}
          </div>
        )}

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
            <label style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4 }}>{t('auth.email')}</label>
            <input
              type="email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              required
              autoFocus
              style={{
                width: '100%',
                padding: '8px 12px',
                borderRadius: 8,
                border: '1px solid var(--border)',
                fontSize: 14,
                boxSizing: 'border-box',
              }}
            />
          </div>

          <div style={{ marginBottom: 20 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
              <label style={{ fontSize: 13, fontWeight: 500 }}>{t('auth.password')}</label>
              <Link to="/forgot-password" style={{ fontSize: 12, color: 'var(--muted, #71717a)', textDecoration: 'none' }}>
                Forgot password?
              </Link>
            </div>
            <input
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              required
              style={{
                width: '100%',
                padding: '8px 12px',
                borderRadius: 8,
                border: '1px solid var(--border)',
                fontSize: 14,
                boxSizing: 'border-box',
              }}
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
            {loading ? t('auth.signingIn') : t('auth.signIn')}
          </button>

          {ssoInfo && !ssoInfo.force_sso && (
            <div style={{ textAlign: 'center', marginTop: 12 }}>
              <a href={ssoInfo.login_url} style={{ fontSize: 13, color: 'var(--accent)', textDecoration: 'none', fontWeight: 500 }}>
                Or sign in with SSO
              </a>
            </div>
          )}
        </form>

        <div style={{ textAlign: 'center', marginTop: 16, fontSize: 13, color: 'var(--muted, #71717a)' }}>
          {t('auth.noAccount')}{' '}
          <Link to="/register" style={{ color: 'var(--text-primary)', fontWeight: 600, textDecoration: 'none' }}>
            {t('auth.register')}
          </Link>
        </div>
      </div>
    </div>
  )
}
