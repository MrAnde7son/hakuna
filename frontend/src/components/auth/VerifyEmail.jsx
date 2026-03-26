import React, { useState, useEffect } from 'react'
import { useSearchParams, Link, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { authVerifyEmail, authResendVerification } from '../../api.js'
import { useAuth } from '../../contexts/AuthContext.jsx'

function HakunaLogo({ size = 40 }) {
  const scale = size / 65
  return (
    <svg width={size} height={Math.round(44 * scale)} viewBox="0 0 65 44" fill="none" xmlns="http://www.w3.org/2000/svg" aria-label="Hakuna">
      <path d="M30.7181 4.27637L26.7728 19H30.4495V25H25.1653L22.4788 35.0273C21.1397 40.0248 16.6106 43.5 11.4368 43.5C3.92067 43.4999 -1.54952 36.3704 0.395817 29.1104L0.671208 28.0791C2.10629 22.7237 6.95988 19 12.5042 19H20.5618L24.9232 2.72363L30.7181 4.27637ZM53.4612 0C60.9775 0 66.4486 7.1295 64.5032 14.3896L64.2269 15.4209C62.7918 20.7761 57.939 24.4998 52.3948 24.5H44.3372L39.9759 40.7764L34.18 39.2236L38.1253 24.5H34.4495V18.5H39.7327L42.4202 8.47266C43.7593 3.47531 48.2876 0.000201552 53.4612 0ZM12.5042 25C9.67544 25 7.19925 26.9004 6.46711 29.6328L6.19074 30.6631C5.26649 34.1124 7.86583 37.4999 11.4368 37.5C13.895 37.5 16.0467 35.849 16.6829 33.4746L18.9544 25H12.5042ZM53.4612 6C51.0033 6.0002 48.8524 7.65123 48.2161 10.0254L45.9446 18.5H52.3948C55.2235 18.4998 57.6998 16.5995 58.4319 13.8672L58.7073 12.8369C59.6316 9.38749 57.0324 6 53.4612 6Z" fill="#590202" />
    </svg>
  )
}

export default function VerifyEmail() {
  const [searchParams] = useSearchParams()
  const token = searchParams.get('token')
  const navigate = useNavigate()
  const { t } = useTranslation()
  const { user, isAuthenticated } = useAuth()

  const [status, setStatus] = useState(token ? 'verifying' : 'pending') // verifying | success | error | pending
  const [error, setError] = useState('')
  const [resendStatus, setResendStatus] = useState('') // '' | sending | sent | error

  // Auto-verify when token is in URL
  useEffect(() => {
    if (!token) return
    authVerifyEmail(token)
      .then(() => setStatus('success'))
      .catch(err => {
        setStatus('error')
        setError(err.message || t('auth.invalidVerificationToken', 'Invalid or expired verification link'))
      })
  }, [token])

  const handleResend = async () => {
    setResendStatus('sending')
    try {
      await authResendVerification()
      setResendStatus('sent')
    } catch (err) {
      setResendStatus('error')
      setError(err.message || 'Failed to resend verification email')
    }
  }

  const cardStyle = {
    width: 420,
    background: 'var(--bg-card)',
    borderRadius: 12,
    border: '1px solid var(--border)',
    padding: 32,
    boxShadow: '0 4px 24px rgba(0,0,0,0.06)',
    textAlign: 'center',
  }

  const btnStyle = {
    padding: '10px 24px',
    borderRadius: 8,
    border: 'none',
    background: 'var(--nav-active-bg)',
    color: 'var(--nav-active-text)',
    fontSize: 14,
    fontWeight: 600,
    cursor: 'pointer',
  }

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'var(--bg-muted, #f4f4f5)',
    }}>
      <div style={cardStyle}>
        <div style={{ marginBottom: 24 }}>
          <HakunaLogo size={40} />
        </div>

        {/* Verifying token... */}
        {status === 'verifying' && (
          <>
            <h1 style={{ fontSize: 20, fontWeight: 700, margin: '0 0 8px' }}>
              {t('auth.verifyingEmail', 'Verifying your email...')}
            </h1>
            <p style={{ fontSize: 14, color: 'var(--muted, #71717a)' }}>
              {t('auth.pleaseWait', 'Please wait a moment.')}
            </p>
          </>
        )}

        {/* Success */}
        {status === 'success' && (
          <>
            <div style={{
              width: 48, height: 48, borderRadius: '50%',
              background: '#dcfce7', display: 'flex', alignItems: 'center',
              justifyContent: 'center', margin: '0 auto 16px',
            }}>
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#16a34a" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="20 6 9 17 4 12" />
              </svg>
            </div>
            <h1 style={{ fontSize: 20, fontWeight: 700, margin: '0 0 8px' }}>
              {t('auth.emailVerified', 'Email verified!')}
            </h1>
            <p style={{ fontSize: 14, color: 'var(--muted, #71717a)', marginBottom: 24 }}>
              {t('auth.emailVerifiedDesc', 'Your email has been verified. You can now use all features.')}
            </p>
            <button style={btnStyle} onClick={() => navigate(isAuthenticated ? '/' : '/login')}>
              {isAuthenticated
                ? t('auth.goToDashboard', 'Go to Dashboard')
                : t('auth.signIn', 'Sign In')}
            </button>
          </>
        )}

        {/* Error verifying token */}
        {status === 'error' && (
          <>
            <div style={{
              width: 48, height: 48, borderRadius: '50%',
              background: '#fee2e2', display: 'flex', alignItems: 'center',
              justifyContent: 'center', margin: '0 auto 16px',
            }}>
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#dc2626" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
              </svg>
            </div>
            <h1 style={{ fontSize: 20, fontWeight: 700, margin: '0 0 8px' }}>
              {t('auth.verificationFailed', 'Verification failed')}
            </h1>
            <p style={{ fontSize: 14, color: 'var(--muted, #71717a)', marginBottom: 24 }}>
              {error}
            </p>
            {isAuthenticated && (
              <button
                style={{ ...btnStyle, opacity: resendStatus === 'sending' ? 0.6 : 1 }}
                onClick={handleResend}
                disabled={resendStatus === 'sending' || resendStatus === 'sent'}
              >
                {resendStatus === 'sent'
                  ? t('auth.verificationSent', 'Verification email sent!')
                  : resendStatus === 'sending'
                    ? t('auth.sending', 'Sending...')
                    : t('auth.resendVerification', 'Resend verification email')}
              </button>
            )}
            <div style={{ marginTop: 16 }}>
              <Link to="/login" style={{ fontSize: 13, color: 'var(--text-primary)', fontWeight: 600, textDecoration: 'none' }}>
                {t('auth.backToLogin', 'Back to Login')}
              </Link>
            </div>
          </>
        )}

        {/* Pending — shown after registration (no token in URL) */}
        {status === 'pending' && (
          <>
            <div style={{
              width: 48, height: 48, borderRadius: '50%',
              background: '#dbeafe', display: 'flex', alignItems: 'center',
              justifyContent: 'center', margin: '0 auto 16px',
            }}>
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#2563eb" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <rect x="2" y="4" width="20" height="16" rx="2" />
                <path d="M22 7l-10 7L2 7" />
              </svg>
            </div>
            <h1 style={{ fontSize: 20, fontWeight: 700, margin: '0 0 8px' }}>
              {t('auth.checkYourEmail', 'Check your email')}
            </h1>
            <p style={{ fontSize: 14, color: 'var(--muted, #71717a)', marginBottom: 8 }}>
              {t('auth.verificationSentTo', "We've sent a verification link to:")}
            </p>
            {user?.email && (
              <p style={{ fontSize: 15, fontWeight: 600, marginBottom: 24 }}>
                {user.email}
              </p>
            )}
            <p style={{ fontSize: 13, color: 'var(--muted, #71717a)', marginBottom: 24 }}>
              {t('auth.checkSpam', 'Check your spam folder if you don\'t see it. The link expires in 24 hours.')}
            </p>
            <button
              style={{ ...btnStyle, opacity: resendStatus === 'sending' ? 0.6 : 1 }}
              onClick={handleResend}
              disabled={resendStatus === 'sending' || resendStatus === 'sent' || !isAuthenticated}
            >
              {resendStatus === 'sent'
                ? t('auth.verificationSent', 'Verification email sent!')
                : resendStatus === 'sending'
                  ? t('auth.sending', 'Sending...')
                  : t('auth.resendVerification', 'Resend verification email')}
            </button>
            {resendStatus === 'error' && (
              <p style={{ fontSize: 13, color: 'var(--danger)', marginTop: 8 }}>{error}</p>
            )}
            <div style={{ marginTop: 16 }}>
              <Link to="/login" style={{ fontSize: 13, color: 'var(--text-primary)', fontWeight: 600, textDecoration: 'none' }}>
                {t('auth.backToLogin', 'Back to Login')}
              </Link>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
