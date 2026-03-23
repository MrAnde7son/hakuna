import React, { useEffect, useRef, useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../../contexts/AuthContext.jsx'

const GOOGLE_ICON = (
  <svg width="18" height="18" viewBox="0 0 48 48">
    <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>
    <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>
    <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/>
    <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>
  </svg>
)

export default function GoogleSignInButton() {
  const { googleLogin } = useAuth()
  const navigate = useNavigate()
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const hiddenBtnRef = useRef(null)

  const clientId = import.meta.env.VITE_GOOGLE_CLIENT_ID

  useEffect(() => {
    if (!clientId || !window.google?.accounts) return

    window.google.accounts.id.initialize({
      client_id: clientId,
      callback: async (response) => {
        setError('')
        setLoading(true)
        try {
          await googleLogin(response.credential)
          navigate('/')
        } catch (err) {
          setError(err.message || 'Google sign-in failed')
        } finally {
          setLoading(false)
        }
      },
      ux_mode: 'popup',
    })

    // Render Google's real button in a hidden div (for popup auth)
    if (hiddenBtnRef.current) {
      window.google.accounts.id.renderButton(hiddenBtnRef.current, {
        type: 'icon',
        size: 'large',
      })
    }
  }, [clientId, googleLogin, navigate])

  const handleClick = useCallback(() => {
    // Click the hidden Google button to trigger the real OAuth popup
    const googleBtn = hiddenBtnRef.current?.querySelector('[role="button"]')
      || hiddenBtnRef.current?.querySelector('div[aria-labelledby]')
      || hiddenBtnRef.current?.querySelector('iframe')
    if (googleBtn) {
      googleBtn.click()
    }
  }, [])

  if (!clientId) return null

  return (
    <>
      {error && (
        <div style={{
          background: 'var(--danger-subtle)',
          color: 'var(--danger)',
          padding: '8px 12px',
          borderRadius: 6,
          fontSize: 13,
          marginBottom: 12,
          border: '1px solid var(--danger)',
        }}>
          {error}
        </div>
      )}
      {/* Hidden Google button — triggers popup when clicked programmatically */}
      <div ref={hiddenBtnRef} style={{ position: 'absolute', opacity: 0, pointerEvents: 'none', width: 0, height: 0, overflow: 'hidden' }} />
      <button
        type="button"
        onClick={handleClick}
        disabled={loading}
        style={{
          width: '100%',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          gap: 10,
          padding: '10px 0',
          borderRadius: 8,
          border: '1px solid var(--border)',
          background: 'var(--bg-card)',
          color: 'var(--text-primary)',
          fontSize: 14,
          fontWeight: 500,
          cursor: loading ? 'not-allowed' : 'pointer',
          opacity: loading ? 0.6 : 1,
        }}
      >
        {GOOGLE_ICON}
        {loading ? 'Signing in...' : 'Continue with Google'}
      </button>
    </>
  )
}
