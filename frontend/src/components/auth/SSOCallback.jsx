import React, { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { setStoredToken, authMe } from '../../api.js'
import { useAuth } from '../../contexts/AuthContext.jsx'

/**
 * Handles the redirect back from the SAML IdP after successful authentication.
 * The backend redirects here with ?token=<jwt> in the URL.
 */
export default function SSOCallback() {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const [error, setError] = useState('')

  useEffect(() => {
    const token = searchParams.get('token')
    if (!token) {
      setError('No authentication token received from SSO provider.')
      return
    }

    // Store the JWT token and redirect to dashboard
    setStoredToken(token)
    // Navigate to home — AuthContext will pick up the token and restore session
    navigate('/', { replace: true })
  }, [searchParams, navigate])

  if (error) {
    return (
      <div style={{
        minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
        background: 'var(--bg-muted, #f4f4f5)',
      }}>
        <div style={{
          width: 400, background: 'var(--bg-card)', borderRadius: 12,
          border: '1px solid var(--border)', padding: 32, textAlign: 'center',
        }}>
          <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 12 }}>SSO Error</h2>
          <p style={{ fontSize: 14, color: 'var(--danger)' }}>{error}</p>
          <a href="/login" style={{
            display: 'inline-block', marginTop: 16, padding: '8px 20px', borderRadius: 8,
            background: 'var(--accent)', color: '#fff', textDecoration: 'none', fontSize: 14,
          }}>
            Back to Login
          </a>
        </div>
      </div>
    )
  }

  return (
    <div style={{
      minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
      color: 'var(--text-muted)',
    }}>
      Completing SSO login...
    </div>
  )
}
