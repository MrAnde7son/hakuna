import React, { useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../../contexts/AuthContext.jsx'

export default function GoogleSignInButton() {
  const { googleLogin } = useAuth()
  const navigate = useNavigate()
  const buttonRef = useRef(null)
  const [error, setError] = React.useState('')

  useEffect(() => {
    const clientId = import.meta.env.VITE_GOOGLE_CLIENT_ID
    if (!clientId || !window.google?.accounts) return

    window.google.accounts.id.initialize({
      client_id: clientId,
      callback: async (response) => {
        setError('')
        try {
          await googleLogin(response.credential)
          navigate('/')
        } catch (err) {
          setError(err.message || 'Google sign-in failed')
        }
      },
    })

    window.google.accounts.id.renderButton(buttonRef.current, {
      theme: 'outline',
      size: 'large',
      width: '100%',
      text: 'continue_with',
    })
  }, [googleLogin, navigate])

  const clientId = import.meta.env.VITE_GOOGLE_CLIENT_ID
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
      <div ref={buttonRef} style={{ display: 'flex', justifyContent: 'center' }} />
    </>
  )
}
