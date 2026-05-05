import { useState, useEffect, useRef } from 'react'
import { CheckCircle2, ExternalLink, Eye, EyeOff, RefreshCw } from 'lucide-react'
import { Button, Spinner, InlineSpinner } from '../../shared/ui.jsx'
import { getAcquisitionFlow, validateCredentials, createCredential, oauthStart, discoverOAuth, oauthClientCredentials, getCredentials } from '../../../api.js'

export default function StepAuthenticate({ connectorId, connectorDetail, onComplete, onSkip }) {
  const [flow, setFlow] = useState(null)
  const [loading, setLoading] = useState(true)
  const [activeStep, setActiveStep] = useState(0)
  const [values, setValues] = useState({})
  const [instanceUrl, setInstanceUrl] = useState('')
  const [validating, setValidating] = useState(false)
  const [validated, setValidated] = useState(false)
  const [validatedUser, setValidatedUser] = useState(null)
  const [error, setError] = useState(null)
  const [showPasswords, setShowPasswords] = useState({})
  const [savedCredId, setSavedCredId] = useState(null)
  const [oauthPending, setOauthPending] = useState(false)
  const [discovered, setDiscovered] = useState(null)   // result from /discovery/oauth
  const [discovering, setDiscovering] = useState(false)
  const [sharedCreds, setSharedCreds] = useState(null) // for shared_credential pattern
  const popupRef = useRef(null)
  const messageListenerRef = useRef(null)

  useEffect(() => {
    if (!connectorId) { onSkip(); return }
    getAcquisitionFlow(connectorId).then(async f => {
      setFlow(f)
      if (f.pattern === 'shared_credential' && f.shared_with) {
        try {
          const all = await getCredentials()
          const matches = (all || []).filter(c => c.connector_id === f.shared_with)
          setSharedCreds(matches)
          if (matches.length === 1) {
            setLoading(false)
            onComplete(matches[0].id, matches[0].connected_user)
            return
          }
        } catch {
          setSharedCreds([])
        }
      }
      setLoading(false)
      if (f.pattern === 'none') onSkip()
    }).catch(() => { setLoading(false); onSkip() })
  }, [connectorId])

  if (loading) return <div style={{ padding: 40, textAlign: 'center' }}><Spinner /></div>
  if (!flow || flow.pattern === 'none') return null

  const handleValidate = async () => {
    setValidating(true)
    setError(null)
    try {
      const result = await validateCredentials(connectorId, { instance_url: instanceUrl, values })
      if (result.success) {
        setValidated(true)
        setValidatedUser(result.connected_user || null)
        // Save credentials
        const authType = flow.pattern === 'oauth2' ? 'oauth2'
          : flow.validation_request?.auth === 'basic' ? 'basic'
          : 'api_key'
        const cred = await createCredential({
          name: `${connectorDetail?.name || connectorId} credentials`,
          connector_id: connectorId,
          auth_type: authType,
          values: values,
          instance_url: instanceUrl || null,
          connected_user: result.connected_user || null,
        })
        setSavedCredId(cred.id)
        onComplete(cred.id, result.connected_user)
      } else {
        setError(result.error || 'Validation failed')
      }
    } catch (e) {
      setError(e.message)
    } finally {
      setValidating(false)
    }
  }

  const handleFieldChange = async (field, value) => {
    const newValues = { ...values, [field]: value }
    setValues(newValues)
    setError(null)
    setValidated(false)

    // Auto-validate on paste if configured
    const currentStep = flow.steps?.[activeStep]
    if (currentStep?.capture?.auto_validate && value.length > 5) {
      // Debounce: validate after 300ms
      setTimeout(() => {
        if (newValues[field] === value) {
          setValidating(true)
          validateCredentials(connectorId, { instance_url: instanceUrl, values: newValues })
            .then(result => {
              if (result.success) {
                setValidated(true)
                setValidatedUser(result.connected_user || null)
                // Auto-advance to next step
                if (activeStep < (flow.steps?.length || 0) - 1) {
                  setActiveStep(prev => prev + 1)
                }
              }
            })
            .catch(() => {})
            .finally(() => setValidating(false))
        }
      }, 300)
    }
  }

  // ── Guided Generation ──
  if (flow.pattern === 'guided_generation') {
    const steps = flow.steps || []
    const simpleFields = flow.fields || []
    const useSimpleForm = steps.length === 0 && simpleFields.length > 0
    const allFieldsFilled = simpleFields.every(f => (values[f.field] || '').trim().length > 0)

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
        <h3 style={{ margin: 0, fontSize: 16, fontWeight: 600 }}>Authenticate</h3>

        {/* Instance URL field */}
        {flow.instance_url_field && (
          <div>
            <label style={labelStyle}>{flow.instance_url_field.label}</label>
            <input
              placeholder={flow.instance_url_field.placeholder}
              value={instanceUrl}
              onChange={e => setInstanceUrl(e.target.value)}
              style={inputStyle}
            />
          </div>
        )}

        {/* Simple form — used when connector declares `fields` instead of `steps` */}
        {useSimpleForm && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <p style={{ margin: 0, fontSize: 12, color: 'var(--text-muted)' }}>
              Enter your {connectorDetail?.name || 'API'} credentials below. Hakuna will validate them by calling the provider.
            </p>
            {simpleFields.map(f => (
              <div key={f.field}>
                <label style={labelStyle}>{f.label}</label>
                <div style={{ position: 'relative' }}>
                  <input
                    type={showPasswords[f.field] ? 'text' : (f.type || 'text')}
                    value={values[f.field] || ''}
                    onChange={e => setValues({ ...values, [f.field]: e.target.value })}
                    placeholder={f.placeholder || f.label}
                    style={inputStyle}
                  />
                  {f.type === 'password' && (
                    <button
                      onClick={() => setShowPasswords(p => ({ ...p, [f.field]: !p[f.field] }))}
                      style={{ position: 'absolute', right: 8, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}
                    >
                      {showPasswords[f.field] ? <EyeOff size={14} /> : <Eye size={14} />}
                    </button>
                  )}
                </div>
                {f.help && <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>{f.help}</div>}
              </div>
            ))}
          </div>
        )}

        {/* Step wizard */}
        {!useSimpleForm && (
        <div style={{ display: 'flex', gap: 24 }}>
          {/* Left: step list */}
          <div style={{ width: '40%', display: 'flex', flexDirection: 'column', gap: 8 }}>
            {steps.map((s, i) => (
              <div
                key={i}
                onClick={() => setActiveStep(i)}
                style={{
                  display: 'flex', gap: 10, padding: '10px 12px', borderRadius: 8,
                  cursor: 'pointer',
                  background: i === activeStep ? 'var(--accent)15' : 'transparent',
                  border: i === activeStep ? '1px solid var(--accent)40' : '1px solid transparent',
                }}
              >
                <div style={{
                  width: 22, height: 22, borderRadius: '50%', display: 'flex',
                  alignItems: 'center', justifyContent: 'center', fontSize: 11, fontWeight: 600, flexShrink: 0,
                  background: i < activeStep ? '#22c55e' : i === activeStep ? 'var(--accent)' : 'var(--border)',
                  color: '#fff',
                }}>
                  {i < activeStep ? <CheckCircle2 size={12} /> : i + 1}
                </div>
                <div style={{ fontSize: 12, lineHeight: 1.4 }}>{s.instruction}</div>
              </div>
            ))}
          </div>

          {/* Right: active step detail */}
          <div style={{ flex: 1 }}>
            {steps[activeStep] && (
              <div>
                {(steps[activeStep].deeplink_override || (steps[activeStep].deeplink_path && instanceUrl)) && (
                  <a
                    href={steps[activeStep].deeplink_override || `${instanceUrl.replace(/\/$/, '')}${steps[activeStep].deeplink_path}`}
                    target="_blank" rel="noopener noreferrer"
                    style={{
                      display: 'inline-flex', alignItems: 'center', gap: 4,
                      color: 'var(--accent)', fontSize: 12, marginBottom: 12, textDecoration: 'none',
                    }}
                  >
                    <ExternalLink size={12} /> Open in Atlassian
                  </a>
                )}

                {steps[activeStep].capture && (
                  <div style={{ marginTop: 8 }}>
                    <label style={labelStyle}>{steps[activeStep].capture.label}</label>
                    <div style={{ position: 'relative' }}>
                      <input
                        type={showPasswords[steps[activeStep].capture.field] ? 'text' : steps[activeStep].capture.type || 'text'}
                        value={values[steps[activeStep].capture.field] || ''}
                        onChange={e => handleFieldChange(steps[activeStep].capture.field, e.target.value)}
                        placeholder={steps[activeStep].capture.label}
                        style={inputStyle}
                        autoFocus
                      />
                      {steps[activeStep].capture.type === 'password' && (
                        <button
                          onClick={() => setShowPasswords(p => ({ ...p, [steps[activeStep].capture.field]: !p[steps[activeStep].capture.field] }))}
                          style={{ position: 'absolute', right: 8, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}
                        >
                          {showPasswords[steps[activeStep].capture.field] ? <EyeOff size={14} /> : <Eye size={14} />}
                        </button>
                      )}
                    </div>
                    {validating && <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>Validating...</div>}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
        )}

        {/* Status + actions */}
        {validated && (
          <div style={{
            padding: '10px 16px', borderRadius: 8, background: '#22c55e18',
            border: '1px solid #22c55e40', display: 'flex', alignItems: 'center', gap: 8,
          }}>
            <CheckCircle2 size={16} color="#22c55e" />
            <span style={{ fontSize: 13, color: '#22c55e' }}>
              Connected{validatedUser ? ` as ${validatedUser}` : ''}
            </span>
          </div>
        )}

        {error && (
          <div style={{ padding: '10px 16px', borderRadius: 8, background: '#ef444418', border: '1px solid #ef444440', color: '#ef4444', fontSize: 12 }}>
            {error}
          </div>
        )}

        <div style={{ display: 'flex', gap: 8 }}>
          {!validated && (
            <Button
              onClick={handleValidate}
              disabled={
                validating ||
                (useSimpleForm ? !allFieldsFilled : Object.keys(values).length === 0)
              }
            >
              {validating ? <InlineSpinner /> : 'Validate & Connect'}
            </Button>
          )}
          {validated && (
            <Button onClick={async () => {
              if (savedCredId) {
                onComplete(savedCredId, validatedUser)
              } else {
                // Auto-validate path — credentials weren't saved yet
                try {
                  const authType = flow.validation_request?.auth === 'basic' ? 'basic' : 'api_key'
                  const cred = await createCredential({
                    name: `${connectorDetail?.name || connectorId} credentials`,
                    connector_id: connectorId,
                    auth_type: authType,
                    values: values,
                    instance_url: instanceUrl || null,
                    connected_user: validatedUser || null,
                  })
                  onComplete(cred.id, validatedUser)
                } catch {
                  onComplete(null, validatedUser)
                }
              }
            }}>
              Continue →
            </Button>
          )}
          <Button onClick={onSkip} style={{ background: 'transparent', color: 'var(--text-muted)', border: '1px solid var(--border)' }}>
            Skip
          </Button>
        </div>
      </div>
    )
  }

  // ── OAuth2 ──
  if (flow.pattern === 'oauth2') {
    const handleOAuthConnect = async () => {
      setOauthPending(true)
      setError(null)

      // Clean up any previous listener
      if (messageListenerRef.current) {
        window.removeEventListener('message', messageListenerRef.current)
      }

      try {
        const { authorization_url } = await oauthStart(connectorId, { instance_url: instanceUrl || undefined })

        // Open popup
        const width = flow.popup?.width || 600
        const height = flow.popup?.height || 700
        const left = Math.round(window.screenX + (window.outerWidth - width) / 2)
        const top = Math.round(window.screenY + (window.outerHeight - height) / 2)
        const popup = window.open(
          authorization_url,
          'hakuna_oauth',
          `width=${width},height=${height},left=${left},top=${top},toolbar=no,menubar=no`
        )
        popupRef.current = popup

        // Listen for callback postMessage
        const listener = (event) => {
          if (event.origin !== window.location.origin) return
          if (!event.data || typeof event.data !== 'object') return
          const { success, error: oauthError, connected_user, credentials_id } = event.data
          if (success === undefined && credentials_id === undefined) return  // not our message

          window.removeEventListener('message', listener)
          messageListenerRef.current = null
          setOauthPending(false)

          if (success && credentials_id) {
            setValidated(true)
            setValidatedUser(connected_user || null)
            onComplete(credentials_id, connected_user)
          } else {
            setError(oauthError || 'Authorization failed or was cancelled')
          }
        }
        messageListenerRef.current = listener
        window.addEventListener('message', listener)

        // Detect popup closed without completing
        const pollClosed = setInterval(() => {
          if (popup && popup.closed) {
            clearInterval(pollClosed)
            if (messageListenerRef.current) {
              window.removeEventListener('message', messageListenerRef.current)
              messageListenerRef.current = null
            }
            setOauthPending(false)
          }
        }, 500)

      } catch (e) {
        setOauthPending(false)
        setError(e.message || 'Failed to start OAuth flow')
      }
    }

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16, alignItems: 'center', padding: 40 }}>
        <h3 style={{ margin: 0, fontSize: 16, fontWeight: 600 }}>Connect to {connectorDetail?.name}</h3>
        <p style={{ fontSize: 12, color: 'var(--text-muted)', textAlign: 'center', maxWidth: 360 }}>
          You'll be redirected to {connectorDetail?.name} to approve access.
          Hakuna never sees your password.
        </p>

        {flow.instance_url_field && (
          <div style={{ width: '100%', maxWidth: 400 }}>
            <label style={labelStyle}>{flow.instance_url_field.label}</label>
            <input
              placeholder={flow.instance_url_field.placeholder}
              value={instanceUrl}
              onChange={e => setInstanceUrl(e.target.value)}
              style={inputStyle}
            />
          </div>
        )}

        {validated ? (
          <div style={{
            padding: '10px 16px', borderRadius: 8, background: '#22c55e18',
            border: '1px solid #22c55e40', display: 'flex', alignItems: 'center', gap: 8,
          }}>
            <CheckCircle2 size={16} color="#22c55e" />
            <span style={{ fontSize: 13, color: '#22c55e' }}>
              Connected{validatedUser ? ` as ${validatedUser}` : ''}
            </span>
          </div>
        ) : (
          <Button
            onClick={handleOAuthConnect}
            disabled={oauthPending || (flow.instance_url_field && !instanceUrl.trim())}
          >
            {oauthPending ? <><InlineSpinner /> Waiting for authorization…</> : `Connect to ${connectorDetail?.name || connectorId}`}
          </Button>
        )}

        {error && (
          <div style={{ padding: '10px 16px', borderRadius: 8, background: '#ef444418', border: '1px solid #ef444440', color: '#ef4444', fontSize: 12, maxWidth: 400, textAlign: 'center' }}>
            {error}
          </div>
        )}

        <Button onClick={onSkip} style={{ background: 'transparent', color: 'var(--text-muted)', border: '1px solid var(--border)', fontSize: 12 }}>
          Skip for now
        </Button>
      </div>
    )
  }

  // ── Auto Provision ──
  if (flow.pattern === 'auto_provision') {
    const promptSteps = flow.admin_credential_prompt?.steps || []
    const adminFields = flow.admin_credentials
      || promptSteps.map(s => ({ ...s.capture, instruction: s.instruction }))
      || []
    const allFilled = adminFields.every(f => (values[f.field] || '').trim().length > 0)

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <h3 style={{ margin: 0, fontSize: 16, fontWeight: 600 }}>Auto-Provision Service Account</h3>
        {flow.description && (
          <p style={{ margin: 0, fontSize: 12, color: 'var(--text-muted)' }}>{flow.description}</p>
        )}
        <div style={{
          padding: '10px 16px', borderRadius: 8, background: '#eab30818',
          border: '1px solid #eab30840', fontSize: 12, color: '#eab308',
        }}>
          These credentials are used once to create a dedicated Hakuna service account and are never stored.
        </div>

        {adminFields.map(field => (
          <div key={field.field}>
            {field.instruction && (
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 6 }}>{field.instruction}</div>
            )}
            <label style={labelStyle}>{field.label}</label>
            <input
              type={field.type || 'text'}
              value={values[field.field] || ''}
              onChange={e => setValues({ ...values, [field.field]: e.target.value })}
              style={inputStyle}
            />
            {field.help && <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{field.help}</div>}
          </div>
        ))}

        {error && (
          <div style={{ padding: '10px 16px', borderRadius: 8, background: '#ef444418', border: '1px solid #ef444440', color: '#ef4444', fontSize: 12 }}>
            {error}
          </div>
        )}

        <Button onClick={handleValidate} disabled={validating || !allFilled}>
          {validating ? <InlineSpinner /> : 'Provision Hakuna Account'}
        </Button>
      </div>
    )
  }

  // ── Client Credentials (machine-to-machine OAuth2) ──
  if (flow.pattern === 'client_credentials') {
    // Build fields from either explicit `fields` array or legacy `client_id_field`/`client_secret_field`/`extra_fields`
    const fields = flow.fields || [
      ...(flow.extra_fields || []).filter(f => f.field !== 'client_id' && f.field !== 'client_secret'),
      { field: 'client_id', label: flow.client_id_field?.label || 'Client ID', type: flow.client_id_field?.type || 'text', help: flow.client_id_field?.help },
      { field: 'client_secret', label: flow.client_secret_field?.label || 'Client Secret', type: flow.client_secret_field?.type || 'password', help: flow.client_secret_field?.help },
    ]

    const handleConnect = async () => {
      setValidating(true)
      setError(null)
      try {
        // Resolve {{credentials.X}} templates in token_url using current field values
        const resolvedTokenUrl = (flow.token_url || '').replace(
          /\{\{credentials\.(\w+)\}\}/g,
          (_, key) => values[key] || ''
        )
        const result = await oauthClientCredentials({
          instance_url: instanceUrl || '',
          token_url: resolvedTokenUrl,
          client_id: values.client_id || '',
          client_secret: values.client_secret || '',
          scopes: flow.scopes || [],
          connector_id: connectorId || 'custom',
          extra_values: Object.fromEntries(
            Object.entries(values).filter(([k]) => k !== 'client_id' && k !== 'client_secret')
          ),
        })
        setValidated(true)
        setValidatedUser(result.connected_user || null)
        onComplete(result.credentials_id, result.connected_user)
      } catch (e) {
        setError(e.message)
      } finally {
        setValidating(false)
      }
    }

    const allFilled = fields.every(f => (values[f.field] || '').trim().length > 0)

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
        <h3 style={{ margin: 0, fontSize: 16, fontWeight: 600 }}>Authenticate</h3>
        <p style={{ margin: 0, fontSize: 12, color: 'var(--text-muted)' }}>
          Enter your API client credentials. Hakuna will obtain an access token automatically and refresh it before it expires.
        </p>

        {flow.instance_url_field && (
          <div>
            <label style={labelStyle}>{flow.instance_url_field.label}</label>
            <input placeholder={flow.instance_url_field.placeholder} value={instanceUrl} onChange={e => setInstanceUrl(e.target.value)} style={inputStyle} />
          </div>
        )}

        {fields.map(f => (
          <div key={f.field}>
            <label style={labelStyle}>{f.label}</label>
            <div style={{ position: 'relative' }}>
              <input
                type={showPasswords[f.field] ? 'text' : (f.type || 'text')}
                value={values[f.field] || ''}
                onChange={e => setValues({ ...values, [f.field]: e.target.value })}
                style={inputStyle}
              />
              {f.type === 'password' && (
                <button onClick={() => setShowPasswords(p => ({ ...p, [f.field]: !p[f.field] }))}
                  style={{ position: 'absolute', right: 8, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}>
                  {showPasswords[f.field] ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              )}
            </div>
            {f.help && <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{f.help}</div>}
          </div>
        ))}

        {validated ? (
          <div style={{ padding: '10px 16px', borderRadius: 8, background: '#22c55e18', border: '1px solid #22c55e40', display: 'flex', alignItems: 'center', gap: 8 }}>
            <CheckCircle2 size={16} color="#22c55e" />
            <span style={{ fontSize: 13, color: '#22c55e' }}>Connected{validatedUser ? ` as ${validatedUser}` : ''}</span>
          </div>
        ) : (
          <Button onClick={handleConnect} disabled={validating || !allFilled}>
            {validating ? <InlineSpinner /> : 'Get Access Token'}
          </Button>
        )}

        {error && (
          <div style={{ padding: '10px 16px', borderRadius: 8, background: '#ef444418', border: '1px solid #ef444440', color: '#ef4444', fontSize: 12 }}>
            {error}
          </div>
        )}

        <Button onClick={onSkip} style={{ background: 'transparent', color: 'var(--text-muted)', border: '1px solid var(--border)' }}>Skip</Button>
      </div>
    )
  }

  // ── Dynamic OAuth2 Discovery ──
  // Used when the connector has pattern: "discover_oauth" (e.g. CrowdStrike, any unknown API).
  // User enters the base URL, we probe for OAuth2 support and present the right flow.
  if (flow.pattern === 'discover_oauth') {
    const handleDiscover = async () => {
      if (!instanceUrl.trim()) return
      setDiscovering(true)
      setError(null)
      setDiscovered(null)
      try {
        const result = await discoverOAuth(instanceUrl.trim())
        setDiscovered(result)
        if (!result.oauth_supported) {
          setError('No OAuth2 support detected at this URL. Try using an API key instead.')
        }
      } catch (e) {
        setError(e.message)
      } finally {
        setDiscovering(false)
      }
    }

    const handleClientCredentials = async () => {
      setValidating(true)
      setError(null)
      try {
        const result = await oauthClientCredentials({
          instance_url: instanceUrl,
          token_url: discovered.token_endpoint,
          client_id: values.client_id || '',
          client_secret: values.client_secret || '',
          scopes: discovered.scopes_supported || [],
          connector_id: connectorId || 'custom',
        })
        if (result.success) {
          setValidated(true)
          setValidatedUser(result.connected_user)
          onComplete(result.credentials_id, result.connected_user)
        }
      } catch (e) {
        setError(e.message)
      } finally {
        setValidating(false)
      }
    }

    const handleAuthCodeConnect = async () => {
      // Use the discovered endpoints to start an OAuth2 popup.
      // This requires the connector to have a registered client_id — prompt for it.
      setOauthPending(true)
      setError(null)
      if (messageListenerRef.current) window.removeEventListener('message', messageListenerRef.current)
      try {
        const { authorization_url } = await oauthStart(connectorId || 'custom', { instance_url: instanceUrl })
        const width = 600, height = 700
        const left = Math.round(window.screenX + (window.outerWidth - width) / 2)
        const top = Math.round(window.screenY + (window.outerHeight - height) / 2)
        const popup = window.open(authorization_url, 'hakuna_oauth', `width=${width},height=${height},left=${left},top=${top},toolbar=no,menubar=no`)
        popupRef.current = popup
        const listener = (event) => {
          if (!event.data || typeof event.data !== 'object') return
          const { success, error: oauthError, connected_user, credentials_id } = event.data
          if (success === undefined && credentials_id === undefined) return
          window.removeEventListener('message', listener)
          messageListenerRef.current = null
          setOauthPending(false)
          if (success && credentials_id) { setValidated(true); setValidatedUser(connected_user); onComplete(credentials_id, connected_user) }
          else setError(oauthError || 'Authorization failed or was cancelled')
        }
        messageListenerRef.current = listener
        window.addEventListener('message', listener)
        const poll = setInterval(() => { if (popup?.closed) { clearInterval(poll); if (messageListenerRef.current) { window.removeEventListener('message', messageListenerRef.current); messageListenerRef.current = null } setOauthPending(false) } }, 500)
      } catch (e) {
        setOauthPending(false)
        setError(e.message)
      }
    }

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
        <h3 style={{ margin: 0, fontSize: 16, fontWeight: 600 }}>Authenticate</h3>

        {/* URL input + probe button */}
        <div style={{ display: 'flex', gap: 8 }}>
          <input
            placeholder={flow.instance_url_field?.placeholder || 'https://api.example.com'}
            value={instanceUrl}
            onChange={e => { setInstanceUrl(e.target.value); setDiscovered(null) }}
            style={{ ...inputStyle, flex: 1 }}
          />
          <Button onClick={handleDiscover} disabled={discovering || !instanceUrl.trim()} style={{ whiteSpace: 'nowrap' }}>
            {discovering ? <InlineSpinner /> : 'Detect Auth'}
          </Button>
        </div>

        {/* Discovery result */}
        {discovered && discovered.oauth_supported && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div style={{ padding: '10px 16px', borderRadius: 8, background: 'var(--accent)10', border: '1px solid var(--accent)30', fontSize: 12 }}>
              OAuth2 detected via <code>{discovered.source}</code> &nbsp;·&nbsp;
              Grant types: <strong>{discovered.grant_types.join(', ') || 'authorization_code'}</strong>
            </div>

            {/* Client Credentials flow (machine-to-machine, e.g. CrowdStrike) */}
            {discovered.client_credentials_supported && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <p style={{ margin: 0, fontSize: 12, color: 'var(--text-muted)' }}>
                  This API uses client credentials (machine-to-machine). Enter your Client ID and Secret.
                </p>
                <div>
                  <label style={labelStyle}>Client ID</label>
                  <input value={values.client_id || ''} onChange={e => setValues({ ...values, client_id: e.target.value })} style={inputStyle} />
                </div>
                <div>
                  <label style={labelStyle}>Client Secret</label>
                  <div style={{ position: 'relative' }}>
                    <input
                      type={showPasswords.client_secret ? 'text' : 'password'}
                      value={values.client_secret || ''}
                      onChange={e => setValues({ ...values, client_secret: e.target.value })}
                      style={inputStyle}
                    />
                    <button onClick={() => setShowPasswords(p => ({ ...p, client_secret: !p.client_secret }))}
                      style={{ position: 'absolute', right: 8, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}>
                      {showPasswords.client_secret ? <EyeOff size={14} /> : <Eye size={14} />}
                    </button>
                  </div>
                </div>
                {!validated ? (
                  <Button onClick={handleClientCredentials} disabled={validating || !values.client_id || !values.client_secret}>
                    {validating ? <InlineSpinner /> : 'Get Access Token'}
                  </Button>
                ) : (
                  <div style={{ padding: '10px 16px', borderRadius: 8, background: '#22c55e18', border: '1px solid #22c55e40', display: 'flex', alignItems: 'center', gap: 8 }}>
                    <CheckCircle2 size={16} color="#22c55e" />
                    <span style={{ fontSize: 13, color: '#22c55e' }}>Connected as {validatedUser}</span>
                  </div>
                )}
              </div>
            )}

            {/* Authorization code popup flow */}
            {discovered.authorization_code_supported && !discovered.client_credentials_supported && (
              <Button onClick={handleAuthCodeConnect} disabled={oauthPending}>
                {oauthPending ? <><InlineSpinner /> Waiting for authorization…</> : 'Connect via OAuth2'}
              </Button>
            )}
          </div>
        )}

        {error && (
          <div style={{ padding: '10px 16px', borderRadius: 8, background: '#ef444418', border: '1px solid #ef444440', color: '#ef4444', fontSize: 12 }}>
            {error}
          </div>
        )}

        <div style={{ display: 'flex', gap: 8 }}>
          <Button onClick={onSkip} style={{ background: 'transparent', color: 'var(--text-muted)', border: '1px solid var(--border)' }}>
            Skip
          </Button>
        </div>
      </div>
    )
  }

  // ── Shared Credential ──
  // This connector reuses credentials from a "primary" connector declared in `shared_with`.
  // If exactly one credential exists for the primary, the useEffect above auto-completes;
  // otherwise prompt the user to pick one or set up the primary first.
  if (flow.pattern === 'shared_credential') {
    const matches = sharedCreds || []
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <h3 style={{ margin: 0, fontSize: 16, fontWeight: 600 }}>Reuse Existing Credentials</h3>
        <p style={{ margin: 0, fontSize: 12, color: 'var(--text-muted)' }}>
          This connector shares credentials with <code>{flow.shared_with}</code>. Hakuna will reuse the same API key — no separate setup needed.
        </p>

        {matches.length === 0 && (
          <div style={{ padding: '12px 16px', borderRadius: 8, background: '#eab30818', border: '1px solid #eab30840', fontSize: 12, color: 'var(--text)' }}>
            No credentials found for <strong>{flow.shared_with}</strong>. Please set up that connector first, then return here.
          </div>
        )}

        {matches.length > 1 && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <label style={labelStyle}>Select credential</label>
            {matches.map(c => (
              <button
                key={c.id}
                onClick={() => onComplete(c.id, c.connected_user)}
                style={{
                  textAlign: 'left', padding: '10px 12px', borderRadius: 8,
                  border: '1px solid var(--border)', background: 'var(--bg)',
                  color: 'var(--text)', cursor: 'pointer', fontSize: 13,
                }}
              >
                <div style={{ fontWeight: 600 }}>{c.name}</div>
                {c.connected_user && <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{c.connected_user}</div>}
              </button>
            ))}
          </div>
        )}

        <div style={{ display: 'flex', gap: 8 }}>
          <Button onClick={onSkip} style={{ background: 'transparent', color: 'var(--text-muted)', border: '1px solid var(--border)' }}>
            Skip
          </Button>
        </div>
      </div>
    )
  }

  return <div>Unknown auth pattern: {flow.pattern}</div>
}

const inputStyle = {
  width: '100%', padding: '8px 12px', background: 'var(--bg)', border: '1px solid var(--border)',
  borderRadius: 8, color: 'var(--text)', fontSize: 13, boxSizing: 'border-box',
}
const labelStyle = { fontSize: 12, color: 'var(--text-muted)', marginBottom: 4, display: 'block' }
