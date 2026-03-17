import { useState, useEffect } from 'react'
import { CheckCircle2, ExternalLink, Eye, EyeOff } from 'lucide-react'
import { Button, Spinner } from '../../shared/ui.jsx'
import { getAcquisitionFlow, validateCredentials, createCredential } from '../../../api.js'

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

  useEffect(() => {
    if (!connectorId) { onSkip(); return }
    getAcquisitionFlow(connectorId).then(f => {
      setFlow(f)
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
        const cred = await createCredential({
          name: `${connectorDetail?.name || connectorId} credentials`,
          connector_id: connectorId,
          auth_type: flow.pattern === 'oauth2' ? 'oauth2' : 'api_key',
          values: values,
          instance_url: instanceUrl || null,
          connected_user: result.connected_user || null,
        })
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

        {/* Step wizard */}
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
                {steps[activeStep].deeplink_path && instanceUrl && (
                  <a
                    href={`${instanceUrl.replace(/\/$/, '')}${steps[activeStep].deeplink_path}`}
                    target="_blank" rel="noopener noreferrer"
                    style={{
                      display: 'inline-flex', alignItems: 'center', gap: 4,
                      color: 'var(--accent)', fontSize: 12, marginBottom: 12, textDecoration: 'none',
                    }}
                  >
                    <ExternalLink size={12} /> Open in tool
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
            <Button onClick={handleValidate} disabled={validating || Object.keys(values).length === 0}>
              {validating ? <Spinner /> : 'Validate & Connect'}
            </Button>
          )}
          {validated && (
            <Button onClick={() => onComplete(null, validatedUser)}>
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
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16, alignItems: 'center', padding: 40 }}>
        <h3 style={{ margin: 0, fontSize: 16, fontWeight: 600 }}>Connect to {connectorDetail?.name}</h3>
        <p style={{ fontSize: 12, color: 'var(--text-muted)', textAlign: 'center' }}>
          Approve access in a popup. No credentials are shared with Hakuna.
        </p>

        {flow.instance_url_field && (
          <input
            placeholder={flow.instance_url_field.placeholder}
            value={instanceUrl}
            onChange={e => setInstanceUrl(e.target.value)}
            style={{ ...inputStyle, maxWidth: 400 }}
          />
        )}

        <Button onClick={() => alert('OAuth2 popup flow will connect to the provider\'s authorization endpoint.\nThis requires server-side OAuth routes to be configured.')}>
          Connect to {connectorDetail?.name}
        </Button>
        <Button onClick={onSkip} style={{ background: 'transparent', color: 'var(--text-muted)', border: '1px solid var(--border)' }}>
          Skip for now
        </Button>
      </div>
    )
  }

  // ── Auto Provision ──
  if (flow.pattern === 'auto_provision') {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <h3 style={{ margin: 0, fontSize: 16, fontWeight: 600 }}>Auto-Provision Service Account</h3>
        <div style={{
          padding: '10px 16px', borderRadius: 8, background: '#eab30818',
          border: '1px solid #eab30840', fontSize: 12, color: '#eab308',
        }}>
          These credentials are used once to create a dedicated Hakuna service account and are never stored.
        </div>

        {(flow.admin_credentials || []).map(field => (
          <div key={field.field}>
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

        <Button onClick={handleValidate} disabled={validating}>
          {validating ? <Spinner /> : 'Provision Hakuna Account'}
        </Button>
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
