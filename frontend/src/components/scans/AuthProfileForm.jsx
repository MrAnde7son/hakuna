import React, { useEffect, useMemo, useState } from 'react'
import { createPortal } from 'react-dom'
import { useTranslation } from 'react-i18next'
import { X, Save, Plus, ChevronDown, ChevronRight, Sparkles } from 'lucide-react'
import {
  createAuthProfile, updateAuthProfile, getCredentials, createCredential,
  detectAuthFlow,
} from '../../api.js'
import { Button, Input, Select, useToast } from '../shared/ui.jsx'

// ── Profile types ────────────────────────────────────────────
const PROFILE_TYPES = [
  {
    value: 'static',
    label: 'Static credential',
    hint: 'Attach a credential (basic, bearer, API key, cookie) directly as headers. No login flow.',
  },
  {
    value: 'form_login',
    label: 'Form login',
    hint: 'Drive a browser through a login form to obtain a session cookie, then replay it on scan requests.',
  },
]

// ── Form login templates — pre-filled step sequences ─────────
const FLOW_TEMPLATES = {
  email_password: {
    label: 'Email + password form',
    successHint: 'Typical: URL matches /dashboard or similar post-login path',
    build: () => ([
      { action: 'goto', url: '' },
      { action: 'fill', selector: 'input[type=email], #email, input[name=email]', value_from: 'username' },
      { action: 'fill', selector: 'input[type=password], #password, input[name=password]', value_from: 'password' },
      { action: 'click', selector: 'button[type=submit]' },
      { action: 'wait_for_url', pattern: '/dashboard', timeout_ms: 10000 },
    ]),
  },
  username_password: {
    label: 'Username + password form',
    successHint: 'Typical: URL changes off /login',
    build: () => ([
      { action: 'goto', url: '' },
      { action: 'fill', selector: 'input[name=username], #username', value_from: 'username' },
      { action: 'fill', selector: 'input[type=password], #password, input[name=password]', value_from: 'password' },
      { action: 'click', selector: 'button[type=submit]' },
      { action: 'wait_for_url', pattern: '^(?!.*/login)', timeout_ms: 10000 },
    ]),
  },
  custom: {
    label: 'Custom',
    successHint: null,
    build: () => ([{ action: 'goto', url: '' }]),
  },
}

const SUCCESS_TYPES = [
  { value: 'url_matches', label: 'URL matches regex' },
  { value: 'cookie_present', label: 'Cookie present' },
  { value: 'element_visible', label: 'Element visible' },
]

// ── Credential auth types for inline creation ────────────────
const CRED_AUTH_TYPES = [
  { value: 'basic',   label: 'Basic (username + password)' },
  { value: 'bearer',  label: 'Bearer token' },
  { value: 'api_key', label: 'API key in custom header' },
  { value: 'cookie',  label: 'Raw cookie string' },
]

export default function AuthProfileForm({ profile, onClose, onSaved }) {
  const { t } = useTranslation()
  const toast = useToast()
  const isNew = !profile?.id

  const [credentials, setCredentials] = useState([])
  const [profileType, setProfileType] = useState(profile?.profile_type || 'form_login')
  const [name, setName] = useState(profile?.name || '')
  const [credentialId, setCredentialId] = useState(profile?.credential_id || '')
  const [loginUrl, setLoginUrl] = useState(profile?.login_url || '')
  const [flow, setFlow] = useState(profile?.login_flow?.length ? profile.login_flow : FLOW_TEMPLATES.email_password.build())
  const [template, setTemplate] = useState('email_password')
  const [showRawJson, setShowRawJson] = useState(false)
  const [flowJson, setFlowJson] = useState('')
  const [flowError, setFlowError] = useState(null)
  const [successCondition, setSuccessCondition] = useState(
    profile?.success_condition?.type ? profile.success_condition : { type: 'url_matches', pattern: '/dashboard' }
  )
  const [ttl, setTtl] = useState(profile?.session_ttl_seconds || 900)
  const [saving, setSaving] = useState(false)
  const [showInlineCred, setShowInlineCred] = useState(false)
  const [detecting, setDetecting] = useState(false)
  const [detectNote, setDetectNote] = useState(null)

  // Credentials limited to types the current profile_type can consume.
  const credOptions = useMemo(() => {
    if (profileType === 'form_login') {
      // Only basic makes sense — login flows fill username/password
      return credentials.filter(c => (c.auth_type || '').toLowerCase() === 'basic')
    }
    return credentials
  }, [credentials, profileType])

  const refreshCredentials = async (selectId = null) => {
    try {
      const rows = await getCredentials()
      const list = Array.isArray(rows) ? rows : (rows?.items || [])
      setCredentials(list)
      if (selectId) setCredentialId(selectId)
    } catch (_) { /* noop */ }
  }

  useEffect(() => { refreshCredentials() }, [])

  // Keep raw JSON and flow array in sync when toggling the view.
  useEffect(() => {
    if (showRawJson) setFlowJson(JSON.stringify(flow, null, 2))
  }, [showRawJson])

  const applyTemplate = (tpl) => {
    setTemplate(tpl)
    if (FLOW_TEMPLATES[tpl]) {
      const built = FLOW_TEMPLATES[tpl].build()
      // Preserve login_url if the user has typed one
      if (loginUrl && built[0]?.action === 'goto') built[0].url = loginUrl
      setFlow(built)
    }
  }

  const onAutoDetect = async () => {
    if (!loginUrl.trim()) {
      toast.error(t('authProfiles.errUrlRequired', 'Login URL is required'))
      return
    }
    setDetecting(true)
    setDetectNote(null)
    try {
      const res = await detectAuthFlow(loginUrl.trim())
      if (!res.success) {
        toast.error(res.error || t('authProfiles.detectFailed', 'Auto-detect failed'))
        return
      }
      setFlow(res.login_flow || [])
      if (res.success_condition?.type) setSuccessCondition(res.success_condition)
      setTemplate('custom')
      setDetectNote(res.notes || null)
      toast.success(t('authProfiles.detectOk', 'Flow proposed — review and save'))
    } catch (e) {
      toast.error(e.message || t('authProfiles.detectFailed', 'Auto-detect failed'))
    } finally {
      setDetecting(false)
    }
  }

  const commitRawJson = () => {
    try {
      const parsed = JSON.parse(flowJson)
      if (!Array.isArray(parsed)) throw new Error('flow must be an array')
      setFlow(parsed)
      setFlowError(null)
      return parsed
    } catch (e) {
      setFlowError(e.message || 'Invalid JSON')
      return null
    }
  }

  const onSubmit = async () => {
    if (!name.trim()) { toast.error(t('authProfiles.errNameRequired', 'Name is required')); return }
    if (!credentialId) { toast.error(t('authProfiles.errCredRequired', 'Pick a credential')); return }

    let finalFlow = flow
    if (profileType === 'form_login') {
      if (showRawJson) {
        const parsed = commitRawJson()
        if (!parsed) return
        finalFlow = parsed
      }
      if (!loginUrl.trim()) { toast.error(t('authProfiles.errUrlRequired', 'Login URL is required')); return }
      if (!finalFlow?.length) { toast.error(t('authProfiles.errFlowEmpty', 'Flow must have at least one step')); return }
      if (!successCondition?.type) { toast.error(t('authProfiles.errSuccessRequired', 'Pick a success condition')); return }
    }

    const payload = {
      name: name.trim(),
      profile_type: profileType,
      credential_id: credentialId,
      login_url: profileType === 'form_login' ? loginUrl.trim() : null,
      login_flow: profileType === 'form_login' ? finalFlow : [],
      success_condition: profileType === 'form_login' ? successCondition : {},
      session_ttl_seconds: Number(ttl) || 900,
    }

    setSaving(true)
    try {
      if (isNew) await createAuthProfile(payload)
      else await updateAuthProfile(profile.id, payload)
      toast.success(isNew ? t('authProfiles.created', 'Profile created') : t('authProfiles.updated', 'Profile updated'))
      onSaved()
    } catch (e) {
      toast.error(e.message || t('authProfiles.saveFailed', 'Save failed'))
    } finally {
      setSaving(false)
    }
  }

  const body = (
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000,
    }}>
      <div style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)',
        borderRadius: 8, padding: 24, width: 680, maxHeight: '92vh', overflow: 'auto',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <h2 style={{ margin: 0, fontSize: 18 }}>
            {isNew ? t('authProfiles.new', 'New profile') : t('authProfiles.edit', 'Edit profile')}
          </h2>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}>
            <X size={18} />
          </button>
        </div>

        {/* Type picker */}
        <Field label={t('authProfiles.fieldType', 'Profile type')}>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {PROFILE_TYPES.map(pt => (
              <label
                key={pt.value}
                style={{
                  flex: 1, minWidth: 260,
                  padding: 10, border: `1px solid ${profileType === pt.value ? 'var(--accent)' : 'var(--border)'}`,
                  background: profileType === pt.value ? 'rgba(99,102,241,0.06)' : 'transparent',
                  borderRadius: 6, cursor: 'pointer',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <input
                    type="radio" name="profile_type" value={pt.value}
                    checked={profileType === pt.value}
                    onChange={() => setProfileType(pt.value)}
                    style={{ accentColor: 'var(--accent)' }}
                  />
                  <strong style={{ fontSize: 13 }}>{t(`authProfiles.type.${pt.value}`, pt.label)}</strong>
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4, marginLeft: 22 }}>
                  {t(`authProfiles.typeHint.${pt.value}`, pt.hint)}
                </div>
              </label>
            ))}
          </div>
        </Field>

        {!isNew && profileType !== (profile?.profile_type || 'form_login') && (
          <div style={{
            margin: '0 0 14px', padding: '8px 10px', borderRadius: 4,
            background: 'rgba(234,179,8,0.08)', border: '1px solid rgba(234,179,8,0.25)',
            color: '#a16207', fontSize: 11, lineHeight: 1.4,
          }}>
            {t('authProfiles.typeSwitchWarn', 'Switching profile type will clear type-specific settings (login URL, flow, success condition) when you save.')}
          </div>
        )}

        <Field label={t('authProfiles.fieldName', 'Name')}>
          <Input value={name} onChange={setName} placeholder="e.g. prod-app-admin" />
        </Field>

        <Field label={t('authProfiles.fieldCredential', 'Credential')}>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <div style={{ flex: 1 }}>
              <Select
                value={credentialId}
                onChange={setCredentialId}
                options={credOptions.map(c => ({ value: c.id, label: `${c.name} (${c.auth_type})` }))}
                placeholder={
                  credOptions.length === 0
                    ? t('authProfiles.noCredentials', 'No compatible credentials — create one →')
                    : t('authProfiles.pickCredential', 'Pick a credential')
                }
              />
            </div>
            <Button variant="secondary" size="sm" onClick={() => setShowInlineCred(v => !v)}>
              <Plus size={14} /> {t('authProfiles.newCredential', 'New')}
            </Button>
          </div>
          {profileType === 'form_login' && (
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
              {t('authProfiles.credentialHintFormLogin', 'Only basic credentials are shown — form_login steps reference "username" and "password" via value_from.')}
            </div>
          )}
          {showInlineCred && (
            <InlineCredentialForm
              profileType={profileType}
              onCancel={() => setShowInlineCred(false)}
              onCreated={async (newId) => {
                setShowInlineCred(false)
                await refreshCredentials(newId)
              }}
            />
          )}
        </Field>

        {/* form_login-only fields */}
        {profileType === 'form_login' && (
          <>
            <Field label={t('authProfiles.fieldLoginUrl', 'Login URL')}>
              <div style={{ display: 'flex', gap: 8 }}>
                <div style={{ flex: 1 }}>
                  <Input
                    value={loginUrl}
                    onChange={v => {
                      setLoginUrl(v)
                      // Keep the first goto step's URL in sync
                      setFlow(f => {
                        if (!f?.length) return f
                        const copy = [...f]
                        if (copy[0]?.action === 'goto') copy[0] = { ...copy[0], url: v }
                        return copy
                      })
                    }}
                    placeholder="https://app.example.com/login"
                  />
                </div>
                <Button variant="secondary" size="sm" onClick={onAutoDetect} disabled={detecting || !loginUrl.trim()}>
                  <Sparkles size={14} />
                  {detecting ? t('authProfiles.detecting', 'Detecting…') : t('authProfiles.autoDetect', 'Auto-detect')}
                </Button>
              </div>
              {detectNote && (
                <div style={{
                  marginTop: 6, fontSize: 11, color: 'var(--text-muted)',
                  padding: '6px 8px', background: 'rgba(99,102,241,0.08)', borderRadius: 4,
                }}>
                  <Sparkles size={11} style={{ verticalAlign: -1, marginRight: 4 }} />
                  {detectNote}
                </div>
              )}
            </Field>

            <Field label={t('authProfiles.fieldTemplate', 'Login flow template')}>
              <Select
                value={template}
                onChange={applyTemplate}
                options={Object.entries(FLOW_TEMPLATES).map(([k, v]) => ({
                  value: k, label: t(`authProfiles.template.${k}`, v.label),
                }))}
              />
            </Field>

            {/* Readable flow preview (non-JSON) */}
            {!showRawJson && (
              <div style={{
                border: '1px solid var(--border)', borderRadius: 6, padding: 10,
                background: 'var(--bg-secondary)', marginBottom: 14, fontSize: 12,
              }}>
                <div style={{ fontWeight: 600, marginBottom: 6, color: 'var(--text-secondary)' }}>
                  {t('authProfiles.flowPreview', 'Flow preview')} ({flow.length} {t('authProfiles.steps', { count: flow.length, defaultValue: 'steps' })})
                </div>
                <ol style={{ margin: 0, paddingLeft: 18, color: 'var(--text-muted)' }}>
                  {flow.map((step, i) => (
                    <li key={i} style={{ marginBottom: 4, fontFamily: 'monospace', fontSize: 11 }}>
                      <strong>{step.action}</strong>
                      {step.selector && <> <code>{step.selector}</code></>}
                      {step.url && <> <code>{step.url}</code></>}
                      {step.value_from && <> ← <em>{step.value_from}</em></>}
                      {step.pattern && <> ~ <code>{step.pattern}</code></>}
                    </li>
                  ))}
                </ol>
                <button
                  onClick={() => setShowRawJson(true)}
                  style={{
                    marginTop: 8, background: 'none', border: 'none', cursor: 'pointer',
                    color: 'var(--accent)', fontSize: 11, padding: 0,
                  }}
                >
                  {t('authProfiles.editRawJson', 'Edit raw JSON')}
                </button>
              </div>
            )}

            {showRawJson && (
              <Field label={t('authProfiles.fieldFlowJson', 'Login flow (raw JSON)')}>
                <textarea
                  value={flowJson}
                  onChange={e => { setFlowJson(e.target.value); setFlowError(null) }}
                  onBlur={commitRawJson}
                  style={{
                    width: '100%', minHeight: 160, fontFamily: 'monospace', fontSize: 12,
                    background: 'var(--bg-input)', border: '1px solid var(--border)',
                    borderRadius: 6, padding: 10, color: 'var(--text-primary)',
                  }}
                />
                {flowError && <div style={{ color: 'var(--danger)', fontSize: 12 }}>{flowError}</div>}
                <button
                  onClick={() => { commitRawJson(); setShowRawJson(false) }}
                  style={{
                    marginTop: 4, background: 'none', border: 'none', cursor: 'pointer',
                    color: 'var(--accent)', fontSize: 11, padding: 0,
                  }}
                >
                  {t('authProfiles.hideRawJson', 'Back to preview')}
                </button>
              </Field>
            )}

            <Field label={t('authProfiles.fieldSuccess', 'Success condition')}>
              <div style={{ display: 'flex', gap: 8 }}>
                <Select
                  value={successCondition.type}
                  onChange={v => setSuccessCondition(
                    v === 'url_matches' ? { type: v, pattern: successCondition.pattern || '' }
                    : v === 'cookie_present' ? { type: v, name: successCondition.name || '' }
                    : { type: v, selector: successCondition.selector || '' }
                  )}
                  options={SUCCESS_TYPES}
                />
                {successCondition.type === 'url_matches' && (
                  <Input value={successCondition.pattern || ''}
                         onChange={v => setSuccessCondition({ ...successCondition, pattern: v })}
                         placeholder="/dashboard" />
                )}
                {successCondition.type === 'cookie_present' && (
                  <Input value={successCondition.name || ''}
                         onChange={v => setSuccessCondition({ ...successCondition, name: v })}
                         placeholder="session" />
                )}
                {successCondition.type === 'element_visible' && (
                  <Input value={successCondition.selector || ''}
                         onChange={v => setSuccessCondition({ ...successCondition, selector: v })}
                         placeholder="[data-testid=user-menu]" />
                )}
              </div>
            </Field>

            <Field label={t('authProfiles.fieldTtl', 'Session TTL (seconds)')}>
              <Input value={String(ttl)} onChange={v => setTtl(v)} placeholder="900" />
            </Field>
          </>
        )}

        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 16 }}>
          <Button variant="secondary" onClick={onClose}>{t('common.cancel', 'Cancel')}</Button>
          <Button onClick={onSubmit} disabled={saving}>
            <Save size={14} /> {saving ? t('common.saving', 'Saving…') : t('common.save', 'Save')}
          </Button>
        </div>
      </div>
    </div>
  )

  return createPortal(body, document.body)
}

function Field({ label, children }) {
  return (
    <div style={{ marginBottom: 14 }}>
      <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 4, fontWeight: 500 }}>{label}</div>
      {children}
    </div>
  )
}

// ─────────────────────────────────────────────────────────────
// Inline credential creator — avoids bouncing to Integrations
// ─────────────────────────────────────────────────────────────
function InlineCredentialForm({ profileType, onCancel, onCreated }) {
  const { t } = useTranslation()
  const toast = useToast()
  // form_login can only consume basic; static picks any.
  const initialAuthType = profileType === 'form_login' ? 'basic' : 'basic'
  const [authType, setAuthType] = useState(initialAuthType)
  const [name, setName] = useState('')
  const [values, setValues] = useState({})
  const [saving, setSaving] = useState(false)

  const authOptions = profileType === 'form_login'
    ? CRED_AUTH_TYPES.filter(o => o.value === 'basic')
    : CRED_AUTH_TYPES

  const onSave = async () => {
    if (!name.trim()) { toast.error(t('authProfiles.errCredName', 'Credential name required')); return }
    setSaving(true)
    try {
      const res = await createCredential({
        name: name.trim(),
        connector_id: 'generic',
        auth_type: authType,
        values,
      })
      toast.success(t('authProfiles.credCreated', 'Credential created'))
      onCreated(res.id)
    } catch (e) {
      toast.error(e.message || t('authProfiles.credCreateFailed', 'Credential create failed'))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div style={{
      marginTop: 10, padding: 12,
      border: '1px solid var(--border)', borderRadius: 6,
      background: 'var(--bg-secondary)',
    }}>
      <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 8 }}>
        {t('authProfiles.newCredentialTitle', 'New credential')}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 8 }}>
        <div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 3 }}>
            {t('authProfiles.credName', 'Name')}
          </div>
          <Input value={name} onChange={setName} placeholder="prod-app-admin" />
        </div>
        <div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 3 }}>
            {t('authProfiles.credAuthType', 'Auth type')}
          </div>
          <Select value={authType} onChange={v => { setAuthType(v); setValues({}) }} options={authOptions} />
        </div>
      </div>

      {authType === 'basic' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
          <Input value={values.username || ''} onChange={v => setValues({ ...values, username: v })} placeholder="username" />
          <Input value={values.password || ''} onChange={v => setValues({ ...values, password: v })} placeholder="password" />
        </div>
      )}
      {authType === 'bearer' && (
        <Input value={values.token || ''} onChange={v => setValues({ ...values, token: v })} placeholder="bearer token" />
      )}
      {authType === 'api_key' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: 8 }}>
          <Input value={values._header_name || ''} onChange={v => setValues({ ...values, _header_name: v })} placeholder="X-API-Key" />
          <Input value={values.api_key || ''} onChange={v => setValues({ ...values, api_key: v })} placeholder="api key value" />
        </div>
      )}
      {authType === 'cookie' && (
        <Input value={values.cookie || ''} onChange={v => setValues({ ...values, cookie: v })} placeholder="session=abc; csrf=xyz" />
      )}

      <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end', marginTop: 10 }}>
        <Button variant="secondary" size="sm" onClick={onCancel}>{t('common.cancel', 'Cancel')}</Button>
        <Button size="sm" onClick={onSave} disabled={saving}>
          {saving ? t('common.saving', 'Saving…') : t('authProfiles.createCredential', 'Create')}
        </Button>
      </div>
    </div>
  )
}
