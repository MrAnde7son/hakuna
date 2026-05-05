import React, { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  Plus, Edit2, Trash2, KeyRound, CheckCircle, XCircle,
  Monitor, Terminal, Radio, Globe, ChevronRight,
} from 'lucide-react'
import {
  listAuthProfiles, deleteAuthProfile, testAuthProfile,
  getCredentials, createCredential, updateCredential, deleteCredential,
  getCredential,
} from '../../api.js'
import { Card, PageHeader, Button, Spinner, EmptyState, useToast, useConfirm } from '../shared/ui.jsx'
import AuthProfileForm from './AuthProfileForm.jsx'

// Connector families. Keep in sync with credential_connector_ids in
// backend/agents/tools/*_tools.py.
const CONNECTORS = [
  { id: 'windows_host', label: 'Windows host',  hint: 'SMB, WMI, LDAP / Active Directory',   icon: Monitor },
  { id: 'linux_host',   label: 'Linux host',    hint: 'SSH',                                 icon: Terminal },
  { id: 'snmp_device',  label: 'SNMP device',   hint: 'Network gear, printers, appliances',  icon: Radio },
  { id: 'generic',      label: 'Generic / web', hint: 'Web auth profiles, custom targets',   icon: Globe },
]
const META = CONNECTORS.reduce((acc, c) => { acc[c.id] = c; return acc }, {})

export default function AuthProfileManager() {
  const { t } = useTranslation()
  const toast = useToast()
  const confirm = useConfirm()

  const [credentials, setCredentials] = useState([])
  const [profiles, setProfiles] = useState([])
  const [loading, setLoading] = useState(true)
  const [editingCred, setEditingCred] = useState(null)       // { id? } for edit, {} for new
  const [editingProfile, setEditingProfile] = useState(null) // AuthProfileForm trigger
  const [testResult, setTestResult] = useState({})
  const [testing, setTesting] = useState({})

  const load = async () => {
    setLoading(true)
    try {
      const [rows, profs] = await Promise.all([getCredentials(), listAuthProfiles()])
      setCredentials(Array.isArray(rows) ? rows : (rows?.items || []))
      setProfiles(profs || [])
    } catch (e) {
      toast.error(t('authProfiles.loadFailed', 'Failed to load credentials'))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  // Map credential_id → web AuthProfile so we can render the flow inline.
  const profileByCred = useMemo(() => {
    const m = {}
    profiles.forEach(p => { if (p.credential_id) m[p.credential_id] = p })
    return m
  }, [profiles])

  const onDeleteCred = async (cred) => {
    const linked = profileByCred[cred.id]
    const message = linked
      ? t('authProfiles.deleteCredLinkedConfirm', 'This will also delete the linked web auth profile "{{name}}". Continue?', { name: linked.name })
      : t('authProfiles.deleteCredConfirm', 'Scans referencing this credential will fail.')
    const ok = await confirm(message, {
      title: t('authProfiles.deleteCredTitle', 'Delete credential?'),
    })
    if (!ok) return
    try {
      if (linked) await deleteAuthProfile(linked.id)
      await deleteCredential(cred.id)
      toast.success(t('authProfiles.credDeleted', 'Credential deleted'))
      load()
    } catch (e) {
      toast.error(e.message || t('authProfiles.credDeleteFailed', 'Delete failed'))
    }
  }

  const onTest = async (profile) => {
    setTesting(s => ({ ...s, [profile.id]: true }))
    try {
      const result = await testAuthProfile(profile.id)
      setTestResult(s => ({ ...s, [profile.id]: result }))
    } catch (e) {
      setTestResult(s => ({ ...s, [profile.id]: { success: false, error: e.message || 'failed' } }))
    } finally {
      setTesting(s => ({ ...s, [profile.id]: false }))
    }
  }

  if (loading) return <div style={{ padding: 40, textAlign: 'center' }}><Spinner /></div>

  return (
    <div>
      <PageHeader
        title={t('authProfiles.pageTitle', 'Credentials')}
        subtitle={t('authProfiles.pageSubtitle', 'One place to manage secrets for audit scans (LDAP, SMB, SSH, WMI, SNMP) and web auth profiles for VM scans')}
        action={
          <Button onClick={() => setEditingCred({})}>
            <Plus size={14} /> {t('authProfiles.newCred', 'New credential')}
          </Button>
        }
      />

      {credentials.length === 0 ? (
        <EmptyState
          icon={KeyRound}
          title={t('authProfiles.credEmptyTitle', 'No credentials yet')}
          sub={t('authProfiles.credEmptySub', 'Add credentials for the hosts, devices, or web apps you want to scan.')}
        />
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {credentials.map(c => {
            const meta = META[c.connector_id] || META.generic
            const Icon = meta.icon
            const profile = profileByCred[c.id]
            return (
              <Card key={c.id}>
                <div style={{ padding: 12 }}>
                  {/* Credential row */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                    <div style={{
                      width: 32, height: 32, borderRadius: 6,
                      background: 'var(--bg-secondary)', display: 'flex',
                      alignItems: 'center', justifyContent: 'center',
                      color: 'var(--text-muted)',
                    }}>
                      <Icon size={16} />
                    </div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', gap: 8, alignItems: 'baseline' }}>
                        <strong style={{ fontSize: 14 }}>{c.name}</strong>
                        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                          {meta.label} · {c.auth_type || 'basic'}
                        </span>
                      </div>
                      {c.connected_user && (
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                          {c.connected_user}
                        </div>
                      )}
                    </div>
                    {!profile && (
                      <button
                        onClick={() => setEditingProfile({ credential_id: c.id, profile_type: 'form_login' })}
                        style={_linkBtn}
                        title={t('authProfiles.attachFlow', 'Attach web login flow')}
                      >
                        <Plus size={12} /> {t('authProfiles.attachFlow', 'Attach web login flow')}
                      </button>
                    )}
                    <button
                      onClick={() => setEditingCred({ id: c.id })}
                      style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 6 }}
                      title={t('common.edit', 'Edit')}
                    ><Edit2 size={16} /></button>
                    <button
                      onClick={() => onDeleteCred(c)}
                      style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--danger)', padding: 6 }}
                      title={t('common.delete', 'Delete')}
                    ><Trash2 size={16} /></button>
                  </div>

                  {/* Inline web-flow sub-panel */}
                  {profile && (
                    <div style={{
                      marginTop: 10, padding: 10,
                      borderLeft: '2px solid var(--accent)',
                      background: 'var(--bg-secondary)',
                      borderRadius: 4,
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <ChevronRight size={12} style={{ color: 'var(--accent)' }} />
                        <strong style={{ fontSize: 12 }}>
                          {profile.profile_type === 'form_login'
                            ? t('authProfiles.webFlow', 'Web login flow')
                            : t('authProfiles.webStatic', 'Static web headers')}
                        </strong>
                        <span style={{
                          fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.05em',
                          padding: '2px 6px', borderRadius: 3,
                          background: (profile.profile_type === 'static') ? 'rgba(14,165,233,0.12)' : 'rgba(236,72,153,0.12)',
                          color: (profile.profile_type === 'static') ? '#0ea5e9' : '#ec4899',
                        }}>{profile.profile_type}</span>
                        {profile.login_url && (
                          <code style={{ fontSize: 11, color: 'var(--text-muted)' }}>{profile.login_url}</code>
                        )}
                        {profile.session_cached && (
                          <span style={{ fontSize: 10, color: 'var(--success)' }}>
                            · {t('authProfiles.cached', 'session cached')}
                          </span>
                        )}
                        <div style={{ flex: 1 }} />
                        <Button variant="secondary" size="sm" onClick={() => onTest(profile)} disabled={testing[profile.id]}>
                          {testing[profile.id] ? t('authProfiles.testing', 'Testing…') : t('authProfiles.test', 'Test login')}
                        </Button>
                        <button
                          onClick={() => setEditingProfile(profile)}
                          style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 4 }}
                          title={t('common.edit', 'Edit')}
                        ><Edit2 size={14} /></button>
                      </div>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4, paddingLeft: 20 }}>
                        {profile.profile_type === 'form_login'
                          ? t('authProfiles.stepsN', { count: (profile.login_flow || []).length, defaultValue: '{{count}} steps' })
                            + ' · '
                            + t('authProfiles.ttl', { seconds: profile.session_ttl_seconds, defaultValue: '{{seconds}}s TTL' })
                          : t('authProfiles.staticHint', 'Headers from credential, replayed on every request')}
                      </div>
                      {testResult[profile.id] && (
                        <div style={{
                          marginTop: 6, fontSize: 12, paddingLeft: 20,
                          color: testResult[profile.id].success ? 'var(--success)' : 'var(--danger)',
                          display: 'flex', alignItems: 'center', gap: 6,
                        }}>
                          {testResult[profile.id].success ? <CheckCircle size={14} /> : <XCircle size={14} />}
                          {testResult[profile.id].success
                            ? t('authProfiles.testOk', {
                                cookies: (testResult[profile.id].captured_cookies || []).length,
                                headers: (testResult[profile.id].captured_headers || []).length,
                                defaultValue: 'Login succeeded — {{cookies}} cookies, {{headers}} headers captured',
                              })
                            : testResult[profile.id].error}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </Card>
            )
          })}
        </div>
      )}

      {editingCred !== null && (
        <CredentialDialog
          credentialId={editingCred.id}
          onClose={() => setEditingCred(null)}
          onSaved={() => { setEditingCred(null); load() }}
        />
      )}

      {editingProfile !== null && (
        <AuthProfileForm
          profile={editingProfile}
          onClose={() => setEditingProfile(null)}
          onSaved={() => { setEditingProfile(null); load() }}
        />
      )}
    </div>
  )
}

// ── Credential create/edit modal ─────────────────────────────

function CredentialDialog({ credentialId, onClose, onSaved }) {
  const { t } = useTranslation()
  const toast = useToast()
  const isEdit = !!credentialId

  const [loading, setLoading] = useState(isEdit)
  const [saving, setSaving] = useState(false)
  const [connectorId, setConnectorId] = useState('windows_host')
  const [name, setName] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [domain, setDomain] = useState('')
  const [community, setCommunity] = useState('')
  const [hasExistingPassword, setHasExistingPassword] = useState(false)
  const [hasExistingCommunity, setHasExistingCommunity] = useState(false)

  useEffect(() => {
    if (!isEdit) return
    let cancelled = false
    ;(async () => {
      try {
        const c = await getCredential(credentialId)
        if (cancelled) return
        setConnectorId(c.connector_id || 'windows_host')
        setName(c.name || '')
        const keys = c.value_keys || []
        const vals = c.values || {}
        setHasExistingPassword(keys.includes('password'))
        setHasExistingCommunity(keys.includes('community'))
        // Non-secret fields (username, domain) come back from the API;
        // secrets (password, community) do not and stay blank → the
        // "leave blank to keep" placeholder signals the existing value.
        if (vals.username) setUsername(vals.username)
        if (vals.domain) setDomain(vals.domain)
      } catch (e) {
        toast.error(e.message || 'Failed to load credential')
        onClose()
      } finally {
        if (!cancelled) setLoading(false)
      }
    })()
    return () => { cancelled = true }
  }, [credentialId]) // eslint-disable-line react-hooks/exhaustive-deps

  const isSnmp = connectorId === 'snmp_device'
  const requiresSecret = isEdit
    ? false  // edit: leave blank = keep existing
    : (isSnmp ? !!community.trim() : (!!username.trim() && !!password))
  const valid = name.trim() && (isEdit || requiresSecret)

  const onSave = async () => {
    if (!valid) return
    setSaving(true)
    try {
      if (isEdit) {
        // Merge: only send values the user typed; empty fields keep their
        // existing encrypted value. Backend treats "" as "delete this key".
        const values = {}
        if (isSnmp) {
          if (community) values.community = community
        } else {
          if (username) values.username = username
          if (password) values.password = password
          if (domain) values.domain = domain
        }
        await updateCredential(credentialId, {
          name: name.trim(),
          ...(Object.keys(values).length ? { values } : {}),
        })
        toast.success(t('authProfiles.credUpdated', 'Credential updated'))
      } else {
        const values = isSnmp
          ? { community }
          : { username, password, ...(domain ? { domain } : {}) }
        await createCredential({
          name: name.trim(),
          connector_id: connectorId,
          auth_type: 'basic',
          values,
        })
        toast.success(t('authProfiles.credCreated', 'Credential created'))
      }
      onSaved()
    } catch (e) {
      toast.error(e.message || t('authProfiles.credCreateFailed', 'Save failed'))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div style={_overlay} onClick={onClose}>
      <div style={_dialog} onClick={e => e.stopPropagation()}>
        <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center' }}>
          <div style={{ fontSize: 14, fontWeight: 600, flex: 1 }}>
            {isEdit
              ? t('authProfiles.editCredTitle', 'Edit credential')
              : t('authProfiles.newCredentialTitle', 'New credential')}
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', fontSize: 18, cursor: 'pointer', color: 'var(--text-muted)' }}>×</button>
        </div>

        {loading ? (
          <div style={{ padding: 40, textAlign: 'center' }}><Spinner /></div>
        ) : (
          <div style={{ padding: 18 }}>
            {!isEdit && (
              <div style={{
                display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 8, marginBottom: 12,
              }}>
                {CONNECTORS.map(c => {
                  const Icon = c.icon
                  const active = c.id === connectorId
                  return (
                    <button key={c.id} onClick={() => setConnectorId(c.id)} style={{
                      padding: 10, borderRadius: 6, textAlign: 'left', cursor: 'pointer',
                      background: active ? 'var(--accent-subtle, rgba(14,165,233,0.08))' : 'var(--bg)',
                      border: `1px solid ${active ? 'var(--accent)' : 'var(--border)'}`,
                      color: 'var(--text-primary)',
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, fontWeight: 600 }}>
                        <Icon size={14} /> {c.label}
                      </div>
                      <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 3 }}>{c.hint}</div>
                    </button>
                  )
                })}
              </div>
            )}

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              <input
                placeholder={t('authProfiles.credNamePlaceholder', 'Name (e.g. prod-domain-admin)')}
                value={name} onChange={e => setName(e.target.value)} style={_inp}
              />
              {!isSnmp && (
                <input
                  placeholder={t('authProfiles.credDomainPlaceholder', 'Domain (optional)')}
                  value={domain} onChange={e => setDomain(e.target.value)} style={_inp}
                />
              )}
              {isSnmp ? (
                <input
                  placeholder={hasExistingCommunity
                    ? t('authProfiles.credCommunityKeep', '••• (leave blank to keep)')
                    : t('authProfiles.credCommunityPlaceholder', 'SNMP community')}
                  value={community} onChange={e => setCommunity(e.target.value)} style={_inp}
                />
              ) : (
                <>
                  <input
                    placeholder={t('authProfiles.credUserPlaceholder', 'Username')}
                    value={username} onChange={e => setUsername(e.target.value)} style={_inp}
                  />
                  <input
                    placeholder={hasExistingPassword
                      ? t('authProfiles.credPassKeep', '••• (leave blank to keep)')
                      : t('authProfiles.credPassPlaceholder', 'Password')}
                    type="password" value={password} onChange={e => setPassword(e.target.value)} style={_inp}
                  />
                </>
              )}
            </div>

            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 14 }}>
              <Button variant="secondary" onClick={onClose}>
                {t('common.cancel', 'Cancel')}
              </Button>
              <Button onClick={onSave} disabled={!valid || saving}>
                {saving ? t('common.saving', 'Saving…') : t('common.save', 'Save')}
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Styles ───────────────────────────────────────────────────

const _inp = {
  padding: '8px 10px', borderRadius: 5,
  border: '1px solid var(--border)', background: 'var(--bg)',
  color: 'var(--text-primary)', fontSize: 12,
}

const _linkBtn = {
  display: 'inline-flex', alignItems: 'center', gap: 4,
  padding: '4px 8px', borderRadius: 4, cursor: 'pointer',
  background: 'transparent', border: '1px dashed var(--border)',
  color: 'var(--text-muted)', fontSize: 11,
}

const _overlay = {
  position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.45)',
  zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center',
}

const _dialog = {
  background: 'var(--bg)', border: '1px solid var(--border)',
  borderRadius: 8, width: 560, maxWidth: '92vw', maxHeight: '86vh',
  overflow: 'auto',
}
