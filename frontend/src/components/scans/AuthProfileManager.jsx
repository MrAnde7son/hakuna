import React, { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Plus, Edit2, Trash2, KeyRound, CheckCircle, XCircle } from 'lucide-react'
import {
  listAuthProfiles, deleteAuthProfile, testAuthProfile,
} from '../../api.js'
import { Card, PageHeader, Button, Spinner, EmptyState, useToast, useConfirm } from '../shared/ui.jsx'
import AuthProfileForm from './AuthProfileForm.jsx'

export default function AuthProfileManager() {
  const { t } = useTranslation()
  const toast = useToast()
  const confirm = useConfirm()

  const [profiles, setProfiles] = useState([])
  const [loading, setLoading] = useState(true)
  const [editing, setEditing] = useState(null)       // profile object being edited, or {} for new
  const [testResult, setTestResult] = useState({})   // { [id]: { success, error, captured_cookies, captured_headers } }
  const [testing, setTesting] = useState({})         // { [id]: bool }

  const load = async () => {
    setLoading(true)
    try {
      const rows = await listAuthProfiles()
      setProfiles(rows || [])
    } catch (e) {
      toast.error(t('authProfiles.loadFailed', 'Failed to load auth profiles'))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const onDelete = async (profile) => {
    const ok = await confirm({
      title: t('authProfiles.deleteTitle', 'Delete auth profile?'),
      message: t('authProfiles.deleteConfirm', 'This cannot be undone.'),
    })
    if (!ok) return
    try {
      await deleteAuthProfile(profile.id)
      toast.success(t('authProfiles.deleted', 'Auth profile deleted'))
      load()
    } catch (e) {
      toast.error(t('authProfiles.deleteFailed', 'Delete failed'))
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
        title={t('authProfiles.title', 'Auth Profiles')}
        subtitle={t('authProfiles.subtitle', 'Login flows for authenticated VM audits')}
        action={
          <Button onClick={() => setEditing({})}>
            <Plus size={14} /> {t('authProfiles.new', 'New profile')}
          </Button>
        }
      />

      {profiles.length === 0 ? (
        <EmptyState
          icon={KeyRound}
          title={t('authProfiles.emptyTitle', 'No auth profiles yet')}
          sub={t('authProfiles.emptySub', 'Create one to scan authenticated parts of a web app.')}
        />
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {profiles.map(p => (
            <Card key={p.id}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: 12 }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <strong style={{ fontSize: 14 }}>{p.name}</strong>
                    <span style={{
                      fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.05em',
                      padding: '2px 6px', borderRadius: 3,
                      background: (p.profile_type === 'static') ? 'rgba(14,165,233,0.12)' : 'rgba(236,72,153,0.12)',
                      color: (p.profile_type === 'static') ? '#0ea5e9' : '#ec4899',
                    }}>
                      {p.profile_type === 'static'
                        ? t('authProfiles.type.static', 'static')
                        : t('authProfiles.type.form_login', 'form login')}
                    </span>
                    {p.login_url && (
                      <code style={{ fontSize: 11, color: 'var(--text-muted)' }}>{p.login_url}</code>
                    )}
                    {p.session_cached && (
                      <span style={{ fontSize: 10, color: 'var(--success)' }}>
                        · {t('authProfiles.cached', 'session cached')}
                      </span>
                    )}
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                    {p.profile_type === 'form_login' && (
                      <>
                        {t('authProfiles.stepsN', { count: (p.login_flow || []).length, defaultValue: '{{count}} steps' })}
                        {' · '}
                        {t('authProfiles.ttl', { seconds: p.session_ttl_seconds, defaultValue: '{{seconds}}s TTL' })}
                      </>
                    )}
                    {p.profile_type === 'static' && (
                      <>{t('authProfiles.staticHint', 'Headers from credential, replayed on every request')}</>
                    )}
                  </div>
                  {testResult[p.id] && (
                    <div style={{
                      marginTop: 6, fontSize: 12,
                      color: testResult[p.id].success ? 'var(--success)' : 'var(--danger)',
                      display: 'flex', alignItems: 'center', gap: 6,
                    }}>
                      {testResult[p.id].success ? <CheckCircle size={14} /> : <XCircle size={14} />}
                      {testResult[p.id].success
                        ? t('authProfiles.testOk', {
                            cookies: (testResult[p.id].captured_cookies || []).length,
                            headers: (testResult[p.id].captured_headers || []).length,
                            defaultValue: 'Login succeeded — {{cookies}} cookies, {{headers}} headers captured',
                          })
                        : testResult[p.id].error}
                    </div>
                  )}
                </div>
                <Button
                  variant="secondary" size="sm"
                  onClick={() => onTest(p)} disabled={testing[p.id]}
                >
                  {testing[p.id]
                    ? t('authProfiles.testing', 'Testing…')
                    : t('authProfiles.test', 'Test login')}
                </Button>
                <button
                  onClick={() => setEditing(p)}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 6 }}
                  title={t('common.edit', 'Edit')}
                ><Edit2 size={16} /></button>
                <button
                  onClick={() => onDelete(p)}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--danger)', padding: 6 }}
                  title={t('common.delete', 'Delete')}
                ><Trash2 size={16} /></button>
              </div>
            </Card>
          ))}
        </div>
      )}

      {editing !== null && (
        <AuthProfileForm
          profile={editing}
          onClose={() => setEditing(null)}
          onSaved={() => { setEditing(null); load() }}
        />
      )}
    </div>
  )
}
