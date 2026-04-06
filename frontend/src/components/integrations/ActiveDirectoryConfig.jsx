import { useState } from 'react'
import { Shield, ChevronDown, ChevronRight, CheckCircle, XCircle, Loader2 } from 'lucide-react'
import { adTestConnection } from '../../api.js'
import { useTranslation } from 'react-i18next'

const inputStyle = {
  width: '100%', padding: '8px 12px', borderRadius: 6,
  border: '1px solid var(--border)', background: 'var(--bg-secondary)',
  color: 'var(--text-primary)', fontSize: 14, boxSizing: 'border-box',
}
const labelStyle = { display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4, color: 'var(--text-secondary)' }
const sectionTitle = { fontSize: 13, fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }
const fieldGroup = { display: 'flex', flexDirection: 'column', gap: 12 }

export default function ActiveDirectoryConfig({ value, onChange }) {
  const { t } = useTranslation()
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState(null)

  const config = {
    host: '', port: 636, bind_dn: '', bind_password: '', base_dn: '',
    use_ssl: true, use_starttls: false, verify_ssl: true,
    auth_mode: 'simple_bind', ntlm_domain: '',
    mode: 'users', custom_filter: '', custom_attributes: '', page_size: 500,
    schedule: '0 */6 * * *',
    ...value,
  }

  const set = (key, val) => onChange({ ...config, [key]: val })

  const handleTestConnection = async () => {
    setTesting(true)
    setTestResult(null)
    try {
      const result = await adTestConnection({
        host: config.host,
        port: parseInt(config.port, 10) || 636,
        bind_dn: config.bind_dn,
        bind_password: config.bind_password,
        base_dn: config.base_dn,
        use_ssl: config.use_ssl,
        use_starttls: config.use_starttls,
        verify_ssl: config.verify_ssl,
        auth_mode: config.auth_mode,
        ntlm_domain: config.ntlm_domain || null,
      })
      setTestResult(result)
    } catch (err) {
      setTestResult({ ok: false, error: err.message || 'Connection failed' })
    } finally {
      setTesting(false)
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Connection */}
      <div>
        <div style={sectionTitle}>Connection</div>
        <div style={fieldGroup}>
          <div>
            <label style={labelStyle}>Domain Controller Host/IP</label>
            <input style={inputStyle} value={config.host} onChange={e => set('host', e.target.value)}
              placeholder="dc01.corp.example.com" />
          </div>
          <div style={{ display: 'flex', gap: 12 }}>
            <div style={{ flex: 1 }}>
              <label style={labelStyle}>Port</label>
              <input style={inputStyle} type="number" value={config.port}
                onChange={e => set('port', e.target.value)} placeholder="636" />
            </div>
            <div style={{ flex: 1 }}>
              <label style={labelStyle}>Use LDAPS</label>
              <select style={inputStyle} value={config.use_ssl ? 'true' : 'false'}
                onChange={e => { set('use_ssl', e.target.value === 'true'); if (e.target.value === 'true') set('use_starttls', false) }}>
                <option value="true">Yes (port 636)</option>
                <option value="false">No</option>
              </select>
            </div>
          </div>
          {!config.use_ssl && (
            <div style={{ display: 'flex', gap: 12 }}>
              <div style={{ flex: 1 }}>
                <label style={labelStyle}>Use StartTLS</label>
                <select style={inputStyle} value={config.use_starttls ? 'true' : 'false'}
                  onChange={e => set('use_starttls', e.target.value === 'true')}>
                  <option value="false">No</option>
                  <option value="true">Yes (port 389)</option>
                </select>
              </div>
              <div style={{ flex: 1 }} />
            </div>
          )}
          <div>
            <label style={labelStyle}>Verify TLS Certificate</label>
            <select style={inputStyle} value={config.verify_ssl ? 'true' : 'false'}
              onChange={e => set('verify_ssl', e.target.value === 'true')}>
              <option value="true">Yes (recommended)</option>
              <option value="false">No (self-signed certs)</option>
            </select>
          </div>
        </div>
      </div>

      {/* Authentication */}
      <div>
        <div style={sectionTitle}>Authentication</div>
        <div style={fieldGroup}>
          <div>
            <label style={labelStyle}>Auth Mode</label>
            <select style={inputStyle} value={config.auth_mode} onChange={e => set('auth_mode', e.target.value)}>
              <option value="simple_bind">Simple Bind (DN + Password)</option>
              <option value="ntlm">NTLM (Active Directory)</option>
            </select>
          </div>
          <div>
            <label style={labelStyle}>Bind DN</label>
            <input style={inputStyle} value={config.bind_dn} onChange={e => set('bind_dn', e.target.value)}
              placeholder="CN=hakuna-svc,OU=ServiceAccounts,DC=corp,DC=example,DC=com" />
          </div>
          <div>
            <label style={labelStyle}>Bind Password</label>
            <input style={{ ...inputStyle }} type="password" value={config.bind_password}
              onChange={e => set('bind_password', e.target.value)} />
          </div>
          {config.auth_mode === 'ntlm' && (
            <div>
              <label style={labelStyle}>NTLM Domain</label>
              <input style={inputStyle} value={config.ntlm_domain} onChange={e => set('ntlm_domain', e.target.value)}
                placeholder="CORP" />
            </div>
          )}
        </div>
      </div>

      {/* Directory */}
      <div>
        <div style={sectionTitle}>Directory</div>
        <div style={fieldGroup}>
          <div>
            <label style={labelStyle}>Base DN</label>
            <input style={inputStyle} value={config.base_dn} onChange={e => set('base_dn', e.target.value)}
              placeholder="DC=corp,DC=example,DC=com" />
          </div>
          <div>
            <label style={labelStyle}>Sync Mode</label>
            <select style={inputStyle} value={config.mode} onChange={e => set('mode', e.target.value)}>
              <option value="users">Users</option>
              <option value="computers">Computers</option>
              <option value="groups">Groups</option>
            </select>
          </div>
        </div>
      </div>

      {/* Advanced (collapsed) */}
      <div>
        <button onClick={() => setShowAdvanced(!showAdvanced)}
          style={{ display: 'flex', alignItems: 'center', gap: 6, background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-secondary)', fontSize: 13, fontWeight: 600, padding: 0, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          {showAdvanced ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
          Advanced
        </button>
        {showAdvanced && (
          <div style={{ ...fieldGroup, marginTop: 12 }}>
            <div>
              <label style={labelStyle}>Custom LDAP Filter</label>
              <input style={inputStyle} value={config.custom_filter} onChange={e => set('custom_filter', e.target.value)}
                placeholder="(department=Engineering)" />
              <div style={{ fontSize: 11, color: 'var(--text-tertiary)', marginTop: 2 }}>
                Appended to the base filter with AND
              </div>
            </div>
            <div>
              <label style={labelStyle}>Custom Attributes</label>
              <input style={inputStyle} value={config.custom_attributes} onChange={e => set('custom_attributes', e.target.value)}
                placeholder="extensionAttribute1, extensionAttribute2" />
              <div style={{ fontSize: 11, color: 'var(--text-tertiary)', marginTop: 2 }}>
                Comma-separated, merged with defaults
              </div>
            </div>
            <div style={{ display: 'flex', gap: 12 }}>
              <div style={{ flex: 1 }}>
                <label style={labelStyle}>Page Size</label>
                <input style={inputStyle} type="number" value={config.page_size}
                  onChange={e => set('page_size', parseInt(e.target.value, 10) || 500)} placeholder="500" />
              </div>
              <div style={{ flex: 1 }}>
                <label style={labelStyle}>Sync Schedule (cron)</label>
                <input style={inputStyle} value={config.schedule} onChange={e => set('schedule', e.target.value)}
                  placeholder="0 */6 * * *" />
                <div style={{ fontSize: 11, color: 'var(--text-tertiary)', marginTop: 2 }}>
                  Default: every 6 hours
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Test Connection */}
      <div>
        <button onClick={handleTestConnection} disabled={testing || !config.host || !config.bind_dn || !config.base_dn}
          style={{
            display: 'flex', alignItems: 'center', gap: 8, padding: '10px 20px',
            borderRadius: 8, border: '1px solid var(--border)',
            background: 'var(--bg-secondary)', color: 'var(--text-primary)',
            cursor: testing ? 'wait' : 'pointer', fontSize: 14, fontWeight: 500,
            opacity: (!config.host || !config.bind_dn || !config.base_dn) ? 0.5 : 1,
          }}>
          {testing ? <Loader2 size={16} style={{ animation: 'spin 1s linear infinite' }} /> : <Shield size={16} />}
          {testing ? 'Testing...' : 'Test Connection'}
        </button>

        {testResult && (
          <div style={{
            marginTop: 12, padding: '12px 16px', borderRadius: 8,
            background: testResult.ok ? 'var(--bg-success, rgba(34,197,94,0.1))' : 'var(--bg-error, rgba(239,68,68,0.1))',
            border: `1px solid ${testResult.ok ? 'var(--border-success, rgba(34,197,94,0.3))' : 'var(--border-error, rgba(239,68,68,0.3))'}`,
            display: 'flex', alignItems: 'flex-start', gap: 10,
          }}>
            {testResult.ok
              ? <CheckCircle size={18} style={{ color: 'var(--text-success, #22c55e)', flexShrink: 0, marginTop: 1 }} />
              : <XCircle size={18} style={{ color: 'var(--text-error, #ef4444)', flexShrink: 0, marginTop: 1 }} />
            }
            <div style={{ fontSize: 13 }}>
              {testResult.ok ? (
                <>
                  <div style={{ fontWeight: 600 }}>
                    Connected to {testResult.domain || config.host}
                    {testResult.user_count_estimate > 0 && ` — ~${testResult.user_count_estimate.toLocaleString()} users found`}
                  </div>
                  {testResult.warning && (
                    <div style={{ marginTop: 4, color: 'var(--text-warning, #f59e0b)' }}>{testResult.warning}</div>
                  )}
                  {testResult.server_version && (
                    <div style={{ marginTop: 2, color: 'var(--text-tertiary)' }}>Server: {testResult.server_version}</div>
                  )}
                </>
              ) : (
                <div style={{ color: 'var(--text-error, #ef4444)' }}>{testResult.error}</div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
