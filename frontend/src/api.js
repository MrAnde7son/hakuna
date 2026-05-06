const API_ORIGIN = import.meta.env.VITE_API_URL || ''
const BASE = API_ORIGIN + '/api'

// ── Auth token helpers ──────────────────────────────────

export function getStoredToken() {
  return localStorage.getItem('auth_token')
}

export function setStoredToken(token) {
  localStorage.setItem('auth_token', token)
}

export function clearStoredToken() {
  localStorage.removeItem('auth_token')
  localStorage.removeItem('org_context')
}

// ── Campaign collaborator (external) session ───────────
// A separate token, set when a collaborator accepts an invite. When present,
// the whole UI runs in collaborator mode: their Bearer is sent on every call,
// no X-Org-Context, and the regular auth_token is ignored.

export function getCollaboratorSession() {
  const raw = localStorage.getItem('collab_session')
  if (!raw) return null
  try { return JSON.parse(raw) } catch { return null }
}

export function setCollaboratorSession(session) {
  if (session) localStorage.setItem('collab_session', JSON.stringify(session))
  else localStorage.removeItem('collab_session')
}

export function clearCollaboratorSession() {
  localStorage.removeItem('collab_session')
}

export function isCollaboratorMode() {
  return !!getCollaboratorSession()
}

export function getOrgContext() {
  return localStorage.getItem('org_context')
}

export function setOrgContext(orgId) {
  if (orgId) localStorage.setItem('org_context', orgId)
  else localStorage.removeItem('org_context')
}

// ── Core request function with auth ─────────────────────

const DEFAULT_TIMEOUT_MS = 30_000 // 30s timeout for mobile networks
const MAX_RETRIES = 2 // retry up to 2 times on network errors
const RETRY_DELAYS = [1000, 2000] // 1s, 2s backoff

// Track whether a 401 redirect is already in progress to prevent loops
let _redirecting = false

// Deduplicate concurrent GET requests to the same URL
const _inflight = new Map()

function isNetworkError(err) {
  return err instanceof TypeError || err.name === 'AbortError'
}

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
}

function formatErrorDetail(detail) {
  if (!detail) return null
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) {
    return detail.map(d => {
      if (typeof d === 'string') return d
      const loc = Array.isArray(d?.loc) ? d.loc.slice(1).join('.') : null
      const msg = d?.msg || JSON.stringify(d)
      return loc ? `${loc}: ${msg}` : msg
    }).join('; ')
  }
  if (typeof detail === 'object') return detail.msg || JSON.stringify(detail)
  return String(detail)
}

async function _doRequest(path, opts = {}) {
  const collab = getCollaboratorSession()
  const token = collab ? collab.access_token : getStoredToken()
  const orgContext = collab ? null : getOrgContext()

  const headers = { ...(opts.headers || {}) }
  if (token) headers['Authorization'] = `Bearer ${token}`
  if (orgContext) headers['X-Org-Context'] = orgContext
  // Send current locale for backend i18n
  const locale = localStorage.getItem('i18nextLng')
  if (locale) headers['Accept-Language'] = locale

  let lastError
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    // Wait before retrying (skip on first attempt)
    if (attempt > 0) await sleep(RETRY_DELAYS[attempt - 1])

    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), opts.timeout || DEFAULT_TIMEOUT_MS)

    try {
      const res = await fetch(`${BASE}${path}`, {
        ...opts,
        headers,
        signal: opts.signal || controller.signal,
      })
      clearTimeout(timeoutId)

      // Handle 401 — attempt token refresh, then redirect to login
      if (res.status === 401) {
        // Collaborators don't have a refresh path — clear and bounce to the
        // expired-session page (a fresh invite email is needed to re-accept).
        if (collab) {
          clearCollaboratorSession()
          if (!_redirecting && !window.location.pathname.startsWith('/campaigns/accept')) {
            _redirecting = true
            window.location.href = '/campaigns/accept?expired=1'
          }
          throw new Error('Collaborator session expired')
        }
        // Try refreshing the token once before giving up
        const refreshed = await tryRefreshToken()
        if (refreshed) {
          // Retry the original request with new token
          const newToken = getStoredToken()
          if (newToken) headers['Authorization'] = `Bearer ${newToken}`
          const retryRes = await fetch(`${BASE}${path}`, { ...opts, headers })
          if (retryRes.ok) return retryRes.json()
        }
        clearStoredToken()
        if (!_redirecting && window.location.pathname !== '/login' && window.location.pathname !== '/register') {
          _redirecting = true
          window.location.href = '/login'
        }
        throw new Error('Authentication required')
      }

      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }))
        const error = new Error(formatErrorDetail(err.detail) || 'Request failed')
        error.status = res.status
        throw error
      }
      return res.json()
    } catch (err) {
      clearTimeout(timeoutId)
      lastError = err
      // Only retry on network/timeout errors, not on HTTP errors
      if (!isNetworkError(err) || attempt === MAX_RETRIES) throw err
      // If the caller passed their own signal and it was aborted, don't retry
      if (opts.signal?.aborted) throw err
    }
  }
  throw lastError
}

// Deduplicate concurrent identical GET requests (e.g. from React StrictMode double-mount)
async function request(path, opts = {}) {
  const method = (opts.method || 'GET').toUpperCase()
  if (method !== 'GET') return _doRequest(path, opts)

  const key = path
  if (_inflight.has(key)) return _inflight.get(key)

  const promise = _doRequest(path, opts).finally(() => _inflight.delete(key))
  _inflight.set(key, promise)
  return promise
}

// ── Token refresh ──────────────────────────────────────

let _refreshPromise = null

async function tryRefreshToken() {
  const token = getStoredToken()
  if (!token) return false
  // Deduplicate concurrent refresh attempts
  if (_refreshPromise) return _refreshPromise
  _refreshPromise = (async () => {
    try {
      const res = await fetch(`${BASE}/auth/refresh`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` },
      })
      if (!res.ok) return false
      const data = await res.json()
      if (data.access_token) {
        setStoredToken(data.access_token)
        return true
      }
      return false
    } catch {
      return false
    } finally {
      _refreshPromise = null
    }
  })()
  return _refreshPromise
}

// ── Auth API ────────────────────────────────────────────

export const authRegister = (data) => request('/auth/register', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})

export const authLogin = (data) => request('/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})

export const authGoogleLogin = (credential) => request('/auth/google', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ credential }),
})

export const authMe = () => request('/auth/me')

export const authVerifyEmail = (token) => request('/auth/verify-email', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ token }),
})

export const authResendVerification = () => request('/auth/resend-verification', {
  method: 'POST',
})

export const authChangePassword = (data) => request('/auth/change-password', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})

export const authUpdateLocale = (locale) => request('/auth/locale', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ locale }),
})

export const authInviteUser = (data) => request('/auth/invite', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})

export const authListUsers = () => request('/auth/users')

export const authUpdateUser = (userId, data) => request(`/auth/users/${userId}`, {
  method: 'PATCH',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})

export const authListOrgs = () => request('/auth/orgs')

export const authCreateOrg = (data) => request('/auth/orgs', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})

export const authDeleteUser = (userId) => request(`/auth/users/${userId}`, { method: 'DELETE' })

export const authUpdateOrg = (orgId, data) => request(`/auth/orgs/${orgId}`, {
  method: 'PATCH',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})

export const authDeleteOrg = (orgId) => request(`/auth/orgs/${orgId}`, { method: 'DELETE' })

export const authMSSPClients = () => request('/auth/mssp/clients')

export const authMSSPInviteClient = (data) => request('/auth/mssp/invite-client', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})

export const getInviteInfo = (token) => request(`/auth/invite/${token}`)

export const acceptInvite = (data) => request('/auth/accept-invite', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})

// Custom Roles
export const authListRoles = () => request('/auth/roles')
export const authGetRole = (roleId) => request(`/auth/roles/${roleId}`)
export const authCreateRole = (data) => request('/auth/roles', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})
export const authUpdateRole = (roleId, data) => request(`/auth/roles/${roleId}`, {
  method: 'PATCH',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})
export const authDeleteRole = (roleId) => request(`/auth/roles/${roleId}`, { method: 'DELETE' })

export const authAddTagPermission = (roleId, data) => request(`/auth/roles/${roleId}/permissions`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})
export const authRemoveTagPermission = (roleId, permId) =>
  request(`/auth/roles/${roleId}/permissions/${permId}`, { method: 'DELETE' })

export const authGetUserCustomRoles = (userId) => request(`/auth/users/${userId}/custom-roles`)
export const authAssignCustomRole = (userId, roleId) =>
  request(`/auth/users/${userId}/custom-roles/${roleId}`, { method: 'POST' })
export const authUnassignCustomRole = (userId, roleId) =>
  request(`/auth/users/${userId}/custom-roles/${roleId}`, { method: 'DELETE' })

// SAML SSO
export const samlDiscover = (email) => request(`/saml/discover?email=${encodeURIComponent(email)}`)
export const getSamlConfig = () => request('/saml/config')
export const createSamlConfig = (data) => request('/saml/config', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})
export const updateSamlConfig = (data) => request('/saml/config', {
  method: 'PATCH',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})
export const deleteSamlConfig = () => request('/saml/config', { method: 'DELETE' })

// Onboarding
export const getOnboardingOptions = () => request('/onboarding/options')
export const getOnboardingStatus = () => request('/onboarding/status')
export const getOnboardingRecommendations = (data) => request('/onboarding/recommend', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})
export const applyOnboardingPackages = (data) => request('/onboarding/apply', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})
export const getOnboardingDomainInfo = (email) => request(`/onboarding/domain-info?email=${encodeURIComponent(email)}`)
export const skipOnboarding = () => request('/onboarding/skip', { method: 'POST' })

// Scans
export const getScans = () => request('/scans')
export const deleteScan = (id) => request(`/scans/${id}`, { method: 'DELETE' })
export const cancelScan = (id) => request(`/scans/${id}/cancel`, { method: 'POST' })
export const getScanStatus = (id) => request(`/scans/${id}`)
export const updateScanSchedule = (id, schedule) => request(`/scans/${id}/schedule`, {
  method: 'PATCH',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ schedule }),
})

// Upload threshold: files larger than 30MB use GCS signed URL to bypass Cloud Run limits
const GCS_UPLOAD_THRESHOLD = 30 * 1024 * 1024

export const uploadScan = async (file) => {
  if (file.size > GCS_UPLOAD_THRESHOLD) {
    // Step 1: Get a signed URL from the backend
    const { url, blob_name } = await request('/upload/signed-url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename: file.name, content_type: file.type || 'application/octet-stream' }),
    })
    // Step 2: Upload directly to GCS (no auth header — signed URL has its own auth)
    const putRes = await fetch(url, {
      method: 'PUT',
      headers: { 'Content-Type': file.type || 'application/octet-stream' },
      body: file,
    })
    if (!putRes.ok) throw new Error(`Upload to storage failed: ${putRes.statusText}`)
    // Step 3: Tell backend to ingest from GCS
    return request('/upload/gcs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ blob_name, filename: file.name }),
    })
  }
  // Small files: direct upload (original flow)
  const fd = new FormData()
  fd.append('file', file)
  return request('/upload', { method: 'POST', body: fd })
}

// NLP Search
export const nlpSearch = (q, scan_id) => {
  const params = new URLSearchParams({ q, ...(scan_id ? { scan_id } : {}) })
  return request(`/search/nlp?${params}`)
}

// NLP Report Query
export const nlpReportQuery = (query, scan_id = null) =>
  request('/reports/nlp-query', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query, scan_id }),
  })

// Assets
// Data sources
export const getSources = () => request('/sources')

export const getAssets = (params = {}) => {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null && v !== ''))
  return request(`/assets?${q}`)
}
// Returns { ids: number[], total, capped, cap } for "select all matching" UI.
export const getAssetIds = (params = {}) => getAssets({ ...params, ids_only: true })
export const getAssetTypes = () => request('/assets/types')
export const getAsset = (id) => request(`/assets/${id}`)
export const getAssetRiskBreakdown = (id) => request(`/assets/${id}/risk-breakdown`)
export const getAssetSources = (id) => request(`/assets/${id}/sources`)
export const getAssetSiemEvents = (id, params = {}) => {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null && v !== ''))
  return request(`/assets/${id}/siem-events?${q}`)
}
export const getAssetAlerts = (id, params = {}) => {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null && v !== ''))
  return request(`/assets/${id}/alerts?${q}`)
}
export const updateAsset = (id, data) => {
  const q = new URLSearchParams(Object.entries(data).filter(([, v]) => v != null && v !== ''))
  return request(`/assets/${id}?${q}`, { method: 'PATCH' })
}

// Findings
export const getFindings = (params = {}) => {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null && v !== ''))
  return request(`/findings?${q}`)
}
// Returns { ids: number[], total, capped, cap } for "select all matching" UI.
export const getFindingIds = (params = {}) => getFindings({ ...params, ids_only: true })
export const getFinding = (id) => request(`/findings/${id}`)
export const getFindingSources = (id) => request(`/findings/${id}/sources`)
export const getFindingProducts = () => request('/findings/products')
export const getFindingCpes = () => request('/findings/cpes')

// Remediation queue
export const getRemediationQueue = (params = {}) => {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null && v !== ''))
  return request(`/remediation-queue?${q}`)
}

// Reports
export const getSummary = (scanId, tags, tagLogic) => {
  const p = new URLSearchParams()
  if (scanId) p.set('scan_id', scanId)
  if (tags) p.set('tags', tags)
  if (tagLogic && tagLogic !== 'AND') p.set('tag_logic', tagLogic)
  const qs = p.toString()
  return request(`/reports/summary${qs ? `?${qs}` : ''}`)
}
export const getRiskGrade = (scanId, tags, tagLogic) => {
  const p = new URLSearchParams()
  if (scanId) p.set('scan_id', scanId)
  if (tags) p.set('tags', tags)
  if (tagLogic && tagLogic !== 'AND') p.set('tag_logic', tagLogic)
  const qs = p.toString()
  return request(`/reports/risk-grade${qs ? `?${qs}` : ''}`)
}
export const getHeatmap = ({ rows = 'family', cols = 'severity', scanId = null, tags = null, tagLogic = 'AND', limit = 15 } = {}) => {
  const p = new URLSearchParams()
  p.set('rows', rows)
  p.set('cols', cols)
  if (scanId) p.set('scan_id', scanId)
  if (tags) p.set('tags', tags)
  if (tagLogic && tagLogic !== 'AND') p.set('tag_logic', tagLogic)
  if (limit) p.set('limit', String(limit))
  return request(`/reports/heatmap?${p.toString()}`)
}
export const getPluginFamilies = (scanId, tags, tagLogic) => {
  const p = new URLSearchParams()
  if (scanId) p.set('scan_id', scanId)
  if (tags) p.set('tags', tags)
  if (tagLogic && tagLogic !== 'AND') p.set('tag_logic', tagLogic)
  const qs = p.toString()
  return request(`/reports/plugin-families${qs ? `?${qs}` : ''}`)
}
export const getBenchmarks = (scanId, industry, orgSize, source) => {
  const p = new URLSearchParams()
  if (scanId) p.set('scan_id', scanId)
  if (industry) p.set('industry', industry)
  if (orgSize) p.set('org_size', orgSize)
  if (source) p.set('source', source)
  const qs = p.toString()
  return request(`/benchmarks${qs ? `?${qs}` : ''}`)
}
export const getTrending = (mode) => request(`/reports/trending${mode ? `?mode=${mode}` : ''}`)
export const getMetricsTimeline = () => request('/reports/metrics-timeline')
export const getFunnel = (body) => request('/reports/funnel', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
})

// Automate
export const logAutomateClick = (findingId) =>
  request(`/automate-click?finding_id=${findingId}`, { method: 'POST' })
export const getAutomateClicks = () => request('/automate-clicks')

// Inventory
const _inv = (path, params = {}) => {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null && v !== ''))
  return request(`/inventory/${path}${q.toString() ? '?' + q : ''}`)
}
export const getInventorySummary = (scanId) => _inv('summary', { scan_id: scanId })
export const getInventoryUsers = (params) => _inv('users', params)
export const getInventoryUserOrgTree = (params) => _inv('users/org-tree', params)
export const getInventoryGroups = (params) => _inv('groups', params)
export const getInventoryServices = (params) => _inv('services', params)
export const getInventoryNetconns = (params) => _inv('netconns', params)
export const getInventoryTasks = (params) => _inv('scheduled-tasks', params)
export const getInventoryPatches = (params) => _inv('patches', params)
export const getInventoryLoggedOn = (params) => _inv('logged-on', params)
export const getInventoryShares = (params) => _inv('shares', params)
export const getInventorySoftware = (params) => _inv('software', params)
export const getInventorySecurityControls = (params) => _inv('security-controls', params)
export const getSecurityCoverage = (params) => _inv('security-coverage', params)
export const getInventoryComputers = (params) => _inv('computers', params)
export const getInventoryPasswordPolicies = (params) => _inv('password-policies', params)
export const getInventoryEnvVars = (params) => _inv('env-vars', params)
export const getInventoryCertificates = (params) => _inv('certificates', params)
export const getInventoryAITools = (params) => _inv('ai-tools', params)
export const getInventoryProcesses = (params) => _inv('processes', params)
export const getInventoryDatabases = (params) => _inv('databases', params)
export const getInventoryCredentials = (params) => _inv('credentials', params)
export const getInventoryAPIEndpoints = (params) => _inv('api-endpoints', params)

// SBOM
const _sbom = (path, params = {}) => {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null && v !== ''))
  return request(`/sbom/${path}${q.toString() ? '?' + q : ''}`)
}
export const getSBOMComponents = (params) => _sbom('components', params)
export const getSBOMComponentVulns = (id) => request(`/sbom/components/${id}/vulnerabilities`)
export const getSBOMBlastRadius = (params) => _sbom('blast-radius', params)
export const getSBOMAssetSummary = (params) => _sbom('asset-summary', params)

// Ownership
export const setAssetOwnership = (id, data) =>
  request(`/assets/${id}/ownership`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
export const setFindingOwnership = (id, data) =>
  request(`/findings/${id}/ownership`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
export const confirmAssetOwner = (id) =>
  request(`/assets/${id}/confirm-owner`, { method: 'POST' })
export const rerunOwnershipInference = (scanId) =>
  request(`/scans/${scanId}/infer-ownership`, { method: 'POST' })
export const getOwnershipSummary = (scanId) =>
  request(`/scans/${scanId}/ownership-summary`)

// Unified rule engine
export const getRuleEngineCatalog = () => request('/rule-engine/catalog')

// Campaigns
export const getConditionCatalog = () => request('/campaigns/condition-catalog')
export const previewCampaignQuery = (data) =>
  request('/campaigns/preview', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
export const nlpToCampaignConditions = (q, scan_id = null) =>
  request('/campaigns/nlp-to-conditions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ q, scan_id }),
  })
export const advancedSearch = (data) =>
  request('/search/advanced', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
export const getCampaigns = (scan_id) =>
  request(`/campaigns${scan_id ? `?scan_id=${scan_id}` : ''}`)
export const createCampaign = (data) =>
  request('/campaigns', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
export const getCampaign = (id) => request(`/campaigns/${id}`)
export const updateCampaign = (id, data) =>
  request(`/campaigns/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
export const deleteCampaign = (id) => request(`/campaigns/${id}`, { method: 'DELETE' })
export const runCampaign = (id) => request(`/campaigns/${id}/run`, { method: 'POST' })
export const updateCampaignFinding = (campaignId, cfId, data) =>
  request(`/campaigns/${campaignId}/findings/${cfId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })

// Blast Radius
export const getBlastRadius = (asset_id, finding_id) =>
  request(`/blast-radius?asset_id=${asset_id}${finding_id ? `&finding_id=${finding_id}` : ''}`)
export const getBlastRadiusBulk = (assetIds) =>
  request(`/blast-radius/bulk?asset_ids=${assetIds.join(',')}`)

// Risk scoring
export const getRiskConfig = () => request('/risk/config')
export const saveRiskConfig = (cfg) => request('/risk/config', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(cfg),
})
export const recalculateRisk = (scan_id = null, apply_criticality_rules = false, recalculate_findings = false) =>
  request('/risk/recalculate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scan_id, apply_criticality_rules, recalculate_findings }),
  })

// Tags
export const getTags = (params = {}) => {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null && v !== ''))
  return request(`/tags?${q}`)
}
export const getOsSoftwareSummary = (scanId) => {
  const p = new URLSearchParams()
  if (scanId) p.set('scan_id', scanId)
  return request(`/tags/os-software-summary?${p}`)
}
export const getTag = (id) => request(`/tags/${id}`)
export const createTag = (data) => request('/tags', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})
export const updateTag = (id, data) => request(`/tags/${id}`, {
  method: 'PATCH',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})
export const deleteTag = (id, strategy = 'reparent') =>
  request(`/tags/${id}?strategy=${strategy}`, { method: 'DELETE' })
export const assignTags = (data) => request('/tags/assign', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})
export const unassignTags = (data) => request('/tags/unassign', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})

// ── Custom fields (user-defined fields on Asset / Finding) ─────────────────

export const listCustomFieldDefinitions = (entityType) => {
  const p = new URLSearchParams()
  if (entityType) p.set('entity_type', entityType)
  return request(`/custom-fields?${p}`)
}

export const createCustomFieldDefinition = (data) => request('/custom-fields', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})

export const updateCustomFieldDefinition = (id, data) => request(`/custom-fields/${id}`, {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})

export const deleteCustomFieldDefinition = (id) =>
  request(`/custom-fields/${id}`, { method: 'DELETE' })

export const backfillCustomFieldDefinition = (id) =>
  request(`/custom-fields/${id}/backfill`, { method: 'POST' })

export const previewCustomField = (data) => request('/custom-fields/preview', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})

export const setAssetCustomFields = (assetId, customFields) =>
  request(`/assets/${assetId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ custom_fields: customFields }),
  })

export const setFindingCustomFields = (findingId, customFields) =>
  request(`/findings/${findingId}/custom-fields`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(customFields),
  })

// Auto-tag rules
export const getAutoTagRules = () => request('/auto-tag-rules')
export const createAutoTagRule = (data) => request('/auto-tag-rules', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})
export const updateAutoTagRule = (id, data) => request(`/auto-tag-rules/${id}`, {
  method: 'PATCH',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})
export const deleteAutoTagRule = (id) => request(`/auto-tag-rules/${id}`, { method: 'DELETE' })
export const runAutoTagRule = (id, scan_id = null) =>
  request(`/auto-tag-rules/${id}/run${scan_id ? `?scan_id=${scan_id}` : ''}`, { method: 'POST' })
export const runAllAutoTagRules = (scan_id = null) =>
  request(`/auto-tag-rules/run-all${scan_id ? `?scan_id=${scan_id}` : ''}`, { method: 'POST' })
export const getTagConditionCatalog = () => request('/auto-tag-rules/condition-catalog')

// Ownership Rules
export const getOwnershipRules = () => request('/ownership-rules')
export const createOwnershipRule = (data) => request('/ownership-rules', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})
export const updateOwnershipRule = (id, data) => request(`/ownership-rules/${id}`, {
  method: 'PATCH',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})
export const deleteOwnershipRule = (id) => request(`/ownership-rules/${id}`, { method: 'DELETE' })
export const runOwnershipRule = (id, scan_id = null) =>
  request(`/ownership-rules/${id}/run${scan_id ? `?scan_id=${scan_id}` : ''}`, { method: 'POST' })
export const runAllOwnershipRules = (scan_id = null, overwrite = null) => {
  const params = new URLSearchParams()
  if (scan_id) params.set('scan_id', scan_id)
  if (overwrite !== null) params.set('overwrite', overwrite)
  const qs = params.toString()
  return request(`/ownership-rules/run-all${qs ? `?${qs}` : ''}`, { method: 'POST' })
}

// External Tag Sources
export const getExternalTagSources = () => request('/external-tag-sources')
export const createExternalTagSource = (data) => request('/external-tag-sources', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})
export const updateExternalTagSource = (id, data) => request(`/external-tag-sources/${id}`, {
  method: 'PATCH',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})
export const deleteExternalTagSource = (id) => request(`/external-tag-sources/${id}`, { method: 'DELETE' })
export const upsertExternalTagMap = (sourceId, data) => request(`/external-tag-sources/${sourceId}/maps`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})
export const deleteExternalTagMap = (sourceId, mapId) =>
  request(`/external-tag-sources/${sourceId}/maps/${mapId}`, { method: 'DELETE' })
export const importExternalTagsCsv = (sourceId, file) => {
  const form = new FormData()
  form.append('file', file)
  return request(`/external-tag-sources/${sourceId}/import`, { method: 'POST', body: form })
}
export const syncExternalTagSource = (sourceId) =>
  request(`/external-tag-sources/${sourceId}/sync`, { method: 'POST' })

// SLA
export const getSLAConfig = () => request('/sla/config')
export const saveSLAConfig = (configs) => request('/sla/config', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ configs }),
})
export const recalculateSLA = (scan_id = null) => request('/sla/recalculate', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ scan_id }),
})
export const getSLASummary = (scanId) => request(`/sla/summary${scanId ? `?scan_id=${scanId}` : ''}`)
export const resolveFinding = (id) => request(`/findings/${id}/resolve`, { method: 'PATCH' })
export const unresolveFinding = (id) => request(`/findings/${id}/unresolve`, { method: 'PATCH' })
export const updateFindingContext = (id, data) => request(`/findings/${id}/context`, {
  method: 'PATCH',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})

// Threat Intelligence Center
const _ti = (path, params = {}) => {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null && v !== ''))
  return request(`/threat-intel/${path}${q.toString() ? '?' + q : ''}`)
}
export const getThreatIntelStats = () => _ti('stats')
export const getThreatFeed = (params = {}) => _ti('feed', params)
export const getThreatCves = (params = {}) => _ti('cves', params)
export const getKevRecent = (limit = 10) => _ti('kev-recent', { limit })
export const getThreatGroups = (params = {}) => _ti('groups', params)
export const getCisaAdvisories = (params = {}) => _ti('advisories', params)
export const getThreatTtps = (params = {}) => _ti('ttps', params)
export const syncThreatIntel = () => request('/threat-intel/sync', { method: 'POST', timeout: 300_000 })
export const getTtpCoverage = (params = {}) => _ti('ttp-coverage', params)
export const getGroupExposure = (groupId, params = {}) => _ti(`groups/${groupId}/exposure`, params)
export const triggerTtpMatching = (scanId = null) =>
  request(`/threat-intel/match-ttps${scanId ? `?scan_id=${scanId}` : ''}`, { method: 'POST' })
export const threatImpactSearch = (data) =>
  request('/threat-intel/impact-search', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
export const getProductLifecycles = (params = {}) => _ti('products', params)
export const getProductLifecycle = (slug) => _ti(`products/${slug}`)
// Patch Catalog
export const getPatchAdvisories = (params = {}) => _ti('patches', params)
export const getPatchCoverage = (cveIds) => _ti('patches/coverage', { cve_ids: cveIds })
export const getPatchStats = () => _ti('patches/stats')
export const syncPatchCatalog = (source = null) =>
  request(`/threat-intel/patches/sync${source ? '/' + source : ''}`, { method: 'POST', timeout: 300_000 })
export const getIntelCampaigns = () => _ti('remediation-campaigns')
export const createIntelCampaign = (data) =>
  request('/threat-intel/remediation-campaigns', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
export const updateIntelCampaign = (id, data) =>
  request(`/threat-intel/remediation-campaigns/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
export const deleteIntelCampaign = (id) =>
  request(`/threat-intel/remediation-campaigns/${id}`, { method: 'DELETE' })

// New intel data sources
export const getCWEs = (params = {}) => _ti('cwes', params)
export const getCWEDetail = (cweId) => _ti(`cwes/${cweId}`)
export const getExploits = (params = {}) => _ti('exploits', params)
export const getExploitSummary = () => _ti('exploits/summary')
export const getSSVCDecisions = (params = {}) => _ti('ssvc', params)
export const getSSVCSummary = () => _ti('ssvc/summary')
export const getMSRCPatches = (params = {}) => _ti('msrc-patches', params)
export const syncExploits = () => request('/threat-intel/sync-exploits', { method: 'POST', timeout: 300_000 })
export const syncSSVC = () => request('/threat-intel/sync-ssvc', { method: 'POST', timeout: 300_000 })
export const syncCWE = () => request('/threat-intel/sync-cwe', { method: 'POST', timeout: 300_000 })
export const syncMSRC = () => request('/threat-intel/sync-msrc', { method: 'POST', timeout: 300_000 })

// Workflows
export const getNodeCatalog = () => request('/workflows/node-catalog')
export const getWorkflowTemplates = () => request('/workflows/templates')
export const getWorkflows = (campaignId) =>
  request(`/workflows${campaignId ? `?campaign_id=${campaignId}` : ''}`)
export const createWorkflow = (data) =>
  request('/workflows', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
export const createWorkflowFromTemplate = (data) =>
  request('/workflows/from-template', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
export const generateWorkflow = (description, model = null) =>
  request('/workflows/generate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ description, model }),
    timeout: 60_000,
  })
export const createWorkflowFromGenerated = (data) =>
  request('/workflows/from-generated', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
export const getWorkflow = (id) => request(`/workflows/${id}`)
export const updateWorkflow = (id, data) =>
  request(`/workflows/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
export const deleteWorkflow = (id) => request(`/workflows/${id}`, { method: 'DELETE' })
export const executeWorkflow = (id) => request(`/workflows/${id}/execute`, { method: 'POST' })
export const getWorkflowExecutions = (id) => request(`/workflows/${id}/executions`)
export const getWorkflowExecution = (execId) => request(`/workflows/executions/${execId}`)

// Integrations
export const getIntegrations = () => request('/integrations')
export const getIntegration = (provider) => request(`/integrations/${provider}`)
export const saveIntegration = (provider, data) => request(`/integrations/${provider}`, {
  method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
})
export const testIntegration = (provider) => request(`/integrations/${provider}/test`, { method: 'POST' })
export const deleteIntegration = (provider) => request(`/integrations/${provider}`, { method: 'DELETE' })

// Finding Workflow Status
export const updateFindingStatus = (id, data) => request(`/findings/${id}/status`, {
  method: 'PATCH',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})
export const bulkUpdateFindingStatus = (data) => request('/findings/bulk-status', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})

// Finding Tickets (bidirectional sync)
export const getFindingTickets = (id) => request(`/findings/${id}/tickets`)
export const syncFindingTickets = (id) => request(`/findings/${id}/tickets/sync`, { method: 'POST' })
export const getTickets = (params = {}) => {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null && v !== ''))
  return request(`/tickets?${q}`)
}
export const triggerTicketSync = () => request('/ticket-sync', { method: 'POST' })
export const getCampaignTickets = (campaignId) => request(`/campaigns/${campaignId}/tickets`)
export const createCampaignSlackChannel = (campaignId) => request(`/campaigns/${campaignId}/slack-channel`, { method: 'POST' })

// Campaign external collaborators
export const listCampaignCollaborators = (campaignId) =>
  request(`/campaigns/${campaignId}/collaborators`)
export const inviteCampaignCollaborator = (campaignId, email) =>
  request(`/campaigns/${campaignId}/collaborators`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email }),
  })
export const revokeCampaignCollaborator = (campaignId, collabId) =>
  request(`/campaigns/${campaignId}/collaborators/${collabId}`, { method: 'DELETE' })
export const resendCampaignCollaborator = (campaignId, collabId) =>
  request(`/campaigns/${campaignId}/collaborators/${collabId}/resend`, { method: 'POST' })
export const acceptCampaignCollaborator = (token) =>
  request('/campaigns/collaborator/accept', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token }),
  })

// Global Exceptions
export const getExceptions = (params = {}) => {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null && v !== ''))
  return request(`/exceptions?${q}`)
}
export const getException = (id) => request(`/exceptions/${id}`)
export const createException = (data) => request('/exceptions', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})
export const updateException = (id, data) => request(`/exceptions/${id}`, {
  method: 'PATCH',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})
export const deleteException = (id) => request(`/exceptions/${id}`, { method: 'DELETE' })
export const applyAllExceptions = (scan_id = null) => request('/exceptions/apply-all', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ scan_id }),
})
export const getExceptionConditionCatalog = () => request('/exceptions/condition-catalog')

// Scan Comparison / Delta
export const compareScans = (baseScanId, compareScanId) =>
  request(`/scans/compare?base_scan_id=${baseScanId}&compare_scan_id=${compareScanId}`)
export const getScanDeltaTimeline = () => request('/scans/delta-timeline')

// Temporal Analytics & Remediation Velocity
export const getRegressions = (scanId) =>
  request(`/reports/regressions${scanId ? `?scan_id=${scanId}` : ''}`)
export const getTemporalSummary = (scanId) =>
  request(`/reports/temporal-summary${scanId ? `?scan_id=${scanId}` : ''}`)
export const getRemediationVelocity = (period = 'month') =>
  request(`/reports/remediation-velocity?period=${period}`)
export const backfillTemporal = (scanId) =>
  request(`/scans/${scanId}/backfill-temporal`, { method: 'POST' })
export const backfillTemporalAll = () =>
  request('/scans/backfill-temporal-all', { method: 'POST' })

// Export (CSV / JSON download)
export const exportDownload = async (entity, params = {}, fmt = 'csv') => {
  const p = new URLSearchParams(Object.entries({ ...params, fmt }).filter(([, v]) => v != null && v !== ''))
  const headers = {}
  const token = getStoredToken()
  if (token) headers['Authorization'] = `Bearer ${token}`
  const orgContext = getOrgContext()
  if (orgContext) headers['X-Org-Context'] = orgContext
  const res = await fetch(`${BASE}/export/${entity}?${p}`, { headers })
  if (!res.ok) throw new Error('Export failed')
  const blob = await res.blob()
  const blobUrl = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = blobUrl
  a.download = `${entity.replace(/\//g, '_')}.${fmt}`
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(blobUrl)
}

// Config Portability (export/import)
export const exportConfig = (type, params = {}) => {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null))
  return request(`/config/export/${type}?${q}`)
}
export const importConfig = async (type, file, conflict = 'skip') => {
  const fd = new FormData()
  fd.append('file', file)
  return request(`/config/import/${type}?conflict=${conflict}`, { method: 'POST', body: fd })
}

// Report Templates
export const getReportTemplates = () => request('/report-templates')
export const createReportTemplate = (data) => request('/report-templates', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})
export const getReportTemplate = (id) => request(`/report-templates/${id}`)
export const updateReportTemplate = (id, data) => request(`/report-templates/${id}`, {
  method: 'PATCH',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})
export const deleteReportTemplate = (id) => request(`/report-templates/${id}`, { method: 'DELETE' })

// Report Schedules (email delivery of saved reports as PDF)
export const listReportSchedulesForTemplate = (templateId) =>
  request(`/report-templates/${templateId}/schedules`)
export const createReportSchedule = (templateId, data) =>
  request(`/report-templates/${templateId}/schedules`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
export const listAllReportSchedules = () => request('/report-schedules')
export const getReportSchedule = (id) => request(`/report-schedules/${id}`)
export const updateReportSchedule = (id, data) =>
  request(`/report-schedules/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
export const deleteReportSchedule = (id) =>
  request(`/report-schedules/${id}`, { method: 'DELETE' })
export const runReportScheduleNow = (id) =>
  request(`/report-schedules/${id}/run-now`, { method: 'POST' })

// Tag-based Risk Reports
export const getRiskByTags = (params = {}) => {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null && v !== ''))
  return request(`/reports/risk-by-tags?${q}`)
}

export const getOwnerRiskSummary = (params = {}) => {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null && v !== ''))
  return request(`/reports/owner-risk-summary?${q}`)
}

// API tokens (long-lived bearer credentials for MCP / agent integrations)
export const listApiTokens = () => request('/auth/tokens')
export const createApiToken = (body) => request('/auth/tokens', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
})
export const revokeApiToken = (id) => request(`/auth/tokens/${id}`, { method: 'DELETE' })

// Deduplication
export const getDedupConfig = () => request('/dedup/config')
export const saveDedupConfig = (cfg) => request('/dedup/config', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(cfg),
})
/** Remove this org's dedup override, reverting to the global defaults. */
export const deleteDedupOrgOverride = () => request('/dedup/config/org-override', {
  method: 'DELETE',
})
export const runDedup = (entity_type, scan_id = null) => request('/dedup/run', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ entity_type, scan_id }),
})
export const getAvailableSources = () => request('/dedup/available-sources')
export const runRollup = () => request('/dedup/rollup', { method: 'POST' })

// Mini Agents
export const getAgentToolCatalog = () => request('/agents/tool-catalog')
export const getAvailableModels = () => request('/agents/available-models')
export const getAgents = () => request('/agents')
export const createAgent = (data) => request('/agents', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})
export const getAgent = (id) => request(`/agents/${id}`)
export const updateAgent = (id, data) => request(`/agents/${id}`, {
  method: 'PATCH',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})
export const deleteAgent = (id) => request(`/agents/${id}`, { method: 'DELETE' })
export const runAgent = (id, input) => request(`/agents/${id}/run`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ input }),
})
export const getAgentRuns = (id, limit = 20) => request(`/agents/${id}/runs?limit=${limit}`)
export const getAgentRun = (agentId, runId) => request(`/agents/${agentId}/runs/${runId}`)
export const getAgentTemplates = () => request('/agents/templates')
export const createAgentFromTemplate = (data) => request('/agents/from-template', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})

// Agent Export/Import
export const exportAgent = (id) => request(`/agents/export/${id}`)
export const importAgent = (data) => request('/agents/import', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})

// Agent Documents (RAG)
export const getAgentDocuments = (agentId) => request(`/agents/documents/${agentId}`)
export const uploadAgentDocument = (agentId, file) => {
  const fd = new FormData()
  fd.append('file', file)
  return request(`/agents/documents/${agentId}`, { method: 'POST', body: fd })
}
export const deleteAgentDocument = (agentId, docId) =>
  request(`/agents/documents/${agentId}/${docId}`, { method: 'DELETE' })

// Agent Schedules
export const getAgentSchedules = () => request('/agents/schedules')
export const createAgentSchedule = (data) => request('/agents/schedules', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})
export const updateAgentSchedule = (id, data) => request(`/agents/schedules/${id}`, {
  method: 'PATCH',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})
export const deleteAgentSchedule = (id) => request(`/agents/schedules/${id}`, { method: 'DELETE' })

// Aggregated Solutions
export const getAggregatedSolutions = (params = {}) => {
  const qs = new URLSearchParams(Object.entries(params).filter(([,v]) => v != null)).toString()
  return request(`/aggregated-solutions${qs ? '?' + qs : ''}`)
}
export const getAggregatedSolution = (id) => request(`/aggregated-solutions/${id}`)
export const rebuildAggregatedSolutions = (scanId) => request(`/aggregated-solutions/rebuild${scanId ? '?scan_id=' + scanId : ''}`, { method: 'POST' })

// EASM (External Attack Surface)
export const getEasmStatus = () => request('/easm/status')
export const scanEasmDomain = (domain, scanType = 'full', suppressAutoFollowup = false) => request(`/easm/scan-domain?domain=${encodeURIComponent(domain)}&scan_type=${scanType}&suppress_auto_followup=${suppressAutoFollowup ? 'true' : 'false'}`, { method: 'POST' })
export const rescanEasmScan = (scanId, scanType = 'full') => request(`/easm/rescan/${scanId}?scan_type=${scanType}`, { method: 'POST' })
export const updateEasmScan = (scanId, patch) => request(`/easm/scans/${scanId}`, {
  method: 'PATCH',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(patch),
})
export const refreshEasmScan = (scanId) => request(`/easm/refresh/${scanId}`, { method: 'POST' })
export const triggerEasmScan = (scanType = 'full') => request(`/easm/scan?scan_type=${scanType}`, { method: 'POST' })
export const getEasmEvents = (since, limit = 100) => request(`/easm/events?limit=${limit}${since ? '&since=' + since : ''}`)
export const setupEasm = (domain) => request(`/easm/setup?domain=${encodeURIComponent(domain)}`, { method: 'POST' })
export const addEasmDomain = (domain) => request(`/easm/domain?domain=${encodeURIComponent(domain)}`, { method: 'POST' })
export const getEasmDomains = () => request('/easm/domains')
export const getEasmScanRuns = (limit = 10, domain = null, scanId = null) => request(`/easm/scan-runs?limit=${limit}${domain ? `&domain=${encodeURIComponent(domain)}` : ''}${scanId ? `&scan_id=${scanId}` : ''}`)
export const syncEasmAssets = () => request('/easm/sync', { method: 'POST' })

// Agent Pipelines
export const getAgentPipelines = () => request('/agents/pipelines')
export const runAgentPipeline = (pipelineId, input, modelOverrides = {}) => request(`/agents/pipelines/${pipelineId}/run`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ input, model_overrides: modelOverrides }),
})

// Agent Approvals (HITL)
export const getAgentApprovals = (status) => request(`/agents/approvals${status ? `?status=${status}` : ''}`)
export const getAgentApproval = (approvalId) => request(`/agents/approvals/${approvalId}`)
export const decideAgentApproval = (approvalId, decision, reason, { grantScope } = {}) => request(`/agents/approvals/${approvalId}/decide`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ decision, reason, grant_scope: grantScope ?? null }),
})
export const getRunApprovals = (agentId, runId) => request(`/agents/${agentId}/runs/${runId}/approvals`)

// ── Security Copilot ───────────────────────────────────────
export const getCopilotConversations = () => request('/copilot/conversations')
export const createCopilotConversation = () => request('/copilot/conversations', { method: 'POST' })
export const getCopilotConversation = (id) => request(`/copilot/conversations/${id}`)
export const deleteCopilotConversation = (id) => request(`/copilot/conversations/${id}`, { method: 'DELETE' })
export const getCopilotSuggestedPrompts = () => request('/copilot/suggested-prompts')
export const getCopilotAutonomy = () => request('/copilot/autonomy')
export const setCopilotAutonomy = (level) => request('/copilot/autonomy', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ level }) })

export function uploadCopilotAttachment(conversationId, file) {
  const fd = new FormData()
  fd.append('file', file)
  return request(`/copilot/conversations/${conversationId}/attachments`, {
    method: 'POST',
    body: fd,
  })
}

export const deleteCopilotAttachment = (conversationId, attachmentId) =>
  request(`/copilot/conversations/${conversationId}/attachments/${attachmentId}`, { method: 'DELETE' })

// ── VM Scanner API (via main backend) ─────────────────────
export const startVmScan = (data) => request('/vm/scan', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})

export const refreshVmScan = (scanId) => request(`/vm/refresh/${scanId}`, { method: 'POST' })

export const rescanVmScan = (scanId, overrides = null) => request(`/vm/rescan/${scanId}`, {
  method: 'POST',
  ...(overrides
    ? { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(overrides) }
    : {}),
})

export const getVmHealth = () => request('/vm/health').catch(() => null)

// ── Protocol Audits (credentialed ReAct audits per protocol) ─
export const listAuditProtocols = () => request('/audits/protocols')
export const getAuditProtocol = (protocol) => request(`/audits/protocols/${protocol}`)
export const startAuditRun = (data) => request('/audits/run', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})
export const getAuditScan = (scanId) => request(`/audits/scans/${scanId}`)
export const getAuditScanHistory = (scanId) => request(`/audits/scans/${scanId}/history`)
export const rescanAuditScan = (scanId, overrides = null) => request(`/audits/scans/${scanId}/rescan`, {
  method: 'POST',
  ...(overrides
    ? { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(overrides) }
    : {}),
})
export const updateAuditScan = (scanId, patch) => request(`/audits/scans/${scanId}`, {
  method: 'PATCH',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(patch),
})

// ── OT Posture (Report Builder source) ──────────────────
// Backend still exposes /api/ot-posture/consent for grant/revoke; the UI
// for managing consent will live on the asset detail page. The Report
// Builder OT Posture template just reads /overview via this fetcher.
export const getOtPostureOverview = () => request('/ot-posture/overview')

// ── Auth Profiles (authenticated VM scans) ────────────────
export const listAuthProfiles = () => request('/auth-profiles')
export const getAuthProfile = (id) => request(`/auth-profiles/${id}`)
export const createAuthProfile = (data) => request('/auth-profiles', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})
export const updateAuthProfile = (id, data) => request(`/auth-profiles/${id}`, {
  method: 'PATCH',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})
export const deleteAuthProfile = (id) => request(`/auth-profiles/${id}`, { method: 'DELETE' })
// Test-login drives Playwright through the full flow (chromium launch + goto +
// fills + click + success-condition wait). Each Playwright step is up to 30s,
// so the total can blow past the default 30s fetch timeout — give it 120s so
// the backend's real success/error reaches the UI instead of an AbortError.
export const testAuthProfile = (id) =>
  request(`/auth-profiles/${id}/test`, { method: 'POST', timeout: 120_000 })
// Detect-flow renders the login page in headless chromium and then calls the
// LLM — comfortably 20–40s on cold cache. 90s gives the second attempt headroom.
export const detectAuthFlow = (loginUrl) => request('/auth-profiles/detect-flow', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ login_url: loginUrl }),
  timeout: 90_000,
})

export const getEasmAssets = (params = {}) => {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null && v !== ''))
  return request(`/easm/assets${q.toString() ? '?' + q : ''}`)
}

// Fetch an EASM asset screenshot as a blob object URL. The <img> element
// can't send auth headers itself, so we fetch the PNG with the current
// session, wrap it in a blob URL, and return the URL for src binding.
// Returns null if the scanner has no screenshot for this asset, if the
// response body is empty, or if the content-type isn't an image (e.g.
// when httpx screenshot capture failed and the scanner wrote a 0-byte file).
export const getEasmScreenshotUrl = async (assetId) => {
  const token = getStoredToken()
  const orgContext = getOrgContext()
  const headers = {}
  if (token) headers['Authorization'] = `Bearer ${token}`
  if (orgContext) headers['X-Org-Context'] = orgContext
  try {
    const resp = await fetch(`${BASE}/easm/assets/${assetId}/screenshot`, { headers })
    if (!resp.ok) return null
    const blob = await resp.blob()
    // Filter out empty / non-image payloads early so the modal shows
    // "No screenshot" instead of a broken image icon.
    if (!blob || blob.size === 0) return null
    if (blob.type && !blob.type.startsWith('image/')) return null
    return URL.createObjectURL(blob)
  } catch {
    return null
  }
}
export const getEasmBreaches = (params = {}) => {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null && v !== ''))
  return request(`/easm/breaches${q.toString() ? '?' + q : ''}`)
}
export const getEasmSubsidiaries = (params = {}) => {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null && v !== ''))
  return request(`/easm/corporate/subsidiaries${q.toString() ? '?' + q : ''}`)
}

// ── Integration Builder API ──────────────────────────────

const IB = '/integration-builder'

export const getIntegrationSchema = (entity) => request(`${IB}/schema${entity ? '?entity=' + entity : ''}`)
export const getTargetModels = () => request(`${IB}/targets`)
export const getTargetSchema = (slug) => request(`${IB}/targets/${slug}/schema`)
export const getConnectors = ({ search, category, page = 1, page_size = 12 } = {}) => {
  const params = new URLSearchParams()
  if (search) params.set('search', search)
  if (category && category !== 'all') params.set('category', category)
  params.set('page', page)
  params.set('page_size', page_size)
  return request(`${IB}/connectors?${params}`)
}
export const getConnectorCategories = () => request(`${IB}/connectors-categories`)
export const getConnector = (id) => request(`${IB}/connectors/${id}`)
export const getAcquisitionFlow = (id) => request(`${IB}/connectors/${id}/acquisition-flow`)
export const validateCredentials = (connectorId, data) => request(`${IB}/connectors/${connectorId}/validate-credentials`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
})
export const createCredential = (data) => request(`${IB}/credentials`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
})
export const getCredentials = () => request(`${IB}/credentials`)
export const getCredential = (id) => request(`${IB}/credentials/${id}`)
export const updateCredential = (id, data) => request(`${IB}/credentials/${id}`, {
  method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
})
export const deleteCredential = (id) => request(`${IB}/credentials/${id}`, { method: 'DELETE' })

export const integrationConnect = (data) => request(`${IB}/connect`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
})
export const getExtractStatus = (taskId) => request(`${IB}/extract-status/${taskId}`)
export async function pollExtraction(taskId, { interval = 2000, maxAttempts = 90 } = {}) {
  for (let i = 0; i < maxAttempts; i++) {
    const result = await getExtractStatus(taskId)
    if (result.status === 'completed') return result
    if (result.status === 'error') throw new Error(result.error || 'Extraction failed')
    await new Promise(r => setTimeout(r, interval))
  }
  throw new Error('Extraction timed out')
}
export const integrationPreview = (data) => request(`${IB}/preview`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
  timeout: data.transport_type === 'file' ? 180_000 : undefined,
})
export const integrationAutoSuggest = (data) => request(`${IB}/auto-suggest`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
})
export const detectFromSample = (data) => request(`${IB}/detect-sample`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
})
export const pollIntegrationEvents = (integrationId) => request(`${IB}/integrations/${integrationId}/poll-events`)

export const ibGetIntegrations = () => request(`${IB}/integrations`)
export const ibCreateIntegration = (data) => request(`${IB}/integrations`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
})
export const ibGetIntegration = (id) => request(`${IB}/integrations/${id}`)
export const ibUpdateIntegration = (id, data) => request(`${IB}/integrations/${id}`, {
  method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
})
export const ibDeleteIntegration = (id) => request(`${IB}/integrations/${id}`, { method: 'DELETE' })
export const ibEnableIntegration = (id) => request(`${IB}/integrations/${id}/enable`, { method: 'POST' })
export const ibDisableIntegration = (id) => request(`${IB}/integrations/${id}/disable`, { method: 'POST' })
export const ibRunIntegration = (id) => request(`${IB}/integrations/${id}/run`, { method: 'POST', timeout: 300_000 })
export const ibGetIntegrationRuns = (id) => request(`${IB}/integrations/${id}/runs`)
export const ibGetIntegrationRun = (integrationId, runId) => request(`${IB}/integrations/${integrationId}/runs/${runId}`)
export const ibUpdateLogo = (id, data) => request(`${IB}/integrations/${id}/logo`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
})
export const ibGetWebhookInfo = (id) => request(`${IB}/integrations/${id}/webhook`)
export const ibRotateWebhookCredentials = (id) => request(`${IB}/integrations/${id}/webhook/rotate`, { method: 'POST' })

// Active Directory / LDAP
export const adTestConnection = (data) => request(`${IB}/integrations/active-directory/test-connection`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data), timeout: 30_000,
})

// Discovery
export const discoverOAuth = (url) => request(`${IB}/discovery/oauth`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }),
})
export const discoverApi = (url) => request(`${IB}/discovery/discover`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }),
})
export const parseDocs = (data) => request(`${IB}/discovery/parse-docs`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
})
export const getCachedSpec = (hostname) => request(`${IB}/discovery/cache/${encodeURIComponent(hostname)}`)
export const discoverMcpTools = (serverUrl, credentialsId) => request(`${IB}/discovery/mcp-tools`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ server_url: serverUrl, credentials_id: credentialsId }),
})
export const mcpOAuthStart = (serverUrl, oauthMetadata) => request(`${IB}/oauth/mcp-start`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ server_url: serverUrl, oauth_metadata: oauthMetadata }),
})

// OAuth
export const oauthStart = (connectorId, data) => request(`${IB}/oauth/start/${connectorId}`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data || {}),
})
export const oauthClientCredentials = (data) => request(`${IB}/oauth/client-credentials`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
})
export const refreshCredential = (id) => request(`${IB}/credentials/${id}/refresh`, { method: 'POST' })

// ── Relay Agents ─────────────────────────────────────────
export const getRelayAgents = () => request('/relay-agents')
export const createRelayAgent = (data) => request('/relay-agents', {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
})
export const getRelayAgent = (id) => request(`/relay-agents/${id}`)
export const updateRelayAgent = (id, data) => request(`/relay-agents/${id}`, {
  method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
})
export const deleteRelayAgent = (id) => request(`/relay-agents/${id}`, { method: 'DELETE' })
export const rotateAgentToken = (id) => request(`/relay-agents/${id}/rotate-token`, { method: 'POST' })
export const getAgentSetup = (id) => request(`/relay-agents/${id}/setup`)

// Auto-provision
export const provisionConnector = (connectorId, data) => request(`${IB}/connectors/${connectorId}/provision`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
})

// File upload
export const uploadIntegrationFile = async (file) => {
  const token = getStoredToken()
  const orgContext = getOrgContext()
  const formData = new FormData()
  formData.append('file', file)
  const headers = {}
  if (token) headers['Authorization'] = `Bearer ${token}`
  if (orgContext) headers['X-Org-Context'] = orgContext
  const res = await fetch(`${BASE}${IB}/upload`, { method: 'POST', headers, body: formData })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || 'Upload failed')
  }
  return res.json()
}

// ── Billing API ─────────────────────────────────────────

export const getBillingPlans = () => request('/billing/plans')

export const getBillingStatus = () => request('/billing/status')

export const getBillingUsage = () => request('/billing/usage')

export const createCheckoutSession = (data) => request('/billing/checkout', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})

export const createPortalSession = (data) => request('/billing/portal', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})

export const adminOverrideSubscription = (org_id, tier) => request('/billing/admin/override', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ org_id, tier, status: tier === 'pro' ? 'active' : 'canceled' }),
})

// ── Notifications ──────────────────────────────────────

export const getNotifications = (params = {}) => {
  const qs = new URLSearchParams(params).toString()
  return request(`/notifications${qs ? '?' + qs : ''}`)
}

export const getUnreadNotificationCount = () => request('/notifications/unread-count')

export const markNotificationRead = (id) => request(`/notifications/${id}/read`, { method: 'POST' })

export const markAllNotificationsRead = () => request('/notifications/read-all', { method: 'POST' })

export const recordPageVisit = (pageKey) => request('/notifications/page-visit', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ page_key: pageKey }),
})

export const getNewSinceCounts = (pages) => {
  const qs = Array.isArray(pages) ? pages.join(',') : pages
  return request(`/notifications/new-since?pages=${encodeURIComponent(qs)}`)
}

// ── Control Assessment ────────────────────────────────

export const getFindingAssessments = (findingId) => request(`/control-assessments/finding/${findingId}`)
export const getAssetPolicies = (assetId) => request(`/control-assessments/asset/${assetId}/policies`)
export const runControlAssessment = (params = {}) => {
  const qs = new URLSearchParams(params).toString()
  return request(`/control-assessments/run${qs ? '?' + qs : ''}`, { method: 'POST' })
}
export const getControlAssessmentStats = () => request('/control-assessments/stats')

// ── SIEM Events ───────────────────────────────────────

export const searchSiemEvents = (params = {}) => {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null && v !== ''))
  return request(`/siem/events/search?${q}`)
}
export const getSiemEvent = (id) => request(`/siem/events/${id}`)
export const getSiemSourceSystems = () => request('/siem/events/source-systems')
export const ingestSiemEvent = (data) => request('/siem/events', { method: 'POST', body: JSON.stringify(data) })
export const ingestSiemEventsBatch = (events) => request('/siem/events/batch', { method: 'POST', body: JSON.stringify({ events }) })

// ── SIEM Detection Rules ──────────────────────────────

export const getDetectionRules = (params = {}) => {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null && v !== ''))
  return request(`/detection-rules?${q}`)
}
export const getDetectionRule = (id) => request(`/detection-rules/${id}`)
export const createDetectionRule = (data) => request('/detection-rules', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) })
export const updateDetectionRule = (id, data) => request(`/detection-rules/${id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) })
export const deleteDetectionRule = (id) => request(`/detection-rules/${id}`, { method: 'DELETE' })
export const testDetectionRule = (data) => request('/detection-rules/test', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) })

// ── SIEM Alerts ───────────────────────────────────────

export const getAlerts = (params = {}) => {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null && v !== ''))
  return request(`/alerts?${q}`)
}
export const getAlert = (id) => request(`/alerts/${id}`)
export const updateAlert = (id, data) => request(`/alerts/${id}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) })
export const triageAlert = (id, data) => request(`/alerts/${id}/triage`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) })

// ── SIEM Ingest Endpoints ─────────────────────────────

export const getSiemEndpoints = () => request('/siem/endpoints')
export const createSiemEndpoint = (data) => request('/siem/endpoints', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) })
export const deleteSiemEndpoint = (id) => request(`/siem/endpoints/${id}`, { method: 'DELETE' })
export const getVectorTemplates = () => request('/siem/vector-templates')

// SIEM reports
export const getSiemSummary = () => request('/reports/siem-summary')
export const getSiemEventVolume = (hours) => request(`/reports/siem-event-volume?hours=${hours || 24}`)
export const getSiemNoisySources = () => request('/reports/siem-noisy-sources')
export const getSiemAlertSeverity = () => request('/reports/siem-alert-severity')
export const getSiemRecentAlerts = (limit) => request(`/reports/siem-recent-alerts?limit=${limit || 15}`)
export const generateVectorConfig = (data) => request('/siem/vector-config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) })

// ── Suppression Rules ─────────────────────────────────

export const getSuppressionRules = (params = {}) => {
  const q = new URLSearchParams(params).toString()
  return request(`/suppression-rules?${q}`)
}
export const createSuppressionRule = (data) => request('/suppression-rules', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) })
export const updateSuppressionRule = (id, data) => request(`/suppression-rules/${id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) })

// ── Background jobs ──────────────────────────────────────

export const getJobStatus = (jobId) => request(`/jobs/${jobId}/status`)

// ── Attack Paths / Corroborated Findings ─────────────────

// Returns { job_id, status, poll_url } — the server runs correlation in the
// background. Use getJobStatus(job_id) to poll. Safe to navigate away; the
// job keeps running server-side.
export const runCorrelation = () => request('/correlations/run', { method: 'POST' })
export const listAttackPaths = (params = {}) => {
  const q = new URLSearchParams(params).toString()
  return request(`/correlations/attack-paths${q ? '?' + q : ''}`)
}
export const getAttackPath = (pathId) => request(`/correlations/attack-paths/${pathId}`)
export const listCorroboratedFindings = (params = {}) => {
  const q = new URLSearchParams(params).toString()
  return request(`/correlations/corroborated${q ? '?' + q : ''}`)
}

// ── Chain Coordinator approval queue ─────────────────────

export const listPendingApprovals = (status = 'pending') =>
  request(`/chain-coordinator/pending-approvals?status=${encodeURIComponent(status)}`)
export const approvePendingApproval = (id) =>
  request(`/chain-coordinator/pending-approvals/${id}/approve`, { method: 'POST' })
export const rejectPendingApproval = (id) =>
  request(`/chain-coordinator/pending-approvals/${id}/reject`, { method: 'POST' })

// ── Validation Agent ─────────────────────────────────────

export const runValidation = (findingId) =>
  request(`/validation/run/${findingId}`, { method: 'POST' })
export const getValidationStatus = (findingId) =>
  request(`/validation/status/${findingId}`)
export const getValidationQueue = (limit = 50) =>
  request(`/validation/queue?limit=${limit}`)
export const deleteSuppressionRule = (id) => request(`/suppression-rules/${id}`, { method: 'DELETE' })

// ── Compliance ───────────────────────────────────────────

export const getComplianceFrameworks = () => request('/compliance/frameworks')

export const subscribeFramework = (slug, body = {}) => request(
  `/compliance/frameworks/${slug}/subscribe`,
  { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) },
)
export const unsubscribeFramework = (slug) => request(
  `/compliance/frameworks/${slug}/subscribe`, { method: 'DELETE' },
)
export const updateFrameworkScope = (slug, body) => request(
  `/compliance/frameworks/${slug}/scope`,
  { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) },
)

export const getComplianceControls = (slug, params = {}) => {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null && v !== ''))
  return request(`/compliance/frameworks/${slug}/controls?${q}`)
}
export const getComplianceControl = (controlId) => request(`/compliance/controls/${controlId}`)
export const getComplianceControlFindings = (controlId, params = {}) => {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null && v !== ''))
  return request(`/compliance/controls/${controlId}/findings?${q}`)
}

export const createCompensatingControl = (controlId, body) => request(
  `/compliance/controls/${controlId}/compensating-controls`,
  { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) },
)

export const createCampaignFromControl = (controlId, body = {}) => request(
  `/compliance/controls/${controlId}/campaign`,
  { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) },
)
export const createCampaignFromFramework = (slug, body = {}) => request(
  `/compliance/frameworks/${slug}/campaign`,
  { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) },
)
export const deleteCompensatingControl = (id) => request(
  `/compliance/compensating-controls/${id}`, { method: 'DELETE' },
)

// Reports
export const createComplianceReport = (body) => request(
  '/compliance/reports',
  { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) },
)
export const listComplianceReports = (params = {}) => {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null && v !== ''))
  return request(`/compliance/reports?${q}`)
}
export const getComplianceReport = (runId) => request(`/compliance/reports/${runId}`)

// Framework import / export — tenant-private packs.
// Export streams YAML; the response Content-Disposition carries the filename.
export const exportComplianceFramework = async (slug) => {
  const headers = {}
  const token = getStoredToken()
  if (token) headers['Authorization'] = `Bearer ${token}`
  const orgContext = getOrgContext()
  if (orgContext) headers['X-Org-Context'] = orgContext
  const res = await fetch(`${BASE}/compliance/frameworks/${slug}/export`, { headers })
  if (!res.ok) {
    let detail = ''
    try { detail = (await res.json()).detail || '' } catch { /* not json */ }
    throw new Error(detail || `Export failed (${res.status})`)
  }
  const blob = await res.blob()
  const blobUrl = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = blobUrl
  a.download = `compliance_${slug}.yaml`
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(blobUrl)
}

export const importComplianceFramework = (yamlText) => request(
  '/compliance/frameworks/import',
  {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ yaml_text: yamlText }),
  },
)

export const deleteImportedFramework = (slug) => request(
  `/compliance/frameworks/${slug}/imported`,
  { method: 'DELETE' },
)

// Download a report artifact (CSV/JSON) — mirrors exportDownload's blob-link flow.
export const downloadComplianceReport = async (runId, frameworkSlug = 'framework', fmt = 'csv') => {
  const headers = {}
  const token = getStoredToken()
  if (token) headers['Authorization'] = `Bearer ${token}`
  const orgContext = getOrgContext()
  if (orgContext) headers['X-Org-Context'] = orgContext
  const res = await fetch(`${BASE}/compliance/reports/${runId}/download`, { headers })
  if (!res.ok) throw new Error(`Download failed (${res.status})`)
  const blob = await res.blob()
  const blobUrl = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = blobUrl
  a.download = `compliance_${frameworkSlug}_${runId}.${fmt}`
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(blobUrl)
}
