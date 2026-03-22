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

export function getOrgContext() {
  return localStorage.getItem('org_context')
}

export function setOrgContext(orgId) {
  if (orgId) localStorage.setItem('org_context', orgId)
  else localStorage.removeItem('org_context')
}

// ── Core request function with auth ─────────────────────

async function request(path, opts = {}) {
  const token = getStoredToken()
  const orgContext = getOrgContext()

  const headers = { ...(opts.headers || {}) }
  if (token) headers['Authorization'] = `Bearer ${token}`
  if (orgContext) headers['X-Org-Context'] = orgContext
  // Send current locale for backend i18n
  const locale = localStorage.getItem('i18nextLng')
  if (locale) headers['Accept-Language'] = locale

  const res = await fetch(`${BASE}${path}`, { ...opts, headers })

  // Handle 401 — redirect to login
  if (res.status === 401) {
    clearStoredToken()
    if (window.location.pathname !== '/login' && window.location.pathname !== '/register') {
      window.location.href = '/login'
    }
    throw new Error('Authentication required')
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || 'Request failed')
  }
  return res.json()
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

export const authMe = () => request('/auth/me')

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

// Scans
export const getScans = () => request('/scans')
export const deleteScan = (id) => request(`/scans/${id}`, { method: 'DELETE' })
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
export const getAsset = (id) => request(`/assets/${id}`)
export const updateAsset = (id, data) => {
  const q = new URLSearchParams(Object.entries(data).filter(([, v]) => v != null && v !== ''))
  return request(`/assets/${id}?${q}`, { method: 'PATCH' })
}

// Findings
export const getFindings = (params = {}) => {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null && v !== ''))
  return request(`/findings?${q}`)
}
export const getFinding = (id) => request(`/findings/${id}`)
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
export const getTrending = () => request('/reports/trending')
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
export const getBlastRadius = (scan_id, asset_id) =>
  request(`/blast-radius?scan_id=${scan_id}&asset_id=${asset_id}`)
export const getBlastRadiusBulk = (scan_id) =>
  request(`/blast-radius/bulk?scan_id=${scan_id}`)

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
export const syncThreatIntel = () => request('/threat-intel/sync', { method: 'POST' })
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
export const syncExploits = () => request('/threat-intel/sync-exploits', { method: 'POST' })
export const syncSSVC = () => request('/threat-intel/sync-ssvc', { method: 'POST' })
export const syncCWE = () => request('/threat-intel/sync-cwe', { method: 'POST' })
export const syncMSRC = () => request('/threat-intel/sync-msrc', { method: 'POST' })

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
export const exportDownload = (entity, params = {}, fmt = 'csv') => {
  const p = new URLSearchParams(Object.entries({ ...params, fmt }).filter(([, v]) => v != null && v !== ''))
  const url = `${API_ORIGIN}/api/export/${entity}?${p}`
  // Trigger browser download
  const a = document.createElement('a')
  a.href = url
  a.download = ''
  document.body.appendChild(a)
  a.click()
  a.remove()
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

// Tag-based Risk Reports
export const getRiskByTags = (params = {}) => {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null && v !== ''))
  return request(`/reports/risk-by-tags?${q}`)
}

// Deduplication
export const getDedupConfig = () => request('/dedup/config')
export const saveDedupConfig = (cfg) => request('/dedup/config', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(cfg),
})
export const runDedup = (entity_type, scan_id = null) => request('/dedup/run', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ entity_type, scan_id }),
})

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
export const scanEasmDomain = (domain, scanType = 'full') => request(`/easm/scan-domain?domain=${encodeURIComponent(domain)}&scan_type=${scanType}`, { method: 'POST' })
export const rescanEasmScan = (scanId, scanType = 'full') => request(`/easm/rescan/${scanId}?scan_type=${scanType}`, { method: 'POST' })
export const refreshEasmScan = (scanId) => request(`/easm/refresh/${scanId}`, { method: 'POST' })
export const triggerEasmScan = (scanType = 'full') => request(`/easm/scan?scan_type=${scanType}`, { method: 'POST' })
export const getEasmEvents = (since, limit = 100) => request(`/easm/events?limit=${limit}${since ? '&since=' + since : ''}`)
export const setupEasm = (domain) => request(`/easm/setup?domain=${encodeURIComponent(domain)}`, { method: 'POST' })
export const addEasmDomain = (domain) => request(`/easm/domain?domain=${encodeURIComponent(domain)}`, { method: 'POST' })
export const getEasmDomains = () => request('/easm/domains')
export const getEasmScanRuns = (limit = 10) => request(`/easm/scan-runs?limit=${limit}`)
export const syncEasmAssets = () => request('/easm/sync', { method: 'POST' })

// Agent Pipelines
export const getAgentPipelines = () => request('/agents/pipelines')
export const runAgentPipeline = (pipelineId, input, modelOverrides = {}) => request(`/agents/pipelines/${pipelineId}/run`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ input, model_overrides: modelOverrides }),
})

// ── VM Scanner API (via main backend) ─────────────────────
export const startVmScan = (data) => request('/vm/scan', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
})

export const refreshVmScan = (scanId) => request(`/vm/refresh/${scanId}`, { method: 'POST' })

export const rescanVmScan = (scanId) => request(`/vm/rescan/${scanId}`, { method: 'POST' })

export const getVmHealth = () => request('/vm/health').catch(() => null)

export const getEasmAssets = () => request('/easm/assets')
export const getEasmBreaches = () => request('/easm/breaches')
export const getEasmSubsidiaries = () => request('/easm/corporate/subsidiaries')

// ── Integration Builder API ──────────────────────────────

const IB = '/integration-builder'

export const getIntegrationSchema = (entity) => request(`${IB}/schema${entity ? '?entity=' + entity : ''}`)
export const getTargetModels = () => request(`${IB}/targets`)
export const getTargetSchema = (slug) => request(`${IB}/targets/${slug}/schema`)
export const getConnectors = () => request(`${IB}/connectors`)
export const getConnector = (id) => request(`${IB}/connectors/${id}`)
export const getAcquisitionFlow = (id) => request(`${IB}/connectors/${id}/acquisition-flow`)
export const validateCredentials = (connectorId, data) => request(`${IB}/connectors/${connectorId}/validate-credentials`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
})
export const createCredential = (data) => request(`${IB}/credentials`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
})
export const getCredentials = () => request(`${IB}/credentials`)
export const deleteCredential = (id) => request(`${IB}/credentials/${id}`, { method: 'DELETE' })

export const integrationConnect = (data) => request(`${IB}/connect`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
})
export const integrationPreview = (data) => request(`${IB}/preview`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
})

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
export const ibRunIntegration = (id) => request(`${IB}/integrations/${id}/run`, { method: 'POST' })
export const ibGetIntegrationRuns = (id) => request(`${IB}/integrations/${id}/runs`)
export const ibGetIntegrationRun = (integrationId, runId) => request(`${IB}/integrations/${integrationId}/runs/${runId}`)
export const ibUpdateLogo = (id, data) => request(`${IB}/integrations/${id}/logo`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
})

// Discovery
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
export const refreshCredential = (id) => request(`${IB}/credentials/${id}/refresh`, { method: 'POST' })

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
