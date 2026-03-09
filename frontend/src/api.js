const BASE = '/api'

async function request(path, opts = {}) {
  const res = await fetch(`${BASE}${path}`, opts)
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || 'Request failed')
  }
  return res.json()
}

// Scans
export const getScans = () => request('/scans')
export const deleteScan = (id) => request(`/scans/${id}`, { method: 'DELETE' })

export const uploadScan = (file) => {
  const fd = new FormData()
  fd.append('file', file)
  return request('/upload', { method: 'POST', body: fd })
}

// Assets
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

// Remediation queue
export const getRemediationQueue = (params = {}) => {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null && v !== ''))
  return request(`/remediation-queue?${q}`)
}

// Reports
export const getSummary = (scanId) => request(`/reports/summary${scanId ? `?scan_id=${scanId}` : ''}`)
export const getPluginFamilies = (scanId) => request(`/reports/plugin-families${scanId ? `?scan_id=${scanId}` : ''}`)
export const getTrending = () => request('/reports/trending')

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
export const getInventoryGroups = (params) => _inv('groups', params)
export const getInventoryServices = (params) => _inv('services', params)
export const getInventoryNetconns = (params) => _inv('netconns', params)
export const getInventoryTasks = (params) => _inv('scheduled-tasks', params)
export const getInventoryPatches = (params) => _inv('patches', params)
export const getInventoryLoggedOn = (params) => _inv('logged-on', params)
export const getInventoryShares = (params) => _inv('shares', params)
export const getInventorySoftware = (params) => _inv('software', params)
export const getInventorySecurityControls = (params) => _inv('security-controls', params)
export const getInventoryComputers = (params) => _inv('computers', params)
export const getInventoryPasswordPolicies = (params) => _inv('password-policies', params)
export const getInventoryEnvVars = (params) => _inv('env-vars', params)
export const getInventoryCertificates = (params) => _inv('certificates', params)
export const getInventoryAITools = (params) => _inv('ai-tools', params)

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
export const getTagConditionCatalog = () => request('/auto-tag-rules/condition-catalog')

// SLA / MTTR
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
export const getThreatTtps = (params = {}) => _ti('ttps', params)
export const syncThreatIntel = () => request('/threat-intel/sync', { method: 'POST' })
export const threatImpactSearch = (data) =>
  request('/threat-intel/impact-search', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
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
