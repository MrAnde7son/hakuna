import { useState, useEffect } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { ArrowLeft, ArrowRight, Check, ChevronRight, ChevronDown, Zap, Database as DbIcon, FileText, Globe, Wand2, Eye, EyeOff, List, Server } from 'lucide-react'
import { Card, Button, useToast } from '../shared/ui.jsx'
import {
  getConnectors, getConnector, getIntegrationSchema, getAcquisitionFlow,
  validateCredentials, createCredential, integrationConnect, integrationPreview,
  integrationAutoSuggest,
  ibCreateIntegration, ibUpdateIntegration, ibGetIntegration,
  discoverApi, parseDocs, uploadIntegrationFile, discoverMcpTools, mcpOAuthStart,
  getTargetModels, getTargetSchema, oauthClientCredentials, discoverOAuth,
  getRelayAgents,
} from '../../api.js'
import StepAuthenticate from './steps/StepAuthenticate.jsx'
import StepFieldMapper from './steps/StepFieldMapper.jsx'

const STEPS_API = [
  { key: 'source', label: 'Choose Source' },
  { key: 'auth', label: 'Authenticate' },
  { key: 'configure', label: 'Connect' },
  { key: 'records', label: 'Pick Records' },
  { key: 'target', label: 'Pick Target' },
  { key: 'map', label: 'Map Fields' },
  { key: 'preview', label: 'Preview' },
  { key: 'save', label: 'Save' },
]
const STEPS_FILE = [
  { key: 'source', label: 'Choose Source' },
  { key: 'auth', label: 'Configure' },
  { key: 'configure', label: 'Upload File' },
  { key: 'records', label: 'Pick Records' },
  { key: 'target', label: 'Pick Target' },
  { key: 'map', label: 'Map Fields' },
  { key: 'preview', label: 'Preview' },
  { key: 'save', label: 'Save' },
]

const TRANSPORT_ICONS = { api: Globe, sql: DbIcon, file: FileText, mcp: Zap }

const AUTH_TYPES = [
  { value: 'none', label: 'None' },
  { value: 'bearer', label: 'Bearer Token' },
  { value: 'oauth2_client', label: 'OAuth2 (Client Credentials)' },
  { value: 'api_key', label: 'API Key (Header)' },
  { value: 'basic', label: 'Basic Auth' },
]

export default function IntegrationBuilder({ embedded, editId: embeddedEditId, onBack, onDone }) {
  const toast = useToast()
  const navigate = !embedded ? useNavigate() : null
  const routeParams = !embedded ? useParams() : {}
  const editId = embeddedEditId || routeParams.id
  const goBack = onBack || (() => navigate('/integrations'))
  const goDone = onDone || (() => navigate('/integrations'))
  const [step, setStep] = useState(0)
  const [loading, setLoading] = useState(false)
  const [connectError, setConnectError] = useState(null)

  // State accumulated across steps
  const [connectors, setConnectors] = useState([])
  const [selectedConnector, setSelectedConnector] = useState(null)
  const [connectorDetail, setConnectorDetail] = useState(null)
  const [credentialsId, setCredentialsId] = useState(null)
  const [connectedUser, setConnectedUser] = useState(null)
  const [transportConfig, setTransportConfig] = useState({})
  const [transportType, setTransportType] = useState('api')
  const STEPS = transportType === 'file' ? STEPS_FILE : STEPS_API
  const [recordsPath, setRecordsPath] = useState('')
  const [rawResponse, setRawResponse] = useState(null)
  const [sampleRecords, setSampleRecords] = useState([])
  const [detectedPaths, setDetectedPaths] = useState([])
  const [fieldMap, setFieldMap] = useState([])
  const [schema, setSchema] = useState([])
  const [previewRecords, setPreviewRecords] = useState([])
  const [suggestions, setSuggestions] = useState(null)
  const [integrationName, setIntegrationName] = useState('')
  const [direction, setDirection] = useState('pull')
  const [entity, setEntity] = useState('finding')
  const [dedupKey, setDedupKey] = useState([])
  const [schedule, setSchedule] = useState('')
  const [enabled, setEnabled] = useState(false)

  // Inline auth for custom builds
  const [inlineAuthType, setInlineAuthType] = useState('none')
  const [inlineAuthValues, setInlineAuthValues] = useState({})
  const [showSecrets, setShowSecrets] = useState(false)
  const [oauthDiscovering, setOauthDiscovering] = useState(false)
  const [oauthDiscovered, setOauthDiscovered] = useState(null) // null | false | { token_endpoint, scopes_supported }

  // Custom request headers (key-value pairs)
  const [customHeaders, setCustomHeaders] = useState([]) // [{key, value}]
  // Custom request body params (key-value pairs, for POST/PUT/PATCH)
  const [customBodyParams, setCustomBodyParams] = useState([]) // [{key, value}]

  // MCP discovery
  const [mcpTools, setMcpTools] = useState(null) // {tools: [...], server_info: {...}}
  const [mcpAuthRequired, setMcpAuthRequired] = useState(false)
  const [mcpOAuthMetadata, setMcpOAuthMetadata] = useState(null) // OAuth metadata from discovery

  // Target models (from model registry)
  const [targetModels, setTargetModels] = useState([])

  // Relay agent support (on-prem)
  const [useRelay, setUseRelay] = useState(false)
  const [relayAgents, setRelayAgents] = useState([])
  const [relayAgentId, setRelayAgentId] = useState(null)

  // Discovery
  const [discoverUrl, setDiscoverUrl] = useState('')
  const [discovering, setDiscovering] = useState(false)
  const [discoveryResult, setDiscoveryResult] = useState(null)
  const [discoveryError, setDiscoveryError] = useState(null)
  const [selectedEndpoint, setSelectedEndpoint] = useState(null)

  const getPrevStep = () => {
    if (step === 2 && !connectorDetail?.credential_acquisition) return 0
    return step - 1
  }

  useEffect(() => {
    getConnectors().then(setConnectors).catch(console.error)
    getIntegrationSchema().then(s => setSchema(s)).catch(console.error)
    getTargetModels().then(setTargetModels).catch(console.error)
    getRelayAgents().then(setRelayAgents).catch(() => {})
  }, [])

  // If editing, load existing integration
  useEffect(() => {
    if (!editId) return
    ibGetIntegration(editId).then(async i => {
      setIntegrationName(i.name)
      setDirection(i.direction)
      setEntity(i.entity)
      setTransportType(i.transport_type)
      setTransportConfig(i.transport_config || {})
      setCustomHeaders(Object.entries(i.transport_config?.headers || {}).map(([key, value]) => ({ key, value })))
      setCustomBodyParams(Object.entries(i.transport_config?.body || {}).map(([key, value]) => ({ key, value: typeof value === 'object' ? JSON.stringify(value) : String(value) })))
      setRecordsPath(i.records_path || '')
      setFieldMap(i.field_map || [])
      setDedupKey(i.dedup_key || [])
      setSchedule(i.schedule || '')
      setEnabled(i.enabled)
      setCredentialsId(i.credentials_id)
      if (i.relay_agent_id) { setRelayAgentId(i.relay_agent_id); setUseRelay(true) }
      if (i.transport_type === 'relay') setUseRelay(true)
      if (i.template_id) setSelectedConnector(i.template_id)
      // Load target schema for the entity
      try {
        const targetSchema = await getTargetSchema(i.entity)
        setSchema(targetSchema || [])
      } catch { /* fall back to full schema already loaded */ }
      // Fetch live data so source fields, records picker, etc. are populated
      try {
        const result = await integrationConnect({
          transport_type: i.transport_type,
          transport_config: i.transport_config || {},
          credentials_id: i.credentials_id,
          records_path: i.records_path || undefined,
        })
        setRawResponse(result.raw_response)
        setSampleRecords(result.sample_records || [])
        setDetectedPaths(result.detected_paths || [])
      } catch (e) {
        console.warn('Could not fetch live data for edit:', e.message)
      }
      setStep(5) // jump to field mapper for edits
    }).catch(console.error)
  }, [editId])

  // Sync customHeaders array → transportConfig.headers object
  useEffect(() => {
    const headerObj = {}
    customHeaders.forEach(({ key, value }) => { if (key.trim()) headerObj[key.trim()] = value })
    setTransportConfig(tc => ({ ...tc, headers: headerObj }))
  }, [customHeaders]) // eslint-disable-line react-hooks/exhaustive-deps

  // Sync customBodyParams array → transportConfig.body object
  useEffect(() => {
    const bodyObj = {}
    customBodyParams.forEach(({ key, value }) => {
      if (key.trim()) {
        try { bodyObj[key.trim()] = JSON.parse(value) } catch { bodyObj[key.trim()] = value }
      }
    })
    setTransportConfig(tc => ({ ...tc, body: bodyObj }))
  }, [customBodyParams]) // eslint-disable-line react-hooks/exhaustive-deps

  // Auto-run auto-suggest when reaching Map Fields step with no existing mappings
  useEffect(() => {
    if (step === 5 && fieldMap.length === 0 && detectedPaths.length > 0 && schema.length > 0) {
      handleAutoSuggest()
    }
  }, [step]) // eslint-disable-line react-hooks/exhaustive-deps

  // ── Step 0: Choose Source ──
  const handleSelectConnector = async (connectorId) => {
    setLoading(true)
    try {
      const detail = await getConnector(connectorId)
      setSelectedConnector(connectorId)
      setConnectorDetail(detail)
      setDirection(detail.direction)
      setEntity(detail.entity)
      setTransportType(detail.transport_type)
      setTransportConfig(detail.transport_config || {})
      setCustomHeaders(Object.entries(detail.transport_config?.headers || {}).map(([key, value]) => ({ key, value })))
      setCustomBodyParams(Object.entries(detail.transport_config?.body || {}).map(([key, value]) => ({ key, value: typeof value === 'object' ? JSON.stringify(value) : String(value) })))
      setFieldMap(detail.default_field_map || [])
      setDedupKey(detail.dedup_key || [])
      setRecordsPath(detail.records_path || '')
      setIntegrationName(detail.name)

      // Load schema for the connector's target entity
      try {
        const targetSchema = await getTargetSchema(detail.entity)
        setSchema(targetSchema || [])
      } catch {
        const s = await getIntegrationSchema()
        setSchema(s || {})
      }

      // Go to auth if connector needs it, otherwise configure
      if (!detail.credential_acquisition) {
        setStep(2)
      } else {
        setStep(1)
      }
    } catch (e) {
      toast.error('Failed to load connector: ' + e.message)
    } finally {
      setLoading(false)
    }
  }

  const handleSelectCustomTransport = (type) => {
    setTransportType(type)
    setSelectedConnector(null)
    setConnectorDetail(null)
    setDirection('pull')
    setEntity('finding')
    setStep(2) // go to configure (which now has inline auth)
  }

  // ── Step 2: Connect ──
  const handleConnect = async () => {
    setLoading(true)
    setConnectError(null)
    try {
      // Save credentials if any auth values were provided
      let cId = credentialsId
      const hasInlineAuth = (inlineAuthType !== 'none' && Object.keys(inlineAuthValues).length > 0)
        || (transportType === 'sql' && inlineAuthValues.connection_string)
        || (transportType === 'mcp' && inlineAuthValues.mcp_api_key)

      if (hasInlineAuth && (!cId || editId)) {
        const authType = transportType === 'sql' ? 'basic' : transportType === 'mcp' ? 'api_key' : inlineAuthType

        if (authType === 'oauth2_client') {
          // Exchange client credentials for a token — backend stores it with auto-refresh
          const result = await oauthClientCredentials({
            instance_url: transportConfig.base_url || '',
            token_url: inlineAuthValues.token_url,
            client_id: inlineAuthValues.client_id,
            client_secret: inlineAuthValues.client_secret,
            scopes: inlineAuthValues.scopes ? inlineAuthValues.scopes.trim().split(/\s+/) : [],
            connector_id: selectedConnector || 'custom',
          })
          cId = result.credentials_id
          setCredentialsId(cId)
          setConnectedUser(result.connected_user || null)
        } else {
          const cred = await createCredential({
            name: `${transportConfig.base_url || transportConfig.server_url || 'Custom'} credentials`,
            connector_id: selectedConnector || 'custom',
            auth_type: authType,
            values: inlineAuthValues,
            instance_url: transportConfig.base_url || transportConfig.server_url || null,
          })
          cId = cred.id
          setCredentialsId(cId)
        }
      }

      const result = await integrationConnect({
        transport_type: transportType,
        transport_config: transportConfig,
        credentials_id: cId,
        records_path: undefined, // don't send — we'll pick from response
      })
      setRawResponse(result.raw_response)
      setSampleRecords(result.sample_records || [])
      setDetectedPaths(result.detected_paths || [])

      // Auto-detect records path
      if (result.detected_records_path) {
        setRecordsPath(result.detected_records_path)
      }

      // For file transports with flat record arrays (PDF, DOCX, CSV, .nessus),
      // skip the records picker — records are already extracted
      const isFlat = transportType === 'file' && (result.sample_records || []).length > 0
        && !result.detected_records_path
      setStep(isFlat ? 4 : 3) // skip to Pick Target if records are flat
    } catch (e) {
      setConnectError(e.message)
    } finally {
      setLoading(false)
    }
  }

  // ── Step 3: Pick Records — re-connect with chosen path ──
  const handlePickRecords = async (path) => {
    setRecordsPath(path)
    setLoading(true)
    try {
      const result = await integrationConnect({
        transport_type: transportType,
        transport_config: transportConfig,
        credentials_id: credentialsId,
        records_path: path,
      })
      setSampleRecords(result.sample_records || [])
      setDetectedPaths(result.detected_paths || [])
      setStep(4) // advance to Pick Target
    } catch (e) {
      toast.error('Failed to fetch records at path: ' + e.message)
    } finally {
      setLoading(false)
    }
  }

  // ── Step 5: Preview ──
  const handlePreview = async () => {
    setLoading(true)
    try {
      const result = await integrationPreview({
        transport_type: transportType,
        transport_config: transportConfig,
        credentials_id: credentialsId,
        records_path: recordsPath || undefined,
        field_map: fieldMap,
        auto_suggest_flag: false,
        sample_records: sampleRecords.length ? sampleRecords : undefined,
      })
      setPreviewRecords(result.records || [])
      setStep(6)
    } catch (e) {
      toast.error('Preview failed: ' + e.message)
    } finally {
      setLoading(false)
    }
  }

  // ── Step 4: Auto-suggest (lightweight — no transport re-run) ──
  const handleAutoSuggest = async () => {
    setLoading(true)
    try {
      const suggestions = await integrationAutoSuggest({
        source_paths: detectedPaths,
        entity: entity || 'finding',
      })
      if (suggestions && suggestions.length) {
        setSuggestions(suggestions)
        setFieldMap(suggestions)
      }
    } catch (e) {
      console.error('Auto-suggest failed:', e)
    } finally {
      setLoading(false)
    }
  }

  // ── Step 6: Save ──
  const handleSave = async (andRun = false) => {
    setLoading(true)
    try {
      const payload = {
        name: integrationName,
        direction, entity,
        transport_type: useRelay ? 'relay' : transportType,
        transport_config: transportConfig,
        credentials_id: useRelay ? null : credentialsId,
        records_path: recordsPath || null,
        field_map: fieldMap,
        dedup_key: dedupKey,
        schedule: schedule || null,
        enabled,
        template_id: selectedConnector || null,
        relay_agent_id: useRelay ? relayAgentId : null,
      }

      let result
      if (editId) {
        result = await ibUpdateIntegration(editId, payload)
      } else {
        result = await ibCreateIntegration(payload)
      }

      if (andRun && result.id) {
        // Fire run in background — don't block the UI
        import('../../api.js').then(api => api.ibRunIntegration(result.id)).catch(() => {})
        toast.success('Integration saved — run started in background')
      } else {
        toast.success('Integration saved')
      }
      goDone()
    } catch (e) {
      toast.error('Save failed: ' + e.message)
    } finally {
      setLoading(false)
    }
  }

  // ── Render steps ──
  const renderStep = () => {
    switch (step) {
      case 0: return renderChooseSource()
      case 1: return renderAuth()
      case 2: return renderConfigure()
      case 3: return renderRecordsPicker()
      case 4: return renderPickTarget()
      case 5: return renderFieldMapper()
      case 6: return renderPreview()
      case 7: return renderSave()
      default: return null
    }
  }

  // ── Discovery handler ──
  const handleDiscover = async () => {
    if (!discoverUrl) return
    setDiscovering(true)
    setDiscoveryError(null)
    setDiscoveryResult(null)
    try {
      const result = await discoverApi(discoverUrl)
      if (result.spec_source === 'none') {
        setDiscoveryError(result.error || 'No spec found')
      } else {
        setDiscoveryResult(result)
        setTransportConfig(prev => ({ ...prev, base_url: result.base_url || discoverUrl }))
      }
    } catch (e) {
      setDiscoveryError(e.message)
    } finally {
      setDiscovering(false)
    }
  }

  const handleSelectEndpoint = (ep) => {
    setSelectedEndpoint(ep)
    setTransportConfig({
      base_url: discoveryResult?.base_url || discoverUrl,
      method: ep.method,
      path: ep.path,
      headers: {},
      query_params: {},
      pagination: ep.pagination_hints || {},
    })
    if (ep.response_schema?.records_path) {
      setRecordsPath(ep.response_schema.records_path)
    }
    setTransportType('api')
    setDirection('pull')
    setIntegrationName(discoveryResult?.tool_name || '')
    setStep(2) // go to Connect (with inline auth)
  }

  const handleLlmParse = async (url) => {
    setDiscovering(true)
    setDiscoveryError(null)
    try {
      const result = await parseDocs({ url })
      if (result.endpoints?.length > 0) {
        setDiscoveryResult(result)
      } else {
        setDiscoveryError('Could not extract endpoints from docs')
      }
    } catch (e) {
      setDiscoveryError(e.message)
    } finally {
      setDiscovering(false)
    }
  }

  // ── Step 0: Choose Source ──
  const renderChooseSource = () => (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Section A: Templates */}
      <div>
        <h3 style={{ margin: '0 0 12px', fontSize: 16, fontWeight: 600 }}>Start from a template</h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))', gap: 12 }}>
          {connectors.map(c => (
            <Card key={c.id} onClick={() => handleSelectConnector(c.id)} style={{ cursor: 'pointer', padding: 16 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                <VendorLogo src={c.logo} size={32} />
                <div>
                  <div style={{ fontWeight: 600, fontSize: 13 }}>{c.name}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{c.description}</div>
                </div>
              </div>
              <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                <Badge bg={DIRECTION_BADGE[c.direction]?.bg} text={DIRECTION_BADGE[c.direction]?.text} label={c.direction.toUpperCase()} />
                <Badge bg={(ENTITY_BADGE[c.entity] || DEFAULT_ENTITY_BADGE).bg} text={(ENTITY_BADGE[c.entity] || DEFAULT_ENTITY_BADGE).text} label={c.entity.toUpperCase()} />
                <Badge bg="var(--border)" text="var(--text-muted)" label={c.transport_type.toUpperCase()} />
              </div>
            </Card>
          ))}
        </div>
      </div>

      {/* Section: On-Prem / Relay Agent */}
      {relayAgents.length > 0 && (
        <div style={{
          padding: 16, borderRadius: 10,
          background: 'linear-gradient(135deg, rgba(124,58,237,0.04), rgba(99,102,241,0.04))',
          border: '1px solid rgba(124,58,237,0.15)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
            <Server size={16} color="#7c3aed" />
            <h3 style={{ margin: 0, fontSize: 14, fontWeight: 600, color: 'var(--text)' }}>On-Prem Connection</h3>
          </div>
          <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: '0 0 12px' }}>
            Connect to services behind your firewall using a relay agent. Select an agent to route traffic through your network.
          </p>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={useRelay}
                onChange={e => { setUseRelay(e.target.checked); if (!e.target.checked) setRelayAgentId(null) }}
              />
              <span style={{ fontSize: 13, color: 'var(--text)' }}>Use relay agent</span>
            </label>
            {useRelay && (
              <select
                value={relayAgentId || ''}
                onChange={e => setRelayAgentId(e.target.value || null)}
                style={{
                  flex: 1, maxWidth: 300, padding: '6px 10px', borderRadius: 8, fontSize: 13,
                  border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)',
                }}
              >
                <option value="">Select an agent...</option>
                {relayAgents.map(a => (
                  <option key={a.id} value={a.id}>
                    {a.name} ({a.status === 'connected' ? 'Online' : 'Offline'})
                  </option>
                ))}
              </select>
            )}
          </div>
        </div>
      )}

      {/* Section B: Connect any tool (discovery) */}
      <div>
        <h3 style={{ margin: '0 0 12px', fontSize: 16, fontWeight: 600 }}>Connect any tool</h3>
        <div style={{ display: 'flex', gap: 8 }}>
          <input
            placeholder="Enter the URL of the tool you want to connect"
            value={discoverUrl}
            onChange={e => setDiscoverUrl(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleDiscover()}
            style={{ ...inputStyle, flex: 1 }}
          />
          <Button onClick={handleDiscover} disabled={discovering || !discoverUrl}>
            {discovering ? <><InlineSpinner /> Discovering...</> : 'Discover API'}
          </Button>
        </div>

        {/* Discovery progress / error */}
        {discoveryError && !discoveryResult && (
          <div style={{ marginTop: 12, padding: 14, borderRadius: 8, background: 'var(--bg-card)', border: '1px solid var(--border)' }}>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 8 }}>{discoveryError}</div>
            <div style={{ display: 'flex', gap: 8 }}>
              <input
                placeholder="Paste API docs URL for AI parsing"
                id="llm-docs-url"
                style={{ ...inputStyle, flex: 1, fontSize: 12 }}
              />
              <Button onClick={() => handleLlmParse(document.getElementById('llm-docs-url').value)}
                disabled={discovering}
                style={{ fontSize: 12, padding: '6px 12px' }}>
                {discovering ? <InlineSpinner /> : 'Parse with AI'}
              </Button>
            </div>
          </div>
        )}

        {/* Endpoint Explorer */}
        {discoveryResult && discoveryResult.endpoints?.length > 0 && (
          <div style={{ marginTop: 12 }}>
            <div style={{
              display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10,
              padding: '8px 12px', background: '#22c55e12', border: '1px solid #22c55e30', borderRadius: 8,
            }}>
              <Check size={14} color="#22c55e" />
              <span style={{ fontSize: 12, color: '#22c55e' }}>
                Found {discoveryResult.spec_source} spec — {discoveryResult.endpoint_count} endpoints
                {discoveryResult.tool_name && ` for ${discoveryResult.tool_name}`}
              </span>
              {discoveryResult.ai_generated && (
                <Badge bg="#eab30820" text="#eab308" label="AI-generated — review carefully" />
              )}
            </div>

            {/* Endpoint list grouped by tag */}
            <EndpointExplorer
              endpoints={discoveryResult.endpoints}
              authSchemes={discoveryResult.auth_schemes}
              onSelect={handleSelectEndpoint}
            />
          </div>
        )}
      </div>

      {/* Section C: Build custom */}
      <div>
        <h3 style={{ margin: '0 0 12px', fontSize: 16, fontWeight: 600 }}>Build custom</h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
          {['api', 'sql', 'file', 'mcp'].map(t => {
            const Icon = TRANSPORT_ICONS[t]
            return (
              <Card key={t} onClick={() => handleSelectCustomTransport(t)} style={{ cursor: 'pointer', padding: 16, textAlign: 'center' }}>
                <Icon size={28} color="var(--text-muted)" style={{ marginBottom: 8 }} />
                <div style={{ fontWeight: 600, fontSize: 13, textTransform: 'uppercase' }}>{t}</div>
              </Card>
            )
          })}
        </div>
      </div>
    </div>
  )

  // ── Step 1: Auth (template connectors only) ──
  const renderAuth = () => (
    <StepAuthenticate
      connectorId={selectedConnector}
      connectorDetail={connectorDetail}
      onComplete={(cId, user) => {
        setCredentialsId(cId)
        setConnectedUser(user)
        setStep(2)
      }}
      onSkip={() => setStep(2)}
    />
  )

  // ── Step 2: Configure + inline auth + connect ──
  const renderConfigure = () => (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <h3 style={{ margin: 0, fontSize: 16, fontWeight: 600 }}>
        {transportType === 'file' ? 'Upload File' : transportType === 'sql' ? 'Connect to Database' : transportType === 'mcp' ? 'Connect to MCP Server' : 'Connect to API'}
      </h3>

      {/* Direction selector (only for custom builds, templates pre-set this) */}
      {!selectedConnector && (
        <div style={{ maxWidth: 300 }}>
          <label style={labelStyle}>Direction</label>
          <div style={{ display: 'flex', gap: 6 }}>
            {['pull', 'push'].map(d => (
              <button key={d} onClick={() => setDirection(d)} style={{
                flex: 1, padding: '6px 0', borderRadius: 6, fontSize: 12, fontWeight: 600,
                cursor: 'pointer', textTransform: 'uppercase',
                background: direction === d ? 'var(--accent)' : 'transparent',
                color: direction === d ? '#fff' : 'var(--text-muted)',
                border: direction === d ? 'none' : '1px solid var(--border)',
              }}>
                {d}
              </button>
            ))}
          </div>
        </div>
      )}

      {transportType === 'api' && (
        <>
          {/* URL + method */}
          <div style={{ display: 'flex', gap: 8 }}>
            <select
              value={transportConfig.method || 'GET'}
              onChange={e => setTransportConfig({ ...transportConfig, method: e.target.value })}
              style={selectStyle}
            >
              {['GET', 'POST', 'PUT', 'PATCH'].map(m => <option key={m}>{m}</option>)}
            </select>
            <input
              placeholder="Base URL (e.g. https://cloud.tenable.com)"
              value={transportConfig.base_url || ''}
              onChange={e => setTransportConfig({ ...transportConfig, base_url: e.target.value })}
              style={{ ...inputStyle, flex: 1 }}
            />
          </div>
          <input
            placeholder="Path (e.g. /assets)"
            value={transportConfig.path || ''}
            onChange={e => setTransportConfig({ ...transportConfig, path: e.target.value })}
            style={inputStyle}
          />

          {/* Inline auth — shown when no credentials yet, or when editing (to allow updating) */}
          {(!credentialsId || editId) && (
            <div style={{ padding: 16, background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8 }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Authentication {editId && credentialsId && <span style={{ fontWeight: 400, textTransform: 'none', color: 'var(--text-muted)' }}>— leave blank to keep existing</span>}
              </div>
              <select
                value={inlineAuthType}
                onChange={e => { setInlineAuthType(e.target.value); setInlineAuthValues({}) }}
                style={{ ...inputStyle, marginBottom: 10 }}
              >
                {AUTH_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
              </select>

              {inlineAuthType === 'bearer' && (
                <div style={{ position: 'relative' }}>
                  <input
                    type={showSecrets ? 'text' : 'password'}
                    placeholder="Bearer token / Access token"
                    value={inlineAuthValues.access_token || ''}
                    onChange={e => setInlineAuthValues({ ...inlineAuthValues, access_token: e.target.value })}
                    style={inputStyle}
                  />
                  <SecretToggle show={showSecrets} onToggle={() => setShowSecrets(!showSecrets)} />
                </div>
              )}

              {inlineAuthType === 'api_key' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <input
                    placeholder="Header name (e.g. X-ApiKeys, Authorization)"
                    value={inlineAuthValues.header_name || ''}
                    onChange={e => setInlineAuthValues({ ...inlineAuthValues, header_name: e.target.value })}
                    style={inputStyle}
                  />
                  <div style={{ position: 'relative' }}>
                    <input
                      type={showSecrets ? 'text' : 'password'}
                      placeholder="Header value (e.g. accessKey=...;secretKey=...)"
                      value={inlineAuthValues.api_key || ''}
                      onChange={e => setInlineAuthValues({ ...inlineAuthValues, api_key: e.target.value })}
                      style={inputStyle}
                    />
                    <SecretToggle show={showSecrets} onToggle={() => setShowSecrets(!showSecrets)} />
                  </div>
                </div>
              )}

              {inlineAuthType === 'basic' && (
                <div style={{ display: 'flex', gap: 8 }}>
                  <input
                    placeholder="Username"
                    value={inlineAuthValues.username || ''}
                    onChange={e => setInlineAuthValues({ ...inlineAuthValues, username: e.target.value })}
                    style={{ ...inputStyle, flex: 1 }}
                  />
                  <div style={{ position: 'relative', flex: 1 }}>
                    <input
                      type={showSecrets ? 'text' : 'password'}
                      placeholder="Password"
                      value={inlineAuthValues.password || ''}
                      onChange={e => setInlineAuthValues({ ...inlineAuthValues, password: e.target.value })}
                      style={inputStyle}
                    />
                    <SecretToggle show={showSecrets} onToggle={() => setShowSecrets(!showSecrets)} />
                  </div>
                </div>
              )}

              {inlineAuthType === 'oauth2_client' && (() => {
                const baseUrl = transportConfig.base_url || ''
                const handleDiscover = async () => {
                  if (!baseUrl) return
                  setOauthDiscovering(true)
                  setOauthDiscovered(null)
                  try {
                    const r = await discoverOAuth(baseUrl)
                    if (r.oauth_supported && r.token_endpoint) {
                      setOauthDiscovered(r)
                      setInlineAuthValues(v => ({
                        ...v,
                        token_url: r.token_endpoint,
                        scopes: (r.scopes_supported || []).join(' '),
                      }))
                    } else {
                      setOauthDiscovered(false)
                    }
                  } catch { setOauthDiscovered(false) }
                  finally { setOauthDiscovering(false) }
                }
                return (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                      Hakuna exchanges your credentials for an access token and refreshes it automatically.
                    </div>

                    {/* Token URL row — auto-discover from base URL */}
                    <div style={{ display: 'flex', gap: 6 }}>
                      <input
                        placeholder="Token URL (e.g. https://api.example.com/oauth2/token)"
                        value={inlineAuthValues.token_url || ''}
                        onChange={e => setInlineAuthValues({ ...inlineAuthValues, token_url: e.target.value })}
                        style={{ ...inputStyle, flex: 1 }}
                      />
                      <button
                        onClick={handleDiscover}
                        disabled={oauthDiscovering || !baseUrl}
                        title={baseUrl ? 'Auto-detect token URL and scopes from this API' : 'Enter a Base URL above first'}
                        style={{
                          padding: '0 10px', borderRadius: 6, border: '1px solid var(--border)',
                          background: 'var(--bg)', color: 'var(--text-muted)', cursor: baseUrl ? 'pointer' : 'not-allowed',
                          fontSize: 11, whiteSpace: 'nowrap', opacity: baseUrl ? 1 : 0.5,
                        }}
                      >
                        {oauthDiscovering ? '…' : oauthDiscovered ? '✓ Detected' : 'Auto-detect'}
                      </button>
                    </div>

                    {oauthDiscovered === false && (
                      <div style={{ fontSize: 11, color: '#f59e0b' }}>
                        No OAuth2 discovery doc found — enter the token URL manually.
                      </div>
                    )}

                    <input
                      placeholder="Client ID"
                      value={inlineAuthValues.client_id || ''}
                      onChange={e => setInlineAuthValues({ ...inlineAuthValues, client_id: e.target.value })}
                      style={inputStyle}
                    />
                    <div style={{ position: 'relative' }}>
                      <input
                        type={showSecrets ? 'text' : 'password'}
                        placeholder="Client Secret"
                        value={inlineAuthValues.client_secret || ''}
                        onChange={e => setInlineAuthValues({ ...inlineAuthValues, client_secret: e.target.value })}
                        style={inputStyle}
                      />
                      <SecretToggle show={showSecrets} onToggle={() => setShowSecrets(!showSecrets)} />
                    </div>
                    <input
                      placeholder="Scopes (space-separated, optional)"
                      value={inlineAuthValues.scopes || ''}
                      onChange={e => setInlineAuthValues({ ...inlineAuthValues, scopes: e.target.value })}
                      style={inputStyle}
                    />
                  </div>
                )
              })()}
            </div>
          )}

          {credentialsId && !editId && (
            <div style={{
              padding: '8px 14px', borderRadius: 8, background: '#22c55e12', border: '1px solid #22c55e30',
              fontSize: 12, color: '#22c55e', display: 'flex', alignItems: 'center', gap: 6,
            }}>
              <Check size={14} /> Credentials saved{connectedUser ? ` — connected as ${connectedUser}` : ''}
            </div>
          )}

          {/* Custom request headers */}
          <div style={{ padding: 16, background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8 }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Request Headers
            </div>
            {customHeaders.map((h, idx) => (
              <div key={idx} style={{ display: 'flex', gap: 8, marginBottom: 6 }}>
                <input
                  placeholder="Header name (e.g. X-Api-Key)"
                  value={h.key}
                  onChange={e => {
                    const next = [...customHeaders]
                    next[idx] = { ...next[idx], key: e.target.value }
                    setCustomHeaders(next)
                  }}
                  style={{ ...inputStyle, flex: 1 }}
                />
                <input
                  placeholder="Value"
                  value={h.value}
                  onChange={e => {
                    const next = [...customHeaders]
                    next[idx] = { ...next[idx], value: e.target.value }
                    setCustomHeaders(next)
                  }}
                  style={{ ...inputStyle, flex: 2 }}
                />
                <button
                  onClick={() => setCustomHeaders(customHeaders.filter((_, i) => i !== idx))}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', fontSize: 16, padding: '0 4px' }}
                  title="Remove header"
                >×</button>
              </div>
            ))}
            <button
              onClick={() => setCustomHeaders([...customHeaders, { key: '', value: '' }])}
              style={{ fontSize: 12, color: 'var(--accent)', background: 'none', border: 'none', cursor: 'pointer', padding: 0, marginTop: 4 }}
            >
              + Add header
            </button>
          </div>

          {/* Request body — shown for POST/PUT/PATCH */}
          {['POST', 'PUT', 'PATCH'].includes(transportConfig.method || 'GET') && (
            <div style={{ padding: 16, background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8 }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Request Body
              </div>
              {customBodyParams.map((p, idx) => (
                <div key={idx} style={{ display: 'flex', gap: 8, marginBottom: 6 }}>
                  <input
                    placeholder="Key (e.g. query)"
                    value={p.key}
                    onChange={e => {
                      const next = [...customBodyParams]
                      next[idx] = { ...next[idx], key: e.target.value }
                      setCustomBodyParams(next)
                    }}
                    style={{ ...inputStyle, flex: 1 }}
                  />
                  <input
                    placeholder='Value (e.g. "Fortinet AND RCE" or 10)'
                    value={p.value}
                    onChange={e => {
                      const next = [...customBodyParams]
                      next[idx] = { ...next[idx], value: e.target.value }
                      setCustomBodyParams(next)
                    }}
                    style={{ ...inputStyle, flex: 2 }}
                  />
                  <button
                    onClick={() => setCustomBodyParams(customBodyParams.filter((_, i) => i !== idx))}
                    style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', fontSize: 16, padding: '0 4px' }}
                    title="Remove param"
                  >×</button>
                </div>
              ))}
              <button
                onClick={() => setCustomBodyParams([...customBodyParams, { key: '', value: '' }])}
                style={{ fontSize: 12, color: 'var(--accent)', background: 'none', border: 'none', cursor: 'pointer', padding: 0, marginTop: 4 }}
              >
                + Add param
              </button>
            </div>
          )}
        </>
      )}

      {/* ── File transport ── */}
      {transportType === 'file' && (
        <div>
          <div
            onDragOver={e => { e.preventDefault(); e.currentTarget.style.borderColor = 'var(--accent)' }}
            onDragLeave={e => { e.currentTarget.style.borderColor = 'var(--border)' }}
            onDrop={async e => {
              e.preventDefault()
              e.currentTarget.style.borderColor = 'var(--border)'
              const file = e.dataTransfer.files[0]
              if (!file) return
              setLoading(true)
              try {
                const result = await uploadIntegrationFile(file)
                setTransportConfig({ ...transportConfig, path: result.path, source: 'local', format: result.format })
              } catch (err) { toast.error('Upload failed: ' + err.message) }
              finally { setLoading(false) }
            }}
            style={{
              border: '2px dashed var(--border)', borderRadius: 8, padding: 24, textAlign: 'center',
              cursor: 'pointer', transition: 'border-color 0.15s',
            }}
            onClick={() => document.getElementById('file-upload-input').click()}
          >
            <FileText size={28} color="var(--text-muted)" style={{ marginBottom: 8 }} />
            <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
              Drop a file here or click to browse
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
              Supports .csv, .json, .xml, .yaml, .nessus, .pdf, .docx
            </div>
            <input
              id="file-upload-input"
              type="file"
              accept=".nessus,.csv,.json,.xml,.yaml,.yml,.html,.txt,.pdf,.docx"
              style={{ display: 'none' }}
              onChange={async e => {
                const file = e.target.files[0]
                if (!file) return
                setLoading(true)
                try {
                  const result = await uploadIntegrationFile(file)
                  setTransportConfig({ ...transportConfig, path: result.path, source: 'local', format: result.format })
                } catch (err) { toast.error('Upload failed: ' + err.message) }
                finally { setLoading(false) }
              }}
            />
          </div>
          {transportConfig.path && (
            <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>
              File: {transportConfig.path.split('/').pop()} ({transportConfig.format || 'auto'})
            </div>
          )}
        </div>
      )}

      {/* ── SQL transport ── */}
      {transportType === 'sql' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div style={{ padding: 16, background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8 }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Connection
            </div>
            <select
              value={transportConfig.dialect || 'postgres'}
              onChange={e => setTransportConfig({ ...transportConfig, dialect: e.target.value })}
              style={{ ...inputStyle, marginBottom: 8 }}
            >
              <option value="postgres">PostgreSQL</option>
              <option value="mysql">MySQL</option>
              <option value="sqlite">SQLite</option>
              <option value="mssql">SQL Server</option>
            </select>
            <div style={{ position: 'relative' }}>
              <input
                type={showSecrets ? 'text' : 'password'}
                placeholder="Connection string (e.g. postgresql://user:pass@host:5432/db)"
                value={inlineAuthValues.connection_string || ''}
                onChange={e => setInlineAuthValues({ ...inlineAuthValues, connection_string: e.target.value })}
                style={inputStyle}
              />
              <SecretToggle show={showSecrets} onToggle={() => setShowSecrets(!showSecrets)} />
            </div>
          </div>
          <div>
            <label style={labelStyle}>SQL Query</label>
            <textarea
              placeholder={"SELECT * FROM vulnerabilities\nWHERE severity >= {{params.min_severity}}"}
              value={transportConfig.query || ''}
              onChange={e => setTransportConfig({ ...transportConfig, query: e.target.value })}
              style={{ ...inputStyle, fontFamily: 'var(--mono)', minHeight: 120, resize: 'vertical' }}
            />
          </div>
        </div>
      )}

      {/* ── MCP transport ── */}
      {transportType === 'mcp' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {/* Server URL + Discover */}
          <div>
            <label style={labelStyle}>MCP Server URL</label>
            <div style={{ display: 'flex', gap: 8 }}>
              <input
                placeholder="http://localhost:3001 or https://mcp.example.com"
                value={transportConfig.server_url || ''}
                onChange={e => { setTransportConfig({ ...transportConfig, server_url: e.target.value }); setMcpTools(null) }}
                style={{ ...inputStyle, flex: 1 }}
              />
              <Button
                onClick={async () => {
                  setLoading(true); setMcpAuthRequired(false); setConnectError(null)
                  try {
                    // Save credentials first if provided
                    let cId = credentialsId
                    if (inlineAuthValues.access_token || inlineAuthValues.mcp_api_key) {
                      const cred = await createCredential({
                        name: `MCP — ${transportConfig.server_url}`,
                        connector_id: 'mcp', auth_type: 'bearer',
                        values: inlineAuthValues,
                        instance_url: transportConfig.server_url,
                      })
                      cId = cred.id; setCredentialsId(cId)
                    }
                    const result = await discoverMcpTools(transportConfig.server_url, cId)
                    if (result.auth_required) {
                      setMcpAuthRequired(true)
                      setConnectError(result.error)
                      if (result.oauth_metadata?.authorization_endpoint) {
                        setMcpOAuthMetadata(result.oauth_metadata)
                      }
                    } else {
                      setMcpTools(result)
                    }
                  } catch (e) { setConnectError(e.message) }
                  finally { setLoading(false) }
                }}
                disabled={loading || !transportConfig.server_url}
                style={{ display: 'inline-flex', alignItems: 'center', gap: 6, whiteSpace: 'nowrap' }}
              >
                {loading ? <InlineSpinner /> : <Zap size={14} />} Discover Tools
              </Button>
            </div>
          </div>

          {/* Auth section */}
          <div style={{ padding: 14, background: 'var(--bg-card)', border: `1px solid ${mcpAuthRequired ? '#ef444440' : 'var(--border)'}`, borderRadius: 8 }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Authentication {mcpAuthRequired && <span style={{ color: '#ef4444', fontWeight: 400, textTransform: 'none' }}>— required by this server</span>}
            </div>

            {/* OAuth button — shown when server exposes OAuth metadata */}
            {mcpOAuthMetadata?.authorization_endpoint && (
              <div style={{ marginBottom: 10 }}>
                <Button
                  onClick={async () => {
                    setLoading(true)
                    try {
                      const { authorization_url, state } = await mcpOAuthStart(transportConfig.server_url, mcpOAuthMetadata)
                      // Open popup
                      const popup = window.open(authorization_url, 'mcp_oauth', 'width=600,height=700,popup=yes')
                      // Listen for callback message
                      const handler = async (event) => {
                        if (!event.data?.credentials_id && !event.data?.success) return
                        window.removeEventListener('message', handler)
                        if (event.data.success && event.data.credentials_id) {
                          setCredentialsId(event.data.credentials_id)
                          setConnectedUser(event.data.connected_user)
                          setMcpAuthRequired(false)
                          setConnectError(null)
                          // Auto-retry discovery with new credentials
                          try {
                            const result = await discoverMcpTools(transportConfig.server_url, event.data.credentials_id)
                            if (!result.auth_required) {
                              setMcpTools(result)
                            }
                          } catch {}
                        } else {
                          setConnectError(event.data.error || 'OAuth failed')
                        }
                        setLoading(false)
                      }
                      window.addEventListener('message', handler)
                      // Fallback timeout
                      setTimeout(() => { window.removeEventListener('message', handler); setLoading(false) }, 120000)
                    } catch (e) {
                      setConnectError(e.message)
                      setLoading(false)
                    }
                  }}
                  disabled={loading}
                  style={{ display: 'inline-flex', alignItems: 'center', gap: 6, width: '100%', justifyContent: 'center' }}
                >
                  {loading ? <InlineSpinner /> : <Globe size={14} />}
                  {loading ? 'Waiting for authorization...' : `Authenticate with ${mcpOAuthMetadata.issuer || 'OAuth'}`}
                </Button>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4, textAlign: 'center' }}>
                  Opens a popup to authorize Hakuna. No credentials are shared directly.
                </div>
              </div>
            )}

            {/* Divider if both OAuth and manual are available */}
            {mcpOAuthMetadata?.authorization_endpoint && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, margin: '8px 0', color: 'var(--text-muted)', fontSize: 11 }}>
                <div style={{ flex: 1, height: 1, background: 'var(--border)' }} />
                or use a token directly
                <div style={{ flex: 1, height: 1, background: 'var(--border)' }} />
              </div>
            )}

            {/* Manual token input */}
            {!mcpOAuthMetadata?.authorization_endpoint && (
              <select
                value={inlineAuthType}
                onChange={e => { setInlineAuthType(e.target.value); setInlineAuthValues({}) }}
                style={{ ...inputStyle, marginBottom: 8 }}
              >
                <option value="none">None</option>
                <option value="bearer">Bearer Token</option>
                <option value="api_key">API Key</option>
              </select>
            )}

            {(inlineAuthType === 'bearer' || mcpAuthRequired) && (
              <div style={{ position: 'relative' }}>
                <input
                  type={showSecrets ? 'text' : 'password'}
                  placeholder="Paste a bearer / access token"
                  value={inlineAuthValues.access_token || ''}
                  onChange={e => setInlineAuthValues({ ...inlineAuthValues, access_token: e.target.value })}
                  style={inputStyle}
                />
                <SecretToggle show={showSecrets} onToggle={() => setShowSecrets(!showSecrets)} />
              </div>
            )}
            {inlineAuthType === 'api_key' && !mcpAuthRequired && (
              <div style={{ position: 'relative' }}>
                <input
                  type={showSecrets ? 'text' : 'password'}
                  placeholder="API key"
                  value={inlineAuthValues.mcp_api_key || ''}
                  onChange={e => setInlineAuthValues({ ...inlineAuthValues, mcp_api_key: e.target.value })}
                  style={inputStyle}
                />
                <SecretToggle show={showSecrets} onToggle={() => setShowSecrets(!showSecrets)} />
              </div>
            )}

            {/* Connected state */}
            {credentialsId && !mcpAuthRequired && (
              <div style={{ marginTop: 8, padding: '6px 10px', borderRadius: 6, background: '#22c55e12', border: '1px solid #22c55e30', display: 'flex', alignItems: 'center', gap: 6 }}>
                <Check size={14} color="#22c55e" />
                <span style={{ fontSize: 12, color: '#22c55e' }}>Authenticated{connectedUser ? ` as ${connectedUser}` : ''}</span>
              </div>
            )}
          </div>

          {/* Tool picker — shown after discovery */}
          {mcpTools && mcpTools.tools?.length > 0 && (
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                <Check size={14} color="#22c55e" />
                <span style={{ fontSize: 12, color: '#22c55e' }}>
                  Found {mcpTools.tool_count} tools
                  {mcpTools.server_info?.name && ` on ${mcpTools.server_info.name}`}
                </span>
              </div>
              <label style={labelStyle}>Select a tool</label>
              <div style={{ maxHeight: 250, overflowY: 'auto', border: '1px solid var(--border)', borderRadius: 8 }}>
                {mcpTools.tools.map((tool, i) => (
                  <div
                    key={tool.name}
                    onClick={() => setTransportConfig({ ...transportConfig, tool_name: tool.name, tool_arguments: {} })}
                    style={{
                      padding: '8px 12px', cursor: 'pointer', borderBottom: '1px solid var(--border)',
                      background: transportConfig.tool_name === tool.name ? 'var(--accent)10' : 'transparent',
                      border: transportConfig.tool_name === tool.name ? '1px solid var(--accent)30' : undefined,
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span style={{ fontSize: 12, fontFamily: 'var(--mono)', fontWeight: 600, color: 'var(--accent)' }}>{tool.name}</span>
                      {transportConfig.tool_name === tool.name && <Check size={12} color="var(--accent)" />}
                    </div>
                    {(tool.description || tool.title) && (
                      <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                        {tool.description || tool.title}
                      </div>
                    )}
                    {tool.inputSchema?.properties && (
                      <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 3 }}>
                        Params: {Object.keys(tool.inputSchema.properties).join(', ')}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Tool arguments — shown after tool is selected */}
          {transportConfig.tool_name && (
            <div>
              <label style={labelStyle}>Tool Arguments (JSON) — {transportConfig.tool_name}</label>
              {/* Pre-populate with schema hints */}
              <textarea
                placeholder={'{\n  "limit": 100\n}'}
                value={transportConfig.tool_arguments ? (typeof transportConfig.tool_arguments === 'string' ? transportConfig.tool_arguments : JSON.stringify(transportConfig.tool_arguments, null, 2)) : '{}'}
                onChange={e => {
                  try { setTransportConfig({ ...transportConfig, tool_arguments: JSON.parse(e.target.value) }) }
                  catch { setTransportConfig({ ...transportConfig, tool_arguments: e.target.value }) }
                }}
                style={{ ...inputStyle, fontFamily: 'var(--mono)', minHeight: 80, resize: 'vertical' }}
              />
            </div>
          )}

          {mcpTools && mcpTools.tools?.length === 0 && (
            <div style={{ padding: 12, borderRadius: 8, background: '#eab30812', border: '1px solid #eab30830', fontSize: 12, color: '#eab308' }}>
              Server responded but has no tools available.
            </div>
          )}
        </div>
      )}

      {connectError && (
        <div style={{ padding: '10px 14px', borderRadius: 8, background: '#ef444412', border: '1px solid #ef444430', color: '#ef4444', fontSize: 12 }}>
          {connectError}
        </div>
      )}

      {transportType === 'file' && loading && ['pdf', 'docx'].includes(transportConfig.format) && (
        <div style={{
          padding: 16, borderRadius: 8, background: 'var(--accent-bg, #3b82f610)',
          border: '1px solid var(--accent-border, #3b82f630)',
          display: 'flex', flexDirection: 'column', gap: 8,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <InlineSpinner />
            <span style={{ fontSize: 13, fontWeight: 600 }}>Extracting findings with AI...</span>
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            The document is being analyzed by AI to extract structured findings. This typically takes 30–90 seconds depending on report size.
          </div>
          <div style={{
            height: 3, borderRadius: 2, background: 'var(--border)', overflow: 'hidden', marginTop: 4,
          }}>
            <div style={{
              height: '100%', borderRadius: 2, background: 'var(--accent)',
              animation: 'indeterminate 1.5s ease-in-out infinite',
              width: '40%',
            }} />
          </div>
          <style>{`@keyframes indeterminate { 0% { transform: translateX(-100%); } 100% { transform: translateX(350%); } }`}</style>
        </div>
      )}
      <Button onClick={handleConnect}
        disabled={loading || (transportType === 'api' && !transportConfig.base_url) || (transportType === 'file' && !transportConfig.path) || (transportType === 'sql' && !transportConfig.query) || (transportType === 'mcp' && !transportConfig.server_url)}
        style={{ alignSelf: 'flex-start', display: 'inline-flex', alignItems: 'center', gap: 6 }}>
        {loading ? <><InlineSpinner /> {transportType === 'file' ? 'Parsing...' : 'Connecting...'}</> : <>{transportType === 'file' ? 'Parse File' : 'Connect & Fetch Response'} <ArrowRight size={14} /></>}
      </Button>
    </div>
  )

  // ── Step 3: Pick Records from Response ──
  const renderRecordsPicker = () => (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <h3 style={{ margin: 0, fontSize: 16, fontWeight: 600 }}>Pick the records array</h3>
      <p style={{ margin: 0, fontSize: 12, color: 'var(--text-muted)' }}>
        Click an array in the response to select it as the data source. Arrays of objects are highlighted.
      </p>

      {recordsPath && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 8, padding: '8px 14px',
          background: 'var(--accent)10', border: '1px solid var(--accent)30', borderRadius: 8,
        }}>
          <List size={14} color="var(--accent)" />
          <span style={{ fontSize: 12 }}>Selected: <b style={{ fontFamily: 'var(--mono)' }}>{recordsPath}</b></span>
          {sampleRecords.length > 0 && (
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>({sampleRecords.length} items)</span>
          )}
        </div>
      )}

      <div style={{ display: 'flex', gap: 16 }}>
        {/* Left: JSON tree of raw response */}
        <div style={{ flex: 1, maxHeight: 500, overflowY: 'auto', border: '1px solid var(--border)', borderRadius: 8, padding: 8 }}>
          {rawResponse && (
            <JsonTreePicker
              data={rawResponse}
              onSelectArray={(path, items) => {
                setRecordsPath(path)
                setSampleRecords(items.slice(0, 10))
                // Re-detect paths from first record
                if (items[0] && typeof items[0] === 'object') {
                  // We'll re-fetch with the path on confirm
                }
              }}
              selectedPath={recordsPath}
            />
          )}
        </div>

        {/* Right: first record preview */}
        <div style={{ width: '40%', maxHeight: 500, overflowY: 'auto', border: '1px solid var(--border)', borderRadius: 8, padding: 12 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 8, textTransform: 'uppercase' }}>
            First Record Preview
          </div>
          {sampleRecords[0] ? (
            <pre style={{ margin: 0, fontSize: 11, fontFamily: 'var(--mono)', whiteSpace: 'pre-wrap', wordBreak: 'break-all', color: 'var(--text)' }}>
              {JSON.stringify(sampleRecords[0], null, 2)}
            </pre>
          ) : (
            <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Select an array to see a preview</span>
          )}
        </div>
      </div>

      <Button onClick={() => handlePickRecords(recordsPath)} disabled={loading || !recordsPath}>
        {loading ? <><InlineSpinner /> Fetching...</> : <>Use These Records <ArrowRight size={14} style={{ marginLeft: 6 }} /></>}
      </Button>
    </div>
  )

  // ── Step 4: Pick Target ──
  const handleSelectTarget = async (slug) => {
    setEntity(slug)
    setLoading(true)
    try {
      const targetSchema = await getTargetSchema(slug)
      setSchema(targetSchema) // Now schema is a flat array for the selected target
      setFieldMap([]) // Reset field map when target changes
      setSuggestions(null)
      setStep(5) // advance to field mapper
    } catch (e) {
      console.error('Failed to load target schema:', e)
    } finally {
      setLoading(false)
    }
  }

  const CATEGORY_LABELS = {
    core: 'Core',
    threat_intel: 'Threat Intelligence',
    inventory: 'Inventory',
    sbom: 'Software Bill of Materials',
  }
  const CATEGORY_COLORS = {
    core: { bg: '#1a2e05', text: '#86efac' },
    threat_intel: { bg: '#451a03', text: '#fcd34d' },
    inventory: { bg: '#1e3a5f', text: '#7dd3fc' },
    sbom: { bg: '#3b1f5e', text: '#d8b4fe' },
  }

  const renderPickTarget = () => {
    // Group targets by category
    const groups = {}
    targetModels.forEach(t => {
      const cat = t.category || 'other'
      if (!groups[cat]) groups[cat] = []
      groups[cat].push(t)
    })

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
        <div>
          <h3 style={{ margin: '0 0 4px', fontSize: 16, fontWeight: 600 }}>Where should this data go?</h3>
          <p style={{ margin: 0, fontSize: 12, color: 'var(--text-muted)' }}>
            Choose the destination model for your imported data. This determines which fields are available for mapping.
          </p>
        </div>

        {Object.entries(groups).map(([category, targets]) => (
          <div key={category}>
            <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>
              {CATEGORY_LABELS[category] || category}
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 10 }}>
              {targets.map(t => {
                const isSelected = entity === t.slug
                const colors = CATEGORY_COLORS[category] || { bg: 'var(--border)', text: 'var(--text-muted)' }
                return (
                  <Card
                    key={t.slug}
                    onClick={() => handleSelectTarget(t.slug)}
                    style={{
                      cursor: 'pointer', padding: 16,
                      border: isSelected ? '2px solid var(--accent)' : '1px solid var(--border)',
                      background: isSelected ? 'var(--accent)08' : undefined,
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 6 }}>
                      <div style={{ fontWeight: 600, fontSize: 13 }}>{t.display_name}</div>
                      <Badge bg={colors.bg} text={colors.text} label={category.toUpperCase().replace('_', ' ')} />
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.4, marginBottom: 8 }}>
                      {t.description}
                    </div>
                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                      {t.dedup_keys.map(k => (
                        <span key={k} style={{ fontSize: 10, padding: '1px 5px', borderRadius: 3, background: 'var(--border)', color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>
                          {k}
                        </span>
                      ))}
                      {t.has_parent && (
                        <span style={{ fontSize: 10, padding: '1px 5px', borderRadius: 3, background: '#3b82f615', color: '#3b82f6', border: '1px solid #3b82f630' }}>
                          parent: {t.parent_slug}
                        </span>
                      )}
                    </div>
                  </Card>
                )
              })}
            </div>
          </div>
        ))}
      </div>
    )
  }

  // ── Step 5: Field Mapper ──
  // Derive the schema fields for the current entity
  const entitySchema = (() => {
    if (Array.isArray(schema)) return schema  // flat array from getTargetSchema or legacy
    if (schema && typeof schema === 'object') {
      // Full schema dict: {asset: [...], finding: [...], action: [...]}
      const primary = schema[entity] || []
      if (direction === 'push') return schema.action || primary
      return primary
    }
    return []
  })()

  const renderFieldMapper = () => (
    <StepFieldMapper
      detectedPaths={detectedPaths}
      sampleRecords={sampleRecords}
      schema={entitySchema}
      entity={entity}
      entityDisplayName={targetModels.find(t => t.slug === entity)?.display_name || entity}
      onChangeTarget={() => setStep(4)}
      fieldMap={fieldMap}
      onFieldMapChange={setFieldMap}
      onAutoSuggest={handleAutoSuggest}
      suggestions={suggestions}
      loading={loading}
      onNext={handlePreview}
    />
  )

  // ── Step 5: Preview ──
  const renderPreview = () => (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <h3 style={{ margin: 0, fontSize: 16, fontWeight: 600 }}>Preview Mapping</h3>
      <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
        {previewRecords.length} records previewed. {previewRecords.filter(r => r.errors.length > 0).length} with errors.
      </div>

      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)' }}>
              <th style={thStyle}>#</th>
              {fieldMap.map(m => <th key={m.target} style={thStyle}>{m.target}</th>)}
              <th style={thStyle}>Errors</th>
            </tr>
          </thead>
          <tbody>
            {previewRecords.map((r, i) => (
              <tr key={i} style={{ borderBottom: '1px solid var(--border)' }}>
                <td style={tdStyle}>{i + 1}</td>
                {fieldMap.map(m => {
                  const val = getNestedValue(r.mapped, m.target)
                  const hasError = r.errors.some(e => e.target === m.target && e.level === 'error')
                  return (
                    <td key={m.target} style={{ ...tdStyle, background: hasError ? '#450a0a33' : undefined }}>
                      {val !== null && val !== undefined ? String(val) : '—'}
                    </td>
                  )
                })}
                <td style={tdStyle}>
                  {r.errors.length > 0 && (
                    <span style={{ color: '#ef4444', fontSize: 11 }}>{r.errors.length} error{r.errors.length > 1 ? 's' : ''}</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div style={{ display: 'flex', gap: 8 }}>
        <Button onClick={() => setStep(5)} style={{ background: 'transparent', color: 'var(--text)', border: '1px solid var(--border)' }}>
          <ArrowLeft size={14} /> Fix Mappings
        </Button>
        <Button onClick={() => setStep(7)}>Looks Good <ArrowRight size={14} style={{ marginLeft: 4 }} /></Button>
      </div>
    </div>
  )

  // ── Step 6: Save & Schedule ──
  const renderSave = () => (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16, maxWidth: 500 }}>
      <h3 style={{ margin: 0, fontSize: 16, fontWeight: 600 }}>Save & Schedule</h3>

      <div>
        <label style={labelStyle}>Integration Name</label>
        <input value={integrationName} onChange={e => setIntegrationName(e.target.value)} style={inputStyle} />
      </div>

      <div>
        <label style={labelStyle}>Target</label>
        <div style={{
          padding: '6px 12px', borderRadius: 6, fontSize: 12, fontWeight: 600,
          background: 'var(--accent)12', border: '1px solid var(--accent)30', color: 'var(--accent)',
          display: 'inline-block',
        }}>
          {targetModels.find(t => t.slug === entity)?.display_name || entity.toUpperCase()}
        </div>
        <button onClick={() => setStep(4)} style={{ marginLeft: 8, background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', fontSize: 11, textDecoration: 'underline' }}>
          change
        </button>
      </div>

      <div>
        <label style={labelStyle}>Schedule</label>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {[
            { label: 'On demand', value: '' },
            { label: 'Every 6h', value: '0 */6 * * *' },
            { label: 'Daily', value: '0 0 * * *' },
            { label: 'Weekly', value: '0 0 * * 1' },
            { label: 'Custom', value: '__custom__' },
          ].map(s => {
            const isCustomPreset = s.value === '__custom__'
            const presetValues = ['', '0 */6 * * *', '0 0 * * *', '0 0 * * 1']
            const isCustomActive = isCustomPreset && schedule && !presetValues.includes(schedule)
            const isActive = isCustomPreset ? isCustomActive : schedule === s.value
            return (
              <button key={s.value} onClick={() => {
                if (isCustomPreset) {
                  if (!isCustomActive) setSchedule('0 0 1 * *') // default custom to monthly
                }  else {
                  setSchedule(s.value)
                }
              }} style={{
                ...pillButtonStyle,
                background: isActive ? 'var(--accent)' : 'transparent',
                color: isActive ? '#fff' : 'var(--text)',
                border: isActive ? 'none' : '1px solid var(--border)',
              }}>
                {s.label}
              </button>
            )
          })}
        </div>
        {schedule && !['', '0 */6 * * *', '0 0 * * *', '0 0 * * 1'].includes(schedule) && (
          <input
            value={schedule}
            onChange={e => setSchedule(e.target.value)}
            placeholder="Cron expression, e.g. 0 0 1 * *"
            style={{ marginTop: 8, padding: '8px 12px', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', fontSize: 13, width: 280, fontFamily: 'monospace' }}
          />
        )}
      </div>

      <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
        <input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} />
        <span style={{ fontSize: 13 }}>Enable immediately</span>
      </label>

      <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
        <Button onClick={() => handleSave(false)} disabled={loading || !integrationName}>
          {loading ? <InlineSpinner /> : 'Save'}
        </Button>
        <Button onClick={() => handleSave(true)} disabled={loading || !integrationName}
          style={{ background: 'var(--accent)' }}>
          {loading ? <InlineSpinner /> : 'Save & Run Now'}
        </Button>
      </div>
    </div>
  )

  return (
    <div style={{ padding: '24px 32px', maxWidth: 1100 }}>
      <button onClick={step > 0 ? () => setStep(getPrevStep()) : goBack}
        style={{ display: 'flex', alignItems: 'center', gap: 4, background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', marginBottom: 16, fontSize: 13 }}>
        <ArrowLeft size={14} /> {step > 0 ? 'Back' : 'Back to Integrations'}
      </button>

      {/* Progress bar */}
      <div style={{ display: 'flex', gap: 2, marginBottom: 32 }}>
        {STEPS.map((s, i) => (
          <div key={s.key} style={{ flex: 1, display: 'flex', alignItems: 'center', gap: 4 }}>
            <div
              onClick={() => { if (i < step) setStep(i) }}
              style={{
                width: 24, height: 24, borderRadius: '50%', display: 'flex',
                alignItems: 'center', justifyContent: 'center', fontSize: 11, fontWeight: 600,
                background: i <= step ? 'var(--accent)' : 'var(--border)',
                color: i <= step ? '#fff' : 'var(--text-muted)',
                cursor: i < step ? 'pointer' : 'default',
              }}
            >
              {i < step ? <Check size={12} /> : i + 1}
            </div>
            <span style={{ fontSize: 11, color: i <= step ? 'var(--text)' : 'var(--text-muted)', fontWeight: i === step ? 600 : 400 }}>
              {s.label}
            </span>
            {i < STEPS.length - 1 && <ChevronRight size={12} color="var(--text-muted)" />}
          </div>
        ))}
      </div>

      {renderStep()}
    </div>
  )
}

// ── JSON Tree Picker — clickable arrays ──

function JsonTreePicker({ data, onSelectArray, selectedPath, _path = '', _depth = 0 }) {
  const [expanded, setExpanded] = useState(_depth < 2)

  if (_depth > 5) return <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>...</span>

  if (Array.isArray(data)) {
    const isArrayOfObjects = data.length > 0 && typeof data[0] === 'object' && data[0] !== null
    const isSelected = selectedPath === _path
    return (
      <div>
        <div
          onClick={(e) => { e.stopPropagation(); if (isArrayOfObjects) onSelectArray(_path, data) }}
          style={{
            display: 'flex', alignItems: 'center', gap: 4, padding: '2px 4px', borderRadius: 4,
            cursor: isArrayOfObjects ? 'pointer' : 'default',
            background: isSelected ? 'var(--accent)18' : isArrayOfObjects ? '#3b82f608' : 'transparent',
            border: isSelected ? '1px solid var(--accent)' : isArrayOfObjects ? '1px solid #3b82f620' : '1px solid transparent',
          }}
        >
          <span onClick={(e) => { e.stopPropagation(); setExpanded(!expanded) }} style={{ cursor: 'pointer', userSelect: 'none' }}>
            {expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
          </span>
          <span style={{
            fontSize: 11, fontWeight: 600,
            color: isArrayOfObjects ? '#3b82f6' : 'var(--text-muted)',
          }}>
            Array [{data.length}]
          </span>
          {isArrayOfObjects && !isSelected && (
            <span style={{ fontSize: 10, color: '#3b82f6', marginLeft: 4 }}>← click to select</span>
          )}
          {isSelected && (
            <span style={{ fontSize: 10, color: 'var(--accent)', fontWeight: 600, marginLeft: 4 }}>SELECTED</span>
          )}
        </div>
        {expanded && data.length > 0 && (
          <div style={{ paddingLeft: 16 }}>
            {typeof data[0] === 'object' ? (
              <JsonTreePicker data={data[0]} onSelectArray={onSelectArray} selectedPath={selectedPath} _path={_path + '[0]'} _depth={_depth + 1} />
            ) : (
              <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>
                {JSON.stringify(data[0])}
              </span>
            )}
            {data.length > 1 && <div style={{ fontSize: 10, color: 'var(--text-muted)', padding: '2px 0' }}>...{data.length - 1} more</div>}
          </div>
        )}
      </div>
    )
  }

  if (data && typeof data === 'object') {
    return (
      <div>
        {Object.entries(data).map(([key, value]) => {
          const childPath = _path ? `${_path}.${key}` : key
          const isObj = value && typeof value === 'object'
          return (
            <div key={key} style={{ paddingLeft: _depth > 0 ? 16 : 0 }}>
              <KeyNode
                keyName={key}
                value={value}
                expanded={isObj && _depth < 2}
                onToggle={null}
              >
                {isObj ? (
                  <JsonTreePicker data={value} onSelectArray={onSelectArray} selectedPath={selectedPath} _path={childPath} _depth={_depth + 1} />
                ) : null}
              </KeyNode>
              {!isObj && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '1px 0' }}>
                  <span style={{ fontSize: 11, color: '#a78bfa', fontFamily: 'var(--mono)' }}>{key}</span>
                  <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>:</span>
                  <span style={{ fontSize: 11, color: typeof value === 'string' ? '#86efac' : '#fcd34d', fontFamily: 'var(--mono)', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'inline-block' }}>
                    {JSON.stringify(value)}
                  </span>
                </div>
              )}
            </div>
          )
        })}
      </div>
    )
  }

  return <span style={{ fontSize: 11, fontFamily: 'var(--mono)', color: 'var(--text)' }}>{JSON.stringify(data)}</span>
}

function KeyNode({ keyName, value, children }) {
  const [open, setOpen] = useState(true)
  const isObj = value && typeof value === 'object'
  if (!isObj) return null

  return (
    <div>
      <div
        onClick={() => setOpen(!open)}
        style={{ display: 'flex', alignItems: 'center', gap: 4, cursor: 'pointer', padding: '1px 0' }}
      >
        {open ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
        <span style={{ fontSize: 11, color: '#a78bfa', fontFamily: 'var(--mono)', fontWeight: 600 }}>{keyName}</span>
      </div>
      {open && <div style={{ paddingLeft: 8 }}>{children}</div>}
    </div>
  )
}

// ── Endpoint Explorer ──

function EndpointExplorer({ endpoints, authSchemes, onSelect }) {
  const [search, setSearch] = useState('')
  const [selectedIdx, setSelectedIdx] = useState(null)

  // Group by first tag
  const groups = {}
  endpoints.forEach((ep, i) => {
    const tag = ep.tags?.[0] || 'General'
    if (!groups[tag]) groups[tag] = []
    groups[tag].push({ ...ep, _idx: i })
  })

  const filtered = search
    ? endpoints.filter(ep =>
        ep.path.toLowerCase().includes(search.toLowerCase()) ||
        ep.summary?.toLowerCase().includes(search.toLowerCase()) ||
        ep.operation_id?.toLowerCase().includes(search.toLowerCase())
      ).map((ep, i) => ({ ...ep, _idx: i }))
    : null

  const METHOD_COLORS = {
    GET: '#22c55e', POST: '#3b82f6', PUT: '#eab308', PATCH: '#f97316', DELETE: '#ef4444',
  }

  const selectedEp = selectedIdx !== null ? endpoints[selectedIdx] : null

  return (
    <div style={{ display: 'flex', gap: 12, maxHeight: 400 }}>
      {/* Left: endpoint list */}
      <div style={{ width: '50%', display: 'flex', flexDirection: 'column' }}>
        <input
          placeholder="Search endpoints..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{ ...inputStyle, marginBottom: 6, fontSize: 12 }}
        />
        <div style={{ flex: 1, overflowY: 'auto', border: '1px solid var(--border)', borderRadius: 8 }}>
          {(filtered ? [{ tag: 'Results', items: filtered }] : Object.entries(groups).map(([tag, items]) => ({ tag, items }))).map(({ tag, items }) => (
            <div key={tag}>
              <div style={{ padding: '4px 8px', fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', background: 'var(--bg)', borderBottom: '1px solid var(--border)' }}>
                {tag}
              </div>
              {items.map(ep => (
                <div
                  key={ep._idx}
                  onClick={() => setSelectedIdx(ep._idx)}
                  style={{
                    padding: '6px 8px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6,
                    borderBottom: '1px solid var(--border)',
                    background: selectedIdx === ep._idx ? 'var(--accent)10' : 'transparent',
                  }}
                >
                  <span style={{
                    fontSize: 9, fontWeight: 700, padding: '1px 4px', borderRadius: 3,
                    color: METHOD_COLORS[ep.method] || '#999',
                    border: `1px solid ${METHOD_COLORS[ep.method] || '#999'}30`,
                    minWidth: 32, textAlign: 'center',
                  }}>
                    {ep.method}
                  </span>
                  <span style={{ fontSize: 11, fontFamily: 'var(--mono)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {ep.path}
                  </span>
                </div>
              ))}
            </div>
          ))}
        </div>
      </div>

      {/* Right: selected endpoint detail */}
      <div style={{ width: '50%', overflowY: 'auto', border: '1px solid var(--border)', borderRadius: 8, padding: 12 }}>
        {selectedEp ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div>
              <span style={{ fontSize: 10, fontWeight: 700, color: METHOD_COLORS[selectedEp.method], marginRight: 6 }}>{selectedEp.method}</span>
              <span style={{ fontSize: 12, fontFamily: 'var(--mono)', fontWeight: 600 }}>{selectedEp.path}</span>
            </div>
            {selectedEp.summary && <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>{selectedEp.summary}</div>}

            {selectedEp.parameters?.length > 0 && (
              <div>
                <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', marginBottom: 4, textTransform: 'uppercase' }}>Parameters</div>
                <table style={{ width: '100%', fontSize: 11, borderCollapse: 'collapse' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border)' }}>
                      <th style={{ textAlign: 'left', padding: 2, color: 'var(--text-muted)', fontSize: 10 }}>Name</th>
                      <th style={{ textAlign: 'left', padding: 2, color: 'var(--text-muted)', fontSize: 10 }}>In</th>
                      <th style={{ textAlign: 'left', padding: 2, color: 'var(--text-muted)', fontSize: 10 }}>Type</th>
                      <th style={{ textAlign: 'left', padding: 2, color: 'var(--text-muted)', fontSize: 10 }}>Req</th>
                    </tr>
                  </thead>
                  <tbody>
                    {selectedEp.parameters.map((p, i) => (
                      <tr key={i} style={{ borderBottom: '1px solid var(--border)' }}>
                        <td style={{ padding: 2, fontFamily: 'var(--mono)' }}>{p.name}</td>
                        <td style={{ padding: 2, color: 'var(--text-muted)' }}>{p.in}</td>
                        <td style={{ padding: 2, color: 'var(--text-muted)' }}>{p.type}</td>
                        <td style={{ padding: 2 }}>{p.required ? '✓' : ''}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {selectedEp.pagination_hints?.detected && (
              <div style={{ fontSize: 11, padding: '4px 8px', background: '#3b82f608', borderRadius: 4, border: '1px solid #3b82f620' }}>
                Pagination: <b>{selectedEp.pagination_hints.strategy}</b>
                {selectedEp.pagination_hints.page_param && ` (${selectedEp.pagination_hints.page_param})`}
              </div>
            )}

            <Button onClick={() => onSelect(selectedEp)} style={{ marginTop: 4, fontSize: 12 }}>
              Use this endpoint <ArrowRight size={12} style={{ marginLeft: 4 }} />
            </Button>
          </div>
        ) : (
          <div style={{ fontSize: 12, color: 'var(--text-muted)', padding: 20, textAlign: 'center' }}>
            Select an endpoint to see details
          </div>
        )}
      </div>
    </div>
  )
}

function InlineSpinner({ size = 14 }) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', minHeight: '1.2em' }}>
      <div style={{
        width: size, height: size, border: '2px solid rgba(255,255,255,0.3)',
        borderTop: '2px solid #fff', borderRadius: '50%',
        animation: 'spin 0.8s linear infinite', flexShrink: 0,
      }} />
      <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
    </span>
  )
}

function VendorLogo({ src, size = 24 }) {
  if (!src || (!src.startsWith('/') && !src.startsWith('http'))) {
    // Fallback: treat as emoji
    return <span style={{ fontSize: size * 0.85, lineHeight: 1 }}>{src || '🔌'}</span>
  }
  return <img src={src} alt="" style={{ width: size, height: size, borderRadius: 4, objectFit: 'contain' }} />
}

function SecretToggle({ show, onToggle }) {
  return (
    <button
      onClick={onToggle}
      style={{
        position: 'absolute', right: 8, top: '50%', transform: 'translateY(-50%)',
        background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 2,
      }}
    >
      {show ? <EyeOff size={14} /> : <Eye size={14} />}
    </button>
  )
}

// ── Shared styles ──
const inputStyle = {
  width: '100%', padding: '8px 12px', background: 'var(--bg)', border: '1px solid var(--border)',
  borderRadius: 8, color: 'var(--text)', fontSize: 13, boxSizing: 'border-box',
}
const selectStyle = { ...inputStyle, width: 'auto', minWidth: 80 }
const labelStyle = { fontSize: 12, color: 'var(--text-muted)', marginBottom: 4, display: 'block' }
const thStyle = { padding: '6px 8px', textAlign: 'left', fontSize: 11, color: 'var(--text-muted)', fontWeight: 600 }
const tdStyle = { padding: '6px 8px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 200 }
const pillButtonStyle = { padding: '4px 12px', borderRadius: 6, fontSize: 11, fontWeight: 600, cursor: 'pointer' }

function Badge({ bg, text, label }) {
  return <span style={{ background: bg, color: text, borderRadius: 4, padding: '2px 6px', fontSize: 10, fontWeight: 600 }}>{label}</span>
}

const DIRECTION_BADGE = {
  pull: { bg: '#1e3a5f', text: '#7dd3fc' },
  push: { bg: '#3b1f5e', text: '#d8b4fe' },
}
const ENTITY_BADGE = {
  asset: { bg: '#1a2e05', text: '#86efac' },
  finding: { bg: '#451a03', text: '#fcd34d' },
  action: { bg: '#1e3a5f', text: '#7dd3fc' },
  threat_cve: { bg: '#451a03', text: '#fcd34d' },
  threat_group: { bg: '#451a03', text: '#fcd34d' },
  threat_campaign: { bg: '#451a03', text: '#fcd34d' },
  exploit_reference: { bg: '#451a03', text: '#fcd34d' },
  cisa_advisory: { bg: '#451a03', text: '#fcd34d' },
  ttp: { bg: '#451a03', text: '#fcd34d' },
  product_lifecycle: { bg: '#451a03', text: '#fcd34d' },
  inventory_software: { bg: '#1e3a5f', text: '#7dd3fc' },
  sbom_component: { bg: '#3b1f5e', text: '#d8b4fe' },
}
const DEFAULT_ENTITY_BADGE = { bg: 'var(--border)', text: 'var(--text-muted)' }

function getNestedValue(obj, path) {
  if (!obj || !path) return null
  return path.split('.').reduce((curr, key) => curr?.[key], obj)
}
