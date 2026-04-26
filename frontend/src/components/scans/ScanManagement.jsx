import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { createPortal } from 'react-dom'
import { useNavigate } from 'react-router-dom'
import {
  Upload, CheckCircle, AlertCircle, FileText, X, Radar, Globe, Plus,
  RefreshCw, Trash2, Search, Clock, Server, Shield, Loader,
  Play, MonitorSmartphone, History, ChevronDown, ChevronUp, Edit2, Save,
  Square, Terminal, Key, Radio, ShieldAlert, Users, HardDrive, Database, Network, Cloud,
} from 'lucide-react'
import { useScan } from '../../App.jsx'
import useURLFilters from '../../hooks/useURLFilters.js'
import {
  uploadScan, deleteScan, cancelScan, getScanStatus, getEasmStatus, scanEasmDomain, rescanEasmScan, refreshEasmScan, setupEasm,
  getEasmScanRuns, startVmScan, refreshVmScan, rescanVmScan, getAssets, updateScanSchedule,
  getCredentials, createCredential, getRelayAgents,
  listAuditProtocols, startAuditRun, getBillingUsage,
  rescanAuditScan, updateAuditScan, getAuditScanHistory, getAgentRun,
} from '../../api.js'
import { Card, PageHeader, Button, Spinner, useConfirm, useToast } from '../shared/ui.jsx'
import { getAssetDisplayName, getAssetTarget } from '../../utils/assetDisplay.js'


// ── Source type metadata ─────────────────────────────────────────────

const SOURCE_TYPES = {
  nessus: { label: 'Nessus', icon: Shield, color: '#6366f1', bg: '#6366f122' },
  file_import: { label: 'File Import', icon: Upload, color: '#6366f1', bg: '#6366f122' },
  easm: { label: 'EASM', icon: Globe, color: '#0ea5e9', bg: '#0ea5e922' },
  qualys: { label: 'Qualys', icon: Shield, color: '#8b5cf6', bg: '#8b5cf622' },
  rapid7: { label: 'Rapid7', icon: Shield, color: '#f97316', bg: '#f9731622' },
  openvas: { label: 'OpenVAS', icon: Shield, color: '#22c55e', bg: '#22c55e22' },
  vm_scanner: { label: 'VM', icon: MonitorSmartphone, color: '#ec4899', bg: '#ec489922' },
  wmi_audit: { label: 'WMI Audit', icon: Terminal, color: '#14b8a6', bg: '#14b8a622' },
  // Future protocol audits land here as siblings: ldap_audit, smb_audit, etc.
}

function getSourceMeta(type) {
  return SOURCE_TYPES[type] || { label: type || 'Unknown', icon: FileText, color: '#71717a', bg: '#71717a22' }
}


// ── Source badge ──────────────────────────────────────────────────────

function SourceBadge({ sourceType }) {
  const meta = getSourceMeta(sourceType)
  const Icon = meta.icon
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 5,
      background: meta.bg, color: meta.color, border: `1px solid ${meta.color}44`,
      borderRadius: 5, padding: '2px 8px', fontSize: 11, fontWeight: 600,
      whiteSpace: 'nowrap',
    }}>
      <Icon size={12} />
      {meta.label}
    </span>
  )
}


// ── Drop zone ────────────────────────────────────────────────────────

function DropZone({ onFile, disabled }) {
  const [dragging, setDragging] = useState(false)
  const inputRef = useRef()

  const handleDrop = (e) => {
    e.preventDefault()
    setDragging(false)
    const file = e.dataTransfer.files[0]
    if (file) onFile(file)
  }

  return (
    <div
      onClick={() => !disabled && inputRef.current.click()}
      onDragOver={e => { e.preventDefault(); setDragging(true) }}
      onDragLeave={() => setDragging(false)}
      onDrop={handleDrop}
      style={{
        border: `2px dashed ${dragging ? 'var(--accent)' : 'var(--border)'}`,
        borderRadius: 12, padding: '32px 24px', textAlign: 'center',
        cursor: disabled ? 'default' : 'pointer',
        background: dragging ? 'rgba(99,102,241,0.05)' : 'transparent',
        transition: 'all 0.2s',
      }}
    >
      <Upload size={32} color={dragging ? '#6366f1' : 'var(--text-muted)'} style={{ marginBottom: 12 }} />
      <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 4 }}>
        {dragging ? 'Drop to upload' : 'Drop a scan file or click to browse'}
      </div>
      <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
        Nessus (.nessus, .html, .csv), Qualys, Rapid7 — auto-detected
      </div>
      <input
        ref={inputRef}
        type="file"
        accept=".html,.htm,.nessus,.csv,.xml"
        style={{ display: 'none' }}
        onChange={e => e.target.files[0] && onFile(e.target.files[0])}
      />
    </div>
  )
}


// ── Upload progress bar ──────────────────────────────────────────────

function UploadRow({ upload, onDismiss }) {
  const { file, status, result, error } = upload
  const borderColor = status === 'done' ? '#16a34a44' : status === 'error' ? '#dc262644' : 'var(--border)'
  const meta = getSourceMeta('nessus')

  return (
    <div style={{
      padding: '14px 16px', borderBottom: `1px solid ${borderColor}`,
      background: (status === 'uploading' || status === 'processing') ? 'rgba(99,102,241,0.03)' : status === 'error' ? 'rgba(220,38,38,0.03)' : 'rgba(22,163,106,0.03)',
    }}>
      <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
        <div style={{
          width: 36, height: 36, borderRadius: 8, flexShrink: 0,
          background: meta.bg, display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          {(status === 'uploading' || status === 'processing') && <Spinner size={18} />}
          {status === 'done' && <CheckCircle size={18} color="#16a34a" />}
          {status === 'error' && <AlertCircle size={18} color="#dc2626" />}
        </div>

        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3 }}>
            <span style={{ fontWeight: 600, fontSize: 14, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {file.name}
            </span>
            {(status === 'uploading' || status === 'processing') && (
              <span style={{
                display: 'inline-flex', alignItems: 'center', gap: 4,
                background: '#6366f118', color: '#6366f1', border: '1px solid #6366f144',
                borderRadius: 4, padding: '2px 8px', fontSize: 11, fontWeight: 600,
              }}>
                <Loader size={10} style={{ animation: 'spin 1.5s linear infinite' }} />
                {status === 'processing' ? 'Processing' : 'Importing'}
              </span>
            )}
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            {status === 'uploading' && 'Parsing & importing...'}
            {status === 'processing' && 'Processing scan data…'}
            {status === 'done' && result && (
              <span style={{ color: '#16a34a' }}>{result.assets} assets, {result.findings} findings imported</span>
            )}
            {status === 'error' && <span style={{ color: '#dc2626' }}>{error}</span>}
          </div>
        </div>

        <button onClick={onDismiss} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', flexShrink: 0, padding: 4 }}>
          <X size={14} />
        </button>
      </div>
      {(status === 'uploading' || status === 'processing') && <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>}
    </div>
  )
}


// ── New scan modal ───────────────────────────────────────────────────

// Per-protocol card visuals. Backend AUDITS registry is the source of truth
// for protocol + mission + tool palette; the frontend reframes the user-facing
// label around the *outcome* (what the audit reveals) rather than the wire
// protocol, since practitioners pick an audit by goal, not transport.
// New protocols fall back to the default ShieldAlert + teal until added here.
const AUDIT_CARD_META = {
  wmi:   { icon: Terminal,  color: '#14b8a6', label: 'Endpoint Audit (WMI)',          description: 'Inspect Windows host config' },
  ldap:  { icon: Users,     color: '#8b5cf6', label: 'Active Directory Audit (LDAP)', description: 'Query users, groups, domain' },
  smb:   { icon: HardDrive, color: '#f97316', label: 'Windows Share Audit (SMB)',     description: 'Inventory shares and exposure' },
  mssql: { icon: Database,  color: '#0284c7', label: 'Database Audit (MSSQL)',        description: 'Inspect SQL Server config' },
  snmp:  { icon: Network,   color: '#65a30d', label: 'Network Device Audit (SNMP)',   description: 'Query routers, switches, printers' },
  ssh:   { icon: Terminal,  color: '#14b8a6', label: 'Linux Audit (SSH)',             description: 'Inspect Linux host config' },
  aws:   { icon: Cloud,     color: '#f59e0b', label: 'AWS Cloud Audit',               description: 'IAM, exposure, posture' },
  azure: { icon: Cloud,     color: '#0284c7', label: 'Azure Cloud Audit',             description: 'IAM, exposure, posture' },
  gcp:   { icon: Cloud,     color: '#16a34a', label: 'GCP Cloud Audit',               description: 'IAM, exposure, posture' },
}

const CLOUD_PROTOCOLS = new Set(['aws', 'azure', 'gcp'])

function NewScanModal({ onClose, onFile, uploading, easmEnabled, onScanDomain, onSetupEasm, onVmScan, onAuditScan }) {
  const [mode, setMode] = useState(null)
  const [domain, setDomain] = useState('')
  const [scanType, setScanType] = useState('full')
  const [scanning, setScanning] = useState(false)
  const [error, setError] = useState(null)
  const [auditProtocols, setAuditProtocols] = useState([])   // flattened from /api/audits/protocols
  const cloudProtocols = useMemo(() => auditProtocols.filter(p => CLOUD_PROTOCOLS.has(p.protocol)), [auditProtocols])
  const hostProtocols  = useMemo(() => auditProtocols.filter(p => !CLOUD_PROTOCOLS.has(p.protocol)), [auditProtocols])

  // Load registered protocol audits so each gets its own top-level card.
  // Cards render immediately for EASM/VM/Import; audit cards append as the
  // list arrives (one round-trip, silently ignored on failure).
  useEffect(() => {
    let cancelled = false
    listAuditProtocols()
      .then(resp => {
        if (cancelled) return
        setAuditProtocols(resp?.audits || [])
      })
      .catch(() => { /* empty list — audit cards simply don't appear */ })
    return () => { cancelled = true }
  }, [])

  const handleScanDomain = async () => {
    if (!domain.trim()) return
    setScanning(true)
    setError(null)
    try {
      await onScanDomain(domain.trim(), scanType)
      onClose()
    } catch (err) {
      setError(err.message)
      setScanning(false)
    }
  }

  const handleSetup = async () => {
    if (!domain.trim()) return
    setScanning(true)
    setError(null)
    try {
      await onSetupEasm(domain.trim())
      onClose()
    } catch (err) {
      setError(err.message)
      setScanning(false)
    }
  }

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 200,
      background: 'rgba(0,0,0,0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center',
    }} onClick={e => { if (e.target === e.currentTarget) onClose() }}>
      <div style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)',
        borderRadius: 14, padding: 28, width: '100%', maxWidth: 520,
        boxShadow: '0 20px 60px rgba(0,0,0,0.3)',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
          <div style={{ fontWeight: 700, fontSize: 16 }}>New Scan</div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 4 }}>
            <X size={18} />
          </button>
        </div>

        {!mode && (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <SourceOption icon={Globe} label="External Surface" description={easmEnabled ? 'Discover internet-facing assets' : 'Set up EASM auditing'} color="#0ea5e9" onClick={() => setMode(easmEnabled ? 'easm' : 'easm-setup')} />
            <SourceOption icon={MonitorSmartphone} label="Network Scan" description="Vulnerability scan — auth optional" color="#ec4899" onClick={() => setMode('vm')} />
            {/* Protocol audits split by target: cloud providers vs. hosts /
                directory services. Some host audits (SMB anonymous shares,
                SNMP public community) don't require creds, so we avoid the
                "Credentialed" label at the top level. */}
            <SourceOption
              icon={Cloud}
              label="Cloud Posture"
              description={cloudProtocols.length ? `${cloudProtocols.length} providers` : 'AWS, Azure, GCP'}
              color="#0284c7"
              disabled={cloudProtocols.length === 0}
              disabledMessage="No cloud audits registered"
              onClick={() => setMode('cloud-picker')}
            />
            <SourceOption
              icon={Key}
              label="Host & Directory Audit"
              description={hostProtocols.length ? `${hostProtocols.length} protocols` : 'WMI, SSH, SMB, LDAP, SNMP'}
              color="#14b8a6"
              disabled={hostProtocols.length === 0}
              disabledMessage="No host audits registered"
              onClick={() => setMode('host-picker')}
            />
            <SourceOption icon={Upload} label="Import File" description="Nessus XML, HTML, CSV" color="#6366f1" onClick={() => setMode('upload')} />
          </div>
        )}

        {(mode === 'cloud-picker' || mode === 'host-picker') && (
          <div>
            <BackButton onClick={() => setMode(null)} />
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 12 }}>
              {mode === 'cloud-picker'
                ? 'Pick a cloud provider to audit.'
                : 'Pick a protocol to audit. Some support unauthenticated discovery; others require credentials.'}
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              {(mode === 'cloud-picker' ? cloudProtocols : hostProtocols).map(p => {
                const meta = AUDIT_CARD_META[p.protocol] || { icon: ShieldAlert, color: '#14b8a6' }
                return (
                  <SourceOption
                    key={p.protocol}
                    icon={meta.icon}
                    label={meta.label || p.label}
                    description={meta.description || 'Protocol ReAct audit'}
                    color={meta.color}
                    onClick={() => setMode(`audit:${p.protocol}`)}
                  />
                )
              })}
            </div>
          </div>
        )}

        {mode === 'upload' && (
          <div>
            <BackButton onClick={() => setMode(null)} />
            <DropZone onFile={(file) => { onFile(file); onClose() }} disabled={uploading} />
            <div style={{ marginTop: 12, fontSize: 12, color: 'var(--text-muted)', padding: '8px 10px', background: 'var(--bg-secondary)', borderRadius: 8 }}>
              Supported: .nessus (XML), .html (Nessus export), .csv — auto-detected
            </div>
          </div>
        )}

        {mode === 'easm-setup' && (
          <div>
            <BackButton onClick={() => setMode(null)} />
            <div style={{
              padding: '14px 16px', borderRadius: 8, marginBottom: 16,
              background: '#0ea5e908', border: '1px solid #0ea5e922',
            }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 4 }}>Set up External Attack Surface Monitoring</div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                Enter your primary domain to start discovering internet-facing assets.
              </div>
            </div>
            <div style={{ marginBottom: 16 }}>
              <label style={{ fontSize: 12, fontWeight: 600, display: 'block', marginBottom: 6, color: 'var(--text-muted)' }}>
                Domain
              </label>
              <input
                value={domain}
                onChange={e => setDomain(e.target.value)}
                placeholder="yourdomain.com"
                onKeyDown={e => e.key === 'Enter' && handleSetup()}
                autoFocus
                style={{
                  width: '100%', padding: '10px 12px', borderRadius: 8,
                  border: '1px solid var(--border)', background: 'var(--bg)',
                  color: 'var(--text-primary)', fontSize: 14, boxSizing: 'border-box',
                }}
              />
            </div>
            {error && (
              <div style={{ fontSize: 12, color: '#dc2626', marginBottom: 12, padding: '8px 10px', background: '#dc262611', borderRadius: 6 }}>
                {error}
              </div>
            )}
            <Button onClick={handleSetup} disabled={scanning || !domain.trim()} style={{ width: '100%', background: '#0ea5e9' }}>
              {scanning ? 'Setting up...' : 'Enable EASM & Start Discovery'}
            </Button>
          </div>
        )}

        {mode === 'vm' && (
          <VmScannerPanel
            onClose={onClose}
            onBack={() => setMode(null)}
            onVmScan={onVmScan}
          />
        )}

        {typeof mode === 'string' && mode.startsWith('audit:') && (() => {
          const proto = mode.slice('audit:'.length)
          const backMode = CLOUD_PROTOCOLS.has(proto) ? 'cloud-picker' : 'host-picker'
          return (
            <AuditScanPanel
              onClose={onClose}
              onBack={() => setMode(backMode)}
              onAuditScan={onAuditScan}
              preselectedProtocol={proto}
              availableProtocols={auditProtocols}
            />
          )
        })()}

        {mode === 'easm' && (
          <div>
            <BackButton onClick={() => setMode(null)} />

            {/* Domain input */}
            <div style={{ marginBottom: 16 }}>
              <label style={{ fontSize: 12, fontWeight: 600, display: 'block', marginBottom: 6, color: 'var(--text-muted)' }}>
                Domain to scan
              </label>
              <input
                value={domain}
                onChange={e => setDomain(e.target.value)}
                placeholder="example.com"
                onKeyDown={e => e.key === 'Enter' && handleScanDomain()}
                autoFocus
                style={{
                  width: '100%', padding: '10px 12px', borderRadius: 8,
                  border: '1px solid var(--border)', background: 'var(--bg)',
                  color: 'var(--text-primary)', fontSize: 14, boxSizing: 'border-box',
                }}
              />
            </div>

            {/* Scan type */}
            <div style={{ marginBottom: 16 }}>
              <label style={{ fontSize: 12, fontWeight: 600, display: 'block', marginBottom: 6, color: 'var(--text-muted)' }}>Scan Type</label>
              <div style={{ display: 'flex', gap: 8 }}>
                {['full', 'discovery', 'enrichment'].map(t => (
                  <button
                    key={t}
                    onClick={() => setScanType(t)}
                    style={{
                      flex: 1, padding: '10px 12px', borderRadius: 8,
                      border: `1px solid ${scanType === t ? '#0ea5e9' : 'var(--border)'}`,
                      background: scanType === t ? '#0ea5e922' : 'transparent',
                      color: scanType === t ? '#0ea5e9' : 'var(--text-secondary)',
                      cursor: 'pointer', fontSize: 13, fontWeight: 600,
                      textTransform: 'capitalize',
                    }}
                  >
                    {t}
                  </button>
                ))}
              </div>
            </div>

            {error && (
              <div style={{ fontSize: 12, color: '#dc2626', marginBottom: 12, padding: '8px 10px', background: '#dc262611', borderRadius: 6 }}>
                {error}
              </div>
            )}

            <Button onClick={handleScanDomain} disabled={scanning || !domain.trim()} style={{ width: '100%', background: '#0ea5e9' }}>
              {scanning ? (
                <><RefreshCw size={13} style={{ animation: 'spin 1s linear infinite' }} /> Scanning...</>
              ) : (
                <><Play size={13} /> Scan Domain</>
              )}
            </Button>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 8, textAlign: 'center' }}>
              Adds the domain, triggers a scan, and imports results.
            </div>
            <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
          </div>
        )}
      </div>
    </div>
  )
}

const PAGE_SIZE = 50

function VmScannerPanel({ onClose, onBack, onVmScan }) {
  const [tab, setTab] = useState('manual') // 'manual' | 'assets'
  const [assets, setAssets] = useState([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [loadingMore, setLoadingMore] = useState(false)
  // selectedAssets: Map<id, assetObj> — persists selection across pages/searches
  const [selectedAssets, setSelectedAssets] = useState(new Map())
  const [assetSearch, setAssetSearch] = useState('')
  const [debouncedSearch, setDebouncedSearch] = useState('')
  const [scanning, setScanning] = useState(false)
  const [error, setError] = useState(null)
  const [manualTarget, setManualTarget] = useState('')
  const [authProfiles, setAuthProfiles] = useState([])
  const [authProfileId, setAuthProfileId] = useState('')
  // Specialist LLM agents — on by default for VM scans. Users can untick
  // per-scan if they want to skip the LLM cost.
  // `agentCategories === null` means "run all seven"; setting it narrows
  // the dispatch to the chosen subset. Matches the scanner API contract.
  const AGENT_CATEGORIES = ['injection', 'xss', 'ssrf', 'authn', 'authz', 'csrf', 'files']
  const [enableAgents, setEnableAgents] = useState(true)
  const [agentCategories, setAgentCategories] = useState(null)

  const toggleAgentCategory = (cat) => {
    setAgentCategories(prev => {
      const current = prev || [...AGENT_CATEGORIES]
      return current.includes(cat)
        ? current.filter(c => c !== cat)
        : [...current, cat]
    })
  }

  useEffect(() => {
    import('../../api.js').then(api => api.listAuthProfiles())
      .then(rows => setAuthProfiles(Array.isArray(rows) ? rows : []))
      .catch(() => setAuthProfiles([]))
  }, [])

  // Debounce search input
  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(assetSearch), 300)
    return () => clearTimeout(t)
  }, [assetSearch])

  // Fetch first page when tab opens or search changes
  useEffect(() => {
    if (tab !== 'assets') return
    setLoading(true)
    setPage(1)
    getAssets({ page: 1, page_size: PAGE_SIZE, search: debouncedSearch || undefined })
      .then(data => {
        const list = Array.isArray(data) ? data : data?.assets || []
        const tot = data?.total ?? list.length
        setAssets(list)
        setTotal(tot)
      })
      .catch(err => setError(err.message))
      .finally(() => setLoading(false))
  }, [tab, debouncedSearch])

  const loadMore = () => {
    const nextPage = page + 1
    setLoadingMore(true)
    getAssets({ page: nextPage, page_size: PAGE_SIZE, search: debouncedSearch || undefined })
      .then(data => {
        const list = Array.isArray(data) ? data : data?.assets || []
        setAssets(prev => [...prev, ...list])
        setPage(nextPage)
      })
      .catch(err => setError(err.message))
      .finally(() => setLoadingMore(false))
  }

  const hasMore = assets.length < total

  const allSelected = assets.length > 0 && assets.every(a => selectedAssets.has(a.id))

  const toggleAll = () => {
    setSelectedAssets(prev => {
      const next = new Map(prev)
      if (allSelected) {
        assets.forEach(a => next.delete(a.id))
      } else {
        assets.forEach(a => next.set(a.id, a))
      }
      return next
    })
  }

  const toggle = (asset) => {
    setSelectedAssets(prev => {
      const next = new Map(prev)
      if (next.has(asset.id)) next.delete(asset.id)
      else next.set(asset.id, asset)
      return next
    })
  }

  const handleScan = async () => {
    setScanning(true)
    setError(null)
    try {
      let payload
      if (tab === 'manual') {
        const targets = manualTarget.split(/[,\n]+/).map(t => t.trim()).filter(Boolean)
        if (targets.length === 0) return
        payload = { targets }
      } else {
        if (selectedAssets.size === 0) return
        // Send asset_ids + targets so backend can link findings to existing assets
        const assetEntries = [...selectedAssets.values()].map(a => ({
          asset_id: a.id,
          target: getAssetTarget(a),
        })).filter(e => e.target)
        if (assetEntries.length === 0) { setError('Selected assets have no IP or hostname'); return }
        payload = {
          targets: assetEntries.map(e => e.target),
          asset_ids: assetEntries.map(e => e.asset_id),
        }
      }
      if (authProfileId) payload.auth_profile_id = authProfileId
      if (enableAgents) {
        payload.enable_agents = true
        // Omit the field entirely when all five are selected — lets the
        // scanner use its own default (every category, self-gated).
        if (agentCategories && agentCategories.length && agentCategories.length < AGENT_CATEGORIES.length) {
          payload.agent_categories = agentCategories
        }
      }
      const res = await startVmScan(payload)
      // No confirmation UI — parent navigates to the live findings view and
      // the panel unmounts. See handleNewVmScan in ScanManagement.
      if (onVmScan) onVmScan(res)
    } catch (err) {
      setError(err.message)
    } finally {
      setScanning(false)
    }
  }

  const manualTargets = manualTarget.split(/[,\n]+/).map(t => t.trim()).filter(Boolean)
  // Preview how many host targets the backend will actually dispatch once
  // CIDR subnets are expanded. Cap mirrors the backend cap so the preview
  // can't spiral past what the server would accept.
  const CIDR_PREVIEW_CAP = 1024
  const expandedTargetCount = (() => {
    let total = 0
    for (const t of manualTargets) {
      const m = t.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/)
      if (m) {
        const prefix = parseInt(m[2], 10)
        if (prefix >= 0 && prefix <= 32) {
          total += prefix >= 31 ? 1 : Math.pow(2, 32 - prefix) - 2
          continue
        }
      }
      total += 1
    }
    return total
  })()
  const targetCountExceedsCap = expandedTargetCount > CIDR_PREVIEW_CAP
  const canScan = tab === 'manual'
    ? manualTargets.length > 0 && !targetCountExceedsCap
    : selectedAssets.size > 0

  const tabStyle = (active) => ({
    flex: 1, padding: '8px 0', fontSize: 12, fontWeight: 600,
    background: 'none', border: 'none', cursor: 'pointer',
    borderBottom: `2px solid ${active ? '#ec4899' : 'transparent'}`,
    color: active ? '#ec4899' : 'var(--text-muted)',
  })

  // Once the scan is queued, the parent handler navigates to the live
  // findings view and closes this panel — we don't block the user on a
  // confirmation modal. Findings stream in per-target, so showing the
  // explorer filtered by scan_id is where they want to be anyway.

  return (
    <div>
      <BackButton onClick={onBack} />

      <div style={{
        padding: '12px 14px', borderRadius: 8, marginBottom: 14,
        background: '#ec489908', border: '1px solid #ec489922',
      }}>
        <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 3 }}>Vulnerability Scanner</div>
        <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
          Run against targets. Provide IPs/hostnames or select from existing assets.
        </div>
      </div>

      {/* Tab switcher */}
      <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', marginBottom: 14 }}>
        <button style={tabStyle(tab === 'manual')} onClick={() => setTab('manual')}>Enter Target</button>
        <button style={tabStyle(tab === 'assets')} onClick={() => setTab('assets')}>Select Assets</button>
      </div>

      {/* Manual target input */}
      {tab === 'manual' && (
        <div>
          <label style={{ fontSize: 12, fontWeight: 600, display: 'block', marginBottom: 6, color: 'var(--text-muted)' }}>
            Target(s) — IP, hostname, or URL
          </label>
          <textarea
            value={manualTarget}
            onChange={e => setManualTarget(e.target.value)}
            placeholder={'192.168.1.1\nexample.com\nhttps://app.example.com'}
            rows={4}
            autoFocus
            style={{
              width: '100%', padding: '10px 12px', borderRadius: 8,
              border: '1px solid var(--border)', background: 'var(--bg)',
              color: 'var(--text-primary)', fontSize: 13, fontFamily: 'monospace',
              boxSizing: 'border-box', resize: 'vertical',
            }}
          />
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4, marginBottom: 14 }}>
            One target per line, or comma-separated. CIDR subnets (e.g. 192.168.1.0/24) expand to individual hosts.
            {manualTargets.length > 0 && (
              <> {expandedTargetCount !== manualTargets.length
                ? `${manualTargets.length} entr${manualTargets.length !== 1 ? 'ies' : 'y'} → ${expandedTargetCount} host${expandedTargetCount !== 1 ? 's' : ''} after expansion.`
                : `${manualTargets.length} target${manualTargets.length !== 1 ? 's' : ''} detected.`}</>
            )}
            {targetCountExceedsCap && (
              <div style={{ color: '#dc2626', marginTop: 4, fontWeight: 600 }}>
                Expansion exceeds the {CIDR_PREVIEW_CAP}-host cap. Narrow your subnet.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Asset selection */}
      {tab === 'assets' && (
        <div>
          <input
            value={assetSearch}
            onChange={e => setAssetSearch(e.target.value)}
            placeholder="Search assets..."
            style={{
              width: '100%', padding: '8px 10px', borderRadius: 6,
              border: '1px solid var(--border)', background: 'var(--bg)',
              color: 'var(--text-primary)', fontSize: 12, marginBottom: 8,
              boxSizing: 'border-box',
            }}
          />

          {loading && (
            <div style={{ textAlign: 'center', padding: 20, color: 'var(--text-muted)', fontSize: 13 }}>
              <Loader size={16} style={{ animation: 'spin 1.5s linear infinite', marginRight: 6, verticalAlign: -3 }} />
              Loading assets...
              <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
            </div>
          )}

          {!loading && assets.length === 0 && (
            <div style={{ textAlign: 'center', padding: 20, color: 'var(--text-muted)', fontSize: 13 }}>
              {debouncedSearch ? 'No assets match your search.' : 'No assets found. Upload a scan or run an EASM scan first, or use "Enter Target" to scan directly.'}
            </div>
          )}

          {!loading && assets.length > 0 && (
            <>
              <div style={{
                display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8,
                padding: '6px 0', borderBottom: '1px solid var(--border)',
              }}>
                <input type="checkbox" checked={allSelected} onChange={toggleAll}
                  style={{ accentColor: '#ec4899' }} />
                <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)' }}>
                  {selectedAssets.size} of {total} selected
                </span>
              </div>

              <div style={{ maxHeight: 220, overflowY: 'auto', marginBottom: 8 }}>
                {assets.map(asset => (
                  <label key={asset.id} style={{
                    display: 'flex', alignItems: 'center', gap: 10,
                    padding: '7px 4px', cursor: 'pointer', fontSize: 13,
                    borderRadius: 5,
                  }}
                    onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-secondary)'}
                    onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                  >
                    <input type="checkbox" checked={selectedAssets.has(asset.id)} onChange={() => toggle(asset)}
                      style={{ accentColor: '#ec4899' }} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {getAssetDisplayName(asset)}
                      </div>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)', display: 'flex', gap: 8 }}>
                        {asset.ip && <span>{asset.ip}</span>}
                        {asset.fqdn && asset.fqdn !== asset.hostname && <span>{asset.fqdn}</span>}
                      </div>
                    </div>
                  </label>
                ))}

                {hasMore && (
                  <button
                    onClick={loadMore}
                    disabled={loadingMore}
                    style={{
                      width: '100%', padding: '7px 0', marginTop: 4,
                      background: 'none', border: '1px dashed var(--border)',
                      borderRadius: 5, cursor: loadingMore ? 'default' : 'pointer',
                      fontSize: 12, color: 'var(--text-muted)',
                    }}
                  >
                    {loadingMore
                      ? 'Loading...'
                      : `Load more (${total - assets.length} remaining)`}
                  </button>
                )}
              </div>
            </>
          )}
        </div>
      )}

      {authProfiles.length > 0 && (
        <div style={{ marginBottom: 12 }}>
          <label style={{ fontSize: 11, fontWeight: 600, display: 'block', marginBottom: 4, color: 'var(--text-muted)' }}>
            Auth profile (optional)
          </label>
          <select
            value={authProfileId}
            onChange={e => setAuthProfileId(e.target.value)}
            style={{
              width: '100%', padding: '7px 10px', fontSize: 12,
              background: 'var(--bg-card)', color: 'var(--text-primary)',
              border: '1px solid var(--border)', borderRadius: 6,
            }}
          >
            <option value="">None — unauthenticated scan</option>
            {authProfiles.map(p => (
              <option key={p.id} value={p.id}>{p.name}</option>
            ))}
          </select>
        </div>
      )}

      {/* Specialist LLM agents — opt-in per scan. Uses the same LLM
          provider the backend resolves (Vertex on GCP via ADC).
          Agents need asset context (asset_endpoints) so they self-gate
          when run against manual targets with no prior discovery. */}
      <div style={{
        marginBottom: 12, padding: '10px 12px', borderRadius: 8,
        background: 'var(--bg-secondary)', border: '1px solid var(--border)',
      }}>
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
          <input
            type="checkbox"
            checked={enableAgents}
            onChange={e => setEnableAgents(e.target.checked)}
          />
          <span style={{ fontSize: 12, fontWeight: 600 }}>Run specialist agents (LLM)</span>
        </label>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4, marginLeft: 22 }}>
          Runs five LLM specialists (Injection, XSS, SSRF, AuthN, AuthZ) per asset.
          Cost: LLM tokens. Best on assets with discovered endpoints.
        </div>
        {enableAgents && (
          <div style={{ marginTop: 10, marginLeft: 22, display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {AGENT_CATEGORIES.map(cat => {
              const selected = !agentCategories || agentCategories.includes(cat)
              return (
                <button
                  key={cat}
                  onClick={() => toggleAgentCategory(cat)}
                  style={{
                    fontSize: 11, padding: '3px 10px', borderRadius: 12, cursor: 'pointer',
                    background: selected ? '#ec489922' : 'transparent',
                    border: `1px solid ${selected ? '#ec4899' : 'var(--border)'}`,
                    color: selected ? '#ec4899' : 'var(--text-muted)',
                    fontWeight: 600,
                  }}
                >
                  {cat}
                </button>
              )
            })}
          </div>
        )}
      </div>

      {error && (
        <div style={{ fontSize: 12, color: '#dc2626', marginBottom: 12, padding: '8px 10px', background: '#dc262611', borderRadius: 6 }}>
          {error}
        </div>
      )}

      <Button onClick={handleScan} disabled={scanning || !canScan} style={{ width: '100%', background: '#ec4899' }}>
        {scanning ? (
          <><RefreshCw size={13} style={{ animation: 'spin 1s linear infinite' }} /> Scanning...</>
        ) : (
          <><Play size={13} /> Scan {tab === 'manual' ? `${expandedTargetCount} Target${expandedTargetCount !== 1 ? 's' : ''}` : `${selectedAssets.size} Asset${selectedAssets.size !== 1 ? 's' : ''}`}</>
        )}
      </Button>
      <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
    </div>
  )
}


// ── Authenticated Audit panel (protocol-scoped ReAct) ────────────────
//
// One panel serves every registered protocol audit (currently WMI; LDAP/SMB/
// Kerberos/SNMP/WinRM land as siblings). The protocol + mission catalog is
// read from /api/audits/protocols so new protocols appear automatically when
// they're registered on the backend.
//
// UX flow:
//   1. Protocol dropdown (one entry per AUDITS registration)
//   2. Mission dropdown (populates from chosen protocol's missions)
//   3. Credential + relay pickers (filtered by the protocol's requirements)
//   4. Asset picker (multi-select)
//   5. Budget editors (max_steps, wallclock_s) pre-filled from the mission
//   6. Rough cost estimate ($ per host × host count)
//   7. Start → scan row + background agent runs

function AuditScanPanel({
  onClose, onBack, onAuditScan, preselectedProtocol, availableProtocols,
  // Edit mode — when set, the panel hydrates from the scan's raw_metadata,
  // locks the protocol (can't change protocol of an existing audit row), and
  // swaps the submit handler: "Save & rerun" hits /rescan, "Save (no rerun)"
  // hits PATCH /scans/{id}. Same UX as NewScan so users don't learn two forms.
  editScan,
}) {
  const md = editScan?.raw_metadata || {}
  const editProtocol = editScan ? (md.protocol || (editScan.scan_type || '').replace('_audit', '')) : null
  // When this panel is invoked as the edit form, the preselectedProtocol is
  // implicit (from the scan itself) and the protocol selector is hidden.
  const effectivePreselected = editProtocol || preselectedProtocol
  const [protocols, setProtocols] = useState(availableProtocols || [])
  const [selectedProtocol, setSelectedProtocol] = useState(effectivePreselected || '')
  const [selectedMission, setSelectedMission] = useState(editScan ? (md.mission || '') : '')
  const [loadingPrereqs, setLoadingPrereqs] = useState(true)

  const [credentials, setCredentials] = useState([])
  const [relayAgents, setRelayAgents] = useState([])
  const [credentialId, setCredentialId] = useState(editScan ? (md.credential_id || '') : '')
  const [relayAgentId, setRelayAgentId] = useState(editScan ? (md.relay_agent_id || '') : '')
  const [showCreateCred, setShowCreateCred] = useState(false)

  // Target source — mirrors VM scanner UX. 'manual' lets the user type
  // free-form IPs/hostnames/CIDRs; 'assets' picks from the asset inventory.
  // Pre-pick the correct tab on edit: if the original scan used ad-hoc targets
  // we land on 'manual' with the targets pre-filled; otherwise we start on
  // 'assets' with the existing asset_ids pre-selected (seeded below once the
  // asset list loads).
  const editAdHocTargets = Array.isArray(md.ad_hoc_targets) ? md.ad_hoc_targets : []
  const editAssetIds = Array.isArray(md.asset_ids) ? md.asset_ids : []
  const [tab, setTab] = useState(editScan
    ? (editAdHocTargets.length ? 'manual' : 'assets')
    : 'assets')
  const [manualTarget, setManualTarget] = useState(editScan ? editAdHocTargets.join('\n') : '')

  const [assets, setAssets] = useState([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [loadingMore, setLoadingMore] = useState(false)
  const [selectedAssets, setSelectedAssets] = useState(new Map())
  const [assetSearch, setAssetSearch] = useState('')
  const [debouncedSearch, setDebouncedSearch] = useState('')

  const [maxSteps, setMaxSteps] = useState(editScan && md.max_steps ? md.max_steps : 20)
  const [wallclockS, setWallclockS] = useState(editScan && md.wallclock_s ? md.wallclock_s : 600)

  const [usage, setUsage] = useState(null)     // {used, limit, percentage, warning, exceeded, tier}

  const [scanning, setScanning] = useState(false)
  const [error, setError] = useState(null)

  // Refetch credentials — call on dropdown focus so creds created elsewhere
  // (Settings → Credentials, another tab) show up without
  // needing to close and reopen the scan modal.
  const refreshCredentials = () => {
    getCredentials()
      .then(rows => setCredentials(Array.isArray(rows) ? rows : []))
      .catch(() => {})
  }

  // ── Load protocols (if not passed in) + credentials + relays + token usage ──
  useEffect(() => {
    let cancelled = false
    async function loadPrereqs() {
      try {
        // Protocols come from the parent modal when preselectedProtocol was used.
        const protoPromise = protocols.length > 0
          ? Promise.resolve({ audits: protocols })
          : listAuditProtocols().catch(() => ({ audits: [] }))
        const [protoResp, creds, relays, usageResp] = await Promise.all([
          protoPromise,
          getCredentials().catch(() => []),
          getRelayAgents().catch(() => ({ items: [] })),
          getBillingUsage().catch(() => null),
        ])
        if (cancelled) return
        const audits = protoResp?.audits || []
        setProtocols(audits)
        // Preselect mission: prefer first mission of the (possibly preselected) protocol,
        // else first mission of the first protocol.
        const activeProto = audits.find(p => p.protocol === selectedProtocol) || audits[0]
        if (activeProto) {
          if (!selectedProtocol) setSelectedProtocol(activeProto.protocol)
          if (activeProto.missions?.length && !selectedMission) {
            setSelectedMission(activeProto.missions[0].key)
          }
        }
        setCredentials(Array.isArray(creds) ? creds : [])
        const connected = (relays?.items || relays || []).filter(r => r.is_connected || r.status === 'connected')
        setRelayAgents(connected)
        if (connected.length === 1) setRelayAgentId(connected[0].id)
        setUsage(usageResp || null)
      } finally {
        if (!cancelled) setLoadingPrereqs(false)
      }
    }
    loadPrereqs()
    return () => { cancelled = true }
  }, [])   // eslint-disable-line react-hooks/exhaustive-deps

  // Current protocol + mission objects from the catalog
  const currentProtocol = protocols.find(p => p.protocol === selectedProtocol)
  const currentMission = currentProtocol?.missions?.find(m => m.key === selectedMission)

  // Filter credentials by the protocol's allowed connector_ids
  const eligibleCredentials = currentProtocol
    ? credentials.filter(c => (currentProtocol.credential_connector_ids || []).includes(c.connector_id))
    : credentials

  // Reset mission + credential when the protocol changes so stale selections don't leak
  useEffect(() => {
    if (!currentProtocol) return
    if (currentProtocol.missions?.length && !currentProtocol.missions.find(m => m.key === selectedMission)) {
      setSelectedMission(currentProtocol.missions[0].key)
    }
    if (credentialId && !eligibleCredentials.find(c => c.id === credentialId)) {
      setCredentialId('')
    }
  }, [selectedProtocol]) // eslint-disable-line react-hooks/exhaustive-deps

  // Pre-fill max_steps from the mission's suggested_budget
  useEffect(() => {
    if (currentMission?.suggested_budget) {
      setMaxSteps(currentMission.suggested_budget)
    }
  }, [currentMission])

  // Debounce asset search
  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(assetSearch), 300)
    return () => clearTimeout(t)
  }, [assetSearch])

  // First page of assets (+ when search changes)
  useEffect(() => {
    setLoading(true)
    setPage(1)
    getAssets({ page: 1, page_size: PAGE_SIZE, search: debouncedSearch || undefined })
      .then(data => {
        const list = Array.isArray(data) ? data : data?.assets || []
        const tot = data?.total ?? list.length
        setAssets(list)
        setTotal(tot)
        // Edit mode: pre-check the scan's existing asset_ids so the user sees
        // the current selection. We seed on every page load rather than once
        // because the picker is paginated — if the original asset isn't on
        // page 1, the seed becomes a no-op until they scroll into it.
        if (editScan && editAssetIds.length > 0) {
          const present = list.filter(a => editAssetIds.includes(a.id))
          if (present.length > 0) {
            setSelectedAssets(prev => {
              const next = new Map(prev)
              present.forEach(a => { if (!next.has(a.id)) next.set(a.id, a) })
              return next
            })
          }
        }
      })
      .catch(err => setError(err.message))
      .finally(() => setLoading(false))
  }, [debouncedSearch])

  const loadMore = () => {
    const nextPage = page + 1
    setLoadingMore(true)
    getAssets({ page: nextPage, page_size: PAGE_SIZE, search: debouncedSearch || undefined })
      .then(data => {
        const list = Array.isArray(data) ? data : data?.assets || []
        setAssets(prev => [...prev, ...list])
        setPage(nextPage)
      })
      .catch(err => setError(err.message))
      .finally(() => setLoadingMore(false))
  }

  const hasMore = assets.length < total
  const allSelected = assets.length > 0 && assets.every(a => selectedAssets.has(a.id))

  const toggleAll = () => {
    setSelectedAssets(prev => {
      const next = new Map(prev)
      if (allSelected) assets.forEach(a => next.delete(a.id))
      else assets.forEach(a => next.set(a.id, a))
      return next
    })
  }
  const toggle = (asset) => {
    setSelectedAssets(prev => {
      const next = new Map(prev)
      if (next.has(asset.id)) next.delete(asset.id)
      else next.set(asset.id, asset)
      return next
    })
  }

  // Manual target parsing + CIDR expansion preview. Mirrors the VM scan
  // panel so users get the same count feedback before dispatch. Cap (64)
  // matches AUDIT_MAX_EXPANDED_HOSTS on the backend — the button disables
  // when exceeded instead of bouncing off a 400.
  const AUDIT_CIDR_PREVIEW_CAP = 64
  const manualTargets = manualTarget.split(/[,\n]+/).map(t => t.trim()).filter(Boolean)
  const expandedManualCount = (() => {
    let total = 0
    for (const t of manualTargets) {
      const m = t.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/)
      if (m) {
        const prefix = parseInt(m[2], 10)
        if (prefix >= 0 && prefix <= 32) {
          total += prefix >= 31 ? 1 : Math.pow(2, 32 - prefix) - 2
          continue
        }
      }
      total += 1
    }
    return total
  })()
  const manualCountExceedsCap = expandedManualCount > AUDIT_CIDR_PREVIEW_CAP

  // Host count drives cost + the button label — switches on the active tab.
  const hostCount = tab === 'manual' ? expandedManualCount : selectedAssets.size

  // Rough cost estimate — pennies-level order of magnitude, not billing-grade.
  // Calibrated to claude-sonnet-4-6 at ~15k tokens per host for a medium audit.
  const { costPerHostUSD, tokensPerHost } = useMemo(() => {
    if (!currentMission) return { costPerHostUSD: 0, tokensPerHost: 0 }
    const hint = currentMission.cost_hint || 'medium'
    const usd = { low: 0.05, medium: 0.12, high: 0.25 }[hint] ?? 0.12
    const tokens = { low: 6_000, medium: 15_000, high: 30_000 }[hint] ?? 15_000
    return { costPerHostUSD: usd, tokensPerHost: tokens }
  }, [currentMission])
  const estimatedCost = costPerHostUSD * hostCount
  const estimatedTokens = tokensPerHost * hostCount

  // Quota-based warnings — would this audit push us over the monthly limit?
  const quotaRemaining = usage ? Math.max(0, (usage.limit || 0) - (usage.used || 0)) : null
  const quotaExhausted = usage?.exceeded
  const quotaWouldExceed = quotaRemaining !== null && estimatedTokens > quotaRemaining
  const quotaWouldWarn = !quotaWouldExceed && usage && !usage.exceeded
    && quotaRemaining !== null && (estimatedTokens + (usage.used || 0)) / (usage.limit || 1) > 0.8

  const hasTargetSource = tab === 'manual'
    ? (manualTargets.length > 0 && !manualCountExceedsCap)
    : selectedAssets.size > 0
  // Protocols whose missions can run without a credential (SMB null sessions,
  // SNMP default-community sweeps).
  // Must match backend/services/audit_runner.py::_ANON_CAPABLE_PROTOCOLS.
  const credentialOptional = selectedProtocol === 'smb' || selectedProtocol === 'snmp'
  const canStart = !!selectedProtocol && !!selectedMission
    && (credentialOptional || !!credentialId)
    && !!relayAgentId && hasTargetSource && !scanning && !quotaExhausted

  const handleCreateCredential = async (data) => {
    try {
      const connector_id = currentProtocol?.credential_connector_ids?.[0] || 'windows_host'
      const auth_type = 'basic'
      const created = await createCredential({ ...data, connector_id, auth_type })
      setCredentials(prev => [...prev, {
        id: created.id, name: created.name, connector_id, auth_type,
      }])
      setCredentialId(created.id)
      setShowCreateCred(false)
    } catch (err) {
      setError(err.message)
    }
  }

  const _buildPayload = () => {
    const payload = {
      protocol: selectedProtocol,
      mission: selectedMission,
      credential_id: credentialId || null,
      relay_agent_id: relayAgentId,
      max_steps: maxSteps,
      wallclock_s: wallclockS,
    }
    if (tab === 'manual') {
      payload.targets = manualTargets
    } else {
      payload.asset_ids = Array.from(selectedAssets.keys())
    }
    return payload
  }

  const handleStart = async () => {
    if (!canStart) return
    setScanning(true)
    setError(null)
    try {
      const payload = _buildPayload()
      // Three dispatch paths, same payload shape:
      //   - new scan           → POST /audits/run          (startAuditRun)
      //   - edit + rerun       → POST /audits/scans/.../rescan  (rescanAuditScan)
      //   - edit, save only    → PATCH /audits/scans/{id}  (updateAuditScan)
      let res
      if (editScan) {
        res = await rescanAuditScan(editScan.id, payload)
      } else {
        res = await startAuditRun(payload)
      }
      if (onAuditScan) onAuditScan(res)
      onClose()
    } catch (err) {
      setError(err.message)
      setScanning(false)
    }
  }

  const handleSaveOnly = async () => {
    // Edit-only path: don't fire a run now, just persist the defaults the
    // schedule (and the next manual rescan) will use. Targets + asset_ids
    // are mutually exclusive on the backend; drop the empty one.
    if (!editScan) return
    setScanning(true)
    setError(null)
    try {
      const payload = _buildPayload()
      if (!payload.targets?.length) delete payload.targets
      if (!payload.asset_ids?.length) delete payload.asset_ids
      await updateAuditScan(editScan.id, payload)
      if (onAuditScan) onAuditScan({ saved: true })
      onClose()
    } catch (err) {
      setError(err.message)
      setScanning(false)
    }
  }

  if (loadingPrereqs) {
    return (
      <div>
        <BackButton onClick={onBack} />
        <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-muted)' }}>
          <Spinner /> Loading audit configuration…
        </div>
      </div>
    )
  }

  if (protocols.length === 0) {
    return (
      <div>
        <BackButton onClick={onBack} />
        <div style={{ padding: 16, background: 'var(--bg-secondary)', borderRadius: 8, fontSize: 13, color: 'var(--text-muted)' }}>
          No authenticated audit protocols are registered. Check that the backend has the audit registry loaded.
        </div>
      </div>
    )
  }

  return (
    <div>
      {/* Back button only makes sense from the NewScan card flow. In edit
          mode the modal has its own close X; suppress the Back link so it
          doesn't read as a second close control. */}
      {!editScan && <BackButton onClick={onBack} />}

      {/* Protocol label (static when preselected from the modal's card click;
          selectable when this panel is invoked generically). Hidden in edit
          mode — the protocol is already in the modal title and not changeable. */}
      {editScan ? null : preselectedProtocol && currentProtocol ? (
        <div style={{
          marginBottom: 10, padding: '8px 10px', borderRadius: 6,
          background: 'var(--bg-secondary)',
          display: 'flex', alignItems: 'center', gap: 8,
        }}>
          <ShieldAlert size={14} color="var(--text-muted)" />
          <span style={{ fontSize: 12, fontWeight: 600 }}>{currentProtocol.label}</span>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            ({(currentProtocol.auth_modes || []).join(', ')})
          </span>
        </div>
      ) : (
        <AuditRow icon={ShieldAlert} label="Protocol">
          <select
            value={selectedProtocol}
            onChange={e => setSelectedProtocol(e.target.value)}
            style={_selectStyle}
          >
            <option value="">Select protocol…</option>
            {protocols.map(p => (
              <option key={p.protocol} value={p.protocol}>{p.label}</option>
            ))}
          </select>
        </AuditRow>
      )}

      {currentProtocol && (
        <AuditRow icon={Shield} label="Mission">
          <select
            value={selectedMission}
            onChange={e => setSelectedMission(e.target.value)}
            style={_selectStyle}
          >
            {currentProtocol.missions.map(m => (
              <option key={m.key} value={m.key}>{m.label}</option>
            ))}
          </select>
        </AuditRow>
      )}

      {currentMission?.description && (
        <div style={{
          fontSize: 11, color: 'var(--text-muted)', marginBottom: 10,
          padding: '6px 10px', background: 'var(--bg-secondary)', borderRadius: 6,
        }}>
          {currentMission.description}
        </div>
      )}

      {/* Credential */}
      <AuditRow
        icon={Key}
        label={credentialOptional ? 'Credential (optional)' : 'Credential'}
      >
        <div style={{ display: 'flex', gap: 6, flex: 1 }}>
          <select
            value={credentialId}
            onChange={e => setCredentialId(e.target.value)}
            onFocus={refreshCredentials}
            style={{ ..._selectStyle, flex: 1 }}
          >
            <option value="">
              {credentialOptional ? 'None — anonymous / null session' : 'Select credential…'}
            </option>
            {eligibleCredentials.map(c => (
              <option key={c.id} value={c.id}>{c.name}</option>
            ))}
          </select>
          <button
            onClick={() => setShowCreateCred(v => !v)}
            style={_compactBtnStyle}
          >
            <Plus size={12} /> New
          </button>
        </div>
      </AuditRow>

      {showCreateCred && (
        <AuditInlineCredForm
          onSave={handleCreateCredential}
          onCancel={() => setShowCreateCred(false)}
        />
      )}

      {/* Relay agent */}
      <AuditRow icon={Radio} label="Relay">
        <select
          value={relayAgentId}
          onChange={e => setRelayAgentId(e.target.value)}
          style={_selectStyle}
        >
          <option value="">Select relay agent…</option>
          {relayAgents.map(r => (
            <option key={r.id} value={r.id}>{r.name || r.id}</option>
          ))}
        </select>
      </AuditRow>

      {/* Target source — tab switcher mirrors VM scan for UX parity */}
      <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', marginTop: 14, marginBottom: 10 }}>
        <button
          style={{
            flex: 1, padding: '8px 0', fontSize: 12, fontWeight: 600,
            background: 'none', border: 'none', cursor: 'pointer',
            borderBottom: `2px solid ${tab === 'manual' ? '#14b8a6' : 'transparent'}`,
            color: tab === 'manual' ? '#14b8a6' : 'var(--text-muted)',
          }}
          onClick={() => setTab('manual')}
        >Enter Target</button>
        <button
          style={{
            flex: 1, padding: '8px 0', fontSize: 12, fontWeight: 600,
            background: 'none', border: 'none', cursor: 'pointer',
            borderBottom: `2px solid ${tab === 'assets' ? '#14b8a6' : 'transparent'}`,
            color: tab === 'assets' ? '#14b8a6' : 'var(--text-muted)',
          }}
          onClick={() => setTab('assets')}
        >Select Assets</button>
      </div>

      {tab === 'manual' && (
        <div style={{ marginBottom: 6 }}>
          <label style={{ fontSize: 11, fontWeight: 600, display: 'block', marginBottom: 6, color: 'var(--text-muted)' }}>
            Target(s) — IP, hostname, URL, or CIDR
          </label>
          <textarea
            value={manualTarget}
            onChange={e => setManualTarget(e.target.value)}
            placeholder={'dc1.corp.local\n10.0.0.5\n192.168.1.0/28'}
            rows={3}
            style={{
              width: '100%', padding: '8px 10px', borderRadius: 6,
              border: '1px solid var(--border)', background: 'var(--bg)',
              color: 'var(--text-primary)', fontSize: 12, fontFamily: 'monospace',
              boxSizing: 'border-box', resize: 'vertical',
            }}
          />
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
            One per line, or comma-separated. CIDR subnets expand to hosts (cap {AUDIT_CIDR_PREVIEW_CAP}).
            {manualTargets.length > 0 && (
              <> {expandedManualCount !== manualTargets.length
                ? ` ${manualTargets.length} entr${manualTargets.length !== 1 ? 'ies' : 'y'} → ${expandedManualCount} host${expandedManualCount !== 1 ? 's' : ''}.`
                : ` ${manualTargets.length} target${manualTargets.length !== 1 ? 's' : ''} detected.`}</>
            )}
          </div>
          {manualCountExceedsCap && (
            <div style={{ fontSize: 11, color: '#dc2626', marginTop: 4, fontWeight: 600 }}>
              Expansion exceeds the {AUDIT_CIDR_PREVIEW_CAP}-host cap. Narrow your subnet or split into multiple runs.
            </div>
          )}
          {manualTargets.length > 0 && currentProtocol && (
            <div style={{
              marginTop: 8, padding: '6px 10px', borderRadius: 6,
              background: '#f59e0b11', border: '1px solid #f59e0b33',
              fontSize: 11, color: 'var(--text-muted)',
            }}>
              Free-form targets are sent as-is — make sure each host actually exposes {currentProtocol.label}.
              Mismatched hosts will still consume LLM tokens before the audit gives up.
            </div>
          )}
        </div>
      )}

      {tab === 'assets' && (
      <div style={{ marginTop: 12, marginBottom: 6 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
          <Server size={13} color="var(--text-muted)" />
          <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)' }}>
            Assets ({selectedAssets.size} selected)
          </span>
          <div style={{ flex: 1 }} />
          <input
            value={assetSearch}
            onChange={e => setAssetSearch(e.target.value)}
            placeholder="Search assets…"
            style={{
              fontSize: 11, padding: '4px 8px', borderRadius: 5,
              border: '1px solid var(--border)', background: 'var(--bg)',
              color: 'var(--text-primary)', width: 140,
            }}
          />
        </div>
        <div style={{
          border: '1px solid var(--border)', borderRadius: 6,
          maxHeight: 180, overflowY: 'auto',
        }}>
          {loading && <div style={{ padding: 16, textAlign: 'center' }}><Spinner /></div>}
          {!loading && assets.length === 0 && (
            <div style={{ padding: 14, textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>
              No assets match.
            </div>
          )}
          {!loading && assets.length > 0 && (
            <>
              <div style={{
                display: 'flex', alignItems: 'center', gap: 8,
                padding: '6px 10px', borderBottom: '1px solid var(--border)',
                background: 'var(--bg-secondary)', fontSize: 11,
              }}>
                <input type="checkbox" checked={allSelected} onChange={toggleAll} />
                <span style={{ color: 'var(--text-muted)' }}>Select all on this page</span>
              </div>
              {assets.map(a => (
                <label key={a.id} style={{
                  display: 'flex', alignItems: 'center', gap: 8,
                  padding: '6px 10px', cursor: 'pointer',
                  borderBottom: '1px solid var(--border-subtle, var(--border))',
                  fontSize: 12,
                }}>
                  <input
                    type="checkbox"
                    checked={selectedAssets.has(a.id)}
                    onChange={() => toggle(a)}
                  />
                  <span style={{ fontWeight: 600 }}>{getAssetDisplayName(a)}</span>
                  <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>{getAssetTarget(a)}</span>
                </label>
              ))}
              {hasMore && (
                <button onClick={loadMore} disabled={loadingMore} style={{
                  width: '100%', padding: 8, background: 'transparent', border: 'none',
                  color: 'var(--accent)', cursor: 'pointer', fontSize: 11,
                }}>
                  {loadingMore ? 'Loading…' : `Load ${Math.min(PAGE_SIZE, total - assets.length)} more`}
                </button>
              )}
            </>
          )}
        </div>
      </div>
      )}

      {/* Budget */}
      <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
        <AuditNumberInput
          icon={Clock} label="Max steps"
          value={maxSteps} onChange={setMaxSteps}
          min={5} max={60}
        />
        <AuditNumberInput
          icon={Clock} label="Wall-clock (s)"
          value={wallclockS} onChange={setWallclockS}
          min={60} max={3600}
        />
      </div>

      {/* Cost + quota hint */}
      {hostCount > 0 && currentMission && (
        <div style={{
          marginTop: 10, padding: '8px 10px', borderRadius: 6,
          background: quotaWouldExceed ? '#dc262611' : (quotaWouldWarn ? '#f59e0b11' : '#14b8a608'),
          border: `1px solid ${quotaWouldExceed ? '#dc262644' : (quotaWouldWarn ? '#f59e0b44' : '#14b8a622')}`,
          fontSize: 11, color: 'var(--text-muted)',
        }}>
          <div>
            ≈ ${costPerHostUSD.toFixed(2)}/host · ~{(tokensPerHost / 1000).toFixed(0)}k tokens/host × {hostCount} host{hostCount === 1 ? '' : 's'} ≈ ${estimatedCost.toFixed(2)} · ~{(estimatedTokens / 1000).toFixed(0)}k tokens
          </div>
          {usage && (
            <div style={{ marginTop: 4, fontSize: 10 }}>
              Quota ({usage.tier}): {(usage.used || 0).toLocaleString()} / {(usage.limit || 0).toLocaleString()} used ({usage.percentage?.toFixed?.(0) ?? 0}%)
              {quotaWouldExceed && (
                <span style={{ color: '#dc2626', fontWeight: 600 }}> — this run would exceed your monthly quota</span>
              )}
              {quotaWouldWarn && (
                <span style={{ color: '#f59e0b', fontWeight: 600 }}> — this run would push you past 80% of monthly quota</span>
              )}
            </div>
          )}
        </div>
      )}

      {quotaExhausted && (
        <div style={{
          marginTop: 10, padding: '8px 10px', borderRadius: 6,
          background: '#dc262611', border: '1px solid #dc262644',
          fontSize: 12, color: '#dc2626',
        }}>
          Monthly AI token quota exhausted. Upgrade your plan or wait for the quota to reset before starting a new audit.
        </div>
      )}

      {error && (
        <div style={{
          fontSize: 12, color: '#dc2626', marginTop: 10,
          padding: '8px 10px', background: '#dc262611', borderRadius: 6,
        }}>{error}</div>
      )}

      {editScan ? (
        <div style={{ display: 'flex', gap: 8, marginTop: 14 }}>
          <Button variant="secondary" onClick={handleSaveOnly} disabled={scanning} style={{ flex: 1 }}>
            Save (no rerun)
          </Button>
          <Button
            onClick={handleStart}
            disabled={!canStart}
            style={{
              flex: 2,
              background: canStart ? '#14b8a6' : 'var(--bg-secondary)',
              opacity: canStart ? 1 : 0.6,
            }}
          >
            {scanning ? (
              <><RefreshCw size={13} style={{ animation: 'spin 1s linear infinite' }} /> Saving…</>
            ) : (
              <><Play size={13} /> Save &amp; rerun on {hostCount} host{hostCount === 1 ? '' : 's'}</>
            )}
          </Button>
        </div>
      ) : (
        <Button
          onClick={handleStart}
          disabled={!canStart}
          style={{
            width: '100%', marginTop: 14,
            background: canStart ? '#14b8a6' : 'var(--bg-secondary)',
            opacity: canStart ? 1 : 0.6,
          }}
        >
          {scanning ? (
            <><RefreshCw size={13} style={{ animation: 'spin 1s linear infinite' }} /> Starting…</>
          ) : (
            <><Play size={13} /> Run {currentMission?.label || 'Audit'} on {hostCount} host{hostCount === 1 ? '' : 's'}</>
          )}
        </Button>
      )}
    </div>
  )
}


// ── Small reusable pieces for AuditScanPanel ─────────────────────────

const _selectStyle = {
  flex: 1, padding: '6px 8px', borderRadius: 6,
  border: '1px solid var(--border)', background: 'var(--bg)',
  color: 'var(--text-primary)', fontSize: 12,
}
const _compactBtnStyle = {
  display: 'flex', alignItems: 'center', gap: 4,
  padding: '6px 10px', borderRadius: 6,
  border: '1px solid var(--border)', background: 'transparent',
  color: 'var(--text-secondary)', fontSize: 11, cursor: 'pointer',
}

function AuditRow({ icon: Icon, label, children }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, width: 80, flexShrink: 0 }}>
        <Icon size={13} color="var(--text-muted)" />
        <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)' }}>{label}</span>
      </div>
      {children}
    </div>
  )
}

function AuditNumberInput({ icon: Icon, label, value, onChange, min, max }) {
  return (
    <div style={{ flex: 1, display: 'flex', alignItems: 'center', gap: 8 }}>
      <Icon size={12} color="var(--text-muted)" />
      <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', minWidth: 70 }}>{label}</span>
      <input
        type="number"
        value={value}
        min={min} max={max}
        onChange={e => onChange(Number(e.target.value) || value)}
        style={{
          width: 70, padding: '4px 6px', borderRadius: 5,
          border: '1px solid var(--border)', background: 'var(--bg)',
          color: 'var(--text-primary)', fontSize: 12,
        }}
      />
    </div>
  )
}

function AuditInlineCredForm({ onSave, onCancel }) {
  const [name, setName] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [domain, setDomain] = useState('')

  const valid = name.trim() && username.trim() && password

  return (
    <div style={{
      padding: 10, borderRadius: 6, marginBottom: 10,
      background: 'var(--bg-secondary)', border: '1px solid var(--border)',
    }}>
      <div style={{ fontSize: 11, fontWeight: 600, marginBottom: 8, color: 'var(--text-muted)' }}>
        New credential
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, marginBottom: 6 }}>
        <input placeholder="Name" value={name} onChange={e => setName(e.target.value)} style={_credInput} />
        <input placeholder="Domain (optional)" value={domain} onChange={e => setDomain(e.target.value)} style={_credInput} />
        <input placeholder="Username" value={username} onChange={e => setUsername(e.target.value)} style={_credInput} />
        <input placeholder="Password" type="password" value={password} onChange={e => setPassword(e.target.value)} style={_credInput} />
      </div>
      <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
        <button onClick={onCancel} style={_compactBtnStyle}>Cancel</button>
        <button
          onClick={() => onSave({ name: name.trim(), values: { username, password, domain } })}
          disabled={!valid}
          style={{ ..._compactBtnStyle, background: valid ? '#14b8a6' : 'var(--bg)', color: valid ? 'white' : 'var(--text-muted)', border: 'none' }}
        >
          Save
        </button>
      </div>
    </div>
  )
}

const _credInput = {
  padding: '6px 8px', borderRadius: 5,
  border: '1px solid var(--border)', background: 'var(--bg)',
  color: 'var(--text-primary)', fontSize: 11,
}


function BackButton({ onClick }) {
  return (
    <button onClick={onClick} style={{
      background: 'none', border: 'none', cursor: 'pointer', color: 'var(--accent)',
      fontSize: 12, marginBottom: 12, padding: 0, display: 'flex', alignItems: 'center', gap: 4,
    }}>
      ← Back
    </button>
  )
}

function SourceOption({ icon: Icon, label, description, color, disabled, disabledMessage, onClick }) {
  return (
    <button
      onClick={disabled ? undefined : onClick}
      style={{
        display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10,
        padding: '20px 12px', borderRadius: 10,
        border: '1px solid var(--border)',
        background: disabled ? 'var(--bg-secondary)' : 'transparent',
        cursor: disabled ? 'not-allowed' : 'pointer',
        opacity: disabled ? 0.5 : 1,
        transition: 'all 0.15s',
      }}
      onMouseEnter={e => { if (!disabled) { e.currentTarget.style.borderColor = color; e.currentTarget.style.background = `${color}11` } }}
      onMouseLeave={e => { if (!disabled) { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.background = 'transparent' } }}
    >
      <div style={{
        width: 44, height: 44, borderRadius: 10,
        background: `${color}22`, display: 'flex', alignItems: 'center', justifyContent: 'center',
      }}>
        <Icon size={22} color={color} />
      </div>
      <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-primary)' }}>{label}</div>
      <div style={{ fontSize: 11, color: 'var(--text-muted)', textAlign: 'center' }}>
        {disabled ? disabledMessage : description}
      </div>
    </button>
  )
}


// ── EASM scan status badge ────────────────────────────────────────────

const STAGE_LABELS = {
  // Individual steps
  subfinder: 'Subdomain Discovery',
  wildcard_bruteforce: 'Wildcard Check',
  asnmap: 'ASN Mapping',
  uncover: 'Search Engines',
  dnsx: 'DNS Resolution',
  naabu: 'Port Scanning',
  liveness_gate: 'Liveness Check',
  tlsx: 'TLS Inspection',
  httpx: 'HTTP Probing',
  cdncheck: 'CDN Detection',
  katana: 'Web Crawling',
  nmap_dispatch: 'Fingerprinting',
  // Composite stage names emitted by the discovery/enrichment chains when
  // multiple steps run in parallel under a single UI banner. These match
  // the exact strings the scanner writes to scan_runs.current_stage.
  'subfinder+wildcard_bruteforce+uncover': 'Subdomain Discovery',
  'dnsx+naabu': 'DNS + Port Scanning',
  'tlsx+httpx+cdncheck': 'Service Inspection',
}

// Given a stage value from scan_runs.current_stage (either a single step
// like "liveness_gate" or a composite like "dnsx+naabu"), return the set of
// individual step names it contains. Used by the progress-bar to figure out
// which dots should be highlighted as active when a parallel group is running.
function stageMembers(stage) {
  if (!stage) return new Set()
  return new Set(stage.split('+'))
}

// VM scans fan each user-submitted target into multiple Celery jobs (nuclei,
// content discovery, agents). Roll the per-job statuses back up to per-target
// counts so the UI speaks the user's language: "2/3 targets", not "5/9 jobs".
function vmTargetProgress(metadata) {
  const jobStatuses = metadata?.job_statuses || {}
  const submittedTargets = metadata?.targets || []
  const perTarget = {}
  for (const t of submittedTargets) {
    if (t) perTarget[t] = { ok: 0, failed: 0, pending: 0 }
  }
  for (const info of Object.values(jobStatuses)) {
    if (!info || !info.target) continue
    if (!perTarget[info.target]) perTarget[info.target] = { ok: 0, failed: 0, pending: 0 }
    if (info.status === 'SUCCESS') perTarget[info.target].ok += 1
    else if (info.status === 'FAILURE') perTarget[info.target].failed += 1
    else perTarget[info.target].pending += 1
  }
  const buckets = { ok: 0, failed: 0, pending: 0 }
  for (const counts of Object.values(perTarget)) {
    if (counts.failed > 0) buckets.failed += 1
    else if (counts.pending === 0 && counts.ok > 0) buckets.ok += 1
    else buckets.pending += 1
  }
  // Legacy scans with no targets list and no job_statuses yet fall back to
  // the raw job counter so we never render "0/0".
  const total = Object.keys(perTarget).length || metadata?.total_jobs || 0
  const completed = buckets.ok + buckets.failed
  return { total, completed, buckets }
}

function EasmStatusBadge({ status, metadata }) {
  if (!status || status === 'completed') return null
  // A scan is "queued" when Celery has accepted the task but no worker has
  // picked it up yet (stage_index=0, started_at=NULL on the backend). It's
  // visually distinct from "running" — no spinner, amber-ish tint — so
  // users understand the scan hasn't actually started yet, usually because
  // worker concurrency is saturated by other scans.
  const isQueued = status === 'queued'
  const isRunning = status === 'running'
  const isFailed = status === 'failed' || status === 'error'
  const isCompletedWithErrors = status === 'completed_with_errors'
  const color = isQueued ? '#f59e0b'
    : isRunning ? '#0ea5e9'
    : isFailed ? '#dc2626'
    : isCompletedWithErrors ? '#f59e0b'
    : '#a78bfa'

  const stage = metadata?.current_stage
  const stageIndex = metadata?.stage_index || 0
  const totalStages = metadata?.total_stages || 0

  // VM scan progress — roll per-job statuses up to per-target so the chip
  // shows "2/3 targets" even when each target spawned multiple worker jobs.
  const vmProgress = vmTargetProgress(metadata)
  const isVm = vmProgress.total > 0 && !stage

  const stageLabel = stage ? (STAGE_LABELS[stage] || stage) : null
  const label = isQueued ? 'Queued'
    : isFailed ? 'Failed'
    : isCompletedWithErrors ? 'Partial'
    : (!isRunning ? status : null)

  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      background: `${color}18`, color, border: `1px solid ${color}44`,
      borderRadius: 4, padding: '2px 8px', fontSize: 11, fontWeight: 600,
    }}>
      {isRunning && <Loader size={10} style={{ animation: 'spin 1.5s linear infinite' }} />}
      {isRunning ? (
        isVm
          ? <>{vmProgress.completed}/{vmProgress.total} targets</>
          : stageLabel
            ? <>{stageLabel} ({stageIndex}/{totalStages})</>
            : 'Scanning...'
      ) : label}
      {isRunning && <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>}
    </span>
  )
}


// ── Scan progress bar (shown under running EASM scans) ───────────────

function ScanProgressBar({ metadata }) {
  if (!metadata) return null
  const stage = metadata.current_stage
  const stageIndex = metadata.stage_index || 0
  const totalStages = metadata.total_stages || 0
  const stageLog = metadata.stage_log || []

  if (!stage && stageLog.length === 0) return null

  // Build combined step list. Discovery has 6 steps (asnmap was removed —
  // the ProjectDiscovery binary hangs on an interactive API-key prompt and
  // was wasting 90s per scan for zero data). Enrichment has 5.
  const discoverySteps = ['subfinder', 'wildcard_bruteforce', 'uncover', 'dnsx', 'naabu', 'liveness_gate']
  const enrichmentSteps = ['tlsx', 'httpx', 'cdncheck', 'katana', 'nmap_dispatch']

  // Stage names in the DB can be composites like "dnsx+naabu" when multiple
  // steps ran concurrently. Flatten the current stage + every stage_log
  // entry into individual step names before deciding which pipeline we're in.
  const stageLogMembers = stageLog.flatMap(s => [...stageMembers(s.stage)])
  const currentMembers = [...stageMembers(stage)]
  const allKnownStages = [...stageLogMembers, ...currentMembers]
  const isEnrichment = allKnownStages.some(s => enrichmentSteps.includes(s))
  const isDiscovery = allKnownStages.some(s => discoverySteps.includes(s))

  // Members of the currently-running group. When the scanner is in a
  // parallel group like "dnsx+naabu", every member dot should highlight
  // as active, not just one.
  const activeMembers = stageMembers(stage)

  // For a "full" scan, show both pipelines
  const steps = isDiscovery && !isEnrichment
    ? discoverySteps
    : !isDiscovery && isEnrichment
    ? enrichmentSteps
    : [...discoverySteps, ...enrichmentSteps]

  // stage_log entries can also be composite (e.g. the chain writes one
  // entry per step, not per group, but defensive split handles both shapes).
  const completedStages = new Set(
    stageLog.filter(s => s.status === 'done').flatMap(s => [...stageMembers(s.stage)])
  )
  const errorStages = new Set(
    stageLog.filter(s => s.status === 'error').flatMap(s => [...stageMembers(s.stage)])
  )
  const pct = totalStages > 0 ? Math.round(((stageIndex - 1) / totalStages) * 100) : 0

  // Estimate time remaining: elapsed / completed% = total → remaining = total - elapsed
  const completedDurations = stageLog.filter(s => s.duration_s).map(s => s.duration_s)
  const elapsedSeconds = completedDurations.reduce((a, b) => a + b, 0)
  const completedFraction = totalStages > 0 ? (stageIndex - 1) / totalStages : 0
  const etaSeconds = completedFraction > 0
    ? Math.round(elapsedSeconds * (1 - completedFraction) / completedFraction)
    : 0

  return (
    <div style={{
      padding: '8px 16px 10px',
      borderTop: '1px solid var(--border)',
      background: 'rgba(14, 165, 233, 0.03)',
    }}>
      {/* Progress bar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
        <div style={{
          flex: 1, height: 4, borderRadius: 2,
          background: 'var(--border)', overflow: 'hidden',
        }}>
          <div style={{
            height: '100%', borderRadius: 2,
            background: '#0ea5e9',
            width: `${Math.max(pct, 3)}%`,
            transition: 'width 0.6s ease',
          }} />
        </div>
        <span style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600, minWidth: 28, textAlign: 'right' }}>
          {pct}%
        </span>
      </div>

      {/* Step dots */}
      <div style={{ display: 'flex', gap: 3, alignItems: 'center', flexWrap: 'wrap' }}>
        {steps.map((step, i) => {
          const isDone = completedStages.has(step)
          const isError = errorStages.has(step)
          // A step is "active" if it's the current single stage OR a member
          // of the currently-running composite group (e.g. "dnsx+naabu"
          // → both dnsx and naabu light up simultaneously).
          const isActive = activeMembers.has(step)
          const color = isDone ? '#22c55e' : isError ? '#dc2626' : isActive ? '#0ea5e9' : 'var(--border)'

          return (
            <div
              key={step}
              title={`${STAGE_LABELS[step] || step}${isDone ? ' (done)' : isError ? ' (error)' : isActive ? ' (running)' : ''}`}
              style={{
                display: 'flex', alignItems: 'center', gap: 3,
              }}
            >
              <div style={{
                width: isActive ? 8 : 6, height: isActive ? 8 : 6,
                borderRadius: '50%', background: color,
                boxShadow: isActive ? `0 0 6px ${color}` : 'none',
                transition: 'all 0.3s',
              }} />
              {isActive && (
                <span style={{ fontSize: 10, color: '#0ea5e9', fontWeight: 600 }}>
                  {STAGE_LABELS[step] || step}
                </span>
              )}
              {i < steps.length - 1 && (
                <div style={{
                  width: 8, height: 1,
                  background: isDone ? '#22c55e44' : 'var(--border)',
                }} />
              )}
            </div>
          )
        })}
      </div>

      {/* ETA */}
      {etaSeconds > 0 && completedDurations.length >= 2 && (
        <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4 }}>
          ~{etaSeconds < 60 ? `${etaSeconds}s` : `${Math.round(etaSeconds / 60)}m`} remaining
        </div>
      )}
    </div>
  )
}


// ── Scan run history (EASM) ──────────────────────────────────────────

function ScanRunHistory({ expanded, domain }) {
  const [runs, setRuns] = useState(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (!expanded) return
    let cancelled = false
    const load = () => {
      if (!runs) setLoading(true)
      getEasmScanRuns(20, domain)
        .then(data => { if (!cancelled) setRuns(data) })
        .catch(() => { if (!cancelled) setRuns([]) })
        .finally(() => { if (!cancelled) setLoading(false) })
    }
    load()
    // Refresh while any run is active
    const hasRunning = runs?.some(r => r.status === 'running' || r.status === 'queued')
    if (hasRunning) {
      const interval = setInterval(load, 10000)
      return () => { cancelled = true; clearInterval(interval) }
    }
    return () => { cancelled = true }
  }, [expanded, domain, runs?.some?.(r => r.status === 'running' || r.status === 'queued')])

  if (!expanded) return null

  const statusColor = (s) => {
    if (s === 'completed' || s === 'done') return '#22c55e'
    if (s === 'failed' || s === 'error') return '#dc2626'
    if (s === 'running' || s === 'queued') return '#0ea5e9'
    return '#71717a'
  }

  return (
    <div style={{
      borderTop: '1px solid var(--border)', padding: '10px 16px 6px',
      background: 'var(--bg-secondary)',
    }}>
      <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 8 }}>
        <History size={11} style={{ marginRight: 4, verticalAlign: -1 }} />
        Scan History
      </div>
      {loading && <div style={{ fontSize: 12, color: 'var(--text-muted)', padding: '4px 0' }}><Loader size={12} style={{ animation: 'spin 1.5s linear infinite', marginRight: 4, verticalAlign: -1 }} />Loading...</div>}
      {runs && runs.length === 0 && (
        <div style={{ fontSize: 12, color: 'var(--text-muted)', padding: '4px 0' }}>No scan history yet.</div>
      )}
      {runs && runs.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginBottom: 4 }}>
          {[...runs].sort((a, b) => new Date(b.started_at || 0) - new Date(a.started_at || 0)).map((run, i) => (
            <React.Fragment key={run.id || i}>
              <div style={{
                display: 'flex', gap: 10, alignItems: 'center', fontSize: 12,
                padding: '5px 8px', borderRadius: 5, background: 'var(--bg)',
                border: '1px solid var(--border)',
              }}>
                <span style={{
                  width: 7, height: 7, borderRadius: '50%', flexShrink: 0,
                  background: statusColor(run.status),
                }} />
                <span style={{ fontWeight: 500, minWidth: 70 }}>{run.scan_type || 'full'}</span>
                <span style={{ color: 'var(--text-muted)', flex: 1 }}>
                  {run.started_at ? formatAge(run.started_at) : '—'}
                </span>
                <span style={{ color: 'var(--text-muted)' }}>
                  {run.assets_found || 0} found{run.assets_changed ? `, ${run.assets_changed} changed` : ''}
                </span>
                <span style={{
                  fontSize: 10, fontWeight: 600, textTransform: 'uppercase',
                  color: statusColor(run.status),
                }}>
                  {(run.status === 'running' && run.current_stage)
                    ? `${STAGE_LABELS[run.current_stage] || run.current_stage} (${run.stage_index}/${run.total_stages})`
                    : run.status === 'queued'
                      ? 'queued'
                      : run.status}
                </span>
              </div>
              {run.error && (
                <div style={{ fontSize: 11, color: '#dc2626', padding: '2px 8px 4px 25px', marginTop: -2 }}>
                  {run.error}
                </div>
              )}
            </React.Fragment>
          ))}
        </div>
      )}
    </div>
  )
}


// ── VM scan progress (shown under running VM scans) ──────────────────

function VmScanProgress({ metadata }) {
  if (!metadata) return null
  const { findings_emitted = 0 } = metadata
  const { total: total_targets, completed: completed_targets, buckets } = vmTargetProgress(metadata)
  const pct = total_targets > 0 ? Math.round((completed_targets / total_targets) * 100) : 0
  const remaining = total_targets - completed_targets

  return (
    <div style={{ padding: '0 16px 12px' }}>
      <div style={{
        height: 6, borderRadius: 3, background: 'var(--border)', overflow: 'hidden', marginBottom: 6,
      }}>
        <div style={{
          height: '100%', borderRadius: 3, background: '#ec4899',
          width: `${pct}%`, transition: 'width 0.5s ease',
        }} />
      </div>
      <div style={{ fontSize: 11, color: 'var(--text-muted)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
        <span>{completed_targets}/{total_targets} targets scanned{findings_emitted > 0 ? ` — ${findings_emitted} findings` : ''}</span>
        <div style={{ display: 'flex', gap: 6 }}>
          {buckets.ok > 0 && (
            <span style={{ color: '#22c55e', fontWeight: 600 }}>{buckets.ok} ok</span>
          )}
          {buckets.failed > 0 && (
            <span style={{ color: '#dc2626', fontWeight: 600 }}>{buckets.failed} failed</span>
          )}
          {buckets.pending > 0 && (
            <span>{buckets.pending} {remaining > 0 ? 'pending' : 'finishing'}</span>
          )}
        </div>
      </div>
    </div>
  )
}


// ── VM scan history (job-level detail from metadata) ─────────────────

function VmScanHistory({ expanded, metadata }) {
  if (!expanded || !metadata) return null

  const targets = metadata.targets || []
  const jobIds = metadata.job_ids || []
  const completed = metadata.completed_jobs || 0
  const total = metadata.total_jobs || 0
  const findings = metadata.findings_emitted || 0
  const status = metadata.status || 'unknown'
  const jobStatuses = metadata.job_statuses || {}

  const statusColor = (s) => {
    if (s === 'completed') return '#22c55e'
    if (s === 'completed_with_errors') return '#f59e0b'
    if (s === 'failed' || s === 'error') return '#dc2626'
    if (s === 'running' || s === 'queued') return '#ec4899'
    return '#71717a'
  }

  const jobStatusDot = (jobStatus) => {
    if (jobStatus === 'SUCCESS') return '#22c55e'
    if (jobStatus === 'FAILURE') return '#dc2626'
    return '#71717a'  // PENDING / unknown
  }

  const jobStatusLabel = (jobStatus) => {
    if (jobStatus === 'SUCCESS') return 'ok'
    if (jobStatus === 'FAILURE') return 'failed'
    return 'pending'
  }

  return (
    <div style={{
      borderTop: '1px solid var(--border)', padding: '10px 16px 6px',
      background: 'var(--bg-secondary)',
    }}>
      <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 8 }}>
        <History size={11} style={{ marginRight: 4, verticalAlign: -1 }} />
        Scan Details
      </div>

      {/* Summary row */}
      <div style={{
        display: 'flex', gap: 10, alignItems: 'center', fontSize: 12,
        padding: '5px 8px', borderRadius: 5, background: 'var(--bg)',
        border: '1px solid var(--border)', marginBottom: 4,
      }}>
        <span style={{
          width: 7, height: 7, borderRadius: '50%', flexShrink: 0,
          background: statusColor(status),
        }} />
        <span style={{ fontWeight: 500 }}>
          {status === 'running' ? 'Scanning' : status === 'completed' ? 'Completed' : status === 'completed_with_errors' ? 'Partial' : status}
        </span>
        <span style={{ color: 'var(--text-muted)', flex: 1 }}>
          {completed}/{total} targets done
        </span>
        <span style={{ color: 'var(--text-muted)' }}>
          {findings} finding{findings !== 1 ? 's' : ''}
        </span>
      </div>

      {/* Target list with per-job verbose status */}
      {targets.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 2, marginBottom: 4 }}>
          {targets.map((target, i) => {
            const jobId = jobIds[i]
            const jobInfo = jobId ? jobStatuses[jobId] : null
            const jobStatus = jobInfo?.status
            const findingsCount = jobInfo?.findings_count
            const errorMsg = jobInfo?.error

            return (
              <div key={i} style={{ display: 'flex', flexDirection: 'column' }}>
                <div style={{
                  display: 'flex', gap: 8, alignItems: 'center', fontSize: 11,
                  padding: '4px 8px', borderRadius: 4,
                  color: 'var(--text-muted)',
                }}>
                  {/* per-target status dot */}
                  <span style={{
                    width: 6, height: 6, borderRadius: '50%', flexShrink: 0,
                    background: jobStatus ? jobStatusDot(jobStatus) : 'var(--border)',
                  }} />
                  <span style={{ fontFamily: 'monospace', fontWeight: 500, color: 'var(--text-secondary)', flex: 1 }}>
                    {target}
                  </span>
                  {jobStatus && (
                    <span style={{ fontSize: 10, color: jobStatusDot(jobStatus), fontWeight: 500 }}>
                      {jobStatusLabel(jobStatus)}
                    </span>
                  )}
                  {jobStatus === 'SUCCESS' && (() => {
                    const ns = jobInfo?.nuclei_status
                    const nsLabel = ns && ns !== 'complete' ? ns : null
                    return (
                      <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                        {findingsCount != null ? `${findingsCount} finding${findingsCount !== 1 ? 's' : ''}` : '0 findings'}
                        {jobInfo?.templates_matched != null && ` · ${jobInfo.templates_matched}/${jobInfo.templates_loaded ?? '?'} templates`}
                        {jobInfo?.requests_sent > 0 && ` · ${jobInfo.requests_sent} reqs`}
                        {jobInfo?.duration_seconds != null && ` · ${jobInfo.duration_seconds}s`}
                        {nsLabel && (
                          <span style={{ marginLeft: 4, color: '#f59e0b', fontWeight: 500 }}>[{nsLabel}]</span>
                        )}
                      </span>
                    )
                  })()}
                  {jobId && (
                    <span style={{ fontSize: 10, opacity: 0.45, fontFamily: 'monospace' }}>
                      {jobId.slice(0, 8)}
                    </span>
                  )}
                </div>
                {/* Error detail for failed jobs */}
                {errorMsg && (
                  <div style={{
                    margin: '0 8px 2px 22px', padding: '4px 8px',
                    borderRadius: 4, background: '#fef2f2',
                    border: '1px solid #fecaca', fontSize: 10,
                    color: '#991b1b', fontFamily: 'monospace',
                    whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                  }}>
                    {errorMsg}
                  </div>
                )}
                {/* Diagnostic panel for 0-template scans */}
                {jobStatus === 'SUCCESS' && jobInfo?.templates_loaded === 0 && (jobInfo?.routing_info || jobInfo?.nuclei_stderr) && (
                  <div style={{
                    margin: '2px 8px 2px 22px', padding: '6px 8px',
                    borderRadius: 4, background: '#fffbeb',
                    border: '1px solid #fde68a', fontSize: 10,
                  }}>
                    <div style={{ fontWeight: 600, color: '#92400e', marginBottom: 4 }}>
                      Why 0 templates?
                    </div>
                    {jobInfo?.routing_info && (
                      <div style={{ color: '#78350f', marginBottom: jobInfo?.nuclei_stderr ? 6 : 0 }}>
                        <div><b>Routing:</b> {jobInfo.routing_info.reason}</div>
                        {jobInfo.routing_info.cpe_list?.length > 0 && (
                          <div>CPE: {jobInfo.routing_info.cpe_list.join(', ')}</div>
                        )}
                        {jobInfo.routing_info.tech_stack_keys?.length > 0 && (
                          <div>Tech stack: {jobInfo.routing_info.tech_stack_keys.join(', ')}</div>
                        )}
                        {jobInfo.routing_info.open_ports?.length > 0 && (
                          <div>Open ports: {jobInfo.routing_info.open_ports.join(', ')}</div>
                        )}
                      </div>
                    )}
                    {jobInfo?.nuclei_stderr && (
                      <details style={{ marginTop: 4 }}>
                        <summary style={{ cursor: 'pointer', color: '#92400e', fontWeight: 500 }}>
                          Nuclei output
                        </summary>
                        <pre style={{
                          margin: '4px 0 0', padding: '4px 6px',
                          background: '#fef3c7', borderRadius: 3,
                          fontSize: 9, whiteSpace: 'pre-wrap',
                          wordBreak: 'break-all', maxHeight: 200,
                          overflowY: 'auto', color: '#451a03',
                        }}>
                          {jobInfo.nuclei_stderr}
                        </pre>
                      </details>
                    )}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}

      {/* Previous run history */}
      {metadata.previous_run && (() => {
        const pr = metadata.previous_run
        const prStatuses = pr.job_statuses || {}
        const prStatus = pr.status || 'unknown'
        const prDate = pr.scan_date ? new Date(pr.scan_date + 'Z') : null
        const prLabel = prStatus === 'completed' ? 'Completed' : prStatus === 'completed_with_errors' ? 'Partial' : prStatus

        return (
          <div style={{ marginTop: 6, borderTop: '1px dashed var(--border)', paddingTop: 6 }}>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 4, fontWeight: 500 }}>
              Previous run {prDate ? `· ${prDate.toLocaleString()}` : ''}
            </div>
            <div style={{
              display: 'flex', gap: 10, alignItems: 'center', fontSize: 11,
              padding: '4px 8px', borderRadius: 4, background: 'var(--bg)',
              border: '1px solid var(--border)', marginBottom: 3, opacity: 0.75,
            }}>
              <span style={{
                width: 6, height: 6, borderRadius: '50%', flexShrink: 0,
                background: statusColor(prStatus),
              }} />
              <span style={{ fontWeight: 500, color: 'var(--text-secondary)' }}>{prLabel}</span>
              <span style={{ color: 'var(--text-muted)', flex: 1 }}>
                {pr.completed_targets ?? pr.completed_jobs ?? 0}/{pr.total_targets ?? pr.total_jobs ?? 0} targets done
              </span>
              <span style={{ color: 'var(--text-muted)' }}>
                {pr.findings_emitted ?? 0} finding{(pr.findings_emitted ?? 0) !== 1 ? 's' : ''}
              </span>
            </div>
            {Object.entries(prStatuses).map(([jobId, info]) => (
              <div key={jobId} style={{
                display: 'flex', gap: 8, alignItems: 'center', fontSize: 10,
                padding: '3px 8px', color: 'var(--text-muted)', opacity: 0.7,
              }}>
                <span style={{
                  width: 5, height: 5, borderRadius: '50%', flexShrink: 0,
                  background: jobStatusDot(info.status),
                }} />
                <span style={{ fontFamily: 'monospace', flex: 1 }}>{info.target || jobId.slice(0, 8)}</span>
                <span style={{ color: jobStatusDot(info.status) }}>{jobStatusLabel(info.status)}</span>
                {info.status === 'SUCCESS' && (
                  <span>{info.findings_count ?? 0} findings</span>
                )}
                {info.error && (
                  <span style={{ color: '#dc2626' }} title={info.error}>error</span>
                )}
              </div>
            ))}
          </div>
        )
      })()}
    </div>
  )
}


// ── Schedule presets ──────────────────────────────────────────────────

const SCHEDULE_PRESETS = [
  { label: 'No schedule', value: '' },
  { label: 'Every 6 hours', value: '0 */6 * * *' },
  { label: 'Every 12 hours', value: '0 */12 * * *' },
  { label: 'Daily', value: '0 8 * * *' },
  { label: 'Weekly', value: '0 8 * * 1' },
  { label: 'Monthly', value: '0 8 1 * *' },
]

function getScheduleLabel(cron) {
  if (!cron) return null
  const preset = SCHEDULE_PRESETS.find(p => p.value === cron)
  return preset ? preset.label : cron
}

function ScheduleDropdown({ scan, onUpdate }) {
  const [open, setOpen] = useState(false)
  const [saving, setSaving] = useState(false)
  const [showCustom, setShowCustom] = useState(false)
  const [customCron, setCustomCron] = useState('')
  const [customError, setCustomError] = useState(null)
  const ref = useRef(null)

  useEffect(() => {
    if (!open) return
    const handler = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [open])

  const handleSelect = async (value) => {
    setSaving(true)
    setCustomError(null)
    try {
      await updateScanSchedule(scan.id, value || null)
      if (onUpdate) await onUpdate()
      setShowCustom(false)
      setOpen(false)
    } catch (err) {
      setCustomError(err.message || 'Invalid cron expression')
      setSaving(false)
      return
    } finally {
      setSaving(false)
    }
  }

  const isCustom = scan.schedule && !SCHEDULE_PRESETS.some(p => p.value === scan.schedule)
  const color = scan.source_type === 'vm_scanner' ? '#ec4899' : '#0ea5e9'

  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <button
        onClick={() => { setOpen(o => !o); setShowCustom(false); setCustomError(null) }}
        title={scan.schedule ? `Schedule: ${scan.schedule}` : 'Set schedule'}
        style={{
          background: 'none', border: '1px solid var(--border)',
          borderRadius: 6, padding: '5px 8px', cursor: 'pointer',
          color: scan.schedule ? color : 'var(--text-muted)',
          borderColor: scan.schedule ? `${color}66` : 'var(--border)',
          display: 'flex', alignItems: 'center', gap: 3, fontSize: 12,
          transition: 'all 0.15s',
        }}
        onMouseEnter={e => { e.currentTarget.style.borderColor = color; e.currentTarget.style.color = color }}
        onMouseLeave={e => { if (!scan.schedule) { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-muted)' } else { e.currentTarget.style.borderColor = `${color}66`; e.currentTarget.style.color = color }}}
      >
        <Clock size={12} />
        {saving ? <Loader size={10} style={{ animation: 'spin 1s linear infinite' }} /> : <ChevronDown size={10} />}
      </button>
      {open && (
        <div style={{
          position: 'absolute', top: '100%', right: 0, marginTop: 4, zIndex: 100,
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: 8, boxShadow: '0 8px 24px rgba(0,0,0,0.2)',
          minWidth: 220, overflow: 'hidden',
        }}>
          <div style={{ padding: '8px 12px', fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', borderBottom: '1px solid var(--border)' }}>
            Schedule
          </div>
          {SCHEDULE_PRESETS.map(preset => (
            <button
              key={preset.value}
              onClick={() => handleSelect(preset.value)}
              style={{
                display: 'block', width: '100%', textAlign: 'left',
                padding: '8px 12px', border: 'none', cursor: 'pointer',
                background: (scan.schedule || '') === preset.value ? `${color}18` : 'transparent',
                color: (scan.schedule || '') === preset.value ? color : 'var(--text-primary)',
                fontSize: 13, fontWeight: (scan.schedule || '') === preset.value ? 600 : 400,
                transition: 'background 0.1s',
              }}
              onMouseEnter={e => e.currentTarget.style.background = `${color}11`}
              onMouseLeave={e => e.currentTarget.style.background = (scan.schedule || '') === preset.value ? `${color}18` : 'transparent'}
            >
              {preset.label}
              {preset.value && <span style={{ fontSize: 10, color: 'var(--text-muted)', marginLeft: 6 }}>{preset.value}</span>}
            </button>
          ))}

          {/* Custom cron option */}
          <div style={{ borderTop: '1px solid var(--border)' }}>
            {!showCustom ? (
              <button
                onClick={() => { setShowCustom(true); setCustomCron(isCustom ? scan.schedule : ''); setCustomError(null) }}
                style={{
                  display: 'block', width: '100%', textAlign: 'left',
                  padding: '8px 12px', border: 'none', cursor: 'pointer',
                  background: isCustom ? `${color}18` : 'transparent',
                  color: isCustom ? color : 'var(--text-primary)',
                  fontSize: 13, fontWeight: isCustom ? 600 : 400,
                  transition: 'background 0.1s',
                }}
                onMouseEnter={e => e.currentTarget.style.background = `${color}11`}
                onMouseLeave={e => e.currentTarget.style.background = isCustom ? `${color}18` : 'transparent'}
              >
                Custom...
                {isCustom && <span style={{ fontSize: 10, color: 'var(--text-muted)', marginLeft: 6 }}>{scan.schedule}</span>}
              </button>
            ) : (
              <div style={{ padding: '10px 12px' }}>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>
                  Cron expression (min hour day month weekday)
                </div>
                <div style={{ display: 'flex', gap: 6 }}>
                  <input
                    value={customCron}
                    onChange={e => { setCustomCron(e.target.value); setCustomError(null) }}
                    placeholder="*/30 * * * *"
                    autoFocus
                    onKeyDown={e => { if (e.key === 'Enter' && customCron.trim()) handleSelect(customCron.trim()) }}
                    style={{
                      flex: 1, padding: '6px 8px', borderRadius: 5,
                      border: `1px solid ${customError ? '#dc2626' : 'var(--border)'}`,
                      background: 'var(--bg)', color: 'var(--text-primary)',
                      fontSize: 12, fontFamily: 'monospace', outline: 'none',
                      minWidth: 0,
                    }}
                  />
                  <button
                    onClick={() => customCron.trim() && handleSelect(customCron.trim())}
                    disabled={!customCron.trim() || saving}
                    style={{
                      padding: '6px 10px', borderRadius: 5, border: 'none',
                      background: color, color: '#fff', fontSize: 12, fontWeight: 600,
                      cursor: !customCron.trim() || saving ? 'not-allowed' : 'pointer',
                      opacity: !customCron.trim() || saving ? 0.5 : 1,
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {saving ? '...' : 'Set'}
                  </button>
                </div>
                {customError && (
                  <div style={{ fontSize: 11, color: '#dc2626', marginTop: 4 }}>{customError}</div>
                )}
                <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 6, lineHeight: 1.4 }}>
                  Examples: <code style={{ background: 'var(--bg-secondary)', padding: '1px 3px', borderRadius: 3 }}>*/30 * * * *</code> every 30m,{' '}
                  <code style={{ background: 'var(--bg-secondary)', padding: '1px 3px', borderRadius: 3 }}>0 9,18 * * *</code> 9am & 6pm
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}


// ── Edit & rerun modal (VM scans) ────────────────────────────────────

function EditVmScanModal({ scan, onClose, onSaved }) {
  const toast = useToast()
  const AGENT_CATEGORIES = ['injection', 'xss', 'ssrf', 'authn', 'authz', 'csrf', 'files']
  const origTargets = (scan.raw_metadata?.targets || []).join('\n')
  const origAuthProfileId = scan.raw_metadata?.auth_profile_id || ''
  const origEnableAgents = !!scan.raw_metadata?.enable_agents
  const origAgentCategories = Array.isArray(scan.raw_metadata?.agent_categories)
    ? scan.raw_metadata.agent_categories
    : null
  const [targets, setTargets] = useState(origTargets)
  const [authProfileId, setAuthProfileId] = useState(origAuthProfileId)
  const [authProfiles, setAuthProfiles] = useState([])
  const [saving, setSaving] = useState(false)
  const [enableAgents, setEnableAgents] = useState(origEnableAgents)
  const [agentCategories, setAgentCategories] = useState(origAgentCategories)

  const toggleAgentCategory = (cat) => {
    setAgentCategories(prev => {
      const current = prev || [...AGENT_CATEGORIES]
      return current.includes(cat)
        ? current.filter(c => c !== cat)
        : [...current, cat]
    })
  }

  useEffect(() => {
    import('../../api.js').then(api => api.listAuthProfiles())
      .then(rows => setAuthProfiles(Array.isArray(rows) ? rows : []))
      .catch(() => setAuthProfiles([]))
  }, [])

  const onSave = async () => {
    const parsed = targets.split(/[,\n]+/).map(t => t.trim()).filter(Boolean)
    if (parsed.length === 0) { toast.error('At least one target is required'); return }
    setSaving(true)
    try {
      // Always send enable_agents explicitly so the backend's rescan
      // path can honour an explicit "turn agents OFF" — sending false
      // is meaningful state, not a default. Categories only flow when
      // the user narrowed the selection.
      const payload = {
        targets: parsed,
        auth_profile_id: authProfileId || null,
        enable_agents: enableAgents,
      }
      if (enableAgents && agentCategories && agentCategories.length
          && agentCategories.length < AGENT_CATEGORIES.length) {
        payload.agent_categories = agentCategories
      }
      await rescanVmScan(scan.id, payload)
      toast.success('Scan re-queued with new config')
      onSaved()
    } catch (e) {
      toast.error(e.message || 'Failed to rerun scan')
    } finally {
      setSaving(false)
    }
  }

  return createPortal(
    <div
      style={{
        position: 'fixed', inset: 0, zIndex: 1000,
        background: 'rgba(0,0,0,0.5)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
      }}
      onClick={e => { if (e.target === e.currentTarget) onClose() }}
    >
      <div style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)',
        borderRadius: 14, padding: 28, width: '100%', maxWidth: 520,
        maxHeight: '92vh', overflow: 'auto',
        boxShadow: '0 20px 60px rgba(0,0,0,0.3)',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
          <div style={{ fontWeight: 700, fontSize: 16 }}>Edit &amp; rerun</div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 4 }}>
            <X size={18} />
          </button>
        </div>

        <div style={{
          padding: '12px 14px', borderRadius: 8, marginBottom: 14,
          background: '#ec489908', border: '1px solid #ec489922',
        }}>
          <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 3 }}>Vulnerability Scanner</div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            Updates this scan's config and re-dispatches. Previous findings are cleared.
          </div>
        </div>

        <div style={{ marginBottom: 14 }}>
          <label style={{ fontSize: 12, fontWeight: 600, display: 'block', marginBottom: 6, color: 'var(--text-muted)' }}>
            Target(s) — IP, hostname, or URL
          </label>
          <textarea
            value={targets}
            onChange={e => setTargets(e.target.value)}
            rows={4}
            style={{
              width: '100%', padding: '10px 12px', borderRadius: 8,
              border: '1px solid var(--border)', background: 'var(--bg)',
              color: 'var(--text-primary)', fontSize: 13, fontFamily: 'monospace',
              boxSizing: 'border-box', resize: 'vertical',
            }}
          />
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
            One per line, or comma-separated.
          </div>
        </div>

        <div style={{ marginBottom: 12 }}>
          <label style={{ fontSize: 11, fontWeight: 600, display: 'block', marginBottom: 4, color: 'var(--text-muted)' }}>
            Auth profile (optional)
          </label>
          <select
            value={authProfileId}
            onChange={e => setAuthProfileId(e.target.value)}
            style={{
              width: '100%', padding: '7px 10px', fontSize: 12,
              background: 'var(--bg-card)', color: 'var(--text-primary)',
              border: '1px solid var(--border)', borderRadius: 6,
            }}
          >
            <option value="">None — unauthenticated scan</option>
            {authProfiles.map(p => (
              <option key={p.id} value={p.id}>
                {p.name} ({p.profile_type === 'static' ? 'static' : 'form login'})
              </option>
            ))}
          </select>
        </div>

        <div style={{
          marginBottom: 12, padding: '10px 12px', borderRadius: 8,
          background: 'var(--bg-secondary)', border: '1px solid var(--border)',
        }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={enableAgents}
              onChange={e => setEnableAgents(e.target.checked)}
            />
            <span style={{ fontSize: 12, fontWeight: 600 }}>Run specialist agents (LLM)</span>
          </label>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4, marginLeft: 22 }}>
            Runs five LLM specialists (Injection, XSS, SSRF, AuthN, AuthZ) per asset.
            Cost: LLM tokens. Best on assets with discovered endpoints.
          </div>
          {enableAgents && (
            <div style={{ marginTop: 10, marginLeft: 22, display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {AGENT_CATEGORIES.map(cat => {
                const selected = !agentCategories || agentCategories.includes(cat)
                return (
                  <button
                    key={cat}
                    onClick={() => toggleAgentCategory(cat)}
                    style={{
                      fontSize: 11, padding: '3px 10px', borderRadius: 12, cursor: 'pointer',
                      background: selected ? '#ec489922' : 'transparent',
                      border: `1px solid ${selected ? '#ec4899' : 'var(--border)'}`,
                      color: selected ? '#ec4899' : 'var(--text-muted)',
                      fontWeight: 600,
                    }}
                  >
                    {cat}
                  </button>
                )
              })}
            </div>
          )}
        </div>

        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
          <Button onClick={onSave} disabled={saving} style={{ background: '#ec4899' }}>
            <Save size={14} /> {saving ? 'Saving…' : 'Save & Rerun'}
          </Button>
        </div>
      </div>
    </div>,
    document.body,
  )
}


// ── Audit scan history + edit modal ──────────────────────────────────

function AuditScanHistory({ expanded, scanId }) {
  // Lazy-load: we only hit /audits/scans/{id}/history when the panel opens.
  // Avoids a per-card fetch on the scan list page.
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState(null)
  const [traceTarget, setTraceTarget] = useState(null)  // {agentId, runId, label}

  useEffect(() => {
    if (!expanded) return
    setLoading(true)
    setErr(null)
    getAuditScanHistory(scanId)
      .then(setData)
      .catch(e => setErr(e.message || 'Failed to load history'))
      .finally(() => setLoading(false))
  }, [expanded, scanId])

  if (!expanded) return null

  const statusColor = (s) => {
    if (s === 'done') return '#22c55e'
    if (s === 'failed' || s === 'error') return '#dc2626'
    if (s === 'running' || s === 'pending') return '#0ea5e9'
    if (s === 'awaiting_approval') return '#f59e0b'
    return '#71717a'
  }
  const statusLabel = (s) => {
    if (s === 'done') return 'ok'
    if (s === 'awaiting_approval') return 'approval'
    return s || 'unknown'
  }

  const runs = (data?.runs) || []
  const total = runs.length
  const completed = runs.filter(r => r.status === 'done' || r.status === 'failed' || r.status === 'error').length
  const totalFindings = runs.reduce((sum, r) => sum + (r.findings_count || 0), 0)

  return (
    <div style={{
      borderTop: '1px solid var(--border)', padding: '10px 16px 6px',
      background: 'var(--bg-secondary)',
    }}>
      <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 8 }}>
        <History size={11} style={{ marginRight: 4, verticalAlign: -1 }} />
        Scan Details
      </div>

      {loading && <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Loading...</div>}
      {err && <div style={{ fontSize: 11, color: '#dc2626' }}>{err}</div>}
      {!loading && total === 0 && (
        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>No runs recorded yet.</div>
      )}

      {!loading && total > 0 && (
        <>
          {/* Summary row — mirrors VM scan summary */}
          <div style={{
            display: 'flex', gap: 10, alignItems: 'center', fontSize: 12,
            padding: '5px 8px', borderRadius: 5, background: 'var(--bg)',
            border: '1px solid var(--border)', marginBottom: 4,
          }}>
            <span style={{ color: 'var(--text-muted)', flex: 1 }}>
              {completed}/{total} runs done
            </span>
            <span style={{ color: 'var(--text-muted)' }}>
              {totalFindings} finding{totalFindings !== 1 ? 's' : ''}
            </span>
          </div>

          {/* Per-run rows — same shape as VM target rows */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 2, marginBottom: 4 }}>
            {runs.map(r => {
              const label = r.asset_label || (r.asset_id ? `asset ${r.asset_id}` : 'asset ?')
              const mission = [r.protocol, r.mission].filter(Boolean).join('/')
              const meta = []
              if (r.findings_count != null) meta.push(`${r.findings_count} finding${r.findings_count !== 1 ? 's' : ''}`)
              if (r.steps_used != null) meta.push(`${r.steps_used} step${r.steps_used !== 1 ? 's' : ''}`)
              if (r.duration_s != null) meta.push(`${r.duration_s}s`)
              const traceLabel = `${label} — ${mission || 'audit'}`
              return (
                <div key={r.agent_run_id} style={{ display: 'flex', flexDirection: 'column' }}>
                  <div style={{
                    display: 'flex', gap: 8, alignItems: 'center', fontSize: 11,
                    padding: '4px 8px', borderRadius: 4,
                    color: 'var(--text-muted)',
                  }}>
                    <span style={{
                      width: 6, height: 6, borderRadius: '50%', flexShrink: 0,
                      background: statusColor(r.status),
                    }} />
                    <span style={{ fontFamily: 'monospace', fontWeight: 500, color: 'var(--text-secondary)', flex: 1 }}>
                      {label}
                      {mission && (
                        <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}> — {mission}</span>
                      )}
                    </span>
                    <span style={{ fontSize: 10, color: statusColor(r.status), fontWeight: 500 }}>
                      {statusLabel(r.status)}
                    </span>
                    {meta.length > 0 && (
                      <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                        {meta.join(' · ')}
                      </span>
                    )}
                    <button
                      onClick={() => setTraceTarget({ agentId: r.agent_id, runId: r.agent_run_id, label: traceLabel })}
                      style={{
                        fontSize: 10, padding: '2px 6px', borderRadius: 3,
                        background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                        color: 'var(--text-secondary)', cursor: 'pointer',
                      }}
                      title="View agent trace"
                    >
                      Trace
                    </button>
                  </div>
                  {r.error && (
                    <div style={{
                      margin: '0 8px 2px 22px', padding: '4px 8px',
                      borderRadius: 4, background: '#fef2f2',
                      border: '1px solid #fecaca', fontSize: 10,
                      color: '#991b1b', fontFamily: 'monospace',
                      whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                    }}>
                      {r.error}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </>
      )}

      {traceTarget && (
        <AuditTraceModal
          agentId={traceTarget.agentId}
          runId={traceTarget.runId}
          label={traceTarget.label}
          onClose={() => setTraceTarget(null)}
        />
      )}
    </div>
  )
}


function AuditTraceModal({ agentId, runId, label, onClose }) {
  const [run, setRun] = useState(null)
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState(null)

  useEffect(() => {
    setLoading(true)
    setErr(null)
    getAgentRun(agentId, runId)
      .then(setRun)
      .catch(e => setErr(e.message || 'Failed to load trace'))
      .finally(() => setLoading(false))
  }, [agentId, runId])

  const trace = Array.isArray(run?.trace) ? run.trace : []

  return createPortal(
    <div
      onClick={onClose}
      style={{
        position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.4)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 10000,
      }}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{
          background: 'var(--bg)', borderRadius: 8, padding: 16,
          width: 760, maxWidth: '92vw', maxHeight: '85vh',
          display: 'flex', flexDirection: 'column',
          border: '1px solid var(--border)',
        }}
      >
        <div style={{
          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          marginBottom: 10, paddingBottom: 8, borderBottom: '1px solid var(--border)',
        }}>
          <div>
            <div style={{ fontSize: 13, fontWeight: 600 }}>Agent Trace</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{label}</div>
          </div>
          <button onClick={onClose} style={{
            background: 'none', border: 'none', cursor: 'pointer',
            color: 'var(--text-muted)', padding: 2,
          }}><X size={16} /></button>
        </div>
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {loading && <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Loading trace...</div>}
          {err && <div style={{ fontSize: 12, color: '#dc2626' }}>{err}</div>}
          {!loading && !err && trace.length === 0 && (
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>No trace recorded.</div>
          )}
          {!loading && trace.length > 0 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {trace.map((entry, i) => (
                <div key={i} style={{
                  padding: 8, borderRadius: 6, fontSize: 12, fontFamily: 'monospace',
                  background: entry.role === 'tool' ? '#1a1a2e' : 'var(--bg-secondary)',
                  border: '1px solid var(--border)',
                }}>
                  <div style={{
                    fontWeight: 600,
                    color: entry.role === 'tool' ? '#818cf8' : 'var(--accent)',
                    marginBottom: 4,
                  }}>
                    {entry.role === 'tool'
                      ? `tool: ${entry.tool_name || '?'}`
                      : `assistant${entry.step != null ? ` (step ${entry.step})` : ''}`}
                  </div>
                  <pre style={{
                    margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                    color: entry.role === 'tool' ? '#e2e8f0' : 'var(--text-secondary)',
                    maxHeight: 240, overflow: 'auto',
                  }}>
                    {entry.role === 'tool'
                      ? (typeof entry.output === 'string'
                          ? entry.output
                          : JSON.stringify(entry.output, null, 2))
                      : (Array.isArray(entry.content)
                          ? entry.content.map(b => b.type === 'text'
                              ? b.text
                              : `[tool_use: ${b.name}(${JSON.stringify(b.input)})]`).join('\n')
                          : (typeof entry.content === 'string' ? entry.content : JSON.stringify(entry.content, null, 2)))}
                  </pre>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>,
    document.body,
  )
}


function EditAuditScanModal({ scan, onClose, onSaved }) {
  // Reuse AuditScanPanel so the edit form has the same UX as the new-scan
  // form: mission picker with description, inline "+ New" credential, connected
  // relay list, Enter-Target / Select-Assets tabs with the actual picker,
  // max_steps + wall-clock inputs. Users don't learn two forms.
  const protocol = (scan.raw_metadata || {}).protocol
    || (scan.scan_type || '').replace('_audit', '')
  const friendlyLabel = AUDIT_CARD_META[protocol]?.label || `${(protocol || '').toUpperCase()} Audit`

  return createPortal(
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.4)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 10000,
    }} onClick={onClose}>
      <div onClick={e => e.stopPropagation()} style={{
        background: 'var(--bg)', borderRadius: 8, padding: 20,
        width: 520, maxWidth: '90vw', maxHeight: '85vh', overflow: 'auto',
        border: '1px solid var(--border)',
      }}>
        <div style={{
          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          marginBottom: 14,
        }}>
          <div style={{ fontSize: 15, fontWeight: 600 }}>Edit {friendlyLabel}</div>
          <button onClick={onClose} style={{
            background: 'none', border: 'none', cursor: 'pointer',
            color: 'var(--text-muted)', padding: 2,
          }}><X size={16} /></button>
        </div>
        <AuditScanPanel
          editScan={scan}
          preselectedProtocol={protocol}
          onClose={onClose}
          onBack={onClose}
          onAuditScan={() => onSaved && onSaved()}
        />
      </div>
    </div>,
    document.body,
  )
}


// ── Scan card ────────────────────────────────────────────────────────

function ScanCard({ scan, onDelete, deleting, onSelect, onRescan, onRefresh, onCancel, cancelling }) {
  const meta = getSourceMeta(scan.source_type)
  const isEasm = scan.source_type === 'easm'
  const isVm = scan.source_type === 'vm_scanner'
  // Audit scans all share the `*_audit` convention (snmp_audit, ssh_audit, ...).
  // Detect on source_type or scan_type — dispatch sets both but older rows may
  // only have scan_type populated.
  const isAudit = (scan.source_type || '').endsWith('_audit')
    || (scan.scan_type || '').endsWith('_audit')
  // Reuse all the "has runtime status + schedule + rescan" plumbing across
  // EASM/VM/Audit. The only thing that differs is which endpoint each button hits.
  const isScheduleable = isEasm || isVm || isAudit
  const lastRunAt = scan.last_run_at || scan.created_at
  const age = lastRunAt ? formatAge(lastRunAt) : null
  const domain = isEasm ? scan.raw_metadata?.domain : null
  // Audit scans stamp the runtime status on scan.status (column) rather than
  // raw_metadata.status. Read both so audits light up "running" the same way
  // EASM/VM do.
  const scanStatus = isScheduleable
    ? (scan.raw_metadata?.status || (isAudit ? scan.status : null))
    : null
  const easmStatus = scanStatus  // keep compat
  const isRunning = scanStatus === 'running' || scanStatus === 'queued'
  const canCancel = isRunning && (isEasm || isVm || isAudit)
  const [showHistory, setShowHistory] = useState(false)
  const [rescanning, setRescanning] = useState(false)
  const [editOpen, setEditOpen] = useState(false)
  const toast = useToast()

  return (
    <div style={{
      borderBottom: '1px solid var(--border)',
      transition: 'background 0.1s',
    }}
    >
      <div style={{ padding: '14px 16px' }}
        onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-secondary)'}
        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
      >
        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          <div style={{
            width: 36, height: 36, borderRadius: 8, flexShrink: 0,
            background: meta.bg, display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <meta.icon size={18} color={meta.color} />
          </div>

          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3 }}>
              <span
                style={{ fontWeight: 600, fontSize: 14, cursor: 'pointer', color: 'var(--text-primary)' }}
                onClick={() => onSelect(scan.id)}
              >
                {getDisplayScanName(scan)}
              </span>
              <SourceBadge sourceType={scan.source_type} />
              {isScheduleable && <EasmStatusBadge status={scanStatus || scan.status} metadata={scan.raw_metadata} />}
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              {age && <span><Clock size={11} style={{ marginRight: 3, verticalAlign: -1 }} />{age}</span>}
              <span><Server size={11} style={{ marginRight: 3, verticalAlign: -1 }} />{scan.asset_count || 0} assets</span>
              <span><Shield size={11} style={{ marginRight: 3, verticalAlign: -1 }} />{(scan.finding_count || 0).toLocaleString()} findings</span>
              {scan.source_version && <span>{scan.source_version}</span>}
              {scan.schedule && (
                <span style={{ color: '#0ea5e9' }}>
                  <RefreshCw size={11} style={{ marginRight: 3, verticalAlign: -1 }} />
                  {getScheduleLabel(scan.schedule)}
                  {scan.run_count > 0 && ` (${scan.run_count} runs)`}
                </span>
              )}
              {scan.next_run_at && (
                <span>Next: {formatAge(scan.next_run_at)}</span>
              )}
            </div>
          </div>

          <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexShrink: 0 }}>
            {isScheduleable && (
              <ScheduleDropdown scan={scan} onUpdate={onRefresh} />
            )}
            {isScheduleable && (
              <button
                onClick={() => setShowHistory(h => !h)}
                title="Scan history"
                style={{
                  background: 'none', border: '1px solid var(--border)',
                  borderRadius: 6, padding: '5px 8px', cursor: 'pointer',
                  color: showHistory ? (isVm ? '#ec4899' : '#0ea5e9') : 'var(--text-muted)',
                  borderColor: showHistory ? (isVm ? '#ec4899' : '#0ea5e9') : 'var(--border)',
                  display: 'flex', alignItems: 'center', gap: 3, fontSize: 12,
                  transition: 'all 0.15s',
                }}
                onMouseEnter={e => { if (!showHistory) { const c = isVm ? '#ec489944' : '#0ea5e944'; e.currentTarget.style.borderColor = c; e.currentTarget.style.color = isVm ? '#ec4899' : '#0ea5e9' }}}
                onMouseLeave={e => { if (!showHistory) { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-muted)' }}}
              >
                <History size={12} />
                {showHistory ? <ChevronUp size={10} /> : <ChevronDown size={10} />}
              </button>
            )}
            {isEasm && domain && onRescan && !isRunning && (
              <button
                disabled={rescanning}
                onClick={async () => {
                  setRescanning(true)
                  try { await onRescan(scan.id) } finally { setRescanning(false) }
                }}
                title={`Rescan ${domain}`}
                style={{
                  background: 'none', border: '1px solid var(--border)',
                  borderRadius: 6, padding: '5px 8px', cursor: rescanning ? 'wait' : 'pointer',
                  color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 4, fontSize: 12,
                  transition: 'all 0.15s', opacity: rescanning ? 0.5 : 1,
                }}
                onMouseEnter={e => { if (!rescanning) { e.currentTarget.style.borderColor = '#0ea5e9'; e.currentTarget.style.color = '#0ea5e9' }}}
                onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-muted)' }}
              >
                <RefreshCw size={12} style={rescanning ? { animation: 'spin 1s linear infinite' } : undefined} />
              </button>
            )}
            {isVm && !isRunning && (
              <button
                onClick={() => setEditOpen(true)}
                title="Edit & rerun (targets, auth profile)"
                style={{
                  background: 'none', border: '1px solid var(--border)',
                  borderRadius: 6, padding: '5px 8px', cursor: 'pointer',
                  color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 4, fontSize: 12,
                  transition: 'all 0.15s',
                }}
                onMouseEnter={e => { e.currentTarget.style.borderColor = '#ec4899'; e.currentTarget.style.color = '#ec4899' }}
                onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-muted)' }}
              >
                <Edit2 size={12} />
              </button>
            )}
            {isVm && !isRunning && (
              <button
                disabled={rescanning}
                onClick={async () => {
                  setRescanning(true)
                  try {
                    await rescanVmScan(scan.id)
                    if (onRefresh) await onRefresh()
                  } catch (err) {
                    toast.error(err?.message || 'Failed to rescan')
                  } finally { setRescanning(false) }
                }}
                title="Rescan targets"
                style={{
                  background: 'none', border: '1px solid var(--border)',
                  borderRadius: 6, padding: '5px 8px', cursor: rescanning ? 'wait' : 'pointer',
                  color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 4, fontSize: 12,
                  transition: 'all 0.15s', opacity: rescanning ? 0.5 : 1,
                }}
                onMouseEnter={e => { if (!rescanning) { e.currentTarget.style.borderColor = '#ec4899'; e.currentTarget.style.color = '#ec4899' }}}
                onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-muted)' }}
              >
                <RefreshCw size={12} style={rescanning ? { animation: 'spin 1s linear infinite' } : undefined} />
              </button>
            )}
            {isAudit && !isRunning && (
              <button
                onClick={() => setEditOpen(true)}
                title="Edit & rerun (mission, targets, credential)"
                style={{
                  background: 'none', border: '1px solid var(--border)',
                  borderRadius: 6, padding: '5px 8px', cursor: 'pointer',
                  color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 4, fontSize: 12,
                  transition: 'all 0.15s',
                }}
                onMouseEnter={e => { e.currentTarget.style.borderColor = '#0ea5e9'; e.currentTarget.style.color = '#0ea5e9' }}
                onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-muted)' }}
              >
                <Edit2 size={12} />
              </button>
            )}
            {isAudit && !isRunning && (
              <button
                disabled={rescanning}
                onClick={async () => {
                  setRescanning(true)
                  try {
                    await rescanAuditScan(scan.id)
                    if (onRefresh) await onRefresh()
                  } catch (err) {
                    // Surface 503 (worker not running) + 4xx dispatch errors
                    // to the user instead of dropping into an unhandled promise
                    // rejection. The backend's 503 message already tells them
                    // how to fix it ("docker compose --profile audits up -d").
                    toast.error(err?.message || 'Failed to rerun audit')
                  } finally { setRescanning(false) }
                }}
                title="Rerun audit"
                style={{
                  background: 'none', border: '1px solid var(--border)',
                  borderRadius: 6, padding: '5px 8px', cursor: rescanning ? 'wait' : 'pointer',
                  color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 4, fontSize: 12,
                  transition: 'all 0.15s', opacity: rescanning ? 0.5 : 1,
                }}
                onMouseEnter={e => { if (!rescanning) { e.currentTarget.style.borderColor = '#0ea5e9'; e.currentTarget.style.color = '#0ea5e9' }}}
                onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-muted)' }}
              >
                <RefreshCw size={12} style={rescanning ? { animation: 'spin 1s linear infinite' } : undefined} />
              </button>
            )}
            {editOpen && isVm && (
              <EditVmScanModal
                scan={scan}
                onClose={() => setEditOpen(false)}
                onSaved={async () => { setEditOpen(false); if (onRefresh) await onRefresh() }}
              />
            )}
            {editOpen && isAudit && (
              <EditAuditScanModal
                scan={scan}
                onClose={() => setEditOpen(false)}
                onSaved={async () => { setEditOpen(false); if (onRefresh) await onRefresh() }}
              />
            )}
            {canCancel && (
              cancelling ? (
                <Spinner size={16} />
              ) : (
                <button
                  onClick={() => onCancel(scan.id)}
                  title="Stop scan"
                  style={{
                    background: 'none', border: '1px solid var(--border)',
                    borderRadius: 6, padding: '5px 8px', cursor: 'pointer',
                    color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 4, fontSize: 12,
                    transition: 'all 0.15s',
                  }}
                  onMouseEnter={e => { e.currentTarget.style.borderColor = '#dc2626'; e.currentTarget.style.color = '#dc2626' }}
                  onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-muted)' }}
                >
                  <Square size={11} fill="currentColor" />
                  Stop
                </button>
              )
            )}
            <Button size="sm" onClick={() => onSelect(scan.id)}>View</Button>
            {deleting ? (
              <Spinner size={16} />
            ) : (
              <button
                onClick={() => onDelete(scan.id)}
                title="Delete scan"
                style={{
                  background: 'none', border: 'none', cursor: 'pointer',
                  color: 'var(--text-muted)', padding: 4, transition: 'color 0.15s',
                }}
                onMouseEnter={e => e.currentTarget.style.color = '#dc2626'}
                onMouseLeave={e => e.currentTarget.style.color = 'var(--text-muted)'}
              >
                <Trash2 size={15} />
              </button>
            )}
          </div>
        </div>
      </div>
      {isEasm && isRunning && <ScanProgressBar metadata={scan.raw_metadata} />}
      {isVm && isRunning && <VmScanProgress metadata={scan.raw_metadata} />}
      {isEasm && <ScanRunHistory expanded={showHistory} domain={domain} />}
      {isVm && <VmScanHistory expanded={showHistory} metadata={scan.raw_metadata} />}
      {isAudit && <AuditScanHistory expanded={showHistory} scanId={scan.id} />}
    </div>
  )
}


// ── Helpers ──────────────────────────────────────────────────────────

function getDisplayScanName(scan) {
  // Audit scans are created on the backend with the registry's bare label
  // ("WMI Audit — Identity Audit — 1 host(s)"). The frontend has a friendlier
  // outcome-oriented naming in AUDIT_CARD_META ("Endpoint Audit (WMI)") used
  // everywhere else — on the New Scan cards, in the scan-type filter, etc.
  // Unify by rewriting audit scan names at render time so the list reads the
  // same language users see in the picker. Non-audit scans pass through.
  const scanType = scan.scan_type || ''
  const isAudit = scanType.endsWith('_audit') || (scan.source_type || '').endsWith('_audit')
  if (!isAudit) return scan.scan_name || scan.filename
  const md = scan.raw_metadata || {}
  const protocol = md.protocol || scanType.replace('_audit', '')
  const friendly = AUDIT_CARD_META[protocol]?.label
  if (!friendly) return scan.scan_name || scan.filename
  // Extract the mission sub-label from the backend-built name if present:
  //   "WMI Audit — Identity Audit — 1 host(s)" → "Identity Audit"
  const backendName = scan.scan_name || ''
  const parts = backendName.split('—').map(p => p.trim()).filter(Boolean)
  const missionLabel = parts.length >= 2 ? parts[1] : null
  const hostCount = scan.asset_count ?? (md.asset_ids?.length || 0)
  return missionLabel
    ? `${friendly} — ${missionLabel} — ${hostCount} host${hostCount === 1 ? '' : 's'}`
    : `${friendly} — ${hostCount} host${hostCount === 1 ? '' : 's'}`
}


function formatAge(isoDate) {
  // Backend stores UTC times without 'Z' suffix — ensure correct parsing
  const d = new Date(isoDate.endsWith('Z') ? isoDate : isoDate + 'Z')
  const now = new Date()
  const diffMs = now - d
  if (diffMs < 0) {
    // Future date — show "in X"
    const mins = Math.floor(-diffMs / 60000)
    if (mins < 1) return 'in <1m'
    if (mins < 60) return `in ${mins}m`
    const hrs = Math.floor(mins / 60)
    if (hrs < 24) return `in ${hrs}h`
    const days = Math.floor(hrs / 24)
    if (days < 30) return `in ${days}d`
    return d.toLocaleDateString()
  }
  const mins = Math.floor(diffMs / 60000)
  if (mins < 1) return 'Just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  const days = Math.floor(hrs / 24)
  if (days < 30) return `${days}d ago`
  return d.toLocaleDateString()
}

// ── Main component ───────────────────────────────────────────────────

export default function ScanManagement() {
  const { scans, scansLoaded, refreshScans, setActiveScanId } = useScan()
  const navigate = useNavigate()
  const confirm = useConfirm()
  const toast = useToast()

  const [uploads, setUploads] = useState([])
  const [deletingId, setDeletingId] = useState(null)
  const [cancellingId, setCancellingId] = useState(null)
  const [showNewScan, setShowNewScan] = useState(false)
  const { filters, setFilter, clearFilters: clearURLFilters } = useURLFilters({
    source: { default: '' },
    status: { default: '' },
    time: { default: '' },
    schedule: { default: '' },
    q: { default: '' },
  })
  const sourceFilter = filters.source
  const statusFilter = filters.status
  const timeFilter = filters.time
  const scheduleFilter = filters.schedule
  const search = filters.q
  const [easmStatus, setEasmStatus] = useState(null)

  // Refresh scans on mount to avoid stale-context race on first login
  useEffect(() => {
    refreshScans()
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  // Load EASM status on mount
  useEffect(() => {
    getEasmStatus()
      .then(setEasmStatus)
      .catch(() => setEasmStatus(null))
  }, [])

  // Poll running EASM / VM scans — refresh their status.
  //
  // Cadence:
  //   - Running scan(s) → 3s. Both pipelines now import incrementally (VM
  //     per Celery job, EASM via the incremental_since watermark), so at 3s
  //     a new target / new enrichment stage surfaces quickly without
  //     flooding the scanner services.
  //   - Queued scan(s) with no running scan → 10s. Queued scans don't
  //     produce data yet, so fast polling buys nothing.
  //   - Scan running > 10 min → 8s. Long-running scans are usually
  //     bottlenecked on external scanning, not on our backend; avoids
  //     pointless load for a user leaving the tab open overnight.
  useEffect(() => {
    const runningEasm = scans.filter(s =>
      s.source_type === 'easm' &&
      s.raw_metadata?.status &&
      (s.raw_metadata.status === 'running' || s.raw_metadata.status === 'queued')
    )
    const runningVm = scans.filter(s =>
      s.source_type === 'vm_scanner' &&
      s.raw_metadata?.status === 'running'
    )
    if (runningEasm.length === 0 && runningVm.length === 0) return

    const anyActivelyRunning = scans.some(s =>
      (s.source_type === 'easm' || s.source_type === 'vm_scanner') &&
      s.raw_metadata?.status === 'running'
    )
    // Age of the oldest running scan — used to back off on long jobs.
    const now = Date.now()
    const oldestRunningAgeMs = scans.reduce((max, s) => {
      const isRunning = s.raw_metadata?.status === 'running'
      if (!isRunning || !s.scan_date) return max
      // Backend stores UTC without 'Z' — align with formatAge() below.
      const d = new Date(s.scan_date.endsWith('Z') ? s.scan_date : s.scan_date + 'Z')
      return Math.max(max, now - d.getTime())
    }, 0)

    const pollMs = !anyActivelyRunning
      ? 10000
      : oldestRunningAgeMs > 10 * 60 * 1000
        ? 8000
        : 3000

    let polling = false
    const interval = setInterval(async () => {
      if (polling) return  // Skip if previous poll is still in-flight
      polling = true
      try {
        for (const s of runningEasm) {
          try { await refreshEasmScan(s.id) } catch { /* ignore */ }
        }
        for (const s of runningVm) {
          try { await refreshVmScan(s.id) } catch { /* ignore */ }
        }
        await refreshScans()
      } finally {
        polling = false
      }
    }, pollMs)
    return () => clearInterval(interval)
  }, [scans, refreshScans])

  // ── Handlers ─────────────────────────────────────────────────────

  const handleFile = async (file) => {
    const id = Date.now()
    setUploads(prev => [...prev, { id, file, status: 'uploading', result: null, error: null }])
    try {
      const result = await uploadScan(file)

      if (result.status === 'processing') {
        setUploads(prev => prev.map(u => u.id === id ? { ...u, status: 'processing' } : u))
        await refreshScans()

        let attempts = 0
        while (attempts < 120) {
          await new Promise(r => setTimeout(r, 3000))
          const statusData = await getScanStatus(result.scan_id)
          if (statusData.status !== 'processing') {
            const finalResult = {
              scan_id: result.scan_id,
              scan_name: statusData.scan_name,
              assets: statusData.asset_count,
              findings: statusData.finding_count,
            }
            if (statusData.status === 'failed') {
              setUploads(prev => prev.map(u => u.id === id ? { ...u, status: 'error', error: 'Scan processing failed' } : u))
            } else {
              setUploads(prev => prev.map(u => u.id === id ? { ...u, status: 'done', result: finalResult } : u))
              await refreshScans()
              setActiveScanId(result.scan_id)
            }
            return
          }
          attempts++
          if (attempts % 5 === 0) await refreshScans()
        }
        setUploads(prev => prev.map(u => u.id === id ? { ...u, status: 'error', error: 'Processing timed out' } : u))
      } else {
        setUploads(prev => prev.map(u => u.id === id ? { ...u, status: 'done', result } : u))
        await refreshScans()
        setActiveScanId(result.scan_id)
      }
    } catch (err) {
      setUploads(prev => prev.map(u => u.id === id ? { ...u, status: 'error', error: err.message } : u))
    }
  }

  const handleDelete = async (scanId) => {
    if (!await confirm('Delete this scan and all its data?')) return
    setDeletingId(scanId)
    try {
      await deleteScan(scanId)
      await refreshScans()
      toast.success('Scan deleted')
    } finally {
      setDeletingId(null)
    }
  }

  const handleCancel = async (scanId) => {
    if (!await confirm('Stop this scan? In-flight jobs will be revoked.')) return
    setCancellingId(scanId)
    try {
      await cancelScan(scanId)
      await refreshScans()
      toast.success('Scan stopped')
    } catch (err) {
      toast.error(err?.message || 'Failed to stop scan')
    } finally {
      setCancellingId(null)
    }
  }

  const handleSelectScan = (scanId) => {
    setActiveScanId(scanId)
    navigate('/')
  }

  const handleScanDomain = async (domain, scanType) => {
    const result = await scanEasmDomain(domain, scanType)
    await refreshScans()
    if (result?.scan_id) {
      setActiveScanId(result.scan_id)
      // Jump to the live findings view so users watch results stream in
      // instead of staring at the scan-management list.
      navigate(`/findings?scan_id=${result.scan_id}`)
    }
    setShowNewScan(false)
    // Refresh EASM status in case it changed
    getEasmStatus().then(setEasmStatus).catch(() => {})
  }

  // After a VM scan is queued, drop straight into the live findings view
  // filtered by the new scan_id. Findings arrive per completed job (see
  // refresh_vm_scan), so the explorer populates incrementally as they land.
  const handleNewVmScan = async (res) => {
    await refreshScans()
    if (res?.scan_id) {
      setActiveScanId(res.scan_id)
      navigate(`/findings?scan_id=${res.scan_id}`)
    }
    setShowNewScan(false)
  }

  // Authenticated audits kick off N background agent runs + write findings
  // as they emit. Like VM scans, the scan id is the entry point — we drop
  // into the findings view filtered by it so results appear as the agents
  // surface them.
  const handleNewAuditScan = async (res) => {
    await refreshScans()
    if (res?.scan_id) {
      setActiveScanId(res.scan_id)
      navigate(`/findings?scan_id=${res.scan_id}`)
    }
    setShowNewScan(false)
  }

  const handleRescanDomain = async (scanId) => {
    try {
      await rescanEasmScan(scanId, 'full')
    } catch (err) {
      console.error('Rescan failed:', err)
    }
    await refreshScans()
  }

  const handleSetupEasm = async (domain) => {
    await setupEasm(domain)
    const status = await getEasmStatus()
    setEasmStatus(status)
    await refreshScans()
  }

  // ── Filter & search ──────────────────────────────────────────────

  const sourceTypes = [...new Set(scans.map(s => s.source_type || 'file_import'))].sort()

  // Normalize status across source types. File-imported scans (Nessus, Qualys,
  // Rapid7, OpenVAS, etc.) don't carry a runtime status, so treat them as
  // completed. EASM and VM scanner scans persist a status on raw_metadata.
  const getNormalizedStatus = (s) => {
    const isEasm = s.source_type === 'easm'
    const isVm = s.source_type === 'vm_scanner'
    // Audit scans (`*_audit`) carry their runtime status on scan.status rather
    // than raw_metadata.status, because audit_runner stamps the column directly.
    // Fall through to the same state machine so the filter UI treats them the
    // same as EASM/VM.
    const isAudit = (s.source_type || '').endsWith('_audit')
      || (s.scan_type || '').endsWith('_audit')
    if (!isEasm && !isVm && !isAudit) return 'completed'
    const raw = (isAudit ? (s.status || s.raw_metadata?.status) : s.raw_metadata?.status) || 'unknown'
    if (raw === 'running' || raw === 'queued') return raw
    if (raw === 'failed' || raw === 'error') return 'failed'
    if (raw === 'completed_with_errors') return 'partial'
    if (raw === 'completed' || raw === 'done') return 'completed'
    return raw
  }

  const TIME_WINDOWS = {
    '24h': 24 * 60 * 60 * 1000,
    '7d': 7 * 24 * 60 * 60 * 1000,
    '30d': 30 * 24 * 60 * 60 * 1000,
    '90d': 90 * 24 * 60 * 60 * 1000,
  }

  const now = Date.now()
  const filteredScans = scans.filter(s => {
    const st = s.source_type || 'file_import'
    if (sourceFilter && st !== sourceFilter) return false
    if (statusFilter && getNormalizedStatus(s) !== statusFilter) return false
    if (scheduleFilter === 'scheduled' && !s.schedule) return false
    if (scheduleFilter === 'manual' && s.schedule) return false
    if (timeFilter && TIME_WINDOWS[timeFilter]) {
      const iso = s.last_run_at || s.created_at
      if (!iso) return false
      const t = new Date(iso.endsWith('Z') ? iso : iso + 'Z').getTime()
      if (isNaN(t) || now - t > TIME_WINDOWS[timeFilter]) return false
    }
    if (search) {
      const q = search.toLowerCase()
      const name = (s.scan_name || s.filename || '').toLowerCase()
      const domain = (s.raw_metadata?.domain || '').toLowerCase()
      if (!name.includes(q) && !domain.includes(q)) return false
    }
    return true
  })

  const activeFilterCount =
    (sourceFilter ? 1 : 0) +
    (statusFilter ? 1 : 0) +
    (timeFilter ? 1 : 0) +
    (scheduleFilter ? 1 : 0)

  const clearFilters = () => clearURLFilters()

  const selectStyle = (hasValue) => ({
    background: 'var(--bg-secondary)',
    border: '1px solid var(--border)',
    color: hasValue ? 'var(--text-primary)' : 'var(--text-muted)',
    borderRadius: 6,
    padding: '6px 10px',
    fontSize: 12,
    fontWeight: 500,
    cursor: 'pointer',
    outline: 'none',
  })

  return (
    <div style={{ maxWidth: 900 }}>
      <PageHeader
        title="Scans"
        subtitle="Manage vulnerability scans from all sources"
        action={
          <Button onClick={() => setShowNewScan(true)}>
            <Plus size={15} /> New Scan
          </Button>
        }
      />

      {/* Filters bar */}
      <Card style={{ marginBottom: 16, padding: '12px 16px' }}>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
          <div style={{
            display: 'flex', alignItems: 'center', gap: 6,
            padding: '5px 10px', borderRadius: 6,
            border: '1px solid var(--border)', background: 'var(--bg)',
            minWidth: 220, flex: '1 1 220px',
          }}>
            <Search size={13} color="var(--text-muted)" />
            <input
              value={search}
              onChange={e => setFilter('q', e.target.value)}
              placeholder="Search scans..."
              style={{
                border: 'none', background: 'transparent', color: 'var(--text-primary)',
                fontSize: 12, outline: 'none', width: '100%',
              }}
            />
            {search && (
              <button onClick={() => setFilter('q', '')} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 0 }}>
                <X size={12} />
              </button>
            )}
          </div>

          <select
            value={sourceFilter}
            onChange={e => setFilter('source', e.target.value)}
            style={selectStyle(!!sourceFilter)}
            title="Filter by source"
          >
            <option value="">All sources</option>
            {sourceTypes.map(st => (
              <option key={st} value={st}>{getSourceMeta(st).label}</option>
            ))}
          </select>

          <select
            value={statusFilter}
            onChange={e => setFilter('status', e.target.value)}
            style={selectStyle(!!statusFilter)}
            title="Filter by status"
          >
            <option value="">All statuses</option>
            <option value="running">Running</option>
            <option value="queued">Queued</option>
            <option value="completed">Completed</option>
            <option value="partial">Partial</option>
            <option value="failed">Failed</option>
            <option value="cancelled">Cancelled</option>
          </select>

          <select
            value={timeFilter}
            onChange={e => setFilter('time', e.target.value)}
            style={selectStyle(!!timeFilter)}
            title="Filter by last run"
          >
            <option value="">Any time</option>
            <option value="24h">Last 24 hours</option>
            <option value="7d">Last 7 days</option>
            <option value="30d">Last 30 days</option>
            <option value="90d">Last 90 days</option>
          </select>

          <select
            value={scheduleFilter}
            onChange={e => setFilter('schedule', e.target.value)}
            style={selectStyle(!!scheduleFilter)}
            title="Filter by schedule"
          >
            <option value="">All schedules</option>
            <option value="scheduled">Scheduled</option>
            <option value="manual">Manual</option>
          </select>

          {(activeFilterCount > 0 || search) && (
            <button
              onClick={clearFilters}
              style={{
                background: 'none', border: '1px solid var(--border)',
                borderRadius: 6, padding: '6px 10px', cursor: 'pointer',
                color: 'var(--text-muted)', fontSize: 12, fontWeight: 500,
                display: 'inline-flex', alignItems: 'center', gap: 4,
              }}
              title="Clear filters"
            >
              <X size={12} /> Clear
              {activeFilterCount > 0 && (
                <span style={{ marginLeft: 2, opacity: 0.7 }}>({activeFilterCount})</span>
              )}
            </button>
          )}
        </div>
      </Card>

      {/* Scan list */}
      <Card style={{ padding: 0 }}>
        {filteredScans.length === 0 && uploads.length === 0 ? (
          <div style={{ padding: 40, textAlign: 'center' }}>
            <Radar size={40} color="var(--text-muted)" style={{ marginBottom: 12, opacity: 0.5 }} />
            <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 6, color: 'var(--text-secondary)' }}>
              {!scansLoaded ? 'Loading scans…' : scans.length === 0 ? 'No scans yet' : 'No scans match your filter'}
            </div>
            <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 16 }}>
              {!scansLoaded
                ? ''
                : scans.length === 0
                  ? 'Import a vulnerability scan or trigger an EASM discovery to get started.'
                  : 'Try adjusting your search or filter.'}
            </div>
            {scansLoaded && scans.length === 0 && (
              <Button onClick={() => setShowNewScan(true)}>
                <Plus size={15} /> Add Your First Scan
              </Button>
            )}
          </div>
        ) : (
          <div>
            <div style={{
              padding: '10px 16px', fontSize: 12, color: 'var(--text-muted)',
              borderBottom: '1px solid var(--border)', fontWeight: 600,
            }}>
              {filteredScans.length} scan{filteredScans.length !== 1 ? 's' : ''}
            </div>
            {/* Inline upload rows at top of list */}
            {uploads.map(u => (
              <UploadRow
                key={u.id}
                upload={u}
                onDismiss={() => setUploads(prev => prev.filter(up => up.id !== u.id))}
              />
            ))}
            {filteredScans.map(scan => (
              <ScanCard
                key={scan.id}
                scan={scan}
                onDelete={handleDelete}
                deleting={deletingId === scan.id}
                onCancel={handleCancel}
                cancelling={cancellingId === scan.id}
                onSelect={handleSelectScan}
                onRescan={handleRescanDomain}
                onRefresh={refreshScans}
              />
            ))}
          </div>
        )}
      </Card>

      {/* New scan modal */}
      {showNewScan && (
        <NewScanModal
          onClose={() => setShowNewScan(false)}
          onFile={handleFile}
          uploading={uploads.some(u => u.status === 'uploading' || u.status === 'processing')}
          easmEnabled={easmStatus?.enabled}
          onScanDomain={handleScanDomain}
          onSetupEasm={handleSetupEasm}
          onVmScan={handleNewVmScan}
          onAuditScan={handleNewAuditScan}
        />
      )}
    </div>
  )
}
