import React, { useState, useEffect, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Upload, CheckCircle, AlertCircle, FileText, X, Radar, Globe, Plus,
  RefreshCw, Trash2, Search, Clock, Server, Shield, Loader,
  Play, MonitorSmartphone,
} from 'lucide-react'
import { useScan } from '../../App.jsx'
import {
  uploadScan, deleteScan, getEasmStatus, scanEasmDomain, refreshEasmScan, setupEasm,
} from '../../api.js'
import { Card, PageHeader, Button, Spinner } from '../shared/ui.jsx'


// ── Source type metadata ─────────────────────────────────────────────

const SOURCE_TYPES = {
  nessus: { label: 'Nessus', icon: Shield, color: '#6366f1', bg: '#6366f122' },
  easm: { label: 'EASM', icon: Globe, color: '#0ea5e9', bg: '#0ea5e922' },
  qualys: { label: 'Qualys', icon: Shield, color: '#8b5cf6', bg: '#8b5cf622' },
  rapid7: { label: 'Rapid7', icon: Shield, color: '#f97316', bg: '#f9731622' },
  openvas: { label: 'OpenVAS', icon: Shield, color: '#22c55e', bg: '#22c55e22' },
  vm_scanner: { label: 'VM Scanner', icon: MonitorSmartphone, color: '#ec4899', bg: '#ec489922' },
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
      background: status === 'uploading' ? 'rgba(99,102,241,0.03)' : status === 'error' ? 'rgba(220,38,38,0.03)' : 'rgba(22,163,106,0.03)',
    }}>
      <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
        <div style={{
          width: 36, height: 36, borderRadius: 8, flexShrink: 0,
          background: meta.bg, display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          {status === 'uploading' && <Spinner size={18} />}
          {status === 'done' && <CheckCircle size={18} color="#16a34a" />}
          {status === 'error' && <AlertCircle size={18} color="#dc2626" />}
        </div>

        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3 }}>
            <span style={{ fontWeight: 600, fontSize: 14, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {file.name}
            </span>
            {status === 'uploading' && (
              <span style={{
                display: 'inline-flex', alignItems: 'center', gap: 4,
                background: '#6366f118', color: '#6366f1', border: '1px solid #6366f144',
                borderRadius: 4, padding: '2px 8px', fontSize: 11, fontWeight: 600,
              }}>
                <Loader size={10} style={{ animation: 'spin 1.5s linear infinite' }} />
                Importing
              </span>
            )}
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            {status === 'uploading' && 'Parsing & importing...'}
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
      {status === 'uploading' && <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>}
    </div>
  )
}


// ── New scan modal ───────────────────────────────────────────────────

function NewScanModal({ onClose, onFile, uploading, easmEnabled, onScanDomain, onSetupEasm }) {
  const [mode, setMode] = useState(null)
  const [domain, setDomain] = useState('')
  const [scanType, setScanType] = useState('full')
  const [scanning, setScanning] = useState(false)
  const [error, setError] = useState(null)

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
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
            <SourceOption icon={Upload} label="Import File" description="Upload Nessus, Qualys, CSV" color="#6366f1" onClick={() => setMode('upload')} />
            <SourceOption icon={Globe} label="EASM Scan" description={easmEnabled ? 'Scan a domain' : 'Set up EASM scanning'} color="#0ea5e9" onClick={() => setMode(easmEnabled ? 'easm' : 'easm-setup')} />
            <SourceOption icon={MonitorSmartphone} label="VM Scanner" description="Coming soon" color="#ec4899" disabled disabledMessage="Coming soon" />
          </div>
        )}

        {mode === 'upload' && (
          <div>
            <BackButton onClick={() => setMode(null)} />
            <DropZone onFile={(file) => { onFile(file); onClose() }} disabled={uploading} />
            <div style={{ marginTop: 12, fontSize: 12, color: 'var(--text-muted)', padding: '8px 10px', background: 'var(--bg-secondary)', borderRadius: 8 }}>
              Supported: .nessus (XML), .html (Tenable export), .csv — all auto-detected
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

function EasmStatusBadge({ status }) {
  if (!status || status === 'completed') return null
  const isRunning = status === 'running' || status === 'queued'
  const isFailed = status === 'failed' || status === 'error'
  const color = isRunning ? '#0ea5e9' : isFailed ? '#dc2626' : '#a78bfa'
  const label = isRunning ? 'Scanning...' : isFailed ? 'Failed' : status
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      background: `${color}18`, color, border: `1px solid ${color}44`,
      borderRadius: 4, padding: '2px 8px', fontSize: 11, fontWeight: 600,
    }}>
      {isRunning && <Loader size={10} style={{ animation: 'spin 1.5s linear infinite' }} />}
      {label}
      {isRunning && <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>}
    </span>
  )
}


// ── Scan card ────────────────────────────────────────────────────────

function ScanCard({ scan, onDelete, deleting, onSelect, onRescan }) {
  const meta = getSourceMeta(scan.source_type)
  const isEasm = scan.source_type === 'easm'
  const age = scan.created_at ? formatAge(scan.created_at) : null
  const domain = isEasm ? scan.raw_metadata?.domain : null
  const easmStatus = isEasm ? scan.raw_metadata?.status : null
  const isRunning = easmStatus === 'running' || easmStatus === 'queued'

  return (
    <div style={{
      padding: '14px 16px', borderBottom: '1px solid var(--border)',
      transition: 'background 0.1s',
    }}
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
              {scan.scan_name || scan.filename}
            </span>
            <SourceBadge sourceType={scan.source_type} />
            <EasmStatusBadge status={easmStatus} />
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            {age && <span><Clock size={11} style={{ marginRight: 3, verticalAlign: -1 }} />{age}</span>}
            <span><Server size={11} style={{ marginRight: 3, verticalAlign: -1 }} />{scan.asset_count || 0} assets</span>
            <span><Shield size={11} style={{ marginRight: 3, verticalAlign: -1 }} />{(scan.finding_count || 0).toLocaleString()} findings</span>
            {scan.source_version && <span>{scan.source_version}</span>}
          </div>
        </div>

        <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexShrink: 0 }}>
          {isEasm && domain && onRescan && !isRunning && (
            <button
              onClick={() => onRescan(domain)}
              title={`Rescan ${domain}`}
              style={{
                background: 'none', border: '1px solid var(--border)',
                borderRadius: 6, padding: '5px 8px', cursor: 'pointer',
                color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 4, fontSize: 12,
                transition: 'all 0.15s',
              }}
              onMouseEnter={e => { e.currentTarget.style.borderColor = '#0ea5e9'; e.currentTarget.style.color = '#0ea5e9' }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-muted)' }}
            >
              <RefreshCw size={12} />
            </button>
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
  )
}


// ── Helpers ──────────────────────────────────────────────────────────

function formatAge(isoDate) {
  // Backend stores UTC times without 'Z' suffix — ensure correct parsing
  const d = new Date(isoDate.endsWith('Z') ? isoDate : isoDate + 'Z')
  const now = new Date()
  const diffMs = now - d
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
  const { scans, refreshScans, setActiveScanId } = useScan()
  const navigate = useNavigate()

  const [uploads, setUploads] = useState([])
  const [deletingId, setDeletingId] = useState(null)
  const [showNewScan, setShowNewScan] = useState(false)
  const [filter, setFilter] = useState('all')
  const [search, setSearch] = useState('')
  const [easmStatus, setEasmStatus] = useState(null)

  // Load EASM status on mount
  useEffect(() => {
    getEasmStatus()
      .then(setEasmStatus)
      .catch(() => setEasmStatus(null))
  }, [])

  // Poll running EASM scans — refresh their status and import assets when done
  useEffect(() => {
    const runningScans = scans.filter(s =>
      s.source_type === 'easm' &&
      s.raw_metadata?.status &&
      (s.raw_metadata.status === 'running' || s.raw_metadata.status === 'queued')
    )
    if (runningScans.length === 0) return

    const interval = setInterval(async () => {
      for (const s of runningScans) {
        try {
          await refreshEasmScan(s.id)
        } catch { /* ignore */ }
      }
      await refreshScans()
    }, 10000)
    return () => clearInterval(interval)
  }, [scans, refreshScans])

  // ── Handlers ─────────────────────────────────────────────────────

  const handleFile = async (file) => {
    const id = Date.now()
    setUploads(prev => [...prev, { id, file, status: 'uploading', result: null, error: null }])
    try {
      const result = await uploadScan(file)
      setUploads(prev => prev.map(u => u.id === id ? { ...u, status: 'done', result } : u))
      await refreshScans()
      setActiveScanId(result.scan_id)
    } catch (err) {
      setUploads(prev => prev.map(u => u.id === id ? { ...u, status: 'error', error: err.message } : u))
    }
  }

  const handleDelete = async (scanId) => {
    if (!confirm('Delete this scan and all its data?')) return
    setDeletingId(scanId)
    try {
      await deleteScan(scanId)
      await refreshScans()
    } finally {
      setDeletingId(null)
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
    }
    // Refresh EASM status in case it changed
    getEasmStatus().then(setEasmStatus).catch(() => {})
  }

  const handleRescanDomain = async (domain) => {
    await scanEasmDomain(domain, 'full')
    await refreshScans()
  }

  const handleSetupEasm = async (domain) => {
    await setupEasm(domain)
    const status = await getEasmStatus()
    setEasmStatus(status)
    await refreshScans()
  }

  // ── Filter & search ──────────────────────────────────────────────

  const sourceTypes = [...new Set(scans.map(s => s.source_type || 'nessus'))]
  const filteredScans = scans.filter(s => {
    const st = s.source_type || 'nessus'
    if (filter !== 'all' && st !== filter) return false
    if (search) {
      const q = search.toLowerCase()
      const name = (s.scan_name || s.filename || '').toLowerCase()
      if (!name.includes(q)) return false
    }
    return true
  })

  const counts = { all: scans.length }
  scans.forEach(s => {
    const st = s.source_type || 'nessus'
    counts[st] = (counts[st] || 0) + 1
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
        <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', gap: 4, flex: 1 }}>
            {['all', ...sourceTypes].map(st => (
              <button
                key={st}
                onClick={() => setFilter(st)}
                style={{
                  padding: '5px 12px', borderRadius: 6, border: 'none',
                  background: filter === st ? 'var(--accent)' : 'transparent',
                  color: filter === st ? '#fff' : 'var(--text-muted)',
                  cursor: 'pointer', fontSize: 12, fontWeight: 600,
                  transition: 'all 0.15s', textTransform: 'capitalize',
                }}
              >
                {st === 'all' ? 'All' : getSourceMeta(st).label}
                {counts[st] != null && <span style={{ marginLeft: 4, opacity: 0.7 }}>({counts[st]})</span>}
              </button>
            ))}
          </div>

          <div style={{
            display: 'flex', alignItems: 'center', gap: 6,
            padding: '5px 10px', borderRadius: 6,
            border: '1px solid var(--border)', background: 'var(--bg)', minWidth: 200,
          }}>
            <Search size={13} color="var(--text-muted)" />
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search scans..."
              style={{
                border: 'none', background: 'transparent', color: 'var(--text-primary)',
                fontSize: 12, outline: 'none', width: '100%',
              }}
            />
            {search && (
              <button onClick={() => setSearch('')} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 0 }}>
                <X size={12} />
              </button>
            )}
          </div>
        </div>
      </Card>

      {/* Scan list */}
      <Card style={{ padding: 0, overflow: 'hidden' }}>
        {filteredScans.length === 0 && uploads.length === 0 ? (
          <div style={{ padding: 40, textAlign: 'center' }}>
            <Radar size={40} color="var(--text-muted)" style={{ marginBottom: 12, opacity: 0.5 }} />
            <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 6, color: 'var(--text-secondary)' }}>
              {scans.length === 0 ? 'No scans yet' : 'No scans match your filter'}
            </div>
            <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 16 }}>
              {scans.length === 0
                ? 'Import a vulnerability scan or trigger an EASM discovery to get started.'
                : 'Try adjusting your search or filter.'}
            </div>
            {scans.length === 0 && (
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
                onSelect={handleSelectScan}
                onRescan={handleRescanDomain}
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
          uploading={uploads.some(u => u.status === 'uploading')}
          easmEnabled={easmStatus?.enabled}
          onScanDomain={handleScanDomain}
          onSetupEasm={handleSetupEasm}
        />
      )}
    </div>
  )
}
