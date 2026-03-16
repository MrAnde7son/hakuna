import React, { useState, useEffect, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Upload, CheckCircle, AlertCircle, FileText, X, Radar, Globe, Plus,
  RefreshCw, Trash2, Search, Clock, Server, Shield, ChevronDown,
  ChevronRight, Play, MonitorSmartphone, XCircle, Loader, Check,
} from 'lucide-react'
import { useScan } from '../../App.jsx'
import {
  uploadScan, deleteScan, getEasmStatus, syncEasmAssets, triggerEasmScan,
  addEasmDomain, getEasmDomains, getEasmScanRuns, setupEasm,
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


// ── Scan run status badge ────────────────────────────────────────────

const SCAN_STATUS = {
  queued:    { label: 'Queued',    color: '#a78bfa', bg: '#a78bfa22', icon: Clock },
  running:   { label: 'Running',   color: '#0ea5e9', bg: '#0ea5e922', icon: Loader },
  completed: { label: 'Completed', color: '#16a34a', bg: '#16a34a22', icon: Check },
  failed:    { label: 'Failed',    color: '#dc2626', bg: '#dc262622', icon: XCircle },
}

function ScanRunStatusBadge({ status }) {
  const s = SCAN_STATUS[status] || SCAN_STATUS.queued
  const Icon = s.icon
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      background: s.bg, color: s.color, border: `1px solid ${s.color}44`,
      borderRadius: 4, padding: '2px 8px', fontSize: 11, fontWeight: 600,
    }}>
      <Icon size={11} style={status === 'running' ? { animation: 'spin 1.5s linear infinite' } : {}} />
      {s.label}
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

function UploadProgress({ file, status, result, error, onDismiss }) {
  return (
    <div style={{
      display: 'flex', gap: 12, padding: '12px 14px', borderRadius: 8,
      background: 'var(--bg-secondary)', border: `1px solid ${
        status === 'done' ? '#16a34a44' : status === 'error' ? '#dc262644' : 'var(--border)'
      }`, alignItems: 'center',
    }}>
      <div style={{ flexShrink: 0 }}>
        {status === 'uploading' && <Spinner size={18} />}
        {status === 'done' && <CheckCircle size={18} color="#16a34a" />}
        {status === 'error' && <AlertCircle size={18} color="#dc2626" />}
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontWeight: 600, fontSize: 13, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{file.name}</div>
        {status === 'uploading' && <div style={{ fontSize: 12, color: 'var(--accent)' }}>Parsing & importing...</div>}
        {status === 'done' && result && (
          <div style={{ fontSize: 12, color: '#86efac' }}>
            {result.assets} assets, {result.findings} findings imported
          </div>
        )}
        {status === 'error' && <div style={{ fontSize: 12, color: '#fca5a5' }}>{error}</div>}
      </div>
      <button onClick={onDismiss} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', flexShrink: 0, padding: 4 }}>
        <X size={14} />
      </button>
    </div>
  )
}


// ── New scan modal ───────────────────────────────────────────────────

function NewScanModal({ onClose, onFile, uploading, easmEnabled, easmDomain, easmDomains, onTriggerEasm, onAddDomain, onSyncEasm, onSetupEasm }) {
  const [mode, setMode] = useState(null)
  const [easmScanType, setEasmScanType] = useState('full')
  const [triggeringEasm, setTriggeringEasm] = useState(false)
  const [syncingEasm, setSyncingEasm] = useState(false)
  const [settingUp, setSettingUp] = useState(false)
  const [setupDomain, setSetupDomain] = useState('')
  const [setupError, setSetupError] = useState(null)
  const [newDomain, setNewDomain] = useState('')
  const [addingDomain, setAddingDomain] = useState(false)
  const [domainAdded, setDomainAdded] = useState(null)

  const handleTriggerEasm = async () => {
    setTriggeringEasm(true)
    try {
      await onTriggerEasm(easmScanType)
      onClose()
    } catch {
      setTriggeringEasm(false)
    }
  }

  const handleSyncEasm = async () => {
    setSyncingEasm(true)
    try {
      await onSyncEasm()
      onClose()
    } catch {
      setSyncingEasm(false)
    }
  }

  const handleSetup = async () => {
    if (!setupDomain.trim()) return
    setSettingUp(true)
    setSetupError(null)
    try {
      await onSetupEasm(setupDomain.trim())
      onClose()
    } catch (err) {
      setSetupError(err.message)
      setSettingUp(false)
    }
  }

  const handleAddDomain = async () => {
    if (!newDomain.trim()) return
    setAddingDomain(true)
    try {
      await onAddDomain(newDomain.trim())
      setDomainAdded(newDomain.trim())
      setNewDomain('')
    } finally {
      setAddingDomain(false)
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
            <SourceOption icon={Globe} label="EASM Scan" description={easmEnabled ? 'External attack surface' : 'Set up EASM scanning'} color="#0ea5e9" onClick={() => setMode(easmEnabled ? 'easm' : 'easm-setup')} />
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
                value={setupDomain}
                onChange={e => setSetupDomain(e.target.value)}
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
            {setupError && (
              <div style={{ fontSize: 12, color: '#dc2626', marginBottom: 12, padding: '8px 10px', background: '#dc262611', borderRadius: 6 }}>
                {setupError}
              </div>
            )}
            <Button onClick={handleSetup} disabled={settingUp || !setupDomain.trim()} style={{ width: '100%', background: '#0ea5e9' }}>
              {settingUp ? 'Setting up...' : 'Enable EASM & Start Discovery'}
            </Button>
          </div>
        )}

        {mode === 'easm' && (
          <div>
            <BackButton onClick={() => setMode(null)} />

            {/* Current domains */}
            <div style={{ marginBottom: 14 }}>
              <label style={{ fontSize: 12, fontWeight: 600, display: 'block', marginBottom: 6, color: 'var(--text-muted)' }}>
                Target Domains
              </label>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {(easmDomains || []).map(d => (
                  <span key={d.id || d.domain} style={{
                    display: 'inline-flex', alignItems: 'center', gap: 5,
                    padding: '5px 10px', borderRadius: 6,
                    background: '#0ea5e911', border: '1px solid #0ea5e933',
                    fontSize: 12, color: 'var(--text-primary)',
                  }}>
                    <Globe size={12} color="#0ea5e9" />
                    {d.domain}
                    {d.domain === easmDomain && (
                      <span style={{ fontSize: 10, color: '#0ea5e9', fontWeight: 600 }}>primary</span>
                    )}
                  </span>
                ))}
                {(!easmDomains || easmDomains.length === 0) && easmDomain && (
                  <span style={{
                    display: 'inline-flex', alignItems: 'center', gap: 5,
                    padding: '5px 10px', borderRadius: 6,
                    background: '#0ea5e911', border: '1px solid #0ea5e933',
                    fontSize: 12, color: 'var(--text-primary)',
                  }}>
                    <Globe size={12} color="#0ea5e9" />
                    {easmDomain}
                  </span>
                )}
              </div>
            </div>

            {/* Add domain */}
            <div style={{ marginBottom: 16 }}>
              <div style={{ display: 'flex', gap: 8 }}>
                <input
                  value={newDomain}
                  onChange={e => setNewDomain(e.target.value)}
                  placeholder="Add another domain..."
                  onKeyDown={e => e.key === 'Enter' && handleAddDomain()}
                  style={{
                    flex: 1, padding: '8px 12px', borderRadius: 8,
                    border: '1px solid var(--border)', background: 'var(--bg)',
                    color: 'var(--text-primary)', fontSize: 13,
                  }}
                />
                <Button size="sm" onClick={handleAddDomain} disabled={addingDomain || !newDomain.trim()}>
                  {addingDomain ? '...' : <><Plus size={13} /> Add</>}
                </Button>
              </div>
              {domainAdded && (
                <div style={{ fontSize: 12, color: '#16a34a', marginTop: 6, display: 'flex', alignItems: 'center', gap: 4 }}>
                  <Check size={12} /> Added {domainAdded}
                </div>
              )}
            </div>

            {/* Scan type */}
            <div style={{ marginBottom: 16 }}>
              <label style={{ fontSize: 12, fontWeight: 600, display: 'block', marginBottom: 6, color: 'var(--text-muted)' }}>Scan Type</label>
              <div style={{ display: 'flex', gap: 8 }}>
                {['full', 'discovery', 'enrichment'].map(t => (
                  <button
                    key={t}
                    onClick={() => setEasmScanType(t)}
                    style={{
                      flex: 1, padding: '10px 12px', borderRadius: 8,
                      border: `1px solid ${easmScanType === t ? '#0ea5e9' : 'var(--border)'}`,
                      background: easmScanType === t ? '#0ea5e922' : 'transparent',
                      color: easmScanType === t ? '#0ea5e9' : 'var(--text-secondary)',
                      cursor: 'pointer', fontSize: 13, fontWeight: 600,
                      textTransform: 'capitalize',
                    }}
                  >
                    {t}
                  </button>
                ))}
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <Button onClick={handleSyncEasm} disabled={syncingEasm || triggeringEasm} style={{ flex: 1, background: '#0ea5e9' }}>
                <RefreshCw size={13} style={syncingEasm ? { animation: 'spin 1s linear infinite' } : {}} />
                {syncingEasm ? 'Syncing...' : 'Sync Assets'}
              </Button>
              <Button onClick={handleTriggerEasm} disabled={triggeringEasm || syncingEasm} variant="ghost" style={{ flex: 1 }}>
                <Play size={13} />
                {triggeringEasm ? 'Triggering...' : 'New Scan'}
              </Button>
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 8, textAlign: 'center' }}>
              Sync imports existing discoveries. New Scan triggers a fresh scan first.
            </div>
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


// ── EASM panel (inline in scan card) ─────────────────────────────────

function EasmPanel({ easmStatus, onSync, onAddDomain, domains, scanRuns, onRefreshRuns }) {
  const [syncing, setSyncing] = useState(false)
  const [newDomain, setNewDomain] = useState('')
  const [addingDomain, setAddingDomain] = useState(false)
  const [showDomainInput, setShowDomainInput] = useState(false)

  const handleSync = async () => {
    setSyncing(true)
    try { await onSync() } finally { setSyncing(false) }
  }

  const handleAddDomain = async () => {
    if (!newDomain.trim()) return
    setAddingDomain(true)
    try {
      await onAddDomain(newDomain.trim())
      setNewDomain('')
      setShowDomainInput(false)
    } finally {
      setAddingDomain(false)
    }
  }

  if (!easmStatus?.enabled) return null

  const hasActiveRun = scanRuns?.some(r => r.status === 'queued' || r.status === 'running')

  return (
    <div style={{ marginTop: 10, background: 'var(--bg-secondary)', borderRadius: 8, overflow: 'hidden' }}>
      {/* Actions row */}
      <div style={{ padding: '12px 16px', display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <Button size="sm" onClick={handleSync} disabled={syncing}>
          <RefreshCw size={13} style={syncing ? { animation: 'spin 1s linear infinite' } : {}} />
          {syncing ? 'Syncing...' : 'Sync Assets'}
        </Button>
        <Button size="sm" variant="ghost" onClick={() => setShowDomainInput(v => !v)}>
          <Plus size={13} /> Add Domain
        </Button>
        {easmStatus.stats && (
          <div style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--text-muted)' }}>
            {easmStatus.stats.total_assets || 0} discovered assets
          </div>
        )}
      </div>

      {/* Add domain input */}
      {showDomainInput && (
        <div style={{ padding: '0 16px 12px', display: 'flex', gap: 8 }}>
          <input
            value={newDomain}
            onChange={e => setNewDomain(e.target.value)}
            placeholder="example.com"
            onKeyDown={e => e.key === 'Enter' && handleAddDomain()}
            autoFocus
            style={{
              flex: 1, padding: '6px 10px', borderRadius: 6,
              border: '1px solid var(--border)', background: 'var(--bg)',
              color: 'var(--text-primary)', fontSize: 13,
            }}
          />
          <Button size="sm" onClick={handleAddDomain} disabled={addingDomain || !newDomain.trim()}>
            {addingDomain ? '...' : 'Add'}
          </Button>
        </div>
      )}

      {/* Domains */}
      {domains && domains.length > 0 && (
        <div style={{ padding: '0 16px 12px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6 }}>
            Target Domains
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {domains.map(d => (
              <span key={d.id || d.domain} style={{
                display: 'inline-flex', alignItems: 'center', gap: 4,
                padding: '3px 8px', borderRadius: 5,
                background: d.active !== false ? '#0ea5e911' : 'var(--bg)',
                border: `1px solid ${d.active !== false ? '#0ea5e933' : 'var(--border)'}`,
                fontSize: 12, color: d.active !== false ? 'var(--text-primary)' : 'var(--text-muted)',
              }}>
                <Globe size={11} color={d.active !== false ? '#0ea5e9' : 'var(--text-muted)'} />
                {d.domain}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Scan run history */}
      {scanRuns && scanRuns.length > 0 && (
        <div style={{ borderTop: '1px solid var(--border)' }}>
          <div style={{
            padding: '10px 16px', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Scan History
            </div>
            {hasActiveRun && (
              <button onClick={onRefreshRuns} style={{
                background: 'none', border: 'none', cursor: 'pointer', color: 'var(--accent)',
                fontSize: 11, padding: 0, display: 'flex', alignItems: 'center', gap: 3,
              }}>
                <RefreshCw size={10} /> Refresh
              </button>
            )}
          </div>
          <div style={{ padding: '0 16px 12px', display: 'flex', flexDirection: 'column', gap: 6 }}>
            {scanRuns.slice(0, 5).map(run => (
              <ScanRunRow key={run.id} run={run} />
            ))}
          </div>
        </div>
      )}

      <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
    </div>
  )
}

function ScanRunRow({ run }) {
  const started = run.started_at ? new Date(run.started_at) : null
  const finished = run.finished_at ? new Date(run.finished_at) : null
  const duration = started && finished ? formatDuration(finished - started) : null

  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 10, padding: '8px 10px',
      background: 'var(--bg)', borderRadius: 6, border: '1px solid var(--border)',
    }}>
      <ScanRunStatusBadge status={run.status} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 12, color: 'var(--text-primary)', fontWeight: 500 }}>
          {run.scan_type} scan
        </div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {started && <span>{formatAge(started.toISOString())}</span>}
          {duration && <span>{duration}</span>}
          {run.status === 'completed' && (
            <span>
              {run.assets_found || 0} found{run.assets_changed ? `, ${run.assets_changed} changed` : ''}
            </span>
          )}
          {run.status === 'failed' && run.error && (
            <span style={{ color: '#dc2626' }}>{run.error}</span>
          )}
        </div>
      </div>
    </div>
  )
}


// ── Scan card ────────────────────────────────────────────────────────

function ScanCard({ scan, onDelete, deleting, easmStatus, onSyncEasm, onAddDomain, domains, scanRuns, onRefreshRuns, onSelect }) {
  const [expanded, setExpanded] = useState(false)
  const isEasm = scan.source_type === 'easm'
  const meta = getSourceMeta(scan.source_type)
  const age = scan.created_at ? formatAge(scan.created_at) : null

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
            {/* Show latest scan run status for EASM */}
            {isEasm && scanRuns && scanRuns.length > 0 && (
              <ScanRunStatusBadge status={scanRuns[0].status} />
            )}
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            {age && <span><Clock size={11} style={{ marginRight: 3, verticalAlign: -1 }} />{age}</span>}
            <span><Server size={11} style={{ marginRight: 3, verticalAlign: -1 }} />{scan.asset_count || 0} assets</span>
            <span><Shield size={11} style={{ marginRight: 3, verticalAlign: -1 }} />{(scan.finding_count || 0).toLocaleString()} findings</span>
            {scan.source_version && <span>{scan.source_version}</span>}
          </div>
        </div>

        <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexShrink: 0 }}>
          {isEasm && (
            <button
              onClick={() => setExpanded(v => !v)}
              title="EASM controls"
              style={{
                background: expanded ? '#0ea5e911' : 'none',
                border: `1px solid ${expanded ? '#0ea5e944' : 'var(--border)'}`,
                borderRadius: 6, padding: '5px 8px', cursor: 'pointer',
                color: 'var(--text-muted)',
                display: 'flex', alignItems: 'center', gap: 4, fontSize: 12,
              }}
            >
              <Radar size={13} color="#0ea5e9" />
              {expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
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

      {isEasm && expanded && (
        <EasmPanel
          easmStatus={easmStatus}
          onSync={onSyncEasm}
          onAddDomain={onAddDomain}
          domains={domains}
          scanRuns={scanRuns}
          onRefreshRuns={onRefreshRuns}
        />
      )}
    </div>
  )
}


// ── Helpers ──────────────────────────────────────────────────────────

function formatAge(isoDate) {
  const d = new Date(isoDate)
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

function formatDuration(ms) {
  const secs = Math.floor(ms / 1000)
  if (secs < 60) return `${secs}s`
  const mins = Math.floor(secs / 60)
  if (mins < 60) return `${mins}m ${secs % 60}s`
  const hrs = Math.floor(mins / 60)
  return `${hrs}h ${mins % 60}m`
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
  const [easmDomains, setEasmDomains] = useState([])
  const [easmScanRuns, setEasmScanRuns] = useState([])

  // Load EASM data on mount
  useEffect(() => {
    getEasmStatus()
      .then(status => {
        setEasmStatus(status)
        if (status?.enabled || status?.domain) {
          getEasmDomains().then(setEasmDomains).catch(() => {})
          getEasmScanRuns().then(setEasmScanRuns).catch(() => {})
        }
      })
      .catch(() => setEasmStatus(null))
  }, [])

  // Auto-poll scan runs if any are active
  useEffect(() => {
    const hasActive = easmScanRuns.some(r => r.status === 'queued' || r.status === 'running')
    if (!hasActive) return
    const interval = setInterval(() => {
      getEasmScanRuns().then(setEasmScanRuns).catch(() => {})
    }, 10000)
    return () => clearInterval(interval)
  }, [easmScanRuns])

  const refreshEasmData = useCallback(() => {
    if (!easmStatus?.enabled) return
    getEasmDomains().then(setEasmDomains).catch(() => {})
    getEasmScanRuns().then(setEasmScanRuns).catch(() => {})
  }, [easmStatus?.enabled])

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

  const handleSyncEasm = async () => {
    await syncEasmAssets()
    await refreshScans()
    const status = await getEasmStatus()
    setEasmStatus(status)
    refreshEasmData()
  }

  const handleAddDomain = async (domain) => {
    await addEasmDomain(domain)
    // Refresh domains list
    getEasmDomains().then(setEasmDomains).catch(() => {})
  }

  const handleTriggerEasm = async (scanType) => {
    await triggerEasmScan(scanType)
    setTimeout(() => {
      getEasmScanRuns().then(setEasmScanRuns).catch(() => {})
    }, 500)
  }

  const handleSetupEasm = async (domain) => {
    await setupEasm(domain)
    // Refresh everything — EASM is now enabled
    const status = await getEasmStatus()
    setEasmStatus(status)
    await refreshScans()
    if (status?.enabled) {
      getEasmDomains().then(setEasmDomains).catch(() => {})
      getEasmScanRuns().then(setEasmScanRuns).catch(() => {})
    }
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

      {/* Upload progress */}
      {uploads.length > 0 && (
        <div style={{ marginBottom: 16, display: 'flex', flexDirection: 'column', gap: 8 }}>
          {uploads.map(u => (
            <UploadProgress
              key={u.id}
              file={u.file}
              status={u.status}
              result={u.result}
              error={u.error}
              onDismiss={() => setUploads(prev => prev.filter(up => up.id !== u.id))}
            />
          ))}
        </div>
      )}

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

      {/* EASM banner (if EASM enabled but no EASM scan exists) */}
      {easmStatus?.enabled && !scans.some(s => s.source_type === 'easm') && (
        <Card style={{ marginBottom: 16, padding: '16px 20px', borderColor: '#0ea5e944' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <Globe size={20} color="#0ea5e9" />
            <div style={{ flex: 1 }}>
              <div style={{ fontWeight: 600, fontSize: 13 }}>EASM is configured for {easmStatus.domain}</div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                Sync external attack surface data to see internet-facing assets
              </div>
            </div>
            <Button size="sm" onClick={handleSyncEasm} style={{ background: '#0ea5e9' }}>
              <RefreshCw size={13} /> Sync Now
            </Button>
          </div>
        </Card>
      )}

      {/* Scan list */}
      <Card style={{ padding: 0, overflow: 'hidden' }}>
        {filteredScans.length === 0 ? (
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
            {filteredScans.map(scan => (
              <ScanCard
                key={scan.id}
                scan={scan}
                onDelete={handleDelete}
                deleting={deletingId === scan.id}
                easmStatus={easmStatus}
                onSyncEasm={handleSyncEasm}
                onAddDomain={handleAddDomain}
                domains={easmDomains}
                scanRuns={easmScanRuns}
                onRefreshRuns={refreshEasmData}
                onSelect={handleSelectScan}
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
          easmDomain={easmStatus?.domain}
          easmDomains={easmDomains}
          onTriggerEasm={handleTriggerEasm}
          onAddDomain={handleAddDomain}
          onSyncEasm={handleSyncEasm}
          onSetupEasm={handleSetupEasm}
        />
      )}
    </div>
  )
}
