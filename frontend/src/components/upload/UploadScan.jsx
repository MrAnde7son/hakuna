import React, { useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Upload, CheckCircle, AlertCircle, FileText, X } from 'lucide-react'
import { useScan } from '../../App.jsx'
import { uploadScan, deleteScan } from '../../api.js'
import { Card, PageHeader, Button } from '../shared/ui.jsx'

function DropZone({ onFile, disabled }) {
  const { t } = useTranslation()
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
        borderRadius: 14, padding: '48px 24px', textAlign: 'center',
        cursor: disabled ? 'default' : 'pointer',
        background: dragging ? 'rgba(99,102,241,0.05)' : 'transparent',
        transition: 'all 0.2s',
      }}
    >
      <Upload size={40} color={dragging ? '#6366f1' : 'var(--text-muted)'} style={{ marginBottom: 16 }} />
      <div style={{ fontWeight: 600, fontSize: 16, marginBottom: 8 }}>
        {dragging ? t('upload.dropIt') : t('upload.dropHere')}
      </div>
      <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 16 }}>
        {t('upload.browseHint')}
      </div>
      <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
        {t('upload.filesAccepted')}
      </div>
      <input
        ref={inputRef}
        type="file"
        accept=".html,.htm,.nessus,.csv"
        style={{ display: 'none' }}
        onChange={e => e.target.files[0] && onFile(e.target.files[0])}
      />
    </div>
  )
}

function UploadProgress({ file, status, result, error, onDismiss }) {
  const { t } = useTranslation()
  return (
    <div style={{
      display: 'flex', gap: 14, padding: '14px 16px', borderRadius: 10,
      background: 'var(--bg-secondary)', border: `1px solid ${
        status === 'done' ? '#16a34a44' : status === 'error' ? '#dc262644' : 'var(--border)'
      }`, alignItems: 'flex-start',
    }}>
      <div style={{ flexShrink: 0, marginTop: 2 }}>
        {status === 'uploading' && (
          <div style={{ width: 20, height: 20, border: '2px solid var(--border)', borderTop: '2px solid var(--accent)', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
        )}
        {status === 'done' && <CheckCircle size={20} color="#16a34a" />}
        {status === 'error' && <AlertCircle size={20} color="#dc2626" />}
        <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
      </div>

      <div style={{ flex: 1 }}>
        <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 4 }}>{file.name}</div>
        <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 4 }}>
          {(file.size / 1024).toFixed(0)} KB
        </div>
        {status === 'uploading' && <div style={{ fontSize: 12, color: 'var(--accent)' }}>{t('upload.parsing')}</div>}
        {status === 'done' && result && (
          <div style={{ fontSize: 12, color: '#86efac' }}>
            ✓ {t('upload.ingested', { assets: result.assets, findings: result.findings })}
          </div>
        )}
        {status === 'error' && <div style={{ fontSize: 12, color: '#fca5a5' }}>{error}</div>}
      </div>

      <button onClick={onDismiss} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', flexShrink: 0 }}>
        <X size={16} />
      </button>
    </div>
  )
}

export default function UploadScan() {
  const { scans, refreshScans, setActiveScanId } = useScan()
  const navigate = useNavigate()
  const [uploads, setUploads] = useState([])
  const [deletingId, setDeletingId] = useState(null)

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

  const removeUpload = (id) => setUploads(prev => prev.filter(u => u.id !== id))

  const handleDeleteScan = async (scanId) => {
    if (!confirm('Delete this scan and all its data?')) return
    setDeletingId(scanId)
    try {
      await deleteScan(scanId)
      await refreshScans()
    } finally {
      setDeletingId(null)
    }
  }

  return (
    <div style={{ maxWidth: 700 }}>
      <PageHeader
        title="Upload"
        subtitle="Import a vulnerability scan to analyze findings"
      />

      <Card style={{ marginBottom: 20 }}>
        <DropZone onFile={handleFile} disabled={uploads.some(u => u.status === 'uploading')} />
      </Card>

      {/* Upload status */}
      {uploads.length > 0 && (
        <div style={{ marginBottom: 20, display: 'flex', flexDirection: 'column', gap: 8 }}>
          {uploads.map(u => (
            <UploadProgress
              key={u.id}
              file={u.file}
              status={u.status}
              result={u.result}
              error={u.error}
              onDismiss={() => removeUpload(u.id)}
            />
          ))}
          {uploads.some(u => u.status === 'done') && (
            <Button onClick={() => navigate('/')} style={{ alignSelf: 'flex-start', marginTop: 8 }}>
              View Dashboard →
            </Button>
          )}
        </div>
      )}

      {/* Existing scans */}
      {scans.length > 0 && (
        <Card>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <div style={{ fontWeight: 600, fontSize: 14 }}>Uploaded Scans</div>
            <Button onClick={() => navigate('/')}>View Dashboard →</Button>
          </div>
          {scans.map(scan => (
            <div key={scan.id} style={{
              display: 'flex', gap: 12, padding: '12px 0', borderBottom: '1px solid rgba(45,49,85,0.5)',
              alignItems: 'center',
            }}>
              <FileText size={18} color="var(--accent)" style={{ flexShrink: 0 }} />
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-primary)' }}>{scan.scan_name || scan.filename}</div>
                <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                  {scan.scan_date || scan.created_at?.split('T')[0]} ·
                  {scan.asset_count} assets ·
                  {scan.finding_count?.toLocaleString()} findings
                  {scan.source_type && ` · ${scan.source_type}${scan.source_version ? ' ' + scan.source_version : ''}`}
                </div>
              </div>
              {deletingId === scan.id ? (
                <div style={{ width: 14, height: 14, border: '2px solid var(--border)', borderTop: '2px solid var(--danger)', borderRadius: '50%', animation: 'spin 0.8s linear infinite', flexShrink: 0 }} />
              ) : (
                <Button
                  variant="danger"
                  size="sm"
                  onClick={() => handleDeleteScan(scan.id)}
                >
                  Delete
                </Button>
              )}
            </div>
          ))}
        </Card>
      )}

      {/* Instructions */}
      <Card style={{ marginTop: 20 }}>
        <div style={{ fontWeight: 600, marginBottom: 12, fontSize: 14 }}>Supported export formats</div>
        {[
          'HTML: Export → HTML (best for full plugin output)',
          '.nessus: Export → Nessus (XML — richest structured data)',
          'CSV: Export → CSV (fastest for large scans)',
          'All three formats are fully supported and auto-detected',
        ].map((step, i) => (
          <div key={i} style={{ display: 'flex', gap: 12, padding: '6px 0', fontSize: 13 }}>
            <span style={{
              width: 22, height: 22, borderRadius: '50%', background: 'var(--accent)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontWeight: 700, fontSize: 11, flexShrink: 0, color: '#fff'
            }}>{i + 1}</span>
            <span style={{ color: 'var(--text-secondary)', paddingTop: 2 }}>{step}</span>
          </div>
        ))}
        <div style={{ marginTop: 12, fontSize: 12, color: 'var(--text-muted)', padding: '10px 12px', background: 'var(--bg-secondary)', borderRadius: 8 }}>
          All scan types are supported: Basic Network Scan, Active Directory, OT/ICS, and more.
          All plugins are ingested — including informational findings that reveal your attack surface.
          CVE enrichment from intel.json is applied automatically.
        </div>
      </Card>
    </div>
  )
}
