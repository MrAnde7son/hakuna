import React, { useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Upload, CheckCircle, AlertCircle, ShieldCheck, Target,
  Globe, Radar, ArrowRight, FileText, Loader,
} from 'lucide-react'
import { useScan } from '../../App.jsx'
import { useAuth } from '../../contexts/AuthContext.jsx'
import { uploadScan, getScanStatus } from '../../api.js'

// ── Drop zone ──────────────────────────────────────────────────────

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
        borderRadius: 12,
        padding: '32px 20px',
        textAlign: 'center',
        cursor: disabled ? 'default' : 'pointer',
        background: dragging ? 'rgba(99,102,241,0.05)' : 'transparent',
        transition: 'all 0.2s',
        opacity: disabled ? 0.6 : 1,
      }}
    >
      <Upload size={28} color={dragging ? 'var(--accent)' : 'var(--text-muted)'} style={{ marginBottom: 10 }} />
      <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 4 }}>
        {dragging ? 'Drop to upload' : 'Drop your scan file here'}
      </div>
      <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 12 }}>
        or click to browse
      </div>
      <div style={{ display: 'flex', gap: 6, justifyContent: 'center', flexWrap: 'wrap' }}>
        {['.nessus XML', 'HTML export', 'CSV'].map(fmt => (
          <span key={fmt} style={{
            fontSize: 11, fontWeight: 600, padding: '2px 8px',
            background: 'var(--bg-primary)', border: '1px solid var(--border)',
            borderRadius: 5, color: 'var(--text-muted)',
          }}>{fmt}</span>
        ))}
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

// ── Upload progress row ────────────────────────────────────────────

function UploadRow({ file, status, result, error }) {
  return (
    <div style={{
      display: 'flex', gap: 12, padding: '12px 14px', borderRadius: 10,
      background: 'var(--bg-secondary)',
      border: `1px solid ${status === 'done' ? '#16a34a44' : status === 'error' ? '#dc262644' : 'var(--border)'}`,
      alignItems: 'center',
    }}>
      <div style={{ flexShrink: 0 }}>
        {(status === 'uploading' || status === 'processing') && (
          <><Loader size={18} color="var(--accent)" style={{ animation: 'spin 1s linear infinite' }} />
            <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
          </>
        )}
        {status === 'done' && <CheckCircle size={18} color="#16a34a" />}
        {status === 'error' && <AlertCircle size={18} color="#dc2626" />}
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{file.name}</div>
        <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
          {status === 'uploading' && 'Uploading…'}
          {status === 'processing' && 'Processing scan data — this usually takes 30–60 seconds…'}
          {status === 'done' && result && <span style={{ color: '#86efac' }}>✓ {result.assets} assets · {result.findings?.toLocaleString()} findings imported</span>}
          {status === 'error' && <span style={{ color: '#fca5a5' }}>{error}</span>}
        </div>
      </div>
    </div>
  )
}

// ── EASM status card ───────────────────────────────────────────────

function EasmStatusCard({ domain }) {
  return (
    <div style={{
      padding: '14px 16px', borderRadius: 12,
      background: 'rgba(99,102,241,0.06)',
      border: '1px solid rgba(99,102,241,0.2)',
      display: 'flex', gap: 12, alignItems: 'flex-start',
    }}>
      <div style={{
        width: 36, height: 36, borderRadius: 10,
        background: 'rgba(99,102,241,0.12)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        flexShrink: 0,
      }}>
        <Radar size={18} color="var(--accent)" />
      </div>
      <div>
        <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 4 }}>
          Scanning <span style={{ color: 'var(--accent)' }}>{domain}</span> for internet-facing assets
        </div>
        <div style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.6 }}>
          We automatically discovered your domain and started an external attack surface scan.
          High-value assets will then be scanned for vulnerabilities.
          This runs in the background — results appear in your dashboard as they come in.
        </div>
        <div style={{ marginTop: 8, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          {[
            { icon: Globe, label: 'Domain discovery' },
            { icon: ShieldCheck, label: 'Port & service scan' },
            { icon: Target, label: 'Vulnerability scan' },
          ].map(({ icon: Icon, label }) => (
            <span key={label} style={{
              display: 'inline-flex', alignItems: 'center', gap: 4,
              fontSize: 11, fontWeight: 600, padding: '3px 8px',
              background: 'var(--bg-secondary)', border: '1px solid var(--border)',
              borderRadius: 6, color: 'var(--text-secondary)',
            }}>
              <Icon size={11} />
              {label}
            </span>
          ))}
        </div>
      </div>
    </div>
  )
}

// ── Success state with guided steps ───────────────────────────────

const GUIDED_STEPS = [
  {
    num: 1,
    title: 'Review your top findings',
    description: 'See which vulnerabilities pose the highest real-world risk to your environment.',
    cta: 'Go to Findings',
    path: '/findings?sort_by=priority_score&order=desc',
  },
  {
    num: 2,
    title: 'Create your first campaign',
    description: 'Use a template like "Quick Wins" to build a remediation plan in seconds.',
    cta: 'Create Campaign',
    path: '/campaigns',
  },
  {
    num: 3,
    title: 'Assign findings to owners',
    description: 'Tag assets with owners so the right people get notified when new issues appear.',
    cta: 'View Assets',
    path: '/assets',
  },
  {
    num: 4,
    title: 'Connect your ticketing system',
    description: 'Push findings to Jira or ServiceNow to fit your existing workflow.',
    cta: 'Set up Integration',
    path: '/settings?tab=integrations',
  },
]

function SuccessState({ result, onComplete }) {
  const navigate = useNavigate()

  return (
    <div style={{ width: '100%', maxWidth: 580 }}>
      {/* Success banner */}
      <div style={{
        textAlign: 'center', padding: '24px 20px',
        background: 'rgba(22,163,74,0.06)',
        border: '1px solid rgba(22,163,74,0.2)',
        borderRadius: 14, marginBottom: 28,
      }}>
        <CheckCircle size={36} color="#16a34a" style={{ marginBottom: 10 }} />
        <div style={{ fontWeight: 700, fontSize: 18, marginBottom: 4 }}>Scan imported successfully</div>
        <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
          {result.assets} assets · {result.findings?.toLocaleString()} findings are ready for review
        </div>
      </div>

      {/* Guided steps */}
      <div style={{ marginBottom: 20, fontWeight: 700, fontSize: 15 }}>
        Here's what to do next
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginBottom: 28 }}>
        {GUIDED_STEPS.map((step) => (
          <div
            key={step.num}
            style={{
              display: 'flex', gap: 14, padding: '14px 16px',
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border)',
              borderRadius: 12, alignItems: 'center',
              cursor: 'pointer', transition: 'border-color 0.15s',
            }}
            onClick={() => { onComplete(); navigate(step.path) }}
            onMouseEnter={e => e.currentTarget.style.borderColor = 'var(--accent)'}
            onMouseLeave={e => e.currentTarget.style.borderColor = 'var(--border)'}
          >
            <div style={{
              width: 32, height: 32, borderRadius: 8,
              background: 'rgba(99,102,241,0.12)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontWeight: 800, fontSize: 14, color: 'var(--accent)', flexShrink: 0,
            }}>{step.num}</div>
            <div style={{ flex: 1 }}>
              <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 2 }}>{step.title}</div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.5 }}>{step.description}</div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 12, fontWeight: 600, color: 'var(--accent)', flexShrink: 0 }}>
              {step.cta} <ArrowRight size={13} />
            </div>
          </div>
        ))}
      </div>

      <div style={{ textAlign: 'center' }}>
        <button
          onClick={onComplete}
          style={{
            display: 'inline-flex', alignItems: 'center', gap: 8,
            padding: '10px 28px', borderRadius: 10, border: 'none',
            background: 'var(--accent)', color: '#fff', fontWeight: 700,
            fontSize: 14, cursor: 'pointer',
          }}
        >
          Go to dashboard <ArrowRight size={15} />
        </button>
      </div>
    </div>
  )
}

// ── Helpers ────────────────────────────────────────────────────────

const FREE_DOMAINS = new Set([
  'gmail.com','googlemail.com','yahoo.com','yahoo.co.uk','yahoo.fr','yahoo.de',
  'hotmail.com','hotmail.co.uk','outlook.com','live.com','msn.com',
  'icloud.com','me.com','mac.com','aol.com','protonmail.com','proton.me',
  'pm.me','zoho.com','tutanota.com','tuta.io','gmx.com','gmx.net','mail.com',
  'mail.ru','inbox.com','yandex.com','yandex.ru','fastmail.com','hey.com',
])

function deriveCorporateDomain(email) {
  if (!email || !email.includes('@')) return null
  const domain = email.split('@')[1].toLowerCase()
  return FREE_DOMAINS.has(domain) ? null : domain
}

// ── Main component ─────────────────────────────────────────────────

export default function FirstScanOnboarding({ onComplete }) {
  const { refreshScans, setActiveScanId } = useScan()
  const { user } = useAuth()
  const [upload, setUpload] = useState(null) // { file, status, result, error }

  // Use stored domain, or derive from email as fallback for accounts registered before the fix
  const easmDomain = user?.org?.easm_domain || deriveCorporateDomain(user?.email)

  const handleFile = async (file) => {
    setUpload({ file, status: 'uploading', result: null, error: null })

    try {
      const result = await uploadScan(file)

      if (result.status === 'processing') {
        setUpload(u => ({ ...u, status: 'processing' }))
        await refreshScans()

        let attempts = 0
        while (attempts < 120) {
          await new Promise(r => setTimeout(r, 3000))
          const statusData = await getScanStatus(result.scan_id)
          if (statusData.status !== 'processing') {
            if (statusData.status === 'failed') {
              setUpload(u => ({ ...u, status: 'error', error: 'Scan processing failed. Please try again.' }))
            } else {
              const finalResult = {
                scan_id: result.scan_id,
                assets: statusData.asset_count,
                findings: statusData.finding_count,
              }
              await refreshScans()
              setActiveScanId(result.scan_id)
              setUpload(u => ({ ...u, status: 'done', result: finalResult }))
            }
            return
          }
          attempts++
          if (attempts % 5 === 0) await refreshScans()
        }
        setUpload(u => ({ ...u, status: 'error', error: 'Processing timed out. Please refresh and try again.' }))
      } else {
        await refreshScans()
        setActiveScanId(result.scan_id)
        setUpload(u => ({ ...u, status: 'done', result }))
      }
    } catch (err) {
      setUpload(u => ({ ...u, status: 'error', error: err.message }))
    }
  }

  const isUploading = upload?.status === 'uploading' || upload?.status === 'processing'
  const isDone = upload?.status === 'done'

  return (
    <div style={{
      minHeight: '80vh', display: 'flex', flexDirection: 'column',
      alignItems: 'center', justifyContent: 'center',
      padding: '40px 24px',
    }}>
      {isDone ? (
        <SuccessState result={upload.result} onComplete={onComplete} />
      ) : (
        <>
          {/* Hero */}
          <div style={{ textAlign: 'center', marginBottom: 36, maxWidth: 500 }}>
            <h1 style={{ fontSize: 26, fontWeight: 800, marginBottom: 10, color: 'var(--text-primary)' }}>
              Welcome to Hakuna
            </h1>
            <p style={{ fontSize: 15, color: 'var(--text-muted)', lineHeight: 1.6, margin: 0 }}>
              {easmDomain
                ? 'We\'ve already started scanning your environment. You can also upload a scan file to see results immediately.'
                : 'Upload your first vulnerability scan to get started. We\'ll prioritize your findings and help you fix what matters most.'}
            </p>
          </div>

          <div style={{ width: '100%', maxWidth: 520, display: 'flex', flexDirection: 'column', gap: 16 }}>
            {/* EASM auto-scan status */}
            {easmDomain && <EasmStatusCard domain={easmDomain} />}

            {/* Divider when EASM is shown */}
            {easmDomain && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <div style={{ flex: 1, height: 1, background: 'var(--border)' }} />
                <span style={{ fontSize: 12, color: 'var(--text-muted)', fontWeight: 600 }}>OR UPLOAD A SCAN MANUALLY</span>
                <div style={{ flex: 1, height: 1, background: 'var(--border)' }} />
              </div>
            )}

            {/* Upload area */}
            <div style={{
              padding: 16, background: 'var(--bg-secondary)',
              border: '1px solid var(--border)', borderRadius: 12,
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
                <FileText size={16} color="var(--accent)" />
                <div style={{ fontWeight: 700, fontSize: 13 }}>Upload a Nessus scan</div>
              </div>
              <DropZone onFile={handleFile} disabled={isUploading} />
            </div>

            {/* Upload progress */}
            {upload && (
              <UploadRow
                file={upload.file}
                status={upload.status}
                result={upload.result}
                error={upload.error}
              />
            )}

            {/* Error retry */}
            {upload?.status === 'error' && (
              <div style={{ textAlign: 'center' }}>
                <button
                  onClick={() => setUpload(null)}
                  style={{ fontSize: 13, color: 'var(--accent)', background: 'none', border: 'none', cursor: 'pointer', textDecoration: 'underline' }}
                >
                  Try a different file
                </button>
              </div>
            )}

            {/* Skip link for EASM-only users */}
            {easmDomain && !upload && (
              <div style={{ textAlign: 'center' }}>
                <button
                  onClick={onComplete}
                  style={{ fontSize: 13, color: 'var(--text-muted)', background: 'none', border: 'none', cursor: 'pointer' }}
                >
                  Skip — go to dashboard while EASM scan runs →
                </button>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  )
}
