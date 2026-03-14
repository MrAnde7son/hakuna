/**
 * ThreatIntelCenter.jsx
 * Comprehensive Threat Intelligence hub — newsroom, CVE intel, threat groups, impact analysis, campaigns.
 */
import React, { useState, useEffect, useCallback, useRef } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  Shield, AlertTriangle, Zap, Globe, Users, Activity, RefreshCw,
  Search, Filter, ChevronDown, ChevronUp, ChevronRight, ExternalLink,
  BookOpen, AlertCircle, CheckCircle, Clock, Plus, X,
  FileText, TrendingUp, Flag, Database, Radio,
} from 'lucide-react'
import { useScan } from '../../App.jsx'
import { Card, Button, Spinner, EmptyState, StatCard, SeverityBadge, ScoreBar } from '../shared/ui.jsx'
import {
  getThreatIntelStats, getThreatCves, getThreatGroups, getThreatTtps,
  syncThreatIntel, getGroupExposure, getCisaAdvisories,
} from '../../api.js'

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Renders markdown-style [text](url) links and (Citation: ...) notes in plain text */
function renderDescription(text) {
  if (!text) return 'No description available.'
  const parts = []
  const linkRe = /\[([^\]]+)\]\((https?:\/\/[^)]+)\)/g
  let last = 0, match
  while ((match = linkRe.exec(text)) !== null) {
    if (match.index > last) {
      parts.push(renderCitations(text.slice(last, match.index)))
    }
    parts.push(
      <a key={match.index} href={match[2]} target="_blank" rel="noreferrer"
        style={{ color: '#7c3aed', textDecoration: 'underline', fontWeight: 600 }}>
        {match[1]}
      </a>
    )
    last = match.index + match[0].length
  }
  if (last < text.length) parts.push(renderCitations(text.slice(last)))
  return parts
}

function renderCitations(text) {
  // Style (Citation: ...) as muted italic footnotes
  return text.split(/(\(Citation:[^)]+\))/g).map((part, i) =>
    /^\(Citation:/.test(part)
      ? <span key={i} style={{ color: 'var(--text-muted)', fontSize: 11, fontStyle: 'italic' }}>{part}</span>
      : part
  )
}

// ─── Constants ───────────────────────────────────────────────────────────────

const SEV_COLORS = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#d97706',
  low: '#65a30d',
  info: '#0ea5e9',
}

const COUNTRY_FLAGS = {
  'Russia': '🇷🇺',
  'China': '🇨🇳',
  'North Korea': '🇰🇵',
  'Iran': '🇮🇷',
  'United States': '🇺🇸',
  'India': '🇮🇳',
  'Unknown': '🌐',
}

const MOTIVATION_COLORS = {
  financial: '#16a34a',
  espionage: '#2563eb',
  destruction: '#dc2626',
  hacktivism: '#7c3aed',
  unknown: '#6b7280',
}

const TABS = [
  { key: 'newsroom', label: 'Newsroom', icon: Radio },
  { key: 'cves', label: 'CVE', icon: Database },
  { key: 'groups', label: 'Threat Groups', icon: Users },
]

// ─── Utility helpers ──────────────────────────────────────────────────────────

function fmtDate(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
}

function epssColor(score) {
  if (score == null) return 'var(--text-muted)'
  if (score >= 0.5) return '#dc2626'
  if (score >= 0.1) return '#d97706'
  return '#16a34a'
}

function sevColor(sev) {
  return SEV_COLORS[sev?.toLowerCase()] || '#6b7280'
}

function SevBadge({ severity }) {
  const color = sevColor(severity)
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center',
      background: `${color}22`, color, border: `1px solid ${color}44`,
      borderRadius: 4, padding: '2px 8px', fontSize: 11, fontWeight: 700,
      textTransform: 'uppercase', letterSpacing: '0.05em', whiteSpace: 'nowrap',
    }}>
      {severity || 'Unknown'}
    </span>
  )
}

function Pill({ label, color = '#6b7280', small }) {
  return (
    <span style={{
      display: 'inline-block',
      padding: small ? '1px 6px' : '2px 8px',
      borderRadius: 999,
      background: `${color}22`,
      color,
      border: `1px solid ${color}44`,
      fontSize: small ? 10 : 11,
      fontWeight: 600,
      whiteSpace: 'nowrap',
    }}>{label}</span>
  )
}

function CountBadge({ count, color = '#6b7280' }) {
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
      background: `${color}22`, color, border: `1px solid ${color}44`,
      borderRadius: 10, padding: '1px 7px', fontSize: 11, fontWeight: 700,
      minWidth: 22,
    }}>{count}</span>
  )
}

function InlineSpinner({ size = 16 }) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center' }}>
      <span style={{
        width: size, height: size,
        border: `2px solid var(--border)`,
        borderTop: `2px solid var(--accent)`,
        borderRadius: '50%',
        animation: 'spin 0.7s linear infinite',
        display: 'inline-block',
      }} />
      <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
    </span>
  )
}

function SectionTitle({ children }) {
  return (
    <div style={{
      fontSize: 11, fontWeight: 700, textTransform: 'uppercase',
      letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 10,
    }}>
      {children}
    </div>
  )
}

function Divider() {
  return <div style={{ borderTop: '1px solid var(--border)', margin: '16px 0' }} />
}

// ─── Modal ────────────────────────────────────────────────────────────────────

function Modal({ title, onClose, children, width = 520 }) {
  useEffect(() => {
    const onKey = e => e.key === 'Escape' && onClose()
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 1000,
      background: 'rgba(0,0,0,0.6)', display: 'flex',
      alignItems: 'center', justifyContent: 'center', padding: 24,
    }} onClick={e => e.target === e.currentTarget && onClose()}>
      <div style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)',
        borderRadius: 12, padding: 24, width, maxWidth: '100%',
        maxHeight: '90vh', overflowY: 'auto',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
          <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)' }}>{title}</div>
          <button onClick={onClose} style={{
            background: 'none', border: 'none', cursor: 'pointer',
            color: 'var(--text-muted)', padding: 4, display: 'flex', alignItems: 'center',
          }}><X size={18} /></button>
        </div>
        {children}
      </div>
    </div>
  )
}

// ─── Stats Bar ────────────────────────────────────────────────────────────────

function StatsBar({ stats, syncing, onSync, syncResult, onStatClick }) {
  return (
    <div style={{ marginBottom: 24 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
        <div style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 10 }}>
          <Shield size={22} color="#6366f1" />
          Threat Intelligence Center
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          {syncResult && (
            <span style={{ fontSize: 12, color: syncResult.status === 'ok' ? '#16a34a' : '#dc2626' }}>
              {syncResult.message || (syncResult.status === 'ok' ? 'Sync complete' : 'Sync failed')}
            </span>
          )}
          <Button onClick={onSync} disabled={syncing} variant="ghost" size="sm">
            {syncing ? <InlineSpinner size={14} /> : <RefreshCw size={14} />}
            {syncing ? 'Syncing…' : 'Sync Intel'}
          </Button>
        </div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12 }}>
        <StatCard
          label="Total Intel CVEs"
          value={stats?.total_cves?.toLocaleString() ?? '—'}
          icon={Database}
          color="#6366f1"
          onClick={() => onStatClick('all_cves')}
        />
        <StatCard
          label="CISA KEV CVEs"
          value={stats?.kev_count?.toLocaleString() ?? '—'}
          icon={AlertTriangle}
          color="#dc2626"
          sub="Known exploited"
          onClick={() => onStatClick('kev')}
        />
        <StatCard
          label="High EPSS (>0.5)"
          value={stats?.high_epss_count?.toLocaleString() ?? '—'}
          icon={TrendingUp}
          color="#ea580c"
          sub={stats?.avg_epss != null ? `Avg EPSS: ${(stats.avg_epss * 100).toFixed(1)}%` : undefined}
          onClick={() => onStatClick('high_epss')}
        />
        <StatCard
          label="Threat Groups"
          value={stats?.exposed_groups?.toLocaleString() ?? '—'}
          icon={Users}
          color="#d97706"
          sub="≥50% TTP overlap"
          onClick={() => onStatClick('exposed_groups')}
        />
        <StatCard
          label="Affected Assets"
          value={stats?.affected_assets?.toLocaleString() ?? '—'}
          icon={Server}
          color="#0ea5e9"
          onClick={() => onStatClick('affected_assets')}
        />
      </div>
    </div>
  )
}

function Server({ size = 16, color }) {
  // Fallback icon component since we import from lucide separately
  return <Globe size={size} color={color} />
}

// ─── Tab Bar ─────────────────────────────────────────────────────────────────

function TabBar({ active, onChange }) {
  return (
    <div style={{
      display: 'flex', gap: 2, borderBottom: '1px solid var(--border)',
      marginBottom: 24, overflowX: 'auto',
    }}>
      {TABS.map(({ key, label, icon: Icon }) => {
        const isActive = active === key
        return (
          <button
            key={key}
            onClick={() => onChange(key)}
            style={{
              display: 'flex', alignItems: 'center', gap: 7,
              padding: '10px 18px',
              background: 'none', border: 'none',
              borderBottom: isActive ? '2px solid var(--accent)' : '2px solid transparent',
              color: isActive ? 'var(--accent)' : 'var(--text-muted)',
              fontWeight: isActive ? 700 : 500,
              fontSize: 13, cursor: 'pointer',
              marginBottom: -1, whiteSpace: 'nowrap',
              transition: 'color 0.15s',
            }}
          >
            <Icon size={14} />
            {label}
          </button>
        )
      })}
    </div>
  )
}

// ─── Newsroom Tab ─────────────────────────────────────────────────────────────


function HighEpssCves({ cves, onSearchCve }) {
  const top = [...cves].sort((a, b) => (b.epss_score || 0) - (a.epss_score || 0)).slice(0, 12)
  return (
    <div>
      <SectionTitle><TrendingUp size={11} style={{ display: 'inline', marginRight: 4 }} />Top EPSS CVEs</SectionTitle>
      {top.length === 0 ? (
        <div style={{ fontSize: 12, color: 'var(--text-muted)', padding: '12px 0' }}>No CVE data — run Sync Intel</div>
      ) : top.map(c => (
        <div
          key={c.cve_id}
          onClick={() => onSearchCve && onSearchCve(c.cve_id)}
          style={{
            display: 'flex', alignItems: 'center', gap: 8, padding: '7px 0',
            borderBottom: '1px solid var(--border)',
            cursor: onSearchCve ? 'pointer' : 'default',
          }}
        >
          <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)', flex: 1, fontFamily: 'monospace' }}>{c.cve_id}</span>
          <span style={{ fontSize: 12, fontWeight: 700, color: epssColor(c.epss_score) }}>
            {c.epss_score != null ? `${(c.epss_score * 100).toFixed(1)}%` : '—'}
          </span>
          {c.in_kev && <Pill label="KEV" color="#dc2626" small />}
        </div>
      ))}
    </div>
  )
}

function ThreatGroupSpotlight() {
  const [groups, setGroups] = useState([])
  useEffect(() => {
    fetch('/api/threat-intel/groups?limit=6')
      .then(r => r.ok ? r.json() : [])
      .then(data => setGroups(Array.isArray(data) ? data.slice(0, 6) : []))
      .catch(() => {})
  }, [])

  if (groups.length === 0) return null

  return (
    <div>
      <SectionTitle><Users size={11} style={{ display: 'inline', marginRight: 4 }} />Threat Actor Spotlight</SectionTitle>
      {groups.map(g => (
        <div key={g.id} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '7px 0', borderBottom: '1px solid var(--border)' }}>
          <span style={{ fontSize: 15 }}>{COUNTRY_FLAGS[g.country] || '🌐'}</span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)' }}>{g.name}</div>
            <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
              {g.mitre_id && <span style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'monospace' }}>{g.mitre_id}</span>}
              {(g.first_seen || g.last_seen) && (
                <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                  {g.first_seen && g.last_seen ? `${g.first_seen} – ${g.last_seen}` : g.first_seen || g.last_seen}
                </span>
              )}
            </div>
          </div>
          {g.motivation && (
            <span style={{
              fontSize: 10, fontWeight: 600, padding: '2px 7px', borderRadius: 10,
              background: (MOTIVATION_COLORS[g.motivation] || '#6b7280') + '20',
              color: MOTIVATION_COLORS[g.motivation] || '#6b7280',
            }}>{g.motivation}</span>
          )}
          {g.is_ransomware && <Pill label="RW" color="#ea580c" small />}
        </div>
      ))}
    </div>
  )
}

// ─── Advisory type helpers ────────────────────────────────────────────────────

const ADVISORY_TYPE_META = {
  advisory:   { label: 'Advisory',   color: '#2563eb' },
  alert:      { label: 'Alert',      color: '#dc2626' },
  ics:        { label: 'ICS',        color: '#d97706' },
  ics_medical:{ label: 'ICS-Med',    color: '#9333ea' },
  malware:    { label: 'Malware',    color: '#64748b' },
}

function AdvisoryTypeBadge({ type }) {
  const meta = ADVISORY_TYPE_META[type] || { label: type, color: '#6b7280' }
  return (
    <span style={{
      fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 10,
      background: meta.color + '18', color: meta.color,
      border: `1px solid ${meta.color}30`, whiteSpace: 'nowrap',
    }}>{meta.label}</span>
  )
}

function AdvisoriesPanel({ onSearchCve }) {
  const [items, setItems] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [showIcs, setShowIcs] = useState(false)
  const [page, setPage] = useState(0)
  const PAGE = 10

  const fetchAdvisories = useCallback(async () => {
    setLoading(true)
    try {
      const params = { limit: PAGE, offset: page * PAGE }
      if (search) params.search = search
      if (!showIcs) params.exclude_ics = true
      const data = await getCisaAdvisories(params)
      setItems(data.items || [])
      setTotal(data.total || 0)
    } catch {
      setItems([])
    } finally {
      setLoading(false)
    }
  }, [search, showIcs, page])

  useEffect(() => { fetchAdvisories() }, [fetchAdvisories])
  useEffect(() => { setPage(0) }, [search, showIcs])

  return (
    <div style={{ marginTop: 24 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14, flexWrap: 'wrap' }}>
        <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 6 }}>
          <FileText size={14} /> CISA Advisories
        </h3>
        {total > 0 && (
          <span style={{ fontSize: 12, color: 'var(--text-muted)', marginLeft: 2 }}>{total} total</span>
        )}
        <div style={{ flex: 1 }} />
        {/* Search */}
        <div style={{ position: 'relative' }}>
          <Search size={12} style={{ position: 'absolute', left: 8, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', pointerEvents: 'none' }} />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search advisories…"
            style={{
              background: 'var(--bg-card)', border: '1px solid var(--border)',
              color: 'var(--text-primary)', borderRadius: 7, padding: '5px 10px 5px 28px',
              fontSize: 12, outline: 'none', width: 180,
            }}
          />
        </div>
        <label style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 12, color: 'var(--text-secondary)', cursor: 'pointer', whiteSpace: 'nowrap' }}>
          <input type="checkbox" checked={showIcs} onChange={e => setShowIcs(e.target.checked)} />
          Include ICS
        </label>
      </div>

      {loading ? (
        <div style={{ display: 'flex', justifyContent: 'center', padding: '20px 0' }}><Spinner /></div>
      ) : items.length === 0 ? (
        <EmptyState icon={FileText} title="No advisories" sub="Run Sync Intel to load CISA advisories" />
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {items.map(adv => {
            const accentColor = ADVISORY_TYPE_META[adv.advisory_type]?.color || '#2563eb'
            // Only show advisory_id if it looks like a real structured ID (AA##/ICSA/ICSMA)
            const structuredId = /^(AA|ICSA|ICSMA)-?\d/i.test(adv.advisory_id) ? adv.advisory_id : null
            return (
              <div key={adv.id} style={{
                background: 'var(--bg-card)', border: '1px solid var(--border)',
                borderRadius: 10, padding: '11px 14px',
                borderLeft: `3px solid ${accentColor}`,
              }}>
                {/* Row 1: title + link */}
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', lineHeight: 1.4 }}>
                      {adv.title}
                    </div>
                  </div>
                  {adv.url && (
                    <a
                      href={adv.url}
                      target="_blank"
                      rel="noreferrer"
                      title="View on CISA"
                      style={{
                        flexShrink: 0, color: 'var(--text-muted)',
                        display: 'flex', alignItems: 'center',
                        padding: '3px 5px', borderRadius: 5,
                        border: '1px solid var(--border)',
                        textDecoration: 'none', marginTop: 1,
                      }}
                      onClick={e => e.stopPropagation()}
                    >
                      <ExternalLink size={11} />
                    </a>
                  )}
                </div>

                {/* Row 2: meta chips */}
                <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', alignItems: 'center', marginTop: 7 }}>
                  <AdvisoryTypeBadge type={adv.advisory_type} />
                  {structuredId && (
                    <span style={{ fontSize: 10, fontWeight: 700, color: accentColor, fontFamily: 'monospace', padding: '1px 5px', background: accentColor + '14', borderRadius: 4 }}>
                      {structuredId}
                    </span>
                  )}
                  {adv.pub_date && (
                    <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>{adv.pub_date}</span>
                  )}
                  {adv.cve_count > 0 && (
                    <span
                      onClick={() => adv.cve_ids[0] && onSearchCve && onSearchCve(adv.cve_ids[0])}
                      title={adv.cve_ids.slice(0, 5).join(', ')}
                      style={{ fontSize: 10, color: '#dc2626', padding: '1px 6px', background: '#dc262615', borderRadius: 4, cursor: adv.cve_ids[0] ? 'pointer' : 'default', fontWeight: 600 }}
                    >
                      {adv.cve_count} CVE{adv.cve_count !== 1 ? 's' : ''}
                    </span>
                  )}
                  {adv.co_sealers.map(s => (
                    <span key={s} style={{ fontSize: 10, color: 'var(--text-muted)', padding: '1px 5px', background: 'var(--bg-muted)', borderRadius: 4, fontWeight: 600 }}>{s}</span>
                  ))}
                  {adv.sectors.map(s => (
                    <span key={s} style={{ fontSize: 10, color: '#0ea5e9', padding: '1px 5px', background: '#0ea5e915', borderRadius: 4 }}>{s}</span>
                  ))}
                  {adv.threat_group_names.map(g => (
                    <span key={g} style={{ fontSize: 10, color: '#7c3aed', padding: '1px 5px', background: '#7c3aed15', borderRadius: 4, fontWeight: 600 }}>👤 {g}</span>
                  ))}
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Pagination */}
      {total > PAGE && (
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 12 }}>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{total} entries · page {page + 1} of {Math.ceil(total / PAGE)}</span>
          <div style={{ display: 'flex', gap: 8 }}>
            <Button size="sm" variant="ghost" disabled={page === 0} onClick={() => setPage(p => p - 1)}>Previous</Button>
            <Button size="sm" variant="ghost" disabled={(page + 1) * PAGE >= total} onClick={() => setPage(p => p + 1)}>Next</Button>
          </div>
        </div>
      )}
    </div>
  )
}

function NewsroomTab({ cves, onSearchCve }) {
  const [ransomwareOnly, setRansomwareOnly] = useState(false)
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(0)
  const PAGE = 15

  const kevCves = cves
    .filter(c => c.in_kev)
    .filter(c => !ransomwareOnly || (c.kev_ransomware_use && c.kev_ransomware_use !== 'Unknown'))
    .filter(c => !search || c.cve_id.toLowerCase().includes(search.toLowerCase()) || (c.description || '').toLowerCase().includes(search.toLowerCase()))
    .sort((a, b) => {
      if (!a.kev_date_added) return 1
      if (!b.kev_date_added) return -1
      return new Date(b.kev_date_added) - new Date(a.kev_date_added)
    })

  const pageSlice = kevCves.slice(page * PAGE, (page + 1) * PAGE)
  const ransomwareCount = cves.filter(c => c.in_kev && c.kev_ransomware_use && c.kev_ransomware_use !== 'Unknown').length
  const overdueCount = cves.filter(c => c.in_kev && c.kev_due_date && new Date(c.kev_due_date) < new Date()).length

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 300px', gap: 20 }}>

      {/* Left: KEV Feed */}
      <div>
        {/* Summary pills */}
        <div style={{ display: 'flex', gap: 10, marginBottom: 16, flexWrap: 'wrap' }}>
          {[
            { label: `${ransomwareCount} ransomware-linked`, color: '#ea580c' },
            { label: `${overdueCount} missed KEV deadlines`, color: '#7c3aed' },
          ].map(({ label, color }) => (
            <span key={label} style={{
              fontSize: 12, fontWeight: 600, padding: '4px 10px',
              background: color + '18', color, borderRadius: 20,
              border: `1px solid ${color}30`,
            }}>{label}</span>
          ))}
        </div>

        {/* Filter bar */}
        <div style={{ display: 'flex', gap: 10, marginBottom: 14, alignItems: 'center' }}>
          <div style={{ position: 'relative', flex: 1 }}>
            <Search size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', pointerEvents: 'none' }} />
            <input
              value={search}
              onChange={e => { setSearch(e.target.value); setPage(0) }}
              placeholder="Search CVE ID or description…"
              style={{
                width: '100%', boxSizing: 'border-box',
                background: 'var(--bg-card)', border: '1px solid var(--border)',
                color: 'var(--text-primary)', borderRadius: 7, padding: '7px 10px 7px 32px',
                fontSize: 12, outline: 'none',
              }}
            />
          </div>
          <label style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 12, color: 'var(--text-secondary)', cursor: 'pointer', whiteSpace: 'nowrap' }}>
            <input type="checkbox" checked={ransomwareOnly} onChange={e => { setRansomwareOnly(e.target.checked); setPage(0) }} />
            Ransomware only
          </label>
        </div>

        {/* KEV entries */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {pageSlice.length === 0 ? (
            <EmptyState icon={AlertCircle} title="No KEV entries" sub="Run Sync Intel to load the CISA catalog" />
          ) : pageSlice.map(c => {
            const isOverdue = c.kev_due_date && new Date(c.kev_due_date) < new Date()
            const isRansomware = c.kev_ransomware_use && c.kev_ransomware_use !== 'Unknown'
            return (
              <div key={c.cve_id} style={{
                background: 'var(--bg-card)', border: '1px solid var(--border)',
                borderRadius: 10, padding: '12px 14px',
                borderLeft: `3px solid ${isRansomware ? '#ea580c' : '#dc2626'}`,
                display: 'flex', gap: 14, alignItems: 'flex-start',
              }}>
                {/* CVE + date */}
                <div style={{ minWidth: 130 }}>
                  <div style={{ fontWeight: 700, fontSize: 13, color: '#dc2626', fontFamily: 'monospace' }}>{c.cve_id}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>Added {fmtDate(c.kev_date_added)}</div>
                  <div style={{ fontSize: 11, color: isOverdue ? '#dc2626' : 'var(--text-muted)', marginTop: 1, fontWeight: isOverdue ? 700 : 400 }}>
                    {isOverdue ? '⚠ Overdue' : `Due ${fmtDate(c.kev_due_date)}`}
                  </div>
                </div>

                {/* Description */}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{
                    fontSize: 12, color: 'var(--text-secondary)',
                    overflow: 'hidden', display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical',
                  }}>
                    {c.description || 'No description available'}
                  </div>
                  <div style={{ display: 'flex', gap: 6, marginTop: 6, flexWrap: 'wrap' }}>
                    {isRansomware && <Pill label="Ransomware" color="#ea580c" small />}
                    {c.cvss3_score != null && (
                      <span style={{ fontSize: 11, color: 'var(--text-muted)', padding: '1px 6px', background: 'var(--bg-muted)', borderRadius: 4 }}>
                        CVSS {c.cvss3_score.toFixed(1)}
                      </span>
                    )}
                    {c.epss_score != null && (
                      <span style={{ fontSize: 11, fontWeight: 700, color: epssColor(c.epss_score), padding: '1px 6px', background: epssColor(c.epss_score) + '15', borderRadius: 4 }}>
                        EPSS {(c.epss_score * 100).toFixed(1)}%
                      </span>
                    )}
                  </div>
                </div>

                {/* Action */}
                <button
                  onClick={() => onSearchCve && onSearchCve(c.cve_id)}
                  title="Search this CVE in CVE Intel"
                  style={{
                    flexShrink: 0, background: 'transparent', border: '1px solid var(--border)',
                    borderRadius: 6, padding: '5px 8px', cursor: 'pointer', color: 'var(--text-muted)',
                    display: 'flex', alignItems: 'center', gap: 4, fontSize: 11,
                  }}
                >
                  <Search size={12} /> Search
                </button>
              </div>
            )
          })}
        </div>

        {/* Pagination */}
        {kevCves.length > PAGE && (
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 12 }}>
            <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{kevCves.length} entries · page {page + 1} of {Math.ceil(kevCves.length / PAGE)}</span>
            <div style={{ display: 'flex', gap: 8 }}>
              <Button size="sm" variant="ghost" disabled={page === 0} onClick={() => setPage(p => p - 1)}>Previous</Button>
              <Button size="sm" variant="ghost" disabled={(page + 1) * PAGE >= kevCves.length} onClick={() => setPage(p => p + 1)}>Next</Button>
            </div>
          </div>
        )}

      </div>

      {/* Middle: CISA Advisories */}
      <div>
        <AdvisoriesPanel onSearchCve={onSearchCve} />
      </div>

      {/* Right: EPSS + Threat Groups */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 12, padding: 16 }}>
          <HighEpssCves cves={cves} onSearchCve={onSearchCve} />
        </div>
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 12, padding: 16 }}>
          <ThreatGroupSpotlight />
        </div>
      </div>
    </div>
  )
}

// ─── CVE Intel Tab ────────────────────────────────────────────────────────────

const SOURCE_DEFS = [
  { key: 'nvd',  label: 'NVD',  color: '#2563eb', test: cve => cve.cvss3_score != null || cve.description },
  { key: 'epss', label: 'EPSS', color: '#7c3aed', test: cve => cve.epss_score != null },
  { key: 'kev',  label: 'KEV',  color: '#dc2626', test: cve => cve.in_kev },
  { key: 'exploit', label: 'ExploitDB', color: '#ea580c', test: cve => cve.has_public_exploit },
]

function CveSources({ cve }) {
  const active = SOURCE_DEFS.filter(s => s.test(cve))
  if (active.length === 0) return <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
  return (
    <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
      {active.map(s => (
        <span key={s.key} style={{
          display: 'inline-block', padding: '1px 5px', borderRadius: 3,
          fontSize: 10, fontWeight: 700, letterSpacing: '0.02em',
          background: `${s.color}18`, color: s.color, border: `1px solid ${s.color}30`,
          whiteSpace: 'nowrap',
        }}>
          {s.label}
        </span>
      ))}
    </div>
  )
}

function CveRow({ cve, expanded, onToggle }) {
  return (
    <>
      <tr
        onClick={onToggle}
        style={{
          borderBottom: '1px solid var(--border)',
          cursor: 'pointer',
          background: expanded ? 'var(--bg-muted)' : 'transparent',
          transition: 'background 0.1s',
        }}
        onMouseEnter={e => !expanded && (e.currentTarget.style.background = 'var(--bg-muted)')}
        onMouseLeave={e => !expanded && (e.currentTarget.style.background = 'transparent')}
      >
        <td style={{ padding: '9px 12px', fontWeight: 600, color: '#dc2626', fontSize: 13, whiteSpace: 'nowrap' }}>
          {cve.cve_id}
        </td>
        <td style={{ padding: '9px 12px' }}>
          {cve.cvss3_score != null ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <div style={{
                width: 36, height: 36, borderRadius: '50%', display: 'flex',
                alignItems: 'center', justifyContent: 'center',
                background: `${cve.cvss3_score >= 9 ? '#dc2626' : cve.cvss3_score >= 7 ? '#ea580c' : cve.cvss3_score >= 4 ? '#d97706' : '#65a30d'}22`,
                color: cve.cvss3_score >= 9 ? '#dc2626' : cve.cvss3_score >= 7 ? '#ea580c' : cve.cvss3_score >= 4 ? '#d97706' : '#65a30d',
                fontWeight: 800, fontSize: 12,
              }}>
                {cve.cvss3_score.toFixed(1)}
              </div>
            </div>
          ) : <span style={{ color: 'var(--text-muted)' }}>—</span>}
        </td>
        <td style={{ padding: '9px 12px' }}>
          <span style={{ fontWeight: 700, fontSize: 13, color: epssColor(cve.epss_score) }}>
            {cve.epss_score != null ? `${(cve.epss_score * 100).toFixed(1)}%` : '—'}
          </span>
          {cve.epss_percentile != null && (
            <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>
              p{Math.round(cve.epss_percentile * 100)}
            </div>
          )}
        </td>
        <td style={{ padding: '9px 12px' }}>
          {cve.in_kev ? (
            <span style={{
              display: 'inline-flex', alignItems: 'center', gap: 3,
              background: '#dc262620', color: '#dc2626', border: '1px solid #dc262640',
              borderRadius: 4, padding: '2px 7px', fontSize: 11, fontWeight: 700,
            }}>
              <AlertTriangle size={10} />KEV
            </span>
          ) : <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>}
        </td>
        <td style={{ padding: '9px 12px' }}>
          {cve.has_public_exploit ? (
            <span style={{
              display: 'inline-flex', alignItems: 'center', gap: 3,
              background: '#ea580c20', color: '#ea580c', border: '1px solid #ea580c40',
              borderRadius: 4, padding: '2px 7px', fontSize: 11, fontWeight: 700,
            }}>
              <Zap size={10} />Exploit
            </span>
          ) : <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>}
        </td>
        <td style={{ padding: '9px 12px' }}>
          <CveSources cve={cve} />
        </td>
        <td style={{ padding: '9px 12px' }}>
          {cve.in_scan_count > 0 ? (
            <CountBadge count={cve.in_scan_count} color="#6366f1" />
          ) : <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>0</span>}
        </td>
        <td style={{ padding: '9px 12px', fontSize: 12, color: 'var(--text-muted)' }}>
          {fmtDate(cve.published_date)}
        </td>
      </tr>
      {expanded && (
        <tr style={{ background: 'var(--bg-muted)' }}>
          <td colSpan={8} style={{ padding: '0 12px 14px 12px' }}>
            <div style={{
              borderTop: '1px solid var(--border)', paddingTop: 12,
              display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16,
            }}>
              <div>
                <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 6 }}>Description</div>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                  {cve.description || 'No description available.'}
                </div>
              </div>
              <div>
                {cve.in_kev && (
                  <div style={{ marginBottom: 8 }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 4 }}>KEV Details</div>
                    <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                      Added: {fmtDate(cve.kev_date_added)} · Due: {fmtDate(cve.kev_due_date)}
                    </div>
                    {cve.kev_ransomware_use && cve.kev_ransomware_use !== 'Unknown' && (
                      <div style={{ marginTop: 4 }}>
                        <Pill label={`Ransomware: ${cve.kev_ransomware_use}`} color="#dc2626" small />
                      </div>
                    )}
                  </div>
                )}
                <div>
                  <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 4 }}>NVD Link</div>
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{ fontSize: 12, color: 'var(--accent)', display: 'flex', alignItems: 'center', gap: 4 }}
                  >
                    <ExternalLink size={11} />
                    View on NVD
                  </a>
                </div>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

function CveIntelTab({ initialSearch = '', initialKevOnly = false, initialMinEpss = 0, initialInScanOnly = false }) {
  const { activeScanId } = useScan()
  const [cves, setCves] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [expandedId, setExpandedId] = useState(null)
  const [page, setPage] = useState(0)
  const PAGE_SIZE = 50

  // Filters
  const [search, setSearch] = useState(initialSearch)
  const [kevOnly, setKevOnly] = useState(initialKevOnly)
  const [minEpss, setMinEpss] = useState(initialMinEpss)
  const [minCvss, setMinCvss] = useState(0)
  const [inScanOnly, setInScanOnly] = useState(initialInScanOnly)

  // Sorting
  const [sortBy, setSortBy] = useState(null)
  const [sortDir, setSortDir] = useState('desc')

  // Sync external filters (e.g. from KPI card clicks)
  useEffect(() => {
    if (initialSearch) setSearch(initialSearch)
    setKevOnly(initialKevOnly)
    setMinEpss(initialMinEpss)
    setInScanOnly(initialInScanOnly)
    setPage(0)
  }, [initialSearch, initialKevOnly, initialMinEpss, initialInScanOnly])

  const fetchCves = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const params = new URLSearchParams({
        limit: PAGE_SIZE,
        offset: page * PAGE_SIZE,
      })
      if (search) params.set('search', search)
      if (kevOnly) params.set('kev_only', 'true')
      if (minEpss > 0) params.set('min_epss', minEpss)
      if (minCvss > 0) params.set('min_cvss', minCvss)
      if (inScanOnly) params.set('in_scan', activeScanId || 'all')
      if (sortBy) { params.set('sort_by', sortBy); params.set('sort_dir', sortDir) }
      const data = await getThreatCves(Object.fromEntries(params))
      const items = Array.isArray(data) ? data : (data.items || [])
      setCves(items)
      setTotal(data.total || items.length)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [search, kevOnly, minEpss, minCvss, inScanOnly, activeScanId, page, sortBy, sortDir])

  useEffect(() => { fetchCves() }, [fetchCves])

  return (
    <div>
      {/* Filter bar */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap',
        marginBottom: 16, padding: 14,
        background: 'var(--bg-card)', border: '1px solid var(--border)',
        borderRadius: 10,
      }}>
        <Search size={14} color="var(--text-muted)" />
        <input
          value={search}
          onChange={e => { setSearch(e.target.value); setPage(0) }}
          placeholder="Search CVE ID or keyword…"
          style={{
            background: 'none', border: 'none', outline: 'none',
            color: 'var(--text-primary)', fontSize: 13, flex: 1, minWidth: 180,
          }}
        />
        <div style={{ width: 1, height: 20, background: 'var(--border)' }} />
        <label style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 12, color: 'var(--text-secondary)', cursor: 'pointer', whiteSpace: 'nowrap' }}>
          <input type="checkbox" checked={kevOnly} onChange={e => { setKevOnly(e.target.checked); setPage(0) }} />
          KEV Only
        </label>
        <label style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 12, color: 'var(--text-secondary)', cursor: 'pointer', whiteSpace: 'nowrap' }} title={activeScanId ? 'CVEs found in the selected scan' : 'CVEs found across all uploaded scans'}>
          <input type="checkbox" checked={inScanOnly} onChange={e => { setInScanOnly(e.target.checked); setPage(0) }} />
          In My Environment
        </label>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, whiteSpace: 'nowrap' }}>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Min EPSS</span>
          <input
            type="range" min={0} max={1} step={0.05}
            value={minEpss}
            onChange={e => { setMinEpss(parseFloat(e.target.value)); setPage(0) }}
            style={{ width: 80 }}
          />
          <span style={{ fontSize: 12, color: epssColor(minEpss), fontWeight: 600, minWidth: 36 }}>
            {(minEpss * 100).toFixed(0)}%
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, whiteSpace: 'nowrap' }}>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Min CVSS</span>
          <input
            type="range" min={0} max={10} step={0.5}
            value={minCvss}
            onChange={e => { setMinCvss(parseFloat(e.target.value)); setPage(0) }}
            style={{ width: 80 }}
          />
          <span style={{ fontSize: 12, fontWeight: 600, minWidth: 24, color: 'var(--text-secondary)' }}>
            {minCvss.toFixed(1)}
          </span>
        </div>
      </div>

      {error && (
        <div style={{ padding: '12px 16px', background: '#dc262620', border: '1px solid #dc262640', borderRadius: 8, color: '#dc2626', fontSize: 13, marginBottom: 12 }}>
          Failed to load CVEs: {error}
        </div>
      )}

      {loading ? <Spinner /> : (
        <>
          <div style={{ overflowX: 'auto', background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 10 }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  {[
                    { label: 'CVE ID', key: 'cve_id' },
                    { label: 'CVSS', key: 'cvss3_score' },
                    { label: 'EPSS', key: 'epss_score' },
                    { label: 'KEV', key: 'in_kev' },
                    { label: 'Exploit', key: null },
                    { label: 'Sources', key: null },
                    { label: 'In Scans', key: 'in_scan_count' },
                    { label: 'Published', key: 'published_date' },
                  ].map(h => {
                    const active = sortBy === h.key
                    return (
                      <th key={h.label}
                        onClick={h.key ? () => {
                          if (active) {
                            setSortDir(d => d === 'desc' ? 'asc' : 'desc')
                          } else {
                            setSortBy(h.key)
                            setSortDir('desc')
                          }
                          setPage(0)
                        } : undefined}
                        style={{
                          padding: '10px 12px', textAlign: 'left', fontWeight: 600,
                          fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.05em',
                          color: active ? 'var(--accent)' : 'var(--text-muted)', whiteSpace: 'nowrap',
                          cursor: h.key ? 'pointer' : 'default', userSelect: 'none',
                        }}
                      >
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                          {h.label}
                          {active && (sortDir === 'asc' ? <ChevronUp size={12} /> : <ChevronDown size={12} />)}
                        </span>
                      </th>
                    )
                  })}
                </tr>
              </thead>
              <tbody>
                {cves.length === 0 ? (
                  <tr>
                    <td colSpan={8} style={{ padding: '40px 12px', textAlign: 'center', color: 'var(--text-muted)' }}>
                      No CVEs match current filters
                    </td>
                  </tr>
                ) : cves.map(cve => (
                  <CveRow
                    key={cve.cve_id}
                    cve={cve}
                    expanded={expandedId === cve.cve_id}
                    onToggle={() => setExpandedId(id => id === cve.cve_id ? null : cve.cve_id)}
                  />
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 12 }}>
            <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              Page {page + 1} · {total} results
            </span>
            <div style={{ display: 'flex', gap: 8 }}>
              <Button size="sm" variant="ghost" disabled={page === 0} onClick={() => setPage(p => p - 1)}>
                Previous
              </Button>
              <Button size="sm" variant="ghost" disabled={(page + 1) * PAGE_SIZE >= total} onClick={() => setPage(p => p + 1)}>
                Next
              </Button>
            </div>
          </div>
        </>
      )}
    </div>
  )
}

// ─── Threat Groups Tab ────────────────────────────────────────────────────────

const SEVERITY_LABELS = ['Info', 'Low', 'Medium', 'High', 'Critical']
const SEVERITY_COLORS = ['#6b7280', '#16a34a', '#d97706', '#ea580c', '#dc2626']

function GroupCard({ group, exposure }) {
  const [expanded, setExpanded] = useState(false)
  const [ttps, setTtps] = useState([])
  const [loadingTtps, setLoadingTtps] = useState(false)
  const [detailExposure, setDetailExposure] = useState(null)
  const [loadingExposure, setLoadingExposure] = useState(false)
  const flag = COUNTRY_FLAGS[group.country] || '🌐'
  const motivColor = MOTIVATION_COLORS[group.motivation?.toLowerCase()] || '#6b7280'
  const sectors = group.target_sectors || []
  const visibleSectors = sectors.slice(0, 3)
  const extraCount = sectors.length - 3
  const hasExposure = exposure && exposure.matched_findings > 0
  const meetsThreshold = exposure?.meets_threshold === true

  const handleExpand = async () => {
    if (!expanded) {
      if (ttps.length === 0 && group.id) {
        setLoadingTtps(true)
        try {
          const data = await getThreatTtps({ group_id: group.id })
          setTtps(Array.isArray(data) ? data : (data.items || []))
        } catch { /* silent */ } finally {
          setLoadingTtps(false)
        }
      }
      // Fetch detailed exposure only if we know there are matches
      if (hasExposure && !detailExposure && group.id) {
        setLoadingExposure(true)
        try {
          const expParams = exposure.scan_id ? { scan_id: exposure.scan_id } : {}
          setDetailExposure(await getGroupExposure(group.id, expParams))
        } catch { /* silent */ } finally {
          setLoadingExposure(false)
        }
      }
    }
    setExpanded(e => !e)
  }

  return (
    <div style={{
      background: 'var(--bg-card)',
      border: `1px solid ${meetsThreshold ? '#dc262660' : hasExposure ? '#d9770640' : 'var(--border)'}`,
      borderRadius: 12, padding: 16, cursor: 'pointer',
      transition: 'border-color 0.15s',
    }}
      onMouseEnter={e => !expanded && (e.currentTarget.style.borderColor = meetsThreshold ? '#dc2626' : hasExposure ? '#d97706' : 'var(--accent)')}
      onMouseLeave={e => !expanded && (e.currentTarget.style.borderColor = meetsThreshold ? '#dc262660' : hasExposure ? '#d9770640' : 'var(--border)')}
      onClick={handleExpand}
    >
      {/* Exposure banner — red for threshold-met, amber for partial */}
      {meetsThreshold && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 8,
          background: '#dc262615', border: '1px solid #dc262640',
          borderRadius: 7, padding: '6px 10px', marginBottom: 10,
        }}>
          <AlertTriangle size={13} color="#dc2626" />
          <span style={{ fontSize: 12, fontWeight: 700, color: '#dc2626', flex: 1 }}>
            {exposure.matched_findings} finding{exposure.matched_findings !== 1 ? 's' : ''} affected
            · {exposure.matched_assets} asset{exposure.matched_assets !== 1 ? 's' : ''}
          </span>
          <span style={{ fontSize: 10, color: '#dc2626', fontFamily: 'monospace', whiteSpace: 'nowrap' }}>
            {exposure.matched_ttps?.length || 0}/{exposure.total_group_ttps || '?'} TTPs
            {exposure.coverage_pct != null ? ` (${exposure.coverage_pct}%)` : ''}
          </span>
        </div>
      )}
      {hasExposure && !meetsThreshold && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 8,
          background: '#d9770610', border: '1px solid #d9770630',
          borderRadius: 7, padding: '5px 10px', marginBottom: 10,
        }}>
          <span style={{ fontSize: 11, color: '#d97706', flex: 1 }}>
            Partial overlap — {exposure.matched_ttps?.length || 0}/{exposure.total_group_ttps || '?'} TTPs
            {exposure.coverage_pct != null ? ` (${exposure.coverage_pct}%)` : ''}
          </span>
        </div>
      )}

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2 }}>
            <span style={{ fontSize: 20 }}>{flag}</span>
            <span style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)' }}>{group.name}</span>
            {group.is_nation_state && (
              <Pill label="Nation-State" color="#2563eb" small />
            )}
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            {group.mitre_id && (
              <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'monospace' }}>{group.mitre_id}</span>
            )}
            {(group.first_seen || group.last_seen) && (
              <span style={{ fontSize: 10, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 3 }}>
                <Clock size={10} />
                {group.first_seen && group.last_seen ? `${group.first_seen} – ${group.last_seen}` : group.first_seen || group.last_seen}
              </span>
            )}
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4 }}>
          <Pill label={group.motivation || 'Unknown'} color={motivColor} />
          {group.is_ransomware && <Pill label="Ransomware" color="#dc2626" small />}
        </div>
      </div>

      {/* Sectors */}
      {sectors.length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginBottom: 8 }}>
          {visibleSectors.map(s => <Pill key={s} label={s} color="#6366f1" small />)}
          {extraCount > 0 && (
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>+{extraCount} more</span>
          )}
        </div>
      )}

      {/* Footer */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <CountBadge count={`${group.ttp_count || 0} TTPs`} color="#7c3aed" />
        <span style={{ color: 'var(--text-muted)' }}>
          {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </span>
      </div>

      {/* Expanded */}
      {expanded && (
        <div onClick={e => e.stopPropagation()}>
          <Divider />

          {/* Exposure details section */}
          {hasExposure && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: '#dc2626', textTransform: 'uppercase', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 5 }}>
                <AlertTriangle size={11} /> Your Environment Exposure
              </div>
              {loadingExposure ? (
                <InlineSpinner />
              ) : detailExposure ? (
                <div>
                  {/* Matched CVEs */}
                  {detailExposure.matched_cves?.length > 0 && (
                    <div style={{ marginBottom: 10 }}>
                      <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 4 }}>
                        Matching CVEs ({detailExposure.matched_cves.length})
                      </div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                        {detailExposure.matched_cves.slice(0, 10).map(cve => (
                          <span key={cve} style={{
                            fontSize: 10, fontFamily: 'monospace', fontWeight: 600,
                            background: '#dc262615', color: '#dc2626',
                            border: '1px solid #dc262640', borderRadius: 4, padding: '1px 5px',
                          }}>{cve}</span>
                        ))}
                        {detailExposure.matched_cves.length > 10 && (
                          <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>+{detailExposure.matched_cves.length - 10} more</span>
                        )}
                      </div>
                    </div>
                  )}
                  {/* Affected assets */}
                  {detailExposure.affected_assets?.length > 0 && (
                    <div style={{ marginBottom: 10 }}>
                      <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 4 }}>
                        Affected Assets ({detailExposure.matched_assets})
                      </div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                        {detailExposure.affected_assets.slice(0, 5).map(a => (
                          <div key={a.id} style={{
                            display: 'flex', alignItems: 'center', gap: 8,
                            padding: '4px 8px', background: 'var(--bg-muted)', borderRadius: 6,
                          }}>
                            <span style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--text-primary)', fontWeight: 600 }}>
                              {a.ip}
                            </span>
                            {a.hostname && (
                              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{a.hostname}</span>
                            )}
                            <span style={{ marginLeft: 'auto', fontSize: 10, color: '#dc2626', fontWeight: 700 }}>
                              {a.finding_count} finding{a.finding_count !== 1 ? 's' : ''}
                            </span>
                          </div>
                        ))}
                        {detailExposure.matched_assets > 5 && (
                          <div style={{ fontSize: 11, color: 'var(--text-muted)', paddingLeft: 8 }}>
                            +{detailExposure.matched_assets - 5} more assets
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                  {/* Top findings */}
                  {detailExposure.top_findings?.length > 0 && (
                    <div>
                      <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 4 }}>
                        Matched Findings (top {Math.min(detailExposure.top_findings.length, 5)})
                      </div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                        {detailExposure.top_findings.slice(0, 5).map(f => (
                          <div key={f.id} style={{
                            display: 'flex', alignItems: 'center', gap: 8,
                            padding: '4px 8px', background: 'var(--bg-muted)', borderRadius: 6,
                          }}>
                            <span style={{
                              fontSize: 10, fontWeight: 700, padding: '1px 5px', borderRadius: 4,
                              background: (SEVERITY_COLORS[f.severity] || '#6b7280') + '20',
                              color: SEVERITY_COLORS[f.severity] || '#6b7280',
                            }}>
                              {SEVERITY_LABELS[f.severity] || '?'}
                            </span>
                            <span style={{ fontSize: 11, color: 'var(--text-primary)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                              {f.plugin_name}
                            </span>
                            <span style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'monospace', flexShrink: 0 }}>
                              {f.asset_ip}
                            </span>
                          </div>
                        ))}
                        {detailExposure.matched_findings > 5 && (
                          <div style={{ fontSize: 11, color: 'var(--text-muted)', paddingLeft: 8 }}>
                            +{detailExposure.matched_findings - 5} more findings
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                // Fallback: show summary from exposure prop
                <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                  {exposure.matched_findings} findings across {exposure.matched_assets} assets.
                  Matched CVEs: {exposure.matched_cves?.join(', ') || '—'}
                </div>
              )}
              <Divider />
            </div>
          )}

          <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: 12 }}>
            {renderDescription(group.description)}
          </div>
          {group.aliases?.length > 0 && (
            <div style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 6 }}>Also known as</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                {group.aliases.map(a => <Pill key={a} label={a} color="#6b7280" small />)}
              </div>
            </div>
          )}
          <div>
            <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 8 }}>
              TTPs ({ttps.length})
              {hasExposure && exposure.matched_ttps?.length > 0 && (
                <span style={{ marginLeft: 8, color: '#16a34a', fontWeight: 700 }}>
                  · {exposure.matched_ttps.length} matched in your env
                </span>
              )}
            </div>
            {loadingTtps ? (
              <InlineSpinner />
            ) : ttps.length === 0 ? (
              <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>No TTPs available</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                {/* Sort matched TTPs to the top */}
                {[...ttps].sort((a, b) => {
                  const aMatch = exposure?.matched_ttps?.includes(a.technique_id) ? 0 : 1
                  const bMatch = exposure?.matched_ttps?.includes(b.technique_id) ? 0 : 1
                  return aMatch - bMatch
                }).slice(0, 15).map(t => {
                  const isMatched = exposure?.matched_ttps?.includes(t.technique_id)
                  return (
                    <div key={t.id} style={{
                      display: 'flex', alignItems: 'center', gap: 8,
                      padding: '6px 8px', borderRadius: 6,
                      borderBottom: '1px solid var(--border)',
                      background: isMatched ? '#16a34a0d' : 'transparent',
                    }}>
                      {isMatched && (
                        <span style={{
                          fontSize: 9, fontWeight: 700, color: '#16a34a',
                          background: '#16a34a20', border: '1px solid #16a34a40',
                          borderRadius: 3, padding: '1px 4px', whiteSpace: 'nowrap',
                        }}>MATCHED</span>
                      )}
                      <span style={{ fontFamily: 'monospace', fontSize: 11, color: isMatched ? '#16a34a' : '#7c3aed', fontWeight: 600 }}>
                        {t.technique_id}
                      </span>
                      <span style={{ fontSize: 12, color: 'var(--text-primary)', flex: 1 }}>{t.name}</span>
                      <Pill label={t.tactic || '?'} color="#6b7280" small />
                    </div>
                  )
                })}
                {ttps.length > 15 && (
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', paddingTop: 4 }}>
                    +{ttps.length - 15} more techniques
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function ThreatGroupsTab({ initialInMyEnv = false }) {
  const { activeScanId } = useScan()
  const [groups, setGroups] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [search, setSearch] = useState('')
  const [motivation, setMotivation] = useState('')
  const [ransomwareOnly, setRansomwareOnly] = useState(false)
  const [inScanOnly, setInScanOnly] = useState(initialInMyEnv)

  useEffect(() => { setInScanOnly(initialInMyEnv) }, [initialInMyEnv])
  // scan_id → group_id → exposure data
  const [scanExposure, setScanExposure] = useState({})
  const [loadingExposure, setLoadingExposure] = useState(false)

  const fetchGroups = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const params = new URLSearchParams()
      if (search) params.set('search', search)
      if (motivation) params.set('motivation', motivation)
      if (ransomwareOnly) params.set('is_ransomware', 'true')
      // Don't use backend in_scan — we filter client-side using scanExposure
      setGroups(await getThreatGroups(Object.fromEntries(params)))
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [search, motivation, ransomwareOnly])

  // Fetch scan exposure whenever activeScanId changes (no scan = all scans)
  useEffect(() => {
    setLoadingExposure(true)
    const url = activeScanId
      ? `/api/threat-intel/scan-exposure?scan_id=${activeScanId}`
      : `/api/threat-intel/scan-exposure`
    fetch(url)
      .then(r => r.ok ? r.json() : [])
      .then(data => {
        const byGroup = {}
        for (const item of (Array.isArray(data) ? data : [])) {
          byGroup[item.group_id] = { ...item, scan_id: activeScanId || null }
        }
        setScanExposure(byGroup)
      })
      .catch(() => setScanExposure({}))
      .finally(() => setLoadingExposure(false))
  }, [activeScanId])

  useEffect(() => { fetchGroups() }, [fetchGroups])

  // Only threshold-meeting groups count for the top banner and "In My Environment" filter
  const exposedGroups = Object.values(scanExposure).filter(e => e.meets_threshold).sort((a, b) => b.matched_findings - a.matched_findings)
  const totalExposedFindings = exposedGroups.reduce((s, e) => s + e.matched_findings, 0)

  // "In My Environment" = meets 50% threshold; partial matches still show TTP highlights
  const visibleGroups = inScanOnly
    ? groups.filter(g => scanExposure[g.id]?.meets_threshold)
    : groups

  return (
    <div>
      {/* Scan exposure summary banner */}
      <div style={{
        marginBottom: 16, padding: '12px 16px',
        background: exposedGroups.length > 0 ? '#dc262610' : 'var(--bg-card)',
        border: `1px solid ${exposedGroups.length > 0 ? '#dc262640' : 'var(--border)'}`,
        borderRadius: 10, display: 'flex', alignItems: 'center', gap: 12,
      }}>
        {loadingExposure ? (
          <><InlineSpinner size={14} /><span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Checking your environment…</span></>
        ) : exposedGroups.length > 0 ? (
          <>
            <AlertTriangle size={16} color="#dc2626" />
            <div>
              <span style={{ fontSize: 13, fontWeight: 700, color: '#dc2626' }}>
                {exposedGroups.length} threat group{exposedGroups.length !== 1 ? 's' : ''} with ≥50% TTP overlap in your environment
              </span>
              <span style={{ fontSize: 12, color: 'var(--text-muted)', marginLeft: 10 }}>
                {totalExposedFindings} findings affected{activeScanId ? ' in this scan' : ' across all scans'}
                {Object.values(scanExposure).length > exposedGroups.length && ` · ${Object.values(scanExposure).length - exposedGroups.length} more with partial overlap`}
              </span>
            </div>
          </>
        ) : (
          <>
            <CheckCircle size={16} color="#16a34a" />
            <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
              No threat groups with sufficient TTP overlap found{activeScanId ? ' in this scan' : ' across any uploaded scan'}.
            </span>
          </>
        )}
      </div>

      {/* Filter bar */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap',
        marginBottom: 16, padding: '12px 14px',
        background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 10,
      }}>
        <Search size={14} color="var(--text-muted)" />
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search threat groups…"
          style={{
            background: 'none', border: 'none', outline: 'none',
            color: 'var(--text-primary)', fontSize: 13, flex: 1, minWidth: 180,
          }}
        />
        <select
          value={motivation}
          onChange={e => setMotivation(e.target.value)}
          style={{
            background: 'var(--bg-card)', border: '1px solid var(--border)',
            color: 'var(--text-secondary)', borderRadius: 6, padding: '5px 10px', fontSize: 12, outline: 'none',
          }}
        >
          <option value="">All motivations</option>
          {['financial', 'espionage', 'destruction', 'hacktivism'].map(m => (
            <option key={m} value={m}>{m.charAt(0).toUpperCase() + m.slice(1)}</option>
          ))}
        </select>
        <label style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 12, color: 'var(--text-secondary)', cursor: 'pointer' }}>
          <input type="checkbox" checked={ransomwareOnly} onChange={e => setRansomwareOnly(e.target.checked)} />
          Ransomware only
        </label>
        <label
          style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 12, color: 'var(--text-secondary)', cursor: 'pointer', whiteSpace: 'nowrap' }}
          title={activeScanId ? 'Show only groups with CVE matches in your active scan' : 'Show only groups with CVE matches across all uploaded scans'}
        >
          <input type="checkbox" checked={inScanOnly} onChange={e => setInScanOnly(e.target.checked)} />
          In My Environment
          {!loadingExposure && inScanOnly && (
            <span style={{ fontSize: 10, color: '#dc2626', fontWeight: 700, marginLeft: 2 }}>
              ({visibleGroups.length})
            </span>
          )}
        </label>
      </div>

      {error && (
        <div style={{ padding: '12px 16px', background: '#dc262620', border: '1px solid #dc262640', borderRadius: 8, color: '#dc2626', fontSize: 13, marginBottom: 12 }}>
          Failed to load groups: {error}
        </div>
      )}

      {loading ? <Spinner /> : groups.length === 0 ? (
        <EmptyState
          icon={Users}
          title="No threat groups found"
          sub="Try adjusting your search filters"
        />
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: 14 }}>
          {visibleGroups.map(g => (
            <GroupCard
              key={g.id}
              group={g}
              exposure={scanExposure[g.id] || null}
            />
          ))}
        </div>
      )}
    </div>
  )
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function ThreatIntelCenter() {
  const { tab: tabParam } = useParams()
  const navigate = useNavigate()
  const VALID_TABS = TABS.map(t => t.key)
  const tab = VALID_TABS.includes(tabParam) ? tabParam : 'newsroom'
  const setTab = (t) => navigate(`/threat-intel/${t}`, { replace: true })
  const [stats, setStats] = useState(null)
  const [cves, setCves] = useState([])
  const [loadingStats, setLoadingStats] = useState(false)
  const [syncing, setSyncing] = useState(false)
  const [syncResult, setSyncResult] = useState(null)
  const [statsError, setStatsError] = useState(null)

  // Pre-fill CVE search/filters from Newsroom or KPI card clicks
  const [cveInitialSearch, setCveInitialSearch] = useState('')
  const [cveInitialKevOnly, setCveInitialKevOnly] = useState(false)
  const [cveInitialMinEpss, setCveInitialMinEpss] = useState(0)
  const [cveInitialInScanOnly, setCveInitialInScanOnly] = useState(false)
  const [groupsInitialInMyEnv, setGroupsInitialInMyEnv] = useState(false)

  // ── Fetch stats ──
  useEffect(() => {
    const fetchStats = async () => {
      setLoadingStats(true)
      setStatsError(null)
      try {
        setStats(await getThreatIntelStats())
      } catch (e) {
        setStatsError(e.message)
        setStats({})
      } finally {
        setLoadingStats(false)
      }
    }
    fetchStats()
  }, [])

  // ── Fetch CVEs (for newsroom panels) ──
  useEffect(() => {
    const fetchCves = async () => {
      try {
        const data = await getThreatCves({ limit: 100 })
        setCves(Array.isArray(data) ? data : (data.items || []))
      } catch { setCves([]) }
    }
    fetchCves()
  }, [])

  // ── Sync handler ──
  const handleSync = async () => {
    setSyncing(true)
    setSyncResult(null)
    try {
      const data = await syncThreatIntel()
      setSyncResult(data)
      // Refresh stats after sync
      try { setStats(await getThreatIntelStats()) } catch { /* ignore */ }
    } catch (e) {
      setSyncResult({ status: 'error', message: e.message })
    } finally {
      setSyncing(false)
    }
  }

  const handleSearchCve = (cveId) => {
    setCveInitialSearch(cveId)
    setCveInitialKevOnly(false)
    setCveInitialMinEpss(0)
    setCveInitialInScanOnly(false)
    setTab('cves')
  }

  const handleStatClick = (key) => {
    setCveInitialSearch('')
    setCveInitialKevOnly(false)
    setCveInitialMinEpss(0)
    setCveInitialInScanOnly(false)
    setGroupsInitialInMyEnv(false)
    if (key === 'all_cves') {
      setTab('cves')
    } else if (key === 'kev') {
      setCveInitialKevOnly(true)
      setTab('cves')
    } else if (key === 'high_epss') {
      setCveInitialMinEpss(0.5)
      setTab('cves')
    } else if (key === 'exposed_groups') {
      setGroupsInitialInMyEnv(true)
      setTab('groups')
    } else if (key === 'affected_assets') {
      setCveInitialInScanOnly(true)
      setTab('cves')
    }
  }

  return (
    <div style={{ padding: '24px 28px', maxWidth: 1400, margin: '0 auto' }}>
      {/* Stats bar */}
      <StatsBar
        stats={stats}
        syncing={syncing}
        onSync={handleSync}
        syncResult={syncResult}
        onStatClick={handleStatClick}
      />

      {statsError && (
        <div style={{
          padding: '10px 14px', background: '#d9772620', border: '1px solid #d9772640',
          borderRadius: 8, color: '#d97706', fontSize: 12, marginBottom: 16,
          display: 'flex', alignItems: 'center', gap: 8,
        }}>
          <AlertTriangle size={13} />
          Threat intel endpoints not yet available — backend sync needed. ({statsError})
        </div>
      )}

      {/* Tab bar */}
      <TabBar active={tab} onChange={setTab} />

      {/* Tab content */}
      {tab === 'newsroom' && (
        <NewsroomTab
          cves={cves}
          onSearchCve={handleSearchCve}
        />
      )}

      {tab === 'cves' && (
        <CveIntelTab
          initialSearch={cveInitialSearch}
          initialKevOnly={cveInitialKevOnly}
          initialMinEpss={cveInitialMinEpss}
          initialInScanOnly={cveInitialInScanOnly}
        />
      )}

      {tab === 'groups' && (
        <ThreatGroupsTab initialInMyEnv={groupsInitialInMyEnv} />
      )}
    </div>
  )
}
