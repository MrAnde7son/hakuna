import React, { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { Search, Clock, Filter, ChevronDown, ChevronRight, X, Radio } from 'lucide-react'
import { searchSiemEvents, getSiemEvent, getSiemSourceSystems } from '../../api'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import { PageHeader, EmptyState } from '../shared/ui'
import { useIsMobile } from '../../App'

const SEVERITY_COLORS = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#6b7280' }
const TIME_RANGES = [
  { label: 'Last 1h', value: 1 },
  { label: 'Last 6h', value: 6 },
  { label: 'Last 24h', value: 24 },
  { label: 'Last 7d', value: 168 },
  { label: 'Last 30d', value: 720 },
]

export default function EventSearch() {
  const { t } = useTranslation()
  const [events, setEvents] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(false)
  const [query, setQuery] = useState('')
  const [timeRange, setTimeRange] = useState(24)
  const [severity, setSeverity] = useState('')
  const [sourceSystem, setSourceSystem] = useState('')
  const [page, setPage] = useState(1)
  const [selectedEvent, setSelectedEvent] = useState(null)
  const [histogram, setHistogram] = useState([])
  const [sourceSystems, setSourceSystems] = useState([])
  const [sortBy, setSortBy] = useState('event_time')
  const [order, setOrder] = useState('desc')
  const isMobile = useIsMobile()

  useEffect(() => {
    getSiemSourceSystems().then(setSourceSystems).catch(() => {})
  }, [])

  const loadEvents = useCallback(async () => {
    setLoading(true)
    try {
      const now = new Date()
      const from = new Date(now.getTime() - timeRange * 3600000).toISOString()
      const params = { time_from: from, page, page_size: 50, sort_by: sortBy, order }
      if (query) params.q = query
      if (severity) params.severity = severity
      if (sourceSystem) params.source_system = sourceSystem

      const data = await searchSiemEvents(params)
      setEvents(data.items || [])
      setTotal(data.total || 0)

      // Build histogram from results
      const buckets = {}
      ;(data.items || []).forEach(ev => {
        const h = ev.event_time ? ev.event_time.substring(0, 13) : 'unknown'
        buckets[h] = (buckets[h] || 0) + 1
      })
      setHistogram(Object.entries(buckets).map(([k, v]) => ({ time: k.substring(11) || k, count: v })).slice(0, 24))
    } catch (e) {
      console.error('Event search failed:', e)
    } finally {
      setLoading(false)
    }
  }, [query, timeRange, severity, sourceSystem, page, sortBy, order])

  useEffect(() => { loadEvents() }, [loadEvents])

  const handleSort = (col) => {
    if (sortBy === col) {
      setOrder(o => o === 'desc' ? 'asc' : 'desc')
    } else {
      setSortBy(col)
      setOrder('desc')
    }
    setPage(1)
  }

  const SortHeader = ({ col, children }) => (
    <th onClick={() => handleSort(col)} style={{ padding: '8px 12px', color: 'var(--text-muted)', fontWeight: 600, cursor: 'pointer', userSelect: 'none', whiteSpace: 'nowrap' }}>
      {children} {sortBy === col ? (order === 'desc' ? '\u25BC' : '\u25B2') : ''}
    </th>
  )

  const handleEventClick = async (ev) => {
    try {
      const detail = await getSiemEvent(ev.id)
      setSelectedEvent(detail)
    } catch { setSelectedEvent(ev) }
  }

  return (
    <div>
      <PageHeader
        title={t('siem.eventSearch', 'Event Search')}
        subtitle={t('siem.eventsCount', '{{count}} events', { count: total.toLocaleString() })}
        action={
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            <select style={{ padding: '8px 12px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text)', fontSize: 13, flex: isMobile ? '1 1 auto' : undefined }}
                    value={timeRange} onChange={e => setTimeRange(Number(e.target.value))}>
              {TIME_RANGES.map(r => <option key={r.value} value={r.value}>{r.label}</option>)}
            </select>
            <select style={{ padding: '8px 12px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text)', fontSize: 13, flex: isMobile ? '1 1 auto' : undefined }}
                    value={severity} onChange={e => setSeverity(e.target.value)}>
              <option value="">{t('siem.allSeverities', 'All severities')}</option>
              {['critical', 'high', 'medium', 'low', 'info'].map(s => <option key={s} value={s}>{s}</option>)}
            </select>
            <select style={{ padding: '8px 12px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text)', fontSize: 13, flex: isMobile ? '1 1 auto' : undefined }}
                    value={sourceSystem} onChange={e => setSourceSystem(e.target.value)}>
              <option value="">{t('siem.allSources', 'All sources')}</option>
              {sourceSystems.map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
        }
      />

      {/* Search bar */}
      <div style={{ marginBottom: 16, position: 'relative' }}>
        <Search size={16} style={{ position: 'absolute', left: 10, top: 10, color: 'var(--text-muted)' }} />
        <input
          style={{ width: '100%', padding: '8px 8px 8px 32px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text)', fontSize: 13 }}
          placeholder={t('siem.searchPlaceholder', 'Search event messages...')}
          value={query} onChange={e => setQuery(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && loadEvents()}
        />
      </div>

      {/* Histogram */}
      {histogram.length > 0 && (
        <div style={{ height: 100, marginBottom: 16, background: 'var(--bg-secondary)', borderRadius: 8, padding: '8px 12px' }}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={histogram}><Bar dataKey="count" fill="var(--accent)" radius={[2,2,0,0]} />
              <XAxis dataKey="time" tick={{ fontSize: 10, fill: 'var(--text-muted)' }} /><Tooltip />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Results table */}
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)', textAlign: 'left' }}>
              <SortHeader col="event_time">{t('siem.time', 'Time')}</SortHeader>
              {!isMobile && <SortHeader col="source_system">{t('siem.source', 'Source')}</SortHeader>}
              <SortHeader col="severity">{t('siem.severity', 'Severity')}</SortHeader>
              {!isMobile && <SortHeader col="host_name">{t('siem.host', 'Host')}</SortHeader>}
              {!isMobile && <SortHeader col="user_name">{t('siem.user', 'User')}</SortHeader>}
              <th style={{ padding: '8px 12px', color: 'var(--text-muted)', fontWeight: 600 }}>{t('siem.message', 'Message')}</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={isMobile ? 3 : 6}><EmptyState icon={Radio} title={t('app.loading', 'Loading...')} /></td></tr>
            ) : events.length === 0 ? (
              <tr><td colSpan={isMobile ? 3 : 6}><EmptyState icon={Radio} title={t('siem.noEvents', 'No events found')} sub={t('siem.noEventsHint', 'Events will appear here once data is ingested through your ingest sources.')} /></td></tr>
            ) : events.map(ev => (
              <tr key={ev.id} onClick={() => handleEventClick(ev)} style={{ borderBottom: '1px solid var(--border)', cursor: 'pointer' }}
                  onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-hover)'}
                  onMouseLeave={e => e.currentTarget.style.background = ''}>
                <td style={{ padding: '8px 12px', whiteSpace: 'nowrap', fontSize: 12, color: 'var(--text-muted)' }}>
                  {ev.event_time ? new Date(ev.event_time).toLocaleString() : '-'}
                </td>
                {!isMobile && <td style={{ padding: '8px 12px' }}>{ev.source_system}</td>}
                <td style={{ padding: '8px 12px' }}>
                  <span style={{ display: 'inline-block', padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600,
                    background: (SEVERITY_COLORS[ev.severity] || '#6b7280') + '20', color: SEVERITY_COLORS[ev.severity] || '#6b7280' }}>
                    {ev.severity}
                  </span>
                </td>
                {!isMobile && <td style={{ padding: '8px 12px' }}>{ev.host_name || '-'}</td>}
                {!isMobile && <td style={{ padding: '8px 12px' }}>{ev.user_name || '-'}</td>}
                <td style={{ padding: '8px 12px', maxWidth: isMobile ? 180 : 400, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {ev.message || '-'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {total > 50 && (() => {
        const totalPages = Math.ceil(total / 50)
        return (
          <div style={{ display: 'flex', justifyContent: 'center', gap: 8, marginTop: 16, alignItems: 'center' }}>
            <button disabled={page <= 1} onClick={() => setPage(p => p - 1)}
                    style={{ padding: '6px 16px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text)', cursor: page <= 1 ? 'default' : 'pointer', opacity: page <= 1 ? 0.5 : 1 }}>
              {t('common.prev', 'Prev')}
            </button>
            <span style={{ padding: '6px 12px', color: 'var(--text-muted)', fontSize: 13 }}>
              {t('common.page', 'Page')} {page} / {totalPages}
            </span>
            <button disabled={page >= totalPages} onClick={() => setPage(p => p + 1)}
                    style={{ padding: '6px 16px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text)', cursor: page >= totalPages ? 'default' : 'pointer', opacity: page >= totalPages ? 0.5 : 1 }}>
              {t('common.next', 'Next')}
            </button>
          </div>
        )
      })()}

      {/* Event detail drawer */}
      {selectedEvent && (
        <div style={{ position: 'fixed', top: 0, right: 0, bottom: 0, width: isMobile ? '100%' : 500, background: 'var(--bg)', borderLeft: isMobile ? 'none' : '1px solid var(--border)',
                       boxShadow: '-4px 0 20px rgba(0,0,0,0.15)', zIndex: 1000, overflow: 'auto', padding: isMobile ? 16 : 24 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <h3 style={{ margin: 0, fontSize: 16, fontWeight: 700 }}>{t('siem.eventDetail', 'Event Detail')}</h3>
            <button onClick={() => setSelectedEvent(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}><X size={18} /></button>
          </div>
          <pre style={{ fontSize: 12, background: 'var(--bg-secondary)', padding: 16, borderRadius: 8, overflow: 'auto', maxHeight: '80vh', color: 'var(--text)' }}>
            {JSON.stringify(selectedEvent, null, 2)}
          </pre>
        </div>
      )}
    </div>
  )
}
