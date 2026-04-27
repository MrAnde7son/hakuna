import React, { useState, useEffect, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Bell, X, Check, CheckCheck, ShieldAlert, Server, Scan, Target, AlertTriangle, Skull, Clock, XCircle, Siren } from 'lucide-react'
import { getNotifications, getUnreadNotificationCount, markNotificationRead, markAllNotificationsRead } from '../../api'

const POLL_INTERVAL = 60_000 // 60s
const CATEGORY_CONFIG = {
  scan_complete:     { icon: Scan,          color: '#2563eb' },
  scan_failed:       { icon: XCircle,       color: '#dc2626' },
  critical_findings: { icon: ShieldAlert,   color: '#dc2626' },
  new_assets:        { icon: Server,        color: '#16a34a' },
  kev_update:        { icon: AlertTriangle, color: '#ea580c' },
  campaign_findings: { icon: Target,        color: '#7c3aed' },
  sla_breach:        { icon: Clock,         color: '#d97706' },
  new_threat_groups: { icon: Skull,         color: '#be185d' },
  eol_update:        { icon: AlertTriangle, color: '#9333ea' },
  security_alert:    { icon: Siren,         color: '#e11d48' },
}

function timeAgo(dateStr) {
  const diff = Date.now() - new Date(dateStr).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  return `${days}d ago`
}

export default function NotificationBell({ bottomOffset = 20, rightOffset = 120 }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const [unreadCount, setUnreadCount] = useState(0)
  const [notifications, setNotifications] = useState([])
  const [hasFetched, setHasFetched] = useState(false)
  const [loading, setLoading] = useState(false)
  const panelRef = useRef(null)

  // Poll unread count
  const fetchCount = useCallback(() => {
    getUnreadNotificationCount()
      .then(data => setUnreadCount(data.count || 0))
      .catch(() => {})
  }, [])

  useEffect(() => {
    fetchCount()
    const interval = setInterval(fetchCount, POLL_INTERVAL)
    return () => clearInterval(interval)
  }, [fetchCount])

  // Fetch notifications when panel opens — show stale list while refreshing
  useEffect(() => {
    if (!open) return
    if (!hasFetched) setLoading(true)
    getNotifications({ page_size: 30 })
      .then(data => {
        setNotifications(data.items || [])
        setHasFetched(true)
      })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [open, hasFetched])

  // Close on click outside
  useEffect(() => {
    if (!open) return
    const handler = (e) => {
      if (panelRef.current && !panelRef.current.contains(e.target)) setOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [open])

  const handleMarkRead = async (id, e) => {
    e.stopPropagation()
    await markNotificationRead(id).catch(() => {})
    setNotifications(prev => prev.map(n => n.id === id ? { ...n, is_read: true } : n))
    setUnreadCount(prev => Math.max(0, prev - 1))
  }

  const handleMarkAllRead = async () => {
    await markAllNotificationsRead().catch(() => {})
    setNotifications(prev => prev.map(n => ({ ...n, is_read: true })))
    setUnreadCount(0)
  }

  const handleClick = (notif) => {
    if (!notif.is_read) {
      markNotificationRead(notif.id).catch(() => {})
      setNotifications(prev => prev.map(n => n.id === notif.id ? { ...n, is_read: true } : n))
      setUnreadCount(prev => Math.max(0, prev - 1))
    }
    if (notif.link) {
      navigate(notif.link)
      setOpen(false)
    }
  }

  return (
    <div ref={panelRef} style={{ position: 'fixed', bottom: bottomOffset, right: rightOffset, zIndex: 91 }}>
      {/* Bell button */}
      <button
        onClick={() => setOpen(!open)}
        title={t('notifications.title', 'Notifications')}
        aria-label={t('notifications.title', 'Notifications')}
        style={{
          width: 40, height: 40, borderRadius: '50%',
          background: 'var(--card)', color: 'var(--text-muted)', border: '1px solid var(--border)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          cursor: 'pointer', boxShadow: '0 2px 8px rgba(0,0,0,0.15)',
          transition: 'transform 0.15s ease, box-shadow 0.15s ease',
          position: 'relative',
        }}
        onMouseEnter={e => { e.currentTarget.style.transform = 'scale(1.1)'; e.currentTarget.style.boxShadow = '0 4px 12px rgba(0,0,0,0.2)' }}
        onMouseLeave={e => { e.currentTarget.style.transform = 'scale(1)'; e.currentTarget.style.boxShadow = '0 2px 8px rgba(0,0,0,0.15)' }}
      >
        <Bell size={18} />
        {unreadCount > 0 && (
          <span style={{
            position: 'absolute', top: -4, right: -4,
            background: '#dc2626', color: '#fff',
            fontSize: 10, fontWeight: 700,
            minWidth: 18, height: 18, borderRadius: 9,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            padding: '0 4px', lineHeight: 1,
          }}>
            {unreadCount > 99 ? '99+' : unreadCount}
          </span>
        )}
      </button>

      {/* Dropdown panel */}
      {open && (
        <div style={{
          position: 'absolute', bottom: 48, right: 0,
          width: 380, maxHeight: 480,
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: 12, boxShadow: '0 8px 32px rgba(0,0,0,0.25)',
          display: 'flex', flexDirection: 'column',
          overflow: 'hidden',
        }}>
          {/* Header */}
          <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            padding: '12px 16px', borderBottom: '1px solid var(--border)',
          }}>
            <span style={{ fontWeight: 700, fontSize: 14 }}>
              {t('notifications.title', 'Notifications')}
            </span>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              {unreadCount > 0 && (
                <button
                  onClick={handleMarkAllRead}
                  style={{
                    background: 'none', border: 'none', color: 'var(--accent)',
                    fontSize: 12, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4,
                  }}
                >
                  <CheckCheck size={14} /> {t('notifications.markAllRead', 'Mark all read')}
                </button>
              )}
              <button
                onClick={() => setOpen(false)}
                style={{
                  background: 'none', border: 'none', color: 'var(--text-muted)',
                  cursor: 'pointer', padding: 2,
                }}
              >
                <X size={16} />
              </button>
            </div>
          </div>

          {/* List */}
          <div style={{ overflowY: 'auto', flex: 1 }}>
            {loading && notifications.length === 0 && (
              <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
                Loading...
              </div>
            )}
            {!loading && notifications.length === 0 && (
              <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
                {t('notifications.noNotifications', 'No notifications yet')}
              </div>
            )}
            {notifications.map(n => {
              const cfg = CATEGORY_CONFIG[n.category] || { icon: Bell, color: 'var(--text-muted)' }
              const Icon = cfg.icon
              return (
                <div
                  key={n.id}
                  onClick={() => handleClick(n)}
                  style={{
                    display: 'flex', gap: 10, padding: '10px 16px',
                    cursor: n.link ? 'pointer' : 'default',
                    background: n.is_read ? 'transparent' : 'var(--bg-hover)',
                    borderBottom: '1px solid var(--border)',
                    transition: 'background 0.1s',
                  }}
                  onMouseEnter={e => { if (n.is_read) e.currentTarget.style.background = 'var(--bg-hover)' }}
                  onMouseLeave={e => { if (n.is_read) e.currentTarget.style.background = 'transparent' }}
                >
                  <div style={{
                    width: 32, height: 32, borderRadius: 8,
                    background: cfg.color + '18', color: cfg.color,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    flexShrink: 0, marginTop: 2,
                  }}>
                    <Icon size={16} />
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{
                      fontSize: 13, fontWeight: n.is_read ? 400 : 600,
                      color: 'var(--text)',
                      overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                    }}>
                      {n.title}
                    </div>
                    {n.body && (
                      <div style={{
                        fontSize: 12, color: 'var(--text-muted)', marginTop: 2,
                        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                      }}>
                        {n.body}
                      </div>
                    )}
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 3 }}>
                      {n.created_at ? timeAgo(n.created_at) : ''}
                    </div>
                  </div>
                  {!n.is_read && (
                    <button
                      onClick={(e) => handleMarkRead(n.id, e)}
                      title="Mark as read"
                      style={{
                        background: 'none', border: 'none', color: 'var(--text-muted)',
                        cursor: 'pointer', padding: 4, flexShrink: 0, alignSelf: 'center',
                      }}
                    >
                      <Check size={14} />
                    </button>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
