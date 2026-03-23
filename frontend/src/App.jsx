import React, { useState, useEffect, createContext, useContext, Suspense } from 'react'

function HakunaLogo({ size = 28, style }) {
  const scale = size / 65
  return (
    <svg
      width={size}
      height={Math.round(44 * scale)}
      viewBox="0 0 65 44"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      style={style}
      aria-label="Hakuna"
    >
      <path d="M30.7181 4.27637L26.7728 19H30.4495V25H25.1653L22.4788 35.0273C21.1397 40.0248 16.6106 43.5 11.4368 43.5C3.92067 43.4999 -1.54952 36.3704 0.395817 29.1104L0.671208 28.0791C2.10629 22.7237 6.95988 19 12.5042 19H20.5618L24.9232 2.72363L30.7181 4.27637ZM53.4612 0C60.9775 0 66.4486 7.1295 64.5032 14.3896L64.2269 15.4209C62.7918 20.7761 57.939 24.4998 52.3948 24.5H44.3372L39.9759 40.7764L34.18 39.2236L38.1253 24.5H34.4495V18.5H39.7327L42.4202 8.47266C43.7593 3.47531 48.2876 0.000201552 53.4612 0ZM12.5042 25C9.67544 25 7.19925 26.9004 6.46711 29.6328L6.19074 30.6631C5.26649 34.1124 7.86583 37.4999 11.4368 37.5C13.895 37.5 16.0467 35.849 16.6829 33.4746L18.9544 25H12.5042ZM53.4612 6C51.0033 6.0002 48.8524 7.65123 48.2161 10.0254L45.9446 18.5H52.3948C55.2235 18.4998 57.6998 16.5995 58.4319 13.8672L58.7073 12.8369C59.6316 9.38749 57.0324 6 53.4612 6Z" fill="#590202" />
    </svg>
  )
}
import { BrowserRouter, Routes, Route, NavLink, Navigate, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import {
  Server,
  Bug,
  BarChart3,
  Database,
  Settings as SettingsIcon,
  Target,
  ShieldAlert,
  Bot,
  LogOut,
  Building2,
  MoreVertical,
  User,
  Moon,
  Sun,
  Layers,
  Globe,
  BookOpen,
  HelpCircle,
  Menu,
  Lock,
  CreditCard,
} from 'lucide-react'
import { SUPPORTED_LANGUAGES } from './i18n/index.js'
// Auth pages loaded eagerly (small, needed immediately)
import Login from './components/auth/Login.jsx'
import Register from './components/auth/Register.jsx'
import ForgotPassword from './components/auth/ForgotPassword.jsx'
import ResetPassword from './components/auth/ResetPassword.jsx'
import { AuthProvider, useAuth } from './contexts/AuthContext.jsx'
import SubscriptionBanner from './components/billing/SubscriptionBanner.jsx'
import { ThemeProvider, useTheme } from './contexts/ThemeContext.jsx'
import { getScans, setOrgContext, authUpdateLocale } from './api.js'
import { ErrorBoundary } from './components/shared/ui.jsx'

// Lazy-loaded route components (code-split per page)
const AssetInventory = React.lazy(() => import('./components/assets/AssetInventory.jsx'))
const FindingExplorer = React.lazy(() => import('./components/findings/FindingExplorer.jsx'))
const FindingDetail = React.lazy(() => import('./components/findings/FindingDetail.jsx'))
const Campaigns = React.lazy(() => import('./components/campaigns/Campaigns.jsx'))
const CampaignDetail = React.lazy(() => import('./components/campaigns/CampaignDetail.jsx'))
const Reports = React.lazy(() => import('./components/reports/Reports.jsx'))
const InventoryExplorer = React.lazy(() => import('./components/assets/InventoryExplorer.jsx'))
const Settings = React.lazy(() => import('./components/settings/Settings.jsx'))
const UploadScan = React.lazy(() => import('./components/upload/UploadScan.jsx'))
const TagManager = React.lazy(() => import('./components/settings/TagManager.jsx'))
const ThreatIntelCenter = React.lazy(() => import('./components/threats/ThreatIntelCenter.jsx'))
const WorkflowBuilder = React.lazy(() => import('./components/workflows/WorkflowBuilder.jsx'))
const AgentBuilder = React.lazy(() => import('./components/agents/AgentBuilder.jsx'))
const AggregatedSolutions = React.lazy(() => import('./components/remediation/AggregatedSolutions.jsx'))
const UserManagement = React.lazy(() => import('./components/settings/UserManagement.jsx'))
const UserDocs = React.lazy(() => import('./components/docs/UserDocs.jsx'))
const BillingPage = React.lazy(() => import('./components/billing/BillingPage.jsx'))

// Global scan context
export const ScanContext = createContext({ activeScanId: null, setActiveScanId: () => {}, scans: [], refreshScans: () => {} })
export const useScan = () => useContext(ScanContext)

const NAV_GROUPS = [
  {
    labelKey: 'nav.intelligence',
    items: [
      { path: '/', labelKey: 'nav.reports', icon: BarChart3, exact: true, alsoPaths: ['/reports'], permission: 'page_reports' },
      { path: '/threat-intel', labelKey: 'nav.threatIntel', icon: ShieldAlert, permission: 'page_threat_intel' },
    ],
  },
  {
    labelKey: 'nav.exposure',
    items: [
      { path: '/assets', labelKey: 'nav.assets', icon: Server, permission: 'page_assets' },
      { path: '/findings', labelKey: 'nav.findings', icon: Bug, permission: 'page_findings' },
      { path: '/inventory', labelKey: 'nav.inventory', icon: Database, permission: 'page_inventory' },
    ],
  },
  {
    labelKey: 'nav.response',
    items: [
      { path: '/campaigns', labelKey: 'nav.campaigns', icon: Target, permission: 'page_campaigns' },
      { path: '/aggregated-solutions', labelKey: 'nav.remediation', icon: Layers, permission: 'page_remediation' },
      { path: '/agents', labelKey: 'nav.agents', icon: Bot, permission: 'page_agents', proOnly: true },
    ],
  },
]

const NAV_SETTINGS = { path: '/settings', labelKey: 'nav.settings', icon: SettingsIcon, permission: 'page_settings' }
const NAV_BILLING = { path: '/billing', labelKey: 'Billing', icon: CreditCard, adminOnly: true }

function ProtectedRoute({ children }) {
  const { isAuthenticated, isLoading } = useAuth()
  const { t } = useTranslation()
  if (isLoading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', color: '#71717a' }}>
        {t('app.loading')}
      </div>
    )
  }
  if (!isAuthenticated) return <Navigate to="/login" replace />
  return children
}

function OrgSwitcher({ collapsed }) {
  const { accessibleOrgs, currentOrgContext, switchOrg, isMSSP, isSuperadmin, org } = useAuth()
  const { t } = useTranslation()

  if (!isMSSP && !isSuperadmin) return null
  if (accessibleOrgs.length <= 1) return null

  return (
    <div style={{
      padding: collapsed ? '8px 6px' : '12px',
      borderTop: '1px solid var(--border)',
    }}>
      <div style={{
        fontSize: collapsed ? 9 : 11,
        color: 'var(--muted)',
        textTransform: 'uppercase',
        letterSpacing: '0.06em',
        marginBottom: 4,
        display: 'flex',
        alignItems: 'center',
        gap: 4,
      }}>
        <Building2 size={10} />
        {!collapsed && t('user.orgContext')}
      </div>
      <select
        value={currentOrgContext || ''}
        onChange={e => switchOrg(e.target.value || null)}
        style={{
          width: '100%',
          background: 'var(--bg)',
          border: '1px solid var(--border)',
          borderRadius: 10,
          padding: collapsed ? '4px 4px' : '5px 8px',
          fontSize: collapsed ? 9 : 11,
          color: 'var(--text)',
          cursor: 'pointer',
        }}
      >
        <option value="">{t('user.allOrgs')}</option>
        {accessibleOrgs.map(o => (
          <option key={o.id} value={o.id}>{o.name}</option>
        ))}
      </select>
    </div>
  )
}

function UserMenu({ collapsed }) {
  const { user, org, logout } = useAuth()
  const { theme, toggleTheme } = useTheme()
  const { t, i18n } = useTranslation()
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const [langOpen, setLangOpen] = useState(false)
  const menuRef = React.useRef(null)

  useEffect(() => {
    if (!open) return
    const handleClick = (e) => {
      if (menuRef.current && !menuRef.current.contains(e.target)) setOpen(false)
    }
    document.addEventListener('mousedown', handleClick)
    return () => document.removeEventListener('mousedown', handleClick)
  }, [open])

  if (!user) return null

  const initials = (user.display_name || user.email || '?').slice(0, 2).toUpperCase()

  return (
    <div ref={menuRef} style={{
      padding: collapsed ? '8px 6px' : '10px 12px',
      borderTop: '1px solid var(--border)',
      position: 'relative',
    }}>
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        justifyContent: collapsed ? 'center' : 'space-between',
      }}>
        {!collapsed && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
            <div style={{
              width: 28, height: 28, borderRadius: '50%',
              background: 'var(--avatar-bg)', color: 'var(--avatar-text)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 11, fontWeight: 700, flexShrink: 0,
            }}>
              {initials}
            </div>
            <div style={{ minWidth: 0 }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{user.display_name}</div>
              <div style={{ fontSize: 10, color: 'var(--muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{org?.name}</div>
            </div>
          </div>
        )}
        <button
          onClick={() => setOpen(prev => !prev)}
          title="Menu"
          style={{
            width: 28, height: 28, borderRadius: 6,
            border: '1px solid var(--border)', background: 'var(--bg)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            cursor: 'pointer', padding: 0, flexShrink: 0,
          }}
        >
          <MoreVertical size={14} color="#71717a" />
        </button>
      </div>

      {open && (
        <div style={{
          position: 'absolute',
          bottom: collapsed ? 0 : '100%',
          left: collapsed ? 'calc(100% + 8px)' : 12,
          transform: 'none',
          marginBottom: collapsed ? 0 : 4,
          background: 'var(--popover)',
          border: '1px solid var(--border)',
          borderRadius: 8,
          boxShadow: 'var(--shadow)',
          minWidth: 160,
          zIndex: 100,
          overflow: 'hidden',
        }}>
          <button
            onClick={toggleTheme}
            style={{
              width: '100%', display: 'flex', alignItems: 'center', gap: 8,
              padding: '9px 14px', border: 'none', background: 'transparent',
              cursor: 'pointer', fontSize: 13, color: 'var(--text)', textAlign: 'left',
            }}
            onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-hover)'}
            onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
          >
            {theme === 'dark' ? <Sun size={14} /> : <Moon size={14} />}
            {theme === 'dark' ? t('user.lightMode') : t('user.darkMode')}
          </button>
          <div style={{ height: 1, background: 'var(--border)' }} />
          <button
            onClick={() => setLangOpen(prev => !prev)}
            style={{
              width: '100%', display: 'flex', alignItems: 'center', gap: 8,
              padding: '9px 14px', border: 'none', background: 'transparent',
              cursor: 'pointer', fontSize: 13, color: 'var(--text)', textAlign: 'left',
            }}
            onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-hover)'}
            onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
          >
            <Globe size={14} /> {t('settings.language')}
          </button>
          {langOpen && (
            <div style={{ padding: '4px 8px', background: 'var(--bg-secondary)' }}>
              {SUPPORTED_LANGUAGES.map(lang => (
                <button
                  key={lang.code}
                  onClick={() => { i18n.changeLanguage(lang.code); authUpdateLocale(lang.code).catch(() => {}); setLangOpen(false); setOpen(false) }}
                  style={{
                    width: '100%', display: 'flex', alignItems: 'center', gap: 8,
                    padding: '6px 10px', border: 'none', borderRadius: 4,
                    background: i18n.language === lang.code ? 'var(--nav-active-bg)' : 'transparent',
                    color: i18n.language === lang.code ? 'var(--nav-active-text)' : 'var(--text)',
                    cursor: 'pointer', fontSize: 12, textAlign: 'left',
                  }}
                  onMouseEnter={e => { if (i18n.language !== lang.code) e.currentTarget.style.background = 'var(--bg-hover)' }}
                  onMouseLeave={e => { if (i18n.language !== lang.code) e.currentTarget.style.background = 'transparent' }}
                >
                  {lang.label}
                </button>
              ))}
            </div>
          )}
          <div style={{ height: 1, background: 'var(--border)' }} />
          <button
            onClick={() => { setOpen(false); navigate('/profile') }}
            style={{
              width: '100%', display: 'flex', alignItems: 'center', gap: 8,
              padding: '9px 14px', border: 'none', background: 'transparent',
              cursor: 'pointer', fontSize: 13, color: 'var(--text)', textAlign: 'left',
            }}
            onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-hover)'}
            onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
          >
            <User size={14} /> {t('user.viewProfile')}
          </button>
          <div style={{ height: 1, background: 'var(--border)' }} />
          <button
            onClick={() => { setOpen(false); logout() }}
            style={{
              width: '100%', display: 'flex', alignItems: 'center', gap: 8,
              padding: '9px 14px', border: 'none', background: 'transparent',
              cursor: 'pointer', fontSize: 13, color: 'var(--danger)', textAlign: 'left',
            }}
            onMouseEnter={e => e.currentTarget.style.background = 'var(--danger-subtle)'}
            onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
          >
            <LogOut size={14} /> {t('user.logOut')}
          </button>
        </div>
      )}
    </div>
  )
}

function Sidebar({ collapsed, onToggle }) {
  const width = collapsed ? 56 : 220
  const { scans, activeScanId, setActiveScanId } = useScan()
  const { hasPermission, isPro, isAdmin } = useAuth()
  const { t } = useTranslation()
  const navigate = useNavigate()

  return (
    <aside
      style={{
        width,
        flexShrink: 0,
        background: 'var(--bg)',
        borderRight: '1px solid var(--border)',
        display: 'flex',
        flexDirection: 'column',
        padding: '16px 0',
        position: 'fixed',
        top: 0,
        left: 0,
        bottom: 0,
        zIndex: 50,
        transition: 'width 0.2s ease'
      }}
    >
      {/* Top row: hamburger + brand */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'flex-start',
          gap: 8,
          padding: '0 12px',
          marginBottom: 20
        }}
      >
        {!collapsed ? (
          <>
            <HakunaLogo size={28} style={{ display: 'block', flexShrink: 0 }} />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 13, fontWeight: 800 }}>{t('app.name')}</div>
              <div style={{ fontSize: 11, color: 'var(--muted)' }}>{t('app.tagline')}</div>
            </div>
            <button
              type="button"
              onClick={onToggle}
              aria-label={t('nav.collapseNav')}
              style={{
                width: 28,
                height: 28,
                borderRadius: 6,
                border: '1px solid var(--border)',
                background: 'transparent',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                cursor: 'pointer',
                padding: 0,
                flexShrink: 0,
              }}
            >
              <Menu size={15} color="var(--text-muted)" />
            </button>
          </>
        ) : (
          <button
            type="button"
            onClick={onToggle}
            aria-label={t('nav.expandNav')}
            style={{
              width: 32,
              height: 32,
              borderRadius: 8,
              border: '1px solid var(--border)',
              background: 'var(--bg)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              cursor: 'pointer',
              padding: 0,
            }}
          >
            <HakunaLogo size={18} style={{ display: 'block' }} />
          </button>
        )}
      </div>

      {/* Nav */}
      <nav
        style={{
          display: 'flex',
          flexDirection: 'column',
          gap: 2,
          alignItems: 'stretch',
          padding: collapsed ? '0 10px' : '0 12px',
          flex: 1,
          overflowY: 'auto',
        }}
      >
        {NAV_GROUPS.map((group, gi) => {
          const visibleItems = group.items.filter(item => !item.permission || hasPermission(item.permission))
          if (visibleItems.length === 0) return null
          return (
          <div key={group.labelKey} style={{ marginBottom: collapsed ? 8 : 4 }}>
            {!collapsed && (
              <div style={{
                fontSize: 10,
                fontWeight: 600,
                color: 'var(--muted)',
                textTransform: 'uppercase',
                letterSpacing: '0.07em',
                padding: '10px 10px 4px',
                opacity: 0.7,
              }}>
                {t(group.labelKey)}
              </div>
            )}
            {collapsed && gi > 0 && (
              <div style={{ height: 1, background: 'var(--border)', margin: '6px 0' }} />
            )}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
              {visibleItems.map(({ path, labelKey, icon: Icon, exact, alsoPaths, proOnly }) => {
                const locked = proOnly && !isPro
                if (locked) {
                  return (
                    <button
                      key={path}
                      onClick={() => navigate('/billing')}
                      title={t(labelKey) + ' (Pro)'}
                      aria-label={t(labelKey)}
                      style={{
                        display: 'flex', alignItems: 'center', gap: 10,
                        padding: '7px 10px', borderRadius: 6,
                        color: 'var(--muted)', background: 'transparent',
                        border: 'none', textDecoration: 'none', cursor: 'pointer',
                        justifyContent: collapsed ? 'center' : 'flex-start',
                        opacity: 0.6, width: '100%', textAlign: 'left',
                      }}
                    >
                      <Icon size={18} />
                      {!collapsed && (
                        <>
                          <span style={{ fontSize: 13, fontWeight: 500, flex: 1 }}>{t(labelKey)}</span>
                          <Lock size={12} style={{ flexShrink: 0 }} />
                        </>
                      )}
                    </button>
                  )
                }
                return (
                <NavLink
                  key={path}
                  to={path}
                  end={exact}
                  title={t(labelKey)}
                  aria-label={t(labelKey)}
                  style={({ isActive }) => {
                    const active = isActive || (alsoPaths && alsoPaths.some(p => window.location.pathname.startsWith(p)))
                    return {
                    display: 'flex',
                    alignItems: 'center',
                    gap: 10,
                    padding: '7px 10px',
                    borderRadius: 6,
                    color: active ? 'var(--nav-active-text)' : 'var(--muted)',
                    background: active ? 'var(--nav-active-bg)' : 'transparent',
                    textDecoration: 'none',
                    cursor: 'pointer',
                    boxShadow: active ? '0 1px 2px rgba(0,0,0,0.12)' : 'none',
                    transition: 'background 0.15s ease, color 0.15s ease, box-shadow 0.15s ease',
                    justifyContent: collapsed ? 'center' : 'flex-start',
                  }}}
                >
                  <Icon size={18} />
                  {!collapsed && <span style={{ fontSize: 13, fontWeight: 500 }}>{t(labelKey)}</span>}
                </NavLink>
              )})}
            </div>
          </div>
        )})}


        {/* Docs & Settings — ungrouped at bottom */}
        <div style={{ marginTop: 'auto', paddingTop: 8, paddingBottom: 8 }}>
          {!collapsed && (
            <div style={{ height: 1, background: 'var(--border)', marginBottom: 8 }} />
          )}
          <NavLink
            to="/docs"
            title={t('nav.documentation')}
            aria-label={t('nav.documentation')}
            style={({ isActive }) => ({
              display: 'flex',
              alignItems: 'center',
              gap: 10,
              padding: '7px 10px',
              borderRadius: 6,
              color: isActive ? 'var(--nav-active-text)' : 'var(--muted)',
              background: isActive ? 'var(--nav-active-bg)' : 'transparent',
              textDecoration: 'none',
              cursor: 'pointer',
              boxShadow: isActive ? '0 1px 2px rgba(0,0,0,0.12)' : 'none',
              transition: 'background 0.15s ease, color 0.15s ease, box-shadow 0.15s ease',
              justifyContent: collapsed ? 'center' : 'flex-start',
            })}
          >
            <BookOpen size={18} />
            {!collapsed && <span style={{ fontSize: 13, fontWeight: 500 }}>{t('nav.docs')}</span>}
          </NavLink>
          {(!NAV_SETTINGS.permission || hasPermission(NAV_SETTINGS.permission)) && (
          <NavLink
            to={NAV_SETTINGS.path}
            title={t(NAV_SETTINGS.labelKey)}
            aria-label={t(NAV_SETTINGS.labelKey)}
            style={({ isActive }) => ({
              display: 'flex',
              alignItems: 'center',
              gap: 10,
              padding: '7px 10px',
              borderRadius: 6,
              color: isActive ? 'var(--nav-active-text)' : 'var(--muted)',
              background: isActive ? 'var(--nav-active-bg)' : 'transparent',
              textDecoration: 'none',
              cursor: 'pointer',
              boxShadow: isActive ? '0 1px 2px rgba(0,0,0,0.12)' : 'none',
              transition: 'background 0.15s ease, color 0.15s ease, box-shadow 0.15s ease',
              justifyContent: collapsed ? 'center' : 'flex-start',
            })}
          >
            <NAV_SETTINGS.icon size={18} />
            {!collapsed && <span style={{ fontSize: 13, fontWeight: 500 }}>{t(NAV_SETTINGS.labelKey)}</span>}
          </NavLink>
          )}
          {isAdmin && (
          <NavLink
            to={NAV_BILLING.path}
            title={NAV_BILLING.labelKey}
            aria-label={NAV_BILLING.labelKey}
            style={({ isActive }) => ({
              display: 'flex',
              alignItems: 'center',
              gap: 10,
              padding: '7px 10px',
              borderRadius: 6,
              color: isActive ? 'var(--nav-active-text)' : 'var(--muted)',
              background: isActive ? 'var(--nav-active-bg)' : 'transparent',
              textDecoration: 'none',
              cursor: 'pointer',
              boxShadow: isActive ? '0 1px 2px rgba(0,0,0,0.12)' : 'none',
              transition: 'background 0.15s ease, color 0.15s ease, box-shadow 0.15s ease',
              justifyContent: collapsed ? 'center' : 'flex-start',
            })}
          >
            <NAV_BILLING.icon size={18} />
            {!collapsed && <span style={{ fontSize: 13, fontWeight: 500 }}>{NAV_BILLING.labelKey}</span>}
          </NavLink>
          )}
        </div>
      </nav>

      {/* Org switcher (MSSP / superadmin) */}
      <OrgSwitcher collapsed={collapsed} />

      {/* Active scan selector */}
      {scans.length > 0 && (
        <div
          style={{
            padding: collapsed ? '8px 6px' : '12px',
            borderTop: '1px solid var(--border)',
          }}
        >
          <div
            style={{
              fontSize: collapsed ? 9 : 11,
              color: 'var(--muted)',
              textTransform: 'uppercase',
              letterSpacing: '0.06em',
              marginBottom: 6
            }}
          >
            {collapsed ? 'Scan' : 'Active Scan'}
          </div>
          <select
            value={activeScanId || ''}
            onChange={e => setActiveScanId(e.target.value ? parseInt(e.target.value) : null)}
            style={{
              width: '100%',
              background: 'var(--bg)',
              border: '1px solid var(--border)',
              borderRadius: 10,
              padding: collapsed ? '4px 6px' : '6px 10px',
              fontSize: collapsed ? 10 : 12,
              color: 'var(--text)',
              cursor: 'pointer',
              boxShadow: '0 1px 2px rgba(0,0,0,0.03)'
            }}
          >
            <option value="">All Scans</option>
            {scans.map(s => (
              <option key={s.id} value={s.id}>
                {s.scan_name || s.filename}
              </option>
            ))}
          </select>
        </div>
      )}

      {/* User menu */}
      <UserMenu collapsed={collapsed} />
    </aside>
  )
}

function HelpButton() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  return (
    <button
      onClick={() => navigate('/docs')}
      title={t('nav.help')}
      aria-label={t('nav.help')}
      style={{
        position: 'fixed', bottom: 20, right: 20, zIndex: 90,
        width: 44, height: 44, borderRadius: '50%',
        background: 'var(--accent)', color: '#fff', border: 'none',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        cursor: 'pointer', boxShadow: '0 2px 8px rgba(0,0,0,0.2)',
        transition: 'transform 0.15s ease, box-shadow 0.15s ease',
      }}
      onMouseEnter={e => { e.currentTarget.style.transform = 'scale(1.1)'; e.currentTarget.style.boxShadow = '0 4px 12px rgba(0,0,0,0.3)' }}
      onMouseLeave={e => { e.currentTarget.style.transform = 'scale(1)'; e.currentTarget.style.boxShadow = '0 2px 8px rgba(0,0,0,0.2)' }}
    >
      <HelpCircle size={22} />
    </button>
  )
}

function AppShell() {
  const [scans, setScans] = useState([])
  const [activeScanId, setActiveScanId] = useState(null)
  const [navCollapsed, setNavCollapsed] = useState(false)
  const [scansLoaded, setScansLoaded] = useState(false)

  useEffect(() => {
    getScans().then(data => {
      setScans(data)
      setScansLoaded(true)
    }).catch(() => { setScansLoaded(true) })
  }, [])

  const refreshScans = () => {
    getScans().then(data => {
      setScans(data)
    }).catch(() => {})
  }

  return (
    <ScanContext.Provider value={{ activeScanId, setActiveScanId, scans, scansLoaded, refreshScans }}>
      <div style={{ display: 'flex', minHeight: '100vh', background: 'var(--bg-muted)' }}>
        <Sidebar
          collapsed={navCollapsed}
          onToggle={() => setNavCollapsed(prev => !prev)}
        />

        {/* Main content */}
        <div
          style={{
            flex: 1,
            minWidth: 0,
            marginLeft: navCollapsed ? 56 : 220,
            minHeight: '100vh',
            display: 'flex',
            flexDirection: 'column'
          }}
        >
          <main
            style={{
              flex: 1,
              padding: 18,
              background: 'var(--bg-muted)',
              overflowY: 'auto',
              overflowX: 'hidden',
            }}
          >
            <SubscriptionBanner />
            <ErrorBoundary fullPage title="Page failed to load">
            <Suspense fallback={<div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '60vh', color: '#71717a' }}>Loading...</div>}>
              <Routes>
                <Route path="/" element={<Reports />} />
                <Route path="/reports/:reportId" element={<Reports />} />
                <Route path="/assets" element={<AssetInventory />} />
                <Route path="/findings" element={<FindingExplorer />} />
                <Route path="/findings/:id" element={<FindingDetail />} />
                <Route path="/campaigns" element={<Campaigns />} />
                <Route path="/campaigns/:id" element={<CampaignDetail />} />
                <Route path="/aggregated-solutions" element={<AggregatedSolutions />} />
                <Route path="/workflows/:id" element={<WorkflowBuilder />} />
                <Route path="/inventory" element={<InventoryExplorer />} />
                <Route path="/agents" element={<AgentBuilder />} />
                <Route path="/tags" element={<TagManager />} />
                <Route path="/threat-intel/:tab?" element={<ThreatIntelCenter />} />
                <Route path="/settings" element={<Settings />} />
                <Route path="/scans" element={<Navigate to="/settings?tab=upload" replace />} />
                <Route path="/upload" element={<Navigate to="/settings?tab=upload" replace />} />
                <Route path="/profile" element={<UserManagement />} />
                <Route path="/billing" element={<BillingPage />} />
                <Route path="/docs" element={<UserDocs />} />
              </Routes>
            </Suspense>
            </ErrorBoundary>
          </main>
        </div>
        <HelpButton />
      </div>
    </ScanContext.Provider>
  )
}

export default function App() {
  return (
    <ThemeProvider>
      <BrowserRouter>
        <AuthProvider>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />
            <Route path="/forgot-password" element={<ForgotPassword />} />
            <Route path="/reset-password" element={<ResetPassword />} />
            <Route path="/*" element={
              <ProtectedRoute>
                <AppShell />
              </ProtectedRoute>
            } />
          </Routes>
        </AuthProvider>
      </BrowserRouter>
    </ThemeProvider>
  )
}
