import React, { useState, useEffect, createContext, useContext, Suspense } from 'react'
import { BrowserRouter, Routes, Route, NavLink, Navigate, useNavigate } from 'react-router-dom'
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
} from 'lucide-react'
// Auth pages loaded eagerly (small, needed immediately)
import Login from './components/auth/Login.jsx'
import Register from './components/auth/Register.jsx'
import { AuthProvider, useAuth } from './contexts/AuthContext.jsx'
import { ThemeProvider, useTheme } from './contexts/ThemeContext.jsx'
import { getScans, setOrgContext } from './api.js'

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

// Global scan context
export const ScanContext = createContext({ activeScanId: null, setActiveScanId: () => {} })
export const useScan = () => useContext(ScanContext)

const NAV_GROUPS = [
  {
    label: 'Intelligence',
    items: [
      { path: '/', label: 'Reports', icon: BarChart3, exact: true, alsoPaths: ['/reports'] },
      { path: '/threat-intel', label: 'Threat Intel', icon: ShieldAlert },
    ],
  },
  {
    label: 'Exposure',
    items: [
      { path: '/assets', label: 'Assets', icon: Server },
      { path: '/findings', label: 'Findings', icon: Bug },
      { path: '/inventory', label: 'Inventory', icon: Database },
    ],
  },
  {
    label: 'Response',
    items: [
      { path: '/campaigns', label: 'Campaigns', icon: Target },
      { path: '/aggregated-solutions', label: 'Remediation', icon: Layers },
      { path: '/agents', label: 'Agents', icon: Bot },
    ],
  },
]

const NAV_SETTINGS = { path: '/settings', label: 'Settings', icon: SettingsIcon }

function ProtectedRoute({ children }) {
  const { isAuthenticated, isLoading } = useAuth()
  if (isLoading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', color: '#71717a' }}>
        Loading...
      </div>
    )
  }
  if (!isAuthenticated) return <Navigate to="/login" replace />
  return children
}

function OrgSwitcher({ collapsed }) {
  const { accessibleOrgs, currentOrgContext, switchOrg, isMSSP, isSuperadmin, org } = useAuth()

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
        {!collapsed && 'Org Context'}
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
        <option value="">All Organizations</option>
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
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
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
            {theme === 'dark' ? 'Light mode' : 'Dark mode'}
          </button>
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
            <User size={14} /> View Profile
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
            <LogOut size={14} /> Log out
          </button>
        </div>
      )}
    </div>
  )
}

function Sidebar({ collapsed, onToggle }) {
  const width = collapsed ? 56 : 220
  const { scans, activeScanId, setActiveScanId } = useScan()

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
        <button
          type="button"
          onClick={onToggle}
          aria-label={collapsed ? 'Expand navigation' : 'Collapse navigation'}
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
            padding: 0
          }}
        >
          <img
            src="/logo-symbol.svg"
            alt="Toggle navigation"
            style={{ width: 18, height: 18, display: 'block' }}
          />
        </button>
        {!collapsed && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <div>
              <div style={{ fontSize: 13, fontWeight: 800 }}>Hakuna</div>
              <div style={{ fontSize: 11, color: 'var(--muted)' }}>Exposure Center</div>
            </div>
          </div>
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
        {NAV_GROUPS.map((group, gi) => (
          <div key={group.label} style={{ marginBottom: collapsed ? 8 : 4 }}>
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
                {group.label}
              </div>
            )}
            {collapsed && gi > 0 && (
              <div style={{ height: 1, background: 'var(--border)', margin: '6px 0' }} />
            )}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
              {group.items.map(({ path, label, icon: Icon, exact, alsoPaths }) => (
                <NavLink
                  key={path}
                  to={path}
                  end={exact}
                  title={label}
                  aria-label={label}
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
                  {!collapsed && <span style={{ fontSize: 13, fontWeight: 500 }}>{label}</span>}
                </NavLink>
              ))}
            </div>
          </div>
        ))}

        {/* Settings — ungrouped at bottom */}
        <div style={{ marginTop: 'auto', paddingTop: 8, paddingBottom: 8 }}>
          {!collapsed && (
            <div style={{ height: 1, background: 'var(--border)', marginBottom: 8 }} />
          )}
          <NavLink
            to={NAV_SETTINGS.path}
            title={NAV_SETTINGS.label}
            aria-label={NAV_SETTINGS.label}
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
            {!collapsed && <span style={{ fontSize: 13, fontWeight: 500 }}>{NAV_SETTINGS.label}</span>}
          </NavLink>
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

function AppShell() {
  const [scans, setScans] = useState([])
  const [activeScanId, setActiveScanId] = useState(null)
  const [navCollapsed, setNavCollapsed] = useState(false)

  useEffect(() => {
    getScans().then(data => {
      setScans(data)
    }).catch(() => {})
  }, [])

  const refreshScans = () => {
    getScans().then(data => {
      setScans(data)
    }).catch(() => {})
  }

  return (
    <ScanContext.Provider value={{ activeScanId, setActiveScanId, scans, refreshScans }}>
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
                <Route path="/upload" element={<UploadScan />} />
                <Route path="/profile" element={<UserManagement />} />
              </Routes>
            </Suspense>
          </main>
        </div>
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
