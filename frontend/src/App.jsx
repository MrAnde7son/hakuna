import React, { useState, useEffect, createContext, useContext } from 'react'
import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import {
  Server,
  Bug,
  BarChart3,
  Database,
  Settings,
  Target,
  ShieldAlert,
} from 'lucide-react'
import AssetInventory from './components/AssetInventory.jsx'
import FindingExplorer from './components/FindingExplorer.jsx'
import FindingDetail from './components/FindingDetail.jsx'
import Campaigns from './components/Campaigns.jsx'
import CampaignDetail from './components/CampaignDetail.jsx'
import Reports from './components/Reports.jsx'
import InventoryExplorer from './components/InventoryExplorer.jsx'
import DedupSettings from './components/DedupSettings.jsx'
import UploadScan from './components/UploadScan.jsx'
import TagManager from './components/TagManager.jsx'
import ThreatIntelCenter from './components/ThreatIntelCenter.jsx'
import WorkflowBuilder from './components/WorkflowBuilder.jsx'
import { getScans } from './api.js'

// Global scan context
export const ScanContext = createContext({ activeScanId: null, setActiveScanId: () => {} })
export const useScan = () => useContext(ScanContext)

const NAV_ITEMS = [
  { path: '/', label: 'Dashboard', icon: BarChart3, exact: true },
  { path: '/assets', label: 'Assets', icon: Server },
  { path: '/findings', label: 'Findings', icon: Bug },
  { path: '/inventory', label: 'Inventory', icon: Database },
  { path: '/campaigns', label: 'Campaigns', icon: Target },
  { path: '/threat-intel', label: 'Threat Intel', icon: ShieldAlert },
  { path: '/settings', label: 'Settings', icon: Settings },
]

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
            background: '#fff',
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
          gap: 8,
          alignItems: 'stretch',
          padding: collapsed ? '0 10px' : '0 12px',
          flex: 1
        }}
      >
        {NAV_ITEMS.map(({ path, label, icon: Icon, exact }) => (
          <NavLink
            key={path}
            to={path}
            end={exact}
            title={label}
            aria-label={label}
            style={({ isActive }) => ({
              display: 'flex',
              alignItems: 'center',
              gap: 10,
              padding: '8px 10px',
              borderRadius: 6,
              color: isActive ? '#fff' : '#71717a',
              background: isActive ? '#18181b' : 'transparent',
              textDecoration: 'none',
              cursor: 'pointer',
              boxShadow: isActive ? '0 1px 2px rgba(0,0,0,0.12)' : 'none',
              transition: 'background 0.15s ease, color 0.15s ease, box-shadow 0.15s ease',
              justifyContent: collapsed ? 'center' : 'flex-start'
            })}
          >
            <Icon size={18} />
            {!collapsed && <span style={{ fontSize: 13, fontWeight: 500 }}>{label}</span>}
          </NavLink>
        ))}
      </nav>

      {/* Active scan selector – always available, compact when collapsed */}
      {scans.length > 0 && (
        <div
          style={{
            padding: collapsed ? '8px 6px' : '12px',
            borderTop: '1px solid var(--border)',
            marginTop: 16
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
              background: '#fff',
              border: '1px solid var(--border)',
              borderRadius: 10,
              padding: collapsed ? '4px 6px' : '6px 10px',
              fontSize: collapsed ? 10 : 12,
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
              overflowY: 'auto'
            }}
          >
            <Routes>
              <Route path="/" element={<Reports />} />
              <Route path="/assets" element={<AssetInventory />} />
              <Route path="/findings" element={<FindingExplorer />} />
              <Route path="/findings/:id" element={<FindingDetail />} />
              <Route path="/campaigns" element={<Campaigns />} />
              <Route path="/campaigns/:id" element={<CampaignDetail />} />
              <Route path="/workflows/:id" element={<WorkflowBuilder />} />
              <Route path="/inventory" element={<InventoryExplorer />} />
              <Route path="/tags" element={<TagManager />} />
              <Route path="/threat-intel" element={<ThreatIntelCenter />} />
              <Route path="/settings" element={<DedupSettings />} />
              <Route path="/upload" element={<UploadScan />} />
            </Routes>
          </main>
        </div>
      </div>
    </ScanContext.Provider>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <AppShell />
    </BrowserRouter>
  )
}
