import { useEffect } from 'react'
import { BrowserRouter, Routes, Route, NavLink, useLocation } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  LayoutDashboard, Database, ShieldAlert, AlertOctagon,
  BookOpen, FileText, ClipboardList, Building2, Wifi, WifiOff
} from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { fetchOrgs, fetchIncidentStats } from './api'
import { useAppStore } from './store'
import { useWebSocket } from './hooks/useWebSocket'
import Dashboard  from './pages/Dashboard'
import LogsPage   from './pages/Logs'
import AlertsPage from './pages/Alerts'
import IncidentsPage from './pages/Incidents'
import PlaybooksPage from './pages/Playbooks'
import ReportsPage   from './pages/Reports'
import AuditPage     from './pages/Audit'
import './index.css'

const qc = new QueryClient({ defaultOptions: { queries: { staleTime: 30_000 } } })

const NAV = [
  { to: '/',          label: 'Dashboard',  icon: LayoutDashboard },
  { to: '/logs',      label: 'Logs',       icon: Database },
  { to: '/alerts',    label: 'Alerts',     icon: ShieldAlert },
  { to: '/incidents', label: 'Incidents',  icon: AlertOctagon },
  { to: '/playbooks', label: 'Playbooks',  icon: BookOpen },
  { to: '/reports',   label: 'Reports',    icon: FileText },
  { to: '/audit',     label: 'Audit',      icon: ClipboardList },
]

function Sidebar() {
  const { orgs, selectedOrg, setOrg, setOrgs } = useAppStore()
  const { connected } = useWebSocket()

  const { data: incStats } = useQuery({
    queryKey: ['incidentStats'],
    queryFn: () => fetchIncidentStats(),
    refetchInterval: 15_000,
  })

  useQuery({
    queryKey: ['orgs'],
    queryFn: () => fetchOrgs().then(data => { setOrgs(data); return data }),
    staleTime: Infinity,
  })

  const pendingCount = incStats?.awaiting_approval ?? 0

  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <div className="logo-mark">
          <div className="logo-icon">🛡️</div>
          <div>
            <div className="logo-text">SENTINEL-AI</div>
            <div className="logo-sub">SOC · Auto-Response</div>
          </div>
        </div>
      </div>

      <nav className="sidebar-nav">
        <div className="nav-section-label">Operations</div>
        {NAV.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}
          >
            <Icon size={16} />
            {label}
            {label === 'Incidents' && pendingCount > 0 && (
              <span className="nav-badge">{pendingCount}</span>
            )}
          </NavLink>
        ))}

        <div className="nav-section-label" style={{ marginTop: 12 }}>System</div>
        <div style={{ padding: '6px 12px', fontSize: 12, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 6 }}>
          {connected
            ? <><div className="ws-dot connected" /><span style={{ color: 'var(--low)' }}>Live</span></>
            : <><div className="ws-dot disconnected" /><span style={{ color: 'var(--critical)' }}>Offline</span></>
          }
          <span style={{ marginLeft: 4 }}>WebSocket</span>
        </div>
      </nav>

      <div className="sidebar-org-picker">
        <div style={{ fontSize: 10, color: 'var(--text-muted)', letterSpacing: 1, fontWeight: 600, textTransform: 'uppercase', marginBottom: 6 }}>
          <Building2 size={10} style={{ display: 'inline', marginRight: 4 }} />
          Organization
        </div>
        <select
          className="org-select"
          value={selectedOrg?.id ?? ''}
          onChange={e => {
            const org = orgs.find(o => o.id === e.target.value) ?? null
            setOrg(org)
          }}
        >
          <option value="">All Organizations</option>
          {orgs.map(org => (
            <option key={org.id} value={org.id}>{org.name}</option>
          ))}
        </select>
        {selectedOrg && (
          <div style={{ marginTop: 6, fontSize: 10, color: 'var(--text-muted)' }}>
            {selectedOrg.industry} · {selectedOrg.domain}
          </div>
        )}
      </div>
    </aside>
  )
}

function Topbar() {
  const location = useLocation()
  const { selectedOrg } = useAppStore()

  const current = NAV.find(n => {
    if (n.to === '/') return location.pathname === '/'
    return location.pathname.startsWith(n.to)
  })

  return (
    <header className="topbar">
      <div className="topbar-title">{current?.label ?? 'SENTINEL-AI'}</div>
      {selectedOrg && (
        <div className="topbar-sub" style={{ marginLeft: 12 }}>
          — {selectedOrg.name}
        </div>
      )}
      <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 12 }}>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
          {new Date().toLocaleDateString(undefined, { weekday: 'short', month: 'short', day: 'numeric' })}
        </div>
        <div style={{
          width: 32, height: 32, borderRadius: '50%',
          background: 'linear-gradient(135deg, var(--cyan) 0%, var(--purple) 100%)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 13, fontWeight: 800, color: '#000'
        }}>AI</div>
      </div>
    </header>
  )
}

function AppLayout() {
  return (
    <div className="layout">
      <Sidebar />
      <div className="main-content">
        <Topbar />
        <Routes>
          <Route path="/"          element={<Dashboard />} />
          <Route path="/logs"      element={<LogsPage />} />
          <Route path="/alerts"    element={<AlertsPage />} />
          <Route path="/incidents" element={<IncidentsPage />} />
          <Route path="/playbooks" element={<PlaybooksPage />} />
          <Route path="/reports"   element={<ReportsPage />} />
          <Route path="/audit"     element={<AuditPage />} />
        </Routes>
      </div>
    </div>
  )
}

export default function App() {
  return (
    <QueryClientProvider client={qc}>
      <BrowserRouter>
        <AppLayout />
      </BrowserRouter>
    </QueryClientProvider>
  )
}
