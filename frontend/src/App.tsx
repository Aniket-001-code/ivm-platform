import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from 'react'
import { Link, NavLink, Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { ChevronDown, CircleHelp, LogOut, Search, Shield } from 'lucide-react'
import { api, setAccessToken, setSessionHandlers, storeRefreshToken } from './api/client'
import { NAV, can, label } from './access'
import type { User } from './types'
import { Login } from './pages/Login'
import { DashboardPage } from './pages/Dashboard'
import { FindingsPage } from './pages/Findings'
import { FindingDetailPage } from './pages/FindingDetail'
import { AssetDetailPage, AssetsPage } from './pages/Assets'
import { AttackPathsPage } from './pages/AttackPaths'
import { TasksPage } from './pages/Tasks'
import { ExceptionsPage } from './pages/Exceptions'
import { ImportsPage } from './pages/Imports'
import { AssistantPage } from './pages/Assistant'
import { AuditPage } from './pages/Audit'
import { AdminPage } from './pages/Admin'
import { ReportsPage } from './pages/Reports'
import { AccountPage } from './pages/Account'
import { NotificationBell } from './components/Notifications'
import './additions.css'

const USER_KEY = 'ivm.user'
const TOKEN_KEY = 'ivm.token'

function readStored<T>(key: string, parse: (raw: string) => T): T | null {
  try {
    const raw = sessionStorage.getItem(key)
    return raw ? parse(raw) : null
  } catch {
    return null
  }
}

function writeStored(key: string, value: string | null) {
  try {
    if (value === null) sessionStorage.removeItem(key)
    else sessionStorage.setItem(key, value)
  } catch {
    /* storage unavailable (private mode): the session lives in memory only */
  }
}

function App() {
  const [user, setUser] = useState<User | null>(() => {
    const stored = readStored(USER_KEY, (raw) => JSON.parse(raw) as User)
    // Sessions saved before permissions were sent with the user must sign in again.
    return stored && Array.isArray(stored.permissions) ? stored : null
  })
  const [token, setToken] = useState<string | null>(() => readStored(TOKEN_KEY, (raw) => raw))
  const [expiredNotice, setExpiredNotice] = useState(false)
  const location = useLocation()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  setAccessToken(token)

  const clearSession = useCallback(() => {
    writeStored(USER_KEY, null)
    writeStored(TOKEN_KEY, null)
    storeRefreshToken(null)
    setUser(null)
    setToken(null)
    setAccessToken(null)
    queryClient.clear()
  }, [queryClient])

  useEffect(() => {
    setSessionHandlers({
      expired: () => {
        clearSession()
        setExpiredNotice(true)
      },
      refreshed: (next) => {
        writeStored(TOKEN_KEY, next)
        setToken(next)
      },
    })
  }, [clearSession])

  function login(result: { access_token: string; refresh_token: string; user: User }) {
    writeStored(USER_KEY, JSON.stringify(result.user))
    writeStored(TOKEN_KEY, result.access_token)
    storeRefreshToken(result.refresh_token)
    setExpiredNotice(false)
    setUser(result.user)
    setToken(result.access_token)
    setAccessToken(result.access_token)
    navigate('/')
  }

  function updateUser(next: User) {
    writeStored(USER_KEY, JSON.stringify(next))
    setUser(next)
  }

  function logout() {
    // Revoke the refresh token server-side; sign out locally even if the call fails.
    void api('/auth/logout', { method: 'POST' }).catch(() => undefined)
    clearSession()
    navigate('/login')
  }

  if (!token || !user)
    return (
      <>
        {expiredNotice && (
          <div className="session-banner" role="status">
            Your session expired. Please sign in again.
          </div>
        )}
        <Login onLogin={login} />
      </>
    )

  const allowed = NAV.filter((item) => can(user, ...item.anyOf))
  const guard = (path: string, element: ReactNode) => {
    const item = NAV.find((x) => x.to === path)
    return !item || can(user, ...item.anyOf) ? element : <Navigate to="/" replace />
  }
  const current = allowed.find((x) => (x.to === '/' ? location.pathname === '/' : location.pathname.startsWith(x.to)))
  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        Skip to main content
      </a>
      <aside className="sidebar">
        <Link to="/" className="brand">
          <span className="brand-icon">
            <Shield size={17} />
          </span>
          <span>
            ivm<span className="brand-dot">.</span>
            <small>RISK COMMAND CENTER</small>
          </span>
        </Link>
        <div className="workspace-switch">
          <span className="workspace-avatar">N</span>
          <span>
            <strong>Northstar Bank</strong>
            <small>Synthetic workspace</small>
          </span>
          <ChevronDown size={15} />
        </div>
        <span className="nav-caption">WORKSPACE</span>
        <nav aria-label="Main navigation">
          {allowed.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
            >
              <item.icon size={17} />
              <span>{item.label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="health-line">
            <span className="status-dot" />
            <span>API connected</span>
          </div>
          <button className="user-switch" onClick={logout} title="Sign out">
            <span className="user-avatar">{user.full_name.slice(0, 1)}</span>
            <span>
              <strong>{user.full_name}</strong>
              <small>{label(user.role)}</small>
            </span>
            <LogOut size={16} />
          </button>
        </div>
      </aside>
      <main className="main-area">
        <header className="topbar">
          <div className="breadcrumb">
            Security <span>/</span>{' '}
            <strong>{current?.label ?? (location.pathname === '/account' ? 'My account' : 'Workspace')}</strong>
          </div>
          {can(user, 'finding:read') && <GlobalSearch />}
          <div className="top-actions">
            <NotificationBell />
            <div className="env-pill">
              <span /> DEMO ENVIRONMENT
            </div>
            <a className="icon-button" aria-label="API documentation" href="/docs" target="_blank" rel="noreferrer">
              <CircleHelp size={18} />
            </a>
            <Link className="user-avatar small" to="/account" title={`${user.email} · my account`} aria-label="My account">
              {user.full_name.slice(0, 1)}
            </Link>
          </div>
        </header>
        <div className="page-wrap" id="main-content" tabIndex={-1}>
          <Routes>
            <Route path="/" element={<DashboardPage user={user} />} />
            <Route path="/findings" element={guard('/findings', <FindingsPage user={user} />)} />
            <Route path="/findings/:id" element={guard('/findings', <FindingDetailPage user={user} />)} />
            <Route path="/assets" element={guard('/assets', <AssetsPage user={user} />)} />
            <Route path="/assets/:id" element={guard('/assets', <AssetDetailPage user={user} />)} />
            <Route path="/attack-paths" element={guard('/attack-paths', <AttackPathsPage user={user} />)} />
            <Route path="/tasks" element={guard('/tasks', <TasksPage user={user} />)} />
            <Route path="/exceptions" element={guard('/exceptions', <ExceptionsPage user={user} />)} />
            <Route path="/imports" element={guard('/imports', <ImportsPage />)} />
            <Route path="/assistant" element={guard('/assistant', <AssistantPage />)} />
            <Route path="/auditor" element={guard('/auditor', <AuditPage />)} />
            <Route path="/admin" element={guard('/admin', <AdminPage user={user} />)} />
            <Route path="/reports" element={guard('/reports', <ReportsPage user={user} />)} />
            <Route path="/account" element={<AccountPage user={user} onUserChange={updateUser} />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </div>
      </main>
    </div>
  )
}

function GlobalSearch() {
  const navigate = useNavigate()
  const [term, setTerm] = useState('')
  function submit(event: FormEvent) {
    event.preventDefault()
    const query = term.trim()
    if (query) navigate(`/findings?search=${encodeURIComponent(query)}`)
  }
  return (
    <form className="global-search" role="search" onSubmit={submit}>
      <Search size={15} />
      <input
        aria-label="Global finding search"
        placeholder="Search findings…"
        value={term}
        onChange={(e) => setTerm(e.target.value)}
      />
    </form>
  )
}

export default App
