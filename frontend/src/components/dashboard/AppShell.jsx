import { useEffect, useState } from 'react'
import { Outlet, useLocation } from 'react-router-dom'

import Sidebar from './Sidebar.jsx'
import TopBar from './TopBar.jsx'
import './AppShell.css'

/**
 * Investigator application shell: persistent sidebar + top bar around a scrolling
 * content column.
 *
 * The landing composition is deliberately left behind here — once a case is open
 * the interface stops being cinematic and becomes an instrument.
 */
export default function AppShell() {
  const [drawerOpen, setDrawerOpen] = useState(false)
  const { pathname } = useLocation()

  // Navigating always dismisses the small-screen drawer.
  useEffect(() => {
    setDrawerOpen(false)
  }, [pathname])

  useEffect(() => {
    if (!drawerOpen) return undefined
    const onKeyDown = (event) => {
      if (event.key === 'Escape') setDrawerOpen(false)
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [drawerOpen])

  return (
    <div className={`app-shell${drawerOpen ? ' app-shell--drawer-open' : ''}`}>
      <TopBar onToggleNav={() => setDrawerOpen((open) => !open)} navOpen={drawerOpen} />
      <Sidebar />
      <main className="app-main">
        <Outlet />
      </main>
      <button
        className="app-scrim"
        type="button"
        tabIndex={drawerOpen ? 0 : -1}
        aria-label="Close navigation"
        onClick={() => setDrawerOpen(false)}
      />
    </div>
  )
}
