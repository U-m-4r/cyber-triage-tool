import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'

import BrandMark from '../BrandMark.jsx'
import Icon from '../ui/Icon.jsx'
import SeverityBadge from '../ui/SeverityBadge.jsx'
import { NOTIFICATIONS } from '../../data/mockDashboard.js'
import { getInvestigatorLabel } from '../../services/authService.js'
import './TopBar.css'

/**
 * Application top bar: brand, global search, notifications, session indicator.
 *
 * Search is a presentational input in Phase 1 — the artifact index it will query
 * does not exist on the backend yet, so it deliberately does not pretend to
 * return results.
 */
export default function TopBar({ onToggleNav, navOpen }) {
  const [notificationsOpen, setNotificationsOpen] = useState(false)
  const notificationsRef = useRef(null)
  const investigator = getInvestigatorLabel()

  useEffect(() => {
    if (!notificationsOpen) return undefined
    const onPointerDown = (event) => {
      if (!notificationsRef.current?.contains(event.target)) setNotificationsOpen(false)
    }
    const onKeyDown = (event) => {
      if (event.key === 'Escape') setNotificationsOpen(false)
    }
    document.addEventListener('pointerdown', onPointerDown)
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('pointerdown', onPointerDown)
      document.removeEventListener('keydown', onKeyDown)
    }
  }, [notificationsOpen])

  const unread = NOTIFICATIONS.length

  return (
    <header className="app-topbar">
      <div className="app-topbar__brand-slot">
        <button
          className="app-topbar__nav-toggle"
          type="button"
          onClick={onToggleNav}
          aria-expanded={navOpen}
          aria-label={navOpen ? 'Close navigation' : 'Open navigation'}
        >
          <Icon name={navOpen ? 'close' : 'menu'} size={18} />
        </button>

        <Link className="app-topbar__brand" to="/dashboard">
          <BrandMark size={22} />
          <span className="app-topbar__word">
            CYBER<span className="app-topbar__word-accent">TRIAGE</span>
          </span>
        </Link>
      </div>

      <div className="app-topbar__search">
        <Icon name="search" size={15} className="app-topbar__search-icon" />
        <input
          type="search"
          placeholder="Search cases, hosts, hashes, indicators…"
          aria-label="Search"
        />
        <kbd className="app-topbar__kbd">Ctrl K</kbd>
      </div>

      <div className="app-topbar__actions">
        <div className="app-topbar__notify" ref={notificationsRef}>
          <button
            className="app-topbar__icon-button"
            type="button"
            onClick={() => setNotificationsOpen((open) => !open)}
            aria-expanded={notificationsOpen}
            aria-label={`Notifications (${unread} unread)`}
          >
            <Icon name="bell" size={17} />
            {unread > 0 && <span className="app-topbar__badge">{unread}</span>}
          </button>

          {notificationsOpen && (
            <div className="notify-panel" role="dialog" aria-label="Notifications">
              <header className="notify-panel__head">
                <span className="eyebrow">Notifications</span>
                <span className="notify-panel__count mono">{unread}</span>
              </header>
              <ul>
                {NOTIFICATIONS.map((item) => (
                  <li key={item.id} className="notify-item">
                    <SeverityBadge severity={item.severity} size="sm" />
                    <span className="notify-item__body">
                      <span className="notify-item__title">{item.title}</span>
                      <span className="notify-item__meta mono">
                        {item.caseId} · {item.relative}
                      </span>
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>

        <div className="app-topbar__session" title="Active investigator session">
          <span className="app-topbar__session-dot" aria-hidden="true" />
          <span className="app-topbar__session-meta">
            <span className="app-topbar__session-id mono">{investigator}</span>
            <span className="app-topbar__session-role">Session active</span>
          </span>
        </div>
      </div>
    </header>
  )
}
