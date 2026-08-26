import { NavLink } from 'react-router-dom'
import { useNavigate } from 'react-router-dom'

import Icon from '../ui/Icon.jsx'
import { NAV_ITEMS } from '../../data/navigation.js'
import { getInvestigatorLabel, signOut } from '../../services/authService.js'
import './Sidebar.css'

/**
 * Primary navigation. Destinations beyond /dashboard resolve to a placeholder
 * that names the phase they belong to, and are marked here so the investigator
 * can tell built from pending at a glance.
 */
export default function Sidebar() {
  const navigate = useNavigate()
  const investigator = getInvestigatorLabel()

  function handleSignOut() {
    signOut()
    navigate('/', { replace: true })
  }

  return (
    <aside className="app-sidebar" aria-label="Primary">
      <nav className="sidebar-nav">
        <span className="sidebar-nav__section eyebrow">Workspace</span>
        <ul>
          {NAV_ITEMS.map((item) => (
            <li key={item.path}>
              <NavLink
                className={({ isActive }) =>
                  `sidebar-link${isActive ? ' sidebar-link--active' : ''}`
                }
                to={item.path}
              >
                <Icon name={item.icon} size={17} />
                <span className="sidebar-link__label">{item.label}</span>
                {item.phase && <span className="sidebar-link__pending" aria-hidden="true" />}
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>

      <div className="sidebar-foot">
        <div className="sidebar-case">
          <span className="eyebrow">Active case</span>
          <span className="sidebar-case__id mono">CASE-2026-0147</span>
          <span className="sidebar-case__host">
            <Icon name="host" size={12} />
            FIN-WKS-014
          </span>
        </div>

        <div className="sidebar-user">
          <span className="sidebar-user__avatar mono" aria-hidden="true">
            {investigator.slice(-2)}
          </span>
          <span className="sidebar-user__meta">
            <span className="sidebar-user__id mono">{investigator}</span>
            <span className="sidebar-user__role">Forensic examiner</span>
          </span>
          <button
            className="sidebar-user__signout"
            type="button"
            onClick={handleSignOut}
            aria-label="Sign out"
            title="Sign out"
          >
            <Icon name="logout" size={16} />
          </button>
        </div>
      </div>
    </aside>
  )
}
