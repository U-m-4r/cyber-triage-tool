import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import BrandMark from '../BrandMark.jsx'
import Icon from '../ui/Icon.jsx'
import { getInvestigatorLabel, getSession } from '../../services/authService.js'
import './TopBar.css'
export default function TopBar({ onToggleNav, navOpen }) {
  const [query, setQuery] = useState('')
  const navigate = useNavigate()
  return <header className="app-topbar">
    <div className="app-topbar__brand-slot"><button type="button" className="app-topbar__nav-toggle" onClick={onToggleNav} aria-expanded={navOpen} aria-label="Toggle navigation"><Icon name="menu" size={18} /></button>
      <Link className="app-topbar__brand" to="/dashboard"><BrandMark size={22} /> CYBER TRIAGE</Link></div>
    <form className="app-topbar__search" onSubmit={e => { e.preventDefault(); navigate(`/cases?q=${encodeURIComponent(query)}`) }}>
      <input type="search" aria-label="Search cases" placeholder="Search cases, hosts, investigators…" value={query} onChange={e => setQuery(e.target.value)} />
      <button type="submit" aria-label="Submit case search"><Icon name="search" size={15} /></button>
    </form>
    <div className="app-topbar__actions"><Link to="/timeline">Activity</Link><div className="app-topbar__session">
      <span>{getInvestigatorLabel()}</span><span>{getSession()?.authMode === 'shared-token' ? 'Shared token access' : 'Development access'}</span>
    </div></div>
  </header>
}
