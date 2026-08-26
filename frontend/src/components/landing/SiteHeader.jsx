import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'

import BrandMark from '../BrandMark.jsx'
import Icon from '../ui/Icon.jsx'
import './SiteHeader.css'

/**
 * Landing header: brand, section labels, system-time panel.
 *
 * Below 1100px the labels and panel collapse into a glass dropdown behind a
 * hamburger, matching the reference's tablet + mobile behaviour.
 *
 * There is no header action: the hero's GET STARTED is the single entry point
 * into the application, so a second login control would duplicate it.
 *
 * Only "Overview" is a link — the remaining labels are rendered as plain text
 * because Phase 1 intentionally ships no additional marketing sections, and a
 * focusable anchor that navigates nowhere is a worse affordance than a label.
 */

const SECTION_LABELS = ['Capabilities', 'Methodology', 'Contact']

export default function SiteHeader() {
  const [menuOpen, setMenuOpen] = useState(false)
  const headerRef = useRef(null)
  const panelRef = useRef(null)

  useEffect(() => {
    if (!menuOpen) return undefined

    const onKeyDown = (event) => {
      if (event.key === 'Escape') setMenuOpen(false)
    }
    const onPointerDown = (event) => {
      if (!headerRef.current?.contains(event.target)) setMenuOpen(false)
    }

    document.addEventListener('keydown', onKeyDown)
    document.addEventListener('pointerdown', onPointerDown)

    // Move focus into the panel so the menu is keyboard-operable.
    panelRef.current?.querySelector('a, button')?.focus()

    return () => {
      document.removeEventListener('keydown', onKeyDown)
      document.removeEventListener('pointerdown', onPointerDown)
    }
  }, [menuOpen])

  return (
    <header ref={headerRef} className={`header${menuOpen ? ' header--menu-open' : ''}`}>
      <Link className="brand" to="/" aria-label="Cyber Triage home">
        <BrandMark size={25} className="brand__mark" />
        <span className="brand__word">
          CYBER<span className="brand__word-accent">TRIAGE</span>
        </span>
      </Link>

      {/* The collapsed panel is taken out of the tab order by `visibility: hidden`
          in the 1100px media query, so no `inert` is needed here — and an
          unconditional one would wrongly disable the always-visible desktop nav. */}
      <div ref={panelRef} className="header__actions" id="site-navigation">
        <nav className="nav" aria-label="Sections">
          <Link className="nav__link nav__link--active" to="/">
            Overview
          </Link>
          {SECTION_LABELS.map((label) => (
            <span key={label} className="nav__link nav__link--upcoming">
              {label}
            </span>
          ))}
        </nav>

        <div className="status-panel">
          <span className="status-panel__label">System Time</span>
          <span className="status-panel__value">14:32 IST&nbsp; • &nbsp;26 August 2026</span>
        </div>
      </div>

      <button
        className="menu-toggle glass-cool"
        type="button"
        aria-expanded={menuOpen}
        aria-controls="site-navigation"
        aria-label={menuOpen ? 'Close menu' : 'Open menu'}
        onClick={() => setMenuOpen((open) => !open)}
      >
        <Icon name={menuOpen ? 'close' : 'menu'} size={20} strokeWidth={1.6} />
      </button>
    </header>
  )
}
