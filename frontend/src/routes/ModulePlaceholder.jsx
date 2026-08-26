import { Link } from 'react-router-dom'
import Icon from '../components/ui/Icon.jsx'
import '../styles/page.css'
import './ModulePlaceholder.css'

/**
 * Stand-in for the forensic modules that arrive after Phase 1.
 *
 * The route exists so the sidebar is honest — every destination resolves — but
 * the screen states plainly that the module is not implemented rather than
 * showing an empty table that looks broken.
 *
 * @param {{ title: string, phase?: string }} props
 */
export default function ModulePlaceholder({ title, phase }) {
  return (
    <div className="page module-placeholder">
      <header className="page-head">
        <div className="page-head__titles">
          <h1 className="page-head__title">{title}</h1>
          <p className="page-head__subtitle">Not implemented in this build</p>
        </div>
      </header>

      <section className="module-card">
        <span className="module-card__icon">
          <Icon name="lock" size={20} />
        </span>

        <h2 className="module-card__title">{title} is not available yet</h2>
        <p className="module-card__copy">
          {phase ??
            'This module is scheduled for a later phase of the build.'}
        </p>

        <Link className="module-card__back" to="/dashboard">
          <Icon name="dashboard" size={13} />
          Back to dashboard
        </Link>
      </section>
    </div>
  )
}
