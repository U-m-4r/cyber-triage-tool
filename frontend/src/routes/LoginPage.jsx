import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'

import BrandMark from '../components/BrandMark.jsx'
import CinematicBackground from '../components/landing/CinematicBackground.jsx'
import Icon from '../components/ui/Icon.jsx'
import useRouteMode from '../hooks/useRouteMode.js'
import { authenticate } from '../services/authService.js'
import '../styles/cinematic.css'
import './LoginPage.css'

/**
 * Investigator sign-in.
 *
 * Same footage, branding and typography as the landing route, turned down: the
 * background is darkened and slowed, and the panel is a plain charcoal surface
 * rather than the landing's expressive glass. No credential check happens here —
 * see authService.
 */
export default function LoginPage() {
  useRouteMode('cinematic')
  const navigate = useNavigate()

  const [investigatorId, setInvestigatorId] = useState('')
  const [password, setPassword] = useState('')
  const [pending, setPending] = useState(false)
  const [error, setError] = useState(null)

  async function handleSubmit(event) {
    event.preventDefault()
    if (pending) return

    if (!investigatorId.trim() || !password) {
      setError('Enter an investigator ID and password to continue.')
      return
    }

    setError(null)
    setPending(true)
    await authenticate({ investigatorId })
    navigate('/dashboard', { replace: true })
  }

  return (
    <main className="viewport">
      <section className="screen login">
        <CinematicBackground dim />

        <div className="login-layout">
          <section className="login-panel" aria-labelledby="login-heading">
            <div className="login-panel__brand">
              <BrandMark size={24} />
              <span className="login-panel__word">
                CYBER<span className="login-panel__word-accent">TRIAGE</span>
              </span>
            </div>

            <h1 className="login-panel__heading" id="login-heading">
              Investigator Sign In
            </h1>
            <p className="login-panel__sub">Sign in to access Cyber Triage.</p>

            <form className="login-form" onSubmit={handleSubmit} noValidate>
              <label className="login-field">
                <span className="login-field__label">Investigator ID</span>
                <input
                  className="login-field__input mono"
                  type="text"
                  name="investigatorId"
                  autoComplete="username"
                  placeholder="INV-0000"
                  value={investigatorId}
                  onChange={(event) => setInvestigatorId(event.target.value)}
                  disabled={pending}
                  autoFocus
                />
              </label>

              <label className="login-field">
                <span className="login-field__label">Password</span>
                <input
                  className="login-field__input"
                  type="password"
                  name="password"
                  autoComplete="current-password"
                  placeholder="••••••••••••"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  disabled={pending}
                />
              </label>

              {/* Fixed-height row so the panel does not shift when validation fires. */}
              <p className="login-form__error" role="alert">
                {error ?? ''}
              </p>

              <button className="login-submit" type="submit" disabled={pending}>
                <span className="login-submit__label">
                  {pending ? 'Authenticating' : 'Authenticate'}
                </span>
                <span className="login-submit__arrow" aria-hidden="true">
                  {pending ? (
                    <span className="login-submit__spinner" />
                  ) : (
                    <Icon name="arrowRight" size={14} strokeWidth={1.7} />
                  )}
                </span>
              </button>
            </form>

            <footer className="login-panel__foot">
              <Link className="login-back" to="/">
                <Icon
                  name="arrowRight"
                  size={13}
                  strokeWidth={1.7}
                  className="login-back__icon"
                />
                Back to landing
              </Link>
            </footer>
          </section>
        </div>
      </section>
    </main>
  )
}
