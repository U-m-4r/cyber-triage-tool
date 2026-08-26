import { Link } from 'react-router-dom'

import CinematicBackground from '../components/landing/CinematicBackground.jsx'
import SiteHeader from '../components/landing/SiteHeader.jsx'
import Icon from '../components/ui/Icon.jsx'
import useEntranceMotion from '../hooks/useEntranceMotion.js'
import useRouteMode from '../hooks/useRouteMode.js'
import '../styles/cinematic.css'
import './LandingPage.css'

/**
 * Landing route.
 *
 * Composition is deliberately minimal: cinematic background, header, hero stack,
 * one CTA. No case data, metrics, or dashboard preview appears before login —
 * the investigation surface starts at /dashboard.
 */
export default function LandingPage() {
  useRouteMode('cinematic')
  const { motionProps, onSettled } = useEntranceMotion()

  return (
    <main className="viewport">
      <section className="screen landing" {...motionProps}>
        <CinematicBackground />
        <SiteHeader />

        <section className="hero">
          <div className="hero-content">
            <h1 className="hero-title">
              <span className="line line-one">
                <span className="line-reveal">Digital Forensics.</span>
              </span>
              <span className="line line-two">
                <span className="line-reveal">Clear Answers. Faster.</span>
              </span>
            </h1>

            <p className="hero-copy">
              Accelerate digital forensic investigations with automated
              <br />
              evidence analysis, intelligent IOC detection, AI-powered
              <br />
              triage, and investigator-focused visualization.
            </p>

            {/* Last element in the entrance timeline, so it closes out the
                choreography for useEntranceMotion. */}
            <div
              className="hero-actions"
              onAnimationEnd={(event) => {
                if (event.animationName === 'entrance-action') onSettled()
              }}
            >
              <Link className="primary-cta" to="/login">
                <span className="primary-cta__label">Get Started</span>
                <span className="primary-cta__arrow" aria-hidden="true">
                  <Icon name="arrowRight" size={14} strokeWidth={1.7} />
                </span>
              </Link>
            </div>
          </div>
        </section>
      </section>
    </main>
  )
}
