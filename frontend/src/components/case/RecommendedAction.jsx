import Panel from '../dashboard/Panel.jsx'
import Icon from '../ui/Icon.jsx'
import './RecommendedAction.css'

const URGENCY_CLASS = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
}

/**
 * The next step on the case, split into what to do and why it is the next step.
 *
 * Both halves are shown because an investigator who cannot see the reasoning
 * cannot judge whether the ordering still holds — and the ordering is the whole
 * value of a recommendation. The rationale explains what would be lost by
 * choosing differently, not just what the steps are.
 *
 * @param {{ recommendation: object }} props
 */
export default function RecommendedAction({ recommendation }) {
  // Aliased so the response window does not shadow the global `window`.
  const { urgency, headline, window: actionWindow, owner, steps, rationale } = recommendation
  const urgencyClass = URGENCY_CLASS[urgency] ?? 'low'

  return (
    <Panel
      className="case-action"
      title="Recommended Next Action"
      subtitle="Suggested by the triage workflow — the examiner decides"
    >
      <div className={`case-action__banner case-action__banner--${urgencyClass}`}>
        <div className="case-action__banner-head">
          <span className="case-action__urgency">{urgency} priority</span>
          <span className="case-action__window">
            <Icon name="clock" size={12} />
            {actionWindow}
            <span className="case-action__owner mono">· {owner}</span>
          </span>
        </div>
        <p className="case-action__headline">{headline}</p>
      </div>

      <div className="case-action__split">
        <section className="case-action__block">
          <h3 className="eyebrow">What to do</h3>
          <ol className="case-action__steps">
            {steps.map((step, index) => (
              <li className="case-action__step" key={step}>
                <span className="case-action__step-index tabular">{index + 1}</span>
                <span className="case-action__step-copy">{step}</span>
              </li>
            ))}
          </ol>
        </section>

        <section className="case-action__block">
          <h3 className="eyebrow">Why this comes first</h3>
          <p className="case-action__rationale">{rationale}</p>
        </section>
      </div>

      <footer className="case-action__foot">
        Sample data — this recommendation was written by hand for UI development. No model produced
        it and no automated response is wired up.
      </footer>
    </Panel>
  )
}
