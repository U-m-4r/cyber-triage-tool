import Panel from '../dashboard/Panel.jsx'
import Icon from '../ui/Icon.jsx'
import SeverityBadge from '../ui/SeverityBadge.jsx'
import { formatCount, formatPercent, formatTimestamp } from '../../utils/format.js'
import './ThreatAssessment.css'

const SEVERITY_CLASS = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
}

const COVERAGE_LABEL = {
  observed: 'Observed',
  partial: 'Partial',
  none: 'Not observed',
}

/**
 * How the headline score was arrived at, and what the scored population looks
 * like underneath it.
 *
 * The point of this panel is traceability: a score an investigator cannot take
 * apart is a score they cannot defend, so the weighted composition is shown
 * explicitly rather than summarised. Cases the pipeline has not scored render a
 * pending state instead of a fabricated breakdown.
 *
 * @param {object} props
 * @param {object|null} props.assessment
 * @param {number} props.threatScore
 * @param {string} props.severity
 * @param {string} props.status
 */
export default function ThreatAssessment({ assessment, threatScore, severity, status }) {
  if (!assessment) {
    return (
      <Panel
        className="case-assess"
        title="Threat Assessment"
        subtitle="No scored breakdown available yet"
      >
        <div className="case-assess__pending">
          <Icon name="clock" size={16} className="case-assess__pending-icon" />
          <p className="case-assess__pending-copy">
            This case is <span className="case-assess__pending-state">{status}</span>. The provisional
            score of <span className="tabular">{threatScore}</span> comes from rule hits recorded
            during intake; no weighted breakdown, artifact ranking or indicator split exists until
            the scoring pass completes.
          </p>
        </div>
      </Panel>
    )
  }

  const { confidence, modelLabel, scoredAt, composition, artifactPriorities, iocBreakdown, coverage } =
    assessment

  const priorityTotal = artifactPriorities.reduce((sum, band) => sum + band.count, 0)
  const iocTotal = iocBreakdown.reduce((sum, entry) => sum + entry.count, 0)

  return (
    <Panel
      className="case-assess"
      title="Threat Assessment"
      subtitle={`${modelLabel} · scored ${formatTimestamp(scoredAt)}`}
    >
      <div className="case-assess__verdict">
        <div className="case-assess__verdict-main">
          <SeverityBadge severity={severity} />
          <span className="case-assess__verdict-copy">
            Examiner classification for the case as a whole
          </span>
        </div>
        <span className="case-assess__confidence">
          Model confidence <span className="tabular">{formatPercent(confidence)}</span>
        </span>
      </div>

      {/* Weighted composition: the two terms have to add up to the headline
          score on screen, or the number is not auditable. */}
      <section className="case-assess__block">
        <h3 className="eyebrow">Score composition</h3>
        <ul className="case-assess__composition">
          {composition.map((term) => (
            <li className="case-assess__term" key={term.id}>
              <div className="case-assess__term-head">
                <span className="case-assess__term-label">{term.label}</span>
                <span className="case-assess__term-weight tabular">
                  ×{term.weight.toFixed(2)}
                </span>
              </div>
              <p className="case-assess__term-detail">{term.detail}</p>
              <div className="case-assess__term-bar" role="presentation">
                <span
                  className="case-assess__term-fill"
                  style={{ width: `${Math.min(100, term.score)}%` }}
                />
              </div>
              <div className="case-assess__term-values">
                <span className="tabular">{term.score.toFixed(1)} raw</span>
                <span className="tabular">+{term.contribution.toFixed(1)} to score</span>
              </div>
            </li>
          ))}
        </ul>
        <div className="case-assess__total">
          <span>Composite threat score</span>
          <span className="case-assess__total-value tabular">{threatScore}/100</span>
        </div>
      </section>

      {/* Band thresholds here are the artifact-level ones from
          ml/risk_scorer.py — they classify individual records, not the case. */}
      <section className="case-assess__block">
        <h3 className="eyebrow">Artifact priority distribution</h3>
        <ul className="case-assess__bands">
          {artifactPriorities.map((band) => {
            const share = priorityTotal ? band.count / priorityTotal : 0
            const key = SEVERITY_CLASS[band.severity] ?? 'low'

            return (
              <li className={`case-assess__band case-assess__band--${key}`} key={band.severity}>
                <span className="case-assess__band-label">{band.severity}</span>
                <span className="case-assess__band-count tabular">{formatCount(band.count)}</span>
                <span className="case-assess__band-bar" role="presentation">
                  <span
                    className="case-assess__band-fill"
                    style={{ width: `${Math.max(share * 100, share > 0 ? 1.5 : 0)}%` }}
                  />
                </span>
                <span className="case-assess__band-share tabular">
                  {formatPercent(share, share < 0.01 ? 2 : 1)}
                </span>
              </li>
            )
          })}
        </ul>
      </section>

      <div className="case-assess__split">
        <section className="case-assess__block">
          <h3 className="eyebrow">Indicators ({iocTotal})</h3>
          <dl className="case-assess__iocs">
            {iocBreakdown.map((entry) => (
              <div className="case-assess__ioc" key={entry.label}>
                <dt>{entry.label}</dt>
                <dd className="tabular">{entry.count}</dd>
              </div>
            ))}
          </dl>
        </section>

        <section className="case-assess__block">
          <h3 className="eyebrow">Tactic coverage</h3>
          <ul className="case-assess__coverage">
            {coverage.map((entry) => (
              <li
                className={`case-assess__tactic case-assess__tactic--${entry.state}`}
                key={entry.tactic}
              >
                <span className="case-assess__tactic-mark" aria-hidden="true" />
                <span className="case-assess__tactic-name">{entry.tactic}</span>
                <span className="case-assess__tactic-note">{entry.note}</span>
                <span className="visually-hidden">{COVERAGE_LABEL[entry.state]}</span>
              </li>
            ))}
          </ul>
        </section>
      </div>
    </Panel>
  )
}
