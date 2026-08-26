import Icon from '../ui/Icon.jsx'
import SeverityBadge from '../ui/SeverityBadge.jsx'
import { formatCount, formatPercent, formatTimestamp } from '../../utils/format.js'
import './AiTriagePanel.css'

const ARTIFACT_ICON = {
  network: 'network',
  file: 'file',
  registry: 'registry',
  system_log: 'reports',
}

/**
 * AI Triage summary for the selected case.
 *
 * The score is presented as a number against a severity-scaled bar rather than a
 * dial: the useful questions are "how high, in which band, how confident" and a
 * ring answers none of them better than a figure does.
 *
 * Every finding carries a rationale line, because "why was this flagged?" is the
 * question that decides whether an investigator trusts the ranking at all.
 *
 * @param {object} props
 * @param {object|null} props.triage  `null` when the case has not been scored yet.
 * @param {object} props.investigation Selected case, used for the pending state.
 */
export default function AiTriagePanel({ triage, investigation }) {
  if (!triage) {
    return (
      <section className="triage-panel triage-panel--pending">
        <header className="triage-panel__head">
          <div>
            <h2 className="triage-panel__title">AI Triage</h2>
            <p className="triage-panel__case mono">{investigation?.id ?? '—'}</p>
          </div>
        </header>

        <div className="triage-pending">
          <span className="triage-pending__icon">
            <Icon name="triage" size={22} />
          </span>
          <p className="triage-pending__headline">No triage summary yet</p>
          <p className="triage-pending__detail">
            {investigation?.status === 'INGESTING'
              ? 'Evidence is still being ingested. Scoring starts once artifact extraction completes.'
              : 'Artifacts are being correlated. The triage summary appears once scoring finishes.'}
          </p>
          {investigation && (
            <div className="triage-pending__meter">
              <span
                className="triage-pending__meter-fill"
                style={{ width: `${investigation.progress}%` }}
              />
            </div>
          )}
          {investigation && (
            <p className="triage-pending__progress tabular">
              {investigation.progress}% complete
            </p>
          )}
        </div>
      </section>
    )
  }

  const { threatScore, severity, confidence, criticalFindings, artifactsScored, scoredAt } = triage
  const severityClass = String(severity).toLowerCase()
  const urgencyClass = String(triage.recommendedAction.urgency ?? severity).toLowerCase()

  return (
    <section className="triage-panel">
      <header className="triage-panel__head">
        <div>
          <h2 className="triage-panel__title">AI Triage</h2>
          <p className="triage-panel__case mono">{triage.caseId}</p>
        </div>
        <SeverityBadge severity={severity} />
      </header>

      {/* ---- Score readout ---- */}
      <div className={`triage-summary triage-summary--${severityClass}`}>
        <span className="triage-summary__label">Threat score</span>

        <div className="triage-score">
          <span className="triage-score__value tabular">{threatScore}</span>
          <span className="triage-score__max">/100</span>
        </div>

        <div className="triage-score__meter" role="presentation">
          <span className="triage-score__meter-fill" style={{ width: `${threatScore}%` }} />
        </div>

        <dl className="triage-summary__stats">
          <div className="triage-stat">
            <dt>Confidence</dt>
            <dd className="tabular">{formatPercent(confidence)}</dd>
          </div>
          <div className="triage-stat triage-stat--critical">
            <dt>Critical findings</dt>
            <dd className="tabular">{criticalFindings}</dd>
          </div>
          <div className="triage-stat">
            <dt>Artifacts scored</dt>
            <dd className="tabular">{formatCount(artifactsScored, 'compact')}</dd>
          </div>
        </dl>
      </div>

      {/* ---- Recommended next action ---- */}
      <div className={`triage-action triage-action--${urgencyClass}`}>
        <span className="triage-action__label">Recommended next action</span>
        <p className="triage-action__headline">{triage.recommendedAction.headline}</p>
        <p className="triage-action__detail">{triage.recommendedAction.detail}</p>
      </div>

      {/* ---- Findings ---- */}
      <div className="triage-findings">
        <div className="triage-findings__head">
          <span className="eyebrow">Top findings</span>
          <span className="triage-findings__count mono">{triage.findings.length}</span>
        </div>

        <ul>
          {triage.findings.map((finding) => (
            <li key={finding.id} className="finding">
              {/* The icon states the artifact type; the badge beside the title
                  carries severity, so the chip itself stays neutral. */}
              <span className="finding__icon">
                <Icon name={ARTIFACT_ICON[finding.artifactType] ?? 'shield'} size={14} />
              </span>

              <div className="finding__body">
                <div className="finding__title-line">
                  <span className="finding__title">{finding.title}</span>
                  <SeverityBadge severity={finding.severity} size="sm" />
                </div>

                <p className="finding__rationale">{finding.rationale}</p>

                <div className="finding__meta">
                  <span className="finding__source mono" title={finding.source}>
                    {finding.source}
                  </span>
                  <span className="finding__technique mono" title="MITRE ATT&CK technique">
                    {finding.technique.id} · {finding.technique.name}
                  </span>
                  <span className="finding__observed">{formatTimestamp(finding.observedAt)}</span>
                </div>
              </div>

              <div className="finding__score">
                <span className="finding__score-label">Risk</span>
                <span className="finding__score-value tabular">{finding.riskScore}</span>
              </div>
            </li>
          ))}
        </ul>
      </div>

      <footer className="triage-panel__foot">
        <span>
          Sample data — scored {formatTimestamp(scoredAt)} · {triage.modelLabel}
        </span>
        <span className="triage-panel__disclaimer">
          Findings on this screen are authored fixtures for UI development. The
          detection pipeline is not connected yet.
        </span>
      </footer>
    </section>
  )
}
