import { Link } from 'react-router-dom'
import Icon from '../ui/Icon.jsx'
import SeverityBadge, { StatusBadge } from '../ui/SeverityBadge.jsx'
import { formatCount, formatTimestamp } from '../../utils/format.js'
import './CaseHeader.css'

const SEVERITY_CLASS = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
}

/**
 * Identity band for a case workspace.
 *
 * Answers, in one glance and in the order an investigator asks them: which case,
 * how serious, where in the pipeline, how much evidence sits behind it, and how
 * fresh that picture is. The score meter is neutral — the severity chip beside it
 * is what carries hue.
 *
 * @param {{ caseRecord: import('../../data/mockCases.js').CaseRecord }} props
 */
export default function CaseHeader({ caseRecord }) {
  const {
    id,
    title,
    description,
    threatScore,
    severity,
    status,
    counts,
    lastActivity,
  } = caseRecord

  const severityClass = SEVERITY_CLASS[severity] ?? 'low'

  return (
    <header className={`case-head case-head--${severityClass}`}>
      <div className="case-head__top">
        <Link className="case-head__back" to="/dashboard">
          <Icon name="chevronRight" size={13} className="case-head__back-icon" />
          Back to Dashboard
        </Link>

        <span className="page-head__notice">
          <Icon name="alert" size={12} strokeWidth={1.7} />
          Sample data — no evidence has been parsed
        </span>
      </div>

      <div className="case-head__identity">
        <div className="case-head__id-line">
          <h1 className="case-head__id mono">{id}</h1>
          <StatusBadge status={status} />
          <SeverityBadge severity={severity} />
        </div>
        <p className="case-head__title">{title}</p>
        <p className="case-head__description">{description}</p>
      </div>

      <dl className="case-head__facts">
        <div className="case-head__score">
          <dt className="case-head__fact-label">Threat score</dt>
          <dd>
            <span className="case-head__score-line">
              <span className="case-head__score-value tabular">{threatScore}</span>
              <span className="case-head__score-max">/100</span>
            </span>
            <span className="case-head__meter" role="presentation">
              <span className="case-head__meter-fill" style={{ width: `${threatScore}%` }} />
            </span>
          </dd>
        </div>

        <div className="case-head__fact">
          <dt className="case-head__fact-label">Evidence</dt>
          <dd className="case-head__fact-value tabular">{counts.evidence}</dd>
        </div>

        <div className="case-head__fact">
          <dt className="case-head__fact-label">Artifacts</dt>
          <dd className="case-head__fact-value tabular">{formatCount(counts.artifacts)}</dd>
        </div>

        <div className="case-head__fact">
          <dt className="case-head__fact-label">IOCs</dt>
          <dd className="case-head__fact-value tabular">{counts.iocs}</dd>
        </div>

        <div className="case-head__fact case-head__fact--activity">
          <dt className="case-head__fact-label">Last activity</dt>
          <dd className="case-head__fact-value">
            {lastActivity.relative}
            <span className="case-head__fact-note" title={lastActivity.label}>
              {formatTimestamp(lastActivity.at)}
            </span>
          </dd>
        </div>
      </dl>
    </header>
  )
}
