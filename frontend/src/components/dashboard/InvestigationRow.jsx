import { Link } from 'react-router-dom'
import Icon from '../ui/Icon.jsx'
import SeverityBadge, { StatusBadge } from '../ui/SeverityBadge.jsx'
import { formatCount, formatDate } from '../../utils/format.js'
import './InvestigationRow.css'

const SEVERITY_CLASS = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
}

/**
 * One row in the Active Investigations list.
 *
 * Reads left to right as the questions an investigator opens the dashboard with:
 * which case, how serious, how far along, what evidence is attached.
 *
 * Two targets, deliberately: the full-row hit area selects the case so its triage
 * summary loads beside the list without leaving the dashboard, while the case ID
 * and the row tail link through to the case workspace. Selecting is the cheap,
 * reversible action, so it keeps the large target.
 *
 * @param {object} props
 * @param {object} props.investigation
 * @param {boolean} props.selected
 * @param {(id: string) => void} props.onSelect
 */
export default function InvestigationRow({ investigation, selected, onSelect }) {
  const {
    id,
    title,
    threatScore,
    severity,
    status,
    progress,
    examiner,
    openedAt,
    lastActivity,
    evidence,
    artifacts,
    criticalFindings,
    iocHits,
    primaryHost,
  } = investigation

  const severityClass = SEVERITY_CLASS[severity] ?? 'low'

  return (
    <article
      className={`inv-row inv-row--${severityClass}${selected ? ' inv-row--selected' : ''}`}
    >
      <button
        className="inv-row__hit"
        type="button"
        onClick={() => onSelect(id)}
        aria-pressed={selected}
        aria-label={`Select ${id}`}
      />

      <div className="inv-row__identity">
        <div className="inv-row__id-line">
          <Link className="inv-row__id mono" to={`/cases/${id}`}>
            {id}
          </Link>
          <StatusBadge status={status} />
        </div>
        <p className="inv-row__title">{title}</p>
        <div className="inv-row__facts">
          <span className="inv-row__fact">
            <Icon name="host" size={12} />
            <span className="mono">{primaryHost}</span>
          </span>
          <span className="inv-row__fact">
            <Icon name="fingerprint" size={12} />
            {examiner}
          </span>
          <span className="inv-row__fact">
            <Icon name="clock" size={12} />
            Opened {formatDate(openedAt)}
          </span>
        </div>
      </div>

      <div className="inv-row__score">
        <div className="inv-row__score-line">
          <span className="inv-row__score-value tabular">{threatScore}</span>
          <span className="inv-row__score-max">/100</span>
        </div>
        <span className="inv-row__score-label">Threat score</span>
        <div className="inv-row__meter" role="presentation">
          <span className="inv-row__meter-fill" style={{ width: `${threatScore}%` }} />
        </div>
      </div>

      <div className="inv-row__severity">
        <SeverityBadge severity={severity} />
        <span className="inv-row__progress-label">
          <span className="tabular">{progress}%</span> triaged
        </span>
      </div>

      <dl className="inv-row__stats">
        <div className="inv-row__stat">
          <dt>Evidence</dt>
          <dd className="tabular">
            {evidence.images + evidence.logSets + evidence.captures}
          </dd>
        </div>
        <div className="inv-row__stat">
          <dt>Artifacts</dt>
          <dd className="tabular">{formatCount(artifacts, 'compact')}</dd>
        </div>
        <div className="inv-row__stat inv-row__stat--critical">
          <dt>Critical</dt>
          <dd className="tabular">{criticalFindings}</dd>
        </div>
        <div className="inv-row__stat">
          <dt>IOCs</dt>
          <dd className="tabular">{iocHits}</dd>
        </div>
      </dl>

      <div className="inv-row__tail">
        <span className="inv-row__activity">{lastActivity}</span>
        <Link className="inv-row__open" to={`/cases/${id}`} aria-label={`Open case ${id}`}>
          Open
          <Icon name="chevronRight" size={14} className="inv-row__chevron" />
        </Link>
      </div>
    </article>
  )
}
