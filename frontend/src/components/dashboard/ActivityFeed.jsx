import Icon from '../ui/Icon.jsx'
import './ActivityFeed.css'

const KIND_ICON = {
  finding: 'alert',
  ioc: 'shield',
  ingest: 'evidence',
  note: 'note',
  escalation: 'triage',
}

/**
 * Recent forensic events across all open cases.
 *
 * @param {{ events: Array<object> }} props
 */
export default function ActivityFeed({ events }) {
  return (
    <ul className="activity-feed">
      {events.map((event) => (
        <li key={event.id} className="activity">
          <span
            className={`activity__icon activity__icon--${String(event.severity).toLowerCase()}`}
          >
            <Icon name={KIND_ICON[event.kind] ?? 'clock'} size={13} />
          </span>

          <div className="activity__body">
            <p className="activity__message">{event.message}</p>
            <div className="activity__meta">
              <span className="activity__case mono">{event.caseId}</span>
              <span className="activity__dot" aria-hidden="true">
                ·
              </span>
              <span className="activity__actor">{event.actor}</span>
            </div>
          </div>

          <time className="activity__time" dateTime={event.at}>
            {event.relative}
          </time>
        </li>
      ))}
    </ul>
  )
}
