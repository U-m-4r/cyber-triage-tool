import { useMemo, useState } from 'react'
import Panel from '../dashboard/Panel.jsx'
import Icon from '../ui/Icon.jsx'
import SeverityBadge from '../ui/SeverityBadge.jsx'
import { formatTimestamp } from '../../utils/format.js'
import './CaseTimeline.css'

const KIND_ICON = {
  finding: 'alert',
  ioc: 'shield',
  ingest: 'evidence',
  note: 'note',
  escalation: 'triage',
}

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
const SEVERITY_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }

/**
 * Timeline tab of the case workspace.
 *
 * Merges the case activity feed and the ranked findings (keyed on each finding's
 * observed time) into one chronological view. Interactive: the investigator can
 * filter by severity and by source, flip the ordering, and click any event to
 * expand its detail. Markers on the vertical rail carry severity by colour and
 * nothing else, so a red dot always means "more serious", never "clickable".
 *
 * @param {{ caseRecord: import('../../data/mockCases.js').CaseRecord }} props
 */
export default function CaseTimeline({ caseRecord }) {
  const [severityFilter, setSeverityFilter] = useState('ALL')
  const [typeFilter, setTypeFilter] = useState('ALL')
  const [newestFirst, setNewestFirst] = useState(true)
  const [openId, setOpenId] = useState(null)

  const events = useMemo(() => {
    const activity = Array.isArray(caseRecord?.activity) ? caseRecord.activity : []
    const findings = Array.isArray(caseRecord?.findings) ? caseRecord.findings : []

    const fromActivity = activity.map((event) => ({
      id: event.id,
      origin: 'activity',
      at: event.at,
      severity: event.severity ?? 'INFO',
      kind: event.kind ?? 'note',
      title: event.message,
      actor: event.actor,
      relative: event.relative,
    }))

    const fromFindings = findings.map((finding) => ({
      id: finding.id,
      origin: 'finding',
      at: finding.observedAt,
      severity: finding.severity ?? 'INFO',
      kind: 'finding',
      title: finding.title,
      host: finding.host,
      sourcePath: finding.source,
      rationale: finding.rationale,
      technique: finding.technique,
      riskScore: finding.riskScore,
    }))

    return [...fromActivity, ...fromFindings].filter((e) => e.at)
  }, [caseRecord])

  const presentSeverities = useMemo(() => {
    const set = new Set(events.map((e) => e.severity))
    return SEVERITY_ORDER.filter((s) => set.has(s))
  }, [events])

  const visible = useMemo(() => {
    const filtered = events.filter(
      (e) =>
        (severityFilter === 'ALL' || e.severity === severityFilter) &&
        (typeFilter === 'ALL' || e.origin === typeFilter),
    )
    filtered.sort((a, b) => {
      const diff = new Date(a.at).getTime() - new Date(b.at).getTime()
      if (diff !== 0) return newestFirst ? -diff : diff
      return (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9)
    })
    return filtered
  }, [events, severityFilter, typeFilter, newestFirst])

  if (events.length === 0) {
    return (
      <div className="case-timeline">
        <Panel title="Timeline" subtitle="Chronological event view">
          <div className="case-timeline__empty">
            <Icon name="timeline" size={16} className="case-timeline__empty-icon" />
            <p className="case-timeline__empty-copy">
              No dated events exist for this case yet. Activity and ranked findings appear on the
              timeline as they are recorded.
            </p>
          </div>
        </Panel>
      </div>
    )
  }

  return (
    <div className="case-timeline">
      <Panel
        className="case-timeline__panel"
        title="Timeline"
        subtitle={`${events.length} events · ${caseRecord?.findings?.length ?? 0} findings merged with activity`}
        action={
          <button
            type="button"
            className="case-timeline__order"
            onClick={() => setNewestFirst((v) => !v)}
            aria-label="Toggle chronological order"
          >
            <Icon name="clock" size={12} />
            {newestFirst ? 'Newest first' : 'Oldest first'}
          </button>
        }
      >
        <div className="case-timeline__controls">
          <div className="case-timeline__filter-group" role="group" aria-label="Filter by severity">
            <span className="case-timeline__filter-label">Severity</span>
            <FilterChip active={severityFilter === 'ALL'} onClick={() => setSeverityFilter('ALL')}>
              All
            </FilterChip>
            {presentSeverities.map((sev) => (
              <FilterChip
                key={sev}
                active={severityFilter === sev}
                severity={sev}
                onClick={() => setSeverityFilter(sev)}
              >
                {sev}
              </FilterChip>
            ))}
          </div>

          <div className="case-timeline__filter-group" role="group" aria-label="Filter by source">
            <span className="case-timeline__filter-label">Source</span>
            <FilterChip active={typeFilter === 'ALL'} onClick={() => setTypeFilter('ALL')}>
              All
            </FilterChip>
            <FilterChip active={typeFilter === 'finding'} onClick={() => setTypeFilter('finding')}>
              Findings
            </FilterChip>
            <FilterChip active={typeFilter === 'activity'} onClick={() => setTypeFilter('activity')}>
              Activity
            </FilterChip>
          </div>
        </div>

        {visible.length === 0 ? (
          <p className="case-timeline__no-match">No events match the current filters.</p>
        ) : (
          <ol className="case-timeline__rail">
            {visible.map((event) => {
              const open = openId === event.id
              const sevKey = String(event.severity).toLowerCase()
              return (
                <li className="tl-event" key={`${event.origin}-${event.id}`}>
                  <span className={`tl-event__marker tl-event__marker--${sevKey}`} aria-hidden="true" />
                  <button
                    type="button"
                    className={`tl-event__card${open ? ' tl-event__card--open' : ''}`}
                    onClick={() => setOpenId(open ? null : event.id)}
                    aria-expanded={open}
                  >
                    <div className="tl-event__head">
                      <span className="tl-event__icon">
                        <Icon name={KIND_ICON[event.kind] ?? 'clock'} size={13} />
                      </span>
                      <time className="tl-event__time tabular" dateTime={event.at}>
                        {formatTimestamp(event.at)}
                      </time>
                      <SeverityBadge severity={event.severity} size="sm" />
                      <span className="tl-event__origin">
                        {event.origin === 'finding' ? 'Finding' : 'Activity'}
                      </span>
                    </div>
                    <p className="tl-event__title">{event.title}</p>

                    {open && (
                      <div className="tl-event__detail">
                        {event.origin === 'finding' ? (
                          <>
                            {event.rationale && <p className="tl-event__rationale">{event.rationale}</p>}
                            <div className="tl-event__meta">
                              {event.id && <span className="mono">{event.id}</span>}
                              {event.host && (
                                <span className="tl-event__meta-item">
                                  <Icon name="host" size={11} />
                                  <span className="mono">{event.host}</span>
                                </span>
                              )}
                              {event.technique && (
                                <span className="mono">
                                  {event.technique.id} · {event.technique.name}
                                </span>
                              )}
                              {typeof event.riskScore === 'number' && (
                                <span className="tabular">Risk {event.riskScore}</span>
                              )}
                            </div>
                            {event.sourcePath && (
                              <p className="tl-event__source mono" title={event.sourcePath}>
                                {event.sourcePath}
                              </p>
                            )}
                          </>
                        ) : (
                          <div className="tl-event__meta">
                            {event.actor && <span>By {event.actor}</span>}
                            {event.relative && <span className="tl-event__meta-item">{event.relative}</span>}
                          </div>
                        )}
                      </div>
                    )}
                  </button>
                </li>
              )
            })}
          </ol>
        )}
      </Panel>
    </div>
  )
}

function FilterChip({ active, severity, onClick, children }) {
  const sevClass = severity ? ` case-timeline__chip--sev-${severity.toLowerCase()}` : ''
  return (
    <button
      type="button"
      className={`case-timeline__chip${active ? ' case-timeline__chip--active' : ''}${sevClass}`}
      onClick={onClick}
      aria-pressed={active}
    >
      {children}
    </button>
  )
}
