import Panel from '../dashboard/Panel.jsx'
import './InvestigationSummary.css'

/**
 * Narrative account of the case plus the fixed facts an examiner cites.
 *
 * The narrative is written prose, not generated text — it is the examiner's own
 * reconstruction of what happened, which is why it reads as a sequence of
 * observations rather than a list of alerts.
 *
 * @param {{ summary: object, status: string, progress: number }} props
 */
export default function InvestigationSummary({ summary, status, progress }) {
  return (
    <Panel
      className="case-summary"
      title="Investigation Summary"
      subtitle={`Pipeline state ${status} · ${progress}% of collected artifacts triaged`}
    >
      <p className="case-summary__narrative">{summary.narrative}</p>

      <dl className="case-summary__facts">
        {summary.facts.map((fact) => (
          <div className="case-summary__fact" key={fact.label}>
            <dt>{fact.label}</dt>
            <dd className={fact.mono ? 'mono' : 'tabular'}>{fact.value}</dd>
          </div>
        ))}
      </dl>
    </Panel>
  )
}
