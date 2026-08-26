import Panel from '../dashboard/Panel.jsx'
import ActivityFeed from '../dashboard/ActivityFeed.jsx'
import InvestigationSummary from './InvestigationSummary.jsx'
import ThreatAssessment from './ThreatAssessment.jsx'
import PriorityFindings from './PriorityFindings.jsx'
import RecommendedAction from './RecommendedAction.jsx'
import EvidenceStatus from './EvidenceStatus.jsx'
import './CaseOverview.css'

/**
 * Overview tab of the case workspace.
 *
 * Section order follows how an investigator picks a case back up: what happened,
 * how bad it is, what specifically was found, what to do next, what has changed
 * since, and what evidence any of it rests on. The grid keeps the summary and the
 * assessment side by side because they are read together; the recommendation gets
 * the full width because it is the one thing on screen that asks for a decision.
 *
 * @param {{ caseRecord: import('../../data/mockCases.js').CaseRecord }} props
 */
export default function CaseOverview({ caseRecord }) {
  return (
    <div className="case-overview">
      <div className="case-overview__summary">
        <InvestigationSummary
          summary={caseRecord.summary}
          status={caseRecord.status}
          progress={caseRecord.progress}
        />
      </div>

      <div className="case-overview__assessment">
        <ThreatAssessment
          assessment={caseRecord.assessment}
          threatScore={caseRecord.threatScore}
          severity={caseRecord.severity}
          status={caseRecord.status}
        />
      </div>

      <div className="case-overview__action">
        <RecommendedAction recommendation={caseRecord.recommendation} />
      </div>

      <div className="case-overview__findings">
        <PriorityFindings findings={caseRecord.findings} status={caseRecord.status} />
      </div>

      <div className="case-overview__activity">
        <Panel title="Recent Activity" subtitle="Newest first, this case only" flush>
          <ActivityFeed events={caseRecord.activity} />
        </Panel>
      </div>

      <div className="case-overview__evidence">
        <EvidenceStatus evidence={caseRecord.evidence} />
      </div>
    </div>
  )
}
