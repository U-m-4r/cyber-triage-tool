import ThreatAssessment from './ThreatAssessment.jsx'
import PriorityFindings from './PriorityFindings.jsx'
import RecommendedAction from './RecommendedAction.jsx'

export default function CaseAnalysis({ caseRecord }) {
  return <div className="integration-page">
    <h2>Analysis & triage</h2>
    <p>Results are generated when you upload in Evidence. Network flows use the trained anomaly model; files, logs and registry records use their evidence-specific rules.</p>
    <ThreatAssessment assessment={caseRecord.assessment} threatScore={caseRecord.threatScore} severity={caseRecord.severity} status={caseRecord.status} />
    <PriorityFindings findings={caseRecord.findings} status={caseRecord.status} />
    <RecommendedAction recommendation={caseRecord.recommendation} />
  </div>
}
