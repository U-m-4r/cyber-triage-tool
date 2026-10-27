import IntakePanel from './IntakePanel.jsx'
import IntakeHistory from './IntakeHistory.jsx'
export default function CaseAnalysis({ caseRecord, onAnalysisComplete }) {
  return <><IntakePanel caseId={caseRecord.id} networkOnly onComplete={onAnalysisComplete} /><IntakeHistory caseId={caseRecord.id} revision={caseRecord.lastActivity?.at} /></>
}
