import { useEffect, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import CaseEditor from '../components/case/CaseEditor.jsx'
import IntakePanel from '../components/case/IntakePanel.jsx'
import IntakeHistory from '../components/case/IntakeHistory.jsx'
import '../routes/Integration.css'
import CaseHeader from '../components/case/CaseHeader.jsx'
import CaseTabs from '../components/case/CaseTabs.jsx'
import CaseOverview from '../components/case/CaseOverview.jsx'
import CaseReports from '../components/case/CaseReports.jsx'
import CaseAnalysis from '../components/case/CaseAnalysis.jsx'
import CaseArtifacts from '../components/case/CaseArtifacts.jsx'
import CaseEvidence from '../components/case/CaseEvidence.jsx'
import CaseTimeline from '../components/case/CaseTimeline.jsx'
import CaseIoc from '../components/case/CaseIoc.jsx'
import Icon from '../components/ui/Icon.jsx'
import { CASE_TABS } from '../data/navigation.js'
import { fetchCase } from '../services/caseService.js'
import '../styles/page.css'
import './CaseWorkspacePage.css'

/** Case workspace: Evidence owns intake; other tabs read its persisted results. */
export default function CaseWorkspacePage() {
  const { caseId } = useParams()
  return <CaseWorkspace key={caseId} />
}

function CaseWorkspace() {
  const { caseId } = useParams()
  const [caseRecord, setCaseRecord] = useState(null)
  const [state, setState] = useState('loading') // 'loading' | 'ready' | 'missing'
  const [params, setParams] = useSearchParams()
  const requestedTab = params.get('tab') === 'ai-triage' ? 'analysis' : params.get('tab') || 'overview'
  const activeTab = CASE_TABS.some(tab => tab.id === requestedTab && tab.available)
    ? requestedTab
    : 'overview'
  const setActiveTab = tab => setParams({ tab })
  const reload = async () => { const record = await fetchCase(caseId); setCaseRecord(record); setState(record ? 'ready' : 'missing') }
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false
    setState('loading')
    setError(null)

    fetchCase(caseId).then((record) => {
      if (cancelled) return
      setCaseRecord(record)
      setState(record ? 'ready' : 'missing')
    }).catch((err) => {
      if (!cancelled) { setError(err.message); setState('error') }
    })

    return () => {
      cancelled = true
    }
  }, [caseId])

  if (state === 'error') {
    return <div className="page" role="alert"><h1>Case unavailable</h1><p>{error}</p><Link to="/dashboard">Back to Dashboard</Link></div>
  }

  if (state === 'loading') {
    return (
      <div className="page case-workspace case-workspace--loading" role="status">
        <span className="case-workspace__loading-text">Loading case {caseId}…</span>
      </div>
    )
  }

  // Unknown case IDs are a normal outcome once URLs get shared around, so this is
  // a dead end with a way out rather than an error screen.
  if (state === 'missing') {
    return (
      <div className="page case-workspace">
        <div className="case-missing">
          <span className="case-missing__icon">
            <Icon name="search" size={20} />
          </span>
          <p className="case-missing__title">
            No case matches <span className="mono">{caseId}</span>
          </p>
          <p className="case-missing__copy">
            Check the case ID or return to the dashboard to select an existing investigation.
          </p>
          <Link className="case-missing__back" to="/dashboard">
            <Icon name="chevronRight" size={13} className="case-missing__back-icon" />
            Back to Dashboard
          </Link>
        </div>
      </div>
    )
  }

  const activeTabMeta = CASE_TABS.find((tab) => tab.id === activeTab)

  return (
    <div className="page case-workspace">
      <CaseHeader caseRecord={caseRecord} />
      <CaseEditor caseRecord={caseRecord} onChange={reload} />

      <p className="case-workspace__workflow">Upload once in Evidence. Review parsed records in Artifacts, scoring in Analysis &amp; triage, events in Timeline, and connections in Relationships. Generate the current report in Reports.</p>
      <CaseTabs activeTab={activeTab} onSelect={setActiveTab} />

      {activeTab === 'overview' ? (
        <CaseOverview caseRecord={caseRecord} />
      ) : activeTab === 'artifacts' ? (
        <CaseArtifacts key={caseId} caseRecord={caseRecord} />
      ) : activeTab === 'evidence' ? (
        <><IntakePanel key={`intake-${caseId}`} caseId={caseId} onComplete={reload} /><CaseEvidence caseRecord={caseRecord} /><IntakeHistory key={`history-${caseId}`} caseId={caseId} revision={caseRecord.lastActivity?.at} /></>
      ) : activeTab === 'timeline' ? (
        <CaseTimeline caseRecord={caseRecord} />
      ) : activeTab === 'ioc-graph' ? (
        <CaseIoc caseRecord={caseRecord} />
      ) : activeTab === 'reports' ? (
        <CaseReports caseRecord={caseRecord} />
      ) : activeTab === 'analysis' ? (
        <CaseAnalysis
          caseRecord={caseRecord}
          onAnalysisComplete={reload}
        />
      ) : (
        // Unreachable while every other tab is disabled, but the workspace should
        // not render a blank panel if one is ever enabled before it is built.
        <div className="case-workspace__unbuilt">
          <p className="case-workspace__unbuilt-title">{activeTabMeta?.label} is not implemented</p>
          <p className="case-workspace__unbuilt-copy">{activeTabMeta?.phase}</p>
        </div>
      )}
    </div>
  )
}
