import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import CaseHeader from '../components/case/CaseHeader.jsx'
import CaseTabs from '../components/case/CaseTabs.jsx'
import CaseOverview from '../components/case/CaseOverview.jsx'
import Icon from '../components/ui/Icon.jsx'
import { CASE_TABS } from '../data/navigation.js'
import { fetchCase } from '../services/caseService.js'
import '../styles/page.css'
import './CaseWorkspacePage.css'

/**
 * Case workspace — /cases/:caseId
 *
 * Reached by opening a case from the dashboard's Active Investigations list. The
 * tab is local state rather than a nested route because only Overview exists; when
 * the other sections are built they become child routes so a specific tab can be
 * linked and shared.
 */
export default function CaseWorkspacePage() {
  const { caseId } = useParams()
  const [caseRecord, setCaseRecord] = useState(null)
  const [state, setState] = useState('loading') // 'loading' | 'ready' | 'missing'
  const [activeTab, setActiveTab] = useState('overview')

  useEffect(() => {
    let cancelled = false
    setState('loading')

    fetchCase(caseId).then((record) => {
      if (cancelled) return
      setCaseRecord(record)
      setState(record ? 'ready' : 'missing')
    })

    return () => {
      cancelled = true
    }
  }, [caseId])

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
            Only the sample cases on the dashboard exist in this build. Case records come from local
            fixtures, so nothing outside that set can be opened yet.
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

      <CaseTabs activeTab={activeTab} onSelect={setActiveTab} />

      {activeTab === 'overview' ? (
        <CaseOverview caseRecord={caseRecord} />
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
