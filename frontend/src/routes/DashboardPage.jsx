import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import Panel from '../components/dashboard/Panel.jsx'
import StatCard from '../components/dashboard/StatCard.jsx'
import InvestigationRow from '../components/dashboard/InvestigationRow.jsx'
import AiTriagePanel from '../components/dashboard/AiTriagePanel.jsx'
import ActivityFeed from '../components/dashboard/ActivityFeed.jsx'
import Icon from '../components/ui/Icon.jsx'
import {
  fetchActiveInvestigations,
  fetchDashboardMetrics,
  fetchRecentActivity,
  fetchTriageSummary,
} from '../services/dashboardService.js'
import { formatTimestamp } from '../utils/format.js'
import '../styles/page.css'
import './DashboardPage.css'

export default function DashboardPage() {
  const [metrics, setMetrics] = useState([])
  const [investigations, setInvestigations] = useState([])
  const [activity, setActivity] = useState([])
  const [selectedCaseId, setSelectedCaseId] = useState(null)
  const [triage, setTriage] = useState(null)
  const [ready, setReady] = useState(false)

  // Initial load. Everything comes through the service layer, so swapping the
  // mock fixtures for the Flask API later touches only services/.
  useEffect(() => {
    let cancelled = false

    Promise.all([
      fetchDashboardMetrics(),
      fetchActiveInvestigations(),
      fetchRecentActivity(),
    ]).then(([nextMetrics, nextInvestigations, nextActivity]) => {
      if (cancelled) return
      setMetrics(nextMetrics)
      setInvestigations(nextInvestigations)
      setActivity(nextActivity)
      setSelectedCaseId(nextInvestigations[0]?.id ?? null)
      setReady(true)
    })

    return () => {
      cancelled = true
    }
  }, [])

  // Triage summary follows the selected case.
  useEffect(() => {
    if (!selectedCaseId) return undefined
    let cancelled = false

    fetchTriageSummary(selectedCaseId).then((summary) => {
      if (!cancelled) setTriage(summary)
    })

    return () => {
      cancelled = true
    }
  }, [selectedCaseId])

  const selected = useMemo(
    () => investigations.find((item) => item.id === selectedCaseId) ?? null,
    [investigations, selectedCaseId],
  )

  if (!ready) {
    return (
      <div className="page dashboard dashboard--loading" role="status">
        <span className="dashboard__loading-text">Loading investigation overview…</span>
      </div>
    )
  }

  return (
    <div className="page dashboard">
      <header className="page-head">
        <div className="page-head__titles">
          <h1 className="page-head__title">Investigation overview</h1>
          <p className="page-head__subtitle">
            {investigations.length} open cases assigned to this workspace
            {triage && (
              <>
                {' · '}
                <span className="page-head__sync">
                  last pipeline sync {formatTimestamp(triage.scoredAt)}
                </span>
              </>
            )}
          </p>
        </div>

        <span className="page-head__notice">
          <Icon name="alert" size={12} strokeWidth={1.7} />
          Sample data — no evidence has been parsed
        </span>
      </header>

      <section className="metric-grid" aria-label="Case metrics">
        {metrics.map((metric) => (
          <StatCard key={metric.id} metric={metric} />
        ))}
      </section>

      <div className="dashboard__grid">
        <Panel
          className="dashboard__cases"
          title="Active Investigations"
          subtitle="Select a case to load its triage summary"
          action={
            <Link className="panel-link" to="/cases">
              All cases
              <Icon name="chevronRight" size={13} />
            </Link>
          }
          flush
        >
          {investigations.map((investigation) => (
            <InvestigationRow
              key={investigation.id}
              investigation={investigation}
              selected={investigation.id === selectedCaseId}
              onSelect={setSelectedCaseId}
            />
          ))}
        </Panel>

        <div className="dashboard__triage">
          <AiTriagePanel triage={triage} investigation={selected} />
        </div>

        <Panel
          className="dashboard__activity"
          title="Recent Activity"
          subtitle="Across all open cases"
          action={
            <Link className="panel-link" to="/timeline">
              Full timeline
              <Icon name="chevronRight" size={13} />
            </Link>
          }
          flush
        >
          <ActivityFeed events={activity} />
        </Panel>
      </div>
    </div>
  )
}
