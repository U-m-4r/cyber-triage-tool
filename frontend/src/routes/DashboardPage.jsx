import { useState } from 'react'
import { Link } from 'react-router-dom'
import Panel from '../components/dashboard/Panel.jsx'
import StatCard from '../components/dashboard/StatCard.jsx'
import InvestigationRow from '../components/dashboard/InvestigationRow.jsx'
import AiTriagePanel from '../components/dashboard/AiTriagePanel.jsx'
import ActivityFeed from '../components/dashboard/ActivityFeed.jsx'
import Icon from '../components/ui/Icon.jsx'
import useApi from '../hooks/useApi.js'
import { formatTimestamp } from '../utils/format.js'
import '../styles/page.css'
import './DashboardPage.css'

export default function DashboardPage() {
  const [revision, refresh] = useState(0)
  const [selectedCaseId, setSelectedCaseId] = useState(null)
  const { data, loading, error } = useApi('/dashboard', revision)
  const metrics = data?.metrics || []
  const investigations = data?.investigations || []
  const activity = data?.recentActivity || []
  const selected = investigations.find(c => c.id === selectedCaseId) || investigations[0] || null
  const triage = data?.triageSummaries?.[selected?.id] || null
  const ready = !loading

  if (error) {
    return <div className="page" role="alert"><h1>Investigation overview unavailable</h1><p>{error}. Check MongoDB and Flask, then retry.</p><button onClick={() => window.location.reload()}>Retry</button></div>
  }

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
            Up to 10 open investigations, ranked by risk
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


      </header>

      <button onClick={() => refresh(v => v + 1)}>Refresh dashboard</button>
      <section className="metric-grid" aria-label="Case metrics">
        {metrics.map((metric) => (
          <StatCard key={metric.id} metric={metric} />
        ))}
      </section>

      <div className="distribution">
        {[['Severity distribution', data?.severityDistribution], ['Artifact categories', data?.artifactTypes]].map(([label, values]) => <section key={label}>
          <h2>{label}</h2>{!values?.length ? <p>No scored artifacts.</p> : values.map(b => <label key={b._id}>{b._id}: {b.count}
            <meter min="0" max={values.reduce((sum, v) => sum + v.count, 0)} value={b.count} /></label>)}
        </section>)}
      </div>
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
          {!investigations.length && <p>No open investigations. Create one from Cases.</p>}
          {investigations.map((investigation) => (
            <InvestigationRow
              key={investigation.id}
              investigation={investigation}
              selected={investigation.id === selected?.id}
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
