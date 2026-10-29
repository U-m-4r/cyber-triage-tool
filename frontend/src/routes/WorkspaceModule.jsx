import { useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import useApi from '../hooks/useApi.js'
import ActivityFeed from '../components/dashboard/ActivityFeed.jsx'
import CaseArtifacts from '../components/case/CaseArtifacts.jsx'
import IntakeHistory from '../components/case/IntakeHistory.jsx'
import './Integration.css'

const MODULES = {
  '/evidence': ['Evidence', 'evidence', 'Open an investigation to upload evidence and inspect its chain of custody.'],
  '/analysis': ['Analysis', 'analysis', 'Review stored artifacts below. Upload evidence in an investigation’s Evidence tab; review its scoring in Analysis & triage.'],
  '/ai-triage': ['Triage', 'ai-triage', 'Open an investigation to review ranked artifacts and scoring rationale.'],
  '/timeline': ['Timeline', 'timeline', 'Recorded workspace activity. Open a case for its findings and event timeline.'],
  '/ioc-graph': ['Relationships', 'ioc-graph', 'Relationships are derived from recorded findings; they are not confirmed compromise classifications.'],
  '/reports': ['Reports', 'reports', 'Open an investigation to export its current PDF report and view generation history.'],
}

export default function WorkspaceModule() {
  const { pathname } = useLocation()
  const [title, tab, description] = MODULES[pathname]
  const [search, setSearch] = useState('')
  const [offset, setOffset] = useState(0)
  const [revision, refresh] = useState(0)
  const cases = useApi(`/cases?${new URLSearchParams({ q: search, limit: 25, offset })}`, revision)
  const model = useApi(tab === 'analysis' || tab === 'ai-triage' ? '/model' : null, revision)
  return <div className="page integration-page">
    <h1>{title}</h1><p>{description}</p>
    <div className="integration-controls"><input aria-label="Find investigation" placeholder="Find investigation" value={search} onChange={e => { setSearch(e.target.value); setOffset(0) }} />
      <button onClick={() => refresh(v => v + 1)}>Refresh</button><Link to="/cases">Create investigation</Link></div>
    {cases.loading && <p>Loading cases…</p>}{cases.error && <p role="alert">{cases.error}</p>}
    {cases.data && <><ul>{cases.data.cases.map(c => <li key={c.id}><Link to={`/cases/${encodeURIComponent(c.id)}?tab=${tab}`}>{c.id} — {c.title}</Link></li>)}</ul>
      {!cases.data.cases.length && <p>No matching investigations.</p>}
      <div><button disabled={!offset} onClick={() => setOffset(v => Math.max(0, v - 25))}>Previous cases</button><button disabled={offset + 25 >= cases.data.total} onClick={() => setOffset(v => v + 25)}>Next cases</button></div></>}
    {(tab === 'analysis' || tab === 'ai-triage') && <section><h2>Network model</h2>
      <p>{model.loading ? 'Checking model…' : model.error || (model.data?.available ? 'Approved baseline available.' : model.data?.message || 'Unavailable.')}</p>
      {model.data?.baseline && <details><summary>Provenance</summary><pre>{JSON.stringify(model.data.baseline, null, 2)}</pre></details>}
      <CaseArtifacts key={revision} />
    </section>}
    {tab === 'evidence' && <IntakeHistory revision={revision} />}
    {tab === 'timeline' && <WorkspaceActivity revision={revision} />}
  </div>
}

function WorkspaceActivity({ revision }) {
  const [offset, setOffset] = useState(0)
  const { data, error, loading } = useApi(`/activity?limit=25&offset=${offset}`, revision)
  return <section><h2>Workspace activity</h2>{loading && <p>Loading…</p>}{error && <p role="alert">{error}</p>}
    {data && <><ActivityFeed events={data.events} /><button disabled={!offset} onClick={() => setOffset(v => Math.max(0, v - 25))}>Previous events</button>
      <button disabled={offset + 25 >= data.total} onClick={() => setOffset(v => v + 25)}>Next events</button></>}
  </section>
}
