import { useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import useApi from '../hooks/useApi.js'
import { createCase } from '../services/caseService.js'
import { getInvestigatorLabel } from '../services/authService.js'
import './Integration.css'

export default function CasesPage() {
  const [params, setParams] = useSearchParams()
  const [revision, refresh] = useState(0)
  const [error, setError] = useState(null)
  const [pending, setPending] = useState(false)
  const navigate = useNavigate()
  const offset = Number(params.get('offset')) || 0
  const { data, loading, error: loadError } = useApi(`/cases?${new URLSearchParams({
    q: params.get('q') || '', status: params.get('status') || '', sort: params.get('sort') || 'openedAt', offset, limit: 25,
  })}`, revision)
  function filter(key, value) {
    const next = new URLSearchParams(params); next.set(key, value); next.delete('offset'); setParams(next)
  }
  async function submit(event) {
    event.preventDefault(); setPending(true); setError(null)
    const form = new FormData(event.currentTarget)
    try {
      const record = await createCase({ title: form.get('title'), description: form.get('description'),
        primaryHost: form.get('primaryHost'), examiner: getInvestigatorLabel() })
      navigate(`/cases/${encodeURIComponent(record.id)}`)
    } catch (err) { setError(err.message) } finally { setPending(false) }
  }
  return <div className="page integration-page">
    <h1>Investigations</h1><p>Shared workspace records. Investigator labels identify assignments, not separate user accounts.</p>
    <details><summary>Create investigation</summary>
      <form onSubmit={submit} className="integration-form">
        <label>Title<input name="title" required maxLength={200} /></label>
        <label>Primary host<input name="primaryHost" maxLength={200} /></label>
        <label>Description<textarea name="description" maxLength={4000} /></label>
        <button disabled={pending}>{pending ? 'Creating…' : 'Create case'}</button>
        {error && <p role="alert">{error}</p>}
      </form>
    </details>
    <div className="integration-controls">
      <input aria-label="Search investigations" placeholder="Search ID, title, host, examiner" value={params.get('q') || ''} onChange={e => filter('q', e.target.value)} />
      <select aria-label="Case status" value={params.get('status') || ''} onChange={e => filter('status', e.target.value)}>
        <option value="">All statuses</option>{['INGESTING', 'ANALYZING', 'REVIEW', 'CLOSED'].map(s => <option key={s}>{s}</option>)}
      </select>
      <select aria-label="Sort cases" value={params.get('sort') || 'openedAt'} onChange={e => filter('sort', e.target.value)}>
        <option value="openedAt">Newest</option><option value="threatScore">Highest risk</option><option value="title">Title (Z–A)</option>
      </select><button onClick={() => refresh(v => v + 1)}>Refresh</button>
    </div>
    {loading && <p role="status">Loading investigations…</p>}
    {loadError && <p role="alert">{loadError} Check MongoDB and Flask, then refresh.</p>}
    {data && <><p>{data.total} matching investigations</p>
      {!data.cases.length ? <p>No investigations match. Create a case or change the filters.</p> :
        <table><thead><tr><th>Case</th><th>Title</th><th>Status</th><th>Risk</th><th>Artifacts</th></tr></thead>
          <tbody>{data.cases.map(c => <tr key={c.id}><td><Link to={`/cases/${encodeURIComponent(c.id)}`}>{c.id}</Link></td>
            <td>{c.title}</td><td>{c.status}</td><td>{c.threatScore ?? 'Not scored'}</td><td>{c.counts?.artifacts ?? 0}</td></tr>)}</tbody></table>}
      <button disabled={!offset} onClick={() => { const p = new URLSearchParams(params); p.set('offset', Math.max(0, offset - 25)); setParams(p) }}>Previous</button>
      <button disabled={offset + 25 >= data.total} onClick={() => { const p = new URLSearchParams(params); p.set('offset', offset + 25); setParams(p) }}>Next</button>
    </>}
  </div>
}
