import { useState } from 'react'
import useApi from '../../hooks/useApi.js'

export default function IntakeHistory({ caseId, revision = 0 }) {
  const [offset, setOffset] = useState(0)
  const { data, loading, error } = useApi(`/ingestions?${new URLSearchParams({ ...(caseId ? { case_id: caseId } : {}), limit: 25, offset })}`, revision)
  return <section className="integration-page"><h3>Ingestion history</h3>
    {loading && <p>Loading intake history…</p>}{error && <p role="alert">{error}</p>}
    {data && <>{!data.ingestions.length && <p>No recorded uploads.</p>}
      {data.ingestions.map(i => <details key={i.id}><summary>{i.evidence.original_filename} — {i.kind} — {i.status} — {i.stored ?? 'unconfirmed'} stored</summary>
        <p>{i.case_id || 'Unlinked intake'} · {new Date(i.created_at).toLocaleString()}</p><p>SHA-256: <code>{i.evidence.sha256}</code></p>
        <pre>{JSON.stringify(i, null, 2)}</pre>
      </details>)}
      <div><button disabled={!offset} onClick={() => setOffset(v => Math.max(0, v - 25))}>Previous</button>
        <button disabled={offset + 25 >= data.total} onClick={() => setOffset(v => v + 25)}>Next</button></div>
    </>}
  </section>
}
