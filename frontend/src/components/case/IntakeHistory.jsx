import { useState } from 'react'
import useApi from '../../hooks/useApi.js'

export default function IntakeHistory({ caseId, revision = 0 }) {
  const [offset, setOffset] = useState(0)
  const { data, loading, error } = useApi(`/ingestions?${new URLSearchParams({ ...(caseId ? { case_id: caseId } : {}), limit: 25, offset })}`, revision)
  return <section className="integration-page"><h3>Ingestion history</h3>
    {loading && <p>Loading intake history…</p>}{error && <p role="alert">{error}</p>}
    {data && <>{!data.ingestions.length && <p>No recorded uploads.</p>}
      {data.ingestions.map(i => <details key={i.id}><summary>{i.evidence.original_filename} — {i.kind} — storage: {i.status} {i.disk_scan && `· scan: ${i.disk_scan.scan_status}`} — {i.stored ?? 'unconfirmed'} stored</summary>
        <p>{i.case_id || 'Unlinked intake'} · {new Date(i.created_at).toLocaleString()}</p><p>SHA-256: <code>{i.evidence.sha256}</code></p>
        {i.inference_metadata && <p>Network detector: {i.inference_metadata.detector_type} · {i.inference_metadata.model_id} · threshold {i.inference_metadata.active_threshold} · {i.network_summary?.total_records} flows · {i.network_summary?.classified_attacks} attack/anomaly decisions · {i.network_summary?.classified_benign} benign/normal decisions</p>}
        {i.disk_scan && <div><p>Content scan: {i.disk_scan.scan_status} · {i.disk_scan.regular_files_discovered} regular files · {i.disk_scan.files_scanned} scanned · {i.disk_scan.files_skipped_limits} excluded by limits · {i.disk_scan.files_failed} failed · {i.disk_scan.non_file_entries_ignored} non-file entries ignored</p>
          <p>No match means no configured signature matched; it does not establish safety.</p>
          {i.disk_scan.pe_ml && <p>PE ML: {i.disk_scan.pe_ml.files_classified} classified · {i.disk_scan.pe_ml.malicious} malicious predictions · {i.disk_scan.pe_ml.benign} benign predictions · {i.disk_scan.pe_ml.files_excluded} excluded · {i.disk_scan.pe_ml.classification_errors} errors · {i.disk_scan.pe_ml.model.model_id}</p>}
          {i.disk_scan.warnings.map((w, n) => <p role="status" key={n}>{w}</p>)}</div>}
        <pre>{JSON.stringify(i, null, 2)}</pre>
      </details>)}
      <div><button disabled={!offset} onClick={() => setOffset(v => Math.max(0, v - 25))}>Previous</button>
        <button disabled={offset + 25 >= data.total} onClick={() => setOffset(v => v + 25)}>Next</button></div>
    </>}
  </section>
}
