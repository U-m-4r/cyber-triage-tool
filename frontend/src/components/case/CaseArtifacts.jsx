import { useState } from 'react'
import SeverityBadge from '../ui/SeverityBadge.jsx'
import useApi from '../../hooks/useApi.js'
import './CaseArtifacts.css'

const TYPE_OPTIONS = [
  { id: '', label: 'All types' },
  { id: 'network', label: 'Network' },
  { id: 'system_log', label: 'System log' },
  { id: 'file', label: 'File' },
  { id: 'registry', label: 'Registry' },
]

const SEVERITY_OPTIONS = [
  { id: '', label: 'All severities' },
  { id: 'CRITICAL', label: 'Critical' },
  { id: 'HIGH', label: 'High' },
  { id: 'MEDIUM', label: 'Medium' },
  { id: 'LOW', label: 'Low' },
]

// Per-type "detail" so one table can render heterogeneous artifacts honestly:
// each type surfaces the field an investigator scans first.
function artifactDetail(a) {
  switch (a.artifact_type) {
    case 'registry':
      return a.RegistryKey || '—'
    case 'file':
      return a.FilePath || a.FileName || '—'
    case 'system_log':
      return `EventID ${a.EventID ?? '—'} · ${a.FailedLogins ?? '—'} failed logins`
    case 'network':
      return `${a['Flow Packets/s'] ?? '—'} pkt/s · ${a['Flow Bytes/s'] ?? '—'} B/s`
    default:
      return '—'
  }
}

/**
 * Artifacts tab — filterable explorer over scored, ingested artifacts
 * (Requirement #2). Also hosts the ingest control so an investigator can pull a
 * log / registry / pcap / file listing into the case from here.
 */
export default function CaseArtifacts({ caseRecord, onChange }) {
  const [type, setType] = useState('')
  const [severity, setSeverity] = useState('')
  const [query, setQuery] = useState('')
  const [offset, setOffset] = useState(0)
  const [revision, refresh] = useState(0)
  const params = new URLSearchParams({ type, severity, q: query, offset, limit: 25,
    ...(caseRecord?.id ? { case_id: caseRecord.id } : {}) })
  const { data, loading, error } = useApi(`/artifacts?${params}`, revision)
  function filter(setter, value) { setter(value); setOffset(0) }
  return <div className="case-artifacts">
    <p>Model predictions mark statistical anomalies, not attack types. Negative decision scores are anomalous.
      Risk combines batch-relative anomaly rankings and forensic rules; it is not a probability of compromise.</p>
    {caseRecord && <p>Upload files in the Evidence tab. This explorer shows the resulting stored artifacts.</p>}
    <div className="integration-controls"><input aria-label="Search artifacts" placeholder="Search source, path, rules" value={query} onChange={e => filter(setQuery, e.target.value)} />
      <button onClick={() => refresh(v => v + 1)}>Refresh artifacts</button></div>
    {error && <p role="alert">Artifacts unavailable: {error}</p>}
    {!error && <ArtifactTable rows={data?.artifacts || []} total={data?.total || 0} loading={loading}
      type={type} setType={v => filter(setType, v)} severity={severity} setSeverity={v => filter(setSeverity, v)} />}
    <div className="integration-controls"><button disabled={!offset || loading} onClick={() => setOffset(v => Math.max(0, v - 25))}>Previous</button>
      <span>Page {Math.floor(offset / 25) + 1}</span><button disabled={loading || !data || offset + 25 >= data.total} onClick={() => setOffset(v => v + 25)}>Next</button></div>
  </div>
}

function ArtifactTable({ rows, total, loading, type, setType, severity, setSeverity }) {
  return (
    <section className="artifacts-explorer">
      <div className="artifacts-toolbar">
        <select
          className="artifacts-select"
          value={type}
          onChange={(e) => setType(e.target.value)}
          aria-label="Filter by type"
        >
          {TYPE_OPTIONS.map((o) => (
            <option key={o.id} value={o.id}>{o.label}</option>
          ))}
        </select>
        <select
          className="artifacts-select"
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          aria-label="Filter by severity"
        >
          {SEVERITY_OPTIONS.map((o) => (
            <option key={o.id} value={o.id}>{o.label}</option>
          ))}
        </select>
        <span className="artifacts-count">
          {loading ? 'Loading…' : `${rows.length} shown of ${total}`}
        </span>
      </div>

      {!loading && rows.length === 0 ? (
        <p className="artifacts-empty">
          No artifacts match. Ingest evidence above, or clear the filters.
        </p>
      ) : (
        <div className="artifacts-table-wrap">
          <table className="artifacts-table">
            <thead>
              <tr>
                <th>Priority</th>
                <th>Risk</th>
                <th>Model prediction</th>
                <th>Type</th>
                <th>Detail</th>
                <th>Matched rules</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((a) => (
                <tr key={a.artifact_id}>
                  <td><SeverityBadge severity={a.priority} size="sm" /></td>
                  <td className="artifacts-risk">{a.risk_score}</td>
                  <td><span>{a.prediction || 'Rules only'}</span>
                    {a.decision_score != null && <small> · decision {Number(a.decision_score).toFixed(5)}</small>}
                    {a.model_id && <div className="mono">{a.model_id}</div>}</td>
                  <td className="artifacts-type">{a.artifact_type}</td>
                  <td className="artifacts-detail mono">{artifactDetail(a)}</td>
                  <td className="artifacts-rules">{a.matched_rules}</td>
                  <td className="artifacts-source mono">{a.source_file}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

