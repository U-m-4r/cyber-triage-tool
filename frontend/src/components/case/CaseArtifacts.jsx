import { useCallback, useEffect, useState } from 'react'
import SeverityBadge from '../ui/SeverityBadge.jsx'
import {
  fetchArtifacts,
  ingestFile,
  INGEST_KINDS,
} from '../../services/artifactService.js'
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
      return `EventID ${a.EventID ?? '—'} · ${a.FailedLogins ?? 0} failed logins`
    case 'network':
      return `${a['Flow Packets/s'] ?? 0} pkt/s · ${a['Flow Bytes/s'] ?? 0} B/s`
    default:
      return '—'
  }
}

/**
 * Artifacts tab — filterable explorer over scored, ingested artifacts
 * (Requirement #2). Also hosts the ingest control so an investigator can pull a
 * log / registry / pcap / file listing into the case from here.
 */
export default function CaseArtifacts({ caseRecord }) {
  const caseId = caseRecord?.id
  const [type, setType] = useState('')
  const [severity, setSeverity] = useState('')
  const [rows, setRows] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)

  const [kind, setKind] = useState(INGEST_KINDS[0].id)
  const [file, setFile] = useState(null)
  const [ingesting, setIngesting] = useState(false)
  const [notice, setNotice] = useState(null)

  const load = useCallback(() => {
    setLoading(true)
    fetchArtifacts({ caseId, type, severity }).then((data) => {
      setRows(data.artifacts)
      setTotal(data.total)
      setLoading(false)
    })
  }, [caseId, type, severity])

  useEffect(() => {
    load()
  }, [load])

  const handleIngest = async () => {
    if (!file) {
      setNotice({ kind: 'error', text: 'Choose a file to ingest first.' })
      return
    }
    setIngesting(true)
    setNotice(null)
    try {
      const res = await ingestFile(file, { kind, caseId })
      setNotice({
        kind: 'ok',
        text: `Ingested ${res.summary.total_records} artifacts (${res.stored} stored).`,
      })
      setFile(null)
      load()
    } catch (err) {
      setNotice({ kind: 'error', text: err.message || 'Ingestion failed.' })
    } finally {
      setIngesting(false)
    }
  }

  return (
    <div className="case-artifacts">
      <IngestPanel
        kind={kind}
        setKind={setKind}
        file={file}
        setFile={setFile}
        ingesting={ingesting}
        onIngest={handleIngest}
        notice={notice}
      />
      <ArtifactTable
        rows={rows}
        total={total}
        loading={loading}
        type={type}
        setType={setType}
        severity={severity}
        setSeverity={setSeverity}
      />
    </div>
  )
}

function IngestPanel({ kind, setKind, file, setFile, ingesting, onIngest, notice }) {
  return (
    <section className="artifacts-ingest">
      <h3 className="artifacts-ingest__title">Ingest evidence</h3>
      <p className="artifacts-ingest__copy">
        Parse a Windows Event Log, registry export, packet capture, or file listing
        into scored artifacts for this case. Binary formats can be uploaded as their
        exported CSV / XML / JSON form.
      </p>
      <div className="artifacts-ingest__controls">
        <select
          className="artifacts-select"
          value={kind}
          onChange={(e) => setKind(e.target.value)}
          disabled={ingesting}
          aria-label="Source kind"
        >
          {INGEST_KINDS.map((k) => (
            <option key={k.id} value={k.id}>{k.label}</option>
          ))}
        </select>
        <input
          type="file"
          id="artifact-ingest-file"
          className="artifacts-file-input"
          onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          disabled={ingesting}
        />
        <label htmlFor="artifact-ingest-file" className="artifacts-file-label">
          {file ? file.name : 'Choose file'}
        </label>
        <button
          type="button"
          className="artifacts-ingest__btn"
          onClick={onIngest}
          disabled={ingesting || !file}
        >
          {ingesting ? 'Ingesting…' : 'Ingest'}
        </button>
      </div>
      {notice && (
        <p className={`artifacts-notice artifacts-notice--${notice.kind}`}>
          {notice.text}
        </p>
      )}
    </section>
  )
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

