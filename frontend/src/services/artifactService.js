import * as apiClient from './apiClient.js'

/**
 * Artifact ingestion + retrieval (Requirement #2).
 *
 * Components talk to this service, never to fetch/apiClient directly. Ingest
 * uploads a forensic export (log / registry / pcap / file listing); the backend
 * parses, scores and persists artifacts. fetchArtifacts reads them back with
 * server-side filtering.
 */

/** Supported ingest source kinds, matching the backend parser registry. */
export const INGEST_KINDS = [
  { id: 'evtx', label: 'Windows Event Log (.evtx / XML / CSV / JSON)' },
  { id: 'registry', label: 'Registry (.reg / CSV / JSON)' },
  { id: 'pcap', label: 'Network flows (PCAP / CSV)' },
  { id: 'file', label: 'File listing (CSV / JSON)' },
]

/**
 * Upload and ingest a forensic source file for a case.
 * @param {File} file
 * @param {{ kind?: string, caseId?: string }} [opts]
 */
export function ingestFile(file, opts = {}) {
  const data = {}
  if (opts.kind) data.kind = opts.kind
  if (opts.caseId) data.caseId = opts.caseId
  return apiClient.postFile('/ingest', file, { data })
}

/**
 * Fetch scored artifacts, filtered server-side.
 * @param {{ caseId?: string, type?: string, severity?: string, from?: string,
 *   to?: string, limit?: number }} [filters]
 * @returns {Promise<{ total: number, returned: number, artifacts: object[] }>}
 */
export async function fetchArtifacts(filters = {}) {
  const params = new URLSearchParams()
  if (filters.caseId) params.set('case_id', filters.caseId)
  if (filters.type) params.set('type', filters.type)
  if (filters.severity) params.set('severity', filters.severity)
  if (filters.from) params.set('from', filters.from)
  if (filters.to) params.set('to', filters.to)
  params.set('limit', String(filters.limit ?? 200))

  const qs = params.toString()
  try {
    const data = await apiClient.get(`/artifacts?${qs}`)
    return data ?? { total: 0, returned: 0, artifacts: [] }
  } catch {
    // No mock fallback: an empty artifact set is the honest state when the
    // backend is unreachable or nothing has been ingested yet.
    return { total: 0, returned: 0, artifacts: [] }
  }
}
