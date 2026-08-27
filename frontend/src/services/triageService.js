/**
 * Backend endpoints exposed by backend/app.py.
 */

import { get, postFile, postJson, BASE_URL } from './apiClient.js'

/** GET /api/health -> { status, service, mongo } */
export function checkHealth(options) {
  return get('/health', options)
}

/**
 * POST /api/analyze (multipart, field `file`)
 *
 * Returns `{ summary: { total_records, critical, high, medium, low },
 *            artifacts: [...], evaluation?: { label_column, metrics } }`
 * where each artifact carries record_id, artifact_type, anomaly_score,
 * rule_score, risk_score, priority and matched_rules.
 */
export function analyzeDataset(file, options = {}) {
  return postFile('/analyze', file, options)
}

/**
 * POST /api/evaluate (multipart, field `file`)
 *
 * Requires a labelled dataset. Returns classification metrics plus the
 * top-k triage metrics used on the Analysis screen in a later phase.
 */
export function evaluateModel(file, options) {
  return postFile('/evaluate', file, options)
}

/**
 * POST /api/report — generate a PDF report for a case.
 *
 * @param {string} caseId
 * @returns {Promise<Blob>} PDF blob for download.
 */
export async function generateReport(caseId) {
  const response = await fetch(`${BASE_URL}/report`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ caseId }),
  })

  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new Error(body?.error?.message ?? `Report generation failed (${response.status})`)
  }

  return response.blob()
}

/**
 * GET /api/report/:caseId — direct download link for a report.
 * Returns the URL string (not a fetch — use as href or window.open target).
 */
export function getReportDownloadUrl(caseId) {
  return `${BASE_URL}/report/${encodeURIComponent(caseId)}`
}

/**
 * GET /api/reports/:caseId — list previously generated reports.
 */
export function listReports(caseId, options) {
  return get(`/reports/${encodeURIComponent(caseId)}`, options)
}

/**
 * Normalises an /api/analyze artifact into the shape the UI components use,
 * so the mock data and the real payload stay interchangeable.
 */
export function toArtifactViewModel(artifact) {
  return {
    id: String(artifact.record_id),
    type: artifact.artifact_type,
    anomalyScore: artifact.anomaly_score,
    ruleScore: artifact.rule_score,
    riskScore: artifact.risk_score,
    severity: artifact.priority,
    matchedRules:
      artifact.matched_rules && artifact.matched_rules !== 'None'
        ? artifact.matched_rules.split(',').map((rule) => rule.trim())
        : [],
  }
}
