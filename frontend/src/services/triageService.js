/**
 * Backend endpoints exposed by backend/app.py.
 *
 * Phase 1 does not call these from the UI yet — the dashboard renders mock data.
 * They are defined now so the wiring is a matter of swapping the data source in
 * `dashboardService`, not of rewriting components.
 */

import { get, postFile } from './apiClient.js'

/** GET /api/health -> { status, service } */
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
export function analyzeDataset(file, options) {
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
 * POST /api/report
 *
 * Currently a 501 stub on the backend (report generation is a later phase).
 */
export function generateReport(payload, options) {
  return postFile('/report', payload, options)
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
