/**
 * Dashboard data source.
 *
 * Phase 1 resolves the static mock fixtures. When the backend grows case
 * persistence and artifact retrieval, replace each function body with the
 * corresponding call from `triageService` — the component contracts do not
 * change, because they already consume these promises.
 */

import {
  ACTIVE_INVESTIGATIONS,
  AI_TRIAGE,
  DASHBOARD_METRICS,
  RECENT_ACTIVITY,
  TRIAGE_BY_CASE,
} from '../data/mockDashboard.js'

export function fetchDashboardMetrics() {
  return Promise.resolve(DASHBOARD_METRICS)
}

export function fetchActiveInvestigations() {
  return Promise.resolve(ACTIVE_INVESTIGATIONS)
}

/**
 * Mock triage summary. These findings are authored UI fixtures — no model
 * produced them. The real version will be derived from /api/analyze output
 * plus the rule hits already emitted by ml/risk_scorer.py.
 *
 * Resolves `null` for cases the pipeline has not scored yet.
 */
export function fetchTriageSummary(caseId) {
  if (!caseId) return Promise.resolve(AI_TRIAGE)
  return Promise.resolve(TRIAGE_BY_CASE[caseId] ?? null)
}

export function fetchRecentActivity() {
  return Promise.resolve(RECENT_ACTIVITY)
}
