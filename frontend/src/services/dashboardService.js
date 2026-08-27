/**
 * Dashboard data source.
 *
 * Tries the backend API first (MongoDB-backed). Falls back to the static mock
 * fixtures when the backend is unreachable so the UI always renders.
 */

import * as apiClient from './apiClient.js'
import {
  ACTIVE_INVESTIGATIONS,
  AI_TRIAGE,
  DASHBOARD_METRICS,
  RECENT_ACTIVITY,
  TRIAGE_BY_CASE,
} from '../data/mockDashboard.js'

let _cachedDashboard = null

async function _fetchDashboard() {
  if (_cachedDashboard) return _cachedDashboard
  try {
    _cachedDashboard = await apiClient.get('/dashboard')
    return _cachedDashboard
  } catch {
    return null
  }
}

export async function fetchDashboardMetrics() {
  const data = await _fetchDashboard()
  return data?.metrics ?? DASHBOARD_METRICS
}

export async function fetchActiveInvestigations() {
  const data = await _fetchDashboard()
  return data?.investigations ?? ACTIVE_INVESTIGATIONS
}

/**
 * Triage summary for a case. Returns null for cases the pipeline has not
 * scored yet.
 */
export async function fetchTriageSummary(caseId) {
  const data = await _fetchDashboard()
  const summaries = data?.triageSummaries ?? TRIAGE_BY_CASE

  if (!caseId) {
    // Default: return first available summary (CASE-2026-0147)
    return summaries['CASE-2026-0147'] ?? AI_TRIAGE
  }
  return summaries[caseId] ?? null
}

export async function fetchRecentActivity() {
  const data = await _fetchDashboard()
  return data?.recentActivity ?? RECENT_ACTIVITY
}

/**
 * Invalidate the cached dashboard data so the next call refetches from the API.
 */
export function invalidateDashboardCache() {
  _cachedDashboard = null
}
