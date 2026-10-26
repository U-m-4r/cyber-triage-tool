/**
 * Dashboard data source.
 *
 * Live requests propagate failures. Authored fixtures require explicit demo mode.
 */

import * as apiClient from './apiClient.js'
import { frontendConfig } from './config.js'
import {
  ACTIVE_INVESTIGATIONS,
  DASHBOARD_METRICS,
  RECENT_ACTIVITY,
  TRIAGE_BY_CASE,
} from '../data/mockDashboard.js'

let _cachedDashboard = null
let _pendingDashboard = null

async function _fetchDashboard() {
  if (_cachedDashboard) return _cachedDashboard
  if (frontendConfig.demoMode) {
    return { metrics: DASHBOARD_METRICS, investigations: ACTIVE_INVESTIGATIONS,
      triageSummaries: TRIAGE_BY_CASE, recentActivity: RECENT_ACTIVITY, dataMode: 'demo' }
  }
  if (!_pendingDashboard) {
    _pendingDashboard = apiClient.get('/dashboard').then((data) => {
      if (!data || !Array.isArray(data.investigations) || !Array.isArray(data.metrics) || !Array.isArray(data.recentActivity)) {
        throw new Error('The backend returned an invalid dashboard response.')
      }
      _cachedDashboard = data
      return data
    }).finally(() => { _pendingDashboard = null })
  }
  return _pendingDashboard
}

export async function fetchDataMode() {
  return (await _fetchDashboard()).dataMode ?? 'live'
}

export async function fetchDashboardMetrics() {
  const data = await _fetchDashboard()
  return data.metrics
}

export async function fetchActiveInvestigations() {
  const data = await _fetchDashboard()
  return data.investigations
}

/**
 * Triage summary for a case. Returns null for cases the pipeline has not
 * scored yet.
 */
export async function fetchTriageSummary(caseId) {
  const data = await _fetchDashboard()
  const summaries = data.triageSummaries ?? {}

  if (!caseId) {
    return null
  }
  return summaries[caseId] ?? null
}

export async function fetchRecentActivity() {
  const data = await _fetchDashboard()
  return data.recentActivity
}

/**
 * Invalidate the cached dashboard data so the next call refetches from the API.
 */
export function invalidateDashboardCache() {
  _cachedDashboard = null
}
