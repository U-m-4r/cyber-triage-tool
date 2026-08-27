import { CASES_BY_ID } from '../data/mockCases.js'
import * as apiClient from './apiClient.js'

/**
 * Case workspace data access.
 *
 * Tries the backend API first (MongoDB-backed). Falls back to the local mock
 * fixtures when the backend is unreachable or returns an error, so the UI
 * always renders something.
 */

/**
 * @param {string} caseId
 * @returns {Promise<import('../data/mockCases.js').CaseRecord|null>} null when
 *   the case ID is unknown, mirroring a 404.
 */
export async function fetchCase(caseId) {
  try {
    const data = await apiClient.get(`/cases/${encodeURIComponent(caseId)}`)
    return data ?? null
  } catch {
    // Fallback to mock data if API is unavailable
    return CASES_BY_ID[caseId] ?? null
  }
}
