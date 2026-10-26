import { CASES_BY_ID } from '../data/mockCases.js'
import * as apiClient from './apiClient.js'
import { frontendConfig } from './config.js'

/**
 * Case workspace data access.
 *
 * Live requests propagate failures. Authored fixtures require explicit demo mode.
 */

/**
 * @param {string} caseId
 * @returns {Promise<import('../data/mockCases.js').CaseRecord|null>} null when
 *   the case ID is unknown, mirroring a 404.
 */
export async function fetchCase(caseId) {
  if (frontendConfig.demoMode) {
    const record = CASES_BY_ID[caseId]
    return record ? { ...record, dataMode: 'demo' } : null
  }
  try {
    const data = await apiClient.get(`/cases/${encodeURIComponent(caseId)}`)
    return data ?? null
  } catch (error) {
    if (error.status === 404) return null
    throw error
  }
}
