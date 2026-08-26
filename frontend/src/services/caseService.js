import { CASES_BY_ID } from '../data/mockCases.js'

/**
 * Case workspace data access.
 *
 * Reads from the mock fixtures in data/mockCases.js. When the backend grows a
 * case endpoint this becomes:
 *
 *   export function fetchCase(caseId) {
 *     return apiClient.get(`/api/cases/${encodeURIComponent(caseId)}`)
 *   }
 *
 * Components already treat the return value as a promise and handle a null
 * record as "not found", so nothing above this layer has to change.
 */

/**
 * @param {string} caseId
 * @returns {Promise<import('../data/mockCases.js').CaseRecord|null>} null when
 *   the case ID is unknown, mirroring a 404 from the future endpoint.
 */
export function fetchCase(caseId) {
  return Promise.resolve(CASES_BY_ID[caseId] ?? null)
}
