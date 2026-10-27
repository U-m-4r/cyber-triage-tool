import * as api from './apiClient.js'
export async function fetchCase(caseId, options) {
  try { return await api.get(`/cases/${encodeURIComponent(caseId)}`, options) }
  catch (error) { if (error.status === 404) return null; throw error }
}
export function listCases(filters = {}, options) {
  return api.get(`/cases?${new URLSearchParams(filters)}`, options)
}
export function createCase(data) { return api.postJson('/cases', data) }
export function updateCase(id, data) {
  return api.request(`/cases/${encodeURIComponent(id)}`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
  })
}
export function addNote(id, text) { return api.postJson(`/cases/${encodeURIComponent(id)}/notes`, { text }) }
