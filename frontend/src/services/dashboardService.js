import { get } from './apiClient.js'
let pending = null
export async function fetchDashboard(options) {
  const data = await get('/dashboard', options)
  if (!data || !Array.isArray(data.investigations) || !Array.isArray(data.metrics) || !Array.isArray(data.recentActivity)) {
    throw new Error('The backend returned an invalid dashboard response.')
  }
  return data
}
function sharedDashboard() {
  if (!pending) pending = fetchDashboard().finally(() => { pending = null })
  return pending
}
export async function fetchDashboardMetrics() { return (await sharedDashboard()).metrics }
export async function fetchActiveInvestigations() { return (await sharedDashboard()).investigations }
export async function fetchRecentActivity() { return (await sharedDashboard()).recentActivity }
export async function fetchDataMode() { return (await sharedDashboard()).dataMode }
export async function fetchTriageSummary(id) { return (await sharedDashboard()).triageSummaries?.[id] ?? null }
export function invalidateDashboardCache() { pending = null }
