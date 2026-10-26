import { test, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { readFrontendConfig } from '../src/services/config.js'
import { fetchCase } from '../src/services/caseService.js'
import { fetchArtifacts } from '../src/services/artifactService.js'
import { fetchActiveInvestigations, fetchDashboardMetrics, fetchTriageSummary, invalidateDashboardCache } from '../src/services/dashboardService.js'
import { request } from '../src/services/apiClient.js'
import { generateReport } from '../src/services/triageService.js'

const originalFetch = globalThis.fetch
afterEach(() => {
  globalThis.fetch = originalFetch
  delete globalThis.sessionStorage
  invalidateDashboardCache()
})

test('demo mode requires explicit configuration', () => {
  assert.deepEqual(readFrontendConfig(), { apiBase: '/api', demoMode: false })
  assert.equal(readFrontendConfig({ VITE_DEMO_MODE: 'true' }).demoMode, true)
  assert.throws(() => readFrontendConfig({ VITE_DEMO_MODE: 'yes' }))
  assert.throws(() => readFrontendConfig({ VITE_API_BASE_URL: 'javascript:bad' }))
  assert.throws(() => readFrontendConfig({ VITE_API_BASE_URL: '//unexpected-host' }))
})

test('network failure never substitutes a known sample case', async () => {
  globalThis.fetch = async () => { throw new Error('offline') }
  await assert.rejects(fetchCase('CASE-2026-0147'), { code: 'NETWORK_ERROR' })
})

test('only case 404 maps to a missing case', async () => {
  globalThis.fetch = async () => Response.json({ error: 'Not found' }, { status: 404 })
  assert.equal(await fetchCase('missing'), null)
  globalThis.fetch = async () => Response.json({ error: { code: 'UNAUTHORIZED', message: 'Unauthorized' } }, { status: 401 })
  await assert.rejects(fetchCase('CASE-2026-0147'), { status: 401, code: 'UNAUTHORIZED' })
})

test('database failure cannot look like an empty artifact collection', async () => {
  globalThis.fetch = async () => Response.json({ error: { code: 'DB_UNAVAILABLE', message: 'Database unavailable' } }, { status: 503 })
  await assert.rejects(fetchArtifacts(), { status: 503 })
})

test('dashboard failures propagate and a subsequent retry can recover', async () => {
  globalThis.fetch = async () => { throw new Error('offline') }
  await assert.rejects(fetchActiveInvestigations(), { code: 'NETWORK_ERROR' })
  globalThis.fetch = async () => Response.json({ investigations: [{ id: 'synthetic' }], metrics: [], recentActivity: [] })
  assert.deepEqual(await fetchActiveInvestigations(), [{ id: 'synthetic' }])
  assert.equal(await fetchTriageSummary('CASE-2026-0147'), null)
})

test('concurrent dashboard reads share one request', async () => {
  let count = 0
  globalThis.fetch = async () => {
    count++
    return Response.json({ investigations: [], metrics: [], recentActivity: [] })
  }
  await Promise.all([fetchActiveInvestigations(), fetchDashboardMetrics()])
  assert.equal(count, 1)
})

test('malformed dashboard response is an error', async () => {
  globalThis.fetch = async () => Response.json({ unexpected: true })
  await assert.rejects(fetchDashboardMetrics(), /invalid dashboard/)
})

test('API requests carry the session token without putting it in the URL', async () => {
  globalThis.sessionStorage = { getItem: () => JSON.stringify({ apiToken: 'synthetic-token' }) }
  globalThis.fetch = async (url, options) => {
    assert.equal(url, '/api/cases')
    assert.equal(options.headers.get('Authorization'), 'Bearer synthetic-token')
    return Response.json({ cases: [] })
  }
  assert.deepEqual(await request('/cases'), { cases: [] })
})

test('PDF downloads use the same authenticated request path', async () => {
  globalThis.sessionStorage = { getItem: () => JSON.stringify({ apiToken: 'synthetic-token' }) }
  globalThis.fetch = async (url, options) => {
    assert.equal(url, '/api/report')
    assert.equal(options.headers.get('Authorization'), 'Bearer synthetic-token')
    assert.equal(options.method, 'POST')
    return new Response('%PDF-synthetic', { headers: { 'Content-Type': 'application/pdf' } })
  }
  assert.equal(await (await generateReport('synthetic')).text(), '%PDF-synthetic')
})
