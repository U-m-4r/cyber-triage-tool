import { test, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { readFrontendConfig } from '../src/services/config.js'
import { fetchCase } from '../src/services/caseService.js'
import { fetchArtifacts } from '../src/services/artifactService.js'
import { fetchActiveInvestigations, fetchDashboardMetrics, fetchTriageSummary, invalidateDashboardCache } from '../src/services/dashboardService.js'
import { request } from '../src/services/apiClient.js'
import { generateReport } from '../src/services/triageService.js'
import { authenticate, getSession } from '../src/services/authService.js'
import { postFile } from '../src/services/apiClient.js'
import { createCase, updateCase, addNote } from '../src/services/caseService.js'

const originalFetch = globalThis.fetch
afterEach(() => {
  globalThis.fetch = originalFetch
  delete globalThis.sessionStorage
  invalidateDashboardCache()
})

test('API configuration is validated and demo mode cannot enable fixtures', () => {
  assert.deepEqual(readFrontendConfig(), { apiBase: '/api' })
  assert.deepEqual(readFrontendConfig({ VITE_DEMO_MODE: 'true' }), { apiBase: '/api' })
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

function storage() {
  const values = new Map()
  globalThis.sessionStorage = { getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key) }
}

test('sign in validates token before storing a session', async () => {
  storage()
  globalThis.fetch = async (url, options) => {
    assert.equal(url, '/api/session')
    assert.equal(options.headers.Authorization, 'Bearer test-token')
    return Response.json({ error: { message: 'Invalid token' } }, { status: 401 })
  }
  await assert.rejects(authenticate({ investigatorId: 'Unit', apiToken: 'test-token' }), /Invalid token/)
  assert.equal(getSession(), null)
  globalThis.fetch = async () => Response.json({ authMode: 'shared-token' })
  await authenticate({ investigatorId: 'Unit', apiToken: 'test-token' })
  assert.equal(getSession().authMode, 'shared-token')
})

test('unauthorized request clears the browser session', async () => {
  storage()
  sessionStorage.setItem('cyber-triage:session', JSON.stringify({ apiToken: 'old' }))
  globalThis.fetch = async () => Response.json({ error: 'Unauthorized' }, { status: 401 })
  await assert.rejects(request('/cases'), { status: 401 })
  assert.equal(getSession(), null)
})

test('cancellation remains AbortError instead of a false service outage', async () => {
  globalThis.fetch = async () => { throw new DOMException('Aborted', 'AbortError') }
  await assert.rejects(request('/cases'), { name: 'AbortError' })
})

test('multipart carries evidence and case ID without forcing a content type', async () => {
  globalThis.fetch = async (url, options) => {
    assert.equal(url, '/api/ingest')
    assert.equal(options.body.get('caseId'), 'UNIT')
    assert.equal(options.body.get('file').name, 'unit.csv')
    assert.equal(options.headers.has('Content-Type'), false)
    assert.equal(options.data, undefined)
    return Response.json({ stored: 1 })
  }
  await postFile('/ingest', new File(['FileName\na.txt\n'], 'unit.csv'), { data: { caseId: 'UNIT' } })
})

test('case mutations use persisted API routes and propagate failures', async () => {
  const calls = []
  globalThis.fetch = async (url, options) => {
    calls.push([url, options.method, JSON.parse(options.body)])
    return Response.json({ id: 'UNIT' })
  }
  await createCase({ title: 'Unit' })
  await updateCase('UNIT', { status: 'REVIEW' })
  await addNote('UNIT', 'Note')
  assert.deepEqual(calls, [['/api/cases', 'POST', { title: 'Unit' }],
    ['/api/cases/UNIT', 'PUT', { status: 'REVIEW' }], ['/api/cases/UNIT/notes', 'POST', { text: 'Note' }]])
})

test('dashboard refetches after earlier request completes', async () => {
  let value = 0
  globalThis.fetch = async () => Response.json({ investigations: [], metrics: [{ value: ++value }], recentActivity: [] })
  assert.equal((await fetchDashboardMetrics())[0].value, 1)
  assert.equal((await fetchDashboardMetrics())[0].value, 2)
})
