import test from 'node:test'
import assert from 'node:assert/strict'
import { screeningView } from '../src/utils/screening.js'

test('historical evidence has unknown screening rather than a clean verdict', () => {
  assert.equal(screeningView(undefined), null)
  assert.equal(screeningView({}), null)
})

test('coverage adapter preserves unavailable, skipped and measured zero counts', () => {
  const view = screeningView({ overall_scan_status:'PARTIAL', evidence_type:'file_export',
    coverage:{findings_total:0}, warnings:['unavailable'],
    screening:{yara:{status:'UNAVAILABLE', examined:0, skipped:1}, pe_ml:{status:'NOT_APPLICABLE'}} })
  assert.equal(view.count, 0)
  assert.equal(view.status, 'PARTIAL')
  assert.equal(view.scanners[0].status, 'UNAVAILABLE')
  assert.equal(view.scanners[1].status, 'NOT_APPLICABLE')
  assert.deepEqual(view.warnings, ['unavailable'])
})
