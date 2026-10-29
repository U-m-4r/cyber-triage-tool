import test from 'node:test'
import assert from 'node:assert/strict'
import { deriveIndicators } from '../src/utils/relationships.js'

test('shared evidence is one entity with distinct finding references and highest severity', () => {
  const entities = deriveIndicators([
    { id: 'a', artifactType: 'file', source: 'disk.dd', severity: 'LOW' },
    { id: 'b', artifactType: 'file', source: 'disk.dd', severity: 'CRITICAL' },
  ])
  assert.equal(entities.length, 1)
  assert.deepEqual(entities[0].findingIds, ['a', 'b'])
  assert.equal(entities[0].severity, 'CRITICAL')
  assert.deepEqual(entities[0].hosts, [])
})

test('host associations come only from findings with recorded hosts', () => {
  const entities = deriveIndicators([
    { id: 'a', artifactType: 'file', source: 'disk.dd', host: 'PC-01' },
    { id: 'b', artifactType: 'file', source: 'disk.dd' },
  ])
  assert.deepEqual(entities[0].hosts, ['PC-01'])
  assert.deepEqual(deriveIndicators([]), [])
})
