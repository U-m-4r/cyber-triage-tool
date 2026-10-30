// Render the actual artifact component with genuine saved API results, no browser.
import fs from 'node:fs'
import path from 'node:path'
import assert from 'node:assert/strict'
import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { createServer } from 'vite'

const [input, output] = process.argv.slice(2)
if (!input || !output) throw new Error('Usage: node verify-pe-render.mjs saved-artifacts.json output.html')
const rows = JSON.parse(fs.readFileSync(input, 'utf8'))
const server = await createServer({ root: path.resolve('frontend'), server: { middlewareMode: true }, appType: 'custom' })
try {
  const { ArtifactTable } = await server.ssrLoadModule('/src/components/case/CaseArtifacts.jsx')
  const html = renderToStaticMarkup(React.createElement(ArtifactTable, {
    rows, total: rows.length, loading: false, type: '', severity: '',
    setType() {}, setSeverity() {},
  }))
  const classified = rows.filter(row => row.pe_ml?.status === 'CLASSIFIED')
  assert.equal(classified.length, 1)
  for (const row of classified) {
    assert.ok(html.includes(row.pe_ml.model_id))
    assert.ok(html.includes(row.pe_ml.model_score.toFixed(6)))
    assert.ok(html.includes(row.pe_ml.prediction))
    assert.ok(html.includes(row.FilePath))
  }
  assert.ok(html.includes('Not calibrated confidence'))
  fs.writeFileSync(output, html)
  console.log(JSON.stringify({ rows: rows.length, genuine_pe_predictions_rendered: classified.length,
    model_id: classified[0].pe_ml.model_id, status: 'PASS', scope: 'Actual React artifact table server-rendered using saved real API payload; no browser interaction verified' }))
} finally {
  await server.close()
}
