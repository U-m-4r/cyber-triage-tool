import fs from 'node:fs'
import path from 'node:path'
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { pathToFileURL } from 'node:url'
const require = createRequire(path.resolve('frontend/package.json'))
const React = require('react')
const { renderToStaticMarkup } = require('react-dom/server')
const { createServer } = await import(pathToFileURL(require.resolve('vite')).href)
const [input, output] = process.argv.slice(2)
const data = JSON.parse(fs.readFileSync(input, 'utf8'))
const server = await createServer({ root: path.resolve('frontend'), server: { middlewareMode: true }, appType: 'custom' })
try {
  const { EvaluationResults } = await server.ssrLoadModule('/src/routes/EvaluationPage.jsx')
  const html = renderToStaticMarkup(React.createElement(EvaluationResults, { data }))
  assert.ok(html.includes('RESEARCH ONLY'))
  assert.ok(html.includes('Positive-only malicious challenge evaluation'))
  for (const group of data.evaluations) for (const entry of group.entries) {
    assert.ok(html.includes(entry.metrics.samples.toLocaleString()))
    assert.ok(html.includes(entry.metrics.confusion_matrix.tp.toLocaleString()))
  }
  fs.writeFileSync(output, html)
  console.log('PASS: genuine saved evaluation counts rendered by actual React component')
} finally { await server.close() }
