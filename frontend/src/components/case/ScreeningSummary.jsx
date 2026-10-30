import { screeningView } from '../../utils/screening.js'

export default function ScreeningSummary({ result }) {
  const view = screeningView(result)
  if (!view) return <p>Screening coverage was not recorded for this historical evidence.</p>
  return <section aria-label="Evidence screening coverage">
    <p><strong>Screening: {view.status}</strong> · {view.type} · {view.count ?? 'Unknown'} findings</p>
    <p>Coverage describes checks performed. No detection does not establish safety. Risk priority is separate from a model score.</p>
    <details><summary>Scanners, coverage and limitations</summary>
      {view.scanners.map(s => <div key={s.key}>
        <p><strong>{s.scanner}: {s.status}</strong> · {s.examined} examined · {s.skipped} skipped · {s.findings} findings</p>
        <p>Scope: {s.input_scope}. {s.reason}</p>
        {s.skipped_count_exact === false && <p>The skipped count is a lower bound; enumeration stopped before the remaining population was known.</p>}
        {s.identifier && <p>Ruleset / model: <code>{s.identifier}</code></p>}
        {s.model && <p>Threshold: {s.model.active_threshold ?? s.model.threshold ?? 'See per-file result'}. {s.model.score_interpretation || 'Static model score is not calibrated confidence.'}</p>}
      </div>)}
      {view.warnings.map((warning, i) => <p key={i}>{warning}</p>)}
      {view.truncated && <p>Finding details are capped; the total includes omitted details.</p>}
      {(result.findings || []).map((f, i) => <details key={i}>
        <summary>{f.priority} · {f.detection_sources.join(', ')} · {Object.values(f.artifact || {}).join(' · ')}</summary>
        <p>Triage risk {f.risk_score}: {f.risk_explanation}</p>
        <pre>{JSON.stringify(f, null, 2)}</pre>
      </details>)}
    </details>
  </section>
}
