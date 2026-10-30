import useApi from '../hooks/useApi.js'
import { useState } from 'react'
import './EvaluationPage.css'

const percent = value => value == null ? 'Not measured' : `${(value * 100).toFixed(4)}%`

function SourceInspection({ id, label }) {
  const [open, setOpen] = useState(false)
  const { data, loading, error } = useApi(open ? `/evaluations/${encodeURIComponent(id)}` : null)
  return <div className="evaluation-source">
    <button type="button" onClick={() => setOpen(value => !value)}>{open ? 'Hide' : 'Inspect'} {label}</button>
    {open && (loading ? <p>Loading verified source…</p> : error ? <p role="alert">VERIFICATION DATA UNAVAILABLE: {error}</p> : <pre>{JSON.stringify(data, null, 2)}</pre>)}
  </div>
}

export function EvaluationResults({ data }) {
  return <main className="evaluation-page">
    <h1>Model Evaluation &amp; Experimental Results</h1>
    <p>Saved labeled experiments. Live investigation flags are not accuracy or recall. Model scores are not calibrated confidence.</p>
    <p>Internal versus external results use different populations and are not a controlled comparison.</p>
    {(data?.evaluations || []).map(group => <section key={group.id} className="evaluation-card">
      <h2>{group.title || group.id}</h2><p className="evaluation-badge">{group.badge || group.status}</p>
      {group.status !== 'VERIFIED_SAVED_RESULT' ? <p role="alert">VERIFICATION DATA UNAVAILABLE</p> : <>
        {group.limitations.map(text => <p key={text}>{text}</p>)}
        {group.entries.map(entry => {
          const m = entry.metrics, c = m.confusion_matrix
          return <article key={entry.name}>
            <h3>{entry.name}</h3><p className="evaluation-badge">{entry.badge}</p>
            <p>{entry.model_id || 'See sealed selection manifest'} · threshold {entry.threshold}</p>
            <details><summary>Model identity and decision policy</summary>
              <p>Model SHA-256: <code>{entry.model_sha256 || 'Not recorded in source'}</code></p>
              <p>Feature contract: {group.provenance.feature_schema}. Model scores are not calibrated confidence.</p>
            </details>
            <p>{m.samples.toLocaleString()} evaluated · {m.benign.toLocaleString()} actual benign · {m.attack.toLocaleString()} actual attacks</p>
            <p>Detected attacks: {c.tp.toLocaleString()} · Missed attacks: {c.fn.toLocaleString()} · Recall: {percent(m.recall)}</p>
            {!entry.positive_only && <>
              <div className="evaluation-bars" aria-label={`${group.title} ${entry.name} metrics; N=${m.samples}`}>
                {['accuracy','precision','recall','f1','false_positive_rate'].map(key => <div key={key}>
                  <span>{key.replaceAll('_',' ')}: {percent(m[key])}</span>
                  <meter min="0" max="1" value={m[key] ?? 0} aria-label={key} />
                </div>)}
              </div><p>ROC-AUC: {m.roc_auc?.toFixed(6) ?? 'Not measured'}</p>
            </>}
            <table><caption>Confusion matrix — actual rows, predicted columns; N={m.samples.toLocaleString()}</caption>
              <thead><tr><th>Actual / Predicted</th><th>Benign</th><th>Attack</th></tr></thead>
              <tbody><tr><th>Benign</th><td>{c.tn?.toLocaleString() ?? 'Not available'}</td><td>{c.fp?.toLocaleString() ?? 'Not available'}</td></tr>
                <tr><th>Attack</th><td>{c.fn.toLocaleString()}</td><td>{c.tp.toLocaleString()}</td></tr></tbody></table>
            {entry.architectures && <table><caption>Unique file comparison</caption><thead><tr><th>Type</th><th>N</th><th>Recall</th><th>FPR</th></tr></thead><tbody>{Object.entries(entry.architectures).map(([name,r]) => <tr key={name}><th>{name}</th><td>{r.samples.toLocaleString()}</td><td>{percent(r.recall)}</td><td>{percent(r.false_positive_rate)}</td></tr>)}</tbody></table>}
            {entry.families && <details><summary>Attack-family results and capture days</summary>
              {entry.days && <p>{entry.days.join(', ')}</p>}
              <table><thead><tr><th>Original family</th><th>Records</th><th>Attack prediction / recall</th></tr></thead><tbody>{Object.entries(entry.families).map(([name,r]) => <tr key={name}><th>{name}</th><td>{r.samples ?? r.rows}</td><td>{percent(r.recall ?? r.attack_recall ?? r.attack_prediction_rate ?? r.false_positive_rate)}</td></tr>)}</tbody></table>
              <p>Binary detection grouped by original labels; benign rows show false-positive behavior, not attack recall.</p>
            </details>}
          </article>
        })}
        <details><summary>Evidence, provenance and reproducibility</summary>
          <p>Recorded evaluation start: {group.recorded_evaluation_start || 'Not recorded'}. {group.date_limitation}</p>
          <pre>{JSON.stringify(group.provenance,null,2)}</pre>
          <SourceInspection id={group.id} label="saved metrics JSON (read only)" />
          {(group.supporting_sources || []).map(source => <SourceInspection key={source.id} id={source.id} label={source.id.replaceAll('-', ' ')} />)}
        </details>
      </>}
    </section>)}
    <details><summary>Metric definitions</summary><pre>{JSON.stringify(data?.definitions,null,2)}</pre></details>
  </main>
}

export default function EvaluationPage() {
  const { data, loading, error } = useApi('/evaluations')
  if (loading) return <p>Loading verified saved evaluations…</p>
  if (error) return <p role="alert">VERIFICATION DATA UNAVAILABLE: {error}</p>
  return <EvaluationResults data={data} />
}
