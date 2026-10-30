import { useState } from 'react'
import useApi from '../../hooks/useApi.js'
import { postFile } from '../../services/apiClient.js'
import ScreeningSummary from './ScreeningSummary.jsx'

const OPTIONS = [
  ['cicids2017', 'CICIDS2017 network-flow CSV', '.csv'],
  ['cicids2018', 'CSE-CIC-IDS2018 external network-flow CSV', '.csv'],
  ['pcap', 'Packet capture / exported network flows', '.pcap,.pcapng,.csv'],
  ['evtx', 'Exported event logs (CSV / JSON / XML)', '.csv,.json,.xml'],
  ['registry', 'Registry export (.reg / CSV / JSON)', '.reg,.csv,.json'],
  ['file', 'File listing (CSV / JSON)', '.csv,.json'],
  ['native', 'Native forensic evidence (.evtx / hive / disk image)', '.evtx,.dat,.hiv,.hive,.dd,.raw,.img,.e01,.001'],
  ['pe', 'Standalone Windows PE executable (static analysis)', '.exe,.dll,.bin'],
]

export default function IntakePanel({ caseId, onComplete, networkOnly = false }) {
  const [kind, setKind] = useState(networkOnly ? 'cicids2017' : 'file')
  const [file, setFile] = useState(null)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState(null)
  const [result, setResult] = useState(null)
  const [revision, refresh] = useState(0)
  const model = useApi('/model', revision)
  const [detectorChoice, setDetectorChoice] = useState('')
  const ext = file?.name.split('.').pop()?.toLowerCase()
  const network = ['cicids2017', 'cicids2018'].includes(kind) || (kind === 'pcap' && ext === 'csv')
  const availableModels = Object.entries(model.data?.models || {}).filter(([, m]) => m.available)
  const detector = detectorChoice || (model.data?.models?.[model.data?.default_detector]?.available ? model.data.default_detector : '')
  const selectedModel = model.data?.models?.[detector]
  const capabilities = useApi('/forensics/capabilities', revision)
  const health = useApi('/health', revision)
  const nativeKind = ext === 'evtx' ? 'evtx' : ['dat', 'hiv', 'hive'].includes(ext) ? 'registry' : 'disk_image'
  const native = capabilities.data?.[nativeKind]
  const unavailable = !caseId ? 'Select an investigation first.'
    : health.loading ? 'Checking database…'
    : health.error || (health.data?.mongo !== 'connected' ? 'MongoDB is unavailable. Start MongoDB, then refresh service status.' : null)
    || (network ? model.error || (model.loading ? 'Checking models…' : !selectedModel?.available ? 'Select an available network detector.' : null) : null)
    || (kind === 'pcap' && ['pcap', 'pcapng'].includes(ext) && !capabilities.data?.pcap?.available ? capabilities.data?.pcap?.reason || 'PCAP parser unavailable.' : null)
    || (kind === 'native' ? capabilities.error || (!native?.available ? native?.reason || 'Native parser unavailable.' : null) : null)

  async function submit(event) {
    event.preventDefault()
    if (!file || unavailable || pending) return
    setError(null); setResult(null)
    const extensions = OPTIONS.find(o => o[0] === kind)[2].split(',')
    if (!file.size || !extensions.includes(`.${ext}`)) { setError('Select a nonempty file in the indicated format.'); return }
    if (file.size > (health.data?.max_upload_bytes || 128 * 1024 * 1024)) { setError('File exceeds the backend upload limit.'); return }
    setPending(true)
    try {
      const path = ['cicids2017','cicids2018'].includes(kind) ? '/analyze' : ['native','pe'].includes(kind) ? '/forensics/ingest' : '/ingest'
      const data = await postFile(path, file, { data: { caseId, ...(network ? {detector} : {}), ...(kind === 'cicids2018' ? {dataset:'cse-cic-ids2018'} : {}), ...(!['native','cicids2017','cicids2018'].includes(kind) ? { kind } : {}) } })
      if (data.persisted === false || (data.stored == null && !data.persisted)) throw new Error('Processing finished but persistence was not confirmed.')
      setResult(data)
      await onComplete?.()
    } catch (err) { setError(err.message) } finally { setPending(false) }
  }
  return <section className="integration-page">
    <h3>{networkOnly ? 'Network ML inference' : 'Upload evidence'}</h3>
    <p>Upload once here to update this case’s evidence, artifacts, analysis, timeline and relationships. Reports use the latest saved results when generated.</p>
    <p>Network CSVs use the selected frozen detector. Host evidence uses forensic rules; supported PE files also use the static malware classifier. Uploads never train a model. SHA-256 and parsed records are retained; the original uploaded file is not retained.</p>
    <p>Network models: {model.loading ? 'Checking…' : model.error || availableModels.map(([,m]) => m.name).join(' · ') || 'Unavailable'}</p>
    <p>PE malware model: {capabilities.loading ? 'Checking…' : capabilities.data?.pe_malware_ml?.available ? capabilities.data.pe_malware_ml.model_id : 'Unavailable; eligible files will retain an explicit model status'}</p>
    <button type="button" onClick={() => refresh(v => v + 1)} disabled={pending}>Refresh service status</button>
    {network && selectedModel && <details><summary>Selected detector provenance</summary><pre>{JSON.stringify(selectedModel, null, 2)}</pre></details>}
    <form onSubmit={submit} className="integration-form">
      {!networkOnly && <label>Evidence type<select value={kind} disabled={pending} onChange={e => { setKind(e.target.value); setFile(null); setResult(null) }}>
        {OPTIONS.map(([id, label]) => <option key={id} value={id}>{label}</option>)}
      </select></label>}
      {network && <label>Network detector<select value={detector} disabled={pending} onChange={e => setDetectorChoice(e.target.value)}>
        <option value="">Choose an available detector</option>
        {availableModels.map(([id,m]) => <option key={id} value={id}>{m.name}</option>)}
      </select></label>}
      {network && selectedModel && <p>Selected: {selectedModel.name} · {selectedModel.model_id} · threshold {selectedModel.active_threshold}. Scores are not accuracy.</p>}
      {kind === 'cicids2018' && <p>CSE-CIC-IDS2018 adapter v1 uses the original flow measurements and frozen detector threshold. Feature compatibility is conditional because the dataset's exact extractor build is unavailable. Invalid required measurements are reported and excluded.</p>}
      <label>Evidence file<input key={kind} type="file" accept={OPTIONS.find(o => o[0] === kind)[2]} disabled={pending}
        onChange={e => { setFile(e.target.files?.[0] || null); setResult(null); setError(null) }} /></label>
      <button disabled={pending || !file || Boolean(unavailable)}>{pending ? 'Processing…' : 'Upload and process'}</button>
      {unavailable && <p role="status">{unavailable}</p>}{error && <p role="alert">{error}</p>}
    </form>
    {result && <div role="status"><p>Stored {result.stored} records. Evidence SHA-256: <code>{result.evidence.sha256}</code></p>
      <ScreeningSummary result={result} />
      {result.inference_metadata && <p>Analyzed by {result.inference_metadata.model_id} · threshold {result.inference_metadata.active_threshold} · {result.summary.total_records} flows · {result.summary.classified_attacks} attack/anomaly decisions · {result.summary.classified_benign} benign/normal decisions</p>}
      {result.inference_metadata?.external_dataset && <p>External compatibility: {result.inference_metadata.external_dataset.compatibility.status} · {result.inference_metadata.external_dataset.input_rows} source rows · {result.inference_metadata.external_dataset.excluded_rows} excluded</p>}
      <details><summary>Processing results and provenance</summary><pre>{JSON.stringify(result, null, 2)}</pre></details>
    </div>}
  </section>
}
