import { useState } from 'react'
import useApi from '../../hooks/useApi.js'
import { postFile } from '../../services/apiClient.js'

const OPTIONS = [
  ['cicids2017', 'CICIDS2017 network-flow CSV', '.csv'],
  ['pcap', 'Packet capture / exported network flows', '.pcap,.pcapng,.csv'],
  ['evtx', 'Exported event logs (CSV / JSON / XML)', '.csv,.json,.xml'],
  ['registry', 'Registry export (.reg / CSV / JSON)', '.reg,.csv,.json'],
  ['file', 'File listing (CSV / JSON)', '.csv,.json'],
  ['native', 'Native forensic evidence (.evtx / hive / disk image)', '.evtx,.dat,.hiv,.hive,.dd,.raw,.img,.e01,.001'],
]

export default function IntakePanel({ caseId, onComplete, networkOnly = false }) {
  const [kind, setKind] = useState(networkOnly ? 'cicids2017' : 'file')
  const [file, setFile] = useState(null)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState(null)
  const [result, setResult] = useState(null)
  const [revision, refresh] = useState(0)
  const model = useApi('/model', revision)
  const capabilities = useApi('/forensics/capabilities', revision)
  const health = useApi('/health', revision)
  const ext = file?.name.split('.').pop()?.toLowerCase()
  const nativeKind = ext === 'evtx' ? 'evtx' : ['dat', 'hiv', 'hive'].includes(ext) ? 'registry' : 'disk_image'
  const native = capabilities.data?.[nativeKind]
  const unavailable = !caseId ? 'Select an investigation first.'
    : health.loading ? 'Checking database…'
    : health.error || (health.data?.mongo !== 'connected' ? 'MongoDB is unavailable. Start MongoDB, then refresh service status.' : null)
    || (['cicids2017', 'pcap'].includes(kind) ? model.error || (model.loading ? 'Checking model…' : !model.data?.available ? model.data?.message || 'Approved network baseline unavailable.' : null) : null)
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
      const path = kind === 'cicids2017' ? '/analyze' : kind === 'native' ? '/forensics/ingest' : '/ingest'
      const data = await postFile(path, file, { data: { caseId, ...(kind !== 'native' && kind !== 'cicids2017' ? { kind } : {}) } })
      if (data.persisted === false || (data.stored == null && !data.persisted)) throw new Error('Processing finished but persistence was not confirmed.')
      setResult(data)
      await onComplete?.()
    } catch (err) { setError(err.message) } finally { setPending(false) }
  }
  return <section className="integration-page">
    <h3>{networkOnly ? 'Network ML inference' : 'Upload evidence'}</h3>
    <p>Upload once here to update this case’s evidence, artifacts, analysis, timeline and relationships. Reports use the latest saved results when generated.</p>
    <p>Network CSVs use the approved CICIDS2017 baseline. Host evidence uses forensic rules; supported PE files also use the static malware classifier. Uploads never train a model. SHA-256 and parsed records are retained; the original uploaded file is not retained.</p>
    <p>Network model: {model.loading ? 'Checking…' : model.error || (model.data?.available ? 'Available' : model.data?.message || 'Unavailable')}</p>
    <p>PE malware model: {capabilities.loading ? 'Checking…' : capabilities.data?.pe_malware_ml?.available ? capabilities.data.pe_malware_ml.model_id : 'Unavailable; eligible files will retain an explicit model status'}</p>
    <button type="button" onClick={() => refresh(v => v + 1)} disabled={pending}>Refresh service status</button>
    {model.data?.available && <details><summary>Model provenance</summary><pre>{JSON.stringify(model.data.baseline, null, 2)}</pre></details>}
    <form onSubmit={submit} className="integration-form">
      {!networkOnly && <label>Evidence type<select value={kind} disabled={pending} onChange={e => { setKind(e.target.value); setFile(null); setResult(null) }}>
        {OPTIONS.map(([id, label]) => <option key={id} value={id}>{label}</option>)}
      </select></label>}
      <label>Evidence file<input key={kind} type="file" accept={OPTIONS.find(o => o[0] === kind)[2]} disabled={pending}
        onChange={e => { setFile(e.target.files?.[0] || null); setResult(null); setError(null) }} /></label>
      <button disabled={pending || !file || Boolean(unavailable)}>{pending ? 'Processing…' : 'Upload and process'}</button>
      {unavailable && <p role="status">{unavailable}</p>}{error && <p role="alert">{error}</p>}
    </form>
    {result && <div role="status"><p>Stored {result.stored} records. Evidence SHA-256: <code>{result.evidence.sha256}</code></p>
      <details><summary>Processing results and provenance</summary><pre>{JSON.stringify(result, null, 2)}</pre></details>
    </div>}
  </section>
}
