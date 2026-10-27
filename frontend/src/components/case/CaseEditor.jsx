import { useState } from 'react'
import { addNote, updateCase } from '../../services/caseService.js'

export default function CaseEditor({ caseRecord, onChange }) {
  const [pending, setPending] = useState(false)
  const [error, setError] = useState(null)
  async function submit(event, note = false) {
    event.preventDefault(); setPending(true); setError(null)
    const form = event.currentTarget
    const fields = Object.fromEntries(new FormData(form))
    try {
      if (note) await addNote(caseRecord.id, fields.text)
      else await updateCase(caseRecord.id, fields)
      await onChange()
      if (note) form.reset()
    } catch (err) { setError(err.message) } finally { setPending(false) }
  }
  return <details><summary>Edit investigation and notes</summary>
    <form className="integration-form" onSubmit={submit} key={caseRecord.id + caseRecord.lastActivity?.at}>
      <label>Title<input required name="title" defaultValue={caseRecord.title} maxLength={200} /></label>
      <label>Description<textarea name="description" defaultValue={caseRecord.description} maxLength={4000} /></label>
      <label>Assigned investigator<input name="examiner" defaultValue={caseRecord.examiner} maxLength={200} /></label>
      <label>Primary host<input name="primaryHost" defaultValue={caseRecord.primaryHost} maxLength={200} /></label>
      <label>Status<select name="status" defaultValue={caseRecord.status}>{['INGESTING', 'ANALYZING', 'REVIEW', 'CLOSED'].map(s => <option key={s}>{s}</option>)}</select></label>
      <button disabled={pending}>Save changes</button>
    </form>
    <form className="integration-form" onSubmit={e => submit(e, true)}>
      <label>New note<textarea name="text" required maxLength={4000} /></label><button disabled={pending}>Add note</button>
    </form>
    {error && <p role="alert">{error}</p>}
    {(caseRecord.notes || []).map(n => <p key={n.id}><time>{new Date(n.at).toLocaleString()}</time> — {n.text}</p>)}
  </details>
}
