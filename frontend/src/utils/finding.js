/** Explain persisted findings, including reports stored before scoring labels changed. */
export function findingRationale(finding) {
  const rationale = finding.rationale || 'Scoring details unavailable.'
  if (!['file', 'registry', 'system_log'].includes(finding.artifactType) || rationale.includes('ML anomaly: not applicable')) return rationale
  return rationale
    .replace(/; anomaly score: None(?: \(Evaluated via domain heuristic rules; ML anomaly detector applies to network flows\))?/, '. ML anomaly: not applicable to this evidence type; the model requires network flows.')
    .replace(/^Rule score: 0(?:\.0)?(?=[.;])/, 'No configured rules matched (rule score: 0)')
}
