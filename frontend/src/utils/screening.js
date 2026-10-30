export function screeningView(result) {
  if (!result?.screening) return null
  return {
    status: result.overall_scan_status,
    type: result.evidence_type,
    count: result.coverage?.findings_total ?? null,
    truncated: Boolean(result.coverage?.findings_truncated),
    warnings: result.warnings || [],
    scanners: Object.entries(result.screening).map(([key, value]) => ({ key, ...value })),
  }
}
