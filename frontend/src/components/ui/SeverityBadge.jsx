import './SeverityBadge.css'

/**
 * Severity chip using the same bands as ml/risk_scorer.py.
 *
 * @param {{ severity: string, size?: 'sm'|'md', dot?: boolean }} props
 */
export default function SeverityBadge({ severity, size = 'md', dot = true }) {
  if (!severity) return null
  const key = String(severity).toLowerCase()

  return (
    <span className={`severity-badge severity-badge--${key} severity-badge--${size}`}>
      {dot && <span className="severity-badge__dot" aria-hidden="true" />}
      {severity}
    </span>
  )
}

/**
 * Case status chip (ANALYZING, INGESTING, ...). Kept alongside SeverityBadge so
 * pipeline state never reads as a severity level: every status renders the same
 * neutral chip except ESCALATED, which changes what happens next.
 */
export function StatusBadge({ status }) {
  if (!status) return null
  return (
    <span className={`status-badge status-badge--${String(status).toLowerCase()}`}>
      <span className="status-badge__dot" aria-hidden="true" />
      {status}
    </span>
  )
}
