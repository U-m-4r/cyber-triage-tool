/** Number and label formatting helpers shared across the dashboard. */

const compactFormatter = new Intl.NumberFormat('en-US', {
  notation: 'compact',
  maximumFractionDigits: 2,
})

const plainFormatter = new Intl.NumberFormat('en-US')

/**
 * @param {number} value
 * @param {'compact'|'plain'} [format]
 */
export function formatCount(value, format = 'plain') {
  if (typeof value !== 'number' || Number.isNaN(value)) return '—'
  return format === 'compact' ? compactFormatter.format(value) : plainFormatter.format(value)
}

/** 0.92 -> "92%" */
export function formatPercent(ratio, digits = 0) {
  if (typeof ratio !== 'number' || Number.isNaN(ratio)) return '—'
  return `${(ratio * 100).toFixed(digits)}%`
}

/** ISO timestamp -> "24 Aug 2026, 02:14:37" */
export function formatTimestamp(iso) {
  if (!iso) return '—'
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return '—'
  return new Intl.DateTimeFormat('en-GB', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(date)
}

/** ISO timestamp -> "24 Aug 2026" */
export function formatDate(iso) {
  if (!iso) return '—'
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return '—'
  return new Intl.DateTimeFormat('en-GB', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
  }).format(date)
}
