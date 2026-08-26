/**
 * Inline icon set — stroke-based, 24x24 grid, inherits `currentColor`.
 *
 * Kept local rather than pulling an icon package, so the frontend stays at four
 * dependencies. Add new glyphs to PATHS.
 */

const PATHS = {
  dashboard: (
    <>
      <rect x="3" y="3" width="7.5" height="7.5" rx="1.5" />
      <rect x="13.5" y="3" width="7.5" height="7.5" rx="1.5" />
      <rect x="3" y="13.5" width="7.5" height="7.5" rx="1.5" />
      <rect x="13.5" y="13.5" width="7.5" height="7.5" rx="1.5" />
    </>
  ),
  cases: (
    <>
      <path d="M3 7.5A1.5 1.5 0 0 1 4.5 6h4l2 2.5h8A1.5 1.5 0 0 1 20 10v7.5a1.5 1.5 0 0 1-1.5 1.5h-14A1.5 1.5 0 0 1 3 17.5Z" />
      <path d="M8 6V4.5h7V8.5" />
    </>
  ),
  evidence: (
    <>
      <rect x="3" y="4.5" width="18" height="6" rx="1.5" />
      <rect x="3" y="13.5" width="18" height="6" rx="1.5" />
      <path d="M6.5 7.5h.01M6.5 16.5h.01" />
      <path d="M10.5 7.5h4M10.5 16.5h4" />
    </>
  ),
  analysis: (
    <>
      <path d="M4 20V9M9.33 20V4M14.67 20v-7M20 20v-9" />
    </>
  ),
  triage: (
    <>
      <circle cx="12" cy="12" r="8" />
      <circle cx="12" cy="12" r="3.2" />
      <path d="M12 1.5v3M12 19.5v3M1.5 12h3M19.5 12h3" />
    </>
  ),
  timeline: (
    <>
      <path d="M3 12h18" />
      <circle cx="7.5" cy="12" r="2.2" />
      <circle cx="16.5" cy="12" r="2.2" />
      <path d="M7.5 9.8V5M16.5 14.2V19" />
    </>
  ),
  graph: (
    <>
      <circle cx="6" cy="7" r="2.5" />
      <circle cx="18" cy="6.5" r="2.5" />
      <circle cx="12" cy="17.5" r="2.5" />
      <path d="M8.2 8.3 10.4 15.4M15.9 8.2 13.6 15.5M8.4 6.6l7.2-.05" />
    </>
  ),
  reports: (
    <>
      <path d="M6 3.5h7.5L19 9v11.5H6Z" />
      <path d="M13 3.5V9h6" />
      <path d="M9.5 13h7M9.5 16.5h4.5" />
    </>
  ),
  search: (
    <>
      <circle cx="11" cy="11" r="6.5" />
      <path d="m16 16 4.5 4.5" />
    </>
  ),
  bell: (
    <>
      <path d="M18 9a6 6 0 1 0-12 0c0 5-2 6.5-2 6.5h16S18 14 18 9Z" />
      <path d="M10.3 19a2 2 0 0 0 3.4 0" />
    </>
  ),
  chevronDown: <path d="m6 9.5 6 5.5 6-5.5" />,
  chevronRight: <path d="m9.5 6 5.5 6-5.5 6" />,
  arrowRight: (
    <>
      <path d="M4.5 12h14" />
      <path d="m13 6.5 5.5 5.5L13 17.5" />
    </>
  ),
  alert: (
    <>
      <path d="M12 4.5 21 19.5H3Z" />
      <path d="M12 10v4M12 16.8h.01" />
    </>
  ),
  shield: (
    <>
      <path d="M12 3.5 19.5 6v6c0 4.5-3.2 7.4-7.5 8.5C7.7 19.4 4.5 16.5 4.5 12V6Z" />
      <path d="m8.8 12 2.4 2.4 4-4.4" />
    </>
  ),
  host: (
    <>
      <rect x="3" y="4.5" width="18" height="11.5" rx="1.5" />
      <path d="M8.5 20h7M12 16v4" />
    </>
  ),
  network: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M3.5 12h17" />
      <path d="M12 3.5c2.3 2.4 3.5 5.3 3.5 8.5S14.3 18.1 12 20.5c-2.3-2.4-3.5-5.3-3.5-8.5S9.7 5.9 12 3.5Z" />
    </>
  ),
  file: (
    <>
      <path d="M6.5 3.5h7L18.5 8.5v12h-12Z" />
      <path d="M13 3.5V9h5.5" />
    </>
  ),
  registry: (
    <>
      <rect x="4" y="4" width="16" height="16" rx="1.5" />
      <path d="M4 9h16M9 9v11" />
      <path d="M12.5 12.5h4M12.5 16h2.5" />
    </>
  ),
  clock: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 7.5V12l3.2 2" />
    </>
  ),
  note: (
    <>
      <path d="M5 4.5h14v10L14 20H5Z" />
      <path d="M14 20v-5.5h5" />
      <path d="M8.5 9h7M8.5 12.5h4" />
    </>
  ),
  logout: (
    <>
      <path d="M14.5 4.5h-8A1.5 1.5 0 0 0 5 6v12a1.5 1.5 0 0 0 1.5 1.5h8" />
      <path d="M15 12h5.5M18 8.5 20.5 12 18 15.5" />
    </>
  ),
  menu: <path d="M3.5 8h17M3.5 16h17" />,
  close: <path d="M6 6l12 12M18 6 6 18" />,
  play: <path d="M9 6.5 18 12l-9 5.5Z" fill="currentColor" stroke="none" />,
  lock: (
    <>
      <rect x="5" y="10.5" width="14" height="9.5" rx="1.5" />
      <path d="M8.5 10.5V8a3.5 3.5 0 0 1 7 0v2.5" />
    </>
  ),
  fingerprint: (
    <>
      <path d="M12 3.5c-4.7 0-8.5 3.8-8.5 8.5" />
      <path d="M12 7c-2.8 0-5 2.2-5 5v3" />
      <path d="M12 10.5c-.8 0-1.5.7-1.5 1.5v6" />
      <path d="M20.5 12c0-4.7-3.8-8.5-8.5-8.5" />
      <path d="M17 15v-3c0-2.8-2.2-5-5-5" />
      <path d="M13.5 18v-6c0-.8-.7-1.5-1.5-1.5" />
    </>
  ),
}

export const ICON_NAMES = Object.keys(PATHS)

export default function Icon({ name, size = 18, strokeWidth = 1.5, className, ...rest }) {
  const glyph = PATHS[name]
  if (!glyph) return null

  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...rest}
    >
      {glyph}
    </svg>
  )
}
