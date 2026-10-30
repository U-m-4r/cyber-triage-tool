/** Workspace destinations; each opens the corresponding case result view. */

export const NAV_ITEMS = [
  { label: 'Model evaluation', path: '/evaluations', icon: 'analysis', phase: 'Saved labeled experiments and limitations' },
  {
    label: 'Dashboard',
    path: '/dashboard',
    icon: 'dashboard',
    phase: null,
  },
  {
    label: 'Cases',
    path: '/cases',
    icon: 'cases',
    phase: 'Case management and chain-of-custody records',
  },
  {
    label: 'Evidence',
    path: '/evidence',
    icon: 'evidence',
    phase: 'Disk image, log, registry and PCAP ingestion',
  },
  {
    label: 'Analysis & triage',
    path: '/analysis',
    icon: 'analysis',
    phase: 'Artifact explorer over the anomaly detection pipeline',
  },
  {
    label: 'Timeline',
    path: '/timeline',
    icon: 'timeline',
    phase: 'Interactive event timeline with zoom-to-second',
  },
  {
    label: 'Relationships',
    path: '/ioc-graph',
    icon: 'graph',
    phase: 'Indicator relationship graph and threat-intel enrichment',
  },
  {
    label: 'Reports',
    path: '/reports',
    icon: 'reports',
    phase: 'PDF, JSON and CSV export of triage findings',
  },
]

/** Distinct steps of an investigation. Legacy ai-triage links resolve to analysis. */
export const CASE_TABS = [
  {
    id: 'overview',
    label: 'Overview',
    available: true,
    phase: null,
  },
  {
    id: 'evidence',
    label: 'Evidence',
    available: true,
    phase: null,
  },
  {
    id: 'artifacts',
    label: 'Artifacts',
    available: true,
    phase: null,
  },
  {
    id: 'analysis',
    label: 'Analysis & triage',
    available: true,
    phase: 'Correlation and per-feature score breakdown',
  },
  {
    id: 'timeline',
    label: 'Timeline',
    available: true,
    phase: null,
  },
  {
    id: 'ioc-graph',
    label: 'Relationships',
    available: true,
    phase: null,
  },
  {
    id: 'reports',
    label: 'Reports',
    available: true,
    phase: null,
  },
]
