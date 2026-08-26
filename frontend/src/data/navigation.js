/**
 * Sidebar destinations for the investigator application shell.
 *
 * `phase` documents what still has to be built behind each destination — the
 * placeholder route surfaces it so the shell is honest about what is mock and
 * what is real.
 */

export const NAV_ITEMS = [
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
    label: 'Analysis',
    path: '/analysis',
    icon: 'analysis',
    phase: 'Artifact explorer over the anomaly detection pipeline',
  },
  {
    label: 'AI Triage',
    path: '/ai-triage',
    icon: 'triage',
    phase: 'Ranked findings with per-artifact scoring rationale',
  },
  {
    label: 'Timeline',
    path: '/timeline',
    icon: 'timeline',
    phase: 'Interactive event timeline with zoom-to-second',
  },
  {
    label: 'IOC Graph',
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
