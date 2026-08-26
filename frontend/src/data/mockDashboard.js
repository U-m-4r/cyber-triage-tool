/**
 * Mock fixtures for the Phase 1 dashboard.
 *
 * IMPORTANT: every value in this file is authored sample data for UI
 * development. Nothing here was produced by a model, a parser, or a threat-intel
 * feed. Timestamps are fixed (rather than derived from the current clock) so the
 * dashboard renders identically on every load.
 *
 * Severity values match the priority bands emitted by ml/risk_scorer.py
 * (CRITICAL >= 75, HIGH >= 50, MEDIUM >= 25, LOW otherwise) so this data stays
 * shape-compatible with the real /api/analyze response.
 */

export const SEVERITY = {
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
  INFO: 'INFO',
}

/**
 * @typedef {object} DashboardMetric
 * @property {string} id
 * @property {string} label
 * @property {number} value
 * @property {'compact'|'plain'} [format]
 * @property {string} detail
 * @property {{ direction: 'up'|'down', value: string, period: string }} [delta]
 */

/** @type {DashboardMetric[]} */
export const DASHBOARD_METRICS = [
  {
    id: 'active-investigations',
    label: 'Active Investigations',
    value: 7,
    detail: '3 awaiting examiner review',
    delta: { direction: 'up', value: '+2', period: 'this week' },
  },
  {
    id: 'evidence-sources',
    label: 'Evidence Sources',
    value: 24,
    detail: '9 disk images · 11 log sets · 4 captures',
    delta: { direction: 'up', value: '+5', period: 'this week' },
  },
  {
    id: 'artifacts-analyzed',
    label: 'Artifacts Analyzed',
    value: 1_284_907,
    format: 'compact',
    detail: 'Across all open cases',
    delta: { direction: 'up', value: '+184K', period: '24h' },
  },
  {
    id: 'detected-iocs',
    label: 'Detected IOCs',
    value: 342,
    detail: '58 hashes · 194 addresses · 90 domains',
    delta: { direction: 'up', value: '+27', period: '24h' },
  },
  {
    id: 'critical-findings',
    label: 'Critical Findings',
    value: 19,
    detail: '6 unreviewed on CASE-2026-0147',
    delta: { direction: 'up', value: '+4', period: '24h' },
  },
]

export const ACTIVE_INVESTIGATIONS = [
  {
    id: 'CASE-2026-0147',
    title: 'Ransomware staging on finance workstation',
    threatScore: 87,
    severity: SEVERITY.HIGH,
    status: 'ANALYZING',
    progress: 68,
    examiner: 'INV-2291',
    openedAt: '2026-08-24T09:12:00+05:30',
    lastActivity: '4 minutes ago',
    evidence: { images: 2, logSets: 5, captures: 1 },
    artifacts: 486_112,
    criticalFindings: 6,
    iocHits: 41,
    primaryHost: 'FIN-WKS-014',
  },
  {
    id: 'CASE-2026-0143',
    title: 'Credential harvesting via phishing payload',
    threatScore: 74,
    severity: SEVERITY.HIGH,
    status: 'CORRELATING',
    progress: 41,
    examiner: 'INV-2104',
    openedAt: '2026-08-22T16:40:00+05:30',
    lastActivity: '38 minutes ago',
    evidence: { images: 1, logSets: 3, captures: 2 },
    artifacts: 213_408,
    criticalFindings: 4,
    iocHits: 26,
    primaryHost: 'HR-LAP-072',
  },
  {
    id: 'CASE-2026-0139',
    title: 'Unauthorised database export, night shift',
    threatScore: 91,
    severity: SEVERITY.CRITICAL,
    status: 'ESCALATED',
    progress: 92,
    examiner: 'INV-2291',
    openedAt: '2026-08-19T22:05:00+05:30',
    lastActivity: '2 hours ago',
    evidence: { images: 3, logSets: 2, captures: 1 },
    artifacts: 391_774,
    criticalFindings: 7,
    iocHits: 18,
    primaryHost: 'DB-PRD-002',
  },
  {
    id: 'CASE-2026-0136',
    title: 'Lateral movement across build agents',
    threatScore: 52,
    severity: SEVERITY.MEDIUM,
    status: 'INGESTING',
    progress: 17,
    examiner: 'INV-2338',
    openedAt: '2026-08-26T08:55:00+05:30',
    lastActivity: '11 minutes ago',
    evidence: { images: 1, logSets: 1, captures: 0 },
    artifacts: 47_260,
    criticalFindings: 1,
    iocHits: 5,
    primaryHost: 'CI-AGT-009',
  },
]

/**
 * Mock triage summary for the selected case. The `rationale` field is what the
 * investigator reads to answer "why was this flagged?" — in the real pipeline it
 * will be populated from the rule labels in ml/risk_scorer.py plus the anomaly
 * score contribution.
 */
export const AI_TRIAGE = {
  caseId: 'CASE-2026-0147',
  threatScore: 87,
  severity: SEVERITY.HIGH,
  confidence: 0.92,
  modelLabel: 'Isolation Forest + rule ensemble',
  criticalFindings: 6,
  artifactsScored: 486_112,
  scoredAt: '2026-08-26T14:28:00+05:30',
  recommendedAction: {
    headline: 'Isolate FIN-WKS-014 and preserve volatile memory before reboot',
    detail:
      'Persistence is established and outbound C2 traffic is still active. Capture RAM and the Run-key hive, then contain the host before continuing artifact review.',
    urgency: SEVERITY.CRITICAL,
  },
  findings: [
    {
      id: 'F-1042',
      title: 'Suspicious PowerShell Execution',
      severity: SEVERITY.CRITICAL,
      riskScore: 94,
      confidence: 0.96,
      source: 'Security.evtx · Event 4688',
      host: 'FIN-WKS-014',
      observedAt: '2026-08-24T02:14:37+05:30',
      technique: { id: 'T1059.001', name: 'PowerShell' },
      rationale:
        'Encoded command line with -nop -w hidden -enc, launched by a Word child process outside business hours.',
      artifactType: 'system_log',
    },
    {
      id: 'F-1043',
      title: 'Malicious File Hash',
      severity: SEVERITY.CRITICAL,
      riskScore: 91,
      confidence: 0.99,
      source: 'C:\\Users\\Public\\svc_host.exe',
      host: 'FIN-WKS-014',
      observedAt: '2026-08-24T02:16:02+05:30',
      technique: { id: 'T1204.002', name: 'Malicious File' },
      rationale:
        'SHA-256 matches a known loader family in the local signature set. Unsigned binary written to a world-writable path.',
      artifactType: 'file',
    },
    {
      id: 'F-1044',
      title: 'Registry Persistence',
      severity: SEVERITY.HIGH,
      riskScore: 78,
      confidence: 0.9,
      source: 'NTUSER.DAT · Run\\WinUpdateSvc',
      host: 'FIN-WKS-014',
      observedAt: '2026-08-24T02:16:44+05:30',
      technique: { id: 'T1547.001', name: 'Registry Run Keys' },
      rationale:
        'Autorun value added seconds after the loader was written, pointing at the same unsigned binary.',
      artifactType: 'registry',
    },
    {
      id: 'F-1045',
      title: 'Unusual Network Connection',
      severity: SEVERITY.HIGH,
      riskScore: 71,
      confidence: 0.84,
      source: 'capture-014.pcap · 45.61.x.x:8443',
      host: 'FIN-WKS-014',
      observedAt: '2026-08-24T02:19:10+05:30',
      technique: { id: 'T1571', name: 'Non-Standard Port' },
      rationale:
        'Sustained beaconing at 60s intervals to a first-seen address; flow duration and packet rate both fall in the top 1% of the baseline.',
      artifactType: 'network',
    },
  ],
}

/** Second populated triage record, so case selection has more than one state. */
export const AI_TRIAGE_0139 = {
  caseId: 'CASE-2026-0139',
  threatScore: 91,
  severity: SEVERITY.CRITICAL,
  confidence: 0.88,
  modelLabel: 'Isolation Forest + rule ensemble',
  criticalFindings: 7,
  artifactsScored: 391_774,
  scoredAt: '2026-08-26T12:22:00+05:30',
  recommendedAction: {
    headline: 'Revoke svc_reporting credentials and freeze the export job',
    detail:
      'A service account exported 4.2 GB outside its baseline window. Rotate the credential, preserve the audit log, and confirm whether the archive left the network.',
    urgency: SEVERITY.CRITICAL,
  },
  findings: [
    {
      id: 'F-0977',
      title: 'Bulk Row Export Outside Baseline',
      severity: SEVERITY.CRITICAL,
      riskScore: 96,
      confidence: 0.94,
      source: 'audit_log · SELECT 8.4M rows',
      host: 'DB-PRD-002',
      observedAt: '2026-08-19T23:41:12+05:30',
      technique: { id: 'T1213', name: 'Data from Repositories' },
      rationale:
        'Single query returned 340x the account\u2019s 30-day median row count, against tables it had never previously read.',
      artifactType: 'system_log',
    },
    {
      id: 'F-0978',
      title: 'Service Account Used Off-Hours',
      severity: SEVERITY.HIGH,
      riskScore: 81,
      confidence: 0.86,
      source: 'Security.evtx · Event 4624 (type 3)',
      host: 'DB-PRD-002',
      observedAt: '2026-08-19T23:38:04+05:30',
      technique: { id: 'T1078', name: 'Valid Accounts' },
      rationale:
        'Interactive-style network logon for svc_reporting at 23:38 from a workstation subnet, not the scheduler host.',
      artifactType: 'system_log',
    },
    {
      id: 'F-0979',
      title: 'Archive Staged in Temp Path',
      severity: SEVERITY.HIGH,
      riskScore: 76,
      confidence: 0.91,
      source: 'D:\\Temp\\rpt_20260819.7z (4.2 GB)',
      host: 'DB-PRD-002',
      observedAt: '2026-08-19T23:52:47+05:30',
      technique: { id: 'T1074.001', name: 'Local Data Staging' },
      rationale:
        'Compressed archive written minutes after the export, sized to match the queried tables.',
      artifactType: 'file',
    },
    {
      id: 'F-0980',
      title: 'Large Outbound Transfer',
      severity: SEVERITY.CRITICAL,
      riskScore: 89,
      confidence: 0.82,
      source: 'capture-db02.pcap · 443/tcp egress',
      host: 'DB-PRD-002',
      observedAt: '2026-08-20T00:14:29+05:30',
      technique: { id: 'T1048', name: 'Exfiltration Over Alt Protocol' },
      rationale:
        'Sustained 4.1 GB upload to an external host; flow bytes/s in the top 0.2% of the network baseline.',
      artifactType: 'network',
    },
  ],
}

/**
 * Triage summaries keyed by case.
 *
 * Cases still INGESTING or CORRELATING map to `null` on purpose — the pipeline
 * has not scored them yet, so the panel shows a pending state rather than
 * inventing findings.
 */
export const TRIAGE_BY_CASE = {
  'CASE-2026-0147': AI_TRIAGE,
  'CASE-2026-0139': AI_TRIAGE_0139,
  'CASE-2026-0143': null,
  'CASE-2026-0136': null,
}

export const RECENT_ACTIVITY = [
  {
    id: 'A-9012',
    kind: 'finding',
    severity: SEVERITY.CRITICAL,
    message: 'Encoded PowerShell execution flagged on FIN-WKS-014',
    caseId: 'CASE-2026-0147',
    actor: 'Triage engine',
    relative: '4m ago',
    at: '2026-08-26T14:28:00+05:30',
  },
  {
    id: 'A-9011',
    kind: 'ioc',
    severity: SEVERITY.HIGH,
    message: '3 new indicators extracted from capture-014.pcap',
    caseId: 'CASE-2026-0147',
    actor: 'Triage engine',
    relative: '17m ago',
    at: '2026-08-26T14:15:00+05:30',
  },
  {
    id: 'A-9010',
    kind: 'ingest',
    severity: SEVERITY.INFO,
    message: 'Evidence source CI-AGT-009.dd verified — SHA-256 hash match',
    caseId: 'CASE-2026-0136',
    actor: 'INV-2338',
    relative: '31m ago',
    at: '2026-08-26T14:01:00+05:30',
  },
  {
    id: 'A-9009',
    kind: 'note',
    severity: SEVERITY.INFO,
    message: 'Examiner note added to finding F-1044 (Registry Persistence)',
    caseId: 'CASE-2026-0147',
    actor: 'INV-2291',
    relative: '52m ago',
    at: '2026-08-26T13:40:00+05:30',
  },
  {
    id: 'A-9008',
    kind: 'escalation',
    severity: SEVERITY.CRITICAL,
    message: 'CASE-2026-0139 escalated to Anti-Cyber Terrorism review',
    caseId: 'CASE-2026-0139',
    actor: 'INV-2291',
    relative: '2h ago',
    at: '2026-08-26T12:30:00+05:30',
  },
  {
    id: 'A-9007',
    kind: 'finding',
    severity: SEVERITY.HIGH,
    message: 'Autorun key WinUpdateSvc correlated with unsigned binary',
    caseId: 'CASE-2026-0147',
    actor: 'Triage engine',
    relative: '3h ago',
    at: '2026-08-26T11:20:00+05:30',
  },
  {
    id: 'A-9006',
    kind: 'ingest',
    severity: SEVERITY.INFO,
    message: '5 log sets parsed from HR-LAP-072 — 213,408 artifacts scored',
    caseId: 'CASE-2026-0143',
    actor: 'Triage engine',
    relative: '5h ago',
    at: '2026-08-26T09:45:00+05:30',
  },
]

export const NOTIFICATIONS = [
  {
    id: 'N-31',
    severity: SEVERITY.CRITICAL,
    title: 'Active C2 beaconing on FIN-WKS-014',
    caseId: 'CASE-2026-0147',
    relative: '4m ago',
  },
  {
    id: 'N-30',
    severity: SEVERITY.HIGH,
    title: '6 critical findings await review',
    caseId: 'CASE-2026-0147',
    relative: '22m ago',
  },
  {
    id: 'N-29',
    severity: SEVERITY.INFO,
    title: 'Ingestion complete for CI-AGT-009.dd',
    caseId: 'CASE-2026-0136',
    relative: '31m ago',
  },
]
