/**
 * Mock case records for the Case Workspace (/cases/:caseId).
 *
 * IMPORTANT: every value in this file is authored sample data for UI
 * development. No model, parser or threat-intel feed produced any of it — the
 * narratives and recommendations were written by hand. Timestamps are fixed
 * (rather than derived from the current clock) so the workspace renders
 * identically on every load; "now" is taken to be 2026-08-26T14:32+05:30, which
 * is what the relative labels in mockDashboard.js already assume.
 *
 * Shape: each record mirrors what a future `GET /api/cases/:caseId` would
 * return, so services/caseService.js can swap the source without any component
 * changing. Header counts mirror ACTIVE_INVESTIGATIONS in mockDashboard.js — the
 * dashboard row and the workspace header must never disagree about a case.
 *
 * Two different severity notions coexist here on purpose:
 *   - `severity` on the case is the examiner's classification of the case as a
 *     whole, which is why CASE-2026-0147 reads HIGH at a score of 87.
 *   - `artifactPriorities` applies the ml/risk_scorer.py bands (CRITICAL >= 75,
 *     HIGH >= 50, MEDIUM >= 25, LOW otherwise) to individual scored records.
 * `composition` reproduces the real weighting (anomaly 60% + rule 40%) so the
 * headline score stays traceable to the pipeline that will eventually produce it.
 *
 * Cases the pipeline has not scored yet carry `assessment: null` and no
 * findings, matching how AiTriagePanel already refuses to invent results for
 * INGESTING and CORRELATING cases.
 */

import { SEVERITY } from './mockDashboard.js'

/**
 * @typedef {object} CaseRecord
 * @property {string} id
 * @property {string} title           Short label, identical to the dashboard row.
 * @property {string} description     Why the case exists, one or two sentences.
 * @property {number} threatScore     0-100 composite.
 * @property {string} severity        Examiner classification of the whole case.
 * @property {string} status          Pipeline state (ANALYZING, ESCALATED, ...).
 * @property {number} progress        Percent triaged.
 * @property {string} examiner
 * @property {string} openedAt        ISO 8601.
 * @property {string} primaryHost
 * @property {{ relative: string, at: string, label: string }} lastActivity
 * @property {{ evidence: number, artifacts: number, iocs: number, criticalFindings: number }} counts
 * @property {{ narrative: string, facts: Array<object> }} summary
 * @property {object|null} assessment `null` until the pipeline has scored the case.
 * @property {Array<object>} findings
 * @property {object} recommendation
 * @property {Array<object>} activity Same shape ActivityFeed consumes.
 * @property {{ sources: Array<object>, pending: Array<object> }} evidence
 */

/** @type {CaseRecord} */
const CASE_0147 = {
  id: 'CASE-2026-0147',
  title: 'Ransomware staging on finance workstation',
  description:
    'Suspected pre-encryption ransomware staging on a Finance department workstation, opened after the endpoint team escalated an alert on encoded PowerShell. Host is still powered on and connected.',
  threatScore: 87,
  severity: SEVERITY.HIGH,
  status: 'ANALYZING',
  progress: 68,
  examiner: 'INV-2291',
  openedAt: '2026-08-24T09:12:00+05:30',
  primaryHost: 'FIN-WKS-014',
  lastActivity: {
    relative: '4 minutes ago',
    at: '2026-08-26T14:28:00+05:30',
    label: 'Encoded PowerShell execution flagged',
  },
  counts: {
    evidence: 8,
    artifacts: 486_112,
    iocs: 41,
    criticalFindings: 6,
  },

  summary: {
    narrative:
      'An encoded PowerShell command launched by a Word child process on FIN-WKS-014 at 02:14 on 24 Aug wrote an unsigned binary to a world-writable path, added a Run-key autorun pointing at it, disabled Defender real-time protection and began beaconing to 45.61.x.x:8443 at 60-second intervals. Shadow copies were deleted and a ransom note was written into two user profiles, but no bulk file encryption has been observed — the intrusion appears to have been interrupted at the staging step. Two adjacent hosts contacted the same destination and are queued for acquisition.',
    facts: [
      { label: 'Opened', value: '24 Aug 2026, 09:12' },
      { label: 'Examiner', value: 'INV-2291', mono: true },
      { label: 'Primary host', value: 'FIN-WKS-014', mono: true },
      { label: 'First observed activity', value: '24 Aug 2026, 02:14:37' },
      { label: 'Detection lag', value: '6 h 57 m' },
      { label: 'Hosts in scope', value: '3' },
      { label: 'Accounts in scope', value: 'jmenon, svc_backup', mono: true },
      { label: 'Triaged', value: '68%' },
    ],
  },

  assessment: {
    scoredAt: '2026-08-26T14:28:00+05:30',
    modelLabel: 'Isolation Forest + rule ensemble',
    confidence: 0.92,
    // Reproduces risk = anomaly * 0.6 + rule * 0.4 from ml/risk_scorer.py.
    composition: [
      {
        id: 'ml-anomaly',
        label: 'ML anomaly score',
        detail: 'IsolationForest decision function, normalised to 0-100',
        score: 84.2,
        weight: 0.6,
        contribution: 50.5,
      },
      {
        id: 'rule-engine',
        label: 'Rule engine score',
        detail: '9 of 14 artifact rules matched',
        score: 91.2,
        weight: 0.4,
        contribution: 36.5,
      },
    ],
    artifactPriorities: [
      { severity: SEVERITY.CRITICAL, count: 312 },
      { severity: SEVERITY.HIGH, count: 1_847 },
      { severity: SEVERITY.MEDIUM, count: 21_406 },
      { severity: SEVERITY.LOW, count: 462_547 },
    ],
    iocBreakdown: [
      { label: 'File hashes', count: 9 },
      { label: 'IP addresses', count: 18 },
      { label: 'Domains', count: 11 },
      { label: 'Registry keys', count: 3 },
    ],
    // Tactic coverage is not a severity, so it renders neutral. `state` is one
    // of observed | partial | none.
    coverage: [
      { tactic: 'Initial Access', state: 'observed', note: 'T1566.001 · macro document' },
      { tactic: 'Execution', state: 'observed', note: 'T1059.001 · encoded PowerShell' },
      { tactic: 'Defense Evasion', state: 'observed', note: 'T1562.001 · Defender disabled' },
      { tactic: 'Persistence', state: 'observed', note: 'T1547.001 · Run key' },
      { tactic: 'Command & Control', state: 'observed', note: 'T1571 · non-standard port' },
      { tactic: 'Impact', state: 'partial', note: 'T1490 · shadow copies deleted, no encryption' },
      { tactic: 'Exfiltration', state: 'none', note: 'No outbound volume above baseline' },
    ],
  },

  // F-1042 to F-1045 are carried over verbatim from AI_TRIAGE in
  // mockDashboard.js so the dashboard preview and the workspace never disagree.
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
      reviewed: false,
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
      reviewed: false,
    },
    {
      id: 'F-1046',
      title: 'Shadow Copy Deletion',
      severity: SEVERITY.CRITICAL,
      riskScore: 89,
      confidence: 0.95,
      source: 'Security.evtx · Event 4688 (vssadmin)',
      host: 'FIN-WKS-014',
      observedAt: '2026-08-24T02:21:53+05:30',
      technique: { id: 'T1490', name: 'Inhibit System Recovery' },
      rationale:
        'vssadmin delete shadows /all /quiet run by the same process tree as the loader, removing the local rollback path before encryption.',
      artifactType: 'system_log',
      reviewed: false,
    },
    {
      id: 'F-1047',
      title: 'Defender Real-Time Protection Disabled',
      severity: SEVERITY.CRITICAL,
      riskScore: 86,
      confidence: 0.93,
      source: 'SOFTWARE\\...\\Real-Time Protection\\DisableRealtimeMonitoring',
      host: 'FIN-WKS-014',
      observedAt: '2026-08-24T02:17:26+05:30',
      technique: { id: 'T1562.001', name: 'Disable or Modify Tools' },
      rationale:
        'Policy value set to 1 by a non-administrative process 84 seconds after the loader was written; no matching change ticket.',
      artifactType: 'registry',
      reviewed: false,
    },
    {
      id: 'F-1048',
      title: 'Ransom Note Staged in Profile Directories',
      severity: SEVERITY.CRITICAL,
      riskScore: 82,
      confidence: 0.9,
      source: 'C:\\Users\\jmenon\\Desktop\\READ_ME_RECOVER.txt',
      host: 'FIN-WKS-014',
      observedAt: '2026-08-24T02:24:11+05:30',
      technique: { id: 'T1486', name: 'Data Encrypted for Impact' },
      rationale:
        'Identical note written to two profiles with a contact address and a wallet identifier. No encrypted file extensions present yet, which places the intrusion before the encryption step.',
      artifactType: 'file',
      reviewed: false,
    },
    {
      id: 'F-1049',
      title: 'Archive Utility Written to Public Path',
      severity: SEVERITY.CRITICAL,
      riskScore: 79,
      confidence: 0.87,
      source: 'C:\\Users\\Public\\7za.exe',
      host: 'FIN-WKS-014',
      observedAt: '2026-08-24T02:18:40+05:30',
      technique: { id: 'T1560.001', name: 'Archive via Utility' },
      rationale:
        'Standalone archive binary dropped alongside the loader and never present in the software inventory for this host.',
      artifactType: 'file',
      reviewed: false,
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
      reviewed: true,
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
      reviewed: true,
    },
  ],

  recommendation: {
    urgency: SEVERITY.CRITICAL,
    headline: 'Isolate FIN-WKS-014 and capture volatile memory before any reboot',
    window: 'Within 1 hour',
    owner: 'INV-2291',
    steps: [
      'Capture RAM with a write-blocked acquisition tool while the host is still running.',
      'Export the NTUSER.DAT Run key and the Defender policy key before containment alters them.',
      'Network-isolate the host at the switch port and leave it powered on.',
      'Block 45.61.x.x:8443 at the perimeter, then sweep FIN-WKS-021 and FIN-SRV-003 for the same destination.',
    ],
    rationale:
      'Persistence is established and the beacon is still answering, so the operator can act on the host at any time. Shadow copies are already deleted and a ransom note is staged, which puts the intrusion one step short of encryption. A reboot or a power-off destroys the loader configuration and any key material that exists only in memory, and a second host contacting the same destination indicates more than one foothold — containing this workstation alone would leave the intrusion live.',
  },

  activity: [
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
      id: 'A-9004',
      kind: 'finding',
      severity: SEVERITY.CRITICAL,
      message: 'Shadow copy deletion detected via vssadmin (F-1046)',
      caseId: 'CASE-2026-0147',
      actor: 'Triage engine',
      relative: '5h ago',
      at: '2026-08-26T09:35:00+05:30',
    },
    {
      id: 'A-9002',
      kind: 'ingest',
      severity: SEVERITY.INFO,
      message: 'Evidence source FIN-WKS-014-D.e01 verified — SHA-256 hash match',
      caseId: 'CASE-2026-0147',
      actor: 'INV-2291',
      relative: '8h ago',
      at: '2026-08-26T06:50:00+05:30',
    },
    {
      id: 'A-9001',
      kind: 'ingest',
      severity: SEVERITY.INFO,
      message: 'Case opened and evidence intake started',
      caseId: 'CASE-2026-0147',
      actor: 'INV-2291',
      relative: '2d ago',
      at: '2026-08-24T09:12:00+05:30',
    },
  ],

  evidence: {
    sources: [
      {
        id: 'EV-0147-01',
        label: 'FIN-WKS-014-C.e01',
        kind: 'image',
        detail: 'C: system volume',
        size: '476 GB',
        acquiredAt: '2026-08-24T10:02:00+05:30',
        custodian: 'INV-2291',
        sha256: '4f2c9a7d1b8e0c356af91d2e7c48b60539ea1f7c2d6b485901ac3e7f9d21b846',
        integrity: 'HASH MATCH',
        state: 'PARSED',
      },
      {
        id: 'EV-0147-02',
        label: 'FIN-WKS-014-D.e01',
        kind: 'image',
        detail: 'D: data volume',
        size: '931 GB',
        acquiredAt: '2026-08-24T13:41:00+05:30',
        custodian: 'INV-2291',
        sha256: '8b1e05c73d29af640c58b1e792da4f0361c7e8b24a0d9f357e2b16c805d3a94f',
        integrity: 'HASH MATCH',
        state: 'INDEXING',
      },
      {
        id: 'EV-0147-03',
        label: 'Security.evtx',
        kind: 'log',
        detail: 'Windows Security log',
        size: '84 MB',
        acquiredAt: '2026-08-24T10:18:00+05:30',
        custodian: 'INV-2291',
        sha256: 'c05a37f91e6b48d20937ac5eb8d10f642c9e75a34f08b1d763ea2c908d5f7b14',
        integrity: 'HASH MATCH',
        state: 'PARSED',
      },
      {
        id: 'EV-0147-04',
        label: 'System.evtx',
        kind: 'log',
        detail: 'Windows System log',
        size: '41 MB',
        acquiredAt: '2026-08-24T10:18:00+05:30',
        custodian: 'INV-2291',
        sha256: '1d74b0e95a2c8f3607be91d4c3620ad89f15e7b246c0d38a71eb5f290c84a6d3',
        integrity: 'HASH MATCH',
        state: 'PARSED',
      },
      {
        id: 'EV-0147-05',
        label: 'PowerShell%4Operational.evtx',
        kind: 'log',
        detail: 'PowerShell operational log',
        size: '22 MB',
        acquiredAt: '2026-08-24T10:19:00+05:30',
        custodian: 'INV-2291',
        sha256: '96ef2a08b4d75c132f80e6a917cb43d58a02f9e63d61b48c0e57a2fbd914630a',
        integrity: 'HASH MATCH',
        state: 'PARSED',
      },
      {
        id: 'EV-0147-06',
        label: 'NTUSER.DAT (jmenon)',
        kind: 'registry',
        detail: 'User registry hive',
        size: '12 MB',
        acquiredAt: '2026-08-24T10:24:00+05:30',
        custodian: 'INV-2291',
        sha256: '3a8d0169c72fb4e59d03a86b145ef0c728b9d43a6f01c25eb7a48d9053c6e1fb',
        integrity: 'HASH MATCH',
        state: 'PARSED',
      },
      {
        id: 'EV-0147-07',
        label: 'edge-proxy-20260824.log',
        kind: 'log',
        detail: 'Perimeter proxy log, 24 Aug',
        size: '318 MB',
        acquiredAt: '2026-08-25T09:05:00+05:30',
        custodian: 'INV-2338',
        sha256: '7e14c3b08f2a95d601db47eca35208f96c8e1b47d90f5a232b76c0e84159da3c',
        integrity: 'HASH MATCH',
        state: 'PARSED',
      },
      {
        id: 'EV-0147-08',
        label: 'capture-014.pcap',
        kind: 'capture',
        detail: 'Span capture, FIN VLAN',
        size: '1.4 GB',
        acquiredAt: '2026-08-25T11:30:00+05:30',
        custodian: 'INV-2338',
        sha256: 'd2039f7a65be18c40a7d532fe91c60b8374af0d91e8b25c6c0956d138b4f27ea',
        integrity: 'HASH MATCH',
        state: 'PARSED',
      },
    ],
    // Outstanding acquisitions are listed separately so they never inflate the
    // evidence count that the dashboard row also reports.
    pending: [
      {
        id: 'EV-0147-P1',
        label: 'Volatile memory (FIN-WKS-014)',
        reason:
          'Host still powered on — required before containment, see the recommendation above',
      },
      {
        id: 'EV-0147-P2',
        label: 'Disk image (FIN-WKS-021)',
        reason: 'Second host contacted the same C2 destination; acquisition not started',
      },
    ],
  },
}

/** @type {CaseRecord} */
const CASE_0139 = {
  id: 'CASE-2026-0139',
  title: 'Unauthorised database export, night shift',
  description:
    'A reporting service account exported 8.4 million rows from production outside its baseline window and staged a compressed archive locally. Escalated to Anti-Cyber Terrorism review.',
  threatScore: 91,
  severity: SEVERITY.CRITICAL,
  status: 'ESCALATED',
  progress: 92,
  examiner: 'INV-2291',
  openedAt: '2026-08-19T22:05:00+05:30',
  primaryHost: 'DB-PRD-002',
  lastActivity: {
    relative: '2 hours ago',
    at: '2026-08-26T12:30:00+05:30',
    label: 'Escalated to Anti-Cyber Terrorism review',
  },
  counts: {
    evidence: 6,
    artifacts: 391_774,
    iocs: 18,
    criticalFindings: 7,
  },

  summary: {
    narrative:
      'The svc_reporting account signed in from a workstation subnet at 23:38 on 19 Aug, was granted sysadmin minutes later, and ran a single query returning 8.4 million rows against tables it had never previously read. A 4.2 GB archive was written to D:\\Temp and a sustained 4.1 GB upload left the host over 443/tcp shortly after midnight. Audit rows covering the export window were then deleted and backup retention was cut from 35 days to 1. The account owner has confirmed they did not schedule the job.',
    facts: [
      { label: 'Opened', value: '19 Aug 2026, 22:05' },
      { label: 'Examiner', value: 'INV-2291', mono: true },
      { label: 'Primary host', value: 'DB-PRD-002', mono: true },
      { label: 'First observed activity', value: '19 Aug 2026, 23:38:04' },
      { label: 'Detection lag', value: '22 h 27 m' },
      { label: 'Hosts in scope', value: '2' },
      { label: 'Accounts in scope', value: 'svc_reporting', mono: true },
      { label: 'Triaged', value: '92%' },
    ],
  },

  assessment: {
    scoredAt: '2026-08-26T12:22:00+05:30',
    modelLabel: 'Isolation Forest + rule ensemble',
    confidence: 0.88,
    composition: [
      {
        id: 'ml-anomaly',
        label: 'ML anomaly score',
        detail: 'IsolationForest decision function, normalised to 0-100',
        score: 88.5,
        weight: 0.6,
        contribution: 53.1,
      },
      {
        id: 'rule-engine',
        label: 'Rule engine score',
        detail: '11 of 14 artifact rules matched',
        score: 94.75,
        weight: 0.4,
        contribution: 37.9,
      },
    ],
    artifactPriorities: [
      { severity: SEVERITY.CRITICAL, count: 604 },
      { severity: SEVERITY.HIGH, count: 3_118 },
      { severity: SEVERITY.MEDIUM, count: 34_902 },
      { severity: SEVERITY.LOW, count: 353_150 },
    ],
    iocBreakdown: [
      { label: 'File hashes', count: 3 },
      { label: 'IP addresses', count: 9 },
      { label: 'Domains', count: 5 },
      { label: 'Registry keys', count: 1 },
    ],
    coverage: [
      {
        tactic: 'Initial Access',
        state: 'partial',
        note: 'Valid account used, entry vector unresolved',
      },
      { tactic: 'Privilege Escalation', state: 'observed', note: 'T1098 · sysadmin granted' },
      { tactic: 'Defense Evasion', state: 'observed', note: 'T1070 · audit rows deleted' },
      { tactic: 'Persistence', state: 'observed', note: 'T1053.005 · scheduled job created' },
      { tactic: 'Collection', state: 'observed', note: 'T1213 · bulk row export' },
      { tactic: 'Exfiltration', state: 'observed', note: 'T1048 · 4.1 GB egress' },
      { tactic: 'Impact', state: 'partial', note: 'T1490 · retention shortened, no data loss yet' },
    ],
  },

  // F-0977 to F-0980 are carried over verbatim from AI_TRIAGE_0139.
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
      reviewed: true,
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
      reviewed: true,
    },
    {
      id: 'F-0981',
      title: 'Audit Rows Deleted After Export',
      severity: SEVERITY.CRITICAL,
      riskScore: 87,
      confidence: 0.91,
      source: 'audit_log · 11,204 rows removed',
      host: 'DB-PRD-002',
      observedAt: '2026-08-20T00:31:08+05:30',
      technique: { id: 'T1070', name: 'Indicator Removal' },
      rationale:
        'Deleted range covers exactly the export window. Sequence gap confirmed against the offline audit copy.',
      artifactType: 'system_log',
      reviewed: false,
    },
    {
      id: 'F-0982',
      title: 'Linked Server Added to External Host',
      severity: SEVERITY.CRITICAL,
      riskScore: 84,
      confidence: 0.86,
      source: 'sys.servers · EXTRPT01',
      host: 'DB-PRD-002',
      observedAt: '2026-08-19T23:52:03+05:30',
      technique: { id: 'T1505.001', name: 'SQL Stored Procedures' },
      rationale:
        'Linked server created pointing outside the datacentre range, with no corresponding change record.',
      artifactType: 'system_log',
      reviewed: false,
    },
    {
      id: 'F-0984',
      title: 'Privileged Role Granted to Service Account',
      severity: SEVERITY.CRITICAL,
      riskScore: 82,
      confidence: 0.93,
      source: 'audit_log · ALTER SERVER ROLE sysadmin',
      host: 'DB-PRD-002',
      observedAt: '2026-08-19T23:39:47+05:30',
      technique: { id: 'T1098', name: 'Account Manipulation' },
      rationale:
        'svc_reporting was added to sysadmin 103 seconds after logon; the account had held read-only rights for the previous 14 months.',
      artifactType: 'system_log',
      reviewed: false,
    },
    {
      id: 'F-0983',
      title: 'Backup Retention Shortened',
      severity: SEVERITY.CRITICAL,
      riskScore: 79,
      confidence: 0.88,
      source: 'msdb.backupset · retention 35d -> 1d',
      host: 'DB-PRD-002',
      observedAt: '2026-08-20T00:33:52+05:30',
      technique: { id: 'T1490', name: 'Inhibit System Recovery' },
      rationale:
        'Retention policy reduced immediately after the audit deletion, which would have aged out the remaining evidence within a day.',
      artifactType: 'system_log',
      reviewed: false,
    },
    {
      id: 'F-0985',
      title: 'Off-Hours Scheduled Job Created',
      severity: SEVERITY.CRITICAL,
      riskScore: 77,
      confidence: 0.85,
      source: 'msdb.sysjobs · rpt_nightly_v2',
      host: 'DB-PRD-002',
      observedAt: '2026-08-20T00:36:19+05:30',
      technique: { id: 'T1053.005', name: 'Scheduled Task/Job' },
      rationale:
        'New job duplicates the export query on a nightly schedule, owned by svc_reporting and disabled but not deleted.',
      artifactType: 'system_log',
      reviewed: false,
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
      reviewed: true,
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
      reviewed: true,
    },
  ],

  recommendation: {
    urgency: SEVERITY.CRITICAL,
    headline: 'Revoke svc_reporting credentials and freeze the export job',
    window: 'Immediately',
    owner: 'INV-2291',
    steps: [
      'Rotate the svc_reporting credential and remove it from sysadmin.',
      'Disable the rpt_nightly_v2 job and drop the EXTRPT01 linked server after imaging the msdb metadata.',
      'Restore backup retention to 35 days and preserve the offline audit copy covering 19-20 Aug.',
      'Confirm with the network team whether the 4.1 GB upload completed, and to which destination.',
    ],
    rationale:
      'The account still holds sysadmin and a scheduled job would repeat the export on its next run, so the same access remains available tonight. Audit rows were deleted and backup retention was cut to a single day, which gives the remaining evidence a short shelf life — restoring retention has to happen before anything else ages out. Whether this becomes a confirmed data breach depends entirely on whether the upload completed, so that answer also determines the notification obligations.',
  },

  activity: [
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
      id: 'A-8998',
      kind: 'finding',
      severity: SEVERITY.CRITICAL,
      message: 'Audit row deletion confirmed against the offline audit copy',
      caseId: 'CASE-2026-0139',
      actor: 'Triage engine',
      relative: '4h ago',
      at: '2026-08-26T10:12:00+05:30',
    },
    {
      id: 'A-8996',
      kind: 'note',
      severity: SEVERITY.INFO,
      message: 'Account owner statement recorded — job was not scheduled by them',
      caseId: 'CASE-2026-0139',
      actor: 'INV-2291',
      relative: '6h ago',
      at: '2026-08-26T08:40:00+05:30',
    },
    {
      id: 'A-8994',
      kind: 'ioc',
      severity: SEVERITY.HIGH,
      message: 'Egress destination added to the case indicator set',
      caseId: 'CASE-2026-0139',
      actor: 'Triage engine',
      relative: '1d ago',
      at: '2026-08-25T15:18:00+05:30',
    },
    {
      id: 'A-8990',
      kind: 'ingest',
      severity: SEVERITY.INFO,
      message: 'DB-PRD-002-mem.raw verified — SHA-256 hash match',
      caseId: 'CASE-2026-0139',
      actor: 'INV-2104',
      relative: '5d ago',
      at: '2026-08-21T11:02:00+05:30',
    },
    {
      id: 'A-8988',
      kind: 'ingest',
      severity: SEVERITY.INFO,
      message: 'Case opened and evidence intake started',
      caseId: 'CASE-2026-0139',
      actor: 'INV-2291',
      relative: '7d ago',
      at: '2026-08-19T22:05:00+05:30',
    },
  ],

  evidence: {
    sources: [
      {
        id: 'EV-0139-01',
        label: 'DB-PRD-002-sys.e01',
        kind: 'image',
        detail: 'System volume',
        size: '240 GB',
        acquiredAt: '2026-08-20T14:20:00+05:30',
        custodian: 'INV-2104',
        sha256: '5c8b02e1a4f7361d09e2c5b87d13fa04b6280c9e31d5a7f24e0bc86392af14d7',
        integrity: 'HASH MATCH',
        state: 'PARSED',
      },
      {
        id: 'EV-0139-02',
        label: 'DB-PRD-002-data.e01',
        kind: 'image',
        detail: 'Data volume',
        size: '2.1 TB',
        acquiredAt: '2026-08-20T22:47:00+05:30',
        custodian: 'INV-2104',
        sha256: '0f6a94c27b1e58d3c40a2f9685d7be011937ca48e2b05f6da83c17046d9fe25b',
        integrity: 'HASH MATCH',
        state: 'PARSED',
      },
      {
        id: 'EV-0139-03',
        label: 'DB-PRD-002-mem.raw',
        kind: 'image',
        detail: 'Volatile memory',
        size: '128 GB',
        acquiredAt: '2026-08-20T09:15:00+05:30',
        custodian: 'INV-2104',
        sha256: 'b3e70d5128ac96f4d105b8e76f39240ac78e1db5043a6f929b25c0e817d4a36f',
        integrity: 'HASH MATCH',
        state: 'PARSED',
      },
      {
        id: 'EV-0139-04',
        label: 'mssql_audit_20260819.xel',
        kind: 'log',
        detail: 'Offline audit copy, 19-20 Aug',
        size: '640 MB',
        acquiredAt: '2026-08-20T08:05:00+05:30',
        custodian: 'INV-2291',
        sha256: '6a2f81d094c3e7b51802af69bd570c342e91d8fa75b06c1ea4396f27c08bd51e',
        integrity: 'HASH MATCH',
        state: 'PARSED',
      },
      {
        id: 'EV-0139-05',
        label: 'Security.evtx (DB-PRD-002)',
        kind: 'log',
        detail: 'Windows Security log',
        size: '128 MB',
        acquiredAt: '2026-08-20T08:11:00+05:30',
        custodian: 'INV-2291',
        sha256: 'e504b7a13f2c9d680b71e4a5c9d3208f5647fb0e1a8dc93572e0b4f68d15c2a9',
        integrity: 'HASH MATCH',
        state: 'PARSED',
      },
      {
        id: 'EV-0139-06',
        label: 'capture-db02.pcap',
        kind: 'capture',
        detail: 'Datacentre egress capture',
        size: '3.8 GB',
        acquiredAt: '2026-08-21T10:30:00+05:30',
        custodian: 'INV-2338',
        sha256: '2c907e4bd13f65a88b40c2e907a51df3f96b280d4e3c7a1605d9be82b7401f6c',
        integrity: 'HASH MATCH',
        state: 'PARSED',
      },
    ],
    pending: [
      {
        id: 'EV-0139-P1',
        label: 'Perimeter NetFlow, 19-20 Aug',
        reason: 'Needed to confirm whether the 4.1 GB upload completed',
      },
    ],
  },
}

/**
 * CASE-2026-0143 — the correlation pass has not finished, so there is no scored
 * assessment and no ranked findings. The recommendation is a workflow step
 * rather than a response action.
 *
 * @type {CaseRecord}
 */
const CASE_0143 = {
  id: 'CASE-2026-0143',
  title: 'Credential harvesting via phishing payload',
  description:
    'A HR laptop opened an attachment that redirected to a credential-capture page. Log sets are being correlated to establish which accounts were entered and whether any were reused.',
  threatScore: 74,
  severity: SEVERITY.HIGH,
  status: 'CORRELATING',
  progress: 41,
  examiner: 'INV-2104',
  openedAt: '2026-08-22T16:40:00+05:30',
  primaryHost: 'HR-LAP-072',
  lastActivity: {
    relative: '38 minutes ago',
    at: '2026-08-26T13:54:00+05:30',
    label: 'Proxy log correlation pass started',
  },
  counts: {
    evidence: 6,
    artifacts: 213_408,
    iocs: 26,
    criticalFindings: 4,
  },

  summary: {
    narrative:
      'HR-LAP-072 opened an invoice attachment at 11:26 on 22 Aug that redirected through two hops to a credential-capture page imitating the internal portal. Proxy logs place four other hosts on the same redirect chain within the following hour. Rule hits are recorded for the redirect domains and for a token replay attempt, but the correlation pass that links those hits to specific accounts is still running, so no ranked assessment exists yet.',
    facts: [
      { label: 'Opened', value: '22 Aug 2026, 16:40' },
      { label: 'Examiner', value: 'INV-2104', mono: true },
      { label: 'Primary host', value: 'HR-LAP-072', mono: true },
      { label: 'First observed activity', value: '22 Aug 2026, 11:26:04' },
      { label: 'Detection lag', value: '5 h 14 m' },
      { label: 'Hosts in scope', value: '5' },
      { label: 'Accounts in scope', value: 'Under review' },
      { label: 'Triaged', value: '41%' },
    ],
  },

  assessment: null,
  findings: [],

  recommendation: {
    urgency: SEVERITY.HIGH,
    headline: 'Finish the proxy log correlation pass, but reset exposed accounts first',
    window: 'Today',
    owner: 'INV-2104',
    steps: [
      'Force a password reset for every account observed on the capture page, ahead of the ranking step.',
      'Complete the correlation pass across the five hosts on the redirect chain.',
      'Add the two redirect domains to the perimeter block list.',
    ],
    rationale:
      'Four critical rule hits are recorded but not yet tied to accounts, so ranking them now would produce findings nobody can act on — the correlation pass has to finish before triage means anything. Credential theft is time-sensitive in a way that artifact review is not, though: every hour before a reset is another hour a captured password stays valid, so the reset should not wait for that pass to complete.',
  },

  activity: [
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
    {
      id: 'A-8992',
      kind: 'ioc',
      severity: SEVERITY.HIGH,
      message: '2 redirect domains added to the case indicator set',
      caseId: 'CASE-2026-0143',
      actor: 'Triage engine',
      relative: '1d ago',
      at: '2026-08-25T16:22:00+05:30',
    },
    {
      id: 'A-8991',
      kind: 'note',
      severity: SEVERITY.INFO,
      message: 'User interview recorded — attachment opened from an invoice thread',
      caseId: 'CASE-2026-0143',
      actor: 'INV-2104',
      relative: '2d ago',
      at: '2026-08-24T14:10:00+05:30',
    },
    {
      id: 'A-8989',
      kind: 'ingest',
      severity: SEVERITY.INFO,
      message: 'Case opened and evidence intake started',
      caseId: 'CASE-2026-0143',
      actor: 'INV-2104',
      relative: '4d ago',
      at: '2026-08-22T16:40:00+05:30',
    },
  ],

  evidence: {
    sources: [
      {
        id: 'EV-0143-01',
        label: 'HR-LAP-072.e01',
        kind: 'image',
        detail: 'C: system volume',
        size: '488 GB',
        acquiredAt: '2026-08-22T19:05:00+05:30',
        custodian: 'INV-2104',
        sha256: '8f31a06d52b7ce94c60e83b11d4f7205a9082e6c3b5d10fa7e4c69b30a2df851',
        integrity: 'HASH MATCH',
        state: 'INDEXING',
      },
      {
        id: 'EV-0143-02',
        label: 'Security.evtx (HR-LAP-072)',
        kind: 'log',
        detail: 'Windows Security log',
        size: '62 MB',
        acquiredAt: '2026-08-22T19:12:00+05:30',
        custodian: 'INV-2104',
        sha256: '41b9d5e00c68a37f92e4b1d8560af92cd8073b6e2f15c40ab96d8e27c3054f1b',
        integrity: 'HASH MATCH',
        state: 'PARSED',
      },
      {
        id: 'EV-0143-03',
        label: 'edge-proxy-20260822.log',
        kind: 'log',
        detail: 'Perimeter proxy log, 22 Aug',
        size: '402 MB',
        acquiredAt: '2026-08-23T09:40:00+05:30',
        custodian: 'INV-2338',
        sha256: '9d0c53f86e2a8147b3f09d5c02c6be7148a1d3e9f57b02641c8e97da350bf42e',
        integrity: 'HASH MATCH',
        state: 'PARSED',
      },
      {
        id: 'EV-0143-04',
        label: 'mail-gateway-20260822.log',
        kind: 'log',
        detail: 'Mail gateway transport log',
        size: '96 MB',
        acquiredAt: '2026-08-23T09:44:00+05:30',
        custodian: 'INV-2338',
        sha256: '07eb4a12c9d3805f65b2ea973f01c8d4b14e76a08d52301ce6b9af432701d5c8',
        integrity: 'HASH MATCH',
        state: 'PARSED',
      },
      {
        id: 'EV-0143-05',
        label: 'capture-hr-072.pcap',
        kind: 'capture',
        detail: 'Endpoint capture, HR VLAN',
        size: '740 MB',
        acquiredAt: '2026-08-23T15:20:00+05:30',
        custodian: 'INV-2338',
        sha256: '5b81f36c0a4d972ec815b0f7e2360d597a94cb181f6023ed4dc5a8708e310b2f',
        integrity: 'HASH MATCH',
        state: 'QUEUED',
      },
      {
        id: 'EV-0143-06',
        label: 'capture-hr-portal.pcap',
        kind: 'capture',
        detail: 'Portal front-end capture',
        size: '1.1 GB',
        acquiredAt: '2026-08-24T10:05:00+05:30',
        custodian: 'INV-2338',
        sha256: 'a6072b9d4e15c8f320db6a079c3f14e8b750d29a6108ef35d34ab01672fc985e',
        integrity: 'HASH MATCH',
        state: 'QUEUED',
      },
    ],
    pending: [
      {
        id: 'EV-0143-P1',
        label: 'Identity provider sign-in logs, 22-24 Aug',
        reason: 'Required to establish which accounts were entered on the capture page',
      },
    ],
  },
}

/**
 * CASE-2026-0136 — evidence is still being ingested. Nothing has been scored, so
 * the workspace shows acquisition state and nothing else.
 *
 * @type {CaseRecord}
 */
const CASE_0136 = {
  id: 'CASE-2026-0136',
  title: 'Lateral movement across build agents',
  description:
    'Repeated authentication from one build agent to three others outside the pipeline schedule. Evidence intake started this morning and artifact extraction is still running.',
  threatScore: 52,
  severity: SEVERITY.MEDIUM,
  status: 'INGESTING',
  progress: 17,
  examiner: 'INV-2338',
  openedAt: '2026-08-26T08:55:00+05:30',
  primaryHost: 'CI-AGT-009',
  lastActivity: {
    relative: '11 minutes ago',
    at: '2026-08-26T14:21:00+05:30',
    label: 'Artifact extraction running on CI-AGT-009.dd',
  },
  counts: {
    evidence: 2,
    artifacts: 47_260,
    iocs: 5,
    criticalFindings: 1,
  },

  summary: {
    narrative:
      'CI-AGT-009 authenticated to three sibling build agents 41 times between 03:10 and 04:55 on 26 Aug, none of which corresponds to a scheduled pipeline run. The shared pipeline service account was used throughout. Evidence intake began at 08:55 and artifact extraction is 17% complete, so nothing has been scored and no findings have been ranked.',
    facts: [
      { label: 'Opened', value: '26 Aug 2026, 08:55' },
      { label: 'Examiner', value: 'INV-2338', mono: true },
      { label: 'Primary host', value: 'CI-AGT-009', mono: true },
      { label: 'First observed activity', value: '26 Aug 2026, 03:10:22' },
      { label: 'Detection lag', value: '5 h 45 m' },
      { label: 'Hosts in scope', value: '4' },
      { label: 'Accounts in scope', value: 'svc_pipeline', mono: true },
      { label: 'Triaged', value: '17%' },
    ],
  },

  assessment: null,
  findings: [],

  recommendation: {
    urgency: SEVERITY.MEDIUM,
    headline: 'Acquire the three sibling build agents before extraction completes',
    window: 'Within 24 hours',
    owner: 'INV-2338',
    steps: [
      'Image CI-AGT-010, CI-AGT-011 and CI-AGT-014 while their disks still hold the session artifacts.',
      'Export the pipeline scheduler history to establish which runs were legitimate.',
      'Hold the svc_pipeline credential rotation until acquisition finishes, so live sessions are not destroyed.',
    ],
    rationale:
      'Build agents are routinely re-imaged between jobs, so the window to acquire the three destination hosts is short and closes on its own. Rotating the shared credential first would tear down the sessions that show where the movement went, which is the one thing the current evidence cannot answer — so on this case acquisition has to come before containment.',
  },

  activity: [
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
      id: 'A-9005',
      kind: 'ingest',
      severity: SEVERITY.INFO,
      message: 'Artifact extraction started — 47,260 records so far',
      caseId: 'CASE-2026-0136',
      actor: 'Triage engine',
      relative: '4h ago',
      at: '2026-08-26T10:18:00+05:30',
    },
    {
      id: 'A-9003',
      kind: 'ingest',
      severity: SEVERITY.INFO,
      message: 'Case opened and evidence intake started',
      caseId: 'CASE-2026-0136',
      actor: 'INV-2338',
      relative: '6h ago',
      at: '2026-08-26T08:55:00+05:30',
    },
  ],

  evidence: {
    sources: [
      {
        id: 'EV-0136-01',
        label: 'CI-AGT-009.dd',
        kind: 'image',
        detail: 'Full disk, build agent',
        size: '256 GB',
        acquiredAt: '2026-08-26T09:40:00+05:30',
        custodian: 'INV-2338',
        sha256: '3e5a08c7b96d21f47c0e4ab918f3d60520a7ce8bdf46190394b5c72e0d8a1f63',
        integrity: 'HASH MATCH',
        state: 'INDEXING',
      },
      {
        id: 'EV-0136-02',
        label: 'Security.evtx (CI-AGT-009)',
        kind: 'log',
        detail: 'Windows Security log',
        size: '58 MB',
        acquiredAt: '2026-08-26T09:52:00+05:30',
        custodian: 'INV-2338',
        sha256: 'c81d6f053a72be94e0578c1d46b90af28d21e6c375409bfa1b6ed382297c05e4',
        integrity: 'HASH MATCH',
        state: 'INDEXING',
      },
    ],
    pending: [
      {
        id: 'EV-0136-P1',
        label: 'Disk images (CI-AGT-010, -011, -014)',
        reason: 'Destination hosts for the observed authentications; not yet acquired',
      },
      {
        id: 'EV-0136-P2',
        label: 'Pipeline scheduler history',
        reason: 'Needed to separate scheduled runs from the 41 unexplained authentications',
      },
    ],
  },
}

/** Case records keyed by case ID. Keys match ACTIVE_INVESTIGATIONS. */
export const CASES_BY_ID = {
  'CASE-2026-0147': CASE_0147,
  'CASE-2026-0139': CASE_0139,
  'CASE-2026-0143': CASE_0143,
  'CASE-2026-0136': CASE_0136,
}

export const CASE_IDS = Object.keys(CASES_BY_ID)
