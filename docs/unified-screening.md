# Unified evidence screening (Issue 5)

The three intake endpoints reuse one versioned screening orchestration layer in
`backend/screening.py`. Existing artifact, model, disk-scan and custody fields are
retained. `screening_result` is saved with ingestion history and each case evidence
source; artifacts retain evidence SHA-256 and scanner coverage. Historical cases
without this field display “coverage was not recorded”, never a clean verdict.

| Evidence | Validation / parser | YARA scope | Forensic rules | ML policy |
|---|---|---|---|---|
| Raw disk image | TSK filesystem probe; real FAT12 integration fixture verified | Actual bounded embedded file streams, never substituted whole-image signatures | File metadata + content indicators | Existing EMBER on supported, completely readable PE bytes |
| Standalone PE | DOS offset, PE signature, headers, machine, subsystem, section bounds | Complete individual file bytes within limit | Existing file rules and YARA review indicator | Existing native I386 PE32 / AMD64 PE32+ EXE/DLL classifier; managed CLR, ARM and drivers outside verified scope |
| CICIDS2017-compatible CSV | CSV structure, ordered 11-feature numeric contract | Supplementary uploaded CSV bytes only | Existing network rules | Explicit selected frozen XGBoost or Isolation Forest; no fallback or fitting |
| CSE-CIC-IDS2018 CSV | Existing explicit adapter, invalid-row exclusions, conditional feature compatibility | Supplementary uploaded CSV bytes only | Existing network rules | Same frozen selected detector / threshold; historical external metrics unchanged |
| PCAP / PCAPNG | Capture magic and Scapy packet reader | Supplementary capture-container bytes only | Rules on measured IPv4 address-pair packet summaries | NOT_APPLICABLE: these summaries do not establish CICFlowMeter feature equivalence |
| Native EVTX | `ElfFile` signature and python-evtx records | Container only; no inferred event association | Event identities, login hour when present, audit-clear and service-install review indicators | Network and PE models NOT_APPLICABLE |
| Event CSV / JSON / XML export | Selected export schema / existing parser | Uploaded export container only | Existing event rules + audit-clear/service-install indicators | NOT_APPLICABLE |
| Native registry hive | `regf` signature and python-registry traversal | Hive container only; no inferred value association | Registry key rules | NOT_APPLICABLE |
| Registry .reg / CSV / JSON export | Export structure / existing parser | Uploaded export container only | Registry key rules | NOT_APPLICABLE |
| File inventory CSV / JSON | Inventory schema / existing parser | Inventory container only, **not files named in it** | Metadata rules only | NOT_APPLICABLE: inventory rows do not provide executable content |
| Other input | Explicit rejection with error/status | No successful scan claimed | No fabricated findings | No inference |

Raw/native PE signatures take precedence over the selected endpoint or suffix.
CSV exports use header/record validation; JSON/XML require a selected export type.
Disk suffixes request a real filesystem probe; a suffix never proves an image is
supported. E01/EWF, deleted recovery, alternate streams and other TSK filesystems
are not newly verified by Issue 5. No evidence binary is executed or imported.

## Contract and coverage

Successful intake adds `schema_version`, `evidence_type`, `evidence_sha256`,
`overall_scan_status`, `screening`, `findings`, `coverage` and `warnings`.
`screening` contains `yara`, `forensic_rules`, `network_ml`, `pe_ml` entries with
scanner/version/identifier, applicability, status, input scope, examined/skipped
counts, finding units/counts, measured duration and reasons. Engine-native raw
statuses remain available in existing artifact fields.

| State | Meaning |
|---|---|
| COMPLETED | The declared applicable scope ran; zero indicators does not establish safety |
| PARTIAL | Exclusions, upstream truncation/failure, unavailable applicable checks, or incomplete enumeration |
| NOT_APPLICABLE | No verified input contract for this mechanism / representation |
| UNAVAILABLE | Dependency, deployment-disabled engine, missing rules or model unavailable |
| SKIPPED_LIMIT | Declared scope was not scanned because of a resource limit |
| INVALID_INPUT | Structural/schema rejection; no successful analysis claimed |
| FAILED | Analysis/worker/compilation failed; no negative verdict claimed |

Modules aggregate per-artifact native outcomes. Overall COMPLETED requires all
applicable modules completed and disk enumeration completed. Rejections have an
explicit overall error status. When enumeration stops, the remaining population is
unknown: `skipped_count_exact=false` and the reason disclose this; zero known
skips must not be read as zero remaining files/values. Finding detail caps expose
total and returned counts; all scored artifact rows are still stored. YARA counts
matched rules; other modules count flagged records / attack decisions / malicious
predictions as specified by `findings_unit`.

## Limits and failure handling

Deployment defaults: upload 128 MiB; supplementary YARA 16 MiB; generic/native
host parser input 16 MiB; standalone PE ML at most 2 MiB; 100,000 records (or packets
for native captures); 1,000 screening finding details; YARA timeout 10 seconds;
parser worker timeout 60 seconds. PE inference retains its existing killable
worker and 20-second default. Disk analysis retains existing file count, byte and
cooperative duration limits. Uploaded bytes are read-only after intake and removed
from the temporary upload location after processing; original evidence is not
retained by the application. SHA-256 is streamed before parsing.

Use application `SCREENING_LIMITS` overrides, or production environment settings
`SCREENING_MAX_YARA_BYTES`, `SCREENING_MAX_PARSE_BYTES`, `SCREENING_MAX_PE_BYTES`,
`SCREENING_MAX_RECORDS`, `SCREENING_MAX_FINDINGS`, `SCREENING_YARA_TIMEOUT`,
`SCREENING_MAX_PARSER_SECONDS`. Values must be positive integers. Native host
parsers check a cooperative 55-second deadline and execute in a worker that is
terminated at the configured outer deadline. These byte/process limits are not
an operating-system memory quota or a global concurrent-job quota.

`SCREENING_YARA_ENABLED=false` explicitly disables YARA, including embedded-file
scanning. `YARA_RULES_DIR` is administrator configuration, never uploaded code.
Only locally reviewed rules should be configured. Rules load deterministically
with unique path-derived namespaces and content-based ruleset IDs. Missing rules,
compiler errors and timeouts remain visible; matching identical namespace/rule
pairs on one raw container is deduplicated. A skipped oversized raw target is not
partially prefix-scanned and then labeled complete.
Dependency/deployment availability is checked before byte eligibility. A host
without YARA reports UNAVAILABLE, including when the same input also exceeds its
scan byte limit; it cannot truthfully claim the unavailable scanner ran.

Native parser errors/limits remain visible. Registry values exceeding 16,384
characters are marked truncated; unreadable value data is marked and coverage
becomes partial. Capture parsing streams packets; non-IPv4 exclusions and packet
limits are reported. A zero-duration capture summary omits rates instead of
inventing rates from an epsilon denominator.

## Risk policy

Existing network 60/40 and PE maximum-floor behavior are retained; no model,
threshold or scaler is changed. Supervised scores remain uncalibrated model
outputs. Source rules and ML predictions remain separate in findings.

An existing file-level YARA indicator contributes the existing 25-point rule
review indicator. Supplementary container YARA has a separate MEDIUM review
floor of 25, recorded against the container. It cannot be attributed to a flow,
event or registry value. Case maximum risk includes this floor without adding it
to every record or double-counting an independent PE malicious review floor.
Missing scanners never subtract risk. Risk bands (25/50/75) are project triage
policy, **not CVSS ratings**.

Two targeted rule corrections: missing packet mean no longer defaults to a
suspicious zero; autorun key matching uses exact Run/RunOnce/Autorun path segments
instead of substrings such as “Pruning”. New host review indicators: Event 1102
audit log cleared = 90 rule points, Event 7045 service installed = 60. They signal
review, not proof of compromise. Native login-hour rules require a login event
and timestamp. Existing exported event normalization is retained; its elevated
context indicators are not proof that privilege escalation occurred.

## Reproduction

Prerequisites: the documented Python/native environment, Node dependencies,
verified model downloads (Issues 2/3), approved cleaned CICIDS2017 source/cleaning
ledger, and the existing real Issue 3/4 demonstration fixtures. No model training
or full external benchmark rerun is required.

```powershell
rtk proxy .venv/Scripts/python.exe -m scripts.acquire_issue5_fixtures
# If the Issue 3 CSV must be reconstructed, read the approved source by published indices:
rtk proxy .venv/Scripts/python.exe -m scripts.prepare_issue5_network_demo
# Optional external-fixture reconstruction from the already acquired official source files:
rtk proxy .venv/Scripts/python.exe -c "from scripts.prepare_external_demo import main; main(output_root='test-results/issue-5',scratch='.test-artifacts/issue5/external-demo')"
# In a separate terminal, only if dedicated test MongoDB is not running:
rtk proxy 'C:/Program Files/MongoDB/Server/9.0/bin/mongod.exe' --dbpath .test-artifacts/issue5/mongo --port 27018 --bind_ip 127.0.0.1
rtk proxy .venv/Scripts/python.exe -m scripts.verify_issue5
rtk proxy .venv/Scripts/python.exe -m scripts.render_issue5_reports
rtk proxy .venv/Scripts/python.exe -m pytest -q --no-training --run-integration
rtk proxy npm --prefix frontend run check
rtk proxy .venv/Scripts/python.exe scripts/check.py
```

Create the named empty MongoDB data directory before its first start; never reuse
production DB files. Verification owns a new UUID database, checks roundtrips,
hashes and reports, then stops its HTTP server. Full API responses, PDFs, raw host
records and generated evidence stay under ignored `.test-artifacts/issue5/`.
Public evidence under `test-results/issue-5/` contains coverage/summary metadata
and controlled synthetic PDF renders, not raw upstream host records or datasets.

## Browser acceptance

**UNVERIFIED**. The last permitted browser access reported exactly: “Local browser
use is disabled in Work settings.” No bypass, repeated permission request or
fabricated screenshot was used. Automated React tests and the production build
are separate evidence from actual UI interaction. Publication with this limitation
was explicitly authorized by the user; it does not turn browser acceptance into PASS.

For manual verification, serve the saved owned database with
`rtk proxy .venv/Scripts/python.exe -m scripts.serve_issue5_demo`, then start React:

```powershell
$env:BACKEND_PROXY_TARGET='http://127.0.0.1:5069'
rtk proxy npm --prefix frontend run dev -- --host 127.0.0.1 --port 5239 --strictPort
```

Open a case ID from the latest Issue 5 summary. In Evidence, expand an acquired
source, then “Scanners, coverage and limitations”. Check modules, hash, counts,
finding source and priority. In Artifacts, compare saved predictions with the API.
Refresh/reopen and compare again. In Reports, Generate PDF Report and compare
coverage with the source. Upload another harmless PE with the new standalone PE
option, test an invalid file, and inspect explicit partial/unavailable statuses.
Capture genuine screenshots of these interactions if performed; label them as
manual verification. No such screenshots are claimed by the automated report.
