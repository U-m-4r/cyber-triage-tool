# Issue #1B verification report

Completion: **PASS for the verified raw FAT12 integration scope**. No disk-image ML implemented.

Branch: `codex/issue-1-file-yara`. Starting/current HEAD:
`928584776e4e65ccb8796e1e1e56eaf18f49b8a8`. Work remains uncommitted.

## Before and after

| Execution | Passed | Skipped | Failed | Errors |
|---|---:|---:|---:|---:|
| Prior full suite, no training | 313 | 30 | 1 | 19 |
| Current full suite, no training, live MongoDB | 319 | 46 | 0 | 0 |
| Synthetic attack-family tests, separately | 21 | 0 | 0 | 0 |
| Final disk tests, live MongoDB | 14 | 0 | 0 | 0 |
| Frontend node tests | 17 | 0 | 0 | 0 |

These rows overlap; do not add their counts. Production frontend build and git diff whitespace checks passed.

The 19 prior errors all originate from `synthetic_attack_bundle` calling
`StandardScaler.fit` under the no-training guard. Its consumer tests cover
validation, eight invalid-bundle variants, schema order, missing features,
empty input, output structure, confidence/margin abstention, API attribution,
calibration scores, class order and calibrator degradation. All 21 tests in that
module now pass separately using disposable 120-row, 10-tree Random Forest
fixtures (5.37 seconds); no Isolation Forest or XGBoost retraining occurred.

The one prior failure is
`test_holdout_fits_training_only_and_evaluation_refuses_tampering`: it calls
`train_baseline`, whose scaler fit was blocked before Isolation Forest fitting.
It remains explicitly skipped because fitting Isolation Forest is prohibited.
The no-training collection filter previously omitted this test and the synthetic
attack-family fixture. The filter now reports these restrictions as skips; no
assertions were weakened. This fixes test orchestration, not model behavior.

The previous 30 skips comprise 25 model/scaler-fitting tests, three MongoDB
integration tests, one absent reference disk image, and one immutable-native-type
fault-injection skip. MongoDB tests now execute. Unreadable-file testing now wraps
real filesystem entries rather than trying to patch an immutable native class.
The current 46 skips are 45 fitting-dependent tests plus the absent reference
image. Nineteen of those 45 are independently verified by the synthetic run.
`test-health-audit.json` lists every original failure/error/skip and every final
skip by exact test name and reason. No observed failure remains attributable to
Issue #1. No missing parser/YARA dependency in the project `.venv`.

## Real end-to-end evidence

Successful evidence directory:
`275bb09aba6f4093ba1b935b14648143/` alongside this report.
It contains actual HTTP response JSON, retrieved case/artifact/intake JSON,
three PDF files and extracted text, screenshots, DOM snapshots, hashes and timings.

MongoDB: `mongodb://127.0.0.1:27018`, isolated database
`cyber_triage_test_275bb09aba6f4093ba1b935b14648143`.
The fresh UUID database has an ownership document. Existing investigation cases
were not edited or deleted. Test databases are retained for browser demonstration.

| Test | Entries | Regular files | Scanned | Limit exclusions | Failures | Ignored non-files | Files matched | Status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| Positive | 9 | 4 | 4 | 0 | 0 | 5 | 1 | COMPLETE |
| Negative-only image | 8 | 3 | 3 | 0 | 0 | 5 | 0 | COMPLETE |
| 100-byte individual limit | 9 | 4 | 3 | 1 | 0 | 5 | 1 | PARTIAL |

Positive image: 1,474,560 bytes. SHA-256 before and after:
`f2c7f6e5bafc0713a8ba800853a1e4d77c219f466e0131fafd2f59ab0197c473`.
Negative image SHA-256 before and after:
`e1f452ed997c2f563a515d82553a604fbcbeefafe5d3c2df53badc6094e7813a`.

`/POSITIVE.TXT`, volume offset 0, inode 4, matched `Harmless_File_Marker`.
File SHA-256: `abb26cde86c7719c4a35bb534535db20249d1c962c4c5676d9e4edfb6469be40`.
Persisted risk 25, priority MEDIUM, anomaly score null. The negative-only image
contains no positive file and produced zero YARA matches. All integrity assertions
passed, including the limited scan. No recovered file was executed.

Each successful HTTP experiment asserted persistence then retrieved the case,
artifacts and ingestion history through the backend API. Equality checks cover
evidence SHA-256, file path/hash, inode, volume, YARA rule metadata, status/reason,
risk/priority, intake ID and complete scan summary. Actual IDs and records are in
the JSON evidence. PDF generation also recorded report metadata in MongoDB.

Two initial experiment attempts aborted before completing verification: the first
encountered an existing service on the default backend port; the second exposed
PDF extraction line wrapping. The successful run uses dedicated port 5019 and
normalized PDF whitespace. The script now additionally checks a per-run HTTP
identity endpoint before creating cases. Failed experiment directories have no
success summary and are not counted as passed evidence.

## Coverage definitions and performance

The four former skips are TSK virtual entries `$MBR`, `$FAT1`, `$FAT2` and
`$OrphanFiles`. The former fifth scanned file was a synthesized FAT volume label.
All five are now ignored non-files; actual regular streams alone are scanned.
Directories and other non-regular metadata types are counted outside file failures.
Missing metadata remains an explicit unreadable discovery. Unknown discoveries,
traversal failures, missing rules/engine, limit exclusions, or file errors prevent
COMPLETE. Successful completion means every regular default stream in the declared
scope was scanned; it does not mean the evidence is safe.

The prior 0.004567 seconds covered `analyze_disk_image` only, including compilation,
filesystem parsing, reads and YARA; it excluded the complete request/persistence.

| Measured scope, seconds | Positive | Negative | Limited |
|---|---:|---:|---:|
| Rules compilation | 0.002112 | 0.000807 | 0.001013 |
| Filesystem enumeration and native setup residual | 0.001445 | 0.000806 | 0.001104 |
| File reads and SHA-256 | 0.000048 | 0.000026 | 0.000030 |
| YARA execution and normalization | 0.000602 | 0.000347 | 0.000496 |
| Total disk analysis | 0.004208 | 0.001986 | 0.002643 |
| Backend analysis before persistence | 0.025394 | 0.016694 | 0.025632 |
| HTTP request through response, including persistence | 0.049647 | 0.034203 | 0.074339 |

Filesystem timing is a residual, not a profiler measurement of pure parser CPU.
Backend analysis starts inside the ingestion handler after pre-request middleware;
HTTP time includes the upload, middleware, persistence and serialization. These are
single-run timings of a tiny local fixture, not a throughput benchmark.

## React and PDF verification

Real React/Vite frontend at `http://127.0.0.1:5189`, proxying to the isolated backend.
Verified dashboard totals: three cases, three intakes, eleven artifacts, two MEDIUM
artifacts and zero CRITICAL artifacts. No duplicate stored files. Verified case
refresh, matching path/hash/rule details, risk/priority and negative-only findings.
Verified COMPLETE evidence and a real PARTIAL warning for the excluded LARGE.BIN.
Actual screenshots and DOM snapshots are stored with the successful evidence.

Fixed browser-discovered duplicate sibling keys in the Evidence tab, parsed counts
that did not recognize COMPLETE/PARTIAL, and clipped file-hash details. Storage
completion and scan completion are now labelled separately. The final browser
error check found no new errors after these fixes.

Positive and limited PDFs have four pages each; negative has three. They were
opened, text-extracted, rendered and visually inspected using the contact sheet.
Contents include evidence hashes, file findings, YARA names, priorities, scan
statistics, scope limits, and the partial coverage warning. API assertions compare
these to persisted records. No-match results are explicitly not a safety verdict;
YARA matches are investigation indicators, not proof of malware. Rendered pages
are readable with no clipping or overlap; long evidence text may continue on the
next page. PDF export is verified independently of browser download mechanics.

## Modified functions and files for #1B

- `forensics/disk_image.py`: `analyze_disk_image`, entry accounting and stage timers.
- `backend/app.py`: `forensics_ingest`, backend analysis timing.
- `backend/integration.py`: `finding`, `persist_intake`, provenance and coverage text.
- `backend/report_generator.py`: `_build_evidence`, evidence digest, counters and scope.
- `frontend/src/components/case/CaseArtifacts.css`: wrap expanded hashes/rule details.
- `frontend/src/components/case/CaseEvidence.jsx`: parsed count.
- `frontend/src/components/case/EvidenceStatus.jsx`: parsed count.
- `frontend/src/components/case/IntakeHistory.jsx`: coverage and storage labels.
- `frontend/src/routes/CaseWorkspacePage.jsx`: distinct sibling keys.
- `tests/conftest.py`: accurate no-training collection classification.
- `tests/test_disk_file_yara.py`: real accounting/persistence and unreadable read tests.
- `scripts/verify_file_yara.py`: generate a genuinely negative-only fixture.
- `scripts/verify_issue1b.py`: owned MongoDB/HTTP/PDF experiment and proof generation.

Initial Issue #1 changes remain intact and uncommitted on the same branch.

## Exact reproduction and demo commands

From the repository root, use the existing project `.venv` with pytsk3,
yara-python and MongoDB installed. Test-only extras: `pyfatfs==1.1.0`,
`setuptools<81`, `pypdf`, `pymupdf`, `requests`.

```powershell
rtk proxy powershell -NoProfile -Command 'New-Item -ItemType Directory -Force .test-artifacts/issue1b-mongo | Out-Null; Start-Process -FilePath "C:\Program Files\MongoDB\Server\9.0\bin\mongod.exe" -ArgumentList "--dbpath", ".test-artifacts/issue1b-mongo", "--port", "27018", "--bind_ip", "127.0.0.1", "--logpath", ".test-artifacts/issue1b-mongo/mongod.log" -WindowStyle Hidden'
rtk proxy .venv\Scripts\python.exe -m scripts.verify_issue1b --serve
```

If the dedicated test MongoDB is already running, reuse it. The script creates a
fresh UUID database each run and prints the new IDs and evidence directory.
It leaves the test backend on 5019 with `--serve`; stop that process before rerunning.

In another terminal:

```powershell
rtk proxy powershell -NoProfile -Command '$env:BACKEND_PROXY_TARGET="http://127.0.0.1:5019"; npm --prefix frontend run dev -- --host 127.0.0.1 --port 5189'
rtk proxy .venv\Scripts\python.exe -m pytest --no-training --run-integration -q
rtk proxy .venv\Scripts\python.exe -m pytest tests/test_attack_family.py -q
rtk proxy .venv\Scripts\python.exe -m pytest tests/test_disk_file_yara.py --no-training --run-integration -q
rtk proxy npm --prefix frontend run check
```

Open `http://127.0.0.1:5189`, enter an investigator display label, leave the token
blank for this loopback-only isolated test app. Capture dashboard, positive case
Artifacts with MATCHED expanded, Evidence with SHA-256 expanded, negative case
Artifacts, limited case Evidence, and its exported PDF. Refresh the positive case
to demonstrate persistence. Existing successful demo case IDs:
positive `CASE-C4D6ACE15097`, negative `CASE-217A92CBA506`, limited `CASE-0241B2061541`.

## Remaining limits

Verified format is unpartitioned raw FAT12 only. E01, ADS, deleted-file recovery
and other real image formats remain unverified. Resource deadlines are cooperative
between native pytsk3 calls, not process-level preemption. The configured reference
NTFS fixture is absent, so that single test remains skipped. Training-dependent
tests are intentionally restricted as detailed above. Test database records and
generated evidence images stay local; no commits were made and no model artifacts
or prior experimental metrics were replaced. No further issue has been started.
