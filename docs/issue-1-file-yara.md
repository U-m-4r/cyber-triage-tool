# Issue #1 file content scanning

Follow-up verification: see `test-results/issue-1b/REPORT.md` for the completed
MongoDB, browser and PDF experiments, corrected file accounting and stage timings.
The limitations below describing those integrations as unverified reflect the
initial Issue #1 run and are superseded by that measured follow-up report.

Starting commit: `928584776e4e65ccb8796e1e1e56eaf18f49b8a8`.
Branch: `codex/issue-1-file-yara`.

`forensics.disk_image.analyze_disk_image` opens evidence through pytsk3's read-only
image/filesystem interfaces. Each regular default file stream is read in 1 MiB
chunks into a bounded buffer, hashed only after a complete read, then passed to
YARA as complete data. Chunks are not scanned independently (that would break
cross-chunk signatures). Files are never executed or extracted to disk.

Locations include partition byte offset, inode and original path. Duplicate paths
remain distinct rows. Traversal uses inode cycle protection and entry/depth bounds.
All discoveries, including virtual/nonregular entries, retain a status and reason.
Discovery counters are lower bounds when traversal stops early.

Configure `DISK_SCAN_LIMITS` in Flask configuration using the keys of `ScanLimits`.
Defaults: 10,000 scan attempts, 32 MiB/file, 256 MiB read total, 120 seconds,
5-second YARA timeout, 20,000 directory entries, depth 64. Duration is cooperative
between native calls: a hung pytsk3 call cannot be interrupted by this implementation.
Deploy in a separately supervised worker for a strict wall-clock kill boundary.
Memory is bounded by the file buffer plus YARA copies and capped artifact metadata.

Set `YARA_RULES_DIR` in Flask configuration or environment. Rule paths are sorted;
namespaces hash relative paths to avoid filename collisions. The ruleset digest
covers paths and content. Compilation failures and absent dependencies are exposed
on both the summary and eligible artifacts. The legacy standalone `scan_file`
empty-directory behavior remains for API compatibility.

Existing rules reviewed: EICAR is a harmless test indicator; PowerShell command
options are contextual indicators (now require PowerShell text); executable temp
paths are contextual references, not evidence that an executable was recovered.
All three compile in the tested environment and preserve description/severity.
These broad indicators can match documentation and logs. They are not malware
verdicts. The dedicated integration-marker rule lives only with generated fixtures.

RiskScorer uses a documented 0.25 contribution for a verified YARA match: MEDIUM
review priority in isolation. Existing file metadata rules can increase it. Rule
severity metadata is not trusted as a numeric weight; no ML probability is assigned.
Network model training and published evaluation results are unchanged.

API: `POST /api/forensics/ingest` retains existing fields and adds `disk_scan`,
including all file findings and measured counters. Whole-image YARA is bypassed
for disk images. Artifact rows and summary metadata use existing MongoDB intake
persistence; case evidence summaries retain scan completion and warnings. The
Artifacts view exposes content status, hash, inode, path and rule descriptions.
The PDF evidence section includes scan counts/status/ruleset; priority findings
retain paths, rule names, hashes and scan explanations through existing finding
mapping. Persistence and PDF visual layout have not been verified end to end.

Verified image format: unpartitioned FAT12 raw image only. No E01 support claim,
ADS support, deleted-file recovery guarantee, or disk-image ML classifier.

## Reproduce

Use the project's existing `.venv` (pytsk3 and yara-python installed).
Test-only fixture dependencies: `pyfatfs==1.1.0` and `setuptools<81`.

```powershell
rtk proxy .venv\Scripts\python.exe -m pip install pyfatfs==1.1.0 "setuptools<81"
rtk proxy .venv\Scripts\python.exe -m scripts.verify_file_yara
rtk proxy .venv\Scripts\python.exe -m pytest tests/test_disk_file_yara.py tests/test_forensics.py tests/test_scoring.py tests/test_chain_of_custody.py tests/test_integration_views.py --no-training -q --junitxml=test-results/issue-1/focused-tests.xml
rtk proxy .venv\Scripts\python.exe -m pytest --no-training -q
rtk proxy npm --prefix frontend run build
```

The fixture script creates a fresh UUID directory under ignored `.test-artifacts/issue1`,
so it never overwrites an existing image. FAT timestamps mean image hashes vary
between runs. Assertions verify exact file contents, the positive rule, negative
and empty scans, API response and byte-for-byte evidence integrity.

## Presentation

Run the script first. For a browser demo use a configured local MongoDB case,
set `YARA_RULES_DIR` to the newly generated rules directory, and upload its sibling
`harmless-fat12.img` in the case Evidence tab. Capture Evidence expanded with
SHA-256 and PARTIAL status, Artifacts filtered to File with POSITIVE.TXT expanded,
NEGATIVE.TXT with SCANNED_NO_MATCH, and priority findings showing the YARA name.
Reopen the case and export its report. These browser/persistence steps still need
live verification; do not present them as tested results from this environment.
