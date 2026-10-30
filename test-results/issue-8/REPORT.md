# Issue8 — real allocated NTFS and segmented EWF verification

**NTFS PASS for verified allocated-default-stream scope. E01 PASS for tested local read-only segmented physical EWF; segmented web upload NOT SUPPORTED. Browser interaction UNVERIFIED. No commits/pushes/PRs/tags/releases/merges.**

## Provenance and compatibility

Public reference: NIST CFReDS DFR01 NTFS, https://cfreds-archive.nist.gov/dfr-test-images.html and https://cfreds-archive.nist.gov/dfr-images/dfr-01-ntfs.dd.bz2 . Separate download under ignored storage; existing private dfr-01-ntfs.dd/ was never opened or modified. Archive2257102bytes; image1073742336bytes. ImageSHA256 c863ccad01804b840a6dfa623a94996ca876e15ded41c6c0d8ae148620eb6493. Full source record:reference-source.json. These are locally measured hashes, not an independently published NIST SHA256 verification. CFReDS reference is a deleted-recovery dataset; no recovery capability is claimed.
NIST filesystem at31232bytes:20allocated regular default streams,2deleted entries excluded, COMPLETE within declared scope. Arcturus.txt and Castor.txt were read and contain the DFR-generated file/path headers. Reference hashes are measured outputs, not externally supplied full-file oracle values. Controlled source files provide independent known-byte hashes for extraction verification.
Controlled64MiB NTFS built from official Alpine ntfs-3g2026.2.25 tools; no privileged containers, physical devices or evidence mounts. Build used isolated /work only. Fixture mkdir helper links libntfs; generated images/launchers are never executed. Harmless PE is PyPA distlib t64.exe bundled with pip. No malware downloaded. Raw sourceSHA256 18defdcac463750fdcb0ef8070b1e7f3411d21efb54c41354b3a7c5e2de8ecf1.
An MBR wrapper at1048576bytes verified partition discovery and exact volume-associated extraction. Unpartitioned image at0verified separately. Nested and nonASCII names, sizes, timestamps, inode identifiers, resident small files and nonresident3MB file were read. Unicode filename bytes are preserved, but initial build script had mojibake relative to intended spelling; unicode-observations.json discloses this. No correct-intended-accented-spelling claim.

## Real findings and performance

Controlled raw: 19regular files; 19YARA scans; 2matching streams; 1genuine PE prediction. Empty, negative, large and launcher hashes equal original known source bytes. Positive marker is in /nested/positive.txt; a second actual byte match occurs in NTFS/$MFT resident content and is labeled by its metadata-file path, not another infected user file. Negative/empty/launcher files have no marker matches.
Frozen EMBER PE@425202786349,2568features,threshold0.5: launcher score 0.012141118467631745; benign prediction; exact direct-byte inference agreement. YARA/rules/model results remain separate and existing risk policy unchanged. NTFS metadata files remain visible, not silently excluded to improve counters.
Raw analysis 3.898852s; EWF analysis 4.551563s. Actual normalHTTP upload→analysis→Mongo response: 7.490808s. API stage timings below are actual measurements; enumeration is residual wall time, not an independently isolated traversal timer. Validation and database-only times were not separately instrumented; do not infer them from the remainder.
```json
{
  "backend_analysis_seconds": 6.097809,
  "disk_analysis_seconds": 4.902794,
  "file_read_hash_seconds": 0.022671,
  "filesystem_enumeration_seconds": 0.444943,
  "pe_ml_seconds": 4.415743,
  "rules_compilation_seconds": 0.001091,
  "yara_execution_seconds": 0.018346
}
```
Testing environment: Windows AMD64/Python3.14,8.30GB RAM,12logicalCPUs; initial availableRAM1.055GB and46.55GB free disk. No OS-level native-reader memory quota is claimed. Native TSK timeouts remain cooperative.

## E01 verification and scope

Debian bookworm ewf-tools20140813 created five real E01–E05 segments from the controlled raw image using16MiB segment size. ewfacquire and ewfverify both returned SUCCESS. Windows official libewf-python20260924 cp314win_amd64 wheel installed; wheel is preserved ignored. Read-only pyewf handle and pytsk external callbacks read bounded logical ranges without raw conversion or whole-image allocation. Every decompressed byte hashed; logicalSHA256 equals rawSHA256, and storedMD5 8e7737b7ef5692126799bafb54cba4a5 equals computedMD5. Per-segment container hashes are in ewf-integrity.json; they are not logical-media hashes.
Both raw and EWF produce matching known content hashes and genuine PE/YARA findings. Original raw and all segment bytes are preserved; final integrity compares against recorded hashes. Missing-segment fixture fails explicitly (missing-segments.json). Logical LEF is rejected. Ex01/encrypted/other compression variants unverified. This controlled acquisition is a genuine EWF format test, not validation of all commercial EnCase variants.
NormalHTTP supports one evidence file, not transfer of a segmented set. Entire complete segment sets must already reside together for bounded local analyze_disk_image(E01). No general web local-path endpoint or upload-limit bypass is added. Segmented E01 upload/reopening through web acquisition remains future work; raw NTFS persistence/frontend/PDF are verified.

## Resource and production-size coverage

128MiB upload limit unchanged;64MiB fixture used normalmultipart upload.1GiB reference analyzed locally under existing file/count/byte/time limits. Controlled limit run verifies PARTIAL and explicit skipped artifacts. Existing regression suite exercises interrupted reads and scan deadlines. Known3MB nonPE file was read and hashed; PE cap remains2MiB with20sec killable worker. No safe increase is established by feature-only throughput. OS concurrency/deployment limits remain necessary.
production-size-metrics.json copies the frozen Issue7 benchmark counts and header/size proxy metrics without reevaluation.112556/479987unique benchmark files exceed2MiB:81098malicious and31458benign. Proxy eligibility is not a guarantee of successful raw parsing or all PE structure validation; do not equate full feature-only benchmark with live coverage.

## Persistence, frontend and report

Case CASE-95006490E558, UUID-owned MongoDB cyber_triage_test_4febd9d57e264b88a9d8a196afebf494: real upload findings retrieved with correct file/evidence hashes, model score and source identity. Case/API/artifacts/summary JSON are under 4febd9d57e264b88a9d8a196afebf494/. No raw bytes stored in MongoDB. Case retrieval tested. Actual React artifact table server-rendered19saved artifacts including1real PE result; saved paths/model/score assertions passed. Initial two-PE-specific renderer failed because this fixture has1PE; original failure log preserved and dedicated1PE renderer passed. No fabricated UI data.
ActualPDF contains correct marker/model/file findings. All pages rendered and text bounds checked; evidence-summary page visually inspected. Browser remains UNVERIFIED: Local browser use is disabled in Work settings. PDF summary PNG is real report output, not a dashboard screenshot. Integrity checks are technical provenance, not a legally complete chain of custody.

## Regression results

418backend tests passed,46skipped,zero failures/errors;19frontend tests passed; production build PASS. Static/configuration checks PASS. Historical primary-image test still skips because its configured acquisition path is absent; actual separate NIST/controlled NTFS/EWF tests did execute. No network model or historical evaluation changed.

## Reproduction

Existing native environment plus optional requirements/ewf.txt, Docker official Alpine3.22 and Debianbookworm-slim. Original package versions and image digests are documented in fixture-provenance.json. Never bind private evidence to fixture-builder containers. Fixture generation writes NEW directory only; do not regenerate over the sealed original.
```powershell
rtk proxy .venv/Scripts/python.exe -m scripts.build_issue8_fixture .test-artifacts/issue8-new/controlled
# Bind only that new directory to /work in Alpine3.22, run sh /work/build.sh
# Then bind the same new directory in Debianbookworm-slim, run sh /work/ewf.sh
rtk proxy .venv/Scripts/python.exe -m scripts.verify_issue8
rtk proxy .venv/Scripts/python.exe -m pytest -q --no-training --run-integration
rtk proxy npm --prefix frontend run check
rtk proxy .venv/Scripts/python.exe scripts/check.py
```
verify_issue8 reads original sealed .test-artifacts/issue8/controlled and writes a new UUID result/case. Fresh generated fixture namespace requires pointing its controlled path to that directory. Fixture UUID/timestamps and build versions can change image hashes; compare extracted known source hashes instead of promising byte-identical image generation. Sources, limits, actual outcomes and file manifest make the experiment reproducible.

## Remaining capability limits / PPT

Allocated default stream reading only. No ADS scanning, deleted recovery, slack/carving, reparse-target traversal, EFS decryption, session reconstruction. Sparse/compressed/deliberately fragmented reads are not independently verified here. NIST metadata and controlled known-byte tests establish tested capabilities, not universal NTFS support.
PPT: Real NTFS file contents reach independent YARA and frozenPEML; known source hashes match; raw and segmentedEWF yield the same logical media; MongoDB/Reactcomponent/PDF preserve provenance. Present EWF local support separately from absent segmented web upload. No fabricated malware detections or accuracy claims.
All work remains local/uncommitted; Issue6B/7 preserved. No further issue started.
