# Issue 5 handoff — planning only; implementation not started

Issue 4's frozen-model negative results must remain intact. One model cannot screen
every evidence type, and an unsupported or failed analysis is not a clean result.

| Existing entry point/module | Reuse | Integration gap to assess next |
|---|---|---|
| backend/app.py `_save_uploaded_file`, `compute_sha256` | upload limits, read-only SHA-256 custody | consistent per-type validation and coverage summary across routes |
| `/api/analyze`, ml/preprocessor.py, baseline.py, supervised_detector.py, external_dataset_adapter.py | per-flow validation, frozen selected network model, model/threshold provenance | comparable row exclusion/coverage statuses across native and external CSV inputs; raw-byte YARA cannot substitute for flow analysis |
| `/api/ingest`, ml/ingestion/* | normalized EVTX/export, registry, file-list and PCAP dispatch | file listing metadata is not file content; packet-derived feature contracts need explicit scope |
| `/api/forensics/ingest`, forensics/disk_image.py | bounded read-only per-file YARA and eligible PE inference | preserve current per-artifact failures/limits; avoid reporting partial images as fully screened |
| forensics/evtx_parser.py, registry_parser.py | native host artifact parsing | map parsed fields to applicable host rules, retain parser errors; whole-container signatures are supplementary |
| forensics/yara_scanner.py | deterministic compilation, real byte/file matches, ruleset provenance | scope each match to its actual target; no universal format-independent clean verdict |
| ml/pe_malware_detector.py | frozen static PE classification | invoke only when actual supported PE bytes are available, not for registry rows or network features |
| ml/risk_scorer.py, backend/integration.py | separate indicators, risk policy, persistence, case linkage | define missing/not-applicable coverage without inventing confidence or lowering risk for missing analyses |
| React case components, backend/report_generator.py | saved findings, provenance and reports | display consistent coverage/error/partial states alongside findings |

Concrete route difference: `/api/analyze` performs per-flow analysis but does not
call `_scan_evidence`; generic `/api/ingest` adds raw-upload YARA, and native disk
ingestion has genuine artifact-level scanning. Decide deliberately which raw-byte
scan is meaningful and label its scope; do not simply apply the same scanner to
every upload. Existing file-list parsers cannot provide bytes for PE/YARA analysis.

Recommended order:

1. Define a per-evidence-type applicability/coverage contract: completed, partial,
   not applicable, unavailable, invalid, skipped and failed; include reasons/counts.
2. Document and test routing, validation, hash custody, resource limits and artifact
   identity through the existing entry points before changing behavior.
3. Wire only applicable content/record analyses using current parsers and scanners.
   Preserve separate YARA, host rules, network ML, PE ML and enrichment outputs.
4. Apply transparent risk rules without fabricated calibrated confidence or
   treating absent analysis as benign. Do not reuse one ML feature contract for
   unrelated formats.
5. Persist versioned coverage metadata and expose it consistently in UI/PDF.
6. Verify real per-type positive/negative fixtures, unsupported inputs, missing
   dependencies, partial recovery and integrity through actual API/database/report
   workflows. Do not train or change models as a side effect of upload.

This document identifies existing modules and investigation targets, not a claim
that universal screening exists. No Issue 5 code, model changes or schema migration
was implemented during Issue 4B.
