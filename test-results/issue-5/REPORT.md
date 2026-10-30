# Issue 5 implementation and verification

Implemented universal evidence-aware orchestration around existing parsers and frozen inference engines. Browser acceptance remains UNVERIFIED and was explicitly accepted as a publication limitation.

Issue 4 integration: normal merge `bee69ac4112e65d90d1426e8cfce22bff5c60103`; remote verified; PR #24 marked MERGED. No new PR created.

## Actual final verification

Run `b80f79a429ab4afbb0f5f291f153d634`; owned DB `cyber_triage_test_b80f79a429ab4afbb0f5f291f153d634`; real HTTP port 5069.

| Scenario | Stored records | YARA examined / rule matches | PE classified | Network examined | Scan status | API + MongoDB + PDF |
|---|---:|---:|---:|---:|---|---|
| disk | 6 | 6 / 3 | 2 | 0 | COMPLETED | PASS |
| standalone-pe | 1 | 1 / 1 | 1 | 0 | COMPLETED | PASS |
| cicids2017-xgb | 84 | 1 / 0 | 0 | 84 | COMPLETED | PASS |
| cicids2017-iforest | 84 | 1 / 0 | 0 | 84 | COMPLETED | PASS |
| external-csv | 60 | 1 / 0 | 0 | 60 | COMPLETED | PASS |
| native-evtx | 1601 | 1 / 0 | 0 | 0 | COMPLETED | PASS |
| native-registry | 2000 | 1 / 0 | 0 | 0 | PARTIAL | PASS |
| event-export | 2 | 1 / 0 | 0 | 0 | COMPLETED | PASS |
| registry-export | 2 | 1 / 0 | 0 | 0 | COMPLETED | PASS |
| pcap | 1 | 1 / 0 | 0 | 0 | COMPLETED | PASS |

Backend: 390 passed; 46 skipped; 0 failures; 0 errors. Training was prohibited. Skips are fitting fixtures and the unacquired primary forensic image; the controlled real FAT12 image ran successfully.
Frontend: see frontend-final.txt (19 passed, 0 failures, production build completed). This is automated coverage, not a browser interaction test.
Static/dependency/config/diff checks: see check-final.txt. PDF pages were rendered; geometry and visual review are recorded in the run pdf-verification.json.

## Observed behavior

- FAT12: six genuine embedded files; harmless marker positive, ordinary negative and empty-file negative; two real distlib PE launchers classified. A test-only header signature intentionally identifies harmless PE structure; it is not a malware rule.
- Standalone PE: actual validated launcher bytes reached YARA and the official EMBER2024 model. Actual benign predictions and uncalibrated scores are saved in the ignored API responses and PDF.
- Real 84-row CICIDS2017 and 60-row CSE-CIC-IDS2018 fixtures reached the selected frozen models. These demonstrations are not new benchmark evaluations or accuracy claims.
- Native EVTX: actual upstream binary log parsed, original EventRecordIDs retained. Native registry hive: real values parsed, with failures/truncation visible. The capped registry run is PARTIAL; the remaining population is unknown, not zero.
- PCAP: real harmless generated capture parsed without applying an unverified CICIDS feature mapping. Single-packet zero-duration rates are unavailable instead of fabricated; packet/non-IPv4 limits are explicit.
- All ten successful scenarios checked original SHA-256 before/after, API versus saved-case screening equality, MongoDB ingestion/artifact linkage and actual PDF text. Detailed timings, hashes, page counts and case IDs are in the run summary.
- Actual deployment-controlled YARA disablement returned UNAVAILABLE/PARTIAL; configured byte and record limits returned skipped/partial coverage. Unsupported bytes were rejected explicitly. Additional deterministic tests exercise corrupt PE, absent model, compiler failure, timeouts and BSON-safe provenance.

## Fixes discovered during verification

Initial backend run: 380 passed, 46 skipped, two supervised persistence failures. New screening provenance retained integer label-map keys, which BSON rejects. Normalizing keys fixed the defect; a BSON regression test now protects it. The initial XML is retained.
An early live attempt stopped at unavailable test MongoDB; a fresh isolated service was started. Another stopped on PDF text whitespace across wrapped lines; normalizing extracted whitespace fixed the check without changing its required text. The subsequent supervised persistence failure was fixed as above. Attempt logs are retained, with no failed attempt counted as a pass.

## Source and file map

- backend/screening.py: identify, module, raw_yara, parse_export, summarize; common statuses, applicability, identity, provenance and risk review findings.
- backend/screening_worker.py: bounded/killable native/export/capture parsing and exclusion accounting.
- backend/app.py: all three intakes, raw signature routing, native PE intake, network caps, common persistence metadata and parser failures.
- backend/config.py: validated deployment resource policy and scanner switch.
- backend/integration.py: persist_intake; per-source/per-artifact coverage and container review risk without false record attribution.
- backend/report_generator.py: _build_evidence; saved coverage, rules, model predictions/provenance, limitations and unknown remaining counts.
- forensics/disk_image.py: additive YARA deployment switch; existing embedded-file logic preserved. forensics/evtx_parser.py and registry_parser.py: identity, native limits, parser failures and metadata truncation.
- ml/ingestion/{evtx_parser,file_parser,registry_parser,pcap_parser}.py: source identities, bounded captures, no epsilon-based packet rates.
- ml/risk_scorer.py: targeted missing-value/registry substring corrections and explicit Event 1102/7045 indicators; model fusion unchanged.
- frontend/src/components/case/{ScreeningSummary,CaseEvidence,CaseArtifacts,IntakePanel}.jsx; frontend/src/utils/screening.js; frontend/tests/screening.test.js.
- tests/test_unified_screening.py; scripts/{acquire_issue5_fixtures,prepare_issue5_network_demo,verify_issue5,render_issue5_reports,report_issue5,serve_issue5_demo}.py; scripts/prepare_external_demo.py adds separate output arguments without altering historical defaults.

## Policy, reproduction and limitations

See [support/applicability matrix, risk policy, limits and exact commands](../../docs/unified-screening.md). Fixture source revisions, SHA-256 and verified upstream Apache-2.0 licenses are in fixture-provenance.json. Raw native fixtures, executable bytes, original network records, databases and full PDFs remain ignored.
YARA does not establish malware; ML scores are not calibrated confidence. File inventories do not provide file bytes. No E01/EWF or universal filesystem/PE variant support is claimed. Native process byte/deadline limits are not an OS memory or concurrent-job quota. Missing scans never lower existing risk. Standard CVSS ratings are separate from project triage bands.
Browser: last permitted tool result was exactly “Local browser use is disabled in Work settings.” No browser bypass, screenshots or UI pass is claimed. Manual steps are in the policy document.
Vercel remains outside acceptance at the owner’s instruction. No model retraining, external benchmark rerun or Issue 6 work was performed.

## Frozen artifacts

| Artifact | Unchanged SHA-256 |
|---|---|
| models/cicids2017_baseline.joblib | `8602d9e6f57d347a10ebbca7290ad2bc75892f9c7f8b29dcc97c2fea20035c0d` |
| models/supervised_binary.joblib | `ee4bc46fee3d1957bd080246c84bf6dedee246b25d29c1ecd6dfaf63d2100e3f` |
| models/pe/EMBER2024_PE.model | `4252027863492ac138785c8c18576f43dad77d00faddc14e8c0072e8db419f99` |
| test-results/issue-4/evaluation.json | `5a6c5ee5682b286e0291600b3b78d7783e63c01a05e17e888d7a20cd93a3a683` |

The final implementation revision is identified by Git history and the verified remote main SHA in the delivery. No self-referential commit hash is embedded in this committed report.
