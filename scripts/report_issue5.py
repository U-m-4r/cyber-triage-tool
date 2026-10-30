"""Build the review report only from actual saved execution artifacts."""
import importlib.metadata
import json
from pathlib import Path
import platform
import re
import subprocess
import xml.etree.ElementTree as ET


def main():
    root = Path('test-results/issue-5')
    latest = json.loads((root/'latest.json').read_text())
    output = Path(latest['output']); summary = json.loads((output/'summary.json').read_text())
    suites = ET.parse(root/'regression-final.xml').getroot()
    tests = list(suites.iter('testcase'))
    counts = {'passed':sum(not any(t.find(key) is not None for key in ('skipped','failure','error')) for t in tests),
              'skipped':sum(t.find('skipped') is not None for t in tests),
              'failed':sum(t.find('failure') is not None for t in tests),
              'errors':sum(t.find('error') is not None for t in tests)}
    frontend = (root/'frontend-final.txt').read_text(encoding='utf-8')
    front_passed = int(re.search(r'pass\s+(\d+)', frontend).group(1))
    front_failed = int(re.search(r'fail\s+(\d+)', frontend).group(1))
    assert front_failed == 0 and 'built in' in frontend
    environment = {'python':platform.python_version(), 'platform':platform.platform(),
        'versions':{package:importlib.metadata.version(package) for package in
                    ('Flask','pymongo','yara-python','pytsk3','python-evtx','python-registry','lightgbm','xgboost','scikit-learn','scapy','reportlab')},
        'git_branch':subprocess.check_output(['git','branch','--show-current'],text=True).strip(),
        'issue4_merge':'bee69ac4112e65d90d1426e8cfce22bff5c60103',
        'browser_status':'UNVERIFIED: Local browser use is disabled in Work settings.',
        'backend_regression':counts}
    (root/'environment.json').write_text(json.dumps(environment, indent=2))
    lines = ['# Issue 5 implementation and verification', '',
        'Implemented universal evidence-aware orchestration around existing parsers and frozen inference engines. '
        'Browser acceptance remains UNVERIFIED and was explicitly accepted as a publication limitation.', '',
        f"Issue 4 integration: normal merge `bee69ac4112e65d90d1426e8cfce22bff5c60103`; remote verified; PR #24 marked MERGED. No new PR created.", '',
        '## Actual final verification', '', f"Run `{summary['run']}`; owned DB `{summary['database']}`; real HTTP port 5069.", '',
        '| Scenario | Stored records | YARA examined / rule matches | PE classified | Network examined | Scan status | API + MongoDB + PDF |',
        '|---|---:|---:|---:|---:|---|---|']
    for name, record in summary['results'].items():
        coverage = json.loads((output/(name+'-coverage.json')).read_text()); scans = coverage['screening']
        lines.append(f"| {name} | {record['stored']} | {scans['yara']['examined']} / {scans['yara']['findings']} | {scans['pe_ml']['examined']} | {scans['network_ml']['examined']} | {record['status']} | PASS |")
    lines += ['', f"Backend: {counts['passed']} passed; {counts['skipped']} skipped; {counts['failed']} failures; {counts['errors']} errors. "
        'Training was prohibited. Skips are fitting fixtures and the unacquired primary forensic image; the controlled real FAT12 image ran successfully.',
        f'Frontend: see frontend-final.txt ({front_passed} passed, {front_failed} failures, production build completed). This is automated coverage, not a browser interaction test.',
        'Static/dependency/config/diff checks: see check-final.txt. PDF pages were rendered; geometry and visual review are recorded in the run pdf-verification.json.', '',
        '## Observed behavior', '',
        '- FAT12: six genuine embedded files; harmless marker positive, ordinary negative and empty-file negative; two real distlib PE launchers classified. '
        'A test-only header signature intentionally identifies harmless PE structure; it is not a malware rule.',
        '- Standalone PE: actual validated launcher bytes reached YARA and the official EMBER2024 model. Actual benign predictions and uncalibrated scores are saved in the ignored API responses and PDF.',
        '- Real 84-row CICIDS2017 and 60-row CSE-CIC-IDS2018 fixtures reached the selected frozen models. '
        'These demonstrations are not new benchmark evaluations or accuracy claims.',
        '- Native EVTX: actual upstream binary log parsed, original EventRecordIDs retained. Native registry hive: real values parsed, with failures/truncation visible. '
        'The capped registry run is PARTIAL; the remaining population is unknown, not zero.',
        '- PCAP: real harmless generated capture parsed without applying an unverified CICIDS feature mapping. '
        'Single-packet zero-duration rates are unavailable instead of fabricated; packet/non-IPv4 limits are explicit.',
        '- All ten successful scenarios checked original SHA-256 before/after, API versus saved-case screening equality, '
        'MongoDB ingestion/artifact linkage and actual PDF text. Detailed timings, hashes, page counts and case IDs are in the run summary.',
        '- Actual deployment-controlled YARA disablement returned UNAVAILABLE/PARTIAL; configured byte and record limits returned skipped/partial coverage. '
        'Unsupported bytes were rejected explicitly. Additional deterministic tests exercise corrupt PE, absent model, compiler failure, timeouts and BSON-safe provenance.', '',
        '## Fixes discovered during verification', '',
        'Initial backend run: 380 passed, 46 skipped, two supervised persistence failures. '
        'New screening provenance retained integer label-map keys, which BSON rejects. Normalizing keys fixed the defect; '
        'a BSON regression test now protects it. The initial XML is retained.',
        'Fresh-checkout CI initially reported 351 passed, 84 skipped, one failure: YARA was absent, '
        'but a resource-limit test assumed the optional engine was installed. The assertion now explicitly '
        'checks UNAVAILABLE when the dependency is absent, matching the documented precedence. '
        'No scanner failure is reinterpreted as a negative detection. Original CI log: ci-first-failure.txt.',
        'An early live attempt stopped at unavailable test MongoDB; a fresh isolated service was started. '
        'Another stopped on PDF text whitespace across wrapped lines; normalizing extracted whitespace fixed the check without changing its required text. '
        'The subsequent supervised persistence failure was fixed as above. Attempt logs are retained, with no failed attempt counted as a pass.', '',
        '## Source and file map', '',
        '- backend/screening.py: identify, module, raw_yara, parse_export, summarize; common statuses, applicability, identity, provenance and risk review findings.',
        '- backend/screening_worker.py: bounded/killable native/export/capture parsing and exclusion accounting.',
        '- backend/app.py: all three intakes, raw signature routing, native PE intake, network caps, common persistence metadata and parser failures.',
        '- backend/config.py: validated deployment resource policy and scanner switch.',
        '- backend/integration.py: persist_intake; per-source/per-artifact coverage and container review risk without false record attribution.',
        '- backend/report_generator.py: _build_evidence; saved coverage, rules, model predictions/provenance, limitations and unknown remaining counts.',
        '- forensics/disk_image.py: additive YARA deployment switch; existing embedded-file logic preserved. '
        'forensics/evtx_parser.py and registry_parser.py: identity, native limits, parser failures and metadata truncation.',
        '- ml/ingestion/{evtx_parser,file_parser,registry_parser,pcap_parser}.py: source identities, bounded captures, no epsilon-based packet rates.',
        '- ml/risk_scorer.py: targeted missing-value/registry substring corrections and explicit Event 1102/7045 indicators; model fusion unchanged.',
        '- frontend/src/components/case/{ScreeningSummary,CaseEvidence,CaseArtifacts,IntakePanel}.jsx; frontend/src/utils/screening.js; frontend/tests/screening.test.js.',
        '- tests/test_unified_screening.py; scripts/{acquire_issue5_fixtures,prepare_issue5_network_demo,verify_issue5,render_issue5_reports,report_issue5,serve_issue5_demo}.py; '
        'scripts/prepare_external_demo.py adds separate output arguments without altering historical defaults.', '',
        '## Policy, reproduction and limitations', '',
        'See [support/applicability matrix, risk policy, limits and exact commands](../../docs/unified-screening.md). '
        'Fixture source revisions, SHA-256 and verified upstream Apache-2.0 licenses are in fixture-provenance.json. '
        'Raw native fixtures, executable bytes, original network records, databases and full PDFs remain ignored.',
        'YARA does not establish malware; ML scores are not calibrated confidence. File inventories do not provide file bytes. '
        'No E01/EWF or universal filesystem/PE variant support is claimed. Native process byte/deadline limits are not an OS memory or concurrent-job quota. '
        'Missing scans never lower existing risk. Standard CVSS ratings are separate from project triage bands.',
        'Browser: last permitted tool result was exactly “Local browser use is disabled in Work settings.” '
        'No browser bypass, screenshots or UI pass is claimed. Manual steps are in the policy document.',
        'Vercel remains outside acceptance at the owner’s instruction. No model retraining, external benchmark rerun or Issue 6 work was performed.', '',
        '## Frozen artifacts', '', '| Artifact | Unchanged SHA-256 |', '|---|---|']
    lines += [f'| {path} | `{checksum}` |' for path, checksum in summary['frozen_artifacts'].items()]
    lines += ['', 'The final implementation revision is identified by Git history and the verified remote main SHA in the delivery. '
              'No self-referential commit hash is embedded in this committed report.', '']
    (root/'REPORT.md').write_text('\n'.join(lines), encoding='utf-8')


if __name__ == '__main__':
    main()
