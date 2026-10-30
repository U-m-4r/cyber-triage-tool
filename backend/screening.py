"""Evidence-aware coverage contract. Existing engines retain their own raw outputs.

No clean verdict is inferred from coverage. Container signatures never identify
an event/flow/value. Policy v1 preserves network/PE scoring and uses a 25-point
review floor for a supplementary container signature, never an ML probability.
"""
import csv
import hashlib
import importlib.metadata
import io
import json
from pathlib import Path
import time
import subprocess
import sys

from forensics import yara_scanner
from ml.risk_scorer import RULES

VERSION = 'unified-screening-v1'
STATES = {'COMPLETED', 'PARTIAL', 'NOT_APPLICABLE', 'UNAVAILABLE',
          'SKIPPED_LIMIT', 'INVALID_INPUT', 'FAILED'}
MODULES = ('yara', 'forensic_rules', 'network_ml', 'pe_ml')


def forensic_rule_matches(row):
    return [item.strip() for item in row.get('matched_rules', 'None').split(',')
            if item.strip() != 'None' and not item.strip().startswith('YARA:')]


def parse_export(path, kind, limit, timeout=60):
    """Bound native/parser hangs in a separate process, with byte caps at intake."""
    try:
        process = subprocess.run([sys.executable, '-m', 'backend.screening_worker',
            str(path), kind, str(limit)], cwd=str(Path(__file__).resolve().parents[1]),
            capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise TimeoutError('Parser deadline exceeded; worker terminated without a complete result') from None
    result = __import__('json').loads(process.stdout)
    if process.returncode or 'error' in result:
        raise ValueError(result.get('error', 'Parser worker failed'))
    return result['records'], result['parsing']


def identify(path, hint=None):
    """Signature/structure first. A disk suffix is only a request to probe TSK."""
    with open(path, 'rb') as source:
        head = source.read(65536)
    if not head:
        return 'invalid'
    if head.startswith(b'MZ'):
        return 'pe'  # Full supported-PE validation occurs in pe_features.
    if head.startswith(b'ElfFile\x00'):
        return 'evtx'
    if head.startswith(b'regf'):
        return 'registry'
    if head[:4] in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1',
                    b'\xa1\xb2\x3c\x4d', b'\x0a\x0d\x0d\x0a'):
        return 'pcap'
    if Path(path).suffix.lower() in {'.dd', '.raw', '.img', '.e01', '.001'}:
        return 'disk_image'
    try:
        text = head.decode('utf-16' if head.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8-sig')
    except UnicodeError:
        return 'unsupported'
    if '\x00' in text:
        return 'unsupported'
    first = next(csv.reader(io.StringIO(text)), [])
    columns = {c.strip() for c in first}
    if {'Flow Duration', 'Flow Packets/s', 'Flow Bytes/s'} & columns:
        return 'network_csv'
    if text.lstrip().startswith(('Windows Registry Editor', 'REGEDIT4', '[HKEY')):
        return 'registry_export'
    # Explicit export schema validation is subsequently performed by its parser.
    if hint in ('evtx', 'registry', 'file', 'pcap') and text.lstrip().startswith(('{', '[', '<')):
        return hint + '_export'
    schema = {'evtx': {'EventID', 'EventId', 'event_id'},
              'registry': {'RegistryKey', 'Key', 'key'},
              'file': {'FileName', 'FilePath', 'filename', 'path'},
              'pcap': {'src_ip', 'Source IP', 'src'}}
    for kind, names in schema.items():
        if names & columns and (hint is None or hint == kind):
            return kind + '_export'
    return 'unsupported'


def module(name, status='NOT_APPLICABLE', scope='none', examined=0, skipped=0,
           findings=0, identifier=None, reason=None, seconds=0, version=VERSION):
    if status not in STATES:
        raise ValueError('Invalid screening status')
    return {'scanner': name, 'scanner_version': version, 'identifier': identifier,
            'applicable': status != 'NOT_APPLICABLE', 'status': status, 'input_scope': scope,
            'examined': examined, 'skipped': skipped, 'findings': findings,
            'processing_seconds': round(seconds, 6), 'reason': reason}


def raw_yara(path, custody, config):
    started = time.monotonic()
    scope = 'individual_file_bytes' if identify(path) == 'pe' else 'uploaded_container_bytes'
    size = custody['size_bytes']
    limits = config.get('SCREENING_LIMITS', {})
    maximum = limits.get('max_yara_bytes', 16 * 1024 * 1024)
    rules_dir = config.get('YARA_RULES_DIR') or yara_scanner.DEFAULT_RULES_DIR
    if not config.get('SCREENING_YARA_ENABLED', True) or not yara_scanner.AVAILABLE:
        return [], module('YARA', 'UNAVAILABLE', scope, skipped=1,
                          reason=yara_scanner.UNAVAILABLE_REASON or 'Disabled by deployment configuration')
    if size > maximum:
        return [], module('YARA', 'SKIPPED_LIMIT', scope, skipped=1,
                          reason=f'Container exceeds {maximum} byte scan limit; no prefix-only verdict')
    rule_id = None
    try:
        rule_id = yara_scanner.ruleset_id(rules_dir)
        rules = yara_scanner.compile_rules(rules_dir)
        if rules is None:
            return [], module('YARA', 'UNAVAILABLE', scope, skipped=1, identifier=rule_id,
                              reason='RULES_NOT_CONFIGURED')
        hits = yara_scanner.scan_file(path, compiled_rules=rules,
                                     timeout=limits.get('yara_timeout', 10))
        unique = {}
        for hit in hits:
            hit.update(target=custody['original_filename'], input_scope=scope,
                       evidence_sha256=custody['sha256'], ruleset_id=rule_id)
            unique[(hit['namespace'], hit['rule'])] = hit
        hits = list(unique.values())
        return hits, module('YARA', 'COMPLETED', scope, examined=1, findings=len(hits),
                            identifier=rule_id, seconds=time.monotonic()-started,
                            version=importlib.metadata.version('yara-python'))
    except Exception as exc:
        return [], module('YARA', 'FAILED', scope, skipped=1, identifier=rule_id,
                          reason=str(exc), seconds=time.monotonic()-started)


def _ml_module(rows, model=None, seconds=0):
    applicable = [r['pe_ml'] for r in rows if 'pe_ml' in r and r['pe_ml'].get('status') != 'NOT_APPLICABLE']
    if not applicable:
        return module('PE malware ML', reason='No supported PE content available')
    good = [p for p in applicable if p.get('status') == 'CLASSIFIED']
    statuses = {p.get('status') for p in applicable}
    status = 'COMPLETED' if len(good) == len(applicable) else 'PARTIAL' if good else (
        'UNAVAILABLE' if statuses == {'MODEL_UNAVAILABLE'} else
        'SKIPPED_LIMIT' if all(str(s).startswith('SKIPPED') for s in statuses) else 'FAILED')
    first = model or next(iter(applicable), {})
    result = module('PE malware ML', status, 'individual_file_bytes', len(good),
                  len(applicable)-len(good), sum(p.get('prediction') == 'malicious' for p in good),
                  identifier=first.get('model_id'), version=first.get('feature_extractor_version', VERSION),
                  seconds=seconds, reason='; '.join(sorted({p.get('reason', p.get('status', ''))
                      for p in applicable if p.get('status') != 'CLASSIFIED'})) or None)
    result['model'] = {key:first.get(key) for key in ('model_id', 'model_version', 'model_sha256', 'feature_extractor_version', 'threshold')}
    result['prediction_counts'] = {'malicious':sum(p.get('prediction') == 'malicious' for p in good),
                                    'benign':sum(p.get('prediction') == 'benign' for p in good)}
    return result


def summarize(path, custody, evidence_type, rows, config, *, network=None,
              disk=None, parsing=None, iocs=None, yara=None, rule_seconds=0):
    """Orchestrate supplementary bytes + normalize measured engine outputs."""
    started = time.monotonic()
    # Model provenance label maps have numeric Python keys. JSON/BSON storage
    # uses string keys consistently with the existing network audit contract.
    if network:
        network = json.loads(json.dumps(network))
    modules = {key: module(key, reason='Not applicable to this evidence representation') for key in MODULES}
    warnings = []
    if disk is not None:
        parsing = {'status':'COMPLETED' if disk['enumeration_complete'] else 'PARTIAL',
                   'enumeration_complete':disk['enumeration_complete'],
                   'skipped_count_exact':disk['enumeration_complete'],
                   'skipped':0, 'reason':None if disk['enumeration_complete'] else 'Filesystem enumeration incomplete; remaining entries unknown'}
        iocs = [dict(hit, evidence_sha256=custody['sha256'], input_scope='embedded_file_bytes',
                     artifact_location=r.get('artifact_location'), sha256=r.get('sha256'))
                for r in rows for hit in r.get('yara_matches', [])]
        state = 'COMPLETED' if disk['scan_status'] == 'COMPLETE' else 'PARTIAL'
        if disk['yara_status'] != 'READY':
            state = 'UNAVAILABLE' if disk['yara_status'] in ('YARA_UNAVAILABLE', 'RULES_NOT_CONFIGURED') else 'FAILED'
        modules['yara'] = module('YARA', state, 'embedded_file_bytes', disk['files_scanned'],
            disk['files_skipped'], len(iocs), disk['ruleset_id'],
            seconds=disk['timings']['yara_execution_seconds'],
            version=importlib.metadata.version('yara-python') if yara_scanner.AVAILABLE else 'unavailable')
        modules['pe_ml'] = _ml_module(rows, disk['pe_ml']['model'], disk['pe_ml']['processing_seconds'])
        warnings.extend(disk['warnings'])
    else:
        if yara is None:
            iocs, yara = raw_yara(path, custody, config)
        modules['yara'] = yara
        modules['pe_ml'] = _ml_module([r for r in rows if 'pe_ml' in r],
            seconds=sum(r.get('pe_ml', {}).get('processing_seconds', 0) for r in rows))
    rules_id = hashlib.sha256((Path(__file__).parents[1]/'ml/risk_scorer.py').read_bytes()).hexdigest()
    parse_status = (parsing or {}).get('status', 'COMPLETED')
    modules['forensic_rules'] = module('Forensic rules', parse_status, 'parsed_records', len(rows),
        (parsing or {}).get('skipped', 0), sum(bool(forensic_rule_matches(r)) for r in rows),
        rules_id, reason=(parsing or {}).get('reason'), seconds=rule_seconds)
    modules['forensic_rules']['skipped_count_exact'] = (parsing or {}).get('skipped_count_exact', True)
    if network:
        modules['network_ml'] = module('Network ML', parse_status, 'validated_network_flows', len(rows),
            (parsing or {}).get('skipped', 0), sum(r.get('binary_prediction') == 'ATTACK' for r in rows),
            network.get('model_id'), seconds=network.get('timings', {}).get('csv_inference_seconds', 0),
            version=network.get('model_version') or VERSION)
        modules['network_ml']['model'] = network
    elif evidence_type in ('pcap', 'pcap_export'):
        modules['network_ml'] = module('Network ML', reason='Packet-derived/exported statistics do not verify the CICIDS2017 feature contract; network rules only')
    findings = []
    for index, row in enumerate(rows):
        row.setdefault('record_id', index)
        row.setdefault('evidence_sha256', custody['sha256'])
    for row in rows:
        if row.get('matched_rules', 'None') != 'None' or row.get('binary_prediction') == 'ATTACK' or (
                row.get('pe_ml', {}).get('status') == 'CLASSIFIED' and row['pe_ml'].get('prediction') == 'malicious'):
            identity = {k: row.get(k) for k in ('artifact_location', 'FilePath', 'RegistryKey', 'RegistryValue',
                         'RecordID', 'record_id', 'source_row', 'source_line', 'sha256', 'inode', 'volume_offset') if row.get(k) is not None}
            findings.append({'evidence_sha256': custody['sha256'], 'artifact': identity,
                'detection_sources': [name for name, present in (
                    ('yara', bool(row.get('yara_matches'))),
                    ('forensic_rules', bool(forensic_rule_matches(row))),
                    ('network_ml', row.get('binary_prediction') == 'ATTACK'),
                    ('pe_ml', row.get('pe_ml', {}).get('prediction') == 'malicious')) if present],
                'matched_rules': row.get('matched_rules'), 'yara_matches': row.get('yara_matches', []),
                'forensic_rule_matches':forensic_rule_matches(row),
                'network_ml': {k: row[k] for k in ('model_id', 'binary_prediction', 'model_score', 'decision_threshold') if k in row},
                'pe_ml': row.get('pe_ml'), 'risk_score': row['risk_score'], 'priority': row['priority'],
                'risk_explanation': row.get('risk_explanation')})
    # Supplementary signatures belong to the container, never any parsed record.
    if disk is None and evidence_type != 'pe':
        for hit in iocs or []:
            findings.append({'evidence_sha256': custody['sha256'], 'artifact': {'container': custody['original_filename']},
                'detection_sources': ['yara'], 'yara_matches': [hit], 'risk_score': 25, 'priority': 'MEDIUM',
                'risk_explanation': 'Container signature review floor 25; no verified event/flow/value association; not proof of malware'})
    for key, value in modules.items():
        value['findings_unit'] = {'yara':'matched_rules', 'network_ml':'attack_or_anomaly_decisions',
                                 'pe_ml':'malicious_predictions', 'forensic_rules':'flagged_records'}[key]
        if value['status'] not in ('COMPLETED', 'NOT_APPLICABLE'):
            warnings.append(f"{key}: {value['status']}: {value.get('reason') or 'Coverage incomplete'}")
    if parsing and parsing.get('reason'):
        warnings.append(parsing['reason'])
    active = [m for m in modules.values() if m['applicable']]
    status = 'COMPLETED' if active and all(m['status'] == 'COMPLETED' for m in active) else 'PARTIAL'
    if disk and disk['scan_status'] != 'COMPLETE':
        status = 'PARTIAL'
    cap = config.get('SCREENING_LIMITS', {}).get('max_findings', 1000)
    return {'schema_version': VERSION, 'evidence_type': evidence_type, 'evidence_sha256': custody['sha256'],
            'overall_scan_status': status, 'screening': modules, 'findings': findings[:cap], 'iocs':iocs or [],
            'coverage': {'records_examined': len(rows), 'findings_total': len(findings),
                         'findings_returned': min(cap, len(findings)), 'findings_truncated': len(findings) > cap,
                         'parsing': parsing or {'status': 'COMPLETED'},
                         **({'disk':{key:disk[key] for key in ('total_files_discovered', 'total_eligible_files', 'files_scanned', 'files_skipped', 'enumeration_complete')}} if disk else {}),
                         'scope': 'Parsed allocated/default streams and supported records; no universal clean verdict'},
            'warnings': warnings + ([f'Finding details capped at {cap}; all artifact results remain in storage'] if len(findings)>cap else []), 'orchestration_seconds': round(time.monotonic()-started, 6),
            'risk_policy': 'Existing source-specific risk; PE malicious max floor; supplementary container YARA floor 25; risk bands are project policy, not CVSS'}
