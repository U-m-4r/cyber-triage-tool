"""Coverage/identity regressions. Real model and parser checks use real fixtures."""
import hashlib
import io
from pathlib import Path

import pytest
from backend import screening
from forensics import yara_scanner
from ml.risk_scorer import RiskScorer


def launcher():
    import pip
    path = Path(pip.__file__).parent/'_vendor/distlib/t64.exe'
    if not path.exists():
        pytest.skip('Redistributable distlib launcher unavailable')
    return path


def upload(client, data, name='input.csv', route='/api/ingest', **fields):
    response = client.post(route, data={'file':(io.BytesIO(data), name), **fields})
    payload = response.json
    response.request.environ['wsgi.input'].close()
    response.close()
    return response.status_code, payload


@pytest.mark.parametrize('route', ['/api/ingest', '/api/forensics/ingest', '/api/analyze'])
def test_structural_pe_reaches_same_engines(client, route):
    path = launcher()
    status, result = upload(client, path.read_bytes(), name='launcher.bin', route=route)
    assert status == 200, result
    assert result['evidence_type'] == 'pe'
    assert result['screening']['network_ml']['status'] == 'NOT_APPLICABLE'
    if Path('models/pe/EMBER2024_PE.model').exists():
        assert result['screening']['pe_ml']['status'] == 'COMPLETED'
        assert result['records'][0]['pe_ml']['status'] == 'CLASSIFIED'
    else:
        assert result['screening']['pe_ml']['status'] == 'UNAVAILABLE'
    assert result['evidence_sha256'] == hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.skipif(not yara_scanner.AVAILABLE, reason='Real YARA engine unavailable')
def test_container_signature_never_assigned_to_registry_record(client, isolated_app, tmp_path):
    rules = tmp_path/'rules'; rules.mkdir()
    (rules/'test.yar').write_text('rule Marker {strings:$x="HARMLESS_CONTAINER_MARKER" condition:$x}')
    isolated_app.config['YARA_RULES_DIR'] = str(rules)
    status, result = upload(client, b'RegistryKey,RegistryValue\nHKCU/Software/Ordinary,HARMLESS_CONTAINER_MARKER\n', kind='registry')
    assert status == 200, result
    assert result['artifacts'][0]['matched_rules'] == 'None'
    assert result['screening']['yara']['findings'] == 1
    assert result['findings'][0]['artifact'] == {'container':'input.csv'}
    assert result['findings'][0]['risk_score'] == 25


@pytest.mark.parametrize('configuration,expected', [
    ({'SCREENING_YARA_ENABLED':False}, 'UNAVAILABLE'),
    ({'SCREENING_LIMITS':{'max_yara_bytes':1}}, 'SKIPPED_LIMIT'),
])
def test_missing_or_skipped_not_negative(client, isolated_app, configuration, expected):
    isolated_app.config.update(configuration)
    code, result = upload(client, b'FileName,FilePath\nordinary.txt,/ordinary.txt\n', kind='file')
    assert code == 200
    # Dependency/deployment availability is checked before eligibility limits.
    # A host without YARA must report UNAVAILABLE even for oversized targets.
    actual_expected = expected if yara_scanner.AVAILABLE else 'UNAVAILABLE'
    assert result['screening']['yara']['status'] == actual_expected
    assert result['overall_scan_status'] == 'PARTIAL'
    assert result['screening']['pe_ml']['status'] == 'NOT_APPLICABLE'
    assert result['warnings']


@pytest.mark.skipif(not yara_scanner.AVAILABLE, reason='Real YARA compiler unavailable')
def test_invalid_rules_are_failed_not_no_match(client, isolated_app, tmp_path):
    (tmp_path/'broken.yar').write_text('invalid rule')
    isolated_app.config['YARA_RULES_DIR'] = str(tmp_path)
    code, result = upload(client, b'FileName\na.txt\n', kind='file')
    assert code == 200
    assert result['screening']['yara']['status'] == 'FAILED'
    assert result['screening']['yara']['reason']


def test_record_limit_reported_and_counters_agree(client, isolated_app):
    isolated_app.config['SCREENING_LIMITS'] = {'max_records':1}
    code, result = upload(client, b'FileName\na.txt\nb.txt\n', kind='file')
    assert code == 200
    assert result['summary']['total_records'] == 1
    assert result['coverage']['records_examined'] == 1
    assert result['screening']['forensic_rules']['skipped'] == 1
    assert result['overall_scan_status'] == 'PARTIAL'


@pytest.mark.parametrize('data,name', [(b'just text','.txt'), (b'\x00\xffgarbage','.exe')])
def test_unsupported_does_not_fall_through(client, data, name):
    code, result = upload(client, data, 'unsupported'+name)
    assert code == 400
    assert result['overall_scan_status'] == 'INVALID_INPUT'


def test_unrelated_registry_run_substring_and_absent_packet_mean_not_flagged():
    scorer = RiskScorer()
    assert scorer.apply_rules({'RegistryKey':'HKLM/Software/Pruning'}, 'registry') == (0, [])
    assert scorer.apply_rules({}, 'network') == (0, [])
    assert scorer.apply_rules({'RegistryKey':'HKCU/Software/Run'}, 'registry')[0] == .9


@pytest.mark.skipif(not yara_scanner.AVAILABLE, reason='Real YARA compiler unavailable')
def test_raw_yara_timeout_status(tmp_path, monkeypatch):
    path = tmp_path/'x'; path.write_bytes(b'harmless')
    def fail(*a, **k):
        raise TimeoutError('controlled timeout')
    monkeypatch.setattr(yara_scanner, 'scan_file', fail)
    _, result = screening.raw_yara(path, {'size_bytes':8, 'sha256':'x', 'original_filename':'x'}, {})
    assert result['status'] == 'FAILED'
    assert 'timeout' in result['reason']


@pytest.mark.parametrize('name,kind', [('system.evtx','evtx'), ('SYSTEM.hive','registry')])
def test_real_native_parser_coverage(client, isolated_app, name, kind):
    path = Path('.test-artifacts/issue5/fixtures')/name
    if not path.exists():
        pytest.skip('Pinned native parser fixtures not acquired')
    isolated_app.config['SCREENING_LIMITS'] = {'max_records':20}
    code, result = upload(client, path.read_bytes(), name='disguised.bin')
    assert code == 200, result
    assert result['evidence_type'] == kind
    assert result['screening']['forensic_rules']['examined'] > 0
    assert result['coverage']['parsing']['status'] == 'PARTIAL'
    assert result['coverage']['parsing']['enumeration_complete'] is False
    assert result['screening']['yara']['input_scope'] == 'uploaded_container_bytes'


def test_native_event_rule_preserves_identity(client):
    data = b'EventID,TimeCreated,EventRecordID\n1102,2026-01-01T12:00:00,819\n'
    code, result = upload(client, data, kind='evtx')
    assert code == 200
    assert result['artifacts'][0]['priority'] == 'CRITICAL'
    assert result['findings'][0]['artifact']['record_id'] == 0
    assert result['findings'][0]['artifact']['RecordID'] == '819'


@pytest.mark.parametrize('option,expected', [({'PE_ML_OPTIONS':{'model_path':'missing.model'}}, 'UNAVAILABLE'),
    ({'SCREENING_LIMITS':{'max_pe_bytes':1}}, 'SKIPPED_LIMIT')])
def test_real_pe_unavailable_and_limit(client, isolated_app, option, expected):
    path = launcher()
    isolated_app.config.update(option)
    code, result = upload(client, path.read_bytes(), 'pe.exe')
    assert code == 200
    assert result['screening']['pe_ml']['status'] == expected
    assert result['screening']['yara']['status'] == ('COMPLETED' if yara_scanner.AVAILABLE else 'UNAVAILABLE')
    assert result['overall_scan_status'] == 'PARTIAL'


def test_corrupt_pe_has_failed_extraction(client):
    code, result = upload(client, b'MZ'+bytes(100), 'corrupt.exe')
    assert code == 200
    assert result['screening']['pe_ml']['status'] == 'FAILED'
    assert result['records'][0]['pe_ml']['status'] == 'EXTRACTION_FAILED'


@pytest.mark.skipif(not yara_scanner.AVAILABLE, reason='Real YARA compiler unavailable')
def test_empty_rules_are_unavailable_not_negative(client, isolated_app, tmp_path):
    isolated_app.config['YARA_RULES_DIR'] = str(tmp_path)
    code, result = upload(client, b'FileName\nordinary.txt\n', kind='file')
    assert code == 200
    assert result['screening']['yara']['status'] == 'UNAVAILABLE'
    assert result['screening']['yara']['reason'] == 'RULES_NOT_CONFIGURED'


def test_capture_single_packet_no_fabricated_rate_and_no_ml(client, tmp_path):
    pytest.importorskip('scapy.all', reason='Real capture parser unavailable')
    from scapy.all import Ether, IP, UDP, Raw, wrpcap
    path = tmp_path/'small.pcap'
    wrpcap(str(path), [Ether()/IP(src='192.0.2.1', dst='198.51.100.1')/UDP()/Raw(b'harmless')])
    code, result = upload(client, path.read_bytes(), 'disguised.csv', kind='pcap')
    assert code == 200, result
    assert result['screening']['network_ml']['status'] == 'NOT_APPLICABLE'
    row = result['artifacts'][0]
    assert 'Flow Packets/s' not in row and 'Flow Bytes/s' not in row
    assert row['Source IP'] == '192.0.2.1'
    assert row['matched_rules'] == 'None'


def test_parser_worker_timeout_is_explicit(monkeypatch):
    import subprocess
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired('controlled worker', .01)
    monkeypatch.setattr(subprocess, 'run', timeout)
    with pytest.raises(TimeoutError, match='worker terminated'):
        screening.parse_export('unused', 'file', 1, timeout=.01)


def test_supervised_provenance_is_bson_safe(tmp_path):
    from bson import BSON
    path = tmp_path/'sample.csv'; path.write_bytes(b'Flow Duration\n1\n')
    custody = {'size_bytes':path.stat().st_size, 'sha256':'test', 'original_filename':path.name}
    result = screening.summarize(path, custody, 'network_csv', [], {'SCREENING_YARA_ENABLED':False},
        network={'model_id':'test', 'provenance':{'label_map':{0:'BENIGN',1:'ATTACK'}}})
    BSON.encode(result)
    assert result['screening']['network_ml']['model']['provenance']['label_map'] == {'0':'BENIGN','1':'ATTACK'}


@pytest.mark.skipif(not yara_scanner.AVAILABLE, reason='Real YARA engine unavailable')
def test_detail_cap_retains_all_container_signatures(client, isolated_app, tmp_path):
    rules = tmp_path/'rules'; rules.mkdir()
    (rules/'test.yar').write_text('rule HarmlessMarker {strings:$x="HARMLESS_MARKER" condition:$x}')
    isolated_app.config.update(YARA_RULES_DIR=str(rules), SCREENING_LIMITS={'max_findings':1})
    code, result = upload(client, b'FileName,FilePath\na.exe,/Temp/a.exe\nHARMLESS_MARKER,/ordinary.txt\n', kind='file')
    assert code == 200
    assert result['coverage']['findings_truncated'] is True
    assert len(result['findings']) == 1
    assert result['findings'][0]['detection_sources'] == ['forensic_rules']
    assert len(result['iocs']) == 1
    assert result['iocs'][0]['rule'] == 'HarmlessMarker'
