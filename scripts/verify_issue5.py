"""Real HTTP -> native engines -> owned MongoDB -> saved-case PDF verification.

No model fitting or recovered-file execution. Browser interactions remain
unverified if local browser use is disabled. Full evidence/PDFs stay ignored.
"""
import hashlib
import io
import json
from pathlib import Path
import threading
import time
import uuid

import requests
from pypdf import PdfReader
from werkzeug.serving import make_server

from backend.app import create_app
from backend.db import get_db, init_db, close_db
from scripts.verify_issue2 import make_pe_fixture


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    run = uuid.uuid4().hex
    work = Path('.test-artifacts/issue5')/run; work.mkdir(parents=True)
    output = Path('test-results/issue-5')/run; output.mkdir(parents=True)
    image, rules, pe_source = make_pe_fixture(work/'fat12')
    # Explicitly test-only structural signature; it does not assert malware.
    (rules/'harmless_pe.yar').write_text('rule Harmless_PE_Header_Test { meta: description="Test-only PE header, not malware" severity="informational" condition: uint16(0)==0x5a4d and uint32(uint32(0x3c))==0x4550 }')
    import pip
    pe = Path(pip.__file__).parent/'_vendor/distlib/t64.exe'
    listing = work/'listing.csv'; listing.write_text('FileName,FilePath\nordinary.txt,/ordinary.txt\nsecond.txt,/second.txt\n')
    events = work/'events.csv'; events.write_text('EventID,TimeCreated,Account\n1102,2026-01-01T12:00:00,test\n4624,2026-01-01T12:00:00,test\n')
    registry = work/'export.reg'; registry.write_text('Windows Registry Editor Version 5.00\n[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\n"HarmlessDemo"="ordinary.txt"\n')
    from scapy.all import Ether, IP, UDP, Raw, wrpcap
    capture = work/'harmless.pcap'
    wrpcap(str(capture), [Ether()/IP(src='192.0.2.1', dst='198.51.100.1')/UDP(sport=12345, dport=53)/Raw(b'Harmless offline capture')])
    db_name = 'cyber_triage_test_'+run
    app = create_app({'TESTING':True, 'APP_ENV':'test', 'DB_MODE':'mongo',
        'MONGO_URI':'mongodb://127.0.0.1:27018', 'MONGO_DB':db_name, 'MONGO_TIMEOUT_MS':10000,
        'TEMP_DIR':str(work/'uploads'), 'YARA_RULES_DIR':str(rules.resolve()),
        'SCREENING_LIMITS':{'max_records':2000, 'max_findings':30}})
    with app.app_context():
        assert get_db().cases.count_documents({}) == 0
        get_db().test_ownership.insert_one({'_id':run}); init_db()
    server = make_server('127.0.0.1',5069,app)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    session = requests.Session(); session.trust_env = False
    base = 'http://127.0.0.1:5069'
    frozen_paths = ['models/cicids2017_baseline.joblib','models/supervised_binary.joblib',
                    'models/pe/EMBER2024_PE.model','test-results/issue-4/evaluation.json']
    frozen = {path:sha(path) for path in frozen_paths}
    external_demo = Path('.test-artifacts/issue5/external-demo/demo.csv')
    if not external_demo.exists():
        external_demo = Path('.test-artifacts/issue4/demo.csv')
    scenarios = [
        ('disk', image, '/api/forensics/ingest', {}),
        ('standalone-pe', pe, '/api/ingest', {}),
        ('cicids2017-xgb', Path('.test-artifacts/issue3/demo.csv'), '/api/analyze', {'detector':'supervised'}),
        ('cicids2017-iforest', Path('.test-artifacts/issue3/demo.csv'), '/api/ingest', {'kind':'pcap','detector':'baseline'}),
        ('external-csv', external_demo, '/api/analyze', {'dataset':'cse-cic-ids2018','detector':'supervised'}),
        ('native-evtx', Path('.test-artifacts/issue5/fixtures/system.evtx'), '/api/ingest', {}),
        ('native-registry', Path('.test-artifacts/issue5/fixtures/SYSTEM.hive'), '/api/forensics/ingest', {}),
        ('event-export', events, '/api/ingest', {'kind':'evtx'}),
        ('registry-export', registry, '/api/ingest', {'kind':'registry'}),
        ('pcap', capture, '/api/ingest', {'kind':'pcap'}),
    ]
    results = {}
    try:
        for name, source, route, fields in scenarios:
            before = sha(source)
            if name.startswith('cicids2017'):
                assert before == json.loads(Path('test-results/issue-3/demo-source.json').read_text())['csv_sha256']
            if name == 'external-csv':
                assert before == json.loads(Path('test-results/issue-4/demo-manifest-summary.json').read_text())['csv_sha256']
            case = session.post(base+'/api/cases', json={'title':'Issue 5 controlled '+name}, timeout=30); case.raise_for_status()
            case_id = case.json()['id']
            started = time.perf_counter()
            with source.open('rb') as stream:
                response = session.post(base+route, data={'caseId':case_id, **fields}, files={'file':(source.name,stream)}, timeout=180)
            response.raise_for_status(); result = response.json()
            assert result['persisted'] and result['evidence_sha256'] == before == sha(source)
            assert set(result['screening']) == {'yara','forensic_rules','network_ml','pe_ml'}
            if name == 'disk':
                by_name = {r['FileName']:r for r in result['disk_scan']['findings']}
                assert by_name['POSITIVE.TXT']['scan_status'] == 'MATCHED'
                assert by_name['NEGATIVE.TXT']['scan_status'] == 'SCANNED_NO_MATCH'
                assert by_name['EMPTY.TXT']['scan_status'] == 'SCANNED_NO_MATCH'
                assert by_name['LAUNCH64.BIN']['pe_ml']['status'] == 'CLASSIFIED'
                assert result['screening']['yara']['input_scope'] == 'embedded_file_bytes'
            if name == 'standalone-pe':
                assert result['screening']['pe_ml']['examined'] == 1
                assert result['screening']['yara']['findings'] >= 1
            if name.startswith('cicids2017') or name == 'external-csv':
                assert result['screening']['network_ml']['status'] == 'COMPLETED'
            if name == 'pcap':
                assert result['screening']['network_ml']['status'] == 'NOT_APPLICABLE'
                assert not any(r.get('model_score') for r in result['artifacts'])
            reopened = session.get(base+'/api/cases/'+case_id, timeout=30); reopened.raise_for_status()
            saved = reopened.json()['evidence']['sources'][0]['screening_result']
            for key in ('screening','coverage','findings','overall_scan_status'):
                assert saved[key] == result[key], key
            with app.app_context():
                db = get_db(); history = db.ingestions.find_one({'id':result['intake_id']})
                assert history['screening_result'] == saved
                assert db.artifacts.count_documents({'intake_id':result['intake_id']}) == result['stored']
                assert db.artifacts.count_documents({'intake_id':result['intake_id'], 'evidence_sha256':before}) == result['stored']
            pdf = session.get(base+'/api/report/'+case_id, timeout=60); pdf.raise_for_status()
            reader = PdfReader(io.BytesIO(pdf.content)); text = ' '.join(' '.join(page.extract_text() for page in reader.pages).split())
            for token in ['Unified screening', before, result['overall_scan_status'], 'No detection does not establish safety']:
                assert token in text, token
            for scan in result['screening'].values():
                assert scan['status'] in text
            (work/(name+'.pdf')).write_bytes(pdf.content)
            (work/(name+'-api.json')).write_text(json.dumps(result, indent=2))
            (work/(name+'-pdf-text.txt')).write_text(text, encoding='utf-8')
            public = {k:result[k] for k in ('evidence_type','evidence_sha256','overall_scan_status','screening','coverage','warnings')}
            if not name.startswith('native-'):
                public.update(findings=result['findings'], iocs=result['iocs'])
            # Avoid publishing historical host records, raw flows, or paths from native fixtures.
            (output/(name+'-coverage.json')).write_text(json.dumps(public, indent=2))
            results[name] = {'case_id':case_id, 'intake_id':result['intake_id'], 'stored':result['stored'],
                'source_size':source.stat().st_size, 'sha256_before':before, 'sha256_after':sha(source),
                'status':result['overall_scan_status'], 'http_seconds':time.perf_counter()-started,
                'mongo_roundtrip':'PASS', 'pdf':'PASS', 'pdf_pages':len(reader.pages), 'pdf_sha256':hashlib.sha256(pdf.content).hexdigest()}
            print(name, json.dumps(results[name]), flush=True)
        # Real config-controlled scanner absence, no dependency monkeypatches.
        app.config['SCREENING_YARA_ENABLED'] = False
        with listing.open('rb') as stream:
            response = session.post(base+'/api/ingest', data={'kind':'file'}, files={'file':(listing.name, stream)}, timeout=30)
        response.raise_for_status(); disabled = response.json()
        assert disabled['screening']['yara']['status'] == 'UNAVAILABLE' and disabled['overall_scan_status'] == 'PARTIAL'
        app.config['SCREENING_YARA_ENABLED'] = True
        app.config['SCREENING_LIMITS'] = {'max_records':1, 'max_yara_bytes':1}
        with listing.open('rb') as stream:
            response = session.post(base+'/api/ingest', data={'kind':'file'}, files={'file':(listing.name,stream)}, timeout=30)
        response.raise_for_status(); limited = response.json()
        assert limited['screening']['forensic_rules']['skipped'] == 1
        assert limited['screening']['yara']['status'] == 'SKIPPED_LIMIT'
        invalid = session.post(base+'/api/ingest', files={'file':('unsupported.exe', b'not an executable')}, timeout=30)
        assert invalid.status_code == 400 and invalid.json()['overall_scan_status'] == 'INVALID_INPUT'
        assert {path:sha(path) for path in frozen_paths} == frozen
        summary = {'run':run, 'database':db_name, 'results':results, 'frozen_artifacts':frozen,
            'frozen_artifacts_unchanged':True, 'pe_fixture_provenance':pe_source,
            'missing_scanner':{k:disabled[k] for k in ('screening','overall_scan_status','warnings')},
            'limits':{k:limited[k] for k in ('screening','overall_scan_status','coverage','warnings')},
            'unsupported':invalid.json(), 'browser':'UNVERIFIED: Local browser use is disabled in Work settings; no bypass or fabricated screenshots',
            'limitations':['Native registry enumeration capped at 2000 records; skipped remainder unknown and explicitly partial',
                           'Harmless PE predictions demonstrate inference, not malware evaluation',
                           'Packet capture is rule-only; no verified CICIDS feature equivalence']}
        (output/'summary.json').write_text(json.dumps(summary, indent=2))
        Path('test-results/issue-5/latest.json').write_text(json.dumps({'run':run, 'output':str(output), 'work':str(work)}, indent=2))
    finally:
        server.shutdown(); thread.join(); session.close(); close_db(app)


if __name__ == '__main__':
    main()
