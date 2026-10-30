"""Real harmless PE disk -> HTTP -> owned MongoDB -> report experiment.

Generated executables/images remain in ignored .test-artifacts. Never executed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import threading
import time
import uuid
import requests
from werkzeug.serving import make_server
from backend.app import create_app
from backend.db import get_db, init_db
from scripts.verify_file_yara import make_fixture


def make_pe_fixture(directory):
    from pyfatfs.PyFatFS import PyFatFS
    import pip
    source = Path(pip.__file__).parent / '_vendor/distlib'
    image, rules = make_fixture(directory)
    provenance = []
    with PyFatFS(str(image)) as filesystem:
        for original, target in [('t64.exe', '/LAUNCH64.BIN'), ('t32.exe', '/LAUNCH32.EXE')]:
            data = (source / original).read_bytes()
            filesystem.writebytes(target, data)
            provenance.append({'file_path': target, 'source': str(source / original),
                               'sha256': hashlib.sha256(data).hexdigest(), 'size_bytes': len(data),
                               'description': 'Harmless PyPA distlib console launcher bundled with pip; never executed'})
    Path(directory, 'PE-LICENSE.txt').write_bytes((source / 'LICENSE.txt').read_bytes())
    return image, rules, provenance


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--serve', action='store_true')
    args = parser.parse_args()
    run = uuid.uuid4().hex
    out = Path('test-results/issue-2') / run
    out.mkdir(parents=True)
    image, rules, provenance = make_pe_fixture(Path('.test-artifacts/issue2') / run)
    database = 'cyber_triage_test_' + run
    app = create_app({'TESTING': True, 'APP_ENV': 'test', 'DB_MODE': 'mongo',
                      'MONGO_URI': 'mongodb://127.0.0.1:27018', 'MONGO_DB': database,
                      'MODEL_PATH': 'missing.joblib', 'YARA_RULES_DIR': str(rules.resolve()),
                      'TEMP_DIR': str(image.parent/'uploads')})
    identity_path = '/__issue2_' + run
    app.add_url_rule(identity_path, 'experiment_identity', lambda: run)
    with app.app_context():
        assert get_db().cases.count_documents({}) == 0
        get_db().test_ownership.insert_one({'_id': run, 'purpose': 'Synthetic Issue 2 verification'})
        init_db()
    server = make_server('127.0.0.1', 5029, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    session = requests.Session()
    session.trust_env = False
    base = 'http://127.0.0.1:5029'
    assert session.get(base + identity_path, timeout=10).text == run
    response = session.post(base+'/api/cases', json={'title': 'Issue 2 real PE + YARA demonstration'}, timeout=30)
    response.raise_for_status()
    case_id = response.json()['id']
    before = hashlib.sha256(image.read_bytes()).hexdigest()
    started = time.perf_counter()
    with image.open('rb') as stream:
        response = session.post(base+'/api/forensics/ingest', data={'caseId': case_id},
                                files={'file': (image.name, stream)}, timeout=120)
    request_seconds = time.perf_counter() - started
    response.raise_for_status()
    payload = response.json()
    assert payload['persisted'], payload
    scan = payload['disk_scan']
    assert scan['files_scanned'] == 6 and scan['files_with_yara_matches'] == 1
    assert scan['pe_ml']['files_classified'] == scan['pe_ml']['pe_files_discovered'] == 2
    assert scan['pe_ml']['classification_errors'] == 0 and scan['scan_status'] == 'COMPLETE'
    case = session.get(base+'/api/cases/'+case_id, timeout=30).json()
    artifacts = session.get(base+'/api/artifacts', params={'case_id': case_id}, timeout=30).json()['artifacts']
    history = session.get(base+'/api/ingestions', params={'case_id': case_id}, timeout=30).json()
    assert len(artifacts) == 6
    for expected in provenance:
        row = next(r for r in artifacts if r['FilePath'] == expected['file_path'])
        original = next(r for r in scan['findings'] if r['FilePath'] == expected['file_path'])
        assert row['pe_ml'] == original['pe_ml']
        assert row['pe_ml']['status'] == 'CLASSIFIED'
        assert row['pe_ml']['sha256'] == row['sha256'] == expected['sha256']
        assert row['evidence_sha256'] == before and row['intake_id'] == payload['intake_id']
        assert row['yara_matches'] == []
    marker = next(r for r in artifacts if r['FilePath'] == '/POSITIVE.TXT')
    assert marker['pe_ml']['status'] == 'NOT_APPLICABLE' and len(marker['yara_matches']) == 1
    after = hashlib.sha256(image.read_bytes()).hexdigest()
    assert before == after == payload['evidence']['sha256']
    pdf_response = session.get(base+'/api/report/'+case_id, timeout=30)
    pdf_response.raise_for_status()
    (out/'forensic-report.pdf').write_bytes(pdf_response.content)
    import io
    from pypdf import PdfReader
    text = ' '.join(' '.join(p.extract_text() for p in PdfReader(io.BytesIO(pdf_response.content)).pages).split())
    for expected in ['PE malware ML: 2 classified', 'Harmless_File_Marker', 'LAUNCH64.BIN',
                     'LAUNCH32.EXE', before, 'not calibrated confidence']:
        assert expected in text, expected
    for row in artifacts:
        if row['pe_ml']['status'] == 'CLASSIFIED':
            assert str(row['pe_ml']['model_score']) in text
    summary = {'run': run, 'case_id': case_id, 'database': database,
               'sha256_before': before, 'sha256_after': after, 'integrity': 'PASS',
               'api_request_seconds': round(request_seconds,6), 'scan': {k:v for k,v in scan.items() if k!='findings'},
               'fixture': str(image.resolve()), 'pe_sources': provenance, 'output': str(out.resolve())}
    for name, obj in [('summary',summary), ('upload',payload), ('case',case), ('artifacts',artifacts), ('history',history)]:
        (out/(name+'.json')).write_text(json.dumps(obj,indent=2))
    (out/'pdf-text.txt').write_text(text, encoding='utf-8')
    (out/'PE-LICENSE.txt').write_bytes((image.parent/'PE-LICENSE.txt').read_bytes())
    print(json.dumps(summary,indent=2), flush=True)
    if args.serve:
        thread.join()
    else:
        server.shutdown()


if __name__ == '__main__':
    main()
