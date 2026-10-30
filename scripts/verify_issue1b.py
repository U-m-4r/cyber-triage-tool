"""Real HTTP, owned MongoDB, and PDF experiment. Never touches production cases.

Run with --serve to leave the isolated backend available for browser verification.
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
from scripts.verify_file_yara import make_fixture, MARKER


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--serve', action='store_true')
    args = parser.parse_args()
    run_id = uuid.uuid4().hex
    output = Path('test-results/issue-1b') / run_id
    output.mkdir(parents=True)
    fixtures = Path('.test-artifacts/issue1b') / run_id
    image, rules = make_fixture(fixtures / 'positive')
    negative, _ = make_fixture(fixtures / 'negative', positive=False)
    database = 'cyber_triage_test_' + run_id
    app = create_app({'TESTING': True, 'APP_ENV': 'test', 'DB_MODE': 'mongo',
                      'MONGO_URI': 'mongodb://127.0.0.1:27018', 'MONGO_DB': database,
                      'YARA_RULES_DIR': str(rules.resolve()), 'MODEL_PATH': 'missing.joblib',
                      'TEMP_DIR': str(fixtures / 'uploads')})
    from backend.db import get_db, init_db
    identity_path = '/__issue1b_' + run_id
    app.add_url_rule(identity_path, 'experiment_identity', lambda: run_id)
    with app.app_context():
        db = get_db()
        # Fresh UUID database only. Never delete or reuse an investigation.
        assert db.name == database and db.cases.count_documents({}) == 0
        db.test_ownership.insert_one({'_id': run_id, 'purpose': 'Issue 1B synthetic evidence'})
        init_db()
    server = make_server('127.0.0.1', 5019, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = 'http://127.0.0.1:5019/api'
    session = requests.Session()
    session.trust_env = False
    identity = session.get('http://127.0.0.1:5019' + identity_path, timeout=10)
    assert identity.status_code == 200 and identity.text == run_id, 'Refusing to write to a different HTTP server'

    def get(path):
        response = session.get(base + path, timeout=30)
        response.raise_for_status()
        return response

    results = []
    for label, source, limits in [('positive', image, {}), ('negative', negative, {}),
                                   ('limited', image, {'max_file_bytes': 100})]:
        app.config['DISK_SCAN_LIMITS'] = limits
        case_response = session.post(base + '/cases', json={'title': 'Issue 1B ' + label}, timeout=30)
        case_response.raise_for_status()
        case_id = case_response.json()['id']
        with app.app_context():
            assert get_db().cases.find_one({'id': case_id}), 'HTTP server database identity mismatch'
        before = hashlib.sha256(source.read_bytes()).hexdigest()
        started = time.perf_counter()
        with source.open('rb') as stream:
            response = session.post(base + '/forensics/ingest', data={'caseId': case_id},
                                    files={'file': (source.name, stream)}, timeout=30)
        elapsed = time.perf_counter() - started
        response.raise_for_status()
        payload = response.json()
        assert payload['persisted'], payload
        scan = payload['disk_scan']
        assert scan['files_with_yara_matches'] == (0 if label == 'negative' else 1)
        assert scan['scan_status'] == ('PARTIAL' if label == 'limited' else 'COMPLETE')
        assert hashlib.sha256(source.read_bytes()).hexdigest() == before == payload['evidence']['sha256']
        case = get('/cases/' + case_id).json()
        artifacts = get('/artifacts?case_id=' + case_id).json()['artifacts']
        history = get('/ingestions?case_id=' + case_id).json()['ingestions']
        assert case['evidence']['sources'][0]['sha256'] == before
        assert history[0]['disk_scan'] == {k: v for k, v in scan.items() if k != 'findings'}
        assert len(artifacts) == scan['regular_files_discovered']
        for artifact in artifacts:
            original = next(r for r in scan['findings'] if r['artifact_location'] == artifact['artifact_location'])
            for key in ('FilePath', 'volume_offset', 'inode', 'sha256', 'yara_matches', 'risk_score', 'priority',
                        'scan_status', 'scan_reason', 'evidence_sha256'):
                assert artifact[key] == original[key], key
            assert artifact['intake_id'] == payload['intake_id']
        if label != 'negative':
            hit = next(r for r in artifacts if r['FileName'] == 'POSITIVE.TXT')
            assert hit['sha256'] == hashlib.sha256(MARKER).hexdigest()
            assert hit['yara_matches'][0]['meta']['description'] == 'Harmless integration marker'
            assert hit['priority'] == 'MEDIUM' and hit['risk_score'] == 25
        pdf = get('/report/' + case_id).content
        (output / (label + '.pdf')).write_bytes(pdf)
        from pypdf import PdfReader
        import io
        text = '\n'.join(p.extract_text() for p in PdfReader(io.BytesIO(pdf)).pages)
        text = ' '.join(text.split())
        for expected in (before, scan['scan_status'], 'No signature match does not establish safety'):
            assert expected in text, expected
        if label != 'negative':
            assert 'Harmless_File_Marker' in text and '/POSITIVE.TXT' in text
            assert hit['sha256'] in text and 'MEDIUM' in text
            assert 'not proof of malware' in text
        if label == 'limited':
            assert 'Reduced coverage' in text
        (output / (label + '-pdf-text.txt')).write_text(text, encoding='utf-8')
        for name, value in [('upload', payload), ('case', case), ('artifacts', artifacts), ('history', history)]:
            (output / (label + '-' + name + '.json')).write_text(json.dumps(value, indent=2), encoding='utf-8')
        results.append({'test': label, 'case_id': case_id, 'image': str(source.resolve()),
                        'sha256_before': before, 'sha256_after': before, 'integrity': 'PASS',
                        'api_request_seconds': round(elapsed, 6), 'scan': {k: v for k, v in scan.items() if k != 'findings'}})
    app.config['DISK_SCAN_LIMITS'] = {}
    summary = {'database': database, 'results': results, 'base_url': base,
               'rules_directory': str(rules.resolve()), 'output': str(output.resolve())}
    (output / 'summary.json').write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2), flush=True)
    if args.serve:
        thread.join()
    else:
        server.shutdown()


if __name__ == '__main__':
    main()
