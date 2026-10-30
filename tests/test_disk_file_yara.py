"""Real filesystem tests plus explicit fault injection for native error paths."""
import hashlib
import io

import pytest
from forensics import disk_image as disk, yara_scanner as yara
from scripts.verify_file_yara import make_fixture, MARKER

pytestmark = pytest.mark.skipif(not disk.AVAILABLE or not yara.AVAILABLE,
                                reason='Requires real pytsk3 and yara-python')


@pytest.fixture
def fixture(tmp_path):
    pytest.importorskip('pyfatfs.PyFatFS')
    return make_fixture(tmp_path)


def test_real_upload_positive_negative_integrity(fixture, client, monkeypatch):
    image, rules = fixture
    monkeypatch.setenv('YARA_RULES_DIR', str(rules))
    before = hashlib.sha256(image.read_bytes()).hexdigest()
    response = client.post('/api/forensics/ingest', data={'file': (io.BytesIO(image.read_bytes()), image.name)})
    assert response.status_code == 200, response.json
    scan = response.json['disk_scan']
    rows = {r['FileName']: r for r in scan['findings']}
    assert rows['POSITIVE.TXT']['scan_status'] == 'MATCHED'
    assert rows['POSITIVE.TXT']['FilePath'] == '/POSITIVE.TXT'
    assert rows['POSITIVE.TXT']['sha256'] == hashlib.sha256(MARKER).hexdigest()
    assert rows['POSITIVE.TXT']['priority'] == 'MEDIUM'
    assert rows['POSITIVE.TXT']['anomaly_score'] is None
    assert rows['NEGATIVE.TXT']['scan_status'] == 'SCANNED_NO_MATCH'
    assert rows['EMPTY.TXT']['sha256'] == hashlib.sha256(b'').hexdigest()
    assert scan['files_with_yara_matches'] == 1
    assert scan['evidence_sha256'] == before == hashlib.sha256(image.read_bytes()).hexdigest()
    response.request.close()
    response.request.environ['wsgi.input'].close()
    response.close()


def test_unreadable_injection(fixture, monkeypatch):
    original = disk.pytsk3.FS_Info
    class Entry:
        def __init__(self, wrapped):
            self.info = wrapped.info
        def read_random(self, *args):
            raise OSError('Injected unreadable file')
    class Filesystem:
        def __init__(self, *args, **kwargs):
            self.wrapped = original(*args, **kwargs)
            self.info = self.wrapped.info
        def open_dir(self, **kwargs):
            return (Entry(e) for e in self.wrapped.open_dir(**kwargs))
    monkeypatch.setattr(disk.pytsk3, 'FS_Info', Filesystem)
    result = disk.analyze_disk_image(fixture[0], rules_dir=str(fixture[1]))
    assert result['files_failed'] == 3  # The empty stream needs no read.
    assert result['scan_status'] == 'PARTIAL'


def test_scope_accounting(fixture):
    result = disk.analyze_disk_image(fixture[0], rules_dir=str(fixture[1]))
    assert result['entries_discovered'] == 9
    assert result['regular_files_discovered'] == result['files_scanned'] == 4
    assert result['non_file_entries_ignored'] == 5
    assert result['virtual_entries_ignored'] == 4
    assert result['metadata_entries_ignored'] == 1
    assert result['files_failed'] == result['files_skipped_limits'] == 0
    assert result['scan_status'] == 'COMPLETE'


@pytest.mark.integration
def test_live_disk_persistence(fixture, mongo_app):
    image, rules = fixture
    mongo_app.config['YARA_RULES_DIR'] = str(rules)
    client = mongo_app.test_client()
    case_id = client.post('/api/cases', json={'title': 'Owned disk test'}).json['id']
    response = client.post('/api/forensics/ingest', data={
        'caseId': case_id, 'file': (io.BytesIO(image.read_bytes()), image.name)})
    assert response.status_code == 200
    payload = response.json
    response.request.environ['wsgi.input'].close()
    response.close()
    assert payload['persisted']
    rows = client.get('/api/artifacts?case_id=' + case_id).json['artifacts']
    assert len(rows) == 4
    hit = next(r for r in rows if r['FileName'] == 'POSITIVE.TXT')
    assert hit['sha256'] == hashlib.sha256(MARKER).hexdigest()
    assert hit['evidence_sha256'] == payload['evidence']['sha256']
    assert hit['intake_id'] == payload['intake_id']
    assert hit['priority'] == 'MEDIUM' and hit['risk_score'] == 25
    assert hit['yara_matches'][0]['meta']['description'] == 'Harmless integration marker'
    case = client.get('/api/cases/' + case_id).json
    assert case['evidence']['sources'][0]['disk_scan']['scan_status'] == 'COMPLETE'
    assert client.get('/api/report/' + case_id).data.startswith(b'%PDF-')


@pytest.mark.parametrize('settings,status', [({'max_file_bytes': 100}, 'SKIPPED_TOO_LARGE'),
                                             ({'max_files': 1}, 'SKIPPED_LIMIT'),
                                             ({'max_total_bytes': 50}, 'SKIPPED_LIMIT'),
                                             ({'max_entries': 1}, None)])
def test_limits(fixture, settings, status):
    image, rules = fixture
    result = disk.analyze_disk_image(image, disk.ScanLimits(**settings), str(rules))
    assert result['scan_status'] == 'PARTIAL'
    if status:
        assert any(r['scan_status'] == status for r in result['findings'])
    else:
        assert not result['enumeration_complete']


def test_missing_yara(fixture, monkeypatch):
    monkeypatch.setattr(yara, 'AVAILABLE', False)
    result = disk.analyze_disk_image(fixture[0])
    assert result['files_scanned'] == 0
    assert any(r['scan_status'] == 'YARA_UNAVAILABLE' for r in result['findings'])


def test_empty_and_invalid_rules(fixture, tmp_path):
    empty = tmp_path / 'empty'
    empty.mkdir()
    assert disk.analyze_disk_image(fixture[0], rules_dir=str(empty))['yara_status'] == 'RULES_NOT_CONFIGURED'
    (empty / 'invalid.yar').write_text('this is not a rule')
    result = disk.analyze_disk_image(fixture[0], rules_dir=str(empty))
    assert result['yara_status'] == 'SCAN_FAILED'
    assert result['warnings']


def test_timeout_injection(fixture, monkeypatch):
    def timeout(*args, **kwargs):
        raise TimeoutError('Injected YARA timeout')
    monkeypatch.setattr(yara, 'scan_bytes', timeout)
    result = disk.analyze_disk_image(fixture[0], rules_dir=str(fixture[1]))
    assert result['files_scanned'] == 0
    assert any(r['scan_status'] == 'SCAN_FAILED' for r in result['findings'])


@pytest.mark.parametrize('payload', [b'not a filesystem', b'\0' * 4096])
def test_corrupt_unsupported(tmp_path, payload):
    image = tmp_path / 'bad.img'
    image.write_bytes(payload)
    with pytest.raises(ValueError, match='No supported filesystem'):
        disk.analyze_disk_image(image)


def test_unique_namespaces(tmp_path):
    for folder in ('a', 'b'):
        target = tmp_path / folder
        target.mkdir()
        (target / 'same.yar').write_text('rule Same { condition: true }')
    assert len(yara._collect_rule_files(str(tmp_path))) == 2
    assert len(yara.compile_rules(str(tmp_path)).match(data=b'hello')) == 2
