r"""Harmless real FAT12 -> pytsk3 -> YARA -> upload API experiment.

Run: .venv\Scripts\python.exe -m scripts.verify_file_yara
Test-only dependency: pyfatfs==1.1.0, setuptools<81.
Generated evidence stays in ignored .test-artifacts/issue1.
"""
import hashlib
import io
import json
import uuid
from pathlib import Path

MARKER = b'CYBER_TRIAGE_HARMLESS_FILE_MARKER_ISSUE_1_2026'


def make_fixture(directory, positive=True):
    from pyfatfs.PyFat import PyFat
    from pyfatfs.PyFatFS import PyFatFS
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    image = directory / 'harmless-fat12.img'
    image.touch()
    fat = PyFat()
    fat.mkfs(str(image), fat_type=PyFat.FAT_TYPE_FAT12, size=1440 * 1024,
             volume_id=123456, label='TRIAGETEST')
    fat.close()
    with PyFatFS(str(image)) as fs:
        if positive:
            fs.writebytes('/POSITIVE.TXT', MARKER)
        fs.writebytes('/NEGATIVE.TXT', b'Ordinary harmless document without the marker.')
        fs.writebytes('/EMPTY.TXT', b'')
        fs.writebytes('/LARGE.BIN', b'A' * 4096)
    rules = directory / 'rules'
    rules.mkdir(exist_ok=True)
    (rules / 'marker.yar').write_text(
        'rule Harmless_File_Marker { meta: description = "Harmless integration marker" '
        'severity = "informational" strings: $a = "' + MARKER.decode() + '" condition: $a }')
    return image, rules


def main():
    import os
    from backend.app import create_app
    image, rules = make_fixture(Path('.test-artifacts/issue1') / uuid.uuid4().hex)
    os.environ['YARA_RULES_DIR'] = str(rules.resolve())
    original = image.read_bytes()
    app = create_app({'TESTING': True, 'APP_ENV': 'test', 'DB_MODE': 'disabled',
                      'TEMP_DIR': str(image.parent / 'uploads'), 'MODEL_PATH': 'missing.joblib'})
    response = app.test_client().post('/api/forensics/ingest', data={
        'file': (io.BytesIO(original), image.name)}, content_type='multipart/form-data')
    result = response.get_json()
    response.request.close()
    response.request.environ['wsgi.input'].close()
    response.close()
    assert response.status_code == 200, result
    scan = result['disk_scan']
    by_name = {r['FileName']: r for r in scan['findings']}
    assert by_name['POSITIVE.TXT']['scan_status'] == 'MATCHED'
    assert by_name['POSITIVE.TXT']['sha256'] == hashlib.sha256(MARKER).hexdigest()
    assert by_name['POSITIVE.TXT']['FilePath'] == '/POSITIVE.TXT'
    assert by_name['NEGATIVE.TXT']['scan_status'] == 'SCANNED_NO_MATCH'
    assert by_name['EMPTY.TXT']['scan_status'] == 'SCANNED_NO_MATCH'
    assert original == image.read_bytes(), 'Evidence changed'
    scan.update(image_name=image.name, image_size=len(original),
                integrity_verified=True, persisted=result['persisted'])
    target = Path('test-results/issue-1')
    target.mkdir(parents=True, exist_ok=True)
    (target / 'actual-api-result.json').write_text(json.dumps(result, indent=2))
    print(json.dumps({k: v for k, v in scan.items() if k != 'findings'}, indent=2))


if __name__ == '__main__':
    main()
