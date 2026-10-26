"""Explicit KaggleHub download, provenance, and source-file protection.

Every network call is mocked: this suite never downloads data, never trains or
fits a model, and never writes to a reviewed source CSV.
"""
import hashlib
import json
import sys
import types
from pathlib import Path

import pytest
import requests

from ml import dataset_source as source
from scripts import download_dataset as download_script
from scripts import train_baseline as trainer


def fake_downloader(root, version=3, calls=None):
    """Stand-in for KaggleHub that reports an already materialised download."""
    def download(handle, *, force_download=False, output_dir=None):
        if calls is not None:
            calls.append({'handle': handle, 'force_download': force_download,
                          'output_dir': output_dir})
        return str(root), version
    return download


def failing_downloader(error):
    def download(handle, *, force_download=False, output_dir=None):
        raise error
    return download


def http_error(status):
    error = requests.exceptions.HTTPError(f'HTTP {status}')
    error.response = types.SimpleNamespace(status_code=status)
    return error


def snapshot(root):
    return {str(path.relative_to(root)): path.read_bytes()
            for path in sorted(Path(root).rglob('*')) if path.is_file()}


@pytest.fixture()
def download_tree(tmp_path):
    """Download whose CSV filename is unknown to this project."""
    root = tmp_path / 'kaggle' / 'cicids2017-cleaned-and-preprocessed'
    csv = root / 'raw' / 'part-00007.csv'
    csv.parent.mkdir(parents=True)
    csv.write_text('Flow Duration,Label\n100,BENIGN\n', encoding='utf-8')
    (root / 'README.md').write_text('dataset notes', encoding='utf-8')
    return root


@pytest.fixture()
def manifest_path(tmp_path):
    return tmp_path / 'provenance' / 'cicids2017_cleaned.provenance.json'


def test_download_records_actual_csv_path_and_provenance(download_tree, tmp_path, manifest_path):
    before = snapshot(download_tree)
    csv = download_tree / 'raw' / 'part-00007.csv'
    report = source.download_dataset(output_dir=tmp_path / 'out', manifest_path=manifest_path,
                                     downloader=fake_downloader(download_tree, version=7))
    assert report['csv']['relative_path'] == str(Path('raw', 'part-00007.csv'))
    assert report['csv']['path'] == str(csv.resolve())
    assert report['csv']['discovered_by'] == 'download tree scan'
    assert report['csv']['sha256'] == hashlib.sha256(before[str(Path('raw', 'part-00007.csv'))]).hexdigest()
    assert report['csv']['size_bytes'] == csv.stat().st_size
    assert report['version'] == {'value': 7, 'status': 'available'}
    assert report['source'] == {
        'provider': 'kaggle',
        'handle': 'ericanacletoribeiro/cicids2017-cleaned-and-preprocessed',
        'url': 'https://www.kaggle.com/datasets/ericanacletoribeiro/cicids2017-cleaned-and-preprocessed',
        'retrieval_tool': 'kagglehub',
        'kagglehub_version': source.package_version('kagglehub'),
    }
    assert report['retrieved_at'] == report['verified_at']
    assert report['handling']['cleaning_policy_applied'] is False
    assert report['handling']['source_files_modified'] is False
    assert report['reused'] is False
    assert report['manifest_path'] == str(manifest_path.resolve())
    stored = json.loads(manifest_path.read_text(encoding='utf-8'))
    assert stored['csv'] == report['csv']
    assert stored['manifest_version'] == source.PROVENANCE_MANIFEST_VERSION
    assert snapshot(download_tree) == before


def test_matching_record_reuses_download_and_keeps_retrieval_time(download_tree, tmp_path,
                                                                  manifest_path):
    calls = []
    stamps = iter(['2026-10-25T10:00:00Z', '2026-10-25T11:00:00Z'])
    downloader = fake_downloader(download_tree, version=4, calls=calls)
    first = source.download_dataset(output_dir=tmp_path / 'out', manifest_path=manifest_path,
                                    downloader=downloader, now=lambda: next(stamps))
    second = source.download_dataset(output_dir=tmp_path / 'out', manifest_path=manifest_path,
                                     downloader=downloader, now=lambda: next(stamps))
    assert first['reused'] is False
    assert second['reused'] is True
    assert second['retrieved_at'] == '2026-10-25T10:00:00Z'
    assert second['verified_at'] == '2026-10-25T11:00:00Z'
    assert second['csv']['sha256'] == first['csv']['sha256']
    assert [call['force_download'] for call in calls] == [False, False]
    assert [call['handle'] for call in calls] == [source.DATASET_HANDLE] * 2


def test_mismatched_record_is_never_overwritten_without_force(download_tree, tmp_path,
                                                               manifest_path):
    output_dir = tmp_path / 'out'
    source.download_dataset(output_dir=output_dir, manifest_path=manifest_path,
                            downloader=fake_downloader(download_tree, version=2))
    recorded = manifest_path.read_bytes()
    (download_tree / 'raw' / 'part-00007.csv').write_text('Flow Duration,Label\n9,BENIGN\n',
                                                           encoding='utf-8')
    with pytest.raises(source.DatasetSourceError) as error:
        source.download_dataset(output_dir=output_dir, manifest_path=manifest_path,
                                downloader=fake_downloader(download_tree, version=2))
    assert error.value.code == 'PROVENANCE_MISMATCH'
    assert 'CSV SHA-256' in str(error.value)
    assert '--force-download' in str(error.value)
    assert manifest_path.read_bytes() == recorded

    calls = []
    forced = source.download_dataset(output_dir=output_dir, manifest_path=manifest_path,
                                     force_download=True,
                                     downloader=fake_downloader(download_tree, version=2, calls=calls))
    assert calls == [{'handle': source.DATASET_HANDLE, 'force_download': True,
                      'output_dir': str(output_dir)}]
    assert forced['reused'] is False
    assert forced['csv']['sha256'] == hashlib.sha256(
        (download_tree / 'raw' / 'part-00007.csv').read_bytes()).hexdigest()
    assert json.loads(manifest_path.read_text(encoding='utf-8'))['csv']['sha256'] == forced['csv']['sha256']


def test_version_change_requires_explicit_confirmation(download_tree, tmp_path, manifest_path):
    output_dir = tmp_path / 'out'
    source.download_dataset(output_dir=output_dir, manifest_path=manifest_path,
                            downloader=fake_downloader(download_tree, version=3))
    with pytest.raises(source.DatasetSourceError) as error:
        source.download_dataset(output_dir=output_dir, manifest_path=manifest_path,
                                downloader=fake_downloader(download_tree, version=4))
    assert error.value.code == 'PROVENANCE_MISMATCH'
    assert 'dataset version' in str(error.value)
    confirmed = source.download_dataset(output_dir=output_dir, manifest_path=manifest_path,
                                        force_download=True,
                                        downloader=fake_downloader(download_tree, version=4))
    assert confirmed['version'] == {'value': 4, 'status': 'available'}


def test_unavailable_version_metadata_is_recorded_and_compared(download_tree, tmp_path,
                                                                manifest_path):
    output_dir = tmp_path / 'out'
    unknown = source.download_dataset(output_dir=output_dir, manifest_path=manifest_path,
                                      downloader=fake_downloader(download_tree, version=None))
    assert unknown['version']['status'] == 'unavailable'
    assert unknown['version']['value'] is None
    assert 'SHA-256' in unknown['version']['detail']
    repeated = source.download_dataset(output_dir=output_dir, manifest_path=manifest_path,
                                       downloader=fake_downloader(download_tree, version=None))
    assert repeated['reused'] is True

    # Losing available version metadata is a change of identity evidence.
    record = json.loads(manifest_path.read_text(encoding='utf-8'))
    record['version'] = {'value': 3, 'status': 'available'}
    manifest_path.write_text(json.dumps(record), encoding='utf-8')
    with pytest.raises(source.DatasetSourceError) as error:
        source.download_dataset(output_dir=output_dir, manifest_path=manifest_path,
                                downloader=fake_downloader(download_tree, version=None))
    assert error.value.code == 'PROVENANCE_MISMATCH'
    assert 'version metadata availability' in str(error.value)


def test_missing_csv_reports_clear_error(tmp_path, manifest_path):
    root = tmp_path / 'out'
    (root / 'nested').mkdir(parents=True)
    (root / 'notes.txt').write_text('no data here', encoding='utf-8')
    with pytest.raises(source.DatasetSourceError) as error:
        source.download_dataset(output_dir=root, manifest_path=manifest_path,
                                downloader=fake_downloader(root))
    assert error.value.code == 'CSV_NOT_FOUND'
    assert '--csv-path' in str(error.value)
    assert not manifest_path.exists()


def test_ambiguous_csv_requires_explicit_path(tmp_path, manifest_path):
    root = tmp_path / 'out'
    root.mkdir(parents=True)
    (root / 'flows-a.csv').write_text('Label\nBENIGN\n', encoding='utf-8')
    (root / 'flows-b.csv').write_text('Label\nBENIGN\n', encoding='utf-8')
    with pytest.raises(source.DatasetSourceError) as error:
        source.download_dataset(output_dir=root, manifest_path=manifest_path,
                                downloader=fake_downloader(root))
    assert error.value.code == 'CSV_AMBIGUOUS'
    assert 'flows-a.csv' in str(error.value) and 'flows-b.csv' in str(error.value)
    assert not manifest_path.exists()

    report = source.download_dataset(output_dir=root, manifest_path=manifest_path,
                                     csv_hint='flows-b.csv', downloader=fake_downloader(root))
    assert report['csv']['relative_path'] == 'flows-b.csv'
    assert report['csv']['discovered_by'] == 'operator --csv-path'


@pytest.mark.parametrize('hint,code', [
    ('absent.csv', 'CSV_NOT_FOUND'),
    ('../escape.csv', 'CSV_PATH_INVALID'),
    ('notes.txt', 'CSV_PATH_INVALID'),
    ('   ', 'CSV_PATH_INVALID'),
])
def test_invalid_csv_hint_is_rejected(tmp_path, manifest_path, hint, code):
    root = tmp_path / 'out'
    root.mkdir(parents=True)
    (root / 'notes.txt').write_text('x', encoding='utf-8')
    (root / 'present.csv').write_text('Label\nBENIGN\n', encoding='utf-8')
    with pytest.raises(source.DatasetSourceError) as error:
        source.download_dataset(output_dir=root, manifest_path=manifest_path, csv_hint=hint,
                                downloader=fake_downloader(root))
    assert error.value.code == code
    assert not manifest_path.exists()


@pytest.mark.parametrize('failure,code', [
    (type('UnauthenticatedError', (Exception,), {})('not signed in'), 'CREDENTIALS_MISSING'),
    (http_error(401), 'CREDENTIALS_MISSING'),
    (http_error(403), 'CREDENTIALS_MISSING'),
    (http_error(404), 'DATASET_NOT_FOUND'),
    (http_error(503), 'SERVICE_FAILURE'),
    (requests.exceptions.ConnectionError('name or service not known'), 'NETWORK_FAILURE'),
    (TimeoutError('timed out'), 'NETWORK_FAILURE'),
    (OSError('network is unreachable'), 'NETWORK_FAILURE'),
])
def test_download_failures_are_reported_with_codes(tmp_path, manifest_path, failure, code):
    root = tmp_path / 'out'
    root.mkdir(parents=True)
    with pytest.raises(source.DatasetSourceError) as error:
        source.download_dataset(output_dir=root, manifest_path=manifest_path,
                                downloader=failing_downloader(failure))
    assert error.value.code == code
    assert not manifest_path.exists()


def test_missing_credentials_fail_before_any_request():
    def no_credentials():
        return None

    def malformed():
        raise ValueError('kaggle.json is missing key')

    absent = types.SimpleNamespace(config=types.SimpleNamespace(get_kaggle_credentials=no_credentials))
    broken = types.SimpleNamespace(config=types.SimpleNamespace(get_kaggle_credentials=malformed))
    present = types.SimpleNamespace(config=types.SimpleNamespace(get_kaggle_credentials=lambda: object()))
    for fake_package in (absent, broken):
        with pytest.raises(source.DatasetSourceError) as error:
            source._require_kaggle_credentials(fake_package)
        assert error.value.code == 'CREDENTIALS_MISSING'
    assert source._require_kaggle_credentials(present) is None


def test_missing_kagglehub_package_is_reported(monkeypatch):
    def missing(name, *args, **kwargs):
        raise ImportError(f'No module named {name!r}')

    monkeypatch.setattr(source.importlib, 'import_module', missing)
    with pytest.raises(source.DatasetSourceError) as error:
        source._import_kagglehub()
    assert error.value.code == 'KAGGLEHUB_MISSING'
    assert 'pip install kagglehub' in str(error.value)


def test_repository_source_csv_is_protected(tmp_path):
    sample = source.PROTECTED_DATASET_PATHS[0]
    assert sample == source.ROOT_DIR / 'data' / 'sample' / 'cicids2017_cleaned.csv'
    created = False
    if not sample.is_file():
        sample.parent.mkdir(parents=True, exist_ok=True)
        sample.write_text('synthetic,protected,data\n1,2,3\n', encoding='utf-8')
        created = True
    try:
        assert sample.is_file()
        stat_before = sample.stat()
        calls = []

        def forbidden(**kwargs):
            calls.append(kwargs)
            raise AssertionError('download was attempted despite source protection')

        with pytest.raises(source.DatasetSourceError) as error:
            source.download_dataset(manifest_path=sample, downloader=forbidden)
        assert error.value.code == 'SOURCE_PROTECTED'
        with pytest.raises(source.DatasetSourceError) as error:
            source.download_dataset(output_dir=sample.parent, downloader=forbidden)
        assert error.value.code == 'SOURCE_PROTECTED'
        assert calls == []
        assert sample.stat().st_size == stat_before.st_size
        assert sample.stat().st_mtime_ns == stat_before.st_mtime_ns
    finally:
        if created:
            sample.unlink(missing_ok=True)


def test_discovered_csv_inside_protected_location_is_rejected(tmp_path, manifest_path,
                                                               monkeypatch):
    root = tmp_path / 'out'
    root.mkdir(parents=True)
    csv = root / 'data.csv'
    csv.write_text('Label\nBENIGN\n', encoding='utf-8')
    monkeypatch.setattr(source, 'PROTECTED_DATASET_PATHS', (csv,))
    with pytest.raises(source.DatasetSourceError) as error:
        source.download_dataset(output_dir=root, manifest_path=manifest_path,
                                downloader=fake_downloader(root))
    assert error.value.code == 'SOURCE_PROTECTED'
    assert not manifest_path.exists()


@pytest.mark.parametrize('content', ['{not json', '{}',
                                     '{"manifest_version": 99}'])
def test_unreadable_manifest_fails_closed(tmp_path, manifest_path, content):
    root = tmp_path / 'out'
    root.mkdir(parents=True)
    (root / 'data.csv').write_text('Label\nBENIGN\n', encoding='utf-8')
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(content, encoding='utf-8')
    before = manifest_path.read_bytes()
    with pytest.raises(source.DatasetSourceError) as error:
        source.download_dataset(output_dir=root, manifest_path=manifest_path,
                                downloader=fake_downloader(root))
    assert error.value.code == 'PROVENANCE_UNREADABLE'
    assert manifest_path.read_bytes() == before


def test_validation_and_training_never_download(tiny_flow_csv, monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        raise AssertionError('validation or training attempted a download')

    monkeypatch.setattr(source, 'download_dataset', forbidden)
    monkeypatch.setattr(source, 'kagglehub_download', forbidden)
    monkeypatch.setattr(download_script, 'download_dataset', forbidden)
    assert trainer.validate_dataset(tiny_flow_csv)['status'] == 'valid'
    monkeypatch.setattr(sys, 'argv', ['train_baseline.py', '--validate-only',
                                      '--data', str(tiny_flow_csv)])
    trainer.main()
    assert json.loads(capsys.readouterr().out)['status'] == 'valid'


def test_sha256_file_streams_in_chunks(tmp_path):
    payload = bytes(range(256)) * 40
    blob = tmp_path / 'blob.bin'
    blob.write_bytes(payload)
    assert source.sha256_file(blob, chunk_size=7) == hashlib.sha256(payload).hexdigest()
    assert blob.read_bytes() == payload


def test_csv_discovery_ignores_names_and_matches_suffix(tmp_path):
    root = tmp_path / 'out'
    (root / 'nested' / 'deep').mkdir(parents=True)
    (root / 'nested' / 'deep' / 'FIRST.CSV').write_text('a\n1\n', encoding='utf-8')
    (root / 'nested' / 'second.csv').write_text('a\n2\n', encoding='utf-8')
    (root / 'notes.txt').write_text('x', encoding='utf-8')
    assert [str(path) for path in source.find_csv_files(root)] == [
        str(Path('nested', 'deep', 'FIRST.CSV')), str(Path('nested', 'second.csv'))]


def test_cli_prints_report_and_passes_options(tmp_path, monkeypatch, capsys):
    received = {}
    expected = {'manifest_path': 'm', 'csv': {'path': 'p'}, 'reused': False}

    def capture(**kwargs):
        received.update(kwargs)
        return expected

    monkeypatch.setattr(download_script, 'download_dataset', capture)
    report = download_script.main(['--output-dir', str(tmp_path / 'out'),
                                   '--manifest', str(tmp_path / 'm.json'),
                                   '--csv-path', 'raw/part.csv', '--force-download'])
    assert report == expected
    assert json.loads(capsys.readouterr().out) == expected
    assert received == {'output_dir': tmp_path / 'out', 'manifest_path': tmp_path / 'm.json',
                        'csv_hint': 'raw/part.csv', 'force_download': True}


def test_cli_reports_error_code_without_a_partial_record(tmp_path, monkeypatch, capsys):
    def failing(**kwargs):
        raise source.DatasetSourceError('No Kaggle credentials were found.',
                                        'CREDENTIALS_MISSING')

    monkeypatch.setattr(download_script, 'download_dataset', failing)
    with pytest.raises(SystemExit) as error:
        download_script.main(['--manifest', str(tmp_path / 'm.json')])
    assert error.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == ''
    assert 'Download failed [CREDENTIALS_MISSING]' in captured.err
    assert not (tmp_path / 'm.json').exists()


def test_is_unsupported_output_dir_error():
    assert source._is_unsupported_output_dir_error(
        TypeError("__call__() got an unexpected keyword argument 'output_dir'"))
    assert source._is_unsupported_output_dir_error(
        TypeError("dataset_download() got an unexpected keyword argument 'output_dir'"))
    assert not source._is_unsupported_output_dir_error(
        TypeError("missing required argument 'handle'"))
    assert not source._is_unsupported_output_dir_error(
        ValueError("unexpected keyword argument 'output_dir'"))
    assert not source._is_unsupported_output_dir_error("not an exception")


def test_resolve_with_version_supports_output_dir():
    calls = []

    def mock_resolver(handle, path, *, force_download, output_dir=None):
        calls.append({'handle': handle, 'path': path, 'force_download': force_download,
                      'output_dir': output_dir})
        return ('/cache/path', 6)

    class MockRegistry:
        dataset_resolver = staticmethod(mock_resolver)

    class MockHandle:
        @staticmethod
        def parse_dataset_handle(handle):
            return f'parsed:{handle}'

    class MockKagglehub:
        registry = MockRegistry
        handle = MockHandle

    path, version = source._resolve_with_version(
        MockKagglehub, 'owner/dataset', force_download=True, output_dir='/custom/dir')
    assert path == '/cache/path'
    assert version == 6
    assert calls == [{'handle': 'parsed:owner/dataset', 'path': None,
                      'force_download': True, 'output_dir': '/custom/dir'}]


def test_resolve_with_version_falls_back_when_output_dir_unsupported():
    calls = []

    def mock_resolver(handle, path, *, force_download, **kwargs):
        calls.append({'handle': handle, 'force_download': force_download, 'kwargs': kwargs})
        if 'output_dir' in kwargs:
            raise TypeError("__call__() got an unexpected keyword argument 'output_dir'")
        return ('/fallback/path', 6)

    class MockRegistry:
        dataset_resolver = staticmethod(mock_resolver)

    class MockHandle:
        @staticmethod
        def parse_dataset_handle(handle):
            return f'parsed:{handle}'

    class MockKagglehub:
        registry = MockRegistry
        handle = MockHandle

    path, version = source._resolve_with_version(
        MockKagglehub, 'owner/dataset', force_download=False, output_dir='/custom/dir')
    assert path == '/fallback/path'
    assert version == 6
    assert len(calls) == 2
    assert calls[0]['kwargs'] == {'output_dir': '/custom/dir'}
    assert calls[1]['kwargs'] == {}


def test_resolve_with_version_does_not_swallow_arbitrary_type_error():
    calls = []

    def mock_resolver(handle, path, *, force_download, **kwargs):
        calls.append(kwargs)
        raise TypeError('internal type error inside resolver')

    class MockRegistry:
        dataset_resolver = staticmethod(mock_resolver)

    class MockHandle:
        @staticmethod
        def parse_dataset_handle(handle):
            return f'parsed:{handle}'

    class MockKagglehub:
        registry = MockRegistry
        handle = MockHandle

    with pytest.raises(TypeError, match='internal type error inside resolver'):
        source._resolve_with_version(
            MockKagglehub, 'owner/dataset', force_download=False, output_dir='/custom/dir')
    assert len(calls) == 1


def test_resolve_with_version_fallback_when_package_layout_differs():
    calls = []

    class MockKagglehub:
        registry = None
        handle = None

        @staticmethod
        def dataset_download(handle, *, force_download, **kwargs):
            calls.append({'handle': handle, 'force_download': force_download, 'kwargs': kwargs})
            if 'output_dir' in kwargs:
                raise TypeError("dataset_download() got an unexpected keyword argument 'output_dir'")
            return '/download/path'

    path, version = source._resolve_with_version(
        MockKagglehub, 'owner/dataset', force_download=True, output_dir='/custom/dir')
    assert path == '/download/path'
    assert version is None
    assert len(calls) == 2
    assert calls[0]['kwargs'] == {'output_dir': '/custom/dir'}
    assert calls[1]['kwargs'] == {}
