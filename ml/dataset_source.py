"""Explicit KaggleHub dataset retrieval and provenance recording.

Downloading is an operator action: only ``scripts/download_dataset.py`` calls
:func:`download_dataset`. Validation, cleaning, and training never import a
network path, so a missing dataset stays a reported error instead of an
implicit request.

Reviewed source CSVs are read-only material. ``data/sample/cicids2017_cleaned.csv``
and its approved copy ``data/cicids2017_cleaned.csv`` are never written,
replaced, or used as a download target.

Locating the CSV and hashing it never loads the dataset into memory: the download
tree is walked for ``.csv`` suffixes and the digest is streamed in 1 MiB chunks.
"""
import hashlib
import importlib
import json
import os
from pathlib import Path
import tempfile
from datetime import datetime, timezone

ROOT_DIR = Path(__file__).resolve().parents[1]

DATASET_HANDLE = 'ericanacletoribeiro/cicids2017-cleaned-and-preprocessed'
DATASET_PAGE_URL = 'https://www.kaggle.com/datasets/' + DATASET_HANDLE
PROVENANCE_MANIFEST_VERSION = 1
HASH_CHUNK_SIZE = 1024 * 1024

PROTECTED_DATASET_PATHS = (
    ROOT_DIR / 'data' / 'sample' / 'cicids2017_cleaned.csv',
    ROOT_DIR / 'data' / 'cicids2017_cleaned.csv',
)
DEFAULT_OUTPUT_DIR = ROOT_DIR / 'data' / 'kaggle' / 'cicids2017-cleaned-and-preprocessed'
DEFAULT_MANIFEST_PATH = ROOT_DIR / 'data' / 'provenance' / 'cicids2017_cleaned.provenance.json'

_CREDENTIAL_ERRORS = {'UnauthenticatedError', 'CredentialError'}
_NOT_FOUND_ERRORS = {'NotFoundError'}
_HTTP_ERRORS = {'HTTPError', 'KaggleApiHTTPError', 'ColabHTTPError'}
_SERVICE_ERRORS = {'BackendError'}


class DatasetSourceError(RuntimeError):
    """Retrieval failure with a stable code for operators and tests."""

    def __init__(self, message, code='DATASET_SOURCE_ERROR'):
        super().__init__(message)
        self.code = code


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def package_version(name):
    try:
        module = importlib.import_module(name)
    except ImportError:
        return 'unavailable'
    return str(getattr(module, '__version__', None) or 'unknown')


def assert_not_protected(path, action='use'):
    """Refuse to touch a reviewed source CSV."""
    resolved = Path(path).resolve()
    for protected in PROTECTED_DATASET_PATHS:
        if resolved == Path(protected).resolve():
            raise DatasetSourceError(
                f'Refusing to {action} the protected source dataset {resolved}. '
                'Reviewed CSV files are never written, replaced, or re-recorded by the download workflow.',
                'SOURCE_PROTECTED')


def check_output_dir(output_dir):
    resolved = Path(output_dir).resolve()
    for protected in PROTECTED_DATASET_PATHS:
        protected = Path(protected).resolve()
        if resolved == protected or resolved in protected.parents:
            raise DatasetSourceError(
                f'Output directory {resolved} contains protected source data and cannot be a download '
                'target. Downloads never overwrite reviewed CSV files.', 'SOURCE_PROTECTED')
    if resolved.exists() and not resolved.is_dir():
        raise DatasetSourceError(f'Output directory is a file, not a directory: {resolved}',
                                 'OUTPUT_DIR_INVALID')


def sha256_file(path, chunk_size=HASH_CHUNK_SIZE):
    """Streamed read-only digest; the file is never loaded into memory."""
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b''):
            digest.update(chunk)
    return digest.hexdigest()


def find_csv_files(root):
    """Relative paths of CSV files under ``root``, found by suffix only."""
    matches = []
    for directory, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            if Path(name).suffix.lower() == '.csv':
                matches.append(Path(directory, name).relative_to(root))
    # Stable order regardless of directory traversal order (reported on ambiguity).
    return sorted(matches, key=str)


def locate_csv(root, csv_hint=None):
    """Return ``(relative_path, discovery_method)`` for the dataset CSV.

    The downloaded filename is never assumed: the tree is scanned for CSV
    suffixes, and an ambiguous or missing result demands an explicit hint.
    """
    root = Path(root)
    if not root.is_dir():
        raise DatasetSourceError(
            f'Download location is not a directory: {root}. The retrieval produced no files to inspect.',
            'DOWNLOAD_MISSING')
    if csv_hint is not None:
        hint = str(csv_hint).strip()
        if not hint:
            raise DatasetSourceError('--csv-path must name a CSV file inside the download.',
                                     'CSV_PATH_INVALID')
        root_resolved = root.resolve()
        candidate = (root / hint).resolve()
        if candidate != root_resolved and root_resolved not in candidate.parents:
            raise DatasetSourceError(
                f'--csv-path must stay inside the download directory: {hint}', 'CSV_PATH_INVALID')
        if candidate.suffix.lower() != '.csv':
            raise DatasetSourceError(f'--csv-path must name a .csv file: {hint}', 'CSV_PATH_INVALID')
        if not candidate.is_file():
            raise DatasetSourceError(
                f'No CSV file at "{hint}" inside {root}. Re-run with --csv-path naming a listed file.',
                'CSV_NOT_FOUND')
        assert_not_protected(candidate, 'record as the retrieved dataset')
        return candidate.relative_to(root_resolved), 'operator --csv-path'
    candidates = find_csv_files(root)
    if not candidates:
        entries = sorted(entry for entry in os.listdir(root))[:10]
        listing = ', '.join(entries) if entries else 'directory is empty'
        raise DatasetSourceError(
            f'No CSV file found under {root} (top level: {listing}). '
            'Re-run with --csv-path naming the dataset CSV.', 'CSV_NOT_FOUND')
    if len(candidates) > 1:
        shown = ', '.join(str(candidate) for candidate in candidates[:10])
        extra = '' if len(candidates) <= 10 else f' (+{len(candidates) - 10} more)'
        raise DatasetSourceError(
            f'{len(candidates)} CSV files found under {root}: {shown}{extra}. '
            'Re-run with --csv-path to select the dataset CSV.', 'CSV_AMBIGUOUS')
    return candidates[0], 'download tree scan'


def read_manifest(path):
    """Load an existing provenance record; an unreadable record fails closed."""
    path = Path(path)
    if not path.exists():
        return None
    try:
        record = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        raise DatasetSourceError(
            f'Cannot read provenance manifest {path}: {exc}. '
            'Re-run with --force-download after reviewing the file.', 'PROVENANCE_UNREADABLE') from exc
    if not isinstance(record, dict) or record.get('manifest_version') != PROVENANCE_MANIFEST_VERSION:
        raise DatasetSourceError(
            f'Unsupported provenance manifest {path}. '
            'Re-run with --force-download after reviewing the file.', 'PROVENANCE_UNREADABLE')
    return record


def write_manifest(path, record):
    """Atomically publish the provenance record (never over a source CSV)."""
    path = Path(path)
    assert_not_protected(path, 'write a provenance manifest to')
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + '.', suffix='.tmp', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
            json.dump(record, handle, indent=2)
            handle.write('\n')
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def version_metadata(version):
    """Version/revision metadata exactly as reported; unavailable is explicit."""
    if version is None or not str(version).strip():
        return {
            'value': None,
            'status': 'unavailable',
            'detail': 'KaggleHub reported no dataset version/revision for this retrieval. '
                      'Identity therefore rests on the recorded SHA-256 of the retrieved file.',
        }
    return {'value': version, 'status': 'available'}


def _dig(mapping, keys):
    value = mapping
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def identity_differences(existing, record):
    """Fields that must agree before an existing download and record are reused."""
    differences = []
    if not isinstance(existing, dict):
        return ['provenance manifest is not a JSON object']
    for label, keys in (('dataset handle', ('source', 'handle')),
                        ('CSV relative path', ('csv', 'relative_path')),
                        ('CSV size in bytes', ('csv', 'size_bytes')),
                        ('CSV SHA-256', ('csv', 'sha256'))):
        recorded, resolved = _dig(existing, keys), _dig(record, keys)
        if recorded != resolved:
            differences.append(f'{label}: recorded {recorded!r} but resolved {resolved!r}')
    recorded_version = existing.get('version') or {}
    resolved_version = record.get('version') or {}
    if recorded_version.get('status') != resolved_version.get('status'):
        differences.append(
            'version metadata availability: recorded '
            f'{recorded_version.get("status")!r} but resolved {resolved_version.get("status")!r}')
    elif (recorded_version.get('status') == 'available'
          and recorded_version.get('value') != resolved_version.get('value')):
        differences.append(
            f'dataset version: recorded {recorded_version.get("value")!r} '
            f'but resolved {resolved_version.get("value")!r}')
    return differences


def translate_download_error(exc):
    """Map Kaggle/HTTP/network failures to stable operator-facing codes."""
    if isinstance(exc, DatasetSourceError):
        return exc
    response = getattr(exc, 'response', None)
    status = getattr(response, 'status_code', None)
    names = {cls.__name__ for cls in type(exc).__mro__}
    if names & _CREDENTIAL_ERRORS or status in (401, 403):
        return DatasetSourceError(
            'Kaggle credentials are missing or were rejected (HTTP '
            f'{status or "authentication error"}). Provide KAGGLE_USERNAME/KAGGLE_KEY, '
            '~/.kaggle/kaggle.json, or kagglehub.login() and retry the download command.',
            'CREDENTIALS_MISSING')
    if names & _NOT_FOUND_ERRORS or status == 404:
        return DatasetSourceError(
            f'Kaggle dataset not found: {DATASET_HANDLE}. Verify the dataset handle and your access.',
            'DATASET_NOT_FOUND')
    if names & _HTTP_ERRORS:
        return DatasetSourceError(
            f'Kaggle service returned HTTP {status or "error"} while retrieving {DATASET_HANDLE}. '
            'Nothing was recorded; retry later.', 'SERVICE_FAILURE')
    if names & _SERVICE_ERRORS:
        return DatasetSourceError(f'Kaggle service error: {exc}. Nothing was recorded.',
                                  'SERVICE_FAILURE')
    if isinstance(exc, OSError) or names & {'ConnectionError', 'Timeout', 'gaierror'}:
        return DatasetSourceError(
            f'Network failure while contacting Kaggle: {exc}. '
            'Nothing was recorded; retry when connectivity is available.', 'NETWORK_FAILURE')
    return DatasetSourceError(f'Kaggle download failed: {exc}', 'DOWNLOAD_FAILED')


def _submodule(package, name):
    module = getattr(package, name, None)
    if module is not None:
        return module
    try:
        return importlib.import_module(f'{package.__name__}.{name}')
    except ImportError:
        return None


def _import_kagglehub():
    try:
        return importlib.import_module('kagglehub')
    except ImportError as exc:
        raise DatasetSourceError(
            'The kagglehub package is required for the explicit download command. '
            'Install it with: python -m pip install kagglehub', 'KAGGLEHUB_MISSING') from exc


def _require_kaggle_credentials(kagglehub):
    """Fail before any request when no Kaggle credentials are configured."""
    getter = getattr(getattr(kagglehub, 'config', None), 'get_kaggle_credentials', None)
    if getter is None:
        return
    try:
        credentials = getter()
    except ValueError as exc:
        raise DatasetSourceError(f'Kaggle credentials could not be read: {exc}',
                                 'CREDENTIALS_MISSING') from exc
    if credentials is None:
        raise DatasetSourceError(
            'No Kaggle credentials were found. Create an API token at '
            'https://www.kaggle.com/settings and provide it through KAGGLE_USERNAME/KAGGLE_KEY, '
            '~/.kaggle/kaggle.json, or kagglehub.login(). No unverified copy will be substituted.',
            'CREDENTIALS_MISSING')


def _resolve_with_version(kagglehub, handle, *, force_download, output_dir):
    handle_module = _submodule(kagglehub, 'handle')
    registry = _submodule(kagglehub, 'registry')
    resolver = getattr(registry, 'dataset_resolver', None)
    if resolver is None or handle_module is None or not hasattr(handle_module, 'parse_dataset_handle'):
        # Package layout differs: use the public helper and record no version
        # metadata instead of guessing one.
        path = kagglehub.dataset_download(handle, force_download=force_download, output_dir=output_dir)
        return str(path), None
    resolved = resolver(handle_module.parse_dataset_handle(handle), None,
                        force_download=force_download, output_dir=output_dir)
    if isinstance(resolved, tuple):
        path, version = (list(resolved) + [None])[:2]
        return str(path), version
    return str(resolved), None


def kagglehub_download(handle=DATASET_HANDLE, *, force_download=False, output_dir=None):
    """Return ``(download_root, version_or_None)`` from the installed KaggleHub package.

    KaggleHub's own cache is used, so an unchanged local copy is reused unless
    ``force_download`` is set. The version is whatever KaggleHub reports;
    ``None`` is recorded as unavailable rather than inferred from a path.
    """
    kagglehub = _import_kagglehub()
    _require_kaggle_credentials(kagglehub)
    try:
        return _resolve_with_version(kagglehub, handle, force_download=force_download,
                                     output_dir=output_dir)
    except Exception as exc:  # noqa: BLE001 - translated to a coded error below
        raise translate_download_error(exc) from exc


def download_dataset(*, output_dir=DEFAULT_OUTPUT_DIR, manifest_path=DEFAULT_MANIFEST_PATH,
                     csv_hint=None, force_download=False, downloader=None, now=None):
    """Retrieve the dataset explicitly and record its provenance.

    Called only by ``scripts/download_dataset.py``. Never invoked by
    validation, cleaning, or training. The injected ``downloader`` exists for
    tests: production uses :func:`kagglehub_download`.
    """
    output_dir = Path(output_dir)
    manifest_path = Path(manifest_path)
    timestamp = utc_now() if now is None else now()
    assert_not_protected(manifest_path, 'write a provenance manifest to')
    check_output_dir(output_dir)
    existing = read_manifest(manifest_path)

    fetch = kagglehub_download if downloader is None else downloader
    try:
        root, version = fetch(DATASET_HANDLE, force_download=force_download,
                              output_dir=str(output_dir))
    except Exception as exc:  # noqa: BLE001 - translated to a coded error below
        raise translate_download_error(exc) from exc

    root = Path(root)
    relative_csv, discovered_by = locate_csv(root, csv_hint)
    csv_path = root / relative_csv
    assert_not_protected(csv_path, 'record as the retrieved dataset')

    record = {
        'manifest_version': PROVENANCE_MANIFEST_VERSION,
        'source': {
            'provider': 'kaggle',
            'handle': DATASET_HANDLE,
            'url': DATASET_PAGE_URL,
            'retrieval_tool': 'kagglehub',
            'kagglehub_version': package_version('kagglehub'),
        },
        'version': version_metadata(version),
        'retrieved_at': timestamp,
        'verified_at': timestamp,
        'download': {
            'root': str(root),
            'output_dir': str(output_dir),
            'force_download': bool(force_download),
        },
        'csv': {
            'relative_path': str(relative_csv),
            'path': str(csv_path.resolve()),
            'discovered_by': discovered_by,
            'size_bytes': csv_path.stat().st_size,
            'sha256': sha256_file(csv_path),
        },
        'handling': {
            'source_files_modified': False,
            'cleaning_policy_applied': False,
            'negative_and_duplicate_rows_preserved': True,
            'validation': 'run scripts/train_baseline.py --validate-only separately',
        },
    }

    reused = False
    if existing is not None:
        differences = identity_differences(existing, record)
        if differences:
            if not force_download:
                raise DatasetSourceError(
                    'Existing provenance does not match this retrieval:\n- '
                    + '\n- '.join(differences)
                    + '\nReview the files, then re-run with --force-download to retrieve and record '
                      'them explicitly. Nothing was overwritten.', 'PROVENANCE_MISMATCH')
        else:
            # Identity and all available version metadata agree: keep the
            # original retrieval time and re-verify instead of re-recording.
            reused = not force_download
            record['retrieved_at'] = existing.get('retrieved_at', timestamp)

    write_manifest(manifest_path, record)
    return {**record, 'manifest_path': str(manifest_path.resolve()), 'reused': reused}
