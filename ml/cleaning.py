"""Offline cleaning of the reviewed CICIDS2017 source: explicit, read-only, reproducible.

Cleaning is a separate operator command (``scripts/clean_dataset.py``) between
validation and training. It never downloads, never fits a model, and never
writes to a reviewed CSV: the source is verified against its provenance
manifest and read read-only, while the exclusion ledger and cleaning record are
published under ``data/provenance/``.

Policy ``cicids2017-offline-cleaning`` v1.0.0 (three reasons, applied together):

1. ``negative_measurements`` - exclude a source row when any of the 11 required
   features parses to a finite value < 0. Impossible measurements are exporter
   defects, not anomaly signal.
2. ``duplicate_row`` - exclude every exact full-row duplicate beyond the first
   occurrence in source order. "Exact" means identical canonical text (the
   parsed value of every column), so rows that differ anywhere are kept.
3. ``label_conflict`` - exclude every row of an 11-feature vector whose
   ``Attack Type`` or ``Label`` value is not constant across that vector.
   Labels are never rewritten.

No row is ever imputed, clipped, sign-flipped, or relabelled; exclusions are
recorded with their source row identity so an auditor can re-include them.

Processing is chunked (10,000 rows by default) and runs two streaming passes so
peak memory depends on the chunk size and the (small) candidate set rather than
on the 717 MB file:

* pass 1 collects per-row, per-feature, and per-label hashes plus per-column
  negative masks;
* pass 2 materialises canonical text only for candidate rows and decides
  duplicates and label conflicts exactly.

Equal canonical text always shares a hash, so pass 2 can only add precision -
it can never lose a true match. Chunk size therefore cannot change counts or
the exclusion ledger.

Live inference does not use this module: ``prepare_network_frame`` keeps
duplicates and negative rows and only drops non-finite values.
"""
import csv
from collections import defaultdict
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import tempfile

import numpy as np
import pandas as pd

from ml import dataset_source
from ml.dataset_source import DATASET_HANDLE, DatasetSourceError
from ml.preprocessor import NETWORK_FEATURES

ROOT_DIR = Path(__file__).resolve().parents[1]

CLEANING_POLICY_ID = 'cicids2017-offline-cleaning'
CLEANING_POLICY_VERSION = '1.0.0'
CLEANING_RECORD_VERSION = 1
LABEL_COLUMNS = ('Attack Type', 'Label')
REASON_ORDER = ('negative_measurements', 'duplicate_row', 'label_conflict')

DEFAULT_CHUNK_ROWS = 10_000
MAX_CANDIDATE_ROWS = 200_000

DEFAULT_LEDGER_PATH = ROOT_DIR / 'data' / 'provenance' / 'cicids2017_cleaning_ledger.csv'
DEFAULT_RECORD_PATH = ROOT_DIR / 'data' / 'provenance' / 'cicids2017_cleaning.json'
LEDGER_HEADER = 'source_row_index,reasons'

# 16-byte pandas hash keys (stable per policy version, not secret material).
ROW_HASH_KEY = 'cttool-row-00000'
FEATURE_HASH_KEY = 'cttool-feat-0000'
LABEL_HASH_KEY = 'cttool-label-000'
ROW_SEPARATOR = '\x1f'

# Read the source as text so parsing cannot depend on chunk boundaries.
TEXT_READ_OPTIONS = dict(keep_default_na=False, skip_blank_lines=False, index_col=False,
                         dtype='string')

POLICY_RULES = (
    {'code': 'negative_measurements',
     'rule': 'exclude a source row when any of the 11 required features parses to a finite '
             'value < 0',
     'effect': 'row excluded from offline training and evaluation; retained verbatim in the ledger'},
    {'code': 'duplicate_row',
     'rule': 'exclude every source row whose canonical text of all parsed columns equals an '
             'earlier row',
     'effect': 'first occurrence kept; copies beyond the first excluded'},
    {'code': 'label_conflict',
     'rule': 'exclude every row of an 11-feature vector whose Attack Type or Label value is not '
             'constant across that vector',
     'effect': 'all rows of the conflicting vector excluded; labels are never rewritten'},
)


class CleaningError(RuntimeError):
    """Cleaning failure with a stable code for operators and tests."""

    def __init__(self, message, code='CLEANING_FAILED'):
        super().__init__(message)
        self.code = code


def iter_source_chunks(path, chunk_rows=DEFAULT_CHUNK_ROWS, **read_options):
    """Yield header-validated chunks of the source CSV (chunked sibling of read_network_csv)."""
    if int(chunk_rows) < 1:
        raise CleaningError('--chunk-rows must be a positive integer.', 'INVALID_ARGUMENT')
    try:
        with open(path, newline='', encoding='utf-8-sig') as handle:
            header = next(csv.reader(handle), [])
    except OSError as exc:
        raise CleaningError(f'Cannot read source CSV {path}: {exc}', 'SOURCE_UNREADABLE') from exc
    except StopIteration as exc:
        raise CleaningError(f'Source CSV is empty: {path}', 'SOURCE_UNREADABLE') from exc
    stripped = [column.strip() for column in header]
    if not stripped or len(stripped) != len(set(stripped)):
        raise CleaningError(f'CSV requires a nonempty, unique column header: {path}',
                            'SOURCE_UNREADABLE')
    options = dict(read_options, chunksize=int(chunk_rows))
    try:
        for chunk in pd.read_csv(path, **options):
            chunk.columns = [str(column).strip() for column in chunk.columns]
            yield chunk
    except (pd.errors.ParserError, pd.errors.EmptyDataError, UnicodeError) as exc:
        raise CleaningError(f'Cannot read source CSV: {exc}', 'SOURCE_UNREADABLE') from exc


def analyze_source(source, *, chunk_rows=DEFAULT_CHUNK_ROWS):
    """Pass 1: row/feature/label hashes and per-column negative masks, streamed.

    Only fixed-size arrays are retained, so peak memory does not grow with the
    file size beyond the recorded hashes and masks.
    """
    row_hash_parts, feature_hash_parts = [], []
    label_hash_parts = {column: [] for column in LABEL_COLUMNS}
    label_present = {column: False for column in LABEL_COLUMNS}
    negative_masks = {column: [] for column in NETWORK_FEATURES}
    non_finite_cells = {column: 0 for column in NETWORK_FEATURES}
    columns = None
    input_rows = 0

    for chunk in iter_source_chunks(source, chunk_rows, **TEXT_READ_OPTIONS):
        if columns is None:
            columns = [str(column).strip() for column in chunk.columns]
            missing = [feature for feature in NETWORK_FEATURES if feature not in columns]
            if missing:
                raise CleaningError('Missing required network features: ' + ', '.join(missing),
                                    'MISSING_FEATURES')
            label_present = {column: column in columns for column in LABEL_COLUMNS}
        count = len(chunk)
        input_rows += count
        row_hash_parts.append(pd.util.hash_pandas_object(
            chunk, index=False, hash_key=ROW_HASH_KEY).to_numpy(dtype=np.uint64))
        feature_hash_parts.append(pd.util.hash_pandas_object(
            chunk.loc[:, list(NETWORK_FEATURES)], index=False,
            hash_key=FEATURE_HASH_KEY).to_numpy(dtype=np.uint64))
        for column in LABEL_COLUMNS:
            if label_present[column]:
                label_hash_parts[column].append(pd.util.hash_pandas_object(
                    chunk[column].fillna(''), index=False,
                    hash_key=LABEL_HASH_KEY).to_numpy(dtype=np.uint64))
        for column in NETWORK_FEATURES:
            numeric = pd.to_numeric(chunk[column], errors='coerce').to_numpy(dtype=float,
                                                                            na_value=np.nan)
            finite = np.isfinite(numeric)
            non_finite_cells[column] += int((~finite).sum())
            negative_masks[column].append(finite & (numeric < 0))

    if columns is None or input_rows == 0:
        raise CleaningError(f'Source CSV contains no data rows: {source}', 'EMPTY_SOURCE')

    row_hashes = np.concatenate(row_hash_parts)
    feature_hashes = np.concatenate(feature_hash_parts)
    if len(row_hashes) != input_rows:
        raise CleaningError('Row accounting changed while reading the source.', 'SOURCE_UNREADABLE')

    negative_indices = {column: np.flatnonzero(np.concatenate(parts))
                        for column, parts in negative_masks.items()}
    with_negatives = [indexes for indexes in negative_indices.values() if len(indexes)]
    negative_rows = (np.unique(np.concatenate(with_negatives)) if with_negatives
                     else np.empty(0, dtype=np.int64))

    unique_hashes, counts = np.unique(row_hashes, return_counts=True)
    repeated = unique_hashes[counts > 1]
    duplicate_candidates = (np.flatnonzero(np.isin(row_hashes, repeated)) if len(repeated)
                            else np.empty(0, dtype=np.int64))

    conflict_candidates = {}
    for column in LABEL_COLUMNS:
        if not label_present[column]:
            continue
        labels = np.concatenate(label_hash_parts[column])
        pairs = np.empty(input_rows, dtype=[('f', 'u8'), ('l', 'u8')])
        pairs['f'] = feature_hashes
        pairs['l'] = labels
        unique_pairs = np.unique(pairs)
        feature_values = unique_pairs['f']
        starts = np.flatnonzero(np.concatenate(([True], feature_values[1:] != feature_values[:-1])))
        sizes = np.diff(np.append(starts, len(feature_values)))
        conflicting = feature_values[starts[sizes > 1]]
        if len(conflicting):
            conflict_candidates[column] = np.flatnonzero(np.isin(feature_hashes, conflicting))

    candidate_parts = [duplicate_candidates] + list(conflict_candidates.values())
    candidates = (np.unique(np.concatenate(candidate_parts)) if candidate_parts
                  else np.empty(0, dtype=np.int64))
    if len(candidates) > MAX_CANDIDATE_ROWS:
        raise CleaningError(
            f'{len(candidates)} candidate rows exceed the verification limit of '
            f'{MAX_CANDIDATE_ROWS}; this source does not look like the reviewed CICIDS2017 '
            'export. Review the file before re-running.', 'CANDIDATE_LIMIT_EXCEEDED')

    return {
        'input_rows': input_rows,
        'columns': columns,
        'label_present': label_present,
        'non_finite_cells': non_finite_cells,
        'negative_indices': negative_indices,
        'negative_rows': negative_rows,
        'duplicate_candidates': duplicate_candidates,
        'conflict_candidates': conflict_candidates,
        'candidates': candidates,
    }


def _verify_candidates(source, analysis, *, chunk_rows=DEFAULT_CHUNK_ROWS):
    """Pass 2: decide duplicates and label conflicts from canonical text, exactly."""
    reasons = defaultdict(set)
    duplicate_rows = 0
    duplicate_group_rows = 0
    conflict_vectors = 0
    conflict_rows = 0
    wanted = set(int(value) for value in analysis['candidates'])
    if not wanted:
        return dict(reasons), duplicate_rows, duplicate_group_rows, conflict_vectors, conflict_rows
    candidate_array = np.sort(np.fromiter(wanted, dtype=np.int64))

    full_text, feature_text, label_text = {}, {}, {column: {} for column in LABEL_COLUMNS}
    position = 0
    read_rows = 0
    for chunk in iter_source_chunks(source, chunk_rows, **TEXT_READ_OPTIONS):
        length = len(chunk)
        read_rows += length
        offsets = np.arange(position, position + length)
        found = np.flatnonzero(np.isin(offsets, candidate_array))
        if len(found):
            subset = chunk.iloc[found].astype('string').fillna('')
            texts = subset.agg(ROW_SEPARATOR.join, axis=1).tolist()
            feature_texts = (subset.loc[:, list(NETWORK_FEATURES)].agg(ROW_SEPARATOR.join,
                                                                      axis=1).tolist())
            label_values = {column: subset[column].tolist() for column in LABEL_COLUMNS
                            if analysis['label_present'][column]}
            for local, offset in enumerate(found):
                row_index = position + int(offset)
                full_text[row_index] = texts[local]
                feature_text[row_index] = feature_texts[local]
                for column, values in label_values.items():
                    label_text[column][row_index] = values[local]
        position += length

    if read_rows != analysis['input_rows']:
        raise CleaningError('Source row count changed between cleaning passes.',
                            'SOURCE_ROWS_MISMATCH')

    duplicate_groups = defaultdict(list)
    for row_index, text in full_text.items():
        duplicate_groups[text].append(row_index)
    for indices in duplicate_groups.values():
        if len(indices) > 1:
            duplicate_group_rows += len(indices)
            duplicate_rows += len(indices) - 1
            keep = min(indices)
            for row_index in indices:
                if row_index != keep:
                    reasons[row_index].add('duplicate_row')

    feature_groups = defaultdict(list)
    for row_index, text in feature_text.items():
        feature_groups[text].append(row_index)
    for indices in feature_groups.values():
        conflicting = False
        for column in LABEL_COLUMNS:
            if not analysis['label_present'][column]:
                continue
            if len({label_text[column][row_index] for row_index in indices}) > 1:
                conflicting = True
                break
        if conflicting:
            conflict_vectors += 1
            conflict_rows += len(indices)
            for row_index in indices:
                reasons[row_index].add('label_conflict')

    for column, indexes in analysis['negative_indices'].items():
        for row_index in indexes:
            reasons[int(row_index)].add('negative_measurements')

    return dict(reasons), duplicate_rows, duplicate_group_rows, conflict_vectors, conflict_rows


def render_ledger(reasons):
    """Deterministic ledger bytes: sorted by source row index, fixed reason order, LF."""
    lines = [LEDGER_HEADER]
    for row_index in sorted(reasons):
        ordered = [code for code in REASON_ORDER if code in reasons[row_index]]
        lines.append(f'{row_index},{ "|".join(ordered)}')
    return ('\n'.join(lines) + '\n').encode('utf-8')


def assert_counts(input_rows, retained_rows, unique_excluded_rows):
    """Input rows must equal retained rows plus the unique excluded-row union."""
    if input_rows < 0 or retained_rows < 0 or unique_excluded_rows < 0:
        raise CleaningError('Row counts cannot be negative.', 'COUNT_MISMATCH')
    if input_rows != retained_rows + unique_excluded_rows:
        raise CleaningError(
            f'Count invariant violated: {input_rows} != {retained_rows} + {unique_excluded_rows}. '
            'No record was written.', 'COUNT_MISMATCH')


def _publish_bytes(path, payload, *, force, label, code):
    """Atomically publish a derived artifact; mismatched existing content needs --force."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() == payload:
            return 'reused'
        if not force:
            raise CleaningError(
                f'{label} at {path} does not match this run. Review it, then re-run with '
                '--force to replace it explicitly.', code)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + '.', suffix='.tmp', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as handle:
            handle.write(payload)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return 'written'


def _record_signature(record):
    """Compare records without the run timestamp."""
    snapshot = json.loads(json.dumps(record))
    snapshot.get('policy', {}).pop('applied_at', None)
    return json.dumps(snapshot, sort_keys=True)


def load_cleaning_record(record_path=DEFAULT_RECORD_PATH):
    record_path = Path(record_path)
    if not record_path.is_file():
        raise CleaningError(f'Cleaning record not found: {record_path}. '
                            'Run scripts/clean_dataset.py first.', 'RECORD_MISSING')
    try:
        record = json.loads(record_path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        raise CleaningError(f'Cannot read cleaning record {record_path}: {exc}',
                            'RECORD_UNREADABLE') from exc
    if not isinstance(record, dict) or record.get('record_version') != CLEANING_RECORD_VERSION:
        raise CleaningError(f'Unsupported cleaning record: {record_path}', 'RECORD_UNREADABLE')
    return record


def clean_dataset(*, source=None, manifest_path=dataset_source.DEFAULT_MANIFEST_PATH,
                  ledger_path=DEFAULT_LEDGER_PATH, record_path=DEFAULT_RECORD_PATH,
                  chunk_rows=DEFAULT_CHUNK_ROWS, force=False, now=None):
    """Apply policy v1.0.0 to the reviewed source; read-only, no fitting, no network."""
    manifest_path = Path(manifest_path)
    ledger_path = Path(ledger_path)
    record_path = Path(record_path)
    timestamp = dataset_source.utc_now() if now is None else now()

    if not manifest_path.is_file():
        raise CleaningError(
            f'Provenance manifest not found: {manifest_path}. '
            'Run scripts/download_dataset.py before cleaning.', 'PROVENANCE_MISSING')
    try:
        manifest = dataset_source.read_manifest(manifest_path)
    except DatasetSourceError as exc:
        raise CleaningError(str(exc), exc.code) from exc
    handle = (manifest.get('source') or {}).get('handle')
    if handle != DATASET_HANDLE:
        raise CleaningError(
            f'Provenance manifest is for {handle!r}, not {DATASET_HANDLE!r}.',
            'PROVENANCE_MISMATCH')
    csv_record = manifest.get('csv') or {}
    recorded_sha = str(csv_record.get('sha256') or '')
    if not re.fullmatch(r'[0-9a-f]{64}', recorded_sha):
        raise CleaningError('Provenance manifest has no valid CSV SHA-256.', 'PROVENANCE_MISMATCH')

    source_path = Path(source if source is not None else csv_record.get('path', ''))
    if not source_path.is_file():
        raise CleaningError(f'Source CSV not found: {source_path}', 'SOURCE_MISSING')
    size_bytes = source_path.stat().st_size
    if size_bytes != int(csv_record.get('size_bytes', -1)):
        raise CleaningError(
            f'Source size {size_bytes} does not match the manifest entry '
            f'{csv_record.get("size_bytes")!r}.', 'SOURCE_SHA_MISMATCH')
    actual_sha = dataset_source.sha256_file(source_path)
    if actual_sha != recorded_sha:
        raise CleaningError(
            f'Source SHA-256 {actual_sha} does not match the provenance manifest '
            f'{recorded_sha}. Nothing was cleaned.', 'SOURCE_SHA_MISMATCH')

    for target in (ledger_path, record_path):
        try:
            dataset_source.assert_not_protected(target, 'write a cleaning record to')
        except DatasetSourceError as exc:
            raise CleaningError(str(exc), exc.code) from exc
        if Path(target).resolve() == source_path.resolve():
            raise CleaningError('Refusing to overwrite the source CSV with a cleaning artifact.',
                                'SOURCE_PROTECTED')

    analysis = analyze_source(source_path, chunk_rows=chunk_rows)
    reasons, duplicate_rows, group_rows, conflict_vectors, conflict_rows = _verify_candidates(
        source_path, analysis, chunk_rows=chunk_rows)

    input_rows = analysis['input_rows']
    unique_excluded = len(reasons)
    retained_rows = input_rows - unique_excluded
    assert_counts(input_rows, retained_rows, unique_excluded)

    ledger_bytes = render_ledger(reasons)
    ledger_sha = hashlib.sha256(ledger_bytes).hexdigest()
    ledger_status = _publish_bytes(ledger_path, ledger_bytes, force=force,
                                   label='Exclusion ledger', code='LEDGER_MISMATCH')

    negative_counts = {column: int(len(indexes))
                       for column, indexes in analysis['negative_indices'].items()}
    per_reason = {code: 0 for code in REASON_ORDER}
    for codes in reasons.values():
        for code in codes:
            per_reason[code] += 1
    pairs = {}
    for index, left in enumerate(REASON_ORDER):
        for right in REASON_ORDER[index + 1:]:
            count = sum(1 for codes in reasons.values() if left in codes and right in codes)
            if count:
                pairs[f'{left} & {right}'] = count
    multi_reason = sum(1 for codes in reasons.values() if len(codes) > 1)
    checked_labels = [column for column in LABEL_COLUMNS if analysis['label_present'][column]]

    record = {
        'record_version': CLEANING_RECORD_VERSION,
        'policy': {
            'id': CLEANING_POLICY_ID,
            'version': CLEANING_POLICY_VERSION,
            'rules': list(POLICY_RULES),
            'reason_codes': list(REASON_ORDER),
            'applied_at': timestamp,
            'offline_only': True,
            'modifications_never_applied': ['imputation', 'clipping', 'absolute_value',
                                            'relabel', 'value_replacement'],
        },
        'source': {
            'path': str(source_path.resolve()),
            'sha256': actual_sha,
            'size_bytes': size_bytes,
            'rows': input_rows,
            'columns': analysis['columns'],
            'label_columns_checked': checked_labels,
            'label_conflict_status': 'checked' if checked_labels else 'not_applicable',
            'manifest_path': str(manifest_path.resolve()),
            'manifest_handle': handle,
            'manifest_csv_path': csv_record.get('path'),
            'manifest_path_matches_source': (str(Path(csv_record.get('path')).resolve())
                                             == str(source_path.resolve())
                                             if csv_record.get('path') else False),
            'dataset_version': manifest.get('version'),
        },
        'issues': {
            'negative_measurements': {
                'rows': int(len(analysis['negative_rows'])),
                'cells': int(sum(negative_counts.values())),
                'columns': negative_counts,
                'non_finite_cells_not_excluded': analysis['non_finite_cells'],
            },
            'duplicate_rows': {'rows': duplicate_rows, 'rows_in_duplicate_groups': group_rows,
                               'comparison': 'exact canonical text of every parsed column; '
                                             'copies beyond the first'},
            'label_conflicts': {'vectors': conflict_vectors, 'rows': conflict_rows,
                                'columns_checked': checked_labels},
        },
        'exclusions': {
            'unique_rows': unique_excluded,
            'by_reason': per_reason,
            'overlaps': {'rows_with_multiple_reasons': multi_reason, 'pairs': pairs},
            'input_rows': input_rows,
            'retained_rows': retained_rows,
            'invariant': 'input_rows == retained_rows + unique_rows',
        },
        'ledger': {
            'path': str(ledger_path.resolve()),
            'sha256': ledger_sha,
            'rows': unique_excluded,
            'columns': ['source_row_index', 'reasons'],
            'newline': 'LF',
            'row_identity': '0-based source data row index, header excluded',
        },
        'processing': {
            'chunk_rows': int(chunk_rows),
            'passes': 2,
            'grouping': 'pandas hash_pandas_object with fixed keys, verified exactly on canonical '
                        'text in pass 2',
            'memory': 'bounded by chunk size and candidate rows, not by file size',
        },
        'environment': {
            'python': platform.python_version(),
            'pandas': pd.__version__,
            'numpy': np.__version__,
        },
    }

    existing = None
    if record_path.is_file():
        try:
            existing = json.loads(record_path.read_text(encoding='utf-8'))
        except (OSError, ValueError) as exc:
            raise CleaningError(
                f'Cannot read cleaning record {record_path}: {exc}. '
                'Review it, then re-run with --force to replace it.', 'RECORD_UNREADABLE') from exc
    if existing is not None and _record_signature(existing) == _record_signature(record):
        record_status = 'reused'
    else:
        if existing is not None and not force:
            raise CleaningError(
                f'Cleaning record at {record_path} does not match this run (policy, source, '
                'counts, or ledger digest differ). Review it, then re-run with --force to '
                'replace it explicitly.', 'RECORD_MISMATCH')
        payload = (json.dumps(record, indent=2) + '\n').encode('utf-8')
        _publish_bytes(record_path, payload, force=force, label='Cleaning record',
                       code='RECORD_MISMATCH')
        record_status = 'written'

    return {**record, 'ledger_status': ledger_status, 'record_status': record_status,
            'record_path': str(record_path.resolve())}


def _eligible_context(source=None, record_path=DEFAULT_RECORD_PATH):
    record = load_cleaning_record(record_path)
    source_path = Path(source if source is not None else record['source']['path'])
    if not source_path.is_file():
        raise CleaningError(f'Source CSV not found: {source_path}', 'SOURCE_MISSING')
    actual_sha = dataset_source.sha256_file(source_path)
    if actual_sha != record['source']['sha256']:
        raise CleaningError(
            f'Source SHA-256 {actual_sha} no longer matches the cleaning record '
            f'{record["source"]["sha256"]}. The eligible view was not derived.',
            'SOURCE_SHA_MISMATCH')
    ledger_path = Path(record['ledger']['path'])
    if not ledger_path.is_file():
        raise CleaningError(f'Exclusion ledger not found: {ledger_path}', 'LEDGER_MISSING')
    payload = ledger_path.read_bytes()
    if hashlib.sha256(payload).hexdigest() != record['ledger']['sha256']:
        raise CleaningError(f'Exclusion ledger {ledger_path} does not match the cleaning record.',
                            'LEDGER_MISMATCH')
    lines = payload.decode('utf-8').splitlines()
    if not lines or lines[0] != LEDGER_HEADER:
        raise CleaningError(f'Exclusion ledger {ledger_path} has an unexpected header.',
                            'LEDGER_MISMATCH')
    indices = []
    for line in lines[1:]:
        if not line:
            continue
        try:
            indices.append(int(line.split(',', 1)[0]))
        except ValueError as exc:
            raise CleaningError(f'Exclusion ledger {ledger_path} is malformed: {line!r}',
                                'LEDGER_MISMATCH') from exc
    if any(index < 0 or index >= record['source']['rows'] for index in indices):
        raise CleaningError('Exclusion ledger references rows outside the source.',
                            'LEDGER_MISMATCH')
    return record, source_path, np.sort(np.asarray(indices, dtype=np.int64))


def iter_eligible_chunks(source=None, record_path=DEFAULT_RECORD_PATH, *, usecols=None,
                         chunk_rows=DEFAULT_CHUNK_ROWS):
    """Stream the eligible view derived at load time; source row index is preserved."""
    record, source_path, excluded = _eligible_context(source, record_path)
    options = dict(keep_default_na=False, skip_blank_lines=False, index_col=False)
    if usecols is not None:
        options['usecols'] = usecols
    position = 0
    for chunk in iter_source_chunks(source_path, chunk_rows, **options):
        length = len(chunk)
        offsets = np.arange(position, position + length)
        keep = ~np.isin(offsets, excluded)
        kept = offsets[keep]
        if len(kept):
            view = chunk.loc[keep].copy()
            view.index = kept
            yield view
        position += length
    if position != record['source']['rows']:
        raise CleaningError(
            f'Eligible view read {position} rows but the cleaning record holds '
            f'{record["source"]["rows"]}.', 'SOURCE_ROWS_MISMATCH')


def load_eligible_frame(source=None, record_path=DEFAULT_RECORD_PATH, *, usecols=None,
                        chunk_rows=DEFAULT_CHUNK_ROWS):
    """Materialise the eligible view (source row index preserved) for offline use."""
    record = load_cleaning_record(record_path)
    parts = list(iter_eligible_chunks(source, record_path, usecols=usecols,
                                      chunk_rows=chunk_rows))
    if not parts:
        raise CleaningError('No eligible rows remain after cleaning.', 'EMPTY_ELIGIBLE_VIEW')
    frame = pd.concat(parts)
    if len(frame) != record['exclusions']['retained_rows']:
        raise CleaningError(
            f'Eligible view holds {len(frame)} rows but the record expects '
            f'{record["exclusions"]["retained_rows"]}.', 'COUNT_MISMATCH')
    return frame
