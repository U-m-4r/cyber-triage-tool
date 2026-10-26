"""Offline cleaning policy (cicids2017-offline-cleaning v1.0.0).

Cleaning is a separate, explicit operation: it verifies provenance, never
downloads, never fits a model, never rewrites the reviewed source, and derives
the eligible view at load time instead of materialising a cleaned CSV.
"""
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from ml import cleaning, dataset_source
from ml.cleaning import (CleaningError, assert_counts, clean_dataset,
                         iter_eligible_chunks, load_eligible_frame)
from ml.preprocessor import ForensicPreprocessor, NETWORK_FEATURES, prepare_network_frame
from scripts import clean_dataset as clean_script
from scripts import run_evaluation as evaluation

from sklearn.preprocessing import StandardScaler

_REAL_STANDARD_SCALER_FIT = StandardScaler.fit
_REAL_STANDARD_SCALER_FIT_TRANSFORM = StandardScaler.fit_transform


@pytest.fixture
def real_scaler(forbid_fitting_and_downloading, monkeypatch):
    """Lift the fitting guard for tests that verify scaler fitting itself."""
    monkeypatch.setattr(StandardScaler, 'fit', _REAL_STANDARD_SCALER_FIT)
    monkeypatch.setattr(StandardScaler, 'fit_transform', _REAL_STANDARD_SCALER_FIT_TRANSFORM)


@pytest.fixture(autouse=True)
def forbid_fitting_and_downloading(monkeypatch):
    """Any fit()/joblib.dump()/dataset download during cleaning fails loudly."""
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import joblib

    def forbidden(*args, **kwargs):
        raise AssertionError('Cleaning attempted model fitting, publication, or download')

    monkeypatch.setattr(IsolationForest, 'fit', forbidden)
    monkeypatch.setattr(StandardScaler, 'fit', forbidden)
    monkeypatch.setattr(StandardScaler, 'fit_transform', forbidden)
    monkeypatch.setattr(joblib, 'dump', forbidden)
    monkeypatch.setattr(dataset_source, 'download_dataset', forbidden)
    monkeypatch.setattr(dataset_source, 'kagglehub_download', forbidden)


def make_row(base, attack, label, flow_id, **overrides):
    """One source row: 11 required features + labels + an extra metadata column."""
    row = {feature: str(base + index * 3 + 1) for index, feature in enumerate(NETWORK_FEATURES)}
    row.update({key: str(value) for key, value in overrides.items()})
    row.update({'Attack Type': attack, 'Label': label, 'Flow ID': flow_id})
    return row


@pytest.fixture
def source_csv(tmp_path):
    rows = [make_row(index * 10, 'Normal Traffic', 'BENIGN', f'flow-{index}')
            for index in range(6)]
    rows += [
        # finite negatives in two columns of the same row (union, not sum)
        make_row(100, 'Normal Traffic', 'BENIGN', 'neg-1',
                 **{'Flow Duration': '-100', 'Flow Packets/s': '-1.5'}),
        # finite negative in a third column
        make_row(110, 'Normal Traffic', 'BENIGN', 'neg-2', **{'Flow Bytes/s': '-3.25'}),
        # exact full-row duplicate of a negative row -> overlapping reasons
        make_row(200, 'DDoS', 'DDoS', 'dup-a', **{'Flow Duration': '-5'}),
        make_row(200, 'DDoS', 'DDoS', 'dup-a', **{'Flow Duration': '-5'}),
        # identical 11-feature vectors with conflicting labels
        make_row(300, 'Normal Traffic', 'BENIGN', 'conflict-1'),
        make_row(300, 'DDoS', 'DDoS', 'conflict-2'),
        # identical 11-feature vectors with the same labels, different metadata
        make_row(400, 'Normal Traffic', 'BENIGN', 'twin-1'),
        make_row(400, 'Normal Traffic', 'BENIGN', 'twin-2'),
    ]
    path = tmp_path / 'cicids2017_cleaning_source.csv'
    pd.DataFrame(rows).to_csv(path, index=False)
    return path


def write_test_manifest(manifest_path, source, *, handle=None, sha=None, size=None):
    """Provenance manifest in the format written by scripts/download_dataset.py."""
    record = {
        'manifest_version': 1,
        'source': {
            'provider': 'kaggle',
            'handle': handle if handle is not None else dataset_source.DATASET_HANDLE,
            'url': 'https://www.kaggle.com/datasets/example',
            'retrieval_tool': 'kagglehub',
            'kagglehub_version': '1.0.3',
        },
        'version': {'value': 1, 'status': 'available'},
        'retrieved_at': '2026-10-26T00:00:00+00:00',
        'verified_at': '2026-10-26T00:00:00+00:00',
        'download': {'mode': 'test-fixture', 'destination': str(source.parent)},
        'csv': {
            'relative_path': source.name,
            'path': str(source),
            'discovered_by': 'test-fixture',
            'size_bytes': source.stat().st_size if size is None else size,
            'sha256': dataset_source.sha256_file(source) if sha is None else sha,
        },
        'handling': {'source_is_reviewed': True, 'write_policy': 'read-only'},
    }
    dataset_source.write_manifest(manifest_path, record)
    return record


@pytest.fixture
def workspace(source_csv, tmp_path):
    provenance = tmp_path / 'provenance'
    provenance.mkdir()
    manifest = provenance / 'source.provenance.json'
    write_test_manifest(manifest, source_csv)
    return {'source': source_csv, 'manifest': manifest,
            'ledger': provenance / 'cleaning_ledger.csv',
            'record': provenance / 'cleaning.json'}


def run_clean(workspace, **overrides):
    options = {'source': workspace['source'], 'manifest_path': workspace['manifest'],
               'ledger_path': workspace['ledger'], 'record_path': workspace['record']}
    options.update(overrides)
    return clean_dataset(**options)


def ledger_entries(path):
    lines = Path(path).read_text(encoding='utf-8').splitlines()
    assert lines[0] == 'source_row_index,reasons'
    return dict(line.split(',', 1) for line in lines[1:] if line)


# --- policy application -------------------------------------------------------

def test_policy_applies_three_reasons_with_union_counts(workspace):
    report = run_clean(workspace)
    assert report['policy']['id'] == 'cicids2017-offline-cleaning'
    assert report['policy']['version'] == cleaning.CLEANING_POLICY_VERSION
    assert report['policy']['offline_only'] is True
    assert 'relabel' in report['policy']['modifications_never_applied']

    assert report['source']['rows'] == 14
    negative = report['issues']['negative_measurements']
    assert negative['rows'] == 4          # union of the per-column row sets
    assert negative['cells'] == 5         # 3 + 1 + 1 cells, never summed as rows
    assert {column: count for column, count in negative['columns'].items() if count} == {
        'Flow Duration': 3, 'Flow Packets/s': 1, 'Flow Bytes/s': 1}

    duplicate = report['issues']['duplicate_rows']
    assert duplicate['rows'] == 1
    assert duplicate['rows_in_duplicate_groups'] == 2

    conflict = report['issues']['label_conflicts']
    assert conflict['vectors'] == 1
    assert conflict['rows'] == 2
    assert conflict['columns_checked'] == ['Attack Type', 'Label']

    exclusions = report['exclusions']
    assert exclusions['unique_rows'] == 6
    assert exclusions['by_reason'] == {'negative_measurements': 4, 'duplicate_row': 1,
                                       'label_conflict': 2}
    assert exclusions['input_rows'] == 14
    assert exclusions['retained_rows'] == 8
    assert exclusions['input_rows'] == exclusions['retained_rows'] + exclusions['unique_rows']


def test_overlapping_exclusions_are_counted_once(workspace):
    report = run_clean(workspace)
    exclusions = report['exclusions']
    reason_total = sum(exclusions['by_reason'].values())
    assert reason_total == 7                    # reasons are reported per reason
    assert exclusions['unique_rows'] == 6       # the union is smaller than the sum
    assert exclusions['overlaps']['rows_with_multiple_reasons'] == 1
    assert exclusions['overlaps']['pairs'] == {'negative_measurements & duplicate_row': 1}


def test_ledger_lists_source_row_identities_in_reason_order(workspace):
    run_clean(workspace)
    assert ledger_entries(workspace['ledger']) == {
        '6': 'negative_measurements',
        '7': 'negative_measurements',
        '8': 'negative_measurements',
        '9': 'negative_measurements|duplicate_row',
        '10': 'label_conflict',
        '11': 'label_conflict',
    }


def test_label_conflicts_exclude_every_row_and_never_relabel(workspace):
    before = workspace['source'].read_bytes()
    report = run_clean(workspace)
    assert workspace['source'].read_bytes() == before
    entries = ledger_entries(workspace['ledger'])
    assert entries['10'] == entries['11'] == 'label_conflict'
    record = json.loads(workspace['record'].read_text(encoding='utf-8'))
    assert record['source']['sha256'] == dataset_source.sha256_file(workspace['source'])
    assert record['exclusions']['by_reason']['label_conflict'] == 2
    assert report['policy']['modifications_never_applied'][-1] == 'value_replacement'


def test_rows_differing_in_one_column_are_never_duplicates(workspace):
    report = run_clean(workspace)
    view = load_eligible_frame(workspace['source'], workspace['record'])
    # twin-1/twin-2 share all 11 features and labels but differ in Flow ID
    assert list(view.index) == [0, 1, 2, 3, 4, 5, 12, 13]
    entries = ledger_entries(workspace['ledger'])
    assert '12' not in entries and '13' not in entries
    assert report['issues']['duplicate_rows']['rows'] == 1  # only the exact dup-a copy
    assert report['exclusions']['unique_rows'] == 6


def test_count_invariant_is_asserted():
    assert_counts(14, 8, 6)
    with pytest.raises(CleaningError) as exc:
        assert_counts(14, 9, 6)
    assert exc.value.code == 'COUNT_MISMATCH'
    with pytest.raises(CleaningError) as exc:
        assert_counts(14, 9, -1)
    assert exc.value.code == 'COUNT_MISMATCH'


def test_missing_required_feature_is_refused(workspace):
    frame = pd.read_csv(workspace['source'])
    frame.drop(columns=['Flow Bytes/s']).to_csv(workspace['source'], index=False)
    write_test_manifest(workspace['manifest'], workspace['source'])
    with pytest.raises(CleaningError) as exc:
        run_clean(workspace)
    assert exc.value.code == 'MISSING_FEATURES'
    assert not workspace['ledger'].exists()


def test_header_only_source_is_refused(workspace):
    pd.DataFrame(columns=list(NETWORK_FEATURES) + ['Attack Type', 'Label', 'Flow ID']).to_csv(
        workspace['source'], index=False)
    write_test_manifest(workspace['manifest'], workspace['source'])
    with pytest.raises(CleaningError) as exc:
        run_clean(workspace)
    assert exc.value.code == 'EMPTY_SOURCE'


def test_candidate_verification_default_constant():
    assert cleaning.MAX_CANDIDATE_ROWS == 250_000


def test_candidate_limit_is_enforced(workspace, monkeypatch):
    monkeypatch.setattr(cleaning, 'MAX_CANDIDATE_ROWS', 1)
    with pytest.raises(CleaningError) as exc:
        run_clean(workspace)
    assert exc.value.code == 'CANDIDATE_LIMIT_EXCEEDED'
    assert not workspace['ledger'].exists()


def test_candidate_limit_accepts_below_or_equal_ceiling(workspace, monkeypatch):
    # workspace has 4 candidate rows (2 duplicates, 2 conflicts)
    monkeypatch.setattr(cleaning, 'MAX_CANDIDATE_ROWS', 4)
    report = run_clean(workspace)
    assert report['record_status'] == 'written'
    assert report['exclusions']['unique_rows'] == 6
    assert workspace['ledger'].exists()


def test_candidate_limit_rejects_above_ceiling(workspace, monkeypatch):
    # workspace has 4 candidate rows; ceiling of 3 must reject
    monkeypatch.setattr(cleaning, 'MAX_CANDIDATE_ROWS', 3)
    with pytest.raises(CleaningError) as exc:
        run_clean(workspace)
    assert exc.value.code == 'CANDIDATE_LIMIT_EXCEEDED'
    assert not workspace['ledger'].exists()


def test_candidate_verification_immutability_and_determinism(workspace):
    stat_before = workspace['source'].stat().st_mtime_ns
    bytes_before = workspace['source'].read_bytes()

    run1 = run_clean(workspace)
    ledger1 = workspace['ledger'].read_bytes()
    record1 = workspace['record'].read_text(encoding='utf-8')

    # Source must remain byte-identical and mtime untouched
    assert workspace['source'].read_bytes() == bytes_before
    assert workspace['source'].stat().st_mtime_ns == stat_before

    # Second run must produce byte-identical ledger and deterministic counts
    workspace['ledger'].unlink()
    workspace['record'].unlink()
    run2 = run_clean(workspace)
    ledger2 = workspace['ledger'].read_bytes()
    record2 = workspace['record'].read_text(encoding='utf-8')

    assert ledger1 == ledger2
    assert json.loads(record1)['exclusions'] == json.loads(record2)['exclusions']


def test_invalid_chunk_size_is_refused(workspace):
    with pytest.raises(CleaningError) as exc:
        run_clean(workspace, chunk_rows=0)
    assert exc.value.code == 'INVALID_ARGUMENT'


# --- determinism -------------------------------------------------------------

def test_counts_and_ledger_do_not_depend_on_chunk_size(workspace):
    runs = []
    for chunk_rows in (1, 5, 1000):
        ledger = workspace['source'].parent / f'ledger-{chunk_rows}.csv'
        record = workspace['source'].parent / f'record-{chunk_rows}.json'
        report = clean_dataset(source=workspace['source'], manifest_path=workspace['manifest'],
                               ledger_path=ledger, record_path=record, chunk_rows=chunk_rows)
        runs.append((report, ledger.read_bytes()))
    digests = {report['ledger']['sha256'] for report, _ in runs}
    exclusions = {json.dumps(report['exclusions'], sort_keys=True) for report, _ in runs}
    assert len(digests) == 1
    assert len(exclusions) == 1
    payloads = {payload for _, payload in runs}
    assert len(payloads) == 1
    assert hashlib.sha256(runs[0][1]).hexdigest() == runs[0][0]['ledger']['sha256']


def test_second_run_reuses_ledger_and_record(workspace):
    first = run_clean(workspace)
    assert (first['ledger_status'], first['record_status']) == ('written', 'written')
    ledger_before = workspace['ledger'].read_bytes()
    record_before = workspace['record'].read_bytes()
    second = run_clean(workspace)
    assert (second['ledger_status'], second['record_status']) == ('reused', 'reused')
    assert workspace['ledger'].read_bytes() == ledger_before
    assert workspace['record'].read_bytes() == record_before


def test_tampered_ledger_requires_explicit_force(workspace):
    run_clean(workspace)
    tampered = workspace['ledger'].read_text(encoding='utf-8').replace('11,', '110,')
    workspace['ledger'].write_text(tampered, encoding='utf-8')
    with pytest.raises(CleaningError) as exc:
        run_clean(workspace)
    assert exc.value.code == 'LEDGER_MISMATCH'
    assert '110,' in workspace['ledger'].read_text(encoding='utf-8')  # nothing overwritten
    forced = run_clean(workspace, force=True)
    assert forced['ledger_status'] == 'written'
    assert ledger_entries(workspace['ledger'])['11'] == 'label_conflict'


def test_tampered_record_requires_explicit_force(workspace):
    run_clean(workspace)
    record = json.loads(workspace['record'].read_text(encoding='utf-8'))
    record['exclusions']['retained_rows'] += 1
    workspace['record'].write_text(json.dumps(record), encoding='utf-8')
    with pytest.raises(CleaningError) as exc:
        run_clean(workspace)
    assert exc.value.code == 'RECORD_MISMATCH'
    forced = run_clean(workspace, force=True)
    assert forced['record_status'] == 'written'
    restored = json.loads(workspace['record'].read_text(encoding='utf-8'))
    assert restored['exclusions']['retained_rows'] == 8


# --- provenance and source safety --------------------------------------------

def test_missing_manifest_is_refused(workspace):
    workspace['manifest'].unlink()
    with pytest.raises(CleaningError) as exc:
        run_clean(workspace)
    assert exc.value.code == 'PROVENANCE_MISSING'
    assert not workspace['ledger'].exists()
    assert not workspace['record'].exists()


def test_unreadable_manifest_is_refused(workspace):
    workspace['manifest'].write_text('{"manifest_version": 1,', encoding='utf-8')
    with pytest.raises(CleaningError) as exc:
        run_clean(workspace)
    assert exc.value.code == 'PROVENANCE_UNREADABLE'


def test_manifest_for_another_dataset_is_refused(workspace):
    write_test_manifest(workspace['manifest'], workspace['source'],
                        handle='somebody/other-dataset')
    with pytest.raises(CleaningError) as exc:
        run_clean(workspace)
    assert exc.value.code == 'PROVENANCE_MISMATCH'


def test_source_sha256_mismatch_is_refused(workspace):
    write_test_manifest(workspace['manifest'], workspace['source'], sha='0' * 64)
    with pytest.raises(CleaningError) as exc:
        run_clean(workspace)
    assert exc.value.code == 'SOURCE_SHA_MISMATCH'
    assert not workspace['ledger'].exists()
    assert not workspace['record'].exists()


def test_source_is_immutable_and_no_cleaned_csv_is_created(workspace):
    payload = workspace['source'].read_bytes()
    stat_before = workspace['source'].stat().st_mtime_ns
    report = run_clean(workspace)
    assert workspace['source'].read_bytes() == payload
    assert workspace['source'].stat().st_mtime_ns == stat_before
    assert set(workspace['source'].parent.glob('*.csv')) == {workspace['source']}
    assert report['ledger']['path'] == str(workspace['ledger'].resolve())


def test_artifacts_never_overwrite_the_source(workspace):
    for override in ({'ledger_path': workspace['source']}, {'record_path': workspace['source']}):
        with pytest.raises(CleaningError) as exc:
            run_clean(workspace, **override)
        assert exc.value.code == 'SOURCE_PROTECTED'
        assert workspace['source'].exists()


def test_protected_source_paths_are_refused(workspace):
    protected = dataset_source.PROTECTED_DATASET_PATHS[0]
    stat_before = protected.stat().st_mtime_ns if protected.exists() else None
    with pytest.raises(CleaningError) as exc:
        run_clean(workspace, ledger_path=protected)
    assert exc.value.code == 'SOURCE_PROTECTED'
    if stat_before is not None:
        assert protected.stat().st_mtime_ns == stat_before
    with pytest.raises(CleaningError) as exc:
        run_clean(workspace, record_path=dataset_source.PROTECTED_DATASET_PATHS[1])
    assert exc.value.code == 'SOURCE_PROTECTED'


def test_cleaning_never_fits_or_downloads(workspace):
    # The autouse fixture turns any fit()/dump()/download attempt into a failure.
    report = run_clean(workspace)
    assert report['record_status'] == 'written'
    assert report['processing']['passes'] == 2
    assert report['policy']['offline_only'] is True


# --- load-time eligible view -------------------------------------------------

def test_eligible_view_is_derived_from_the_source(workspace):
    run_clean(workspace)
    view = load_eligible_frame(workspace['source'], workspace['record'], chunk_rows=4)
    assert list(view.index) == [0, 1, 2, 3, 4, 5, 12, 13]
    assert len(view) == 8
    assert (view['Flow Duration'].astype(float) >= 0).all()
    assert (view['Flow Bytes/s'].astype(float) >= 0).all()


def test_view_chunks_preserve_source_row_identity(workspace):
    run_clean(workspace)
    chunks = list(iter_eligible_chunks(workspace['source'], workspace['record'], chunk_rows=3))
    assert len(chunks) > 1
    combined = pd.concat(chunks)
    assert list(combined.index) == [0, 1, 2, 3, 4, 5, 12, 13]


def test_view_is_refused_when_the_source_changed(workspace):
    run_clean(workspace)
    with workspace['source'].open('a', encoding='utf-8') as handle:
        handle.write('999999,0,0,0,0,0,0,0,0,0,0,Normal Traffic,BENIGN,extra\n')
    with pytest.raises(CleaningError) as exc:
        load_eligible_frame(workspace['source'], workspace['record'])
    assert exc.value.code == 'SOURCE_SHA_MISMATCH'


def test_view_is_refused_when_the_ledger_tampered(workspace):
    run_clean(workspace)
    workspace['ledger'].write_text('source_row_index,reasons\n0,negative_measurements\n',
                                   encoding='utf-8')
    with pytest.raises(CleaningError) as exc:
        load_eligible_frame(workspace['source'], workspace['record'])
    assert exc.value.code == 'LEDGER_MISMATCH'


def test_view_requires_a_cleaning_record(workspace):
    with pytest.raises(CleaningError) as exc:
        load_eligible_frame(workspace['source'], workspace['record'])
    assert exc.value.code == 'RECORD_MISSING'


# --- live inference stays untouched ------------------------------------------

def inference_frame():
    rows = [make_row(index * 7, 'Normal Traffic', 'BENIGN', f'live-{index}')
            for index in range(3)]
    rows[0] = make_row(0, 'Normal Traffic', 'BENIGN', 'live-0', **{'Flow Duration': '-42'})
    rows.append(dict(rows[1]))  # exact duplicate, must survive inference prep
    frame = pd.DataFrame(rows)
    frame.insert(0, 'artifact_type', 'network')
    return frame


def test_live_inference_keeps_duplicates_and_negative_rows(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('live inference must not apply the offline cleaning policy')

    monkeypatch.setattr(cleaning, 'clean_dataset', forbidden)
    monkeypatch.setattr(cleaning, 'load_eligible_frame', forbidden)
    frame = inference_frame()
    clean, _, report = prepare_network_frame(frame)
    assert len(clean) == len(frame)
    assert report['duplicates_preserved'] is True
    assert report['dropped_invalid_rows'] == 0
    assert (clean['Flow Duration'] < 0).any()
    assert (clean.duplicated(subset=list(NETWORK_FEATURES)).sum() >= 1)


def test_live_inference_never_imports_the_cleaning_module():
    from ml import preprocessor
    assert 'clean_dataset' not in vars(preprocessor)
    assert 'load_eligible_frame' not in vars(preprocessor)
    source = Path(preprocessor.__file__).read_text(encoding='utf-8')
    assert 'ml.cleaning' not in source


# --- train/test leakage ------------------------------------------------------

def test_scaler_is_fit_on_training_rows_only(real_scaler):
    features = pd.DataFrame({column: [float(row * 3 + index + 1) for row in range(12)]
                             for index, column in enumerate(NETWORK_FEATURES)})
    train_idx = np.array([0, 1, 2, 3, 4, 5])
    test_idx = np.array([6, 7, 8, 9, 10, 11])
    pre = ForensicPreprocessor()
    scaled_train, scaled_test = evaluation.scale_train_and_test(pre, features, train_idx, test_idx)

    expected_mean = features.iloc[train_idx].mean().to_numpy()
    assert np.allclose(pre.scaler.mean_, expected_mean)
    assert not np.allclose(pre.scaler.mean_, features.mean().to_numpy())  # no test leakage
    expected_test = ((features.iloc[test_idx] - expected_mean)
                     / features.iloc[train_idx].std(ddof=0).to_numpy())
    assert np.allclose(scaled_test.to_numpy(), expected_test.to_numpy())
    assert len(scaled_train) == len(train_idx)
    assert len(scaled_test) == len(test_idx)


def test_evaluation_script_splits_before_scaling():
    import inspect
    source = inspect.getsource(evaluation.main)
    assert source.index('train_test_split(') < source.index('scale_train_and_test(')
    assert 'df_scaled' not in source


# --- command line ------------------------------------------------------------

def test_cli_prints_the_cleaning_record(workspace, capsys):
    report = clean_script.main([
        '--data', str(workspace['source']),
        '--manifest', str(workspace['manifest']),
        '--ledger', str(workspace['ledger']),
        '--record', str(workspace['record']),
        '--chunk-rows', '4',
    ])
    payload = json.loads(capsys.readouterr().out)
    assert payload['policy']['id'] == 'cicids2017-offline-cleaning'
    assert payload['exclusions']['unique_rows'] == 6
    assert report['record_status'] == 'written'


def test_cli_reports_the_refusal_code(workspace, capsys):
    workspace['manifest'].unlink()
    with pytest.raises(SystemExit) as exc:
        clean_script.main([
            '--data', str(workspace['source']),
            '--manifest', str(workspace['manifest']),
            '--ledger', str(workspace['ledger']),
            '--record', str(workspace['record']),
        ])
    assert exc.value.code == 1
    assert '[PROVENANCE_MISSING]' in capsys.readouterr().err


# --- Step 5: hardened validation & cleaning tests ----------------------------

# A. Edge cases for real CICIDS2017 CSV ----------------------------------------

def test_bom_header_is_handled(tmp_path):
    """UTF-8 BOM (\\xef\\xbb\\xbf) at byte 0 must not corrupt the first column name."""
    header = ','.join(list(NETWORK_FEATURES) + ['Attack Type', 'Label', 'Flow ID'])
    row = make_row(42, 'Normal Traffic', 'BENIGN', 'bom-row')
    values = ','.join(row[col] for col in list(NETWORK_FEATURES) + ['Attack Type', 'Label', 'Flow ID'])
    raw = ('\ufeff' + header + '\n' + values + '\n').encode('utf-8')
    path = tmp_path / 'bom.csv'
    path.write_bytes(raw)
    analysis = cleaning.analyze_source(path, chunk_rows=5)
    assert analysis['input_rows'] == 1
    assert 'Flow Duration' in analysis['columns']
    assert len(analysis['negative_rows']) == 0


def test_whitespace_padded_headers_are_stripped(tmp_path):
    """Leading/trailing whitespace in column headers must be stripped transparently."""
    header = '  Flow Duration ,Total Fwd Packets , Total Length of Fwd Packets'
    for feature in NETWORK_FEATURES[3:]:
        header += f', {feature} '
    header += ', Attack Type , Label , Flow ID'
    row = make_row(10, 'Normal Traffic', 'BENIGN', 'ws-row')
    values = ','.join(row[col] for col in list(NETWORK_FEATURES) + ['Attack Type', 'Label', 'Flow ID'])
    path = tmp_path / 'whitespace_headers.csv'
    path.write_text(header + '\n' + values + '\n', encoding='utf-8')
    analysis = cleaning.analyze_source(path, chunk_rows=5)
    assert analysis['input_rows'] == 1
    for feature in NETWORK_FEATURES:
        assert feature in analysis['columns']


def test_non_finite_values_are_not_flagged_as_negative(workspace):
    """NaN, +inf, -inf feature values are non-finite and must NOT appear as negative_measurements."""
    rows = [make_row(i * 10, 'Normal Traffic', 'BENIGN', f'flow-{i}') for i in range(4)]
    # Row with NaN in Flow Duration
    rows[1]['Flow Duration'] = 'NaN'
    # Row with +inf
    rows[2]['Flow Bytes/s'] = 'inf'
    # Row with -inf (negative infinity is infinite, not a finite negative)
    rows[3]['Flow Packets/s'] = '-inf'
    path = workspace['source']
    pd.DataFrame(rows).to_csv(path, index=False)
    write_test_manifest(workspace['manifest'], path)
    report = run_clean(workspace)
    # None of these should be flagged as negative_measurements
    assert report['issues']['negative_measurements']['rows'] == 0
    assert report['issues']['negative_measurements']['cells'] == 0


# B. Chunked processing across chunk boundaries --------------------------------

def test_duplicate_pair_straddling_chunk_boundary(tmp_path):
    """Two identical rows in different chunks must still be detected as duplicates."""
    rows = [
        make_row(100, 'Normal Traffic', 'BENIGN', 'unique-1'),
        make_row(200, 'DDoS', 'DDoS', 'dup-cross'),       # first occurrence
        make_row(300, 'Normal Traffic', 'BENIGN', 'unique-2'),
        make_row(200, 'DDoS', 'DDoS', 'dup-cross'),       # exact duplicate
        make_row(400, 'Normal Traffic', 'BENIGN', 'unique-3'),
    ]
    path = tmp_path / 'cross_boundary.csv'
    pd.DataFrame(rows).to_csv(path, index=False)
    manifest_path = tmp_path / 'manifest.json'
    write_test_manifest(manifest_path, path)
    ledger_path = tmp_path / 'ledger.csv'
    record_path = tmp_path / 'record.json'

    # chunk_rows=2 forces row 1 and row 3 into different chunks
    report = clean_dataset(source=path, manifest_path=manifest_path,
                           ledger_path=ledger_path, record_path=record_path, chunk_rows=2)
    assert report['issues']['duplicate_rows']['rows'] == 1
    entries = ledger_entries(ledger_path)
    assert entries['3'] == 'duplicate_row'
    assert '1' not in entries  # first occurrence kept

    # Verify the same result with chunk_rows=1 (every row is its own chunk)
    ledger_1 = tmp_path / 'ledger_1.csv'
    record_1 = tmp_path / 'record_1.json'
    report_1 = clean_dataset(source=path, manifest_path=manifest_path,
                             ledger_path=ledger_1, record_path=record_1, chunk_rows=1)
    assert report_1['issues']['duplicate_rows']['rows'] == 1
    assert report_1['ledger']['sha256'] == report['ledger']['sha256']


def test_conflict_pair_straddling_chunk_boundary(tmp_path):
    """Two rows with the same feature vector but conflicting labels in different chunks."""
    rows = [
        make_row(100, 'Normal Traffic', 'BENIGN', 'unique-1'),
        make_row(500, 'Normal Traffic', 'BENIGN', 'conflict-a'),  # first label
        make_row(200, 'Normal Traffic', 'BENIGN', 'unique-2'),
        make_row(500, 'DDoS', 'DDoS', 'conflict-b'),              # conflicting label
        make_row(300, 'Normal Traffic', 'BENIGN', 'unique-3'),
    ]
    path = tmp_path / 'cross_conflict.csv'
    pd.DataFrame(rows).to_csv(path, index=False)
    manifest_path = tmp_path / 'manifest.json'
    write_test_manifest(manifest_path, path)
    ledger_path = tmp_path / 'ledger.csv'
    record_path = tmp_path / 'record.json'

    # chunk_rows=2 forces the pair into different chunks
    report = clean_dataset(source=path, manifest_path=manifest_path,
                           ledger_path=ledger_path, record_path=record_path, chunk_rows=2)
    assert report['issues']['label_conflicts']['vectors'] == 1
    assert report['issues']['label_conflicts']['rows'] == 2
    entries = ledger_entries(ledger_path)
    assert entries['1'] == 'label_conflict'
    assert entries['3'] == 'label_conflict'

    # Same result with chunk_rows=1
    ledger_1 = tmp_path / 'ledger_1.csv'
    record_1 = tmp_path / 'record_1.json'
    report_1 = clean_dataset(source=path, manifest_path=manifest_path,
                             ledger_path=ledger_1, record_path=record_1, chunk_rows=1)
    assert report_1['ledger']['sha256'] == report['ledger']['sha256']


# C. Overlapping exclusion reasons ---------------------------------------------

def test_three_way_overlapping_reasons(tmp_path):
    """A row that is negative, a duplicate, AND part of a conflicting vector."""
    # All three rows share the same 11-feature vector (with Flow Duration = -7).
    # Rows 1 and 3 are exact full-row duplicates (same labels, same Flow ID).
    # Row 2 has a different label, creating a label conflict for the entire vector.
    rows = [
        make_row(100, 'Normal Traffic', 'BENIGN', 'clean-1'),
        make_row(500, 'Normal Traffic', 'BENIGN', 'triple-a',
                 **{'Flow Duration': '-7'}),                     # negative + conflict
        make_row(500, 'DDoS', 'DDoS', 'triple-b',
                 **{'Flow Duration': '-7'}),                     # negative + conflict
        make_row(500, 'Normal Traffic', 'BENIGN', 'triple-a',
                 **{'Flow Duration': '-7'}),                     # duplicate of row 1 + negative + conflict
    ]
    path = tmp_path / 'triple.csv'
    pd.DataFrame(rows).to_csv(path, index=False)
    manifest_path = tmp_path / 'manifest.json'
    write_test_manifest(manifest_path, path)
    ledger_path = tmp_path / 'ledger.csv'
    record_path = tmp_path / 'record.json'

    report = clean_dataset(source=path, manifest_path=manifest_path,
                           ledger_path=ledger_path, record_path=record_path)
    entries = ledger_entries(ledger_path)
    # Row 3 (index 3) should have all three reasons
    assert entries['3'] == 'negative_measurements|duplicate_row|label_conflict'
    # Row 1 (index 1) should have negative + conflict
    assert entries['1'] == 'negative_measurements|label_conflict'
    # Row 2 (index 2) should have negative + conflict
    assert entries['2'] == 'negative_measurements|label_conflict'

    assert report['exclusions']['unique_rows'] == 3
    assert report['exclusions']['retained_rows'] == 1
    assert report['exclusions']['overlaps']['rows_with_multiple_reasons'] == 3
    assert report['exclusions']['input_rows'] == 4
    cleaning.assert_counts(4, 1, 3)


def test_all_rows_excluded_still_satisfies_invariant(tmp_path):
    """When every row has an exclusion reason, retained_rows == 0 and the invariant holds."""
    rows = [
        make_row(100, 'Normal Traffic', 'BENIGN', 'all-neg-1', **{'Flow Duration': '-1'}),
        make_row(200, 'DDoS', 'DDoS', 'all-neg-2', **{'Flow Bytes/s': '-2'}),
    ]
    path = tmp_path / 'all_excluded.csv'
    pd.DataFrame(rows).to_csv(path, index=False)
    manifest_path = tmp_path / 'manifest.json'
    write_test_manifest(manifest_path, path)
    ledger_path = tmp_path / 'ledger.csv'
    record_path = tmp_path / 'record.json'

    report = clean_dataset(source=path, manifest_path=manifest_path,
                           ledger_path=ledger_path, record_path=record_path)
    assert report['exclusions']['retained_rows'] == 0
    assert report['exclusions']['unique_rows'] == 2
    assert report['exclusions']['input_rows'] == 2
    cleaning.assert_counts(2, 0, 2)

    # load_eligible_frame should refuse because no rows remain
    with pytest.raises(CleaningError) as exc:
        load_eligible_frame(path, record_path)
    assert exc.value.code == 'EMPTY_ELIGIBLE_VIEW'


# D. Deterministic ledgers and source-file immutability -------------------------

def test_ledger_bytes_are_identical_across_independent_runs(tmp_path):
    """Two completely independent clean_dataset invocations produce byte-identical ledgers."""
    rows = [make_row(i * 10, 'Normal Traffic', 'BENIGN', f'det-{i}') for i in range(5)]
    rows.append(make_row(100, 'DDoS', 'DDoS', 'det-neg', **{'Flow Duration': '-1'}))
    rows.append(make_row(200, 'Normal Traffic', 'BENIGN', 'det-dup'))
    rows.append(make_row(200, 'Normal Traffic', 'BENIGN', 'det-dup'))  # exact dup
    path = tmp_path / 'deterministic.csv'
    pd.DataFrame(rows).to_csv(path, index=False)
    manifest_path = tmp_path / 'manifest.json'
    write_test_manifest(manifest_path, path)

    payloads = []
    for run_id in range(3):
        ledger = tmp_path / f'ledger_{run_id}.csv'
        record = tmp_path / f'record_{run_id}.json'
        report = clean_dataset(source=path, manifest_path=manifest_path,
                               ledger_path=ledger, record_path=record)
        payloads.append(ledger.read_bytes())
        assert hashlib.sha256(payloads[-1]).hexdigest() == report['ledger']['sha256']
    # All three must be byte-identical
    assert payloads[0] == payloads[1] == payloads[2]
    # Verify LF line endings (no CR)
    assert b'\r' not in payloads[0]


def test_source_immutability_across_chunk_sizes(workspace):
    """Source CSV mtime and content must be unchanged regardless of chunk size."""
    payload_before = workspace['source'].read_bytes()
    mtime_before = workspace['source'].stat().st_mtime_ns
    for chunk_rows in (1, 3, 7, 1000):
        ledger = workspace['source'].parent / f'immut_ledger_{chunk_rows}.csv'
        record = workspace['source'].parent / f'immut_record_{chunk_rows}.json'
        clean_dataset(source=workspace['source'], manifest_path=workspace['manifest'],
                      ledger_path=ledger, record_path=record, chunk_rows=chunk_rows)
        assert workspace['source'].read_bytes() == payload_before
        assert workspace['source'].stat().st_mtime_ns == mtime_before


def test_no_csv_leaks_into_provenance_directory(workspace):
    """Cleaning must not create any CSV files in the provenance directory beyond the ledger."""
    provenance_dir = workspace['ledger'].parent
    csvs_before = set(provenance_dir.glob('*.csv'))
    run_clean(workspace)
    csvs_after = set(provenance_dir.glob('*.csv'))
    assert csvs_after - csvs_before == {workspace['ledger']}


# E. No preprocessing leakage --------------------------------------------------

def test_eligible_view_contains_no_negative_or_nonfinite_features(workspace):
    """The eligible view must have no negative, NaN, or infinite values in required features."""
    run_clean(workspace)
    view = load_eligible_frame(workspace['source'], workspace['record'])
    for feature in NETWORK_FEATURES:
        values = pd.to_numeric(view[feature], errors='coerce').to_numpy(dtype=float)
        finite = np.isfinite(values)
        assert finite.all(), f'{feature} has non-finite values in the eligible view'
        assert (values[finite] >= 0).all(), f'{feature} has negatives in the eligible view'


def test_cleaning_module_never_imports_scaler_or_model():
    """ml/cleaning.py must not import model or scaler fitting machinery."""
    source = Path(cleaning.__file__).read_text(encoding='utf-8')
    # These imports would indicate leakage of fitting into the cleaning path
    for forbidden_import in ('IsolationForest', 'StandardScaler', 'joblib',
                             'sklearn.ensemble', 'sklearn.preprocessing'):
        assert forbidden_import not in source, \
            f'cleaning.py imports {forbidden_import}, which risks preprocessing leakage'


def test_eligible_view_row_count_matches_record(workspace):
    """load_eligible_frame must agree with the cleaning record on retained rows."""
    report = run_clean(workspace)
    record = json.loads(workspace['record'].read_text(encoding='utf-8'))
    view = load_eligible_frame(workspace['source'], workspace['record'])
    assert len(view) == record['exclusions']['retained_rows']
    assert len(view) == report['exclusions']['retained_rows']
    assert len(view) + record['exclusions']['unique_rows'] == record['exclusions']['input_rows']
