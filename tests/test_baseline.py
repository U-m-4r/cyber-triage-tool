"""Phase 1 lifecycle tests. All training data here is synthetic and isolated."""
import copy
import io
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from ml.baseline import BaselineError, infer_network_csv, load_baseline, validate_bundle
from ml.drift import build_reference, monitor_drift
from ml.preprocessor import (NETWORK_FEATURES, NetworkInputError,
                             prepare_network_frame, read_network_csv)
from scripts import train_baseline as trainer


def test_training_saves_complete_benign_only_bundle(baseline_bundle, tiny_flow_csv):
    path, bundle = baseline_bundle
    raw = read_network_csv(tiny_flow_csv)
    expected = raw.loc[raw.Label == 'BENIGN', list(NETWORK_FEATURES)]
    np.testing.assert_allclose(bundle['scaler'].mean_, expected.mean())
    assert bundle['provenance']['training_rows'] == 3
    assert bundle['provenance']['excluded_non_benign_rows'] == 2
    assert bundle['provenance']['dataset_version'] == 'synthetic-test-fixture'
    assert bundle['drift_reference']['reference_rows'] == 3
    assert bundle['feature_schema']['columns'] == list(NETWORK_FEATURES)
    assert path.is_file()


def test_missing_dataset_never_uses_sample_or_upload(tmp_path, monkeypatch):
    monkeypatch.setattr(trainer, 'APPROVED_DATASET_PATH', tmp_path / 'missing.csv')
    output = tmp_path / 'baseline.joblib'
    with pytest.raises(ValueError, match='Approved dataset not found'):
        trainer.train_baseline(dataset_version='test', expected_sha256='0' * 64, output=output)
    assert not output.exists()


def test_bad_checksum_does_not_publish(tmp_path, monkeypatch, tiny_flow_csv):
    monkeypatch.setattr(trainer, 'APPROVED_DATASET_PATH', tiny_flow_csv)
    output = tmp_path / 'baseline.joblib'
    with pytest.raises(ValueError, match='SHA-256'):
        trainer.train_baseline(dataset_version='test', expected_sha256='0' * 64, output=output)
    assert not output.exists()


def test_training_refuses_accidental_replacement(baseline_bundle):
    path, _ = baseline_bundle
    before = path.read_bytes()
    with pytest.raises(ValueError, match='already exists'):
        trainer.train_baseline(dataset_version='test', expected_sha256='0' * 64, output=path)
    assert path.read_bytes() == before


def test_load_missing_model(tmp_path):
    with pytest.raises(BaselineError) as error:
        load_baseline(tmp_path / 'missing.joblib')
    assert error.value.code == 'MODEL_MISSING'


def test_legacy_and_corrupt_models_rejected(tmp_path):
    legacy = tmp_path / 'legacy.pkl'
    joblib.dump(IsolationForest(), legacy)
    with pytest.raises(BaselineError):
        load_baseline(legacy)
    legacy.write_bytes(b'corrupt artifact')
    with pytest.raises(BaselineError):
        load_baseline(legacy)


@pytest.mark.parametrize('problem', ['no_scaler', 'unfitted', 'schema', 'provenance', 'version', 'drift'])
def test_incomplete_bundle_rejected(baseline_bundle, problem):
    _, original = baseline_bundle
    bundle = copy.deepcopy(original)
    if problem == 'no_scaler':
        del bundle['scaler']
    elif problem == 'unfitted':
        bundle['scaler'] = StandardScaler()
    elif problem == 'schema':
        bundle['feature_schema']['columns'].reverse()
    elif problem == 'provenance':
        bundle['provenance']['dataset_id'] = 'uploaded-data'
    elif problem == 'version':
        bundle['versions']['scikit_learn'] = 'incompatible'
    else:
        bundle['drift_reference']['features']['Flow Duration']['proportions'] = [0]
    with pytest.raises(BaselineError):
        validate_bundle(bundle)


def test_inference_reuses_scaler_and_survives_reload(baseline_bundle, tiny_flow_csv, monkeypatch):
    path, bundle = baseline_bundle
    mean = bundle['scaler'].mean_.copy()
    before = path.read_bytes()

    def forbidden(*args, **kwargs):
        raise AssertionError('Inference attempted to fit')

    monkeypatch.setattr(StandardScaler, 'fit', forbidden)
    monkeypatch.setattr(IsolationForest, 'fit', forbidden)
    first = infer_network_csv(tiny_flow_csv, bundle)
    second = infer_network_csv(tiny_flow_csv, load_baseline(path))
    np.testing.assert_allclose(first[2], second[2])
    np.testing.assert_array_equal(bundle['scaler'].mean_, mean)
    assert path.read_bytes() == before


def test_preprocessing_order_metadata_and_invalid_rows(tiny_flow_csv):
    frame = read_network_csv(tiny_flow_csv)
    frame['Flow Duration'] = frame['Flow Duration'].astype(float)
    frame.loc[1, 'Flow Duration'] = np.inf
    frame['Flow Packets/s'] = frame['Flow Packets/s'].astype(object)
    frame.loc[2, 'Flow Packets/s'] = 'invalid'
    frame['metadata'] = np.nan
    frame = frame[frame.columns[::-1]]
    clean, features, report = prepare_network_frame(frame)
    assert list(features.columns) == list(NETWORK_FEATURES)
    assert list(clean.index) == [0, 3, 4]
    assert report['dropped_invalid_rows'] == 2
    assert clean['metadata'].isna().all()


def test_preprocessing_preserves_duplicates(tiny_flow_csv):
    frame = read_network_csv(tiny_flow_csv)
    clean, _, report = prepare_network_frame(pd.concat([frame, frame]))
    assert len(clean) == 10 and report['duplicates_preserved']


def test_missing_features_and_empty_data(tiny_flow_csv):
    frame = read_network_csv(tiny_flow_csv)
    with pytest.raises(NetworkInputError, match='Total Fwd Packets'):
        prepare_network_frame(frame.drop(columns=['Total Fwd Packets']))
    with pytest.raises(NetworkInputError, match='No valid network rows'):
        prepare_network_frame(frame.iloc[:0])


def test_duplicate_csv_headers_rejected(tmp_path):
    path = tmp_path / 'duplicates.csv'
    path.write_text('Flow Duration, Flow Duration\n1,2\n')
    with pytest.raises(NetworkInputError, match='unique'):
        read_network_csv(path)


def test_non_network_artifacts_rejected(tiny_flow_csv):
    frame = read_network_csv(tiny_flow_csv)
    frame['artifact_type'] = 'registry'
    with pytest.raises(NetworkInputError, match='only network'):
        prepare_network_frame(frame)


def test_drift_stable_shifted_and_read_only():
    features = pd.DataFrame({'rate': np.arange(1000, dtype=float), 'constant': np.zeros(1000)})
    reference = build_reference(features)
    original = copy.deepcopy(reference)
    stable = monitor_drift(features, reference)
    shifted = monitor_drift(features + 10000, reference)
    assert stable['status'] == 'stable'
    assert stable['features']['rate']['psi'] == pytest.approx(0)
    assert shifted['drift_detected'] is True
    assert shifted['features']['constant']['drift_detected'] is True
    assert shifted['retraining_triggered'] is False
    assert reference == original


def test_small_drift_batches_unassessed():
    features = pd.DataFrame({'rate': np.arange(200, dtype=float)})
    reference = build_reference(features)
    assert monitor_drift(features.iloc[:2], reference)['status'] == 'insufficient_data'
    assert monitor_drift(features, build_reference(features.iloc[:2]))['status'] == 'insufficient_reference'


def _upload(client, endpoint, content, **fields):
    return client.post(endpoint, data={'file': (io.BytesIO(content), 'flows.csv'), **fields},
                       content_type='multipart/form-data')


@pytest.mark.parametrize('endpoint', ['/api/analyze', '/api/evaluate', '/api/ingest'])
def test_api_missing_model_fails_without_training(baseline_api, tiny_flow_csv, monkeypatch, endpoint):
    from backend import app as app_module
    client, path, _ = baseline_api
    path.unlink()
    fields = {'kind': 'pcap'} if endpoint == '/api/ingest' else {}
    response = _upload(client, endpoint, Path(tiny_flow_csv).read_bytes(), **fields)
    assert response.status_code == 503
    assert response.get_json()['error']['code'] == 'MODEL_MISSING'
    assert not path.exists()
    assert not list(Path(app_module.app.config['TEMP_DIR']).glob('*_flows.csv'))


def test_analyze_evaluate_and_ingest_never_fit(baseline_api, tiny_flow_csv, monkeypatch):
    client, path, _ = baseline_api
    before = path.read_bytes()

    def forbidden(*args, **kwargs):
        raise AssertionError('Upload attempted to fit')

    monkeypatch.setattr(StandardScaler, 'fit', forbidden)
    monkeypatch.setattr(StandardScaler, 'fit_transform', forbidden)
    monkeypatch.setattr(IsolationForest, 'fit', forbidden)
    content = Path(tiny_flow_csv).read_bytes()
    analyzed = _upload(client, '/api/analyze', content)
    evaluated = _upload(client, '/api/evaluate', content)
    ingested = _upload(client, '/api/ingest', content, kind='pcap')
    for response in (analyzed, evaluated, ingested):
        assert response.status_code == 200, response.get_json()
        assert response.get_json()['drift']['retraining_triggered'] is False
        assert response.get_json()['baseline']['provenance']['training_rows'] == 3
    assert evaluated.get_json()['records'] == {'total': 5, 'train': 0, 'test': 5}
    assert path.read_bytes() == before
    assert sorted(a['anomaly_score'] for a in ingested.get_json()['artifacts']) == sorted(
        a['anomaly_score'] for a in analyzed.get_json()['artifacts'])


@pytest.mark.parametrize('endpoint', ['/api/analyze', '/api/evaluate', '/api/ingest'])
def test_api_missing_features_clear_error(baseline_api, endpoint):
    client, _, _ = baseline_api
    fields = {'kind': 'pcap'} if endpoint == '/api/ingest' else {}
    response = _upload(client, endpoint, b'Flow Duration\n100\n', **fields)
    assert response.status_code == 400
    assert response.get_json()['error']['code'] == 'MISSING_FEATURES'


def test_health_reports_missing_baseline(baseline_api):
    client, path, _ = baseline_api
    assert client.get('/api/health').get_json()['network_baseline']['status'] == 'ready'
    path.unlink()
    body = client.get('/api/health').get_json()
    assert body['status'] == 'ok'
    assert body['network_baseline']['code'] == 'MODEL_MISSING'


def test_host_ingestion_works_without_network_baseline(baseline_api):
    client, path, _ = baseline_api
    path.unlink()
    response = _upload(client, '/api/ingest', b'FileName,FilePath\nevil.exe,C:\\Temp\\evil.exe\n', kind='file')
    assert response.status_code == 200
    assert response.get_json()['artifacts'][0]['anomaly_score'] is None
    assert response.get_json()['artifacts'][0]['priority'] == 'CRITICAL'


def test_api_reports_drift_without_changing_bundle(baseline_api, tmp_path, monkeypatch):
    from backend import app as app_module
    client, _, _ = baseline_api
    frame = pd.DataFrame({column: np.arange(200, dtype=float) + i + 1
                          for i, column in enumerate(NETWORK_FEATURES)})
    frame['Attack Type'] = 'Normal Traffic'
    dataset = tmp_path / 'reviewed_test_dataset.csv'
    frame.to_csv(dataset, index=False)
    monkeypatch.setattr(trainer, 'APPROVED_DATASET_PATH', dataset)
    output = tmp_path / 'drift_test_bundle.joblib'
    trainer.train_baseline(dataset_version='synthetic', expected_sha256=trainer.file_sha256(dataset),
                           output=output)
    monkeypatch.setitem(app_module.app.config, 'MODEL_PATH', str(output))
    before = output.read_bytes()
    frame.loc[:, list(NETWORK_FEATURES)] *= 1000
    response = _upload(client, '/api/analyze', frame.to_csv(index=False).encode())
    assert response.status_code == 200, response.get_json()
    assert response.get_json()['drift']['status'] == 'drift_detected'
    assert response.get_json()['drift']['retraining_triggered'] is False
    assert output.read_bytes() == before


@pytest.mark.parametrize('failure', ['no_labels', 'no_benign', 'missing_feature'])
def test_training_rejects_unusable_baseline(tmp_path, monkeypatch, tiny_flow_csv, failure):
    frame = read_network_csv(tiny_flow_csv)
    if failure == 'no_labels':
        frame = frame.drop(columns='Label')
    elif failure == 'no_benign':
        frame['Label'] = 'DDoS'
    else:
        frame = frame.drop(columns='Total Fwd Packets')
    dataset = tmp_path / 'invalid_baseline.csv'
    frame.to_csv(dataset, index=False)
    monkeypatch.setattr(trainer, 'APPROVED_DATASET_PATH', dataset)
    output = tmp_path / 'invalid_bundle.joblib'
    with pytest.raises(ValueError):
        trainer.train_baseline(dataset_version='synthetic', expected_sha256=trainer.file_sha256(dataset),
                               output=output)
    assert not output.exists()


def test_changed_training_dataset_not_published(tmp_path, monkeypatch, tiny_flow_csv):
    monkeypatch.setattr(trainer, 'APPROVED_DATASET_PATH', tiny_flow_csv)
    checksum = trainer.file_sha256(tiny_flow_csv)
    hashes = iter([checksum, '0' * 64])
    monkeypatch.setattr(trainer, 'file_sha256', lambda _: next(hashes))
    output = tmp_path / 'changed_bundle.joblib'
    with pytest.raises(ValueError, match='Dataset changed during training'):
        trainer.train_baseline(dataset_version='synthetic', expected_sha256=checksum, output=output)
    assert not output.exists()
