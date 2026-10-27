"""Regression checks for partition leakage and frozen held-out evaluation."""
import numpy as np
import pandas as pd
import pytest

from ml.holdout import split_masks
from ml.preprocessor import NETWORK_FEATURES
from scripts import train_baseline as trainer
from scripts.evaluate_baseline import evaluate


def test_identical_features_never_cross_partitions():
    frame = pd.DataFrame({c: np.arange(300, dtype=float) + i for i, c in enumerate(NETWORK_FEATURES)})
    repeated = pd.concat([frame, frame], ignore_index=True)
    masks = split_masks(repeated)
    assert np.all(sum(masks.values()) == 1)
    for mask in masks.values():
        assert mask.any()
        np.testing.assert_array_equal(mask[:300], mask[300:])
    shuffled = repeated.sample(frac=1, random_state=1)
    for name, mask in split_masks(shuffled).items():
        np.testing.assert_array_equal(mask, masks[name][shuffled.index])


def test_holdout_fits_training_only_and_evaluation_refuses_tampering(tmp_path):
    from ml.dataset_source import register_local_dataset
    from ml.cleaning import clean_dataset
    frame = pd.DataFrame({c: np.arange(300, dtype=float) + i + 1 for i, c in enumerate(NETWORK_FEATURES)})
    frame['Label'] = ['BENIGN' if i % 3 else 'attack' for i in range(len(frame))]
    data, record, model = (tmp_path / name for name in ('flows.csv', 'cleaning.json', 'model.joblib'))
    frame.to_csv(data, index=False)
    manifest = tmp_path / 'manifest.json'
    register_local_dataset(local_path=data, manifest_path=manifest)
    clean_dataset(source=data, manifest_path=manifest, record_path=record, ledger_path=tmp_path / 'ledger.csv')
    bundle = trainer.train_baseline(data=data, cleaning_record=record, eligible=True, holdout=True,
        output=model, dataset_version='test', expected_sha256=trainer.file_sha256(data))
    expected = frame.loc[split_masks(frame)['train'] & (frame.Label == 'BENIGN'), list(NETWORK_FEATURES)]
    np.testing.assert_allclose(bundle['scaler'].mean_, expected.mean())
    assert bundle['provenance']['training_rows'] == len(expected)
    before = model.read_bytes()
    result = evaluate(data, model, record)
    assert set(result['partitions']) == {'validation', 'test'}
    assert model.read_bytes() == before
    record.write_text(record.read_text() + ' ')
    with pytest.raises(ValueError, match='record mismatch'):
        evaluate(data, model, record)
