"""Trusted CICIDS2017 bundle loading and transform-only network inference.

Joblib is executable serialization: load only the operator-owned path below,
never an uploaded artifact. Legacy bare estimators are deliberately rejected.
"""
from pathlib import Path
import re
import io
import hashlib

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.utils.validation import check_is_fitted

from ml.cleaning import CLEANING_POLICY_ID, CLEANING_POLICY_VERSION
from ml.dataset_source import DATASET_HANDLE, DATASET_PAGE_URL
from ml.drift import monitor_drift
from ml.preprocessor import (NETWORK_FEATURES, NetworkInputError,
                             prepare_network_frame, read_network_csv)

ROOT_DIR = Path(__file__).resolve().parents[1]
APPROVED_DATASET_PATH = ROOT_DIR / 'data' / 'cicids2017_cleaned.csv'
BASELINE_PATH = ROOT_DIR / 'models' / 'cicids2017_baseline.joblib'
# Single source of truth for the reviewed dataset identity: ml/dataset_source.py.
DATASET_ID = DATASET_HANDLE
SOURCE_URL = DATASET_PAGE_URL
BUNDLE_VERSION = 1


class BaselineError(RuntimeError):
    def __init__(self, message, code='MODEL_INVALID'):
        super().__init__(message)
        self.code = code


def validate_bundle(bundle):
    """Fail closed on incomplete, unfitted, incompatible or mismatched artifacts."""
    def require(condition):
        # Runtime validation must also work under python -O.
        if not condition:
            raise ValueError('Invalid baseline component')

    try:
        require(isinstance(bundle, dict) and bundle['bundle_version'] == BUNDLE_VERSION)
        schema = bundle['feature_schema']
        require(schema['version'] == 1 and schema['artifact_type'] == 'network')
        require(schema['columns'] == list(NETWORK_FEATURES))
        require(schema['dtype'] == 'float64')
        require(schema['flow_duration_unit'] == 'microseconds')
        require(bundle['versions']['scikit_learn'] == sklearn.__version__)
        model, scaler = bundle['model'], bundle['scaler']
        require(isinstance(model, IsolationForest) and isinstance(scaler, StandardScaler))
        check_is_fitted(model)
        check_is_fitted(scaler)
        for fitted in (model, scaler):
            require(fitted.n_features_in_ == len(NETWORK_FEATURES))
            require(list(fitted.feature_names_in_) == list(NETWORK_FEATURES))
        require(np.isfinite(scaler.mean_).all() and np.isfinite(scaler.scale_).all())
        require((scaler.scale_ > 0).all())
        provenance = bundle['provenance']
        require(provenance['dataset_id'] == DATASET_ID)
        require(provenance['source_url'] == SOURCE_URL)
        normalized_dataset_path = str(provenance.get('dataset_path', '')).replace('\\', '/')
        require(normalized_dataset_path in ('data/cicids2017_cleaned.csv', 'data/sample/cicids2017_cleaned.csv')
                or normalized_dataset_path.startswith('data/'))
        if 'training_source_path' in provenance:
            require(isinstance(provenance['training_source_path'], str) and provenance['training_source_path'].strip())
        require(re.fullmatch(r'[0-9a-f]{64}', provenance['sha256']))
        require(str(provenance['dataset_version']).strip())
        require(provenance['training_policy'] == 'benign_only')
        require(provenance['training_rows'] >= 2)
        require(provenance['trained_at'])
        if 'cleaning' in provenance:
            cleaning_meta = provenance['cleaning']
            require(isinstance(cleaning_meta, dict))
            require(cleaning_meta.get('policy_id') == CLEANING_POLICY_ID)
            require(cleaning_meta.get('policy_version') == CLEANING_POLICY_VERSION)
            require(re.fullmatch(r'[0-9a-f]{64}', str(cleaning_meta.get('ledger_sha256') or '')))
            if 'record_fingerprint' in cleaning_meta:
                require(re.fullmatch(r'cleanfp-v[0-9]+-[0-9a-f]{64}', str(cleaning_meta['record_fingerprint'])))
            if 'record_sha256' in cleaning_meta:
                require(re.fullmatch(r'[0-9a-f]{64}', str(cleaning_meta['record_sha256'])))
        reference = bundle['drift_reference']
        require(reference['method'] == 'psi' and reference['min_samples'] >= 1)
        require(reference['reference_rows'] == provenance['training_rows'])
        require(np.isfinite(reference['threshold']) and reference['threshold'] > 0)
        require(set(reference['features']) == set(NETWORK_FEATURES))
        for frozen in reference['features'].values():
            cuts, proportions = np.asarray(frozen['cut_points']), np.asarray(frozen['proportions'])
            require(np.isfinite(cuts).all() and (np.diff(cuts) > 0).all())
            require(len(proportions) == len(cuts) + 1)
            require(np.isfinite(proportions).all() and (proportions > 0).all())
            require(np.isclose(proportions.sum(), 1))
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise BaselineError('Baseline bundle is incomplete, incompatible, or invalid. '
                            'Train it with scripts/train_baseline.py using the approved dataset.') from exc
    return bundle


def load_baseline(path=BASELINE_PATH):
    path = Path(path)
    if not path.is_file():
        raise BaselineError('Approved CICIDS2017 baseline is missing. Run scripts/train_baseline.py; '
                            'uploaded evidence cannot train a model.', 'MODEL_MISSING')
    try:
        payload = path.read_bytes()
        bundle = joblib.load(io.BytesIO(payload))
    except Exception as exc:
        raise BaselineError('Could not load the approved baseline bundle.') from exc
    bundle = validate_bundle(bundle)
    bundle['_artifact_sha256'] = hashlib.sha256(payload).hexdigest()
    return bundle


def infer_network(frame, bundle):
    clean, features, preprocessing = prepare_network_frame(frame, bundle['feature_schema']['columns'])
    # Preserve names, order, and original row index for aligned labels/records.
    scaled = pd.DataFrame(bundle['scaler'].transform(features),
                          columns=features.columns, index=features.index)
    if not np.isfinite(scaled.to_numpy()).all():
        raise NetworkInputError('Network values overflowed the fitted scaler; verify feature units.')
    predictions = bundle['model'].predict(scaled)
    scores = bundle['model'].decision_function(scaled)
    drift = monitor_drift(features, bundle['drift_reference'])
    return clean, predictions, scores, preprocessing, drift


def infer_network_csv(path, bundle):
    return infer_network(read_network_csv(path), bundle)


def baseline_metadata(bundle):
    return {'bundle_version': bundle['bundle_version'],
            'feature_schema': bundle['feature_schema'], 'provenance': bundle['provenance']}
