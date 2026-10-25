"""Offline training from a reviewed dataset CSV; no upload entry point."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import sys
import tempfile
import warnings

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from ml.baseline import (APPROVED_DATASET_PATH, BASELINE_PATH, BUNDLE_VERSION,
                         DATASET_ID, SOURCE_URL, validate_bundle)
from ml.drift import build_reference
from ml.preprocessor import (NETWORK_FEATURES, NetworkInputError, prepare_network_frame,
                             read_network_csv, validate_network_frame)
from evaluation.evaluate import BENIGN_TOKENS


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def validate_dataset(data=None):
    """Inspect the source CSV only; no cleaning, fitting, or artifact publication."""
    dataset_path = Path(APPROVED_DATASET_PATH if data is None else data)
    try:
        if not dataset_path.is_file():
            raise NetworkInputError(f'Dataset file not found: {dataset_path}', 'DATASET_MISSING')
        # Preserve blank and explicit NaN tokens for separate issue counts.
        with warnings.catch_warnings():
            # Refuse rows that pandas would truncate or interpret as an implicit index.
            warnings.simplefilter('error', pd.errors.ParserWarning)
            raw = read_network_csv(dataset_path, keep_default_na=False,
                                   skip_blank_lines=False, index_col=False)
    except pd.errors.ParserWarning as exc:
        raise NetworkInputError(f'Cannot read dataset CSV {dataset_path}: {exc}',
                                'DATASET_UNREADABLE') from exc
    except OSError as exc:
        raise NetworkInputError(f'Cannot read dataset CSV {dataset_path}: {exc}',
                                'DATASET_UNREADABLE') from exc
    report = validate_network_frame(raw)
    report['dataset_path'] = str(dataset_path.resolve())
    return report


def train_baseline(*, dataset_version, expected_sha256, output=BASELINE_PATH,
                   contamination=0.1, overwrite=False, data=None):
    """Explicit operator action; checksum must come from the reviewed download.

    The input defaults to the approved dataset path and can be supplied via --data.
    """
    dataset_path = Path(APPROVED_DATASET_PATH if data is None else data)
    output = Path(output)
    if not dataset_path.is_file():
        raise ValueError(f'Approved dataset not found: {dataset_path}. Download {SOURCE_URL}. '
                         'Sample files and uploaded evidence will not be substituted.')
    if output.exists() and not overwrite:
        raise ValueError(f'Bundle already exists: {output}. Use --overwrite only after manual review.')
    if not str(dataset_version).strip():
        raise ValueError('A Kaggle dataset version is required for provenance.')
    checksum = file_sha256(dataset_path)
    if checksum != expected_sha256.lower():
        raise ValueError('Approved dataset SHA-256 does not match --expected-sha256.')
    columns = set(NETWORK_FEATURES) | {'Attack Type', 'Label'}
    raw = read_network_csv(dataset_path, usecols=lambda c: c.strip() in columns)
    clean, _, preprocessing = prepare_network_frame(raw)
    label_column = next((c for c in ('Attack Type', 'Label') if c in clean), None)
    if label_column is None:
        raise ValueError('Approved dataset requires Attack Type or Label for benign-only training.')
    labels = clean[label_column].fillna('').astype(str).str.strip().str.lower()
    benign = clean.loc[labels.isin(BENIGN_TOKENS), list(NETWORK_FEATURES)]
    training = benign.drop_duplicates()
    if len(training) < 2:
        raise ValueError('At least two distinct valid benign rows are required.')
    scaler = StandardScaler()
    scaled = pd.DataFrame(scaler.fit_transform(training), columns=NETWORK_FEATURES,
                          index=training.index)
    model = IsolationForest(n_estimators=100, contamination=contamination,
                            random_state=42, n_jobs=-1)
    model.fit(scaled)
    if file_sha256(dataset_path) != checksum:
        raise ValueError('Dataset changed during training; no bundle was published.')
    bundle = {
        'bundle_version': BUNDLE_VERSION, 'model': model, 'scaler': scaler,
        'feature_schema': {'version': 1, 'artifact_type': 'network',
                           'columns': list(NETWORK_FEATURES), 'dtype': 'float64',
                           'flow_duration_unit': 'microseconds'},
        'versions': {'python': platform.python_version(), 'scikit_learn': sklearn.__version__,
                     'numpy': np.__version__, 'pandas': pd.__version__, 'joblib': joblib.__version__},
        'provenance': {
            'dataset_id': DATASET_ID, 'source_url': SOURCE_URL,
            'dataset_path': 'data/cicids2017_cleaned.csv', 'dataset_version': str(dataset_version),
            'sha256': checksum, 'size_bytes': dataset_path.stat().st_size,
            'trained_at': datetime.now(timezone.utc).isoformat(),
            'training_policy': 'benign_only', 'label_column': label_column,
            'input_rows': len(raw), 'valid_rows': len(clean),
            'dropped_invalid_rows': preprocessing['dropped_invalid_rows'],
            'excluded_non_benign_rows': int((~labels.isin(BENIGN_TOKENS)).sum()),
            'dropped_benign_duplicates': len(benign) - len(training),
            'training_rows': len(training), 'model_parameters': model.get_params(),
        },
        'drift_reference': build_reference(training),
    }
    validate_bundle(bundle)
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=output.name + '.', suffix='.tmp', dir=output.parent)
    os.close(fd)
    try:
        joblib.dump(bundle, temporary)
        if overwrite:
            os.replace(temporary, output)
        elif os.name == 'nt':
            # Windows rename is atomic and refuses an existing destination.
            os.rename(temporary, output)
        else:
            # Atomic exclusive publication: another operator cannot be overwritten
            # if they publish while this training run is in progress.
            os.link(temporary, output)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return bundle


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', type=Path, default=APPROVED_DATASET_PATH,
                        help='Dataset CSV path (defaults to the existing approved dataset path)')
    parser.add_argument('--validate-only', action='store_true',
                        help='Report CSV data quality without cleaning, fitting, or saving a model')
    parser.add_argument('--dataset-version', help='Version of the reviewed Kaggle download (required for training)')
    parser.add_argument('--expected-sha256', help='SHA-256 of the reviewed dataset bytes (required for training)')
    parser.add_argument('--contamination', type=float, default=0.1)
    parser.add_argument('--overwrite', action='store_true', help='Explicitly replace a reviewed baseline')
    args = parser.parse_args()
    options = vars(args)
    if options.pop('validate_only'):
        try:
            report = validate_dataset(args.data)
        except (ValueError, OSError) as exc:
            parser.exit(1, f'Validation failed: {exc}\n')
        print(json.dumps(report, indent=2))
        if report['status'] != 'valid':
            parser.exit(2)
        return
    required = [name for name in ('dataset_version', 'expected_sha256')
                if options[name] is None]
    if required:
        parser.error('the following arguments are required for training: ' +
                     ', '.join('--' + name.replace('_', '-') for name in required))
    try:
        bundle = train_baseline(**options)
    except (ValueError, OSError) as exc:
        parser.exit(1, f'Training failed: {exc}\n')
    print(json.dumps({'bundle': str(BASELINE_PATH), 'provenance': bundle['provenance']}, indent=2))


if __name__ == '__main__':
    main()
