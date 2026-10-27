"""Fixed feature-group holdouts; no fitted statistics or label-dependent tuning."""
import hashlib

import numpy as np
import pandas as pd

from ml.preprocessor import NETWORK_FEATURES

SPLIT_POLICY = {'method': 'numeric-feature-group-hash-v1', 'seed': 42,
                'train_percent': 70, 'validation_percent': 15, 'test_percent': 15}


def split_masks(frame):
    # Numerically identical vectors stay together even if their source text differs.
    features = frame.loc[:, list(NETWORK_FEATURES)].astype('float64').copy()
    features[features == 0] = 0.0  # canonicalize signed zero
    hashes = pd.util.hash_pandas_object(features, index=False).to_numpy(dtype='uint64')
    buckets = (hashes ^ np.uint64(42)) % np.uint64(100)
    return {'train': buckets < 70, 'validation': (buckets >= 70) & (buckets < 85),
            'test': buckets >= 85}


def split_metadata(frame, masks):
    return {**SPLIT_POLICY, 'partitions': {
        name: {'rows': int(mask.sum()), 'source_indices_sha256': hashlib.sha256(
            np.asarray(frame.index[mask], dtype='<i8').tobytes()).hexdigest()}
        for name, mask in masks.items()}}
