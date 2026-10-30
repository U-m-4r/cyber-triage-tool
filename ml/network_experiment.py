"""Research-only network contracts, leakage controls and validation selection.

No import from production inference; candidate weights never replace incumbents.
Identity preprocessing is explicit. No functions here tune on final-test labels.
"""
import hashlib
import json
import os
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.metrics import roc_curve
from evaluation.external_metrics import binary_metrics
from ml.preprocessor import NETWORK_FEATURES, NetworkInputError

RESULTS_DIR = Path(os.getenv('ISSUE6_RESULTS_DIR', 'test-results/issue-6'))
WORK_DIR = Path(os.getenv('ISSUE6_WORK_DIR', '.test-artifacts/issue6'))


def repo_path(value):
    """Read repository-relative manifest paths captured on either operating system."""
    return Path(str(value).replace('\\','/'))

SCHEMA = {'version':'network-generalization-11-v1', 'columns':list(NETWORK_FEATURES),
          'preprocessing':'identity-float32-no-fit', 'duration_unit':'microseconds',
          'counts_unit':'packets', 'lengths_unit':'bytes', 'rates_unit':'per-second',
          'calibrated':False}


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as source:
        for data in iter(lambda:source.read(1048576), b''):
            digest.update(data)
    return digest.hexdigest()


def write_once(path, data):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as output:
        json.dump(data, output, indent=2, allow_nan=False)


def validate_features(frame):
    missing = set(NETWORK_FEATURES)-set(frame.columns)
    if missing:
        raise NetworkInputError('Candidate requires exact measured features: '+str(sorted(missing)))
    values = frame.loc[:,list(NETWORK_FEATURES)].to_numpy(dtype=np.float64)
    if not np.isfinite(values).all() or (values<0).any() or (values>np.finfo(np.float32).max).any():
        raise NetworkInputError('Candidate input must be finite, nonnegative and float32 representable')
    return values.astype(np.float32)


def fingerprints(values, near=False):
    values = np.asarray(values, dtype=np.float32).copy()
    if near:
        values = np.round(np.log1p(values.astype(np.float64)), 3)
    values[values == 0] = 0
    return pd.util.hash_pandas_object(pd.DataFrame(values), index=False).to_numpy(dtype=np.uint64)


def overlaps(values, reference):
    if not len(reference):
        return np.zeros(len(values), dtype=bool)
    locations = np.searchsorted(reference, values)
    return (locations<len(reference)) & (reference[np.minimum(locations,len(reference)-1)]==values)


def development_blocks(timestamps):
    parsed = pd.to_datetime(timestamps, format='%d/%m/%Y %H:%M:%S', errors='coerce')
    valid = parsed.notna().to_numpy()
    minute = parsed.dt.minute.fillna(-1).to_numpy()
    block = minute//10
    training = valid & (block%2==0) & (minute%10>=1) & (minute%10<=8)
    validation = valid & (block%2==1)
    return training, validation, ~(training|validation)


def operating_point(y, scores, max_fpr=.05):
    y = np.asarray(y); scores = np.asarray(scores, dtype=float)
    if set(np.unique(y)) != {0,1} or not np.isfinite(scores).all() or len(y)!=len(scores):
        raise ValueError('Both genuine classes and finite aligned validation scores required')
    fpr, tpr, thresholds = roc_curve(y, scores, drop_intermediate=False)
    allowed = np.flatnonzero(fpr<=max_fpr)
    # Positive predictions include complete tied-score groups, including reject-all.
    prevalence = float(y.mean())
    precision = np.divide(tpr*prevalence, tpr*prevalence+fpr*(1-prevalence),
                          out=np.zeros_like(tpr), where=(tpr*prevalence+fpr*(1-prevalence))!=0)
    best = max(allowed, key=lambda i:(tpr[i], precision[i], thresholds[i]))
    threshold = float(thresholds[best])
    if not np.isfinite(threshold):
        threshold = float(np.nextafter(scores.max(), np.inf))
    return {'threshold':threshold, 'constraint':max_fpr,
            'metrics':binary_metrics(y, (scores>=threshold).astype(int), scores),
            'selection_population':'validation only; maximize recall then precision then threshold'}


def review_budgets(y, scores, budgets=(.001,.01,.05,.10,.20)):
    y = np.asarray(y); scores = np.asarray(scores)
    ordered = np.sort(scores)[::-1]
    result = []
    for budget in budgets:
        k = max(1,int(np.floor(len(y)*budget)))
        boundary = ordered[k-1]
        certain = scores>boundary; tied = scores==boundary
        slots = k-int(certain.sum())
        positives = int(y[certain].sum()); tied_positive = int(y[tied].sum()); tied_negative = int(tied.sum())-tied_positive
        result.append({'fraction':budget, 'k':k, 'boundary_score':float(boundary),
            'tie_group_size':int(tied.sum()), 'certain_true_positives':positives,
            'recall_lower_bound':(positives+max(0,slots-tied_negative))/int(y.sum()) if y.sum() else None,
            'recall_upper_bound':(positives+min(slots,tied_positive))/int(y.sum()) if y.sum() else None})
    return result


def family_metrics(labels, y, predictions):
    labels = np.asarray(labels); y = np.asarray(y); predictions = np.asarray(predictions)
    output = {}
    for label in sorted(set(labels)):
        mask = labels==label; positive = bool(y[mask][0])
        tp = int(predictions[mask].sum())
        output[str(label)] = {'samples':int(mask.sum()), 'binary_label':int(positive),
            'true_positive':tp if positive else None, 'false_negative':int(mask.sum())-tp if positive else None,
            'recall':float(predictions[mask].mean()) if positive else None,
            'false_positive':tp if not positive else None,
            'false_positive_rate':float(predictions[mask].mean()) if not positive else None,
            'small_sample':bool(mask.sum()<30)}
    return output


def measured_result(y, score, threshold, labels):
    pred = (np.asarray(score)>=threshold).astype(np.int8)
    return {'threshold':threshold, 'overall':binary_metrics(y,pred,score),
            'per_family':family_metrics(labels,y,pred), 'top_k':review_budgets(y,score)}


def deployment_gates(challenger, incumbent, per_day, throughput, loading_seconds):
    metric = challenger['overall']; original = incumbent['overall']
    return {'recall_gain_at_least_10pp':metric['recall']-original['recall']>=.10,
        'overall_fpr_at_most_5pct':metric['false_positive_rate']<=.05,
        'every_day_fpr_at_most_5pct':all(r['overall']['false_positive_rate']<=.05 for r in per_day.values()),
        'precision_at_least_20pct':metric['precision']>=.20,
        'balanced_accuracy_at_least_60pct':metric['balanced_accuracy']>=.60,
        'supported_family_recall_at_least_10pct':all(r['recall']>=.10 for r in challenger['per_family'].values()
            if r['binary_label'] and r['samples']>=30),
        'inference_at_least_1000_flows_per_second':throughput>=1000,
        'loading_under_5seconds':loading_seconds<5}


def load_candidate(directory, expected_sha):
    directory = Path(directory); metadata = json.loads((directory/'metadata.json').read_text())
    model = directory/metadata['filename']
    if model.resolve().parent != directory.resolve():
        raise ValueError('Candidate model path must stay within reviewed artifact directory')
    if metadata['feature_schema'] != SCHEMA or sha(model)!=expected_sha or metadata['sha256']!=expected_sha:
        raise ValueError('Candidate model integrity/schema mismatch')
    if metadata['estimator']=='lightgbm':
        import lightgbm
        if metadata['versions']['lightgbm'] != lightgbm.__version__:
            raise ValueError('Candidate LightGBM runtime version mismatch')
        booster = lightgbm.Booster(model_file=str(model))
        if booster.num_feature()!=len(SCHEMA['columns']) or booster.params.get('objective')!='binary':
            raise ValueError('Candidate LightGBM objective/dimension mismatch')
        def predict(frame):
            return booster.predict(validate_features(frame), num_threads=2)
    elif metadata['estimator']=='xgboost':
        import xgboost
        if metadata['versions']['xgboost'] != xgboost.__version__:
            raise ValueError('Candidate XGBoost runtime version mismatch')
        booster = xgboost.Booster(); booster.load_model(model)
        if booster.num_features()!=len(SCHEMA['columns']):
            raise ValueError('Candidate XGBoost feature dimension mismatch')
        def predict(frame):
            return booster.inplace_predict(validate_features(frame), iteration_range=(0,metadata['best_iteration']+1))
    else:
        raise ValueError('Unsupported candidate estimator')
    return predict, metadata
