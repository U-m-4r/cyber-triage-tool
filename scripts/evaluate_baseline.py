"""Evaluate the frozen approved bundle on its reserved partitions without fitting."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import numpy as np
from ml.baseline import APPROVED_DATASET_PATH, BASELINE_PATH, load_baseline, infer_network
from ml.cleaning import DEFAULT_RECORD_PATH, load_eligible_frame
from ml.holdout import split_masks, split_metadata
from ml.preprocessor import NETWORK_FEATURES, prepare_network_frame
from evaluation.evaluate import extract_binary_ground_truth, evaluate_predictions
from scripts.train_baseline import file_sha256


def evaluate(data=APPROVED_DATASET_PATH, model=BASELINE_PATH, record=DEFAULT_RECORD_PATH):
    bundle = load_baseline(model)
    provenance = bundle['provenance']
    if not provenance.get('split') or not provenance.get('cleaning'):
        raise ValueError('This model has no verified eligible holdout; evaluation refused.')
    if file_sha256(data) != provenance['sha256']:
        raise ValueError('Evaluation source checksum mismatch.')
    if file_sha256(record) != provenance['cleaning']['record_sha256']:
        raise ValueError('Evaluation cleaning record mismatch.')
    columns = set(NETWORK_FEATURES) | {provenance['label_column']}
    raw = load_eligible_frame(source=data, record_path=record, usecols=lambda c: c.strip() in columns)
    frame, _, _ = prepare_network_frame(raw)
    masks = split_masks(frame)
    if split_metadata(frame, masks) != provenance['split']:
        raise ValueError('Evaluation split differs from the frozen training split.')
    result = {'model_id': provenance['model_id'], 'bundle_sha256': file_sha256(model),
              'source_sha256': provenance['sha256'], 'split': provenance['split'],
              'cleaning': provenance['cleaning'],
              'limitations': 'Filtered benchmark; 65.34% of Port Scanning and 38.50% of Bots excluded. '
                  'Anomaly detection, not attack classification. No test-set tuning. '
                  'Feature-group split is not a temporal or independent-site validation.',
              'partitions': {}}
    for name in ('validation', 'test'):
        subset = frame.loc[masks[name]]
        clean, predictions, scores, _, _ = infer_network(subset, bundle)
        truth, label = extract_binary_ground_truth(clean, override=provenance['label_column'])
        metrics = evaluate_predictions(truth, predictions, scores)
        metrics['by_source_label'] = {
            str(value): {'rows': int((clean[label] == value).sum()),
                         'anomaly_rate': float(np.mean(predictions[clean[label] == value] == -1))}
            for value in sorted(clean[label].unique())}
        result['partitions'][name] = metrics
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', type=Path, default=APPROVED_DATASET_PATH)
    parser.add_argument('--model', type=Path, default=BASELINE_PATH)
    parser.add_argument('--record', type=Path, default=DEFAULT_RECORD_PATH)
    parser.add_argument('--output', type=Path, default=ROOT / 'evaluation/baseline_holdout.json')
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Evaluation output exists; choose a new output to preserve it.')
    result = evaluate(args.data, args.model, args.record)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as handle:
        json.dump(result, handle, indent=2)
        handle.write('\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
