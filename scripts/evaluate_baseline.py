"""Evaluate the frozen approved bundle on its reserved partitions without fitting."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import numpy as np
from ml.baseline import APPROVED_DATASET_PATH, BASELINE_PATH, load_baseline, infer_network
from ml.cleaning import DEFAULT_RECORD_PATH, load_eligible_frame, load_cleaning_record, verify_cleaning_record
from ml.holdout import split_masks, split_metadata
from ml.preprocessor import NETWORK_FEATURES, prepare_network_frame
from evaluation.evaluate import extract_binary_ground_truth, evaluate_predictions
from scripts.train_baseline import file_sha256


def evaluate(data=APPROVED_DATASET_PATH, model=BASELINE_PATH, record=DEFAULT_RECORD_PATH,
             *, allow_semantic_record=False):
    bundle = load_baseline(model)
    provenance = bundle['provenance']
    if not provenance.get('split') or not provenance.get('cleaning'):
        raise ValueError('This model has no verified eligible holdout; evaluation refused.')
    if file_sha256(data) != provenance['sha256']:
        raise ValueError('Evaluation source checksum mismatch.')
    cleaning_prov = provenance['cleaning']
    rec = load_cleaning_record(record)
    current_fp = verify_cleaning_record(
        rec,
        expected_source_sha=provenance['sha256'],
        expected_ledger_sha=cleaning_prov['ledger_sha256'],
    )
    expected_file_sha = cleaning_prov.get('record_sha256')
    expected_fp = cleaning_prov.get('record_fingerprint')
    actual_file_sha = file_sha256(record)

    match = False
    if expected_file_sha and actual_file_sha == expected_file_sha:
        match = True
    elif allow_semantic_record:
        if expected_fp and current_fp == expected_fp:
            match = True
        elif (rec.get('exclusions') == cleaning_prov.get('exclusions')
              and rec.get('ledger', {}).get('sha256') == cleaning_prov.get('ledger_sha256')):
            match = True

    if not match:
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
    parser.add_argument('--allow-semantic-record', action='store_true',
                        help='Permit cleaning record matching via semantic fingerprint and substantive fields even if raw file hash differs')
    parser.add_argument('--output', type=Path, default=ROOT / 'evaluation/baseline_holdout.json')
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Evaluation output exists; choose a new output to preserve it.')
    result = evaluate(args.data, args.model, args.record, allow_semantic_record=args.allow_semantic_record)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as handle:
        json.dump(result, handle, indent=2)
        handle.write('\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
