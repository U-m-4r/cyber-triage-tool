"""Stream official held-out positive-only challenge features; never raw malware.

Every archive record is accounted for. No training, threshold tuning, or silent
sample removal. Native Win32/Win64 rows are the predeclared evaluation scope.
"""
import hashlib
import json
from pathlib import Path
import time
import zipfile
import numpy as np
import requests
from ml.pe_features import get_extractor
from ml.pe_malware_detector import load_model, get_model_metadata, DEFAULT_THRESHOLD

REVISION = '3d23efef7c0f0b702c5024400cfff4c3744a3832'
SHA256 = 'dd215997b10596e4397d2b305d54afe9678e91e3051918262f0172b36e40baf1'


def main():
    started = time.perf_counter()
    archive = Path('.test-artifacts/issue2/challenge.zip')
    archive.parent.mkdir(parents=True, exist_ok=True)
    if not archive.exists():
        url = f'https://huggingface.co/datasets/joyce8/EMBER2024/resolve/{REVISION}/challenge.zip'
        with requests.get(url, stream=True, timeout=90) as response:
            response.raise_for_status()
            with archive.open('wb') as stream:
                for chunk in response.iter_content(1024*1024):
                    stream.write(chunk)
                    if stream.tell() > 32144161:
                        raise ValueError('Unexpected dataset download size')
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == SHA256
    extractor, model = get_extractor(), load_model()
    predictions, exclusions, errors = [], [], []
    seen = set()
    with zipfile.ZipFile(archive) as zipped:
        for member in sorted(zipped.namelist()):
            if member.endswith('/'):
                continue
            assert member.endswith('.jsonl'), member
            with zipped.open(member) as stream:
                for line_number, line in enumerate(stream, 1):
                    row = json.loads(line)
                    identifier = row['sha256']
                    if identifier in seen:
                        raise ValueError('Duplicate sample: ' + identifier)
                    seen.add(identifier)
                    if row['file_type'] not in ('Win32', 'Win64'):
                        exclusions.append({'sha256': identifier, 'file_type': row['file_type'], 'reason': 'Outside declared native PE evaluation scope'})
                        continue
                    assert row['label'] == 1, 'Challenge labels changed; reassess metrics'
                    try:
                        vector = extractor.process_raw_features(row)
                        assert vector.shape == (2568,) and np.isfinite(vector).all()
                        score = float(model.predict(vector.reshape(1,-1), num_threads=1)[0])
                        predictions.append({'sha256': identifier, 'label': row['label'],
                                            'file_type': row['file_type'], 'score': score,
                                            'predicted': int(score >= DEFAULT_THRESHOLD)})
                    except Exception as exc:
                        errors.append({'sha256': identifier, 'error': str(exc), 'member': member, 'line': line_number})
    tp = sum(p['predicted'] for p in predictions)
    fn = len(predictions) - tp
    result = {'model': get_model_metadata(), 'dataset_revision': REVISION, 'archive_sha256': SHA256,
              'partition': 'official held-out challenge; all native Win32/Win64 feature records',
              'sampling': 'All records in declared file-type scope; no label/prediction-based sampling',
              'threshold': DEFAULT_THRESHOLD, 'total_records': len(seen), 'evaluated': len(predictions),
              'positive_examples': len(predictions), 'negative_examples': 0,
              'excluded_out_of_scope': len(exclusions), 'errors': errors,
              'recall': tp/len(predictions) if predictions else None,
              'false_negative_rate': fn/len(predictions) if predictions else None,
              'confusion_matrix': {'true_positive': tp, 'false_negative': fn, 'true_negative': None, 'false_positive': None},
              'accuracy': None, 'precision': None, 'f1': None, 'roc_auc': None, 'false_positive_rate': None,
              'metric_limitation': 'Positive-only challenge cannot measure accuracy, precision, F1, ROC-AUC or specificity meaningfully. Not representative of all PE files.',
              'elapsed_seconds': round(time.perf_counter()-started, 3)}
    output = Path('test-results/issue-2/evaluation-v1')
    output.mkdir(parents=True, exist_ok=True)
    (output/'metrics.json').write_text(json.dumps(result,indent=2))
    (output/'predictions.json').write_text(json.dumps(predictions,indent=2))
    (output/'exclusions.json').write_text(json.dumps(exclusions,indent=2))
    print(json.dumps(result,indent=2))
    assert not errors, 'Evaluation incomplete: inspect explicitly recorded errors'


if __name__ == '__main__':
    main()
