"""Rebuild Issue 3's exact real 84-row fixture without rerunning any benchmark.

Requires the approved cleaned source and cleaning ledger documented in Issue 3.
Uses the already published source indices, not model predictions or test tuning.
"""
import json
from pathlib import Path
import pandas as pd
from ml.cleaning import iter_eligible_chunks
from ml.preprocessor import NETWORK_FEATURES, prepare_network_frame
from scripts.verify_network_models import sha


def main():
    manifest = json.loads(Path('test-results/issue-3/demo-source.json').read_text())
    wanted = manifest['source_indices']
    parts = []
    for chunk in iter_eligible_chunks('data/sample/cicids2017_cleaned.csv',
            usecols=lambda column:column.strip() in (*NETWORK_FEATURES, 'Attack Type')):
        clean, _, _ = prepare_network_frame(chunk)
        parts.append(clean.loc[clean.index.isin(wanted)])
    selected = pd.concat(parts).loc[wanted]
    output = Path('.test-artifacts/issue3/demo.csv'); output.parent.mkdir(parents=True, exist_ok=True)
    candidate = output.with_suffix('.reproduced.csv'); selected.to_csv(candidate, index=False)
    assert sha(candidate) == manifest['csv_sha256'], 'Byte representation differs; preserve the original fixture'
    if output.exists():
        assert sha(output) == sha(candidate)
        candidate.unlink()
    else:
        candidate.rename(output)
    print(json.dumps({'path':str(output), 'sha256':sha(output), 'rows':len(selected)}))


if __name__ == '__main__':
    main()
