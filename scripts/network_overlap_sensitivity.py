"""Diagnose frozen model-input train/test aliases; no split or threshold tuning."""
import hashlib
import argparse
import json
import sqlite3
from pathlib import Path
import numpy as np
import pandas as pd
from ml.baseline import load_baseline, infer_network
from ml.supervised_detector import load_supervised_detector, infer_supervised_network
from ml.preprocessor import NETWORK_FEATURES
from scripts.benchmark_supervised import evaluate_binary


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--audit-db',type=Path,help='Specific scratch SQLite file from verify_network_models')
    args=parser.parse_args()
    root=Path('.test-artifacts/issue3')
    paths=[args.audit_db] if args.audit_db else list(root.glob('*.sqlite'))
    if len(paths)!=1:
        raise ValueError('Select the specific audited scratch DB; ambiguous run')
    db=sqlite3.connect(paths[0])
    test=pd.read_csv(root/'heldout-test.csv',index_col='source_row',float_precision='round_trip')
    audit=json.loads(Path('test-results/issue-3/split-audit.json').read_text())
    assert hashlib.sha256(np.asarray(test.index,dtype='<i8').tobytes()).hexdigest()==audit['split']['partitions']['test']['source_indices_sha256']
    results={}
    for name,kind,bundle in [('Isolation Forest',4,load_baseline()),('Production XGBoost',3,load_supervised_detector())]:
        scaled=bundle['scaler'].transform(test[list(NETWORK_FEATURES)])
        scaled=scaled.astype('<f4'); scaled[scaled==0]=0
        in_training=[]
        for row in scaled:
            match=db.execute('SELECT lo FROM groups WHERE kind=? AND h=?',(kind,hashlib.sha256(row.tobytes()).digest())).fetchone()
            if match is None:
                raise ValueError('Serialized held-out vector differs from original audit')
            in_training.append(match[0]==0)
        in_training=np.asarray(in_training)
        unique=int(db.execute('SELECT count(*) FROM groups WHERE kind=? AND lo=0 AND hi=2',(kind,)).fetchone()[0])
        subset=test.loc[~in_training]
        y=(subset['Attack Type']!='Normal Traffic').to_numpy(dtype=int)
        if kind==4:
            _,p,s,_,_=infer_network(subset,bundle); p=(p==-1).astype(int); s=-s
        else:
            _,p,s,_=infer_supervised_network(subset,bundle)
        results[name]={'model_input_train_test_alias_groups':unique,'test_rows_with_training_alias':int(in_training.sum()),
                       'remaining_rows':len(subset),'remaining_class_distribution':subset['Attack Type'].value_counts().to_dict(),
                       'metrics_on_nonaliased_subset':evaluate_binary(y,p,s),
                       'limitations':'Post-hoc diagnostic exclusion; not a newly independent test set and not directly denominator-comparable across models. Does not address near-duplicate/session leakage or historical test-informed model selection.'}
    Path('test-results/issue-3/overlap-sensitivity.json').write_text(json.dumps(results,indent=2))
    print(json.dumps(results,indent=2))


if __name__=='__main__':
    main()
