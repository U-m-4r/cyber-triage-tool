"""Frozen-artifact evaluation and streaming split audit. Does not fit any model."""
import collections
import hashlib
import json
from pathlib import Path
import platform
import sqlite3
import time
import joblib
import numpy as np
import pandas as pd
from ml.baseline import load_baseline, infer_network
from ml.supervised_detector import load_supervised_detector, infer_supervised_network
from ml.cleaning import iter_eligible_chunks, load_cleaning_record, DEFAULT_RECORD_PATH
from ml.holdout import split_masks, SPLIT_POLICY
from ml.preprocessor import NETWORK_FEATURES, prepare_network_frame
from scripts.benchmark_supervised import evaluate_binary, evaluate_multiclass, CLASS_NAMES

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT/'test-results/issue-3'
TEMP = ROOT/'.test-artifacts/issue3'
DATA = ROOT/'data/sample/cicids2017_cleaned.csv'


def sha(path):
    h = hashlib.sha256()
    with open(path,'rb') as stream:
        for data in iter(lambda:stream.read(1024*1024),b''):
            h.update(data)
    return h.hexdigest()


def dump(name, value):
    (OUT/name).write_text(json.dumps(value,indent=2,default=str))


def main():
    OUT.mkdir(exist_ok=True)
    TEMP.mkdir(parents=True,exist_ok=True)
    started = time.perf_counter()
    baseline = load_baseline()
    supervised = load_supervised_detector()
    record = load_cleaning_record()
    dataset_sha = sha(DATA)
    for b in (baseline,supervised):
        assert b['provenance']['sha256'] == dataset_sha == record['source']['sha256']
        assert b['provenance']['cleaning']['ledger_sha256'] == record['ledger']['sha256']
        assert b['provenance']['cleaning']['exclusions'] == record['exclusions']
        assert b['provenance']['cleaning']['record_sha256'] == sha(DEFAULT_RECORD_PATH)
    # New audit scratch DB each invocation. Never use an investigation database.
    import uuid
    db = sqlite3.connect(TEMP/(uuid.uuid4().hex+'.sqlite'))
    db.execute('PRAGMA journal_mode=OFF')
    db.execute('PRAGMA cache_size=-32768')
    db.execute('CREATE TABLE groups(kind INT,h BLOB,lo INT,hi INT,n INT,PRIMARY KEY(kind,h)) WITHOUT ROWID')
    counts = {k:collections.Counter() for k in ('train','validation','test')}
    digests = {k:hashlib.sha256() for k in counts}
    train_count=0
    train_sum=np.zeros(11)
    train_sumsq=np.zeros(11)
    # Verify baseline benign-only deduplicated training moments independently.
    db.execute('CREATE TABLE benign(h BLOB PRIMARY KEY, vector BLOB) WITHOUT ROWID')
    test_parts=[]
    for chunk in iter_eligible_chunks(DATA,usecols=lambda c:c.strip() in (*NETWORK_FEATURES,'Attack Type'),chunk_rows=50000):
        clean,features,report=prepare_network_frame(chunk)
        assert report['dropped_invalid_rows']==0
        masks=split_masks(clean)
        x=features.to_numpy(dtype='<f8',copy=True)
        x[x==0]=0
        labels=clean['Attack Type'].astype(str).str.strip()
        partitions=np.zeros(len(clean),dtype=np.int8)
        for i,(name,mask) in enumerate(masks.items()):
            partitions[mask]=i
            counts[name].update(labels[mask])
            digests[name].update(np.asarray(clean.index[mask],dtype='<i8').tobytes())
        train=x[masks['train']]
        train_count+=len(train)
        train_sum+=train.sum(axis=0)
        train_sumsq+=(train*train).sum(axis=0)
        normalized = [x, supervised['scaler'].transform(x), baseline['scaler'].transform(features)]
        normalized += [normalized[1].astype('<f4'),normalized[2].astype('<f4')]
        for kind,values in enumerate(normalized):
            values[values==0]=0
            batch=[(kind,hashlib.sha256(row.tobytes()).digest(),int(part),int(part),1) for row,part in zip(values,partitions)]
            db.executemany('INSERT INTO groups VALUES(?,?,?,?,?) ON CONFLICT(kind,h) DO UPDATE SET lo=min(lo,excluded.lo),hi=max(hi,excluded.hi),n=n+1',batch)
        benign=x[masks['train'] & labels.eq('Normal Traffic').to_numpy()]
        db.executemany('INSERT OR IGNORE INTO benign VALUES(?,?)',[(hashlib.sha256(row.tobytes()).digest(),row.tobytes()) for row in benign])
        db.commit()
        test_parts.append(clean.loc[masks['test']])
        print('audited rows',sum(sum(c.values()) for c in counts.values()),flush=True)
    split = {**SPLIT_POLICY,'partitions':{name:{'rows':sum(c.values()),'source_indices_sha256':digests[name].hexdigest()} for name,c in counts.items()}}
    for bundle in (baseline,supervised):
        assert bundle['provenance']['split']==split, 'Frozen split metadata mismatch'
    overlaps={}
    for i,name in enumerate(['canonical_raw_float64','supervised_scaled_float64','baseline_scaled_float64','supervised_model_float32','baseline_model_float32']):
        overlaps[name]={'unique_vectors':db.execute('SELECT count(*) FROM groups WHERE kind=?',(i,)).fetchone()[0],
                        'cross_partition_groups':db.execute('SELECT count(*) FROM groups WHERE kind=? AND lo<>hi',(i,)).fetchone()[0],
                        'duplicate_copies':db.execute('SELECT sum(n-1) FROM groups WHERE kind=?',(i,)).fetchone()[0]}
    bn=0; bs=np.zeros(11); bss=np.zeros(11)
    for row, in db.execute('SELECT vector FROM benign'):
        a=np.frombuffer(row,dtype='<f8'); bn+=1; bs+=a; bss+=a*a
    moments={}
    for name,bundle,n,s,q in [('supervised',supervised,train_count,train_sum,train_sumsq),('baseline',baseline,bn,bs,bss)]:
        mean=s/n; variance=np.maximum(0,q/n-mean*mean)
        moments[name]={'rows':n,'matches_saved_sample_count':n==int(bundle['scaler'].n_samples_seen_),
                       'mean_matches':bool(np.allclose(mean,bundle['scaler'].mean_,rtol=1e-8,atol=1e-8)),
                       'variance_matches':bool(np.allclose(variance,bundle['scaler'].var_,rtol=1e-7,atol=1e-7))}
        assert all(v for k,v in moments[name].items() if k!='rows'), moments
    dump('split-audit.json',{'dataset_sha256':dataset_sha,'dataset_bytes':DATA.stat().st_size,
        'split':split,'class_distributions':counts,'overlaps':overlaps,'scaler_training_moments':moments,
        'cleaning_record_sha256':sha(DEFAULT_RECORD_PATH),'hash_method':'SHA-256 of canonical numeric little-endian row bytes; assumes no cryptographic collisions',
        'limitations':'Feature-group split is not session, host, time or independent-site separation. Float32 model-input collisions are audited separately.'})
    db.close()
    test=pd.concat(test_parts)
    test.to_csv(TEMP/'heldout-test.csv',index=True,index_label='source_row')
    # Deterministic actual held-out demonstration, up to 12 records per source class.
    demo=test.groupby('Attack Type',sort=True,group_keys=False).head(12)
    demo.to_csv(TEMP/'demo.csv',index=False)
    dump('demo-source.json',{'sampling':'First 12 held-out source-order records per class, no prediction selection',
                             'source_indices':demo.index.tolist(),'csv_sha256':sha(TEMP/'demo.csv'),
                             'class_counts':demo['Attack Type'].value_counts().to_dict()})
    y=(test['Attack Type']!='Normal Traffic').to_numpy(dtype=int)
    results={}
    for name,path,loader,threshold in [('Isolation Forest',ROOT/'models/cicids2017_baseline.joblib',load_baseline,0.0),
                                       ('Production XGBoost',ROOT/'models/supervised_binary.joblib',load_supervised_detector,supervised['threshold_config']['threshold'])]:
        t=time.perf_counter(); b=loader(path); load_seconds=time.perf_counter()-t
        t=time.perf_counter()
        if name=='Isolation Forest':
            _,pred,score,_,_=infer_network(test,b); pred=(pred==-1).astype(int); ranking=-score
        else:
            _,pred,score,_=infer_supervised_network(test,b); ranking=score
        elapsed=time.perf_counter()-t
        results[name]={'model_sha256':sha(path),'threshold':threshold,'model_id':b['provenance']['model_id'],
                        'metrics':evaluate_binary(y,pred,ranking),'loading_seconds':load_seconds,
                        'inference_seconds':elapsed,'records_per_second':len(test)/elapsed,
                        'by_attack_type':{str(label):{'rows':int((test['Attack Type']==label).sum()),
                            'attack_prediction_rate':float(np.mean(pred[test['Attack Type']==label]))} for label in sorted(test['Attack Type'].unique())}}
    # Historical double scaling reconstructed using the frozen supervised scaler,
    # whose training-only moments match the benchmark's documented scaler fit.
    double=pd.DataFrame(supervised['scaler'].transform(test[list(NETWORK_FEATURES)]),columns=NETWORK_FEATURES,index=test.index)
    _,dp,ds,_,_=infer_network(double,baseline)
    results['Historical double-scaled IF reconstruction']={'metrics':evaluate_binary(y,(dp==-1).astype(int),-ds),'invalid_preprocessing':True}
    # Existing experiment estimators lack full bundles. Use the verified common
    # training scaler; label this weaker provenance explicitly, never deploy them.
    scaled=supervised['scaler'].transform(test[list(NETWORK_FEATURES)])
    for task in ('binary','multiclass'):
        for name in ('lightgbm','xgboost','extra_trees','random_forest','catboost'):
            path=ROOT/'models/experiments'/f'{task}_{name}.joblib'
            if not path.exists():
                results[f'Experimental {task} {name}']={'status':'UNAVAILABLE','reason':'Experimental estimator not installed; no substitution or retraining'}
                continue
            try:
                estimator=joblib.load(path)
                pred=estimator.predict(scaled).astype(int).reshape(-1)
                probability=estimator.predict_proba(scaled)
                truth=y if task=='binary' else test['Attack Type'].map({n:i for i,n in enumerate(CLASS_NAMES)}).to_numpy()
                metric=evaluate_binary(truth,pred,probability[:,1]) if task=='binary' else evaluate_multiclass(truth,pred,probability)
                results[f'Experimental {task} {name}']={'model_sha256':sha(path),'threshold':0.5 if task=='binary' else 'argmax',
                    'preprocessing':'Verified production training-only scaler; experimental scaler was not packaged. Historical code contract, not complete artifact provenance.',
                    'metrics':metric,'estimator':type(estimator).__module__+'.'+type(estimator).__name__}
                del estimator
            except Exception as exc:
                results[f'Experimental {task} {name}']={'error':str(exc)}
    dump('evaluation.json',{'dataset_sha256':dataset_sha,'split':split,'models':results,
                          'python':platform.python_version(),'total_seconds':time.perf_counter()-started})
    print(json.dumps(results,indent=2),flush=True)


if __name__=='__main__':
    main()
