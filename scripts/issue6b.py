"""Local-only, inductive capture-day experiment. Never imported by production."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import gzip
import json
from pathlib import Path
import time

import numpy as np
import pandas as pd
from ml.network_experiment import (SCHEMA, sha, write_once, validate_features,
    fingerprints, overlaps, measured_result, operating_point, deployment_gates)
from scripts.prepare_issue6 import external_chunks, sample_priority
from ml.external_dataset_adapter import adapt_frame

OUT = Path('test-results/issue-6b')
WORK = Path('.test-artifacts/issue6b')


def now():
    return datetime.now(timezone.utc).isoformat()


def source_paths():
    return {'train_bot': Path('.test-artifacts/issue4/raw/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv'),
        'validation_web': Path('.test-artifacts/issue4/raw/Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv'),
        'validation_dos': Path('.test-artifacts/issue6/raw/Friday-16-02-2018_TrafficForML_CICFlowMeter.csv'),
        'calibration': Path('.test-artifacts/issue6/raw/Friday-23-02-2018_TrafficForML_CICFlowMeter.csv')}


def lock():
    import psutil
    import requests
    from urllib.parse import quote
    OUT.mkdir(parents=True, exist_ok=True); WORK.mkdir(parents=True, exist_ok=True)
    if (OUT/'protocol.json').exists():
        raise RuntimeError('Protocol already sealed')
    name = 'Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv'
    url = 'https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/'+quote('Processed Traffic Data for ML Algorithms/'+name, safe='/')
    protocol = {'created_at': now(), 'schema': SCHEMA, 'final_source': name,
        'training': 'Original eligible 2017 training mask + March 2 2018; cap 20000 per source/family, bottom row hash seed42',
        'validation': 'Entire February22 and February16 capture days (already opened; development only)',
        'calibration': 'Entire February23 capture day (already opened; development only)',
        'final': 'Entire previously unused February15; no feature access before selection; inductive',
        'sampling': 'Only training sampled/deduplicated. All eligible validation/calibration/final rows retained.',
        'overlap': 'Train purged exact/rounded-log against development only; final overlaps measured AFTER selection, never filtered',
        'candidates': ['lightgbm','xgboost'], 'seeds': [42,43], 'threads': 2,
        'rounds': 200, 'max_training_seconds': 120, 'max_process_tree_rss_bytes': 1500000000,
        'threshold': 'Calibration only: maximize recall under 1% empirical FPR; complete ties; no calibration fitting',
        'selection': 'maximize worst validation-day attack recall at calibration threshold; tie average precision then name/seed',
        'gates': 'Original Issue6 gates unmodified, family N>=30; missing families explicitly unverified',
        'timestamp_limitation': 'Local write-once hash chain only; no independent timestamp authentication',
        'resources': {'available_ram': psutil.virtual_memory().available},
        'scope': 'Four fits only, no ensembles/family cascade, no production deployment without gates'}
    write_once(OUT/'protocol.json', protocol)
    sources={k:{'path':str(v),'sha256':sha(v)} for k,v in source_paths().items()}
    clean=Path('data/sample/cicids2017_cleaned.csv')
    sources['train_2017']={'path':str(clean),'sha256':sha(clean)}
    write_once(OUT/'development-sources.json',sources)
    session=requests.Session();session.trust_env=False
    response=session.head(url,timeout=60);response.raise_for_status()
    size=int(response.headers['Content-Length'])
    if size>600000000: raise ValueError('Download exceeds 600MB budget')
    target=WORK/name
    with session.get(url,stream=True,timeout=(30,120)) as response:
        response.raise_for_status()
        with target.open('xb') as stream:
            count=0
            for block in response.iter_content(1048576):
                count+=len(block)
                if count>size: raise ValueError('Download size mismatch')
                stream.write(block)
    assert target.stat().st_size==size
    write_once(OUT/'locked-test.json',{'protocol_sha256':sha(OUT/'protocol.json'),'locked_at':now(),
        'path':str(target),'sha256':sha(target),'bytes':size,'url':url,'labels_opened':False})
    old=Path('test-results/issue-6')
    write_once(OUT/'checkpoint.json', {str(p):sha(p) for p in old.rglob('*') if p.is_file()})
    print('Protocol and source hashes sealed; final bytes downloaded without CSV parsing',flush=True)


def load_day(path):
    parts=[]; counts=Counter()
    ledger=WORK/(path.stem+'-excluded.jsonl.gz')
    with gzip.open(ledger,'xt',encoding='utf8') as stream:
        for chunk in external_chunks(path):
            x,labels,y,reasons,_=adapt_frame(chunk,require_labels=True)
            overflow=(x.to_numpy()>np.finfo(np.float32).max).any(axis=1)
            reasons.loc[x.index[overflow]]='float32_overflow';x=x.loc[~overflow]
            counts.update(input=len(chunk),eligible=len(x),excluded=len(chunk)-len(x))
            for i in reasons.index[reasons.ne('')]:
                stream.write(json.dumps({'row':int(i),'label':labels.loc[i],'reason':reasons.loc[i]})+'\n')
            x=x.copy();x['family']=labels.loc[x.index];x['truth']=y.loc[x.index].astype(int)
            x['source']=path.name;x['source_row']=x.index
            parts.append(x)
    return pd.concat(parts,ignore_index=True),dict(counts)


def assert_day_separation(train, validation, calibration):
    groups=[set(f['source']) for f in (train,validation,calibration)]
    if any(groups[i]&groups[j] for i in range(3) for j in range(i)):
        raise ValueError('Capture source overlap between partitions')


def prepare():
    from ml.cleaning import iter_eligible_chunks
    from ml.holdout import split_masks
    if (OUT/'prepared.json').exists(): raise RuntimeError('Preparation sealed')
    refs=json.loads((OUT/'development-sources.json').read_text())
    for ref in refs.values(): assert sha(ref['path'])==ref['sha256']
    paths=source_paths(); quality={};days={}
    for role,path in paths.items():
        days[role],quality[role]=load_day(path)
        print('Loaded',role,quality[role],flush=True)
    from scripts.prepare_issue6 import retain
    reservoir={}
    for chunk in iter_eligible_chunks('data/sample/cicids2017_cleaned.csv',chunk_rows=10000):
        f=chunk.loc[split_masks(chunk)['train']].copy()
        v=f[SCHEMA['columns']].to_numpy(float)
        f=f.loc[np.isfinite(v).all(axis=1)&(v>=0).all(axis=1)&(v<=np.finfo(np.float32).max).all(axis=1)]
        f['family']=f['Attack Type'].astype(str);f['truth']=(f['family']!='Normal Traffic').astype(int)
        f['source']='CICIDS2017';f['source_row']=f.index;f['priority']=sample_priority(f.index)
        retain(reservoir,f,'train','CICIDS2017',20000)
    bot=days.pop('train_bot');bot['priority']=sample_priority(bot['source_row'])
    retain(reservoir,bot,'train','March2',20000)
    train=pd.concat(reservoir.values(),ignore_index=True)
    validation=pd.concat([days['validation_web'],days['validation_dos']],ignore_index=True)
    calibration=days['calibration']
    assert_day_separation(train,validation,calibration)
    ref=np.concatenate([validate_features(validation),validate_features(calibration)])
    tx=validate_features(train)
    purge=overlaps(fingerprints(tx),np.unique(fingerprints(ref)))|overlaps(fingerprints(tx,True),np.unique(fingerprints(ref,True)))
    sampled=len(train);train=train.loc[~purge].copy()
    train['hash']=fingerprints(validate_features(train))
    audit=train.groupby('hash')['truth'].agg(['size','nunique','sum'])
    # Conflicts are retained: label-preserving equal-vector normalization weights below.
    before=len(train);train=train.drop_duplicates(['hash','truth'])
    summary={'sampled_training':sampled,'purged_development_overlap':int(purge.sum()),'training_duplicates_removed':before-len(train),
        'training_conflict_groups':int((audit['nunique']>1).sum()),'quality':quality,'partitions':{}}
    for name,frame in [('train',train),('validation',validation),('calibration',calibration)]:
        path=WORK/(name+'.npz')
        np.savez_compressed(path,x=frame[SCHEMA['columns']].to_numpy(float),y=frame.truth.to_numpy(np.int8),
            family=frame.family.to_numpy(str),source=frame.source.to_numpy(str),row=frame.source_row.to_numpy(np.int64))
        summary['partitions'][name]={'rows':len(frame),'sha256':sha(path),'groups':{str(k):int(v) for k,v in frame.groupby(['source','family']).size().items()}}
    summary['protocol_sha256']=sha(OUT/'protocol.json')
    write_once(OUT/'prepared.json',summary)


def train():
    if (OUT/'selection.json').exists() or (OUT/'final-test-receipt.json').exists(): raise RuntimeError('Experiment frozen')
    arrays={n:np.load(WORK/(n+'.npz'),allow_pickle=False) for n in ('train','validation','calibration')}
    for n,a in arrays.items(): assert sha(WORK/(n+'.npz'))==json.loads((OUT/'prepared.json').read_text())['partitions'][n]['sha256']
    t,v,c=(arrays[n] for n in ('train','validation','calibration'))
    group=np.char.add(np.char.add(t['source'],'|'),t['family'])
    _,idx,count=np.unique(group,return_inverse=True,return_counts=True)
    weights=len(group)/(len(count)*count[idx]);results=[]
    for name in ('lightgbm','xgboost'):
        for seed in (42,43):
            started=time.perf_counter()
            params=dict(n_estimators=200,max_depth=4,learning_rate=.05,reg_lambda=20,n_jobs=2,random_state=seed,subsample=.8,colsample_bytree=.8)
            if name=='lightgbm':
                from lightgbm import LGBMClassifier
                model=LGBMClassifier(**params,num_leaves=15,min_child_samples=100,verbosity=-1,deterministic=True,force_col_wise=True)
            else:
                from xgboost import XGBClassifier
                model=XGBClassifier(**params,min_child_weight=20,tree_method='hist',max_bin=128)
            bounded_fit(model,t['x'].astype(np.float32),t['y'],weights)
            fit=time.perf_counter()-started
            cs=model.predict_proba(c['x'].astype(np.float32))[:,1]
            threshold=operating_point(c['y'],cs,.01)['threshold']
            vs=model.predict_proba(v['x'].astype(np.float32))[:,1]
            result=measured_result(v['y'],vs,threshold,v['family'])
            result['per_day']={str(s):measured_result(v['y'][v['source']==s],vs[v['source']==s],threshold,v['family'][v['source']==s]) for s in np.unique(v['source'])}
            path=WORK/f'{name}-{seed}.model'
            if name=='lightgbm': model.booster_.save_model(str(path))
            else: model.save_model(path.with_suffix('.ubj'));path=path.with_suffix('.ubj')
            result.update(name=name,seed=seed,path=str(path),sha256=sha(path),fit_seconds=fit,params=params,
                calibration=measured_result(c['y'],cs,threshold,c['family']))
            results.append(result); print(name,seed,result['overall'],flush=True)
    write_once(OUT/'validation.json',results)
    selected=sorted(results,key=lambda r:(-min(d['overall']['recall'] for d in r['per_day'].values()),-r['overall']['average_precision'],r['name'],r['seed']))[0]
    write_once(OUT/'selection.json',{'selected':selected,'sealed_at':now(),'protocol_sha256':sha(OUT/'protocol.json'),
        'prepared_sha256':sha(OUT/'prepared.json'),'lock_sha256':sha(OUT/'locked-test.json'),'feature_schema':SCHEMA,'final_features_or_labels_accessed':False})


def bounded_fit(model,x,y,weights):
    """Stop this offline worker on declared wall/RSS limits, including children."""
    import os
    import threading
    import psutil
    done=threading.Event();started=time.monotonic();peak=[0]
    def watch():
        while not done.wait(.1):
            parent=psutil.Process()
            peak[0]=max(peak[0],sum(p.memory_info().rss for p in [parent,*parent.children(recursive=True)]))
            if peak[0]>1500000000 or time.monotonic()-started>120:
                print('LIMIT_EXCEEDED: training wall/RSS guard',flush=True)
                os._exit(124)
    thread=threading.Thread(target=watch,daemon=True);thread.start()
    try:
        model.fit(x,y,sample_weight=weights)
    finally:
        done.set();thread.join()
    print('Actual fitting-process observed peak RSS:',peak[0],flush=True)


def evaluate():
    if (OUT/'final-test-receipt.json').exists(): raise RuntimeError('Final evaluation already opened')
    selection=json.loads((OUT/'selection.json').read_text());locked=json.loads((OUT/'locked-test.json').read_text());sel=selection['selected']
    assert sha(OUT/'protocol.json')==selection['protocol_sha256']==locked['protocol_sha256']
    assert sha(OUT/'locked-test.json')==selection['lock_sha256'] and sha(sel['path'])==sel['sha256']
    assert sha(locked['path'])==locked['sha256']
    started=time.perf_counter()
    if sel['name']=='lightgbm':
        from lightgbm import Booster
        model=Booster(model_file=sel['path']);predict=lambda x:model.predict(x,num_threads=2)
    else:
        from xgboost import XGBClassifier
        model=XGBClassifier();model.load_model(sel['path']);predict=lambda x:model.predict_proba(x)[:,1]
    loading=time.perf_counter()-started
    write_once(OUT/'final-test-receipt.json',{'opened_at':now(),'selection_sha256':sha(OUT/'selection.json'),'locked_sha256':sha(OUT/'locked-test.json'),'policy':'one shot, no refit or retuning'})
    frame,quality=load_day(Path(locked['path']))
    x=validate_features(frame);y=frame.truth.to_numpy(np.int8);labels=frame.family.to_numpy(str)
    started=time.perf_counter();score=np.concatenate([predict(x[i:i+10000]) for i in range(0,len(x),10000)]);elapsed=time.perf_counter()-started
    challenger=measured_result(y,score,sel['threshold'],labels)
    from ml.supervised_detector import load_supervised_detector,infer_supervised_network
    incumbent=load_supervised_detector();scores=[]
    for i in range(0,len(frame),10000): scores.append(infer_supervised_network(frame.iloc[i:i+10000][SCHEMA['columns']],incumbent)[2])
    oldscore=np.concatenate(scores);old=measured_result(y,oldscore,incumbent['threshold_config']['threshold'],labels)
    gates=deployment_gates(challenger,old,{'February15':challenger},len(x)/elapsed,loading)
    from scripts.diagnose_issue6 import curves
    write_once(OUT/'curves.json',{'incumbent':curves(y,oldscore),'challenger':curves(y,score)})
    np.savez_compressed(WORK/'final-predictions.npz',truth=y,score=score,incumbent=oldscore,family=labels)
    # Retain final duplicates and conflicts; report representation ambiguity without relabeling.
    groups=pd.DataFrame({'h':fingerprints(x),'y':y}).groupby('h').y.agg(['size','sum','nunique'])
    ambiguity={'mixed_groups':int((groups['nunique']>1).sum()),'minimum_deterministic_errors':int(np.minimum(groups['sum'],groups['size']-groups['sum']).sum())}
    train=np.load(WORK/'train.npz',allow_pickle=False)
    overlap=int(overlaps(fingerprints(x),np.unique(fingerprints(train['x']))).sum())
    write_once(OUT/'final-results.json',{'challenger':challenger,'incumbent':old,'quality':quality,'gates':gates,
        'deployment_eligible':all(gates.values()),'loading_seconds':loading,'inference_seconds':elapsed,'throughput':len(x)/elapsed,
        'ambiguity':ambiguity,'posthoc_exact_train_overlap_rows_retained':overlap,'selection_sha256':sha(OUT/'selection.json'),
        'independence':'New capture day, same testbed; no new independent SlowHTTPTest/web/bot claim'})
    print(json.dumps({'challenger':challenger['overall'],'incumbent':old['overall'],'gates':gates},indent=2),flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('stage',choices=['lock','prepare','train','evaluate']);args=parser.parse_args()
    globals()[args.stage]()
