"""Two predeclared, bounded training candidates; never reads final CSV labels."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import time

import numpy as np
import pandas as pd
import psutil
from ml.network_experiment import (SCHEMA, sha, write_once, operating_point,
                                  measured_result, load_candidate)

OUT=Path('test-results/issue-6');WORK=Path('.test-artifacts/issue6')


def read_partition(partition, prepared):
    path=WORK/(partition+'.npz');assert sha(path)==prepared['artifacts'][path.name]
    return np.load(path,allow_pickle=False)


def validation_raw(val):
    """Restore source float64 for the incumbent's scaler-before-float32 contract.

    Candidate arrays are identity float32; converting those back to float64 is
    not byte-equivalent to raw measurements before incumbent standardization.
    Only already sampled validation row identities are read; no final labels.
    """
    from scripts.prepare_issue6 import external_chunks
    from ml.external_dataset_adapter import adapt_frame
    from ml.network_experiment import validate_features
    values=np.empty((len(val['y']),len(SCHEMA['columns'])),dtype=float)
    seen=np.zeros(len(values),dtype=bool)
    for source in np.unique(val['source']):
        positions=np.flatnonzero(val['source']==source)
        locations=pd.Series(positions,index=val['source_row'][positions])
        for chunk in external_chunks(Path('.test-artifacts/issue4/raw')/str(source),labels=False):
            indices=chunk.index.intersection(locations.index)
            if len(indices):
                frame,_,_,_,_=adapt_frame(chunk.loc[indices])
                target=locations.loc[frame.index].to_numpy()
                values[target]=frame.to_numpy(dtype=float);seen[target]=True
    assert seen.all()
    frame=pd.DataFrame(values,columns=SCHEMA['columns'])
    np.testing.assert_array_equal(validate_features(frame),val['x'])
    return frame


def worker(name):
    import importlib.metadata
    prepared=json.loads((OUT/'prepared.json').read_text())
    assert prepared['protocol_sha256']==sha(OUT/'PROTOCOL.md')
    train=read_partition('train',prepared);val=read_partition('validation',prepared)
    x,y=train['x'],train['y'];v,vy=val['x'],val['y']
    groups=np.char.add(np.char.add(train['source'],'|'),train['family'])
    unique,indices,counts=np.unique(groups,return_inverse=True,return_counts=True)
    weights=len(y)/(len(unique)*counts[indices])
    directory=WORK/'candidates'/name;directory.mkdir(parents=True,exist_ok=False)
    started=time.perf_counter()
    common={'n_estimators':300,'learning_rate':.05,'subsample':.8,'colsample_bytree':.9,
            'reg_lambda':10,'random_state':42,'n_jobs':2}
    if name=='xgboost':
        import xgboost
        params={**common,'max_depth':5,'min_child_weight':10,'tree_method':'hist','max_bin':128,
                'early_stopping_rounds':30,'eval_metric':'logloss'}
        model=xgboost.XGBClassifier(**params)
        model.fit(x,y,sample_weight=weights,eval_set=[(v,vy)],verbose=False)
        score=model.predict_proba(v)[:,1]
        filename='model.ubj';model.save_model(directory/filename)
        best=int(model.best_iteration)
    else:
        import lightgbm
        params={**common,'num_leaves':31,'max_depth':6,'min_child_samples':50,'subsample_freq':1,
                'max_bin':127,'deterministic':True,'force_col_wise':True,'verbosity':-1}
        model=lightgbm.LGBMClassifier(**params)
        model.fit(x,y,sample_weight=weights,eval_set=[(v,vy)],eval_metric='binary_logloss',
                  callbacks=[lightgbm.early_stopping(30,verbose=False)])
        score=model.predict_proba(v)[:,1]
        filename='model.txt';model.booster_.save_model(str(directory/filename));best=int(model.best_iteration_)-1
    elapsed=time.perf_counter()-started
    metadata={'estimator':name,'filename':filename,'sha256':sha(directory/filename),'feature_schema':SCHEMA,
        'model_id':'issue6-'+name+'-'+sha(directory/filename)[:12], 'version':'issue6-protocol-v1',
        'parameters':params,'best_iteration':best,'fit_seconds':elapsed,
        'training_rows':len(y),'validation_rows':len(vy),'training_only_preprocessing':'identity, no fitted statistics',
        'prepared_sha256':sha(OUT/'prepared.json'),'protocol_sha256':sha(OUT/'PROTOCOL.md'),
        'training_groups':{str(g):{'count':int(n),'per_record_weight':float(len(y)/(len(unique)*n))} for g,n in zip(unique,counts)},
        'versions':{p:importlib.metadata.version(p) for p in ('xgboost','lightgbm','numpy','pandas','scikit-learn')},
        'created_at':datetime.now(timezone.utc).isoformat()}
    write_once(directory/'metadata.json',metadata)
    loaded,_=load_candidate(directory,metadata['sha256'])
    restored=loaded(pd.DataFrame(v,columns=SCHEMA['columns']))
    np.testing.assert_allclose(restored,score,rtol=1e-6,atol=1e-7)
    np.savez_compressed(directory/'validation.npz',score=restored,truth=vy,family=val['family'])
    points={str(budget):operating_point(vy,restored,budget) for budget in (.01,.05,.10)}
    result=measured_result(vy,restored,points['0.05']['threshold'],val['family'])
    result.update(model=metadata,operating_points=points,serialization_roundtrip='PASS')
    write_once(OUT/(name+'-validation.json'),result)
    print(json.dumps(result,indent=2),flush=True)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--worker',choices=['xgboost','lightgbm']);args=parser.parse_args()
    if args.worker:return worker(args.worker)
    if (OUT/'selection.json').exists():raise RuntimeError('Selection sealed; new fitting would invalidate untouched test')
    prepared=json.loads((OUT/'prepared.json').read_text())
    assert prepared['protocol_sha256']==sha(OUT/'PROTOCOL.md')
    assert not (OUT/'final-test-receipt.json').exists()
    resources={}
    for name in ('xgboost','lightgbm'):
        with (OUT/(name+'-training.log')).open('x',encoding='utf-8') as log:
            process=subprocess.Popen([sys.executable,'-m','scripts.train_issue6','--worker',name],stdout=log,stderr=subprocess.STDOUT)
            started=time.monotonic();peak=0
            while process.poll() is None:
                try:
                    parent=psutil.Process(process.pid)
                    peak=max(peak,sum(p.memory_info().rss for p in [parent,*parent.children(recursive=True)] if p.is_running()))
                except psutil.Error:pass
                if time.monotonic()-started>120:
                    try:
                        for child in psutil.Process(process.pid).children(recursive=True):child.kill()
                    except psutil.Error:pass
                    process.kill();process.wait();raise TimeoutError('Candidate exceeded predeclared 120-second budget')
                time.sleep(.2)
            if process.returncode:raise RuntimeError('Candidate failed: see '+str(OUT/(name+'-training.log')))
        resources[name]={'wall_seconds':time.monotonic()-started,'peak_worker_rss_bytes':peak}
    from ml.supervised_detector import load_supervised_detector,infer_supervised_network
    val=read_partition('validation',prepared);original=load_supervised_detector()
    frame=validation_raw(val)
    _,_,score,_=infer_supervised_network(frame,original)
    frozen=measured_result(val['y'],score,original['threshold_config']['threshold'],val['family'])
    frozen['validation_only_retuned_points']={str(b):operating_point(val['y'],score,b) for b in (.01,.05,.10)}
    frozen['model_sha256']=original['_artifact_sha256']
    frozen['input_contract']='Original float64 measurements restored by source row; incumbent scaler applied once before native float32'
    np.savez_compressed(WORK/'incumbent-validation.npz',score=score,truth=val['y'],family=val['family'])
    write_once(OUT/'incumbent-validation.json',frozen)
    candidates={name:json.loads((OUT/(name+'-validation.json')).read_text()) for name in ('xgboost','lightgbm')}
    ranking=[]
    for name,result in candidates.items():
        recalls=[r['recall'] for r in result['per_family'].values() if r['binary_label']]
        ranking.append({'name':name,'macro_family_recall':float(np.mean(recalls)),
            'average_precision':result['overall']['average_precision'],'fpr':result['overall']['false_positive_rate']})
    winner=sorted(ranking,key=lambda r:(-r['macro_family_recall'],-r['average_precision'],r['fpr'],r['name']))[0]['name']
    selected=candidates[winner]
    write_once(OUT/'selection.json',{'selected':winner,'threshold':selected['threshold'],
        'model_id':selected['model']['model_id'],'model_sha256':selected['model']['sha256'],
        'candidate_metadata_sha256':sha(WORK/'candidates'/winner/'metadata.json'),
        'protocol_sha256':sha(OUT/'PROTOCOL.md'),'lock_sha256':sha(OUT/'locked-test.json'),
        'prepared_sha256':sha(OUT/'prepared.json'),'ranking':ranking,'resources':resources,
        'sealed_at':datetime.now(timezone.utc).isoformat(),'final_labels_accessed':False,
        'selected_by':'validation macro attack-family recall under empirical FPR <=5%, tie AP then FPR then name'})
    print(json.dumps({'winner':winner,'ranking':ranking,'resources':resources},indent=2),flush=True)


if __name__=='__main__':main()
