"""Predeclared two-day external evaluation, frozen models and full exclusion accounting."""
import argparse
import collections
import gzip
import hashlib
import json
from pathlib import Path
import sqlite3
import time
import warnings
import uuid
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier
from ml.baseline import load_baseline,infer_network
from ml.supervised_detector import load_supervised_detector,infer_supervised_network
from ml.preprocessor import NETWORK_FEATURES
from ml.external_dataset_adapter import read_external_csv,adapt_frame,validate_columns
from evaluation.external_metrics import binary_metrics
from scripts.acquire_external_dataset import sha,RAW

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'test-results/issue-4'
SCRATCH=ROOT/'.test-artifacts/issue4'


def forbid_fit(*args,**kwargs): raise RuntimeError('Fitting is prohibited during external evaluation')


def bulk_overlap(db,path):
    db.execute('ATTACH DATABASE ? AS original',(path.resolve().as_uri()+'?mode=ro',))
    db.execute('PRAGMA original.cache_size=-131072')
    counts={}
    for kind,name in [(0,'raw'),(3,'supervised'),(4,'baseline')]:
        any_rows,train_rows=db.execute('SELECT coalesce(sum(e.n),0),coalesce(sum(CASE WHEN g.lo=0 THEN e.n ELSE 0 END),0) FROM external_fingerprints e CROSS JOIN original.groups g ON g.kind=e.kind AND g.h=e.h WHERE e.kind=?',(kind,)).fetchone()
        counts[name+'_rows_matching_any_2017_partition']=int(any_rows)
        if kind:counts[name+'_rows_matching_2017_training']=int(train_rows)
    return counts


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--chunk-size',type=int,default=25000)
    parser.add_argument('--overlap-db',type=Path,help='Verified Issue 3 raw/model-input fingerprint SQLite audit')
    args=parser.parse_args()
    if args.chunk_size<1: parser.error('positive chunk size required')
    started=time.perf_counter(); run=uuid.uuid4().hex; work=SCRATCH/run; work.mkdir(parents=True)
    for cls in [IsolationForest,StandardScaler,XGBClassifier]:
        cls.fit=forbid_fit
    StandardScaler.fit_transform=forbid_fit
    warnings.filterwarnings('ignore',message='X has feature names, but StandardScaler was fitted without feature names')
    manifest=json.loads((OUT/'dataset-manifest.json').read_text())
    expected=json.loads((ROOT/'models/network-artifacts.json').read_text())['artifacts']
    models={'supervised':load_supervised_detector(),'baseline':load_baseline()}
    for name,b in models.items():
        identity=expected['supervised_binary.joblib' if name=='supervised' else 'cicids2017_baseline.joblib']
        assert b['_artifact_sha256']==identity['sha256'] and b['provenance']['model_id']==identity['model_id']
        assert b.get('threshold_config',{}).get('threshold',0)==identity['decision_threshold']
    db=sqlite3.connect(str(work/'duplicates.sqlite'),uri=True)
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA synchronous=NORMAL')
    db.execute('PRAGMA cache_size=-65536')
    db.execute('CREATE TABLE records(day INT,h BLOB,n INT,PRIMARY KEY(day,h)) WITHOUT ROWID')
    db.execute('CREATE TABLE vectors(h BLOB,label TEXT,conflict INT,PRIMARY KEY(h)) WITHOUT ROWID')
    db.execute('CREATE TABLE external_fingerprints(kind INT,h BLOB,n INT,PRIMARY KEY(kind,h)) WITHOUT ROWID')
    reference_db=sqlite3.connect(args.overlap_db.resolve().as_uri()+'?mode=ro',uri=True) if args.overlap_db else None
    if reference_db:
        audit=json.loads((ROOT/'test-results/issue-3/split-audit.json').read_text())
        assert audit['dataset_sha256']==models['baseline']['provenance']['sha256']
        assert reference_db.execute('SELECT count(*) FROM groups WHERE kind=0').fetchone()[0]==audit['overlaps']['canonical_raw_float64']['unique_vectors']
    predictions={name:[] for name in models}; truths=[]; labels_all=[]; days_all=[]
    quality={}; compat={}; demo=[]; demo_manifest=[]; drift_counts={}; summaries={}
    inference_seconds=collections.Counter(); overlap=collections.Counter(); demo_counts=collections.Counter()
    for name,b in models.items():
        drift_counts[name]={feature:np.zeros(len(frozen['proportions']),dtype=np.int64) for feature,frozen in b.get('drift_reference',models['baseline']['drift_reference'])['features'].items()}
    with gzip.open(work/'exclusion-ledger.jsonl.gz','wt',encoding='utf-8') as ledger:
        for day,source in enumerate(manifest['sources']):
            path=RAW/source['filename']; assert sha(path)==source['sha256']
            totals=collections.Counter(); reasons_count=collections.Counter(); source_labels=collections.Counter(); kept_labels=collections.Counter(); excluded_labels=collections.Counter(); excluded_reasons={}
            for frame in read_external_csv(path,chunksize=args.chunk_size):
                features,labels,truth,reasons,report=adapt_frame(frame,require_labels=True)
                compat[path.name]=validate_columns(frame.columns)
                # Invalid scaled/float32 inputs must be excluded for both detectors,
                # before prediction, and remain in the complete source-row ledger.
                overflow=np.zeros(len(features),dtype=bool)
                scaled={}
                with np.errstate(over='ignore',invalid='ignore'):
                    for name,b in models.items():
                        a=b['scaler'].transform(features)
                        scaled[name]=a
                        overflow|=~np.isfinite(a).all(axis=1)|(np.abs(a)>np.finfo(np.float32).max).any(axis=1)
                reasons.loc[features.index[overflow]]='model_input_overflow'
                features=features.loc[~overflow]
                kept=features.index
                totals.update(source_records=len(frame),valid_records=len(features),excluded_records=len(frame)-len(features),zero_duration_rows=report['zero_duration_rows'])
                source_labels.update(labels);kept_labels.update(labels.loc[kept]);excluded_labels.update(labels[reasons.ne('')])
                for index in reasons.index[reasons.ne('')]:
                    reason=reasons.loc[index];label=labels.loc[index]
                    for r in reason.split(';'):
                        reasons_count[r]+=1; excluded_reasons.setdefault(label,collections.Counter())[r]+=1
                    ledger.write(json.dumps({'filename':path.name,'source_row':int(index),'original_label':label,'reasons':reason.split(';')})+'\n')
                # SHA-256 full parsed row fingerprints; original tokens retained.
                hashes=[hashlib.sha256(json.dumps(row,separators=(',',':'),ensure_ascii=True).encode()).digest() for row in frame.itertuples(index=False,name=None)]
                db.executemany('INSERT INTO records VALUES(?,?,1) ON CONFLICT(day,h) DO UPDATE SET n=n+1',[(day,h) for h in hashes])
                if features.empty: continue
                for label in sorted(labels.loc[kept].unique()):
                    candidates=kept[labels.loc[kept].eq(label)]
                    count=10-demo_counts[(path.name,label)]
                    for index in candidates[:max(0,count)]:
                        row=frame.loc[index].drop(labels=['Label']).to_dict();demo.append(row)
                        demo_manifest.append({'demo_row':len(demo)-1,'filename':path.name,'source_row':int(index),'original_label':label,'binary_label':int(truth.loc[index])})
                        demo_counts[(path.name,label)]+=1
                x=features.to_numpy(dtype='<f8');x[x==0]=0
                raw_hash=[hashlib.sha256(row.tobytes()).digest() for row in x]
                db.executemany('INSERT INTO vectors VALUES(?,?,0) ON CONFLICT(h) DO UPDATE SET conflict=1 WHERE conflict=0 AND label<>excluded.label',list(zip(raw_hash,labels.loc[kept])))
                for name,b in models.items():
                    t=time.perf_counter()
                    if name=='supervised':
                        clean,pred,score,_=infer_supervised_network(features,b)
                    else:
                        clean,pred,score,_,_=infer_network(features,b);pred=(pred==-1).astype(int);score=-score
                    inference_seconds[name]+=time.perf_counter()-t
                    assert clean.index.equals(kept)
                    predictions[name].append((np.asarray(pred),np.asarray(score)))
                    reference=b.get('drift_reference',models['baseline']['drift_reference'])
                    for feature,frozen in reference['features'].items():
                        drift_counts[name][feature]+=np.histogram(features[feature],[-np.inf,*frozen['cut_points'],np.inf])[0]
                    if reference_db:
                        a=scaled[name][~overflow].astype('<f4');a[a==0]=0
                        kind=3 if name=='supervised' else 4
                        grouped=collections.Counter(hashlib.sha256(row.tobytes()).digest() for row in a)
                        db.executemany('INSERT INTO external_fingerprints VALUES(?,?,?) ON CONFLICT(kind,h) DO UPDATE SET n=n+excluded.n',[(kind,h,n) for h,n in grouped.items()])
                if reference_db:
                    grouped=collections.Counter(raw_hash)
                    db.executemany('INSERT INTO external_fingerprints VALUES(?,?,?) ON CONFLICT(kind,h) DO UPDATE SET n=n+excluded.n',[(0,h,n) for h,n in grouped.items()])
                truths.append(truth.loc[kept].to_numpy(dtype=np.int8));labels_all.extend(labels.loc[kept]);days_all.extend([day]*len(kept))
                db.commit()
                print(json.dumps({'progress_source':path.name,'source_rows_processed':totals['source_records'],'valid_so_far':totals['valid_records']}),flush=True)
            duplicates=int(db.execute('SELECT coalesce(sum(n-1),0) FROM records WHERE day=?',(day,)).fetchone()[0])
            quality[path.name]={'counts':dict(totals),'source_labels':dict(source_labels),'valid_labels':dict(kept_labels),'excluded_labels':dict(excluded_labels),'exclusion_reasons':dict(reasons_count),'exclusions_by_label_and_reason':{k:dict(v) for k,v in excluded_reasons.items()},'duplicate_copies_retained':duplicates}
            print(json.dumps({'source_complete':path.name,'quality':quality[path.name]}),flush=True)
            assert sha(path)==source['sha256']
    if reference_db:
        reference_db.close()
        # Sorted B-tree join, rather than random per-row Python lookups.
        overlap.update(bulk_overlap(db,args.overlap_db))
    y=np.concatenate(truths);label_array=np.asarray(labels_all);day_array=np.asarray(days_all)
    drift={}; results={}
    for name,b in models.items():
        pred=np.concatenate([v[0] for v in predictions[name]]);score=np.concatenate([v[1] for v in predictions[name]])
        np.savez_compressed(work/(name+'-predictions.npz'),truth=y,prediction=pred,score=score,day=day_array)
        result={'model_id':b['provenance']['model_id'],'sha256':b['_artifact_sha256'],'threshold':b.get('threshold_config',{}).get('threshold',0),
                'overall':binary_metrics(y,pred,score),'per_day':{},'per_label':{},'inference_seconds':inference_seconds[name], 'records_per_second':len(y)/inference_seconds[name]}
        for day,source in enumerate(manifest['sources']):
            mask=day_array==day;result['per_day'][source['filename']]=binary_metrics(y[mask],pred[mask],score[mask])
        for label in sorted(set(labels_all)):
            mask=label_array==label;positive=int(y[mask][0]);correct=int((pred[mask]==y[mask]).sum())
            result['per_label'][label]={'samples':int(mask.sum()),'binary_label':positive,'correct':correct,'incorrect':int(mask.sum())-correct,
                                      'detected':int(pred[mask].sum()) if positive else None,'missed':int((pred[mask]==0).sum()) if positive else None,
                                      'attack_recall':float(pred[mask].mean()) if positive else None,'false_positive_rate':float(pred[mask].mean()) if not positive else None}
        results[name]=result
        reference=b.get('drift_reference',models['baseline']['drift_reference'])
        feature_drift={}
        for feature,frozen in reference['features'].items():
            observed=np.maximum(drift_counts[name][feature]/len(y),1e-6);observed/=observed.sum();expected_p=np.asarray(frozen['proportions'])
            feature_drift[feature]={'psi':float(((observed-expected_p)*np.log(observed/expected_p)).sum()),'observed_counts':drift_counts[name][feature].tolist(),**frozen}
        drift[name]={'reference_rows':reference['reference_rows'],'reference_population':'saved training-only reference','external_rows':len(y),'features':feature_drift}
    pd.DataFrame(demo).to_csv(SCRATCH/'demo.csv',index=False)
    (SCRATCH/'demo-labels.json').write_text(json.dumps(demo_manifest,indent=2))
    for filename,value in [('evaluation.json',{'run':run,'chunk_size':args.chunk_size,'selection_protocol':'PROTOCOL.md','status':'CONDITIONALLY_COMPATIBLE_EVALUATION','models':results,'total_seconds':time.perf_counter()-started}),
                           ('data-quality.json',quality),('compatibility.json',compat),('drift.json',drift),
                           ('overlap.json',{'status':'AUDITED' if reference_db else 'NOT_RUN','matching_rows':dict(overlap),'rows_removed':0,'source':str(args.overlap_db),'external_conflicting_feature_groups_retained':db.execute('SELECT count(*) FROM vectors WHERE conflict=1').fetchone()[0]}),
                           ('demo-manifest-summary.json',{'selection':'first 10 eligible source rows per original label per day; before inference','records':len(demo),'labels':dict(collections.Counter(r['original_label'] for r in demo_manifest)),'csv_sha256':sha(SCRATCH/'demo.csv'),'manifest_sha256':sha(SCRATCH/'demo-labels.json')}),
                           ('exclusion-ledger-summary.json',{'path':str(work/'exclusion-ledger.jsonl.gz'),'sha256':sha(work/'exclusion-ledger.jsonl.gz'),'complete':True,'source_rows_are_zero_based':True})]:
        (OUT/filename).write_text(json.dumps(value,indent=2))
    print(json.dumps({n:r['overall'] for n,r in results.items()},indent=2),flush=True)


if __name__=='__main__':main()
