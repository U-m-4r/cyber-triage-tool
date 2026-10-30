"""Prepare bounded development samples and unlabeled final-feature quarantine."""
import collections
import csv
import gzip
import json
from pathlib import Path
import time

import numpy as np
import pandas as pd
from ml.cleaning import iter_eligible_chunks
from ml.holdout import split_masks
from ml.external_dataset_adapter import MAPPING, adapt_frame, validate_columns
from ml.preprocessor import NETWORK_FEATURES
from ml.network_experiment import (SCHEMA, sha, write_once, validate_features, fingerprints,
                                   overlaps, development_blocks, RESULTS_DIR, WORK_DIR, repo_path)

OUT=RESULTS_DIR; WORK=WORK_DIR


def external_chunks(path, labels=True):
    with Path(path).open(encoding='utf-8-sig',newline='') as stream:
        header=next(csv.reader(stream));validate_columns(header)
    columns=list(MAPPING.values())+(['Timestamp','Label'] if labels else [])
    return pd.read_csv(path,dtype=str,keep_default_na=False,usecols=columns,chunksize=10000)


def sample_priority(indices):
    # Fixed invertible integer mixing for source-row sampling; labels/predictions
    # never determine the random value. Family quotas are explicit protocol.
    with np.errstate(over='ignore'):
        value=np.asarray(indices,dtype=np.uint64)+np.uint64(42)
        value=(value^(value>>30))*np.uint64(0xbf58476d1ce4e5b9)
        value=(value^(value>>27))*np.uint64(0x94d049bb133111eb)
        return value^(value>>31)


def retain(reservoir, frame, partition, source, cap):
    for label, group in frame.groupby('family',sort=True):
        key=(partition,source,label)
        combined=pd.concat([reservoir[key],group]) if key in reservoir else group
        if len(combined)>cap:
            positions=np.argpartition(combined['priority'].to_numpy(),cap-1)[:cap]
            combined=combined.iloc[positions]
        reservoir[key]=combined


def save_partition(path, frame):
    np.savez_compressed(path, x=validate_features(frame), y=frame['truth'].to_numpy(dtype=np.int8),
        family=frame['family'].to_numpy(dtype=str), source=frame['source'].to_numpy(dtype=str),
        source_row=frame['source_row'].to_numpy(dtype=np.int64))


def main():
    if (OUT/'prepared.json').exists():raise RuntimeError('Prepared population already sealed')
    WORK.mkdir(parents=True,exist_ok=True)
    lock=json.loads((OUT/'locked-test.json').read_text())
    assert lock['protocol_sha256']==sha(OUT/'PROTOCOL.md')
    started=time.perf_counter();exact_parts=[];near_parts=[];test_audit={}
    with gzip.open(WORK/'unlabeled-test-exclusions.jsonl.gz','wt',encoding='utf-8') as ledger:
        for source in lock['sources']:
            path=repo_path(source['path']);assert sha(path)==source['sha256']
            counts=collections.Counter()
            for chunk in external_chunks(path,labels=False):
                x,_,_,reasons,report=adapt_frame(chunk)
                overflow=(x.to_numpy()>np.finfo(np.float32).max).any(axis=1)
                reasons.loc[x.index[overflow]]='float32_overflow'
                x=x.loc[~overflow];values=validate_features(x)
                exact_parts.append(fingerprints(values));near_parts.append(fingerprints(values,True))
                counts.update(source_rows=len(chunk),eligible_features=len(x),excluded_features=len(chunk)-len(x))
                for index in reasons.index[reasons.ne('')]:
                    ledger.write(json.dumps({'source':path.name,'source_row':int(index),'reason':reasons.loc[index]})+'\n')
            test_audit[path.name]=dict(counts)
            print('Unlabeled quarantine',path.name,dict(counts),flush=True)
    exact=np.unique(np.concatenate(exact_parts));near=np.unique(np.concatenate(near_parts));del exact_parts,near_parts
    np.savez_compressed(WORK/'quarantine.npz',exact=exact,near=near)
    reservoir={};counts=collections.Counter();source_quality={}
    with gzip.open(WORK/'development-exclusions.jsonl.gz','wt',encoding='utf-8') as ledger:
        for source in json.loads(Path('test-results/issue-4/dataset-manifest.json').read_text())['sources']:
            path=Path('.test-artifacts/issue4/raw')/source['filename'];assert sha(path)==source['sha256']
            quality=collections.Counter()
            for chunk in external_chunks(path):
                x,labels,truth,reasons,_=adapt_frame(chunk,require_labels=True)
                overflow=(x.to_numpy()>np.finfo(np.float32).max).any(axis=1)
                reasons.loc[x.index[overflow]]='float32_overflow';x=x.loc[~overflow]
                training,validation,embargo=development_blocks(chunk.loc[x.index,'Timestamp'])
                quality.update(source_rows=len(chunk),invalid=len(chunk)-len(x),embargo_or_bad_timestamp=int(embargo.sum()),
                    train_before_sampling=int(training.sum()),validation_before_sampling=int(validation.sum()))
                reasons.loc[x.index[embargo]]='temporal_embargo_or_invalid_timestamp'
                for index in reasons.index[reasons.ne('')]:
                    ledger.write(json.dumps({'source':path.name,'source_row':int(index),'reason':reasons.loc[index]})+'\n')
                for partition,mask,cap in [('train',training,25000),('validation',validation,20000)]:
                    frame=x.loc[mask].copy();frame['family']=labels.loc[frame.index]
                    frame['truth']=truth.loc[frame.index].astype(int);frame['source']=path.name
                    frame['source_row']=frame.index;frame['priority']=sample_priority(frame.index)
                    retain(reservoir,frame,partition,path.name,cap)
            source_quality[path.name]=dict(quality)
            print('Sampled development',path.name,dict(quality),flush=True)
        # Source verification and original cleaning/split policy are reused.
        for chunk in iter_eligible_chunks('data/sample/cicids2017_cleaned.csv',
                usecols=lambda c:c.strip() in (*NETWORK_FEATURES,'Attack Type'),chunk_rows=10000):
            frame=chunk.loc[split_masks(chunk)['train']].copy()
            valid=np.isfinite(frame.loc[:,list(NETWORK_FEATURES)].to_numpy()).all(axis=1)
            valid&=(frame.loc[:,list(NETWORK_FEATURES)].to_numpy()>=0).all(axis=1)
            valid&=(frame.loc[:,list(NETWORK_FEATURES)].to_numpy()<=np.finfo(np.float32).max).all(axis=1)
            counts.update(cicids2017_original_train_rows=len(frame),cicids2017_invalid=int((~valid).sum()))
            frame=frame.loc[valid];frame['family']=frame['Attack Type'].astype(str)
            frame['truth']=(frame['family']!='Normal Traffic').astype(int);frame['source']='CICIDS2017'
            frame['source_row']=frame.index;frame['priority']=sample_priority(frame.index)
            retain(reservoir,frame,'train','CICIDS2017',10000)
    partitions={p:pd.concat([frame for (part,_,_),frame in reservoir.items() if part==p])
                .sort_values(['source','source_row']).reset_index(drop=True) for p in ('train','validation')}
    stages={}
    for partition,frame in partitions.items():
        values=validate_features(frame)
        purge=overlaps(fingerprints(values),exact)|overlaps(fingerprints(values,True),near)
        stages[partition]={'sampled_rows':len(frame),'quarantined_against_unlabeled_test':int(purge.sum())}
        partitions[partition]=frame.loc[~purge].copy()
    train,val=partitions['train'],partitions['validation']
    tx=validate_features(train);vx=validate_features(val)
    purge=overlaps(fingerprints(tx),np.unique(fingerprints(vx)))|overlaps(fingerprints(tx,True),np.unique(fingerprints(vx,True)))
    stages['train']['purged_against_validation']=int(purge.sum());train=train.loc[~purge].copy()
    train['vector_hash']=fingerprints(validate_features(train))
    conflicts=train.groupby('vector_hash')['truth'].nunique();bad=conflicts.index[conflicts>1]
    conflict=train['vector_hash'].isin(bad)
    stages['train']['conflicting_label_rows_excluded']=int(conflict.sum())
    train=train.loc[~conflict];before=len(train);train=train.drop_duplicates('vector_hash')
    stages['train']['duplicate_training_rows_removed']=before-len(train)
    partitions={'train':train,'validation':val}
    for partition,frame in partitions.items():
        stages[partition]['retained_rows']=len(frame)
        stages[partition]['groups']={str(k):int(v) for k,v in frame.groupby(['source','family','truth']).size().items()}
        stages[partition]['source_identity_sha256']=__import__('hashlib').sha256(
            frame[['source','source_row']].to_csv(index=False).encode()).hexdigest()
        save_partition(WORK/(partition+'.npz'),frame)
    tx=validate_features(train);vx=validate_features(val)
    overlap={'exact_model_input_train_validation':int(overlaps(fingerprints(tx),np.unique(fingerprints(vx))).sum()),
             'near_bins_train_validation':int(overlaps(fingerprints(tx,True),np.unique(fingerprints(vx,True))).sum()),
             'train_final_exact':int(overlaps(fingerprints(tx),exact).sum()),
             'validation_final_exact':int(overlaps(fingerprints(vx),exact).sum()),
             'train_final_near':int(overlaps(fingerprints(tx,True),near).sum()),
             'validation_final_near':int(overlaps(fingerprints(vx,True),near).sum())}
    assert not any(overlap.values())
    write_once(OUT/'prepared.json',{'protocol_sha256':sha(OUT/'PROTOCOL.md'),'lock_sha256':sha(OUT/'locked-test.json'),
        'schema':SCHEMA,'unlabeled_final_features':test_audit,'development_quality':source_quality,
        'cicids2017':dict(counts),'partitions':stages,'overlap_checks':overlap,
        'artifacts':{name:sha(WORK/name) for name in ('train.npz','validation.npz','quarantine.npz')},
        'elapsed_seconds':time.perf_counter()-started,'no_final_label_access':True})
    print(json.dumps(stages,indent=2),flush=True)


if __name__=='__main__':main()
