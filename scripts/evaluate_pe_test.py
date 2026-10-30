"""Local, frozen EMBER2024 ordinary test evaluation; feature JSON only."""
from collections import Counter
from datetime import datetime, timezone
import gzip
import json
import os
from pathlib import Path
import time
import zipfile
import numpy as np
from evaluation.external_metrics import binary_metrics
from ml.network_experiment import sha,write_once
from ml.pe_features import get_extractor,DIMENSIONS
from ml.pe_malware_detector import get_model_metadata,load_model,DEFAULT_THRESHOLD,DEFAULT_MAX_BYTES

OUT=Path(os.getenv('PE_TEST_RESULTS','test-results/issue-7'))
WORK=Path(os.getenv('PE_TEST_WORK','.test-artifacts/issue7'))
ARCHIVES=Path('.test-artifacts/issue7')
REVISION='3d23efef7c0f0b702c5024400cfff4c3744a3832'


def download():
    import requests
    import psutil
    import shutil
    OUT.mkdir(parents=True,exist_ok=True)
    if not (OUT/'official-api.json').exists():
        session=requests.Session();session.trust_env=False
        response=session.get(f'https://huggingface.co/api/datasets/joyce8/EMBER2024/revision/{REVISION}',params={'blobs':'true'},timeout=60)
        response.raise_for_status();write_once(OUT/'official-api.json',response.json())
    api=json.loads((OUT/'official-api.json').read_text())
    sources=[s for s in api['siblings'] if s['rfilename'] in ('Win32_test.zip','Win64_test.zip')]
    if len(sources)!=2 or sum(s['size'] for s in sources)>4000000000 or shutil.disk_usage('.').free<5000000000:
        raise RuntimeError('Archive/download storage budget failed')
    WORK.mkdir(parents=True,exist_ok=True)
    write_once(OUT/'protocol.json',{'created_at':datetime.now(timezone.utc).isoformat(),
        'model':get_model_metadata(),'threshold':DEFAULT_THRESHOLD,'revision':REVISION,
        'population':'Every record in official Win32_test.zip and Win64_test.zip, all12testweeks; no sampling',
        'scope':'Benchmark native categories; separate header-based application eligibility proxy and <=2MiB subset; no raw-byte validation claim',
        'no_training_or_tuning':True,'batch_size':256,'sources':sources,
        'resources':{'ram_available':psutil.virtual_memory().available,'disk_free':shutil.disk_usage('.').free},
        'timestamp':'Local write-once receipt, no independent timestamp authentication'})
    session=requests.Session();session.trust_env=False
    for s in sources:
        target=WORK/s['rfilename']
        url=f'https://huggingface.co/datasets/joyce8/EMBER2024/resolve/{REVISION}/'+s['rfilename']
        with session.get(url,stream=True,timeout=(30,120)) as response:
            response.raise_for_status()
            with target.open('xb') as stream:
                size=0
                for data in response.iter_content(1048576):
                    size+=len(data)
                    if size>s['size']:raise ValueError('Archive exceeded official size')
                    stream.write(data)
        assert target.stat().st_size==s['size'] and sha(target)==s['lfs']['sha256']
        print('Verified',target.name,flush=True)
    write_once(OUT/'source-lock.json',{'protocol_sha256':sha(OUT/'protocol.json'),
        'archives':{s['rfilename']:sha(WORK/s['rfilename']) for s in sources}})


def applicability(row):
    h=row.get('header') or {};coff=h.get('coff') or {};opt=h.get('optional') or {}
    native=(coff.get('machine'),opt.get('magic')) in {('IMAGE_FILE_MACHINE_I386',267),('IMAGE_FILE_MACHINE_AMD64',523)}
    clr=any(d.get('name')=='COM_DESCRIPTOR' and (d.get('size',0) or d.get('virtual_address',0)) for d in row['datadirectories'])
    return bool(native and not clr and opt.get('subsystem') in ('IMAGE_SUBSYSTEM_WINDOWS_GUI','IMAGE_SUBSYSTEM_WINDOWS_CUI'))


def evaluate():
    if (OUT/'evaluation-receipt.json').exists():raise RuntimeError('Evaluation already opened')
    lock=json.loads((OUT/'source-lock.json').read_text())
    assert lock['protocol_sha256']==sha(OUT/'protocol.json')
    for name,digest in lock['archives'].items():assert sha(ARCHIVES/name)==digest
    WORK.mkdir(parents=True,exist_ok=True)
    model=load_model();extractor=get_extractor()
    assert model.num_feature()==extractor.dim==DIMENSIONS==2568
    write_once(OUT/'evaluation-receipt.json',{'started_at':datetime.now(timezone.utc).isoformat(),
        'protocol_sha256':sha(OUT/'protocol.json'),'source_lock_sha256':sha(OUT/'source-lock.json'),
        'implementation_sha256':sha(__file__),'model':get_model_metadata()})
    start=time.perf_counter();batch=[];meta=[];seen=set();records=[];counts=Counter();weeks=Counter()
    def flush(stream):
        if not batch:return
        matrix=np.asarray(batch,dtype=np.float32)
        assert matrix.shape==(len(meta),DIMENSIONS) and np.isfinite(matrix).all()
        scores=model.predict(matrix,num_threads=2)
        for row,score in zip(meta,scores):
            assert np.isfinite(score) and 0<=score<=1
            row['score']=float(score);row['prediction']=int(score>=DEFAULT_THRESHOLD)
            records.append(row);stream.write(json.dumps(row)+'\n')
        batch.clear();meta.clear()
    with gzip.open(WORK/'predictions.jsonl.gz','xt',encoding='utf8') as output, gzip.open(WORK/'errors.jsonl.gz','xt',encoding='utf8') as errors:
        for archive in sorted(lock['archives']):
            with zipfile.ZipFile(ARCHIVES/archive) as zipped:
                for member in sorted(zipped.namelist()):
                    if member.endswith('/'):continue
                    if not member.endswith('.jsonl'):raise ValueError('Unexpected archive member')
                    with zipped.open(member) as source:
                        for number,line in enumerate(source,1):
                            counts['total']+=1
                            try:
                                row=json.loads(line);identifier=row['sha256']
                                if identifier in seen:counts['duplicate_identity_rows_retained']+=1
                                seen.add(identifier)
                                assert row['file_type']==archive.removesuffix('_test.zip') and row['label'] in (0,1)
                                vector=extractor.process_raw_features(row)
                                if vector.shape!=(DIMENSIONS,) or not np.isfinite(vector).all():raise ValueError('Feature compatibility failure')
                                proxy=applicability(row);size=row['general']['size'];weeks[str(row['week_id'])]+=1
                                batch.append(vector);meta.append({'sha256':identifier,'label':row['label'],'file_type':row['file_type'],
                                    'week':row['week_id'],'first_submission_date':row['first_submission_date'],
                                    'size':size,'entropy':row['general']['entropy'],'section_count':((row.get('header') or {}).get('coff') or {}).get('number_of_sections'),
                                    'import_count':sum(len(v) for v in row['imports'].values()),'app_header_proxy':proxy,
                                    'within_live_scope_proxy':proxy and size<=DEFAULT_MAX_BYTES})
                                if len(batch)==256:flush(output)
                            except Exception as exc:
                                counts['errors']+=1;errors.write(json.dumps({'archive':archive,'member':member,'line':number,'reason':str(exc)})+'\n')
                            if counts['total']%10000==0:print('Processed',counts['total'],'elapsed',round(time.perf_counter()-start),flush=True)
                    flush(output)
    import pandas as pd
    frame=pd.DataFrame(records)
    def metrics(f):return binary_metrics(f.label.to_numpy(),f.prediction.to_numpy(),f.score.to_numpy())
    overall=metrics(frame);per_type={t:metrics(f) for t,f in frame.groupby('file_type')}
    unique=frame.drop_duplicates('sha256')
    by_week={str(w):metrics(f) for w,f in frame.groupby('week')}
    false_positive={}
    for typ,f in frame[frame.label==0].groupby('file_type'):
        false_positive[typ]={}
        for pred,g in f.groupby('prediction'):
            false_positive[typ]['false_positive' if pred else 'true_negative']={'count':len(g),
                'quantiles':{c:np.quantile(g[c].dropna(),[.1,.5,.9,.99]).tolist() if g[c].notna().any() else None for c in ('score','size','entropy','section_count','import_count')},
                'missing_section_metadata':int(g.section_count.isna().sum())}
    from scripts.diagnose_issue6 import curves
    write_once(OUT/'curves.json',curves(frame.label.to_numpy(),frame.score.to_numpy()))
    scope={str(k):{'rows':len(f),'metrics':metrics(f)} for k,f in frame.groupby('within_live_scope_proxy')}
    size={str(k):{'rows':len(f),'malicious':int(f.label.sum()),'benign':int((f.label==0).sum())} for k,f in frame.groupby(frame['size']>DEFAULT_MAX_BYTES)}
    result={'model':get_model_metadata(),'threshold':DEFAULT_THRESHOLD,'overall':overall,'per_type':per_type,
        'unique_identity_metrics':metrics(unique),'duplicate_label_conflicts':int((frame.groupby('sha256').label.nunique()>1).sum()),
        'per_week':by_week,'weeks':dict(weeks),'record_counts':dict(counts),'false_positive_analysis':false_positive,
        'application_scope_proxy':scope,'over_2mib':size,'elapsed_seconds':time.perf_counter()-start,
        'predictions_sha256':sha(WORK/'predictions.jsonl.gz'),'complete':counts['total']==len(frame) and counts['errors']==0,
        'limitations':['Benchmark category metadata is not a substitute for the live structural PE gate',
            'Natural benchmark prevalence is not deployment prevalence','FP feature associations are descriptive, not causal',
            'No binaries downloaded; no training, calibration or threshold selection']}
    write_once(OUT/'metrics.json',result)
    print(json.dumps({'overall':overall,'per_type':per_type,'counts':dict(counts)},indent=2),flush=True)
    assert result['complete'],'Evaluation incomplete; see explicit error ledger'


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('stage',choices=['download','evaluate']);args=parser.parse_args()
    globals()[args.stage]()
