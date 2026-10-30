"""One-shot final comparison, only after validation selection has been sealed."""
from datetime import datetime, timezone
import gzip
import json
from pathlib import Path
import time

import numpy as np
import pandas as pd
from ml.external_dataset_adapter import adapt_frame
from ml.network_experiment import (sha, write_once, load_candidate, measured_result,
                                   deployment_gates, validate_features, fingerprints, RESULTS_DIR, WORK_DIR, repo_path)
from ml.supervised_detector import load_supervised_detector, infer_supervised_network
from scripts.prepare_issue6 import external_chunks
from scripts.diagnose_issue6 import curves

OUT=RESULTS_DIR;WORK=WORK_DIR


def main():
    if (OUT/'final-test-receipt.json').exists():
        raise RuntimeError('Final test already opened; refusing a second evaluation in this experiment')
    import psutil
    selection=json.loads((OUT/'selection.json').read_text());lock=json.loads((OUT/'locked-test.json').read_text())
    assert selection['protocol_sha256']==sha(OUT/'PROTOCOL.md')==lock['protocol_sha256']
    assert selection['lock_sha256']==sha(OUT/'locked-test.json')
    assert selection['prepared_sha256']==sha(OUT/'prepared.json')
    directory=WORK/'candidates'/selection['selected']
    assert selection['candidate_metadata_sha256']==sha(directory/'metadata.json')
    loading=time.perf_counter();predict,metadata=load_candidate(directory,selection['model_sha256'])
    loading=time.perf_counter()-loading
    original=load_supervised_detector()
    checkpoint=json.loads((OUT/'checkpoint.json').read_text())
    assert original['_artifact_sha256']==checkpoint['frozen_sha256']['models/supervised_binary.joblib']
    # Write receipt BEFORE opening labels. Existing receipt forbids re-evaluation.
    write_once(OUT/'final-test-receipt.json',{'selection_sha256':sha(OUT/'selection.json'),
        'protocol_sha256':sha(OUT/'PROTOCOL.md'),'locked_test_sha256':sha(OUT/'locked-test.json'),
        'started_at':datetime.now(timezone.utc).isoformat(),'policy':'One final-label evaluation; no model changes after this receipt',
        'model_sha256':selection['model_sha256'],'selected_threshold':selection['threshold']})
    started=time.perf_counter();elapsed={'incumbent':0.,'challenger':0.};quality={};peak=0
    ys=[];scores={'incumbent':[],'challenger':[]};days=[];codes=[];names=[];vectors=[];identities=[]
    prediction_dir=WORK/'final-chunks';prediction_dir.mkdir(exist_ok=False)
    with gzip.open(WORK/'final-exclusions.jsonl.gz','wt',encoding='utf-8') as ledger:
        for day,source in enumerate(lock['sources']):
            path=repo_path(source['path']);assert sha(path)==source['sha256']
            count={'source_rows':0,'eligible':0,'excluded':0,'reason_counts':{}}
            for chunk_number,chunk in enumerate(external_chunks(path,labels=True)):
                x,labels,truth,reasons,_=adapt_frame(chunk,require_labels=True)
                overflow=(x.to_numpy()>np.finfo(np.float32).max).any(axis=1)
                reasons.loc[x.index[overflow]]='float32_overflow';x=x.loc[~overflow]
                count['source_rows']+=len(chunk);count['eligible']+=len(x);count['excluded']+=len(chunk)-len(x)
                for index in reasons.index[reasons.ne('')]:
                    reason=reasons.loc[index]
                    count['reason_counts'][reason]=count['reason_counts'].get(reason,0)+1
                    ledger.write(json.dumps({'day':path.name,'source_row':int(index),'original_label':labels.loc[index],'reason':reason})+'\n')
                if x.empty:continue
                before=time.perf_counter();_,_,inc_score,_=infer_supervised_network(x,original)
                elapsed['incumbent']+=time.perf_counter()-before
                before=time.perf_counter();new_score=predict(x)
                elapsed['challenger']+=time.perf_counter()-before
                for values in (inc_score,new_score):
                    assert np.isfinite(values).all() and ((values>=0)&(values<=1)).all()
                kept_labels=labels.loc[x.index];code=np.empty(len(x),dtype=np.uint8)
                for label in sorted(kept_labels.unique()):
                    if label not in names:names.append(label)
                    code[kept_labels.to_numpy()==label]=names.index(label)
                y=truth.loc[x.index].to_numpy(dtype=np.int8)
                ys.append(y);scores['incumbent'].append(inc_score);scores['challenger'].append(new_score)
                days.append(np.full(len(x),day,dtype=np.uint8));codes.append(code)
                vectors.append(fingerprints(validate_features(x)));identities.append(x.index.to_numpy(dtype=np.int64))
                np.savez_compressed(prediction_dir/f'{day}-{chunk_number:04d}.npz',truth=y,incumbent=inc_score,
                    challenger=new_score,source_row=x.index.to_numpy(dtype=np.int64),family_code=code)
                peak=max(peak,psutil.Process().memory_info().rss)
            quality[path.name]=count;assert count['source_rows']==count['eligible']+count['excluded']
            print('Completed locked day',path.name,json.dumps(count),flush=True)
    y=np.concatenate(ys);day=np.concatenate(days);family=np.concatenate(codes);hashes=np.concatenate(vectors)
    del ys,days,codes,vectors
    thresholds={'incumbent':original['threshold_config']['threshold'],'challenger':selection['threshold']}
    results={};curve_data={}
    for name,parts in scores.items():
        score=np.concatenate(parts);parts.clear()
        result=measured_result(y,score,thresholds[name],family)
        result['per_family']={names[int(key)]:value for key,value in result['per_family'].items()}
        result['per_day']={source['filename']:measured_result(y[day==i],score[day==i],thresholds[name],family[day==i])
                           for i,source in enumerate(lock['sources'])}
        for record in result['per_day'].values():
            record['per_family']={names[int(key)]:value for key,value in record['per_family'].items()}
        result.update(model_id=original['provenance']['model_id'] if name=='incumbent' else metadata['model_id'],
            model_sha256=original['_artifact_sha256'] if name=='incumbent' else metadata['sha256'],
            inference_seconds=elapsed[name],records_per_second=len(y)/elapsed[name])
        curve_data[name]=curves(y,score)
        np.savez_compressed(WORK/(name+'-final.npz'),truth=y,score=score,day=day,family_code=family,
                            family_names=np.asarray(names),source_row=np.concatenate(identities))
        results[name]=result
    audit=pd.DataFrame({'vector':hashes,'label':y})
    groups=audit.groupby('vector')['label'].agg(['size','nunique'])
    duplicates={'population_rows':len(y),'unique_float32_vectors':len(groups),
                'duplicate_copies_retained':int((groups['size']-1).sum()),
                'conflicting_binary_label_groups_retained':int((groups['nunique']>1).sum())}
    gates=deployment_gates(results['challenger'],results['incumbent'],results['challenger']['per_day'],
        results['challenger']['records_per_second'],loading)
    write_once(OUT/'final-results.json',{'selection_sha256':sha(OUT/'selection.json'),
        'receipt_sha256':sha(OUT/'final-test-receipt.json'),'population':'All eligible rows on two locked, previously unused capture days',
        'models':results,'quality':quality,'duplicates':duplicates,'deployment_gates':gates,
        'deployment_eligible':all(gates.values()),'candidate_loading_seconds':loading,
        'elapsed_seconds':time.perf_counter()-started,'peak_observed_rss_bytes':max(peak,psutil.Process().memory_info().rss),
        'final_score_archives':{name:sha(WORK/(name+'-final.npz')) for name in results},
        'no_post_test_model_changes':True,
        'limitations':['Final labels untouched until sealed selection, but unlabeled test features informed duplicate quarantine',
            'Feature semantics conditional on CICFlowMeter family; same testbed may reuse hosts/sessions across days',
            'No independent bot scenario; development bot validation is within the known March 2 capture',
            '64-bit fingerprints and rounded-log bins are a conservative surrogate, not all possible near-duplicate relations']})
    write_once(OUT/'final-curves.json',curve_data)
    print(json.dumps({'metrics':{name:r['overall'] for name,r in results.items()},'gates':gates},indent=2),flush=True)


if __name__=='__main__':main()
