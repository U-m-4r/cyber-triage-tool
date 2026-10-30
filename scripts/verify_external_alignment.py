"""Independently reconstruct source identities and verify full saved-score decisions."""
import hashlib
import json
from pathlib import Path
import numpy as np
import pandas as pd
from ml.external_dataset_adapter import read_external_csv,adapt_frame
from ml.baseline import load_baseline,infer_network
from ml.supervised_detector import load_supervised_detector,infer_supervised_network
from scripts.acquire_external_dataset import RAW,sha
from evaluation.external_metrics import binary_metrics


def main():
    root=Path('test-results/issue-4');e=json.loads((root/'evaluation.json').read_text())
    work=Path('.test-artifacts/issue4')/e['run'];sources=json.loads((root/'dataset-manifest.json').read_text())['sources']
    models={'supervised':load_supervised_detector(),'baseline':load_baseline()}
    label_names=sorted(e['models']['supervised']['per_label']);label_codes={s:i for i,s in enumerate(label_names)}
    ids=[];days=[];codes=[];truths=[];samples=[];offset=0
    for day,source in enumerate(sources):
        path=RAW/source['filename'];assert sha(path)==source['sha256']
        with read_external_csv(path,chunksize=25000) as reader:
            for frame in reader:
                x,labels,truth,*_=adapt_frame(frame,require_labels=True)
                overflow=np.zeros(len(x),dtype=bool)
                for b in models.values():
                    a=b['scaler'].transform(x);overflow|=~np.isfinite(a).all(axis=1)|(np.abs(a)>np.finfo(np.float32).max).any(axis=1)
                x=x.loc[~overflow]
                if not len(x):continue
                ids.append(x.index.to_numpy(dtype=np.uint64));days.append(np.full(len(x),day,dtype=np.uint8))
                truths.append(truth.loc[x.index].to_numpy(dtype=np.int8));codes.append(labels.loc[x.index].map(label_codes).to_numpy(dtype=np.uint8))
                sample=x.iloc[:1].copy();sample.index=[offset];samples.append(sample);offset+=len(x)
    identity=np.concatenate(ids);day=np.concatenate(days);truth=np.concatenate(truths);code=np.concatenate(codes)
    np.savez_compressed(work/'source-row-index.npz',source_row=identity,day=day,binary_label=truth,original_label_code=code,label_names=np.asarray(label_names))
    checks={};sample=pd.concat(samples)
    for name,b in models.items():
        with np.load(work/(name+'-predictions.npz')) as saved:
            np.testing.assert_array_equal(saved['truth'],truth);np.testing.assert_array_equal(saved['day'],day)
            threshold=b.get('threshold_config',{}).get('threshold',0)
            decision=(saved['score']>=threshold).astype(int) if name=='supervised' else (saved['score']>0).astype(int)
            np.testing.assert_array_equal(saved['prediction'],decision)
            assert binary_metrics(truth,saved['prediction'],saved['score'])==e['models'][name]['overall']
            result=infer_supervised_network(sample,b) if name=='supervised' else infer_network(sample,b)
            score=result[2] if name=='supervised' else -result[2]
            pred=result[1] if name=='supervised' else (result[1]==-1).astype(int)
            np.testing.assert_array_equal(saved['prediction'][sample.index],pred)
            np.testing.assert_array_equal(saved['score'][sample.index],score)
        checks[name]={'source_labels_and_order':'EXACT_MATCH','all_frozen_threshold_decisions':'EXACT_MATCH','independent_metric_recomputation':'EXACT_MATCH',
                       'deterministic_direct_inference_sample_rows':len(sample),'direct_scores_and_predictions':'EXACT_MATCH',
                       'prediction_array_sha256':sha(work/(name+'-predictions.npz'))}
    report={'eligible_rows':len(truth),'source_row_identity_sha256':hashlib.sha256(identity.tobytes()).hexdigest(),
            'traceability_archive':str(work/'source-row-index.npz'),'traceability_sha256':sha(work/'source-row-index.npz'),
            'original_label_names':label_names,'original_label_counts':{s:int((code==i).sum()) for s,i in label_codes.items()},
            'checks':checks,'selection':'First eligible row of each fixed 25000-row source chunk; no prediction-based selection'}
    (root/'alignment-verification.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2))


if __name__=='__main__':main()
