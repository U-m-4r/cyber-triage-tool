"""Prepare the declared demo before inference; never inspect predictions."""
import collections
import json
from pathlib import Path
import numpy as np
import pandas as pd
from ml.external_dataset_adapter import read_external_csv,adapt_frame
from ml.baseline import load_baseline
from ml.supervised_detector import load_supervised_detector
from scripts.acquire_external_dataset import RAW,sha


def main(output_root=None, scratch=None):
    root=Path('test-results/issue-4');scratch=Path(scratch or '.test-artifacts/issue4')
    output_root=Path(output_root or root);scratch.mkdir(parents=True,exist_ok=True);output_root.mkdir(parents=True,exist_ok=True)
    sources=json.loads((root/'dataset-manifest.json').read_text())['sources']
    models=[load_baseline(),load_supervised_detector()]
    counts=collections.Counter();demo=[];manifest=[]
    for source in sources:
        path=RAW/source['filename'];assert sha(path)==source['sha256']
        with read_external_csv(path,chunksize=25000) as reader:
            for frame in reader:
                x,labels,truth,_,_=adapt_frame(frame,require_labels=True)
                overflow=np.zeros(len(x),dtype=bool)
                for b in models:
                    a=b['scaler'].transform(x)
                    overflow|=~np.isfinite(a).all(axis=1)|(np.abs(a)>np.finfo(np.float32).max).any(axis=1)
                kept=x.index[~overflow]
                for label in sorted(labels.loc[kept].unique()):
                    candidates=kept[labels.loc[kept].eq(label)]
                    for index in candidates[:max(0,10-counts[(path.name,label)])]:
                        demo.append(frame.loc[index].drop(labels=['Label']).to_dict())
                        manifest.append({'demo_row':len(demo)-1,'filename':path.name,'source_row':int(index),'original_label':label,'binary_label':int(truth.loc[index])})
                        counts[(path.name,label)]+=1
    pd.DataFrame(demo).to_csv(scratch/'demo.csv',index=False)
    (scratch/'demo-labels.json').write_text(json.dumps(manifest,indent=2))
    summary={'selection':'first 10 eligible source rows per original label per day; before inference',
             'records':len(demo),'labels':dict(collections.Counter(r['original_label'] for r in manifest)),
             'csv_sha256':sha(scratch/'demo.csv'),'manifest_sha256':sha(scratch/'demo-labels.json')}
    (output_root/'demo-manifest-summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary,indent=2))


if __name__=='__main__':main()
