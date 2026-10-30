"""Descriptive full-source missingness and eligible feature moments; no fitting."""
import json
from pathlib import Path
import collections
import numpy as np
import pandas as pd
from ml.external_dataset_adapter import MAPPING,adapt_frame,read_external_csv
from ml.preprocessor import NETWORK_FEATURES
from scripts.acquire_external_dataset import RAW,sha


def main():
    root=Path('test-results/issue-4');manifest=json.loads((root/'dataset-manifest.json').read_text())
    feature_counts={};populations={}
    sources=[('CICIDS2017_internal_heldout',Path('.test-artifacts/issue3/heldout-test.csv'))]+[(s['filename'],RAW/s['filename']) for s in manifest['sources']]
    for name,path in sources:
        counts={feature:collections.Counter() for feature in NETWORK_FEATURES}
        moments={f:{'valid_count':0,'sum':0.,'minimum':np.inf,'maximum':-np.inf} for f in NETWORK_FEATURES}
        internal=name.startswith('CICIDS2017')
        if not path.exists():
            populations[name]={'status':'UNAVAILABLE','reason':'Verified internal held-out source absent'};continue
        if not internal:
            assert sha(path)==next(s['sha256'] for s in manifest['sources'] if s['filename']==name)
        reader=pd.read_csv(path,dtype=str,keep_default_na=False,chunksize=50000) if internal else read_external_csv(path,chunksize=50000)
        rows=0;eligible=0
        with reader:
            for frame in reader:
                if internal:
                    numeric=frame[list(NETWORK_FEATURES)].apply(pd.to_numeric,errors='coerce');x=numeric
                    selected=frame[list(NETWORK_FEATURES)]
                else:
                    x,*_=adapt_frame(frame,require_labels=True)
                    selected=frame[list(MAPPING.values())].copy();selected.columns=list(NETWORK_FEATURES)
                    numeric=selected.apply(pd.to_numeric,errors='coerce')
                rows+=len(frame);eligible+=len(x)
                for feature in NETWORK_FEATURES:
                    text=selected[feature].astype(str).str.strip();v=numeric[feature].to_numpy(dtype=float)
                    missing=text.eq('').to_numpy();nan=text.str.lower().isin(['nan','+nan','-nan']).to_numpy()
                    counts[feature].update(missing=int(missing.sum()),nan=int(nan.sum()),
                        nonnumeric=int((np.isnan(v)&~missing&~nan).sum()),infinite=int(np.isinf(v).sum()),
                        negative=int(((v<0)&np.isfinite(v)).sum()),zero=int((v==0).sum()))
                    a=x[feature].to_numpy(dtype=float)
                    if len(a):
                        m=moments[feature];m['valid_count']+=len(a);m['sum']+=float(a.sum());m['minimum']=min(m['minimum'],float(a.min()));m['maximum']=max(m['maximum'],float(a.max()))
        for feature,m in moments.items():
            m['mean']=m.pop('sum')/m['valid_count'] if m['valid_count'] else None
        feature_counts[name]={k:dict(v) for k,v in counts.items()}
        populations[name]={'status':'MEASURED','source_rows':rows,'eligible_rows':eligible,'moments_on_eligible_rows':moments}
    (root/'feature-quality.json').write_text(json.dumps({'scope':'Source-level required-feature missingness; descriptive means/min/max over objectively eligible rows, no refitted normalization/reference. Internal source is the saved Issue 3 held-out partition.',
        'quality_counts':feature_counts,'populations':populations},indent=2));print('Full source feature-quality comparison complete')


if __name__=='__main__':main()
