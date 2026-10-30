"""CSE-CIC-IDS2018 v1: explicit raw-feature mapping, no fitted transformations.

Definitions/units follow CICFlowMeter's historical source; exact dataset binary
revision is unavailable, so compatibility is conditional, not bitwise equivalence.
Ground-truth labels are returned separately and never enter the feature frame.
"""
import csv
from pathlib import Path
import numpy as np
import pandas as pd
from ml.preprocessor import NETWORK_FEATURES, NetworkInputError

ADAPTER_VERSION='cse-cic-ids2018-v1'
MAPPING=dict(zip(NETWORK_FEATURES,(
    'Flow Duration','Tot Fwd Pkts','TotLen Fwd Pkts','Fwd Pkt Len Max',
    'Fwd Pkt Len Min','Fwd Pkt Len Mean','Bwd Pkt Len Max','Bwd Pkt Len Min',
    'Flow Byts/s','Flow Pkts/s','Pkt Len Mean')))
LABELS={'Benign':0,'Bot':1,'Brute Force -Web':1,'Brute Force -XSS':1,'SQL Injection':1,
        'FTP-BruteForce':1,'SSH-Bruteforce':1,'DoS attacks-GoldenEye':1,
        'DoS attacks-Slowloris':1,'DoS attacks-SlowHTTPTest':1,'DoS attacks-Hulk':1,
        'DDOS attack-LOIC-UDP':1,'DDOS attack-HOIC':1,'DDoS attacks-LOIC-HTTP':1,
        'Infilteration':1}
UNITS={name:('microseconds' if name=='Flow Duration' else 'packets' if name=='Total Fwd Packets'
       else 'bytes/second' if name=='Flow Bytes/s' else 'packets/second' if name=='Flow Packets/s'
       else 'bytes') for name in NETWORK_FEATURES}


def validate_columns(columns, *, duration_unit='microseconds'):
    columns=[str(c).strip() for c in columns]
    if len(columns)!=len(set(columns)):
        raise NetworkInputError('Duplicate external CSV columns','AMBIGUOUS_EXTERNAL_SCHEMA')
    if duration_unit!='microseconds':
        raise NetworkInputError('External duration must be microseconds; no unit conversion is inferred','INCOMPATIBLE_UNITS')
    missing=[source for source in MAPPING.values() if source not in columns]
    ambiguous=[target for target,source in MAPPING.items() if source!=target and target in columns]
    if missing or ambiguous:
        raise NetworkInputError(f'External schema missing: {missing}; ambiguous target aliases: {ambiguous}','INCOMPATIBLE_EXTERNAL_SCHEMA')
    return {'adapter_version':ADAPTER_VERSION,'status':'CONDITIONALLY_COMPATIBLE',
            'dataset':'CSE-CIC-IDS2018','mapping':MAPPING,'units':UNITS,
            'limitations':'CICFlowMeter family definitions/units verified; exact generating binary/commit for both published datasets is not available. Version-specific flow/packet statistics may differ.',
            'values_changed':False,'threshold_changes':False}


def read_external_csv(path, chunksize=None):
    path=Path(path)
    with path.open(encoding='utf-8-sig',newline='') as stream:
        header=next(csv.reader(stream),[])
    validate_columns(header)
    # Keep original tokens, including NaN/Infinity, for an exact exclusion ledger.
    return pd.read_csv(path,dtype=str,keep_default_na=False,chunksize=chunksize)


def adapt_frame(frame, *, duration_unit='microseconds', require_labels=False):
    frame=frame.copy(deep=False); frame.columns=[str(c).strip() for c in frame.columns]
    compatibility=validate_columns(frame.columns,duration_unit=duration_unit)
    selected=frame.loc[:,list(MAPPING.values())].copy()
    selected.columns=list(NETWORK_FEATURES)
    numeric=selected.apply(pd.to_numeric,errors='coerce').astype('float64')
    values=numeric.to_numpy()
    text=selected.astype('string').apply(lambda c:c.str.strip())
    missing=(selected.isna().any(axis=1)|text.eq('').any(axis=1)).to_numpy()
    nan=text.apply(lambda c:c.str.lower().isin(['nan','+nan','-nan'])).any(axis=1).to_numpy()
    masks={'missing_measurement':missing,'nan_measurement':nan,
           'nonnumeric_measurement':np.isnan(values).any(axis=1)&~missing&~nan,
           'infinite_measurement':np.isinf(values).any(axis=1),
           'negative_measurement':((values<0)&np.isfinite(values)).any(axis=1)}
    labels=frame['Label'].astype(str).str.strip() if 'Label' in frame else pd.Series('',index=frame.index)
    truth=labels.map(LABELS)
    if require_labels: masks['unknown_label']=truth.isna().to_numpy()
    valid=~np.logical_or.reduce(list(masks.values()))
    reasons=pd.Series([';'.join(name for name,mask in masks.items() if mask[i]) for i in range(len(frame))],index=frame.index)
    report={'input_rows':len(frame),'valid_rows':int(valid.sum()),'excluded_rows':int((~valid).sum()),
            'reason_counts':{name:int(mask.sum()) for name,mask in masks.items()},
            'zero_duration_rows':int((numeric['Flow Duration']==0).sum()),
            'unknown_labels':labels[truth.isna()].value_counts().to_dict() if require_labels else {},
            'duplicates_policy':'retained; no prediction-dependent exclusions',
            'compatibility':compatibility}
    return numeric.loc[valid],labels,truth,reasons,report
