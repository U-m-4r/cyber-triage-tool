"""Lock two unused official capture days without opening their labels."""
from datetime import datetime, timezone
import json
from pathlib import Path
from urllib.parse import quote
import requests
from ml.network_experiment import sha, write_once, SCHEMA, RESULTS_DIR, WORK_DIR

ROOT = RESULTS_DIR
RAW = WORK_DIR/'raw'
SOURCES = {'Friday-16-02-2018_TrafficForML_CICFlowMeter.csv':333723605,
           'Friday-23-02-2018_TrafficForML_CICFlowMeter.csv':382840456}


def main():
    if (ROOT/'locked-test.json').exists():
        raise RuntimeError('Final sources already locked; refusing a new lock')
    RAW.mkdir(parents=True, exist_ok=True)
    session = requests.Session(); session.trust_env=False
    sources = []
    for name,size in SOURCES.items():
        url = 'https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/'+quote('Processed Traffic Data for ML Algorithms/'+name,safe='/')
        head=session.head(url,timeout=60);head.raise_for_status()
        assert int(head.headers['Content-Length'])==size
        target=RAW/name
        if not target.exists():
            temporary=target.with_suffix('.partial')
            with session.get(url,stream=True,timeout=(30,120)) as response:
                response.raise_for_status(); count=0
                with temporary.open('xb') as stream:
                    for data in response.iter_content(1048576):
                        count+=len(data)
                        if count>size:raise ValueError('Unexpected object size')
                        stream.write(data)
            assert count==size
            temporary.rename(target)
        assert target.stat().st_size==size
        item={'filename':name,'path':str(target),'url':url,'size_bytes':size,'sha256':sha(target),
              'etag':head.headers.get('ETag'),'last_modified':head.headers.get('Last-Modified')}
        sources.append(item); print(json.dumps(item),flush=True)
    write_once(ROOT/'locked-test.json', {'protocol_sha256':sha(ROOT/'PROTOCOL.md'),
        'locked_at':datetime.now(timezone.utc).isoformat(),'sources':sources,'feature_schema':SCHEMA,
        'label_access':'No CSV parsing or label access during byte acquisition and locking',
        'official_origin':'UNB/CIC official AWS public bucket; multipart ETag is not an authenticity signature'})


if __name__=='__main__':main()
