"""Acquire only the predeclared two official CSE-CIC-IDS2018 daily CSVs."""
import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import quote
import requests

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'test-results/issue-4'
RAW=ROOT/'.test-artifacts/issue4/raw'
SOURCES={'Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv':382636202,
         'Friday-02-03-2018_TrafficForML_CICFlowMeter.csv':352368373}
CHECKSUMS={'Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv':'da33c927018274f9d49b145baa00e4ce0526c25b3b890b34c489e247b5e24544',
           'Friday-02-03-2018_TrafficForML_CICFlowMeter.csv':'d96f38e7496aba83475031e6fb8c6fdf1abf6aa1b71325a917798f3c7de93de1'}
BASE='https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/'


def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1048576),b''): h.update(block)
    return h.hexdigest()


def main():
    RAW.mkdir(parents=True,exist_ok=True); OUT.mkdir(parents=True,exist_ok=True)
    manifest=[]
    for name,size in SOURCES.items():
        key='Processed Traffic Data for ML Algorithms/'+name
        url=BASE+quote(key,safe='/'); target=RAW/name
        head=requests.head(url,timeout=60);head.raise_for_status()
        assert int(head.headers['Content-Length'])==size
        if not target.exists():
            partial=target.with_suffix('.partial')
            with requests.get(url,stream=True,timeout=(30,120)) as response:
                response.raise_for_status(); total=0
                with partial.open('wb') as stream:
                    for block in response.iter_content(1048576):
                        total+=len(block)
                        if total>size: raise ValueError('Unexpected source size')
                        stream.write(block)
            assert partial.stat().st_size==size
            partial.rename(target)
        assert target.stat().st_size==size
        if sha(target)!=CHECKSUMS[name]:
            raise ValueError('Source differs from the originally measured official object; preserve it and review provenance before evaluation')
        item={'filename':name,'s3_uri':'s3://cse-cic-ids2018/'+key,'url':url,
              'size_bytes':size,'sha256':sha(target),'etag':head.headers.get('ETag'),
              'last_modified':head.headers.get('Last-Modified'),
              'verified_at':datetime.now(timezone.utc).isoformat()}
        manifest.append(item); print(json.dumps(item),flush=True)
    (OUT/'dataset-manifest.json').write_text(json.dumps({'dataset':'CSE-CIC-IDS2018',
        'official_documentation':'https://www.unb.ca/cic/datasets/ids-2018.html',
        'registry':'https://registry.opendata.aws/cse-cic-ids2018/',
        'etag_note':'Multipart ETags are object identifiers, not SHA-256 authenticity signatures; HTTPS official origin and locally measured SHA-256 are recorded.',
        'sources':manifest},indent=2))


if __name__=='__main__': main()
