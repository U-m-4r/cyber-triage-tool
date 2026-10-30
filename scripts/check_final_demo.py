"""Read-only pre-presentation acceptance; no ingestion, inference or DB writes.

Checks the actual running API, owned MongoDB, saved report backups and frozen
result sources. Every run writes a separate local receipt, preserving old proof.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time
from urllib.parse import urlparse
import uuid

from ml.network_experiment import repo_path, sha, write_once

ROOT=Path('test-results/final-demo')


def local_url(value):
    parsed=urlparse(value)
    if (parsed.scheme!='http' or parsed.hostname not in ('127.0.0.1','localhost')
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in ('','/')):
        raise argparse.ArgumentTypeError('Use a loopback HTTP origin without credentials or a path')
    return value.rstrip('/')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backend',type=local_url,default='http://127.0.0.1:5109')
    parser.add_argument('--frontend',type=local_url,default='http://127.0.0.1:5259')
    args=parser.parse_args()
    import requests
    from pymongo import MongoClient
    from pypdf import PdfReader
    run=uuid.uuid4().hex;started=time.perf_counter()
    receipt={'run':run,'started_at_utc':datetime.now(timezone.utc).isoformat(),
             'operation':'Read-only acceptance; no inference/ingestion/database writes',
             'checks':[],'status':'CHECKING'}
    def checked(name,details):
        receipt['checks'].append({'name':name,'status':'PASS','details':details})
        print(name,'PASS',flush=True)
    session=requests.Session();session.trust_env=False
    token=os.environ.get('CYBER_TRIAGE_API_TOKEN','')
    if token:session.headers['Authorization']='Bearer '+token
    client=None
    try:
        manifest=json.loads((ROOT/'case-manifest.json').read_text())
        if not manifest['database'].startswith('cyber_triage_test_'):
            raise ValueError('Refusing non-test database in demonstration manifest')
        client=MongoClient('mongodb://127.0.0.1:27018',serverSelectionTimeoutMS=5000)
        db=client[manifest['database']]
        assert db.test_ownership.find_one({'_id':manifest['run']}),'Owned database marker missing'
        checked('owned_mongodb',{'database':manifest['database'],'ownership_marker':True})
        def get(path):
            response=session.get(args.backend+path,timeout=30);response.raise_for_status()
            return response.json()
        health=get('/api/health');checked('backend_health',{'status':health.get('status')})
        response=session.get(args.frontend+'/evaluations',timeout=30);response.raise_for_status()
        checked('frontend',{'http':response.status_code})
        evaluation=get('/api/evaluations')
        assert len(evaluation['evaluations'])==5
        for group in evaluation['evaluations']:
            assert group['status']=='VERIFIED_SAVED_RESULT',group
            for source in [group,*group.get('supporting_sources',[])]:
                result=get(source['source_url'])
                assert result['provenance']['sha256']==source['provenance']['sha256']
        checked('saved_evaluation_provenance',{'groups':len(evaluation['evaluations']),
            'supporting_sources':sum(len(g['supporting_sources']) for g in evaluation['evaluations'])})
        pdf_checks=json.loads((ROOT/'pdf-verification.json').read_text())
        pages=0
        for entry in manifest['cases']:
            case_id=entry['case_id'];case=get('/api/cases/'+case_id)
            stored=db.artifacts.count_documents({'case_id':case_id})
            assert case['counts']['artifacts']==stored
            expected=entry.get('stored',entry.get('files_scanned'))
            assert stored==expected,(case_id,stored,expected)
            expected_hash=entry.get('sha256_before') or entry.get('source_sha256')
            sources=case['evidence']['sources'];assert sources
            assert any(s['sha256']==expected_hash for s in sources)
            saved=sources[0]['screening_result']
            assert saved['overall_scan_status'] in ('COMPLETED','PARTIAL')
            assert all('status' in module for module in saved['screening'].values())
            history=db.ingestions.find_one({'case_id':case_id})
            assert history and history['screening_result']==saved
            if entry['name']=='partial':
                assert saved['overall_scan_status']=='PARTIAL'
                assert saved['screening']['yara']['status']=='SKIPPED_LIMIT'
            if entry['name']=='unavailable':
                assert saved['screening']['yara']['status']=='UNAVAILABLE'
            if entry['name']=='pcap':
                assert saved['screening']['network_ml']['status']=='NOT_APPLICABLE'
            pdf=repo_path(entry['pdf_path'])
            assert sha(pdf)==pdf_checks[pdf.name]['sha256']
            reader=PdfReader(pdf);text=' '.join(page.extract_text() or '' for page in reader.pages)
            assert case_id in text and expected_hash in text
            assert saved['overall_scan_status'] in text
            pages+=len(reader.pages)
            checked(entry['name'],{'case_id':case_id,'records':stored,
                'scan_status':saved['overall_scan_status'],'evidence_sha256':expected_hash,
                'mongo_roundtrip':True,'pdf_pages':len(reader.pages),'pdf_sha256':sha(pdf)})
        receipt.update(status='PASS',case_count=len(manifest['cases']),pdf_pages_checked=pages)
    except Exception as exc:
        receipt.update(status='FAILED',error_type=type(exc).__name__,reason=str(exc))
        raise
    finally:
        receipt['processing_seconds']=time.perf_counter()-started
        write_once(ROOT/'acceptance-runs'/(run+'.json'),receipt)
        session.close()
        if client:client.close()
    print(json.dumps({'status':receipt['status'],'cases':receipt['case_count'],
        'pdf_pages':receipt['pdf_pages_checked'],'seconds':receipt['processing_seconds'],
        'receipt':str(ROOT/'acceptance-runs'/(run+'.json'))}),flush=True)


if __name__=='__main__':main()
