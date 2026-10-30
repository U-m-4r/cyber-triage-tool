"""Verify retained production detector after challenger rejection, using real HTTP.

No failed challenger is exposed to application users. Separate owned test DB.
"""
import io
import json
from pathlib import Path
import threading
import time
import uuid

import numpy as np
import requests
from pypdf import PdfReader
from werkzeug.serving import make_server
from backend.app import create_app
from backend.db import get_db,init_db,close_db
from ml.network_experiment import sha
from ml.preprocessor import read_network_csv
from ml.supervised_detector import load_supervised_detector,infer_supervised_network
from ml.baseline import load_baseline,infer_network


def main():
    root=Path('test-results/issue-6');final=json.loads((root/'final-results.json').read_text())
    if final['deployment_eligible']:raise RuntimeError('A passing candidate needs optional deployment verification; this harness is for retained incumbents')
    run=uuid.uuid4().hex;work=Path('.test-artifacts/issue6')/run;work.mkdir()
    output=root/run;output.mkdir()
    database='cyber_triage_test_'+run
    app=create_app({'TESTING':True,'APP_ENV':'test','DB_MODE':'mongo','MONGO_URI':'mongodb://127.0.0.1:27018',
        'MONGO_DB':database,'MONGO_TIMEOUT_MS':10000,'TEMP_DIR':str(work/'uploads')})
    with app.app_context():
        assert get_db().cases.count_documents({})==0
        get_db().test_ownership.insert_one({'_id':run});init_db()
    server=make_server('127.0.0.1',5079,app);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    session=requests.Session();session.trust_env=False;base='http://127.0.0.1:5079'
    source=Path('.test-artifacts/issue3/demo.csv');before=sha(source)
    assert before==json.loads(Path('test-results/issue-3/demo-source.json').read_text())['csv_sha256']
    x=read_network_csv(source);results={}
    try:
        inventory=session.get(base+'/api/model',timeout=20);inventory.raise_for_status()
        assert 'challenger' not in inventory.json()['models']
        for detector in ('supervised','baseline'):
            case=session.post(base+'/api/cases',json={'title':'Issue 6 retained detector '+detector},timeout=30);case.raise_for_status();case_id=case.json()['id']
            started=time.perf_counter()
            with source.open('rb') as stream:
                response=session.post(base+'/api/analyze',data={'caseId':case_id,'detector':detector},files={'file':(source.name,stream)},timeout=90)
            response.raise_for_status();payload=response.json();elapsed=time.perf_counter()-started
            assert payload['persisted'] and payload['overall_scan_status']=='COMPLETED'
            if detector=='supervised':
                bundle=load_supervised_detector();_,pred,score,_=infer_supervised_network(x,bundle)
                expected=np.where(pred==1,'ATTACK','BENIGN').tolist()
            else:
                bundle=load_baseline();_,pred,score,_,_=infer_network(x,bundle)
                expected=np.where(pred==-1,'ATTACK','BENIGN').tolist()
            stored=session.get(base+'/api/artifacts',params={'case_id':case_id,'limit':100},timeout=30);stored.raise_for_status()
            rows=sorted(stored.json()['artifacts'],key=lambda r:r['record_id'])
            assert len(rows)==len(x)==84
            np.testing.assert_allclose([r['model_score'] for r in rows],score,rtol=0,atol=1e-12)
            assert [r['binary_prediction'] for r in rows]==expected
            assert all(r['model_id']==bundle['provenance']['model_id'] for r in rows)
            saved=session.get(base+'/api/cases/'+case_id,timeout=30);saved.raise_for_status()
            source_saved=saved.json()['evidence']['sources'][0]
            assert source_saved['screening_result']['screening']==payload['screening']
            with app.app_context():
                history=get_db().ingestions.find_one({'id':payload['intake_id']})
                assert history['screening_result']['screening']==payload['screening']
                assert get_db().artifacts.count_documents({'case_id':case_id,'evidence_sha256':before})==84
            pdf=session.get(base+'/api/report/'+case_id,timeout=60);pdf.raise_for_status()
            text=' '.join(' '.join(page.extract_text() for page in PdfReader(io.BytesIO(pdf.content)).pages).split())
            for token in (bundle['provenance']['model_id'],'Unified screening',before,'Flows: 84'):
                assert token in text,token
            (work/(detector+'.pdf')).write_bytes(pdf.content)
            (work/(detector+'-api.json')).write_text(json.dumps(payload,indent=2))
            public={k:v for k,v in payload.items() if k!='artifacts'}
            public['predictions']=[{k:r[k] for k in ('record_id','binary_prediction','model_score','decision_threshold','model_id','risk_score','priority')} for r in rows]
            (output/(detector+'-api.json')).write_text(json.dumps(public,indent=2))
            results[detector]={'case_id':case_id,'summary':payload['summary'],'model_id':bundle['provenance']['model_id'],
                'threshold':payload['inference_metadata']['active_threshold'],'direct_inference_consistency':'PASS',
                'mongo_roundtrip':'PASS','pdf':'PASS','pdf_sha256':__import__('hashlib').sha256(pdf.content).hexdigest(),
                'http_seconds':elapsed,'screening':payload['overall_scan_status']}
        assert sha(source)==before
        summary={'run':run,'database':database,'source_sha256_before':before,'source_sha256_after':sha(source),
            'source_selection':'Published first 12 source-order held-out rows per 2017 class, no prediction selection; not performance evaluation',
            'results':results,'retained_incumbents':True,'challenger_deployed':False,
            'browser':'UNVERIFIED: Local browser use is disabled in Work settings; no workaround or screenshot claim',
            'inventory':inventory.json()}
        (output/'summary.json').write_text(json.dumps(summary,indent=2))
        (root/'demo-latest.json').write_text(json.dumps({'run':run,'output':str(output),'work':str(work)},indent=2))
        print(json.dumps(summary,indent=2))
    finally:
        server.shutdown();thread.join();session.close();close_db(app)


if __name__=='__main__':main()
