"""Real held-out CSV -> selected detector -> owned MongoDB -> PDF verification."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import threading
import time
import uuid
import numpy as np
import requests
from werkzeug.serving import make_server
from backend.app import create_app
from backend.db import get_db,init_db
from ml.baseline import load_baseline,infer_network
from ml.supervised_detector import load_supervised_detector,infer_supervised_network
from ml.preprocessor import read_network_csv
from ml.preprocessor import NETWORK_FEATURES


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--serve',action='store_true')
    args=parser.parse_args()
    run=uuid.uuid4().hex
    output=Path('test-results/issue-3')/run
    output.mkdir(parents=True)
    source=Path('.test-artifacts/issue3/demo.csv')
    expected_manifest=json.loads(Path('test-results/issue-3/demo-source.json').read_text())
    before=hashlib.sha256(source.read_bytes()).hexdigest()
    assert before==expected_manifest['csv_sha256']
    data=read_network_csv(source)
    database='cyber_triage_test_'+run
    app=create_app({'TESTING':True,'APP_ENV':'test','DB_MODE':'mongo',
                    'MONGO_URI':'mongodb://127.0.0.1:27018','MONGO_DB':database,
                    'MODEL_PATH':str(Path('models/cicids2017_baseline.joblib').resolve()),
                    'TEMP_DIR':str(Path('.test-artifacts/issue3')/run/'uploads')})
    identity='/__issue3_'+run
    app.add_url_rule(identity,'experiment_identity',lambda:run)
    with app.app_context():
        assert get_db().cases.count_documents({})==0
        get_db().test_ownership.insert_one({'_id':run})
        init_db()
    server=make_server('127.0.0.1',5039,app)
    thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    session=requests.Session(); session.trust_env=False
    base='http://127.0.0.1:5039'
    assert session.get(base+identity,timeout=10).text==run
    inventory=session.get(base+'/api/model',timeout=30).json()
    assert all(inventory['models'][d]['available'] for d in ['baseline','supervised'])
    results=[]
    for detector in ('supervised','baseline'):
        case_response=session.post(base+'/api/cases',json={'title':'Issue 3 '+detector+' real held-out network flows'},timeout=30)
        case_response.raise_for_status(); case_id=case_response.json()['id']
        t=time.perf_counter()
        with source.open('rb') as stream:
            response=session.post(base+'/api/analyze',data={'caseId':case_id,'detector':detector},files={'file':(source.name,stream)},timeout=90)
        request_seconds=time.perf_counter()-t
        response.raise_for_status(); payload=response.json()
        assert payload['persisted'] and payload['summary']['total_records']==len(data)
        if detector=='supervised':
            bundle=load_supervised_detector(); _,pred,score,meta=infer_supervised_network(data,bundle)
            expected_decisions=np.where(pred==1,'ATTACK','BENIGN')
        else:
            bundle=load_baseline(); _,pred,score,_,_=infer_network(data,bundle)
            expected_decisions=np.where(pred==-1,'ATTACK','BENIGN')
        assert payload['inference_metadata']['model_id']==bundle['provenance']['model_id']
        assert payload['summary']['classified_attacks']==int((expected_decisions=='ATTACK').sum())
        assert payload['summary']['classified_benign']==int((expected_decisions=='BENIGN').sum())
        retrieved=session.get(base+'/api/artifacts',params={'case_id':case_id,'limit':100},timeout=30).json()['artifacts']
        assert len(retrieved)==len(data)
        ordered=sorted(retrieved,key=lambda r:r['record_id'])
        np.testing.assert_allclose([r['model_score'] for r in ordered],score,rtol=0,atol=1e-12)
        assert [r['binary_prediction'] for r in ordered]==expected_decisions.tolist()
        assert all(r['model_id']==bundle['provenance']['model_id'] for r in ordered)
        assert all(r['decision_threshold']==payload['inference_metadata']['active_threshold'] for r in ordered)
        for feature in NETWORK_FEATURES:
            np.testing.assert_array_equal([r[feature] for r in ordered],data[feature].to_numpy())
        assert payload['evidence']['sha256']==before
        case=session.get(base+'/api/cases/'+case_id,timeout=30).json()
        history=session.get(base+'/api/ingestions',params={'case_id':case_id},timeout=30).json()
        assert history['ingestions'][0]['inference_metadata']['model_id']==bundle['provenance']['model_id']
        report=session.get(base+'/api/report/'+case_id,timeout=30)
        report.raise_for_status()
        (output/(detector+'.pdf')).write_bytes(report.content)
        from pypdf import PdfReader
        text=' '.join(' '.join(p.extract_text() for p in PdfReader(io.BytesIO(report.content)).pages).split())
        assert bundle['provenance']['model_id'] in text
        assert 'Network analysis:' in text and 'Flows: '+str(len(data)) in text
        assert 'not accuracy or calibrated confidence' in text
        (output/(detector+'-pdf-text.txt')).write_text(text,encoding='utf-8')
        for name,value in [('upload',payload),('artifacts',retrieved),('case',case),('history',history)]:
            (output/(detector+'-'+name+'.json')).write_text(json.dumps(value,indent=2))
        results.append({'detector':detector,'case_id':case_id,'model_id':bundle['provenance']['model_id'],
                        'summary':payload['summary'],'timings':payload['timings'],'http_request_seconds':request_seconds,
                        'direct_inference_consistency':'PASS','persistence':'PASS','pdf_content':'PASS'})
    # Real incompatible evidence: remove a required feature from the actual CSV.
    broken=data.drop(columns=['Flow Duration']).to_csv(index=False).encode()
    response=session.post(base+'/api/analyze',data={'detector':'supervised'},files={'file':('missing-feature.csv',broken)},timeout=30)
    assert response.status_code==400
    invalid_response=response.json()
    original_path=app.config['SUPERVISED_MODEL_PATH']
    app.config['SUPERVISED_MODEL_PATH']=str(Path('.test-artifacts/issue3')/run/'absent.joblib')
    response=session.post(base+'/api/analyze',data={'detector':'supervised'},files={'file':(source.name,source.read_bytes())},timeout=30)
    assert response.status_code==503 and response.json()['error']['code']=='SUPERVISED_MODEL_MISSING'
    missing_response=response.json()
    app.config['SUPERVISED_MODEL_PATH']=original_path
    assert hashlib.sha256(source.read_bytes()).hexdigest()==before
    summary={'run':run,'database':database,'records':len(data),'input_bytes':source.stat().st_size,
             'csv_sha256_before':before,'csv_sha256_after':hashlib.sha256(source.read_bytes()).hexdigest(),
             'source_sampling':expected_manifest,'model_inventory':inventory,'results':results,
             'missing_features':invalid_response,'model_unavailable':missing_response,'output':str(output.resolve())}
    (output/'summary.json').write_text(json.dumps(summary,indent=2))
    print(json.dumps(summary,indent=2),flush=True)
    if args.serve:
        thread.join()
    else:
        server.shutdown()


if __name__=='__main__':
    main()
