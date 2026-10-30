"""Real external CSV -> selected frozen model -> owned MongoDB -> saved-case PDF."""
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
from ml.external_dataset_adapter import read_external_csv,adapt_frame
from ml.baseline import load_baseline,infer_network
from ml.supervised_detector import load_supervised_detector,infer_supervised_network
from ml.preprocessor import NETWORK_FEATURES
from evaluation.external_metrics import binary_metrics


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--serve',action='store_true');args=parser.parse_args()
    run=uuid.uuid4().hex;root=Path('test-results/issue-4');work=Path('.test-artifacts/issue4')/run;work.mkdir(parents=True)
    output=root/run;output.mkdir()
    source=Path('.test-artifacts/issue4/demo.csv');raw=read_external_csv(source);x,*_=adapt_frame(raw)
    labels=json.loads(Path('.test-artifacts/issue4/demo-labels.json').read_text());y=np.asarray([r['binary_label'] for r in labels])
    assert len(x)==len(labels)==len(raw)
    before=hashlib.sha256(source.read_bytes()).hexdigest()
    assert before==json.loads((root/'demo-manifest-summary.json').read_text())['csv_sha256']
    app=create_app({'TESTING':True,'APP_ENV':'test','DB_MODE':'mongo','MONGO_URI':'mongodb://127.0.0.1:27018',
                    'MONGO_DB':'cyber_triage_test_'+run,'TEMP_DIR':str(work/'uploads')})
    identity='/__issue4_'+run;app.add_url_rule(identity,'experiment_identity',lambda:run)
    with app.app_context():
        assert get_db().cases.count_documents({})==0
        get_db().test_ownership.insert_one({'_id':run});init_db()
    server=make_server('127.0.0.1',5049,app);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    session=requests.Session();session.trust_env=False;base='http://127.0.0.1:5049'
    assert session.get(base+identity,timeout=10).text==run
    results={}
    for detector in ['supervised','baseline']:
        response=session.post(base+'/api/cases',json={'title':'Issue 4 external CSE-CIC-IDS2018 '+detector},timeout=30);response.raise_for_status();case_id=response.json()['id']
        t=time.perf_counter()
        with source.open('rb') as stream:
            response=session.post(base+'/api/analyze',data={'caseId':case_id,'dataset':'cse-cic-ids2018','detector':detector},files={'file':(source.name,stream)},timeout=90)
        elapsed=time.perf_counter()-t;response.raise_for_status();payload=response.json();assert payload['persisted']
        if detector=='supervised':
            bundle=load_supervised_detector();_,pred,score,_=infer_supervised_network(x,bundle)
        else:
            bundle=load_baseline();_,p,margin,_,_=infer_network(x,bundle);pred=(p==-1).astype(int);score=margin
        artifact_response=session.get(base+'/api/artifacts',params={'case_id':case_id,'limit':100},timeout=30)
        artifact_response.raise_for_status();retrieved=artifact_response.json()['artifacts']
        assert len(retrieved)==len(x)
        ordered=sorted(retrieved,key=lambda r:r['record_id'])
        np.testing.assert_allclose([r['model_score'] for r in ordered],score,rtol=0,atol=1e-12)
        assert [r['binary_prediction'] for r in ordered]==np.where(pred==1,'ATTACK','BENIGN').tolist()
        for feature in NETWORK_FEATURES:
            np.testing.assert_array_equal([r[feature] for r in ordered],x[feature].to_numpy())
        assert all(r['model_id']==bundle['provenance']['model_id'] for r in ordered)
        assert payload['inference_metadata']['active_threshold']==bundle.get('threshold_config',{}).get('threshold',0)
        assert payload['inference_metadata']['external_dataset']['valid_rows']==len(x)
        case=session.get(base+'/api/cases/'+case_id,timeout=30).json()
        assert case['evidence']['sources'][0]['network_analysis']['model']['external_dataset']['compatibility']['dataset']=='CSE-CIC-IDS2018'
        history=session.get(base+'/api/ingestions',params={'case_id':case_id},timeout=30).json()
        assert history['ingestions'][0]['inference_metadata']['model_id']==bundle['provenance']['model_id']
        pdf=session.get(base+'/api/report/'+case_id,timeout=30);pdf.raise_for_status();(work/(detector+'.pdf')).write_bytes(pdf.content)
        from pypdf import PdfReader
        text=' '.join(' '.join(p.extract_text() for p in PdfReader(io.BytesIO(pdf.content)).pages).split())
        for token in ['CSE-CIC-IDS2018','CONDITIONALLY_COMPATIBLE',bundle['provenance']['model_id'],'no retraining']:
            assert token in text,token
        (work/(detector+'-pdf-text.txt')).write_text(text,encoding='utf-8')
        (work/(detector+'-full-api.json')).write_text(json.dumps(payload,indent=2))
        # Public review artifacts omit original source feature records.
        public={k:v for k,v in payload.items() if k!='artifacts'}
        public['artifact_predictions']=[{k:r[k] for k in ['record_id','source_row','model_id','model_score','decision_threshold','binary_prediction','risk_score','priority']} for r in ordered]
        (output/(detector+'-api.json')).write_text(json.dumps(public,indent=2))
        results[detector]={'case_id':case_id,'model_id':bundle['provenance']['model_id'],'summary':payload['summary'],
                           'http_seconds':elapsed,'timings':payload['timings'],'metrics':binary_metrics(y,pred,score if detector=='supervised' else -score),
                           'direct_inference_and_exact_feature_roundtrip':'PASS','persistence':'PASS','pdf':'PASS','pdf_sha256':hashlib.sha256(pdf.content).hexdigest(),'pdf_path':str(work/(detector+'.pdf'))}
    # Real missing-feature and frozen-threshold error paths.
    bad=raw.drop(columns=['Flow Duration']).to_csv(index=False).encode()
    response=session.post(base+'/api/analyze',data={'dataset':'cse-cic-ids2018','detector':'supervised'},files={'file':('missing-feature.csv',bad)},timeout=30)
    assert response.status_code==400;bad_response=response.json()
    response=session.post(base+'/api/analyze',data={'dataset':'cse-cic-ids2018','detector':'supervised','threshold':'.5'},files={'file':('external.csv',source.read_bytes())},timeout=30)
    assert response.status_code==400 and response.json()['error']['code']=='FROZEN_THRESHOLD_REQUIRED'
    assert hashlib.sha256(source.read_bytes()).hexdigest()==before
    summary={'run':run,'database':'cyber_triage_test_'+run,'records':len(x),'input_sha256_before':before,'input_sha256_after':before,
             'sampling':'first 10 eligible rows per original label per source, before predictions; scenario-balanced demo, not representative accuracy',
             'results':results,'missing_feature':bad_response,'threshold_override':response.json()}
    (output/'summary.json').write_text(json.dumps(summary,indent=2));(root/'demo-latest.json').write_text(json.dumps({'run':run,'output':str(output)},indent=2))
    print(json.dumps(summary,indent=2),flush=True)
    if args.serve:thread.join()
    else:server.shutdown()


if __name__=='__main__':main()
