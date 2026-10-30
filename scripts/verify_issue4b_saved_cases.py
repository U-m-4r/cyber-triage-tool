"""Read-only saved-case recheck; HTTP/PDF evidence is not browser verification."""
import hashlib
import io
import json
from pathlib import Path
import requests
from pymongo import MongoClient
from pypdf import PdfReader


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    root=Path('test-results/issue-4');out=root/'issue-4b';out.mkdir(exist_ok=True)
    saved=json.loads((root/'817fc3c335cf496fa7ff25a55b4ee01a/summary.json').read_text())
    protected=[root/'evaluation.json',Path('models/supervised_binary.joblib'),Path('models/cicids2017_baseline.joblib'),Path('models/pe/EMBER2024_PE.model')]
    before={str(p):digest(p) for p in protected}
    evaluation=json.loads((root/'evaluation.json').read_text())
    assert evaluation['models']['supervised']['overall']['confusion_matrix']['tp']==38
    assert evaluation['models']['supervised']['overall']['confusion_matrix']['fn']==286515
    assert evaluation['models']['baseline']['overall']['confusion_matrix']['tp']==174
    session=requests.Session();session.trust_env=False
    response=session.get('http://127.0.0.1:5049/api/health',timeout=20);response.raise_for_status()
    assert response.json()['mongo']=='connected'
    frontend=session.get('http://127.0.0.1:5219/',timeout=20);frontend.raise_for_status()
    mongo=MongoClient('mongodb://127.0.0.1:27018',serverSelectionTimeoutMS=5000)
    db=mongo[saved['database']];assert db.test_ownership.find_one({'_id':saved['run']})
    result={'browser_verification':'BLOCKED','screenshots_captured':[],
            'browser_tool_error':'Local browser use is disabled in Work settings.',
            'alternative_automation':'Not permitted: UI automation must use cua_repl; project frontend uses Node service tests, not browser automation.',
            'backend_health':response.json(),'frontend_http_status':frontend.status_code,
            'database':saved['database'],'cases':{}}
    work=Path('.test-artifacts/issue4b');work.mkdir(exist_ok=True)
    for detector,expected in saved['results'].items():
        case_id=expected['case_id'];original=json.loads((root/saved['run']/(detector+'-api.json')).read_text())
        rows=list(db.artifacts.find({'case_id':case_id},{'_id':0}).sort('record_id',1))
        assert len(rows)==saved['records']
        for row,old in zip(rows,original['artifact_predictions']):
            for key,value in old.items():assert row[key]==value,(detector,key)
        case_response=session.get('http://127.0.0.1:5219/api/cases/'+case_id,timeout=20);case_response.raise_for_status()
        case=case_response.json()
        assert case['evidence']['sources'][0]['network_analysis']['summary']==expected['summary']
        history=session.get('http://127.0.0.1:5219/api/ingestions',params={'case_id':case_id},timeout=20);history.raise_for_status()
        assert history.json()['ingestions'][0]['inference_metadata']['model_id']==expected['model_id']
        pdf=session.get('http://127.0.0.1:5049/api/report/'+case_id,timeout=30);pdf.raise_for_status()
        path=work/(detector+'-rechecked.pdf');path.write_bytes(pdf.content)
        reader=PdfReader(io.BytesIO(pdf.content));text=' '.join(' '.join(p.extract_text() for p in reader.pages).split())
        for token in [case_id,expected['model_id'],'CSE-CIC-IDS2018','CONDITIONALLY_COMPATIBLE','Flows: 60']:
            assert token in text,token
        result['cases'][detector]={'case_id':case_id,'model_id':expected['model_id'],'summary':expected['summary'],
            'artifact_fields_match_saved_api':'PASS','mongo_direct_read':'PASS','frontend_proxy_case_and_history':'PASS',
            'pdf_http_content_check':'PASS','pdf_pages':len(reader.pages),'pdf_path':str(path),'pdf_sha256':digest(path),
            'browser_upload_refresh_and_download':'NOT_VERIFIED'}
    mongo.close()
    after={str(p):digest(p) for p in protected};assert before==after
    result['protected_hashes_before']=before;result['protected_hashes_after']=after
    (out/'saved-case-recheck.json').write_text(json.dumps(result,indent=2))
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
