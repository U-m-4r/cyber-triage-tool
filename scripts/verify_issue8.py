"""Real controlled NTFS and EWF verification, local UUID-owned persistence."""
from pathlib import Path
import hashlib
import json
import time
import uuid
from forensics.disk_image import analyze_disk_image,ScanLimits
from ml.network_experiment import sha,write_once
from ml.pe_features import extract_features
from ml.pe_malware_detector import load_model,MODEL_ID,DEFAULT_THRESHOLD

ROOT=Path('test-results/issue-8');WORK=Path('.test-artifacts/issue8')


def main():
    run=uuid.uuid4().hex;out=ROOT/run;out.mkdir()
    controlled=WORK/'controlled';raw=controlled/'controlled.img'
    rules=WORK/'rules';rules.mkdir(exist_ok=True)
    rule=rules/'marker.yar'
    if not rule.exists():rule.write_text('rule Issue8_Harmless_Marker { meta: description="Harmless controlled NTFS test" severity="low" strings: $a="CYBER_TRIAGE_HARMLESS_TEST_MARKER_2026" condition: $a }')
    results={}
    paths=[raw]+sorted(controlled.glob('*.E01'))
    for path in paths:
        before=sha(path);start=time.perf_counter()
        scan=analyze_disk_image(path,rules_dir=rules)
        assert before==sha(path)
        files={r['FilePath']:r for r in scan['findings']}
        expected={'/nested/positive.txt':'positive.txt','/nested/negative.txt':'negative.txt','/empty.txt':'empty.txt','/nested/launcher.bin':'launcher.exe','/large.txt':'large.txt'}
        for name,source in expected.items():
            assert files[name]['sha256']==sha(controlled/source),(name,files[name])
        assert len(files['/nested/positive.txt']['yara_matches'])==1
        for name in ('/nested/negative.txt','/empty.txt','/nested/launcher.bin'):
            assert not files[name]['yara_matches']
        pe=files['/nested/launcher.bin']['pe_ml'];data=(controlled/'launcher.exe').read_bytes()
        score=float(load_model().predict(extract_features(data).reshape(1,-1),num_threads=1)[0])
        assert pe['status']=='CLASSIFIED' and abs(score-pe['model_score'])<1e-12
        assert pe['model_id']==MODEL_ID and pe['threshold']==DEFAULT_THRESHOLD
        assert files['/large.txt']['pe_ml']['status']=='NOT_APPLICABLE'
        results[path.name]={'sha256_before':before,'sha256_after':sha(path),'bytes':path.stat().st_size,'elapsed_seconds':time.perf_counter()-start,'scan':scan}
        write_once(out/(path.name+'.json'),results[path.name])
    limited=analyze_disk_image(raw,rules_dir=rules,limits=ScanLimits(max_file_bytes=100000,max_files=2))
    assert limited['scan_status']=='PARTIAL' and limited['files_skipped']>0
    write_once(out/'limited.json',limited)
    # Normal HTTP multipart ingestion, limits unchanged (64MiB fixture <128MiB).
    import requests,threading
    from werkzeug.serving import make_server
    from backend.app import create_app
    from backend.db import get_db,init_db
    db='cyber_triage_test_'+run
    app=create_app({'TESTING':True,'APP_ENV':'test','DB_MODE':'mongo','MONGO_URI':'mongodb://127.0.0.1:27018','MONGO_DB':db,
        'YARA_RULES_DIR':str(rules.resolve()),'TEMP_DIR':str((WORK/run/'uploads').resolve()),'MODEL_PATH':'missing.joblib'})
    with app.app_context():
        assert get_db().cases.count_documents({})==0
        get_db().test_ownership.insert_one({'_id':run,'purpose':'Issue8 controlled NTFS'})
        init_db()
    server=make_server('127.0.0.1',5098,app);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    session=requests.Session();session.trust_env=False;base='http://127.0.0.1:5098'
    try:
        response=session.post(base+'/api/cases',json={'title':'Issue8 genuine NTFS verification'},timeout=30);response.raise_for_status();case=response.json()['id']
        start=time.perf_counter()
        with raw.open('rb') as stream:
            response=session.post(base+'/api/forensics/ingest',data={'caseId':case},files={'file':(raw.name,stream)},timeout=180)
        response.raise_for_status();payload=response.json();api_seconds=time.perf_counter()-start
        assert payload['persisted'];assert payload['disk_scan']['pe_ml']['files_classified']==1
        response=session.get(base+'/api/artifacts',params={'case_id':case},timeout=30);response.raise_for_status();artifacts=response.json()['artifacts']
        found=next(r for r in artifacts if r['FilePath']=='/nested/launcher.bin')
        assert found['pe_ml']['model_score']==score
        assert found['sha256']==sha(controlled/'launcher.exe')
        for name,obj in [('api',payload),('artifacts',artifacts),('case',session.get(base+'/api/cases/'+case,timeout=30).json())]:write_once(out/(name+'.json'),obj)
        pdf=session.get(base+'/api/report/'+case,timeout=60);pdf.raise_for_status()
        pdfpath=WORK/run/'report.pdf';pdfpath.parent.mkdir(exist_ok=True);pdfpath.write_bytes(pdf.content)
        from pypdf import PdfReader
        import io
        text=' '.join(p.extract_text() for p in PdfReader(io.BytesIO(pdf.content)).pages)
        for term in ('launcher.bin','Issue8_Harmless_Marker',MODEL_ID):assert term in text
        write_once(out/'summary.json',{'run':run,'case_id':case,'database':db,'api_end_to_end_seconds':api_seconds,'image_integrity':sha(raw)==results[raw.name]['sha256_before'],
            'pdf':str(pdfpath),'pdf_content':'PASS','mongo':'PASS','direct_pe_score':score,'outputs':str(out)})
        print(json.dumps({'run':run,'case':case,'out':str(out),'raw_status':results[raw.name]['scan']['scan_status'],'containers_tested':list(results)},indent=2),flush=True)
    finally:server.shutdown()


if __name__=='__main__':main()
