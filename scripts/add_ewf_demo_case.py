"""Persist real local EWF analysis through existing scoring/case persistence.

This is an owned demonstration CLI, not browser segmented upload support.
"""
import json
from pathlib import Path
from datetime import datetime,timezone
from backend.app import create_app,scorer
from backend.db import get_db
from backend.integration import persist_intake
from backend.screening import summarize
from forensics.disk_image import analyze_disk_image
from ml.network_experiment import sha,write_once


def main():
    latest=json.loads(Path('test-results/final-demo/latest.json').read_text());out=Path(latest['output']);work=Path(latest['work'])
    summary=json.loads((out/'summary.json').read_text())
    source=Path('.test-artifacts/issue8/controlled/controlled-ewf.E01');rules=Path('.test-artifacts/issue8/rules')
    app=create_app({'TESTING':True,'APP_ENV':'test','DB_MODE':'mongo','MONGO_URI':'mongodb://127.0.0.1:27018','MONGO_DB':summary['database'],'YARA_RULES_DIR':str(rules.resolve())})
    import time
    started=time.perf_counter();scan=analyze_disk_image(source,rules_dir=rules)
    scored=scorer.score_records(scan['findings'])
    custody={'original_filename':source.name,'sha256':sha(source),'size_bytes':source.stat().st_size,'ingested_at':datetime.now(timezone.utc).isoformat(),
        'source':'Local complete segmented EWF; not browser upload','segments':json.loads(Path('test-results/issue-8/ewf-integrity.json').read_text())}
    unified=summarize(source,custody,'disk_image',scored,app.config,disk=scan)
    client=app.test_client();response=client.post('/api/cases',json={'title':'Presentation local segmented E01 — not browser upload'});assert response.status_code==201
    case=response.json['id']
    with app.app_context():
        db=get_db();assert db.test_ownership.find_one({'_id':summary['run']})
        intake,stored=persist_intake(db,scored,case,custody,'disk_image',metadata={'disk_scan':scan,'screening_result':unified})
        assert db.artifacts.count_documents({'intake_id':intake})==stored
    reopened=client.get('/api/cases/'+case);assert reopened.status_code==200
    assert reopened.json['evidence']['sources'][0]['screening_result']==unified
    pdf=client.get('/api/report/'+case);assert pdf.status_code==200
    (work/'local-ewf.pdf').write_bytes(pdf.data)
    write_once(work/'local-ewf-api.json',unified)
    write_once(out/'local-ewf-summary.json',{'case_id':case,'stored':stored,'intake_id':intake,'source_sha256':custody['sha256'],
        'scan':scan,'screening':unified,'elapsed_seconds':time.perf_counter()-started,'workflow':'Local existing analysis/scoring/persist_intake; no segmented web upload','pdf':str(work/'local-ewf.pdf'),'mongo_roundtrip':'PASS'})
    print(case,stored)


if __name__=='__main__':main()
