"""Reopen already populated isolated demo cases; no inference or reseeding."""
import json
from pathlib import Path
from backend.app import create_app
from backend.db import get_db


def main():
    latest=json.loads(Path('test-results/final-demo/latest.json').read_text())
    summary=json.loads((Path(latest['output'])/'summary.json').read_text())
    app=create_app({'TESTING':True,'APP_ENV':'test','DB_MODE':'mongo','MONGO_URI':'mongodb://127.0.0.1:27018',
        'MONGO_DB':summary['database'],'TEMP_DIR':str(Path(latest['work'])/'manual-uploads'),
        'YARA_RULES_DIR':str((Path(latest['work'])/'fat12/rules').resolve())})
    with app.app_context():assert get_db().test_ownership.find_one({'_id':summary['run']})
    app.run(host='127.0.0.1',port=5109,debug=False,use_reloader=False)


if __name__=='__main__':main()
