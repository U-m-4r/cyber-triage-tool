"""Manual review server for the retained production-model demonstration only."""
import json
from pathlib import Path
from backend.app import create_app
from backend.db import get_db
from ml.network_experiment import repo_path


def main():
    latest=json.loads(Path('test-results/issue-6/demo-latest.json').read_text())
    summary=json.loads((repo_path(latest['output'])/'summary.json').read_text())
    app=create_app({'TESTING':True,'APP_ENV':'test','DB_MODE':'mongo','MONGO_URI':'mongodb://127.0.0.1:27018',
        'MONGO_DB':summary['database'],'TEMP_DIR':str(repo_path(latest['work'])/'manual-uploads')})
    with app.app_context():
        assert get_db().test_ownership.find_one({'_id':summary['run']}),'Owned test database marker missing'
    app.run(host='127.0.0.1',port=5079,debug=False,use_reloader=False)


if __name__=='__main__':main()
