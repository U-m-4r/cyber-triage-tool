"""Replay the fixed experiment into a fresh ignored directory, preserving reports.

This is reproduction on an already disclosed test, NOT another untouched test.
Requires the source datasets and native environment documented in REPORT.md.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

from ml.network_experiment import sha, write_once, repo_path


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--run',action='store_true',
        help='Actually refit the two candidates and reproduce already-disclosed final results')
    args=parser.parse_args()
    if not args.run:
        print('Pass --run to execute the bounded replay; results go to a fresh UUID under .test-artifacts/issue6/replays. No historical output is overwritten.')
        return
    source_root=Path('test-results/issue-6');lock=json.loads((source_root/'locked-test.json').read_text())
    run=uuid.uuid4().hex;root=Path('.test-artifacts/issue6/replays')/run
    output=root/'results';work=root/'work';output.mkdir(parents=True);(work/'raw').mkdir(parents=True)
    (output/'PROTOCOL.md').write_bytes((source_root/'PROTOCOL.md').read_bytes())
    for source in lock['sources']:
        original=repo_path(source['path']);assert sha(original)==source['sha256']
        # Hard links preserve disk space; all data consumers open evidence read-only.
        target=work/'raw'/source['filename'];os.link(original,target);source['path']=str(target)
    write_once(output/'locked-test.json',lock)
    write_once(output/'replay-notice.json',{'status':'REPRODUCTION_ONLY_ALREADY_DISCLOSED_TEST',
        'original_final_results_sha256':sha(source_root/'final-results.json'),
        'run':run,'no_claim_of_new_unseen_validation':True})
    environment={**os.environ,'ISSUE6_RESULTS_DIR':str(output.resolve()),'ISSUE6_WORK_DIR':str(work.resolve())}
    for module in ('prepare_issue6','train_issue6','evaluate_issue6'):
        with (output/(module+'.log')).open('x',encoding='utf-8') as log:
            subprocess.run([sys.executable,'-m','scripts.'+module],env=environment,
                           stdout=log,stderr=subprocess.STDOUT,check=True)
    original=json.loads((source_root/'final-results.json').read_text())
    reproduced=json.loads((output/'final-results.json').read_text())
    for name in ('incumbent','challenger'):
        assert original['models'][name]['overall']['confusion_matrix']==reproduced['models'][name]['overall']['confusion_matrix']
    print(json.dumps({'run':run,'output':str(output),'exact_confusion_reproduction':'PASS',
                      'status':'Already-disclosed test replay, not a new independent evaluation'},indent=2))


if __name__=='__main__':main()
