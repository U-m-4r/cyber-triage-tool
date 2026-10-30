"""Actual candidate loading/inference memory on validation data, no final rerun."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import threading
import time
import numpy as np
import pandas as pd
import psutil
from ml.network_experiment import SCHEMA,load_candidate,write_once


def worker(name):
    directory=Path('.test-artifacts/issue6/candidates')/name
    metadata=json.loads((directory/'metadata.json').read_text())
    process=psutil.Process();peak=[process.memory_info().rss];stop=threading.Event()
    def sample():
        while not stop.wait(.005):peak[0]=max(peak[0],process.memory_info().rss)
    thread=threading.Thread(target=sample,daemon=True);thread.start()
    started=time.perf_counter();predict,_=load_candidate(directory,metadata['sha256']);loaded=time.perf_counter()-started
    data=np.load('.test-artifacts/issue6/validation.npz',allow_pickle=False)
    frame=pd.DataFrame(data['x'],columns=SCHEMA['columns'])
    started=time.perf_counter();scores=predict(frame);elapsed=time.perf_counter()-started
    archived=np.load(directory/'validation.npz',allow_pickle=False)['score']
    np.testing.assert_allclose(scores,archived,rtol=0,atol=1e-12)
    peak[0]=max(peak[0],process.memory_info().rss);stop.set();thread.join()
    print(json.dumps({'candidate':name,'population':'Already used validation only; no final evaluation',
        'rows':len(frame),'loading_seconds':loaded,'inference_seconds':elapsed,'rows_per_second':len(frame)/elapsed,
        'observed_peak_inference_process_rss_bytes':peak[0],'poll_seconds':.005,
        'archive_score_consistency':'PASS','training_peak_memory':'NOT_MEASURED: initial launcher observer limitation documented separately'}))


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--worker');args=parser.parse_args()
    if args.worker:return worker(args.worker)
    results={}
    for name in ('xgboost','lightgbm'):
        response=subprocess.run([sys.executable,'-m','scripts.measure_issue6_candidates','--worker',name],capture_output=True,text=True,timeout=60)
        if response.returncode:raise RuntimeError(response.stderr)
        results[name]=json.loads(response.stdout)
    write_once('test-results/issue-6/candidate-performance.json',results)
    print(json.dumps(results,indent=2))


if __name__=='__main__':main()
