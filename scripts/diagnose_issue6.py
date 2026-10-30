"""Retrospective Issue 4 score diagnostics only; never deploy these thresholds."""
import json
from pathlib import Path
import numpy as np
from sklearn.metrics import roc_curve, precision_recall_curve
from ml.network_experiment import sha, write_once, operating_point, review_budgets

OUT=Path('test-results/issue-6');WORK=Path('.test-artifacts/issue6')


def downsample(values, maximum=1500):
    indices=np.unique(np.linspace(0,len(values)-1,min(maximum,len(values))).astype(int))
    return values[indices]


def curves(y, score):
    fpr,tpr,t=roc_curve(y,score)
    precision,recall,pr_t=precision_recall_curve(y,score)
    # Shared indices preserve each curve's paired coordinates.
    roc_i=np.unique(np.linspace(0,len(fpr)-1,min(1500,len(fpr))).astype(int))
    pr_i=np.unique(np.linspace(0,len(precision)-1,min(1500,len(precision))).astype(int))
    return {'roc':{'fpr':fpr[roc_i].tolist(),'recall':tpr[roc_i].tolist()},
            'pr':{'precision':precision[pr_i].tolist(),'recall':recall[pr_i].tolist()}}


def main():
    audit=json.loads(Path('test-results/issue-4/alignment-verification.json').read_text())
    original=json.loads(Path('test-results/issue-4/evaluation.json').read_text())
    work=Path('.test-artifacts/issue4')/original['run']
    output={'population':'Historical inspected Issue 4 days; retrospective diagnostic only',
            'production_unchanged':True,'samples':audit['eligible_rows'],'models':{}}
    curve_data={}
    for name in ('supervised','baseline'):
        path=work/(name+'-predictions.npz')
        assert sha(path)==audit['checks'][name]['prediction_array_sha256']
        data=np.load(path,allow_pickle=False);y=data['truth'];score=data['score'];prediction=data['prediction']
        # The archive already stores negative IF margin (higher = more anomalous).
        threshold=original['models'][name]['threshold']
        assert np.array_equal((score>=threshold).astype(int),prediction) if name=='supervised' else True
        entry={'archive_sha256':sha(path),'frozen_threshold':threshold,'historical_metrics':original['models'][name]['overall'],
               'score_quantiles':{},'retrospective_fpr_points':{},'top_k':review_budgets(y,score)}
        for label,binary in [('benign',0),('attack',1)]:
            values=score[y==binary]
            quantiles=[0,.01,.10,.25,.5,.75,.90,.99,1]
            entry['score_quantiles'][label]={str(q):float(np.quantile(values,q)) for q in quantiles}
        for budget in (.01,.05,.10):
            entry['retrospective_fpr_points'][str(budget)]=operating_point(y,score,budget)
        curve_data[name]=curves(y,score)
        if name=='supervised':
            bins=np.r_[0,np.geomspace(1e-7,1,80)]
        else:bins=np.linspace(score.min(),score.max(),81)
        entry['histogram']={'edges':bins.tolist(),**{label:np.histogram(score[y==binary],bins=bins)[0].tolist()
                            for label,binary in [('benign',0),('attack',1)]}}
        # Exact cumulative counts, then select presentation points. Never recommend
        # a test-selected operating point for production.
        order=np.argsort(score,kind='stable')[::-1];sorted_score=score[order]
        ends=np.r_[np.flatnonzero(np.diff(sorted_score)!=0),len(y)-1]
        tp=np.cumsum(y[order])[ends];fp=(ends+1)-tp
        indices=np.unique(np.linspace(0,len(ends)-1,min(200,len(ends))).astype(int))
        entry['threshold_sensitivity']=[{'threshold':float(sorted_score[ends[i]]),
            'recall':float(tp[i]/y.sum()),'fpr':float(fp[i]/(len(y)-y.sum())),
            'precision':float(tp[i]/(tp[i]+fp[i]))} for i in indices]
        output['models'][name]=entry
    write_once(OUT/'historical-diagnosis.json',output)
    write_once(OUT/'historical-curves.json',curve_data)
    print(json.dumps({name:{'quantiles':result['score_quantiles'],'top_k':result['top_k'],
                    'fpr_points':{b:p['metrics']['recall'] for b,p in result['retrospective_fpr_points'].items()}}
                      for name,result in output['models'].items()},indent=2))


if __name__=='__main__':main()
