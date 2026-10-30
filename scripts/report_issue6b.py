"""Summarize actual local experiment, preserving previously published records."""
import json
from pathlib import Path
import numpy as np
import pandas as pd
from ml.network_experiment import sha,write_once,SCHEMA,fingerprints
from scripts.issue6b import OUT,WORK


def wilson(success,total):
    if not total:return None
    p=success/total;z=1.96;den=1+z*z/total
    mid=(p+z*z/(2*total))/den
    half=z*((p*(1-p)/total+z*z/(4*total*total))**.5)/den
    return [mid-half,mid+half]


def main():
    prepared=json.loads((OUT/'prepared.json').read_text())
    final=json.loads((OUT/'final-results.json').read_text())
    selected=json.loads((OUT/'selection.json').read_text())['selected']
    candidates=json.loads((OUT/'validation.json').read_text())
    diagnostics={}
    for part in ('train','validation','calibration'):
        a=np.load(WORK/(part+'.npz'),allow_pickle=False)
        x=a['x'];h=fingerprints(x)
        frame=pd.DataFrame({'source':a['source'],'family':a['family'],'h':h,'y':a['y']})
        groups=[]
        for (source,family),indices in frame.groupby(['source','family']).groups.items():
            indices=np.asarray(indices);vectors=x[indices]
            groups.append({'source':source,'family':family,'rows':len(indices),'unique_vectors':len(np.unique(h[indices])),
                'feature_quantiles':{c:np.quantile(vectors[:,i],[.1,.5,.9]).tolist() for i,c in enumerate(SCHEMA['columns'])}})
        labelgroups=frame.groupby('h').y.agg(['size','sum','nunique'])
        diagnostics[part]={'groups':groups,'ambiguous_groups':int((labelgroups['nunique']>1).sum()),
            'minimum_errors':int(np.minimum(labelgroups['sum'],labelgroups['size']-labelgroups['sum']).sum())}
    old=np.load('.test-artifacts/issue6/challenger-final.npz',allow_pickle=False)
    oldscore={str(f):{'count':int((old['family_code']==i).sum()),'score_quantiles':np.quantile(old['score'][old['family_code']==i],[.1,.5,.9]).tolist()} for i,f in enumerate(old['family_names'])}
    diagnostics['old_final_score_quantiles']=oldscore
    diagnostics['old_training_composition']=json.loads(Path('test-results/issue-6/prepared.json').read_text())['partitions']['train']['groups']
    ci={}
    # Ordinary Wilson intervals are descriptive: correlation/duplicate sessions invalidate IID coverage claims.
    for name in ('challenger','incumbent'):
        m=final[name]['overall'];cm=m['confusion_matrix']
        if isinstance(cm,list):tn,fp,fn,tp=np.asarray(cm).ravel()
        else:
            tn,fp,fn,tp=[cm[k] for k in ('tn','fp','fn','tp')]
        ci[name]={'fpr_wilson_iid_only':wilson(fp,tn+fp),'recall_wilson_iid_only':wilson(tp,tp+fn)}
    diagnostics['intervals']=ci
    write_once(OUT/'diagnostics.json',diagnostics)
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig,axes=plt.subplots(1,2,figsize=(11,4))
    for name in ('incumbent','challenger'):
        m=final[name]['overall'];axes[0].bar(name,m['recall']);axes[1].bar(name,m['false_positive_rate'])
    axes[0].set_title('Locked February15 recall');axes[1].set_title('Locked February15 false-positive rate');axes[1].axhline(.05,color='red',linestyle='--')
    fig.tight_layout();fig.savefig(OUT/'comparison.png',dpi=200);plt.close(fig)
    lines=['# Issue 6B — local controlled research','',
        '**No commits, pushes, merges, tags, releases or remote changes. Production models unchanged.**','',
        '## Protocol and provenance','',
        'Local protocol/hash receipts precede final access but lack independent authenticated timestamps. Four fixed fits: two algorithms × seeds42/43. No expanded features, hyperparameter search, calibration fitting or ensemble. All stages are local research only.',
        'Training uses the original 2017 train mask and March2; validation holds entire February22/16 days; separate February23 calibrates a conservative 1% empirical FPR threshold. Previously opened days are development, never new independent tests. Final February15 was not parsed or used for transductive filtering before selection. All eligible final rows and overlaps were retained.',
        'Official source: https://registry.opendata.aws/cse-cic-ids2018/ and https://www.unb.ca/cic/datasets/ids-2018.html . Use with official CIC citation/attribution. The existing adapter verifies feature mapping and units conditionally; exact extractor binary equivalence is unavailable.',
        '', 'Final source/hash: `'+json.loads((OUT/'locked-test.json').read_text())['sha256']+'` (375,945,899 bytes). Development hashes: development-sources.json. Protocol, code, preparation, selection and final receipts have separate SHA-256 links.',
        '', '## Measured diagnosis','',
        'Issue6 validation shared the same source/scenario days as training. Exact and rounded-bin quarantine did not establish scenario independence. Source/family quotas and balancing changed score semantics and prevalence. Precision depends on prevalence; prevalence alone does not explain an FPR change. A single causal explanation is not established.',
        'Old training had no explicitly labeled 2018 SlowHTTPTest examples; 2017 DoS is a broad merged category. Zero SlowHTTP recall therefore does not prove that all slow attacks are intrinsically indistinguishable. Diagnostics.json records per-partition family counts, unique vectors, quantiles and contradictory-vector minimum errors. Those lower bounds demonstrate observed representation ambiguity, not universal impossibility of the 11 features.',
        'New day separation, conservative calibration and both seed results test the former optimistic within-scenario validation. They do not make the already opened development days independently unseen. Capture-day independence is stronger than alternating blocks but cannot prove host/session independence.',
        '', '## Actual candidate validation','', '| Model | Seed | Recall | Precision | FPR | Threshold |','|---|---:|---:|---:|---:|---:|']
    for r in candidates:
        m=r['overall'];lines.append(f"| {r['name']} | {r['seed']} | {m['recall']:.6f} | {m['precision']:.6f} | {m['false_positive_rate']:.6f} | {r['threshold']:.12g} |")
    lines+=['','Selection uses worst-day validation recall, then AP, name/seed. Selected: '+selected['name']+' seed '+str(selected['seed'])+'. Seed spread is descriptive, not an exhaustive stability study. Full day/family/top-K metrics reside in validation.json. Training memory watchdog includes the actual process and child RSS; log values are sampled observations.',
        '', '## One-shot final comparison','', '| Model | Accuracy | Precision | Recall | F1 | FPR |','|---|---:|---:|---:|---:|---:|']
    for name in ('incumbent','challenger'):
        m=final[name]['overall'];lines.append('| '+name+' | '+' | '.join(f'{m[k]:.6f}' for k in ('accuracy','precision','recall','f1','false_positive_rate'))+' |')
    lines+=['','```json',json.dumps(final,indent=2),'```','',
        'ROC/PR coordinates: curves.json. Comparison chart: comparison.png. Confusion matrices, every family recall, all original gate outcomes, exclusions, throughput and ambiguity are actual execution outputs above. Only one final day was evaluated, so the per-day gate covers that day alone. No independent web/bot/SlowHTTPTest confirmation is claimed.',
        '', '## Deployment / limitations','',
        'Retain production detectors. No threshold/default/UI/API change is made. A newly qualifying binary test alone would not establish previously failed absent-family reliability. Prior Issue6 failures remain historical evidence. This experiment does not demonstrate generalization to independent real networks.',
        'Completion is PARTIAL: deployability requires the original gates and meaningful family coverage; see final-results.json. Browser remains UNVERIFIED: “Local browser use is disabled in Work settings.” No screenshots or new UI acceptance are claimed. Application integration for a new detector is conditional on qualification, and no challenger has been deployed.',
        '', '## Reproduction','',
        'Prerequisites: existing native environment plus requirements/network-research.txt and reviewed source files identified by development-sources.json. Raw/model/prediction files are preserved ignored under .test-artifacts/issue6b. Do not remove receipts to refit against opened labels. A reproduction needs a new local output namespace and must be labeled disclosed replay, never unseen validation.',
        'Original commands:','```powershell','rtk proxy .venv/Scripts/python.exe -m scripts.issue6b lock','rtk proxy .venv/Scripts/python.exe -m scripts.issue6b prepare','rtk proxy .venv/Scripts/python.exe -m scripts.issue6b train','rtk proxy .venv/Scripts/python.exe -m scripts.issue6b evaluate','rtk proxy .venv/Scripts/python.exe -m scripts.report_issue6b','rtk proxy .venv/Scripts/python.exe -m pytest -q --no-training --run-integration','rtk proxy npm --prefix frontend run check','rtk proxy .venv/Scripts/python.exe scripts/check.py','```','',
        'Current test execution and local-file manifest are recorded separately after checks finish. Existing private evidence is untouched. No Git mutation/publication is authorized or performed.']
    (OUT/'REPORT.md').write_text('\n'.join(lines)+'\n',encoding='utf8')


if __name__=='__main__':main()
