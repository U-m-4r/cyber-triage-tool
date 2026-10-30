"""Build presentation figures and report exclusively from actual saved results."""
import json
from pathlib import Path
import numpy as np
from ml.network_experiment import write_once
from scripts.evaluate_pe_test import OUT,WORK


def interval(k,n):
    if not n:return None
    z=1.96;p=k/n;d=1+z*z/n
    mid=(p+z*z/(2*n))/d;half=z*((p*(1-p)/n+z*z/(4*n*n))**.5)/d
    return [mid-half,mid+half]


def main():
    result=json.loads((OUT/'metrics.json').read_text());m=result['overall']
    import pandas as pd
    from evaluation.external_metrics import binary_metrics
    identities=pd.concat([chunk[['sha256','label','file_type','score','prediction']]
        for chunk in pd.read_json(WORK/'predictions.jsonl.gz',lines=True,chunksize=10000)],ignore_index=True)
    grouped=identities.groupby('sha256')
    unique=identities.drop_duplicates('sha256')
    unique_types={str(t):binary_metrics(g.label.to_numpy(),g.prediction.to_numpy(),g.score.to_numpy()) for t,g in unique.groupby('file_type')}
    identity_audit={'raw_rows':len(identities),'unique_identities':len(unique),'unique_per_type':unique_types,
        'multiplicity_distribution':{str(k):int(v) for k,v in grouped.size().value_counts().items()},
        'score_disagreement_groups':int((grouped.score.nunique()>1).sum()),
        'label_disagreement_groups':int((grouped.label.nunique()>1).sum()),
        'policy':'All original rows evaluated; unique metrics retain first archive/member/line observation, never select by score/label'}
    write_once(OUT/'unique-identity-analysis.json',identity_audit)
    del identities,grouped,unique
    challenge=json.loads(Path('test-results/issue-2/evaluation-v1/metrics.json').read_text())
    assert challenge['positive_examples']==4039 and challenge['confusion_matrix']['true_positive']==2730
    intervals={}
    for name,r in [('all',m),*result['per_type'].items()]:
        c=r['confusion_matrix'];intervals[name]={'recall':interval(c['tp'],c['tp']+c['fn']),
            'false_positive_rate':interval(c['fp'],c['tn']+c['fp'])}
    unique_intervals={}
    for name,r in [('all',result['unique_identity_metrics']),*unique_types.items()]:
        c=r['confusion_matrix'];unique_intervals[name]={'recall':interval(c['tp'],c['tp']+c['fn']),
            'false_positive_rate':interval(c['fp'],c['tn']+c['fp'])}
    write_once(OUT/'confidence-intervals.json',{'method':'95% Wilson binomial, descriptive IID assumption; not deployment guarantee','archive_row_groups':intervals,'unique_identity_groups':unique_intervals})
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    title=f"EMBER2024 official Win32/Win64 test; N={m['samples']:,}; frozen PE@425202786349; threshold=0.5"
    def save(fig,name):
        fig.suptitle(title,fontsize=9);fig.tight_layout(rect=(0,0,1,.92));fig.savefig(OUT/name,dpi=200);plt.close(fig)
    c=m['confusion_matrix'];matrix=[[c['tn'],c['fp']],[c['fn'],c['tp']]]
    fig,a=plt.subplots(figsize=(6,5));a.imshow(matrix,cmap='Blues')
    a.set(xticks=[0,1],yticks=[0,1],xticklabels=['Benign','Malicious'],yticklabels=['Benign','Malicious'],xlabel='Predicted',ylabel='Actual')
    for i in range(2):
        for j in range(2):a.text(j,i,f'{matrix[i][j]:,}',ha='center',va='center',color='red')
    save(fig,'confusion-matrix.png')
    fig,a=plt.subplots(figsize=(7,4));keys=['accuracy','precision','recall','f1'];a.bar(keys,[m[k] for k in keys]);a.set_ylim(0,1);save(fig,'binary-metrics.png')
    fig,a=plt.subplots(figsize=(8,4));x=np.arange(2);keys=['accuracy','precision','recall','f1','false_positive_rate']
    for i,k in enumerate(keys):a.bar(x+(i-2)*.15,[result['per_type'][t][k] for t in ('Win32','Win64')],width=.15,label=k)
    a.set_xticks(x,['Win32','Win64']);a.set_ylim(0,1);a.legend(fontsize=7);save(fig,'architecture-comparison.png')
    fig,a=plt.subplots(figsize=(7,4));a.bar(['Ordinary malware','Positive-only challenge'],[m['recall'],challenge['recall']]);a.set_ylim(0,1);a.set_ylabel('Malware recall')
    a.text(.5,.02,f"Challenge N=4,039; no benign examples; threshold0.5",transform=a.transAxes,ha='center',fontsize=8);save(fig,'ordinary-vs-challenge.png')
    frame=pd.concat([chunk.loc[chunk.label==0,['file_type','label','score']]
        for chunk in pd.read_json(WORK/'predictions.jsonl.gz',lines=True,chunksize=10000)],ignore_index=True)
    fig,a=plt.subplots(figsize=(8,4))
    for typ in ('Win32','Win64'):
        scores=frame.loc[(frame.file_type==typ)&(frame.label==0),'score']
        a.hist(scores,bins=np.linspace(0,1,51),histtype='step',label=f'{typ} benign N={len(scores):,}')
    a.set_yscale('log');a.axvline(.5,color='red',linestyle='--');a.set(xlabel='Uncalibrated model score',ylabel='Benign records (log)');a.legend();save(fig,'benign-score-distributions.png')
    curves=json.loads((OUT/'curves.json').read_text());fig,axes=plt.subplots(1,2,figsize=(10,4))
    axes[0].plot(curves['roc']['fpr'],curves['roc']['recall']);axes[0].set(xlabel='FPR',ylabel='Recall',title='ROC')
    axes[1].plot(curves['pr']['recall'],curves['pr']['precision']);axes[1].set(xlabel='Recall',ylabel='Precision',title='Precision–recall');save(fig,'roc-pr.png')
    lines=['# Issue7 — frozen PE classifier evaluation','',
        '## Model, features and dataset','',
        'Official sources: https://github.com/FutureComputing4AI/EMBER2024 and https://huggingface.co/datasets/joyce8/EMBER2024 . Dataset/model/code declare Apache-2.0. Cite Joyce et al., EMBER2024 — A Benchmark Dataset for Holistic Evaluation of Malware Classifiers, KDD2025. Model and extractor were pretrained/authored upstream, never retrained here.',
        'Exact deployed model: EMBER2024_PE.model; SHA256 `4252027863492ac138785c8c18576f43dad77d00faddc14e8c0072e8db419f99`; model revision e5b945dd90e1a1a1ec0cc07b3a17b52e9ba2d0c2. Frozen threshold0.5. Sigmoid score is not calibrated confidence.',
        'Extractor v3 at 0ef753e81d98bf209f71b03cd331dfc190b5b54d: 2568float32 values, original twelve-block order, official hashing/normalization; no extra scaling, padding, imputation or truncation. Production checksum/dependency checks and direct model dimensionality assertions ran. Missing or nonfinite vectors produce explicit evaluation errors, not substitutions.',
        'Full ordinary Win32 and Win64 test archives, revision3d23efef7c0f0b702c5024400cfff4c3744a3832. All12official testweeks, no sampling or prevalence balancing. Sources/source hashes and sizes: protocol.json and source-lock.json. All predictions preserve source identity, original label, week and first-submission date in the ignored ledger. Test labels never changed threshold or model. Benchmark prevalence is not deployment prevalence.',
        '', '## Actual binary results','', '| Population | N | Benign | Malicious | Accuracy | Precision | Recall | F1 | FPR |','|---|---:|---:|---:|---:|---:|---:|---:|---:|']
    for n,r in [('All',m),*result['per_type'].items()]:
        lines.append('| '+n+' | '+' | '.join(str(r[k]) for k in ('samples','benign','attack','accuracy','precision','recall','f1','false_positive_rate'))+' |')
    lines+=['',f"Malware prevalence: {m['attack']/m['samples']:.6f}. Complete metrics including balanced accuracy, specificity, FNR, ROC-AUC, AP and confusion matrices are in metrics.json. 95% Wilson recall/FPR intervals are in confidence-intervals.json. Correlation and sampling design limit nominal IID interval interpretation.",
        'Repeated sample identities are retained in archive-row metrics; unique_identity_metrics in metrics.json reports deterministic first-observation deduplication separately. Label-conflict counts are explicit. Repetitions do not constitute independent observations, so row-based intervals may overstate precision.',
        '', '## False positives and input-size coverage','',
        'False positives add review workload; they do not prove malware. false_positive_analysis in metrics.json compares benign FP/TN score, size, entropy, import-count and section-count quantiles separately by type. These feature associations are descriptive; no unknown binaries were obtained, inspected dynamically or executed. Architecture differences are reported without a causal claim or independent significance assertion.',
        'The live cap remains2MiB with a killable20-second worker. It is a conservative resource policy, not a model dimension limit. The benchmark intentionally measures larger files too; metrics.json reports size counts by label and a separate application-header/size proxy subset. Existing SKIPPED_TOO_LARGE statuses retain null predictions and partial coverage. No unsafe increase is justified merely by feature-only throughput. The metadata proxy cannot verify section bounds, full parse success, worker duration or raw-byte integrity; benchmark accuracy is not full live-upload coverage.',
        '', '## Ordinary versus challenge','',
        f"Ordinary malware recall: {m['recall']:.8f}. Preserved positive-only challenge: 2730/4039 detected, 1309missed, recall {challenge['recall']:.8f}. Challenge accuracy/precision/specificity/FPR are undefined without negatives. Evasive-challenge construction differs from ordinary testing; no ordinary result guarantees evasive detection. Harmless launcher demos verify inference integration, not malware ground truth.",
        '', '## Real disk-image / risk / persistence / reporting','',
        'Fresh verify_issue7 run creates a UUID-owned MongoDB and harmless FAT12 fixture. Two PyPA native launcher PEs are read through pytsk3, independently scanned by YARA and the actual classifier. Each model score matches direct extraction/inference, model identity and threshold are checked, MongoDB retrieval agrees, and original evidence SHA256 is unchanged. One separate harmless marker file matches YARA. Raw executables and PDFs stay ignored. Actual summary/upload/artifact/history/case records are under demo/. The genuine report was rendered on all pages, checked for off-page text, and its PE summary visually inspected. Browser interactions remain UNVERIFIED: Local browser use is disabled in Work settings.',
        'Risk review found the existing policy separates ML predictions, YARA and forensic indicators. Malicious PE prediction sets max(existing rule risk,50), a documented HIGH-review floor; no scores are added and benign/unavailable results cannot reduce existing risk. Model scores are neither per-file accuracy nor proof of malware. Network inference is unchanged.',
        '', '## Reproduction / slide notes','',
        'All commands use the existing pinned native environment. Data preparation is streaming with256-row batches; only feature JSON archives are downloaded. First-run commands:','```powershell',
        'rtk proxy .venv/Scripts/python.exe -m scripts.evaluate_pe_test download',
        'rtk proxy .venv/Scripts/python.exe -m scripts.evaluate_pe_test evaluate',
        'rtk proxy .venv/Scripts/python.exe -m scripts.verify_issue7',
        'rtk proxy .venv/Scripts/python.exe -m scripts.report_pe_test',
        'rtk proxy .venv/Scripts/python.exe -m pytest -q --no-training --run-integration',
        'rtk proxy npm --prefix frontend run check','rtk proxy .venv/Scripts/python.exe scripts/check.py','```',
        'Write-once protocol/receipt prevents overwriting this experiment. To reproduce, use a fresh output namespace in a separate checkout with the same verified sources; do not delete original receipts. No training or threshold selection is performed. All changes remain local, with no Git mutation or publication.',
        'Slide: LightGBM combines static file statistics and PE structure through boosted decision trees. A fixed threshold yields a prediction for review; YARA provides independent signature evidence. The model does not execute files. Present ordinary two-class performance, evasive challenge recall and harmless integration demonstrations separately.',
        '', '## Limitations / verification','',
        'Live scope is native I386 PE32/AMD64 PE32+ GUI/console only. .NET/ARM/drivers/EFI remain unsupported. Ordinary benchmark type metadata covers a broader group than byte-validated upload eligibility. Scores are uncalibrated. Dataset results do not establish new malware or real-world prevalence performance. Regression logs, final integrity checks and complete file inventory are recorded separately after execution. No historical network/PE results or Issue6B work are changed.']
    (OUT/'REPORT.md').write_text('\n'.join(lines)+'\n',encoding='utf8')


if __name__=='__main__':main()
