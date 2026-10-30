"""Publication figures derived solely from the executed frozen-model JSONs."""
import json
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

ROOT=Path('test-results/issue-4')
NAMES={'supervised':'Production XGBoost','baseline':'Isolation Forest'}


def save(fig,name):
    fig.savefig(ROOT/(name+'.png'),dpi=220,bbox_inches='tight')
    plt.close(fig)


def main():
    external=json.loads((ROOT/'evaluation.json').read_text())['models']
    internal=json.loads(Path('test-results/issue-3/evaluation.json').read_text())['models']
    quality=json.loads((ROOT/'data-quality.json').read_text())
    n=external['supervised']['overall']['samples']
    condition=f'CSE-CIC-IDS2018 selected two days · n={n:,}\nXGBoost + Isolation Forest · frozen 2017 scalers/thresholds; conditional compatibility'
    plt.rcParams.update({'font.size':10,'axes.spines.top':False,'axes.spines.right':False})
    fig,axes=plt.subplots(1,2,figsize=(12,5),layout='constrained')
    metrics=['accuracy','precision','recall','f1','roc_auc','balanced_accuracy'];positions=np.arange(len(metrics))
    for axis,(key,name) in zip(axes,NAMES.items()):
        a=dict(internal[name]['metrics']);b=external[key]['overall']
        a['balanced_accuracy']=(a['recall']+1-a['fpr'])/2
        axis.bar(positions-.18,[a[k] for k in metrics],.36,label='CICIDS2017 internal (n=345,892)')
        bars=axis.bar(positions+.18,[b[k] for k in metrics],.36,label=f'2018 external (n={n:,})')
        axis.bar_label(bars,labels=[f'{b[k]:.3%}' for k in metrics],rotation=90,padding=3,fontsize=8)
        axis.set(xticks=positions,xticklabels=['Accuracy','Precision','Recall','F1','ROC-AUC','Balanced acc.'],ylim=(0,1.17),title=name,ylabel='Metric (0–1)')
        axis.tick_params(axis='x',rotation=25);axis.legend(fontsize=8)
    fig.suptitle('Different populations and class prevalence; not a controlled accuracy comparison\n'+condition,fontsize=11)
    fig.supxlabel('Accuracy=(TP+TN)/N; precision=TP/(TP+FP); recall=TP/(TP+FN); F1=2PR/(P+R); balanced accuracy=(recall+specificity)/2; AUC=ranking discrimination',fontsize=7)
    save(fig,'internal-vs-external')
    fig,axes=plt.subplots(1,2,figsize=(11,5),layout='constrained')
    for axis,(key,name) in zip(axes,NAMES.items()):
        c=external[key]['overall']['confusion_matrix'];m=np.array([[c['tn'],c['fp']],[c['fn'],c['tp']]])
        axis.imshow(m,cmap='Blues')
        for (i,j),v in np.ndenumerate(m):axis.text(j,i,f'{v:,}',ha='center',va='center',color='white' if v>m.max()/2 else 'black')
        axis.set(xticks=[0,1],yticks=[0,1],xticklabels=['Benign','Attack'],yticklabels=['Benign','Attack'],xlabel='Predicted binary class',ylabel='Original binary label',title=name)
    fig.suptitle('Confusion counts · '+condition,fontsize=11);save(fig,'external-confusion')
    labels=[label for label,v in external['supervised']['per_label'].items() if v['binary_label']==1]
    fig,axis=plt.subplots(figsize=(10,6),layout='constrained');positions=np.arange(len(labels))
    for offset,(key,name) in zip([-.18,.18],NAMES.items()):
        values=[external[key]['per_label'][label]['attack_recall'] for label in labels]
        bars=axis.barh(positions+offset,values,.36,label=name)
        axis.bar_label(bars,labels=[f'{v:.3%}' for v in values],padding=3,fontsize=8)
    ticks=[f"{label} (n={external['supervised']['per_label'][label]['samples']:,})" for label in labels]
    axis.set(yticks=positions,yticklabels=ticks,xlim=(0,1.05),xlabel='Attack recall = detected / original attack examples',title=condition)
    axis.legend();save(fig,'attack-family-recall')
    fig,axis=plt.subplots(figsize=(10,5),layout='constrained');positions=np.arange(4);names=[];fpr=[];fnr=[]
    for key,name in NAMES.items():
        for dataset,m in [('2017 internal',internal[name]['metrics']),('2018 external',external[key]['overall'])]:
            names.append(name+'\n'+dataset);fpr.append(m.get('fpr',m.get('false_positive_rate')));fnr.append(m.get('fnr',m.get('false_negative_rate')))
    axis.bar(positions-.18,fpr,.36,label='FPR = FP / benign');axis.bar(positions+.18,fnr,.36,label='FNR = FN / attack')
    axis.set(xticks=positions,xticklabels=names,ylim=(0,1),ylabel='Error rate',title=condition+'\n2017 internal n=345,892');axis.legend();save(fig,'false-positive-negative-rates')
    label_counts={}
    for day,v in quality.items():
        for label,count in v['valid_labels'].items():label_counts[label]=label_counts.get(label,0)+count
    fig,axis=plt.subplots(figsize=(10,5),layout='constrained');axis.barh(list(label_counts),list(label_counts.values()))
    axis.set(xlabel='Eligible source-record count (duplicates retained)',title=condition+'\nClass composition shared by both models')
    for i,v in enumerate(label_counts.values()):axis.text(v,i,f' {v:,}',va='center')
    axis.margins(x=.2);save(fig,'class-distribution')
    drift=json.loads((ROOT/'drift.json').read_text())
    features=['Flow Duration','Total Fwd Packets','Packet Length Mean','Flow Bytes/s']
    fig,axes=plt.subplots(2,2,figsize=(12,8),layout='constrained')
    for axis,feature in zip(axes.flat,features):
        f=drift['baseline']['features'][feature];positions=np.arange(len(f['proportions']))
        counts=np.asarray(f['observed_counts']);axis.bar(positions-.18,f['proportions'],.36,label='Frozen 2017 benign-training reference (n=1,051,117)')
        axis.bar(positions+.18,counts/counts.sum(),.36,label=f'2018 eligible external (n={n:,})')
        axis.set(title=f"{feature} · PSI={f['psi']:.3f}",xlabel='Saved training-bin index (increasing raw units)',ylabel='Fraction of flows');axis.legend(fontsize=7)
    fig.suptitle('Measured distribution shifts\n'+condition,fontsize=11)
    fig.supxlabel('PSI = sum((observed fraction − reference fraction) × ln(observed/reference)); saved bin boundaries, no refitting',fontsize=8)
    save(fig,'feature-distribution-shifts')
    print('Six measured high-resolution figures generated')


if __name__=='__main__':main()
