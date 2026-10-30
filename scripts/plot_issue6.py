"""Measured, labeled review figures; never invent model performance."""
import json
from pathlib import Path
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from ml.network_experiment import SCHEMA, RESULTS_DIR, WORK_DIR, repo_path

OUT=RESULTS_DIR;WORK=WORK_DIR


def save(fig,name):
    fig.tight_layout();fig.savefig(OUT/(name+'.png'),dpi=220,bbox_inches='tight');plt.close(fig)


def main():
    final=json.loads((OUT/'final-results.json').read_text());selection=json.loads((OUT/'selection.json').read_text())
    historical=json.loads((OUT/'historical-diagnosis.json').read_text())
    final_curves=json.loads((OUT/'final-curves.json').read_text());history_curves=json.loads((OUT/'historical-curves.json').read_text())
    models=final['models'];names=['incumbent','challenger'];n=models['incumbent']['overall']['samples']
    title=f'Locked CSE-CIC-IDS2018 capture days Feb 16/23; N={n:,}\nSelected {selection["selected"]} vs frozen XGBoost; thresholds sealed before final labels'
    colors=['#4b5563','#d56622'];plt.rcParams.update({'font.size':10,'axes.spines.top':False,'axes.spines.right':False})
    fig,axes=plt.subplots(1,2,figsize=(13,4.5))
    metrics=['accuracy','precision','recall','f1','balanced_accuracy'];x=np.arange(len(metrics))
    for i,name in enumerate(names):
        axes[0].bar(x+(i-.5)*.35,[models[name]['overall'][m] for m in metrics],.35,label=name,color=colors[i])
        axes[1].bar(i,models[name]['overall']['false_positive_rate'],color=colors[i])
    axes[0].set_xticks(x,[m.replace('_','\n') for m in metrics]);axes[0].set_ylim(0,1);axes[0].legend()
    axes[1].set_xticks([0,1],names);axes[1].axhline(.05,color='red',ls='--',label='Prespecified FPR gate 5%');axes[1].legend();axes[1].set_ylabel('False-positive rate')
    fig.suptitle(title);save(fig,'model-comparison')
    fig,axes=plt.subplots(1,2,figsize=(11,5))
    for ax,name in zip(axes,names):
        cm=models[name]['overall']['confusion_matrix'];a=np.array([[cm['tn'],cm['fp']],[cm['fn'],cm['tp']]])
        ax.imshow(np.log1p(a),cmap='Blues')
        for (i,j),v in np.ndenumerate(a):ax.text(j,i,f'{v:,}',ha='center',va='center',bbox={'facecolor':'white','alpha':.8,'edgecolor':'none'})
        ax.set_xticks([0,1],['Predicted benign','Predicted attack']);ax.set_yticks([0,1],['True benign','True attack']);ax.set_title(f"{name}: threshold {models[name]['threshold']:.6g}")
    fig.suptitle(title);save(fig,'confusion-matrices')
    fig,axes=plt.subplots(1,2,figsize=(12,5))
    for name,color in zip(names,colors):
        curve=final_curves[name];axes[0].plot(curve['roc']['fpr'],curve['roc']['recall'],label=name,color=color)
        axes[1].plot(curve['pr']['recall'],curve['pr']['precision'],label=name,color=color)
    axes[0].set(xlabel='False-positive rate',ylabel='Attack recall',xlim=(0,1),ylim=(0,1));axes[0].axvline(.05,ls='--',color='red')
    axes[1].set(xlabel='Recall',ylabel='Precision',xlim=(0,1),ylim=(0,1))
    for ax in axes:ax.legend();ax.grid(alpha=.2)
    fig.suptitle(title+'\nCurves descriptive only; no final-threshold tuning');save(fig,'final-roc-pr')
    families=[key for key,v in models['challenger']['per_family'].items() if v['binary_label']]
    fig,ax=plt.subplots(figsize=(12,5));x=np.arange(len(families))
    for i,name in enumerate(names):ax.bar(x+(i-.5)*.35,[models[name]['per_family'][f]['recall'] for f in families],.35,label=name,color=colors[i])
    ax.set_xticks(x,[f+f"\nN={models['challenger']['per_family'][f]['samples']:,}" for f in families]);ax.set_ylim(0,1);ax.set_ylabel('Binary attack recall (not family classification)');ax.legend()
    fig.suptitle(title);save(fig,'attack-family-recall')
    fig,ax=plt.subplots(figsize=(8,5))
    for name,color in zip(names,colors):
        rows=models[name]['top_k'];x=[r['fraction']*100 for r in rows]
        ax.plot(x,[r['recall_lower_bound'] for r in rows],marker='o',label=name,color=color)
        ax.fill_between(x,[r['recall_lower_bound'] for r in rows],[r['recall_upper_bound'] for r in rows],alpha=.2,color=color)
    ax.set(xlabel='Investigation budget (% of all flows)',ylabel='Attack recall',ylim=(0,1));ax.legend();ax.grid(alpha=.2)
    fig.suptitle(title+'\nShading: label-independent tie bounds');save(fig,'top-k-recall')
    fig,ax=plt.subplots(figsize=(8,5))
    bars=ax.bar(names,[models[name]['records_per_second'] for name in names],color=colors)
    for bar in bars:ax.text(bar.get_x()+bar.get_width()/2,bar.get_height(),f'{bar.get_height():,.0f}',ha='center',va='bottom')
    ax.set_ylabel('Flows / second; same chunked raw-feature population');ax.set_ylim(0,max(b.get_height() for b in bars)*1.2)
    fig.suptitle(title+'\nRecorded local CPU; transformation + inference timing');save(fig,'inference-throughput')
    h=historical['models']['supervised'];fig,axes=plt.subplots(1,3,figsize=(16,5))
    bins=np.asarray(h['histogram']['edges']);centers=np.sqrt(np.maximum(bins[:-1],1e-9)*np.maximum(bins[1:],1e-9))
    for name in ('benign','attack'):
        a=np.asarray(h['histogram'][name]);axes[0].plot(centers,a/a.sum(),label=name)
    axes[0].set_xscale('log');axes[0].axvline(h['frozen_threshold'],color='red',ls='--',label='Frozen threshold');axes[0].set(xlabel='Uncalibrated attack score (log)',ylabel='Within-class histogram mass');axes[0].legend()
    curve=history_curves['supervised'];axes[1].plot(curve['roc']['fpr'],curve['roc']['recall']);axes[1].axvline(.05,color='red',ls='--');axes[1].set(xlabel='False-positive rate',ylabel='Attack recall')
    axes[2].plot(curve['pr']['recall'],curve['pr']['precision']);axes[2].set(xlabel='Recall',ylabel='Precision')
    fig.suptitle(f'RETROSPECTIVE diagnosis only: Issue 4 inspected days Feb 22 / Mar 2; N={historical["samples"]:,}\nFrozen XGBoost; these labels/scores never select the new production threshold');save(fig,'historical-score-diagnosis')
    fig,axes=plt.subplots(1,2,figsize=(12,5));s=h['threshold_sensitivity']
    axes[0].plot([r['threshold'] for r in s],[r['recall'] for r in s],label='recall');axes[0].plot([r['threshold'] for r in s],[r['fpr'] for r in s],label='FPR');axes[0].set_xscale('log');axes[0].legend();axes[0].set_xlabel('Threshold (retrospective, not selected)')
    axes[1].plot([r['fraction']*100 for r in h['top_k']],[r['recall_lower_bound'] for r in h['top_k']],marker='o');axes[1].set(xlabel='Review budget (% flows)',ylabel='Lower-bound attack recall')
    fig.suptitle(f'Historical XGBoost threshold / workload sensitivity; inspected Issue 4 N={historical["samples"]:,}\nDescriptive diagnosis, not a deployment recommendation');save(fig,'historical-threshold-review')
    # Training-only bins, objective feature comparison with locked test features.
    train=np.load(WORK/'train.npz',allow_pickle=False)['x'];counts=[np.zeros(40,dtype=np.int64) for _ in range(11)]
    bins=[np.r_[-np.inf,np.linspace(0,float(np.log1p(train[:,i]).max()),39),np.inf] for i in range(11)]
    from scripts.prepare_issue6 import external_chunks
    from ml.external_dataset_adapter import adapt_frame
    lock=json.loads((OUT/'locked-test.json').read_text());total=0
    for source in lock['sources']:
        for frame in external_chunks(repo_path(source['path']),labels=False):
            x,*_=adapt_frame(frame);x=x.loc[(x.to_numpy()<=np.finfo(np.float32).max).all(axis=1)];total+=len(x)
            for i,column in enumerate(SCHEMA['columns']):counts[i]+=np.histogram(np.log1p(x[column].to_numpy()),bins[i])[0]
    fig,axes=plt.subplots(3,4,figsize=(15,10))
    for i,ax in enumerate(axes.flat):
        if i>=11:ax.axis('off');continue
        tr=np.histogram(np.log1p(train[:,i]),bins[i])[0]
        ax.plot(tr/len(train),label='training');ax.plot(counts[i]/total,label='locked final features');ax.set_title(SCHEMA['columns'][i]);ax.set_ylabel('Fraction in log1p bins')
    axes[0,0].legend();fig.suptitle(f'Feature distributions: candidate training N={len(train):,}; locked 2018 final N={total:,}\nTraining-only bin boundaries; eleven measured features; no final-label grouping or imputation');save(fig,'feature-distributions')


if __name__=='__main__':main()
