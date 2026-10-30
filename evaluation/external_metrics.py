"""Binary metrics with explicit single-class limitations and exact score ranking."""
import numpy as np
from sklearn.metrics import (accuracy_score,precision_score,recall_score,f1_score,
                             roc_auc_score,average_precision_score,confusion_matrix)


def binary_metrics(truth,prediction,score):
    y=np.asarray(truth,dtype=int); p=np.asarray(prediction,dtype=int); s=np.asarray(score,dtype=float)
    if not (len(y)==len(p)==len(s)) or not np.isfinite(s).all():
        raise ValueError('Aligned finite predictions and labels are required')
    if not np.isin(y,[0,1]).all() or not np.isin(p,[0,1]).all(): raise ValueError('Binary labels required')
    tn,fp,fn,tp=map(int,confusion_matrix(y,p,labels=[0,1]).ravel())
    both=bool(tn+fp) and bool(tp+fn)
    recall=tp/(tp+fn) if tp+fn else None
    specificity=tn/(tn+fp) if tn+fp else None
    return {'samples':len(y),'benign':tn+fp,'attack':tp+fn,
            'confusion_matrix':{'tn':tn,'fp':fp,'fn':fn,'tp':tp},
            'accuracy':float(accuracy_score(y,p)) if both else None,
            'precision':float(precision_score(y,p,zero_division=0)) if both else None,
            'recall':recall,'f1':float(f1_score(y,p,zero_division=0)) if both else None,
            'macro_f1':float(f1_score(y,p,average='macro',zero_division=0)) if both else None,
            'roc_auc':float(roc_auc_score(y,s)) if both else None,
            'average_precision':float(average_precision_score(y,s)) if both else None,
            'specificity':specificity,'false_positive_rate':1-specificity if specificity is not None else None,
            'false_negative_rate':1-recall if recall is not None else None,
            'balanced_accuracy':(recall+specificity)/2 if both else None,
            'status':'EVALUATED' if both else 'SINGLE_CLASS_LIMITED' if len(y) else 'EMPTY'}
