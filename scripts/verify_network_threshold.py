"""Reproduce validation-only threshold selection without changing any artifact."""
import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from ml.supervised_detector import load_supervised_detector,infer_supervised_network
from ml.cleaning import iter_eligible_chunks
from ml.preprocessor import NETWORK_FEATURES,prepare_network_frame
from ml.holdout import split_masks
from ml.thresholding import select_validation_threshold


def main():
    bundle=load_supervised_detector()
    truth=[]; scores=[]
    for chunk in iter_eligible_chunks('data/sample/cicids2017_cleaned.csv',usecols=lambda c:c.strip() in (*NETWORK_FEATURES,'Attack Type'),chunk_rows=50000):
        frame,_,_=prepare_network_frame(chunk)
        subset=frame.loc[split_masks(frame)['validation']]
        if len(subset):
            _,_,s,_=infer_supervised_network(subset,bundle)
            truth.extend((subset['Attack Type']!='Normal Traffic').astype(int))
            scores.extend(s)
    selected=select_validation_threshold(np.asarray(truth),np.asarray(scores),max_fpr=bundle['threshold_config']['max_fpr_constraint'],objective=bundle['threshold_config']['objective'],candidate_thresholds=200)
    assert selected['selected_threshold']==bundle['threshold_config']['threshold']
    assert selected['metrics']==bundle['threshold_config']['validation_metrics']
    test=pd.read_csv('.test-artifacts/issue3/heldout-test.csv',index_col='source_row',float_precision='round_trip')
    _,production,score,meta=infer_supervised_network(test,bundle)
    experiment=joblib.load('models/experiments/binary_xgboost.joblib')
    old_score=experiment.predict_proba(bundle['scaler'].transform(test[list(NETWORK_FEATURES)]))[:,1]
    result={'validation_rows':len(truth),'threshold_reproduced':selected,'saved_threshold':bundle['threshold_config']['threshold'],
             'experimental_threshold':0.5,'continuous_scores_identical_to_experimental':bool(np.array_equal(score,old_score)),
             'maximum_score_difference':float(np.max(np.abs(score-old_score))),
             'changed_test_decisions_due_to_threshold':int(np.sum(production!=(old_score>=.5))),
             'no_test_labels_used_for_threshold_selection':True,
             'limitation':'Historical candidate comparison inspected test results; future independent evaluation is needed for unbiased model-selection assessment.'}
    Path('test-results/issue-3/threshold-audit.json').write_text(json.dumps(result,indent=2))
    print(json.dumps(result,indent=2))


if __name__=='__main__':
    main()
