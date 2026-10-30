"""Protocol and inference invariants; synthetic arrays are unit proof only."""
import json
from pathlib import Path
import numpy as np
import pandas as pd
import pytest

from ml.network_experiment import (SCHEMA, development_blocks, fingerprints, overlaps,
    operating_point, review_budgets, validate_features, write_once, deployment_gates, sha)


def test_feature_order_is_fixed_and_no_scaler_fit():
    frame=pd.DataFrame([np.arange(11)],columns=SCHEMA['columns'])
    assert np.array_equal(validate_features(frame),validate_features(frame[frame.columns[::-1]]))
    assert SCHEMA['preprocessing']=='identity-float32-no-fit'
    assert validate_features(frame).dtype==np.float32


@pytest.mark.parametrize('value',[np.nan,np.inf,-1,np.finfo(np.float64).max])
def test_candidate_rejects_incompatible_measurements(value):
    frame=pd.DataFrame(np.ones((1,11)),columns=SCHEMA['columns']);frame.iloc[0,0]=value
    with pytest.raises(ValueError):validate_features(frame)


def test_missing_features_not_imputed():
    with pytest.raises(ValueError):validate_features(pd.DataFrame({'wrong':[1]}))


def test_float32_and_near_duplicate_collision_purged_without_labels():
    x=np.ones((3,11));x[1,0]=1+1e-8;x[2,0]=1.0001
    assert fingerprints(x)[0]==fingerprints(x)[1]
    assert fingerprints(x,True)[0]==fingerprints(x,True)[2]
    assert overlaps(fingerprints(x),np.unique(fingerprints(x[:1]))).tolist()==[True,True,False]


def test_temporal_blocks_and_embargo_are_disjoint():
    ts=pd.Series(['22/02/2018 10:00:00','22/02/2018 10:01:00','22/02/2018 10:09:00',
                  '22/02/2018 10:10:00','22/02/2018 10:28:00','invalid'])
    train,val,excluded=development_blocks(ts)
    assert train.tolist()==[False,True,False,False,True,False]
    assert val.tolist()==[False,False,False,True,False,False]
    assert np.all(train.astype(int)+val.astype(int)+excluded.astype(int)==1)


def test_threshold_ties_cannot_spend_more_than_fpr_budget():
    y=np.array([0,0,0,0,1,1]);s=np.array([.8,.8,.1,.1,.8,.9])
    point=operating_point(y,s,.05)
    assert point['threshold']==.9 and point['metrics']['false_positive_rate']==0
    assert point['metrics']['recall']==.5
    with pytest.raises(ValueError):operating_point(np.ones(3),np.arange(3))


def test_reject_all_operating_point_is_available():
    point=operating_point([0,1],[1,0],0)
    assert point['threshold']>1 and point['metrics']['recall']==0


def test_top_k_does_not_break_ties_using_labels():
    result=review_budgets(np.array([1,0,1,0]),np.ones(4),(.5,))[0]
    assert result['k']==2 and result['tie_group_size']==4
    assert result['recall_lower_bound']==0 and result['recall_upper_bound']==1


def test_lock_cannot_be_overwritten(tmp_path):
    path=tmp_path/'sealed.json';write_once(path,{'selected':'first'})
    with pytest.raises(FileExistsError):write_once(path,{'selected':'changed'})
    assert json.loads(path.read_text())=={'selected':'first'}


def test_high_recall_alone_cannot_pass_deployment():
    result={'overall':{'recall':1,'false_positive_rate':1,'precision':.3,'balanced_accuracy':.5},
            'per_family':{'attack':{'binary_label':1,'samples':100,'recall':1}}}
    gates=deployment_gates(result,{'overall':{'recall':0}}, {'day':result},10000,.1)
    assert not gates['overall_fpr_at_most_5pct'] and not gates['every_day_fpr_at_most_5pct']
    assert not all(gates.values())


def test_executed_protocol_and_test_selection_lock():
    root=Path('test-results/issue-6')
    lock=json.loads((root/'locked-test.json').read_text())
    assert lock['protocol_sha256']==sha(root/'PROTOCOL.md')
    assert all('16-02-2018' in s['filename'] or '23-02-2018' in s['filename'] for s in lock['sources'])
    if (root/'selection.json').exists():
        selection=json.loads((root/'selection.json').read_text())
        assert selection['final_labels_accessed'] is False
        assert selection['lock_sha256']==sha(root/'locked-test.json')
        assert selection['protocol_sha256']==sha(root/'PROTOCOL.md')
