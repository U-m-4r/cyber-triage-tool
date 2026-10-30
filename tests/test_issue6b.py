"""Capture-day separation guards for local research, independent of model fitting."""
import pandas as pd
import pytest
from scripts.issue6b import assert_day_separation
from ml.network_experiment import validate_features
from ml.preprocessor import NETWORK_FEATURES


def test_reject_same_capture_in_training_and_validation():
    train=pd.DataFrame({'source':['same-day']})
    with pytest.raises(ValueError,match='Capture source overlap'):
        assert_day_separation(train,train,pd.DataFrame({'source':['calibration']}))


def test_reject_calibration_overlap():
    with pytest.raises(ValueError):
        assert_day_separation(pd.DataFrame({'source':['a']}),pd.DataFrame({'source':['b']}),pd.DataFrame({'source':['b']}))


def test_metadata_cannot_enter_feature_vector():
    frame=pd.DataFrame({c:[1.] for c in NETWORK_FEATURES})
    frame['source']='secret-capture';frame['Label']='Benign'
    before=validate_features(frame)
    frame['source']='another-day';frame['Label']='Attack'
    assert (before==validate_features(frame)).all()
