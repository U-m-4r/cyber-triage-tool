"""Frozen-artifact regressions; synthetic inputs here are unit probes, not demos."""
import io
import numpy as np
import pandas as pd
import pytest
from ml.baseline import load_baseline, infer_network
from ml.preprocessor import NETWORK_FEATURES
from ml.risk_scorer import RiskScorer
from scripts import benchmark_supervised as benchmark


def test_benchmark_baseline_receives_raw_once(monkeypatch,tmp_path):
    bundle=load_baseline()
    raw=pd.DataFrame([bundle['scaler'].mean_,bundle['scaler'].mean_+bundle['scaler'].scale_*10],columns=NETWORK_FEATURES)
    expected=infer_network(raw,bundle)
    data={'X_train':np.zeros((2,11)),'y_train_bin':np.array([0,1]),
          'X_val':np.zeros((2,11)),'y_val_bin':np.array([0,1]),
          'X_test':np.zeros((2,11)),'y_test_bin':np.array([0,1]),'raw_test':raw}
    calls=[]
    def checked(frame,b):
        pd.testing.assert_frame_equal(frame,raw)
        calls.append(True)
        return infer_network(frame,b)
    monkeypatch.setattr(benchmark,'get_candidate_models',lambda task:{})
    monkeypatch.setattr(benchmark,'infer_network',checked)
    result=benchmark.benchmark_binary_task(data,tmp_path)['Isolation Forest (Baseline)']['test']
    assert calls==[True]
    assert result==benchmark.evaluate_binary(data['y_test_bin'],(expected[1]==-1).astype(int),-expected[2])


def test_supervised_risk_direction_and_batch_independence():
    rows=[{'artifact_type':'network','Packet Length Mean':80}]*3
    scored=RiskScorer().score_records(rows,[.1,.5,.9],network_score_kind='supervised')
    by_score=sorted(scored,key=lambda r:r['record_id']) if all('record_id' in r for r in scored) else scored
    risks=sorted(r['risk_score'] for r in by_score)
    assert risks==[6,30,54]
    assert all(r['anomaly_score'] is None for r in scored)
    assert RiskScorer().score_records(rows[:1],[.9],network_score_kind='supervised')[0]['risk_score']==54


def test_invalid_detector_does_not_fallback(client):
    response=client.post('/api/analyze?detector=unknown',data={'file':(io.BytesIO(b'a,b\n1,2\n'),'unit.csv')})
    assert response.status_code==400
    assert response.json['error']['code']=='INVALID_DETECTOR'


def test_unavailable_explicit_supervised_no_fallback(isolated_app,tmp_path):
    isolated_app.config['SUPERVISED_MODEL_PATH']=str(tmp_path/'missing.joblib')
    response=isolated_app.test_client().post('/api/analyze?detector=supervised',data={'file':(io.BytesIO(b'a,b\n1,2\n'),'unit.csv')})
    assert response.status_code==503
    assert response.json['error']['code']=='SUPERVISED_MODEL_MISSING'


def test_model_inventory_and_default(client):
    payload=client.get('/api/model').json
    assert payload['default_detector']=='baseline'
    assert not payload['models']['baseline']['available']  # isolated missing baseline
    assert payload['models']['supervised']['available']
    assert payload['models']['supervised']['active_threshold'] > 0


def test_supervised_validates_unit_and_label_contract():
    import copy
    from ml.supervised_detector import load_supervised_detector,validate_supervised_bundle,SupervisedDetectorError
    bundle=load_supervised_detector()
    bad=copy.deepcopy(bundle); bad['feature_schema']['flow_duration_unit']='seconds'
    with pytest.raises(SupervisedDetectorError):
        validate_supervised_bundle(bad)


@pytest.mark.integration
@pytest.mark.parametrize('detector',['baseline','supervised'])
def test_live_selected_detector_persistence(mongo_app,detector):
    from pathlib import Path
    source=Path('.test-artifacts/issue3/demo.csv')
    if not source.exists():
        pytest.skip('Real held-out CSV fixture absent; run verify_network_models first')
    mongo_app.config['MODEL_PATH']=str(Path('models/cicids2017_baseline.joblib').resolve())
    client=mongo_app.test_client()
    case_id=client.post('/api/cases',json={'title':'Selected network detector persistence'}).json['id']
    with source.open('rb') as stream:
        response=client.post('/api/analyze',data={'caseId':case_id,'detector':detector,'file':(stream,source.name)})
    assert response.status_code==200,response.json
    payload=response.json
    response.request.environ['wsgi.input'].close(); response.close()
    assert payload['persisted']
    rows=client.get('/api/artifacts?case_id='+case_id+'&limit=100').json['artifacts']
    assert len(rows)==payload['summary']['total_records']
    assert all(r['model_id']==payload['inference_metadata']['model_id'] for r in rows)
    assert all(r['decision_threshold']==payload['inference_metadata']['active_threshold'] for r in rows)
    from ml.preprocessor import read_network_csv
    raw=read_network_csv(source)
    ordered=sorted(rows,key=lambda r:r['record_id'])
    for feature in NETWORK_FEATURES:
        np.testing.assert_array_equal([r[feature] for r in ordered],raw[feature].to_numpy())
    case=client.get('/api/cases/'+case_id).json
    assert case['evidence']['sources'][0]['network_analysis']['summary']==payload['summary']
    assert client.get('/api/report/'+case_id).data.startswith(b'%PDF-')


def test_supervised_evaluation_selects_requested_model(client):
    from pathlib import Path
    source=Path('.test-artifacts/issue3/demo.csv')
    if not source.exists():
        pytest.skip('Real held-out CSV fixture absent')
    with source.open('rb') as stream:
        response=client.post('/api/evaluate?detector=supervised',data={'file':(stream,source.name)})
    assert response.status_code==200,response.json
    assert response.json['evaluation_mode']=='fixed_supervised'
    assert response.json['inference_metadata']['model_id'].startswith('xgb-bin-')
    response.request.environ['wsgi.input'].close(); response.close()
