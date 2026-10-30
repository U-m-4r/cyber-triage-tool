import copy
import pytest
from backend.evaluation_results import catalog,validate_metrics,read_source


def test_actual_catalog_validates_all_historical_groups():
    result=catalog()
    assert len(result['evaluations'])==5
    assert all(g['status']=='VERIFIED_SAVED_RESULT' for g in result['evaluations'])
    challenge=result['evaluations'][-1]['entries'][0]
    assert challenge['positive_only'] and 'accuracy' not in challenge['metrics']
    external=result['evaluations'][1]['entries'][0]
    assert external['families']['Bot']['attack_recall'] is not None
    assert result['evaluations'][3]['recorded_evaluation_start']
    assert result['evaluations'][3]['supporting_sources']


def test_inconsistent_metrics_rejected():
    result=catalog()['evaluations'][0]['entries'][0]['metrics']
    bad=copy.deepcopy(result);bad['confusion_matrix']['tp']+=1
    with pytest.raises(ValueError):validate_metrics(bad)


def test_unknown_result_path_never_allowed():
    with pytest.raises(KeyError):read_source('../../.env')


def test_evaluation_routes_use_api_prefix_and_reject_unknown_source():
    from backend.app import create_app
    app=create_app({'TESTING':True,'APP_ENV':'test','DB_MODE':'disabled'})
    client=app.test_client()
    response=client.get('/api/evaluations')
    assert response.status_code==200
    assert len(response.json['evaluations'])==5
    assert client.get('/api/evaluations/not-allowlisted').status_code==404


def test_missing_verification_manifest_shows_unavailable(tmp_path,monkeypatch):
    import backend.evaluation_results as module
    monkeypatch.setattr(module,'ROOT',tmp_path)
    result=module.catalog()
    assert all(g['status']=='VERIFICATION DATA UNAVAILABLE' and not g['entries'] for g in result['evaluations'])


def test_evaluation_script_references_exist():
    from backend.evaluation_results import ROOT,SOURCES
    for key in SOURCES:
        _,pin=read_source(key)
        if 'evaluation_script' in pin:
            assert (ROOT/pin['evaluation_script']).is_file()


def test_source_size_limit_is_enforced_before_parsing(tmp_path,monkeypatch):
    import json
    import backend.evaluation_results as module
    monkeypatch.setattr(module,'ROOT',tmp_path)
    target=tmp_path/module.SOURCES['internal'];target.parent.mkdir(parents=True)
    with target.open('wb') as stream:stream.truncate(module.MAX_SOURCE_BYTES+100)
    manifest=tmp_path/'evaluation/presentation-manifest.json';manifest.parent.mkdir()
    manifest.write_text(json.dumps({'internal':{'sha256':'untrusted'}}))
    with pytest.raises(ValueError,match='checksum/size'):
        module.read_source('internal')


def test_corrupt_supporting_source_disables_dependent_evaluation(monkeypatch):
    import backend.evaluation_results as module
    original=module.read_source
    def read(key):
        if key=='pe-source-lock':raise ValueError('Support checksum mismatch')
        return original(key)
    monkeypatch.setattr(module,'read_source',read)
    result=module.catalog()
    assert result['evaluations'][3]['status']=='VERIFICATION DATA UNAVAILABLE'
    assert result['evaluations'][0]['status']=='VERIFIED_SAVED_RESULT'
