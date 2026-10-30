import io
import numpy as np
import pandas as pd
import pytest
from ml.external_dataset_adapter import (MAPPING,adapt_frame,validate_columns,
                                         read_external_csv,LABELS)
from ml.preprocessor import NETWORK_FEATURES,NetworkInputError
from evaluation.external_metrics import binary_metrics


def sample():
    return pd.DataFrame({**{c:['1','2'] for c in MAPPING.values()},'Label':['Benign','Bot']})


def test_mapping_order_values_and_label_separation():
    frame=sample();x,labels,y,reasons,report=adapt_frame(frame,require_labels=True)
    assert list(x)==list(NETWORK_FEATURES)
    assert 'Label' not in x and 'Label' not in NETWORK_FEATURES
    np.testing.assert_array_equal(x.iloc[1],np.full(11,2))
    assert y.tolist()==[0,1] and labels.tolist()==['Benign','Bot']
    assert not reasons.any() and report['valid_rows']==2


@pytest.mark.parametrize('mode',['missing','wrong_name','duplicate','ambiguous','wrong_unit'])
def test_reject_incompatible_schema(mode):
    columns=list(sample())
    if mode=='missing':columns.remove('Tot Fwd Pkts')
    if mode=='wrong_name':columns[1]='total packets maybe'
    if mode=='duplicate':columns.append('Tot Fwd Pkts')
    if mode=='ambiguous':columns.append('Total Fwd Packets')
    with pytest.raises(NetworkInputError):
        validate_columns(columns,duration_unit='seconds' if mode=='wrong_unit' else 'microseconds')


@pytest.mark.parametrize('value,reason',[('', 'missing_measurement'),('NaN','nan_measurement'),('Infinity','infinite_measurement'),('junk','nonnumeric_measurement'),('-1','negative_measurement')])
def test_explicit_exclusions_preserve_following_row_identity(value,reason):
    frame=sample();frame.loc[0,'Flow Duration']=value
    x,labels,y,reasons,report=adapt_frame(frame,require_labels=True)
    assert x.index.tolist()==[1] and y.loc[x.index].tolist()==[1]
    assert labels.loc[1]=='Bot' and reason in reasons.loc[0]
    assert report['excluded_rows']==1


def test_unknown_labels_and_duplicates_are_explicit():
    frame=pd.concat([sample(),sample().iloc[:1]],ignore_index=True)
    frame.loc[1,'Label']='Unreviewed label'
    x,_,_,reasons,report=adapt_frame(frame,require_labels=True)
    assert x.index.tolist()==[0,2] and reasons.loc[1]=='unknown_label'
    assert report['unknown_labels']=={'Unreviewed label':1}
    frame.loc[0,'Flow Duration']='0'
    assert adapt_frame(frame)[0].loc[0,'Flow Duration']==0


def test_reader_rejects_duplicate_before_pandas_mangling(tmp_path):
    path=tmp_path/'duplicate.csv';path.write_text('Flow Duration,Flow Duration\n1,2\n')
    with pytest.raises(NetworkInputError):read_external_csv(path)


def test_metrics_counts_and_single_class_limitations():
    m=binary_metrics([0,0,1,1],[0,1,0,1],[.1,.9,.2,.8])
    assert m['confusion_matrix']=={'tn':1,'fp':1,'fn':1,'tp':1}
    assert m['accuracy']==m['balanced_accuracy']==.5
    limited=binary_metrics([1,1],[0,1],[.2,.8])
    assert limited['recall']==.5 and limited['roc_auc'] is None and limited['specificity'] is None


def test_bulk_overlap_preserves_duplicate_row_counts(tmp_path):
    import sqlite3
    from scripts.evaluate_external_network import bulk_overlap
    path=tmp_path/'reference.sqlite';reference=sqlite3.connect(path)
    reference.execute('CREATE TABLE groups(kind INT,h BLOB,lo INT,hi INT,n INT,PRIMARY KEY(kind,h)) WITHOUT ROWID')
    reference.executemany('INSERT INTO groups VALUES(?,?,?,?,?)',[(0,b'a',0,0,1),(3,b'b',0,1,2),(3,b'c',2,2,1),(4,b'b',2,2,1)])
    reference.commit();reference.close()
    db=sqlite3.connect(':memory:',uri=True)
    db.execute('CREATE TABLE external_fingerprints(kind INT,h BLOB,n INT,PRIMARY KEY(kind,h)) WITHOUT ROWID')
    db.executemany('INSERT INTO external_fingerprints VALUES(?,?,?)',[(0,b'a',4),(3,b'b',3),(3,b'c',2),(3,b'x',7),(4,b'b',6)])
    result=bulk_overlap(db,path);db.close()
    assert result=={'raw_rows_matching_any_2017_partition':4,'supervised_rows_matching_any_2017_partition':5,'supervised_rows_matching_2017_training':3,'baseline_rows_matching_any_2017_partition':6,'baseline_rows_matching_2017_training':0}


def test_frozen_real_inference_is_chunk_invariant():
    from scripts.acquire_external_dataset import RAW
    path=RAW/'Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv'
    if not path.exists():pytest.skip('Official external source absent; real inference not verified')
    from ml.baseline import load_baseline,infer_network
    from ml.supervised_detector import load_supervised_detector,infer_supervised_network
    with read_external_csv(path,chunksize=113) as reader:
        frame=next(reader)
    x,*_=adapt_frame(frame,require_labels=True)
    for loader,infer in [(load_baseline,infer_network),(load_supervised_detector,infer_supervised_network)]:
        bundle=loader();whole=infer(x,bundle)
        chunks=[infer(x.iloc[i:i+17],bundle) for i in range(0,len(x),17)]
        np.testing.assert_array_equal(whole[1],np.concatenate([r[1] for r in chunks]))
        np.testing.assert_array_equal(whole[2],np.concatenate([r[2] for r in chunks]))
        assert bundle.get('threshold_config',{}).get('threshold',0) in [0,0.4343418846451664]


@pytest.mark.parametrize('detector',['baseline','supervised'])
def test_external_api_selected_frozen_model(client,detector):
    from pathlib import Path
    from backend.app import create_app
    app=create_app({'TESTING':True,'APP_ENV':'test','MODEL_PATH':str(Path('models/cicids2017_baseline.joblib').resolve())})
    response=app.test_client().post('/api/analyze',data={'dataset':'cse-cic-ids2018','detector':detector,'file':(io.BytesIO(sample().drop(columns='Label').to_csv(index=False).encode()),'mapping-unit.csv')})
    assert response.status_code==200,response.json
    m=response.json['inference_metadata']
    assert m['external_dataset']['compatibility']['dataset']=='CSE-CIC-IDS2018'
    assert m['active_threshold']==(0 if detector=='baseline' else .4343418846451664)
    assert response.json['summary']['total_records']==2
    response.request.environ['wsgi.input'].close();response.close()


def test_external_threshold_override_rejected(client):
    response=client.post('/api/analyze',data={'dataset':'cse-cic-ids2018','detector':'supervised','threshold':'0.5','file':(io.BytesIO(sample().to_csv(index=False).encode()),'schema-unit.csv')})
    assert response.status_code==400 and response.json['error']['code']=='FROZEN_THRESHOLD_REQUIRED'
    response.request.environ['wsgi.input'].close();response.close()


@pytest.mark.integration
@pytest.mark.parametrize('detector',['baseline','supervised'])
def test_real_external_mongo_and_pdf(mongo_app,detector):
    import json
    from pathlib import Path
    from pypdf import PdfReader
    source=Path('.test-artifacts/issue4/demo.csv')
    if not source.exists():pytest.skip('Real official external demo not prepared')
    mongo_app.config['MODEL_PATH']=str(Path('models/cicids2017_baseline.joblib').resolve())
    client=mongo_app.test_client();case=client.post('/api/cases',json={'title':'Official external flow persistence regression'}).json['id']
    with source.open('rb') as stream:
        response=client.post('/api/analyze',data={'caseId':case,'dataset':'cse-cic-ids2018','detector':detector,'file':(stream,source.name)})
    assert response.status_code==200,response.json
    payload=response.json;response.request.environ['wsgi.input'].close();response.close()
    assert payload['persisted']
    rows=client.get('/api/artifacts?case_id='+case+'&limit=100').json['artifacts']
    assert len(rows)==payload['summary']['total_records']
    expected=json.loads(__import__('pathlib').Path('test-results/issue-4/demo-manifest-summary.json').read_text())
    assert payload['evidence']['sha256']==expected['csv_sha256']
    assert all(row['model_id']==payload['inference_metadata']['model_id'] for row in rows)
    pdf=client.get('/api/report/'+case)
    text=' '.join(page.extract_text() for page in PdfReader(io.BytesIO(pdf.data)).pages)
    assert 'CSE-CIC-IDS2018' in text and 'CONDITIONALLY_COMPATIBLE' in text
    assert payload['inference_metadata']['model_id'] in text


def test_executed_external_accounting_is_complete():
    import json
    from pathlib import Path
    root=Path('test-results/issue-4')
    if not (root/'evaluation.json').exists():pytest.skip('Full external evaluation has not executed here')
    evaluation=json.loads((root/'evaluation.json').read_text());quality=json.loads((root/'data-quality.json').read_text())
    total=0
    for q in quality.values():
        counts=q['counts'];assert counts['source_records']==counts['valid_records']+counts['excluded_records']
        assert sum(q['source_labels'].values())==counts['source_records']
        assert sum(q['valid_labels'].values())==counts['valid_records']
        assert sum(q['excluded_labels'].values())==counts['excluded_records']
        total+=counts['valid_records']
    for model in evaluation['models'].values():
        m=model['overall'];assert m['samples']==total==sum(m['confusion_matrix'].values())
        assert sum(v['samples'] for v in model['per_label'].values())==total
        assert sum(v['samples'] for v in model['per_day'].values())==total
