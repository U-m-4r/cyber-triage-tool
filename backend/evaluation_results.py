"""Allowlisted, hash-pinned historical results; no dataset/pickle/path execution."""
import hashlib
import json
import math
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
MAX_SOURCE_BYTES=5*1024*1024
SOURCES={
    'internal': 'test-results/issue-3/evaluation.json',
    'external': 'test-results/issue-4/evaluation.json',
    'research': 'test-results/issue-6b/final-results.json',
    'pe': 'test-results/issue-7/evaluation-v3/metrics.json',
    'pe-types': 'test-results/issue-7/evaluation-v3/unique-identity-analysis.json',
    'challenge': 'test-results/issue-2/evaluation-v1/metrics.json',
    'research-selection': 'test-results/issue-6b/selection.json',
    'internal-split': 'test-results/issue-3/split-audit.json',
    'external-manifest': 'test-results/issue-4/dataset-manifest.json',
    'research-test-lock': 'test-results/issue-6b/locked-test.json',
    'research-receipt': 'test-results/issue-6b/final-test-receipt.json',
    'pe-source-lock': 'test-results/issue-7/evaluation-v3/source-lock.json',
    'pe-receipt': 'test-results/issue-7/evaluation-v3/evaluation-receipt.json',
}
SUPPORTING={
    'internal': ['internal-split'], 'external': ['external-manifest'],
    'research': ['research-selection','research-test-lock','research-receipt'],
    'pe': ['pe-types','pe-source-lock','pe-receipt'], 'challenge': [],
}


def read_source(key):
    path=ROOT/SOURCES[key]
    pins=json.loads((ROOT/'evaluation/presentation-manifest.json').read_text())
    with path.open('rb') as source:
        data=source.read(MAX_SOURCE_BYTES+1)
    if len(data)>MAX_SOURCE_BYTES or hashlib.sha256(data).hexdigest()!=pins[key]['sha256']:
        raise ValueError('Saved result checksum/size verification failed')
    def invalid(value):raise ValueError('Nonfinite JSON value')
    return json.loads(data,parse_constant=invalid),pins[key]


def validate_metrics(metric):
    """Reject inconsistent counts and percentages instead of displaying defaults."""
    c=metric['confusion_matrix']
    for key in ('tn','fp','fn','tp'):
        if type(c[key]) is not int or c[key]<0:raise ValueError('Invalid confusion counts')
    n=sum(c.values());support=metric.get('support',{})
    total=metric.get('samples',support.get('total'))
    if n!=total or n<=0:raise ValueError('Confusion matrix total mismatch')
    benign=c['tn']+c['fp'];attack=c['tp']+c['fn']
    for key,value in [('benign',benign),('attack',attack)]:
        if metric.get(key,support.get(key))!=value:raise ValueError('Class count mismatch')
    expected={'accuracy':(c['tp']+c['tn'])/n,'precision':c['tp']/(c['tp']+c['fp']) if c['tp']+c['fp'] else 0,
        'recall':c['tp']/attack if attack else None,'f1':2*c['tp']/(2*c['tp']+c['fp']+c['fn']) if 2*c['tp']+c['fp']+c['fn'] else 0,
        'false_positive_rate':c['fp']/benign if benign else None}
    result={'samples':n,'benign':benign,'attack':attack,'confusion_matrix':c}
    for key in (*expected,'roc_auc'):
        value=metric.get(key,metric.get('fpr') if key=='false_positive_rate' else None)
        if value is not None and (not isinstance(value,(int,float)) or not math.isfinite(value) or not 0<=value<=1):raise ValueError('Invalid metric')
        if key in expected and expected[key] is not None and (value is None or abs(value-expected[key])>1e-6):raise ValueError('Metric/count inconsistency')
        result[key]=value
    return result


def catalog():
    groups=[]
    for key in ('internal','external','research','pe','challenge'):
        try:
            data,pin=read_source(key);entries=[]
            supporting=[];recorded_date=None
            for support in SUPPORTING[key]:
                document,support_pin=read_source(support)
                supporting.append({'id':support,'source_url':'/api/evaluations/'+support,'provenance':support_pin})
                if support.endswith('-receipt'):
                    recorded_date=document.get('started_at') or document.get('opened_at')
            if key=='internal':
                for name in ('Production XGBoost','Isolation Forest'):
                    r=data['models'][name];entries.append({'name':name,'badge':'PRODUCTION MODEL','model_id':r['model_id'],
                        'model_sha256':r['model_sha256'],'threshold':r['threshold'],'metrics':validate_metrics(r['metrics']),'families':r.get('by_attack_type',{})})
                title='CICIDS2017 — internal held-out evaluation';limitations=['Feature-group hashing; not independent external validation.','Internal and external populations differ; comparisons are not controlled cross-dataset trials.']
            elif key=='external':
                for name,r in data['models'].items():
                    entries.append({'name':name,'badge':'PRODUCTION MODEL','model_id':r['model_id'],'model_sha256':r['sha256'],'threshold':r['threshold'],
                        'metrics':validate_metrics(r['overall']),'families':r.get('per_label',{}),'days':list(r.get('per_day',{}))})
                title='CSE-CIC-IDS2018 — external evaluation';limitations=['Poor external generalization is retained.','CICFlowMeter compatibility is conditional; capture days and testbed limit generalization.']
            elif key=='research':
                selection,_=read_source('research-selection')
                selected=selection['selected']
                internal,_=read_source('internal')
                for name in ('incumbent','challenger'):
                    r=data[name];entries.append({'name':name,'badge':'RESEARCH ONLY — NOT DEPLOYED' if name=='challenger' else 'PRODUCTION MODEL',
                        'model_id':('issue6b-'+selected['name']+'-'+str(selected['seed'])+'-'+selected['sha256'][:12]) if name=='challenger' else internal['models']['Production XGBoost']['model_id'],
                        'model_sha256':selected['sha256'] if name=='challenger' else internal['models']['Production XGBoost']['model_sha256'],
                        'metrics':validate_metrics(r['overall']),'threshold':r['threshold'],'families':r['per_family']})
                title='Issue6B — locked February15 research';limitations=['Challenger failed recall-improvement and balanced-accuracy gates; not deployed.',data['independence']]
            elif key=='pe':
                r=data['model'];types,_=read_source('pe-types')
                entries=[{'name':'Native PE — unique identities','badge':'PRODUCTION MODEL','model_id':r['model_id'],'model_sha256':r['model_sha256'],
                    'threshold':data['threshold'],'metrics':validate_metrics(data['unique_identity_metrics']),
                    'architectures':{k:validate_metrics(v) for k,v in types['unique_per_type'].items()}}]
                title='EMBER2024 — ordinary feature benchmark';limitations=['Feature-based benchmark differs from complete disk-image coverage.','Live PE cap:2MiB; unsupported variants remain excluded.','Balanced benchmark prevalence is not deployment prevalence; duplicate observations are deduplicated here.']
            else:
                c=data['confusion_matrix'];n=data['positive_examples'];tp=c['true_positive'];fn=c['false_negative']
                if tp+fn!=n or data['negative_examples']!=0 or abs(data['recall']-tp/n)>1e-9:raise ValueError('Challenge counts invalid')
                entries=[{'name':'Positive-only malicious challenge evaluation','badge':'PRODUCTION MODEL','model_id':data['model']['model_id'],
                    'model_sha256':data['model']['model_sha256'],'threshold':data['threshold'],'positive_only':True,
                    'metrics':{'samples':n,'benign':0,'attack':n,'recall':tp/n,'confusion_matrix':{'tp':tp,'fn':fn,'tn':None,'fp':None}}}]
                title='EMBER2024 — evasive challenge';limitations=['Positive-only: accuracy, precision, specificity and FPR cannot be measured.']
            groups.append({'id':key,'title':title,'status':'VERIFIED_SAVED_RESULT','badge':'HISTORICAL EVALUATION','entries':entries,
                'limitations':limitations,'provenance':pin,'source_url':'/api/evaluations/'+key,
                'supporting_sources':supporting,'recorded_evaluation_start':recorded_date,
                'date_limitation':'Local saved receipt time is not independently authenticated' if recorded_date else 'No exact evaluation timestamp in this saved source; not inferred from file modification time'})
        except (OSError,ValueError,KeyError,TypeError,ZeroDivisionError) as exc:
            groups.append({'id':key,'status':'VERIFICATION DATA UNAVAILABLE','reason':str(exc),'entries':[]})
    return {'schema_version':'presentation-evaluations-v1','evaluations':groups,
        'definitions':{'accuracy':'(TP+TN)/N','precision':'TP/(TP+FP)','recall':'TP/(TP+FN)','false_positive_rate':'FP/(FP+TN)'},
        'warning':'Historical labeled evaluation is separate from live unlabeled investigation findings. Scores are not calibrated confidence.'}
