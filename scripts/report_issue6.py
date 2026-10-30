"""Generate the review report from sealed actual execution artifacts."""
import importlib.metadata
import json
from pathlib import Path
import platform
import re
import xml.etree.ElementTree as ET
from ml.network_experiment import repo_path

ROOT=Path('test-results/issue-6')


def load(name):return json.loads((ROOT/name).read_text())


def main():
    final=load('final-results.json');selection=load('selection.json');prepared=load('prepared.json')
    historical=load('historical-diagnosis.json');ambiguity=load('feature-ambiguity.json');lock=load('locked-test.json')
    models=final['models'];candidates={n:load(n+'-validation.json') for n in ('xgboost','lightgbm')}
    latest=load('demo-latest.json');demo=json.loads((repo_path(latest['output'])/'summary.json').read_text())
    regression=next(ROOT/name for name in ('post-portability-regression.xml','regression-final.xml','regression.xml') if (ROOT/name).exists())
    nodes=list(ET.parse(regression).getroot().iter('testcase'))
    tests={'passed':sum(not any(t.find(k) is not None for k in ('failure','error','skipped')) for t in nodes),
           'failed':sum(t.find('failure') is not None for t in nodes),'errors':sum(t.find('error') is not None for t in nodes),
           'skipped':sum(t.find('skipped') is not None for t in nodes)}
    front=(ROOT/'frontend.txt').read_text(encoding='utf-8')
    front_count=int(re.search(r'pass\s+(\d+)',front).group(1))
    environment={'python':platform.python_version(),'platform':platform.platform(),
        'versions':{p:importlib.metadata.version(p) for p in ('numpy','pandas','scikit-learn','xgboost','lightgbm','psutil','Flask','pymongo','yara-python','pytsk3')},
        'regression':tests,'frontend_passed':front_count,'training_seed':42,'threads':2,
        'browser':'UNVERIFIED: Local browser use is disabled in Work settings.'}
    (ROOT/'environment.json').write_text(json.dumps(environment,indent=2))
    lines=['# Issue 6 — real recall gains, deployment rejected', '',
        '**Completion: PARTIAL for the operational model-improvement objective.** The complete research workflow ran, '
        'but the selected challenger failed prespecified FPR and family-coverage gates. No incumbent model, scaler, '
        'threshold, detector default, historical result or forensic pipeline was changed.', '',
        '## 1. Root-cause investigation / existing weaknesses', '',
        f"The historical Issue 4 archived population contains {historical['samples']:,} rows and is diagnostic only. "
        'Its archives were verified against the previously published SHA-256 before analysis.',
        'High ROC-AUC does not imply useful recall at a specific FPR or review budget. The external attack score '
        f"median is {historical['models']['supervised']['score_quantiles']['attack']['0.5']:.8g}, while the frozen threshold is "
        f"{historical['models']['supervised']['frozen_threshold']:.8g}. The benign score distribution has a large high-score plateau. "
        'This is not solely an easily repairable threshold offset.', '',
        '| Historical model | Retrospective recall @1% FPR | @5% FPR | @10% FPR |', '|---|---:|---:|---:|']
    for name,result in historical['models'].items():
        recalls=[result['retrospective_fpr_points'][str(b)]['metrics']['recall'] for b in (.01,.05,.10)]
        lines.append('| '+name+' | '+' | '.join(f'{100*r:.6f}%' for r in recalls)+' |')
    lines+=['', 'These operating points use already inspected labels and are **not deployed or used to select the new threshold**. '
        'Historical high-score benign ties limit low-FPR/top-K behavior even though many low-scoring attacks outrank other benign flows. '
        'Nine figures and the score/curve JSONs show this directly.',
        'Measured evidence also supports representation and label limitations: '
        f"the final audit found {ambiguity['conflicting_binary_groups']:,} identical float32 input groups carrying both labels, "
        f"covering {ambiguity['rows_in_conflicting_groups']:,} rows. Even an otherwise perfect deterministic classifier of these eleven inputs "
        f"must misclassify at least {ambiguity['minimum_errors_for_any_deterministic_classifier_on_these_vectors']:,} observed records "
        f"({100*ambiguity['minimum_error_rate_from_observed_label_ambiguity']:.4f}%). This does not identify whether the publisher labels, "
        'information loss, or traffic construction is responsible.',
        'Issue 4 measured feature shift and source-rate units; the candidate training/final feature histograms also differ. '
        'Exact CICFlowMeter binary/build equivalence remains unproven. This study does not establish a unique causal '
        'explanation or claim that distribution shift alone caused failure. Production inference still scales exactly once; '
        'the previously corrected benchmark double-scaling defect was not reintroduced.', '',
        '## 2. Datasets, feature engineering and leakage prevention', '',
        'Official dataset origin: [UNB/CIC documentation](https://www.unb.ca/cic/datasets/ids-2018.html) and '
        '[AWS open-data registry](https://registry.opendata.aws/cse-cic-ids2018/). Source selection and gates were '
        'committed in cb47698; source hashes/implementation in cd68caa; validation selection in 567f3ac, '
        'all before final label evaluation. Exact lock and receipt timestamps/hashes are in JSON.', '',
        '| Locked final source | Bytes | SHA-256 |', '|---|---:|---|']
    for source in lock['sources']:lines.append(f"| {source['filename']} | {source['size_bytes']:,} | `{source['sha256']}` |")
    lines+=['', 'The previously inspected Feb 22 web and Mar 2 bot days are development only. CICIDS2017 uses only its '
        'existing eligible training mask. Alternating whole 10-minute blocks on the development days separate train/validation; '
        'training boundary minutes are embargoed. Deterministic bottom-hash family caps are declared in PROTOCOL.md. '
        'No final-test labels, model predictions, port/IP/day identifiers or timestamp enter training features.',
        'Before training, **unlabeled final features** informed a conservative quarantine of development vectors. '
        'This is explicitly transductive overlap control, not an untouched-covariate or independent-site test. '
        'Training was also purged against validation; exact float32 and rounded-log-bin overlap counts are all zero. '
        'These 64-bit hashes/bin relations do not prove all session/host/near-duplicate separation. The two new days '
        'can share the 2018 testbed; independent bot scenario validation is unavailable.', '',
        '| Partition | Sampled | Purged against final features | Retained |', '|---|---:|---:|---:|']
    for name,part in prepared['partitions'].items():
        lines.append(f"| {name} | {part['sampled_rows']:,} | {part['quarantined_against_unlabeled_test']:,} | {part['retained_rows']:,} |")
    lines+=['',f"Training additionally lost {prepared['partitions']['train']['purged_against_validation']:,} validation-overlap rows and "
        f"{prepared['partitions']['train']['duplicate_training_rows_removed']:,} duplicate model-input rows; "
        f"{prepared['partitions']['train']['conflicting_label_rows_excluded']:,} conflicting-label training rows were excluded. "
        'Full group distributions/identities, quality and stage counts are recorded in prepared.json. '
        'Development is quota sampled, so validation precision reflects its selected prevalence.',
        'Candidate schema `network-generalization-11-v1`: the same ordered eleven measured features; identity float32 preprocessing, '
        'no scaler fitting, imputation, calibration or guessed features. Expanded Candidate B was not approved because '
        'the reviewed 2017 source and supported application uploads do not supply the additional 2018 IAT/flag fields. '
        'The incumbent validation path restores original float64 source values before applying its own saved scaler; '
        'it does not mistakenly standardize already rounded candidate input.', '',
        '## 3. Candidate training and validation-only selection', '',
        'Exactly two candidates, seed 42, two threads, at most 300 rounds, fixed regularization and '
        '30-round validation-logloss early stopping. Training-only source/family sample weights give each '
        'observed training group equal total weight; metadata records all weights. No hyperparameter or seed search. '
        'Class balancing changes score semantics; outputs remain uncalibrated.', '',
        '| Candidate | Fit seconds | Best round (zero based) | Validation threshold | Recall | Precision | FPR | AP |',
        '|---|---:|---:|---:|---:|---:|---:|---:|']
    for name,r in candidates.items():
        m=r['overall'];lines.append(f"| {name} | {r['model']['fit_seconds']:.4f} | {r['model']['best_iteration']} | {r['threshold']:.9g} | {m['recall']:.6f} | {m['precision']:.6f} | {m['false_positive_rate']:.6f} | {m['average_precision']:.9f} |")
    lines+=['',f"Validation N={candidates['lightgbm']['overall']['samples']:,}, "
        f"benign={candidates['lightgbm']['overall']['benign']:,}, attacks={candidates['lightgbm']['overall']['attack']:,}. "
        'Threshold maximizes recall under empirical FPR <=5%, preserving entire score ties; ties prefer precision and '
        'higher threshold. Candidate selection maximizes validation macro original-attack-label recall, then AP, '
        f"then FPR/name. Both reached macro family recall 1; the prespecified AP tie-break selected **{selection['selected']}**. "
        'The tiny AP difference is not evidence of stable algorithm superiority. Rare validation web counts are '
        '28 brute-force, 20 XSS, 14 SQL; bot validation shares a known capture scenario.', '',
        '| Candidate | Recall @validation FPR 1% | @5% | @10% |', '|---|---:|---:|---:|']
    for name,r in candidates.items():
        lines.append('| '+name+' | '+' | '.join(f"{r['operating_points'][str(b)]['metrics']['recall']:.6f}" for b in (.01,.05,.10))+' |')
    reference=load('incumbent-validation.json')
    lines+=['', 'The frozen incumbent was also diagnosed at validation-only retuned points (never deployed):', '',
        '| Validation FPR budget | Threshold | Recall | Actual FPR |', '|---|---:|---:|---:|']
    for budget,point in reference['validation_only_retuned_points'].items():
        lines.append(f"| {budget} | {point['threshold']:.9g} | {point['metrics']['recall']:.6f} | {point['metrics']['false_positive_rate']:.6f} |")
    lines+=['', 'Training memory observation correction: the original monitor saw the Windows venv launcher, not '
        'the worker. The sealed selection resource field is mislabeled and **not a valid training RSS measurement**. '
        'resource-observation-note.json records this; no refit was performed to hide the issue. A separate '
        'actual-process, validation-only inference memory measurement is in candidate-performance.json. '
        'The future watchdog now includes recursive child processes.', '',
        '## 4. One-shot final results', '',
        f"Common final population: **{models['incumbent']['overall']['samples']:,}**, "
        f"including {models['incumbent']['overall']['benign']:,} benign and {models['incumbent']['overall']['attack']:,} attacks. "
        'Only the sealed challenger and frozen production incumbent were evaluated. No final threshold/model '
        'tuning or XGBoost-challenger final evaluation was performed.', '',
        '| Metric | Frozen incumbent XGBoost | Selected research LightGBM |', '|---|---:|---:|']
    for key in ('accuracy','precision','recall','f1','macro_f1','balanced_accuracy','roc_auc','average_precision','specificity','false_positive_rate','false_negative_rate'):
        lines.append(f"| {key} | {models['incumbent']['overall'][key]:.9f} | {models['challenger']['overall'][key]:.9f} |")
    lines+=['', '| Model | TN | FP | FN | TP |', '|---|---:|---:|---:|---:|']
    for name,r in models.items():lines.append('| '+name+' | '+' | '.join(f"{r['overall']['confusion_matrix'][k]:,}" for k in ('tn','fp','fn','tp'))+' |')
    lines+=['', '| Final source | Original rows | Eligible | Excluded |', '|---|---:|---:|---:|']
    for name,q in final['quality'].items():lines.append(f"| {name} | {q['source_rows']:,} | {q['eligible']:,} | {q['excluded']:,} |")
    lines+=['', 'All exclusions and original label/reason counts are explicit in final-results.json and the ignored '
        'row ledger. One Feb 16 repeated-header/invalid measurement row and 5,708 invalid-measurement Feb 23 '
        'rows were excluded. No difficult attacks were selectively removed. '
        f"{final['duplicates']['duplicate_copies_retained']:,} duplicate copies and "
        f"{final['duplicates']['conflicting_binary_label_groups_retained']:,} conflicting binary-label groups are retained. "
        'The initial feature audit had unused zero rate-check placeholders; its initial record is preserved, '
        'and the corrected audit removes those unmeasured fields without changing any ambiguity counts.', '',
        '## 5. Attack-family and capture-day performance', '',
        '| Publisher attack label | N | Incumbent TP / FN | Challenger TP / FN | Incumbent recall | Challenger recall |',
        '|---|---:|---:|---:|---:|---:|']
    for family,r in models['challenger']['per_family'].items():
        if not r['binary_label']:continue
        old=models['incumbent']['per_family'][family]
        lines.append(f"| {family} | {r['samples']:,} | {old['true_positive']:,} / {old['false_negative']:,} | {r['true_positive']:,} / {r['false_negative']:,} | {old['recall']:.6f} | {r['recall']:.6f} |")
    lines+=['', 'These are **binary** detection recalls grouped by genuine labels, not implemented attack-family '
        'classification. SQL N=53 and other web counts are limited; session/testbed dependence limits statistical '
        'certainty. SlowHTTPTest remains 0/139,890 despite aggregate gains. There is no new independent bot result.', '',
        '| Final day | Model | Recall | Precision | FPR |', '|---|---|---:|---:|---:|']
    for name,r in models.items():
        for day,result in r['per_day'].items():
            m=result['overall'];lines.append(f"| {day} | {name} | {m['recall']:.6f} | {m['precision']:.6f} | {m['false_positive_rate']:.6f} |")
    lines+=['', '## 6. Operating budget, performance and deployment decision', '',
        '| Final model | Load seconds | Chunk inference seconds | Flows/second |', '|---|---:|---:|---:|']
    for name,r in models.items():lines.append(f"| {name} | {final['candidate_loading_seconds']:.6f} (challenger only) | {r['inference_seconds']:.6f} | {r['records_per_second']:,.0f} |")
    lines+=['', f"Observed final-process RSS was {final['peak_observed_rss_bytes']:,} bytes (sampled observation, not an OS-enforced quota); "
        f"complete final evaluation elapsed {final['elapsed_seconds']:.3f}s. Inference timings exclude CSV IO and metric computation. "
        'Candidate validation-only memory/load timing is separate. Top-K recall uses conservative bounds when a '
        'review boundary intersects tied scores; no labels are used to break ranking ties.', '',
        '| Prespecified gate | Result |', '|---|---|']
    lines += [f"| {gate} | {'PASS' if passed else 'FAIL'} |" for gate,passed in final['deployment_gates'].items()]
    lines+=['', '**Decision: RETAIN INCUMBENTS.** New optional deployment is disallowed because the challenger '
        'fails overall/per-day FPR and family coverage gates. No application schema/default/threshold changes, '
        'no misleading fallback and no challenger selection in React. The new model is an experimental text artifact '
        'only. Research packaging/acquisition is opt-in, hash-pinned, and explicitly marked rejected; it never '
        'replaces production files. Further improvement requires another protocol and newly unused test source, '
        'not continued tuning against these final results.', '',
        '## 7. Application and regression verification', '',
        f"Real HTTP demo run `{demo['run']}`, separate owned MongoDB `{demo['database']}`. "
        'Both retained detectors process the same real 84-row, source-order-selected CICIDS2017 fixture. '
        'Predictions and scores exactly match direct saved-bundle inference, persisted cases retain model IDs, '
        'thresholds, custody and screening, and actual PDFs contain the saved results.', '',
        '| Retained detector | Case | Model ID | Direct inference | MongoDB | PDF |', '|---|---|---|---|---|---|']
    for name,r in demo['results'].items():lines.append(f"| {name} | {r['case_id']} | {r['model_id']} | {r['direct_inference_consistency']} | {r['mongo_roundtrip']} | {r['pdf']} |")
    lines+=['', f"Backend: **{tests['passed']} passed, {tests['skipped']} skipped, {tests['failed']} failures, {tests['errors']} errors**. "
        f"Frontend: **{front_count} passed**, production build succeeded. Regression fitting was disabled; "
        'the two explicit research candidates were trained only by the budgeted research stage. '
        'Skip reasons are preserved, including disposable fitting fixtures and the absent primary forensic image; '
        'real controlled FAT12/PE/YARA/MongoDB/PDF tests ran.',
        '**Browser UNVERIFIED:** “Local browser use is disabled in Work settings.” Existing permission limitation '
        'preserved, no repeated request, bypass, screenshot fabrication or claim of actual React interactions. '
        'Automated React tests/build are distinct from browser acceptance. Rendered genuine PDF sample pages '
        'and geometry checks are recorded; raw PDFs remain ignored.', '',
        '## 8. Reproducibility, figures and known limits', '',
        '[Exact commands, input setup, optional artifact download and non-overwriting replay](../../docs/network-generalization.md). '
        'The original stages are write-once; final label receipt prevents another final evaluation or fitting under '
        'the same experiment. Replay is labeled already-disclosed reproduction, not new validation. '
        'Raw datasets, NPZ score/identity archives, exclusion ledgers, models and databases stay outside Git.',
        'Figures: model-comparison.png, confusion-matrices.png, final-roc-pr.png, attack-family-recall.png, '
        'feature-distributions.png, top-k-recall.png, inference-throughput.png, historical-score-diagnosis.png, '
        'historical-threshold-review.png. Figures contain actual populations/protocols, never illustrative values.',
        'Limits: no independent site/bot scenario; conditional extractor semantics; quota-sampled validation; '
        'tiny rare-class training counts; finite one-seed/two-model budget; incomplete session/host independence; '
        'unmeasured training peak RSS; browser interactions unavailable. High recall on the known development '
        'scenario did not transfer under the fixed FPR gate. The original 2017 cleaned source has historical '
        'label-conflict cleaning and partition limitations documented in Issue 3; they are not erased here.',
        'Current production model hashes and all historical Issue 3–5 scientific files are verified against '
        'checkpoint.json. Research code and honest negative deployment results may be published, as authorized. '
        'Final commit/remote SHA is reported from Git after publication; no self-referential hash is embedded here. '
        'No further development issue was started.', '']
    # Avoid falsely giving the challenger load measurement to the incumbent.
    lines=[line.replace(f"| incumbent | {final['candidate_loading_seconds']:.6f} (challenger only)", '| incumbent | Not measured in final harness') for line in lines]
    (ROOT/'REPORT.md').write_text('\n'.join(lines),encoding='utf-8')
    # Git ignores .log by policy; publish text transcripts without changing raw logs.
    for log in ROOT.glob('*.log'):
        transcript=log.with_suffix('.txt')
        if not transcript.exists():
            transcript.write_text(''.join(line.rstrip()+'\n' for line in log.read_text(encoding='utf-8',errors='replace').splitlines()),encoding='utf-8')


if __name__=='__main__':main()
