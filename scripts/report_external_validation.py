"""Assemble a reproducible report and slide text from measured Issue 4 evidence."""
import collections
import hashlib
import json
from pathlib import Path
import platform
import os
import shutil
import importlib.metadata
import xml.etree.ElementTree as ET
from ml.baseline import load_baseline
from ml.supervised_detector import load_supervised_detector

ROOT=Path('test-results/issue-4')


def main():
    read=lambda name:json.loads((ROOT/name).read_text())
    data=read('dataset-manifest.json');evaluation=read('evaluation.json');quality=read('data-quality.json');drift=read('drift.json');overlap=read('overlap.json')
    demo=read(read('demo-latest.json')['run']+'/summary.json')
    browser=read('browser-verification.json')
    internal=json.loads(Path('test-results/issue-3/evaluation.json').read_text())['models']
    tests=ET.parse(ROOT/'regression-final.xml').getroot().find('testsuite')
    env={'platform':platform.platform(),'python':platform.python_version(),'logical_cpus':os.cpu_count(),
         'free_disk_bytes_at_report':shutil.disk_usage('.').free,'dependencies':{n:importlib.metadata.version(n) for n in ['numpy','pandas','scikit-learn','xgboost','pymongo','pytsk3','yara-python','reportlab','pypdf','PyMuPDF']}}
    (ROOT/'environment.json').write_text(json.dumps(env,indent=2))
    frozen={}
    for name,loader,path in [('supervised',load_supervised_detector,Path('models/supervised_binary.joblib')),('baseline',load_baseline,Path('models/cicids2017_baseline.joblib'))]:
        bundle=loader(); checksum=hashlib.sha256(path.read_bytes()).hexdigest()
        assert checksum==evaluation['models'][name]['sha256']
        frozen[name]={'model_id':bundle['provenance']['model_id'],'sha256_after':checksum,
                       'threshold_after':bundle.get('threshold_config',{}).get('threshold',0),
                       'bundle_version':bundle['bundle_version'],'provenance':bundle['provenance'],'versions':bundle['versions']}
    (ROOT/'frozen-model-verification.json').write_text(json.dumps(frozen,indent=2))
    out=['# Issue 4 — frozen external dataset validation','',
         'This report records an executed two-day CSE-CIC-IDS2018 evaluation of the unchanged CICIDS2017-trained detectors. It is not full-dataset evaluation, independent-site validation, retraining, calibration or threshold optimization. Feature compatibility is **CONDITIONALLY_COMPATIBLE**; all eleven published measurements map, but generating extractor builds are unrecorded. Read FEATURE_COMPATIBILITY.md before interpreting metrics.',
         '', 'The result is negative: at their unchanged thresholds both models miss nearly all attacks in the selected external population. No threshold was adjusted to conceal this. Application verification status is separate from model performance.',
         '', '## Protocol and data provenance','',
         'The prediction-independent selection policy was recorded in PROTOCOL.md before external inference: the earlier documented web-attack day (22 February) and the bot day (2 March), targeting the previously weak categories. Both contain benign traffic. All objectively valid rows from both files were evaluated. No performance-based sample selection, duplicate removal, outlier removal or false-negative removal occurred. No PCAPs or full dataset collection were downloaded.',
         '', 'Official source: [UNB CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html), [AWS registry](https://registry.opendata.aws/cse-cic-ids2018/), anonymous bucket cse-cic-ids2018, region ca-central-1. Source inventory was inspected first. The two files total 735,004,575 bytes; full original CSVs remain in ignored scratch storage. Official HTTPS origin establishes retrieval provenance; multipart ETags are not cryptographic signatures. Locally measured SHA-256 pins exact retrieved bytes.',
         '', '| Source file | Bytes | SHA-256 |','|---|---:|---|']
    for s in data['sources']:out.append(f"| {s['filename']} | {s['size_bytes']} | `{s['sha256']}` |")
    out += ['', '## Models, compatibility and processing','',
            'Both exact production bundles were verified before inference and after evaluation. IDs, frozen thresholds and post-run hashes are in frozen-model-verification.json. The existing fitted StandardScaler transforms raw mapped features once; labels are kept in separate arrays and never passed to a model. The evaluation process actively forbids IsolationForest, StandardScaler and XGBClassifier fitting. External application uploads reject threshold overrides. Historical Issue 3 files were not modified.',
            '', '| Detector | Actual ID | Original threshold | Artifact SHA-256 after evaluation |','|---|---|---:|---|']
    for name,b in frozen.items():out.append(f"| {name} | {b['model_id']} | {b['threshold_after']} | `{b['sha256_after']}` |")
    out += ['', 'The versioned adapter, explicit mapping, source headers and numerical type/units checks are in ml/external_dataset_adapter.py, compatibility.json, feature-preflight.json and FEATURE_COMPATIBILITY.md. Source aliases match historical official CICFlowMeter code. Duration is microseconds; packet lengths/totals are payload bytes; packet counts are counts; rates are per second. Published rounding is preserved. The exact originating binary for either dataset is unavailable, so extractor-specific flow construction/packet statistics remain a limitation, not an asserted equivalence.',
            '', f"Chunks: {evaluation['chunk_size']:,} source rows; total executed evaluation/audit time: {evaluation['total_seconds']:.3f} seconds. All selected source bytes were SHA-256 checked before and after processing. The protocol assessed approximately 8.3 GB RAM, 12 logical CPUs and 49.6 GB free disk at start. SQLite and compressed ledgers limit memory growth; exact score arrays support ROC-AUC/AP without score binning. environment.json records the actual runtime versions.",
            '', '## Data quality and exclusions','',
            'Only missing/nonnumeric/NaN/infinite/negative required measurements, transformed input overflow and explicitly unknown ground-truth labels are ineligible. Optional-field missingness is not an exclusion. Finite zero-duration rows and all duplicates remain eligible. Repeated header rows are invalid source records, counted rather than silently skipped. Reason counts can overlap; excluded-record totals are unions. Original labels are retained, including original spelling. Unknown labels are never guessed.',
            '', '| Day | Source records | Eligible | Excluded | Duplicate copies retained | Zero duration (source) |','|---|---:|---:|---:|---:|---:|']
    for day,q in quality.items():
        c=q['counts'];out.append(f"| {day} | {c['source_records']} | {c['valid_records']} | {c['excluded_records']} | {q['duplicate_copies_retained']} | {c['zero_duration_rows']} |")
    out += ['', 'Detailed source/eligible/excluded class distributions and exclusion counts per label/reason are in data-quality.json. A complete compressed ledger with source filename, zero-based row index, original label and all exclusion reasons is retained outside Git; exclusion-ledger-summary.json pins its location and SHA-256. Duplicate auditing uses SHA-256 over all original parsed column tokens, with original records unchanged; it assumes no cryptographic collision. Conflicting valid feature vectors are counted in overlap.json and retained.',
            '', '## Actual external metrics','',
            'Both models use the same eligible external population and their original decision thresholds. ROC-AUC uses attack-oriented scores (negated decision margin for Isolation Forest); PR-AUC is exact average precision. Unsupported single-class metrics are null. Model scores are uncalibrated and are not accuracy; final triage risk is a separate review priority.',
            '', '| Metric | Production XGBoost | Isolation Forest |','|---|---:|---:|']
    for metric in ['samples','benign','attack','accuracy','precision','recall','f1','macro_f1','roc_auc','average_precision','specificity','false_positive_rate','false_negative_rate','balanced_accuracy']:
        values=[evaluation['models'][name]['overall'][metric] for name in ['supervised','baseline']]
        out.append('| '+metric+' | '+' | '.join(str(v) if isinstance(v,int) else f'{v:.8f}' if v is not None else 'UNAVAILABLE' for v in values)+' |')
    out += ['', '| Detector | TN | FP | FN | TP |','|---|---:|---:|---:|---:|']
    for name in ['supervised','baseline']:
        c=evaluation['models'][name]['overall']['confusion_matrix'];out.append('| '+name+' | '+' | '.join(str(c[k]) for k in ['tn','fp','fn','tp'])+' |')
    out += ['', '![External confusion matrices](external-confusion.png)', '', '## Per-day and attack-label performance','',
            '| Detector / day | Samples | Accuracy | Attack recall | FPR | Balanced accuracy |','|---|---:|---:|---:|---:|---:|']
    for name,v in evaluation['models'].items():
        for day,m in v['per_day'].items():
            out.append(f"| {name} / {day} | {m['samples']} | {m['accuracy']:.8f} | {m['recall']:.8f} | {m['false_positive_rate']:.8f} | {m['balanced_accuracy']:.8f} |")
    out += ['', '| Original attack label | Samples | XGBoost detected / missed | Recall | IF detected / missed | Recall |','|---|---:|---|---:|---|---:|']
    for label,m in evaluation['models']['supervised']['per_label'].items():
        if not m['binary_label']:continue
        b=evaluation['models']['baseline']['per_label'][label]
        out.append(f"| {label} | {m['samples']} | {m['detected']} / {m['missed']} | {m['attack_recall']:.8f} | {b['detected']} / {b['missed']} | {b['attack_recall']:.8f} |")
    out += ['', 'The original per-label counts, correct/incorrect decisions and benign false-positive rate are in evaluation.json. These are binary attack-detection results by original family, not predictions of a multiclass model.',
            '', '![Attack-family recall](attack-family-recall.png)', '', '## Internal vs external comparison','',
            'The internal 2017 partition and targeted external two-day population have different class mixtures, prevalence and collection conditions. Their difference is descriptive, not a controlled causal estimate. Neither dataset name proves statistical independence.',
            '', '| Detector / metric | CICIDS2017 internal (n=345892) | Selected CSE-CIC-IDS2018 external |','|---|---:|---:|']
    for name,title in [('supervised','Production XGBoost'),('baseline','Isolation Forest')]:
        a=internal[title]['metrics'];b=evaluation['models'][name]['overall']
        for key in ['accuracy','precision','recall','f1','roc_auc','false_positive_rate']:
            old=a['fpr'] if key=='false_positive_rate' else a[key]
            out.append(f'| {title} / {key} | {old:.8f} | {b[key]:.8f} |')
    out += ['', '![Internal vs external](internal-vs-external.png)', '', '![False positive / negative rates](false-positive-negative-rates.png)',
            '', '## Drift and representation overlap','',
            'PSI is computed by accumulating all eligible external values in saved training-only reference bins, not by averaging chunk PSI or refitting reference bins. It measures distribution change, not attack confidence. Supervised inference has no separately required drift calibration; where no supervised reference is packaged, the saved baseline benign-training reference is explicitly used. Contrast against a benign-only reference is confounded by external attack prevalence.',
            '', '| Feature | XGBoost reference PSI | IF reference PSI |','|---|---:|---:|']
    for feature in drift['baseline']['features']:
        out.append(f"| {feature} | {drift['supervised']['features'][feature]['psi']:.6f} | {drift['baseline']['features'][feature]['psi']:.6f} |")
    out += ['', '![Feature distribution shifts](feature-distribution-shifts.png)', '', 'Measured overlap against all approved eligible 2017 raw vectors and each model-specific float32 representation:', '', '```json',json.dumps(overlap,indent=2),'```',
            '', 'The read-only Issue 3 audit was checked against the approved dataset identity and raw unique-vector count. Matching rows were not filtered. Simple/repeated flows and quantization can produce aliases; matches alone do not prove copied captures, and absent exact matches would not exclude related sessions. If no reference audit is supplied, the tool explicitly reports NOT_RUN.',
            '', 'Measured findings are the PSI histograms, class distributions, exclusions, overlaps and detection errors above. Plausible explanations include network/environment differences, attack implementations, collection policies, rounded rates and CICFlowMeter revisions. Those are hypotheses; this experiment does not establish their causal contributions.',
            '', 'feature-quality.json additionally records full-source missing, explicit NaN, nonnumeric, infinity, negative and zero counts for every required feature, together with eligible-population means/min/max and the saved 2017 holdout comparison. These are descriptive statistics, not new model normalization. Exact raw-vector overlap is parser- and precision-dependent; the separate model-specific float32 audit captures the representation actually consumed by the trees.',
            '', '## Real application demonstration','',
            f"Run {demo['run']}: actual HTTP backend 5049, owned MongoDB {demo['database']} on dedicated port 27018; React proxy 5219. The {demo['records']}-row demo consists of the first 10 eligible source rows per original label per day, selected before predictions. Raw source aliases/measurements are unchanged and labels are retained separately in the ignored source manifest. Input SHA-256 before/after: {demo['input_sha256_before']}. This class-stratified demonstration is not representative external population accuracy.",
            '', '| Detector / saved case | Flows | Attack decisions | Normal decisions | Demo accuracy | Demo recall | HTTP seconds |','|---|---:|---:|---:|---:|---:|---:|']
    for name,r in demo['results'].items():
        s=r['summary'];m=r['metrics'];out.append(f"| {name} / {r['case_id']} | {s['total_records']} | {s['classified_attacks']} | {s['classified_benign']} | {m['accuracy']:.6f} | {m['recall']:.6f} | {r['http_seconds']:.6f} |")
    out += ['', 'Actual API predictions agree with direct frozen inference; scores match within 1e-12 and all eleven source measurements survive MongoDB exactly. Model IDs and thresholds persist in artifacts, case evidence and history. Missing features and external threshold overrides return structured 400 errors. Public API evidence omits raw feature records; full source/prediction evidence and PDFs are retained outside Git. Summary JSON pins PDF paths/checksums. Both 20-page PDFs were rendered and visually inspected, including source/compatibility sections; render verification is in the demo directory.',
            '', f"Live browser verification: **{browser['status']}**. Observation: {browser.get('last_observation',browser.get('tool_observation'))}. Real screenshots captured: {browser['live_screenshots_captured']}. No mock dashboard is counted as UI integration. Service tests/build and HTTP/database/PDF checks are distinct from a live click-through. If browser access remains blocked, overall application acceptance is PARTIAL even though external metric evaluation executed.",
            '', '## Regression and reproducibility','',
            f"Full native/MongoDB regression: {int(tests.get('tests'))-int(tests.get('skipped'))} passed, {tests.get('skipped')} skipped, {tests.get('failures')} failures, {tests.get('errors')} errors. Exact output is in regression-final.txt/XML. Original no-training skip reasons remain explicit. Frontend test/build output is in frontend.txt and check-all.txt. The actual CSV chunk-invariance regression compares exact predictions and scores over different chunk sizes. Source mapping, bad names/units, duplicate headers, missing/nonnumeric/infinite/NaN/negative measurements, unknown labels, zero durations, frozen thresholds, metrics and selector paths are covered.",
            '', 'alignment-verification.json independently reconstructs all source row identities and original labels, checks every saved-score threshold decision, recomputes all metrics, and compares a deterministic source-chunk sample with fresh direct inference. Source-row and prediction archives remain outside Git, pinned by SHA-256. execution-note.json records the interrupted IO-bound attempt and tested bulk-join optimization without changing population, model or thresholds.',
            '', 'Commands and setup: docs/external_validation.md. Full experiment commands:', '', '```powershell',
            'rtk proxy .venv/Scripts/python.exe -m scripts.acquire_external_dataset',
            'rtk proxy .venv/Scripts/python.exe -m scripts.evaluate_external_network --chunk-size 25000 --overlap-db .test-artifacts/issue3/513da53c9db64dd9a545e980271dad37.sqlite',
            'rtk proxy .venv/Scripts/python.exe -m scripts.verify_issue4 --serve',
            'rtk proxy .venv/Scripts/python.exe -m scripts.external_feature_quality',
            'rtk proxy .venv/Scripts/python.exe -m scripts.verify_external_alignment',
            'rtk proxy .venv/Scripts/python.exe -m scripts.render_external_reports',
            'rtk proxy .venv/Scripts/python.exe -m scripts.plot_external_validation',
            'rtk proxy .venv/Scripts/python.exe -m scripts.report_external_validation',
            'rtk proxy .venv/Scripts/python.exe -m pytest --no-training --run-integration -q',
            'rtk proxy .venv/Scripts/python.exe scripts/check.py --all --no-training',
            '```',
            '', '## Known limits and review status','',
            'Chunk-size invariance applies to frozen predictions, scores and detection metrics. The unchanged baseline triage policy remains upload-batch-relative; no batch-relative risk scores are used for this external evaluation.',
            'This is a genuine external benchmark subset, not arbitrary real-world deployment proof. Both CIC datasets are old and related by research group/extractor family. Only web-attack and bot days were selected; other attack families/days are untested. Objective validity filtering changes prevalence, duplicates remain, and per-family counts may be small. Generating-binary provenance and possible label/collection artifacts limit compatibility certainty. Poor recall and false alarms must not be hidden behind overall accuracy. No model was retrained, retuned or replaced after observing these results.',
            '', 'Feature branch: codex/issue-4-external-validation from published Issue 3 main 365e5568fa97c573307da02f10b84ae49040674d. Main must remain unchanged pending review. Exact final commit, PR and CI verification are given in the final task response. No private evidence, raw CSV records, dataset binaries or complete source-row ledgers are intended for Git.']
    out += ['', '## Interpretation notes', '',
            'The overflow guard separately inspects a saved-scaler transform, but never passes that transformed matrix back as raw inference input. Each model receives the mapped original measurements and uses its own frozen preprocessing; direct-inference equality checks rule out the earlier double-scaling path.',
            '', 'Both external balanced accuracies are below 0.5 and attack recall is extremely low. Aggregate accuracy must not be presented as acceptable external detection. XGBoost score-ranking ROC-AUC differs from thresholded recall; this observation does not justify choosing a new threshold from external labels.',
            '', 'Both official CSVs have 1,048,575 source records. Evaluating every row in these files does not establish completeness of the underlying daily packet captures.']
    (ROOT/'REPORT.md').write_text('\n'.join(out)+'\n',encoding='utf-8')
    slides=['# Phase 2 Review 2 — presentation content','',
            '## Slide A — External dataset','Two official CSE-CIC-IDS2018 daily flow CSVs: web attacks (22 February) and bots (2 March). Chosen before predictions to test known weak categories. Include benign traffic; evaluate every eligible row. Evidence: PROTOCOL.md, dataset-manifest.json, data-quality.json.','',
            '## Slide B — Methodology','Official CSV → explicit versioned feature adapter → validity ledger → original saved scaler → frozen XGBoost / Isolation Forest → unchanged threshold → predictions → ground-truth metrics. No training, calibration or tuning. Ground truth remains separate. Compatibility is conditional on documented CICFlowMeter family definitions, not a proved identical extractor build. Evidence: FEATURE_COMPATIBILITY.md, frozen-model-verification.json.','',
            '## Slide C — Results','Use external-confusion.png and attack-family-recall.png. Cite evaluation.json for every value.']
    for name,m in evaluation['models'].items():
        q=m['overall'];slides.append(f"- {name}: n={q['samples']:,}, accuracy={q['accuracy']:.4%}, recall={q['recall']:.4%}, balanced accuracy={q['balanced_accuracy']:.4%}, FPR={q['false_positive_rate']:.4%}. Evidence: evaluation.json models.{name}.overall.")
    slides += ['', '## Slide D — Internal vs external','Use internal-vs-external.png and false-positive-negative-rates.png. Different populations/prevalence; do not attribute the entire difference to domain shift or call it a controlled experiment. Evidence: Issue 3 evaluation.json and Issue 4 evaluation.json.','',
               '## Slide E — Observations and limits','Use feature-distribution-shifts.png and class-distribution.png. PSI measures distribution changes against the frozen training reference. Explain per-family misses and false alarms. Mention conditional feature compatibility, related dataset origins, limited two-day coverage, retained duplicates, representation overlap and unknown live-network performance. No threshold adjustment was made. Evidence: drift.json, overlap.json, FEATURE_COMPATIBILITY.md.','',
               '## Live demonstration','Run verify_issue4 --serve, start React with BACKEND_PROXY_TARGET=http://127.0.0.1:5049 on 5219. Open Cases → a generated external case → Evidence → select CSE-CIC-IDS2018 external network-flow CSV → choose detector → choose .test-artifacts/issue4/demo.csv → Upload and process. Open Artifacts to inspect ID, score, fixed threshold and risk; refresh/reopen; open Reports and generate the saved-case PDF. Repeat for the other detector. Compare genuine labels only in the separate demo metrics. Do not cite the small stratified demo accuracy as dataset accuracy.']
    slides += ['', 'Future work only: establish exact extractor provenance, expand scenario/host/time-separated evaluation, and preregister any new model-training study separately. None of those activities was started during Issue 4.']
    (ROOT/'PRESENTATION.md').write_text('\n'.join(slides)+'\n',encoding='utf-8')


if __name__=='__main__':main()
