"""Build the Issue 3 review tables from executed experiment outputs."""
import json
from pathlib import Path
import xml.etree.ElementTree as ET


def main():
    root=Path('test-results/issue-3')
    read=lambda name:json.loads((root/name).read_text(encoding='utf-8-sig'))
    e=read('evaluation.json'); audit=read('split-audit.json')
    demo=read('371f97c025e041eba3108ab6c89424fb/summary.json')
    manifest=json.loads(Path('models/network-artifacts.json').read_text())
    tests=ET.parse(root/'regression-final.xml').getroot().find('testsuite')
    out=['# Issue 3 — executed network reliability review',
         '', 'Completed locally on 2026-10-30. Frozen inference only; no model/scaler training, threshold retuning, full-dataset download, or external-dataset validation was performed.',
         '', '## Implementation and checkpoint',
         '', 'Issue 2 was reviewed and checkpointed as `10bd89dd62037b21901fb2612c99e0520a4af359` on `codex/issue-2-pe-malware-ml`. Issue 1 checkpoint `4701b7d99fb3d22168031312353686e2a15f7a28` remains in history. Work continued on `codex/issue-3-network-ml`. The existing untracked `dfr-01-ntfs.dd/` evidence directory was not changed or staged. Model binaries, source CSVs, scratch databases, credentials and .env files are excluded from source commits.',
         '', 'Changes:',
         '', '- `scripts/benchmark_supervised.py`: baseline inference now receives raw held-out features and applies its own scaler exactly once. Raw test/validation frames are retained alongside candidate-scaled arrays. Training requires an explicit flag and refuses overwriting historical results.',
         '- `ml/supervised_detector.py`: validate estimator type, fitted feature dimensions/order, microsecond units, runtime versions, label semantics, threshold and uncalibrated score contract. Both network loaders fingerprint the exact bytes loaded.',
         '- `ml/risk_scorer.py`: supervised attack scores increase triage severity directly; they are no longer inverted as anomaly margins. Existing 60/40 empirical network ML/rule weighting remains, documented separately from confidence. Rule-only host and PE/YARA scoring is preserved.',
         '- `backend/app.py`, `backend/config.py`: explicit selector/default, accurate inventory, no fallback, per-flow model ID/score/threshold, measured counters/timings, selected evaluation endpoint and exact original numeric-feature persistence. MongoDB metadata normalizes label-map keys to BSON-compatible strings.',
         '- `backend/integration.py`, `backend/report_generator.py`: preserve selected detector in artifacts, case-source summaries, rationale and saved-case PDFs.',
         '- React `IntakePanel`, `IntakeHistory`, `CaseArtifacts`: availability-aware selector, selection/provenance, actual decisions and separate prediction/score/threshold/risk.',
         '- Nine new network regression cases plus frozen evaluation, threshold replay, overlap diagnosis, real HTTP demonstration and artifact-acquisition scripts. CI uses pinned released weights and never trains them.',
         '', '## Deployed artifacts and preprocessing',
         '', '| Artifact / actual estimator | ID | Threshold | Bytes | SHA-256 |', '|---|---|---:|---:|---|']
    for name,m in manifest['artifacts'].items():
        out.append(f"| {name} / {'IsolationForest' if name.startswith('cicids') else 'XGBClassifier'} | {m['model_id']} | {m['decision_threshold']} | {m['size_bytes']} | `{m['sha256']}` |")
    out += ['', 'The two original fitted bundles are published as [network-models-v1](https://github.com/U-m-4r/cyber-triage-tool/releases/tag/network-models-v1), outside Git source history. A fresh public download, checksum verification, model load and 84-row inference passed (`release-download.txt`, `release-verification.json`, `release-assets.json`). Joblib is executable serialization; the downloader accepts only the reviewed checksum-pinned project assets. No recovered/uploaded model is loaded.',
            '', 'Feature schema v1: `Flow Duration`, `Total Fwd Packets`, `Total Length of Fwd Packets`, `Fwd Packet Length Max`, `Fwd Packet Length Min`, `Fwd Packet Length Mean`, `Bwd Packet Length Max`, `Bwd Packet Length Min`, `Flow Bytes/s`, `Flow Packets/s`, `Packet Length Mean`. Raw float64 inputs, exact order; duration microseconds, packet lengths/totals bytes, counts packets, rates per second. Each bundle applies its own saved StandardScaler once. Tree implementations reduce model inputs to float32, audited below.',
            '', 'Isolation Forest: 100 trees, seed 42, contamination 0.1; fitted only on 1,051,117 unique benign training vectors. Decision function <0 is anomaly (score_samples offset -0.47321778481357596). XGBoost: 200 trees, max_depth 8, learning_rate 0.08, histogram method, seed 42; scaler fit on all 1,612,277 training rows, labels 0=BENIGN and 1=ATTACK. Exact saved metadata, versions, training provenance and scaler means are in `initial-model-audit.json`. Independent streaming reconstruction matched saved scaler sample counts, means and variances; no scaler was refitted.',
            '', 'XGBoost validation-only threshold selection (F1 under FPR <=0.002) was replayed on 343,070 validation rows and reproduced **0.4343418846451664**, including saved validation metrics (`threshold-audit.json`). Historical experimental XGBoost uses 0.5. Continuous test scores are identical (maximum difference 0), but thresholds change 32 decisions. Production must cite its own metrics below rather than copy the old benchmark number. Neither tree scores nor triage scores are calibrated confidence.',
            '', '## Benchmark defect and measured binary results',
            '', 'The old benchmark supplied the supervised StandardScaler output to `infer_network`, which then applied the baseline scaler. Reconstructing that exact mistake reproduces historical accuracy 0.8447260994761371 and recall 0. Correct raw-input inference therefore explains the old zero-recall result. Correction reduces overall accuracy, increases recall and increases false positives. This is not a performance-improvement claim. The historical JSON remains byte-for-byte unchanged, with a separate `evaluation/benchmark/HISTORICAL_NOTICE.md` warning.',
            '', 'All rows below use the same 345,892 internal held-out eligible rows: 292,184 benign and 53,708 attack. PR-AUC is average precision (not trapezoidal interpolation).',
            '', '| Frozen model | Accuracy | Precision | Recall | F1 | Macro-F1 | ROC-AUC | PR-AUC/AP | FPR | FNR |', '|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
    binary=[(n,v) for n,v in e['models'].items() if 'metrics' in v and 'f1' in v['metrics']]
    for name,v in binary:
        m=v['metrics']; out.append('| '+name+' | '+' | '.join(f"{m[k]:.8f}" for k in ['accuracy','precision','recall','f1','macro_f1','roc_auc','pr_auc','fpr','fnr'])+' |')
    out += ['', '| Model | TN | FP | FN | TP |', '|---|---:|---:|---:|---:|']
    for name,v in binary:
        cm=v['metrics']['confusion_matrix']; out.append('| '+name+' | '+' | '.join(str(cm[k]) for k in ['tn','fp','fn','tp'])+' |')
    out += ['', '![Production confusion matrices](confusion-matrices.png)',
            '', 'The experimental binary LightGBM/XGBoost/ExtraTrees/RandomForest/CatBoost estimators and five multiclass estimators were actually loaded and evaluated. Their checksums and all per-class precision/recall/F1/confusions are in `evaluation.json`. They lack packaged scalers and complete provenance. Their documented historical training-only transformation was reconstructed using the independently verified production supervised scaler; exact historical binary values reproduce. This is weaker provenance than the deployment bundles, and differences in objectives/thresholds prevent treating the table as a perfectly controlled training comparison. They are not exposed as production options.',
            '', '### Class-specific weaknesses',
            '', '| Model | Web Attack precision | Web Attack recall | Web Attack F1 | Macro-F1 | Weighted-F1 |', '|---|---:|---:|---:|---:|---:|']
    for name,v in e['models'].items():
        if 'Experimental multiclass' not in name or 'metrics' not in v: continue
        m=v['metrics']; w=m['per_class']['Web Attacks']; out.append(f"| {name} | {w['precision']:.8f} | {w['recall']:.8f} | {w['f1']:.8f} | {m['macro_f1']:.8f} | {m['weighted_f1']:.8f} |")
    out += ['', '**Production binary XGBoost detects only 20/272 Web Attacks (7.35% recall), and 96/156 Bots (61.54%).** Corrected Isolation Forest detects 11/272 Web Attacks, 4/156 Bots and 3/1,284 Brute Force flows. Experimental multiclass XGBoost identifies 21/272 Web Attacks despite 99.7736% overall multiclass accuracy. Experimental LightGBM has high Web recall but very low precision/F1. These limitations must accompany presentation accuracy claims.',
            '', '![Experimental multiclass confusion matrix](multiclass-xgboost-confusion.png)',
            '', '## Dataset, splits and leakage audit',
            '', f"Approved source: Kaggle `ericanacletoribeiro/cicids2017-cleaned-and-preprocessed`, local `data/sample/cicids2017_cleaned.csv`, {audit['dataset_bytes']:,} bytes; SHA-256 `{audit['dataset_sha256']}`. Cleaning record SHA-256 `{audit['cleaning_record_sha256']}`; exclusion ledger SHA-256 `b6221758be8c0febced43df021e62d80ac94a8ab4361da7d74199b3f236b9460`. Original 2,520,751 rows; 219,512 excluded; 2,301,239 eligible. Source labels and previously approved exclusions were preserved. The scripts verify dataset/cleaning hashes against each frozen bundle.",
            '', 'Unchanged `numeric-feature-group-hash-v1`, seed 42, nominal 70/15/15. Split-index SHA-256 fingerprints exactly match both deployment bundles (`split-audit.json`).',
            '', '| Partition | Total | Benign | Attack |', '|---|---:|---:|---:|']
    for split,dist in audit['class_distributions'].items():
        total=sum(dist.values()); benign=dist['Normal Traffic']; out.append(f'| {split} | {total} | {benign} | {total-benign} |')
    out += ['', '| Representation | Unique vectors | Duplicate copies | Cross-partition groups |', '|---|---:|---:|---:|']
    for name,v in audit['overlaps'].items():
        out.append(f"| {name} | {v['unique_vectors']} | {v['duplicate_copies']} | {v['cross_partition_groups']} |")
    out += ['', 'The streaming audit independently hashes canonical little-endian numeric rows with SHA-256 and tracks partition membership in ignored SQLite scratch storage. It does not infer zero overlap solely from the split policy. Raw exact duplicates stay grouped, but rounding in preprocessing/model float32 conversion produces cross-partition aliases. The assumption is no SHA-256 collisions.',
            '', 'A separately labeled post-hoc diagnostic removes test vectors aliased to training model inputs (`overlap-sensitivity.json`). Isolation Forest: 8,713 alias groups / 36,200 test rows excluded; remaining 309,692, accuracy 0.82935303. XGBoost: 8,744 groups / 36,090 rows excluded; remaining 309,802, accuracy 0.99746935. These different denominators are not a replacement benchmark or new independent validation. Do not call the original split leakage-free.',
            '', 'No evidence of scaler fitting on test data was found; training-only moments match. Threshold selection is validated independently. However, historical candidate comparisons inspected the final test set before production model choice, so test-informed algorithm selection cannot be excluded. Global label-conflict cleaning uses source labels before splitting and changes the evaluated population. Feature selection provenance cannot establish that final-test feedback never influenced earlier research choices. Hash grouping does not separate sessions, hosts, time, near-duplicate or highly related traffic. The safest future correction is a separately versioned quantization-aware/session/temporal policy and independent evaluation, preserving these results. No split change, retraining or Issue 4 validation was begun.',
            '', '## Actual application experiment',
            '', f"Final run: `{demo['run']}`, owned MongoDB `{demo['database']}` on 127.0.0.1:27018; real HTTP backend 5039, React proxy 5209. Fixture: first 12 held-out source rows from each of seven classes (84 total), selected without looking at predictions. Input {demo['input_bytes']} bytes. Original source indices/class counts are in `demo-source.json`; the raw CSV is ignored. Before/after SHA-256 `{demo['csv_sha256_before']}` is identical. This balanced demonstration is not used for population performance metrics.",
            '', '| Selected detector | Case | Flows | Attack/anomaly | Benign/normal | Load seconds | CSV inference seconds | Flows/s | HTTP seconds |', '|---|---|---:|---:|---:|---:|---:|---:|---:|']
    for r in demo['results']:
        s=r['summary']; t=r['timings']; out.append(f"| {r['detector']} | {r['case_id']} | {s['total_records']} | {s['classified_attacks']} | {s['classified_benign']} | {t['model_loading_seconds']:.6f} | {t['csv_inference_seconds']:.6f} | {t['records_per_second']:.2f} | {r['http_request_seconds']:.6f} |")
    out += ['', 'CSV inference timings include read/validation, transformation, prediction and applicable drift work; throughput is that measured stage, not a pure estimator benchmark. HTTP time includes risk scoring, persistence and response; report generation is separate. These are single warm-process observations, not statistically established latency guarantees. Full evaluation load/inference/throughput timings are also in `evaluation.json`. Hardware and dependency versions are in `environment.json` (Windows 11, Python 3.14.7, 12 logical CPUs, about 8.30 GB RAM).',
            '', 'Both selected models agree with direct inference on exactly the same raw records, scaler and threshold. Retrieved MongoDB scores match within 1e-12; all eleven numeric feature inputs round-trip exactly. IDs, decisions and thresholds survive retrieval and case history. Real missing-feature CSV returns 400; temporarily configured absent supervised artifact returns explicit 503 without baseline fallback. See actual `*-upload.json`, `*-artifacts.json`, `*-history.json`, `*-case.json`, `summary.json` and `live-experiment-final.txt`.',
            '', 'Actual React file-picker upload also ran in earlier owned run `42789c78b77a474a8851169426de8515`, creating `CASE-B2C4773FE166`: selected XGBoost, 84 stored, 55 attack /29 benign. Selection, success and artifacts screenshots/DOM are retained. Final-run cases were opened after navigation/reload; screenshots and DOM show saved XGBoost and Isolation Forest model IDs, exact thresholds and genuine scores. Browser console error check returned no errors. These are live application screenshots, not mock dashboards.',
            '', 'Both final PDFs have 26 pages and contain saved model IDs, SHA-256, decision thresholds, actual counts and per-finding prediction rationale. Text assertions passed; all pages rendered; no extracted text block falls outside page bounds. All-page contact sheets and representative pages were visually inspected, including the source/model summary on page 26. See `pdf-render-checks.json`, PDFs, extracted text and PNGs in the final run directory.',
            '', '## Regression evidence',
            '', f"Final full native/MongoDB suite: **{int(tests.get('tests'))-int(tests.get('skipped'))-int(tests.get('failures'))-int(tests.get('errors'))} passed, {tests.get('skipped')} skipped, {tests.get('failures')} failures, {tests.get('errors')} errors** (`regression-final.txt`, XML). Nine cases added to the prior 336-pass baseline. Disk-image/YARA/PE tests remain passing. Skips include tests prohibited from fitting by --no-training and the unavailable large primary image; exact skip reasons are logged. No tests or assertions were weakened.",
            '', '`scripts/check.py --all --no-training` also passed syntax, pip dependency consistency, Ruff checks/required formatting, Flask configuration, diff whitespace checks, backend **338 passed/53 skipped** (seven MongoDB tests disabled without integration flag), frontend **17 passed**, and Vite production build (`check-all-final.txt`). PowerShell labels Git line-ending warnings as NativeCommandError text, but Git exits 0 and the checks continue successfully. Earlier failed logs are retained: BSON integer label-map keys and a missing feature-constant import were corrected, then the final runs passed.',
            '', '## Reproduction commands',
            '', 'Run from the repository root. This environment uses RTK; replace the interpreter path with `.venv/bin/python` on Linux. The full approved CSV/cleaning ledger and optional experiment estimators are required to reproduce all evaluation rows; missing experimental artifacts are explicitly UNAVAILABLE rather than trained or substituted.',
            '', '```powershell',
            'rtk proxy .venv/Scripts/python.exe -m pip install -r requirements/dev.txt -r requirements/network-ml.txt',
            'rtk proxy .venv/Scripts/python.exe -m scripts.acquire_network_models',
            'rtk proxy .venv/Scripts/python.exe -m scripts.verify_network_models',
            'rtk proxy .venv/Scripts/python.exe -m scripts.verify_network_threshold',
            'rtk proxy .venv/Scripts/python.exe -m scripts.network_overlap_sensitivity --audit-db <scratch-file-from-evaluation.sqlite>',
            'rtk proxy .venv/Scripts/python.exe -m scripts.verify_issue3 --serve',
            '# Separate terminals; dedicated test MongoDB must already listen on 27018.',
            'rtk proxy powershell -NoProfile -Command "$env:BACKEND_PROXY_TARGET=\'http://127.0.0.1:5039\'; npm --prefix frontend run dev -- --port 5209 --strictPort"',
            'rtk proxy .venv/Scripts/python.exe -m pytest --no-training --run-integration -q --junitxml=test-results/issue-3/regression-final.xml',
            'rtk proxy .venv/Scripts/python.exe scripts/check.py --all --no-training',
            'rtk proxy .venv/Scripts/python.exe -m scripts.render_network_evidence test-results/issue-3/<new-run-id>',
            'rtk proxy .venv/Scripts/python.exe -m scripts.build_network_review',
            '```',
            '', 'Rendering additionally uses PyMuPDF 2.0 and pypdf (already installed for review); it does not affect inference. The review builder currently points at this final UUID run, so update that one run-directory argument in the builder for a new experiment. Audit scratch filenames are unique and passed explicitly to sensitivity analysis. Back up this Issue 3 output directory before repeating an experiment; historical evaluation directories remain untouched.',
            '', 'For presentation, capture Evidence with the selected detector/provenance and upload counters, Artifacts with predictions/scores/thresholds, Ingestion history after reopening, and the saved-case report page 26. Use the confusion matrices alongside the Web Attack limitations. XGBoost learns boosted decision trees over eleven static flow features; Isolation Forest isolates unusual benign-relative patterns. Neither is the EMBER2024 PE malware classifier.',
            '', '## Limits and publication',
            '', 'CICIDS2017 is old, imbalanced and dataset-specific. Related-flow/quantization overlap, globally filtered labels and historical model selection limit the strength of internal results. Distribution shift and new-network attack generalization remain untested. A 99% internal accuracy does not guarantee 99% live performance. Optional attack-family production bundle is absent; that advisory stage is reported unavailable and does not replace either selected binary detector. Non-network functionality is preserved. No external validation was started.',
            '', 'Release assets were published and independently downloaded/verified. Source commits, feature/main push and GitHub check outcomes are reported in the final task response after remote verification; no publication is claimed solely from a local commit. All evidence here contains public benchmark-derived results and dedicated test-case identifiers, not private forensic evidence.']
    (root/'REPORT.md').write_text('\n'.join(out)+'\n',encoding='utf-8')


if __name__=='__main__':
    main()
