# Issue 6B — local controlled research

**No commits, pushes, merges, tags, releases or remote changes. Production models unchanged.**

## Protocol and provenance

Local protocol/hash receipts precede final access but lack independent authenticated timestamps. Four fixed fits: two algorithms × seeds42/43. No expanded features, hyperparameter search, calibration fitting or ensemble. All stages are local research only.
Training uses the original 2017 train mask and March2; validation holds entire February22/16 days; separate February23 calibrates a conservative 1% empirical FPR threshold. Previously opened days are development, never new independent tests. Final February15 was not parsed or used for transductive filtering before selection. All eligible final rows and overlaps were retained.
Official source: https://registry.opendata.aws/cse-cic-ids2018/ and https://www.unb.ca/cic/datasets/ids-2018.html . Use with official CIC citation/attribution. The existing adapter verifies feature mapping and units conditionally; exact extractor binary equivalence is unavailable.

Final source/hash: `fa2947a8256d81ee9103ae16139d62d0e17aa23e696ee80d9e76fb51c01c9c4b` (375,945,899 bytes). Development hashes: development-sources.json. Protocol, code, preparation, selection and final receipts have separate SHA-256 links.

## Measured diagnosis

Issue6 validation shared the same source/scenario days as training. Exact and rounded-bin quarantine did not establish scenario independence. Source/family quotas and balancing changed score semantics and prevalence. Precision depends on prevalence; prevalence alone does not explain an FPR change. A single causal explanation is not established.
Old training had no explicitly labeled 2018 SlowHTTPTest examples; 2017 DoS is a broad merged category. Zero SlowHTTP recall therefore does not prove that all slow attacks are intrinsically indistinguishable. Diagnostics.json records per-partition family counts, unique vectors, quantiles and contradictory-vector minimum errors. Those lower bounds demonstrate observed representation ambiguity, not universal impossibility of the 11 features.
New day separation, conservative calibration and both seed results test the former optimistic within-scenario validation. They do not make the already opened development days independently unseen. Capture-day independence is stronger than alternating blocks but cannot prove host/session independence.

## Actual candidate validation

| Model | Seed | Recall | Precision | FPR | Threshold |
|---|---:|---:|---:|---:|---:|
| lightgbm | 42 | 0.000073 | 0.013245 | 0.002201 | 0.879776527174 |
| lightgbm | 43 | 0.000070 | 0.021053 | 0.001311 | 0.902094029511 |
| xgboost | 42 | 0.000063 | 0.038776 | 0.000632 | 0.91864490509 |
| xgboost | 43 | 0.000850 | 0.085390 | 0.003682 | 0.867114067078 |

Selection uses worst-day validation recall, then AP, name/seed. Selected: xgboost seed 43. Seed spread is descriptive, not an exhaustive stability study. Full day/family/top-K metrics reside in validation.json. Training memory watchdog includes the actual process and child RSS; log values are sampled observations.

## One-shot final comparison

| Model | Accuracy | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|
| incumbent | 0.923100 | 0.268147 | 0.303135 | 0.284570 | 0.043959 |
| challenger | 0.949661 | 0.503259 | 0.173530 | 0.258074 | 0.009101 |

```json
{
  "challenger": {
    "threshold": 0.8671140670776367,
    "overall": {
      "samples": 1040548,
      "benign": 988050,
      "attack": 52498,
      "confusion_matrix": {
        "tn": 979058,
        "fp": 8992,
        "fn": 43388,
        "tp": 9110
      },
      "accuracy": 0.9496611400915671,
      "precision": 0.5032593083637167,
      "recall": 0.17353042020648404,
      "f1": 0.2580736543909348,
      "macro_f1": 0.616010190982314,
      "roc_auc": 0.847234966237332,
      "average_precision": 0.25553069505580145,
      "specificity": 0.9908992459895755,
      "false_positive_rate": 0.009100754010424539,
      "false_negative_rate": 0.826469579793516,
      "balanced_accuracy": 0.5822148330980298,
      "status": "EVALUATED"
    },
    "per_family": {
      "Benign": {
        "samples": 988050,
        "binary_label": 0,
        "true_positive": null,
        "false_negative": null,
        "recall": null,
        "false_positive": 8992,
        "false_positive_rate": 0.009100754010424573,
        "small_sample": false
      },
      "DoS attacks-GoldenEye": {
        "samples": 41508,
        "binary_label": 1,
        "true_positive": 4441,
        "false_negative": 37067,
        "recall": 0.10699142334007902,
        "false_positive": null,
        "false_positive_rate": null,
        "small_sample": false
      },
      "DoS attacks-Slowloris": {
        "samples": 10990,
        "binary_label": 1,
        "true_positive": 4669,
        "false_negative": 6321,
        "recall": 0.4248407643312102,
        "false_positive": null,
        "false_positive_rate": null,
        "small_sample": false
      }
    },
    "top_k": [
      {
        "fraction": 0.001,
        "k": 1040,
        "boundary_score": 0.9367421865463257,
        "tie_group_size": 2138,
        "certain_true_positives": 77,
        "recall_lower_bound": 0.00554306830736409,
        "recall_upper_bound": 0.00554306830736409
      },
      {
        "fraction": 0.01,
        "k": 10405,
        "boundary_score": 0.8803173899650574,
        "tie_group_size": 2952,
        "certain_true_positives": 7859,
        "recall_lower_bound": 0.14970094098822812,
        "recall_upper_bound": 0.14970094098822812
      },
      {
        "fraction": 0.05,
        "k": 52027,
        "boundary_score": 0.8373504877090454,
        "tie_group_size": 19258,
        "certain_true_positives": 10719,
        "recall_lower_bound": 0.20417920682692675,
        "recall_upper_bound": 0.2041982551716256
      },
      {
        "fraction": 0.1,
        "k": 104054,
        "boundary_score": 0.7915781140327454,
        "tie_group_size": 32,
        "certain_true_positives": 15501,
        "recall_lower_bound": 0.29526839117680675,
        "recall_upper_bound": 0.29526839117680675
      },
      {
        "fraction": 0.2,
        "k": 208109,
        "boundary_score": 0.6772331595420837,
        "tie_group_size": 45136,
        "certain_true_positives": 36023,
        "recall_lower_bound": 0.6861785210865176,
        "recall_upper_bound": 0.6861785210865176
      }
    ]
  },
  "incumbent": {
    "threshold": 0.4343418846451664,
    "overall": {
      "samples": 1040548,
      "benign": 988050,
      "attack": 52498,
      "confusion_matrix": {
        "tn": 944616,
        "fp": 43434,
        "fn": 36584,
        "tp": 15914
      },
      "accuracy": 0.9231001356977285,
      "precision": 0.26814719956864597,
      "recall": 0.30313535753743,
      "f1": 0.28456985497916776,
      "macro_f1": 0.6219680555840361,
      "roc_auc": 0.9043861022818243,
      "average_precision": 0.37886953294000875,
      "specificity": 0.9560406862000911,
      "false_positive_rate": 0.04395931379990892,
      "false_negative_rate": 0.69686464246257,
      "balanced_accuracy": 0.6295880218687605,
      "status": "EVALUATED"
    },
    "per_family": {
      "Benign": {
        "samples": 988050,
        "binary_label": 0,
        "true_positive": null,
        "false_negative": null,
        "recall": null,
        "false_positive": 43434,
        "false_positive_rate": 0.04395931379990891,
        "small_sample": false
      },
      "DoS attacks-GoldenEye": {
        "samples": 41508,
        "binary_label": 1,
        "true_positive": 6706,
        "false_negative": 34802,
        "recall": 0.1615592175002409,
        "false_positive": null,
        "false_positive_rate": null,
        "small_sample": false
      },
      "DoS attacks-Slowloris": {
        "samples": 10990,
        "binary_label": 1,
        "true_positive": 9208,
        "false_negative": 1782,
        "recall": 0.837852593266606,
        "false_positive": null,
        "false_positive_rate": null,
        "small_sample": false
      }
    },
    "top_k": [
      {
        "fraction": 0.001,
        "k": 1040,
        "boundary_score": 0.9993206262588501,
        "tie_group_size": 1990,
        "certain_true_positives": 215,
        "recall_lower_bound": 0.019810278486799497,
        "recall_upper_bound": 0.019810278486799497
      },
      {
        "fraction": 0.01,
        "k": 10405,
        "boundary_score": 0.9259073138237,
        "tie_group_size": 1047,
        "certain_true_positives": 9167,
        "recall_lower_bound": 0.17461617585431827,
        "recall_upper_bound": 0.17465427254371596
      },
      {
        "fraction": 0.05,
        "k": 52027,
        "boundary_score": 0.761345624923706,
        "tie_group_size": 819,
        "certain_true_positives": 11047,
        "recall_lower_bound": 0.2104270638881481,
        "recall_upper_bound": 0.21221760828983963
      },
      {
        "fraction": 0.1,
        "k": 104054,
        "boundary_score": 0.01047564297914505,
        "tie_group_size": 25,
        "certain_true_positives": 28739,
        "recall_lower_bound": 0.5477542001600061,
        "recall_upper_bound": 0.5477542001600061
      },
      {
        "fraction": 0.2,
        "k": 208109,
        "boundary_score": 0.0014871377497911453,
        "tie_group_size": 219,
        "certain_true_positives": 45010,
        "recall_lower_bound": 0.8573659948950436,
        "recall_upper_bound": 0.8573659948950436
      }
    ]
  },
  "quality": {
    "input": 1048575,
    "eligible": 1040548,
    "excluded": 8027
  },
  "gates": {
    "recall_gain_at_least_10pp": false,
    "overall_fpr_at_most_5pct": true,
    "every_day_fpr_at_most_5pct": true,
    "precision_at_least_20pct": true,
    "balanced_accuracy_at_least_60pct": false,
    "supported_family_recall_at_least_10pct": true,
    "inference_at_least_1000_flows_per_second": true,
    "loading_under_5seconds": true
  },
  "deployment_eligible": false,
  "loading_seconds": 0.13613420000183396,
  "inference_seconds": 0.5325802999977896,
  "throughput": 1953786.1239034166,
  "ambiguity": {
    "mixed_groups": 62,
    "minimum_deterministic_errors": 122
  },
  "posthoc_exact_train_overlap_rows_retained": 497,
  "selection_sha256": "21ca1164330c641cba16b3a05fa5fb9167e37794ec841e93659ca7876c3bfb78",
  "independence": "New capture day, same testbed; no new independent SlowHTTPTest/web/bot claim"
}
```

ROC/PR coordinates: curves.json. Comparison chart: comparison.png. Confusion matrices, every family recall, all original gate outcomes, exclusions, throughput and ambiguity are actual execution outputs above. Only one final day was evaluated, so the per-day gate covers that day alone. No independent web/bot/SlowHTTPTest confirmation is claimed.

## Deployment / limitations

Retain production detectors. No threshold/default/UI/API change is made. A newly qualifying binary test alone would not establish previously failed absent-family reliability. Prior Issue6 failures remain historical evidence. This experiment does not demonstrate generalization to independent real networks.
Completion is PARTIAL: deployability requires the original gates and meaningful family coverage; see final-results.json. Browser remains UNVERIFIED: “Local browser use is disabled in Work settings.” No screenshots or new UI acceptance are claimed. Application integration for a new detector is conditional on qualification, and no challenger has been deployed.

## Reproduction

Prerequisites: existing native environment plus requirements/network-research.txt and reviewed source files identified by development-sources.json. Raw/model/prediction files are preserved ignored under .test-artifacts/issue6b. Do not remove receipts to refit against opened labels. A reproduction needs a new local output namespace and must be labeled disclosed replay, never unseen validation.
Original commands:
```powershell
rtk proxy .venv/Scripts/python.exe -m scripts.issue6b lock
rtk proxy .venv/Scripts/python.exe -m scripts.issue6b prepare
rtk proxy .venv/Scripts/python.exe -m scripts.issue6b train
rtk proxy .venv/Scripts/python.exe -m scripts.issue6b evaluate
rtk proxy .venv/Scripts/python.exe -m scripts.report_issue6b
rtk proxy .venv/Scripts/python.exe -m pytest -q --no-training --run-integration
rtk proxy npm --prefix frontend run check
rtk proxy .venv/Scripts/python.exe scripts/check.py
```

Current test execution and local-file manifest are recorded separately after checks finish. Existing private evidence is untouched. No Git mutation/publication is authorized or performed.

## Final current verification

Backend **411 passed, 46 skipped**, zero failures/errors; frontend **19 passed**, production build PASS; static checks PASS. Logs are in this directory. All 246 frozen historical/model files match their raw hashes. Git HEAD remains dd3fcdddb99910317076cfac7b30547a823b9278; no Git mutations or remote changes. Skips include forbidden regression fitting fixtures and the absent primary forensic image. Real native controlled disk/PE/YARA/MongoDB/report tests ran.

Additional charts: roc-pr.png and confusion-matrices.png. availability-and-stability.json records original eligible2017 family counts and two-seed metric mean/std. Diagnostics contains descriptive IID Wilson intervals; correlated/duplicate flows mean these are not session-aware coverage guarantees. 497 final rows exactly overlap training vectors; these were counted after inference and retained. This is inductive capture-day evaluation, not duplicate-free independent-site validation. Final peak RSS was not measured; training resource observations are in training.txt.
