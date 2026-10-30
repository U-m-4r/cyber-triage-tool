# Issue 6 protocol v1 — fixed before candidate training

Starting main: `982faa5327723f3b3931831e4bdc4b6da0982061`.
Issue 3/4/5 reports and all deployed model bytes are frozen in checkpoint.json.
No original model, threshold, cleaning ledger or scientific result is overwritten.

## Sources and locked final test

Official source: UNB/CIC https://www.unb.ca/cic/datasets/ids-2018.html and
AWS registry https://registry.opendata.aws/cse-cic-ids2018/ . Public official
bucket `cse-cic-ids2018`, ca-central-1, prefix
`Processed Traffic Data for ML Algorithms/`.

Previously inspected Thursday-22-02-2018 (web) and Friday-02-03-2018 (bot) are
**development only**. Their historical prediction archives are diagnostic only.

Lock before training the complete official daily objects:

- Friday-16-02-2018_TrafficForML_CICFlowMeter.csv (333,723,605 bytes).
- Friday-23-02-2018_TrafficForML_CICFlowMeter.csv (382,840,456 bytes).

These days have not previously been evaluated in this project. Official attack
schedules inform source choice, but no final CSV labels are read for model,
feature or threshold selection. Download and SHA-256 both sources, write
locked-test.json, and commit this protocol and lock before fitting any candidate.
The gate creates a one-shot final-evaluation receipt before opening final labels.
No rerun after seeing test labels is an untouched comparison.

The final population is all structurally valid, finite, nonnegative 11-feature
records with a genuine recognized publisher label, on these two days. Invalid
rows/labels have explicit reason counts and row-index ledgers. Do not sample away
difficult attacks, remove test duplicates or tune on final labels. Retain
conflicting-label test vectors and disclose them. Both incumbent and selected
challenger use the identical retained rows. Final reporting separates each day
and original attack label. Bot independent-scenario testing is unavailable: bot
examples in development come from the same March 2 scenario. Do not claim
independent bot generalization.

## Feature contract / candidate schema

Candidate schema `network-generalization-11-v1` is the existing ordered eleven
raw flow measurements, with exactly the established units and external adapter.
Finite nonnegative values only, no guessed values or unit conversion. Candidate
trees use raw float32 measurements, **identity preprocessing** (no fitted scaler).
The incumbent still uses its own unchanged saved scaler exactly once.

Candidate B (expanded columns) is not approved: the available reviewed 2017
cleaned source and current intended application uploads provide only the eleven
features. Extra IAT/flag columns in 2018 cannot be reproduced across those inputs.
No ports, timestamp, source/day, labels, addresses or identifiers enter prediction.
Timestamp is used only to partition development. Conditional CICFlowMeter build
equivalence remains a limitation, not a claim of exact extractor compatibility.

## Training / validation / duplicate controls

- CICIDS2017: use only the original eligible **training** mask, never its existing
  validation/test rows. Fixed per-family bottom-hash sample, at most 10,000 per
  original training class (seed 42, source row hash; no prediction selection).
- The two development 2018 days: parse day-first timestamps. Whole 10-minute
  blocks with an even block number within the hour are training; odd blocks are
  validation. Exclude training rows in the first/last minute of a block as a
  temporal embargo. Missing/unparseable timestamps are excluded explicitly.
  This separates time blocks, not guaranteed sessions/hosts; no complete 5-tuple
  is available in these processed CSVs. Sample training at most 25,000 per
  source/original label and validation at most 20,000 per source/original label,
  using the same deterministic bottom-hash policy. Retain all rare classes up to
  their cap. Sampling changes class prevalence; measured validation precision
  is for that population and is not a deployment prevalence estimate.
- Before training, scan **unlabeled features only** on locked final days. Purge
  training and validation vectors that overlap final features in either canonical
  float32 model representation or `round(log1p(x),3)` near-duplicate bins. This
  conservative, test-feature-informed quarantine is disclosed as transductive
  leakage control; no test labels or predictions influence it. Final population
  is never pruned. A 64-bit fingerprint collision can only over-purge development;
  record implementation/dependency versions and counts. This is a bounded
  quantization surrogate, not proof that all near duplicates/sessions are removed.
- Purge training overlaps with validation using both representations, then
  deduplicate training by float32 vector without labels. Conflicting training
  labels for a model vector exclude the full vector group and are counted.
  Validation duplicates retained; report overlaps and distributions before/after.
- Store source row identities and all exclusion counts; no silent discarded rows.

## Controlled candidate budget and selection

Seed 42, two CPU threads, at most 120 seconds fit per candidate, sequential fits,
maximum two trained candidates; no search or repeated tuning:

1. Frozen production XGBoost reference at its published threshold.
2. Revised XGBoost: 300 maximum rounds, learning rate .05, max depth 5,
   min_child_weight 10, subsample .8, colsample_bytree .9, reg_lambda 10,
   histogram method, max_bin 128; validation logloss early stopping 30 rounds.
3. LightGBM: 300 maximum rounds, learning rate .05, num_leaves 31,
   max_depth 6, min_child_samples 50, subsample .8/subsample_freq 1,
   colsample_bytree .9, reg_lambda 10, max_bin 127; validation logloss early
   stopping 30 rounds, deterministic column-wise mode.

Training sample weights: each observed source/original-label group has equal
total weight, normalized to mean one. This prevents abundant bot/benign records
from erasing rare web examples. Record every group/count/weight. No validation or
test labels determine weights. Class prior is deliberately changed: outputs are
uncalibrated scores; no probability calibration is claimed.

For each candidate and the incumbent as a *diagnostic optional operating point*,
select the validation threshold maximizing recall under empirical **FPR <=5%**;
ties choose higher precision, then higher threshold. Include a reject-all option
and complete tied-score groups; never split ties to satisfy a budget. Report
1/5/10% FPR operating points, AP, ROC, macro-F1, balanced accuracy, family recall,
review budgets and Top-K recall with conservative tied-score handling.

Select one challenger by highest validation macro recall across original attack
labels under its 5% FPR point; ties highest AP, then lower FPR, then name.
Model, feature order, model hash, training identity hash and threshold are sealed
in selection.json **before** final labels are opened. Only that challenger and
the frozen incumbent (published threshold) reach final evaluation. No other
candidate final testing, post-test tuning or seed search. Validation-only
incumbent retuning is a diagnostic comparator and does not alter production.

## Deployment gates fixed before final testing

Optional deployment requires all of:

- Final recall improves over incumbent by >=10 percentage points.
- Overall and each final-day FPR <=5%; precision >=20%; balanced accuracy >=.60.
- Each final attack label with >=30 records recall >=10%; smaller labels are
  reported but cannot substantiate a reliable per-family claim.
- Final test and production byte/feature/inference consistency and resource
  checks pass; loading <5s and inference >=1,000 flows/s on the recorded machine.
- All critical app regressions pass; model integrity/provenance is pinned.

If a gate fails, **no deployment integration or production default change**.
Publish the honest negative research result. Candidate artifacts remain outside
Git and are not shown as production detectors. A promising sampled-development
result alone is not a generalization success.

## Resources, diagnostics and reporting

Resource observation before acquisition: 8.30 GB RAM, ~1.72 GB available, 46.5 GB
free disk, 6 physical /12 logical cores. New objects total 716.6 MB; no PCAPs,
malware or full dataset download. Chunk size 10,000, <=~220k sampled development
rows; sorted numeric fingerprint arrays avoid a large Python object/SQLite join.
Process fits sequentially with a watchdog; no multi-hour job authorized here.

Historical scores: independently verify archive hashes against Issue 4 alignment
report before diagnostic histograms/ROC/PR/threshold/review curves. These curves
are retrospective, not new operating-point validation. Record data shift,
timestamp/family representation, model score distributions and feature units;
separate measured findings from plausible causes.

Persist protocol, data/model hashes, configurations, dependencies, execution logs,
selection receipt, final one-shot receipt, metrics, confusion matrices, family
counts, timing/memory and plots under test-results/issue-6. Raw CSVs, model text
files, prediction arrays and row ledgers stay in ignored .test-artifacts/issue6.
No final-test feedback changes the candidate; further iteration requires another
previously unused locked test source and a new protocol.
