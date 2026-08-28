# Phase-2 Review-1 — Results Defence and Deck Review

Companion to `scripts/verify_results.py`. Everything below is derived from
`evaluation/results.json` (run of 2026-08-27, commit `00379bc`) and from the
code in `ml/` and `evaluation/`. Regenerate the evidence with:

```
python scripts/verify_results.py                                       # offline audit
python scripts/verify_results.py --data data/cicids2017_cleaned.csv    # full diagnostics
```

---

## 1. Verdict on the deck

The deck is structurally sound and unusually honest for a Phase-2 review. The
abstract, methodology and implementation slides are specific, the module status
table is the strongest slide in the pack, and the references now include the
primary sources that actually matter (Liu/Ting/Zhou for Isolation Forest,
Fawcett for ROC, Sokolova/Lapalme for imbalanced metrics). Citing the repository
as `[25]` with named files is exactly what a reviewer wants to see.

Three things will cost marks, in descending order of severity.

**The Experimental Setup, Results and Analysis slide is empty.** Slide 11 is
still the template's list of headings — "Dataset / test cases", "Experimental
environment", "Parameters / configurations", "Evaluation metrics", "Testing
procedure", "Results", "Expected results" — with no content under any of them.
This is the slide the entire question "how did you get these results" attaches
to. Presenting the results in the abstract and conclusion while leaving the
results slide blank invites the reviewer to ask the question in its most
hostile form.

**The numbers are weak and one of them is beatable by a one-line baseline.** The
reported 0.746 accuracy is *lower* than the 0.8215 you get by labelling every
record benign. A reviewer who knows the CICIDS2017 class balance will spot this
in seconds. This is survivable — but only if you raise it first and reframe it.
Section 3 is how.

**`pptcontent.md` in the repo still contains a completely different, inflated
set of results** — 91.4% accuracy, 0.924 ROC-AUC, 98% Top-25% recall, a
756,177-row test split, and a confusion matrix that does not reproduce its own
stated precision. Those figures came from mistaking the Isolation Forest's
*predictions* at `contamination=0.1` (252,059 flagged rows) for the dataset's
*ground-truth* class distribution. The deck you are presenting uses the correct
numbers, so this is not currently an error in the presentation — but the file is
in the repository you cite as `[25]`, and a reviewer who opens it finds two
irreconcilable result sets under one project. Fix or delete those sections
before the review.

Smaller items: slide numbering repeats (9 appears three times, 11 four times);
the contents slide says "Implementation of project Execution" while the slide
itself is titled "Demonstration of Project Execution"; and references [6]–[15]
carry no venue, volume or page numbers, which reads as placeholder padding next
to the properly formed [17]–[24].

---

## 2. The numbers, verified

Every metric in `results.json` reproduces exactly from its own confusion matrix,
so nothing is mistyped or hand-edited. `scripts/verify_results.py` prints the
PASS lines for this.

| Stage | Rows |
|---|---|
| Loaded from CSV | 2,520,751 |
| After `replace(inf→NaN) → dropna() → drop_duplicates()` | 1,829,580 |
| Removed | 691,171 (27.42%) |
| Benign / attack | 1,503,049 (82.15%) / 326,531 (17.85%) |
| Train / test (70/30 stratified, seed 42) | 1,280,706 / 548,874 |

Confusion matrix on the 548,874-row held-out split:

|  | Pred BENIGN | Pred ATTACK |
|---|---|---|
| **Actual BENIGN** | TN = 402,643 | FP = 48,272 |
| **Actual ATTACK** | FN = 91,270 | TP = 6,689 |

| Metric | Value |
|---|---|
| Accuracy | 0.7458 |
| Attack precision / recall / F1 | 0.1217 / 0.0683 / 0.0875 |
| ROC-AUC | 0.6195 (Gini 0.239) |
| Top-10% triage: recall / precision | 0.0678 / 0.1210 |
| Top-25% triage: recall / precision | 0.3039 / 0.2169 |

And the comparison that decides how this review goes:

| Strategy | Accuracy | Precision | Recall | F1 |
|---|---|---|---|---|
| Predict everything BENIGN | **0.8215** | — | 0.0000 | 0.0000 |
| Predict everything ATTACK | 0.1785 | 0.1785 | 1.0000 | **0.3029** |
| Random 10.01% flagged | 0.7571 | 0.1785 | 0.1001 | 0.1283 |
| Isolation Forest (ours) | 0.7458 | 0.1217 | 0.0683 | 0.0875 |

At the same 10% flag rate, random selection beats the model on precision, recall
and F1. That is the fact to walk in already holding an answer to.

---

## 3. What the numbers actually say

There is a real, teachable finding buried in this run, and it is a much better
story than the metrics look.

**The anomaly score is not monotonic in attack probability.** Lift — precision
at K divided by the base rate — is 0.678× in the top 10% and 1.215× in the top
25%. The most extreme decile of anomaly scores is *attack-poorer* than random,
while the top quartile as a whole is attack-richer. The ROC-AUC of 0.6195 stays
above 0.5 because the bulk ordering is informative; the tail is inverted.

The mechanism is a property of the dataset meeting an assumption of the
algorithm, not a bug:

Isolation Forest is built on the premise that anomalies are "few and different"
(Liu, Ting & Zhou, ICDM 2008) — rare points in sparse regions get short
isolation paths. CICIDS2017's attack mass is the opposite: DoS Hulk, DDoS and
PortScan are high-volume, near-identical flows that form dense clusters. Dense
points get long isolation paths, so the algorithm scores them as *normal*. The
genuine extremes in these eleven flow features are rare-but-legitimate benign
flows — very long sessions, bulk transfers, unusual byte rates — and those take
the top decile instead. Sections D and E of `verify_results.py` show this
directly: a score-decile table where D1 sits below 1.0× lift, and a per-class
table where the high-volume attack families have mean percentile ranks near or
below 50.

Two further factors compound it. `contamination` was set to 0.1 while the actual
prevalence is 17.85%, so the model is only permitted to flag 54,961 of 97,959
attacks — recall is capped at 56.11% before the model does anything, and it
reached 12.17% of that ceiling. And the feature set is eleven of roughly
seventy-eight CICIDS2017 columns, weighted toward the forward direction: no
backward packet counts, no inter-arrival-time features, no TCP flag counts. Those
are precisely the discriminative features for PortScan (SYN flags, tiny flows)
and for slowloris-style attacks (IAT structure).

**One more gap to own before it is found.** The Top-25% recall of 0.304 — the
headline triage number — is computed by ranking on the raw Isolation Forest
`decision_function` alone (`evaluation/evaluate.py`, `compute_top_k_metrics`).
The 60/40 hybrid risk score, which is the project's actual contribution, plays
no part in producing it. Section H of `verify_results.py` runs the missing
comparison. Relatedly, only four of the twelve rules can ever fire on a
network-flow CSV — `detect_artifact_type` returns `network` for every row, so the
failed-login, temp-executable and autorun-registry rules on the deck's rule
slide are structurally unreachable on the data you evaluated. Section G counts
this. The rule threshold on the deck (100,000 packets/s) also disagrees with the
code (`> 10000` in `ml/risk_scorer.py`).

---

## 4. Fill slide 11 with this

Replace the seven template headings with content. Suggested layout, two columns
of setup on the left and the results table on the right:

**Setup.** Dataset: CICIDS2017 cleaned release (Kaggle,
`ericanacletoribeiro/cicids2017-cleaned-and-preprocessed`), 2,520,751 rows →
1,829,580 after cleaning, label column `Attack Type`, 82.15% benign / 17.85%
attack. Environment: Intel Core i7, 16 GB RAM, no GPU; Python 3, scikit-learn.
Configuration: `IsolationForest(n_estimators=100, contamination=0.1,
max_samples=256, random_state=42)`, StandardScaler z-scores on 11 flow features,
70/30 stratified split, seed 42. Metrics: accuracy, per-class precision/recall/F1,
ROC-AUC, and Top-K triage recall. Procedure: `python scripts/run_evaluation.py`
writes `evaluation/results.json` plus three PNG artifacts — the run is
reproducible from the repository.

**Results.** Put the confusion matrix and the metric table from section 2 here,
then the line that saves you:

> At 17.85% attack prevalence, an all-benign classifier scores 0.8215 accuracy.
> Accuracy is therefore not a meaningful measure for this task. We report it for
> completeness and evaluate the system on ranking quality instead: ROC-AUC 0.620
> and Top-25% triage recall 0.304 (1.22× lift over random selection).

**Expected results.** State the target and the route to it: ROC-AUC ≥ 0.85 and
Top-10% recall ≥ 0.60 by Review-2, via `contamination` matched to prevalence, the
full ~78-feature set including backward-direction and IAT features, and Top-K
ranked on the hybrid risk score rather than the raw anomaly score.

Also worth doing to the rest of the deck: add the class balance to the abstract
(one clause — "82.15% benign / 17.85% attack" — pre-empts the whole accuracy
line of attack), fix the duplicated slide numbers, align the contents-slide
wording with the slide title, and either complete references [6]–[15] with real
venues and page numbers or cut them. With a Scopus submission claimed on the
publications slide, a reviewer is entitled to check a citation.

---

## 5. Reviewer question bank

**"How did you get 74.6% accuracy?"**
TP+TN over N on a 30% stratified held-out split of 1,829,580 cleaned records —
409,332 of 548,874. It is in `evaluation/results.json`, regenerable with
`python scripts/run_evaluation.py`, and every metric in that file reproduces from
the committed confusion matrix.

**"Isn't 74.6% worse than just calling everything benign?"**
Yes — 82.15%, and we say so on the slide. That is the point we want to make about
metric choice: at this prevalence accuracy rewards the majority class, so it
cannot distinguish a useful triage tool from a trivial one. The system is not a
classifier; it is a ranker whose job is to order an investigator's queue. The
metrics that measure that are ROC-AUC (0.620) and Top-K recall (0.304 at 25%,
1.22× random).

**"Why is attack recall only 6.8%? That means you miss 93% of attacks."**
Two reasons, and one of them is our configuration error. We set `contamination`
to 0.1 while true prevalence is 17.85%, so the model may flag only 54,961 records
against 97,959 real attacks — recall is capped at 56.1% before the model makes a
single decision. The remainder is the algorithmic limitation in the next answer.
Matching contamination to prevalence is the first change for Review-2.

**"Your ROC-AUC is 0.62. That is barely better than guessing. Why?"**
Because CICIDS2017 violates Isolation Forest's core assumption. The algorithm
isolates points that are few and different; the attacks that dominate this
dataset — DoS Hulk, DDoS, PortScan — are high-volume and near-identical, so they
sit in dense regions and receive long isolation paths, i.e. they look normal. The
true outliers on our eleven features are unusual but legitimate benign flows. We
can show this: the most anomalous decile has lift 0.678× — worse than random —
while the top quartile has 1.215×. The ranking is non-monotonic, and we can name
the cause rather than guess at it.

**"Then why use Isolation Forest at all?"**
Because the deployment premise is that labels do not exist. In a real
investigation nobody hands you an annotated disk image, so the triage stage has
to be unsupervised, and Isolation Forest is linear in samples and needs no GPU,
which is why it runs on a standard laptop. What this evaluation establishes is
that the assumption behind it does not hold for volumetric network attacks. That
is a result, and it is what motivates the Review-2 direction.

**"Only 11 features out of 78. Why?"**
They were selected as the forward-direction volume and rate features common to
network, log and file artifacts, so the same pipeline generalises across evidence
types. The cost is that we dropped exactly the features that separate the attacks
we are missing: backward packet statistics, inter-arrival times, and TCP flag
counts. Expanding the feature set is the second change for Review-2.

**"You removed 691,171 rows — 27% of the data. What did you remove and why?"**
Rows with NaN or ±inf (divide-by-zero artifacts in the packet-rate columns) are
dropped rather than imputed, because imputing medians into an anomaly detector
either masks or manufactures anomalies. The rest is `drop_duplicates()`. Note
honestly that de-duplication runs on the twelve loaded columns, not all
fifty-three, so it is aggressive: repetitive flood flows that differ only in
unloaded columns collapse to one row. Section A of `verify_results.py` measures
whether that deletes attacks faster than benign traffic. It is defensible — no
duplicate flow can appear in both train and test — but the cost is that it
removes the volumetric repetition that makes DoS recognisable.

**"Is there label leakage?"**
No. `ForensicPreprocessor.extract_features` selects from a hard-coded whitelist of
eleven feature names, so no label column can reach the feature matrix. One honest
caveat: `scale_features` fits the StandardScaler on the full dataset before the
split, so test-set means and variances influence the scaling. That is a minor
transductive leak, it affects only two summary statistics per column, and we are
moving the fit inside the training fold.

**"Why 60/40 for the hybrid score? Did you tune it?"**
No. It is a documented empirical default, and `ml/risk_scorer.py` says so in a
comment — "an empirical default, not a learned optimum". The weighted-sum form
follows standard score-level fusion (Kittler et al., 1998) and the priority bands
are mapped onto the CVSS v3.1 qualitative severity scale. Learning the weights
against labelled data is Review-2 work. Do not claim the split was validated;
`FORMULAS.md` currently says "validated empirically on CICIDS2017" and that
sentence should be corrected, because the code comment contradicts it.

**"Does the hybrid score actually improve the ranking over the raw anomaly score?"**
We have not yet measured it, and the Top-25% figure of 0.304 does not use it —
Top-K is ranked on the raw `decision_function`. Section H of
`verify_results.py` runs the comparison; that experiment belongs in Review-2 and
it is the one that tests our actual contribution.

**"Your rule engine slide lists failed logins and autorun registry keys. Were
those active in this evaluation?"**
No. On a network-flow CSV `detect_artifact_type` returns `network` for every row,
so only the four network rules are reachable. The log, file and registry rules are
implemented and unit-testable but were not exercised by this dataset, because
CICIDS2017 contains no registry hives or event logs. Say this before being asked.

**"Your objectives say disk images, registry and system logs. You evaluated
network flows. Why the mismatch?"**
The parsers for EVTX, registry hives, YARA and disk images exist under
`forensics/` and are wired into the ingestion path, but there is no labelled
ground truth for them, so they cannot be scored quantitatively. CICIDS2017 was
chosen because it is the only component of the pipeline with labels, which makes
it the only part we can report metrics on. Quantitative evaluation of the
artifact parsers, on GovDocs / Digital Corpora, is scheduled for Review-2.

**"What is the practical benefit if recall is this low?"**
At the current numbers, honestly, the ranking is only worth using at the quartile
level: inspecting 25% of the queue surfaces 30.4% of attacks, a 1.22× saving over
inspecting at random. That is a weak but real gain. The engineering contribution —
reproducible pipeline, hybrid scoring framework, case workspace, automated PDF
reporting — stands independently, and the diagnostic finding about why Isolation
Forest fails on volumetric attacks is what makes the Review-2 plan specific
rather than speculative.

---

## 6. If you can re-run before the review

In rough order of expected payoff: set `contamination` to the measured prevalence
(0.1785) instead of 0.1, which lifts the recall ceiling from 56% to 100%; expand
the feature set beyond the eleven forward-direction columns to include backward
packet statistics, flow IAT and TCP flag counts; rank Top-K on the hybrid risk
score as well as the raw anomaly score and report both; and report per-attack-class
recall so the strong classes are visible instead of being averaged into one weak
number. Reporting average precision alongside ROC-AUC is also worth doing —
it is the more honest summary statistic under class imbalance.

---

## 7. Paste-ready prompt for Claude Code

Run this inside the repository when you want the numbers improved and the
documentation reconciled. It is written to be self-contained.

```text
Context: this repo backs a 7th-semester major project review. evaluation/results.json
(commit 00379bc) is the only trustworthy record of results: 1,829,580 cleaned rows,
82.15% benign / 17.85% attack, accuracy 0.7458, ROC-AUC 0.6195, attack recall 0.0683,
Top-25% triage recall 0.3039. Read docs/review1_defence.md first — it explains why
these numbers are weak and what the diagnosis is. Do not invent or estimate any
metric; every number you write down must come from a run you actually executed.

Do the following, in order, and stop to report if any step cannot be completed:

1. Reconcile the documentation. pptcontent.md still contains a stale, inflated result
   set (91.4% accuracy, 0.924 ROC-AUC, 98% Top-25% recall, 756,177-row test split,
   class distribution of 2,268,531 benign / 252,059 attack). Those figures came from
   mistaking Isolation Forest predictions at contamination=0.1 for ground-truth
   labels. Replace every such figure with the values from evaluation/results.json, or
   delete the sections outright. Also fix: docs/preprocessing.md claims cleaning
   removes 161 rows (it removes 691,171); docs/anomaly_detection.md presents 252,059
   predicted anomalies as if they were labels; FORMULAS.md section 2 documents a
   logistic score squash that ml/detector.py no longer implements (it uses batch
   min-max) and claims the 60/40 weighting was "validated empirically on CICIDS2017"
   while ml/risk_scorer.py calls it "an empirical default, not a learned optimum";
   docs/evaluation_metrics.md sets pass criteria of ROC-AUC > 0.90 and F1 > 0.80
   without noting the committed run fails them, and its sample Top-K recalls are
   arithmetically wrong. Grep for every occurrence of the stale numbers so none survive.

2. Extend scripts/run_evaluation.py, without changing its existing CLI behaviour, to
   additionally record in results.json: the measured attack prevalence; average
   precision (sklearn average_precision_score); per-attack-class recall and mean
   anomaly-score percentile, keyed by the raw "Attack Type" value; Top-K metrics at
   k = 1, 5, 10, 25, 50 for BOTH the raw anomaly ranking and the 60/40 hybrid risk
   ranking from ml/risk_scorer.py; and a lift figure (precision@K / prevalence) for
   each. Move the StandardScaler fit inside the training fold so the scaler no longer
   sees test rows, and note that change in the results metadata.

3. Re-run the evaluation with contamination matched to the measured prevalence
   rather than 0.1, keeping seed 42 and the 70/30 stratified split. Write the output
   to evaluation/results_tuned.json — do not overwrite results.json, because the
   original is cited in the presentation. Report the before/after delta for accuracy,
   ROC-AUC, attack recall, average precision, and Top-10%/Top-25% recall and lift.

4. Then, and only if steps 2-3 succeed, try an expanded feature set: keep the existing
   11 columns and add every available backward-direction, flow-IAT and TCP-flag-count
   column present in data/cicids2017_cleaned.csv. Write to
   evaluation/results_features.json and report the same deltas. Keep the 11-feature
   configuration as the documented baseline so the comparison is fair.

5. Verify with: python scripts/verify_results.py --results evaluation/results_tuned.json
   and confirm the recomputation PASS lines still hold. Then summarise, in a table, what
   changed and which single change contributed most. If a change made things worse, say
   so plainly and leave it out of the recommendation.

Constraints: do not modify evaluation/results.json or evaluation/artifacts/*. Do not
commit anything. If data/cicids2017_cleaned.csv is missing, stop at step 1 and tell me.
```
