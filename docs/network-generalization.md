# Issue 6 — measured recall improvement, rejected deployment

The selected research LightGBM improves recall on two previously unused 2018
capture days, but **fails the prespecified false-positive and attack-family
gates**. It is not a production detector, selectable option or default. Original
XGBoost, Isolation Forest, EMBER, YARA and unified screening remain unchanged.

Read [the executed report](../test-results/issue-6/REPORT.md),
[the protocol committed before training](../test-results/issue-6/PROTOCOL.md),
[locked source hashes](../test-results/issue-6/locked-test.json),
[sealed validation selection](../test-results/issue-6/selection.json) and
[one-shot final results](../test-results/issue-6/final-results.json).

The model comparison uses the **same 2,091,441 eligible final records**. These
are distinct from Issue 4's original 2,087,481 inspected records. Do not compare
the two denominators as if they were the same experiment. The new test has
1,489,073 benign and 602,368 attack records. It is capture-day/label held out;
unlabeled test features were consulted only to quarantine development overlap.
It is not an untouched-covariate, independent-site or independent-bot benchmark.

| Final model | Recall | Precision | FPR | Accuracy | Deployment |
|---|---:|---:|---:|---:|---|
| Frozen incumbent XGBoost | 0.003984% | 0.019628% | 8.209806% | 65.354318% | Retained with documented limitations |
| Selected research LightGBM | 34.554458% | 56.352728% | 10.826602% | 73.442282% | Rejected; 5% FPR gate failed, SlowHTTPTest recall zero |

Scores are uncalibrated outputs. No threshold was changed after final labels were
opened. Bot validation is from different time blocks within the already known
March 2 scenario; independent bot detection has not been established.

## Reproduce the recorded stages

Prerequisites: the project native Python environment and
`requirements/network-research.txt` (network models, LightGBM and psutil); reviewed CICIDS2017 cleaned source
and its cleaning ledger; the original Issue 4 development CSVs; frozen incumbent
downloads; official test sources pinned in locked-test.json. No additional full
dataset, PCAP or malware download is required. Consult the existing dataset
acquisition/setup documents for the approved 2017 source.

The actual first-run commands were:

```powershell
rtk proxy .venv/Scripts/python.exe -m scripts.acquire_issue6
rtk proxy .venv/Scripts/python.exe -m scripts.prepare_issue6
rtk proxy .venv/Scripts/python.exe -m scripts.diagnose_issue6
rtk proxy .venv/Scripts/python.exe -m scripts.train_issue6
# Selection was sealed and committed before the next command:
rtk proxy .venv/Scripts/python.exe -m scripts.evaluate_issue6
rtk proxy .venv/Scripts/python.exe -m scripts.plot_issue6
rtk proxy .venv/Scripts/python.exe -m scripts.issue6_feature_audit
rtk proxy .venv/Scripts/python.exe -m scripts.measure_issue6_candidates
rtk proxy .venv/Scripts/python.exe -m scripts.verify_issue6_app
rtk proxy .venv/Scripts/python.exe -m scripts.render_issue6_reports
rtk proxy .venv/Scripts/python.exe -m pytest -q --no-training --run-integration
rtk proxy npm --prefix frontend run check
rtk proxy .venv/Scripts/python.exe scripts/check.py
```

Stage outputs are write-once. Do not delete the final receipt, replace selection
or rerun fitting against the already opened test under an “untouched” label.
The default commands intentionally refuse to overwrite existing sealed results.

For a full reproduction in a new ignored UUID directory, retaining all original
results, use:

```powershell
rtk proxy .venv/Scripts/python.exe -m scripts.replay_issue6 --run
```

This wrapper hard-links already downloaded read-only test sources, uses the same
protocol, fits exactly the same two candidates and compares final confusion
matrices. It requires the original input files; no implicit downloads occur.
It is explicitly **a replay of an already disclosed benchmark**, not another
independent final evaluation. The wrapper's help/guards and constituent stages
were tested; an additional full replay was not run merely to repeat training.

Direct research stages accept `ISSUE6_RESULTS_DIR` and `ISSUE6_WORK_DIR` for
isolated outputs. Production code does not read these variables or import the
research module. A new scientific iteration needs genuinely unused test sources
and a separately approved/recorded protocol; Issue 6 did not begin that iteration.

## Exact research artifacts

Sealed protocol and JSON hash-chain files are stored byte-for-byte using
`.gitattributes`, so Windows/Linux checkout conversion cannot invalidate their
checksums. The initial raw checkpoint is preserved. Historical text comparison
also records a separate canonical-LF digest; this accepts only newline conversion,
not scientific content changes. Production binaries remain byte-exact.

The first fresh-checkout CI run exposed eager `psutil` imports before sealed-test
guards. These now load only when an actual research stage starts. Receipt guards
remain testable without optional research/native dependencies; no guard assertion
was skipped or weakened. The original CI failure transcript is preserved.

Both trained text-format candidate artifacts and their metadata are packaged
outside source Git history. `research-artifacts.json` records the prerelease
asset URL, size and SHA-256; the bundle prominently states **rejected for
deployment**. It contains no data records, credentials, evidence or pickle files.
The research downloader is opt-in and verifies archive size/hash and each member:

```powershell
rtk proxy .venv/Scripts/python.exe -m scripts.acquire_issue6_research_model
```

It extracts under ignored `.test-artifacts/issue6/released-research` and never
replaces an existing directory or any production model. Runtime feature order,
model dimension, version and hashes are validated by `load_candidate()`.

## Presentation evidence and UI status

High-resolution figures under `test-results/issue-6/` show model comparison,
confusions, final ROC/PR, family recalls, feature distributions, Top-K recall,
inference throughput and retrospective Issue 4 score/threshold diagnostics.
Each identifies its population and protocol. No published internal accuracy is
presented as reproduced external accuracy.

Fresh actual API/database/report verification exercises **retained** XGBoost and
Isolation Forest on real source-order-selected CICIDS2017 records, without
prediction selection. Full PDFs/API records stay ignored; public prediction
summaries and rendered report sample pages accompany the review evidence.

Browser acceptance remains **UNVERIFIED**: the last tool result was “Local browser
use is disabled in Work settings.” No repeated permission request, unauthorized
workaround, screenshot fabrication or UI pass is claimed. React tests/build and
HTTP checks are separate from browser interactions. The failed challenger was
not added to the detector selector.

For manual review of the saved cases, keep the dedicated test MongoDB on 27018
running and use two terminals:

```powershell
rtk proxy .venv/Scripts/python.exe -m scripts.serve_issue6_demo
# Second terminal:
$env:BACKEND_PROXY_TARGET='http://127.0.0.1:5079'
rtk proxy npm --prefix frontend run dev -- --host 127.0.0.1 --port 5249 --strictPort
```

Open a case ID from demo-latest.json's summary, inspect Evidence/Artifacts, refresh
and reopen, then generate its report. These remain the retained incumbent models,
not the failed challenger. Manual interactions and screenshots are not claimed
until actually performed.

## Important limits

- Exact CICFlowMeter build provenance is unavailable; matching family feature
  names and units does not establish identical extraction semantics.
- Sampled development changes prevalence, and strict purging leaves few rare
  training/validation web attacks. Model selection stability across seeds was
  not estimated; one predeclared seed and budget were used.
- Temporal blocks/embargo and rounded-log bins reduce leakage but do not prove
  session/host or all-near-duplicate separation. Fingerprints are 64-bit and may
  conservatively over-purge in the unlikely event of collision.
- The final population retains duplicates and contradictory publisher labels.
  Ambiguity evidence is descriptive; labels were never “fixed” to boost metrics.
- Initial training memory monitoring observed only the Windows launcher. Its
  mislabeled sealed resource values are explicitly invalid as training RSS.
  Separate actual-process inference memory checks are recorded. Training peak
  memory remains unmeasured; models were not refit to repair this measurement.
- Research code and reproducibility are complete. The operational objective of
  improved recall **within the prespecified FPR/family gates remains PARTIAL**.
