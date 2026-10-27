# Phase 1: reviewed CICIDS2017 baseline

## Explicit download and provenance

Downloading is a separate, operator-initiated command. Nothing in validation,
cleaning, or training calls it or KaggleHub, so a missing dataset stays a
reported error instead of a silent network request.

From the repository root, with the project Python environment and Kaggle
credentials (`KAGGLE_USERNAME`/`KAGGLE_KEY`, `~/.kaggle/kaggle.json`, or
`kagglehub.login()`):

```bash
python -m pip install -r requirements.txt
python scripts/download_dataset.py
```

The manifest it writes, `data/provenance/cicids2017_cleaned.provenance.json`,
records the fields later steps read: `csv.path` (the actual CSV path inside
`data/kaggle/...`), `csv.sha256` (the streamed SHA-256 of that file), and
`version.value` (the reviewed Kaggle version, or `null` when unavailable).

Optional flags: `--output-dir`, `--manifest`, `--csv-path`, and
`--force-download`.

What the command does:

- Retrieves `ericanacletoribeiro/cicids2017-cleaned-and-preprocessed` through
  the installed KaggleHub package into
  `data/kaggle/cicids2017-cleaned-and-preprocessed` (gitignored). KaggleHub's
  own cache is reused unless `--force-download` is given.
- Locates the CSV by walking the download tree for `.csv` suffixes; the
  downloaded filename is never assumed. Zero CSV files raise `CSV_NOT_FOUND`
  and several raise `CSV_AMBIGUOUS` with the candidate list, resolved by
  `--csv-path`, which must stay inside the download directory and name a
  `.csv` file.
- Writes `data/provenance/cicids2017_cleaned.provenance.json` atomically with
  source metadata (provider, handle, URL, retrieval tool and its version),
  version/revision metadata (`status: available` with the reported value, or
  `status: unavailable` plus an explicit detail — never inferred from a path),
  `retrieved_at` and `verified_at` in UTC, the resolved and relative CSV paths,
  size, SHA-256, and the handling policy. Files are opened read-only and the
  digest is streamed in 1 MiB chunks, so neither discovery nor hashing loads
  the dataset into memory.
- Reuses an existing download only when the recorded identity (handle, CSV
  relative path, size, SHA-256) and every available version field match the
  manifest; `retrieved_at` is preserved while `verified_at` is refreshed. Any
  difference raises `PROVENANCE_MISMATCH` and overwrites nothing until the
  operator reruns with `--force-download`.
- Protects `data/sample/cicids2017_cleaned.csv` and
  `data/cicids2017_cleaned.csv`: an output directory containing them, a
  manifest path pointing at them, or a discovered CSV resolving to them fails
  with `SOURCE_PROTECTED` before any request is made.
- Fails with distinct codes and no partial manifest: `CREDENTIALS_MISSING`
  (checked before the first request), `NETWORK_FAILURE`, `SERVICE_FAILURE`,
  `DATASET_NOT_FOUND`, `KAGGLEHUB_MISSING`, `PROVENANCE_UNREADABLE`,
  `DOWNLOAD_MISSING`, `OUTPUT_DIR_INVALID`, `CSV_PATH_INVALID`.

Downloading, validation, cleaning, and training remain separate commands. This
step applies no cleaning policy: the reviewed file keeps all of its rows,
including the 107 rows with finite negative measurements and the duplicate
rows. Validation reports them as findings for review, not as edits.

## Validate only

From the repository root, validate the existing original CSV:

```bash
python scripts/train_baseline.py --validate-only --data data/sample/cicids2017_cleaned.csv
echo $?   # exit status ($LASTEXITCODE in PowerShell)
```

Omitting `--data` uses the existing `data/cicids2017_cleaned.csv` default.
Validation does not require a dataset version or checksum and makes no download,
CSV edits, row exclusions, value replacements, model fits, or model saves.
Training still requires its reviewed version and checksum arguments.

The JSON report counts missing cells (nulls and blank/whitespace values) in all
columns. Numeric conversion checks use the 11 required network features; explicit
`NaN`/`+NaN`/`-NaN` tokens, nonnumeric values, infinity, and finite negative
measurements have separate cell counts and affected-column counts. Numeric nulls
already present in an in-memory frame count as missing. Negative infinity counts
as infinity, not as a finite negative measurement. Missing feature columns and
unreadable files are errors. All parsed rows, including blank lines, are inspected.

Duplicates compare every parsed column before the validator's numeric conversion.
The report counts extra copies beyond the first and all rows in duplicate groups.
Rows can have multiple issues: category counts must not be summed to estimate
affected rows. `rows_with_issues` is the union; `overlapping_issues` records rows
with multiple categories and nonzero pairwise intersections. Detection is a
finding for review, not a cleaning policy or an approval to train. The validator
currently loads the CSV into memory.

Exit codes: **0** means no detected issues, **2** means a completed report found
issues (or no data rows), and **1** means a file, parsing, or schema error.

## Clean explicitly (offline policy)

Cleaning is a separate operator command between validation and training. It
never downloads, never fits a model, and never writes to a reviewed CSV: it
verifies provenance first, reads the source read-only, and publishes two derived
artifacts under `data/provenance/`.

From the repository root, with the project Python environment:

```bash
python scripts/clean_dataset.py                 # source = csv.path from the manifest
python scripts/clean_dataset.py --data PATH_FROM_MANIFEST --chunk-rows 20000
python scripts/clean_dataset.py --force         # replace a mismatching ledger/record
echo $?   # exit status ($LASTEXITCODE in PowerShell)
```

Optional flags: `--data`, `--manifest`, `--ledger`, `--record`, `--chunk-rows`,
`--force`. `--data` defaults to the CSV path recorded in the manifest;
`PATH_FROM_MANIFEST` above is that manifest's `csv.path` value.

Refusals (exit 1, nothing written): a missing, unparsable, or wrong-dataset
manifest raises `PROVENANCE_MISSING`, `PROVENANCE_UNREADABLE`,
`PROVENANCE_MISMATCH`; a source whose size or streamed SHA-256 differs from the
manifest entry raises `SOURCE_SHA_MISMATCH`; `SOURCE_MISSING`,
`MISSING_FEATURES`, and `EMPTY_SOURCE` cover an absent file, absent required
columns, and a header-only CSV. Ledger or record paths that resolve to a
protected source (`data/sample/cicids2017_cleaned.csv`,
`data/cicids2017_cleaned.csv`) or to the source itself raise `SOURCE_PROTECTED`.

Policy `cicids2017-offline-cleaning` v1.0.0 records one of three reasons per
excluded row:

| reason code | rule |
| --- | --- |
| `negative_measurements` | any of the 11 required features parses to a finite value < 0 |
| `duplicate_row` | canonical text of every parsed column equals an earlier row; first occurrence kept |
| `label_conflict` | the 11-feature vector appears with more than one `Attack Type`/`Label` value; every row of the vector excluded |

- Nothing is imputed, clipped, sign-flipped, or relabelled, and no row is
  rewritten. A row can carry several reasons: `exclusions.unique_rows` is the
  union, `by_reason` counts rows per reason, and `overlaps` records rows with
  multiple reasons plus pairwise intersections. Never sum `by_reason` to estimate
  affected rows.
- `data/provenance/cicids2017_cleaning_ledger.csv` holds
  `source_row_index,reasons` (0-based data-row index with the header excluded,
  LF line endings, reasons in fixed policy order). Its bytes are deterministic,
  so `ledger.sha256` in the record identifies the exact exclusion set.
- `data/provenance/cicids2017_cleaning.json` records the policy id, version and
  rules, source identity (path, size, rows, SHA-256, bound manifest path/handle
  and dataset version), per-column negative counts with their union, duplicate
  and label-conflict counts, `input_rows`, `retained_rows`, `unique_rows`,
  overlap pairs, the ledger digest, chunk size, and environment versions. The
  invariant `input_rows == retained_rows + unique_rows` is asserted in code: a
  disagreement raises `COUNT_MISMATCH` and writes nothing.
- Two streaming passes keep memory bounded. Pass 1 reads the CSV as text in
  `--chunk-rows` slices (default 10,000) and keeps per-row, per-feature and
  per-label hashes plus per-column negative masks; pass 2 re-reads the file and
  materialises canonical text only for candidate rows (capped by
  `MAX_CANDIDATE_ROWS = 250_000`, otherwise `CANDIDATE_LIMIT_EXCEEDED`). The ceiling
  was calibrated from empirical Step 7A measurements of the verified 2,520,751-row
  source, which exhibits 219,489 candidate rows and requires ~549 MB peak RAM.
  Equal text always shares a hash, so pass 2 can only add precision — chunk size
  cannot change the counts or the ledger — and peak memory depends on the chunk
  size and candidate set, not on the 717 MB file. Reading as text also makes
  duplicate detection conservative: rows that are numerically equal but textually
  different are kept.
- Re-running is idempotent: an identical ledger and record are reported `reused`
  and left byte-identical. A ledger or record that does not match this run raises
  `LEDGER_MISMATCH` or `RECORD_MISMATCH` and is only replaced with `--force`.
- **Dataset limitations and benchmark filtering**: The approved offline policy
  excludes approximately 8.71% of all source rows (219,512 unique rows),
  including 65.34% of Port Scanning records (59,258 rows) and 38.50% of Bots
  records (750 rows). These exclusions arise because degenerate zero-payload flows
  (e.g., single SYN probes or aborted handshakes) produce 11-feature summary vectors
  identical to background benign traffic. The cleaned dataset represents a filtered
  benchmark subset, and future evaluation must report these exclusions transparently;
  removing ambiguous vectors eliminates contradictory training signals for the
  benign-only baseline, but does not imply that real-world operational traffic
  will be free of such flow ambiguities.

No cleaned CSV is written. The eligible view is derived at load time from the
immutable source and keeps the original source row index on every retained row:

```python
from ml.cleaning import iter_eligible_chunks, load_eligible_frame

view = load_eligible_frame()                 # verifies source SHA-256 and ledger digest
for chunk in iter_eligible_chunks(usecols=..., chunk_rows=10000):
    ...
```

Both refuse a changed source (`SOURCE_SHA_MISMATCH`), a tampered ledger
(`LEDGER_MISMATCH`), a missing record (`RECORD_MISSING`), and any row-count
disagreement (`SOURCE_ROWS_MISMATCH`, `COUNT_MISMATCH`).

Live inference does not use this module: `prepare_network_frame` still preserves
duplicates and finite negative rows and only drops non-finite required values, so
batch frequency still contributes to drift monitoring.

### Split and fit separation

Cleaning and deduplication precede any split, and fitted statistics come from
training rows only:

- `scripts/run_evaluation.py` now splits first and fits the scaler on the
  training rows only (`scale_train_and_test`). The historical version scaled the
  whole frame before splitting, which leaked test-set statistics into training.
  Its CLI is unchanged and its metrics stay historical until rerun.
- Training itself is unchanged in this step: `scripts/train_baseline.py` still
  reads the path the operator supplies, and no model was fitted. Once it consumes
  the eligible view above, the required order is: clean, split, then fit the
  scaler and model on training rows only.

## Train explicitly

Retrieve the cleaned dataset with the explicit command above, or download it
manually from
[Kaggle](https://www.kaggle.com/datasets/ericanacletoribeiro/cicids2017-cleaned-and-preprocessed),
and review the download and its version. Training never downloads anything:
it reads a path the operator supplies. Either keep the downloaded CSV where the
manifest recorded it (`csv.path`) or place the reviewed file at
`data/cicids2017_cleaned.csv`. Training never searches `data/sample/`, accepts
an API upload, or substitutes synthetic data. The trainer reads all rows but
only the required feature and label columns to limit memory use.

From the repository root, with the project Python environment:

```bash
python -m pip install -r backend/requirements.txt
python -m pip install pytest
python scripts/train_baseline.py --data PATH_FROM_MANIFEST --validate-only   # report only, no fitting
python scripts/train_baseline.py --data PATH_FROM_MANIFEST --dataset-version VERSION_FROM_MANIFEST --expected-sha256 SHA256_FROM_MANIFEST
python backend/app.py
python -m pytest -q
```

`PATH_FROM_MANIFEST`, `VERSION_FROM_MANIFEST`, and `SHA256_FROM_MANIFEST` are the
manifest's `csv.path`, `version.value`, and `csv.sha256` fields.

The supplied checksum is an operator-approved fingerprint, not independent proof
that a file came from Kaggle. Verify the download before approving its checksum.
The trainer records that fingerprint and checks again after fitting to reject
changes during training. It requires at least two distinct valid benign rows;
tests use isolated synthetic fixtures and are not production training evidence.

Run every command with one interpreter: activate a project environment (or use
whichever `python` already has the project dependencies installed) so training
and serving share it, and call that interpreter explicitly when the system
default `python` does not have them. Use the same scikit-learn version for
training and serving.

Training fits on valid, deduplicated benign feature vectors only (`Attack Type`
or `Label`; `Normal Traffic`/`BENIGN` and benign aliases are accepted).
Excluded attacks, invalid rows, duplicate benign rows, and training counts are
recorded. Isolation Forest uses 100 trees, seed 42, and contamination 0.1 by
default (`--contamination` can be set explicitly). That threshold is a heuristic
for outliers within benign training data, not a claimed attack rate.

## Bundle and approval boundary

`models/cicids2017_baseline.joblib` holds the fitted model, fitted scaler, ordered
versioned feature schema with units, dataset ID/URL/version/path/SHA-256, training
timestamp and row counts, model parameters, dependency versions, and frozen drift
histograms. A complete bundle is published atomically after validation.
Existing bundles are preserved unless the operator explicitly uses `--overwrite`
after manual review. Drift never invokes this command or replaces the bundle.

The legacy `models/isolation_forest.pkl` is ignored and preserved. It cannot be
used safely without the original scaler/schema/provenance. The loader rejects
missing components, unfitted objects, schema/name mismatches, and scikit-learn
version differences. A bundle contains executable Python serialization: the
model directory must be operator-owned, and a deployed API account should have
read-only model access. Metadata and checksum validation do not make an arbitrary
uploaded joblib file safe. Requests cannot select the model path.

Uploads only transform and predict. `/api/analyze`, `/api/evaluate`, and network
`/api/ingest` return clear model/input errors and never fit or publish models.
Loading one complete bundle per request avoids mutable global estimator state
and stale readiness caches. Health reports actual bundle readiness separately
from API liveness. Analysis records retain baseline provenance, preprocessing
counts, drift, and evidence custody when MongoDB is available.

## Basic drift monitoring

Training freezes per-feature quantile bins and proportions on the benign
baseline. Each retained incoming batch is compared with these bins using
population stability index:

`PSI = sum((incoming_fraction - reference_fraction) * log(incoming_fraction / reference_fraction))`

Bins include both tails; repeated cut points are collapsed, constant features
get their own bin, and fractions have a 1e-6 floor and are renormalized. A feature
PSI of at least 0.2 flags distribution change. This conventional heuristic needs
deployment-specific calibration; it is not a significance test or attack
verdict. At least 100 reference rows and 100 incoming rows are needed; smaller
sets return `insufficient_reference` or `insufficient_data` with
`drift_detected: null`. Otherwise status is `stable` or `drift_detected`.
`retraining_triggered` is always false. Reports do not update histograms,
scaling statistics, or model weights.

Monitoring is per uploaded batch, not a rolling stream. Duplicates are preserved
at inference so flow frequency contributes to drift. Attack bursts, collection
changes, or unit mismatches can cause drift; analysts should investigate them.
Bad-row counts are separately reported so malformed uploads are visible.

## Current status and remaining work

During Phase 1 implementation, the required `data/cicids2017_cleaned.csv` was
absent. The training command exited with a missing-dataset error. No production
baseline was trained or published, and no new production metrics are claimed.
Historical `evaluation/results.json` and plots describe prior offline experiments,
not this benign-only baseline. The historical evaluation scripts remain separate
and never publish the approved production bundle; their preprocessing/split
methodology needs review before reusing their metrics.

The explicit download command and provenance manifest are implemented but were
not executed: no dataset was downloaded and no manifest exists. The reviewed
source file under `data/sample/` remains byte-identical.

The cleaning policy `cicids2017-offline-cleaning` v1.0.0 and its command are
implemented but were not run either: cleaning requires a matching provenance
manifest, so it stays a refused operation until a download is reviewed. No ledger
or record exists yet, no cleaned CSV was produced, and no model was trained.

Next: run `scripts/download_dataset.py`, review the manifest and the retrieved
CSV, validate it read-only, run `scripts/clean_dataset.py` and review the ledger
and record, train the bundle from the eligible view, measure it on an independent
labeled holdout, calibrate contamination and drift thresholds, add rolling
telemetry/analyst review, and improve source-specific host detectors.
Native PCAP aggregation still has simplified direction/flow semantics; use
compatible CICFlowMeter exports for baseline evaluation until that parser is
validated. EVTX, registry, file, disk-image, YARA, and reputation workflows remain
available through their source-specific forensic paths.

Phase 1 validation on 25 October 2026: the full pytest suite returned 75 passed
and 4 skipped (two MongoDB tests because the database was unreachable, and two
YARA tests because yara-python was unavailable). The Windows sandbox denied
atomic model-file operations in pytest temporary folders; the complete suite
passed when rerun outside that sandbox.

Step 3 (explicit KaggleHub download and provenance) verification on 25 October
2026: the full suite returned **142 passed and 4 skipped**, including 31 new
mocked tests for download success, cache reuse, failure codes, provenance
records, and source-file protection. No test performs a network request, fits a
model, or writes to a reviewed CSV. `git diff --check` passed. Baseline training
on the real path still exits with the missing-dataset error described above.

Step 4 (offline cleaning policy, ledger, and eligible view) verification on 26
October 2026: the full suite returned **175 passed and 4 skipped**, including 33
new tests covering overlapping exclusions, feature-vector label conflicts,
count and ledger determinism across chunk sizes (1/5/1000 rows), ledger and
record tampering with and without `--force`, provenance and SHA-256 refusals,
source immutability, protected paths, candidate/argument guards, load-time view
integrity, live inference keeping duplicates and negative rows, and scaler
fitting on training rows only. The suite's fixture makes any `fit()`,
`joblib.dump()`, or download attempt fail the test. `git diff --check` passed.
No dataset was downloaded, no cleaning was run against the real source, and no
model was fitted during this step.

---

## Phase 14: Deterministic Provenance, Clean-Install & Reproducible Setup

### 1. Fresh-Checkout Architecture & Ignored Artifacts
A fresh clone of the Cyber Triage Tool repository contains neither the large dataset (`data/cicids2017_cleaned.csv`, ~717 MB) nor the trained baseline model (`models/cicids2017_baseline.joblib`). Both are excluded via `.gitignore` to prevent repository bloat and guard against unverified binary execution.

The repository includes committed provenance infrastructure under `data/provenance/`:
- `data/provenance/cicids2017_cleaning_ledger.csv`: Deterministic exclusion ledger (219,512 excluded rows, SHA-256: `b6221758be8c0febced43df021e62d80ac94a8ab4361da7d74199b3f236b9460`).
- `data/provenance/cicids2017_cleaning.json`: Offline cleaning record holding policy metadata, exclusion reason breakdowns, and semantic fingerprint `cleanfp-v1-aac7d01cbefe7acd99ffb610c29a87c8cddbe51ca9ec6294a0925278964e0c1d`.

### 2. Windows Clean-Install Procedure

#### Step A: Environment & Dependency Setup
From a clean checkout in PowerShell:
```powershell
# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install core and ML dependencies
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

# Optional: Install native forensic dependencies (pytsk3, yara-python, etc.)
# If prebuilt wheels are located locally:
# python -m pip install <path-to-wheels>\*.whl
```

#### Step B: Obtain the Reviewed Dataset & Verify Hash
Place the reviewed CICIDS2017 CSV at `data/cicids2017_cleaned.csv` (or `data/sample/cicids2017_cleaned.csv`).
Verify content integrity before proceeding:
```powershell
Get-FileHash data\cicids2017_cleaned.csv -Algorithm SHA256
```
The output must match the verified content hash:
`0ce5a39edffcde3fce59d0dc4aabc9b1f6acab2c626fd7163be9c694f224c292`

Validate CSV formatting and header structure (read-only; no training):
```powershell
python scripts\train_baseline.py --validate-only --data data\cicids2017_cleaned.csv
```

#### Step C: Establish Provenance Manifest
If the dataset was placed manually:
```powershell
python scripts\download_dataset.py --from-local data\cicids2017_cleaned.csv
```
Alternatively, if retrieving directly via KaggleHub with valid Kaggle credentials:
```powershell
python scripts\download_dataset.py
```

#### Step D: Generate and Validate Cleaning Provenance
Run the offline cleaning policy `cicids2017-offline-cleaning` v1.0.0:
```powershell
python scripts\clean_dataset.py --data data\cicids2017_cleaned.csv
```
This generates and verifies:
- `data\provenance\cicids2017_cleaning_ledger.csv`: Excludes 219,512 rows across negative measurements (107), duplicate rows (161), and label conflicts (219,323).
- `data\provenance\cicids2017_cleaning.json`: Derives semantic fingerprint `cleanfp-v1-aac7d01cbefe7acd99ffb610c29a87c8cddbe51ca9ec6294a0925278964e0c1d`.

#### Step E: Explicitly Train the Approved Baseline
Train the Isolation Forest baseline on the approved training partition:
```powershell
python scripts\train_baseline.py `
    --data data\cicids2017_cleaned.csv `
    --eligible `
    --holdout `
    --dataset-version 1 `
    --expected-sha256 0ce5a39edffcde3fce59d0dc4aabc9b1f6acab2c626fd7163be9c694f224c292
```
This creates `models\cicids2017_baseline.joblib` (SHA-256 `8602d9e6f57d347a10ebbca7290ad2bc75892f9c7f8b29dcc97c2fea20035c0d`, Model ID `iforest-65dd0b57a2b1a2020a0b`).

#### Step F: Evaluate the Baseline on Frozen Holdouts
Evaluate on reserved validation and test partitions without model fitting:
```powershell
python scripts\evaluate_baseline.py --data data\cicids2017_cleaned.csv --allow-semantic-record
```

#### Step G: Verify API Readiness
Start the backend application:
```powershell
python -m backend.app
```
Query health and model endpoints:
```powershell
Invoke-RestMethod http://127.0.0.1:5001/api/ready
Invoke-RestMethod http://127.0.0.1:5001/api/model
```
Expected responses:
- `/api/ready`: `{ "ready": true, "model_available": true }`
- `/api/model`: `{ "available": true, "model_id": "iforest-65dd0b57a2b1a2020a0b", "dataset_id": "ericanacletoribeiro/cicids2017-cleaned-and-preprocessed", ... }`

---

### 3. Semantic Cleaning Fingerprint Specification (`cleanfp-v1-`)

#### Root Cause of Raw File Hash Discrepancies
Previous phases observed that raw file hashing (`file_sha256`) of `cicids2017_cleaning.json` differed across operating systems and execution runs (`772216...` vs `77a22f...`). Investigation identified that `cicids2017_cleaning.json` contains dynamic host-specific fields:
1. `applied_at`: Execution timestamp in UTC.
2. `source.path`, `source.manifest_path`, `ledger.path`: Absolute filesystem paths varying by host and OS.
3. `environment`: Python, Pandas, and NumPy version strings.
4. JSON formatting differences: indentation, whitespace, and key ordering.

While these dynamic fields vary, the substantive cleaning results (source content SHA, ledger SHA, row counts, and exclusion rules) are mathematically deterministic.

#### Canonical Representation & Hashing Rules
The semantic fingerprint `cleanfp-v1-<sha256>` is derived from a strict canonical dictionary containing only stable fields:
1. `schema_version`: `1`
2. `policy`: `id`, `version`, `reason_codes` (sorted), `rules` (sorted by code), `modifications_never_applied` (sorted), `offline_only`.
3. `source`: `sha256`, `size_bytes`, `rows`, `columns`, `label_columns_checked`, `label_conflict_status`, `manifest_handle`, `dataset_version`.
4. `issues`: issue breakdown counts (`negative_measurements`, `duplicate_rows`, `label_conflicts`).
5. `exclusions`: `input_rows`, `retained_rows`, `unique_rows`, `by_reason` (sorted keys), `overlaps` (sorted pairs), `invariant`.
6. `ledger`: `sha256`, `rows`, `columns`, `newline`, `row_identity`.

Canonicalization rules:
- Excludes: all local paths, timestamps, environment versions, and formatting whitespace.
- Serialization: `json.dumps(canonical_dict, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('utf-8')`.
- Digest: `cleanfp-v1-` + `hashlib.sha256(canonical_bytes).hexdigest()`.

Both the raw-file SHA-256 and the semantic fingerprint are preserved as separate fields:
- `record_sha256`: For exact byte-level integrity checks within the same host.
- `record_fingerprint`: For cross-platform, deterministic verification across independent environments.

---

### 4. Distribution Options and Trade-Offs

| Distribution Strategy | Security & Trust Boundary | Reproducibility & Portability | Operational Overhead |
| :--- | :--- | :--- | :--- |
| **Option 1: Pinned Release Asset (Recommended for Deployments)** | High: Bundle is signed and checksum-verified against pinned SHA-256 `8602d9e6...` before loading. Operator owns deployment directory; API account has read-only access. | High: Guarantees byte-identical model artifact across production containers without retraining. | Low: Instant container boot; no 717 MB download or 3-minute CPU training step during container startup. |
| **Option 2: Local Pipeline Reproduction (Recommended for Audits & CI)** | Highest: Model is built from verified source CSV using deterministic code; no opaque binary transfers. | Deterministic: Model produces verified ID `iforest-65dd0b57a2b1a2020a0b` from fixed seed 42. | High: Requires fetching 717 MB dataset and executing full training pipeline (~3 min, ~2 GB RAM). |
| **Option 3: Enterprise Remote Model Store (e.g., S3/MinIO/OCI)** | Medium-High: Requires IAM access controls, TLS, and pre-load hash verification to prevent man-in-the-middle tampering. | High: Centralized registry tracks model versions across deployment stages. | Moderate: Introduces network dependency on external object store; requires credential management in runtime containers. |

