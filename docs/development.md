# Development and verification

Run commands from the repository root. The tested environment is CPython 3.14.7,
Node 24.20.0 and npm 11.19.0 on Windows x64. `.python-version` and `.node-version`
record these versions. The code does not inherently need every 3.14 feature,
but the exact dependency set is verified on 3.14; other Python versions are not
claimed as verified. Vite requires a recent Node runtime; package.json requires
Node >=22.12. The CI workflow targets Python 3.14 / Node 24 on Linux and has not
been executed remotely as part of this local phase.

## Install locally

PowerShell (no activation or global installs needed):

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements/dev.txt
npm --prefix frontend ci --ignore-scripts
```

POSIX equivalent: `python3.14 -m venv .venv`, then use `.venv/bin/python` for
every Python command below. `requirements.txt` installs only runtime dependencies;
`requirements/dev.txt` adds pytest, coverage, Ruff and offline plotting tools.
Both use the exact transitive versions in `requirements/constraints.txt`.
Keep the trainer and API on the same scikit-learn version: bundle loading rejects
version mismatches. Do not overwrite a model to resolve a dependency mismatch.

`requirements/optional.txt` is a separate, constrained capability manifest for
native EVTX, registry, YARA, disk-image and PCAP support, plus explicit Kaggle
retrieval. It is not part of the core install or lock; native wheel availability
varies by OS/Python and those capabilities require separate verification.
No setup/test command downloads a dataset. Synthetic baseline lifecycle tests fit
tiny disposable estimators under `.test-artifacts/`; they never train production
models or read the protected source CSV.

## Configure and start

Copy `.env.example` to `.env` only if `.env` does not already exist. Existing
environment variables take precedence. The backend explicitly loads the root
`.env`; tests never load it. Configure a development MongoDB instance separately.
No application import, server startup or health request creates indexes or seeds
data. When ready to create indexes in your configured development database:

```powershell
.venv\Scripts\python.exe -m flask --app backend.app check-config
.venv\Scripts\python.exe -m flask --app backend.app init-db
.venv\Scripts\python.exe -m backend.app
```

Backend: `http://127.0.0.1:5001`. Debug defaults off and the development listener
binds loopback. `python backend/app.py` remains supported. `backend.app:app` is
the compatible WSGI entry point; `create_app(config)` creates isolated instances.
Use a production WSGI server for deployment, not Flask's development listener.
Production mode rejects missing API tokens, wildcard CORS and debug mode.

Set `DB_MODE=disabled` explicitly for stateless local parser/ML work without
MongoDB. Case-linked uploads, case APIs, artifact retrieval and reporting require
the database. Transient database outages recover on later requests, without
restarting or relying on a stale startup flag. Writes that fail return an error;
multi-document operations are not yet transactional and may require reconciliation.

Frontend, in a second terminal:

```powershell
npm --prefix frontend run dev
```

Vite uses port 5173 (fails if occupied), proxying `/api` to port 5001. Optional
`frontend/.env` settings are documented in `frontend/.env.example`. There is no
frontend API token build variable. The development access screen accepts an
optional shared API token and retains it in browser session storage; requests
and PDF downloads send it as a bearer header. Investigator labels are still
prototype UI, not authenticated identities or per-case authorization.

Backend failures show errors. `VITE_DEMO_MODE=true` explicitly enables authored
case/dashboard fixtures, never as an automatic fallback. For database-backed
demo records, select **only** `MONGO_DB=cyber_triage_demo` in development and run
`python -m flask --app backend.app seed-demo`. Other databases are rejected by
that command. Old reserved sample case IDs remain labelled as demo; existing
records are neither deleted nor migrated automatically. The remaining live
triage-summary integration is Phase 2 work, so live missing summaries stay null.

## Health and readiness

- `GET /api/health`: HTTP 200 liveness, plus `ready`, `mongo` and model status.
- `GET /api/ready`: HTTP 200 only when MongoDB and the approved network baseline
  are ready; otherwise HTTP 503. No dataset/model training is triggered.
- `GET /api/forensics/capabilities`: native capability/provider availability.

These probes expose no case data or dataset provenance. Every other API route
requires the shared token when configured, including read and download routes.
The 128 MiB upload limit is configurable through `MAX_CONTENT_LENGTH`; larger
disk-image streaming is deferred. Uploaded temporary copies are deleted on
success/failure, including partial save failures. Durable evidence retention is
still Phase 2 work. The standalone runner closes its Mongo client on exit;
embedding code/tests should call `backend.db.close_db(app)` when disposing an app.

## Verification commands

```powershell
# Syntax, dependency consistency, correctness lint, formatting of foundation files,
# import/config validation and Git whitespace checks; no service connection.
.venv\Scripts\python.exe scripts/check.py

# All of the above plus backend tests and frontend service tests/build.
.venv\Scripts\python.exe scripts/check.py --all

# Backend with measured coverage and machine-readable results.
.venv\Scripts\python.exe -m pytest -q --cov --cov-report=term --cov-report=xml:.test-artifacts/coverage.xml --junitxml=.test-artifacts/backend-tests.xml
npm --prefix frontend run check
```

Ruff's repository-wide rules detect syntax/undefined-name/control-flow errors.
Formatting is enforced on the new configuration, foundation tests and check
script; existing forensic modules are not reformatted wholesale. To format that
scope: `python -m ruff format backend/config.py tests/test_foundation.py scripts/check.py`.
Type checking is deferred until meaningful domain types are introduced. Frontend
tests use Node's built-in runner and stub fetch at the service boundary; Vite
validates JSX/imports and bundling. Browser interaction coverage is still absent.

`scripts/verify_results.py` is a historical evaluation/demo tool, not the foundation
gate. Use the commands above for current test results and avoid its data/training
modes during foundation verification.

## Test database isolation

Ordinary pytest runs disable all MongoDB access and block socket connections.
Every test gets a new Flask app and project-local temporary directory. Test
configuration ignores inherited development database settings and credentials;
explicit unsafe overrides are rejected before client creation. Tests cannot turn
off test mode. Configuration is checked again at database access.

Integration tests are marked `integration` and skipped unless explicitly enabled.
Provision a **dedicated** disposable MongoDB instance bound to loopback port 27018
using your existing infrastructure (not the development server on 27017). Then:

```powershell
$env:TEST_MONGO_URI = 'mongodb://127.0.0.1:27018'
.venv\Scripts\python.exe -m pytest -q -m integration --run-integration
```

Only `mongodb://127.0.0.1:27018` or `mongodb://localhost:27018` is accepted: remote
hosts, credentials, URI database names, query options and replica discovery are
rejected. Each fixture creates a fresh `cyber_triage_test_<uuid>` database, refuses
an existing name, records ownership, and drops **only its own database** after
checking the ownership record. Missing service means test setup **fails**; there
is no fallback. Unit tests still run safely when MongoDB is absent. Interrupted
runs may leave a uniquely named test database; cleanup is never broadened to all
test databases. No cleanup command is provided for investigation databases.

See [Phase 1 progress](phase1-progress.md) for actual results and remaining limits.
