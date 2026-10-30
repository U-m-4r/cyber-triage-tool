# Manual acceptance procedure — still BLOCKED pending genuine evidence

The approved browser capability returned `Local browser use is disabled in Work
settings.` No browser screenshots were captured. The runtime permits UI automation
only through cua_repl; using a separate Playwright process to bypass that restriction
is not an authorized fallback. frontend/package.json provides Node service tests and
a Vite build, not an existing browser-test framework. Passing those does not prove UI
acceptance. The following steps must be performed in a real browser by the user.

## Environment

Open http://127.0.0.1:5219. The frontend must proxy to http://127.0.0.1:5049;
the dedicated MongoDB is on 27018. The current server uses ONLY owned test database
`cyber_triage_test_817fc3c335cf496fa7ff25a55b4ee01a`.
The frontend was restarted with an explicit IPv4 bind:

```powershell
rtk proxy powershell -NoProfile -Command '$env:BACKEND_PROXY_TARGET="http://127.0.0.1:5049"; npm --prefix frontend run dev -- --host 127.0.0.1 --port 5219 --strictPort'
```

Reuse these services if running. Do not restart the 2-million-row evaluation.
Use genuine fixture:
`C:\Users\aumar\OneDrive\Desktop\Projects\cyber-triage-tool\.test-artifacts\issue4\demo.csv`
SHA-256: `ea02d2e08195e16fa5d88e2bcd61f59ac85e9d8057a8075cc39ddf45e47921e8`.
It has 60 rows. The separate original-label manifest remains outside Git.

## Upload and XGBoost

1. Open Cases and create a NEW test investigation titled `Issue 4B manual XGBoost`.
   Do not upload into or modify the existing verified cases.
2. Open its Evidence tab. Select **CSE-CIC-IDS2018 external network-flow CSV**.
3. Select **XGBoost — Supervised Intrusion Detection**. Confirm
   `xgb-bin-12ad91fa39`, threshold `0.4343418846451664`, and conditional compatibility.
4. Capture `01-external-upload-selection.png` with the chosen file/detector visible.
5. Open browser developer tools → Network, then click **Upload and process**.
   Inspect the POST `/api/analyze` payload: `dataset=cse-cic-ids2018`,
   `detector=supervised`, and the new test case ID. Inspect the real JSON response.
   Do not capture authentication headers, cookies, or unrelated investigations.
6. Verify Stored 60, 3 attack decisions, 57 benign decisions, correct model ID,
   unchanged threshold and evidence hash. Capture `02-xgboost-success.png`.
7. Open Artifacts. Verify model prediction/score, threshold and ID are separate
   from final triage priority/risk. Capture `04-prioritized-findings.png` while
   rows and their headings are readable; note pagination may show 25 of 60.

## Isolation Forest

Create a second NEW test investigation titled `Issue 4B manual Isolation Forest`.
Repeat the upload with **Isolation Forest — Unsupervised Anomaly Detection**.
Verify `iforest-65dd0b57a2b1a2020a0b`, threshold 0, 60 stored, 19 anomaly/attack
decisions and 41 normal/benign decisions. Negative decision margin means anomaly;
it is not confidence or accuracy. Capture `03-isolation-forest-success.png`.
Compare actual responses with `817fc3c335cf496fa7ff25a55b4ee01a/*-api.json`.
The new case/record IDs and timestamps will differ, but model outputs must agree.

## Refresh, reopen and report

For each new case, inspect Evidence → acquired source, hash, ingestion history and
model provenance. Refresh with F5; return to Cases and reopen the same case.
Verify the SAME 60 stored findings, model identity, risk values and evidence details.
Capture `05-case-reopened-after-refresh.png` with case ID and model rows visible.
For read-only comparison, original cases are:

- XGBoost: http://127.0.0.1:5219/cases/CASE-02C1EFF54BC5?tab=artifacts
- IF: http://127.0.0.1:5219/cases/CASE-3EACD8C7674C?tab=artifacts

Open Reports on the actual case and click **Generate PDF Report**. Confirm a
real PDF opens/downloads for that exact case. Inspect source/detector section:
CSE-CIC-IDS2018, compatibility CONDITIONAL, model ID/version/hash, fixed threshold,
60 flows, actual decision totals and separate risk ranking. Capture
`06-genuine-pdf-report.png` with case ID and source/model information. Record the
downloaded filename and SHA-256. Browser download is a separate check from the
already-passed API PDF generation; do not mark it passed from API evidence alone.

## Errors

Create a controlled invalid fixture from the real demo, preserving the original:

```powershell
rtk proxy .venv/Scripts/python.exe -c "import pandas as pd; pd.read_csv('.test-artifacts/issue4/demo.csv').drop(columns=['Flow Duration']).to_csv('.test-artifacts/issue4b/missing-feature.csv',index=False)"
```

Choose that file in the new manual case. Upload using the external dataset option.
Expect meaningful missing-feature error, no Stored/success banner from the old
request, no new evidence/findings. Also check an empty `.csv`: the form should reject
it before upload. Capture an error screenshot and the response code/message.

Missing-model behavior is already tested by automated regression. To verify it in
the UI without deleting/renaming models, use a separate TEST-ONLY backend process
on port 5059 with the same owned database and missing configured model path:

```powershell
rtk proxy .venv/Scripts/python.exe -c "from backend.app import create_app; from backend.db import get_db; app=create_app({'TESTING':True,'APP_ENV':'test','DB_MODE':'mongo','MONGO_URI':'mongodb://127.0.0.1:27018','MONGO_DB':'cyber_triage_test_817fc3c335cf496fa7ff25a55b4ee01a','SUPERVISED_MODEL_PATH':'.test-artifacts/issue4b/absent.joblib'}); ctx=app.app_context();ctx.push();assert get_db().test_ownership.find_one({'_id':'817fc3c335cf496fa7ff25a55b4ee01a'});app.run(host='127.0.0.1',port=5059,debug=False)"
rtk proxy powershell -NoProfile -Command '$env:BACKEND_PROXY_TARGET="http://127.0.0.1:5059"; npm --prefix frontend run dev -- --host 127.0.0.1 --port 5229 --strictPort'
```

Open 5229 and refresh service status. Verify XGBoost is unavailable and cannot
silently run as baseline. To check a stale selected model's actual failure: first
load/select XGBoost while the separate 5059 backend uses its valid default model,
then restart ONLY that test backend with the missing-path override above WITHOUT
refreshing the page and submit. Expect explicit missing-model error and no stale
success. Never rename or remove the real model artifacts. Stop only these extra
test processes afterward; the 5049/5219 verified services stay unchanged.

## Evidence submission and acceptance

Save original screenshots under `test-results/issue-4/issue-4b/screenshots/`.
Record date/time, browser/version, case IDs, screenshot filename, request parameters,
observed totals and PASS/FAIL for A–F. Keep original screenshots; do not reconstruct
or draw dashboards. Do not commit raw upload bodies, credentials or private records.
Review the evidence before changing status to PASS or marking PR #24 ready.
