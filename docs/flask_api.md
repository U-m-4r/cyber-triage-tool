# Flask API

Run `python backend/app.py` from the repository root. The API listens on port 5001.
Set `CYBER_TRIAGE_API_TOKEN` and `CORS_ALLOWED_ORIGINS` for shared deployments.
Protected endpoints accept `Authorization: Bearer <token>` or `X-API-Key`.
Uploads are hashed with SHA-256 at intake, stored under UUID names in `temp/`,
and removed after processing, including failures.

## Network endpoints

`POST /api/analyze` accepts a network flow CSV in multipart field `file`. It uses
only the [approved baseline](baseline.md), returning `summary`, the top 100
`artifacts`, `evidence`, `baseline` (schema and dataset provenance),
`preprocessing` (row counts), and `drift` (fixed-reference PSI). Optional
`caseId` links results to a case when MongoDB is available. An `evaluation` block
with actual classification metrics is included when a supported label exists.

`POST /api/evaluate` accepts the same schema with a label column. It evaluates
the fixed baseline on retained uploaded rows, with `evaluation_mode` set to
`fixed_baseline` and `records` containing `total`, `train: 0`, and `test: total`.
It returns `metrics`, `baseline`, `preprocessing`, `drift`, and `evidence`.
It does not split uploaded data or fit any estimator. These metrics describe the
uploaded batch; it may overlap training data and is not automatically a holdout.

Both endpoints accept an optional `?label_column=Name` override. Automatic labels
include `Attack Type`, `Label`, `label`, `Class`, `class`, `Target`, `target`,
`attack_type`, and `Attack`. Benign tokens include `BENIGN`, `Normal Traffic`,
`normal`, `0`, and `benign traffic`; other labels map to attack.
Only evaluate when the uploaded labels are meaningful.

`GET /api/health` preserves liveness and MongoDB status, and adds
`network_baseline.status` (`ready` or `unavailable`). Liveness can be healthy
while network inference is unavailable. Missing-model health does not train.

Errors use `{"error": {"code": "...", "message": "..."}}`:

| HTTP | Code | Meaning |
| --- | --- | --- |
| 503 | `MODEL_MISSING` | Approved bundle absent; operator must train offline |
| 503 | `MODEL_INVALID` | Corrupt, incomplete, incompatible, or legacy artifact |
| 400 | `MISSING_FEATURES` | Required missing network column names are listed |
| 400 | `EMPTY_NETWORK_DATA` | No finite numeric feature rows remain |
| 400 | `INVALID_NETWORK_DATA` | Malformed/duplicate headers or invalid numeric range |
| 400 | `WRONG_ARTIFACT_TYPE` | Non-network records on a network inference path |
| 400 | `MISSING_LABEL_COLUMN` | Evaluation has no usable label column |

## Other evidence and persistence

`POST /api/ingest` takes `file`, optional `kind` (`evtx`, `registry`, `pcap`,
`file`), and optional `caseId`. Supply a kind for ambiguous CSV/JSON exports.
Network records use the approved model, scaler, and drift reference, with the
same missing-feature/model errors. Other source types retain their domain-rule
scoring and continue working without a network baseline. Responses include
`summary`, `artifacts`, `stored`, `kind`, and `evidence`. Network responses also
include `baseline`, `preprocessing`, and `drift`.

`GET /api/artifacts` filters persisted artifacts by type, severity, case ID,
ingestion time, and limit. MongoDB is optional for analysis but required for
artifact retrieval, case CRUD, dashboard, and report persistence.

`GET /api/forensics/capabilities` reports optional EVTX, registry, YARA,
disk-image, and threat-intel support. `POST /api/forensics/ingest` preserves the
native EVTX/hive/disk-image parsing path, rule findings, YARA IOCs, threat-intel
enrichment, and chain of custody. It never uses the network model.

Case/dashboard routes remain `/api/cases`, `/api/cases/<id>`,
`/api/dashboard`, and `/api/triage/<id>`. PDF generation is implemented via
`POST /api/report` with `{"caseId": "..."}` or `GET /api/report/<id>`;
`GET /api/reports/<id>` lists prior reports.

Example from the repository root after baseline setup:

```bash
curl http://localhost:5001/api/health
curl -X POST -F "file=@your_flows.csv" http://localhost:5001/api/analyze
curl -X POST -F "file=@your_labeled_flows.csv" http://localhost:5001/api/evaluate
curl -X POST -F "file=@files.csv" -F "kind=file" http://localhost:5001/api/ingest
```
