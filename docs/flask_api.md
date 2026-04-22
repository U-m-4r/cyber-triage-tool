# Flask API — Cyber Triage Backend

## What We Built

A REST API using Flask that acts as the brain of the Cyber Triage Tool. It accepts network traffic CSV files, runs them through the ML pipeline, and returns anomaly detection results with risk scores. It also has a dedicated endpoint to evaluate model performance against labeled datasets.

---

## How It Works (End to End)

1. You upload a CSV file to one of the API endpoints.
2. The `ForensicPreprocessor` cleans the data, extracts 11 network features, and scales them.
3. The `AnomalyDetector` (Isolation Forest) scores each record — negative scores mean anomalous.
4. The `RiskScorer` combines the ML anomaly score with rule-based checks to produce a final risk score (0–100) and a priority label: `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`.
5. The API returns a JSON response with a summary and the top 100 flagged records.

---

## Endpoints

### `GET /api/health`
Simple health check. Returns `{ "status": "ok" }`.

---

### `POST /api/analyze`
Main analysis endpoint. Upload any CSV (labeled or unlabeled).

**Request:**
```
Content-Type: multipart/form-data
file: <your_csv_file>
```

**Optional query param:**
```
?label_column=YourLabelColumnName
```
If your CSV has a label column with a non-standard name, pass it here.

**Response:**
```json
{
  "summary": {
    "total_records": 2000,
    "critical": 45,
    "high": 120,
    "medium": 300,
    "low": 1535
  },
  "artifacts": [ ... top 100 records with risk scores ... ],
  "evaluation": {
    "label_column": "Label",
    "metrics": { ... }
  }
}
```
The `evaluation` block only appears if a label column is detected in the CSV.

---

### `POST /api/evaluate`
Dedicated evaluation endpoint. Trains on 70% of your labeled data and tests on the remaining 30%.

**Request:**
```
Content-Type: multipart/form-data
file: <your_labeled_csv_file>
```

**Optional query param:**
```
?label_column=YourLabelColumnName
```

**Response:**
```json
{
  "status": "ok",
  "label_column": "Label",
  "records": {
    "total": 2000,
    "train": 1400,
    "test": 600
  },
  "metrics": {
    "accuracy": 0.91,
    "precision": 0.88,
    "recall": 0.85,
    "f1_score": 0.86,
    "roc_auc": 0.93,
    "class_metrics": { ... },
    "confusion_matrix": { ... },
    "triage_top_k": { ... }
  }
}
```

---

### `POST /api/report`
Placeholder — PDF report generation (not yet implemented, returns 501).

---

## Supported Label Column Names

The API auto-detects these column names for ground truth:
`Label`, `label`, `Class`, `class`, `Target`, `target`

Benign traffic is mapped to `0`, everything else to `1` (attack).

---

## How to Run the Backend

### 1. Install dependencies
```bash
pip install -r backend/requirements.txt
```

### 2. Start the server
```bash
python backend/app.py
```
Server runs at `http://localhost:5000`.

### 3. Test with curl
```bash
# Health check
curl http://localhost:5000/api/health

# Analyze a CSV
curl -X POST -F "file=@data/sample/cicids_sample_2000.csv" http://localhost:5000/api/analyze

# Evaluate with labeled data
curl -X POST -F "file=@data/sample/cicids_sample_2000.csv" http://localhost:5000/api/evaluate
```

---

## Key Design Decisions

- Files are saved to `temp/` with a UUID prefix to avoid collisions, then deleted after processing.
- The model is loaded from `models/isolation_forest.pkl` if it exists; otherwise it trains on the uploaded data and saves the model automatically.
- CORS is enabled so a frontend can call the API from a different port.
- All errors return a structured JSON: `{ "error": { "code": "...", "message": "..." } }`.
