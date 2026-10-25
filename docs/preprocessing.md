# Network preprocessing

The production schema contains these ordered numeric columns:

1. Flow Duration (microseconds)
2. Total Fwd Packets
3. Total Length of Fwd Packets (bytes)
4. Fwd Packet Length Max
5. Fwd Packet Length Min
6. Fwd Packet Length Mean
7. Bwd Packet Length Max
8. Bwd Packet Length Min
9. Flow Bytes/s
10. Flow Packets/s
11. Packet Length Mean

Packet lengths are in bytes; rates are per second. Export compatible CICFlowMeter
flows. Headers are whitespace-trimmed, and duplicates after trimming are rejected.
The network ingestion parser also recognizes its documented CSV aliases; arbitrary
tshark/Zeek fields are not equivalent to the complete flow schema. Missing model
features are errors, never fabricated zeros. Extra metadata and label columns are
allowed and excluded from the feature matrix. Explicit `artifact_type` values
must be `network` on network inference paths.

Required values are converted to numeric. Rows containing nonnumeric, NaN, or
infinite required values are dropped, and `preprocessing.dropped_invalid_rows`
reports that count. Missing optional metadata does not discard a valid flow.
No valid rows remaining produces `EMPTY_NETWORK_DATA`. Feature order follows the
saved schema, independent of upload column order. Labels and records remain
aligned to retained rows.

Training selects benign rows, removes duplicate feature vectors, and fits
`StandardScaler` once. Inference preserves repeated flows because their frequency
matters for drift, and calls only the saved scaler's `transform`. Z-score scaling
uses training mean and standard deviation, never uploaded-batch statistics.
Scaler overflow is an input error.

`ForensicPreprocessor`'s older generic fitting helpers remain available for
isolated offline experiments and historical evaluation scripts. The Flask upload
handlers do not use them. Historical full-frame cleaning and split evaluation
have different semantics from the production baseline; their metrics must not
be described as validation of this baseline.

See [baseline setup](baseline.md) and [API behavior](flask_api.md).
