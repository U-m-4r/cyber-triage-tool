# Dataset and algorithm sources

Accessed 2026-10-30. No full external dataset or packet capture was downloaded.

- CSE-CIC-IDS2018: [UNB/CIC official documentation](https://www.unb.ca/cic/datasets/ids-2018.html),
  [official AWS registry](https://registry.opendata.aws/cse-cic-ids2018/).
  UNB documents the testbed, capture schedule, labels, CICFlowMeter-V3 feature
  extraction and permission to use/redistribute with dataset citation and AWS
  registry attribution. This work cites **CSE-CIC-IDS2018**, the collaboration
  between CSE and CIC/University of New Brunswick, accessed from the official AWS
  bucket on 2026-10-30. No raw records are republished in Git.
- Iman Sharafaldin, Arash Habibi Lashkari, Ali A. Ghorbani, “Toward Generating a
  New Intrusion Detection Dataset and Intrusion Traffic Characterization”,
  ICISSP 2018; cited by the official dataset documentation.
- CICIDS2017: existing reviewed
  [Kaggle cleaned source](https://www.kaggle.com/datasets/ericanacletoribeiro/cicids2017-cleaned-and-preprocessed),
  approved source SHA-256
  `0ce5a39edffcde3fce59d0dc4aabc9b1f6acab2c626fd7163be9c694f224c292`.
  The existing source cleaning and original training-mask policy are reused.
  Their historical limitations remain documented in Issue 3; this study does not
  claim that source preprocessing was never informed by historical test labels.
- [XGBoost official Python API](https://xgboost.readthedocs.io/en/stable/python/python_api.html):
  sample weights, histogram tree training, early stopping and native model
  serialization. Actual local library version is recorded in candidate metadata;
  current online documentation can describe newer versions.
- [LightGBM official API](https://lightgbm.readthedocs.io/en/stable/pythonapi/lightgbm.LGBMClassifier.html):
  regularized gradient boosting, sample weighting and explicit warning that class
  weighting does not provide calibrated individual probabilities. Actual fitted
  parameters/runtime are in the candidate validation JSONs.

Feature compatibility was established at the family-definition/unit level in
Issue 4's FEATURE_COMPATIBILITY.md. No new build-equivalence assertion is made.
Expanded 2018 features were deliberately not included because the reviewed 2017
source and intended compatible production CSVs do not provide them.

Locked final source hashes are in locked-test.json. The two prior development
source hashes remain in the unchanged Issue 4 dataset-manifest.json. Source
hashing is performed on complete official object bytes before parsing; multipart
ETags identify objects but are not independent authenticity signatures.
