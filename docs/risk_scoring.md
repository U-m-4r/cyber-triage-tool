# Risk Scoring Engine — Issue #3

## Formula

Risk Score = (Anomaly Score × 0.6) + (Rule Score × 100 × 0.4)
Range: 0 to 100

## Priority Levels

| Score    | Priority |
| -------- | -------- |
| 75 - 100 | CRITICAL |
| 50 - 74  | HIGH     |
| 25 - 49  | MEDIUM   |
| 0 - 24   | LOW      |

## Supported Artifact Types

| Type       | Auto-detected by                      |
| ---------- | ------------------------------------- |
| network    | Flow Duration, Flow Packets/s columns |
| system_log | EventID, LogonType columns            |
| file       | FileName, FileExtension columns       |
| registry   | RegistryKey, RegistryValue columns    |

## Rule Weights

| Rule                    | Weight | Artifact Type |
| ----------------------- | ------ | ------------- |
| High Packet Rate        | 0.8    | network       |
| Long Flow Duration      | 0.6    | network       |
| Large Byte Transfer     | 0.7    | network       |
| Low Packet Size         | 0.4    | network       |
| High Failed Logins      | 0.9    | system_log    |
| Odd Hour Login          | 0.6    | system_log    |
| Privilege Escalation    | 1.0    | system_log    |
| Executable in Temp      | 0.8    | file          |
| Large File Created      | 0.5    | file          |
| Hidden File Detected    | 0.7    | file          |
| Autorun Entry           | 0.9    | registry      |
| Suspicious Registry Key | 0.8    | registry      |

## Test Results

| Priority | Count     |
| -------- | --------- |
| CRITICAL | 38,283    |
| HIGH     | 764,890   |
| MEDIUM   | 662,716   |
| LOW      | 1,054,701 |

Top risk score: 97.52 — matched rules: High Packet Rate, Large Byte Transfer

## Why this formula?

- Anomaly score (60%) — AI model output, objective measure
- Rule score (40%) — domain knowledge, human expertise
- Combined gives better results than either alone
