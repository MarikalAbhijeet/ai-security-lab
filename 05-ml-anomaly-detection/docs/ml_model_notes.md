# ML Model Notes

This module uses scikit-learn `IsolationForest` to score synthetic security log events.

## Model Choice

IsolationForest is an unsupervised anomaly detection algorithm. It is useful for a lab because it can identify unusual rows without requiring labeled training data. The included CSV does have `expected_is_anomaly`, but that column is included for testing and discussion only. It is not used as a training feature.

## Features Used

The model uses numeric security features:

- Failed login count
- Login hour
- Impossible travel flag
- New device flag
- Risky country flag
- File deletion count
- PowerShell event count
- MFA failure flag derived from `mfa_result`

String fields such as user, IP, country, device ID, and user agent are retained for reporting context but are not directly encoded into the model in version 1.

## Scoring

The tool scales numeric features with `StandardScaler`, trains `IsolationForest`, and converts the decision function into an anomaly score where higher values are more suspicious.

The `--contamination` option controls the expected anomaly ratio. It must be between `0.01` and `0.5`.

## Report Reasoning

The report includes human-readable reasons for suspicion. These reasons are heuristic triage explanations based on visible security fields, such as failed login count, impossible travel, MFA outcome, file deletion count, and PowerShell event count.

They are not IsolationForest feature attributions and should not be presented as formal model explainability.

## Limitations

- This model is trained on small synthetic data.
- It is not tuned for a real environment.
- It does not understand user baselines, device inventory, travel history, business context, or asset criticality.
- It does not replace SIEM rules, EDR detections, identity protection, or analyst review.
- It should be treated as a portfolio demonstration of ML-assisted triage concepts.
