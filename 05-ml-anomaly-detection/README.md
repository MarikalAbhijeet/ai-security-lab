# ML Anomaly Detection

This project uses scikit-learn `IsolationForest` to identify unusual events in fake/synthetic security logs.

It is a portfolio lab model only. It is not a production detection, UEBA, SIEM analytics, or incident response system.

## Purpose

The module demonstrates how machine learning can support SOC triage by scoring synthetic sign-in and activity events for unusual combinations of security signals.

Example signals include failed login count, MFA result, login hour, impossible travel flag, new device flag, risky country flag, file deletion count, and PowerShell activity count.

## Files

```text
05-ml-anomaly-detection/
|-- anomaly_detector.py
|-- README.md
|-- requirements.txt
|-- docs/
|   |-- ml_model_notes.md
|   `-- security_use_cases.md
|-- sample-inputs/
|   `-- synthetic_signin_logs.csv
|-- sample-output/
|   `-- anomaly_report.md
`-- tests/
    `-- test_anomaly_detector.py
```

## Setup

From this project folder:

```powershell
python -m pip install -r requirements.txt
```

On Windows, if `python` is not available:

```powershell
py -3 -m pip install -r requirements.txt
```

## Run

From this project folder:

```powershell
python .\anomaly_detector.py --input .\sample-inputs\synthetic_signin_logs.csv --output .\sample-output\anomaly_report.md
```

With a custom contamination setting:

```powershell
python .\anomaly_detector.py --input .\sample-inputs\synthetic_signin_logs.csv --output .\sample-output\anomaly_report.md --contamination 0.15
```

## Output

The Markdown report includes:

- Total events analyzed
- Anomaly count
- Top suspicious events
- Anomaly score
- Reasons for suspicion
- Reasoning note explaining that suspicion reasons are heuristic triage explanations, not model feature attributions
- Recommended SOC triage steps
- MITRE ATT&CK mapping
- Limitations and human review warning

## Safe Use

- Use fake/synthetic security data only.
- Do not use real company, client, tenant, user, vendor, or production data.
- Do not store secrets, tokens, passwords, API keys, credentials, private documents, or internal policies in this project.
- Treat model results as triage leads that require human review.

## Tests

From this project folder:

```powershell
python -m unittest discover -s tests
```
