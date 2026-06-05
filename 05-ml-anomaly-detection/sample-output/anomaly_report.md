# ML Anomaly Detection Report

## Summary

- Total events analyzed: 40
- Anomalous events identified: 6
- IsolationForest contamination setting: 0.15
- Data source: fake/synthetic security logs only

## Top Suspicious Events

| Timestamp | User | Source IP | Country | Anomaly Score | Reasons for Suspicion |
| --- | --- | --- | --- | --- | --- |
| 2026-05-01T15:44:00Z | nina.patel@example.test | 203.0.113.88 | KP | 0.2169 | impossible travel indicator; new device sign-in; risky country indicator; high failed login count; MFA did not succeed; unusual file deletion volume; elevated PowerShell activity |
| 2026-05-02T10:58:00Z | nina.patel@example.test | 192.0.2.41 | US | 0.1907 | new device sign-in; MFA did not succeed |
| 2026-05-01T18:40:00Z | taylor.kim@example.test | 203.0.113.35 | BR | 0.1877 | impossible travel indicator; risky country indicator; high failed login count |
| 2026-05-01T22:50:00Z | alex.jordan@example.test | 198.51.100.91 | NG | 0.1787 | impossible travel indicator; new device sign-in; risky country indicator; high failed login count; MFA did not succeed; unusual file deletion volume; elevated PowerShell activity |
| 2026-05-01T10:41:00Z | priya.shah@example.test | 198.51.100.44 | RU | 0.1481 | impossible travel indicator; new device sign-in; risky country indicator; high failed login count; MFA did not succeed; elevated PowerShell activity |
| 2026-05-02T01:12:00Z | sam.rivera@example.test | 192.0.2.35 | US | 0.0195 | unusual combination of numeric security features |

## Reasoning Note

Reasons for suspicion are heuristic triage explanations based on visible security fields. They are not IsolationForest feature attributions and should not be treated as model explainability.

## Recommended SOC Triage Steps

1. Review sign-in context for the flagged user, source IP, country, and device.
2. Confirm whether impossible travel, new device, or risky-country indicators are expected.
3. Check MFA outcome, failed login volume, and recent successful authentication activity.
4. Review endpoint and cloud activity for file deletion or PowerShell spikes.
5. Escalate to SOC/IAM if the user cannot validate the activity or follow-on activity looks suspicious.

## Related MITRE ATT&CK Mapping

- Initial Access / Credential Access: T1078 - Valid Accounts
- Credential Access: T1110 - Brute Force
- Execution: T1059.001 - PowerShell
- Impact: T1485 - Data Destruction

## Limitations and Human Review Warning

This is a synthetic lab model trained on fake sample data. IsolationForest results are anomaly scores, not confirmed incidents. A human analyst must validate context, business justification, identity signals, endpoint telemetry, and user confirmation before taking response action.

## Safe Data Notice

This report was generated from fake/synthetic security logs for portfolio and lab use only. Do not use real company, client, tenant, user, vendor, or production data in this lab.
