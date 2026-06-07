# SOC Escalation Matrix

## Purpose
This sample matrix helps Local SecOps Copilot explain when an analyst should escalate a fake/sample investigation.

## Severity Guidance

| Severity | Sample Conditions | Suggested Handling |
| --- | --- | --- |
| Low | No suspicious behavior, expected admin activity, or benign internal notification. | Document and close after review. |
| Medium | Suspicious indicator exists but no confirmed execution, credential entry, or spread. | Continue triage and collect artifacts. |
| High | Malware execution, encoded PowerShell with download behavior, successful login after failures, failed MFA plus risky context, or mass deletion. | Escalate to incident lead through approved process. |

## Escalation Criteria
- User denies activity tied to identity alerts.
- Privileged/admin action follows suspicious sign-in.
- Endpoint shows malware plus suspicious process tree.
- Phishing recipient entered credentials or opened suspicious attachment.
- Mass deletion affects sensitive or business-critical paths.

## Ticket Note Pattern
`Reviewed fake/sample alert for [user/device]. Key evidence: [IOC summary]. Risk drivers: [behavior summary]. Recommended escalation: [decision]. Human analyst validation required.`

## Human Review Warning
This matrix is portfolio guidance only. It does not replace organizational escalation policy.

## Safe-Data Disclaimer
Do not add real company policy, client data, vendor data, tenant identifiers, or production logs.
