# SOC Alert Triage Report

## Short Incident Summary

Microsoft Entra ID Protection generated a high severity alert for alex.wood@example.com on ENTRA-SIGNIN-LOG. The alert was 'Risky sign-in detected for user' at 2026-06-03T14:12:00Z.

## Severity Explanation

Alert severity: **High**

A risky sign-in can indicate compromised credentials, especially when the sign-in includes unfamiliar locations, new devices, or failed MFA.

## Likely MITRE ATT&CK Tactic

- Tactic: Credential Access / Initial Access
- Technique: T1078 - Valid Accounts

## Recommended Triage Steps

1. Review Entra ID sign-in logs for the user, IP address, device, and application.
2. Confirm whether the location and device are expected for the user.
3. Check MFA result, conditional access result, and authentication method used.
4. Review recent mailbox, SharePoint, and endpoint activity for the account.
5. If suspicious, revoke sessions and require password reset or strong reauthentication.

## KQL Hunting Query

```kql
SigninLogs
| where UserPrincipalName == "alex.wood@example.com"
| where IPAddress == "203.0.113.25" or LocationDetails contains "Toronto, Canada"
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName,
          Location, RiskLevelAggregated, ConditionalAccessStatus
| order by TimeGenerated desc
```

## Freshservice-Style Ticket Update

Analyst Update:
Reviewed sample alert SAMPLE-001 from Microsoft Entra ID Protection.
Initial assessment: Risky sign-in detected for user requires validation of user, device, and related activity.
Current severity: High - A risky sign-in can indicate compromised credentials, especially when the sign-in includes unfamiliar locations, new devices, or failed MFA.
MITRE mapping: Credential Access / Initial Access (T1078 - Valid Accounts).
Next action: Complete recommended triage steps and document whether the activity is expected, suspicious, or confirmed malicious.
Escalation: Escalate to Tier 2 IAM/SOC if the user does not recognize the sign-in or MFA failed unexpectedly.

## Escalation Recommendation

Escalate to Tier 2 IAM/SOC if the user does not recognize the sign-in or MFA failed unexpectedly.

## Sample Data Notice

This report was generated from fake/sample alert data for portfolio and lab use only.
