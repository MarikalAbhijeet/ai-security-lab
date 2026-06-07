# Risky Sign-In Playbook

## Alert Overview
Investigates fake/sample risky sign-ins, failed MFA, unfamiliar device usage, risky country indicators, and successful login after failures.

## Why It Matters
Risky sign-ins can indicate credential misuse, account takeover attempts, MFA fatigue, or access from unmanaged devices.

## Common True-Positive Indicators
- Multiple failed logins followed by a successful login.
- Failed MFA or repeated denied MFA prompts.
- New device, risky country, impossible travel, or privileged action after sign-in.

## Common False-Positive Indicators
- User travel confirmed through approved channels.
- Known VPN egress change.
- Managed device enrollment or expected application sign-in.

## Data Sources To Review
- Entra ID `SigninLogs`.
- User risk and sign-in risk details.
- Conditional Access result.
- Device compliance and Intune ownership context.
- Recent privileged role or group activity.

## Triage Steps
1. Identify the user, source IP, device, app, MFA result, and geolocation.
2. Compare failures and successful sign-ins in sequence.
3. Review whether the device is managed and familiar.
4. Check for privileged/admin actions after the sign-in.
5. Validate user activity through approved process.

## IOCs / Investigation Artifacts To Collect
- User principal name, source IP, country, device ID, app, MFA result.
- Failed login count, successful login after failures, impossible travel, risky country, new device.

## Recommended KQL Queries
- `automation/kql/risky-signin.kql`
- `automation/kql/impossible-travel.kql`

## Read-Only PowerShell Checks
- `automation/powershell/Get-RiskyUsers-Sample.ps1`
- `automation/powershell/Get-EntraMFAStatus-Sample.ps1`
- `automation/powershell/Export-IntuneCompliance-Sample.ps1`

## MITRE ATT&CK Mapping
- Initial Access: Valid Accounts
- Credential Access: Brute Force
- Credential Access: Multi-Factor Authentication Request Generation

## Containment Recommendations
Escalate to the approved identity response process if the user cannot confirm activity, privileged access is involved, or suspicious session activity continues.

## Escalation Criteria
- Successful login after repeated failures.
- Failed MFA plus new device or risky country.
- Impossible travel or privileged action after the sign-in.

## Freshservice-Style Ticket Note
Risky sign-in review for `user@example.com` found authentication anomalies from `203.0.113.10`. Review MFA result, device context, geolocation, and post-authentication activity before deciding escalation.

## Human Review Warning
This playbook is sample guidance. Identity response decisions require analyst and business validation.

## Safe-Data Disclaimer
Fake/sample values only. Do not paste production sign-in logs, tenant IDs, or real user data.
