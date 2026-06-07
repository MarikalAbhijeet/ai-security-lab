# Impossible Travel Playbook

## Alert Overview
Investigates fake/sample identity events where sign-ins appear from geographically distant locations within an unrealistic time window.

## Why It Matters
Impossible travel can indicate credential misuse, session theft, proxy activity, or risky access from unfamiliar locations.

## Common True-Positive Indicators
- Different countries in a short time window.
- New or unmanaged device.
- Failed MFA, risky country, or successful login after failures.
- Privileged action after the suspicious sign-in.

## Common False-Positive Indicators
- Corporate VPN or secure access service egress shift.
- User travel confirmed through approved process.
- Mobile carrier geolocation inaccuracies.

## Data Sources To Review
- Entra ID `SigninLogs`.
- User risk and sign-in risk.
- Device compliance and user travel notes.
- Privileged role activity.

## Triage Steps
1. Compare timestamps, IP addresses, locations, app names, and devices.
2. Check whether VPN or known proxy infrastructure explains location changes.
3. Review MFA result, device state, and user risk.
4. Look for privileged or sensitive actions after the suspicious sign-in.
5. Escalate if the user cannot confirm activity.

## IOCs / Investigation Artifacts To Collect
- User, IPs, countries, timestamps, device IDs, app names, MFA results, privileged activity indicators.

## Recommended KQL Queries
- `automation/kql/impossible-travel.kql`
- `automation/kql/risky-signin.kql`

## Read-Only PowerShell Checks
- `automation/powershell/Get-RiskyUsers-Sample.ps1`
- `automation/powershell/Get-EntraMFAStatus-Sample.ps1`

## MITRE ATT&CK Mapping
- Initial Access: Valid Accounts
- Defense Evasion: Use Alternate Authentication Material

## Containment Recommendations
Use the approved identity response process if compromise is suspected. This playbook does not perform any action.

## Escalation Criteria
- Impossible travel plus failed MFA or new device.
- Suspicious successful login followed by privileged activity.
- User denies activity.

## Freshservice-Style Ticket Note
Impossible travel review for `user@example.com` found sign-ins from differing locations. Review IP, country, timestamp, device, MFA, and privileged activity context.

## Human Review Warning
Geolocation can be noisy. Validate with a human analyst and approved user-verification process.

## Safe-Data Disclaimer
Fake/sample values only. Do not add real user travel data or production sign-in records.
