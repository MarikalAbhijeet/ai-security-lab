# Mass File Deletion Playbook

## Alert Overview
Investigates fake/sample endpoint or cloud-file activity where many files are deleted or renamed within a short time.

## Why It Matters
Mass deletion may indicate ransomware preparation, destructive activity, insider risk, or sync tool misconfiguration.

## Common True-Positive Indicators
- High deletion count in a short time window.
- Unusual process initiating deletions.
- Same user/device also shows malware, suspicious script, or failed sign-ins.
- File extensions or paths suggest business-impacting data.

## Common False-Positive Indicators
- Approved cleanup job.
- Known backup or sync tool behavior.
- User-initiated project archive with documented change.

## Data Sources To Review
- Defender `DeviceFileEvents`.
- Process tree and command line.
- Cloud app audit logs when applicable.
- Backup/sync tool telemetry.

## Triage Steps
1. Confirm user, device, process, file count, file paths, and time window.
2. Determine whether the initiating process is expected.
3. Check for ransomware, malware, or suspicious PowerShell activity.
4. Identify whether files are recoverable through approved processes.
5. Escalate if destructive intent or malware is suspected.

## IOCs / Investigation Artifacts To Collect
- User, device, initiating process, file paths, file count, hashes, related malware or script indicators.

## Recommended KQL Queries
- `automation/kql/mass-file-deletion.kql`
- `automation/kql/malware-detection.kql`

## Read-Only PowerShell Checks
- `automation/powershell/Get-DefenderAlertSummary-Sample.ps1`

## MITRE ATT&CK Mapping
- Impact: Data Destruction
- Impact: Data Encrypted for Impact when ransomware indicators are present

## Containment Recommendations
Escalate for approved endpoint/cloud response if deletion is unexplained, malicious, or ongoing. This sample does not perform remediation.

## Escalation Criteria
- Unusual process deletes many files.
- Malware or ransomware indicators exist.
- User denies activity or business-critical paths are affected.

## Freshservice-Style Ticket Note
Mass file deletion review for `DEVICE-NAME` found elevated deletion activity. Validate initiating process, user context, file paths, and related malware/script telemetry.

## Human Review Warning
Confirm business context before labeling activity malicious.

## Safe-Data Disclaimer
Fake/sample values only. Do not include production file paths or client data.
