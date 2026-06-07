# Suspicious PowerShell Playbook

## Alert Overview
Investigates fake/sample PowerShell activity with encoded commands, policy bypass flags, download behavior, or suspicious parent processes.

## Why It Matters
PowerShell is a legitimate administration tool, but suspicious command-line flags can indicate execution, defense evasion, payload staging, or post-compromise automation.

## Common True-Positive Indicators
- `WINWORD.EXE` or another Office process spawning `powershell.exe`.
- `EncodedCommand`, `-ExecutionPolicy Bypass`, `Invoke-WebRequest`, `DownloadString`, `IEX`, or hidden window execution.
- Defender malware detection near the same timestamp.

## Common False-Positive Indicators
- Approved admin scripts from known management hosts.
- Signed internal scripts running from documented paths.
- Software deployment tooling with expected change records.

## Data Sources To Review
- Defender `DeviceProcessEvents`.
- Defender `DeviceFileEvents`.
- Defender `DeviceNetworkEvents`.
- Alert evidence and endpoint timeline.
- User and device inventory context.

## Triage Steps
1. Confirm user, device, parent process, command line, timestamp, and destination URL/domain.
2. Pivot on the process tree and look for payload writes or network connections.
3. Decode encoded PowerShell safely in a lab.
4. Check for related Defender malware alerts or suspicious file hashes.
5. Document whether activity matches approved administration.

## IOCs / Investigation Artifacts To Collect
- User, device, source IP, destination IP, URL/domain.
- Parent process, child process, command-line flags.
- File paths, hashes, script block indicators, malware names.

## Recommended KQL Queries
- `automation/kql/suspicious-powershell.kql`
- `automation/kql/malware-detection.kql`

## Read-Only PowerShell Checks
- `automation/powershell/Get-DefenderAlertSummary-Sample.ps1`

## MITRE ATT&CK Mapping
- Execution: Command and Scripting Interpreter
- Defense Evasion: Obfuscated Files or Information
- Command and Control: Ingress Tool Transfer

## Containment Recommendations
Escalate for endpoint containment review if payload execution, malware detection, or lateral movement indicators are present. The sample script does not perform containment.

## Escalation Criteria
- Office spawned PowerShell with encoded or download behavior.
- Defender malware detection is linked to the same device or user.
- Unknown external URL/domain or suspicious file hash is present.

## Freshservice-Style Ticket Note
Suspicious PowerShell was identified on `DEVICE-NAME` for `user@example.com`. Key artifacts include parent process, command-line indicators, destination URL/domain, and related Defender evidence. Human analyst validation is required before containment.

## Human Review Warning
This playbook provides sample guidance only. A human analyst must validate telemetry and business context.

## Safe-Data Disclaimer
Fake/sample values only. Do not paste production logs, secrets, tenant data, or real user data.
