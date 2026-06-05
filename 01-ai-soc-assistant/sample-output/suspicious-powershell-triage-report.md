# SOC Alert Triage Report

## Short Incident Summary

Microsoft Defender for Endpoint generated a medium severity alert for jamie.rivera@example.com on LAB-WIN-021. The alert was 'Suspicious PowerShell command line observed' at 2026-06-03T15:03:00Z.

## Severity Explanation

Alert severity: **Medium**

Encoded or hidden PowerShell can be used for payload execution, discovery, credential access, or defense evasion.

## Likely MITRE ATT&CK Tactic

- Tactic: Execution / Defense Evasion
- Technique: T1059.001 - PowerShell

## Recommended Triage Steps

1. Review the full command line, parent process, script block logs, and user context.
2. Check whether the command used encoded, hidden, download, or bypass flags.
3. Review Defender device timeline around the process start time.
4. Search for the same command, hash, or parent process across other endpoints.
5. If malicious behavior is confirmed, isolate the device and collect investigation package.

## KQL Hunting Query

```kql
DeviceProcessEvents
| where DeviceName == "LAB-WIN-021"
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "EncodedCommand", "IEX", "Bypass", "Hidden")
| project Timestamp, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

## Freshservice-Style Ticket Update

Analyst Update:
Reviewed sample alert SAMPLE-002 from Microsoft Defender for Endpoint.
Initial assessment: Suspicious PowerShell command line observed requires validation of user, device, and related activity.
Current severity: Medium - Encoded or hidden PowerShell can be used for payload execution, discovery, credential access, or defense evasion.
MITRE mapping: Execution / Defense Evasion (T1059.001 - PowerShell).
Next action: Complete recommended triage steps and document whether the activity is expected, suspicious, or confirmed malicious.
Escalation: Escalate to endpoint security if encoded PowerShell, suspicious parent process, or network download behavior is confirmed.

## Escalation Recommendation

Escalate to endpoint security if encoded PowerShell, suspicious parent process, or network download behavior is confirmed.

## Sample Data Notice

This report was generated from fake/sample alert data for portfolio and lab use only.
