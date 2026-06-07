# Suspicious PowerShell Ticket Note

## Summary
Detected fake/sample suspicious PowerShell execution on `DEVICE-NAME`.

## Analyst Findings
- Parent process: `WINWORD.EXE`
- Process: `powershell.exe`
- Indicators: `EncodedCommand`, `Invoke-WebRequest`, `-ExecutionPolicy Bypass`
- Example destination: `hxxps://example[.]invalid/payload`

## Recommended Next Steps
- Review process tree, command line, script block telemetry, downloaded file path, and hash.
- Validate whether the parent process is expected for the user.
- Escalate if payload download, malware alert, or lateral movement indicators are present.

## Safety Note
Sample/demo only. Do not include real endpoint logs or secrets.
