# Threat Evidence Workbench

Threat Evidence Workbench is the local evidence upload and threat analysis module for AI Security Command Center.

It supports fake/sample evidence files only:

- JSON
- CSV
- TXT
- LOG

The module parses uploaded evidence in memory, detects the likely evidence type, extracts IOCs and investigation artifacts, runs simple rule-based threat detections, builds an Evidence Intelligence profile, and generates a Markdown report for SOC-style review.

## Safety Model

- Local-only processing.
- No paid APIs.
- No external service calls.
- Uploaded files are not permanently saved.
- Uploaded files are not indexed into the repository RAG store.
- Local SecOps Copilot receives only a bounded evidence and IOC summary from the current dashboard session, not the full raw uploaded file.
- Sensitive-looking content is blocked before analysis.

Do not upload secrets, passwords, tokens, API keys, company logs, client data, tenant data, production logs, or vendor confidential data.

## Evidence Types

The schema detector looks for:

- Entra sign-in style logs
- Defender alert style JSON
- PowerShell event logs
- Phishing/email indicators
- Generic security logs
- Unknown evidence

## Rule-Based Detections

Current rules cover:

- Multiple failed logins
- Successful login after failures
- Failed MFA
- New device indicators
- Risky country indicators
- Impossible travel indicators
- Suspicious PowerShell keywords
- Encoded PowerShell commands
- Download cradle indicators
- Mass file deletion
- Suspicious URL indicators
- Admin role or privileged action keywords
- Malware or high-severity alert indicators

## Evidence Intelligence Layer

For every uploaded fake/sample file, the workbench builds a structured profile with:

- Evidence type, file name, total records/lines, severity, and highest-priority finding
- Top risky users, devices, IPs, processes, and events
- Explainable risk scores with reasons and recommended review actions
- Extracted IOCs and detected suspicious behaviors
- MITRE ATT&CK mappings, recommended KQL topics, SOC actions, and a ticket-note summary

Local SecOps Copilot receives this bounded profile and IOC summary instead of raw uploaded file content.

## IOC Extraction

The workbench extracts and displays:

- IP addresses
- URLs and domains
- Users and email addresses
- Devices and hostnames
- Processes and parent processes
- Command-line indicators
- File paths
- MD5, SHA1, and SHA256 hashes
- Malware or threat names
- Authentication and privileged activity indicators

URLs, domains, and IP-like values are defanged in display output.

## Sample Data

All sample files in `sample-inputs` are fake/synthetic lab data:

- `sample_signin_logs.csv`
- `sample_defender_alert.json`
- `sample_powershell_events.log`

## Dashboard Usage

1. Start the dashboard from the repository root:

```powershell
.\start-dashboard.ps1
```

1. Open `Threat Evidence Workbench`.
2. Upload a fake/sample JSON, CSV, TXT, or LOG file.
3. Select `Analyze evidence`.
4. Review the parsed summary, suspicious findings, and Markdown report.
5. Select `Ask Local SecOps Copilot about this evidence` to pass only the safe session summary to the Copilot.

## Limitations

This is a portfolio/demo lab module. It is not a production detector, SIEM parser, malware sandbox, or data loss prevention system. Rule matches require human review before operational action.
