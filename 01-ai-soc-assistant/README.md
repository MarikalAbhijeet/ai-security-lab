# AI-Assisted SOC Alert Triage Assistant

This project is a beginner-friendly, rule-based SOC alert triage assistant for fake Microsoft Defender and Microsoft Sentinel-style alerts.

Version 1 does not use paid APIs, real company data, secrets, tokens, or live security logs. It reads one local sample JSON alert file and generates a Markdown triage report.

## What It Generates

For each alert, the tool creates:

- Short incident summary
- Severity explanation
- Likely MITRE ATT&CK tactic and technique
- Recommended triage steps
- KQL hunting query
- Freshservice-style ticket update
- Escalation recommendation

## Project Structure

```text
01-ai-soc-assistant/
|-- README.md
|-- requirements.txt
|-- triage_assistant.py
|-- sample-inputs/
|   |-- risky-sign-in.json
|   |-- suspicious-powershell.json
|   |-- malware-detected.json
|   |-- impossible-travel.json
|   `-- mass-file-deletion.json
|-- sample-output/
|   `-- risky-sign-in-triage-report.md
`-- tests/
    `-- test_triage_assistant.py
```

## Sample Alerts Included

The lab includes five fake alerts:

1. Risky sign-in
2. Suspicious PowerShell
3. Malware detected
4. Impossible travel
5. Mass file deletion

## Requirements

- Python 3.9 or newer
- No external Python packages are required

## Run Instructions

From this project folder:

```powershell
python .\triage_assistant.py .\sample-inputs\risky-sign-in.json
```

To save the report to a Markdown file:

```powershell
python .\triage_assistant.py .\sample-inputs\risky-sign-in.json -o .\sample-output\risky-sign-in-triage-report.md
```

Run the other sample alerts:

```powershell
python .\triage_assistant.py .\sample-inputs\suspicious-powershell.json
python .\triage_assistant.py .\sample-inputs\malware-detected.json
python .\triage_assistant.py .\sample-inputs\impossible-travel.json
python .\triage_assistant.py .\sample-inputs\mass-file-deletion.json
```

Run all sample alerts in batch mode:

```powershell
python .\triage_assistant.py --batch
python .\triage_assistant.py --batch --output-dir .\sample-output\batch
```

By default, batch mode saves reports to `sample-output/batch`.

## Example Workflow

1. Open one sample alert JSON file.
2. Run the Python triage assistant.
3. Review the generated summary, MITRE mapping, KQL query, and ticket update.
4. Use the output as a sample SOC analyst triage note.

## Example Output

```text
## Short Incident Summary

Microsoft Entra ID Protection generated a high severity alert for alex.wood@example.com on ENTRA-SIGNIN-LOG.

## Likely MITRE ATT&CK Tactic

- Tactic: Credential Access / Initial Access
- Technique: T1078 - Valid Accounts
```

## Security Notes

- All data is fake and safe for portfolio use.
- The tool does not connect to Microsoft Defender, Microsoft Sentinel, Entra ID, or Freshservice.
- The KQL queries are examples for learning and should be reviewed before use in a real environment.
- Rule-based logic is used first so the reasoning is transparent and easy to improve.
- Saved reports must use the `.md` extension and stay inside the `sample-output` folder.

## Limitations

- This is not a live Microsoft Defender, Microsoft Sentinel, Entra ID, or Freshservice integration.
- The KQL is intentionally simple and may need field-name adjustments in a real workspace.
- The tool uses rule-based mappings, so analyst review is still required.
- Sample JSON files must include the required fields used by the script.

## Run Tests

The tests use only the Python standard library:

```powershell
python -m unittest discover -s tests
```

## Portfolio Value

This project demonstrates practical skills in:

- SOC alert triage
- Microsoft Defender and Sentinel-style investigation workflows
- MITRE ATT&CK mapping
- KQL hunting query development
- Ticket documentation
- Safe AI Security portfolio design
