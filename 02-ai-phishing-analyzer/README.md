# AI Phishing Analyzer

This project is a beginner-friendly, rule-based phishing email analyzer for fake user-reported email samples.

Version 1 does not use paid APIs, real company data, secrets, tokens, live mailboxes, or external threat intelligence. It reads one local sample JSON email file and generates a Markdown phishing analysis report.

## What It Generates

For each email, the tool creates:

- Risk rating: Low, Medium, or High
- Suspicious indicators
- Benign indicators
- Sample data safety notes
- Phishing classification
- Recommended analyst action
- Suggested user response
- Containment steps
- MITRE ATT&CK mapping
- Freshservice-style ticket note

## Project Structure

```text
02-ai-phishing-analyzer/
|-- README.md
|-- requirements.txt
|-- phishing_analyzer.py
|-- sample-inputs/
|   |-- microsoft-365-password-reset.json
|   |-- fake-invoice-attachment.json
|   |-- vendor-payment-change.json
|   |-- executive-impersonation.json
|   |-- qr-code-phishing.json
|   `-- benign-internal-it-notification.json
|-- sample-output/
|   `-- microsoft-365-password-reset-report.md
`-- tests/
    `-- test_phishing_analyzer.py
```

## Sample Emails Included

The lab includes six fake email samples:

1. Microsoft 365 password reset lure
2. Fake invoice attachment
3. Vendor payment change request
4. Executive impersonation
5. QR-code phishing example
6. Benign internal IT notification

Each sample includes sender, reply-to, subject, body, safe fake URLs, attachment name when applicable, received timestamp, SPF/DKIM/DMARC results, and the user-reported reason.

## Requirements

- Python 3.9 or newer
- No external Python packages are required

## Run Instructions

From this project folder:

```powershell
python .\phishing_analyzer.py .\sample-inputs\microsoft-365-password-reset.json
```

To save the report to a Markdown file:

```powershell
python .\phishing_analyzer.py .\sample-inputs\microsoft-365-password-reset.json -o .\sample-output\microsoft-365-password-reset-report.md
```

Run the other sample emails:

```powershell
python .\phishing_analyzer.py .\sample-inputs\fake-invoice-attachment.json
python .\phishing_analyzer.py .\sample-inputs\vendor-payment-change.json
python .\phishing_analyzer.py .\sample-inputs\executive-impersonation.json
python .\phishing_analyzer.py .\sample-inputs\qr-code-phishing.json
python .\phishing_analyzer.py .\sample-inputs\benign-internal-it-notification.json
```

## Example Output

```text
## Risk Rating

High

## Phishing Classification

Likely phishing

## MITRE ATT&CK Mapping

- Tactic: Initial Access; Technique: T1566 - Phishing
```

## Security Notes

- All email samples are fake and safe for portfolio use.
- URLs must use safe sample domains such as `example.com`, `example.net`, `example.org`, or `example.invalid`.
- Sender and reply-to addresses must use safe sample domains.
- The tool does not connect to Microsoft Defender, Microsoft Sentinel, Exchange Online, Freshservice, or external APIs.
- Saved reports must use the `.md` extension and stay inside the `sample-output` folder.
- Rule-based logic is used first so the reasoning is transparent and easy to improve.

## Limitations

- This is not a live mailbox or Defender integration.
- The scoring rules are intentionally simple and should not be treated as production phishing detection.
- Header authentication values are sample fields, not parsed raw message headers.
- Safe sample domains are a lab safety control, not a signal that an email is benign.
- Analyst review is still required before taking containment action.

## Run Tests

The tests use only the Python standard library:

```powershell
python -m unittest discover -s tests
```

## Portfolio Value

This project demonstrates practical skills in:

- User-reported phishing triage
- Email security investigation workflow
- SPF, DKIM, and DMARC review concepts
- MITRE ATT&CK phishing mapping
- SOC ticket documentation
- Safe rule-based AI Security portfolio design
