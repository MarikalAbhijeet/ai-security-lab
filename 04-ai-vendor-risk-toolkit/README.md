# AI Vendor Risk Toolkit

This project is a beginner-friendly AI vendor risk toolkit using Python, Markdown templates, and fake/sample vendor data.

Version 1 does not use paid APIs, real company data, real vendor confidential data, secrets, tokens, or external services. It reads one local sample vendor JSON profile and generates a Markdown vendor risk report.

## What It Generates

For each fake vendor profile, the tool creates:

- Overall risk rating: Low, Medium, or High
- Key findings
- Missing controls
- AI-specific risks
- Compliance claims review
- Data protection concerns
- IAM concerns
- Logging and monitoring concerns
- Recommended security requirements
- Suggested approval decision
- Follow-up questions for the vendor
- Executive-style summary

## Project Structure

```text
04-ai-vendor-risk-toolkit/
|-- README.md
|-- requirements.txt
|-- vendor_risk_assessment.py
|-- docs/
|   |-- owasp_llm_vendor_risks.md
|   |-- security_controls_mapping.md
|   `-- vendor_review_process.md
|-- templates/
|   |-- vendor_questionnaire.md
|   |-- risk_register_template.md
|   |-- vendor_review_summary.md
|   `-- ai_acceptable_use_review.md
|-- sample-inputs/
|   |-- contoso-ai-notes.json
|   |-- fabrikam-support-copilot.json
|   `-- northwind-ai-email-assistant.json
|-- sample-output/
|   `-- fabrikam-support-copilot-risk-report.md
`-- tests/
    `-- test_vendor_risk_assessment.py
```

## Sample Vendors Included

The lab includes three fake vendor profiles:

1. Contoso AI Notes
2. Fabrikam Support Copilot
3. Northwind AI Email Assistant

Each profile includes sample data types, IAM controls, logging, retention, encryption, model training policy, subprocessors, data residency, deletion support, compliance claims, and risk notes.

## Requirements

- Python 3.9 or newer
- No external Python packages are required

## Run Instructions

From this project folder:

```powershell
python .\vendor_risk_assessment.py .\sample-inputs\fabrikam-support-copilot.json
```

To save the report to a Markdown file:

```powershell
python .\vendor_risk_assessment.py .\sample-inputs\fabrikam-support-copilot.json -o .\sample-output\fabrikam-support-copilot-risk-report.md
```

Run the other sample vendor profiles:

```powershell
python .\vendor_risk_assessment.py .\sample-inputs\contoso-ai-notes.json
python .\vendor_risk_assessment.py .\sample-inputs\northwind-ai-email-assistant.json
```

## Example Output

```text
## Overall Risk Rating

High (score: 97)

## Suggested Approval Decision

Do not approve until high-priority security gaps are remediated.
```

## Security Notes

- All vendor profiles are fake and safe for portfolio use.
- Do not place real vendor confidential data in sample profiles.
- The tool does not connect to external APIs, vendor portals, ticketing systems, or AI services.
- Vendor profile inputs must be local `.json` files inside the `sample-inputs` folder.
- Saved reports must use the `.md` extension and stay inside the `sample-output` folder.
- Rule-based scoring is used first so the reasoning is transparent and easy to improve.

## Limitations

- This is not a replacement for legal, privacy, procurement, or compliance review.
- Scoring is intentionally simple and should not be treated as production-grade vendor risk scoring.
- Compliance claims are fake placeholders and should not be interpreted as real assurances.
- Human review is required before any real vendor approval decision.

## Run Tests

The tests use only the Python standard library:

```powershell
python -m unittest discover -s tests
```

## Portfolio Value

This project demonstrates practical skills in:

- AI vendor security review
- IAM and data protection assessment
- AI training and data retention risk analysis
- SOC logging and monitoring requirements
- OWASP LLM vendor risk awareness
- Security governance documentation
