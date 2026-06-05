# AI Security Lab

AI Security Lab is a portfolio repository of beginner-friendly but professional security projects focused on the intersection of Security Operations and AI Security. The projects use Python, Markdown, safe sample inputs, and rule-based logic to demonstrate practical workflows without relying on paid APIs or real organizational data.

This lab is designed around a security profile focused on Security Operations, Microsoft Defender, Microsoft Sentinel, Entra ID / IAM, Cloud Security, and AI Security.

## Projects

| Project | Description | Primary Focus |
| --- | --- | --- |
| `01-ai-soc-assistant` | Rule-based SOC alert triage assistant for fake Microsoft Defender and Sentinel-style alerts. | SOC triage, MITRE ATT&CK, KQL, ticket updates |
| `02-ai-phishing-analyzer` | Rule-based analyzer for fake user-reported phishing emails. | Email security, phishing triage, containment guidance |
| `03-prompt-injection-lab` | Safe prompt injection testing lab using fake sample prompts. | OWASP LLM Top 10, MITRE ATLAS-style mapping, AI defensive patterns |
| `04-ai-vendor-risk-toolkit` | AI vendor risk toolkit with fake vendor profiles, templates, and rule-based scoring. | AI governance, vendor risk, IAM, data protection |

## Skills Demonstrated

- SOC alert triage and analyst documentation
- Microsoft Defender and Microsoft Sentinel-style investigation workflows
- KQL hunting query development
- User-reported phishing analysis
- IAM, SSO, MFA, RBAC, and access-control review
- Cloud and SaaS security risk thinking
- AI prompt injection testing and defensive design
- AI vendor risk and security governance
- Markdown reporting and portfolio documentation
- Python automation using only the standard library
- Unit testing with `unittest`

## Frameworks Referenced

- MITRE ATT&CK
- MITRE ATLAS
- OWASP LLM Top 10
- AI vendor risk and security governance concepts

## Safe-Use Disclaimer

All data in this repository is fake/sample data only. Do not add real company data, real client data, real vendor confidential data, secrets, passwords, tokens, API keys, private documents, internal policies, or production logs.

The tools in this lab are educational portfolio projects. They do not connect to Microsoft Defender, Microsoft Sentinel, Entra ID, Exchange Online, Freshservice, vendor portals, external AI services, paid APIs, or live security systems.

## How To Run

Each project uses Python standard-library code only. From the repository root, move into a project folder and run the relevant script.

If `python` is not available on Windows, use `py -3` with the same arguments.

### Project 1: SOC Alert Triage Assistant

```powershell
cd .\01-ai-soc-assistant
python .\triage_assistant.py .\sample-inputs\risky-sign-in.json
python .\triage_assistant.py .\sample-inputs\risky-sign-in.json -o .\sample-output\risky-sign-in-triage-report.md
python -m unittest discover -s tests
```

### Project 2: AI Phishing Analyzer

```powershell
cd .\02-ai-phishing-analyzer
python .\phishing_analyzer.py .\sample-inputs\microsoft-365-password-reset.json
python .\phishing_analyzer.py .\sample-inputs\microsoft-365-password-reset.json -o .\sample-output\microsoft-365-password-reset-report.md
python -m unittest discover -s tests
```

### Project 3: Prompt Injection Testing Lab

```powershell
cd .\03-prompt-injection-lab
python .\prompt_injection_lab.py .\sample-inputs\direct-instruction-override.json
python .\prompt_injection_lab.py .\sample-inputs\direct-instruction-override.json -o .\sample-output\direct-instruction-override-report.md
python -m unittest discover -s tests
```

### Project 4: AI Vendor Risk Toolkit

```powershell
cd .\04-ai-vendor-risk-toolkit
python .\vendor_risk_assessment.py .\sample-inputs\fabrikam-support-copilot.json
python .\vendor_risk_assessment.py .\sample-inputs\fabrikam-support-copilot.json -o .\sample-output\fabrikam-support-copilot-risk-report.md
python -m unittest discover -s tests
```

## Suggested Use Cases

### SOC Teams

- Practice alert triage note writing with safe sample Defender and Sentinel-style alerts.
- Generate repeatable analyst summaries, escalation recommendations, and sample KQL.
- Review user-reported phishing workflows and containment decision points.

### AI Security Teams

- Demonstrate prompt injection categories with safe, non-operational examples.
- Map AI threats to OWASP LLM Top 10 and MITRE ATLAS-style concepts.
- Document defensive patterns such as instruction hierarchy, input separation, output validation, and least-privilege tool use.

### Governance and Vendor Risk Teams

- Review AI vendor controls using sample questionnaires and templates.
- Evaluate IAM, logging, data retention, model training, subprocessors, and deletion support.
- Produce executive-style sample reports for conditional approval or risk remediation.

## Repository Notes

- Each project has its own `README.md`, `sample-inputs`, `sample-output`, and `tests` folder.
- Projects intentionally start with simple rule-based logic before any AI integration.
- No external Python packages are required for version 1 of any project.
