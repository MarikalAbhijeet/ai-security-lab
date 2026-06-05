# AI Security Lab

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Tests](https://github.com/MarikalAbhijeet/ai-security-lab/actions/workflows/python-tests.yml/badge.svg)
![Security](https://img.shields.io/badge/Focus-AI%20Security%20%7C%20SOC-green)
![Portfolio](https://img.shields.io/badge/Portfolio-Security%20Lab-purple)

AI Security Lab is a professional portfolio repository that demonstrates practical security automation, SOC triage, phishing analysis, prompt injection testing, AI vendor risk review, and synthetic ML anomaly detection using safe local sample data.

The lab reflects a profile focused on Security Operations, Microsoft Defender, Microsoft Sentinel, Entra ID / IAM, Cloud Security, Python automation, and AI Security. Each tool starts with simple rule-based logic so the workflows are easy to review, extend, and explain.

## Projects

| Project | What It Does | Portfolio Signal |
| --- | --- | --- |
| [`01-ai-soc-assistant`](01-ai-soc-assistant/README.md) | Generates SOC triage reports from fake Microsoft Defender/Sentinel-style alert JSON files. | SOC investigation, MITRE ATT&CK, KQL, analyst notes, escalation handling |
| [`02-ai-phishing-analyzer`](02-ai-phishing-analyzer/README.md) | Reviews fake user-reported phishing emails and produces risk ratings, indicators, containment steps, and ticket notes. | Email security, phishing triage, authentication checks, user response guidance |
| [`03-prompt-injection-lab`](03-prompt-injection-lab/README.md) | Evaluates safe sample prompt injection tests and maps findings to AI security concepts. | OWASP LLM Top 10, MITRE ATLAS-style mapping, defensive AI patterns |
| [`04-ai-vendor-risk-toolkit`](04-ai-vendor-risk-toolkit/README.md) | Scores fake AI vendor profiles and generates Markdown risk reports. | Vendor risk governance, IAM review, data protection, logging, compliance review |
| [`05-ml-anomaly-detection`](05-ml-anomaly-detection/README.md) | Uses IsolationForest to score fake/synthetic security logs for unusual activity. | ML-assisted SOC triage, anomaly scoring, human review limits |

## Why This Project Matters

AI Security Lab shows how security teams can evaluate AI-related risks without relying on black-box tooling or live production data. The projects model common workflows for security analysts, AI security teams, and governance teams: triaging alerts, reviewing suspicious emails, testing unsafe prompt behavior, and assessing vendor controls.

The repository is intentionally local, transparent, and rule-based. That makes it useful for interviews, GitHub portfolio review, learning, and future extension into richer detection logic or approved enterprise integrations.

## Skills Demonstrated

- Python automation with readable, beginner-friendly structure
- Rule-based security analysis and scoring
- JSON input validation and safe file handling
- Markdown report generation
- SOC alert triage and analyst documentation
- Microsoft Defender and Microsoft Sentinel-style investigation workflows
- KQL hunting query development
- User-reported phishing analysis and containment planning
- IAM, SSO, MFA, RBAC, logging, retention, and deletion control review
- AI prompt injection testing and defensive response design
- AI vendor risk and governance documentation
- Batch processing and repeatable report generation
- Unit testing with `unittest`
- GitHub Actions CI for test automation
- Streamlit dashboard presentation for local demos
- scikit-learn IsolationForest modeling on synthetic security data
- pandas-based CSV validation and feature preparation

## Frameworks And Concepts

- MITRE ATT&CK for SOC alert and phishing-style tactic/technique mapping
- MITRE ATLAS-style concepts for AI threat scenarios
- OWASP LLM Top 10 for prompt injection and AI application risk categories
- AI vendor risk and security governance concepts
- SOC automation, triage consistency, escalation decisions, and ticket updates
- Secure local development practices using fake/sample data only
- ML-assisted triage concepts with human review limitations

See [docs/framework_mapping.md](docs/framework_mapping.md) for the cross-project mapping.

## How To Run

Each project can run from its own folder using local samples. Projects 1-4 use JSON inputs and Python standard-library logic. Project 5 uses a synthetic CSV input with pandas and scikit-learn.

On Windows, use `py -3` if `python` is not available.

### Project 1: SOC Alert Triage Assistant

```powershell
cd .\01-ai-soc-assistant
python .\triage_assistant.py .\sample-inputs\risky-sign-in.json
python .\triage_assistant.py --batch
```

### Project 2: AI Phishing Analyzer

```powershell
cd .\02-ai-phishing-analyzer
python .\phishing_analyzer.py .\sample-inputs\microsoft-365-password-reset.json
python .\phishing_analyzer.py --batch
```

### Project 3: Prompt Injection Lab

```powershell
cd .\03-prompt-injection-lab
python .\prompt_injection_lab.py .\sample-inputs\direct-instruction-override.json
python .\prompt_injection_lab.py --batch
```

### Project 4: AI Vendor Risk Toolkit

```powershell
cd .\04-ai-vendor-risk-toolkit
python .\vendor_risk_assessment.py .\sample-inputs\fabrikam-support-copilot.json
python .\vendor_risk_assessment.py --batch
```

### Project 5: ML Anomaly Detection

```powershell
cd .\05-ml-anomaly-detection
python -m pip install -r requirements.txt
python .\anomaly_detector.py --input .\sample-inputs\synthetic_signin_logs.csv --output .\sample-output\anomaly_report.md
```

Batch mode for Projects 1-4 processes every JSON file in the project's `sample-inputs` folder. By default, generated reports are saved under `sample-output/batch`.

## Dashboard

A simple Streamlit dashboard is available in [`dashboard/`](dashboard/README.md). It lets you choose a project, use an included fake/sample input file, run the matching analyzer, and view the generated Markdown report in the browser. Projects 1-4 also support custom fake/sample JSON uploads in the dashboard; Project 5 uses the included synthetic CSV sample.

Install the dashboard dependency from the repository root:

```powershell
python -m pip install -r .\dashboard\requirements.txt
```

Run the dashboard from the repository root:

```powershell
python -m streamlit run .\dashboard\app.py
```

The dashboard is local-only. Uploads are parsed in memory and are not saved to the repository. Do not upload real secrets, passwords, tokens, company data, client data, or vendor confidential data. The dashboard does not call paid APIs, external AI services, Microsoft services, vendor portals, or live security systems.

## Screenshots

Screenshots are planned for `assets/screenshots/`. The image files are not included yet; the references below show the intended portfolio gallery layout.

| Screenshot | Purpose |
| --- | --- |
| ![Dashboard home placeholder](assets/screenshots/dashboard-home.png) | Streamlit dashboard project selector and sample input picker |
| ![SOC assistant report placeholder](assets/screenshots/soc-assistant-report.png) | AI SOC Assistant Markdown triage report |
| ![Phishing analyzer report placeholder](assets/screenshots/phishing-analyzer-report.png) | AI Phishing Analyzer risk rating and containment report |
| ![Prompt injection report placeholder](assets/screenshots/prompt-injection-report.png) | Prompt Injection Lab risk mapping and safe-response report |
| ![Vendor risk report placeholder](assets/screenshots/vendor-risk-report.png) | AI Vendor Risk Toolkit executive-style vendor risk report |
| ![GitHub Actions tests placeholder](assets/screenshots/github-actions-tests.png) | GitHub Actions workflow showing passing Python tests |

See [assets/screenshots/README.md](assets/screenshots/README.md) for capture guidance.

## Testing And CI

Run all project tests from the repository root:

```powershell
python .\run_all_tests.py
```

Or on Windows:

```powershell
py -3 .\run_all_tests.py
```

GitHub Actions runs the full test suite on push and pull request using `.github/workflows/python-tests.yml`. See [docs/testing_guide.md](docs/testing_guide.md) for details.

## Safe Data Disclaimer

All data in this repository is fake/sample data only. Do not add real company data, real client data, real vendor confidential data, secrets, passwords, tokens, API keys, private documents, internal policies, or production logs.

The tools do not connect to Microsoft Defender, Microsoft Sentinel, Entra ID, Exchange Online, Freshservice, vendor portals, external AI services, paid APIs, or live security systems. Do not add real tenant, user, client, company, vendor, or production telemetry to the ML anomaly detection module.

## Documentation

- [Architecture overview](docs/architecture_overview.md)
- [Security design notes](docs/security_design_notes.md)
- [Framework mapping](docs/framework_mapping.md)
- [Demo walkthrough](docs/demo_walkthrough.md)
- [Testing guide](docs/testing_guide.md)

## Future Roadmap

- Add optional CSV summary exports for batch reports.
- Add richer scoring explanations and confidence fields.
- Add sample screenshots for dashboard-driven demos.
- Add optional local configuration files for custom rule tuning.
- Add approved enterprise integration examples as documentation only.
- Add more unit tests for malformed sample data and edge cases.
- Add lightweight diagrams for data flow and analyst workflows.
- Add a small sample report gallery for quick GitHub review.
- Add CI documentation that explains what each automated test suite validates.
