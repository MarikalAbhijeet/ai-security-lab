# Demo Walkthrough

This walkthrough provides a simple path for presenting AI Security Lab in a GitHub portfolio review, interview, or personal lab demo.

## 1. Start With The Repository Summary

Open the top-level `README.md` and explain that the repo contains four local, rule-based security projects:

- SOC alert triage assistant
- Phishing analyzer
- Prompt injection lab
- AI vendor risk toolkit
- ML anomaly detection
- Security Copilot Chat

Emphasize that all data is fake/sample only and no paid APIs or live systems are used. Security Copilot uses local Ollama when enabled, or mock mode for tests.

## 2. Run The Test Suite

From the repository root:

```powershell
py -3 .\run_all_tests.py
```

Expected result:

```text
All project tests passed.
```

This shows that the project has repeatable validation, not just scripts that work manually.

## 3. Demo The SOC Assistant

```powershell
cd .\01-ai-soc-assistant
py -3 .\triage_assistant.py .\sample-inputs\risky-sign-in.json
```

Point out the generated incident summary, severity explanation, MITRE ATT&CK mapping, KQL query, triage steps, ticket update, and escalation recommendation.

## 4. Demo The Phishing Analyzer

```powershell
cd ..\02-ai-phishing-analyzer
py -3 .\phishing_analyzer.py .\sample-inputs\microsoft-365-password-reset.json
```

Highlight the risk rating, suspicious indicators, benign indicators, classification, containment steps, user response, and Freshservice-style ticket note.

## 5. Demo The Prompt Injection Lab

```powershell
cd ..\03-prompt-injection-lab
py -3 .\prompt_injection_lab.py .\sample-inputs\direct-instruction-override.json
```

Explain how the sample prompt is defensive and fake. Show the OWASP LLM Top 10 mapping, MITRE ATLAS-style mapping, recommended mitigation, expected safe response, and pass/fail result.

## 6. Demo The Vendor Risk Toolkit

```powershell
cd ..\04-ai-vendor-risk-toolkit
py -3 .\vendor_risk_assessment.py .\sample-inputs\fabrikam-support-copilot.json
```

Discuss the overall risk rating, missing controls, AI-specific risks, IAM concerns, data protection concerns, follow-up questions, and suggested approval decision.

## 7. Demo Batch Processing

Use the matching batch command for the project being demonstrated:

```powershell
cd .\01-ai-soc-assistant
py -3 .\triage_assistant.py --batch
cd ..\02-ai-phishing-analyzer
py -3 .\phishing_analyzer.py --batch
cd ..\03-prompt-injection-lab
py -3 .\prompt_injection_lab.py --batch
cd ..\04-ai-vendor-risk-toolkit
py -3 .\vendor_risk_assessment.py --batch
```

Batch mode processes all JSON files in that project's `sample-inputs` folder and writes Markdown reports to `sample-output/batch`.

This is useful for showing automation and repeatability across multiple samples.

## 8. Demo The ML Anomaly Detection Module

```powershell
cd ..\05-ml-anomaly-detection
py -3 -m pip install -r .\requirements.txt
py -3 .\anomaly_detector.py --input .\sample-inputs\synthetic_signin_logs.csv --output .\sample-output\anomaly_report.md
```

Explain that the model uses fake/synthetic logs, pandas feature handling, and scikit-learn IsolationForest. Point out that the report treats anomalies as triage leads that require human validation.

## 9. Demo Security Copilot Chat

```powershell
cd ..\security_copilot
py -3 -m pip install -r .\requirements.txt
ollama pull qwen2.5:3b
ollama run qwen2.5:3b
py -3 .\copilot_assistant.py --question "Summarize the SOC triage guidance for suspicious script activity."
```

Point out that the answer cites local files, uses only local lab documentation as retrieval context, and sends generation only to local Ollama. If Ollama is not running, the CLI and dashboard show setup instructions instead of failing.

## 10. Demo The Dashboard

From the repository root, install the dashboard dependency if needed:

```powershell
py -3 -m pip install -r .\dashboard\requirements.txt
```

Start the dashboard:

```powershell
py -3 -m streamlit run .\dashboard\app.py
```

In the browser:

1. Select a project.
2. Select a sample JSON file.
3. Generate the report.
4. Review the Markdown output.

The dashboard is a local presentation layer over the same analyzer scripts and the Security Copilot Chat module. Projects 1-4 use JSON samples and optional custom fake/sample JSON uploads. Project 5 uses the included synthetic CSV sample.

## 11. Explain The Security Boundary

Close the demo by stating the safety model:

- Fake/sample data only.
- No secrets, tokens, passwords, API keys, real company data, real client data, or real vendor confidential data.
- No real tenant, user, vendor, client, company, or production telemetry in the ML lab.
- No real secrets, private documents, or company data typed into Security Copilot Chat.
- No paid APIs or cloud AI calls.
- Security Copilot can call only local Ollama and has mock mode for tests.
- No live Microsoft, email, ticketing, vendor, or security system integrations.

This keeps the portfolio safe to publish while still showing practical security thinking.
