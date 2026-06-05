# Screenshot Capture Guide

Store final portfolio screenshots in this folder. Do not add screenshots that contain real company data, real client data, real vendor data, secrets, tokens, passwords, API keys, private documents, internal policies, or production logs.

Use only the fake/sample data already included in this repository.

## Files To Capture

| File | What It Should Show | Suggested Capture Steps |
| --- | --- | --- |
| `dashboard-home.png` | The Streamlit dashboard with the project dropdown, sample JSON selector, and generate button visible. | Run `py -3 -m streamlit run .\dashboard\app.py` from the repository root, open the local Streamlit URL, and capture the default dashboard view. |
| `soc-assistant-report.png` | A generated SOC alert triage report with summary, severity, MITRE ATT&CK mapping, KQL, and escalation sections visible. | In the dashboard, choose AI SOC Assistant and a sample alert such as `risky-sign-in.json`, then generate the report and capture the report area. |
| `phishing-analyzer-report.png` | A generated phishing report with risk rating, suspicious indicators, recommended action, containment steps, and ticket note visible. | In the dashboard, choose AI Phishing Analyzer and a sample email such as `microsoft-365-password-reset.json`, then generate the report and capture the report area. |
| `prompt-injection-report.png` | A generated prompt injection report with risk level, attack type, OWASP LLM mapping, MITRE ATLAS-style mapping, mitigation, and pass/fail result visible. | In the dashboard, choose Prompt Injection Lab and a sample prompt such as `direct-instruction-override.json`, then generate the report and capture the report area. |
| `vendor-risk-report.png` | A generated vendor risk report with overall risk rating, key findings, missing controls, follow-up questions, and approval decision visible. | In the dashboard, choose AI Vendor Risk Toolkit and a sample vendor such as `fabrikam-support-copilot.json`, then generate the report and capture the report area. |
| `github-actions-tests.png` | The GitHub Actions workflow page showing the Python tests workflow completed successfully. | Open the repository on GitHub, go to Actions, select the latest Python tests run, and capture the successful run summary. |

## Capture Tips

- Use a clean browser window with no personal bookmarks, account details, or unrelated tabs visible.
- Keep the viewport wide enough that headings and report sections are readable.
- Crop screenshots to the app or GitHub content area.
- Prefer PNG files for crisp text.
- Re-run tests before capturing `github-actions-tests.png` so the workflow result is current.
- Review each image before committing to confirm it contains only fake/sample lab data.
