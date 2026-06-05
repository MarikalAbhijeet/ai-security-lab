# AI Security Lab Dashboard

This is a simple Streamlit dashboard for running the four local AI Security Lab analyzers from one browser interface.

The dashboard can use fake/sample JSON files already stored in this repository or a custom JSON file uploaded from your computer. It does not call Microsoft services, paid APIs, external AI services, vendor portals, or live security systems.

## Included Projects

- AI SOC Assistant
- AI Phishing Analyzer
- Prompt Injection Lab
- AI Vendor Risk Toolkit
- ML Anomaly Detection
- Security Copilot Chat

## Setup

From the repository root:

```powershell
python -m pip install -r .\dashboard\requirements.txt
```

On Windows, if `python` is not available:

```powershell
py -3 -m pip install -r .\dashboard\requirements.txt
```

## Run

From the repository root:

```powershell
python -m streamlit run .\dashboard\app.py
```

Or on Windows:

```powershell
py -3 -m streamlit run .\dashboard\app.py
```

Then open the local URL shown by Streamlit.

## Dashboard Tabs

- `Project Reports`: run the local project analyzers and view Markdown reports.
- `Security Copilot Chat`: ask a question and retrieve an answer from local AI Security Lab documentation with cited source files.

## Input Options

### Use Sample JSON

1. Choose a project.
2. Select `Use sample JSON`.
3. Pick a JSON file from that project's `sample-inputs` folder.
4. Select `Generate report`.

Sample mode keeps the existing local workflow and runs the matching analyzer script against the selected sample file.

### Upload Custom JSON

1. Choose a project.
2. Select `Upload custom JSON`.
3. Upload a `.json` file that matches the selected project's expected schema.
4. Select `Generate report`.

Uploaded JSON is parsed and validated in memory. The dashboard does not save uploaded custom JSON files to the repository, does not overwrite sample files, and does not use the uploaded filename as a filesystem path.

The ML Anomaly Detection project currently uses the included synthetic CSV sample from `05-ml-anomaly-detection/sample-inputs`.

## Safe Use

- Use only the fake/sample JSON files in each project's `sample-inputs` folder.
- If using upload mode, upload fake/sample JSON only.
- Do not add or upload real company data, client data, vendor confidential data, secrets, passwords, tokens, API keys, internal policies, or production logs.
- Do not type real company data, client data, tenant data, vendor confidential data, secrets, passwords, tokens, API keys, internal policies, or production logs into Security Copilot Chat.
- The dashboard runs local Python scripts only and displays the generated Markdown report in the app.

## Notes

- The dashboard validates selections against known local sample files.
- The dashboard validates uploaded JSON before generating a report.
- Invalid JSON and missing required fields are shown as user-friendly errors.
- Analyzer failures are shown as safe error messages in the app.
- Version 1 is intentionally simple and rule-based for portfolio review.
