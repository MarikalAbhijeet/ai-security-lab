# AI Security Lab Dashboard

This is a simple Streamlit dashboard for running the local AI Security Lab analyzers and the local-first Security Copilot from one browser interface.

The dashboard can use fake/sample JSON files already stored in this repository or a custom JSON file uploaded from your computer. It does not call Microsoft services, paid APIs, cloud AI services, vendor portals, or live security systems. Security Copilot can call only local Ollama when enabled.

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

Recommended Windows startup from the repository root:

```powershell
.\start-dashboard.ps1
```

The launcher sets the local Security Copilot environment variables, checks Ollama, pulls `qwen2.5:3b` if needed, preloads the model, and starts Streamlit.

Manual fallback from the repository root:

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
- `Security Copilot Chat`: ask a question, choose an answer mode, retrieve local source files, and generate a source-cited answer through local Ollama or mock mode.

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

## Security Copilot Chat

The chat tab uses the `security_copilot` module. It shows:

- Ollama provider status
- Configured local model
- Setup instructions when Ollama or `qwen2.5:3b` is unavailable
- Answer mode selection
- Retrieved source count selection
- Chat-style message history
- Clear chat button
- Local source citations
- Provider debug fields for API reachability, model installation, timeout settings, and last error

Default local model setup:

```powershell
ollama pull qwen2.5:3b
ollama run qwen2.5:3b
```

For CI or a dashboard demo without Ollama, set mock mode before starting Streamlit:

```powershell
$env:COPILOT_TEST_MODE="true"
python -m streamlit run .\dashboard\app.py
```

## Safe Use

- Use only the fake/sample JSON files in each project's `sample-inputs` folder.
- If using upload mode, upload fake/sample JSON only.
- Do not add or upload real company data, client data, vendor confidential data, secrets, passwords, tokens, API keys, internal policies, or production logs.
- Do not type real company data, client data, tenant data, vendor confidential data, secrets, passwords, tokens, API keys, internal policies, or production logs into Security Copilot Chat.
- The dashboard runs local Python scripts only and displays the generated Markdown report in the app.
- Security Copilot sends prompts only to local Ollama when enabled. It does not use paid APIs or cloud LLM keys.

## Notes

- The dashboard validates selections against known local sample files.
- The dashboard validates uploaded JSON before generating a report.
- Invalid JSON and missing required fields are shown as user-friendly errors.
- Analyzer failures are shown as safe error messages in the app.
- Version 1 is intentionally simple and rule-based for portfolio review.
