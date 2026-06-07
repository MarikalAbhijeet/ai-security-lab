# AI Security Command Center

AI Security Command Center is a Streamlit dashboard for running the local AI Security Lab analyzers, ML anomaly detection module, and Local SecOps Copilot from one browser interface.

The dashboard can use fake/sample JSON files already stored in this repository or a custom JSON file uploaded from your computer. It does not call Microsoft services, paid APIs, cloud AI services, vendor portals, or live security systems. Local SecOps Copilot can call only local Ollama when enabled.

## Included Projects

- AI SOC Assistant
- AI Phishing Analyzer
- Prompt Injection Lab
- AI Vendor Risk Toolkit
- ML Anomaly Detection
- Threat Evidence Workbench
- Local SecOps Copilot

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

- `Security Analysis Modules`: run the local project analyzers and view Markdown reports.
- `Threat Evidence Workbench`: upload fake/sample JSON, CSV, TXT, or LOG evidence for local threat analysis.
- `Local SecOps Copilot`: ask a question, choose an answer mode, retrieve local source files, and generate a source-cited answer through local Ollama or mock mode.

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

## Threat Evidence Workbench

Threat Evidence Workbench supports local-only analysis for fake/sample evidence files:

- `.json`
- `.csv`
- `.txt`
- `.log`

The dashboard validates file type and size, parses the uploaded evidence in memory, blocks sensitive-looking content, extracts IOCs and investigation artifacts, runs rule-based detections, and generates a Markdown evidence report. Uploaded files are not saved permanently and are not indexed into the repository RAG store.

When you select `Ask Local SecOps Copilot about this evidence`, the Copilot receives only the summarized evidence and IOC context from the current session. The raw full uploaded file is not sent to the Copilot prompt and is not written to disk.

## Local SecOps Copilot

The Copilot tab uses the `security_copilot` module. It shows:

- Compact local Ollama status, such as `Ollama Ready | qwen2.5:3b | Local Mode`
- Setup instructions when Ollama or `qwen2.5:3b` is unavailable
- Answer mode selection
- Example prompt buttons for common SOC, phishing, prompt injection, and vendor review questions
- Retrieved source count selection inside `Advanced Settings`
- Chat-style message history
- Clear chat button
- Visible local-model loading panel while Ollama generates
- Local source citations
- Provider debug fields for API reachability, model installation, timeout settings, and last error inside `Provider Debug Details`

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

The `Retrieved sources` slider is hidden under `Advanced Settings` because larger values can improve local context but may slow responses on laptops.

## Safe Use

- Use only the fake/sample JSON files in each project's `sample-inputs` folder.
- If using upload mode, upload fake/sample JSON only.
- Do not add or upload real company data, client data, vendor confidential data, secrets, passwords, tokens, API keys, internal policies, or production logs.
- Do not type real company data, client data, tenant data, vendor confidential data, secrets, passwords, tokens, API keys, internal policies, or production logs into Local SecOps Copilot.
- Do not upload real evidence files, company logs, tenant data, client data, vendor confidential data, secrets, passwords, tokens, or API keys into Threat Evidence Workbench.
- The dashboard runs local Python scripts only and displays the generated Markdown report in the app.
- Security Copilot sends prompts only to local Ollama when enabled. It does not use paid APIs or cloud LLM keys.

## Notes

- The dashboard validates selections against known local sample files.
- The dashboard validates uploaded JSON before generating a report.
- Invalid JSON and missing required fields are shown as user-friendly errors.
- Analyzer failures are shown as safe error messages in the app.
- Version 1 is intentionally simple and rule-based for portfolio review.
