# AI Security Lab Dashboard

This is a simple Streamlit dashboard for running the four local AI Security Lab analyzers from one browser interface.

The dashboard uses only fake/sample JSON files already stored in this repository. It does not call Microsoft services, paid APIs, external AI services, vendor portals, or live security systems.

## Included Projects

- AI SOC Assistant
- AI Phishing Analyzer
- Prompt Injection Lab
- AI Vendor Risk Toolkit

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

## Safe Use

- Use only the fake/sample JSON files in each project's `sample-inputs` folder.
- Do not add real company data, client data, vendor confidential data, secrets, passwords, tokens, API keys, internal policies, or production logs.
- The dashboard runs local Python scripts only and displays the generated Markdown report in the app.

## Notes

- The dashboard validates selections against known local sample files.
- Analyzer failures are shown as safe error messages in the app.
- Version 1 is intentionally simple and rule-based for portfolio review.
