# AI Email Threat Analyzer

Local email phishing/spam triage module for the AI Security Command Center.

This module analyzes fake/sample `.eml`, pasted headers, pasted body text, URLs/domains, and attachment metadata. It does not open links, execute attachments, call paid APIs, or save uploaded emails permanently.

## Run Locally

```powershell
py -3 -m unittest discover -s tests
```

The dashboard uses this module through `dashboard/app.py` helper functions:

- `analyze_uploaded_email_bytes(file_name, file_bytes)`
- `analyze_pasted_email_text(text, source_type)`
- `build_email_session_context(analysis)`
- `get_email_ioc_rows(analysis)`
- `get_email_category_scores(analysis)`

## Safety

- Use fake/sample email evidence only.
- Do not upload secrets, passwords, tokens, API keys, company data, client data, tenant data, production logs, or vendor confidential data.
- Raw email content is not passed to Local SecOps Copilot. Only summarized findings, extracted IOCs, risk scores, and recommended actions are used.
- Online enrichment is disabled by default.

## Optional Online Enrichment

Online enrichment is intentionally disabled by default:

```powershell
$env:EMAIL_ONLINE_ENRICHMENT="false"
```

Google Safe Browsing is the first supported live provider. It checks extracted URLs only. The analyzer does not send raw email body text, raw headers, attachments, or uploaded files to the provider.

To enable it for local testing, set:

```powershell
$env:EMAIL_ONLINE_ENRICHMENT="true"
$env:GOOGLE_SAFE_BROWSING_API_KEY="<your-local-key>"
```

Do not commit API keys or `.env` files. If online enrichment is enabled without `GOOGLE_SAFE_BROWSING_API_KEY`, the analyzer continues offline and reports `Online enrichment not configured`.
