# Security Copilot Chat

Security Copilot Chat is a local-first AI security assistant for the AI Security Lab. It retrieves context from this repository's own docs, READMEs, sample reports, framework notes, SOC playbooks, KQL hunting queries, read-only PowerShell samples, ticket templates, JSON samples, and CSV samples, then generates source-cited answers.

The default LLM provider is local Ollama using `qwen2.5:3b`. Tests and CI use mock mode, so Ollama is not required for automated test runs.

This is a synthetic portfolio/demo assistant, not a production security copilot.

## Safe Data Boundary

- Use local fake/sample lab documentation only.
- Do not paste real company data, client data, tenant data, vendor confidential data, secrets, passwords, tokens, API keys, credentials, private documents, internal policies, or production logs.
- Do not commit `.env` files or API keys.
- Use `.env.example` only as a safe configuration reference.

## Setup

Install Python dependencies from this folder:

```powershell
python -m pip install -r requirements.txt
```

Install and start Ollama, then download the default local model:

```powershell
ollama pull qwen2.5:3b
ollama run qwen2.5:3b
```

Optional local configuration can be set with environment variables:

```powershell
$env:COPILOT_PROVIDER="ollama"
$env:OLLAMA_BASE_URL="http://localhost:11434"
$env:OLLAMA_MODEL="qwen2.5:3b"
```

## Run With Ollama

```powershell
python .\copilot_assistant.py --question "What should an analyst check for suspicious PowerShell?"
```

Choose an answer mode:

```powershell
python .\copilot_assistant.py --question "What KQL should I use for risky sign-ins?" --answer-mode "KQL Recommendation"
```

Save an answer:

```powershell
python .\copilot_assistant.py --question "Explain the synthetic anomaly detection workflow." --output .\sample-output\copilot_sample_answers.md
```

## Run In Mock/Test Mode

Mock mode is deterministic and does not call Ollama or any network service:

```powershell
$env:COPILOT_TEST_MODE="true"
python .\copilot_assistant.py --question "What are the limitations of this lab?"
```

## How It Works

1. Guardrails inspect the question before retrieval or LLM use.
2. The retriever indexes safe local files only.
3. TF-IDF and cosine similarity select the most relevant local chunks, with SOC-topic boosting for matching playbooks and automation resources.
4. The assistant builds a constrained prompt from retrieved local context.
5. Ollama generates an answer locally, or mock mode returns a deterministic test response.
6. The final Markdown answer includes citations, confidence notes, limitations, and safe-use warnings.

When AI Email Threat Analyzer context is active in the dashboard, the Copilot receives only the summarized verdict, risk score, category scores, defanged IOCs, and recommended actions. Raw `.eml` content, full headers, full body text, and attachment content are not sent to Ollama.

## Local Knowledge Sources

The retriever indexes safe local Markdown, TXT, KQL, PowerShell, JSON, and CSV files. It excludes hidden folders, `.env` files, virtual environments, cache folders, sensitive-looking filenames, and binary files.

Important SOC sources include:

- `docs/soc_playbooks/*.md`
- `automation/kql/*.kql`
- `automation/powershell/*.ps1`
- `automation/ticket-templates/*.md`

For suspicious PowerShell, risky sign-in, phishing, malware, impossible travel, mass file deletion, and evidence-analysis questions, the Copilot prefers matching playbooks and automation references and avoids unrelated prompt-injection samples.

When Threat Evidence Workbench context is active, the Copilot prioritizes:

1. Uploaded evidence summary from the current session
2. Extracted IOC summary
3. Matching SOC playbook
4. Matching KQL file
5. Matching ticket template
6. Matching read-only PowerShell sample
7. General docs

The raw uploaded file is not sent to Ollama and is not saved permanently.

## Answer Modes

- SOC Analyst
- Executive Summary
- KQL Recommendation
- MITRE Mapping
- AI Security Review
- Vendor Risk Review
- Incident Response
- Detection Engineering

## If Ollama Is Not Running

The CLI and dashboard show setup-required guidance instead of failing. Start Ollama and run:

```powershell
ollama pull qwen2.5:3b
ollama run qwen2.5:3b
```

## Tests

From this folder:

```powershell
python -m unittest discover -s tests
```

From the repository root:

```powershell
python .\run_all_tests.py
```
