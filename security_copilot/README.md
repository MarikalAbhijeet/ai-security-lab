# Security Copilot Chat

Security Copilot Chat is an offline retrieval-based assistant for AI Security Lab. It answers questions using local repository documents only, including project READMEs, docs, sample reports, Markdown notes, KQL snippets, and PowerShell notes if they are present.

Version 1 does not call paid APIs, external LLMs, Microsoft services, vendor systems, or live security platforms.

## Purpose

This module makes the repository feel more like an AI/ML security platform by adding a local RAG-style assistant over the lab's own documentation.

It is designed for portfolio/demo use with fake/sample data only.

## Setup

From this project folder:

```powershell
python -m pip install -r requirements.txt
```

On Windows, if `python` is not available:

```powershell
py -3 -m pip install -r requirements.txt
```

## Run

From this project folder:

```powershell
python .\copilot_assistant.py --question "Summarize the SOC triage guidance for suspicious script activity."
```

Save an answer:

```powershell
python .\copilot_assistant.py --question "Explain the synthetic anomaly detection workflow." --output .\sample-output\copilot_sample_answers.md
```

Use a repo subfolder as the index root:

```powershell
python .\copilot_assistant.py --question "What questions should we ask an AI vendor before approval?" --index-root ..\04-ai-vendor-risk-toolkit
```

## How It Works

1. Discovers local `.md`, `.txt`, `.kql`, `.ps1`, and `README`-style documents.
2. Excludes `.git`, hidden files, `__pycache__`, `.env`, virtual environments, `node_modules`, build/cache folders, internal instruction files, dependency manifests, and sensitive filename patterns.
3. Uses TF-IDF and cosine similarity to retrieve relevant local documents.
4. Generates a concise answer from retrieved snippets.
5. Cites the local source files used.
6. Adds a confidence-style note based on the strongest retrieval score.
7. Clearly says when there is not enough local context to answer well.

## Optional LLM Mode

Future versions may add an optional LLM generation layer. It is intentionally disabled in version 1. Do not add `.env` files, API keys, tokens, secrets, or credentials to this repository.

## Safe Use

- Ask questions about this lab and its fake/sample documentation only.
- Do not paste real company data, client data, tenant data, vendor confidential data, secrets, passwords, tokens, API keys, credentials, private documents, internal policies, or production logs.
- Answers are based only on local AI Security Lab files and should not be treated as production security advice.

## Tests

From this project folder:

```powershell
python -m unittest discover -s tests
```
