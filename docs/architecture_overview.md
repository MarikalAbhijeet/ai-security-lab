# Architecture Overview

AI Security Lab is organized as four independent Python projects plus one Streamlit dashboard. Each project reads local fake/sample JSON files, applies transparent rule-based logic, and produces Markdown output that resembles analyst or governance documentation.

No project calls paid APIs, external AI services, Microsoft services, vendor systems, or live security platforms.

## Repository Layout

| Path | Purpose |
| --- | --- |
| `01-ai-soc-assistant` | SOC alert triage assistant for fake Defender/Sentinel-style alerts |
| `02-ai-phishing-analyzer` | Phishing analysis tool for fake user-reported emails |
| `03-prompt-injection-lab` | Safe prompt injection test evaluator |
| `04-ai-vendor-risk-toolkit` | AI vendor risk scoring and report generator |
| `dashboard` | Streamlit UI that runs the four local analyzers |
| `docs` | Portfolio documentation, testing guide, mappings, and walkthroughs |
| `run_all_tests.py` | Repo-wide test runner |

## How The SOC Assistant Works

The SOC assistant reads one fake Microsoft Defender/Sentinel-style alert JSON file from `01-ai-soc-assistant/sample-inputs`. It validates required fields, identifies the alert type, applies a matching rule, and generates a Markdown report.

The output includes a short incident summary, severity explanation, likely MITRE ATT&CK tactic and technique, recommended triage steps, KQL hunting query, Freshservice-style ticket update, and escalation recommendation.

The tool is intentionally rule-based so the decision path is easy to inspect. It models the first-pass work a SOC analyst might perform before deeper investigation.

## How The Phishing Analyzer Works

The phishing analyzer reads one fake email JSON file from `02-ai-phishing-analyzer/sample-inputs`. It validates sender metadata, authentication results, body content, URLs, attachments, timestamps, and user-reported reason.

Rules identify suspicious and benign indicators such as failed SPF/DKIM/DMARC, payment-change language, suspicious attachments, QR-code lure language, executive impersonation, and normal internal IT notification patterns.

The generated report includes risk rating, classification, analyst action, user response, containment steps, MITRE ATT&CK mapping, and a Freshservice-style ticket note.

## How The Prompt Injection Lab Works

The prompt injection lab reads one safe sample prompt JSON file from `03-prompt-injection-lab/sample-inputs`. The examples are defensive and non-operational: they demonstrate categories of prompt injection without including real secrets, private policies, or harmful jailbreak instructions.

Rules detect indicators such as instruction override attempts, prompt extraction requests, sensitive data requests, output manipulation, indirect injection, and fake data exfiltration language.

The Markdown report includes risk rating, detected indicators, attack type, OWASP LLM Top 10 mapping, MITRE ATLAS-style mapping, recommended mitigation, expected safe response, and pass/fail result.

## How The Vendor Risk Toolkit Works

The vendor risk toolkit reads one fake AI vendor profile from `04-ai-vendor-risk-toolkit/sample-inputs`. It evaluates controls such as SSO, MFA, RBAC, logging, audit retention, data retention, encryption, model training policy, subprocessors, data residency, deletion support, and incident response SLA.

The scoring logic produces an overall risk rating and a Markdown report with key findings, missing controls, AI-specific risks, data protection concerns, IAM concerns, logging and monitoring concerns, recommended requirements, approval decision, follow-up questions, and an executive-style summary.

## How Batch Processing Works

Each project supports single-file mode and batch mode.

Single-file mode processes one JSON input and prints the Markdown report to the console unless an output path is provided.

Batch mode uses `--batch` to process every JSON file in the project's `sample-inputs` folder. By default, batch reports are written to `sample-output/batch`. Custom batch output directories must stay inside that project's `sample-output` folder.

This design keeps batch processing predictable and prevents reports from being written to arbitrary locations.

## How The Dashboard Works

The Streamlit dashboard in `dashboard/app.py` provides a simple browser interface over the four local analyzers. It uses a fixed project mapping, lists JSON files only from the selected project's `sample-inputs` folder, and runs the matching analyzer script locally.

The dashboard displays the generated Markdown report and raw Markdown. It uses safe error handling for invalid selections, missing scripts, analyzer failures, and timeouts.

The dashboard does not implement separate security logic. It is a presentation layer over the existing project scripts.
