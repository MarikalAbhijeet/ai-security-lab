# Security Copilot Chat Answer

## Question

What questions should we ask an AI vendor before approval?

## Answer Mode

Vendor Risk Review

## Answer

Mock Vendor Risk Review answer for local lab testing.

Question: What questions should we ask an AI vendor before approval?

Local context preview: [Source 1] docs/architecture_overview.md :: How The Vendor Risk Toolkit Works :: score=0.1636
The vendor risk toolkit reads one fake AI vendor profile from `04-ai-vendor-risk-toolkit/sample-inputs`. It evaluates controls such as SSO, MFA, RBAC, logging, audit retention, data retention, encryption, model training policy, subprocessors, data residency, deletion support, and incident response SLA. The scoring logic produces an overall risk rating and a Markdown report with key findings, missing controls, AI-specific risks, data protection concerns, IAM concerns, logging and monitoring concerns, recommended requirements, approval decision, follow-up questions, and an executive-style summary.

[Source 2] dashboard/README.md :: Included Projects :: score=0.1547
- AI SOC Assistant - AI Phishing Analyzer - Prompt Injection Lab - AI Vendor Risk Toolkit - ML Anomaly Detection - Security Copilot Ch

This mock response is for CI/tests only and does not call Ollama or any external API.

## Recommended Next Steps

1. Review cited vendor risk notes.
2. Document missing controls.
3. Ask follow-up questions before approval.

## Local Sources Used

- `docs/architecture_overview.md` :: How The Vendor Risk Toolkit Works (score: 0.1636)
- `dashboard/README.md` :: Included Projects (score: 0.1547)
- `04-ai-vendor-risk-toolkit/README.md` :: Limitations (score: 0.1476)
- `docs/demo_walkthrough.md` :: 6. Demo The Vendor Risk Toolkit (score: 0.1307)
- `docs/framework_mapping.md` :: AI Vendor Risk And Governance (score: 0.1234)

## Guardrail Result

- Allowed: True
- No guardrail warnings.

## Provider

- Provider: mock
- Model: qwen2.5:3b
- Setup required: False
- Status: Mock provider enabled for tests.

## Retrieval Confidence

Moderate confidence: strongest local retrieval score was 0.164.

## Limitations

- Uses local AI Security Lab documentation and sample files only.
- Generated answers require human review before operational use.
- Do not use this lab with real company, client, tenant, vendor, or production data.

## Safety Note

Local-first lab assistant. Do not enter secrets, passwords, tokens, API keys, company logs, client data, tenant data, or vendor confidential data.
