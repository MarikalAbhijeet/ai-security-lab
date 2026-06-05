# Framework Mapping

This document summarizes how AI Security Lab maps the four projects to security operations, AI security, and governance concepts.

## Cross-Project Mapping

| Project | MITRE ATT&CK | MITRE ATLAS | OWASP LLM Top 10 | Governance Concepts |
| --- | --- | --- | --- | --- |
| AI SOC Assistant | Maps fake alerts to likely tactics and techniques such as initial access, execution, credential access, and impact. | Not the primary focus. | Not the primary focus. | Escalation, analyst documentation, repeatable triage |
| AI Phishing Analyzer | Maps phishing-style activity to initial access, credential access, and social engineering-related investigation themes. | Not the primary focus. | Not the primary focus. | User reporting, containment, ticket notes, email security review |
| Prompt Injection Lab | Not the primary focus, though some concepts overlap with exfiltration and defense evasion thinking. | Uses MITRE ATLAS-style AI threat categories for unsafe prompt behavior. | Maps prompt injection, sensitive information disclosure, insecure output handling, and excessive agency themes. | AI application controls, safe response behavior, defensive testing |
| AI Vendor Risk Toolkit | Not the primary focus. | References AI system risk concepts at a governance level. | References LLM application risks in vendor review questions and findings. | Vendor due diligence, IAM controls, data protection, logging, retention, subprocessors, deletion support |
| ML Anomaly Detection | Maps suspicious synthetic log patterns to valid accounts, brute force, PowerShell, and data destruction concepts. | Not the primary focus. | Not the primary focus. | Human review, model limitations, synthetic ML security lab practices |

## MITRE ATT&CK

The SOC assistant and phishing analyzer use MITRE ATT&CK as a practical investigation language. The mapping helps connect sample alerts and suspicious email patterns to analyst triage decisions.

Examples include:

- Risky sign-in and impossible travel as identity-focused investigation scenarios.
- Suspicious PowerShell as an execution and defense-evasion scenario.
- Malware detection as a malicious file or execution scenario.
- Mass file deletion as an impact-focused scenario.
- Phishing lures as initial access and credential access scenarios.
- ML anomaly results as triage leads for identity, PowerShell, and file deletion review.

## MITRE ATLAS

The prompt injection lab uses MITRE ATLAS-style concepts to frame AI-specific threat scenarios. The goal is not to claim formal coverage of every ATLAS technique, but to show how AI security testing can be documented in a structured way.

Examples include:

- Direct instruction override attempts.
- System prompt extraction attempts.
- Indirect prompt injection through fake document content.
- Fake data exfiltration attempts using non-real secret names.
- Output manipulation attempts.

## OWASP LLM Top 10

The prompt injection lab maps sample tests to OWASP LLM Top 10 categories such as prompt injection, sensitive information disclosure, insecure output handling, and excessive agency.

The vendor risk toolkit also uses OWASP LLM concepts as review prompts for third-party AI systems, especially around training data use, access controls, logging, deletion support, model behavior, and governance.

## AI Vendor Risk And Governance

The vendor risk toolkit models a lightweight AI vendor review. It focuses on:

- Business use case and data types processed
- SSO, MFA, RBAC, and admin controls
- Audit logging and retention
- Encryption at rest and in transit
- Customer data use for model training
- Subprocessor disclosure
- Data residency
- Deletion request support
- Incident response SLA
- Compliance claims that need validation

The reports produce suggested approval decisions and follow-up questions, which are useful for governance and security review conversations.

## SOC Automation

The lab demonstrates SOC automation by turning structured sample inputs into consistent Markdown outputs. This supports:

- Faster first-pass triage
- Repeatable documentation
- Consistent escalation language
- Analyst training
- Portfolio demos that are safe to publish

## ML-Assisted Triage

The ML anomaly detection module demonstrates how synthetic security features can be scored for unusual activity. It uses anomaly scores as triage leads and explicitly warns that model output is not a confirmed incident. This keeps the portfolio claim realistic while showing familiarity with ML security workflows.
