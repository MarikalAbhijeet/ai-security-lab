# OWASP LLM Vendor Risk Mapping

This document maps common AI vendor review areas to OWASP LLM Top 10-style risks.

| Vendor Review Area | OWASP LLM Risk | Review Focus |
| --- | --- | --- |
| Prompt and output handling | LLM01: Prompt Injection | Ask how the product handles malicious or untrusted content. |
| Sensitive data processing | LLM02: Sensitive Information Disclosure | Confirm secrets, credentials, and private data are protected. |
| Supply chain and subprocessors | LLM03: Supply Chain | Review subprocessors, model providers, and third-party integrations. |
| Output use in workflows | LLM05: Improper Output Handling | Require human review and output validation before action. |
| Agentic actions and integrations | LLM06: Excessive Agency | Limit tools, exports, and automated actions. |
| System prompts and configuration | LLM07: System Prompt Leakage | Ask how hidden instructions and tenant configuration are protected. |
| Model behavior and overreliance | LLM09: Misinformation | Require user training and review for generated content. |
| Excessive permissions | LLM10: Unbounded Consumption | Review abuse controls, rate limits, and cost controls. |
