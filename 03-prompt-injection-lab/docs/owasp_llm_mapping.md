# OWASP LLM Top 10 Mapping

This lab focuses on safe examples aligned to common OWASP LLM Top 10 risk areas.

| Lab Scenario | OWASP Mapping | Why It Matters |
| --- | --- | --- |
| Direct instruction override | LLM01: Prompt Injection | User input attempts to override trusted instructions. |
| System prompt extraction | LLM07: System Prompt Leakage | The prompt attempts to reveal hidden instructions. |
| Sensitive data request | LLM02: Sensitive Information Disclosure | The request asks for secrets, credentials, or private data. |
| Role-play jailbreak | LLM01: Prompt Injection | The prompt tries to bypass safeguards through role-play. |
| Indirect prompt injection | LLM01: Prompt Injection | Untrusted document text contains embedded instructions. |
| Output manipulation | LLM05: Improper Output Handling | The prompt attempts to force a misleading final answer. |
| Data exfiltration attempt | LLM06: Excessive Agency | The prompt asks the assistant to transmit fake secret names. |
| Benign normal prompt | No OWASP LLM risk detected | The request is safe and aligned with the user task. |
