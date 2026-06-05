# MITRE ATLAS-Style Mapping

This project uses MITRE ATLAS-style labels for portfolio-friendly AI security testing. Review official MITRE ATLAS entries before using these mappings in production documentation.

| Lab Scenario | MITRE ATLAS-Style Mapping | Defensive Focus |
| --- | --- | --- |
| Direct instruction override | AML.T0051 - LLM Prompt Injection | Preserve instruction hierarchy. |
| System prompt extraction | AML.T0057 - LLM System Prompt Discovery | Do not reveal hidden instructions. |
| Sensitive data request | AML.T0058 - Sensitive Information Disclosure | Prevent exposure of secrets or private data. |
| Role-play jailbreak | AML.T0054 - Jailbreak | Keep safety controls active during role-play. |
| Indirect prompt injection | AML.T0051 - LLM Prompt Injection | Treat retrieved content as untrusted data. |
| Output manipulation | AML.T0051 - LLM Prompt Injection | Validate outputs before use. |
| Data exfiltration attempt | AML.T0048 - Data Exfiltration | Restrict tool use and outbound data movement. |
| Benign normal prompt | No MITRE ATLAS-style behavior detected | Normal safe assistant behavior. |
