# Microsoft Security Automation Library

This folder contains sample-safe Microsoft Sentinel, Defender, Entra ID, Intune, and Freshservice-style investigation resources for AI Security Lab.

All content is fake/demo only. Queries and scripts use placeholders such as `user@example.com`, `DEVICE-NAME`, `203.0.113.10`, and `example.invalid`.

## Safety Boundary

- Do not use these examples directly in production without review.
- Do not add real tenant IDs, users, IPs, domains, client data, vendor data, secrets, tokens, passwords, or API keys.
- PowerShell samples are read-only references and do not modify users, sessions, devices, policies, files, or tenant settings.
- KQL examples are generic Microsoft Sentinel / Defender-style hunting patterns for lab learning.

## Contents

- `kql/` - Microsoft Sentinel / Defender-style hunting queries.
- `powershell/` - Read-only sample PowerShell investigation snippets.
- `ticket-templates/` - Freshservice-style analyst note templates.
