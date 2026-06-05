# Security Use Cases

This lab module demonstrates how anomaly scoring could support SOC investigation workflows using fake/synthetic security logs.

## Identity Risk Triage

Unusual combinations of failed login count, MFA failure, impossible travel, new device activity, and risky country flags may help identify events worth analyst review.

Related MITRE ATT&CK concepts:

- T1078 - Valid Accounts
- T1110 - Brute Force

## Endpoint And Cloud Activity Review

High file deletion counts and elevated PowerShell event counts may support investigation of suspicious post-authentication activity.

Related MITRE ATT&CK concepts:

- T1059.001 - PowerShell
- T1485 - Data Destruction

## SOC Workflow Fit

This model can produce triage leads for:

- Reviewing sign-in context
- Checking MFA outcomes
- Comparing device and country changes
- Looking for endpoint activity spikes
- Escalating events that need human validation

## Safe Data Boundary

Use synthetic logs only. Do not use real tenant logs, user data, company data, client data, vendor data, credentials, API keys, tokens, passwords, or production telemetry in this lab.
