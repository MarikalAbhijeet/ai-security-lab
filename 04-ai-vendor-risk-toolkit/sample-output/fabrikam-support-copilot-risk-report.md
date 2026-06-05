# AI Vendor Risk Assessment Report

## Executive-Style Summary

Fabrikam Support Copilot was assessed for the sample use case 'Assist support analysts with draft responses for fake customer support tickets'. The overall sample risk rating is High with a rule-based score of 97. The review identified 2 high-risk and 7 medium-risk findings. Approval should follow the suggested decision and require documented remediation or compensating controls where applicable.

## Vendor Profile

- Product name: Fabrikam Support Copilot
- Business use case: Assist support analysts with draft responses for fake customer support tickets.
- Data types processed:
  - sample support ticket text
  - sample customer names
  - sample troubleshooting notes
- Authentication method: Username and password with optional SSO add-on
- SSO support: No
- MFA support: Yes
- RBAC: Yes

## Overall Risk Rating

High (score: 97)

## Key Findings

| Category | Severity | Finding | Recommendation |
| --- | --- | --- | --- |
| IAM | High | SSO is not supported. | Require SSO integration before approval for production use. |
| Logging and Monitoring | Medium | Audit log retention is shorter than 90 days. | Require at least 90 days of audit log retention, preferably 180 or more. |
| Data Protection | Medium | Customer data retention is longer than one year. | Require configurable retention and documented deletion workflows. |
| AI-Specific Risk | High | Customer data may be used for model training. | Require contractual opt-out or prohibition on training with customer data. |
| AI-Specific Risk | Medium | Training opt-out language is missing or unclear. | Require explicit opt-out, opt-in, or prohibition language for customer data training. |
| Data Protection | Medium | Export controls are not available. | Require controls for bulk export, sharing, and download activity. |
| Third-Party Risk | Medium | Subprocessors are not disclosed. | Require subprocessor list, notification process, and data flow documentation. |
| Data Protection | Medium | Data residency is not clearly documented. | Require data residency documentation for storage, processing, and support access. |
| Incident Response | Medium | Incident response SLA is best effort. | Require defined security notification timelines and escalation contacts. |

## Missing Controls

- Require SSO integration before approval for production use.
- Require at least 90 days of audit log retention, preferably 180 or more.
- Require configurable retention and documented deletion workflows.
- Require contractual opt-out or prohibition on training with customer data.
- Require controls for bulk export, sharing, and download activity.
- Require data residency documentation for storage, processing, and support access.
- Require defined security notification timelines and escalation contacts.
- Require explicit opt-out, opt-in, or prohibition language for customer data training.
- Require subprocessor list, notification process, and data flow documentation.

## AI-Specific Risks

- Customer data may be used for model training.
- Training opt-out language is missing or unclear.

## Compliance Claims Review

- Unverified sample claim: Sample SOC 2 in progress claim

## Data Protection Concerns

- Customer data retention is longer than one year.
- Export controls are not available.
- Data residency is not clearly documented.

## IAM Concerns

- SSO is not supported.

## Logging and Monitoring Concerns

- Audit log retention is shorter than 90 days.

## Recommended Security Requirements

- Require SSO integration before approval for production use.
- Require at least 90 days of audit log retention, preferably 180 or more.
- Require configurable retention and documented deletion workflows.
- Require contractual opt-out or prohibition on training with customer data.
- Require explicit opt-out, opt-in, or prohibition language for customer data training.
- Require controls for bulk export, sharing, and download activity.
- Require subprocessor list, notification process, and data flow documentation.
- Require data residency documentation for storage, processing, and support access.
- Require defined security notification timelines and escalation contacts.

## Suggested Approval Decision

Do not approve until high-priority security gaps are remediated.

## Follow-Up Questions for the Vendor

- Can you provide current security architecture and data flow documentation?
- Can you provide the latest SOC 2, ISO 27001, or equivalent security assessment summary if available?
- How are customer prompts, outputs, metadata, and audit logs retained and deleted?
- Can you contractually confirm customer data is not used to train models without explicit approval?
- What SSO, MFA, SCIM, and role-based access controls are available for enterprise customers?
- Can audit logs be exported to a SIEM such as Microsoft Sentinel?

## Vendor Risk Notes

- Training policy requires contract review.
- SSO and export controls are not sufficient for production use.

## Sample Data Notice

This report was generated from fake/sample vendor data for portfolio and lab use only.
