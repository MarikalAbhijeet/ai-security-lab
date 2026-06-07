# Phishing Response Playbook

## Alert Overview
Investigates fake/sample user-reported phishing emails, credential lures, invoice fraud, QR-code phishing, and suspicious attachments.

## Why It Matters
Phishing can lead to credential theft, malware delivery, payment fraud, or account takeover.

## Common True-Positive Indicators
- Sender and reply-to mismatch.
- Failed SPF, DKIM, or DMARC.
- Suspicious URL/domain, QR-code lure, or unexpected attachment.
- Request for payment change, password reset, or urgent executive action.

## Common False-Positive Indicators
- Known business partner sending expected invoice.
- Internal IT notification from approved sender.
- Message already blocked or quarantined with no user interaction.

## Data Sources To Review
- Microsoft 365 Defender email events.
- URL and attachment telemetry.
- User report details.
- Sign-in events after email interaction.

## Triage Steps
1. Review sender, reply-to, subject, body, URLs, attachments, and authentication results.
2. Check whether the user clicked, opened an attachment, or entered credentials.
3. Pivot on URL/domain, sender, attachment hash, and recipient set.
4. Review sign-ins for the recipient after interaction.
5. Draft a user-safe response and document containment.

## IOCs / Investigation Artifacts To Collect
- Sender, reply-to, subject, URLs/domains, attachment name, hashes, recipient list, message ID.

## Recommended KQL Queries
- `automation/kql/phishing-investigation.kql`
- `automation/kql/risky-signin.kql`

## Read-Only PowerShell Checks
No PowerShell action is required for this sample playbook. Use approved read-only message trace tooling in a lab if available.

## MITRE ATT&CK Mapping
- Initial Access: Phishing
- Credential Access: Credentials from Web Browsers
- Execution: User Execution

## Containment Recommendations
Escalate if credentials were entered, attachment execution is suspected, or many users received the same lure. Use approved email security workflows for any production action.

## Escalation Criteria
- User clicked and entered credentials.
- Attachment was opened and endpoint telemetry shows execution.
- Similar emails reached multiple recipients.

## Freshservice-Style Ticket Note
User-reported phishing investigation for `user@example.com` found suspicious sender/domain artifacts and requires review of URL, attachment, and recipient telemetry. Human validation required.

## Human Review Warning
This is sample guidance and not a final phishing verdict.

## Safe-Data Disclaimer
Fake/sample values only. Do not paste real email content, client messages, or production headers.
