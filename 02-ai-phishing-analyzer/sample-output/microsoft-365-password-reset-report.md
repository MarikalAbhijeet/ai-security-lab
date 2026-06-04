# Phishing Email Analysis Report

## Email Summary

- Sender: security-alert@m365-login.example.com
- Reply-To: helpdesk-reset@support.example.net
- Subject: Microsoft 365 password expires today
- Received: 2026-06-03T09:15:00Z
- User-reported reason: User reported a password reset message they were not expecting.

## Risk Rating

High

## Phishing Classification

Likely phishing

## Suspicious Indicators

- Contains credential lure phrase: 'password expires'
- Contains credential lure phrase: 'verify your account'
- Contains credential lure phrase: 'microsoft 365'
- Contains urgency phrase: 'immediately'
- SPF result is fail
- DKIM result is none
- DMARC result is fail
- Sender domain and reply-to domain do not match

## Benign Indicators

- No strong benign indicators found.

## Sample Data Safety Notes

- URLs use safe sample domains for this lab.

## Recommended Analyst Action

Open or update the phishing ticket, preserve the email, review headers, and search for other recipients.

## Suggested User Response

Tell the user not to click links, open attachments, reply, or scan QR codes. Thank them for reporting.

## Containment Steps

1. Search mail logs for additional recipients.
2. Quarantine matching messages if confirmed malicious.
3. Block malicious sender, domain, URL, or attachment hash where appropriate.
4. Check for clicked links, submitted credentials, or opened attachments.
5. Reset credentials and revoke sessions if credential exposure is suspected.

## MITRE ATT&CK Mapping

- Tactic: Initial Access; Technique: T1566 - Phishing

## Freshservice-Style Ticket Note

Analyst Update:
Reviewed user-reported email received at 2026-06-03T09:15:00Z.
Subject: Microsoft 365 password expires today
Sender: security-alert@m365-login.example.com
Risk rating: High
Classification: Likely phishing
Recommended action: Open or update the phishing ticket, preserve the email, review headers, and search for other recipients.
User guidance: Tell the user not to click links, open attachments, reply, or scan QR codes. Thank them for reporting.

## Sample Data Notice

This report was generated from fake/sample email data for portfolio and lab use only.
