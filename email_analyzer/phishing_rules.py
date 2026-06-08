"""Body and social-engineering indicators for email threat analysis."""

from __future__ import annotations

from dataclasses import dataclass

from email_parser import ParsedEmail


@dataclass
class BodyFinding:
    """One body/social-engineering finding."""

    title: str
    severity: str
    description: str


RULES = [
    ("Urgency language", "Medium", ("urgent", "immediately", "today", "final notice", "action required")),
    ("Account suspension warning", "High", ("account suspended", "service interruption", "locked out", "deactivated")),
    ("Password reset lure", "High", ("password reset", "password expires", "verify your account")),
    ("Payroll or HR lure", "Medium", ("payroll", "human resources", "benefits", "w-2", "direct deposit")),
    ("Invoice or payment lure", "Medium", ("invoice", "payment", "wire", "bank details", "remittance")),
    ("Executive or vendor impersonation", "Medium", ("ceo", "executive", "vendor", "supplier", "confidential request")),
    ("Credential harvesting language", "High", ("sign in", "login", "credentials", "authenticate")),
    ("MFA reset lure", "High", ("mfa reset", "multi-factor", "authenticator reset")),
    ("QR phishing language", "Medium", ("scan the qr", "qr code", "mobile camera")),
    ("Suspicious call to action", "Medium", ("click here", "open the attachment", "download the document")),
]


def analyze_body(parsed: ParsedEmail) -> list[BodyFinding]:
    """Analyze body text for social-engineering patterns."""
    text = " ".join([parsed.subject, parsed.plain_text_body, parsed.html_body_text]).lower()
    findings = []
    for title, severity, terms in RULES:
        if any(term in text for term in terms):
            findings.append(BodyFinding(title, severity, f"Email text contains {title.lower()} indicators."))
    sender_domain = parsed.from_address.rsplit("@", 1)[-1].lower() if "@" in parsed.from_address else ""
    if sender_domain and any(domain for domain in parsed.domains if domain not in sender_domain and any(brand in domain for brand in ("microsoft", "sharepoint", "onedrive", "docusign", "google"))):
        findings.append(BodyFinding("Sender and URL brand mismatch", "High", "Sender domain and URL/domain brand indicators do not align."))
    if len(findings) >= 4 and not any("spelling" in text for _ in [0]):
        findings.append(BodyFinding("Polished suspicious business email pattern", "Low", "Message has multiple business-lure indicators and may be AI-assisted or templated."))
    return findings

