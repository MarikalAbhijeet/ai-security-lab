"""Header and sender identity checks for email evidence."""

from __future__ import annotations

import re
from dataclasses import dataclass
from email.utils import parseaddr

from email_parser import ParsedEmail


@dataclass
class HeaderFinding:
    """One header analysis result."""

    title: str
    severity: str
    description: str


BRAND_TERMS = ("microsoft", "sharepoint", "onedrive", "docusign", "google", "payroll", "hr", "bank", "invoice")


def analyze_headers(parsed: ParsedEmail) -> list[HeaderFinding]:
    """Analyze sender identity and authentication headers."""
    findings: list[HeaderFinding] = []
    from_name, from_email = parseaddr(parsed.from_address)
    _, reply_email = parseaddr(parsed.reply_to)
    _, return_email = parseaddr(parsed.return_path)

    if parsed.reply_to and domain(reply_email) and domain(from_email) and domain(reply_email) != domain(from_email):
        findings.append(HeaderFinding("From and Reply-To mismatch", "High", f"Reply-To domain `{domain(reply_email)}` differs from sender domain `{domain(from_email)}`."))
    if parsed.return_path and domain(return_email) and domain(from_email) and domain(return_email) != domain(from_email):
        findings.append(HeaderFinding("Return-Path mismatch", "Medium", f"Return-Path domain `{domain(return_email)}` differs from sender domain `{domain(from_email)}`."))
    if display_name_spoof(from_name, from_email):
        findings.append(HeaderFinding("Display name spoofing indicator", "Medium", "Display name references a known brand but sender domain does not match that brand."))

    add_auth_finding(findings, "SPF", parsed.spf_result)
    add_auth_finding(findings, "DKIM", parsed.dkim_result)
    add_auth_finding(findings, "DMARC", parsed.dmarc_result)

    received_text = " ".join(parsed.received_headers).lower()
    if "unknown" in received_text or "localhost" in received_text:
        findings.append(HeaderFinding("Suspicious Received path", "Low", "Received headers contain an obvious unknown or localhost relay indicator."))
    if from_email and not from_email.lower().endswith((".test", ".invalid", ".example")):
        findings.append(HeaderFinding("External sender", "Low", "Sender appears external to the fake lab domain set."))
    if any(term in parsed.subject.lower() or term in from_name.lower() for term in BRAND_TERMS):
        if from_email and not any(term in domain(from_email) for term in BRAND_TERMS):
            findings.append(HeaderFinding("Brand impersonation indicator", "Medium", "Subject or display name references a brand not represented in the sender domain."))
    return findings


def add_auth_finding(findings: list[HeaderFinding], mechanism: str, result: str) -> None:
    """Append authentication findings for fail/missing states."""
    normalized = (result or "missing").lower()
    if normalized in {"fail", "softfail"}:
        findings.append(HeaderFinding(f"{mechanism} {normalized}", "High", f"{mechanism} authentication result is `{normalized}`."))
    elif normalized in {"neutral", "none"}:
        findings.append(HeaderFinding(f"{mechanism} weak result", "Medium", f"{mechanism} authentication result is `{normalized}`."))
    elif normalized == "missing":
        findings.append(HeaderFinding(f"{mechanism} missing", "Low", f"{mechanism} authentication result was not present."))


def domain(address: str) -> str:
    """Return lower-case domain from an email address."""
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].lower()


def display_name_spoof(display_name: str, sender_email: str) -> bool:
    """Return True when display name references a brand but domain does not."""
    name = (display_name or "").lower()
    sender_domain = domain(sender_email)
    for brand in BRAND_TERMS:
        if re.search(rf"\b{re.escape(brand)}\b", name) and brand not in sender_domain:
            return True
    return False

