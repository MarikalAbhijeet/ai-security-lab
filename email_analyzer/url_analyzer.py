"""URL and domain extraction and risk checks."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlparse, urlunparse


@dataclass
class URLFinding:
    """One URL/domain analysis finding."""

    indicator: str
    indicator_type: str
    severity: str
    reason: str
    display_value: str


SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"}
SUSPICIOUS_TLDS = {".zip", ".mov", ".top", ".xyz", ".click", ".work", ".support"}
BRAND_TERMS = ("microsoft", "sharepoint", "onedrive", "docusign", "google", "payroll", "bank", "invoice")


def analyze_urls(urls: list[str], domains: list[str]) -> list[URLFinding]:
    """Analyze extracted URLs and domains without opening them."""
    findings: list[URLFinding] = []
    for url in urls:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        text = unquote(url).lower()
        if parsed.hostname and re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", parsed.hostname):
            findings.append(make_finding(url, "URL", "High", "URL uses an IP address host."))
        if host in SHORTENER_DOMAINS:
            findings.append(make_finding(url, "URL", "Medium", "URL uses a known shortener."))
        if "redirect" in text or "url=" in text or "continue=" in text:
            findings.append(make_finding(url, "URL", "Medium", "URL contains redirect-looking parameters."))
        if len(host.split(".")) >= 5:
            findings.append(make_finding(url, "Domain", "Medium", "Domain has excessive subdomains."))
        if host.startswith("xn--"):
            findings.append(make_finding(url, "Domain", "High", "Domain uses punycode/IDN syntax."))
        if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
            findings.append(make_finding(url, "Domain", "Medium", "Domain uses a suspicious TLD for email links."))
        if any(term in text for term in ("login", "password", "reset", "verify", "mfa", "signin")):
            findings.append(make_finding(url, "URL", "High", "URL contains credential or login lure keywords."))
        if parse_qs(parsed.query):
            if any(key.lower() in {"token", "session", "auth", "redirect", "url", "continue"} for key in parse_qs(parsed.query)):
                findings.append(make_finding(url, "URL", "Medium", "URL contains suspicious query parameters."))
        if brand_impersonation(host):
            findings.append(make_finding(url, "Domain", "High", "Domain appears to impersonate a known brand."))

    for domain in domains:
        lower = domain.lower()
        if brand_impersonation(lower):
            findings.append(make_finding(domain, "Domain", "High", "Domain appears to impersonate a known brand."))
    return group_findings(findings)


def brand_impersonation(host: str) -> bool:
    """Return True for simple brand lookalike indicators."""
    if host.endswith((".microsoft.com", ".google.com", ".sharepoint.com", ".docusign.com")):
        return False
    return any(term in host for term in BRAND_TERMS)


def make_finding(value: str, indicator_type: str, severity: str, reason: str) -> URLFinding:
    """Create URL finding with defanged display value."""
    return URLFinding(value, indicator_type, severity, reason, defang(strip_url_query(value)))


def strip_url_query(value: str) -> str:
    """Strip query and fragment values before display or Copilot context."""
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        return value
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))


def defang(value: str) -> str:
    """Defang URLs, domains, and IP-like values for display."""
    result = str(value).replace("https://", "hxxps://").replace("http://", "hxxp://")
    return result.replace(".", "[.]")


def group_findings(findings: list[URLFinding]) -> list[URLFinding]:
    """Group URL/domain findings by display value and combine reasons."""
    grouped: dict[str, URLFinding] = {}
    reasons_by_key: dict[str, list[str]] = {}
    for finding in findings:
        key = finding.display_value.lower()
        reason = normalize_reason(finding.reason)
        if key not in grouped:
            grouped[key] = URLFinding(
                indicator=finding.indicator,
                indicator_type=finding.indicator_type,
                severity=finding.severity,
                reason=reason,
                display_value=finding.display_value,
            )
            reasons_by_key[key] = [reason]
            continue
        grouped[key].severity = highest_severity(grouped[key].severity, finding.severity)
        if reason not in reasons_by_key[key]:
            reasons_by_key[key].append(reason)
        grouped[key].reason = "; ".join(reasons_by_key[key])
    return list(grouped.values())


def normalize_reason(reason: str) -> str:
    """Normalize finding reason for grouped display."""
    clean = str(reason).strip().rstrip(".")
    replacements = {
        "URL contains redirect-looking parameters": "redirect-looking parameters",
        "URL contains credential or login lure keywords": "credential/login keywords",
        "URL contains suspicious query parameters": "suspicious query parameters",
        "Domain appears to impersonate a known brand": "brand impersonation",
        "URL uses an IP address host": "IP-address URL",
        "URL uses a known shortener": "URL shortener",
        "Domain has excessive subdomains": "excessive subdomains",
        "Domain uses punycode/IDN syntax": "punycode/IDN",
        "Domain uses a suspicious TLD for email links": "suspicious TLD",
    }
    return replacements.get(clean, clean)


def highest_severity(left: str, right: str) -> str:
    """Return the higher severity label."""
    order = {"Low": 1, "Medium": 2, "High": 3}
    return left if order.get(left, 0) >= order.get(right, 0) else right
