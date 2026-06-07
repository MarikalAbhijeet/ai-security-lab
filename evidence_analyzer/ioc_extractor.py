"""IOC and investigation artifact extraction for uploaded evidence."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from evidence_parser import EvidenceDocument


IP_PATTERN = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")
URL_PATTERN = re.compile(r"https?://[^\s\"')<>]+", re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
MD5_PATTERN = re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])")
SHA1_PATTERN = re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])")
SHA256_PATTERN = re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])")
PROCESS_PATTERN = re.compile(r"\b[A-Za-z][A-Za-z0-9_.-]+\.exe\b", re.IGNORECASE)
DEVICE_KV_PATTERN = re.compile(r"\b(?:device|device_name|devicename|host|hostname|computer|computername)=([A-Za-z0-9_.-]+)", re.IGNORECASE)
PARENT_PROCESS_KV_PATTERN = re.compile(r"\b(?:parent_process|parentprocess|initiatingprocessfilename)=([A-Za-z0-9_.-]+\.exe)", re.IGNORECASE)
WINDOWS_PATH_PATTERN = re.compile(r"\b[A-Za-z]:\\[^\s\"']+", re.IGNORECASE)
UNC_PATH_PATTERN = re.compile(r"\\\\[A-Za-z0-9_.-]+\\[^\s\"']+", re.IGNORECASE)
DOMAIN_PATTERN = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+(?:test|example|invalid|local|com|net|org|io|top|zip|ru|cn)\b", re.IGNORECASE)

POWERSHELL_INDICATORS = {
    "EncodedCommand": re.compile(r"(-enc\b|-encodedcommand\b)", re.IGNORECASE),
    "-ExecutionPolicy Bypass": re.compile(r"-executionpolicy\s+bypass", re.IGNORECASE),
    "Invoke-WebRequest": re.compile(r"\binvoke-webrequest\b|\biwr\b", re.IGNORECASE),
    "IEX": re.compile(r"\biex\b|invoke-expression", re.IGNORECASE),
    "DownloadString": re.compile(r"downloadstring", re.IGNORECASE),
    "FromBase64String": re.compile(r"frombase64string", re.IGNORECASE),
    "Start-Process": re.compile(r"start-process", re.IGNORECASE),
    "hidden window": re.compile(r"(-windowstyle\s+hidden|\bhidden window\b)", re.IGNORECASE),
}

AUTH_INDICATORS = {
    "failed MFA": re.compile(r"failed mfa|mfa_result[=: ]+failed|mfaresult[=: ]+failed", re.IGNORECASE),
    "successful login after failures": re.compile(r"successful login after failures|success_after_failures[=: ]+true", re.IGNORECASE),
    "impossible travel": re.compile(r"impossible travel|impossible_travel_flag[=: ]+true", re.IGNORECASE),
    "new device": re.compile(r"new device|new_device_flag[=: ]+true", re.IGNORECASE),
    "risky country": re.compile(r"risky country|risky_country_flag[=: ]+true", re.IGNORECASE),
}

PRIVILEGED_INDICATORS = {
    "role assignment": re.compile(r"role assignment", re.IGNORECASE),
    "admin consent": re.compile(r"admin consent", re.IGNORECASE),
    "privileged action": re.compile(r"privileged action|privileged", re.IGNORECASE),
    "group membership change": re.compile(r"group membership change|added to group|removed from group", re.IGNORECASE),
}

MALWARE_PATTERN = re.compile(r"\b(?:malware|trojan|ransomware|backdoor|loader|defender detection|detected threat)[:= ]+([A-Za-z0-9._/-]+)", re.IGNORECASE)


@dataclass(frozen=True)
class IOC:
    """One extracted indicator or investigation artifact."""

    type: str
    value: str
    display_value: str
    source: str
    why_it_matters: str


def extract_iocs(document: EvidenceDocument) -> list[IOC]:
    """Extract IOCs and investigation artifacts from parsed evidence."""
    iocs: list[IOC] = []
    for source, text, record in iter_evidence_text(document):
        iocs.extend(extract_from_text(text, source, record))
    return deduplicate_iocs(iocs)


def iter_evidence_text(document: EvidenceDocument):
    """Yield source labels, text, and optional records."""
    if document.records:
        for index, record in enumerate(document.records, start=1):
            text = " ".join(str(value) for value in record.values())
            yield build_source_label("Record", index, record), text, record
    for index, line in enumerate(document.lines, start=1):
        yield build_source_label("Line", index, parse_key_value_line(line)), line, {}


def extract_from_text(text: str, source: str, record: dict[str, Any]) -> list[IOC]:
    """Extract IOCs from one text blob."""
    iocs: list[IOC] = []
    lowered = text.lower()

    for ip in IP_PATTERN.findall(text):
        iocs.append(build_ioc("IP Address", ip, source, "Network indicator for source or destination investigation."))

    urls = URL_PATTERN.findall(text)
    url_domains = set()
    for url in urls:
        clean_url = url.rstrip(".,;")
        iocs.append(build_ioc("URL", clean_url, source, "URL should be defanged, reputation checked, and correlated with email/web telemetry."))
        domain = urlparse(clean_url).hostname
        if domain:
            url_domains.add(domain.lower())
            iocs.append(build_ioc("Domain", domain, source, "Domain extracted from URL for DNS/proxy investigation."))

    email_domains = {email.split("@", 1)[1].lower() for email in EMAIL_PATTERN.findall(text)}
    for domain in DOMAIN_PATTERN.findall(text):
        normalized_domain = domain.rstrip(".,;").lower()
        if "@" not in domain and normalized_domain not in email_domains and normalized_domain not in url_domains:
            iocs.append(build_ioc("Domain", domain.rstrip(".,;"), source, "Domain-like artifact for DNS/proxy investigation."))

    for email in EMAIL_PATTERN.findall(text):
        iocs.append(build_ioc("User", email, source, "User/account artifact for identity and endpoint correlation."))

    device = first_record_value(record, ["device", "device_name", "devicename", "host", "hostname", "computer", "computername"])
    if device:
        iocs.append(build_ioc("Device / Host", device, source, "Device or hostname to review in endpoint and sign-in telemetry."))
    for device_match in DEVICE_KV_PATTERN.findall(text):
        iocs.append(build_ioc("Device / Host", device_match, source, "Device or hostname to review in endpoint and sign-in telemetry."))

    parent = first_record_value(record, ["parent_process", "parentprocess", "initiatingprocessfilename"])
    if parent:
        iocs.append(build_ioc("Parent Process", parent, source, "Parent process helps establish execution chain and user action."))
    for parent_match in PARENT_PROCESS_KV_PATTERN.findall(text):
        iocs.append(build_ioc("Parent Process", parent_match, source, "Parent process helps establish execution chain and user action."))

    for process in PROCESS_PATTERN.findall(text):
        iocs.append(build_ioc("Process", process, source, "Process artifact for endpoint timeline and command-line review."))

    for path in WINDOWS_PATH_PATTERN.findall(text) + UNC_PATH_PATTERN.findall(text):
        iocs.append(build_ioc("File Path", path.rstrip(".,;"), source, "File path can identify payload location, staging path, or affected data."))

    for pattern, hash_type in ((SHA256_PATTERN, "SHA256"), (SHA1_PATTERN, "SHA1"), (MD5_PATTERN, "MD5")):
        for value in pattern.findall(text):
            iocs.append(build_ioc(hash_type, value, source, "Hash artifact for malware, file, and reputation validation."))

    for label, pattern in POWERSHELL_INDICATORS.items():
        if pattern.search(text):
            iocs.append(build_ioc("Command-Line Indicator", label, source, "Suspicious PowerShell behavior that may indicate execution, obfuscation, or download activity."))

    for label, pattern in AUTH_INDICATORS.items():
        if pattern.search(text):
            iocs.append(build_ioc("Authentication Indicator", label, source, "Identity signal that may indicate account compromise or risky access."))

    for label, pattern in PRIVILEGED_INDICATORS.items():
        if pattern.search(text):
            iocs.append(build_ioc("Privileged Activity Indicator", label, source, "Privileged activity should be validated against approvals and actor context."))

    if "malware" in lowered or "detected threat" in lowered or "defender detection" in lowered:
        match = MALWARE_PATTERN.search(text)
        malware_name = match.group(1).rstrip(".,;") if match else "Malware alert indicator"
        iocs.append(build_ioc("Malware / Threat Name", malware_name, source, "Threat name or malware alert for Defender timeline and containment review."))

    return iocs


def build_ioc(ioc_type: str, value: str, source: str, why_it_matters: str) -> IOC:
    """Build an IOC with a defanged display value."""
    value = str(value).strip()
    return IOC(ioc_type, value, display_value_for(ioc_type, value), source, why_it_matters)


def first_record_value(record: dict[str, Any], names: list[str]) -> str:
    """Return first matching record value."""
    normalized = {normalize_key(key): value for key, value in record.items()}
    for name in names:
        value = normalized.get(normalize_key(name))
        if value:
            return str(value)
    return ""


def normalize_key(value: Any) -> str:
    """Normalize field names for matching."""
    return str(value).lower().replace("_", "").replace("-", "").replace(" ", "")


def deduplicate_iocs(iocs: list[IOC]) -> list[IOC]:
    """Deduplicate by type and value while preserving order."""
    seen = set()
    result = []
    for item in iocs:
        key = (item.type.lower(), item.value.lower())
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def build_source_label(prefix: str, index: int, record: dict[str, Any]) -> str:
    """Build a concise source label without exposing raw evidence content."""
    context_fields = []
    for label, names in (
        ("user", ["user", "userprincipalname", "account", "username"]),
        ("device", ["device", "device_name", "devicename", "host", "hostname", "computer", "computername"]),
        ("process", ["process", "process_name", "processname", "filename"]),
        ("parent", ["parent_process", "parentprocess", "initiatingprocessfilename"]),
    ):
        value = first_record_value(record, names)
        if value:
            context_fields.append(f"{label}={value}")
    context = "; ".join(context_fields[:3])
    return f"{prefix} {index}" + (f" ({context})" if context else "")


def parse_key_value_line(line: str) -> dict[str, str]:
    """Parse simple key=value pairs from a text/log line for safe source labeling."""
    matches = re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)=([^\s\"]+|\"[^\"]+\")", line)
    return {key: value.strip('"') for key, value in matches}


def ioc_counts(iocs: list[IOC]) -> dict[str, int]:
    """Return dashboard/report summary counts."""
    return {
        "total_ips": count_types(iocs, {"IP Address"}),
        "total_urls_domains": count_types(iocs, {"URL", "Domain"}),
        "total_users": count_types(iocs, {"User"}),
        "total_devices": count_types(iocs, {"Device / Host"}),
        "total_suspicious_command_indicators": count_types(iocs, {"Command-Line Indicator"}),
    }


def count_types(iocs: list[IOC], types: set[str]) -> int:
    """Count IOCs by type."""
    return sum(1 for item in iocs if item.type in types)


def defang(value: str) -> str:
    """Defang URLs, domains, and IP-like values for display."""
    display = value.replace("https://", "hxxps://").replace("http://", "hxxp://")
    display = display.replace(".", "[.]")
    return display


def display_value_for(ioc_type: str, value: str) -> str:
    """Defang network indicators while preserving readability for process and threat names."""
    if ioc_type in {"IP Address", "URL", "Domain", "User"}:
        return defang(value)
    return value
