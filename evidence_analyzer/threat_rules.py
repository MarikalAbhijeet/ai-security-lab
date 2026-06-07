"""Rule-based threat detections for parsed evidence."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from evidence_parser import EvidenceDocument


POWERSHELL_KEYWORDS = [
    "invoke-expression",
    "iex",
    "downloadstring",
    "downloadfile",
    "frombase64string",
    "-enc",
    "-encodedcommand",
    "bypass",
    "hidden",
]
URL_PATTERN = re.compile(r"https?://[^\s\"']+", re.IGNORECASE)
SUSPICIOUS_TLDS = (".zip", ".top", ".ru", ".cn")


@dataclass(frozen=True)
class ThreatFinding:
    """One rule-based suspicious indicator."""

    title: str
    severity: str
    description: str
    mitre_attack: str
    evidence: str
    recommendation: str


def analyze_document(document: EvidenceDocument) -> list[ThreatFinding]:
    """Run rule-based detections over parsed evidence."""
    findings = []
    records = document.records or [{"line": line} for line in document.lines]
    findings.extend(analyze_signin_sequences(records))
    for index, record in enumerate(records, start=1):
        findings.extend(analyze_record(record, index))
    return deduplicate_findings(findings)


def analyze_signin_sequences(records: list[dict[str, Any]]) -> list[ThreatFinding]:
    """Detect sign-in patterns that require multiple rows."""
    grouped = {}
    for index, record in enumerate(records, start=1):
        normalized = {normalize_key(key): value for key, value in record.items()}
        user = str(first_value(normalized, "user", "userprincipalname", "account", "username")).strip().lower()
        source_ip = str(first_value(normalized, "sourceip", "source_ip", "ipaddress", "ip")).strip().lower()
        key = (user or "unknown-user", source_ip or "unknown-ip")
        grouped.setdefault(key, []).append((index, record, normalized))

    findings = []
    for (user, source_ip), events in grouped.items():
        if len(events) < 2:
            continue
        failed_events = [(index, record) for index, record, normalized in events if is_failed_signin(record, normalized)]
        total_failures = sum(failed_count_for(record, normalized) for _, record, normalized in events)
        if len(failed_events) >= 5 or total_failures >= 5:
            evidence = f"User={user}; source_ip={source_ip}; failed_events={len(failed_events)}; failed_count_total={total_failures}"
            findings.append(finding("Multiple failed logins", "Medium", "Repeated failed authentication attempts were observed across multiple evidence rows.", "Credential Access: Brute Force", evidence, "Review sign-in history, source IP, user risk, and MFA prompts."))

        first_success_after_failure = first_success_after_failures(events)
        if first_success_after_failure and (len(failed_events) > 0 or total_failures > 0):
            index, record = first_success_after_failure
            evidence = summarize_record(record, index)
            findings.append(finding("Successful login after failures", "High", "A successful login occurred after earlier failed attempts in the same evidence set.", "Credential Access: Brute Force", evidence, "Validate the successful session, reset credentials if suspicious, and revoke sessions."))
    return findings


def analyze_record(record: dict[str, Any], index: int) -> list[ThreatFinding]:
    """Analyze one row or event."""
    findings = []
    normalized = {normalize_key(key): value for key, value in record.items()}
    text = " ".join(str(value) for value in record.values()).lower()
    evidence = summarize_record(record, index)

    failed_count = failed_count_for(record, normalized)
    if failed_count >= 5 or "multiple failed logins" in text:
        findings.append(finding("Multiple failed logins", "Medium", "Repeated failed authentication attempts were observed.", "Credential Access: Brute Force", evidence, "Review sign-in history, source IP, user risk, and MFA prompts."))

    if failed_count > 0 and truthy(first_value(normalized, "successafterfailures", "successful_after_failures")):
        findings.append(finding("Successful login after failures", "High", "A successful login occurred after failed attempts.", "Credential Access: Brute Force", evidence, "Validate the successful session, reset credentials if suspicious, and revoke sessions."))

    if "failed mfa" in text or str(first_value(normalized, "mfaresult", "mfa_result")).lower() in {"failed", "denied", "rejected"}:
        findings.append(finding("Failed MFA", "Medium", "MFA failure or denial was observed.", "Credential Access: Multi-Factor Authentication Request Generation", evidence, "Check for MFA fatigue, unfamiliar device, and suspicious source IP."))

    if truthy(first_value(normalized, "newdeviceflag", "new_device_flag")) or "new device" in text:
        findings.append(finding("New device indicator", "Medium", "The activity references a new or unfamiliar device.", "Initial Access: Valid Accounts", evidence, "Confirm device ownership and review conditional access context."))

    if truthy(first_value(normalized, "riskycountryflag", "risky_country_flag")) or "risky country" in text:
        findings.append(finding("Risky country indicator", "High", "The activity references a risky or unusual country.", "Initial Access: Valid Accounts", evidence, "Review geolocation, travel patterns, and impossible travel context."))

    if truthy(first_value(normalized, "impossibletravelflag", "impossible_travel_flag")) or "impossible travel" in text:
        findings.append(finding("Impossible travel indicator", "High", "The evidence suggests geographically impossible travel.", "Initial Access: Valid Accounts", evidence, "Compare sign-in timestamps, IPs, countries, and device identifiers."))

    if "powershell" in text and any(keyword in text for keyword in POWERSHELL_KEYWORDS):
        findings.append(finding("Suspicious PowerShell keywords", "High", "PowerShell command text contains suspicious execution or download indicators.", "Execution: PowerShell", evidence, "Collect process lineage, script block logs, command line, and network destinations."))

    if "-enc" in text or "-encodedcommand" in text or "frombase64string" in text:
        findings.append(finding("Encoded PowerShell command", "High", "Encoded PowerShell execution was observed.", "Defense Evasion: Obfuscated Files or Information", evidence, "Decode the command in a sandbox and review parent process and user context."))

    if "downloadstring" in text or "downloadfile" in text or "iwr " in text or "invoke-webrequest" in text:
        findings.append(finding("Download cradle indicator", "High", "The command may download and execute remote content.", "Command and Control: Ingress Tool Transfer", evidence, "Block suspicious URLs, collect endpoint telemetry, and isolate if execution occurred."))

    delete_count = int_like(first_value(normalized, "filedeletecount", "file_delete_count", "deletedfiles"))
    if delete_count >= 100 or "mass file deletion" in text:
        findings.append(finding("Mass file deletion", "High", "Large-volume file deletion activity was observed.", "Impact: Data Destruction", evidence, "Preserve evidence, isolate host, and review backup/restore options."))

    for url in URL_PATTERN.findall(text):
        if any(url.rstrip("/").endswith(tld) for tld in SUSPICIOUS_TLDS) or "login" in url or "verify" in url:
            findings.append(finding("Suspicious URL indicator", "Medium", "URL includes suspicious wording or uncommon high-risk indicators.", "Initial Access: Phishing", evidence, "Defang URL, check reputation, and review email/user interaction telemetry."))
            break

    if any(keyword in text for keyword in ("global admin", "privileged", "admin role", "role assignment", "owner role")):
        findings.append(finding("Privileged action keyword", "High", "Evidence references admin role or privileged action activity.", "Privilege Escalation: Valid Accounts", evidence, "Verify the actor, approval trail, and recent role assignment changes."))

    severity_value = str(first_value(normalized, "alertseverity", "severity")).lower()
    if severity_value in {"high", "critical"} or "malware" in text:
        findings.append(finding("Malware or high-severity alert", "High", "Evidence references malware or a high-severity alert.", "Execution: Malicious File", evidence, "Review affected host, detection name, quarantine status, and endpoint timeline."))

    return findings


def finding(title: str, severity: str, description: str, mitre_attack: str, evidence: str, recommendation: str) -> ThreatFinding:
    """Build a finding."""
    return ThreatFinding(title, severity, description, mitre_attack, evidence, recommendation)


def deduplicate_findings(findings: list[ThreatFinding]) -> list[ThreatFinding]:
    """Keep output concise by de-duplicating title/evidence pairs."""
    seen = set()
    deduped = []
    for item in findings:
        key = (item.title, item.evidence)
        if key not in seen:
            seen.add(key)
            deduped.append(item)
    return deduped


def normalize_key(key: Any) -> str:
    """Normalize a dictionary key for rule matching."""
    return str(key).lower().replace("_", "").replace("-", "").replace(" ", "")


def first_value(record: dict[str, Any], *keys: str) -> Any:
    """Return the first matching normalized key value."""
    wanted = {normalize_key(key) for key in keys}
    for key, value in record.items():
        if normalize_key(key) in wanted:
            return value
    return ""


def truthy(value: Any) -> bool:
    """Return True for common true-like values."""
    return str(value).strip().lower() in {"true", "yes", "1", "y"}


def int_like(value: Any) -> int:
    """Parse an integer-like value safely."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0


def summarize_record(record: dict[str, Any], index: int) -> str:
    """Return a bounded event summary for reports."""
    pieces = []
    for key, value in list(record.items())[:8]:
        clean_value = str(value).replace("\n", " ").strip()
        if clean_value:
            pieces.append(f"{key}={clean_value[:120]}")
    summary = "; ".join(pieces) if pieces else "No event fields available"
    return f"Event {index}: {summary}"


def failed_count_for(record: dict[str, Any], normalized: dict[str, Any]) -> int:
    """Return failed count from known fields or status text."""
    failed_count = int_like(first_value(normalized, "failedlogincount", "failed_login_count", "failurecount"))
    if failed_count:
        return failed_count
    return 1 if is_failed_signin(record, normalized) else 0


def is_failed_signin(record: dict[str, Any], normalized: dict[str, Any]) -> bool:
    """Return True when a row looks like a failed sign-in."""
    status = " ".join(
        str(first_value(normalized, "status", "result", "resulttype", "signinstatus", "authenticationstatus")).lower().split()
    )
    text = " ".join(str(value) for value in record.values()).lower()
    return status in {"failure", "failed", "denied", "error"} or "failed login" in text or "sign-in failed" in text


def is_success_signin(record: dict[str, Any], normalized: dict[str, Any]) -> bool:
    """Return True when a row looks like a successful sign-in."""
    status = " ".join(
        str(first_value(normalized, "status", "result", "resulttype", "signinstatus", "authenticationstatus")).lower().split()
    )
    text = " ".join(str(value) for value in record.values()).lower()
    return status in {"success", "succeeded", "successful", "0"} or "successful login" in text or "sign-in succeeded" in text


def first_success_after_failures(events: list[tuple[int, dict[str, Any], dict[str, Any]]]) -> tuple[int, dict[str, Any]] | None:
    """Return first success that appears after a failure in uploaded order."""
    saw_failure = False
    for index, record, normalized in events:
        if is_failed_signin(record, normalized) or failed_count_for(record, normalized) > 0:
            saw_failure = True
        elif saw_failure and is_success_signin(record, normalized):
            return index, record
    return None
