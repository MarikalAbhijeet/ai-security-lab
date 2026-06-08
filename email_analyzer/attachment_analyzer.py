"""Attachment metadata risk checks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from email_parser import AttachmentMetadata


@dataclass
class AttachmentFinding:
    """One attachment risk finding."""

    name: str
    extension: str
    severity: str
    reason: str


HIGH_RISK_EXTENSIONS = {".lnk", ".js", ".vbs", ".ps1", ".exe"}
MEDIUM_RISK_EXTENSIONS = {".html", ".htm", ".zip", ".rar", ".7z", ".iso", ".img", ".docm", ".xlsm"}


def analyze_attachments(attachments: list[AttachmentMetadata]) -> list[AttachmentFinding]:
    """Analyze attachment metadata only."""
    findings = []
    for item in attachments:
        extension = (item.extension or Path(item.name).suffix).lower()
        name_lower = item.name.lower()
        notes_lower = item.notes.lower()
        if extension in HIGH_RISK_EXTENSIONS:
            findings.append(AttachmentFinding(item.name, extension, "High", "Attachment extension can execute script or binary content."))
        elif extension in MEDIUM_RISK_EXTENSIONS:
            findings.append(AttachmentFinding(item.name, extension, "Medium", "Attachment extension is commonly used in phishing delivery."))
        if has_double_extension(item.name):
            findings.append(AttachmentFinding(item.name, extension, "High", "Attachment uses a double extension."))
        if "password" in notes_lower or "protected" in notes_lower:
            findings.append(AttachmentFinding(item.name, extension, "Medium", "Metadata indicates a password-protected archive or document."))
        if any(term in name_lower for term in ("invoice", "payment", "payroll", "secure-message", "secure_message")):
            findings.append(AttachmentFinding(item.name, extension, "Medium", "Filename uses invoice, payment, payroll, or secure-message lure language."))
        if "qr" in name_lower or "qr" in notes_lower:
            findings.append(AttachmentFinding(item.name, extension, "Medium", "Attachment metadata references QR phishing."))
    return group_attachment_findings(findings)


def has_double_extension(name: str) -> bool:
    """Return True for suspicious double extensions such as invoice.pdf.exe."""
    parts = [part for part in Path(name).name.lower().split(".") if part]
    return len(parts) >= 3 and f".{parts[-1]}" in HIGH_RISK_EXTENSIONS


def group_attachment_findings(findings: list[AttachmentFinding]) -> list[AttachmentFinding]:
    """Group attachment findings by filename and combine reasons."""
    grouped: dict[str, AttachmentFinding] = {}
    reasons_by_name: dict[str, list[str]] = {}
    for finding in findings:
        key = finding.name.lower()
        reason = normalize_attachment_reason(finding.reason)
        if key not in grouped:
            grouped[key] = AttachmentFinding(finding.name, finding.extension, finding.severity, reason)
            reasons_by_name[key] = [reason]
            continue
        grouped[key].severity = highest_severity(grouped[key].severity, finding.severity)
        if reason not in reasons_by_name[key]:
            reasons_by_name[key].append(reason)
        grouped[key].reason = "; ".join(reasons_by_name[key])
    return list(grouped.values())


def normalize_attachment_reason(reason: str) -> str:
    """Normalize attachment reason wording for grouped rows."""
    replacements = {
        "Attachment extension is commonly used in phishing delivery.": "HTML or archive attachment commonly used in phishing delivery",
        "Attachment extension can execute script or binary content.": "Executable or script-capable attachment extension",
        "Attachment uses a double extension.": "double extension",
        "Metadata indicates a password-protected archive or document.": "password-protected archive/document indicator",
        "Filename uses invoice, payment, payroll, or secure-message lure language.": "invoice/payment/payroll/secure-message lure language",
        "Attachment metadata references QR phishing.": "QR phishing indicator",
    }
    return replacements.get(reason, reason.rstrip("."))


def highest_severity(left: str, right: str) -> str:
    """Return the higher severity label."""
    order = {"Low": 1, "Medium": 2, "High": 3}
    return left if order.get(left, 0) >= order.get(right, 0) else right
