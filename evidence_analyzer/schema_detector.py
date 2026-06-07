"""Evidence type detection for uploaded threat evidence."""

from __future__ import annotations

from evidence_parser import EvidenceDocument


EVIDENCE_TYPES = {
    "entra_signin": "Entra sign-in style logs",
    "defender_alert": "Defender alert style JSON",
    "powershell": "PowerShell event logs",
    "phishing": "Phishing/email indicators",
    "generic_security_log": "Generic security log",
    "unknown": "Unknown",
}


def detect_evidence_type(document: EvidenceDocument) -> str:
    """Detect the most likely evidence type from parsed fields and text."""
    field_names = collect_field_names(document)
    text = collect_text(document)

    if {"userprincipalname", "signinstatus", "mfaresult"} & field_names or "impossibletravel" in field_names:
        return EVIDENCE_TYPES["entra_signin"]
    if {"alerttitle", "alertseverity", "providername"} & field_names or "defender" in text and "alert" in text:
        return EVIDENCE_TYPES["defender_alert"]
    if "powershell" in text or {"scriptblocktext", "commandline", "powershelleventcount"} & field_names:
        return EVIDENCE_TYPES["powershell"]
    if {"sender", "reply_to", "subject", "url"} & field_names or "phishing" in text:
        return EVIDENCE_TYPES["phishing"]
    if any(keyword in text for keyword in ("failed login", "malware", "mfa", "deleted files", "risky")):
        return EVIDENCE_TYPES["generic_security_log"]
    return EVIDENCE_TYPES["unknown"]


def collect_field_names(document: EvidenceDocument) -> set[str]:
    """Collect normalized field names from parsed records."""
    fields = set()
    for record in document.records:
        fields.update(str(key).lower().replace("_", "").replace(" ", "") for key in record)
    return fields


def collect_text(document: EvidenceDocument) -> str:
    """Collect bounded lower-case text for schema detection."""
    pieces = []
    for record in document.records[:50]:
        pieces.extend(str(value) for value in record.values())
    pieces.extend(document.lines[:100])
    return " ".join(pieces).lower()
