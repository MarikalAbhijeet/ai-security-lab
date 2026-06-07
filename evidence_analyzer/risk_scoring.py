"""Explainable risk scoring for parsed threat evidence."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from evidence_parser import EvidenceDocument
from ioc_extractor import IOC
from threat_rules import ThreatFinding, first_value, int_like, normalize_key, truthy


@dataclass(frozen=True)
class RiskScore:
    """One explainable entity risk score."""

    entity: str
    entity_type: str
    score: int
    reasons: list[str] = field(default_factory=list)
    related_iocs: list[str] = field(default_factory=list)
    recommended_review: str = "Review related telemetry and validate with a human analyst."
    display_entity: str = ""


def score_evidence(document: EvidenceDocument, findings: list[ThreatFinding], iocs: list[IOC]) -> list[RiskScore]:
    """Generate explainable risk scores for users, devices, IPs, and processes."""
    scores: dict[tuple[str, str], dict[str, Any]] = {}
    records = document.records or [{"line": line} for line in document.lines]

    aggregate_signin_user_scores(scores, records)

    for index, record in enumerate(records, start=1):
        normalized = {normalize_key(key): value for key, value in record.items()}
        text = " ".join(str(value) for value in record.values()).lower()
        entities = extract_entities(normalized, text)
        points, reasons = score_record(normalized, text)
        if not points:
            continue
        for entity_type, entity in entities:
            add_score(scores, entity_type, entity, points, reasons, f"Record {index}")

    for finding in findings:
        text = finding.evidence.lower()
        points = severity_points(finding.severity)
        for entity_type, entity in entities_from_text(text):
            add_score(scores, entity_type, entity, points, [finding.title], finding.evidence[:120])

    for item in iocs:
        if item.type in {"User", "Device / Host", "IP Address", "Process", "Parent Process"}:
            key_type = {
                "User": "user",
                "Device / Host": "device",
                "IP Address": "ip",
                "Process": "process",
                "Parent Process": "process",
            }[item.type]
            add_score(scores, key_type, item.display_value, 3, [f"{item.type} observed"], item.display_value)

    return sorted(
        [
            RiskScore(
                entity=data.get("entity", entity),
                entity_type=entity_type,
                score=final_entity_score(entity_type, data),
                reasons=dedupe(data["reasons"])[:8],
                related_iocs=dedupe(data["iocs"])[:8],
                recommended_review=recommended_review_for(entity_type),
                display_entity=data.get("display_entity", data.get("entity", entity)),
            )
            for (entity_type, entity), data in scores.items()
        ],
        key=lambda item: item.score,
        reverse=True,
    )


def final_entity_score(entity_type: str, data: dict[str, Any]) -> int:
    """Apply final explainable score caps for comparable entity ranking."""
    score = min(100, data["score"])
    reasons = {str(reason).lower() for reason in data.get("reasons", [])}
    if entity_type == "user":
        has_account_takeover_chain = bool(
            reasons
            & {
                "multiple failed logins",
                "successful login after failures",
                "failed mfa",
                "failed mfa or denied mfa",
                "impossible travel",
                "new device",
                "risky country",
                "unknown device",
            }
        )
        has_service_or_privileged_signal = any(
            "service/admin" in reason or "privileged" in reason or "role assignment" in reason
            for reason in reasons
        )
        if has_service_or_privileged_signal and not has_account_takeover_chain:
            return min(score, 85)
    return score


def extract_entities(normalized: dict[str, Any], text: str) -> list[tuple[str, str]]:
    """Extract scoreable entities from a record."""
    candidates = [
        ("user", first_value(normalized, "user", "userprincipalname", "account", "username", "sender", "recipient")),
        ("device", first_value(normalized, "device", "devicename", "host", "hostname", "computer", "deviceid")),
        ("ip", first_value(normalized, "sourceip", "source_ip", "ipaddress", "ip", "destinationip")),
        ("process", first_value(normalized, "process", "processname", "filename", "parentprocess", "parent_process")),
    ]
    results = [(kind, str(value).strip()) for kind, value in candidates if str(value).strip()]
    if not results:
        if "powershell" in text:
            results.append(("process", "powershell.exe"))
        elif "malware" in text:
            results.append(("entity", "malware alert"))
        else:
            results.append(("entity", "uploaded evidence"))
    return results


def score_record(normalized: dict[str, Any], text: str) -> tuple[int, list[str]]:
    """Score one record or log line."""
    score = 0
    reasons = []

    failed_count = int_like(first_value(normalized, "failedlogincount", "failed_login_count", "failurecount"))
    if failed_count >= 5 or "multiple failed" in text:
        score += 18
        reasons.append("multiple failed logins")
    if truthy(first_value(normalized, "successafterfailures", "successful_after_failures")) or "successful login after failures" in text:
        score += 25
        reasons.append("successful login after failures")
    if "failed mfa" in text or "mfa denied" in text or str(first_value(normalized, "mfaresult", "mfa_result")).lower() in {"failed", "denied"}:
        score += 18
        reasons.append("failed MFA or denied MFA")
    if truthy(first_value(normalized, "impossibletravelflag", "impossible_travel_flag")) or "impossible travel" in text:
        score += 22
        reasons.append("impossible travel")
    if truthy(first_value(normalized, "newdeviceflag", "new_device_flag")) or "new device" in text:
        score += 12
        reasons.append("new device")
        device_value = str(first_value(normalized, "device", "devicename", "deviceid", "device_id", "host")).upper()
        if "UNKNOWN" in device_value:
            score += 8
            reasons.append("unknown device")
    if truthy(first_value(normalized, "riskycountryflag", "risky_country_flag")) or "risky country" in text:
        score += 15
        reasons.append("risky country")
    privileged_value = " ".join(
        str(first_value(normalized, "adminaction", "admin_action", "privilegedaction", "privileged_action", "roleassignmentattempt", "role_assignment_attempt")).lower().split()
    )
    user_value = str(first_value(normalized, "user", "userprincipalname", "account", "username")).lower()
    if (
        any(term in text for term in ("admin role", "role assignment", "privileged action", "admin consent", "service account"))
        or truthy(privileged_value)
        or "service.admin" in user_value
    ):
        score += 22
        reasons.append("privileged or admin activity")
    if "service.admin" in user_value or "service account" in text or "admin account" in text:
        score += 10
        reasons.append("suspicious service/admin account use")

    if "winword.exe" in text and "powershell.exe" in text:
        score += 25
        reasons.append("Office parent process spawning PowerShell")
    if "encodedcommand" in text or " -enc" in text:
        score += 22
        reasons.append("encoded PowerShell command")
    if "executionpolicy bypass" in text:
        score += 16
        reasons.append("ExecutionPolicy Bypass")
    if "invoke-webrequest" in text or "downloadstring" in text:
        score += 20
        reasons.append("PowerShell download behavior")
    if "frombase64string" in text or "hidden" in text:
        score += 14
        reasons.append("PowerShell obfuscation or hidden window")
    if "malware" in text or "defender detection" in text or "detected threat" in text:
        score += 28
        reasons.append("Defender malware detection")

    if any(term in text for term in ("spf_result fail", "spf=fail", "dkim_result fail", "dmarc_result fail", "reply_to mismatch")):
        score += 15
        reasons.append("email authentication or reply-to mismatch")
    if any(term in text for term in ("password reset", "verify your account", "credential", "urgent", "invoice", "qr")):
        score += 12
        reasons.append("phishing lure language")

    delete_count = int_like(first_value(normalized, "filedeletecount", "file_delete_count", "deletedfiles"))
    if delete_count >= 100 or "mass file deletion" in text or "sharepoint" in text or "onedrive" in text:
        score += 25
        reasons.append("mass deletion or cloud file activity")
    if any(term in text for term in ("sensitive", "finance", "hr", "payroll")):
        score += 10
        reasons.append("sensitive file path or business data label")

    return score, reasons


def entities_from_text(text: str) -> list[tuple[str, str]]:
    """Extract simple entities from finding evidence text."""
    results = []
    for marker, entity_type in (("user=", "user"), ("device=", "device"), ("devicename=", "device"), ("source_ip=", "ip"), ("ipaddress=", "ip")):
        if marker in text:
            value = text.split(marker, 1)[1].split(";", 1)[0].strip()
            if value:
                results.append((entity_type, value))
    return results or [("entity", "uploaded evidence")]


def aggregate_signin_user_scores(scores: dict, records: list[dict[str, Any]]) -> None:
    """Aggregate sign-in/IAM indicators by user so risky chains rank correctly."""
    grouped: dict[str, dict[str, Any]] = {}
    for index, record in enumerate(records, start=1):
        normalized = {normalize_key(key): value for key, value in record.items()}
        user = str(first_value(normalized, "user", "userprincipalname", "account", "username")).strip()
        if not user:
            continue
        key = canonical_entity("user", user)
        state = grouped.setdefault(
            key,
            {
                "user": user,
                "failed_login_count": 0,
                "success_after_failures": False,
                "failed_mfa": False,
                "new_device": False,
                "impossible_travel": False,
                "risky_country": False,
                "unknown_device": False,
                "high_risk": False,
                "medium_risk": False,
                "privileged_action": False,
                "service_admin": False,
                "risky_ips": set(),
                "rows": [],
            },
        )
        text = " ".join(str(value) for value in record.values()).lower()
        failed_count = int_like(first_value(normalized, "failedlogincount", "failed_login_count", "failurecount"))
        state["failed_login_count"] += failed_count
        state["success_after_failures"] = state["success_after_failures"] or truthy(first_value(normalized, "successafterfailures", "successful_after_failures")) or "successful login after failures" in text
        state["failed_mfa"] = state["failed_mfa"] or "failed mfa" in text or "mfa denied" in text or str(first_value(normalized, "mfaresult", "mfa_result")).lower() in {"failed", "denied", "rejected"}
        state["new_device"] = state["new_device"] or truthy(first_value(normalized, "newdeviceflag", "new_device_flag")) or "new device" in text
        state["impossible_travel"] = state["impossible_travel"] or truthy(first_value(normalized, "impossibletravelflag", "impossible_travel_flag")) or "impossible travel" in text
        state["risky_country"] = state["risky_country"] or truthy(first_value(normalized, "riskycountryflag", "risky_country_flag")) or "risky country" in text
        device_value = str(first_value(normalized, "device", "devicename", "deviceid", "device_id", "host", "hostname")).lower()
        state["unknown_device"] = state["unknown_device"] or "unknown" in device_value or "unfamiliar device" in text
        risk_level = str(first_value(normalized, "risklevel", "risk_level", "risklevelaggregated", "risk_level_aggregated")).lower()
        state["high_risk"] = state["high_risk"] or risk_level == "high"
        state["medium_risk"] = state["medium_risk"] or risk_level == "medium"
        privileged_value = str(first_value(normalized, "adminaction", "admin_action", "privilegedaction", "privileged_action", "roleassignmentattempt", "role_assignment_attempt")).lower()
        state["privileged_action"] = state["privileged_action"] or truthy(privileged_value) or any(term in text for term in ("admin role", "role assignment", "privileged action", "admin consent"))
        state["service_admin"] = state["service_admin"] or "service.admin" in key or "service account" in text or "admin account" in text
        source_ip = str(first_value(normalized, "sourceip", "source_ip", "ipaddress", "ip")).strip()
        if source_ip:
            state["risky_ips"].add(source_ip)
        state["rows"].append(f"Record {index}")

    for state in grouped.values():
        score, reasons = score_signin_user_state(state)
        if score:
            add_score(scores, "user", state["user"], score, reasons, "; ".join(state["rows"][:5]))


def score_signin_user_state(state: dict[str, Any]) -> tuple[int, list[str]]:
    """Score an aggregated user sign-in state."""
    score = 0
    reasons = []
    if state["failed_login_count"] >= 5:
        score += 25
        reasons.append("multiple failed logins")
    if state["success_after_failures"]:
        score += 30
        reasons.append("successful login after failures")
    if state["failed_mfa"]:
        score += 25
        reasons.append("failed MFA")
    if state["impossible_travel"]:
        score += 35
        reasons.append("impossible travel")
    if state["new_device"]:
        score += 20
        reasons.append("new device")
    if state["risky_country"]:
        score += 20
        reasons.append("risky country")
    if state["unknown_device"]:
        score += 15
        reasons.append("unknown device")
    if state["high_risk"]:
        score += 25
        reasons.append("high risk level")
    elif state["medium_risk"]:
        score += 10
        reasons.append("medium risk level")
    if state["privileged_action"]:
        score += 30
        reasons.append("privileged action")
    if state["service_admin"]:
        score += 20
        reasons.append("service/admin account use")
    if state["risky_ips"]:
        reasons.append("risky source IP: " + ", ".join(sorted(state["risky_ips"])[:3]))
    return score, reasons


def add_score(scores: dict, entity_type: str, entity: str, points: int, reasons: list[str], ioc: str) -> None:
    """Add points and context to an entity score."""
    canonical = canonical_entity(entity_type, entity)
    key = (entity_type, canonical)
    scores.setdefault(
        key,
        {
            "entity": canonical,
            "display_entity": display_entity(entity_type, canonical),
            "score": 0,
            "reasons": [],
            "iocs": [],
        },
    )
    scores[key]["score"] += points
    scores[key]["reasons"].extend(reasons)
    scores[key]["iocs"].append(ioc)


def canonical_entity(entity_type: str, value: str) -> str:
    """Normalize entity keys so raw/defanged/case variants merge."""
    entity = str(value or "").strip()
    entity = entity.replace("[.]", ".").replace("(.)", ".")
    entity = entity.replace("hxxps://", "https://").replace("hxxp://", "http://")
    entity = entity.strip("`'\".,; ")
    if entity_type in {"user", "device", "ip", "process", "entity"}:
        entity = entity.lower()
    return entity or "unknown"


def display_entity(entity_type: str, canonical: str) -> str:
    """Return safe display value for an entity."""
    if entity_type in {"user", "ip"}:
        return canonical.replace(".", "[.]")
    return canonical


def severity_points(severity: str) -> int:
    """Convert severity to points."""
    return {"High": 20, "Medium": 12, "Low": 5}.get(severity, 5)


def recommended_review_for(entity_type: str) -> str:
    """Return entity-specific review guidance."""
    return {
        "user": "Review sign-ins, MFA results, device context, and privileged activity for this user.",
        "device": "Review endpoint timeline, process tree, Defender alerts, and network connections for this device.",
        "ip": "Review sign-in, proxy, DNS, and network telemetry for this IP.",
        "process": "Review parent-child process lineage, command line, script blocks, and related file/network events.",
    }.get(entity_type, "Review related evidence, scope, and business context.")


def dedupe(values: list[str]) -> list[str]:
    """Deduplicate values while preserving order."""
    result = []
    seen = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result
