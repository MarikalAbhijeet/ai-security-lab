"""Structured Evidence Intelligence Layer for uploaded evidence."""

from __future__ import annotations

from dataclasses import dataclass, field

from ioc_extractor import IOC
from risk_scoring import RiskScore
from threat_rules import ThreatFinding


@dataclass(frozen=True)
class EvidenceProfile:
    """Product-ready structured evidence profile."""

    evidence_type: str = "Unknown evidence"
    file_name: str = "uploaded evidence"
    total_records_or_lines: int = 0
    severity_recommendation: str = "Low"
    highest_priority_finding: str = "No suspicious behavior exceeded the local rule threshold."
    top_risky_users: list[RiskScore] = field(default_factory=list)
    top_risky_devices: list[RiskScore] = field(default_factory=list)
    top_risky_ips: list[RiskScore] = field(default_factory=list)
    top_suspicious_processes: list[RiskScore] = field(default_factory=list)
    top_suspicious_events: list[str] = field(default_factory=list)
    extracted_iocs: list[IOC] = field(default_factory=list)
    detected_behaviors: list[ThreatFinding] = field(default_factory=list)
    risk_scores: list[RiskScore] = field(default_factory=list)
    mitre_attack_mapping: list[str] = field(default_factory=list)
    recommended_kql_topics: list[str] = field(default_factory=list)
    recommended_soc_actions: list[str] = field(default_factory=list)
    ticket_note_summary: str = ""
    human_review_warning: str = "Human analyst review is required before operational action."


def build_evidence_profile(
    file_name: str,
    evidence_type: str,
    total_items: int,
    severity: str,
    findings: list[ThreatFinding],
    iocs: list[IOC],
    risk_scores: list[RiskScore],
) -> EvidenceProfile:
    """Build a structured evidence profile for reports, dashboard, and Copilot."""
    highest = highest_priority_finding(evidence_type, findings, risk_scores)
    return EvidenceProfile(
        evidence_type=evidence_type,
        file_name=file_name,
        total_records_or_lines=total_items,
        severity_recommendation=severity,
        highest_priority_finding=highest,
        top_risky_users=top_by_type(risk_scores, "user"),
        top_risky_devices=top_by_type(risk_scores, "device"),
        top_risky_ips=top_by_type(risk_scores, "ip"),
        top_suspicious_processes=top_by_type(risk_scores, "process"),
        top_suspicious_events=[finding.evidence for finding in findings[:8]],
        extracted_iocs=iocs,
        detected_behaviors=findings,
        risk_scores=risk_scores[:12],
        mitre_attack_mapping=sorted({finding.mitre_attack for finding in findings}),
        recommended_kql_topics=recommended_kql_topics(evidence_type, findings),
        recommended_soc_actions=recommended_soc_actions(evidence_type, findings, iocs),
        ticket_note_summary=ticket_note(file_name, evidence_type, severity, findings, risk_scores),
    )


def top_by_type(scores: list[RiskScore], entity_type: str) -> list[RiskScore]:
    """Return top scores for a specific entity type."""
    return [score for score in scores if score.entity_type == entity_type][:5]


def highest_priority_finding(evidence_type: str, findings: list[ThreatFinding], scores: list[RiskScore]) -> str:
    """Return a concise top finding."""
    if "sign-in" in evidence_type.lower() or "entra" in evidence_type.lower() or any("login" in finding.title.lower() or "mfa" in finding.title.lower() for finding in findings):
        top_user = next((score for score in scores if score.entity_type == "user"), None)
        if top_user:
            return f"Suspicious sign-in pattern for `{top_user.entity}` scored {top_user.score} due to {', '.join(top_user.reasons[:8])}."
    if scores:
        top = scores[0]
        return f"{top.entity_type.title()} `{top.entity}` scored {top.score} due to {', '.join(top.reasons[:3])}."
    if findings:
        item = findings[0]
        return f"{item.title} ({item.severity}): {item.description}"
    return "No suspicious behavior exceeded the local rule threshold."


def recommended_kql_topics(evidence_type: str, findings: list[ThreatFinding]) -> list[str]:
    """Return KQL topics relevant to the evidence."""
    text = " ".join([evidence_type] + [finding.title for finding in findings]).lower()
    topics = []
    if any(term in text for term in ("sign-in", "login", "mfa", "travel")):
        topics.extend(["failed logins", "successful login after failures", "risky sign-ins", "failed MFA", "new device and impossible travel"])
    if "powershell" in text:
        topics.extend(["encoded PowerShell", "suspicious parent process", "Invoke-WebRequest or DownloadString", "Defender alert correlation"])
    if "phishing" in text or "url" in text:
        topics.extend(["email sender", "URL indicators", "user click or credential risk"])
    if "malware" in text:
        topics.extend(["Defender malware detection", "file hash and device correlation"])
    if "file deletion" in text or "sharepoint" in text:
        topics.extend(["mass file deletion", "unusual file access"])
    return dedupe(topics) or ["generic security event review"]


def recommended_soc_actions(evidence_type: str, findings: list[ThreatFinding], iocs: list[IOC]) -> list[str]:
    """Return SOC action recommendations from the profile."""
    actions = [
        "Validate the highest-risk entity and timeline with a human analyst.",
        "Pivot on extracted users, devices, IPs, URLs/domains, processes, file paths, and hashes.",
        "Document scope, assumptions, and escalation decision in the ticket.",
    ]
    text = " ".join([evidence_type] + [finding.title for finding in findings]).lower()
    if "powershell" in text:
        actions.insert(0, "Review parent-child process lineage and safely decode encoded PowerShell in a lab.")
    if any(term in text for term in ("sign-in", "login", "mfa", "travel")):
        actions.insert(0, "Review sign-in sequence, MFA result, device state, location, and privileged actions.")
    if "malware" in text:
        actions.insert(0, "Review Defender alert timeline, malware name, hash, and remediation status.")
    if "phishing" in text:
        actions.insert(0, "Review sender, reply-to, URLs, attachments, authentication results, and user action.")
    if "file deletion" in text:
        actions.insert(0, "Review deletion count, initiating process, affected paths, and recovery options.")
    return dedupe(actions)


def ticket_note(file_name: str, evidence_type: str, severity: str, findings: list[ThreatFinding], scores: list[RiskScore]) -> str:
    """Return a Freshservice-style ticket summary."""
    top_entity = f"{scores[0].entity_type} `{scores[0].entity}` score {scores[0].score}" if scores else "no high-risk entity"
    behaviors = ", ".join(finding.title for finding in findings[:4]) or "no suspicious behavior above threshold"
    return (
        f"Reviewed fake/sample evidence `{file_name}`. Evidence type: {evidence_type}. "
        f"Severity recommendation: {severity}. Highest-risk entity: {top_entity}. "
        f"Observed behaviors: {behaviors}. Local-only summarized evidence was used; human validation required."
    )


def render_profile_for_copilot(profile: EvidenceProfile) -> str:
    """Render a bounded safe intelligence profile for Copilot."""
    sections = [
        "Structured Evidence Intelligence Profile:",
        f"Evidence type: {profile.evidence_type}",
        f"File name: {profile.file_name}",
        f"Total records or lines: {profile.total_records_or_lines}",
        f"Severity recommendation: {profile.severity_recommendation}",
        f"Highest priority finding: {profile.highest_priority_finding}",
        "Risk scores:",
    ]
    for score in profile.risk_scores[:6]:
        sections.append(
            f"- {score.entity_type}: {score.entity}; score={score.score}; "
            f"reasons={', '.join(score.reasons[:8])}; review={score.recommended_review}"
        )
    sections.append("MITRE ATT&CK mapping:")
    sections.extend(f"- {mapping}" for mapping in profile.mitre_attack_mapping[:5] or ["No mapping generated."])
    sections.append("Recommended KQL topics:")
    sections.extend(f"- {topic}" for topic in profile.recommended_kql_topics[:5])
    sections.append("Recommended SOC actions:")
    sections.extend(f"- {action}" for action in profile.recommended_soc_actions[:5])
    sections.append(f"Freshservice ticket note summary: {profile.ticket_note_summary}")
    sections.append(f"Human review warning: {profile.human_review_warning}")
    return "\n".join(sections)


def dedupe(values: list[str]) -> list[str]:
    """Deduplicate strings while preserving order."""
    result = []
    seen = set()
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result
