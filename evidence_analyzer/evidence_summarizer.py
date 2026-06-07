"""Markdown reporting for uploaded threat evidence analysis."""

from __future__ import annotations

from dataclasses import dataclass, field

from evidence_intelligence import EvidenceProfile, build_evidence_profile, render_profile_for_copilot
from evidence_parser import EvidenceDocument, parse_evidence_file
from ioc_extractor import IOC, extract_iocs, ioc_counts
from risk_scoring import RiskScore, score_evidence
from schema_detector import detect_evidence_type
from threat_rules import ThreatFinding, analyze_document


@dataclass(frozen=True)
class EvidenceAnalysis:
    """Structured evidence analysis result."""

    file_name: str = "uploaded evidence"
    evidence_type: str = "Unknown evidence"
    total_items: int = 0
    findings: list[ThreatFinding] = field(default_factory=list)
    iocs: list[IOC] = field(default_factory=list)
    ioc_summary_counts: dict[str, int] = field(default_factory=dict)
    risk_scores: list[RiskScore] = field(default_factory=list)
    evidence_profile: EvidenceProfile = field(default_factory=EvidenceProfile)
    severity: str = "Low"
    markdown_report: str = ""
    copilot_context: str = ""
    extracted_iocs: list[IOC] = field(default_factory=list)
    detected_behaviors: list[ThreatFinding] = field(default_factory=list)
    highest_priority_finding: str = "No suspicious behavior exceeded the local rule threshold."
    severity_recommendation: str = "Low"
    top_risky_users: list[RiskScore] = field(default_factory=list)
    top_risky_devices: list[RiskScore] = field(default_factory=list)
    top_risky_ips: list[RiskScore] = field(default_factory=list)
    top_suspicious_processes: list[RiskScore] = field(default_factory=list)
    mitre_attack_mapping: list[str] = field(default_factory=list)
    recommended_soc_actions: list[str] = field(default_factory=list)
    ticket_note_summary: str = ""


def analyze_evidence(file_name: str, content: bytes) -> EvidenceAnalysis:
    """Parse, analyze, extract IOCs, and summarize evidence bytes."""
    document = parse_evidence_file(file_name, content)
    evidence_type = detect_evidence_type(document)
    findings = analyze_document(document)
    iocs = extract_iocs(document)
    counts = ioc_counts(iocs)
    severity = recommend_severity(findings)
    total_items = len(document.records) if document.records else len(document.lines)
    risk_scores = score_evidence(document, findings, iocs)
    profile = build_evidence_profile(document.file_name, evidence_type, total_items, severity, findings, iocs, risk_scores)
    markdown = render_markdown_report(document, evidence_type, total_items, findings, iocs, counts, severity, profile)
    context = render_copilot_context(document, evidence_type, total_items, findings, iocs, counts, severity, profile)
    return EvidenceAnalysis(
        file_name=document.file_name,
        evidence_type=evidence_type,
        total_items=total_items,
        findings=findings,
        iocs=iocs,
        ioc_summary_counts=counts,
        risk_scores=risk_scores,
        evidence_profile=profile,
        severity=severity,
        markdown_report=markdown,
        copilot_context=context,
        extracted_iocs=iocs,
        detected_behaviors=findings,
        highest_priority_finding=profile.highest_priority_finding,
        severity_recommendation=profile.severity_recommendation,
        top_risky_users=profile.top_risky_users,
        top_risky_devices=profile.top_risky_devices,
        top_risky_ips=profile.top_risky_ips,
        top_suspicious_processes=profile.top_suspicious_processes,
        mitre_attack_mapping=profile.mitre_attack_mapping,
        recommended_soc_actions=profile.recommended_soc_actions,
        ticket_note_summary=profile.ticket_note_summary,
    )


def render_markdown_report(
    document: EvidenceDocument,
    evidence_type: str,
    total_items: int,
    findings: list[ThreatFinding],
    iocs: list[IOC],
    counts: dict[str, int],
    severity: str,
    profile: EvidenceProfile,
) -> str:
    """Render a structured Markdown evidence report."""
    return "\n\n".join(
        [
            "# Threat Evidence Workbench Report",
            "## File Summary",
            f"- File name: `{document.file_name}`\n- Detected evidence type: {evidence_type}\n- Total records/lines: {total_items}",
            "## Severity Recommendation",
            severity,
            "## Highest-Priority IOCs",
            render_priority_iocs(iocs),
            "## Evidence Intelligence Profile",
            render_profile_summary(profile),
            "## Risk Score Breakdown",
            render_risk_scores(profile.risk_scores),
            "## IOC Summary Counts",
            render_ioc_counts(counts),
            "## Indicators and Investigation Artifacts",
            render_ioc_sections(iocs),
            "## Suspicious Behaviors",
            render_findings(findings),
            "## Top Risky Rows Or Events",
            render_risky_events(findings),
            "## MITRE ATT&CK Mapping",
            render_mitre(findings),
            "## Suggested KQL Queries",
            render_kql(findings, evidence_type, document),
            "## Containment Recommendations",
            render_containment(findings),
            "## Recommended Validation Steps",
            render_ioc_validation_steps(iocs),
            "## Freshservice-Style Ticket Note",
            render_ticket_note(document.file_name, evidence_type, severity, findings),
            "## Human Review Warning",
            "This is a local lab analysis using rule-based indicators and optional local Copilot review. A human analyst must validate findings before operational action.",
            "## Safety Disclaimer",
            "Uploaded evidence is processed locally for the current dashboard session only. Do not upload secrets, passwords, tokens, API keys, company logs, client data, tenant data, or vendor confidential data.",
        ]
    )


def render_copilot_context(
    document: EvidenceDocument,
    evidence_type: str,
    total_items: int,
    findings: list[ThreatFinding],
    iocs: list[IOC],
    counts: dict[str, int],
    severity: str,
    profile: EvidenceProfile,
) -> str:
    """Render bounded safe context for Local SecOps Copilot."""
    lines = [
        "Uploaded evidence summary from current session.",
        f"File name: {document.file_name}",
        f"Detected evidence type: {evidence_type}",
        f"Total records or lines: {total_items}",
        f"Severity recommendation: {severity}",
        "IOC summary counts:",
        f"- Total IPs found: {counts['total_ips']}",
        f"- Total URLs/domains found: {counts['total_urls_domains']}",
        f"- Total users found: {counts['total_users']}",
        f"- Total devices found: {counts['total_devices']}",
        f"- Total suspicious command indicators found: {counts['total_suspicious_command_indicators']}",
        render_profile_for_copilot(profile),
        "IOCs / Investigation Artifacts Observed:",
    ]
    if iocs:
        for item in select_copilot_iocs(iocs):
            lines.append(f"- {item.type}: {item.display_value}; Source: {compact_source(item.source)}")
    else:
        lines.append("- No IOCs were extracted by the local rule set.")

    lines.append("Suspicious behaviors:")
    if findings:
        for item in findings[:6]:
            lines.append(
                f"- {item.title} ({item.severity}): {item.description}; "
                f"MITRE: {item.mitre_attack}; Recommended review: {item.recommendation}"
            )
    else:
        lines.append("- No suspicious indicators were detected by the local rule set.")

    lines.extend(
        [
            "The Copilot answer must include a section titled: IOCs / Investigation Artifacts Observed.",
            "Use this summary only. Do not assume access to the raw uploaded file.",
            "Uploaded file content is not permanently saved or indexed.",
        ]
    )
    return bound_context("\n".join(lines))


def compact_source(source: str) -> str:
    """Keep Copilot session context bounded while preserving source location."""
    return source.split(" (", 1)[0]


def select_copilot_iocs(iocs: list[IOC]) -> list[IOC]:
    """Select concise high-value IOCs for Copilot context."""
    priority_order = [
        "User",
        "Device / Host",
        "IP Address",
        "URL",
        "Domain",
        "Parent Process",
        "Process",
        "Command-Line Indicator",
        "File Path",
        "SHA256",
        "SHA1",
        "MD5",
        "Malware / Threat Name",
        "Authentication Indicator",
        "Privileged Activity Indicator",
    ]
    selected = []
    for ioc_type in priority_order:
        selected.extend(item for item in iocs if item.type == ioc_type)
    return selected[:15]


def bound_context(context: str, max_chars: int = 4800) -> str:
    """Keep Copilot context safely below validation limits."""
    if len(context) <= max_chars:
        return context
    trimmed = context[:max_chars].rsplit("\n", 1)[0]
    return trimmed + "\nContext truncated to safe summarized fields only."


def recommend_severity(findings: list[ThreatFinding]) -> str:
    """Recommend overall severity from findings."""
    severities = {finding.severity for finding in findings}
    if "High" in severities:
        return "High"
    if "Medium" in severities:
        return "Medium"
    return "Low"


def render_priority_iocs(iocs: list[IOC]) -> str:
    """Render high-value IOCs at the top of the report."""
    priority_types = {
        "URL",
        "Domain",
        "IP Address",
        "User",
        "Device / Host",
        "Process",
        "Parent Process",
        "Command-Line Indicator",
        "SHA256",
        "SHA1",
        "MD5",
        "Malware / Threat Name",
    }
    priority = [item for item in iocs if item.type in priority_types][:12]
    if not priority:
        return "- No high-priority IOCs extracted."
    return "\n".join(f"- **{item.type}:** `{item.display_value}` ({item.source})" for item in priority)


def render_ioc_counts(counts: dict[str, int]) -> str:
    """Render IOC summary counts."""
    return "\n".join(
        [
            f"- Total IPs found: {counts['total_ips']}",
            f"- Total URLs/domains found: {counts['total_urls_domains']}",
            f"- Total users found: {counts['total_users']}",
            f"- Total devices found: {counts['total_devices']}",
            f"- Total suspicious command indicators found: {counts['total_suspicious_command_indicators']}",
        ]
    )


def render_profile_summary(profile: EvidenceProfile) -> str:
    """Render profile summary for the Markdown report."""
    return "\n".join(
        [
            f"- Evidence type: {profile.evidence_type}",
            f"- Severity recommendation: {profile.severity_recommendation}",
            f"- Highest priority finding: {profile.highest_priority_finding}",
            f"- Recommended KQL topics: {', '.join(profile.recommended_kql_topics)}",
            f"- Ticket note summary: {profile.ticket_note_summary}",
        ]
    )


def render_risk_scores(scores: list[RiskScore]) -> str:
    """Render explainable risk scores."""
    if not scores:
        return "- No entity risk scores were generated."
    lines = []
    for score in scores[:10]:
        lines.append(
            f"- **{score.entity_type}: `{score.entity}`** - score `{score.score}`; "
            f"reasons: {', '.join(score.reasons[:8])}; review: {score.recommended_review}"
        )
    return "\n".join(lines)


def render_ioc_sections(iocs: list[IOC]) -> str:
    """Render grouped IOC report sections."""
    sections = {
        "IP Addresses": ["IP Address"],
        "URLs and Domains": ["URL", "Domain"],
        "Users": ["User"],
        "Devices / Hosts": ["Device / Host"],
        "Processes and Parent Processes": ["Process", "Parent Process"],
        "Command-Line Indicators": ["Command-Line Indicator"],
        "File Paths": ["File Path"],
        "Hashes": ["MD5", "SHA1", "SHA256"],
        "Malware / Threat Names": ["Malware / Threat Name"],
        "Authentication Indicators": ["Authentication Indicator"],
        "Privileged Activity Indicators": ["Privileged Activity Indicator"],
    }
    rendered = []
    for heading, types in sections.items():
        rendered.append(f"### {heading}")
        matches = [item for item in iocs if item.type in types]
        if matches:
            rendered.extend(f"- `{item.display_value}` ({item.source}) - {item.why_it_matters}" for item in matches[:15])
        else:
            rendered.append("- None found.")
    return "\n".join(rendered)


def render_findings(findings: list[ThreatFinding]) -> str:
    """Render suspicious behaviors separately from IOCs."""
    if not findings:
        return "- No suspicious behaviors detected by the local rule set."
    return "\n".join(f"- **{item.title}** ({item.severity}): {item.description}" for item in findings[:10])


def render_risky_events(findings: list[ThreatFinding]) -> str:
    """Render top risky events."""
    if not findings:
        return "- No risky rows or events identified."
    return "\n".join(f"- {item.evidence}" for item in findings[:10])


def render_mitre(findings: list[ThreatFinding]) -> str:
    """Render MITRE mappings."""
    if not findings:
        return "- No MITRE ATT&CK mapping generated because no suspicious indicators were detected."
    mappings = sorted({item.mitre_attack for item in findings})
    return "\n".join(f"- {mapping}" for mapping in mappings)


def render_ioc_validation_steps(iocs: list[IOC]) -> str:
    """Render validation guidance for extracted IOCs."""
    if not iocs:
        return "- No IOCs were extracted. Validate the evidence source and review suspicious behavior findings."
    return "\n".join(
        [
            "- Search IPs, URLs, and domains in proxy, DNS, email, and endpoint telemetry.",
            "- Pivot on users and devices to confirm scope, sign-in history, and endpoint timeline.",
            "- Review process and parent-process chains for suspicious execution flow.",
            "- Decode or safely inspect suspicious PowerShell flags and command-line indicators in a lab.",
            "- Check hashes and malware/threat names in Defender or an approved malware intelligence source.",
        ]
    )


def render_kql(findings: list[ThreatFinding], evidence_type: str, document: EvidenceDocument) -> str:
    """Render suggested KQL based on evidence type and findings."""
    queries = []
    fields = available_fields(document)
    user_field = choose_field(fields, ["UserPrincipalName", "user", "account", "username"])
    ip_field = choose_field(fields, ["IPAddress", "source_ip", "sourceIp", "ip"])
    mfa_field = choose_field(fields, ["mfa_result", "mfaResult", "MFAResult", "ConditionalAccessStatus"])
    if "sign-in" in evidence_type.lower() or any("login" in item.title.lower() or "mfa" in item.title.lower() for item in findings):
        queries.append(
            "SigninLogs\n"
            f"| where ResultType != 0 or {mfa_field} !~ 'success'\n"
            f"| summarize FailedOrMfaEvents=count() by {user_field}, {ip_field}"
        )
    if any("PowerShell" in item.title for item in findings):
        queries.append("DeviceProcessEvents | where FileName =~ 'powershell.exe' | where ProcessCommandLine has_any ('-enc','DownloadString','IEX','Bypass','Invoke-WebRequest')")
    if any("Malware" in item.title for item in findings):
        queries.append("DeviceEvents | where ActionType has_any ('AntivirusDetection','Malware') | project Timestamp, DeviceName, FileName, SHA256")
    if any("file deletion" in item.title.lower() for item in findings):
        queries.append("DeviceFileEvents | where ActionType has 'Deleted' | summarize DeletedFiles=count() by DeviceName, InitiatingProcessAccountName")
    if any("URL" in item.title for item in findings):
        queries.append("EmailUrlInfo | where Url has_any ('login','verify') | join kind=leftouter EmailEvents on NetworkMessageId")
    if not queries:
        queries.append("SecurityEvent | take 50")
    return "\n\n".join(f"```kql\n{query}\n```" for query in queries)


def available_fields(document: EvidenceDocument) -> set[str]:
    """Return original field names seen in parsed evidence."""
    fields = set()
    for record in document.records:
        fields.update(str(key) for key in record)
    return fields


def choose_field(fields: set[str], preferred: list[str]) -> str:
    """Choose an uploaded schema field when available, otherwise use a Sentinel-style default."""
    normalized = {field.lower().replace("_", ""): field for field in fields}
    for field in preferred:
        match = normalized.get(field.lower().replace("_", ""))
        if match:
            return match
    return preferred[0]


def render_containment(findings: list[ThreatFinding]) -> str:
    """Render containment recommendations."""
    if not findings:
        return "- Continue monitoring and validate the evidence source with a human analyst."
    recommendations = []
    for item in findings[:8]:
        recommendations.append(f"- {item.recommendation}")
    recommendations.append("- Preserve evidence and document analyst decisions in the ticket.")
    return "\n".join(dict.fromkeys(recommendations))


def render_ticket_note(file_name: str, evidence_type: str, severity: str, findings: list[ThreatFinding]) -> str:
    """Render a Freshservice-style note."""
    indicator_text = ", ".join(item.title for item in findings[:5]) or "No suspicious indicators detected"
    return (
        f"Reviewed uploaded fake/sample evidence `{file_name}` in Threat Evidence Workbench. "
        f"Detected type: {evidence_type}. Recommended severity: {severity}. "
        f"Key indicators: {indicator_text}. Local-only analysis; human validation required before action."
    )
