"""Email threat analyzer orchestration and Markdown reporting."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from email.utils import parseaddr

from attachment_analyzer import AttachmentFinding, analyze_attachments
from email_parser import ParsedEmail, parse_email_file, parse_pasted_text
from header_analyzer import HeaderFinding, analyze_headers
from online_enrichment import EnrichmentResult, enrich_indicators
from phishing_rules import BodyFinding, analyze_body
from phishing_score import ScoreResult, calculate_score
from url_analyzer import URLFinding, defang, strip_url_query, analyze_urls


@dataclass
class EmailIOC:
    """Safe email indicator display row."""

    type: str
    value: str
    source: str
    why_it_matters: str


@dataclass
class EmailAnalysis:
    """Complete email threat analysis result."""

    parsed_email: ParsedEmail
    header_findings: list[HeaderFinding] = field(default_factory=list)
    url_findings: list[URLFinding] = field(default_factory=list)
    attachment_findings: list[AttachmentFinding] = field(default_factory=list)
    body_findings: list[BodyFinding] = field(default_factory=list)
    score: ScoreResult = field(default_factory=ScoreResult)
    iocs: list[EmailIOC] = field(default_factory=list)
    online_enrichment: EnrichmentResult = field(default_factory=EnrichmentResult)
    markdown_report: str = ""
    copilot_context: str = ""
    user_action: str = ""
    user_do_not: str = ""
    agent_action: str = ""


def analyze_email_file(file_name: str, file_bytes: bytes, online_enrichment_enabled: bool = False) -> EmailAnalysis:
    """Analyze uploaded email evidence bytes without saving them."""
    return analyze_parsed_email(parse_email_file(file_name, file_bytes), online_enrichment_enabled=online_enrichment_enabled)


def analyze_pasted_email(text: str, source_type: str = "pasted_text", online_enrichment_enabled: bool = False) -> EmailAnalysis:
    """Analyze pasted email evidence."""
    return analyze_parsed_email(parse_pasted_text(text, source_type=source_type), online_enrichment_enabled=online_enrichment_enabled)


def analyze_parsed_email(parsed: ParsedEmail, online_enrichment_enabled: bool = False) -> EmailAnalysis:
    """Run all local email analysis steps."""
    header_findings = analyze_headers(parsed)
    url_findings = analyze_urls(parsed.urls, parsed.domains)
    attachment_findings = analyze_attachments(parsed.attachments)
    body_findings = analyze_body(parsed)
    score = calculate_score(header_findings, url_findings, attachment_findings, body_findings)
    iocs = build_iocs(parsed)
    enrichment_env = dict(os.environ)
    enrichment_env["EMAIL_ONLINE_ENRICHMENT"] = "true" if online_enrichment_enabled else "false"
    enrichment = enrich_indicators(enrichment_indicators(iocs), env=enrichment_env)
    analysis = EmailAnalysis(
        parsed_email=parsed,
        header_findings=header_findings,
        url_findings=url_findings,
        attachment_findings=attachment_findings,
        body_findings=body_findings,
        score=score,
        iocs=iocs,
        online_enrichment=enrichment,
        user_action=user_action(score.verdict),
        user_do_not=user_do_not(score.verdict),
        agent_action=agent_action(score.verdict),
    )
    analysis.markdown_report = render_markdown_report(analysis)
    analysis.copilot_context = render_copilot_context(analysis)
    return analysis


def build_iocs(parsed: ParsedEmail) -> list[EmailIOC]:
    """Build defanged email IOCs."""
    rows = []
    for label, value in (
        ("Sender", parsed.from_address),
        ("Reply-To", parsed.reply_to),
        ("Return-Path", parsed.return_path),
        ("Subject", parsed.subject),
        ("Message-ID", parsed.message_id),
    ):
        if value:
            rows.append(EmailIOC(label, defang(value), "Email headers", "Header artifact for investigation."))
    for url in parsed.urls:
        rows.append(EmailIOC("URL", defang(strip_url_query(url)), "Email body or HTML", "URL should be investigated without opening it. Query values were removed for safety."))
    for domain in parsed.domains:
        rows.append(EmailIOC("Domain", defang(domain), "Extracted indicator", "Domain pivot for email, DNS, and proxy review."))
    for ip in parsed.ips:
        rows.append(EmailIOC("IP Address", defang(ip), "Extracted indicator", "IP pivot for mail header and network review."))
    for attachment in parsed.attachments:
        rows.append(EmailIOC("Attachment", defang(attachment.name), "Attachment metadata", "Attachment metadata only; file was not opened or executed."))
    return rows


def enrichment_indicators(iocs: list[EmailIOC]) -> list[dict]:
    """Return only extracted indicators safe for optional online enrichment."""
    allowed_types = {"URL", "Domain", "IP Address", "MD5", "SHA1", "SHA256", "Hash"}
    indicators = []
    for ioc in iocs:
        if ioc.type in allowed_types:
            indicator_type = "Hash" if ioc.type in {"MD5", "SHA1", "SHA256"} else ioc.type
            indicators.append({"type": indicator_type, "value": ioc.value})
    return indicators


def render_markdown_report(analysis: EmailAnalysis) -> str:
    """Render product-grade Markdown email report."""
    return "\n\n".join(
        [
            "# AI Email Threat Analyzer Report",
            "## Email Verdict",
            f"- **Verdict:** {analysis.score.verdict}",
            f"- **Risk Score:** {analysis.score.overall_score}/100",
            f"- **Plain-English reason:** {plain_reason(analysis)}",
            f"- **Recommended user action:** {analysis.user_action}",
            f"- **Do not do this:** {analysis.user_do_not}",
            "## Agent / SOC Details",
            render_finding_section("Header analysis", analysis.header_findings),
            render_url_section(analysis.url_findings),
            render_attachment_section(analysis.attachment_findings),
            render_finding_section("Social engineering indicators", analysis.body_findings),
            "## Evidence / IOCs",
            render_ioc_table(analysis.iocs),
            "## MITRE ATT&CK Mapping",
            "- Initial Access: Phishing (T1566)\n- Credential Access: Credentials from Web Browsers or Input Capture when credential harvesting indicators are present",
            "## Recommended SOC Actions",
            "\n".join(f"- {item}" for item in recommended_soc_actions(analysis)),
            "## KQL Follow-Up Query",
            f"```kql\n{build_kql(analysis)}\n```",
            "## Freshservice-Style Ticket Note",
            build_ticket_note(analysis),
            "## Online Enrichment",
            render_online_enrichment_summary(analysis),
            "## Safety Note",
            "Uploaded or pasted email content is processed locally in memory. Raw email content is not sent to the local LLM; only this summarized context is used.",
        ]
    )


def render_copilot_context(analysis: EmailAnalysis) -> str:
    """Render bounded safe email summary for Local SecOps Copilot."""
    lines = [
        "Uploaded email analysis summary from current session.",
        "Evidence type: Email threat analysis",
        "Detected evidence type: Email threat analysis",
        f"File name: {analysis.parsed_email.file_name}",
        f"Verdict: {analysis.score.verdict}",
        f"Risk score: {analysis.score.overall_score}",
        "Category scores:",
    ]
    lines.extend(f"- {key}: {value}" for key, value in analysis.score.category_scores.items())
    lines.append("Main reasons:")
    lines.extend(f"- {reason}" for reason in analysis.score.reasons[:8])
    lines.append("IOCs / Investigation Artifacts Observed:")
    lines.extend(f"- {ioc.type}: {ioc.value}; Source: {ioc.source}; Why: {ioc.why_it_matters}" for ioc in analysis.iocs[:20])
    lines.append("Recommended user guidance:")
    lines.append(f"- Do: {analysis.user_action}")
    lines.append(f"- Do not: {analysis.user_do_not}")
    lines.append("Recommended SOC actions:")
    lines.extend(f"- {action}" for action in recommended_soc_actions(analysis)[:6])
    lines.append("Online enrichment summary:")
    lines.extend(online_enrichment_context_lines(analysis.online_enrichment))
    lines.append("Recommended KQL topics:")
    lines.append("- phishing investigation")
    lines.append("- sender, URL, attachment, and recipient pivots")
    lines.append("Freshservice ticket note summary:")
    lines.append(build_ticket_note(analysis))
    lines.append("Raw email content was not included in this summary.")
    return "\n".join(lines)


def online_enrichment_context_lines(enrichment: EnrichmentResult) -> list[str]:
    """Return safe provider summary lines for Copilot context."""
    lines = [
        f"- Status: {enrichment.status}",
        f"- URLs checked: {enrichment.urls_checked}",
        f"- Threats found: {enrichment.total_threats_found}",
        f"- Providers checked: {enrichment.providers_checked}",
    ]
    for result in enrichment.provider_results:
        if result.provider not in {"Google Safe Browsing", "URLhaus"}:
            continue
        lines.append(
            f"- {result.provider}: "
            f"status={result.status}; verdict={result.threat_result}; "
            f"score={result.score}; indicator={result.indicator}; note={result.note}"
        )
        if result.details:
            lines.append(f"- {result.provider} details: {result.details}")
        if result.error:
            lines.append(f"- {result.provider} error: {result.error}")
    lines.append("- Raw email body, raw headers, attachments, and files were not sent to online providers.")
    return lines


def plain_reason(analysis: EmailAnalysis) -> str:
    """Return a plain-English summary reason."""
    if analysis.score.reasons:
        return "; ".join(analysis.score.reasons[:3])
    return "No strong phishing indicators were found in the local rule-based checks."


def user_action(verdict: str) -> str:
    """Return user-friendly action."""
    if verdict in {"Likely Phishing", "Suspicious / Needs Review", "Needs Review"}:
        return "Report the email to IT/SOC and wait for guidance."
    if verdict == "Likely Spam":
        return "Mark as spam or delete if it is unwanted marketing."
    return "No action needed beyond normal caution."


def user_do_not(verdict: str) -> str:
    """Return user-friendly do-not guidance."""
    if verdict in {"Likely Phishing", "Suspicious / Needs Review", "Needs Review"}:
        return "Do not click links, scan QR codes, open attachments, reply, or enter credentials."
    return "Do not share sensitive information unless the request is expected and verified."


def agent_action(verdict: str) -> str:
    """Return helpdesk/SOC action."""
    if verdict in {"Likely Phishing", "Suspicious / Needs Review", "Needs Review"}:
        return "Review sender authentication, URLs/domains, attachments, user exposure, and mailbox delivery scope."
    return "Document the report and close if no additional suspicious context exists."


def render_finding_section(title: str, findings) -> str:
    """Render generic findings."""
    if not findings:
        return f"### {title}\n- No notable findings."
    lines = [f"### {title}"]
    for finding in findings:
        lines.append(f"- **{finding.title} ({finding.severity}):** {finding.description}")
    return "\n".join(lines)


def render_url_section(findings: list[URLFinding]) -> str:
    """Render URL/domain findings."""
    if not findings:
        return "### URL/domain analysis\n- No suspicious URL/domain findings."
    lines = ["### URL/domain analysis", "| Indicator | Severity | Reason |", "| --- | --- | --- |"]
    lines.extend(f"| `{finding.display_value}` | {finding.severity} | {finding.reason} |" for finding in findings)
    return "\n".join(lines)


def render_attachment_section(findings: list[AttachmentFinding]) -> str:
    """Render attachment findings."""
    if not findings:
        return "### Attachment analysis\n- No risky attachment metadata found."
    lines = ["### Attachment analysis", "| Attachment | Extension | Severity | Reason |", "| --- | --- | --- | --- |"]
    lines.extend(f"| `{defang(finding.name)}` | `{finding.extension}` | {finding.severity} | {finding.reason} |" for finding in findings)
    return "\n".join(lines)


def render_ioc_table(iocs: list[EmailIOC]) -> str:
    """Render IOC table."""
    if not iocs:
        return "- No email IOCs extracted."
    lines = ["| Type | Value | Source | Why it matters |", "| --- | --- | --- | --- |"]
    lines.extend(f"| {ioc.type} | `{ioc.value}` | {ioc.source} | {ioc.why_it_matters} |" for ioc in iocs)
    return "\n".join(lines)


def render_online_enrichment_summary(analysis: EmailAnalysis) -> str:
    """Render a simple online enrichment summary for Markdown output."""
    enrichment = analysis.online_enrichment
    lines = [
        f"- Status: {enrichment.status}",
        f"- Total indicators checked: {enrichment.total_indicators_checked}",
        f"- Total threats found: {enrichment.total_threats_found}",
        f"- Highest provider score: {enrichment.highest_provider_score}",
    ]
    if enrichment.provider_results:
        lines.append("| Provider | Status | Threat result | Score | Note |")
        lines.append("| --- | --- | --- | --- | --- |")
        for item in enrichment.provider_results:
            lines.append(f"| {item.provider} | {item.status} | {item.threat_result} | {item.score} | {item.note} |")
    return "\n".join(lines)


def recommended_soc_actions(analysis: EmailAnalysis) -> list[str]:
    """Return SOC actions."""
    actions = [
        "Do not open URLs or attachments during triage.",
        "Search for sender, recipient, subject, URLs/domains, and attachment names in Microsoft 365 Defender/Sentinel.",
        "Check whether other users received or clicked the message.",
        "If phishing is confirmed, purge the message, block indicators where appropriate, and notify affected users.",
    ]
    if analysis.attachment_findings:
        actions.insert(1, "Review attachment metadata and detonation status in approved sandbox tooling only.")
    return actions


def build_kql(analysis: EmailAnalysis) -> str:
    """Return safe sample KQL follow-up."""
    _, sender_address = parseaddr(analysis.parsed_email.from_address)
    sender_address = sender_address or "sender@example.invalid"
    sender_domain = sender_address.rsplit("@", 1)[-1] if "@" in sender_address else "example.invalid"
    subject_keyword = subject_keyword_for_kql(analysis.parsed_email.subject)
    return "\n".join(
        [
            "// Sample KQL for email threat investigation. Demo placeholders only.",
            f"let SenderAddress = \"{sender_address}\";",
            f"let SenderDomain = \"{sender_domain}\";",
            f"let SubjectKeyword = \"{subject_keyword}\";",
            "",
            "EmailEvents",
            "| where SenderFromAddress =~ SenderAddress",
            "   or SenderFromDomain =~ SenderDomain",
            "   or Subject has SubjectKeyword",
            "| join kind=leftouter EmailUrlInfo on NetworkMessageId",
            "| join kind=leftouter EmailAttachmentInfo on NetworkMessageId",
            "| project Timestamp, SenderFromAddress, SenderFromDomain, RecipientEmailAddress, Subject, DeliveryAction, ThreatTypes, Url, FileName, SHA256",
            "| order by Timestamp desc",
        ]
    )


def subject_keyword_for_kql(subject: str) -> str:
    """Return a safe short subject keyword for sample KQL."""
    text = str(subject or "").lower()
    for phrase in ("password expires", "signature required", "planned maintenance", "invoice", "payment", "secure document"):
        if phrase in text:
            return phrase
    words = [word.strip(".,:;!?") for word in text.split() if len(word.strip(".,:;!?")) >= 4]
    return " ".join(words[:2]) if words else "suspicious email"


def build_ticket_note(analysis: EmailAnalysis) -> str:
    """Return Freshservice-style ticket note."""
    return "\n".join(
        [
            "**Subject:** Reported suspicious email requires review",
            f"**Verdict:** {analysis.score.verdict}",
            f"**Risk Score:** {analysis.score.overall_score}/100",
            f"**Summary:** {plain_reason(analysis)}",
            f"**User Guidance:** {analysis.user_action} {analysis.user_do_not}",
            f"**SOC Action:** {analysis.agent_action}",
            "**Safety:** Local analysis only; raw email content was not sent to external services or the local LLM.",
        ]
    )
