"""Streamlit dashboard for the AI Security Lab sample analyzers."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import streamlit as st

from helpers import (
    REPO_ROOT,
    PROJECTS,
    generate_report_from_json,
    list_sample_files,
    load_uploaded_json,
    run_analyzer_for_sample,
    validate_sample_file,
)


SECURITY_COPILOT_DIR = REPO_ROOT / "security_copilot"
if str(SECURITY_COPILOT_DIR) not in sys.path:
    sys.path.insert(0, str(SECURITY_COPILOT_DIR))

from config import load_config  # noqa: E402
from copilot_assistant import ANSWER_MODES, answer_question, render_markdown  # noqa: E402
from ollama_client import SETUP_INSTRUCTIONS, check_ollama_status  # noqa: E402

EVIDENCE_ANALYZER_DIR = REPO_ROOT / "evidence_analyzer"
if str(EVIDENCE_ANALYZER_DIR) not in sys.path:
    sys.path.insert(0, str(EVIDENCE_ANALYZER_DIR))

from evidence_summarizer import analyze_evidence  # noqa: E402

EMAIL_ANALYZER_DIR = REPO_ROOT / "email_analyzer"
if str(EMAIL_ANALYZER_DIR) not in sys.path:
    sys.path.insert(0, str(EMAIL_ANALYZER_DIR))

from email_summarizer import analyze_email_file, analyze_pasted_email  # noqa: E402


EXAMPLE_PROMPTS = {
    "Investigate risky sign-in": "What should an analyst check when investigating a risky sign-in?",
    "Generate suspicious PowerShell KQL": "What KQL should I use to hunt for suspicious PowerShell activity?",
    "Create phishing ticket note": "Create a Freshservice-style ticket note for a phishing investigation.",
    "Review malware alert": "How should I investigate a Defender malware alert?",
    "Explain impossible travel escalation": "When should an impossible travel alert be escalated?",
    "Analyze uploaded evidence IOCs": "Based on the uploaded evidence, list the IOCs and tell me what a SOC analyst should investigate first.",
}


def main() -> None:
    st.set_page_config(page_title="AI Security Command Center", layout="wide")

    st.title("AI Security Command Center")
    st.caption(
        "Local-first AI/ML security operations platform using Ollama, RAG, ML anomaly detection, "
        "evidence analysis, IOC extraction, and SOC automation."
    )
    render_command_center_status()

    reports_tab, evidence_tab, email_tab, copilot_tab = st.tabs(
        ["Security Analysis Modules", "Threat Evidence Workbench", "Email Threat Analyzer", "Local SecOps Copilot"]
    )

    with reports_tab:
        render_project_reports()

    with evidence_tab:
        render_threat_evidence_workbench()

    with email_tab:
        render_email_threat_analyzer()

    with copilot_tab:
        render_copilot_chat()


def render_project_reports() -> None:
    project_name = st.selectbox("Project", options=list(PROJECTS.keys()))
    project = PROJECTS[project_name]
    st.write(project.description)
    st.warning(
        "Use fake/sample data only. Do not upload real secrets, passwords, tokens, "
        "company data, client data, tenant data, or vendor confidential data."
    )

    input_options = [f"Use sample {project.sample_extension.upper().lstrip('.')}"]
    if project.upload_enabled:
        input_options.append("Upload custom JSON")

    input_mode = st.radio("Input source", options=input_options, horizontal=True)

    report = None

    if input_mode.startswith("Use sample"):
        sample_files = list_sample_files(project)
        if not sample_files:
            st.error("No sample files were found for this project.")
            return

        selected_sample = st.selectbox("Sample input file", options=[path.name for path in sample_files])

        with st.expander("Sample file path", expanded=False):
            st.code(str(project.sample_input_dir / selected_sample), language="text")

        if st.button("Generate report", type="primary"):
            try:
                sample_path = validate_sample_file(project, selected_sample)
                report = run_analyzer_for_sample(project, sample_path)
            except (ValueError, FileNotFoundError, RuntimeError) as error:
                st.error(str(error))
                return

    else:
        uploaded_file = st.file_uploader("Upload custom JSON", type=["json"])
        st.caption("Uploaded JSON is parsed in memory and is not saved to the repository.")

        if st.button("Generate report", type="primary"):
            if uploaded_file is None:
                st.error("Upload a JSON file before generating a report.")
                return

            try:
                payload = load_uploaded_json(uploaded_file.getvalue())
                report = generate_report_from_json(project, payload)
            except (ValueError, FileNotFoundError, RuntimeError) as error:
                st.error(str(error))
                return

    if report:
        st.subheader("Generated Markdown Report")
        st.markdown(report)
        with st.expander("Raw Markdown"):
            st.code(report, language="markdown")


def render_command_center_status() -> None:
    """Render product status cards at the top of the dashboard."""
    cards = [
        ("Local LLM", "Ollama"),
        ("Model", "qwen2.5:3b"),
        ("Evidence Analysis", "Enabled"),
        ("IOC Extraction", "Enabled"),
        ("Playbook Library", "Enabled"),
    ]
    columns = st.columns(len(cards))
    for column, (label, value) in zip(columns, cards):
        with column:
            with st.container(border=True):
                st.caption(label)
                st.markdown(f"**{value}**")


def render_threat_evidence_workbench() -> None:
    """Render local-only uploaded evidence analysis."""
    st.subheader("Threat Evidence Workbench")
    st.write(
        "Upload fake/sample JSON, CSV, TXT, or LOG evidence for local rule-based threat analysis. "
        "Uploaded files are processed in memory for this dashboard session and are not saved permanently."
    )
    st.warning(
        "Do not upload secrets, passwords, tokens, API keys, company logs, client data, tenant data, "
        "production logs, or vendor confidential data. Sensitive-looking content is blocked before analysis."
    )
    st.caption("Supported file types: `.json`, `.csv`, `.txt`, `.log`. Maximum file size: 5 MB.")

    uploaded_file = st.file_uploader(
        "Upload threat evidence",
        type=["json", "csv", "txt", "log"],
        key="threat_evidence_upload",
    )

    if uploaded_file is None:
        st.session_state.pop("last_evidence_upload_id", None)
        st.info("Upload a fake/sample evidence file to generate a local report.")
        return

    upload_id = f"{uploaded_file.name}:{uploaded_file.size}"
    if st.session_state.get("last_evidence_upload_id") != upload_id:
        st.session_state["last_evidence_upload_id"] = upload_id
        st.session_state.pop("evidence_analysis", None)
        st.session_state.pop("copilot_session_context", None)

    st.write(f"Selected file: `{uploaded_file.name}`")
    st.caption("The uploaded file name is displayed for the current session only; the file is not written to disk.")

    action_left, action_right = st.columns([1, 1])
    with action_left:
        analyze_clicked = st.button("Analyze evidence", type="primary")
    with action_right:
        clear_clicked = st.button("Clear uploaded evidence")

    if clear_clicked:
        st.session_state.pop("evidence_analysis", None)
        st.session_state.pop("copilot_session_context", None)
        st.session_state.pop("last_evidence_upload_id", None)
        st.success("Cleared analyzed evidence and Copilot evidence context. The uploaded file was not saved.")
        st.rerun()

    if analyze_clicked:
        try:
            analysis = analyze_evidence(uploaded_file.name, uploaded_file.getvalue())
        except ValueError as error:
            st.error(str(error))
            st.session_state.pop("evidence_analysis", None)
            st.session_state.pop("copilot_session_context", None)
            return
        st.session_state["evidence_analysis"] = analysis
        st.session_state["copilot_session_context"] = analysis.copilot_context

    analysis = st.session_state.get("evidence_analysis")
    if not analysis:
        return

    iocs = get_analysis_iocs(analysis)
    findings = get_analysis_findings(analysis)
    risk_scores = get_analysis_risk_scores(analysis)
    ioc_counts = get_analysis_ioc_counts(analysis)
    profile = get_analysis_profile(analysis)

    total_iocs = len(iocs)
    high_risk_entities = len([score for score in risk_scores if getattr(score, "score", 0) >= 50])
    summary_cards = st.columns(5)
    summary_values = [
        ("Records / Lines", getattr(analysis, "total_items", 0)),
        ("Total IOCs", total_iocs),
        ("High-Risk Entities", high_risk_entities),
        ("Suspicious Behaviors", len(findings)),
        ("Severity", getattr(analysis, "severity", "Unknown")),
    ]
    for column, (label, value) in zip(summary_cards, summary_values):
        with column:
            st.metric(label, value)

    with st.container(border=True):
        st.markdown("### Highest Priority Finding")
        st.markdown(f"**{get_highest_priority_finding(analysis)}**")
        st.caption(f"Evidence type: {getattr(analysis, 'evidence_type', 'Unknown evidence')}")

    process_count = len({getattr(item, "display_value", "") for item in iocs if getattr(item, "type", "") in {"Process", "Parent Process"}})
    ioc_metric_cards = st.columns(6)
    ioc_metric_values = [
        ("IPs", ioc_counts["total_ips"]),
        ("URLs / Domains", ioc_counts["total_urls_domains"]),
        ("Users", ioc_counts["total_users"]),
        ("Devices", ioc_counts["total_devices"]),
        ("Processes", process_count),
        ("Command Indicators", ioc_counts["total_suspicious_command_indicators"]),
    ]
    for column, (label, value) in zip(ioc_metric_cards, ioc_metric_values):
        with column:
            st.metric(label, value)

    chart_left, chart_right = st.columns(2)
    with chart_left:
        st.markdown("### IOC Counts")
        st.bar_chart(
            {
                "Count": {
                    "IPs": ioc_counts["total_ips"],
                    "URLs/Domains": ioc_counts["total_urls_domains"],
                    "Users": ioc_counts["total_users"],
                    "Devices": ioc_counts["total_devices"],
                    "Processes": process_count,
                    "Command Indicators": ioc_counts["total_suspicious_command_indicators"],
                }
            }
        )
    with chart_right:
        st.markdown("### Entity Risk Scores")
        risk_chart = {getattr(score, "entity", "unknown")[:28]: getattr(score, "score", 0) for score in risk_scores[:8]}
        if risk_chart:
            st.bar_chart({"Risk Score": risk_chart})
        else:
            st.write("No entity risk scores were generated.")

    entity_user_col, entity_device_col, entity_ip_col = st.columns(3)
    with entity_user_col:
        st.markdown("### Top Risky Users")
        entity_rows = [
            {
                "Type": score.entity_type,
                "Entity": score.entity,
                "Score": score.score,
                "Reasons": ", ".join(score.reasons[:8]),
            }
            for score in getattr(profile, "top_risky_users", [])[:8]
        ]
        if entity_rows:
            st.dataframe(entity_rows, width="stretch", hide_index=True)
        else:
            st.write("No risky users scored.")
    with entity_device_col:
        st.markdown("### Top Risky Devices")
        device_rows = [
            {
                "Entity": score.entity,
                "Score": score.score,
                "Reasons": ", ".join(score.reasons[:8]),
            }
            for score in getattr(profile, "top_risky_devices", [])[:8]
        ]
        if device_rows:
            st.dataframe(device_rows, width="stretch", hide_index=True)
        else:
            st.write("No risky devices scored.")
    with entity_ip_col:
        st.markdown("### Top Risky IPs")
        ip_rows = [
            {
                "Entity": score.entity,
                "Score": score.score,
                "Reasons": ", ".join(score.reasons[:8]),
            }
            for score in getattr(profile, "top_risky_ips", [])[:8]
        ]
        if ip_rows:
            st.dataframe(ip_rows, width="stretch", hide_index=True)
        else:
            st.write("No risky IPs scored.")

    with st.container():
        st.markdown("### Detected Behaviors")
        behavior_rows = [
            {
                "Behavior": finding.title,
                "Severity": finding.severity,
                "MITRE ATT&CK": finding.mitre_attack,
                "Recommended Review": finding.recommendation,
            }
            for finding in findings[:10]
        ]
        if behavior_rows:
            st.dataframe(behavior_rows, width="stretch", hide_index=True)
        else:
            st.write("No suspicious behaviors detected.")

    st.markdown("### Indicators and Investigation Artifacts")
    st.caption("All sample IOCs shown here are fake/demo values. URLs, domains, and IP-like values are defanged for display.")
    if iocs:
        ioc_types = ["All"] + sorted({getattr(item, "type", "") for item in iocs if getattr(item, "type", "")})
        selected_ioc_type = st.selectbox("IOC table filter", options=ioc_types, index=0)
        visible_iocs = iocs if selected_ioc_type == "All" else [
            item for item in iocs if getattr(item, "type", "") == selected_ioc_type
        ]
        ioc_rows = [
            {
                "Type": getattr(item, "type", "Unknown"),
                "Value": getattr(item, "display_value", ""),
                "Source / Context": getattr(item, "source", ""),
                "Why It Matters": getattr(item, "why_it_matters", ""),
            }
            for item in visible_iocs[:50]
        ]
        st.dataframe(ioc_rows, width="stretch", hide_index=True)
    else:
        st.write("No IOCs or investigation artifacts were extracted by the local rule set.")

    with st.expander("IOC Summary Counts", expanded=False):
        st.write(f"- Total IPs found: `{ioc_counts['total_ips']}`")
        st.write(f"- Total URLs/domains found: `{ioc_counts['total_urls_domains']}`")
        st.write(f"- Total users found: `{ioc_counts['total_users']}`")
        st.write(f"- Total devices found: `{ioc_counts['total_devices']}`")
        st.write(
            "- Total suspicious command indicators found: "
            f"`{ioc_counts['total_suspicious_command_indicators']}`"
        )

    st.markdown("### Suspicious Findings")
    if findings:
        for finding in findings[:10]:
            with st.container(border=True):
                st.markdown(f"**{finding.title}** ({finding.severity})")
                st.write(finding.description)
                st.caption(f"MITRE ATT&CK: {finding.mitre_attack}")
    else:
        st.write("No suspicious findings were detected by the local rule set.")

    st.markdown("### Generated Evidence Report")
    st.markdown(getattr(analysis, "markdown_report", "No Markdown report was generated."))
    with st.expander("Raw Markdown Evidence Report", expanded=False):
        st.code(getattr(analysis, "markdown_report", ""), language="markdown")

    st.info("Local SecOps Copilot will receive only the summarized evidence context, not the raw uploaded file.")
    if st.button("Ask Local SecOps Copilot about this evidence"):
        st.session_state["copilot_session_context"] = getattr(analysis, "copilot_context", "")
        st.session_state["pending_copilot_question"] = (
            "Analyze the uploaded evidence summary from the current session. "
            "What suspicious behavior should a SOC analyst prioritize?"
        )
        st.success("Evidence summary is ready for Local SecOps Copilot. Open the Copilot tab to review the answer.")


def render_email_threat_analyzer() -> None:
    """Render local AI Email Threat Analyzer workflow."""
    st.subheader("AI Email Threat Analyzer")
    st.write("Upload or paste a suspicious email for local phishing/spam triage.")
    st.warning(
        "Do not upload real secrets, passwords, tokens, company data, client data, tenant data, "
        "production logs, or vendor confidential data. Emails are processed locally in memory."
    )
    st.caption("Supported uploads: `.eml`, `.txt`, `.json` metadata. `.msg support planned`.")
    online_enabled = st.checkbox(
        "Enable online enrichment for extracted indicators",
        value=False,
        help="Only extracted indicators such as URLs, domains, IPs, and hashes are sent. Raw email body, raw headers, and attachments are not sent.",
        key="email_online_enrichment_enabled",
    )

    input_mode = st.radio(
        "Email evidence input",
        options=["Upload .eml or metadata file", "Paste headers", "Paste email body", "Paste URLs/domains", "Paste attachment metadata"],
        horizontal=False,
    )

    analysis = None
    if input_mode == "Upload .eml or metadata file":
        uploaded_file = st.file_uploader("Upload email evidence", type=["eml", "txt", "json"], key="email_evidence_upload")
        if uploaded_file is not None:
            upload_id = f"{uploaded_file.name}:{uploaded_file.size}"
            if st.session_state.get("last_email_upload_id") != upload_id:
                clear_email_state(clear_upload_id=False)
                st.session_state["last_email_upload_id"] = upload_id
            st.caption("The uploaded file is parsed in memory and is not saved permanently.")
        if st.button("Analyze email", type="primary"):
            if uploaded_file is None:
                st.error("Upload an email evidence file before analyzing.")
                return
            try:
                analysis = analyze_uploaded_email_bytes(uploaded_file.name, uploaded_file.getvalue(), online_enrichment_enabled=online_enabled)
            except ValueError as error:
                st.error(str(error))
                return
    else:
        source_type = input_mode.lower().replace("paste ", "").replace(" ", "_")
        pasted_text = st.text_area("Paste email evidence", height=220)
        if st.button("Analyze pasted email", type="primary"):
            if not pasted_text.strip():
                st.error("Paste email evidence before analyzing.")
                return
            try:
                analysis = analyze_pasted_email_text(pasted_text, source_type=source_type, online_enrichment_enabled=online_enabled)
            except ValueError as error:
                st.error(str(error))
                return

    if analysis is not None:
        st.session_state["email_analysis"] = analysis
        st.session_state["email_session_context"] = build_email_session_context(analysis)
        st.session_state["copilot_session_context"] = build_email_session_context(analysis)

    clear_left, clear_right = st.columns([1, 4])
    with clear_left:
        if st.button("Clear Email Analysis"):
            clear_email_state()
            st.success("Cleared email analysis and Copilot email context. Uploaded email content was not saved.")
            st.rerun()

    analysis = st.session_state.get("email_analysis")
    if not analysis:
        st.info("Upload or paste fake/sample email evidence to generate a local email threat report.")
        return

    render_email_summary_cards(analysis)
    render_online_enrichment_snapshot(analysis)
    render_email_detail_sections(analysis)

    st.info("Local SecOps Copilot will receive only summarized email findings, extracted IOCs, and risk scores.")
    if st.button("Ask Local SecOps Copilot about this email"):
        st.session_state["copilot_session_context"] = build_email_session_context(analysis)
        st.session_state["pending_copilot_question"] = "Is this email phishing, and what should I tell the user?"
        st.success("Email summary is ready for Local SecOps Copilot. Open the Copilot tab to review the answer.")


def render_email_summary_cards(analysis) -> None:
    """Render user-friendly email verdict cards first."""
    st.markdown("### Email Verdict")
    columns = st.columns(4)
    card_values = [
        ("Verdict", analysis.score.verdict),
        ("Risk Score", f"{analysis.score.overall_score}/100"),
        ("User Action", analysis.user_action),
        ("IT / SOC Action", analysis.agent_action),
    ]
    for column, (label, value) in zip(columns, card_values):
        with column:
            with st.container(border=True):
                st.caption(label)
                st.markdown(f"**{value}**")
    st.markdown("### Why this email was flagged")
    for reason in analysis.score.reasons[:5] or ["No strong phishing indicators were found."]:
        st.markdown(f"- {reason}")
    st.markdown(f"**Recommended user action:** {analysis.user_action}")
    st.markdown(f"**Do not do this:** {analysis.user_do_not}")


def render_online_enrichment_snapshot(analysis) -> None:
    """Render top-level online enrichment cards for email analysis."""
    enrichment = analysis.online_enrichment
    st.markdown("### Online Enrichment Snapshot")
    st.caption("Online enrichment supports local analysis but does not replace analyst review.")
    if not should_show_full_enrichment_snapshot(enrichment):
        with st.container(border=True):
            st.markdown("**Online Enrichment: Off**")
            st.write("Offline analysis only. No external lookups were performed.")
            st.caption("Enable online enrichment to check extracted URLs, domains, IPs, and hashes with configured free providers.")
        render_enrichment_metrics(enrichment)
        with st.expander("Provider status", expanded=False):
            for provider in enrichment.provider_results:
                st.write(f"- **{provider.provider}:** Offline only / Not checked")
        return

    st.markdown(f"**{online_enrichment_verdict(enrichment)}**")
    render_enrichment_metrics(enrichment)

    provider_columns = st.columns(len(enrichment.provider_results))
    for column, provider in zip(provider_columns, enrichment.provider_results):
        with column:
            with st.container(border=True):
                st.markdown(f"**{provider.provider}**")
                st.write(status_text(provider.status, provider.threat_result))
                st.caption(f"Score: {provider.score}")
                st.caption(provider.note)

    provider_rows = provider_result_rows(enrichment)
    st.dataframe(provider_rows, width="stretch", hide_index=True)

    with st.expander("Online Enrichment Details", expanded=False):
        render_online_enrichment_details(enrichment)


def render_enrichment_metrics(enrichment) -> None:
    """Render compact enrichment metrics."""
    metric_columns = st.columns(6)
    metric_values = [
        ("URLs checked", enrichment.urls_checked),
        ("Domains checked", enrichment.domains_checked),
        ("IPs checked", enrichment.ips_checked),
        ("Hashes checked", enrichment.hashes_checked),
        ("Threats found", enrichment.total_threats_found),
        ("Providers checked", enrichment.providers_checked),
    ]
    for column, (label, value) in zip(metric_columns, metric_values):
        with column:
            st.metric(label, value)


def provider_result_rows(enrichment) -> list[dict]:
    """Return provider rows for dashboard tables."""
    return [
        {
            "Provider": item.provider,
            "Indicator": item.indicator,
            "Type": item.indicator_type,
            "Result": item.threat_result,
            "Score / Detection": item.score,
            "Notes": item.note,
        }
        for item in enrichment.provider_results
    ]


def render_online_enrichment_details(enrichment) -> None:
    """Render raw provider details in an expander."""
    st.write(f"Status: `{enrichment.status}`")
    st.write(f"Total indicators checked: `{enrichment.total_indicators_checked}`")
    st.write(f"Highest provider score: `{enrichment.highest_provider_score}`")
    st.json(
        [
            item.raw_details or {
            "provider": item.provider,
            "status": item.status,
            "threat_result": item.threat_result,
            "score": item.score,
            "note": item.note,
            }
            for item in enrichment.provider_results
        ]
    )


def should_show_full_enrichment_snapshot(enrichment) -> bool:
    """Return True when provider cards/results should be shown by default."""
    return bool(getattr(enrichment, "enabled", False))


def online_enrichment_verdict(enrichment) -> str:
    """Return simple online enrichment verdict text."""
    if not getattr(enrichment, "enabled", False):
        return "Offline analysis only"
    if enrichment.total_threats_found > 0:
        return "One or more providers flagged indicators"
    if enrichment.providers_checked > 0:
        return "No online provider flagged the indicators"
    if all(getattr(result, "status", "") == "Not configured" for result in enrichment.provider_results):
        return "Online enrichment not configured"
    if any(getattr(result, "status", "") in {"Not configured", "Error", "Rate limited"} for result in enrichment.provider_results):
        return "Online enrichment incomplete"
    return "Online enrichment not enabled"


def status_text(status: str, threat_result: str) -> str:
    """Return readable provider status text."""
    if threat_result == "Threat found":
        return f":warning: {status} | {threat_result}"
    if threat_result == "Clean":
        return f":green[{status} | {threat_result}]"
    return f"{status} | {threat_result}"


def render_email_detail_sections(analysis) -> None:
    """Render technical email analysis sections."""
    st.markdown("### Risk Breakdown")
    category_scores = get_email_category_scores(analysis)
    st.bar_chart({"Risk Score": category_scores})

    url_rows = [
        {
            "Indicator": finding.display_value,
            "Type": finding.indicator_type,
            "Severity": finding.severity,
            "Reason": finding.reason,
        }
        for finding in analysis.url_findings
    ]
    attachment_rows = [
        {
            "Attachment": finding.name,
            "Extension": finding.extension,
            "Severity": finding.severity,
            "Reason": finding.reason,
        }
        for finding in analysis.attachment_findings
    ]
    ioc_rows = get_email_ioc_rows(analysis)

    with st.expander("Header Details", expanded=True):
        auth_columns = st.columns(3)
        for column, (label, value) in zip(
            auth_columns,
            [
                ("SPF", analysis.parsed_email.spf_result),
                ("DKIM", analysis.parsed_email.dkim_result),
                ("DMARC", analysis.parsed_email.dmarc_result),
            ],
        ):
            with column:
                st.metric(label, value)
        if analysis.header_findings:
            st.dataframe(
                [{"Finding": item.title, "Severity": item.severity, "Description": item.description} for item in analysis.header_findings],
                width="stretch",
                hide_index=True,
            )
        else:
            st.write("No notable header findings.")

    with st.expander("URL/Domain Details", expanded=True):
        if url_rows:
            st.dataframe(url_rows, width="stretch", hide_index=True)
        else:
            st.write("No suspicious URL/domain findings.")

    with st.expander("Attachment Details", expanded=True):
        if attachment_rows:
            st.dataframe(attachment_rows, width="stretch", hide_index=True)
        else:
            st.write("No risky attachment metadata found.")

    st.markdown("### Email IOCs")
    st.caption("All values are fake/sample or user-provided lab values. URLs/domains/IPs are defanged for display.")
    if ioc_rows:
        st.dataframe(ioc_rows, width="stretch", hide_index=True)
    else:
        st.write("No IOCs extracted.")

    with st.expander("SOC Details", expanded=False):
        st.markdown(analysis.markdown_report)
        st.write(f"Online enrichment: `{analysis.online_enrichment.status}`")

    with st.expander("Raw Markdown Report", expanded=False):
        st.code(analysis.markdown_report, language="markdown")


def analyze_uploaded_email_bytes(file_name: str, file_bytes: bytes, online_enrichment_enabled: bool = False):
    """Dashboard path for uploaded email analysis."""
    return analyze_email_file(file_name, file_bytes, online_enrichment_enabled=online_enrichment_enabled)


def analyze_pasted_email_text(text: str, source_type: str, online_enrichment_enabled: bool = False):
    """Dashboard path for pasted email analysis."""
    return analyze_pasted_email(text, source_type=source_type, online_enrichment_enabled=online_enrichment_enabled)


def build_email_session_context(analysis) -> str:
    """Return safe summarized email context for Copilot."""
    return getattr(analysis, "copilot_context", "")


def get_email_ioc_rows(analysis) -> list[dict]:
    """Return dashboard email IOC rows."""
    return [
        {
            "Type": item.type,
            "Value": item.value,
            "Source": item.source,
            "Why It Matters": item.why_it_matters,
        }
        for item in getattr(analysis, "iocs", [])[:50]
    ]


def get_email_category_scores(analysis) -> dict:
    """Return dashboard email category score mapping."""
    return getattr(getattr(analysis, "score", None), "category_scores", {}) or {}


def clear_email_state(clear_upload_id: bool = True) -> None:
    """Clear dashboard email analysis state."""
    st.session_state.pop("email_analysis", None)
    st.session_state.pop("email_session_context", None)
    if clear_upload_id:
        st.session_state.pop("last_email_upload_id", None)
    if "Uploaded email analysis summary" in st.session_state.get("copilot_session_context", ""):
        st.session_state.pop("copilot_session_context", None)


def render_copilot_chat() -> None:
    st.subheader("Local SecOps Copilot")
    st.write(
        "Ask source-cited questions across the local AI Security Lab docs, sample reports, framework notes, "
        "and safe lab data. The Copilot uses local Ollama for answer generation and local RAG retrieval for context."
    )
    st.warning(
        "Do not enter real secrets, passwords, tokens, company data, client data, tenant data, "
        "or vendor confidential data. Answers use fake/sample lab files only."
    )

    try:
        config = load_config()
        status = check_ollama_status(config)
    except ValueError as error:
        st.error(str(error))
        return

    render_provider_status(status)

    if status.setup_required and not config.uses_mock:
        st.warning(status.message)
        st.code(SETUP_INSTRUCTIONS, language="text")

    if "copilot_messages" not in st.session_state:
        st.session_state["copilot_messages"] = []

    session_context = st.session_state.get("copilot_session_context", "")
    if session_context:
        context_left, context_right = st.columns([4, 1])
        with context_left:
            st.info("Threat Evidence Workbench summary is active for this chat session. Raw uploaded file content is not sent.")
        with context_right:
            if st.button("Clear evidence context"):
                st.session_state.pop("copilot_session_context", None)
                st.rerun()
        analysis = st.session_state.get("evidence_analysis")
        email_analysis = st.session_state.get("email_analysis")
        if email_analysis:
            with st.container(border=True):
                st.markdown("**Email-aware mode active: using summarized email findings and extracted IOCs.**")
                st.write(f"Verdict: `{email_analysis.score.verdict}`")
                st.write(f"Risk score: `{email_analysis.score.overall_score}/100`")
        elif analysis:
            with st.container(border=True):
                st.markdown("**Evidence-aware mode active: using summarized uploaded evidence and extracted IOCs.**")
                st.write(f"Evidence type: `{getattr(analysis, 'evidence_type', 'Unknown evidence')}`")
                st.write(f"Highest priority: {get_highest_priority_finding(analysis)}")

    controls_left, controls_right = st.columns([4, 1])
    with controls_left:
        answer_mode = st.selectbox("Answer mode", options=ANSWER_MODES, index=0)
        with st.expander("Advanced Settings", expanded=False):
            top_k = st.slider(
                "Retrieved sources",
                min_value=1,
                max_value=10,
                value=5,
                help="Higher values may improve context but can slow local model responses.",
            )
            latest_intent = st.session_state.get("copilot_latest_result", {}).get("detected_intent", "None")
            st.write(f"Detected intent: `{latest_intent}`")
    with controls_right:
        st.write("")
        st.write("")
        if st.button("Clear chat"):
            st.session_state["copilot_messages"] = []
            st.session_state.pop("copilot_latest_result", None)
            st.session_state.pop("copilot_latest_question", None)
            st.rerun()

    st.markdown("**Example prompts**")
    prompt_columns = st.columns(len(EXAMPLE_PROMPTS))
    for column, (label, prompt) in zip(prompt_columns, EXAMPLE_PROMPTS.items()):
        with column:
            if st.button(label, use_container_width=True):
                st.session_state["pending_copilot_question"] = prompt
                st.rerun()

    question = st.session_state.pop("pending_copilot_question", None)
    with st.form("copilot_question_form", clear_on_submit=True):
        typed_question = st.text_input("Ask Local SecOps Copilot", value=question or "")
        submitted = st.form_submit_button("Send question", type="primary")
    if submitted and typed_question:
        question = typed_question

    if question:
        previous_result = st.session_state.get("copilot_latest_result")
        previous_question = st.session_state.get("copilot_latest_question")
        if previous_result and previous_question:
            st.session_state["copilot_messages"].append({"question": previous_question, "result": previous_result})

        try:
            result = generate_copilot_answer(
                question=question,
                answer_mode=answer_mode,
                top_k=top_k,
                config=config,
                session_context=session_context,
            )
        except ValueError as error:
            st.error(str(error))
            return

        if result["setup_required"]:
            st.warning("Ollama setup is required before local LLM answers are available.")
            st.code(SETUP_INSTRUCTIONS, language="text")
        elif result.get("timed_out"):
            st.warning(result["answer"])

        st.session_state["copilot_latest_question"] = question
        st.session_state["copilot_latest_result"] = result

    latest_result = st.session_state.get("copilot_latest_result")
    latest_question = st.session_state.get("copilot_latest_question")
    if latest_result:
        st.markdown("### Latest Answer")
        with st.container(border=True):
            st.markdown(f"**Question:** {latest_question}")
        render_copilot_answer_card(latest_result)

    if st.session_state["copilot_messages"]:
        with st.expander("Previous Responses", expanded=False):
            for index, item in enumerate(reversed(st.session_state["copilot_messages"]), start=1):
                st.markdown(f"#### Previous Response {index}")
                st.markdown(f"**Question:** {item['question']}")
            render_copilot_answer_card(item["result"])


def get_analysis_iocs(analysis) -> list:
    """Return extracted IOCs from current or older EvidenceAnalysis objects."""
    return getattr(analysis, "iocs", None) or getattr(analysis, "extracted_iocs", None) or []


def get_analysis_findings(analysis) -> list:
    """Return detected behaviors from current or older EvidenceAnalysis objects."""
    findings = getattr(analysis, "findings", None) or getattr(analysis, "detected_behaviors", None) or []
    return [item for item in findings if not is_streamlit_delta_generator(item)]


def get_analysis_risk_scores(analysis) -> list:
    """Return risk scores safely for dashboard rendering."""
    return getattr(analysis, "risk_scores", None) or []


def get_analysis_ioc_counts(analysis) -> dict:
    """Return IOC counts with stable dashboard keys."""
    counts = getattr(analysis, "ioc_summary_counts", None) or {}
    return {
        "total_ips": counts.get("total_ips", 0),
        "total_urls_domains": counts.get("total_urls_domains", 0),
        "total_users": counts.get("total_users", 0),
        "total_devices": counts.get("total_devices", 0),
        "total_suspicious_command_indicators": counts.get("total_suspicious_command_indicators", 0),
    }


def get_analysis_profile(analysis):
    """Return the structured profile when present."""
    return getattr(analysis, "evidence_profile", None)


def get_highest_priority_finding(analysis) -> str:
    """Return a stable highest-priority finding string."""
    profile = get_analysis_profile(analysis)
    if profile and getattr(profile, "highest_priority_finding", ""):
        return profile.highest_priority_finding
    return getattr(analysis, "highest_priority_finding", "") or "No suspicious behavior exceeded the local rule threshold."


def is_streamlit_delta_generator(value) -> bool:
    """Return True for Streamlit UI objects that must never be treated as analysis data."""
    value_type = type(value)
    module = getattr(value_type, "__module__", "").lower()
    name = getattr(value_type, "__name__", "").lower()
    return "streamlit" in module and "deltagenerator" in name


def render_provider_status(status) -> None:
    """Render compact provider status plus hidden debug details."""
    status_text = "Ollama Ready" if not status.setup_required else "Ollama Setup Required"
    mode_text = "Local Mode" if status.provider == "ollama" else "Test Mode"
    status_icon = "OK" if not status.setup_required else "Action needed"

    with st.container(border=True):
        st.markdown(f"**{status_text} | {status.model} | {mode_text}**")
        st.caption(status_icon)

    with st.expander("Provider Debug Details", expanded=False):
        st.write(f"- Provider: `{status.provider}`")
        st.write(f"- Model: `{status.model}`")
        st.write(f"- Ollama API reachable: `{status.reachable}`")
        st.write(f"- Model installed: `{status.model_installed}`")
        st.write(f"- Timeout seconds: `{status.generation_timeout_seconds}`")
        st.write(f"- Health timeout seconds: `{status.health_timeout_seconds}`")
        st.write(f"- Last error: `{status.last_error or 'None'}`")


def generate_copilot_answer(
    question: str,
    answer_mode: str,
    top_k: int,
    config: object,
    session_context: str | None = None,
) -> dict:
    """Generate an answer while displaying a clear local-model loading state."""
    start_time = time.monotonic()
    loading_panel = st.empty()

    with loading_panel.container(border=True):
        st.markdown("**Generating local AI response with Ollama...**")
        st.write(f"Model: `{config.ollama_model}`")
        st.caption("This can take 30-90 seconds on local laptops.")
        st.caption("Status: retrieving local context and waiting for the local model response.")
        with st.spinner("Local SecOps Copilot is thinking..."):
            result = answer_question(
                question,
                answer_mode=answer_mode,
                index_root=Path(REPO_ROOT),
                top_k=top_k,
                config=config,
                session_context=session_context,
            )

        elapsed_seconds = time.monotonic() - start_time
        st.success(f"Local response ready in {elapsed_seconds:.1f} seconds.")

    return result


def render_copilot_answer_card(result: dict) -> None:
    """Render the Copilot answer in a product-style card."""
    with st.container(border=True):
        render_copilot_metadata_cards(result)

        st.markdown("### Answer")
        st.markdown(result["answer"])

        kql_query = extract_fenced_kql(result["answer"])
        if kql_query:
            st.markdown("### KQL Query")
            st.code(kql_query, language="kql")

        render_copilot_evidence_tables()

        st.markdown("### Recommended Next Steps")
        for index, step in enumerate(result["recommended_next_steps"], start=1):
            st.markdown(f"{index}. {step}")

        st.markdown("### Local Sources Used")
        render_source_list(result["sources"])

        st.markdown("### Guardrail Result")
        st.markdown(f"- Allowed: `{result['guardrails']['allowed']}`")
        warnings = result["guardrails"]["warnings"] or ["No guardrail warnings."]
        for warning in warnings:
            st.markdown(f"- {warning}")

        st.markdown("### Provider")
        st.markdown(
            "\n".join(
                [
                    f"- Provider: `{result['provider']}`",
                    f"- Model: `{result['model']}`",
                    f"- Setup required: `{result['setup_required']}`",
                    f"- Timed out: `{result['timed_out']}`",
                    f"- Status: {result['provider_message']}",
                ]
            )
        )

        st.markdown("### Retrieval Confidence")
        st.markdown(result["retrieval_confidence"])

        st.markdown("### Detected Intent")
        st.markdown(f"`{result.get('detected_intent', 'general_question')}`")

        st.markdown("### Limitations")
        for limitation in result["limitations"]:
            st.markdown(f"- {limitation}")

        st.markdown("### Safety Note")
        st.markdown(result["safety_note"])

    with st.expander("Raw Markdown Report", expanded=False):
        st.code(render_markdown(result), language="markdown")


def render_copilot_metadata_cards(result: dict) -> None:
    """Render compact metadata cards above a Copilot answer."""
    analysis = st.session_state.get("evidence_analysis")
    email_analysis = st.session_state.get("email_analysis")
    risk_scores = get_analysis_risk_scores(analysis) if analysis else []
    iocs = get_analysis_iocs(analysis) if analysis else []
    if email_analysis:
        highest_score = email_analysis.score.overall_score
        evidence_type = "Email threat analysis"
        ioc_count = len(email_analysis.iocs)
    else:
        highest_score = max([getattr(score, "score", 0) for score in risk_scores], default=0)
        evidence_type = getattr(analysis, "evidence_type", "No uploaded evidence") if analysis else "No uploaded evidence"
        ioc_count = len(iocs)
    card_values = [
        ("Detected Intent", result.get("detected_intent", "general_question")),
        ("Evidence Type", evidence_type),
        ("Highest Risk Score", highest_score),
        ("Number of IOCs", ioc_count),
        ("Source Count", len(result.get("sources", []))),
    ]
    columns = st.columns(len(card_values))
    for column, (label, value) in zip(columns, card_values):
        with column:
            st.metric(label, value)


def render_copilot_evidence_tables() -> None:
    """Render active evidence risk and IOC details alongside Copilot answers."""
    email_analysis = st.session_state.get("email_analysis")
    if email_analysis:
        st.markdown("### Email Risk Scores")
        st.dataframe(
            [{"Category": key, "Score": value} for key, value in get_email_category_scores(email_analysis).items()],
            width="stretch",
            hide_index=True,
        )
        st.markdown("### Email IOCs")
        st.dataframe(get_email_ioc_rows(email_analysis), width="stretch", hide_index=True)
        return

    analysis = st.session_state.get("evidence_analysis")
    if not analysis:
        return

    risk_scores = get_analysis_risk_scores(analysis)
    if risk_scores:
        st.markdown("### Evidence Risk Scores")
        risk_rows = [
            {
                "Rank": index,
                "Entity": getattr(score, "entity", "unknown"),
                "Type": getattr(score, "entity_type", "Unknown"),
                "Score": getattr(score, "score", 0),
                "Reasons": ", ".join(getattr(score, "reasons", [])[:8]),
            }
            for index, score in enumerate(risk_scores[:8], start=1)
        ]
        st.dataframe(risk_rows, width="stretch", hide_index=True)

    iocs = get_analysis_iocs(analysis)
    if iocs:
        st.markdown("### IOCs / Investigation Artifacts Observed")
        grouped_rows = [
            {
                "Type": getattr(item, "type", "Unknown"),
                "Value": getattr(item, "display_value", ""),
                "Source / Context": getattr(item, "source", ""),
                "Why It Matters": getattr(item, "why_it_matters", ""),
            }
            for item in iocs[:30]
        ]
        st.dataframe(grouped_rows, width="stretch", hide_index=True)


def extract_fenced_kql(markdown: str) -> str:
    """Return the first fenced KQL block from a Markdown answer."""
    marker = "```kql"
    if marker not in markdown:
        return ""
    after_marker = markdown.split(marker, 1)[1]
    content, separator, _ = after_marker.partition("```")
    if not separator:
        return ""
    return content.strip()


def render_source_list(sources: list[dict]) -> None:
    """Render retrieved local sources as readable source cards."""
    if not sources:
        st.write("No local sources used.")
        return

    for source in sources:
        heading = source.get("heading") or "Untitled section"
        source_type = classify_source_type(source["path"])
        with st.container(border=True):
            st.markdown(f"**{source_type}**")
            st.code(source["path"], language="text")
            st.caption(f"{heading} | score: {source['score']}")


def classify_source_type(path: str) -> str:
    """Return a friendly source type label for dashboard citations."""
    lowered = path.lower()
    if "docs/soc_playbooks/" in lowered:
        return "SOC Playbook"
    if "automation/kql/" in lowered:
        return "KQL Hunting Query"
    if "automation/powershell/" in lowered:
        return "Read-Only PowerShell Sample"
    if "automation/ticket-templates/" in lowered:
        return "Freshservice-Style Ticket Template"
    if "uploaded evidence summary" in lowered:
        return "Current Session Evidence Summary"
    return "Local Lab Source"


def build_history_summary(result: dict) -> str:
    """Build compact content for chat history state."""
    return "\n\n".join(
        [
            result["answer"],
            f"**Retrieval confidence:** {result['retrieval_confidence']}",
            result["safety_note"],
        ]
    )


if __name__ == "__main__":
    main()
