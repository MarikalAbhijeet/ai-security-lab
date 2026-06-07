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


EXAMPLE_PROMPTS = {
    "Investigate risky sign-in": "What should an analyst check when investigating a risky sign-in?",
    "Generate suspicious PowerShell KQL": "What KQL should I use to hunt for suspicious PowerShell activity?",
    "Review phishing response steps": "What response steps should an analyst take for a suspected phishing email?",
    "Explain prompt injection controls": "How does prompt injection map to OWASP LLM Top 10, and what controls help?",
    "Review AI vendor risk": "What questions should we ask an AI vendor before approval?",
}


def main() -> None:
    st.set_page_config(page_title="AI Security Command Center", layout="wide")

    st.title("AI Security Command Center")
    st.caption(
        "Local-first AI/ML security operations platform using Ollama, RAG, ML anomaly detection, "
        "and sample SOC workflows."
    )

    reports_tab, evidence_tab, copilot_tab = st.tabs(
        ["Security Analysis Modules", "Threat Evidence Workbench", "Local SecOps Copilot"]
    )

    with reports_tab:
        render_project_reports()

    with evidence_tab:
        render_threat_evidence_workbench()

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
        st.info("Upload a fake/sample evidence file to generate a local report.")
        return

    st.write(f"Selected file: `{uploaded_file.name}`")
    st.caption("The uploaded file name is displayed for the current session only; the file is not written to disk.")

    if st.button("Analyze evidence", type="primary"):
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

    summary_left, summary_right = st.columns(2)
    with summary_left:
        st.metric("Detected Evidence Type", analysis.evidence_type)
        st.metric("Total Records/Lines", analysis.total_items)
    with summary_right:
        st.metric("Severity Recommendation", analysis.severity)
        st.metric("Suspicious Findings", len(analysis.findings))

    st.markdown("### Indicators and Investigation Artifacts")
    st.caption("All sample IOCs shown here are fake/demo values. URLs, domains, and IP-like values are defanged for display.")
    if analysis.iocs:
        ioc_types = ["All"] + sorted({item.type for item in analysis.iocs})
        selected_ioc_type = st.selectbox("IOC table filter", options=ioc_types, index=0)
        visible_iocs = analysis.iocs if selected_ioc_type == "All" else [
            item for item in analysis.iocs if item.type == selected_ioc_type
        ]
        ioc_rows = [
            {
                "Type": item.type,
                "Value": item.display_value,
                "Source / Context": item.source,
                "Why It Matters": item.why_it_matters,
            }
            for item in visible_iocs[:50]
        ]
        st.dataframe(ioc_rows, width="stretch", hide_index=True)
    else:
        st.write("No IOCs or investigation artifacts were extracted by the local rule set.")

    with st.expander("IOC Summary Counts", expanded=False):
        st.write(f"- Total IPs found: `{analysis.ioc_summary_counts['total_ips']}`")
        st.write(f"- Total URLs/domains found: `{analysis.ioc_summary_counts['total_urls_domains']}`")
        st.write(f"- Total users found: `{analysis.ioc_summary_counts['total_users']}`")
        st.write(f"- Total devices found: `{analysis.ioc_summary_counts['total_devices']}`")
        st.write(
            "- Total suspicious command indicators found: "
            f"`{analysis.ioc_summary_counts['total_suspicious_command_indicators']}`"
        )

    st.markdown("### Suspicious Findings")
    if analysis.findings:
        for finding in analysis.findings[:10]:
            with st.container(border=True):
                st.markdown(f"**{finding.title}** ({finding.severity})")
                st.write(finding.description)
                st.caption(f"MITRE ATT&CK: {finding.mitre_attack}")
    else:
        st.write("No suspicious findings were detected by the local rule set.")

    st.markdown("### Generated Evidence Report")
    st.markdown(analysis.markdown_report)
    with st.expander("Raw Markdown Evidence Report", expanded=False):
        st.code(analysis.markdown_report, language="markdown")

    st.info("Local SecOps Copilot will receive only the summarized evidence context, not the raw uploaded file.")
    if st.button("Ask Local SecOps Copilot about this evidence"):
        st.session_state["copilot_session_context"] = analysis.copilot_context
        st.session_state["pending_copilot_question"] = (
            "Analyze the uploaded evidence summary from the current session. "
            "What suspicious behavior should a SOC analyst prioritize?"
        )
        st.success("Evidence summary is ready for Local SecOps Copilot. Open the Copilot tab to review the answer.")


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
    with controls_right:
        st.write("")
        st.write("")
        if st.button("Clear chat"):
            st.session_state["copilot_messages"] = []
            st.rerun()

    st.markdown("**Example prompts**")
    prompt_columns = st.columns(len(EXAMPLE_PROMPTS))
    for column, (label, prompt) in zip(prompt_columns, EXAMPLE_PROMPTS.items()):
        with column:
            if st.button(label, use_container_width=True):
                st.session_state["pending_copilot_question"] = prompt
                st.rerun()

    for message in st.session_state["copilot_messages"]:
        with st.chat_message(message["role"]):
            if message["role"] == "assistant" and message.get("result"):
                render_copilot_answer_card(message["result"])
            else:
                st.markdown(message["content"])
            if message.get("sources") and not message.get("result"):
                with st.expander("Retrieved source files"):
                    render_source_list(message["sources"])

    question = st.session_state.pop("pending_copilot_question", None)
    chat_question = st.chat_input("Ask Local SecOps Copilot about the AI Security Lab")
    if chat_question:
        question = chat_question

    if question:
        st.session_state["copilot_messages"].append({"role": "user", "content": question})
        with st.chat_message("user"):
            st.markdown(question)

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

        history_content = build_history_summary(result)
        st.session_state["copilot_messages"].append(
            {
                "role": "assistant",
                "content": history_content,
                "sources": result["sources"],
                "result": result,
            }
        )
        with st.chat_message("assistant"):
            render_copilot_answer_card(result)


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
        st.markdown("### Answer")
        st.markdown(result["answer"])

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

        st.markdown("### Limitations")
        for limitation in result["limitations"]:
            st.markdown(f"- {limitation}")

        st.markdown("### Safety Note")
        st.markdown(result["safety_note"])

    with st.expander("Raw Markdown Report", expanded=False):
        st.code(render_markdown(result), language="markdown")


def render_source_list(sources: list[dict]) -> None:
    """Render retrieved local sources as readable bullets."""
    if not sources:
        st.write("No local sources used.")
        return

    for source in sources:
        heading = source.get("heading") or "Untitled section"
        st.markdown(f"- `{source['path']}` - {heading} (score: {source['score']})")


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
