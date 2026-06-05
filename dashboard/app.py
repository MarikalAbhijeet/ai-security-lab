"""Streamlit dashboard for the AI Security Lab sample analyzers."""

from __future__ import annotations

import sys
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

from copilot_assistant import answer_question, render_markdown  # noqa: E402


def main() -> None:
    st.set_page_config(page_title="AI Security Lab Dashboard", layout="wide")

    st.title("AI Security Lab Dashboard")
    st.caption("Local-only dashboard for fake/sample security lab data. No paid APIs or live systems are used.")

    reports_tab, copilot_tab = st.tabs(["Project Reports", "Security Copilot Chat"])

    with reports_tab:
        render_project_reports()

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


def render_copilot_chat() -> None:
    st.subheader("Security Copilot Chat")
    st.write("Ask questions about this repository's local documentation, sample reports, and framework notes.")
    st.warning(
        "Do not enter real secrets, passwords, tokens, company data, client data, tenant data, "
        "or vendor confidential data. Answers use local lab files only."
    )

    question = st.text_area(
        "Question",
        value="Summarize the SOC triage guidance for suspicious script activity.",
        height=100,
    )
    top_k = st.slider("Retrieved sources", min_value=1, max_value=10, value=5)

    if st.button("Ask Security Copilot", type="primary"):
        try:
            result = answer_question(question, index_root=Path(REPO_ROOT), top_k=top_k)
            markdown = render_markdown(result)
        except ValueError as error:
            st.error(str(error))
            return

        st.markdown(markdown)
        with st.expander("Retrieved source files"):
            for source in result["sources"]:
                st.write(f"- `{source['path']}` (score: {source['score']})")


if __name__ == "__main__":
    main()
