"""Streamlit dashboard for the AI Security Lab sample analyzers."""

from __future__ import annotations

import streamlit as st

from helpers import (
    PROJECTS,
    generate_report_from_json,
    list_sample_files,
    load_uploaded_json,
    run_analyzer_for_sample,
    validate_sample_file,
)


def main() -> None:
    st.set_page_config(page_title="AI Security Lab Dashboard", layout="wide")

    st.title("AI Security Lab Dashboard")
    st.caption("Local-only dashboard for fake/sample security lab data. No paid APIs or live systems are used.")

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


if __name__ == "__main__":
    main()
