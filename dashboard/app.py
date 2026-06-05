"""Streamlit dashboard for the AI Security Lab sample analyzers."""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import streamlit as st


REPO_ROOT = Path(__file__).resolve().parents[1]
MAX_REPORT_CHARS = 60_000


@dataclass(frozen=True)
class ProjectConfig:
    display_name: str
    folder: str
    script_name: str
    description: str

    @property
    def project_dir(self) -> Path:
        return REPO_ROOT / self.folder

    @property
    def script_path(self) -> Path:
        return self.project_dir / self.script_name

    @property
    def sample_input_dir(self) -> Path:
        return self.project_dir / "sample-inputs"


PROJECTS = {
    "AI SOC Assistant": ProjectConfig(
        display_name="AI SOC Assistant",
        folder="01-ai-soc-assistant",
        script_name="triage_assistant.py",
        description="Generate a SOC alert triage report from fake Defender/Sentinel-style alerts.",
    ),
    "AI Phishing Analyzer": ProjectConfig(
        display_name="AI Phishing Analyzer",
        folder="02-ai-phishing-analyzer",
        script_name="phishing_analyzer.py",
        description="Analyze fake user-reported phishing emails with rule-based indicators.",
    ),
    "Prompt Injection Lab": ProjectConfig(
        display_name="Prompt Injection Lab",
        folder="03-prompt-injection-lab",
        script_name="prompt_injection_lab.py",
        description="Evaluate safe sample prompt injection tests and expected defensive behavior.",
    ),
    "AI Vendor Risk Toolkit": ProjectConfig(
        display_name="AI Vendor Risk Toolkit",
        folder="04-ai-vendor-risk-toolkit",
        script_name="vendor_risk_assessment.py",
        description="Create Markdown risk reports from fake AI vendor profiles.",
    ),
}


def list_sample_files(project: ProjectConfig) -> list[Path]:
    """Return JSON sample files for a project."""
    if not project.sample_input_dir.is_dir():
        return []

    return sorted(path for path in project.sample_input_dir.glob("*.json") if path.is_file())


def validate_sample_file(project: ProjectConfig, selected_name: str) -> Path:
    """Resolve a selected sample file and ensure it stays in sample-inputs."""
    allowed_files = {path.name: path for path in list_sample_files(project)}
    if selected_name not in allowed_files:
        raise ValueError("Select a valid sample JSON file from the project sample-inputs folder.")

    sample_path = allowed_files[selected_name].resolve()
    sample_root = project.sample_input_dir.resolve()
    if sample_root not in sample_path.parents:
        raise ValueError("Selected sample file must stay inside the project sample-inputs folder.")

    return sample_path


def run_analyzer(project: ProjectConfig, sample_path: Path) -> str:
    """Run a local analyzer script and return the generated Markdown report."""
    if not project.script_path.is_file():
        raise FileNotFoundError(f"Analyzer script not found: {project.script_name}")

    try:
        result = subprocess.run(
            [sys.executable, str(project.script_path), str(sample_path)],
            cwd=project.project_dir,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("Analyzer timed out while generating the report.") from error
    except OSError as error:
        raise RuntimeError(f"Unable to start analyzer: {error}") from error

    if result.returncode != 0:
        error_text = (result.stderr or result.stdout or "Unknown analyzer error.").strip()
        raise RuntimeError(error_text[:2_000])

    report = result.stdout.strip()
    if not report:
        raise RuntimeError("Analyzer completed but did not return a Markdown report.")

    if len(report) > MAX_REPORT_CHARS:
        return report[:MAX_REPORT_CHARS] + "\n\n_Report truncated for dashboard display._"

    return report


def main() -> None:
    st.set_page_config(page_title="AI Security Lab Dashboard", layout="wide")

    st.title("AI Security Lab Dashboard")
    st.caption("Local-only dashboard for fake/sample security lab data. No paid APIs or live systems are used.")

    project_name = st.selectbox("Project", options=list(PROJECTS.keys()))
    project = PROJECTS[project_name]
    st.write(project.description)

    sample_files = list_sample_files(project)
    if not sample_files:
        st.error("No sample JSON files were found for this project.")
        return

    selected_sample = st.selectbox("Sample input JSON", options=[path.name for path in sample_files])

    with st.expander("Sample file path", expanded=False):
        st.code(str(project.sample_input_dir / selected_sample), language="text")

    if st.button("Generate report", type="primary"):
        try:
            sample_path = validate_sample_file(project, selected_sample)
            report = run_analyzer(project, sample_path)
        except (ValueError, FileNotFoundError, RuntimeError) as error:
            st.error(str(error))
            return

        st.subheader("Generated Markdown Report")
        st.markdown(report)
        with st.expander("Raw Markdown"):
            st.code(report, language="markdown")


if __name__ == "__main__":
    main()
