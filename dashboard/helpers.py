"""Shared helpers for the AI Security Lab Streamlit dashboard."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
MAX_UPLOAD_BYTES = 1_000_000
MAX_REPORT_CHARS = 60_000


@dataclass(frozen=True)
class ProjectConfig:
    display_name: str
    folder: str
    script_name: str
    description: str
    validate_function: str
    report_function: str
    input_label: str

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
        validate_function="validate_alert",
        report_function="generate_report",
        input_label="alert",
    ),
    "AI Phishing Analyzer": ProjectConfig(
        display_name="AI Phishing Analyzer",
        folder="02-ai-phishing-analyzer",
        script_name="phishing_analyzer.py",
        description="Analyze fake user-reported phishing emails with rule-based indicators.",
        validate_function="validate_email",
        report_function="generate_report",
        input_label="email",
    ),
    "Prompt Injection Lab": ProjectConfig(
        display_name="Prompt Injection Lab",
        folder="03-prompt-injection-lab",
        script_name="prompt_injection_lab.py",
        description="Evaluate safe sample prompt injection tests and expected defensive behavior.",
        validate_function="validate_prompt",
        report_function="generate_report",
        input_label="prompt",
    ),
    "AI Vendor Risk Toolkit": ProjectConfig(
        display_name="AI Vendor Risk Toolkit",
        folder="04-ai-vendor-risk-toolkit",
        script_name="vendor_risk_assessment.py",
        description="Create Markdown risk reports from fake AI vendor profiles.",
        validate_function="validate_vendor_profile",
        report_function="generate_report",
        input_label="vendor profile",
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


def load_project_module(project: ProjectConfig) -> ModuleType:
    """Load a project analyzer module from its script path."""
    if not project.script_path.is_file():
        raise FileNotFoundError(f"Analyzer script not found: {project.script_name}")

    module_name = f"dashboard_{project.folder.replace('-', '_')}"
    spec = importlib.util.spec_from_file_location(module_name, project.script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load analyzer script: {project.script_name}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_uploaded_json(uploaded_bytes: bytes) -> dict[str, Any]:
    """Parse uploaded JSON bytes without writing them to disk."""
    if not uploaded_bytes:
        raise ValueError("Uploaded JSON file is empty.")

    if len(uploaded_bytes) > MAX_UPLOAD_BYTES:
        raise ValueError("Uploaded JSON file is too large for this dashboard demo.")

    try:
        decoded = uploaded_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("Uploaded JSON file must be UTF-8 encoded.") from error

    try:
        payload = json.loads(decoded)
    except json.JSONDecodeError as error:
        raise ValueError(f"Uploaded file is not valid JSON: {error.msg}.") from error

    if not isinstance(payload, dict):
        raise ValueError("Uploaded JSON must contain one JSON object.")

    return payload


def generate_report_from_json(project: ProjectConfig, payload: dict[str, Any]) -> str:
    """Validate uploaded JSON and generate a Markdown report in memory."""
    module = load_project_module(project)
    validate = getattr(module, project.validate_function, None)
    generate = getattr(module, project.report_function, None)

    if not callable(validate) or not callable(generate):
        raise RuntimeError(f"Analyzer functions are not available for {project.display_name}.")

    try:
        validate(payload)
        report = generate(payload)
    except ValueError as error:
        raise ValueError(f"Uploaded {project.input_label} JSON is invalid: {error}") from error

    return limit_report(report)


def run_analyzer_for_sample(project: ProjectConfig, sample_path: Path) -> str:
    """Run a local analyzer script for a selected sample file."""
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

    return limit_report(result.stdout.strip())


def limit_report(report: str) -> str:
    """Limit very large Markdown reports for dashboard display."""
    if not report:
        raise RuntimeError("Analyzer completed but did not return a Markdown report.")

    if len(report) > MAX_REPORT_CHARS:
        return report[:MAX_REPORT_CHARS] + "\n\n_Report truncated for dashboard display._"

    return report
