"""Tests for dashboard helper behavior."""

import json
import unittest
from pathlib import Path

import sys


DASHBOARD_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DASHBOARD_ROOT))

from helpers import (  # noqa: E402
    PROJECTS,
    build_sample_command,
    generate_report_from_json,
    list_sample_files,
    load_uploaded_json,
    validate_sample_file,
)
from app import (  # noqa: E402
    extract_fenced_kql,
    get_analysis_findings,
    get_analysis_ioc_counts,
    get_analysis_risk_scores,
    get_highest_priority_finding,
)


class DashboardHelperTests(unittest.TestCase):
    def test_sample_file_validation_allows_known_sample(self):
        project = PROJECTS["AI SOC Assistant"]
        sample_name = "risky-sign-in.json"

        sample_path = validate_sample_file(project, sample_name)

        self.assertEqual(sample_path.name, sample_name)
        self.assertIn(project.sample_input_dir.resolve(), sample_path.parents)

    def test_sample_file_validation_rejects_unknown_name(self):
        project = PROJECTS["AI SOC Assistant"]

        with self.assertRaises(ValueError):
            validate_sample_file(project, "..\\outside.json")

    def test_uploaded_json_must_be_valid_json_object(self):
        with self.assertRaises(ValueError):
            load_uploaded_json(b"{not-json")

        with self.assertRaises(ValueError):
            load_uploaded_json(b'["not", "an", "object"]')

    def test_uploaded_json_generates_soc_report_in_memory(self):
        project = PROJECTS["AI SOC Assistant"]
        sample_path = project.sample_input_dir / "risky-sign-in.json"
        payload = load_uploaded_json(sample_path.read_bytes())

        report = generate_report_from_json(project, payload)

        self.assertIn("# SOC Alert Triage Report", report)
        self.assertIn("## KQL Hunting Query", report)

    def test_uploaded_json_missing_required_fields_is_friendly_error(self):
        project = PROJECTS["AI Phishing Analyzer"]
        payload = {"sender": "notice@example.test"}

        with self.assertRaises(ValueError) as context:
            generate_report_from_json(project, payload)

        self.assertIn("Uploaded email JSON is invalid", str(context.exception))
        self.assertIn("missing required fields", str(context.exception))

    def test_uploaded_vendor_profile_does_not_require_sample_path(self):
        project = PROJECTS["AI Vendor Risk Toolkit"]
        sample_path = project.sample_input_dir / "fabrikam-support-copilot.json"
        payload = json.loads(sample_path.read_text(encoding="utf-8"))

        report = generate_report_from_json(project, payload)

        self.assertIn("# AI Vendor Risk Assessment Report", report)
        self.assertIn("Fabrikam Support Copilot", report)

    def test_sample_files_exist_for_all_projects(self):
        for project in PROJECTS.values():
            with self.subTest(project=project.display_name):
                self.assertGreater(len(list_sample_files(project)), 0)

    def test_ml_project_uses_csv_sample_files(self):
        project = PROJECTS["ML Anomaly Detection"]
        sample_files = list_sample_files(project)

        self.assertEqual(project.sample_extension, ".csv")
        self.assertFalse(project.upload_enabled)
        self.assertTrue(any(path.name == "synthetic_signin_logs.csv" for path in sample_files))

    def test_ml_project_sample_command_uses_input_option(self):
        project = PROJECTS["ML Anomaly Detection"]
        sample_path = validate_sample_file(project, "synthetic_signin_logs.csv")
        command = build_sample_command(project, sample_path)

        self.assertIn("--input", command)
        self.assertIn(str(sample_path), command)

    def test_dashboard_analysis_helpers_handle_missing_optional_fields(self):
        class MinimalAnalysis:
            pass

        analysis = MinimalAnalysis()

        self.assertEqual(get_analysis_risk_scores(analysis), [])
        self.assertEqual(get_analysis_ioc_counts(analysis)["total_ips"], 0)
        self.assertIn("No suspicious behavior", get_highest_priority_finding(analysis))

    def test_dashboard_filters_streamlit_delta_generator_like_behaviors(self):
        class DeltaGenerator:
            __module__ = "streamlit.delta_generator"

        class Finding:
            title = "Failed MFA"
            severity = "Medium"
            mitre_attack = "Credential Access"
            recommendation = "Review MFA context."

        class Analysis:
            findings = [DeltaGenerator(), Finding()]

        findings = get_analysis_findings(Analysis())

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "Failed MFA")

    def test_extract_fenced_kql_returns_query_only(self):
        answer = "### Recommended KQL\n```kql\nSigninLogs\n| take 10\n```\nMore text"

        query = extract_fenced_kql(answer)

        self.assertEqual(query, "SigninLogs\n| take 10")

    def test_extract_fenced_kql_handles_missing_block(self):
        self.assertEqual(extract_fenced_kql("No query here."), "")


if __name__ == "__main__":
    unittest.main()
