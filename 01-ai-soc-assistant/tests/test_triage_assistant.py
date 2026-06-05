import unittest
import shutil
import subprocess
import sys
from pathlib import Path

import triage_assistant


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TEST_BATCH_DIR = PROJECT_ROOT / "sample-output" / "test-batch"


class TriageAssistantTests(unittest.TestCase):
    def test_loads_valid_sample_alert(self):
        alert_path = PROJECT_ROOT / "sample-inputs" / "risky-sign-in.json"

        alert = triage_assistant.load_alert(alert_path)

        self.assertEqual(alert["alert_type"], "risky_sign_in")

    def test_generates_required_report_sections(self):
        alert_path = PROJECT_ROOT / "sample-inputs" / "suspicious-powershell.json"
        alert = triage_assistant.load_alert(alert_path)

        report = triage_assistant.generate_report(alert)

        self.assertIn("## Short Incident Summary", report)
        self.assertIn("## KQL Hunting Query", report)
        self.assertIn("## Freshservice-Style Ticket Update", report)
        self.assertIn("T1059.001 - PowerShell", report)

    def test_rejects_missing_required_field(self):
        bad_alert = {
            "alert_type": "risky_sign_in",
            "title": "Missing required fields",
        }

        with self.assertRaises(ValueError):
            triage_assistant.validate_alert(bad_alert)

    def test_rejects_output_outside_sample_output(self):
        with self.assertRaises(ValueError):
            triage_assistant.save_report("sample report", PROJECT_ROOT / "report.md")

    def test_rejects_non_markdown_output(self):
        with self.assertRaises(ValueError):
            triage_assistant.save_report(
                "sample report",
                PROJECT_ROOT / "sample-output" / "report.txt",
            )

    def test_batch_generates_one_report_per_sample_alert(self):
        shutil.rmtree(TEST_BATCH_DIR, ignore_errors=True)
        try:
            saved_reports = triage_assistant.generate_batch_reports(TEST_BATCH_DIR)
            sample_count = len(list((PROJECT_ROOT / "sample-inputs").glob("*.json")))

            self.assertEqual(len(saved_reports), sample_count)
            self.assertTrue((TEST_BATCH_DIR / "risky-sign-in-triage-report.md").exists())
        finally:
            shutil.rmtree(TEST_BATCH_DIR, ignore_errors=True)

    def test_rejects_batch_output_dir_outside_sample_output(self):
        with self.assertRaises(ValueError):
            triage_assistant.generate_batch_reports(PROJECT_ROOT / "batch-output")

    def test_cli_batch_defaults_to_batch_output_folder(self):
        batch_dir = PROJECT_ROOT / "sample-output" / "batch"
        shutil.rmtree(batch_dir, ignore_errors=True)
        try:
            result = subprocess.run(
                [sys.executable, "-B", "triage_assistant.py", "--batch"],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("sample-output", result.stdout)
            self.assertTrue((batch_dir / "risky-sign-in-triage-report.md").exists())
        finally:
            shutil.rmtree(batch_dir, ignore_errors=True)

    def test_cli_rejects_batch_with_single_file_argument(self):
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                "triage_assistant.py",
                "--batch",
                "sample-inputs/risky-sign-in.json",
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--batch cannot be used", result.stderr)


if __name__ == "__main__":
    unittest.main()
