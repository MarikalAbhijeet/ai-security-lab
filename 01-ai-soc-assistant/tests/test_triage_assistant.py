import unittest
from pathlib import Path

import triage_assistant


PROJECT_ROOT = Path(__file__).resolve().parents[1]


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


if __name__ == "__main__":
    unittest.main()
