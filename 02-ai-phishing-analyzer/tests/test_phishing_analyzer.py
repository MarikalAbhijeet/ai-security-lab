import unittest
from pathlib import Path

import phishing_analyzer


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class PhishingAnalyzerTests(unittest.TestCase):
    def test_loads_valid_sample_email(self):
        email_path = PROJECT_ROOT / "sample-inputs" / "microsoft-365-password-reset.json"

        email = phishing_analyzer.load_email(email_path)

        self.assertEqual(email["subject"], "Microsoft 365 password expires today")

    def test_high_risk_password_lure(self):
        email_path = PROJECT_ROOT / "sample-inputs" / "microsoft-365-password-reset.json"
        email = phishing_analyzer.load_email(email_path)

        analysis = phishing_analyzer.analyze_email(email)

        self.assertEqual(analysis["risk_rating"], "High")
        self.assertEqual(analysis["classification"], "Likely phishing")

    def test_low_risk_benign_it_notice(self):
        email_path = PROJECT_ROOT / "sample-inputs" / "benign-internal-it-notification.json"
        email = phishing_analyzer.load_email(email_path)

        analysis = phishing_analyzer.analyze_email(email)

        self.assertEqual(analysis["risk_rating"], "Low")
        self.assertEqual(analysis["classification"], "Likely benign")

    def test_generates_required_report_sections(self):
        email_path = PROJECT_ROOT / "sample-inputs" / "vendor-payment-change.json"
        email = phishing_analyzer.load_email(email_path)

        report = phishing_analyzer.generate_report(email)

        self.assertIn("## Risk Rating", report)
        self.assertIn("## Suspicious Indicators", report)
        self.assertIn("## Sample Data Safety Notes", report)
        self.assertIn("## MITRE ATT&CK Mapping", report)
        self.assertIn("## Freshservice-Style Ticket Note", report)

    def test_rejects_non_sample_url_domain(self):
        email = phishing_analyzer.load_email(
            PROJECT_ROOT / "sample-inputs" / "benign-internal-it-notification.json"
        )
        email["urls"] = ["https://real-domain.test/login"]

        with self.assertRaises(ValueError):
            phishing_analyzer.validate_email(email)

    def test_rejects_malformed_url(self):
        email = phishing_analyzer.load_email(
            PROJECT_ROOT / "sample-inputs" / "benign-internal-it-notification.json"
        )
        email["urls"] = ["https://internal-it.example.com@example.net/login"]

        with self.assertRaises(ValueError):
            phishing_analyzer.validate_email(email)

    def test_rejects_malformed_sender(self):
        email = phishing_analyzer.load_email(
            PROJECT_ROOT / "sample-inputs" / "benign-internal-it-notification.json"
        )
        email["sender"] = "not-an-email"

        with self.assertRaises(ValueError):
            phishing_analyzer.validate_email(email)

    def test_rejects_real_sender_domain(self):
        email = phishing_analyzer.load_email(
            PROJECT_ROOT / "sample-inputs" / "benign-internal-it-notification.json"
        )
        email["sender"] = "service-desk@real-domain.test"

        with self.assertRaises(ValueError):
            phishing_analyzer.validate_email(email)

    def test_rejects_malformed_timestamp(self):
        email = phishing_analyzer.load_email(
            PROJECT_ROOT / "sample-inputs" / "benign-internal-it-notification.json"
        )
        email["received_timestamp"] = "June 3rd at lunch"

        with self.assertRaises(ValueError):
            phishing_analyzer.validate_email(email)

    def test_rejects_non_list_urls(self):
        email = phishing_analyzer.load_email(
            PROJECT_ROOT / "sample-inputs" / "benign-internal-it-notification.json"
        )
        email["urls"] = "https://internal-it.example.com/status"

        with self.assertRaises(ValueError):
            phishing_analyzer.validate_email(email)

    def test_qr_image_attachment_is_suspicious_when_qr_lure_present(self):
        email = phishing_analyzer.load_email(PROJECT_ROOT / "sample-inputs" / "qr-code-phishing.json")

        analysis = phishing_analyzer.analyze_email(email)

        self.assertIn(
            "Image attachment may contain a QR phishing lure: mfa_qr_code.png",
            analysis["suspicious_indicators"],
        )

    def test_rejects_output_outside_sample_output(self):
        with self.assertRaises(ValueError):
            phishing_analyzer.save_report("sample report", PROJECT_ROOT / "report.md")

    def test_rejects_non_markdown_output(self):
        with self.assertRaises(ValueError):
            phishing_analyzer.save_report(
                "sample report",
                PROJECT_ROOT / "sample-output" / "report.txt",
            )


if __name__ == "__main__":
    unittest.main()
