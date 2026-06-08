"""Tests for email summarization and safe Copilot context."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from email_summarizer import analyze_email_file, enrichment_indicators  # noqa: E402


class EmailSummarizerTests(unittest.TestCase):
    def test_report_uses_email_verdict_instead_of_generic_summary(self):
        sample = PROJECT_ROOT / "sample-inputs" / "sample_phishing_email.eml"
        analysis = analyze_email_file(sample.name, sample.read_bytes())

        self.assertIn("## Email Verdict", analysis.markdown_report.split("## Agent / SOC Details")[0])
        self.assertNotIn("User-Friendly Summary", analysis.markdown_report)
        self.assertIn("**Verdict:**", analysis.markdown_report)
        self.assertIn("Freshservice-Style Ticket Note", analysis.markdown_report)

    def test_copilot_context_is_summarized_without_raw_body(self):
        sample = PROJECT_ROOT / "sample-inputs" / "sample_phishing_email.eml"
        raw_text = sample.read_text(encoding="utf-8")
        analysis = analyze_email_file(sample.name, sample.read_bytes())

        self.assertIn("Uploaded email analysis summary", analysis.copilot_context)
        self.assertIn("Raw email content was not included", analysis.copilot_context)
        self.assertNotIn("Open the secure SharePoint document and sign in here", analysis.copilot_context)
        self.assertNotEqual(raw_text, analysis.copilot_context)

    def test_email_report_kql_uses_clean_sender_variables(self):
        sample = PROJECT_ROOT / "sample-inputs" / "sample_phishing_email.eml"
        analysis = analyze_email_file(sample.name, sample.read_bytes())

        self.assertIn('let SenderAddress = "alerts@security-update.example.invalid";', analysis.markdown_report)
        self.assertIn('let SenderDomain = "security-update.example.invalid";', analysis.markdown_report)
        self.assertIn('let SubjectKeyword = "password expires";', analysis.markdown_report)
        self.assertNotIn('let Sender = "\"Microsoft 365 Support"', analysis.markdown_report)

    def test_ioc_rows_keep_attachment_out_of_domain_list(self):
        sample = PROJECT_ROOT / "sample-inputs" / "sample_phishing_email.eml"
        analysis = analyze_email_file(sample.name, sample.read_bytes())
        domain_values = [ioc.value for ioc in analysis.iocs if ioc.type == "Domain"]
        attachment_values = [ioc.value for ioc in analysis.iocs if ioc.type == "Attachment"]

        self.assertNotIn("secure-message[.]html", domain_values)
        self.assertIn("secure-message[.]html", attachment_values)

    def test_online_enrichment_receives_only_extracted_indicators(self):
        sample = PROJECT_ROOT / "sample-inputs" / "sample_phishing_email.eml"
        analysis = analyze_email_file(sample.name, sample.read_bytes())
        indicators = enrichment_indicators(analysis.iocs)
        joined = "\n".join(item["value"] for item in indicators)

        self.assertTrue(indicators)
        self.assertNotIn("Open the secure SharePoint document and sign in here", joined)
        self.assertNotIn("Authentication-Results", joined)
        self.assertNotIn("smtp.mailfrom", joined)
        self.assertNotIn("secure-message[.]html", joined)
        self.assertTrue(all(item["type"] in {"URL", "Domain", "IP Address", "Hash"} for item in indicators))

    def test_copilot_context_includes_safe_online_enrichment_summary_only(self):
        sample = PROJECT_ROOT / "sample-inputs" / "sample_phishing_email.eml"
        with patch.dict("os.environ", {"GOOGLE_SAFE_BROWSING_API_KEY": "", "URLHAUS_AUTH_KEY": ""}, clear=False):
            analysis = analyze_email_file(sample.name, sample.read_bytes(), online_enrichment_enabled=True)

        self.assertIn("Online enrichment summary:", analysis.copilot_context)
        self.assertIn("Google Safe Browsing", analysis.copilot_context)
        self.assertIn("URLhaus", analysis.copilot_context)
        self.assertIn("Raw email body, raw headers, attachments, and files were not sent", analysis.copilot_context)
        self.assertNotIn("Open the secure SharePoint document and sign in here", analysis.copilot_context)


if __name__ == "__main__":
    unittest.main()
