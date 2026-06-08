"""Tests for safe email parsing."""

import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from email_parser import parse_email_file, parse_pasted_text  # noqa: E402


class EmailParserTests(unittest.TestCase):
    def test_parse_eml_extracts_headers_body_urls_and_attachments(self):
        sample = PROJECT_ROOT / "sample-inputs" / "sample_phishing_email.eml"
        parsed = parse_email_file(sample.name, sample.read_bytes())

        self.assertIn("Microsoft 365 Support", parsed.from_address)
        self.assertEqual(parsed.spf_result, "fail")
        self.assertEqual(parsed.dkim_result, "fail")
        self.assertEqual(parsed.dmarc_result, "fail")
        self.assertTrue(parsed.urls)
        self.assertTrue(parsed.domains)
        self.assertTrue(any(item.name == "secure-message.html" for item in parsed.attachments))

    def test_rejects_unsupported_extension(self):
        with self.assertRaises(ValueError):
            parse_email_file("sample.exe", b"not allowed")

    def test_pasted_headers_parse_authentication_results(self):
        text = (PROJECT_ROOT / "sample-inputs" / "sample_email_headers.txt").read_text(encoding="utf-8")
        parsed = parse_pasted_text(text, source_type="headers")

        self.assertEqual(parsed.spf_result, "softfail")
        self.assertEqual(parsed.dmarc_result, "fail")
        self.assertIn("DocuSign", parsed.from_address)

    def test_domain_extraction_filters_parser_artifacts_and_attachments(self):
        sample = PROJECT_ROOT / "sample-inputs" / "sample_phishing_email.eml"
        parsed = parse_email_file(sample.name, sample.read_bytes())

        self.assertIn("security-update.example.invalid", parsed.domains)
        self.assertIn("helpdesk-example.invalid", parsed.domains)
        self.assertIn("mailer-example.invalid", parsed.domains)
        self.assertIn("microsoft-sharepoint-login.example.invalid", parsed.domains)
        self.assertNotIn("smtp.mailfrom", parsed.domains)
        self.assertNotIn("header.from", parsed.domains)
        self.assertNotIn("2fexample.invalid", parsed.domains)
        self.assertNotIn("secure-message.html", parsed.domains)


if __name__ == "__main__":
    unittest.main()
