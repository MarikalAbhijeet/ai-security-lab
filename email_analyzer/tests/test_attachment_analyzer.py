"""Tests for attachment metadata checks."""

import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from attachment_analyzer import analyze_attachments  # noqa: E402
from email_parser import AttachmentMetadata  # noqa: E402


class AttachmentAnalyzerTests(unittest.TestCase):
    def test_flags_html_zip_and_double_extension(self):
        findings = analyze_attachments(
            [
                AttachmentMetadata(name="secure-message.html", extension=".html"),
                AttachmentMetadata(name="invoice.pdf.exe", extension=".exe"),
                AttachmentMetadata(name="invoice.zip", extension=".zip", notes="password protected"),
            ]
        )
        joined = " ".join(finding.reason for finding in findings).lower()

        self.assertIn("phishing delivery", joined)
        self.assertIn("double extension", joined)
        self.assertIn("password-protected", joined)

    def test_duplicate_attachment_findings_are_grouped(self):
        findings = analyze_attachments([AttachmentMetadata(name="secure-message.html", extension=".html")])
        secure_rows = [finding for finding in findings if finding.name == "secure-message.html"]

        self.assertEqual(len(secure_rows), 1)
        self.assertEqual(secure_rows[0].severity, "Medium")
        self.assertIn("phishing delivery", secure_rows[0].reason)
        self.assertIn("secure-message lure language", secure_rows[0].reason)


if __name__ == "__main__":
    unittest.main()
