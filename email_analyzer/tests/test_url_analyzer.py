"""Tests for URL analysis and defanging."""

import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from url_analyzer import analyze_urls, defang  # noqa: E402


class URLAnalyzerTests(unittest.TestCase):
    def test_defangs_urls_and_domains(self):
        self.assertEqual(defang("https://example.invalid/path"), "hxxps://example[.]invalid/path")

    def test_detects_suspicious_url_indicators(self):
        findings = analyze_urls(
            ["https://microsoft-login.example.invalid/reset?redirect=https%3A%2F%2Fexample.invalid&continue=sample"],
            ["microsoft-login.example.invalid"],
        )
        reasons = " ".join(finding.reason for finding in findings)

        self.assertIn("credential", reasons.lower())
        self.assertIn("brand impersonation", reasons.lower())

    def test_duplicate_url_findings_are_grouped(self):
        findings = analyze_urls(
            ["https://microsoft-sharepoint-login.example.invalid/reset?redirect=https%3A%2F%2Fexample.invalid&continue=sample"],
            ["microsoft-sharepoint-login.example.invalid"],
        )
        url_rows = [finding for finding in findings if finding.display_value == "hxxps://microsoft-sharepoint-login[.]example[.]invalid/reset"]

        self.assertEqual(len(url_rows), 1)
        self.assertEqual(url_rows[0].severity, "High")
        self.assertIn("redirect-looking parameters", url_rows[0].reason)
        self.assertIn("credential/login keywords", url_rows[0].reason)
        self.assertIn("suspicious query parameters", url_rows[0].reason)
        self.assertIn("brand impersonation", url_rows[0].reason)


if __name__ == "__main__":
    unittest.main()
