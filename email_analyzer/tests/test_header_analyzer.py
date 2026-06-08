"""Tests for header analysis."""

import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from email_parser import parse_email_file  # noqa: E402
from header_analyzer import analyze_headers  # noqa: E402


class HeaderAnalyzerTests(unittest.TestCase):
    def test_detects_auth_failures_and_reply_to_mismatch(self):
        sample = PROJECT_ROOT / "sample-inputs" / "sample_phishing_email.eml"
        findings = analyze_headers(parse_email_file(sample.name, sample.read_bytes()))
        titles = [finding.title for finding in findings]

        self.assertIn("From and Reply-To mismatch", titles)
        self.assertIn("SPF fail", titles)
        self.assertIn("DKIM fail", titles)
        self.assertIn("DMARC fail", titles)


if __name__ == "__main__":
    unittest.main()

