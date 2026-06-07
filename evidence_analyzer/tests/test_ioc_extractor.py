"""Tests for IOC and investigation artifact extraction."""

import unittest

from evidence_parser import EvidenceDocument
from ioc_extractor import extract_iocs


class IOCExtractorTests(unittest.TestCase):
    def extract_values(self, text):
        document = EvidenceDocument("events.log", ".log", "text", records=[], lines=[text])
        return extract_iocs(document)

    def test_ip_extraction(self):
        iocs = self.extract_values("source_ip=203.0.113.55 destination_ip=198.51.100.10")
        values = {item.value for item in iocs if item.type == "IP Address"}
        self.assertIn("203.0.113.55", values)
        self.assertIn("198.51.100.10", values)

    def test_url_and_domain_extraction(self):
        iocs = self.extract_values("url=https://login.example.test/update.ps1")
        values = {item.value for item in iocs}
        displays = {item.display_value for item in iocs}
        self.assertIn("https://login.example.test/update.ps1", values)
        self.assertIn("login.example.test", values)
        self.assertIn("hxxps://login[.]example[.]test/update[.]ps1", displays)

    def test_email_user_extraction(self):
        iocs = self.extract_values("user=devon.kim@example.test")
        self.assertIn("devon.kim@example.test", {item.value for item in iocs if item.type == "User"})

    def test_process_extraction(self):
        iocs = self.extract_values("device=LAB-ENDPOINT-02 parent_process=WINWORD.EXE process=powershell.exe")
        values = {item.value.lower() for item in iocs if item.type in {"Process", "Parent Process"}}
        displays = {item.display_value for item in iocs if item.type in {"Process", "Parent Process"}}
        devices = {item.value for item in iocs if item.type == "Device / Host"}
        self.assertIn("LAB-ENDPOINT-02", devices)
        self.assertIn("winword.exe", values)
        self.assertIn("powershell.exe", values)
        self.assertIn("WINWORD.EXE", displays)

    def test_powershell_indicator_extraction(self):
        iocs = self.extract_values("powershell.exe -ExecutionPolicy Bypass -EncodedCommand AAA Invoke-WebRequest")
        values = {item.value for item in iocs if item.type == "Command-Line Indicator"}
        self.assertIn("EncodedCommand", values)
        self.assertIn("-ExecutionPolicy Bypass", values)
        self.assertIn("Invoke-WebRequest", values)

    def test_hash_extraction(self):
        sha256 = "0" * 64
        iocs = self.extract_values(f"sha256={sha256}")
        self.assertIn(sha256, {item.value for item in iocs if item.type == "SHA256"})
        self.assertNotIn(sha256[:32], {item.value for item in iocs if item.type == "MD5"})

    def test_email_and_url_do_not_create_parent_domain_noise(self):
        iocs = self.extract_values("user=devon.kim@example.test url=https://login.example.test/a.ps1")
        domains = {item.value for item in iocs if item.type == "Domain"}
        self.assertIn("login.example.test", domains)
        self.assertNotIn("example.test", domains)

    def test_safe_source_context_label(self):
        iocs = self.extract_values("device=LAB-ENDPOINT-02 user=devon.kim@example.test process=powershell.exe")
        sources = {item.source for item in iocs}
        self.assertTrue(any("device=LAB-ENDPOINT-02" in source for source in sources))


if __name__ == "__main__":
    unittest.main()
