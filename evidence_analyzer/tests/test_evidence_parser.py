"""Tests for evidence parsing and safety validation."""

import unittest

from evidence_parser import parse_evidence_file


class EvidenceParserTests(unittest.TestCase):
    def test_parse_csv_into_rows(self):
        content = b"user,failed_login_count,mfa_result\nalex@example.test,6,failed\n"
        document = parse_evidence_file("signin.csv", content)
        self.assertEqual(document.parsed_type, "csv")
        self.assertEqual(len(document.records), 1)
        self.assertEqual(document.records[0]["failed_login_count"], "6")

    def test_parse_json_into_records(self):
        content = b'{"alerts":[{"alertTitle":"Malware detected","alertSeverity":"High"}]}'
        document = parse_evidence_file("alert.json", content)
        self.assertEqual(document.parsed_type, "json")
        self.assertEqual(len(document.records), 1)
        self.assertEqual(document.records[0]["alertSeverity"], "High")

    def test_parse_txt_log_into_lines(self):
        content = b"line one\nline two\n"
        document = parse_evidence_file("events.log", content)
        self.assertEqual(document.parsed_type, "text")
        self.assertEqual(document.lines, ["line one", "line two"])

    def test_reject_unsupported_extension(self):
        with self.assertRaises(ValueError):
            parse_evidence_file("evidence.exe", b"not executable")

    def test_reject_path_traversal_file_name(self):
        with self.assertRaises(ValueError):
            parse_evidence_file("..\\secret.log", b"line")

    def test_block_sensitive_content(self):
        with self.assertRaises(ValueError) as context:
            parse_evidence_file("sample.log", b"password=NeverUseThis123")
        self.assertIn("Sensitive-looking content detected", str(context.exception))

    def test_reject_csv_rows_with_extra_columns(self):
        with self.assertRaises(ValueError) as context:
            parse_evidence_file("signin.csv", b"user,status\nalex@example.test,failed,extra\n")
        self.assertIn("more values than headers", str(context.exception))

    def test_reject_csv_rows_with_missing_values(self):
        with self.assertRaises(ValueError) as context:
            parse_evidence_file("signin.csv", b"user,status\nalex@example.test\n")
        self.assertIn("missing values", str(context.exception))


if __name__ == "__main__":
    unittest.main()
