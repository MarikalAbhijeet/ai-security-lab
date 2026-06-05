import unittest
import shutil
import subprocess
import sys
from pathlib import Path

import prompt_injection_lab


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TEST_BATCH_DIR = PROJECT_ROOT / "sample-output" / "test-batch"


class PromptInjectionLabTests(unittest.TestCase):
    def test_loads_valid_sample_prompt(self):
        prompt = prompt_injection_lab.load_prompt(
            PROJECT_ROOT / "sample-inputs" / "direct-instruction-override.json"
        )

        self.assertEqual(prompt["test_id"], "PI-001")

    def test_direct_override_is_high_risk(self):
        prompt = prompt_injection_lab.load_prompt(
            PROJECT_ROOT / "sample-inputs" / "direct-instruction-override.json"
        )

        result = prompt_injection_lab.evaluate_prompt(prompt)

        self.assertEqual(result["risk_rating"], "High")
        self.assertEqual(result["pass_fail_result"], "Pass")

    def test_role_play_jailbreak_is_medium_risk(self):
        prompt = prompt_injection_lab.load_prompt(
            PROJECT_ROOT / "sample-inputs" / "role-play-jailbreak.json"
        )

        result = prompt_injection_lab.evaluate_prompt(prompt)

        self.assertEqual(result["risk_rating"], "Medium")
        self.assertIn("Role-Play Jailbreak", result["attack_type"])

    def test_benign_prompt_is_low_risk(self):
        prompt = prompt_injection_lab.load_prompt(
            PROJECT_ROOT / "sample-inputs" / "benign-normal-prompt.json"
        )

        result = prompt_injection_lab.evaluate_prompt(prompt)

        self.assertEqual(result["risk_rating"], "Low")
        self.assertEqual(result["attack_type"], "Benign / No injection detected")
        self.assertEqual(result["pass_fail_result"], "Pass")

    def test_generates_required_report_sections(self):
        prompt = prompt_injection_lab.load_prompt(
            PROJECT_ROOT / "sample-inputs" / "system-prompt-extraction.json"
        )

        report = prompt_injection_lab.generate_report(prompt)

        self.assertIn("## Risk Rating", report)
        self.assertIn("## OWASP LLM Top 10 Mapping", report)
        self.assertIn("## MITRE ATLAS-Style Mapping", report)
        self.assertIn("## Pass/Fail Result", report)

    def test_rejects_missing_required_field(self):
        bad_prompt = {
            "test_id": "BAD-001",
            "title": "Missing fields",
        }

        with self.assertRaises(ValueError):
            prompt_injection_lab.validate_prompt(bad_prompt)

    def test_rejects_invalid_expected_risk_level(self):
        prompt = prompt_injection_lab.load_prompt(
            PROJECT_ROOT / "sample-inputs" / "benign-normal-prompt.json"
        )
        prompt["expected_risk_level"] = "Severe"

        with self.assertRaises(ValueError):
            prompt_injection_lab.validate_prompt(prompt)

    def test_rejects_output_outside_sample_output(self):
        with self.assertRaises(ValueError):
            prompt_injection_lab.save_report("sample report", PROJECT_ROOT / "report.md")

    def test_rejects_non_markdown_output(self):
        with self.assertRaises(ValueError):
            prompt_injection_lab.save_report(
                "sample report",
                PROJECT_ROOT / "sample-output" / "report.txt",
            )

    def test_batch_generates_one_report_per_sample_prompt(self):
        shutil.rmtree(TEST_BATCH_DIR, ignore_errors=True)
        try:
            saved_reports = prompt_injection_lab.generate_batch_reports(TEST_BATCH_DIR)
            sample_count = len(list((PROJECT_ROOT / "sample-inputs").glob("*.json")))

            self.assertEqual(len(saved_reports), sample_count)
            self.assertTrue((TEST_BATCH_DIR / "direct-instruction-override-report.md").exists())
        finally:
            shutil.rmtree(TEST_BATCH_DIR, ignore_errors=True)

    def test_rejects_batch_output_dir_outside_sample_output(self):
        with self.assertRaises(ValueError):
            prompt_injection_lab.generate_batch_reports(PROJECT_ROOT / "batch-output")

    def test_cli_batch_defaults_to_batch_output_folder(self):
        batch_dir = PROJECT_ROOT / "sample-output" / "batch"
        shutil.rmtree(batch_dir, ignore_errors=True)
        try:
            result = subprocess.run(
                [sys.executable, "-B", "prompt_injection_lab.py", "--batch"],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("sample-output", result.stdout)
            self.assertTrue((batch_dir / "direct-instruction-override-report.md").exists())
        finally:
            shutil.rmtree(batch_dir, ignore_errors=True)

    def test_cli_rejects_batch_with_single_file_argument(self):
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                "prompt_injection_lab.py",
                "--batch",
                "sample-inputs/direct-instruction-override.json",
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--batch cannot be used", result.stderr)


if __name__ == "__main__":
    unittest.main()
