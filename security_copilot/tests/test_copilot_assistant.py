"""Tests for the local-first Security Copilot orchestration."""

import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PROJECT_ROOT.parent
sys.path.insert(0, str(PROJECT_ROOT))

from config import CopilotConfig, load_config  # noqa: E402
from copilot_assistant import answer_question, render_markdown, resolve_output_path, validate_answer_mode  # noqa: E402


class CopilotAssistantTests(unittest.TestCase):
    def test_load_config_defaults_to_ollama_model(self):
        config = load_config({})

        self.assertEqual(config.provider, "ollama")
        self.assertEqual(config.ollama_model, "qwen2.5:3b")
        self.assertEqual(config.ollama_timeout_seconds, 180)
        self.assertEqual(config.ollama_health_timeout_seconds, 10)
        self.assertFalse(config.test_mode)

    def test_invalid_provider_is_rejected(self):
        with self.assertRaises(ValueError):
            load_config({"COPILOT_PROVIDER": "paid-cloud"})

    def test_non_loopback_ollama_url_is_rejected(self):
        with self.assertRaises(ValueError):
            load_config({"OLLAMA_BASE_URL": "https://example.test:11434"})

    def test_invalid_timeout_is_rejected(self):
        with self.assertRaises(ValueError):
            load_config({"OLLAMA_TIMEOUT_SECONDS": "0"})

    def test_mock_mode_answer_includes_sources_and_safety_note(self):
        config = CopilotConfig(provider="mock", test_mode=True)

        result = answer_question(
            "How does prompt injection map to OWASP LLM Top 10?",
            answer_mode="AI Security Review",
            top_k=4,
            index_root=REPO_ROOT,
            config=config,
        )

        self.assertIn("Mock AI Security Review answer", result["answer"])
        self.assertGreater(len(result["sources"]), 0)
        self.assertIn("Do not enter secrets", result["safety_note"])
        self.assertEqual(result["provider"], "mock")

    def test_session_evidence_context_is_cited_without_indexing_raw_file(self):
        config = CopilotConfig(provider="mock", test_mode=True)
        session_context = (
            "Uploaded evidence summary from current session.\n"
            "File name: sample_powershell_events.log\n"
            "IOCs / Investigation Artifacts Observed:\n"
            "- Process: powershell.exe; Source: Line 1; Why it matters: Process artifact.\n"
            "- Command-Line Indicator: EncodedCommand; Source: Line 1; Why it matters: Suspicious PowerShell.\n"
            "Suspicious behaviors:\n"
            "Suspicious indicators:\n"
            "- Encoded PowerShell command (High): encoded command observed."
        )

        result = answer_question(
            "Based on the uploaded evidence, list the IOCs and tell me what to prioritize.",
            config=config,
            index_root=REPO_ROOT,
            session_context=session_context,
        )

        self.assertEqual(result["sources"][0]["path"], "Uploaded evidence summary from current session")
        self.assertEqual(len(result["sources"]), 1)
        self.assertIn("current-session evidence summary only", result["retrieval_confidence"])
        for heading in (
            "## Highest Priority Finding",
            "## Why this matters",
            "## Evidence Observed",
            "## IOCs / Investigation Artifacts Observed",
            "## Recommended SOC Actions",
            "## MITRE ATT&CK Mapping",
            "## Freshservice Ticket Note",
            "## Human Review Warning",
        ):
            self.assertIn(heading, result["answer"])
        self.assertIn("## IOCs / Investigation Artifacts Observed", result["answer"])
        self.assertIn("EncodedCommand", result["answer"])
        self.assertNotIn("## Local Model Notes", result["answer"])

    def test_active_evidence_context_prioritizes_vague_follow_up(self):
        config = CopilotConfig(provider="mock", test_mode=True)
        session_context = (
            "Uploaded evidence summary from current session.\n"
            "File name: sample_powershell_events.log\n"
            "Detected evidence type: PowerShell event log\n"
            "IOCs / Investigation Artifacts Observed:\n"
            "- User: devon[.]kim@example[.]test; Source: Line 1\n"
            "- Device / Host: LAB-ENDPOINT-02; Source: Line 1\n"
            "- Parent Process: WINWORD.EXE; Source: Line 1\n"
            "- Process: powershell.exe; Source: Line 1\n"
            "- Command-Line Indicator: EncodedCommand; Source: Line 1\n"
            "- Command-Line Indicator: Invoke-WebRequest; Source: Line 3\n"
            "Suspicious behaviors:\n"
            "- Encoded PowerShell command (High): encoded command observed.; MITRE: Defense Evasion: Obfuscated Files or Information; Recommended review: Decode safely in a lab.\n"
        )

        result = answer_question(
            "What should I investigate first?",
            config=config,
            index_root=REPO_ROOT,
            session_context=session_context,
        )

        self.assertEqual(len(result["sources"]), 1)
        self.assertEqual(result["sources"][0]["path"], "Uploaded evidence summary from current session")
        self.assertIn("devon[.]kim@example[.]test", result["answer"])
        self.assertIn("LAB-ENDPOINT-02", result["answer"])
        self.assertIn("WINWORD.EXE", result["answer"])
        self.assertIn("powershell.exe", result["answer"])
        self.assertIn("EncodedCommand", result["answer"])
        self.assertIn("Invoke-WebRequest", result["answer"])
        self.assertNotIn("prompt-injection", "\n".join(source["path"] for source in result["sources"]).lower())

    def test_signin_evidence_context_drives_specific_answer(self):
        config = CopilotConfig(provider="mock", test_mode=True)
        session_context = (
            "Uploaded evidence summary from current session.\n"
            "File name: sample_signin_logs.csv\n"
            "Detected evidence type: Entra sign-in style logs\n"
            "Severity recommendation: High\n"
            "IOCs / Investigation Artifacts Observed:\n"
            "- User: jordan[.]lee@example[.]test; Source: Record 2\n"
            "- IP Address: 203[.]0[.]113[.]44; Source: Record 2\n"
            "- Device / Host: UNKNOWN-DEVICE; Source: Record 2\n"
            "Suspicious behaviors:\n"
            "- Multiple failed logins (Medium): Repeated failed authentication attempts were observed.; MITRE: Credential Access: Brute Force; Recommended review: Review sign-in history, source IP, user risk, and MFA prompts.\n"
            "- Successful login after failures (High): A successful login occurred after earlier failed attempts in the same evidence set.; MITRE: Credential Access: Brute Force; Recommended review: Validate the successful session, reset credentials if suspicious, and revoke sessions.\n"
            "- Failed MFA (Medium): MFA failure or denial was observed.; MITRE: Credential Access: Multi-Factor Authentication Request Generation; Recommended review: Check for MFA fatigue, unfamiliar device, and suspicious source IP.\n"
            "- Impossible travel indicator (High): The evidence suggests geographically impossible travel.; MITRE: Initial Access: Valid Accounts; Recommended review: Compare sign-in timestamps, IPs, countries, and device identifiers.\n"
            "- New device indicator (Medium): The activity references a new or unfamiliar device.; MITRE: Initial Access: Valid Accounts; Recommended review: Confirm device ownership and review conditional access context.\n"
            "- Risky country indicator (High): The activity references a risky or unusual country.; MITRE: Initial Access: Valid Accounts; Recommended review: Review geolocation, travel patterns, and impossible travel context."
        )

        result = answer_question(
            "Which user looks most suspicious in the uploaded evidence and why?",
            config=config,
            index_root=REPO_ROOT,
            session_context=session_context,
        )

        self.assertEqual(len(result["sources"]), 1)
        self.assertIn("jordan[.]lee@example[.]test", result["answer"])
        self.assertIn("Multiple failed logins", result["answer"])
        self.assertIn("Successful login after failures", result["answer"])
        self.assertIn("Failed MFA", result["answer"])
        self.assertIn("Impossible travel", result["answer"])
        self.assertIn("New device", result["answer"])
        self.assertIn("Risky country", result["answer"])

    def test_guardrails_block_secret_like_questions_before_llm(self):
        config = CopilotConfig(provider="mock", test_mode=True)

        result = answer_question(
            "Here is an api_key=not-a-real-secret-value, please analyze it.",
            config=config,
        )

        self.assertFalse(result["guardrails"]["allowed"])
        self.assertEqual(result["sources"], [])
        self.assertIn("blocked", result["answer"].lower())

    def test_missing_ollama_returns_setup_required_message(self):
        config = CopilotConfig(
            provider="ollama",
            ollama_base_url="http://127.0.0.1:9",
            ollama_model="qwen2.5:3b",
            test_mode=False,
        )

        result = answer_question(
            "What should an analyst check for suspicious PowerShell?",
            top_k=3,
            index_root=REPO_ROOT,
            config=config,
        )

        self.assertTrue(result["setup_required"])
        self.assertIn("ollama pull qwen2.5:3b", result["answer"])
        self.assertGreater(len(result["sources"]), 0)

    def test_render_markdown_cites_sources(self):
        config = CopilotConfig(provider="mock", test_mode=True)
        result = answer_question("What are the limitations of this lab?", config=config)
        markdown = render_markdown(result)

        self.assertIn("# Security Copilot Chat Answer", markdown)
        self.assertIn("## Local Sources Used", markdown)
        self.assertIn("## Safety Note", markdown)

    def test_output_path_must_stay_inside_sample_output(self):
        unsafe_path = PROJECT_ROOT / "outside.md"

        with self.assertRaises(ValueError):
            resolve_output_path(unsafe_path)

    def test_answer_mode_validation(self):
        with self.assertRaises(ValueError):
            validate_answer_mode("Unsupported Mode")


if __name__ == "__main__":
    unittest.main()
