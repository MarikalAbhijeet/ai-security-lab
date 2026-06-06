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
