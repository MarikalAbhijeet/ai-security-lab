"""Tests for Ollama provider behavior without requiring Ollama."""

import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from config import CopilotConfig  # noqa: E402
from ollama_client import chat, provider_status  # noqa: E402


class OllamaClientTests(unittest.TestCase):
    def test_mock_provider_does_not_require_ollama(self):
        config = CopilotConfig(provider="mock", test_mode=True)

        status = provider_status(config)
        response = chat(config, "What is this lab?", "SOC Analyst", "Local context.")

        self.assertTrue(status.reachable)
        self.assertFalse(status.setup_required)
        self.assertIn("Mock SOC Analyst answer", response.answer)

    def test_unavailable_ollama_returns_setup_required(self):
        config = CopilotConfig(
            provider="ollama",
            ollama_base_url="http://127.0.0.1:9",
            ollama_model="qwen2.5:3b",
        )

        status = provider_status(config)

        self.assertFalse(status.reachable)
        self.assertTrue(status.setup_required)
        self.assertIn("ollama pull qwen2.5:3b", status.message)


if __name__ == "__main__":
    unittest.main()
