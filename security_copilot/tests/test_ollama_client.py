"""Tests for Ollama provider behavior without requiring Ollama."""

import sys
import socket
import unittest
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from config import CopilotConfig  # noqa: E402
from ollama_client import ProviderStatus, chat, provider_status  # noqa: E402


class OllamaClientTests(unittest.TestCase):
    def test_mock_provider_does_not_require_ollama(self):
        config = CopilotConfig(provider="mock", test_mode=True)

        status = provider_status(config)
        response = chat(config, "What is this lab?", "SOC Analyst", "Local context.")

        self.assertTrue(status.reachable)
        self.assertTrue(status.model_installed)
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
        self.assertFalse(status.model_installed)
        self.assertTrue(status.setup_required)
        self.assertIn("ollama pull qwen2.5:3b", status.message)

    def test_generation_timeout_is_not_setup_required(self):
        config = CopilotConfig(
            provider="ollama",
            ollama_base_url="http://localhost:11434",
            ollama_model="qwen2.5:3b",
            ollama_timeout_seconds=1,
            ollama_health_timeout_seconds=1,
        )
        status = ProviderStatus(
            provider="ollama",
            model="qwen2.5:3b",
            reachable=True,
            model_installed=True,
            setup_required=False,
            message="Ollama reachable with model `qwen2.5:3b`.",
            health_timeout_seconds=1,
            generation_timeout_seconds=1,
        )

        with patch("urllib.request.urlopen", side_effect=socket.timeout("timed out")):
            response = chat(config, "Question", "SOC Analyst", "Context", status=status)

        self.assertFalse(response.setup_required)
        self.assertTrue(response.timed_out)
        self.assertIn("model response timed out", response.answer)


if __name__ == "__main__":
    unittest.main()
