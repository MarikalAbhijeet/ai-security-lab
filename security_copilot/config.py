"""Configuration for the local-first Security Copilot."""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlparse


DEFAULT_PROVIDER = "ollama"
DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434"
DEFAULT_OLLAMA_MODEL = "qwen2.5:3b"
DEFAULT_OLLAMA_TIMEOUT_SECONDS = 180
DEFAULT_OLLAMA_HEALTH_TIMEOUT_SECONDS = 10
SUPPORTED_PROVIDERS = {"ollama", "mock"}


@dataclass(frozen=True)
class CopilotConfig:
    """Runtime configuration loaded from environment variables."""

    provider: str = DEFAULT_PROVIDER
    ollama_base_url: str = DEFAULT_OLLAMA_BASE_URL
    ollama_model: str = DEFAULT_OLLAMA_MODEL
    ollama_timeout_seconds: int = DEFAULT_OLLAMA_TIMEOUT_SECONDS
    ollama_health_timeout_seconds: int = DEFAULT_OLLAMA_HEALTH_TIMEOUT_SECONDS
    test_mode: bool = False

    @property
    def uses_mock(self) -> bool:
        return self.provider == "mock" or self.test_mode


def load_config(env=None) -> CopilotConfig:
    """Load configuration from environment variables."""
    values = env or os.environ
    provider = values.get("COPILOT_PROVIDER", DEFAULT_PROVIDER).strip().lower()
    if provider not in SUPPORTED_PROVIDERS:
        raise ValueError("COPILOT_PROVIDER must be one of: ollama, mock.")

    base_url = values.get("OLLAMA_BASE_URL", DEFAULT_OLLAMA_BASE_URL).strip().rstrip("/")
    model = values.get("OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL).strip()
    generation_timeout = parse_positive_int(
        values.get("OLLAMA_TIMEOUT_SECONDS", DEFAULT_OLLAMA_TIMEOUT_SECONDS),
        "OLLAMA_TIMEOUT_SECONDS",
    )
    health_timeout = parse_positive_int(
        values.get("OLLAMA_HEALTH_TIMEOUT_SECONDS", DEFAULT_OLLAMA_HEALTH_TIMEOUT_SECONDS),
        "OLLAMA_HEALTH_TIMEOUT_SECONDS",
    )
    if not base_url.startswith(("http://", "https://")):
        raise ValueError("OLLAMA_BASE_URL must start with http:// or https://.")
    if not is_loopback_ollama_url(base_url):
        raise ValueError("OLLAMA_BASE_URL must point to localhost or a loopback address for this local-first lab.")
    if not model:
        raise ValueError("OLLAMA_MODEL must not be empty.")

    return CopilotConfig(
        provider=provider,
        ollama_base_url=base_url,
        ollama_model=model,
        ollama_timeout_seconds=generation_timeout,
        ollama_health_timeout_seconds=health_timeout,
        test_mode=parse_bool(values.get("COPILOT_TEST_MODE", "false")),
    )


def parse_bool(value) -> bool:
    """Parse common boolean environment variable values."""
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def is_loopback_ollama_url(base_url: str) -> bool:
    """Return True when the configured Ollama URL is local-only."""
    parsed = urlparse(base_url)
    host = (parsed.hostname or "").lower()
    return host in {"localhost", "127.0.0.1", "::1"}


def parse_positive_int(value, name: str) -> int:
    """Parse a positive integer configuration value."""
    try:
        parsed = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{name} must be a positive integer.") from error
    if parsed < 1:
        raise ValueError(f"{name} must be a positive integer.")
    return parsed
