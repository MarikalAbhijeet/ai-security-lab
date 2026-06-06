"""Local Ollama client for Security Copilot."""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from config import CopilotConfig


PROJECT_ROOT = Path(__file__).resolve().parent
PROMPT_DIR = PROJECT_ROOT / "prompts"
SETUP_INSTRUCTIONS = "\n".join(
    [
        "Ollama setup is required for local LLM answers.",
        "1. Install Ollama from https://ollama.com/download.",
        "2. Start Ollama locally.",
        "3. Run `ollama pull qwen2.5:3b`.",
        "4. Run `ollama run qwen2.5:3b`.",
    ]
)


@dataclass(frozen=True)
class ProviderStatus:
    """Provider health status."""

    provider: str
    model: str
    reachable: bool
    model_installed: bool
    setup_required: bool
    message: str
    health_timeout_seconds: int
    generation_timeout_seconds: int
    last_error: str = ""


@dataclass(frozen=True)
class LLMResponse:
    """LLM response wrapper."""

    answer: str
    provider: str
    model: str
    setup_required: bool = False
    timed_out: bool = False
    last_error: str = ""


def provider_status(config: CopilotConfig) -> ProviderStatus:
    """Return provider health without logging secrets."""
    if config.uses_mock:
        return ProviderStatus(
            provider="mock",
            model=config.ollama_model,
            reachable=True,
            model_installed=True,
            setup_required=False,
            message="Mock provider enabled for tests.",
            health_timeout_seconds=config.ollama_health_timeout_seconds,
            generation_timeout_seconds=config.ollama_timeout_seconds,
        )

    return ollama_health(config)


def check_ollama_status(config: CopilotConfig) -> ProviderStatus:
    """Public status helper for dashboard and tests."""
    return provider_status(config)


def ollama_health(config: CopilotConfig) -> ProviderStatus:
    """Check Ollama health and configured model availability."""
    try:
        with urllib.request.urlopen(
            f"{config.ollama_base_url}/api/tags",
            timeout=config.ollama_health_timeout_seconds,
        ) as response:
            data = json.loads(response.read().decode("utf-8"))
    except (OSError, urllib.error.URLError, json.JSONDecodeError, TimeoutError) as error:
        return ProviderStatus(
            provider="ollama",
            model=config.ollama_model,
            reachable=False,
            model_installed=False,
            setup_required=True,
            message=f"{SETUP_INSTRUCTIONS}\n\nDetail: {error}",
            health_timeout_seconds=config.ollama_health_timeout_seconds,
            generation_timeout_seconds=config.ollama_timeout_seconds,
            last_error=str(error),
        )

    models = {item.get("name", "") for item in data.get("models", [])}
    if config.ollama_model not in models:
        return ProviderStatus(
            provider="ollama",
            model=config.ollama_model,
            reachable=True,
            model_installed=False,
            setup_required=True,
            message=f"Configured Ollama model `{config.ollama_model}` was not found. Run `ollama pull {config.ollama_model}`.",
            health_timeout_seconds=config.ollama_health_timeout_seconds,
            generation_timeout_seconds=config.ollama_timeout_seconds,
        )
    return ProviderStatus(
        provider="ollama",
        model=config.ollama_model,
        reachable=True,
        model_installed=True,
        setup_required=False,
        message=f"Ollama reachable with model `{config.ollama_model}`.",
        health_timeout_seconds=config.ollama_health_timeout_seconds,
        generation_timeout_seconds=config.ollama_timeout_seconds,
    )


def chat(config: CopilotConfig, question: str, answer_mode: str, context: str, status: ProviderStatus | None = None) -> LLMResponse:
    """Generate an answer with mock mode or local Ollama."""
    if config.uses_mock:
        return LLMResponse(mock_answer(question, answer_mode, context), "mock", config.ollama_model)

    status = status or provider_status(config)
    if status.setup_required:
        return LLMResponse(status.message, "ollama", config.ollama_model, setup_required=True)

    payload = {
        "model": config.ollama_model,
        "stream": False,
        "messages": [
            {"role": "system", "content": load_prompt("system_prompt.md")},
            {"role": "user", "content": build_user_prompt(question, answer_mode, context)},
        ],
    }
    request = urllib.request.Request(
        f"{config.ollama_base_url}/api/chat",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=config.ollama_timeout_seconds) as response:
            data = json.loads(response.read().decode("utf-8"))
    except (socket.timeout, TimeoutError) as error:
        return LLMResponse(timeout_message(), "ollama", config.ollama_model, timed_out=True, last_error=str(error))
    except (OSError, urllib.error.URLError) as error:
        if is_timeout_error(error):
            return LLMResponse(timeout_message(), "ollama", config.ollama_model, timed_out=True, last_error=str(error))
        return LLMResponse(f"{SETUP_INSTRUCTIONS} Detail: {error}", "ollama", config.ollama_model, setup_required=True)
    except json.JSONDecodeError as error:
        return LLMResponse(f"Ollama returned an unreadable response. Detail: {error}", "ollama", config.ollama_model, last_error=str(error))

    answer = data.get("message", {}).get("content", "").strip()
    if not answer:
        answer = "Ollama returned an empty response. Review local setup and try again."
    return LLMResponse(answer, "ollama", config.ollama_model)


def timeout_message() -> str:
    """Return user-facing guidance for slow local model responses."""
    return (
        "Ollama is running, but the model response timed out. The model may still be loading or your system may be slow. "
        "Try again, reduce retrieved sources, or use a smaller model."
    )


def is_timeout_error(error: BaseException) -> bool:
    """Return True when urllib wrapped a timeout-like error."""
    return "timed out" in str(error).lower()


def build_user_prompt(question: str, answer_mode: str, context: str) -> str:
    """Build the user prompt sent to local Ollama."""
    mode_template = load_mode_prompt(answer_mode)
    return (
        f"{mode_template}\n\n"
        "Use only the local context below. If the context is insufficient, say so clearly.\n\n"
        f"Question:\n{question}\n\n"
        f"Retrieved local context:\n{context}"
    )


def load_prompt(name: str) -> str:
    """Load one prompt template."""
    return (PROMPT_DIR / name).read_text(encoding="utf-8")


def load_mode_prompt(answer_mode: str) -> str:
    """Load an answer-mode prompt template."""
    mapping = {
        "SOC Analyst": "soc_analyst_prompt.md",
        "Executive Summary": "executive_summary_prompt.md",
        "KQL Recommendation": "kql_recommendation_prompt.md",
        "MITRE Mapping": "mitre_mapping_prompt.md",
        "AI Security Review": "ai_security_review_prompt.md",
        "Vendor Risk Review": "vendor_risk_prompt.md",
        "Incident Response": "incident_response_prompt.md",
        "Detection Engineering": "detection_engineering_prompt.md",
    }
    return load_prompt(mapping.get(answer_mode, "soc_analyst_prompt.md"))


def mock_answer(question: str, answer_mode: str, context: str) -> str:
    """Return deterministic test-mode answer text."""
    preview = context[:900].strip() if context else "No local context was retrieved."
    return (
        f"Mock {answer_mode} answer for local lab testing.\n\n"
        f"Question: {question}\n\n"
        f"Local context preview: {preview}\n\n"
        "This mock response is for CI/tests only and does not call Ollama or any external API."
    )
