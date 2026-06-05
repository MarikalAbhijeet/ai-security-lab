"""Input guardrails for Security Copilot questions."""

from __future__ import annotations

import re
from dataclasses import dataclass


MAX_QUESTION_CHARS = 1200
MAX_QUESTION_LINES = 30

BLOCK_PATTERNS = [
    ("private key", re.compile(r"BEGIN (RSA |OPENSSH |DSA |EC |)PRIVATE KEY", re.IGNORECASE)),
    ("bearer token", re.compile(r"bearer\s+[A-Za-z0-9._~+/=-]{16,}", re.IGNORECASE)),
    ("AWS-style access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("OpenAI-style API key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("API key", re.compile(r"(api[_-]?key|apikey)\s*[:=]\s*[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)),
    ("secret", re.compile(r"(client_secret|secret|token)\s*[:=]\s*\S{6,}", re.IGNORECASE)),
    ("password", re.compile(r"password\s*[:=]\s*\S{4,}", re.IGNORECASE)),
    ("connection string", re.compile(r"(AccountKey=|SharedAccessKey=|DefaultEndpointsProtocol=|mongodb://|postgres://|Server=.*Password=)", re.IGNORECASE)),
    ("prompt injection", re.compile(r"(ignore (all )?(previous|prior) instructions|disregard (all )?(previous|prior) instructions|reveal your system prompt|show the system prompt|bypass safety|developer message)", re.IGNORECASE)),
]


@dataclass(frozen=True)
class GuardrailResult:
    """Result of pre-LLM input guardrail checks."""

    allowed: bool
    warnings: list[str]
    sanitized_question: str


def evaluate_question(question: str) -> GuardrailResult:
    """Evaluate and sanitize a user question before retrieval or LLM use."""
    if not isinstance(question, str) or not question.strip():
        return GuardrailResult(False, ["Question must be a non-empty string."], "")

    sanitized = normalize_question(question)
    warnings = []

    if len(sanitized) > MAX_QUESTION_CHARS or sanitized.count("\n") + 1 > MAX_QUESTION_LINES:
        warnings.append("Question looks like a long pasted log or document. Ask a short lab question instead.")

    for label, pattern in BLOCK_PATTERNS:
        if pattern.search(sanitized):
            warnings.append(f"Blocked possible {label} content.")

    allowed = not warnings
    return GuardrailResult(allowed=allowed, warnings=warnings, sanitized_question=sanitized)


def normalize_question(question: str) -> str:
    """Normalize question text while preserving user intent."""
    normalized = question.replace("\r\n", "\n").replace("\r", "\n").strip()
    return re.sub(r"[ \t]+", " ", normalized)
