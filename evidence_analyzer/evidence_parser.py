"""Safe parsing helpers for uploaded threat evidence files."""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


MAX_FILE_BYTES = 5 * 1024 * 1024
SUPPORTED_EXTENSIONS = {".csv", ".json", ".txt", ".log"}
MAX_TEXT_LINES = 5000
MAX_CSV_ROWS = 5000

SENSITIVE_PATTERNS = [
    ("private key", re.compile(r"BEGIN (RSA |OPENSSH |DSA |EC |)PRIVATE KEY", re.IGNORECASE)),
    ("bearer token", re.compile(r"bearer\s+[A-Za-z0-9._~+/=-]{16,}", re.IGNORECASE)),
    ("AWS-style access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("OpenAI-style API key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("API key", re.compile(r"(api[_-]?key|apikey)\s*[:=]\s*[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)),
    ("secret", re.compile(r"(client_secret|secret|token)\s*[:=]\s*\S{6,}", re.IGNORECASE)),
    ("password", re.compile(r"password\s*[:=]\s*\S{4,}", re.IGNORECASE)),
    ("connection string", re.compile(r"(AccountKey=|SharedAccessKey=|DefaultEndpointsProtocol=|Server=.*Password=)", re.IGNORECASE)),
]


@dataclass(frozen=True)
class EvidenceDocument:
    """Parsed evidence content held in memory for the current analysis."""

    file_name: str
    extension: str
    parsed_type: str
    records: list[dict[str, Any]]
    lines: list[str]
    raw_json: Any | None = None


def parse_evidence_file(file_name: str, content: bytes, max_file_bytes: int = MAX_FILE_BYTES) -> EvidenceDocument:
    """Parse supported evidence bytes without executing or permanently saving content."""
    safe_name = sanitize_file_name(file_name)
    extension = Path(safe_name).suffix.lower()
    if extension not in SUPPORTED_EXTENSIONS:
        raise ValueError("Unsupported evidence file type. Use JSON, CSV, TXT, or LOG.")
    if not isinstance(content, bytes):
        raise ValueError("Evidence content must be bytes.")
    if len(content) == 0:
        raise ValueError("Evidence file is empty.")
    if len(content) > max_file_bytes:
        raise ValueError("Evidence file is too large for local dashboard analysis.")
    if b"\x00" in content:
        raise ValueError("Evidence file appears to be binary. Upload text-based JSON, CSV, TXT, or LOG.")

    text = decode_text(content)
    sensitive_findings = detect_sensitive_content(text)
    if sensitive_findings:
        labels = ", ".join(sorted(set(sensitive_findings)))
        raise ValueError(f"Sensitive-looking content detected: {labels}. Analysis blocked for safety.")

    if extension == ".csv":
        records = parse_csv(text)
        return EvidenceDocument(safe_name, extension, "csv", records=records, lines=[])
    if extension == ".json":
        raw_json = parse_json(text)
        records = flatten_json_records(raw_json)
        return EvidenceDocument(safe_name, extension, "json", records=records, lines=[], raw_json=raw_json)

    lines = parse_text_lines(text)
    return EvidenceDocument(safe_name, extension, "text", records=[], lines=lines)


def sanitize_file_name(file_name: str) -> str:
    """Return a basename-only file name to prevent path traversal."""
    if not isinstance(file_name, str) or not file_name.strip():
        raise ValueError("Evidence file name is required.")
    if "/" in file_name or "\\" in file_name:
        raise ValueError("Evidence file name must not include a path.")
    safe_name = Path(file_name).name
    if safe_name in {"", ".", ".."}:
        raise ValueError("Evidence file name must not include a path.")
    return safe_name


def decode_text(content: bytes) -> str:
    """Decode uploaded text bytes as UTF-8."""
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("Evidence file must be UTF-8 text.") from error


def detect_sensitive_content(text: str) -> list[str]:
    """Return sensitive-looking pattern labels found in text."""
    findings = []
    for label, pattern in SENSITIVE_PATTERNS:
        if pattern.search(text):
            findings.append(label)
    return findings


def parse_csv(text: str) -> list[dict[str, Any]]:
    """Parse CSV text into dictionaries."""
    try:
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames:
            raise ValueError("CSV evidence must include a header row.")
        records = []
        for index, row in enumerate(reader, start=1):
            if index > MAX_CSV_ROWS:
                break
            if None in row:
                raise ValueError("CSV evidence contains rows with more values than headers.")
            if any(value is None for value in row.values()):
                raise ValueError("CSV evidence contains rows with missing values.")
            records.append({str(key).strip(): (value or "").strip() for key, value in row.items() if key})
    except csv.Error as error:
        raise ValueError("CSV evidence could not be parsed.") from error
    if not records:
        raise ValueError("CSV evidence did not contain any data rows.")
    return records


def parse_json(text: str) -> Any:
    """Parse JSON text safely."""
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as error:
        raise ValueError("JSON evidence could not be parsed.") from error
    if not isinstance(payload, (dict, list)):
        raise ValueError("JSON evidence must be an object or array.")
    return payload


def flatten_json_records(payload: Any) -> list[dict[str, Any]]:
    """Convert common JSON object/list structures into rows for rule evaluation."""
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    for key in ("records", "alerts", "events", "value", "items"):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return [payload]


def parse_text_lines(text: str) -> list[str]:
    """Parse TXT/LOG text into bounded non-empty lines."""
    lines = [line.strip() for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n") if line.strip()]
    if not lines:
        raise ValueError("Text evidence did not contain any non-empty lines.")
    return lines[:MAX_TEXT_LINES]
