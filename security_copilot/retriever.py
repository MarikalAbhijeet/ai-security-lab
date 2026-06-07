"""Local RAG retrieval for Security Copilot."""

from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


REPO_ROOT = Path(__file__).resolve().parents[1]
SUPPORTED_EXTENSIONS = {".md", ".txt", ".kql", ".ps1", ".json", ".csv"}
EXCLUDED_DIRS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".streamlit",
    "build",
    "dist",
    "cache",
    ".cache",
    "coverage",
    ".coverage",
    ".venv",
    "venv",
    "env",
    "node_modules",
}
EXCLUDED_FILENAMES = {".env", ".env.local", "AGENTS.md", "requirements.txt"}
EXCLUDED_PATH_PARTS = {
    ("security_copilot", "sample-output"),
    ("security_copilot", "sample-questions"),
    ("security_copilot", "prompts"),
}
SENSITIVE_NAME_TOKENS = {"secret", "secrets", "credential", "credentials", "token", "tokens", "password", "passwords", "private"}
MAX_FILE_BYTES = 250_000
CHUNK_SIZE_CHARS = 1200
CHUNK_OVERLAP_CHARS = 150


@dataclass(frozen=True)
class DocumentChunk:
    """One retrievable local document chunk."""

    source_path: str
    heading: str
    text: str
    score: float = 0.0


def resolve_index_root(index_root=None) -> Path:
    """Resolve and validate the index root."""
    root = Path(index_root or REPO_ROOT).resolve()
    repo_root = REPO_ROOT.resolve()
    if root != repo_root and repo_root not in root.parents:
        raise ValueError("Index root must stay inside the ai-security-lab repository.")
    if not root.exists() or not root.is_dir():
        raise ValueError(f"Index root does not exist or is not a directory: {root}")
    return root


def should_exclude_path(path: Path) -> bool:
    """Return True when a path should not be indexed."""
    path_parts = tuple(part.lower() for part in path.parts)
    if any(part.startswith(".") and part not in {".", ".."} for part in path_parts):
        return True
    if set(path_parts) & EXCLUDED_DIRS:
        return True
    if path.name.lower() in {name.lower() for name in EXCLUDED_FILENAMES}:
        return True
    if any(contains_path_sequence(path_parts, sequence) for sequence in EXCLUDED_PATH_PARTS):
        return True
    return has_sensitive_name_token(path)


def has_sensitive_name_token(path: Path) -> bool:
    """Return True when a path part has an exact sensitive filename token."""
    for part in path.parts:
        tokens = {token for token in re.split(r"[^A-Za-z0-9]+", part.lower()) if token}
        if tokens & SENSITIVE_NAME_TOKENS:
            return True
        if "key" in tokens and tokens & {"api", "access", "private", "ssh"}:
            return True
    return False


def contains_path_sequence(path_parts: tuple[str, ...], sequence: tuple[str, ...]) -> bool:
    """Return True when a path contains a directory sequence."""
    for index in range(len(path_parts) - len(sequence) + 1):
        if path_parts[index:index + len(sequence)] == sequence:
            return True
    return False


def discover_files(index_root=None) -> list[Path]:
    """Discover safe local files for indexing."""
    root = resolve_index_root(index_root)
    files = []
    for path in sorted(root.rglob("*")):
        if should_exclude_path(path):
            continue
        if path.is_file() and path.suffix.lower() in SUPPORTED_EXTENSIONS:
            files.append(path)
    return files


def load_file_text(path: Path) -> str:
    """Load safe text from a local file."""
    if should_exclude_path(path) or not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
        return ""
    try:
        raw = path.read_bytes()
    except OSError:
        return ""
    if b"\x00" in raw:
        return ""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return ""
    if path.suffix.lower() == ".json":
        return json_to_text(text)
    if path.suffix.lower() == ".csv":
        return csv_to_text(text)
    return text.replace("\r\n", "\n").replace("\r", "\n").strip()


def json_to_text(text: str) -> str:
    """Convert JSON text into compact searchable text."""
    try:
        return normalize_text(json.dumps(json.loads(text), indent=2))
    except json.JSONDecodeError:
        return normalize_text(text)


def csv_to_text(text: str) -> str:
    """Convert CSV rows into compact searchable text."""
    try:
        rows = list(csv.reader(text.splitlines()))
    except csv.Error:
        return normalize_text(text)
    return normalize_text("\n".join(" | ".join(row) for row in rows[:80]))


def build_chunks(index_root=None) -> list[DocumentChunk]:
    """Build retrievable chunks from local files."""
    chunks = []
    for path in discover_files(index_root):
        text = load_file_text(path)
        if not text:
            continue
        relative_path = path.resolve().relative_to(REPO_ROOT.resolve()).as_posix()
        for heading, chunk_text in chunk_text_by_heading(text):
            for piece in split_large_chunk(chunk_text):
                if piece.strip():
                    chunks.append(DocumentChunk(source_path=relative_path, heading=heading, text=piece))
    return chunks


def retrieve(question: str, index_root=None, top_k=5) -> list[DocumentChunk]:
    """Retrieve top local chunks for a question."""
    question = validate_question(question)
    top_k = validate_top_k(top_k)
    chunks = build_chunks(index_root)
    if not chunks:
        raise ValueError("No safe local documents were available for retrieval.")

    vectorizer = TfidfVectorizer(stop_words="english", ngram_range=(1, 2), max_features=10000)
    matrix = vectorizer.fit_transform([chunk.text for chunk in chunks])
    scores = cosine_similarity(vectorizer.transform([question]), matrix).flatten()
    boosted_scores = [
        float(score) + source_priority_boost(question, chunks[index])
        for index, score in enumerate(scores)
    ]
    ranked = []
    seen_sources = set()
    for index in sorted(range(len(chunks)), key=lambda item: boosted_scores[item], reverse=True):
        if chunks[index].source_path in seen_sources:
            continue
        ranked.append(index)
        seen_sources.add(chunks[index].source_path)
        if len(ranked) == top_k:
            break
    return [
        DocumentChunk(
            source_path=chunks[index].source_path,
            heading=chunks[index].heading,
            text=chunks[index].text,
            score=float(boosted_scores[index]),
        )
        for index in ranked
        if float(boosted_scores[index]) > 0
    ]


def source_priority_boost(question: str, chunk: DocumentChunk) -> float:
    """Prefer SOC playbooks and automation assets for matching SOC questions."""
    lowered_question = question.lower()
    source = chunk.source_path.lower()
    topic_terms = {
        "suspicious-powershell": ("powershell", "encodedcommand", "script", "winword"),
        "risky-signin": ("risky sign", "risky-sign", "sign-in", "signin", "failed mfa", "mfa"),
        "phishing": ("phishing", "email", "invoice", "qr"),
        "malware": ("malware", "defender alert", "threat"),
        "impossible-travel": ("impossible travel", "travel"),
        "mass-file-deletion": ("mass file", "file deletion", "deleted files", "deletion"),
    }
    if not any(any(term in lowered_question for term in terms) for terms in topic_terms.values()):
        return 0.0

    boost = 0.0
    if "docs/soc_playbooks/" in source:
        boost += 0.35
    if "automation/kql/" in source:
        boost += 0.28
    if "automation/ticket-templates/" in source:
        boost += 0.22
    if "automation/powershell/" in source:
        boost += 0.18

    if "kql" in lowered_question or "query" in lowered_question or "hunt" in lowered_question:
        if "automation/kql/" in source:
            boost += 0.35
        if "automation/ticket-templates/" in source:
            boost -= 0.1

    for topic, terms in topic_terms.items():
        if any(term in lowered_question for term in terms) and topic in source:
            boost += 0.45

    if "03-prompt-injection-lab/" in source and any(
        term in lowered_question
        for term in ("powershell", "sign-in", "signin", "phishing", "malware", "impossible travel", "file deletion", "evidence")
    ):
        boost -= 0.6
    return boost


def chunk_text_by_heading(text: str) -> list[tuple[str, str]]:
    """Split text into heading-aware chunks."""
    current_heading = "Document"
    current_lines = []
    chunks = []
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            if current_lines:
                chunks.append((current_heading, "\n".join(current_lines).strip()))
                current_lines = []
            current_heading = line.lstrip("#").strip() or "Document"
        else:
            current_lines.append(line)
    if current_lines:
        chunks.append((current_heading, "\n".join(current_lines).strip()))
    if not chunks and text.strip():
        chunks.append((current_heading, text.strip()))
    return chunks


def split_large_chunk(text: str) -> list[str]:
    """Split long text into overlapping chunks."""
    text = normalize_text(strip_code_blocks(text))
    if len(text) <= CHUNK_SIZE_CHARS:
        return [text]
    pieces = []
    start = 0
    while start < len(text):
        end = min(start + CHUNK_SIZE_CHARS, len(text))
        piece = text[start:end].strip()
        if piece:
            pieces.append(piece)
        if end == len(text):
            break
        start = max(0, end - CHUNK_OVERLAP_CHARS)
    return pieces


def confidence_note(chunks: list[DocumentChunk]) -> str:
    """Return a simple retrieval confidence note."""
    if not chunks:
        return "Low confidence: no relevant local chunks were retrieved."
    top_score = chunks[0].score
    if top_score >= 0.35:
        return f"Higher confidence: strongest local retrieval score was {top_score:.3f}."
    if top_score >= 0.15:
        return f"Moderate confidence: strongest local retrieval score was {top_score:.3f}."
    return f"Low confidence: strongest local retrieval score was {top_score:.3f}."


def citations(chunks: list[DocumentChunk]) -> list[dict]:
    """Return source citations for retrieved chunks."""
    return [
        {
            "path": chunk.source_path,
            "heading": chunk.heading,
            "score": round(chunk.score, 4),
        }
        for chunk in chunks
    ]


def validate_question(question: str) -> str:
    """Validate a retrieval question."""
    if not isinstance(question, str) or not question.strip():
        raise ValueError("Question must be a non-empty string.")
    return question.strip()


def validate_top_k(top_k) -> int:
    """Validate retrieval count."""
    try:
        value = int(top_k)
    except (TypeError, ValueError) as error:
        raise ValueError("top-k must be an integer between 1 and 10.") from error
    if value < 1 or value > 10:
        raise ValueError("top-k must be between 1 and 10.")
    return value


def strip_code_blocks(text: str) -> str:
    """Remove fenced code blocks from text snippets."""
    return re.sub(r"```.*?```", " ", text, flags=re.DOTALL)


def normalize_text(text: str) -> str:
    """Normalize whitespace."""
    return re.sub(r"\s+", " ", text).strip()
