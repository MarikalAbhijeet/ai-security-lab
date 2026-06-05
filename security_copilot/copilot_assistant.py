"""Offline retrieval-based Security Copilot assistant for AI Security Lab.

Version 1 uses local repository documents only. It does not call paid APIs,
external LLMs, or live security systems.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


REPO_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_OUTPUT_PATH = PROJECT_ROOT / "sample-output" / "copilot_sample_answers.md"
SUPPORTED_EXTENSIONS = {".md", ".txt", ".kql", ".ps1"}
EXCLUDED_DIRS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".streamlit",
    "build",
    "dist",
    "coverage",
    ".coverage",
    ".venv",
    "venv",
    "env",
    "node_modules",
}
EXCLUDED_FILENAMES = {
    ".env",
    ".env.local",
    ".env.example",
    "AGENTS.md",
    "requirements.txt",
}
EXCLUDED_PATH_PARTS = {
    ("security_copilot", "sample-output"),
    ("security_copilot", "sample-questions"),
}
SENSITIVE_NAME_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"secret",
        r"credential",
        r"token",
        r"api[_-]?key",
        r"private[_-]?key",
        r"password",
    )
]
MAX_FILE_BYTES = 250_000
MAX_SNIPPET_CHARS = 900


@dataclass(frozen=True)
class Document:
    """One indexed local document."""

    path: Path
    relative_path: str
    text: str


@dataclass(frozen=True)
class RetrievalResult:
    """One retrieved document and its similarity score."""

    document: Document
    score: float


def resolve_index_root(index_root=None) -> Path:
    """Resolve and validate the index root."""
    root = Path(index_root or REPO_ROOT).resolve()
    repo_root = REPO_ROOT.resolve()

    if root != repo_root and repo_root not in root.parents:
        raise ValueError("Index root must stay inside the ai-security-lab repository.")

    if not root.exists() or not root.is_dir():
        raise ValueError(f"Index root does not exist or is not a directory: {root}")

    return root


def resolve_output_path(output_path=None) -> Path:
    """Resolve and validate an optional Markdown output path."""
    path = Path(output_path or DEFAULT_OUTPUT_PATH).resolve()
    output_root = (PROJECT_ROOT / "sample-output").resolve()

    if path.suffix.lower() != ".md":
        raise ValueError("Output file must use the .md extension.")

    if path != output_root and output_root not in path.parents:
        raise ValueError("Output file must stay inside security_copilot/sample-output.")

    return path


def should_exclude_path(path: Path) -> bool:
    """Return True when a path should not be indexed."""
    if any(part.startswith(".") and part not in {".", ".."} for part in path.parts):
        return True

    parts = set(path.parts)
    if parts & EXCLUDED_DIRS:
        return True

    normalized_parts = tuple(part.replace("\\", "/") for part in path.parts)
    for excluded_parts in EXCLUDED_PATH_PARTS:
        if contains_path_sequence(normalized_parts, excluded_parts):
            return True

    if path.name in EXCLUDED_FILENAMES:
        return True

    path_text = str(path)
    return any(pattern.search(path_text) for pattern in SENSITIVE_NAME_PATTERNS)


def contains_path_sequence(path_parts: tuple[str, ...], sequence: tuple[str, ...]) -> bool:
    """Return True when a path contains a directory sequence."""
    if len(sequence) > len(path_parts):
        return False

    for index in range(len(path_parts) - len(sequence) + 1):
        if path_parts[index:index + len(sequence)] == sequence:
            return True
    return False


def is_supported_document(path: Path) -> bool:
    """Return True if a file extension is supported for indexing."""
    return path.is_file() and path.suffix.lower() in SUPPORTED_EXTENSIONS


def discover_documents(index_root=None) -> list[Path]:
    """Discover supported local documents under the index root."""
    root = resolve_index_root(index_root)
    documents = []

    for path in sorted(root.rglob("*")):
        if should_exclude_path(path):
            continue
        if is_supported_document(path):
            documents.append(path)

    return documents


def load_document(path: Path) -> Document | None:
    """Load one document, returning None if it cannot be safely read."""
    if should_exclude_path(path) or not is_supported_document(path):
        return None

    if path.stat().st_size > MAX_FILE_BYTES:
        return None

    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None

    text = normalize_text(text)
    if not text:
        return None

    relative_path = path.resolve().relative_to(REPO_ROOT.resolve()).as_posix()
    return Document(path=path.resolve(), relative_path=relative_path, text=text)


def build_corpus(index_root=None) -> list[Document]:
    """Load all safe supported documents for retrieval."""
    corpus = []
    for path in discover_documents(index_root):
        document = load_document(path)
        if document is not None:
            corpus.append(document)
    return corpus


def retrieve(question: str, index_root=None, top_k=5) -> list[RetrievalResult]:
    """Retrieve the most relevant local documents for a question."""
    question = validate_question(question)
    top_k = validate_top_k(top_k)
    corpus = build_corpus(index_root)

    if not corpus:
        raise ValueError("No local documents were available for retrieval.")

    texts = [document.text for document in corpus]
    vectorizer = TfidfVectorizer(stop_words="english", ngram_range=(1, 2), max_features=8000)
    matrix = vectorizer.fit_transform(texts)
    question_vector = vectorizer.transform([question])
    scores = cosine_similarity(question_vector, matrix).flatten()

    ranked_indexes = scores.argsort()[::-1][:top_k]
    results = [
        RetrievalResult(document=corpus[index], score=float(scores[index]))
        for index in ranked_indexes
        if float(scores[index]) > 0
    ]
    return results


def answer_question(question: str, index_root=None, top_k=5) -> dict:
    """Answer a question using retrieved local lab context."""
    results = retrieve(question, index_root=index_root, top_k=top_k)
    answer = synthesize_answer(question, results)
    return {
        "question": question.strip(),
        "answer": answer,
        "sources": [
            {"path": result.document.relative_path, "score": round(result.score, 4)}
            for result in results
        ],
        "confidence": confidence_note(results),
        "safe_use_note": (
            "Answer is based only on local AI Security Lab sample documentation and reports. "
            "Do not paste real secrets, passwords, tokens, company data, client data, tenant data, or vendor confidential data."
        ),
    }


def synthesize_answer(question: str, results: list[RetrievalResult]) -> str:
    """Create a concise answer from retrieved snippets."""
    if not results:
        return (
            "I do not have enough local AI Security Lab context to answer that question. "
            "This assistant only answers from indexed local lab documentation and sample files."
        )

    if results[0].score < 0.05:
        return (
            "I found only weak local matches for that question, so I do not have enough local context "
            "to provide a strong answer. Review the retrieved files below or add more local documentation."
        )

    snippets = []
    for result in results:
        snippets.append(f"From `{result.document.relative_path}`:\n{best_snippet(result.document.text, question)}")

    return (
        "This answer is based only on local AI Security Lab documentation and sample outputs.\n\n"
        + "\n\n".join(snippets)
        + "\n\nTreat this as lab guidance for portfolio/demo use, not production security advice."
    )


def best_snippet(text: str, question: str) -> str:
    """Return a compact snippet with overlap against the question."""
    sentences = split_sentences(text)
    question_terms = set(tokenize(question))
    scored = []

    for sentence in sentences:
        terms = set(tokenize(sentence))
        score = len(question_terms & terms)
        if score:
            scored.append((score, sentence))

    if scored:
        selected = [
            sentence
            for _, sentence in sorted(scored, key=lambda item: (item[0], len(item[1])), reverse=True)[:4]
            if is_useful_snippet(sentence)
        ]
    else:
        selected = [sentence for sentence in sentences[:4] if is_useful_snippet(sentence)]

    if not selected:
        selected = sentences[:2]

    snippet = " ".join(selected)
    if len(snippet) > MAX_SNIPPET_CHARS:
        snippet = snippet[:MAX_SNIPPET_CHARS].rsplit(" ", 1)[0] + "..."
    return snippet


def confidence_note(results: list[RetrievalResult]) -> str:
    """Return a simple confidence-style note based on retrieval score."""
    if not results:
        return "Low confidence: no relevant local documents were retrieved."

    top_score = results[0].score
    if top_score >= 0.35:
        return f"Higher confidence: strongest local retrieval score was {top_score:.3f}."
    if top_score >= 0.15:
        return f"Moderate confidence: strongest local retrieval score was {top_score:.3f}."
    return f"Low confidence: strongest local retrieval score was {top_score:.3f}."


def render_markdown(result: dict) -> str:
    """Render an assistant result as Markdown."""
    sources = "\n".join(f"- `{source['path']}` (score: {source['score']})" for source in result["sources"])
    if not sources:
        sources = "- No local sources retrieved."

    return "\n\n".join(
        [
            "# Security Copilot Chat Answer",
            "## Question",
            result["question"],
            "## Answer",
            result["answer"],
            "## Retrieved Local Sources",
            sources,
            "## Confidence",
            result["confidence"],
            "## Safe Use Note",
            result["safe_use_note"],
        ]
    )


def save_markdown(markdown: str, output_path=None) -> Path:
    """Save a Markdown answer under sample-output."""
    path = resolve_output_path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(markdown + "\n", encoding="utf-8")
    return path


def validate_question(question: str) -> str:
    """Validate a user question."""
    if not isinstance(question, str) or not question.strip():
        raise ValueError("Question must be a non-empty string.")
    if len(question) > 500:
        raise ValueError("Question must be 500 characters or fewer.")
    return question.strip()


def validate_top_k(top_k) -> int:
    """Validate top-k retrieval count."""
    try:
        value = int(top_k)
    except (TypeError, ValueError) as error:
        raise ValueError("top-k must be an integer between 1 and 10.") from error

    if value < 1 or value > 10:
        raise ValueError("top-k must be between 1 and 10.")
    return value


def normalize_text(text: str) -> str:
    """Normalize local document text for retrieval."""
    return re.sub(r"\s+", " ", text).strip()


def split_sentences(text: str) -> list[str]:
    """Split text into simple sentence-like chunks."""
    text = re.sub(r"```.*?```", " ", text, flags=re.DOTALL)
    chunks = re.split(r"(?<=[.!?])\s+|(?<=\|)\s+|(?<=\n)\s*", text)
    return [chunk.strip() for chunk in chunks if chunk.strip()]


def tokenize(text: str) -> list[str]:
    """Tokenize text for lightweight snippet scoring."""
    return re.findall(r"[a-zA-Z0-9_:+.-]{3,}", text.lower())


def is_useful_snippet(sentence: str) -> bool:
    """Filter setup/navigation snippets that do not answer security questions."""
    lowered = sentence.lower()
    noisy_terms = [
        "python -m pip install",
        "py -3",
        "cd .\\",
        "cd ..\\",
        "from this project folder",
        "on windows",
        "```powershell",
    ]
    return not any(term in lowered for term in noisy_terms)


def parse_args():
    parser = argparse.ArgumentParser(description="Offline local-document Security Copilot assistant.")
    parser.add_argument("--question", required=True, help="Security question to answer from local repo docs.")
    parser.add_argument("--top-k", type=int, default=5, help="Number of local documents to retrieve, 1-10.")
    parser.add_argument("--index-root", default=str(REPO_ROOT), help="Repo subfolder to index. Must stay in repo.")
    parser.add_argument("--output", help="Optional Markdown output path under security_copilot/sample-output.")
    return parser.parse_args()


def main():
    try:
        args = parse_args()
        result = answer_question(args.question, index_root=args.index_root, top_k=args.top_k)
        markdown = render_markdown(result)
        print(markdown)
        if args.output:
            saved_path = save_markdown(markdown, args.output)
            print(f"\nAnswer saved to {saved_path}")
    except ValueError as error:
        raise SystemExit(f"Error: {error}") from error


if __name__ == "__main__":
    main()
