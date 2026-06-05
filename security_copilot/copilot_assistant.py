"""Local-first AI Security Copilot orchestrator."""

from __future__ import annotations

import argparse
from pathlib import Path

from config import CopilotConfig, load_config
from guardrails import evaluate_question
from ollama_client import SETUP_INSTRUCTIONS, chat, provider_status
from retriever import REPO_ROOT, citations, confidence_note, retrieve


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_OUTPUT_PATH = PROJECT_ROOT / "sample-output" / "copilot_sample_answers.md"
ANSWER_MODES = [
    "SOC Analyst",
    "Executive Summary",
    "KQL Recommendation",
    "MITRE Mapping",
    "AI Security Review",
    "Vendor Risk Review",
    "Incident Response",
    "Detection Engineering",
]


def answer_question(question: str, answer_mode="SOC Analyst", top_k=5, index_root=None, config: CopilotConfig | None = None) -> dict:
    """Run guardrails, retrieval, and local LLM synthesis."""
    answer_mode = validate_answer_mode(answer_mode)
    config = config or load_config()
    guardrail = evaluate_question(question)

    if not guardrail.allowed:
        return build_result(
            question=question,
            answer="Request blocked by safety guardrails before retrieval or LLM processing.",
            answer_mode=answer_mode,
            config=config,
            guardrail=guardrail,
            sources=[],
            retrieval_confidence="No retrieval performed because guardrails blocked the question.",
            setup_required=False,
            next_steps=["Remove sensitive content and ask a short question about the local lab."],
            limitations=["The assistant cannot process secrets, credentials, pasted logs, or prompt-injection requests."],
        )

    status = provider_status(config)
    chunks = retrieve(guardrail.sanitized_question, index_root=index_root, top_k=top_k)
    source_citations = citations(chunks)
    retrieval_confidence = confidence_note(chunks)
    context = format_context(chunks)

    if not chunks or (chunks and chunks[0].score < 0.03):
        answer = "I do not have enough local AI Security Lab context to answer that question confidently."
        setup_required = False
    else:
        llm_response = chat(config, guardrail.sanitized_question, answer_mode, context)
        answer = llm_response.answer
        setup_required = llm_response.setup_required

    if setup_required and not config.uses_mock:
        next_steps = ["Start Ollama locally.", "Run `ollama pull qwen2.5:3b`.", "Run `ollama run qwen2.5:3b`.", "Ask the question again."]
    else:
        next_steps = default_next_steps(answer_mode)

    return build_result(
        question=guardrail.sanitized_question,
        answer=answer,
        answer_mode=answer_mode,
        config=config,
        guardrail=guardrail,
        sources=source_citations,
        retrieval_confidence=retrieval_confidence,
        setup_required=setup_required,
        next_steps=next_steps,
        limitations=[
            "Uses local AI Security Lab documentation and sample files only.",
            "Generated answers require human review before operational use.",
            "Do not use this lab with real company, client, tenant, vendor, or production data.",
        ],
        provider_message=status.message,
    )


def build_result(**kwargs) -> dict:
    """Build the structured assistant result."""
    config = kwargs["config"]
    guardrail = kwargs["guardrail"]
    return {
        "question": kwargs["question"],
        "answer_mode": kwargs["answer_mode"],
        "answer": kwargs["answer"],
        "recommended_next_steps": kwargs["next_steps"],
        "sources": kwargs["sources"],
        "limitations": kwargs["limitations"],
        "safety_note": (
            "Local-first lab assistant. Do not enter secrets, passwords, tokens, API keys, company logs, "
            "client data, tenant data, or vendor confidential data."
        ),
        "guardrails": {
            "allowed": guardrail.allowed,
            "warnings": guardrail.warnings,
        },
        "provider": "mock" if config.uses_mock else config.provider,
        "model": config.ollama_model,
        "setup_required": kwargs["setup_required"],
        "provider_message": kwargs.get("provider_message", ""),
        "retrieval_confidence": kwargs["retrieval_confidence"],
    }


def format_context(chunks) -> str:
    """Format retrieved chunks for prompt context."""
    if not chunks:
        return "No local context retrieved."
    formatted = []
    for index, chunk in enumerate(chunks, start=1):
        formatted.append(
            f"[Source {index}] {chunk.source_path} :: {chunk.heading} :: score={chunk.score:.4f}\n{chunk.text}"
        )
    return "\n\n".join(formatted)


def render_markdown(result: dict) -> str:
    """Render a structured result as Markdown."""
    sources = "\n".join(
        f"- `{source['path']}` :: {source['heading']} (score: {source['score']})"
        for source in result["sources"]
    ) or "- No local sources used."
    warnings = "\n".join(f"- {warning}" for warning in result["guardrails"]["warnings"]) or "- No guardrail warnings."
    steps = "\n".join(f"{index}. {step}" for index, step in enumerate(result["recommended_next_steps"], start=1))
    limitations = "\n".join(f"- {item}" for item in result["limitations"])

    return "\n\n".join(
        [
            "# Security Copilot Chat Answer",
            "## Question",
            result["question"],
            "## Answer Mode",
            result["answer_mode"],
            "## Answer",
            result["answer"],
            "## Recommended Next Steps",
            steps,
            "## Local Sources Used",
            sources,
            "## Guardrail Result",
            f"- Allowed: {result['guardrails']['allowed']}\n{warnings}",
            "## Provider",
            f"- Provider: {result['provider']}\n- Model: {result['model']}\n- Setup required: {result['setup_required']}\n- Status: {result['provider_message']}",
            "## Retrieval Confidence",
            result["retrieval_confidence"],
            "## Limitations",
            limitations,
            "## Safety Note",
            result["safety_note"],
        ]
    )


def save_markdown(markdown: str, output_path=None) -> Path:
    """Save Markdown output under sample-output."""
    path = resolve_output_path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(markdown + "\n", encoding="utf-8")
    return path


def resolve_output_path(output_path=None) -> Path:
    """Resolve and validate an output path."""
    path = Path(output_path or DEFAULT_OUTPUT_PATH).resolve()
    output_root = (PROJECT_ROOT / "sample-output").resolve()
    if path.suffix.lower() != ".md":
        raise ValueError("Output file must use the .md extension.")
    if path != output_root and output_root not in path.parents:
        raise ValueError("Output file must stay inside security_copilot/sample-output.")
    return path


def validate_answer_mode(answer_mode: str) -> str:
    """Validate answer mode."""
    if answer_mode not in ANSWER_MODES:
        raise ValueError("Answer mode must be one of: " + ", ".join(ANSWER_MODES))
    return answer_mode


def default_next_steps(answer_mode: str) -> list[str]:
    """Return answer-mode-specific next steps."""
    if answer_mode == "KQL Recommendation":
        return ["Review the cited local KQL examples.", "Adapt field names to the target workspace.", "Validate in a lab before production use."]
    if answer_mode == "Vendor Risk Review":
        return ["Review cited vendor risk notes.", "Document missing controls.", "Ask follow-up questions before approval."]
    return ["Review the cited local sources.", "Validate findings with a human analyst.", "Do not use real sensitive data in this lab."]


def parse_args():
    parser = argparse.ArgumentParser(description="Local-first AI Security Copilot using Ollama or mock mode.")
    parser.add_argument("--question", required=True, help="Security question to answer from local repo docs.")
    parser.add_argument("--answer-mode", "--mode", dest="mode", default="SOC Analyst", choices=ANSWER_MODES, help="Answer mode.")
    parser.add_argument("--top-k", type=int, default=5, help="Number of local chunks to retrieve, 1-10.")
    parser.add_argument("--index-root", default=str(REPO_ROOT), help="Repo subfolder to index. Must stay in repo.")
    parser.add_argument("--output", help="Optional Markdown output path under security_copilot/sample-output.")
    return parser.parse_args()


def main():
    try:
        args = parse_args()
        result = answer_question(args.question, answer_mode=args.mode, top_k=args.top_k, index_root=args.index_root)
        markdown = render_markdown(result)
        print(markdown)
        if args.output:
            saved_path = save_markdown(markdown, args.output)
            print(f"\nAnswer saved to {saved_path}")
    except ValueError as error:
        raise SystemExit(f"Error: {error}") from error


if __name__ == "__main__":
    main()
