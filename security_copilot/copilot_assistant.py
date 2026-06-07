"""Local-first AI Security Copilot orchestrator."""

from __future__ import annotations

import argparse
from pathlib import Path

from config import CopilotConfig, load_config
from guardrails import BLOCK_PATTERNS, evaluate_question
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


def answer_question(
    question: str,
    answer_mode="SOC Analyst",
    top_k=5,
    index_root=None,
    config: CopilotConfig | None = None,
    session_context: str | None = None,
) -> dict:
    """Run guardrails, retrieval, and local LLM synthesis."""
    answer_mode = validate_answer_mode(answer_mode)
    config = config or load_config()
    guardrail = evaluate_question(question)
    safe_session_context = validate_session_context(session_context)

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
    evidence_focused = is_evidence_focused_question(guardrail.sanitized_question, safe_session_context)
    chunks = [] if evidence_focused else retrieve(guardrail.sanitized_question, index_root=index_root, top_k=top_k)
    source_citations = []
    if safe_session_context and evidence_focused:
        source_citations.insert(
            0,
            {
                "path": "Uploaded evidence summary from current session",
                "heading": "Threat Evidence Workbench",
                "score": 1.0,
            },
        )
    else:
        source_citations = citations(chunks)
        if safe_session_context:
            source_citations.insert(
                0,
                {
                    "path": "Uploaded evidence summary from current session",
                    "heading": "Threat Evidence Workbench",
                    "score": 1.0,
                },
            )
    retrieval_confidence = "Evidence-focused answer: cited current-session evidence summary only." if evidence_focused else confidence_note(chunks)
    if safe_session_context and not evidence_focused:
        retrieval_confidence = f"{retrieval_confidence} Current-session evidence summary was also provided to the model."
    context = "" if evidence_focused else format_context(chunks)
    if safe_session_context and evidence_focused:
        context = "[Uploaded Evidence Summary from current session]\n" + safe_session_context
    elif safe_session_context:
        context = "\n\n".join(
            [
                context,
                "[Uploaded Evidence Summary from current session]\n" + safe_session_context,
            ]
        )

    has_context = bool(safe_session_context) or (chunks and chunks[0].score >= 0.03)
    if not has_context:
        answer = "I do not have enough local AI Security Lab context to answer that question confidently."
        setup_required = False
    else:
        llm_response = chat(config, guardrail.sanitized_question, answer_mode, context, status=status)
        answer = llm_response.answer
        if safe_session_context:
            if evidence_focused:
                answer = build_evidence_focused_answer(safe_session_context, answer)
            else:
                answer = append_session_ioc_section(answer, safe_session_context)
        setup_required = llm_response.setup_required
        timed_out = llm_response.timed_out
        generation_error = llm_response.last_error

    if not has_context:
        timed_out = False
        generation_error = ""

    if setup_required and not config.uses_mock:
        next_steps = ["Start Ollama locally.", "Run `ollama pull qwen2.5:3b`.", "Run `ollama run qwen2.5:3b`.", "Ask the question again."]
    elif timed_out:
        next_steps = ["Ask the question again.", "Reduce retrieved sources.", "Confirm the local model has finished loading.", "Consider a smaller local model if the workstation is resource constrained."]
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
        timed_out=timed_out,
        generation_error=generation_error,
        next_steps=next_steps,
        limitations=[
            "Uses local AI Security Lab documentation and sample files only.",
            "Generated answers require human review before operational use.",
            "Do not use this lab with real company, client, tenant, vendor, or production data.",
        ],
        provider_message=status.message,
        provider_status=status,
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
        "timed_out": kwargs.get("timed_out", False),
        "provider_message": kwargs.get("provider_message", ""),
        "provider_status": format_provider_status(kwargs.get("provider_status"), config),
        "generation_error": kwargs.get("generation_error", ""),
        "retrieval_confidence": kwargs["retrieval_confidence"],
    }


def format_provider_status(status, config: CopilotConfig) -> dict:
    """Return dashboard-friendly provider status details."""
    if status is None:
        return {
            "provider": "mock" if config.uses_mock else config.provider,
            "model": config.ollama_model,
            "ollama_api_reachable": False,
            "model_installed": False,
            "health_timeout_seconds": config.ollama_health_timeout_seconds,
            "generation_timeout_seconds": config.ollama_timeout_seconds,
            "last_error": "",
        }
    return {
        "provider": status.provider,
        "model": status.model,
        "ollama_api_reachable": status.reachable,
        "model_installed": status.model_installed,
        "health_timeout_seconds": status.health_timeout_seconds,
        "generation_timeout_seconds": status.generation_timeout_seconds,
        "last_error": status.last_error,
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
            f"- Provider: {result['provider']}\n- Model: {result['model']}\n- Setup required: {result['setup_required']}\n- Timed out: {result['timed_out']}\n- Status: {result['provider_message']}",
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


def validate_session_context(session_context: str | None) -> str:
    """Validate bounded temporary dashboard context."""
    if session_context is None:
        return ""
    if not isinstance(session_context, str):
        raise ValueError("Session context must be text.")
    context = session_context.strip()
    if not context:
        return ""
    if len(context) > 5000:
        raise ValueError("Session context is too large for local Copilot analysis.")
    for label, pattern in BLOCK_PATTERNS:
        if pattern.search(context):
            raise ValueError(f"Session context contains possible {label} content and cannot be sent to the local model.")
    return context


def append_session_ioc_section(answer: str, session_context: str) -> str:
    """Ensure uploaded-evidence answers explicitly include extracted IOCs."""
    ioc_lines = extract_session_ioc_lines(session_context)
    if not ioc_lines:
        return answer
    heading = "## IOCs / Investigation Artifacts Observed"
    section_heading = "### Extracted From Threat Evidence Workbench Summary" if heading in answer else heading
    section = "\n".join(["", section_heading, *ioc_lines])
    return answer.rstrip() + "\n\n" + section


def build_evidence_focused_answer(session_context: str, _model_answer: str) -> str:
    """Build a deterministic SOC answer from safe uploaded evidence context."""
    ioc_lines = extract_session_ioc_lines(session_context)
    behavior_lines = extract_session_behavior_lines(session_context)
    metadata = extract_session_metadata(session_context)
    mitre_lines = extract_mitre_lines(behavior_lines)
    priority = highest_priority_finding(ioc_lines, behavior_lines)
    evidence_observed = evidence_observed_lines(ioc_lines, behavior_lines)
    actions = recommended_soc_actions(ioc_lines, behavior_lines)
    ticket_note = build_ticket_note(metadata, priority, ioc_lines, behavior_lines)

    sections = [
        "## Highest Priority Finding",
        priority,
        "## Why this matters",
        why_this_matters(ioc_lines, behavior_lines),
        "## Evidence Observed",
        "\n".join(evidence_observed) if evidence_observed else "- No concrete evidence lines were available in the session summary.",
        "## IOCs / Investigation Artifacts Observed",
        "\n".join(ioc_lines) if ioc_lines else "- No IOCs were extracted by the local rule set.",
        "## Recommended SOC Actions",
        "\n".join(actions),
        "## MITRE ATT&CK Mapping",
        "\n".join(mitre_lines) if mitre_lines else "- No MITRE mapping was present in the uploaded evidence summary.",
        "## Freshservice Ticket Note",
        ticket_note,
        "## Human Review Warning",
        "This response is based on a local, summarized evidence context from Threat Evidence Workbench. Validate all findings with a human analyst before operational action.",
    ]
    return "\n\n".join(sections)


def extract_session_ioc_lines(session_context: str) -> list[str]:
    """Extract safe IOC lines from the bounded session summary."""
    lines = []
    capture = False
    for line in session_context.splitlines():
        if line.strip() == "IOCs / Investigation Artifacts Observed:":
            capture = True
            continue
        if capture and line.strip() == "Suspicious behaviors:":
            break
        if capture and line.startswith("- "):
            lines.append(line)
    return lines[:20]


def extract_session_behavior_lines(session_context: str) -> list[str]:
    """Extract suspicious behavior lines from the bounded session summary."""
    lines = []
    capture = False
    for line in session_context.splitlines():
        if line.strip() == "Suspicious behaviors:":
            capture = True
            continue
        if capture and line.startswith("The Copilot answer must include"):
            break
        if capture and line.startswith("- "):
            lines.append(line)
    return lines[:12]


def extract_session_metadata(session_context: str) -> dict[str, str]:
    """Extract simple metadata from the evidence summary."""
    metadata = {}
    for line in session_context.splitlines():
        if ": " in line and not line.startswith("- "):
            key, value = line.split(": ", 1)
            metadata[key.strip().lower()] = value.strip()
    return metadata


def extract_mitre_lines(behavior_lines: list[str]) -> list[str]:
    """Extract MITRE mapping snippets from behavior lines."""
    mappings = []
    for line in behavior_lines:
        marker = "MITRE: "
        if marker in line:
            mapping = line.split(marker, 1)[1].split("; ", 1)[0].strip()
            if mapping and f"- {mapping}" not in mappings:
                mappings.append(f"- {mapping}")
    return mappings


def highest_priority_finding(ioc_lines: list[str], behavior_lines: list[str]) -> str:
    """Select the highest priority evidence finding."""
    joined = "\n".join(ioc_lines + behavior_lines).lower()
    if "encodedcommand" in joined or "executionpolicy bypass" in joined or "invoke-webrequest" in joined:
        details = []
        if contains_value(ioc_lines, "WINWORD.EXE") and contains_value(ioc_lines, "powershell.exe"):
            details.append("WINWORD.EXE spawning powershell.exe")
        if "encodedcommand" in joined:
            details.append("encoded PowerShell")
        if "executionpolicy bypass" in joined:
            details.append("ExecutionPolicy Bypass")
        if "invoke-webrequest" in joined or "downloadstring" in joined:
            details.append("Invoke-WebRequest/download behavior")
        return "- Suspicious PowerShell execution chain observed: " + ", ".join(details) + "."
    if any(term in joined for term in ("successful login after failures", "failed mfa", "impossible travel", "new device", "risky country")):
        return "- Suspicious sign-in pattern observed with authentication risk indicators from the uploaded evidence."
    if "malware" in joined or "threat name" in joined:
        return "- Malware or Defender threat indicator observed in the uploaded evidence summary."
    return behavior_lines[0] if behavior_lines else "- Uploaded evidence contains extracted IOCs that require analyst review."


def why_this_matters(ioc_lines: list[str], behavior_lines: list[str]) -> str:
    """Return SOC impact explanation based on evidence."""
    joined = "\n".join(ioc_lines + behavior_lines).lower()
    reasons = []
    if "winword.exe" in joined and "powershell.exe" in joined:
        reasons.append("Office spawning PowerShell can indicate macro-driven execution or user-initiated payload staging.")
    if "encodedcommand" in joined or "executionpolicy bypass" in joined:
        reasons.append("Encoded PowerShell and policy bypass are common obfuscation and defense-evasion signals.")
    if "invoke-webrequest" in joined or "downloadstring" in joined:
        reasons.append("Download behavior can indicate payload retrieval or command-and-control staging.")
    if "failed mfa" in joined or "impossible travel" in joined or "successful login after failures" in joined:
        reasons.append("Authentication anomalies can indicate credential misuse or account takeover.")
    if "malware" in joined:
        reasons.append("Malware indicators require endpoint containment and timeline review.")
    if not reasons:
        reasons.append("The extracted indicators provide pivot points for identity, endpoint, network, and ticket review.")
    return "\n".join(f"- {reason}" for reason in reasons)


def evidence_observed_lines(ioc_lines: list[str], behavior_lines: list[str]) -> list[str]:
    """Build concrete evidence observations."""
    observations = []
    joined = "\n".join(ioc_lines + behavior_lines)
    for value in ("WINWORD.EXE", "powershell.exe", "EncodedCommand", "-ExecutionPolicy Bypass", "Invoke-WebRequest", "DownloadString"):
        if value in joined:
            observations.append(f"- Observed `{value}` in the uploaded evidence summary.")
    for line in behavior_lines[:6]:
        observations.append(line)
    return observations


def recommended_soc_actions(ioc_lines: list[str], behavior_lines: list[str]) -> list[str]:
    """Return evidence-specific SOC actions."""
    joined = "\n".join(ioc_lines + behavior_lines).lower()
    actions = [
        "- Pivot on the listed user, device, process, IP, URL/domain, and file path artifacts in Defender/Sentinel.",
        "- Preserve the evidence summary and document triage decisions in the ticket.",
    ]
    if "winword.exe" in joined and "powershell.exe" in joined:
        actions.insert(0, "- Review the endpoint process tree for WINWORD.EXE spawning powershell.exe and confirm whether a document or macro initiated execution.")
    if "encodedcommand" in joined:
        actions.insert(1, "- Decode the encoded PowerShell safely in a lab and compare it with script block and command-line telemetry.")
    if "invoke-webrequest" in joined or "downloadstring" in joined:
        actions.insert(2, "- Investigate download behavior, block or review the defanged URL/domain, and look for payload writes on the endpoint.")
    if "failed mfa" in joined or "impossible travel" in joined or "successful login after failures" in joined:
        actions.insert(0, "- Review sign-in timeline, MFA results, device state, source IPs, travel context, and recent privileged activity for the user.")
    if "malware" in joined:
        actions.insert(0, "- Check Defender alert timeline, malware name, file hash, quarantine status, and device isolation needs.")
    return actions


def build_ticket_note(metadata: dict[str, str], priority: str, ioc_lines: list[str], behavior_lines: list[str]) -> str:
    """Build a Freshservice-style ticket note."""
    file_name = metadata.get("file name", "uploaded evidence")
    severity = metadata.get("severity recommendation", "Review needed")
    ioc_preview = "; ".join(line.removeprefix("- ") for line in ioc_lines[:5]) or "No IOCs extracted"
    behavior_preview = "; ".join(line.removeprefix("- ") for line in behavior_lines[:3]) or "No suspicious behaviors extracted"
    return (
        f"Reviewed `{file_name}` in Threat Evidence Workbench. Severity recommendation: {severity}. "
        f"Highest priority: {priority.removeprefix('- ')} "
        f"Key IOCs: {ioc_preview}. Suspicious behaviors: {behavior_preview}. "
        "Local-only summarized evidence was used; human validation required."
    )


def contains_value(lines: list[str], value: str) -> bool:
    """Return True when a value appears in IOC lines."""
    return any(value in line for line in lines)


def is_evidence_focused_question(question: str, session_context: str) -> bool:
    """Return True when a question should cite only current-session evidence."""
    return bool(session_context)


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
