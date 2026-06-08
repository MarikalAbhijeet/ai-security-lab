"""Local-first AI Security Copilot orchestrator."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from config import CopilotConfig, load_config
from guardrails import BLOCK_PATTERNS, evaluate_question
from ollama_client import SETUP_INSTRUCTIONS, chat, provider_status
from retriever import REPO_ROOT, citations, confidence_note, retrieve


PROJECT_ROOT = Path(__file__).resolve().parent
EVIDENCE_ANALYZER_DIR = PROJECT_ROOT.parent / "evidence_analyzer"
if str(EVIDENCE_ANALYZER_DIR) not in sys.path:
    sys.path.insert(0, str(EVIDENCE_ANALYZER_DIR))

from intent_classifier import classify_intent  # noqa: E402

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
    detected_intent = classify_intent(guardrail.sanitized_question)

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
            detected_intent=detected_intent,
        )

    status = provider_status(config)
    evidence_focused = is_evidence_focused_question(guardrail.sanitized_question, safe_session_context)
    retrieval_question = build_retrieval_question(guardrail.sanitized_question, safe_session_context)
    chunks = retrieve(retrieval_question, index_root=index_root, top_k=top_k)
    if safe_session_context:
        chunks = filter_evidence_chunks(chunks, safe_session_context)
        if not chunks:
            chunks = filter_evidence_chunks(
                retrieve(evidence_retrieval_hint(safe_session_context), index_root=index_root, top_k=top_k),
                safe_session_context,
            )
    source_citations = []
    if safe_session_context and evidence_focused:
        source_citations.insert(0, session_context_citation(safe_session_context))
        source_citations.extend(citations(chunks))
    else:
        source_citations = citations(chunks)
        if safe_session_context:
            source_citations.insert(0, session_context_citation(safe_session_context))
    retrieval_confidence = (
        "Evidence-focused answer: cited current-session evidence summary first, then matching local SOC sources."
        if evidence_focused
        else confidence_note(chunks)
    )
    if safe_session_context and not evidence_focused:
        retrieval_confidence = f"{retrieval_confidence} Current-session evidence summary was also provided to the model."
    context = format_context(chunks)
    if safe_session_context and evidence_focused:
        context = "\n\n".join(
            [
                "[Uploaded Evidence Summary from current session]\n" + safe_session_context,
                "[Matching local SOC playbook and automation sources]\n" + context,
            ]
        )
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
                answer = build_evidence_focused_answer(safe_session_context, answer, guardrail.sanitized_question, detected_intent)
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
        detected_intent=detected_intent,
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
        "detected_intent": kwargs.get("detected_intent", "general_question"),
    }


def session_context_citation(session_context: str) -> dict:
    """Return the correct source label for temporary dashboard context."""
    if "Uploaded email analysis summary" in session_context:
        return {
            "path": "Email Threat Analyzer summary from current session",
            "heading": "AI Email Threat Analyzer",
            "score": 1.0,
        }
    return {
        "path": "Uploaded evidence summary from current session",
        "heading": "Threat Evidence Workbench",
        "score": 1.0,
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


def build_retrieval_question(question: str, session_context: str) -> str:
    """Build a retrieval query that can use safe summarized session context."""
    if not session_context:
        return question
    context_terms = []
    for line in session_context.splitlines():
        if line.startswith(("Detected evidence type:", "- ")):
            context_terms.append(line)
        if len(" ".join(context_terms)) > 1000:
            break
    hint = evidence_retrieval_hint(session_context)
    return "\n".join([question, hint, *context_terms])


def evidence_retrieval_hint(session_context: str) -> str:
    """Return explicit retrieval hints for the uploaded evidence category."""
    context = session_context.lower()
    if any(term in context for term in ("sign-in", "signin", "entra", "failed mfa", "impossible travel", "risky country")):
        return "risky sign-in impossible travel failed MFA authentication SOC playbook KQL"
    if any(term in context for term in ("powershell", "encodedcommand", "winword.exe", "invoke-webrequest")):
        return "suspicious PowerShell encoded command endpoint SOC playbook KQL"
    if any(term in context for term in ("phishing", "email", "sender", "reply-to")):
        return "phishing response email investigation ticket KQL"
    if any(term in context for term in ("malware", "defender alert", "sha256", "threat name")):
        return "Defender malware alert investigation ticket KQL"
    if any(term in context for term in ("file deletion", "sharepoint", "onedrive", "mass deletion")):
        return "mass file deletion SharePoint OneDrive investigation KQL"
    return "SOC evidence investigation playbook KQL"


def filter_evidence_chunks(chunks, session_context: str):
    """Filter supporting sources so evidence answers avoid unrelated SOC scenarios."""
    evidence_type = extract_session_metadata(session_context).get("detected evidence type", "").lower()
    allowed_topics = evidence_allowed_topics(evidence_type, session_context.lower())
    filtered = []
    for chunk in chunks:
        source = chunk.source_path.lower()
        if "03-prompt-injection-lab/" in source:
            continue
        if not allowed_topics or source_matches_allowed_topic(source, allowed_topics):
            filtered.append(chunk)
    return filtered


def evidence_allowed_topics(evidence_type: str, context: str) -> set[str]:
    """Return allowed source topic slugs for the evidence type."""
    if any(term in evidence_type for term in ("sign-in", "signin", "entra", "iam", "mfa", "travel")):
        return {"risky-signin", "impossible-travel"}
    if any(term in evidence_type for term in ("powershell", "endpoint")):
        return {"suspicious-powershell", "malware"}
    if any(term in evidence_type for term in ("defender", "malware", "alert json")):
        return {"malware", "suspicious-powershell"}
    if any(term in evidence_type for term in ("phishing", "email")):
        return {"phishing", "risky-signin"}
    if any(term in evidence_type for term in ("file deletion", "sharepoint", "onedrive", "mass")):
        return {"mass-file-deletion", "malware"}
    if any(term in context for term in ("sign-in", "signin", "entra", "failed mfa", "impossible travel", "risky country")):
        return {"risky-signin", "impossible-travel"}
    if any(term in context for term in ("powershell", "encodedcommand", "winword.exe", "invoke-webrequest")):
        return {"suspicious-powershell", "malware"}
    if any(term in context for term in ("phishing", "email", "sender", "reply-to")):
        return {"phishing", "risky-signin"}
    if any(term in context for term in ("defender", "malware", "sha256", "threat name")):
        return {"malware", "suspicious-powershell"}
    if any(term in context for term in ("file deletion", "sharepoint", "onedrive", "mass deletion")):
        return {"mass-file-deletion", "malware"}
    return set()


def source_matches_allowed_topic(source: str, allowed_topics: set[str]) -> bool:
    """Return True when source matches the evidence topic or is general evidence documentation."""
    if "evidence_analyzer/" in source or source.endswith("automation/readme.md"):
        return True
    return any(topic in source for topic in allowed_topics)


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


def build_evidence_focused_answer(session_context: str, _model_answer: str, question: str, detected_intent: str) -> str:
    """Build a deterministic SOC answer from safe uploaded evidence context."""
    if "Uploaded email analysis summary" in session_context:
        return render_email_focused_answer(session_context, question, detected_intent)

    ioc_lines = extract_session_ioc_lines(session_context)
    behavior_lines = extract_session_behavior_lines(session_context)
    metadata = extract_session_metadata(session_context)
    risk_lines = extract_named_section_lines(session_context, "Risk scores:")
    kql_topics = extract_named_section_lines(session_context, "Recommended KQL topics:")
    soc_actions = extract_named_section_lines(session_context, "Recommended SOC actions:")
    mitre_lines = extract_mitre_lines(behavior_lines)
    priority = highest_priority_finding(ioc_lines, behavior_lines)
    evidence_observed = evidence_observed_lines(ioc_lines, behavior_lines)
    actions = soc_actions or recommended_soc_actions(ioc_lines, behavior_lines)
    ticket_note = build_ticket_note(metadata, priority, ioc_lines, behavior_lines)
    if detected_intent == "entity_risk_ranking":
        return render_entity_risk_answer(priority, risk_lines, evidence_observed, ioc_lines, actions, mitre_lines, question)
    if detected_intent == "ioc_listing":
        return render_ioc_answer(ioc_lines, session_context)
    if detected_intent == "kql_recommendation":
        return render_kql_answer(session_context, kql_topics, ioc_lines, question)
    if detected_intent == "ticket_generation":
        return render_ticket_answer(ticket_note, priority, evidence_observed, actions)
    if detected_intent == "mitre_mapping":
        return render_mitre_answer(mitre_lines, evidence_observed)
    if detected_intent == "containment_recommendation":
        return render_containment_answer(priority, evidence_observed, actions)
    if detected_intent == "executive_summary":
        return render_executive_answer(metadata, priority, behavior_lines, actions)
    if detected_intent == "severity_explanation":
        return render_severity_answer(metadata, priority, behavior_lines)

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


def render_email_focused_answer(session_context: str, question: str, detected_intent: str) -> str:
    """Render a user-friendly email-aware Copilot answer from summarized context."""
    metadata = extract_session_metadata(session_context)
    reasons = extract_named_section_lines(session_context, "Main reasons:")
    iocs = extract_named_section_lines(session_context, "IOCs / Investigation Artifacts Observed:")
    user_guidance = extract_named_section_lines(session_context, "Recommended user guidance:")
    soc_actions = extract_named_section_lines(session_context, "Recommended SOC actions:")
    enrichment_lines = extract_named_section_lines(session_context, "Online enrichment summary:")
    kql_topics = extract_named_section_lines(session_context, "Recommended KQL topics:")
    verdict = metadata.get("verdict", "Needs Review")
    risk_score = metadata.get("risk score", "Unknown")
    question_lower = question.lower()

    if detected_intent == "kql_recommendation":
        return render_kql_answer(session_context, kql_topics, iocs, question)
    if detected_intent == "ticket_generation":
        return "\n\n".join(
            [
                "## Freshservice-Style Ticket Note",
                "**Subject:** Reported suspicious email requires phishing/spam triage",
                f"**Verdict:** {verdict}",
                f"**Risk Score:** {risk_score}/100",
                f"**Summary:** {'; '.join(reason.removeprefix('- ') for reason in reasons[:4]) or 'Local email analysis requires review.'}",
                f"**User Guidance:** {' '.join(line.removeprefix('- ') for line in user_guidance[:2])}",
                f"**SOC Action:** {' '.join(action.removeprefix('- ') for action in soc_actions[:3])}",
                f"**Google Safe Browsing:** {single_line_enrichment_summary(enrichment_lines)}",
                "**Safety:** Raw email content was not sent to Ollama; this ticket is based on summarized local findings and defanged IOCs.",
            ]
        )
    if detected_intent == "ioc_listing":
        return render_ioc_answer(iocs, session_context)
    if "google safe browsing" in question_lower or "provider" in question_lower or "online enrichment" in question_lower:
        return "\n\n".join(
            [
                "## Local Email Analysis",
                f"- Verdict: {verdict}",
                f"- Risk Score: {risk_score}/100",
                "\n".join(reasons[:4]) if reasons else "- No strong local phishing indicators were found.",
                "## Google Safe Browsing Enrichment",
                "\n".join(enrichment_lines) if enrichment_lines else "- No Google Safe Browsing enrichment summary is active.",
                "## Safety Boundary",
                "- Only extracted URL indicators are eligible for Google Safe Browsing checks.",
                "- Raw email body, raw headers, attachments, and uploaded files are not sent to online providers.",
            ]
        )

    return "\n\n".join(
        [
            "## User-Friendly Answer",
            f"**Verdict:** {verdict}",
            f"**Risk Score:** {risk_score}/100",
            f"**What to tell the user:** {first_guidance(user_guidance, 'Report the email to IT/SOC and do not interact with it until reviewed.')}",
            "**What the user should not do:** Do not click links, scan QR codes, open attachments, reply, or enter credentials.",
            "## Why This Email Looks Suspicious",
            "\n".join(reasons[:6]) if reasons else "- The local email analyzer did not find enough high-confidence indicators.",
            "## Email IOCs / Investigation Artifacts",
            "\n".join(iocs[:15]) if iocs else "- No email IOCs were extracted.",
            "## Google Safe Browsing Enrichment",
            "\n".join(enrichment_lines) if enrichment_lines else "- Online enrichment was not enabled or no provider summary is active.",
            "## SOC Details",
            "\n".join(format_bullets_with_label(soc_actions[:6], "Recommended Action")) if soc_actions else "- **Recommended Action:** Review sender, authentication, URLs, attachments, and mailbox scope.",
            "## Human Review Warning",
            "This is a local lab result from summarized email analysis only. Validate before taking operational action.",
        ]
    )


def single_line_enrichment_summary(enrichment_lines: list[str]) -> str:
    """Return a compact enrichment summary for ticket answers."""
    google_lines = [line.removeprefix("- ").strip() for line in enrichment_lines if "Google Safe Browsing" in line]
    if google_lines:
        return " ".join(google_lines[:2])
    status_lines = [line.removeprefix("- ").strip() for line in enrichment_lines if line.strip()]
    return " ".join(status_lines[:2]) if status_lines else "No online enrichment summary was active."


def first_guidance(lines: list[str], fallback: str) -> str:
    """Return first guidance line without the bullet prefix."""
    if not lines:
        return fallback
    return lines[0].removeprefix("- ").strip()


def render_entity_risk_answer(priority: str, risk_lines: list[str], evidence_lines: list[str], ioc_lines: list[str], actions: list[str], mitre_lines: list[str], question: str) -> str:
    """Render entity risk ranking answer."""
    risk_rows = parse_risk_lines(risk_lines)
    if "user" in question.lower():
        user_rows = [row for row in risk_rows if row["type"].lower() == "user"]
        if user_rows:
            risk_rows = user_rows
    return "\n\n".join(
        [
            "### Highest Priority Entity",
            render_highest_entity_block(risk_rows, priority),
            "### Ranked Risk Summary",
            render_risk_table(risk_rows),
            "### Evidence Observed",
            render_evidence_summary(evidence_lines, ioc_lines),
            "### IOCs / Investigation Artifacts",
            "\n".join(ioc_lines[:12]) if ioc_lines else "- No IOCs were extracted by the local rule set.",
            "### Recommended SOC Actions",
            "\n".join(format_bullets_with_label(actions, "Recommended Action")),
            "### MITRE ATT&CK Mapping",
            "\n".join(mitre_lines) if mitre_lines else "- No MITRE mapping was present in the uploaded evidence summary.",
        ]
    )


def parse_risk_lines(risk_lines: list[str]) -> list[dict]:
    """Parse bounded risk-score summary bullets into display rows."""
    rows = []
    for line in risk_lines:
        clean = line.removeprefix("- ").strip()
        if not clean or ": " not in clean:
            continue
        entity_part, *parts = clean.split("; ")
        entity_type, entity = entity_part.split(": ", 1)
        row = {
            "type": entity_type.strip().title(),
            "entity": entity.strip(),
            "score": 0,
            "reasons": [],
            "review": "Validate against source telemetry.",
        }
        for part in parts:
            key, _, value = part.partition("=")
            key = key.strip().lower()
            value = value.strip()
            if key == "score":
                try:
                    row["score"] = int(value)
                except ValueError:
                    row["score"] = 0
            elif key == "reasons":
                row["reasons"] = [reason.strip() for reason in value.split(",") if reason.strip()]
            elif key == "review":
                row["review"] = value
        rows.append(row)
    return sorted(rows, key=lambda item: item["score"], reverse=True)


def render_highest_entity_block(risk_rows: list[dict], fallback_priority: str) -> str:
    """Render the top entity as a readable analyst summary."""
    if not risk_rows:
        return fallback_priority
    top = risk_rows[0]
    reasons = ", ".join(top["reasons"]) if top["reasons"] else "risk scoring reasons were not available"
    return "\n".join(
        [
            f"**{top['type']}:** `{top['entity']}`",
            f"**Risk Score:** `{top['score']}`",
            f"**Why it is suspicious:** {reasons}.",
            f"**Recommended Review:** {top['review']}",
        ]
    )


def render_risk_table(risk_rows: list[dict]) -> str:
    """Render risk scores as a Markdown table."""
    if not risk_rows:
        return "- No ranked entity risk scores were available in the evidence summary."
    rows = ["| Rank | Entity | Type | Score | Key Reasons |", "| --- | --- | --- | ---: | --- |"]
    for index, row in enumerate(risk_rows[:8], start=1):
        reasons = ", ".join(row["reasons"][:8]) if row["reasons"] else "No reason provided"
        rows.append(f"| {index} | `{row['entity']}` | {row['type']} | {row['score']} | {reasons} |")
    return "\n".join(rows)


def render_evidence_summary(evidence_lines: list[str], ioc_lines: list[str]) -> str:
    """Render compact evidence observations with labels."""
    lines = evidence_lines[:8] or ioc_lines[:8]
    if not lines:
        return "- No concrete evidence lines were available in the session summary."
    rendered = []
    for line in lines:
        clean = line.removeprefix("- ").strip()
        label, separator, value = clean.partition(":")
        if separator and len(label) <= 40:
            rendered.append(f"- **{label}:** {value.strip()}")
        else:
            rendered.append(f"- **Evidence:** {clean}")
    return "\n".join(rendered)


def parse_ioc_line(line: str) -> dict:
    """Parse a safe IOC display line from session summary."""
    clean = line.removeprefix("- ").strip()
    ioc_type, _, rest = clean.partition(": ")
    value, _, context = rest.partition("; ")
    return {
        "type": ioc_type.strip() or "Indicator",
        "value": value.strip() or clean,
        "context": context.strip() or "Uploaded evidence summary",
    }


def group_ioc_lines(ioc_lines: list[str]) -> dict[str, list[dict]]:
    """Group IOC lines by type for readable display."""
    grouped: dict[str, list[dict]] = {}
    for line in ioc_lines:
        parsed = parse_ioc_line(line)
        grouped.setdefault(parsed["type"], []).append(parsed)
    return grouped


def render_grouped_iocs(grouped: dict[str, list[dict]]) -> str:
    """Render grouped IOCs as compact Markdown tables."""
    if not grouped:
        return "- No IOCs were extracted by the local rule set."
    sections = []
    preferred_order = [
        "User",
        "Device / Host",
        "IP Address",
        "URL",
        "Domain",
        "Process",
        "Parent Process",
        "Command-Line Indicator",
        "File Path",
        "MD5",
        "SHA1",
        "SHA256",
        "Malware / Threat Name",
        "Authentication Indicator",
        "Privileged Activity Indicator",
    ]
    ordered_types = [ioc_type for ioc_type in preferred_order if ioc_type in grouped]
    ordered_types.extend(sorted(ioc_type for ioc_type in grouped if ioc_type not in ordered_types))
    for ioc_type in ordered_types:
        sections.append(f"#### {ioc_type}")
        sections.append("| Value | Source / Context |")
        sections.append("| --- | --- |")
        for item in grouped[ioc_type][:8]:
            sections.append(f"| `{item['value']}` | {item['context']} |")
    return "\n".join(sections)


def format_bullets_with_label(lines: list[str], label: str) -> list[str]:
    """Ensure action bullets have consistent bold labels."""
    formatted = []
    for line in lines:
        clean = line.removeprefix("- ").strip()
        if clean.startswith(f"**{label}:**"):
            formatted.append(f"- {clean}")
        else:
            formatted.append(f"- **{label}:** {clean}")
    return formatted


def short_text(value: str, limit: int) -> str:
    """Return a Markdown table friendly short value."""
    clean = " ".join(value.split())
    if len(clean) <= limit:
        return clean
    return clean[: limit - 3].rstrip() + "..."


def render_ioc_answer(ioc_lines: list[str], session_context: str) -> str:
    """Render IOC listing answer."""
    counts = extract_ioc_count_lines(session_context)
    grouped = group_ioc_lines(ioc_lines)
    return "\n\n".join(
        [
            "## IOCs / Investigation Artifacts Observed",
            render_grouped_iocs(grouped),
            "## IOC Counts",
            "\n".join(counts) if counts else "- IOC counts were not available.",
            "## High-Priority IOCs",
            "- **Recommended Action:** Start with the highest-risk user/device/process chain represented by the top IOCs, then pivot to related IPs, URLs/domains, hashes, and behaviors.",
            "## Validation Steps",
            "\n".join(
                [
                    "- Pivot users and devices in Defender/Sentinel.",
                    "- Search IPs, URLs, and domains in DNS, proxy, email, and endpoint telemetry.",
                    "- Validate process, file path, hash, and malware artifacts with endpoint timeline data.",
                ]
            ),
        ]
    )


def render_kql_answer(session_context: str, kql_topics: list[str], ioc_lines: list[str], question: str) -> str:
    """Render evidence-aware KQL answer with actual KQL."""
    evidence_type = extract_session_metadata(session_context).get("detected evidence type", "")
    kql = generate_evidence_kql(evidence_type, session_context, question)
    return "\n\n".join(
        [
            "### Recommended KQL",
            "Use this as a **sample-safe KQL** starting point for the uploaded evidence. Replace placeholders only in an approved lab workspace.",
            f"```kql\n{kql}\n```",
            "### Why this KQL is relevant",
            "\n".join(kql_topics[:6]) if kql_topics else "- It targets the main evidence type and extracted suspicious behaviors.",
            "### Fields to replace",
            "- **User:** `user@example.com`\n- **Device:** `DEVICE-NAME`\n- **IP Address:** `203.0.113.10`\n- **Domain:** `example.invalid`",
            "### Related IOCs",
            "\n".join(ioc_lines[:10]) if ioc_lines else "- No IOCs were extracted by the local rule set.",
            "### Local Sources Used",
            "- Matching local SOC playbooks and `automation/kql` sources are cited below this answer.",
        ]
    )


def render_ticket_answer(ticket_note: str, priority: str, evidence_lines: list[str], actions: list[str]) -> str:
    """Render Freshservice-style ticket answer."""
    return "\n\n".join(
        [
            "### Freshservice-style Ticket Note",
            "**Subject:** Security investigation required for uploaded evidence",
            "**Summary:** " + ticket_note,
            "### Evidence Observed",
            "\n".join(evidence_lines[:8]) if evidence_lines else "- No concrete evidence lines were available in the session summary.",
            "### Risk / Impact",
            priority,
            "### Recommended Action",
            "\n".join(format_bullets_with_label(actions, "Recommended Action")),
            "### Escalation",
            "- **Escalation:** Escalate if activity is confirmed, privileged access is involved, malware executed, or business-impacting data may be affected.",
            "### Human Review Note",
            "- **Human Review Note:** Local lab output requires analyst validation before action.",
        ]
    )


def render_mitre_answer(mitre_lines: list[str], evidence_lines: list[str]) -> str:
    """Render MITRE mapping answer."""
    table_rows = ["| Tactic | Technique | Why it applies | Evidence |", "| --- | --- | --- | --- |"]
    for mapping in mitre_lines or ["- No MITRE mapping was present in the uploaded evidence summary."]:
        clean = mapping.removeprefix("- ").strip()
        tactic, _, technique = clean.partition(":")
        table_rows.append(f"| {tactic or 'Unknown'} | {technique or clean} | Matched by uploaded evidence summary | {short_text('; '.join(evidence_lines[:2]), 120)} |")
    return "\n\n".join(
        [
            "### MITRE ATT&CK Mapping",
            "\n".join(table_rows),
            "### Supporting Evidence",
            "\n".join(evidence_lines[:8]) if evidence_lines else "- No concrete evidence lines were available in the session summary.",
            "### Analyst Validation Steps",
            "- Validate each mapping against the source telemetry, user/device context, and timeline before using it in an incident report.",
        ]
    )


def render_containment_answer(priority: str, evidence_lines: list[str], actions: list[str]) -> str:
    """Render containment recommendation answer."""
    return "\n\n".join(
        [
            "## Highest Priority Finding",
            priority,
            "## Evidence Observed",
            "\n".join(evidence_lines[:8]) if evidence_lines else "- No concrete evidence lines were available in the session summary.",
            "## Containment / Escalation",
            "\n".join(actions),
            "## Human Review Warning",
            "This lab does not perform containment. Use approved operational process after analyst validation.",
        ]
    )


def render_executive_answer(metadata: dict[str, str], priority: str, behavior_lines: list[str], actions: list[str]) -> str:
    """Render executive summary answer."""
    return "\n\n".join(
        [
            "## Executive Summary",
            f"Uploaded evidence `{metadata.get('file name', 'current session evidence')}` was assessed as `{metadata.get('severity recommendation', 'Review needed')}`. {priority.removeprefix('- ')}",
            "## Key Risk Drivers",
            "\n".join(behavior_lines[:5]) if behavior_lines else "- No suspicious behaviors were detected above the local rule threshold.",
            "## Recommended Next Steps",
            "\n".join(actions[:5]),
            "## Human Review Warning",
            "This is a local lab summary and must be validated by a human analyst.",
        ]
    )


def render_severity_answer(metadata: dict[str, str], priority: str, behavior_lines: list[str]) -> str:
    """Render severity explanation answer."""
    return "\n\n".join(
        [
            "## Severity Explanation",
            f"Recommended severity: `{metadata.get('severity recommendation', 'Review needed')}`.",
            "## Why",
            priority,
            "## Supporting Behaviors",
            "\n".join(behavior_lines[:8]) if behavior_lines else "- No suspicious behaviors were detected above the local rule threshold.",
            "## Human Review Warning",
            "Severity is a local rule-based recommendation, not a final incident classification.",
        ]
    )


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


def extract_named_section_lines(session_context: str, heading: str) -> list[str]:
    """Extract bullet lines from a named section in the session summary."""
    lines = []
    capture = False
    for line in session_context.splitlines():
        stripped = line.strip()
        if stripped == heading:
            capture = True
            continue
        if capture and stripped.endswith(":") and not stripped.startswith("- "):
            break
        if capture and stripped.startswith("- "):
            lines.append(stripped)
    return lines[:12]


def extract_ioc_count_lines(session_context: str) -> list[str]:
    """Extract IOC count lines from session context."""
    lines = []
    capture = False
    for line in session_context.splitlines():
        stripped = line.strip()
        if stripped == "IOC summary counts:":
            capture = True
            continue
        if capture and stripped == "Structured Evidence Intelligence Profile:":
            break
        if capture and stripped.startswith("- "):
            lines.append(stripped)
    return lines


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


def generate_evidence_kql(evidence_type: str, session_context: str, question: str) -> str:
    """Generate safe sample KQL for uploaded evidence intent."""
    text = f"{evidence_type}\n{session_context}\n{question}".lower()
    if any(term in text for term in ("sign-in", "signin", "mfa", "impossible travel", "risky country")):
        return "\n".join(
            [
                "// Sample Sentinel KQL for uploaded sign-in evidence. Demo only.",
                "let TargetUser = \"user@example.com\";",
                "SigninLogs",
                "| where UserPrincipalName =~ TargetUser or IPAddress == \"203.0.113.10\"",
                "| extend IsFailure = ResultType != 0",
                "| extend MfaIssue = ConditionalAccessStatus in~ (\"failure\", \"notApplied\") or Status has_any (\"MFA\", \"denied\", \"failed\")",
                "| extend RiskSignal = RiskLevelAggregated in~ (\"medium\", \"high\") or RiskState in~ (\"atRisk\", \"confirmedCompromised\")",
                "| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ResultType, ConditionalAccessStatus, RiskState, RiskLevelAggregated, DeviceDetail, Location",
                "| order by TimeGenerated desc",
            ]
        )
    if any(term in text for term in ("powershell", "encodedcommand", "invoke-webrequest", "downloadstring", "winword.exe")):
        return "\n".join(
            [
                "// Sample Defender KQL for uploaded PowerShell evidence. Demo only.",
                "DeviceProcessEvents",
                "| where DeviceName =~ \"DEVICE-NAME\" or AccountName has \"user\"",
                "| where FileName in~ (\"powershell.exe\", \"pwsh.exe\")",
                "| where ProcessCommandLine has_any (\"EncodedCommand\", \"-ExecutionPolicy Bypass\", \"Invoke-WebRequest\", \"DownloadString\", \"FromBase64String\", \"IEX\", \"-WindowStyle Hidden\")",
                "| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, ReportId",
                "| order by Timestamp desc",
            ]
        )
    if any(term in text for term in ("phishing", "email", "sender", "reply-to")):
        return "\n".join(
            [
                "// Sample Microsoft 365 Defender KQL for uploaded phishing evidence. Demo only.",
                "let SenderAddress = \"alerts@security-update.example.invalid\";",
                "let SenderDomain = \"security-update.example.invalid\";",
                "let SubjectKeyword = \"password expires\";",
                "",
                "EmailEvents",
                "| where SenderFromAddress =~ SenderAddress",
                "   or SenderFromDomain =~ SenderDomain",
                "   or Subject has SubjectKeyword",
                "| join kind=leftouter EmailUrlInfo on NetworkMessageId",
                "| join kind=leftouter EmailAttachmentInfo on NetworkMessageId",
                "| project Timestamp, SenderFromAddress, SenderFromDomain, RecipientEmailAddress, Subject, DeliveryAction, ThreatTypes, Url, FileName, SHA256",
                "| order by Timestamp desc",
            ]
        )
    if any(term in text for term in ("malware", "defender", "sha256", "threat")):
        return "\n".join(
            [
                "// Sample Defender KQL for uploaded malware evidence. Demo only.",
                "AlertInfo",
                "| where Title has_any (\"malware\", \"trojan\", \"defender\")",
                "| join kind=leftouter AlertEvidence on AlertId",
                "| where DeviceName =~ \"DEVICE-NAME\" or SHA256 == \"0000000000000000000000000000000000000000000000000000000000000000\"",
                "| project Timestamp, Title, Severity, Category, DeviceName, FileName, FolderPath, SHA256, AccountName, RemoteUrl",
                "| order by Timestamp desc",
            ]
        )
    if any(term in text for term in ("file deletion", "mass deletion", "sharepoint", "onedrive")):
        return "\n".join(
            [
                "// Sample Defender KQL for uploaded mass file deletion evidence. Demo only.",
                "DeviceFileEvents",
                "| where ActionType in~ (\"FileDeleted\", \"FileRenamed\")",
                "| summarize DeletedFileCount=count(), SampleFiles=make_set(FileName, 10) by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, bin(Timestamp, 15m)",
                "| where DeletedFileCount >= 25",
                "| order by DeletedFileCount desc",
            ]
        )
    return "SecurityEvent\n| take 50"


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
