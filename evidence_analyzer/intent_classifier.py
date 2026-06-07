"""Rule-based intent classification for evidence-aware Copilot questions."""

from __future__ import annotations


INTENTS = {
    "entity_risk_ranking",
    "ioc_listing",
    "kql_recommendation",
    "ticket_generation",
    "mitre_mapping",
    "containment_recommendation",
    "executive_summary",
    "severity_explanation",
    "investigation_steps",
    "general_question",
}


def classify_intent(question: str) -> str:
    """Classify a user question into a supported evidence answer intent."""
    text = str(question or "").lower()
    if any(term in text for term in ("which user", "which device", "most suspicious", "riskiest", "top risky", "highest risk")):
        return "entity_risk_ranking"
    if any(term in text for term in ("ioc", "iocs", "indicator", "artifact", "artifacts", "list all")):
        return "ioc_listing"
    if any(term in text for term in ("kql", "query", "hunt", "hunting")):
        return "kql_recommendation"
    if any(term in text for term in ("ticket", "freshservice", "incident note", "case note")):
        return "ticket_generation"
    if any(term in text for term in ("mitre", "att&ck", "attack mapping", "tactic")):
        return "mitre_mapping"
    if any(term in text for term in ("contain", "containment", "isolate", "escalate", "escalation")):
        return "containment_recommendation"
    if any(term in text for term in ("executive", "summary for leadership", "brief summary", "summarize for")):
        return "executive_summary"
    if any(term in text for term in ("severity", "how bad", "priority", "risk level")):
        return "severity_explanation"
    if any(term in text for term in ("investigate", "what happened", "what should", "next", "first", "triage", "soc action")):
        return "investigation_steps"
    return "general_question"
