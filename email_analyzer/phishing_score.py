"""Explainable email phishing/spam risk scoring."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ScoreResult:
    """Email score breakdown."""

    category_scores: dict[str, int] = field(default_factory=dict)
    overall_score: int = 0
    verdict: str = "Unable to Determine"
    reasons: list[str] = field(default_factory=list)


def calculate_score(header_findings, url_findings, attachment_findings, body_findings) -> ScoreResult:
    """Calculate explainable category and overall risk scores."""
    category_scores = {
        "Header/authentication risk": cap(sum(points(item.severity) for item in header_findings), 25),
        "Sender identity risk": cap(sum(points(item.severity) for item in header_findings if "mismatch" in item.title.lower() or "spoof" in item.title.lower() or "brand" in item.title.lower()), 20),
        "URL/domain risk": cap(sum(points(item.severity) for item in url_findings), 25),
        "Attachment risk": cap(sum(points(item.severity) for item in attachment_findings), 20),
        "Body/social-engineering risk": cap(sum(points(item.severity) for item in body_findings), 25),
        "AI/social-engineering likelihood": cap(8 if len(body_findings) >= 4 else 0, 10),
    }
    weighted = min(100, sum(category_scores.values()))
    reasons = [finding.title for finding in header_findings[:4]]
    reasons.extend(finding.reason for finding in url_findings[:4])
    reasons.extend(finding.reason for finding in attachment_findings[:4])
    reasons.extend(finding.title for finding in body_findings[:4])
    return ScoreResult(category_scores, weighted, verdict_for(weighted, reasons), dedupe(reasons)[:10])


def points(severity: str) -> int:
    """Map severity to scoring points."""
    return {"High": 18, "Medium": 10, "Low": 4}.get(severity, 3)


def cap(value: int, maximum: int) -> int:
    """Cap score value."""
    return min(maximum, value)


def verdict_for(score: int, reasons: list[str]) -> str:
    """Return user-facing verdict."""
    reason_text = " ".join(reasons).lower()
    if score >= 70:
        return "Likely Phishing"
    if "marketing" in reason_text and score < 45:
        return "Likely Spam"
    if score >= 45:
        return "Suspicious / Needs Review"
    if score >= 20:
        return "Needs Review"
    if score >= 1:
        return "Likely Benign"
    return "Unable to Determine"


def dedupe(values: list[str]) -> list[str]:
    """Deduplicate reason strings."""
    result = []
    seen = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result

