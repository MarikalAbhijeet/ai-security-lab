"""Disabled-by-default online enrichment hooks for email indicators."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class ProviderResult:
    """One provider status/result row for dashboard display."""

    provider: str
    status: str = "Offline only"
    threat_result: str = "Unknown"
    score: str = "Not checked"
    note: str = "Offline / Not checked"
    indicator: str = "-"
    indicator_type: str = "-"
    raw_details: dict = field(default_factory=dict)


@dataclass
class EnrichmentResult:
    """Online enrichment status and findings."""

    status: str = "Offline analysis only"
    enabled: bool = False
    findings: list[str] = field(default_factory=list)
    provider_results: list[ProviderResult] = field(default_factory=list)
    total_indicators_checked: int = 0
    total_threats_found: int = 0
    highest_provider_score: str = "Not checked"
    urls_checked: int = 0
    domains_checked: int = 0
    ips_checked: int = 0
    hashes_checked: int = 0
    providers_checked: int = 0


PROVIDERS = {
    "Google Safe Browsing": "GOOGLE_SAFE_BROWSING_API_KEY",
    "VirusTotal": "VIRUSTOTAL_API_KEY",
    "AbuseIPDB": "ABUSEIPDB_API_KEY",
    "URLhaus": "URLHAUS_API_KEY",
    "urlscan.io": "URLSCAN_API_KEY",
}


def enrich_indicators(
    indicators: list[str] | list[dict],
    env: dict[str, str] | None = None,
    timeout_seconds: int = 5,
    mock_results: list[ProviderResult] | None = None,
) -> EnrichmentResult:
    """Return disabled-by-default enrichment status without live API calls."""
    env = env or os.environ
    normalized_indicators = normalize_indicators(indicators)
    enabled = str(env.get("EMAIL_ONLINE_ENRICHMENT", "false")).lower() == "true"
    if not enabled:
        return build_result("Offline analysis only", False, offline_provider_results(), normalized_indicators)

    if mock_results is not None:
        return build_result("Mocked online enrichment results", True, mock_results, normalized_indicators)

    provider_results = []
    for provider, key_name in PROVIDERS.items():
        if not env.get(key_name):
            provider_results.append(
                ProviderResult(
                    provider=provider,
                    status="Not configured",
                    threat_result="Unknown",
                    score="Not checked",
                    note="No API key configured",
                )
            )
        else:
            provider_results.append(
                ProviderResult(
                    provider=provider,
                    status="Configured",
                    threat_result="Unknown",
                    score="Not checked",
                    note="Configured but live lookups are disabled in this MVP adapter",
                )
            )
    if all(result.status == "Not configured" for result in provider_results):
        return build_result("Online enrichment not configured", True, provider_results, normalized_indicators)
    return EnrichmentResult(
        status="Online enrichment adapter ready, live calls disabled in MVP tests",
        enabled=True,
        findings=[f"{len(normalized_indicators)} extracted indicators would be enriched with strict timeouts."],
        provider_results=provider_results,
        total_indicators_checked=len(normalized_indicators),
        providers_checked=len([result for result in provider_results if result.status in {"Configured", "Checked"}]),
        urls_checked=count_type(normalized_indicators, "URL"),
        domains_checked=count_type(normalized_indicators, "Domain"),
        ips_checked=count_type(normalized_indicators, "IP Address"),
        hashes_checked=count_type(normalized_indicators, "Hash"),
    )


def offline_provider_results() -> list[ProviderResult]:
    """Return provider cards for offline-only mode."""
    return [ProviderResult(provider=provider) for provider in PROVIDERS]


def build_result(status: str, enabled: bool, provider_results: list[ProviderResult], indicators: list[dict]) -> EnrichmentResult:
    """Build enrichment result summary metrics."""
    threats = [result for result in provider_results if result.threat_result == "Threat found"]
    checked = [result for result in provider_results if result.status == "Checked"]
    return EnrichmentResult(
        status=status,
        enabled=enabled,
        findings=[result.note for result in provider_results if result.note],
        provider_results=provider_results,
        total_indicators_checked=len(indicators) if checked else 0,
        total_threats_found=len(threats),
        highest_provider_score=highest_score(provider_results),
        urls_checked=count_type(indicators, "URL") if checked else 0,
        domains_checked=count_type(indicators, "Domain") if checked else 0,
        ips_checked=count_type(indicators, "IP Address") if checked else 0,
        hashes_checked=count_type(indicators, "Hash") if checked else 0,
        providers_checked=len(checked),
    )


def normalize_indicators(indicators: list[str] | list[dict]) -> list[dict]:
    """Normalize indicators into type/value dictionaries."""
    normalized = []
    for item in indicators:
        if isinstance(item, dict):
            value = str(item.get("value", "")).strip()
            indicator_type = str(item.get("type", "Unknown")).strip()
        else:
            value = str(item).strip()
            indicator_type = "Unknown"
        if value:
            normalized.append({"type": indicator_type, "value": value})
    return normalized


def count_type(indicators: list[dict], indicator_type: str) -> int:
    """Count indicators by type."""
    return len([item for item in indicators if item.get("type") == indicator_type])


def highest_score(provider_results: list[ProviderResult]) -> str:
    """Return highest available provider score string."""
    scores = [result.score for result in provider_results if result.score not in {"", "Not checked", "Unknown"}]
    if not scores:
        return "Not checked"
    return scores[0]
