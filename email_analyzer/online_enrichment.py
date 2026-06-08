"""Disabled-by-default online enrichment hooks for email indicators."""

from __future__ import annotations

import json
import os
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlencode
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import certifi


GOOGLE_SAFE_BROWSING_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
URLHAUS_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
DEFAULT_TIMEOUT_SECONDS = 5


@dataclass
class ProviderResult:
    """One provider status/result row for dashboard display."""

    provider: str
    status: str = "Offline only"
    threat_result: str = "Unknown"
    verdict: str = "Unknown"
    score: str = "Not checked"
    note: str = "Offline / Not checked"
    indicator: str = "-"
    indicator_type: str = "-"
    details: str = ""
    error: str = ""
    checked_at: str = ""
    raw_details: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Keep legacy and normalized verdict fields in sync."""
        if self.verdict == "Unknown" and self.threat_result != "Unknown":
            self.verdict = self.threat_result
        if self.threat_result == "Unknown" and self.verdict != "Unknown":
            self.threat_result = self.verdict
        if not self.details:
            self.details = self.note
        if not self.raw_details:
            self.raw_details = normalized_provider_result(self)


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
    "URLhaus": "URLHAUS_AUTH_KEY",
    "urlscan.io": "URLSCAN_API_KEY",
}


def enrich_indicators(
    indicators: list[str] | list[dict],
    env: dict[str, str] | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    mock_results: list[ProviderResult] | None = None,
    http_post=None,
    urlhaus_post=None,
) -> EnrichmentResult:
    """Return disabled-by-default enrichment status for extracted indicators only."""
    env = env or os.environ
    normalized_indicators = normalize_indicators(indicators)
    enabled = str(env.get("EMAIL_ONLINE_ENRICHMENT", "false")).lower() == "true"
    if not enabled:
        return build_result("Offline analysis only", False, offline_provider_results(), normalized_indicators)

    if mock_results is not None:
        return build_result("Mocked online enrichment results", True, mock_results, normalized_indicators)

    provider_results = configured_provider_results(
        normalized_indicators,
        env,
        timeout_seconds,
        http_post=http_post,
        urlhaus_post=urlhaus_post,
    )
    if not any(result.status == "Checked" for result in provider_results) and any(
        result.provider == "Google Safe Browsing" and result.status == "Not configured"
        for result in provider_results
    ):
        return build_result("Online enrichment not configured", True, provider_results, normalized_indicators)
    return build_result("Online enrichment completed", True, provider_results, normalized_indicators)


def configured_provider_results(
    indicators: list[dict],
    env: dict[str, str],
    timeout_seconds: int,
    http_post=None,
    urlhaus_post=None,
) -> list[ProviderResult]:
    """Return implemented provider results plus non-implemented provider statuses."""
    results = []
    google_key = env.get("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if google_key:
        results.append(check_google_safe_browsing(indicators, google_key, timeout_seconds, http_post=http_post))
    else:
        results.append(missing_key_result("Google Safe Browsing"))

    for provider in ("VirusTotal", "AbuseIPDB"):
        results.append(
            ProviderResult(
                provider=provider,
                status="Not enabled",
                threat_result="Not checked",
                score="Not checked",
                note="Provider adapter not enabled in this step.",
                details="Provider adapter not enabled in this step.",
            )
        )

    urlhaus_key = env.get("URLHAUS_AUTH_KEY", "").strip()
    if urlhaus_key:
        results.append(check_urlhaus(indicators, urlhaus_key, timeout_seconds, urlhaus_post=urlhaus_post))
    else:
        results.append(missing_key_result("URLhaus"))

    results.append(
        ProviderResult(
            provider="urlscan.io",
            status="Not enabled",
            threat_result="Not checked",
            score="Not checked",
            note="Provider adapter not enabled in this step.",
            details="Provider adapter not enabled in this step.",
        )
    )
    return results


def check_google_safe_browsing(
    indicators: list[dict],
    api_key: str,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    http_post=None,
) -> ProviderResult:
    """Check extracted URLs with Google Safe Browsing v4."""
    url_indicators = [item for item in indicators if item.get("type") == "URL" and item.get("value")]
    checked_at = datetime.now(UTC).isoformat(timespec="seconds")
    if not url_indicators:
        return ProviderResult(
            provider="Google Safe Browsing",
            status="Checked",
            threat_result="Not found",
            score="0 URLs",
            note="No extracted URLs were available for Google Safe Browsing.",
            indicator="-",
            indicator_type="URL",
            checked_at=checked_at,
        )

    payload = google_safe_browsing_payload(url_indicators)
    endpoint = f"{GOOGLE_SAFE_BROWSING_ENDPOINT}?key={api_key}"
    try:
        status_code, response_text = (http_post or post_json)(endpoint, payload, timeout_seconds)
    except TimeoutError as error:
        return google_error_result("Error", "Provider timeout", str(error), checked_at)
    except HTTPError as error:
        if error.code == 429:
            return google_error_result("Rate limited", "Rate limited", "HTTP 429 rate limited", checked_at)
        return google_error_result("Error", "Provider error", f"HTTP {error.code}", checked_at)
    except (URLError, OSError, ValueError) as error:
        return google_error_result("Error", "Provider error", str(error), checked_at)

    if status_code == 429:
        return google_error_result("Rate limited", "Rate limited", "HTTP 429 rate limited", checked_at)
    if status_code >= 400:
        return google_error_result("Error", "Provider error", f"HTTP {status_code}", checked_at)

    try:
        data = json.loads(response_text or "{}")
    except json.JSONDecodeError as error:
        return google_error_result("Error", "Provider error", f"Invalid JSON response: {error}", checked_at)

    matches = data.get("matches", []) or []
    if matches:
        first_url = display_indicator(matches[0].get("threat", {}).get("url") or url_indicators[0]["value"])
        threat_types = sorted({str(match.get("threatType", "Unknown")) for match in matches})
        return ProviderResult(
            provider="Google Safe Browsing",
            status="Checked",
            threat_result="Threat found",
            score=f"{len(matches)} match{'es' if len(matches) != 1 else ''}",
            note="Provider flagged this URL.",
            indicator=first_url,
            indicator_type="URL",
            details=", ".join(threat_types),
            checked_at=checked_at,
        )

    return ProviderResult(
        provider="Google Safe Browsing",
        status="Checked",
        threat_result="Clean",
        score="0 detections",
        note="No match found.",
        indicator=f"{len(url_indicators)} URL(s)",
        indicator_type="URL",
        checked_at=checked_at,
    )


def check_urlhaus(
    indicators: list[dict],
    auth_key: str,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    urlhaus_post=None,
) -> ProviderResult:
    """Check extracted URLs with URLhaus by abuse.ch / Spamhaus."""
    url_indicators = [item for item in indicators if item.get("type") == "URL" and item.get("value")]
    checked_at = datetime.now(UTC).isoformat(timespec="seconds")
    if not url_indicators:
        return ProviderResult(
            provider="URLhaus",
            status="Checked",
            threat_result="Not found",
            score="0 URLs",
            note="No extracted URLs were available for URLhaus.",
            indicator="-",
            indicator_type="URL",
            checked_at=checked_at,
        )

    findings = []
    checked_count = 0
    try:
        for item in unique_url_indicators(url_indicators):
            checked_count += 1
            status_code, response_text = (urlhaus_post or post_form)(
                URLHAUS_ENDPOINT,
                {"url": refang(item["value"])},
                {"Auth-Key": auth_key},
                timeout_seconds,
            )
            if status_code == 429:
                return urlhaus_error_result("Rate limited", "Rate limit warning", "HTTP 429 rate limited", checked_at)
            if status_code >= 400:
                return urlhaus_error_result("Error", "Provider error", f"HTTP {status_code}", checked_at)
            data = json.loads(response_text or "{}")
            if urlhaus_response_is_match(data):
                findings.append((item, data))
    except TimeoutError as error:
        return urlhaus_error_result("Error", "Provider timeout", str(error), checked_at)
    except ssl.SSLCertVerificationError:
        return urlhaus_error_result(
            "Error",
            "SSL certificate verification failed. Check local Python CA bundle.",
            "SSL certificate verification failed. Check local Python CA bundle.",
            checked_at,
        )
    except HTTPError as error:
        if error.code == 429:
            return urlhaus_error_result("Rate limited", "Rate limit warning", "HTTP 429 rate limited", checked_at)
        return urlhaus_error_result("Error", "Provider error", f"HTTP {error.code}", checked_at)
    except URLError as error:
        if is_ssl_verification_error(error):
            return urlhaus_error_result(
                "Error",
                "SSL certificate verification failed. Check local Python CA bundle.",
                "SSL certificate verification failed. Check local Python CA bundle.",
                checked_at,
            )
        return urlhaus_error_result("Error", "Provider error", str(error), checked_at)
    except json.JSONDecodeError as error:
        return urlhaus_error_result("Error", "Provider error", f"Invalid JSON response: {error}", checked_at)
    except (OSError, ValueError) as error:
        return urlhaus_error_result("Error", "Provider error", str(error), checked_at)

    if findings:
        first_item, first_match = findings[0]
        return ProviderResult(
            provider="URLhaus",
            status="Checked",
            threat_result="Threat found",
            score="Match found",
            note=urlhaus_details(first_match),
            indicator=display_indicator(first_item["value"]),
            indicator_type="URL",
            details=urlhaus_details(first_match),
            checked_at=checked_at,
        )

    return ProviderResult(
        provider="URLhaus",
        status="Checked",
        threat_result="Clean",
        score="0 detections",
        note="No match found.",
        indicator=f"{checked_count} URL(s)",
        indicator_type="URL",
        details="No match found.",
        checked_at=checked_at,
    )


def google_safe_browsing_payload(url_indicators: list[dict]) -> dict:
    """Build a Safe Browsing request from original URLs only."""
    return {
        "client": {"clientId": "ai-security-lab", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": refang(item["value"])} for item in url_indicators],
        },
    }


def post_json(url: str, payload: dict, timeout_seconds: int) -> tuple[int, str]:
    """Post JSON with a strict timeout."""
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=timeout_seconds) as response:
        body = response.read().decode("utf-8")
        return int(getattr(response, "status", 200)), body


def post_form(url: str, form_data: dict, headers: dict, timeout_seconds: int) -> tuple[int, str]:
    """Post form data with a strict timeout."""
    request_headers = {"Content-Type": "application/x-www-form-urlencoded"}
    request_headers.update(headers)
    request = Request(
        url,
        data=urlencode(form_data).encode("utf-8"),
        headers=request_headers,
        method="POST",
    )
    with urlopen(request, timeout=timeout_seconds, context=verified_ssl_context()) as response:
        body = response.read().decode("utf-8")
        return int(getattr(response, "status", 200)), body


def verified_ssl_context() -> ssl.SSLContext:
    """Return a certifi-backed SSL context with certificate validation enabled."""
    context = ssl.create_default_context(cafile=certifi.where())
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def is_ssl_verification_error(error: URLError) -> bool:
    """Return True for wrapped SSL certificate verification errors."""
    reason = getattr(error, "reason", None)
    return isinstance(reason, ssl.SSLCertVerificationError) or "CERTIFICATE_VERIFY_FAILED" in str(error)


def google_error_result(status: str, note: str, error: str, checked_at: str) -> ProviderResult:
    """Return normalized Google Safe Browsing error state."""
    return ProviderResult(
        provider="Google Safe Browsing",
        status=status,
        threat_result="Unknown",
        score="Not checked",
        note=note,
        indicator="-",
        indicator_type="URL",
        error=error,
        checked_at=checked_at,
    )


def urlhaus_error_result(status: str, details: str, error: str, checked_at: str) -> ProviderResult:
    """Return normalized URLhaus error state."""
    return ProviderResult(
        provider="URLhaus",
        status=status,
        threat_result="Unknown",
        score="Not checked",
        note=details,
        indicator="-",
        indicator_type="URL",
        details=details,
        error=error,
        checked_at=checked_at,
    )


def missing_key_result(provider: str) -> ProviderResult:
    """Return normalized missing API key state."""
    return ProviderResult(
        provider=provider,
        status="Not configured",
        threat_result="Unknown",
        score="Not checked",
        note="Missing API key",
        details="No API key configured",
    )


def normalized_provider_result(result: ProviderResult) -> dict:
    """Return a dashboard-safe normalized provider result."""
    return {
        "provider": result.provider,
        "indicator": result.indicator,
        "indicator_type": result.indicator_type,
        "status": result.status,
        "verdict": result.threat_result,
        "score": result.score,
        "details": result.details,
        "error": result.error,
        "checked_at": result.checked_at,
    }


def offline_provider_results() -> list[ProviderResult]:
    """Return provider cards for offline-only mode."""
    return [ProviderResult(provider=provider) for provider in PROVIDERS]


def build_result(status: str, enabled: bool, provider_results: list[ProviderResult], indicators: list[dict]) -> EnrichmentResult:
    """Build enrichment result summary metrics."""
    threats = [result for result in provider_results if result.threat_result == "Threat found"]
    checked = [result for result in provider_results if result.status == "Checked"]
    checked_urls = unique_url_count(indicators) if checked else 0
    return EnrichmentResult(
        status=status,
        enabled=enabled,
        findings=[result.note for result in provider_results if result.note],
        provider_results=provider_results,
        total_indicators_checked=checked_urls,
        total_threats_found=len(threats),
        highest_provider_score=highest_score(provider_results),
        urls_checked=checked_urls,
        domains_checked=0,
        ips_checked=0,
        hashes_checked=0,
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


def checked_url_count(provider_results: list[ProviderResult]) -> int:
    """Return the number of URLs checked by Google Safe Browsing."""
    for result in provider_results:
        if result.provider == "Google Safe Browsing" and result.status == "Checked":
            return int(result.raw_details.get("urls_checked", 0))
    return 0


def unique_url_count(indicators: list[dict]) -> int:
    """Count unique extracted URLs."""
    return len({refang(item.get("value", "")) for item in indicators if item.get("type") == "URL" and item.get("value")})


def unique_url_indicators(url_indicators: list[dict]) -> list[dict]:
    """Return unique URL indicators while preserving order."""
    seen = set()
    unique = []
    for item in url_indicators:
        url = refang(item.get("value", ""))
        if not url or url in seen:
            continue
        seen.add(url)
        unique.append(item)
    return unique


def urlhaus_response_is_match(data: dict) -> bool:
    """Return True when URLhaus response indicates a known malicious URL."""
    query_status = str(data.get("query_status", "")).lower()
    url_status = str(data.get("url_status", "")).lower()
    if query_status in {"ok", "known"}:
        return True
    return url_status in {"online", "offline", "unknown"}


def urlhaus_details(data: dict) -> str:
    """Build a bounded URLhaus result details string."""
    parts = []
    for key, label in (
        ("threat", "Threat"),
        ("malware_family", "Malware family"),
        ("url_status", "URL status"),
    ):
        value = data.get(key)
        if value:
            parts.append(f"{label}: {value}")
    tags = data.get("tags")
    if isinstance(tags, list) and tags:
        parts.append("Tags: " + ", ".join(str(tag) for tag in tags[:5]))
    if not parts and data.get("query_status"):
        parts.append(f"Query status: {data['query_status']}")
    return "; ".join(parts) if parts else "Match found."


def count_type(indicators: list[dict], indicator_type: str) -> int:
    """Count indicators by type."""
    return len([item for item in indicators if item.get("type") == indicator_type])


def highest_score(provider_results: list[ProviderResult]) -> str:
    """Return highest available provider score string."""
    scores = [result.score for result in provider_results if result.score not in {"", "Not checked", "Unknown"}]
    if not scores:
        return "Not checked"
    return scores[0]


def refang(value: str) -> str:
    """Convert display-safe URL back to original form for provider API requests."""
    return (
        str(value)
        .replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
        .replace("[.]", ".")
    )


def display_indicator(value: str) -> str:
    """Defang URL/domain-like values for display."""
    display = str(value or "-")
    return display.replace("https://", "hxxps://").replace("http://", "hxxp://").replace(".", "[.]")
