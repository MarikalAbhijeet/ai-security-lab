"""Tests for disabled-by-default online enrichment hooks."""

import json
import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from online_enrichment import ProviderResult, enrich_indicators  # noqa: E402


class OnlineEnrichmentTests(unittest.TestCase):
    def test_disabled_by_default(self):
        result = enrich_indicators(["example.invalid"], env={})

        self.assertFalse(result.enabled)
        self.assertEqual(result.status, "Offline analysis only")
        self.assertEqual(len(result.provider_results), 5)
        self.assertTrue(all(item.status == "Offline only" for item in result.provider_results))
        self.assertTrue(all(item.score == "Not checked" for item in result.provider_results))

    def test_enabled_without_keys_does_not_break(self):
        def fail_if_called(_url, _payload, _timeout):
            raise AssertionError("Google Safe Browsing should not be called without an API key.")

        result = enrich_indicators(
            [{"type": "URL", "value": "hxxps://example[.]invalid/login"}],
            env={"EMAIL_ONLINE_ENRICHMENT": "true"},
            http_post=fail_if_called,
        )

        self.assertTrue(result.enabled)
        self.assertEqual(result.status, "Online enrichment not configured")
        self.assertEqual(result.provider_results[0].status, "Not configured")
        self.assertEqual(result.provider_results[0].note, "Missing API key")
        self.assertTrue(all(item.status == "Not enabled" for item in result.provider_results[1:]))
        self.assertEqual(result.urls_checked, 0)

    def test_google_safe_browsing_not_called_when_toggle_off(self):
        def fail_if_called(_url, _payload, _timeout):
            raise AssertionError("Google Safe Browsing should not be called while enrichment is disabled.")

        result = enrich_indicators(
            [{"type": "URL", "value": "hxxps://example[.]invalid/login"}],
            env={"EMAIL_ONLINE_ENRICHMENT": "false", "GOOGLE_SAFE_BROWSING_API_KEY": "fake-test-key"},
            http_post=fail_if_called,
        )

        self.assertFalse(result.enabled)
        self.assertEqual(result.urls_checked, 0)
        self.assertEqual(result.providers_checked, 0)

    def test_google_safe_browsing_receives_only_extracted_urls(self):
        captured = {}

        def mock_post(url, payload, timeout):
            captured["url"] = url
            captured["payload"] = payload
            captured["timeout"] = timeout
            return 200, "{}"

        result = enrich_indicators(
            [
                {"type": "URL", "value": "hxxps://login[.]example[.]invalid/secure"},
                {"type": "Domain", "value": "example[.]invalid"},
                {"type": "IP Address", "value": "203[.]0[.]113[.]10"},
                {"type": "Attachment", "value": "invoice.html"},
                {"type": "Header", "value": "Authentication-Results: raw header"},
                {"type": "Body", "value": "raw email body should never be submitted"},
            ],
            env={"EMAIL_ONLINE_ENRICHMENT": "true", "GOOGLE_SAFE_BROWSING_API_KEY": "fake-test-key"},
            http_post=mock_post,
        )

        entries = captured["payload"]["threatInfo"]["threatEntries"]
        self.assertEqual(entries, [{"url": "https://login.example.invalid/secure"}])
        payload_text = json.dumps(captured["payload"])
        self.assertNotIn("raw email body", payload_text)
        self.assertNotIn("Authentication-Results", payload_text)
        self.assertNotIn("invoice.html", payload_text)
        self.assertEqual(result.urls_checked, 1)
        self.assertEqual(result.providers_checked, 1)

    def test_mocked_google_clean_response(self):
        def mock_post(_url, _payload, _timeout):
            return 200, "{}"

        result = enrich_indicators(
            [{"type": "URL", "value": "hxxps://clean[.]example[.]invalid/login"}],
            env={"EMAIL_ONLINE_ENRICHMENT": "true", "GOOGLE_SAFE_BROWSING_API_KEY": "fake-test-key"},
            http_post=mock_post,
        )

        google = result.provider_results[0]
        self.assertEqual(google.provider, "Google Safe Browsing")
        self.assertEqual(google.status, "Checked")
        self.assertEqual(google.threat_result, "Clean")
        self.assertEqual(google.raw_details["provider"], "Google Safe Browsing")
        self.assertEqual(google.raw_details["indicator"], "1 URL(s)")
        self.assertEqual(google.raw_details["indicator_type"], "URL")
        self.assertEqual(google.raw_details["status"], "Checked")
        self.assertEqual(google.raw_details["verdict"], "Clean")
        self.assertEqual(google.raw_details["score"], "0 detections")
        self.assertEqual(google.raw_details["details"], "No match found.")
        self.assertEqual(google.raw_details["error"], "")
        self.assertIn("checked_at", google.raw_details)
        self.assertEqual(result.total_threats_found, 0)
        self.assertEqual(result.urls_checked, 1)

    def test_non_implemented_providers_are_not_enabled_not_missing_key(self):
        def mock_post(_url, _payload, _timeout):
            return 200, "{}"

        result = enrich_indicators(
            [{"type": "URL", "value": "hxxps://clean[.]example[.]invalid/login"}],
            env={"EMAIL_ONLINE_ENRICHMENT": "true", "GOOGLE_SAFE_BROWSING_API_KEY": "fake-test-key"},
            http_post=mock_post,
        )

        inactive = result.provider_results[1:]
        self.assertTrue(inactive)
        self.assertTrue(all(item.status == "Not enabled" for item in inactive))
        self.assertTrue(all(item.threat_result == "Not checked" for item in inactive))
        self.assertTrue(all(item.note == "Provider adapter not enabled in this step." for item in inactive))
        self.assertNotIn("Missing API key", "\n".join(item.note for item in inactive))

    def test_missing_api_key_only_shown_for_google_when_key_absent(self):
        result = enrich_indicators(
            [{"type": "URL", "value": "hxxps://example[.]invalid/login"}],
            env={"EMAIL_ONLINE_ENRICHMENT": "true"},
        )

        google = result.provider_results[0]
        inactive = result.provider_results[1:]
        self.assertEqual(google.provider, "Google Safe Browsing")
        self.assertEqual(google.status, "Not configured")
        self.assertEqual(google.note, "Missing API key")
        self.assertTrue(all(item.status == "Not enabled" for item in inactive))
        self.assertTrue(all(item.note != "Missing API key" for item in inactive))

    def test_mocked_google_threat_response(self):
        def mock_post(_url, _payload, _timeout):
            return 200, json.dumps(
                {
                    "matches": [
                        {
                            "threatType": "SOCIAL_ENGINEERING",
                            "threat": {"url": "https://evil.example.invalid/login"},
                        }
                    ]
                }
            )

        result = enrich_indicators(
            [{"type": "URL", "value": "hxxps://evil[.]example[.]invalid/login"}],
            env={"EMAIL_ONLINE_ENRICHMENT": "true", "GOOGLE_SAFE_BROWSING_API_KEY": "fake-test-key"},
            http_post=mock_post,
        )

        google = result.provider_results[0]
        self.assertEqual(google.threat_result, "Threat found")
        self.assertEqual(google.indicator, "hxxps://evil[.]example[.]invalid/login")
        self.assertEqual(google.raw_details["verdict"], "Threat found")
        self.assertEqual(google.raw_details["details"], "SOCIAL_ENGINEERING")
        self.assertEqual(result.total_threats_found, 1)
        self.assertEqual(result.highest_provider_score, "1 match")

    def test_mocked_google_timeout_response(self):
        def mock_post(_url, _payload, _timeout):
            raise TimeoutError("timed out")

        result = enrich_indicators(
            [{"type": "URL", "value": "hxxps://slow[.]example[.]invalid/login"}],
            env={"EMAIL_ONLINE_ENRICHMENT": "true", "GOOGLE_SAFE_BROWSING_API_KEY": "fake-test-key"},
            http_post=mock_post,
        )

        google = result.provider_results[0]
        self.assertEqual(google.status, "Error")
        self.assertEqual(google.note, "Provider timeout")
        self.assertIn("timed out", google.error)

    def test_mocked_google_rate_limit_response(self):
        def mock_post(_url, _payload, _timeout):
            return 429, "{}"

        result = enrich_indicators(
            [{"type": "URL", "value": "hxxps://limited[.]example[.]invalid/login"}],
            env={"EMAIL_ONLINE_ENRICHMENT": "true", "GOOGLE_SAFE_BROWSING_API_KEY": "fake-test-key"},
            http_post=mock_post,
        )

        google = result.provider_results[0]
        self.assertEqual(google.status, "Rate limited")
        self.assertEqual(google.note, "Rate limited")

    def test_mocked_threat_results_calculate_counts(self):
        result = enrich_indicators(
            [{"type": "URL", "value": "hxxps://example[.]invalid/login"}],
            env={"EMAIL_ONLINE_ENRICHMENT": "true"},
            mock_results=[
                ProviderResult(
                    provider="VirusTotal",
                    status="Checked",
                    threat_result="Threat found",
                    score="2 detections",
                    note="Provider flagged this URL",
                    indicator="hxxps://example[.]invalid/login",
                    indicator_type="URL",
                )
            ],
        )

        self.assertEqual(result.total_threats_found, 1)
        self.assertEqual(result.total_indicators_checked, 1)
        self.assertEqual(result.urls_checked, 1)
        self.assertEqual(result.providers_checked, 1)


if __name__ == "__main__":
    unittest.main()
