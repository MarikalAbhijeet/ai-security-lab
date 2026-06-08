"""Tests for disabled-by-default online enrichment hooks."""

import json
import ssl
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from online_enrichment import ProviderResult, enrich_indicators, post_form  # noqa: E402


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
        self.assertTrue(all(item.status == "Not enabled" for item in result.provider_results[1:3]))
        self.assertEqual(result.provider_results[3].provider, "URLhaus")
        self.assertEqual(result.provider_results[3].status, "Not configured")
        self.assertEqual(result.provider_results[3].note, "Missing API key")
        self.assertEqual(result.provider_results[4].status, "Not enabled")
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

        inactive = [result.provider_results[1], result.provider_results[2], result.provider_results[4]]
        self.assertTrue(inactive)
        self.assertTrue(all(item.status == "Not enabled" for item in inactive))
        self.assertTrue(all(item.threat_result == "Not checked" for item in inactive))
        self.assertTrue(all(item.note == "Provider adapter not enabled in this step." for item in inactive))
        self.assertNotIn("Missing API key", "\n".join(item.note for item in inactive))

    def test_missing_api_key_shown_for_implemented_providers_when_keys_absent(self):
        result = enrich_indicators(
            [{"type": "URL", "value": "hxxps://example[.]invalid/login"}],
            env={"EMAIL_ONLINE_ENRICHMENT": "true"},
        )

        google = result.provider_results[0]
        urlhaus = result.provider_results[3]
        inactive = [result.provider_results[1], result.provider_results[2], result.provider_results[4]]
        self.assertEqual(google.provider, "Google Safe Browsing")
        self.assertEqual(google.status, "Not configured")
        self.assertEqual(google.note, "Missing API key")
        self.assertEqual(urlhaus.provider, "URLhaus")
        self.assertEqual(urlhaus.status, "Not configured")
        self.assertEqual(urlhaus.note, "Missing API key")
        self.assertTrue(all(item.status == "Not enabled" for item in inactive))
        self.assertTrue(all(item.note != "Missing API key" for item in inactive))

    def test_urlhaus_not_called_when_toggle_off(self):
        def fail_if_called(_url, _form_data, _headers, _timeout):
            raise AssertionError("URLhaus should not be called while enrichment is disabled.")

        result = enrich_indicators(
            [{"type": "URL", "value": "hxxps://example[.]invalid/login"}],
            env={"EMAIL_ONLINE_ENRICHMENT": "false", "URLHAUS_AUTH_KEY": "fake-urlhaus-key"},
            urlhaus_post=fail_if_called,
        )

        self.assertFalse(result.enabled)
        self.assertEqual(result.providers_checked, 0)

    def test_urlhaus_not_called_when_key_missing(self):
        def fail_if_called(_url, _form_data, _headers, _timeout):
            raise AssertionError("URLhaus should not be called without an Auth-Key.")

        result = enrich_indicators(
            [{"type": "URL", "value": "hxxps://example[.]invalid/login"}],
            env={"EMAIL_ONLINE_ENRICHMENT": "true"},
            urlhaus_post=fail_if_called,
        )

        urlhaus = result.provider_results[3]
        self.assertEqual(urlhaus.provider, "URLhaus")
        self.assertEqual(urlhaus.status, "Not configured")
        self.assertEqual(urlhaus.note, "Missing API key")

    def test_urlhaus_receives_only_extracted_urls(self):
        captured = {}

        def mock_urlhaus_post(url, form_data, headers, timeout):
            captured["url"] = url
            captured["form_data"] = form_data
            captured["headers"] = headers
            captured["timeout"] = timeout
            return 200, json.dumps({"query_status": "no_results"})

        result = enrich_indicators(
            [
                {"type": "URL", "value": "hxxps://download[.]example[.]invalid/payload.exe"},
                {"type": "Domain", "value": "example[.]invalid"},
                {"type": "IP Address", "value": "203[.]0[.]113[.]20"},
                {"type": "Attachment", "value": "payload.exe"},
                {"type": "Header", "value": "Authentication-Results: raw header"},
                {"type": "Body", "value": "raw email body should never be submitted"},
            ],
            env={"EMAIL_ONLINE_ENRICHMENT": "true", "URLHAUS_AUTH_KEY": "fake-urlhaus-key"},
            urlhaus_post=mock_urlhaus_post,
        )

        self.assertEqual(captured["form_data"], {"url": "https://download.example.invalid/payload.exe"})
        self.assertEqual(captured["headers"], {"Auth-Key": "fake-urlhaus-key"})
        sent_text = json.dumps(captured["form_data"])
        self.assertNotIn("raw email body", sent_text)
        self.assertNotIn("Authentication-Results", sent_text)
        self.assertNotIn("payload.exe", sent_text.replace("payload.exe", "", 1))
        self.assertEqual(result.provider_results[3].threat_result, "Clean")

    def test_mocked_urlhaus_no_match_response(self):
        def mock_urlhaus_post(_url, _form_data, _headers, _timeout):
            return 200, json.dumps({"query_status": "no_results"})

        result = enrich_indicators(
            [{"type": "URL", "value": "hxxps://clean[.]example[.]invalid/login"}],
            env={"EMAIL_ONLINE_ENRICHMENT": "true", "URLHAUS_AUTH_KEY": "fake-urlhaus-key"},
            urlhaus_post=mock_urlhaus_post,
        )

        urlhaus = result.provider_results[3]
        self.assertEqual(urlhaus.status, "Checked")
        self.assertEqual(urlhaus.threat_result, "Clean")
        self.assertEqual(urlhaus.score, "0 detections")
        self.assertEqual(urlhaus.raw_details["provider"], "URLhaus")
        self.assertEqual(urlhaus.raw_details["verdict"], "Clean")

    def test_mocked_urlhaus_match_response(self):
        def mock_urlhaus_post(_url, _form_data, _headers, _timeout):
            return 200, json.dumps(
                {
                    "query_status": "ok",
                    "url_status": "online",
                    "threat": "malware_download",
                    "malware_family": "DemoLoader",
                    "tags": ["exe", "loader"],
                }
            )

        result = enrich_indicators(
            [{"type": "URL", "value": "hxxps://bad[.]example[.]invalid/payload.exe"}],
            env={"EMAIL_ONLINE_ENRICHMENT": "true", "URLHAUS_AUTH_KEY": "fake-urlhaus-key"},
            urlhaus_post=mock_urlhaus_post,
        )

        urlhaus = result.provider_results[3]
        self.assertEqual(urlhaus.status, "Checked")
        self.assertEqual(urlhaus.threat_result, "Threat found")
        self.assertEqual(urlhaus.score, "Match found")
        self.assertIn("DemoLoader", urlhaus.details)
        self.assertEqual(result.total_threats_found, 1)

    def test_mocked_urlhaus_timeout_and_rate_limit(self):
        def timeout_post(_url, _form_data, _headers, _timeout):
            raise TimeoutError("timed out")

        timeout_result = enrich_indicators(
            [{"type": "URL", "value": "hxxps://slow[.]example[.]invalid/login"}],
            env={"EMAIL_ONLINE_ENRICHMENT": "true", "URLHAUS_AUTH_KEY": "fake-urlhaus-key"},
            urlhaus_post=timeout_post,
        )
        self.assertEqual(timeout_result.provider_results[3].status, "Error")
        self.assertEqual(timeout_result.provider_results[3].note, "Provider timeout")

        def rate_limit_post(_url, _form_data, _headers, _timeout):
            return 429, "{}"

        rate_result = enrich_indicators(
            [{"type": "URL", "value": "hxxps://limited[.]example[.]invalid/login"}],
            env={"EMAIL_ONLINE_ENRICHMENT": "true", "URLHAUS_AUTH_KEY": "fake-urlhaus-key"},
            urlhaus_post=rate_limit_post,
        )
        self.assertEqual(rate_result.provider_results[3].status, "Rate limited")

    def test_urlhaus_http_client_uses_verified_ssl_context(self):
        captured = {}

        class MockResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, _exc_type, _exc, _traceback):
                return False

            def read(self):
                return b'{"query_status":"no_results"}'

        def mock_urlopen(request, timeout, context):
            captured["request"] = request
            captured["timeout"] = timeout
            captured["context"] = context
            return MockResponse()

        with patch("online_enrichment.urlopen", mock_urlopen):
            status_code, body = post_form(
                "https://urlhaus-api.abuse.ch/v1/url/",
                {"url": "https://example.invalid/login"},
                {"Auth-Key": "fake-urlhaus-key"},
                5,
            )

        self.assertEqual(status_code, 200)
        self.assertIn("no_results", body)
        self.assertIsInstance(captured["context"], ssl.SSLContext)
        self.assertTrue(captured["context"].check_hostname)
        self.assertEqual(captured["context"].verify_mode, ssl.CERT_REQUIRED)
        self.assertNotEqual(captured["context"].verify_mode, ssl.CERT_NONE)
        self.assertEqual(captured["timeout"], 5)

    def test_urlhaus_ssl_failure_is_handled_safely(self):
        def ssl_failure_post(_url, _form_data, _headers, _timeout):
            raise URLError(ssl.SSLCertVerificationError("certificate verify failed"))

        result = enrich_indicators(
            [{"type": "URL", "value": "hxxps://ssl[.]example[.]invalid/login"}],
            env={"EMAIL_ONLINE_ENRICHMENT": "true", "URLHAUS_AUTH_KEY": "fake-urlhaus-key"},
            urlhaus_post=ssl_failure_post,
        )

        urlhaus = result.provider_results[3]
        self.assertEqual(urlhaus.status, "Error")
        self.assertEqual(urlhaus.threat_result, "Unknown")
        self.assertEqual(urlhaus.score, "Not checked")
        self.assertEqual(urlhaus.details, "SSL certificate verification failed. Check local Python CA bundle.")
        self.assertEqual(urlhaus.error, "SSL certificate verification failed. Check local Python CA bundle.")
        self.assertNotIn("Traceback", urlhaus.details)

    def test_google_and_urlhaus_configured_count_two_providers_one_unique_url(self):
        def mock_google_post(_url, _payload, _timeout):
            return 200, "{}"

        urlhaus_calls = []

        def mock_urlhaus_post(_url, form_data, _headers, _timeout):
            urlhaus_calls.append(form_data["url"])
            return 200, json.dumps({"query_status": "no_results"})

        result = enrich_indicators(
            [
                {"type": "URL", "value": "hxxps://clean[.]example[.]invalid/login"},
                {"type": "URL", "value": "hxxps://clean[.]example[.]invalid/login"},
            ],
            env={
                "EMAIL_ONLINE_ENRICHMENT": "true",
                "GOOGLE_SAFE_BROWSING_API_KEY": "fake-google-key",
                "URLHAUS_AUTH_KEY": "fake-urlhaus-key",
            },
            http_post=mock_google_post,
            urlhaus_post=mock_urlhaus_post,
        )

        self.assertEqual(result.providers_checked, 2)
        self.assertEqual(result.urls_checked, 1)
        self.assertEqual(urlhaus_calls, ["https://clean.example.invalid/login"])

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
