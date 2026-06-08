"""Tests for disabled-by-default online enrichment hooks."""

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
        result = enrich_indicators(["example.invalid"], env={"EMAIL_ONLINE_ENRICHMENT": "true"})

        self.assertTrue(result.enabled)
        self.assertEqual(result.status, "Online enrichment not configured")
        self.assertTrue(all(item.status == "Not configured" for item in result.provider_results))

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
