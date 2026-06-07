"""Tests for evidence intent classification."""

import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from intent_classifier import classify_intent  # noqa: E402


class IntentClassifierTests(unittest.TestCase):
    def test_supported_intents(self):
        cases = {
            "Which user is most suspicious?": "entity_risk_ranking",
            "List all IOCs": "ioc_listing",
            "What KQL should I run?": "kql_recommendation",
            "What KQL should I run next for this uploaded sign-in evidence?": "kql_recommendation",
            "Give me KQL": "kql_recommendation",
            "Generate a query": "kql_recommendation",
            "Create a Freshservice ticket": "ticket_generation",
            "Map this to MITRE": "mitre_mapping",
            "What containment steps should I take?": "containment_recommendation",
            "Create an executive summary": "executive_summary",
            "Explain severity": "severity_explanation",
            "What should I investigate first?": "investigation_steps",
        }
        for question, expected in cases.items():
            with self.subTest(question=question):
                self.assertEqual(classify_intent(question), expected)


if __name__ == "__main__":
    unittest.main()
