"""Tests for evidence risk scoring and intelligence profiles."""

import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from evidence_summarizer import analyze_evidence  # noqa: E402
from evidence_summarizer import EvidenceAnalysis  # noqa: E402
from risk_scoring import RiskScore, canonical_entity, score_evidence  # noqa: E402
from evidence_parser import EvidenceDocument  # noqa: E402
from ioc_extractor import IOC  # noqa: E402


class RiskScoringTests(unittest.TestCase):
    def test_signin_csv_scores_suspicious_user(self):
        sample = PROJECT_ROOT / "sample-inputs" / "sample_signin_logs.csv"
        result = analyze_evidence(sample.name, sample.read_bytes())

        self.assertGreater(len(result.risk_scores), 0)
        self.assertIn("alex.chen@example.com", result.risk_scores[0].entity.lower())
        self.assertTrue(any("failed" in reason.lower() for reason in result.risk_scores[0].reasons))
        self.assertIn("unknown device", result.risk_scores[0].reasons)
        self.assertIn("successful login after failures", result.copilot_context.lower())

    def test_signin_csv_exposes_full_user_sequence_reasons(self):
        sample = PROJECT_ROOT / "sample-inputs" / "sample_signin_logs.csv"
        result = analyze_evidence(sample.name, sample.read_bytes())

        alex_score = next(
            score for score in result.evidence_profile.top_risky_users
            if score.entity.lower() == "alex.chen@example.com"
        )
        joined_reasons = " | ".join(alex_score.reasons).lower()

        for reason in (
            "multiple failed logins",
            "successful login after failures",
            "new device",
            "impossible travel",
            "risky country",
        ):
            self.assertIn(reason, joined_reasons)

    def test_signin_csv_ranks_service_admin_as_secondary_concern(self):
        sample = PROJECT_ROOT / "sample-inputs" / "sample_signin_logs.csv"
        result = analyze_evidence(sample.name, sample.read_bytes())
        ranked_users = [score.entity.lower() for score in result.evidence_profile.top_risky_users]

        self.assertEqual(ranked_users[0], "alex.chen@example.com")
        self.assertIn("service.admin@example.com", ranked_users[1:])
        self.assertNotIn("alex[.]chen@example[.]com", ranked_users)
        self.assertIn("suspicious sign-in pattern", result.evidence_profile.highest_priority_finding.lower())

    def test_device_and_ip_scores_are_separate_from_user_ranking(self):
        sample = PROJECT_ROOT / "sample-inputs" / "sample_signin_logs.csv"
        result = analyze_evidence(sample.name, sample.read_bytes())

        self.assertTrue(result.evidence_profile.top_risky_devices)
        self.assertTrue(result.evidence_profile.top_risky_ips)
        self.assertTrue(all(score.entity_type == "user" for score in result.evidence_profile.top_risky_users))
        self.assertTrue(all(score.entity_type == "device" for score in result.evidence_profile.top_risky_devices))
        self.assertTrue(all(score.entity_type == "ip" for score in result.evidence_profile.top_risky_ips))

    def test_entity_normalization_merges_raw_and_defanged_emails(self):
        document = EvidenceDocument(file_name="sample.csv", extension=".csv", parsed_type="csv", records=[], lines=[])
        iocs = [
            IOC("User", "alex.chen@example.com", "alex[.]chen@example[.]com", "Record 1", "User"),
            IOC("User", "alex[.]chen@example[.]com", "alex[.]chen@example[.]com", "Record 2", "User"),
        ]

        scores = score_evidence(document, [], iocs)
        users = [score for score in scores if score.entity_type == "user"]

        self.assertEqual(len(users), 1)
        self.assertEqual(users[0].entity, "alex.chen@example.com")

    def test_entity_normalization_merges_device_case(self):
        self.assertEqual(canonical_entity("device", "UNKNOWN-DEVICE"), "unknown-device")
        self.assertEqual(canonical_entity("device", "unknown-device"), "unknown-device")

    def test_evidence_analysis_defaults_include_risk_scores(self):
        analysis = EvidenceAnalysis()

        self.assertEqual(analysis.risk_scores, [])
        self.assertEqual(analysis.extracted_iocs, [])
        self.assertEqual(analysis.detected_behaviors, [])
        self.assertEqual(analysis.top_risky_users, [])
        self.assertEqual(analysis.mitre_attack_mapping, [])

    def test_powershell_log_scores_process_and_device(self):
        sample = PROJECT_ROOT / "sample-inputs" / "sample_powershell_events.log"
        result = analyze_evidence(sample.name, sample.read_bytes())
        joined = "\n".join(f"{score.entity} {' '.join(score.reasons)}" for score in result.risk_scores).lower()

        self.assertIn("powershell", joined)
        self.assertIn("encoded powershell", joined)
        self.assertIn("office parent process", joined)

    def test_defender_json_scores_malware_alert(self):
        sample = PROJECT_ROOT / "sample-inputs" / "sample_defender_alert.json"
        result = analyze_evidence(sample.name, sample.read_bytes())

        self.assertIn("malware", result.evidence_profile.highest_priority_finding.lower())
        self.assertTrue(result.evidence_profile.mitre_attack_mapping)


if __name__ == "__main__":
    unittest.main()
