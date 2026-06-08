"""Tests for email risk scoring."""

import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from email_summarizer import analyze_email_file  # noqa: E402


class PhishingScoreTests(unittest.TestCase):
    def test_phishing_sample_scores_high(self):
        sample = PROJECT_ROOT / "sample-inputs" / "sample_phishing_email.eml"
        analysis = analyze_email_file(sample.name, sample.read_bytes())

        self.assertEqual(analysis.score.verdict, "Likely Phishing")
        self.assertGreaterEqual(analysis.score.overall_score, 70)
        self.assertGreater(analysis.score.category_scores["URL/domain risk"], 0)

    def test_benign_sample_scores_lower_than_phishing(self):
        phishing = PROJECT_ROOT / "sample-inputs" / "sample_phishing_email.eml"
        benign = PROJECT_ROOT / "sample-inputs" / "sample_benign_email.eml"

        phishing_analysis = analyze_email_file(phishing.name, phishing.read_bytes())
        benign_analysis = analyze_email_file(benign.name, benign.read_bytes())

        self.assertLess(benign_analysis.score.overall_score, phishing_analysis.score.overall_score)


if __name__ == "__main__":
    unittest.main()

