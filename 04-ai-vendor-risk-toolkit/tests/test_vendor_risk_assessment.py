import unittest
from pathlib import Path

import vendor_risk_assessment


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class VendorRiskAssessmentTests(unittest.TestCase):
    def test_loads_valid_vendor_profile(self):
        profile = vendor_risk_assessment.load_vendor_profile(
            PROJECT_ROOT / "sample-inputs" / "contoso-ai-notes.json"
        )

        self.assertEqual(profile["product_name"], "Contoso AI Notes")

    def test_low_risk_vendor_profile(self):
        profile = vendor_risk_assessment.load_vendor_profile(
            PROJECT_ROOT / "sample-inputs" / "contoso-ai-notes.json"
        )

        assessment = vendor_risk_assessment.assess_vendor(profile)

        self.assertEqual(assessment["overall_risk_rating"], "Low")

    def test_high_risk_vendor_profile(self):
        profile = vendor_risk_assessment.load_vendor_profile(
            PROJECT_ROOT / "sample-inputs" / "northwind-ai-email-assistant.json"
        )

        assessment = vendor_risk_assessment.assess_vendor(profile)

        self.assertEqual(assessment["overall_risk_rating"], "High")
        self.assertIn("SSO is not supported.", assessment["iam_concerns"])
        self.assertIn("Authentication relies on local application accounts.", assessment["iam_concerns"])

    def test_generates_required_report_sections(self):
        profile = vendor_risk_assessment.load_vendor_profile(
            PROJECT_ROOT / "sample-inputs" / "fabrikam-support-copilot.json"
        )

        report = vendor_risk_assessment.generate_report(profile)

        self.assertIn("## Overall Risk Rating", report)
        self.assertIn("## AI-Specific Risks", report)
        self.assertIn("## Compliance Claims Review", report)
        self.assertIn("Unverified sample claim: Sample SOC 2 in progress claim", report)
        self.assertIn("## Vendor Risk Notes", report)
        self.assertIn("## Suggested Approval Decision", report)
        self.assertIn("## Executive-Style Summary", report)

    def test_rejects_input_outside_sample_inputs(self):
        with self.assertRaises(ValueError):
            vendor_risk_assessment.load_vendor_profile(PROJECT_ROOT / "vendor.json")

    def test_rejects_missing_required_field(self):
        bad_profile = {
            "product_name": "Bad Sample Vendor",
            "business_use_case": "Missing fields",
        }

        with self.assertRaises(ValueError):
            vendor_risk_assessment.validate_vendor_profile(bad_profile)

    def test_rejects_bad_boolean_field(self):
        profile = vendor_risk_assessment.load_vendor_profile(
            PROJECT_ROOT / "sample-inputs" / "contoso-ai-notes.json"
        )
        profile["sso_support"] = "yes"

        with self.assertRaises(ValueError):
            vendor_risk_assessment.validate_vendor_profile(profile)

    def test_rejects_bad_list_field(self):
        profile = vendor_risk_assessment.load_vendor_profile(
            PROJECT_ROOT / "sample-inputs" / "contoso-ai-notes.json"
        )
        profile["data_types_processed"] = "sample notes"

        with self.assertRaises(ValueError):
            vendor_risk_assessment.validate_vendor_profile(profile)

    def test_no_compliance_claims_creates_finding(self):
        profile = vendor_risk_assessment.load_vendor_profile(
            PROJECT_ROOT / "sample-inputs" / "northwind-ai-email-assistant.json"
        )

        assessment = vendor_risk_assessment.assess_vendor(profile)

        self.assertIn("No sample compliance claims are provided.", [item["finding"] for item in assessment["key_findings"]])
        self.assertIn("No sample compliance claims were provided. Treat this as a review gap.", assessment["compliance_claims_review"])

    def test_local_account_authentication_creates_iam_finding(self):
        profile = vendor_risk_assessment.load_vendor_profile(
            PROJECT_ROOT / "sample-inputs" / "northwind-ai-email-assistant.json"
        )

        assessment = vendor_risk_assessment.assess_vendor(profile)

        self.assertIn("Authentication relies on local application accounts.", assessment["iam_concerns"])

    def test_rejects_output_outside_sample_output(self):
        with self.assertRaises(ValueError):
            vendor_risk_assessment.save_report("sample report", PROJECT_ROOT / "report.md")

    def test_rejects_non_markdown_output(self):
        with self.assertRaises(ValueError):
            vendor_risk_assessment.save_report(
                "sample report",
                PROJECT_ROOT / "sample-output" / "report.txt",
            )


if __name__ == "__main__":
    unittest.main()
