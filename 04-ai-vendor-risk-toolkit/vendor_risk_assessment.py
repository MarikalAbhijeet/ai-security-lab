"""Rule-based AI vendor risk assessment toolkit.

Version 1 uses only local fake/sample vendor JSON files and deterministic
scoring. It does not call paid APIs, external services, or AI providers.
"""

import argparse
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
SAMPLE_INPUT_DIR = PROJECT_ROOT / "sample-inputs"
SAMPLE_OUTPUT_DIR = PROJECT_ROOT / "sample-output"
DEFAULT_BATCH_OUTPUT_DIR = SAMPLE_OUTPUT_DIR / "batch"

REQUIRED_VENDOR_FIELDS = {
    "product_name",
    "business_use_case",
    "data_types_processed",
    "authentication_method",
    "sso_support",
    "mfa_support",
    "role_based_access_control",
    "logging_available",
    "audit_log_retention_days",
    "data_retention_days",
    "encryption_at_rest",
    "encryption_in_transit",
    "customer_data_used_for_training",
    "model_training_policy",
    "admin_controls",
    "export_controls",
    "incident_response_sla",
    "compliance_claims",
    "subprocessors_disclosed",
    "data_residency",
    "deletion_request_support",
    "risk_notes",
}

BOOLEAN_FIELDS = {
    "sso_support",
    "mfa_support",
    "role_based_access_control",
    "logging_available",
    "encryption_at_rest",
    "encryption_in_transit",
    "customer_data_used_for_training",
    "admin_controls",
    "export_controls",
    "subprocessors_disclosed",
    "deletion_request_support",
}

LIST_FIELDS = {
    "data_types_processed",
    "compliance_claims",
    "risk_notes",
}


def load_vendor_profile(profile_path):
    """Load and validate one fake/sample vendor profile JSON file."""
    profile_path = Path(profile_path).resolve()
    sample_input_dir = SAMPLE_INPUT_DIR.resolve()

    if profile_path.suffix.lower() != ".json":
        raise ValueError("Vendor profile input must use the .json extension.")

    if sample_input_dir not in profile_path.parents:
        raise ValueError("Vendor profile input must be inside the sample-inputs folder.")

    try:
        with open(profile_path, "r", encoding="utf-8") as profile_file:
            profile = json.load(profile_file)
    except FileNotFoundError as error:
        raise ValueError(f"Vendor profile was not found: {profile_path}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"Vendor profile is not valid JSON: {profile_path}") from error

    validate_vendor_profile(profile)
    return profile


def validate_vendor_profile(profile):
    """Validate the required shape for a sample vendor profile."""
    if not isinstance(profile, dict):
        raise ValueError("Vendor profile JSON must contain one JSON object.")

    missing_fields = sorted(REQUIRED_VENDOR_FIELDS - set(profile))
    if missing_fields:
        raise ValueError(f"Vendor profile is missing required fields: {', '.join(missing_fields)}")

    for field_name in BOOLEAN_FIELDS:
        if not isinstance(profile[field_name], bool):
            raise ValueError(f"Vendor field must be true or false: {field_name}")

    for field_name in LIST_FIELDS:
        if not isinstance(profile[field_name], list) or not profile[field_name]:
            raise ValueError(f"Vendor field must be a non-empty list: {field_name}")
        for item in profile[field_name]:
            if not isinstance(item, str) or not item.strip():
                raise ValueError(f"Every value in {field_name} must be a non-empty string.")

    for field_name in REQUIRED_VENDOR_FIELDS - BOOLEAN_FIELDS - LIST_FIELDS:
        if field_name in {"audit_log_retention_days", "data_retention_days"}:
            if not isinstance(profile[field_name], int) or profile[field_name] < 0:
                raise ValueError(f"Vendor field must be a non-negative integer: {field_name}")
        elif not isinstance(profile[field_name], str) or not profile[field_name].strip():
            raise ValueError(f"Vendor field must be a non-empty string: {field_name}")


def clean_markdown(value):
    """Keep sample values readable in Markdown output."""
    text = str(value).replace("\r", " ").replace("\n", " ").strip()
    return text.replace("```", "` ` `")


def yes_no(value):
    """Convert booleans into report-friendly text."""
    return "Yes" if value else "No"


def add_finding(findings, category, severity, finding, recommendation, points):
    findings.append(
        {
            "category": category,
            "severity": severity,
            "finding": finding,
            "recommendation": recommendation,
            "points": points,
        }
    )


def assess_vendor(profile):
    """Assess one vendor profile and return structured risk findings."""
    findings = []

    if not profile["sso_support"]:
        add_finding(
            findings,
            "IAM",
            "High",
            "SSO is not supported.",
            "Require SSO integration before approval for production use.",
            18,
        )

    if "local application accounts" in profile["authentication_method"].lower():
        add_finding(
            findings,
            "IAM",
            "Medium",
            "Authentication relies on local application accounts.",
            "Require federated SSO and centralized lifecycle management.",
            10,
        )

    if not profile["mfa_support"]:
        add_finding(
            findings,
            "IAM",
            "High",
            "MFA is not supported.",
            "Require MFA for all administrative and user access.",
            18,
        )

    if not profile["role_based_access_control"]:
        add_finding(
            findings,
            "IAM",
            "Medium",
            "Role-based access control is not available.",
            "Require least-privilege roles for admins, reviewers, and standard users.",
            10,
        )

    if not profile["logging_available"]:
        add_finding(
            findings,
            "Logging and Monitoring",
            "High",
            "Security or audit logging is not available.",
            "Require user, admin, authentication, data access, and export logs.",
            16,
        )
    elif profile["audit_log_retention_days"] < 90:
        add_finding(
            findings,
            "Logging and Monitoring",
            "Medium",
            "Audit log retention is shorter than 90 days.",
            "Require at least 90 days of audit log retention, preferably 180 or more.",
            8,
        )

    if profile["data_retention_days"] > 365:
        add_finding(
            findings,
            "Data Protection",
            "Medium",
            "Customer data retention is longer than one year.",
            "Require configurable retention and documented deletion workflows.",
            9,
        )

    if profile["data_retention_days"] > 730:
        add_finding(
            findings,
            "Data Protection",
            "Medium",
            "Customer data retention exceeds two years.",
            "Require a shorter default retention period and customer-configurable retention.",
            8,
        )

    if not profile["encryption_at_rest"]:
        add_finding(
            findings,
            "Data Protection",
            "High",
            "Encryption at rest is not confirmed.",
            "Require encryption at rest for customer content, logs, and backups.",
            16,
        )

    if not profile["encryption_in_transit"]:
        add_finding(
            findings,
            "Data Protection",
            "High",
            "Encryption in transit is not confirmed.",
            "Require TLS for all user, API, and administrative traffic.",
            16,
        )

    if profile["customer_data_used_for_training"]:
        add_finding(
            findings,
            "AI-Specific Risk",
            "High",
            "Customer data may be used for model training.",
            "Require contractual opt-out or prohibition on training with customer data.",
            20,
        )

    training_policy = profile["model_training_policy"].lower()
    if profile["customer_data_used_for_training"] and "opt out" not in training_policy and "not used" not in training_policy:
        add_finding(
            findings,
            "AI-Specific Risk",
            "Medium",
            "Training opt-out language is missing or unclear.",
            "Require explicit opt-out, opt-in, or prohibition language for customer data training.",
            10,
        )

    if "unclear" in profile["model_training_policy"].lower():
        add_finding(
            findings,
            "AI-Specific Risk",
            "Medium",
            "Model training policy is unclear.",
            "Require clear documentation for training, retention, and human review practices.",
            10,
        )

    if not profile["admin_controls"]:
        add_finding(
            findings,
            "Administrative Controls",
            "Medium",
            "Admin controls are limited or unavailable.",
            "Require tenant-level controls for users, data sharing, retention, and integrations.",
            8,
        )

    if not profile["export_controls"]:
        add_finding(
            findings,
            "Data Protection",
            "Medium",
            "Export controls are not available.",
            "Require controls for bulk export, sharing, and download activity.",
            8,
        )

    if not profile["subprocessors_disclosed"]:
        add_finding(
            findings,
            "Third-Party Risk",
            "Medium",
            "Subprocessors are not disclosed.",
            "Require subprocessor list, notification process, and data flow documentation.",
            8,
        )

    if only_no_compliance_claims(profile["compliance_claims"]):
        add_finding(
            findings,
            "Compliance",
            "Medium",
            "No sample compliance claims are provided.",
            "Request current independent assurance documentation or document compensating controls.",
            8,
        )

    if not profile["deletion_request_support"]:
        add_finding(
            findings,
            "Data Protection",
            "Medium",
            "Deletion request support is not available.",
            "Require documented deletion request process and deletion SLA.",
            9,
        )

    if "not provided" in profile["data_residency"].lower() or "unknown" in profile["data_residency"].lower():
        add_finding(
            findings,
            "Data Protection",
            "Medium",
            "Data residency is not clearly documented.",
            "Require data residency documentation for storage, processing, and support access.",
            8,
        )

    if "best effort" in profile["incident_response_sla"].lower():
        add_finding(
            findings,
            "Incident Response",
            "Medium",
            "Incident response SLA is best effort.",
            "Require defined security notification timelines and escalation contacts.",
            8,
        )

    score = sum(finding["points"] for finding in findings)
    if score >= 45:
        risk_rating = "High"
        approval_decision = "Do not approve until high-priority security gaps are remediated."
    elif score >= 20:
        risk_rating = "Medium"
        approval_decision = "Conditional approval only after documented compensating controls."
    else:
        risk_rating = "Low"
        approval_decision = "Approve for limited use with standard monitoring and periodic review."

    return {
        "score": score,
        "overall_risk_rating": risk_rating,
        "key_findings": findings or [
            {
                "category": "Overall",
                "severity": "Low",
                "finding": "No major control gaps were identified from the sample profile.",
                "recommendation": "Continue normal vendor review and periodic reassessment.",
                "points": 0,
            }
        ],
        "missing_controls": missing_controls(findings),
        "ai_specific_risks": category_findings(findings, "AI-Specific Risk"),
        "data_protection_concerns": category_findings(findings, "Data Protection"),
        "iam_concerns": category_findings(findings, "IAM"),
        "logging_monitoring_concerns": category_findings(findings, "Logging and Monitoring"),
        "recommended_security_requirements": recommended_requirements(findings),
        "suggested_approval_decision": approval_decision,
        "follow_up_questions": follow_up_questions(profile, findings),
        "compliance_claims_review": compliance_claims_review(profile),
        "executive_summary": executive_summary(profile, risk_rating, score, findings),
    }


def category_findings(findings, category):
    results = [finding["finding"] for finding in findings if finding["category"] == category]
    return results or [f"No {category.lower()} concerns identified from the sample profile."]


def missing_controls(findings):
    controls = sorted({finding["recommendation"] for finding in findings})
    return controls or ["No major missing controls identified from the sample profile."]


def recommended_requirements(findings):
    requirements = []
    for finding in findings:
        if finding["recommendation"] not in requirements:
            requirements.append(finding["recommendation"])

    if not requirements:
        requirements.append("Maintain SSO, MFA, logging, encryption, deletion support, and annual reassessment.")
    return requirements


def only_no_compliance_claims(compliance_claims):
    """Return true when the profile explicitly states no sample claims exist."""
    return all("no sample compliance claims" in claim.lower() for claim in compliance_claims)


def compliance_claims_review(profile):
    """Label compliance claims as fake and unverified for portfolio safety."""
    claims = profile["compliance_claims"]
    if only_no_compliance_claims(claims):
        return ["No sample compliance claims were provided. Treat this as a review gap."]
    return [f"Unverified sample claim: {claim}" for claim in claims]


def follow_up_questions(profile, findings):
    questions = [
        "Can you provide current security architecture and data flow documentation?",
        "Can you provide the latest SOC 2, ISO 27001, or equivalent security assessment summary if available?",
        "How are customer prompts, outputs, metadata, and audit logs retained and deleted?",
    ]

    categories = {finding["category"] for finding in findings}
    if "AI-Specific Risk" in categories:
        questions.append("Can you contractually confirm customer data is not used to train models without explicit approval?")
    if "IAM" in categories:
        questions.append("What SSO, MFA, SCIM, and role-based access controls are available for enterprise customers?")
    if "Logging and Monitoring" in categories:
        questions.append("Can audit logs be exported to a SIEM such as Microsoft Sentinel?")
    if "Compliance" in categories:
        questions.append("Can you provide current independent compliance or assurance documentation?")
    if profile["subprocessors_disclosed"]:
        questions.append("How often are customers notified about subprocessor changes?")
    return questions


def executive_summary(profile, risk_rating, score, findings):
    high_count = sum(1 for finding in findings if finding["severity"] == "High")
    medium_count = sum(1 for finding in findings if finding["severity"] == "Medium")
    business_use_case = profile["business_use_case"].rstrip(".")
    return (
        f"{profile['product_name']} was assessed for the sample use case "
        f"'{business_use_case}'. The overall sample risk rating is {risk_rating} "
        f"with a rule-based score of {score}. The review identified {high_count} high-risk "
        f"and {medium_count} medium-risk findings. Approval should follow the suggested decision "
        "and require documented remediation or compensating controls where applicable."
    )


def bullet_list(items):
    return "\n".join(f"- {clean_markdown(item)}" for item in items)


def indented_bullet_list(items):
    return "\n".join(f"  - {clean_markdown(item)}" for item in items)


def findings_table(findings):
    rows = ["| Category | Severity | Finding | Recommendation |", "| --- | --- | --- | --- |"]
    for finding in findings:
        rows.append(
            "| "
            + " | ".join(
                [
                    clean_markdown(finding["category"]),
                    clean_markdown(finding["severity"]),
                    clean_markdown(finding["finding"]),
                    clean_markdown(finding["recommendation"]),
                ]
            )
            + " |"
        )
    return "\n".join(rows)


def generate_report(profile):
    """Generate a Markdown vendor risk report."""
    assessment = assess_vendor(profile)
    sections = [
        "# AI Vendor Risk Assessment Report",
        "## Executive-Style Summary",
        clean_markdown(assessment["executive_summary"]),
        "## Vendor Profile",
        (
            f"- Product name: {clean_markdown(profile['product_name'])}\n"
            f"- Business use case: {clean_markdown(profile['business_use_case'])}\n"
            f"- Data types processed:\n{indented_bullet_list(profile['data_types_processed'])}\n"
            f"- Authentication method: {clean_markdown(profile['authentication_method'])}\n"
            f"- SSO support: {yes_no(profile['sso_support'])}\n"
            f"- MFA support: {yes_no(profile['mfa_support'])}\n"
            f"- RBAC: {yes_no(profile['role_based_access_control'])}"
        ),
        "## Overall Risk Rating",
        f"{assessment['overall_risk_rating']} (score: {assessment['score']})",
        "## Key Findings",
        findings_table(assessment["key_findings"]),
        "## Missing Controls",
        bullet_list(assessment["missing_controls"]),
        "## AI-Specific Risks",
        bullet_list(assessment["ai_specific_risks"]),
        "## Compliance Claims Review",
        bullet_list(assessment["compliance_claims_review"]),
        "## Data Protection Concerns",
        bullet_list(assessment["data_protection_concerns"]),
        "## IAM Concerns",
        bullet_list(assessment["iam_concerns"]),
        "## Logging and Monitoring Concerns",
        bullet_list(assessment["logging_monitoring_concerns"]),
        "## Recommended Security Requirements",
        bullet_list(assessment["recommended_security_requirements"]),
        "## Suggested Approval Decision",
        clean_markdown(assessment["suggested_approval_decision"]),
        "## Follow-Up Questions for the Vendor",
        bullet_list(assessment["follow_up_questions"]),
        "## Vendor Risk Notes",
        bullet_list(profile["risk_notes"]),
        "## Sample Data Notice",
        "This report was generated from fake/sample vendor data for portfolio and lab use only.",
    ]
    return "\n\n".join(sections)


def save_report(report, output_path):
    """Save a generated report to sample-output."""
    output_path = output_path.resolve()
    project_root = PROJECT_ROOT.resolve()
    sample_output_dir = SAMPLE_OUTPUT_DIR.resolve()

    if output_path.suffix.lower() != ".md":
        raise ValueError("Output file must use the .md extension.")

    if project_root not in output_path.parents:
        raise ValueError("Output path must stay inside this project folder.")

    if output_path != sample_output_dir and sample_output_dir not in output_path.parents:
        raise ValueError("Output reports must be saved inside the sample-output folder.")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report + "\n", encoding="utf-8")


def resolve_output_dir(output_dir):
    """Resolve and validate a batch output directory."""
    output_dir = Path(output_dir or DEFAULT_BATCH_OUTPUT_DIR).resolve()
    sample_output_dir = SAMPLE_OUTPUT_DIR.resolve()

    if output_dir != sample_output_dir and sample_output_dir not in output_dir.parents:
        raise ValueError("Batch output directory must stay inside the sample-output folder.")

    return output_dir


def report_name_for_vendor(profile_path):
    """Return a deterministic report filename for one vendor profile."""
    return f"{Path(profile_path).stem}-risk-report.md"


def generate_report_for_file(profile_path, output_path=None):
    """Generate a report for one vendor profile and optionally save it."""
    profile = load_vendor_profile(profile_path)
    report = generate_report(profile)
    if output_path:
        save_report(report, Path(output_path))
    return report


def generate_batch_reports(output_dir=None):
    """Generate reports for every sample vendor profile JSON file."""
    output_dir = resolve_output_dir(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    saved_reports = []

    for profile_path in sorted(SAMPLE_INPUT_DIR.glob("*.json")):
        output_path = output_dir / report_name_for_vendor(profile_path)
        generate_report_for_file(profile_path, output_path)
        saved_reports.append(output_path)

    return saved_reports


def parse_args():
    parser = argparse.ArgumentParser(description="Generate a rule-based AI vendor risk report.")
    parser.add_argument("vendor_profile", nargs="?", help="Path to one fake/sample vendor JSON profile.")
    parser.add_argument(
        "-o",
        "--output",
        help="Optional path for the generated Markdown report. If omitted, the report prints to the console.",
    )
    parser.add_argument(
        "--batch",
        action="store_true",
        help="Process all JSON files in the sample-inputs folder.",
    )
    parser.add_argument(
        "--output-dir",
        help="Directory for batch Markdown reports. Defaults to sample-output/batch and must stay inside sample-output.",
    )
    return parser.parse_args()


def main():
    try:
        args = parse_args()
        if args.batch:
            if args.vendor_profile or args.output:
                raise ValueError("--batch cannot be used with vendor_profile or --output.")
            saved_reports = generate_batch_reports(args.output_dir)
            print(f"Saved {len(saved_reports)} reports to {resolve_output_dir(args.output_dir)}")
            return

        if not args.vendor_profile:
            raise ValueError("vendor_profile is required unless --batch is used.")

        if args.output:
            generate_report_for_file(args.vendor_profile, args.output)
            print(f"Report saved to {Path(args.output)}")
        else:
            report = generate_report_for_file(args.vendor_profile)
            print(report)
    except ValueError as error:
        raise SystemExit(f"Error: {error}") from error


if __name__ == "__main__":
    main()
