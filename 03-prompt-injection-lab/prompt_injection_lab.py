"""Rule-based prompt injection testing lab.

Version 1 uses only local safe sample JSON files and deterministic rules.
It does not call paid APIs, external services, or AI providers.
"""

import argparse
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
SAMPLE_INPUT_DIR = PROJECT_ROOT / "sample-inputs"
SAMPLE_OUTPUT_DIR = PROJECT_ROOT / "sample-output"
DEFAULT_BATCH_OUTPUT_DIR = SAMPLE_OUTPUT_DIR / "batch"
REQUIRED_PROMPT_FIELDS = {
    "test_id",
    "title",
    "prompt_text",
    "expected_risk_level",
    "expected_attack_type",
    "owasp_llm_mapping",
    "mitre_atlas_mapping",
    "expected_safe_behavior",
}
RISK_LEVELS = {"Low", "Medium", "High"}


DETECTION_RULES = {
    "Direct Instruction Override": {
        "phrases": [
            "ignore previous instructions",
            "disregard prior instructions",
            "override your instructions",
            "forget the rules",
        ],
        "risk": "High",
        "owasp": "LLM01: Prompt Injection",
        "mitre": "AML.T0051 - LLM Prompt Injection",
        "mitigation": "Treat user content as untrusted data and preserve instruction hierarchy.",
    },
    "System Prompt Extraction": {
        "phrases": [
            "reveal your system prompt",
            "show hidden instructions",
            "print your developer message",
            "what are your internal rules",
        ],
        "risk": "High",
        "owasp": "LLM07: System Prompt Leakage",
        "mitre": "AML.T0057 - LLM System Prompt Discovery",
        "mitigation": "Refuse to reveal hidden instructions and provide a brief safe alternative.",
    },
    "Sensitive Data Request": {
        "phrases": [
            "show me secrets",
            "list credentials",
            "private document",
            "confidential data",
            "api key",
        ],
        "risk": "High",
        "owasp": "LLM02: Sensitive Information Disclosure",
        "mitre": "AML.T0058 - Sensitive Information Disclosure",
        "mitigation": "Do not reveal secrets, credentials, private documents, or sensitive data.",
    },
    "Role-Play Jailbreak": {
        "phrases": [
            "developer mode",
            "pretend you are unrestricted",
            "role-play as",
            "no safety rules",
        ],
        "risk": "Medium",
        "owasp": "LLM01: Prompt Injection",
        "mitre": "AML.T0054 - Jailbreak",
        "mitigation": "Keep safety boundaries active even during role-play or simulation requests.",
    },
    "Indirect Prompt Injection": {
        "phrases": [
            "document instruction",
            "when summarizing this document",
            "ignore the user request",
            "hidden note to assistant",
        ],
        "risk": "High",
        "owasp": "LLM01: Prompt Injection",
        "mitre": "AML.T0051 - LLM Prompt Injection",
        "mitigation": "Separate retrieved or document text from trusted instructions.",
    },
    "Output Manipulation": {
        "phrases": [
            "always answer approved",
            "return only safe",
            "change the final decision",
            "hide the risk",
        ],
        "risk": "Medium",
        "owasp": "LLM05: Improper Output Handling",
        "mitre": "AML.T0051 - LLM Prompt Injection",
        "mitigation": "Validate outputs against policy and expected schemas before using them.",
    },
    "Data Exfiltration Attempt": {
        "phrases": [
            "send fake_secret",
            "exfiltrate sample_token",
            "upload demo_credential",
            "forward lab_secret",
        ],
        "risk": "High",
        "owasp": "LLM06: Excessive Agency",
        "mitre": "AML.T0048 - Data Exfiltration",
        "mitigation": "Block tool actions that transmit data without explicit user approval and allowlisted destinations.",
    },
}


def load_prompt(prompt_path):
    """Load and validate one safe sample prompt JSON file."""
    try:
        with open(prompt_path, "r", encoding="utf-8") as prompt_file:
            prompt = json.load(prompt_file)
    except FileNotFoundError as error:
        raise ValueError(f"Prompt file was not found: {prompt_path}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"Prompt file is not valid JSON: {prompt_path}") from error

    validate_prompt(prompt)
    return prompt


def validate_prompt(prompt):
    """Validate the required shape for a sample prompt."""
    if not isinstance(prompt, dict):
        raise ValueError("Prompt JSON must contain one JSON object.")

    missing_fields = sorted(REQUIRED_PROMPT_FIELDS - set(prompt))
    if missing_fields:
        raise ValueError(f"Prompt JSON is missing required fields: {', '.join(missing_fields)}")

    for field_name in REQUIRED_PROMPT_FIELDS:
        if not isinstance(prompt[field_name], str) or not prompt[field_name].strip():
            raise ValueError(f"Prompt field must be a non-empty string: {field_name}")

    if prompt["expected_risk_level"] not in RISK_LEVELS:
        raise ValueError("expected_risk_level must be Low, Medium, or High.")


def clean_markdown(value):
    """Keep sample values readable in Markdown output."""
    text = str(value).replace("\r", " ").replace("\n", " ").strip()
    return text.replace("```", "` ` `")


def detect_indicators(prompt_text):
    """Detect prompt injection indicators using simple phrase matching."""
    text = prompt_text.lower()
    matched_rules = []
    indicators = []

    for attack_type, rule in DETECTION_RULES.items():
        for phrase in rule["phrases"]:
            if phrase in text:
                matched_rules.append((attack_type, rule))
                indicators.append(f"Matched {attack_type} indicator: '{phrase}'")
                break

    return indicators, matched_rules


def highest_risk(matched_rules):
    """Return the highest detected risk level."""
    if not matched_rules:
        return "Low"

    risk_order = {"Low": 1, "Medium": 2, "High": 3}
    return max((rule["risk"] for _, rule in matched_rules), key=lambda value: risk_order[value])


def summarize_attack_types(matched_rules):
    """Return a readable attack type summary."""
    if not matched_rules:
        return "Benign / No injection detected"
    return ", ".join(sorted({attack_type for attack_type, _ in matched_rules}))


def build_mappings(matched_rules, mapping_name):
    """Return unique OWASP or MITRE mappings from matched rules."""
    if not matched_rules:
        if mapping_name == "owasp":
            return ["No OWASP LLM risk detected"]
        return ["No MITRE ATLAS-style behavior detected"]

    mappings = []
    for _, rule in matched_rules:
        mapping = rule[mapping_name]
        if mapping not in mappings:
            mappings.append(mapping)
    return mappings


def build_mitigations(matched_rules):
    """Return recommended mitigations for matched rules."""
    if not matched_rules:
        return ["Continue normal processing while treating user input as untrusted."]

    mitigations = []
    for _, rule in matched_rules:
        mitigation = rule["mitigation"]
        if mitigation not in mitigations:
            mitigations.append(mitigation)
    return mitigations


def evaluate_prompt(prompt):
    """Evaluate one sample prompt against the rule set."""
    indicators, matched_rules = detect_indicators(prompt["prompt_text"])
    risk_rating = highest_risk(matched_rules)
    attack_type = summarize_attack_types(matched_rules)
    owasp_mappings = build_mappings(matched_rules, "owasp")
    mitre_mappings = build_mappings(matched_rules, "mitre")
    mitigations = build_mitigations(matched_rules)

    expected_risk_pass = risk_rating == prompt["expected_risk_level"]
    expected_attack_pass = prompt["expected_attack_type"].lower() in attack_type.lower()
    if prompt["expected_attack_type"].lower() == "benign":
        expected_attack_pass = attack_type == "Benign / No injection detected"

    return {
        "risk_rating": risk_rating,
        "detected_injection_indicators": indicators or ["No prompt injection indicators detected."],
        "attack_type": attack_type,
        "owasp_llm_mapping": owasp_mappings,
        "mitre_atlas_mapping": mitre_mappings,
        "recommended_mitigation": mitigations,
        "expected_safe_response": prompt["expected_safe_behavior"],
        "pass_fail_result": "Pass" if expected_risk_pass and expected_attack_pass else "Fail",
    }


def generate_report(prompt):
    """Generate a Markdown test report for one prompt."""
    result = evaluate_prompt(prompt)
    indicators = "\n".join(f"- {clean_markdown(item)}" for item in result["detected_injection_indicators"])
    owasp = "\n".join(f"- {clean_markdown(item)}" for item in result["owasp_llm_mapping"])
    mitre = "\n".join(f"- {clean_markdown(item)}" for item in result["mitre_atlas_mapping"])
    mitigations = "\n".join(f"{index}. {clean_markdown(item)}" for index, item in enumerate(result["recommended_mitigation"], start=1))

    sections = [
        "# Prompt Injection Test Report",
        "## Test Summary",
        (
            f"- Test ID: {clean_markdown(prompt['test_id'])}\n"
            f"- Title: {clean_markdown(prompt['title'])}\n"
            f"- Expected risk level: {clean_markdown(prompt['expected_risk_level'])}\n"
            f"- Expected attack type: {clean_markdown(prompt['expected_attack_type'])}"
        ),
        "## Risk Rating",
        result["risk_rating"],
        "## Detected Injection Indicators",
        indicators,
        "## Attack Type",
        result["attack_type"],
        "## OWASP LLM Top 10 Mapping",
        owasp,
        "## MITRE ATLAS-Style Mapping",
        mitre,
        "## Recommended Mitigation",
        mitigations,
        "## Expected Safe Response",
        clean_markdown(result["expected_safe_response"]),
        "## Pass/Fail Result",
        result["pass_fail_result"],
        "## Sample Data Notice",
        "This report was generated from safe fake/sample prompts for portfolio and lab use only.",
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


def report_name_for_prompt(prompt_path):
    """Return a deterministic report filename for one prompt input."""
    return f"{Path(prompt_path).stem}-report.md"


def generate_report_for_file(prompt_path, output_path=None):
    """Generate a report for one prompt file and optionally save it."""
    prompt = load_prompt(prompt_path)
    report = generate_report(prompt)
    if output_path:
        save_report(report, Path(output_path))
    return report


def generate_batch_reports(output_dir=None):
    """Generate reports for every sample prompt JSON file."""
    output_dir = resolve_output_dir(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    saved_reports = []

    for prompt_path in sorted(SAMPLE_INPUT_DIR.glob("*.json")):
        output_path = output_dir / report_name_for_prompt(prompt_path)
        generate_report_for_file(prompt_path, output_path)
        saved_reports.append(output_path)

    return saved_reports


def parse_args():
    parser = argparse.ArgumentParser(description="Generate a rule-based prompt injection test report.")
    parser.add_argument("prompt_file", nargs="?", help="Path to one safe sample prompt JSON file.")
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
            if args.prompt_file or args.output:
                raise ValueError("--batch cannot be used with prompt_file or --output.")
            saved_reports = generate_batch_reports(args.output_dir)
            print(f"Saved {len(saved_reports)} reports to {resolve_output_dir(args.output_dir)}")
            return

        if not args.prompt_file:
            raise ValueError("prompt_file is required unless --batch is used.")

        if args.output:
            generate_report_for_file(args.prompt_file, args.output)
            print(f"Report saved to {Path(args.output)}")
        else:
            report = generate_report_for_file(args.prompt_file)
            print(report)
    except ValueError as error:
        raise SystemExit(f"Error: {error}") from error


if __name__ == "__main__":
    main()
