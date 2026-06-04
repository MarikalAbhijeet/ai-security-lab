"""Rule-based phishing email analyzer.

Version 1 uses only local sample JSON files and deterministic rules.
It does not call paid APIs, external services, or AI providers.
"""

import argparse
import json
import re
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
SAMPLE_OUTPUT_DIR = PROJECT_ROOT / "sample-output"
REQUIRED_EMAIL_FIELDS = {
    "sender",
    "reply_to",
    "subject",
    "body",
    "urls",
    "attachment_name",
    "received_timestamp",
    "spf_result",
    "dkim_result",
    "dmarc_result",
    "user_reported_reason",
}
AUTH_RESULTS = {"pass", "fail", "softfail", "neutral", "none"}
SAFE_SAMPLE_DOMAINS = (
    ".example.com",
    ".example.net",
    ".example.org",
    ".example.invalid",
)


SUSPICIOUS_KEYWORDS = {
    "credential_lure": [
        "password expires",
        "verify your account",
        "sign in immediately",
        "account will be locked",
        "microsoft 365",
        "mfa",
    ],
    "payment_lure": [
        "updated bank",
        "wire instructions",
        "payment change",
        "past due",
        "invoice",
        "remittance",
    ],
    "urgency": [
        "urgent",
        "immediately",
        "today only",
        "final notice",
        "within 24 hours",
        "do not delay",
    ],
    "impersonation": [
        "ceo",
        "cfo",
        "executive",
        "confidential",
        "do not call",
        "are you available",
    ],
    "qr_phishing": [
        "scan the qr",
        "qr code",
        "mobile authentication",
        "use your phone camera",
    ],
}


BENIGN_KEYWORDS = [
    "scheduled maintenance",
    "no action required",
    "internal it",
    "change window",
    "service desk",
    "informational",
]


MITRE_MAPPINGS = {
    "credential_lure": ("Initial Access", "T1566 - Phishing"),
    "payment_lure": ("Initial Access", "T1566 - Phishing"),
    "urgency": ("Initial Access", "T1566 - Phishing"),
    "impersonation": ("Initial Access", "T1566 - Phishing"),
    "qr_phishing": ("Initial Access", "T1566.002 - Spearphishing Link"),
    "attachment": ("Initial Access", "T1566.001 - Spearphishing Attachment"),
    "auth_failure": ("Initial Access", "T1566 - Phishing"),
}


def load_email(email_path):
    """Load and validate one sample email JSON file."""
    try:
        with open(email_path, "r", encoding="utf-8") as email_file:
            email = json.load(email_file)
    except FileNotFoundError as error:
        raise ValueError(f"Email file was not found: {email_path}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"Email file is not valid JSON: {email_path}") from error

    validate_email(email)
    return email


def validate_email(email):
    """Validate the required shape for a sample email."""
    if not isinstance(email, dict):
        raise ValueError("Email JSON must contain one JSON object.")

    missing_fields = sorted(REQUIRED_EMAIL_FIELDS - set(email))
    if missing_fields:
        raise ValueError(f"Email JSON is missing required fields: {', '.join(missing_fields)}")

    for field_name in REQUIRED_EMAIL_FIELDS - {"urls", "attachment_name"}:
        if not isinstance(email[field_name], str) or not email[field_name].strip():
            raise ValueError(f"Email field must be a non-empty string: {field_name}")

    if not isinstance(email["urls"], list):
        raise ValueError("Email field must be a list: urls")

    for url in email["urls"]:
        if not isinstance(url, str) or not url.strip():
            raise ValueError("Every URL value must be a non-empty string.")
        validate_sample_url(url)

    attachment_name = email["attachment_name"]
    if attachment_name is not None and not isinstance(attachment_name, str):
        raise ValueError("Email field must be a string or null: attachment_name")

    for field_name in ["spf_result", "dkim_result", "dmarc_result"]:
        result = email[field_name].strip().lower()
        if result not in AUTH_RESULTS:
            raise ValueError(f"{field_name} must be one of: {', '.join(sorted(AUTH_RESULTS))}")


def validate_sample_url(url):
    """Require safe sample domains for portfolio data."""
    if not url.startswith(("https://", "http://")):
        raise ValueError(f"URL must start with http:// or https://: {url}")

    host_match = re.match(r"^https?://([^/]+)", url)
    if not host_match:
        raise ValueError(f"URL host could not be parsed: {url}")

    host = host_match.group(1).lower()
    if not host.endswith(SAFE_SAMPLE_DOMAINS):
        raise ValueError(f"URL must use a safe sample domain: {url}")


def clean_markdown(value):
    """Keep sample email values readable in Markdown output."""
    if value is None:
        return "None"
    text = str(value).replace("\r", " ").replace("\n", " ").strip()
    return text.replace("```", "` ` `")


def normalize_text(email):
    """Combine searchable email fields into lowercase text."""
    values = [
        email.get("sender", ""),
        email.get("reply_to", ""),
        email.get("subject", ""),
        email.get("body", ""),
        email.get("user_reported_reason", ""),
        " ".join(email.get("urls", [])),
        email.get("attachment_name") or "",
    ]
    return " ".join(values).lower()


def find_keyword_indicators(text):
    """Return suspicious keyword indicators and categories."""
    indicators = []
    categories = set()

    for category, keywords in SUSPICIOUS_KEYWORDS.items():
        for keyword in keywords:
            if keyword in text:
                indicators.append(f"Contains {category.replace('_', ' ')} phrase: '{keyword}'")
                categories.add(category)

    return indicators, categories


def analyze_email(email):
    """Analyze one email and return structured phishing findings."""
    text = normalize_text(email)
    suspicious_indicators, categories = find_keyword_indicators(text)
    benign_indicators = []
    score = 0

    score += len(suspicious_indicators)

    auth_failures = []
    for field_name in ["spf_result", "dkim_result", "dmarc_result"]:
        result = email[field_name].strip().lower()
        if result != "pass":
            auth_name = field_name.replace("_result", "").upper()
            auth_failures.append(f"{auth_name} result is {result}")
            categories.add("auth_failure")

    suspicious_indicators.extend(auth_failures)
    score += len(auth_failures) * 2

    if email.get("attachment_name"):
        attachment = email["attachment_name"].lower()
        if attachment.endswith((".html", ".htm", ".exe", ".js", ".vbs", ".iso", ".zip")):
            suspicious_indicators.append(f"Attachment has a risky file type: {email['attachment_name']}")
            categories.add("attachment")
            score += 3
        else:
            benign_indicators.append(f"Attachment name is present for review: {email['attachment_name']}")

    if email["sender"].split("@")[-1].lower() != email["reply_to"].split("@")[-1].lower():
        suspicious_indicators.append("Sender domain and reply-to domain do not match")
        score += 2

    if not email["urls"]:
        benign_indicators.append("No URLs were included in the message.")
    else:
        benign_indicators.append("URLs use safe sample domains for this lab.")

    for keyword in BENIGN_KEYWORDS:
        if keyword in text:
            benign_indicators.append(f"Contains benign business phrase: '{keyword}'")

    if email["spf_result"].lower() == "pass" and email["dkim_result"].lower() == "pass" and email["dmarc_result"].lower() == "pass":
        benign_indicators.append("SPF, DKIM, and DMARC all passed.")

    if score >= 7:
        risk_rating = "High"
        classification = "Likely phishing"
    elif score >= 3:
        risk_rating = "Medium"
        classification = "Suspicious - needs analyst review"
    else:
        risk_rating = "Low"
        classification = "Likely benign"

    return {
        "risk_rating": risk_rating,
        "classification": classification,
        "suspicious_indicators": suspicious_indicators or ["No strong suspicious indicators found."],
        "benign_indicators": benign_indicators or ["No strong benign indicators found."],
        "mitre_mappings": build_mitre_mappings(categories),
        "recommended_analyst_action": analyst_action(risk_rating),
        "suggested_user_response": user_response(risk_rating),
        "containment_steps": containment_steps(risk_rating),
    }


def build_mitre_mappings(categories):
    """Build unique MITRE ATT&CK mappings from triggered categories."""
    mappings = []
    seen = set()

    for category in sorted(categories):
        mapping = MITRE_MAPPINGS.get(category)
        if mapping and mapping not in seen:
            tactic, technique = mapping
            mappings.append({"tactic": tactic, "technique": technique})
            seen.add(mapping)

    if not mappings:
        mappings.append({"tactic": "No clear malicious tactic identified", "technique": "N/A"})

    return mappings


def analyst_action(risk_rating):
    if risk_rating == "High":
        return "Open or update the phishing ticket, preserve the email, review headers, and search for other recipients."
    if risk_rating == "Medium":
        return "Review headers, sender reputation, URLs, and attachment details before disposition."
    return "Document as likely benign if business context confirms the message is expected."


def user_response(risk_rating):
    if risk_rating == "High":
        return "Tell the user not to click links, open attachments, reply, or scan QR codes. Thank them for reporting."
    if risk_rating == "Medium":
        return "Ask the user to avoid interacting with the message while the SOC reviews it."
    return "Let the user know the message appears expected, but to report anything unusual."


def containment_steps(risk_rating):
    if risk_rating == "High":
        return [
            "Search mail logs for additional recipients.",
            "Quarantine matching messages if confirmed malicious.",
            "Block malicious sender, domain, URL, or attachment hash where appropriate.",
            "Check for clicked links, submitted credentials, or opened attachments.",
            "Reset credentials and revoke sessions if credential exposure is suspected.",
        ]
    if risk_rating == "Medium":
        return [
            "Hold message disposition until header and URL review is complete.",
            "Search for similar messages by sender, subject, and URL.",
            "Escalate if user interaction or broader delivery is identified.",
        ]
    return [
        "No containment needed unless new evidence appears.",
        "Close ticket with benign disposition after analyst review.",
    ]


def build_ticket_note(email, analysis):
    """Create a Freshservice-style analyst note."""
    return (
        "Analyst Update:\n"
        f"Reviewed user-reported email received at {clean_markdown(email['received_timestamp'])}.\n"
        f"Subject: {clean_markdown(email['subject'])}\n"
        f"Sender: {clean_markdown(email['sender'])}\n"
        f"Risk rating: {analysis['risk_rating']}\n"
        f"Classification: {analysis['classification']}\n"
        f"Recommended action: {analysis['recommended_analyst_action']}\n"
        f"User guidance: {analysis['suggested_user_response']}"
    )


def generate_report(email):
    """Generate a Markdown phishing analysis report."""
    analysis = analyze_email(email)
    suspicious = "\n".join(f"- {clean_markdown(item)}" for item in analysis["suspicious_indicators"])
    benign = "\n".join(f"- {clean_markdown(item)}" for item in analysis["benign_indicators"])
    containment = "\n".join(f"{index}. {clean_markdown(step)}" for index, step in enumerate(analysis["containment_steps"], start=1))
    mitre = "\n".join(
        f"- Tactic: {clean_markdown(item['tactic'])}; Technique: {clean_markdown(item['technique'])}"
        for item in analysis["mitre_mappings"]
    )

    sections = [
        "# Phishing Email Analysis Report",
        "## Email Summary",
        (
            f"- Sender: {clean_markdown(email['sender'])}\n"
            f"- Reply-To: {clean_markdown(email['reply_to'])}\n"
            f"- Subject: {clean_markdown(email['subject'])}\n"
            f"- Received: {clean_markdown(email['received_timestamp'])}\n"
            f"- User-reported reason: {clean_markdown(email['user_reported_reason'])}"
        ),
        "## Risk Rating",
        analysis["risk_rating"],
        "## Phishing Classification",
        analysis["classification"],
        "## Suspicious Indicators",
        suspicious,
        "## Benign Indicators",
        benign,
        "## Recommended Analyst Action",
        analysis["recommended_analyst_action"],
        "## Suggested User Response",
        analysis["suggested_user_response"],
        "## Containment Steps",
        containment,
        "## MITRE ATT&CK Mapping",
        mitre,
        "## Freshservice-Style Ticket Note",
        build_ticket_note(email, analysis),
        "## Sample Data Notice",
        "This report was generated from fake/sample email data for portfolio and lab use only.",
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


def parse_args():
    parser = argparse.ArgumentParser(description="Generate a rule-based phishing email analysis report.")
    parser.add_argument("email_file", help="Path to one sample email JSON file.")
    parser.add_argument(
        "-o",
        "--output",
        help="Optional path for the generated Markdown report. If omitted, the report prints to the console.",
    )
    return parser.parse_args()


def main():
    try:
        args = parse_args()
        email = load_email(args.email_file)
        report = generate_report(email)

        if args.output:
            output_path = Path(args.output)
            save_report(report, output_path)
            print(f"Report saved to {output_path}")
        else:
            print(report)
    except ValueError as error:
        raise SystemExit(f"Error: {error}") from error


if __name__ == "__main__":
    main()
