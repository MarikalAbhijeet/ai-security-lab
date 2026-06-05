"""Rule-based AI-assisted SOC alert triage assistant.

Version 1 uses only local sample JSON files and deterministic rules.
It does not call paid APIs, external services, or AI providers.
"""

import argparse
import json
import re
from pathlib import Path
from textwrap import dedent


PROJECT_ROOT = Path(__file__).resolve().parent
SAMPLE_INPUT_DIR = PROJECT_ROOT / "sample-inputs"
SAMPLE_OUTPUT_DIR = PROJECT_ROOT / "sample-output"
DEFAULT_BATCH_OUTPUT_DIR = SAMPLE_OUTPUT_DIR / "batch"
ALLOWED_SEVERITIES = {"informational", "low", "medium", "high", "critical"}
REQUIRED_ALERT_FIELDS = {
    "alert_id",
    "alert_type",
    "title",
    "timestamp",
    "source_product",
    "severity",
    "user",
}


TRIAGE_RULES = {
    "risky_sign_in": {
        "mitre_tactic": "Credential Access / Initial Access",
        "mitre_technique": "T1078 - Valid Accounts",
        "severity_reason": (
            "A risky sign-in can indicate compromised credentials, especially when "
            "the sign-in includes unfamiliar locations, new devices, or failed MFA."
        ),
        "triage_steps": [
            "Review Entra ID sign-in logs for the user, IP address, device, and application.",
            "Confirm whether the location and device are expected for the user.",
            "Check MFA result, conditional access result, and authentication method used.",
            "Review recent mailbox, SharePoint, and endpoint activity for the account.",
            "If suspicious, revoke sessions and require password reset or strong reauthentication.",
        ],
        "kql_query": """
            SigninLogs
            | where UserPrincipalName == "{user}"
            | where IPAddress == "{ip_address}" or LocationDetails contains "{location}"
            | project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName,
                      Location, RiskLevelAggregated, ConditionalAccessStatus
            | order by TimeGenerated desc
        """,
        "escalation": "Escalate to Tier 2 IAM/SOC if the user does not recognize the sign-in or MFA failed unexpectedly.",
    },
    "suspicious_powershell": {
        "mitre_tactic": "Execution / Defense Evasion",
        "mitre_technique": "T1059.001 - PowerShell",
        "severity_reason": (
            "Encoded or hidden PowerShell can be used for payload execution, discovery, "
            "credential access, or defense evasion."
        ),
        "triage_steps": [
            "Review the full command line, parent process, script block logs, and user context.",
            "Check whether the command used encoded, hidden, download, or bypass flags.",
            "Review Defender device timeline around the process start time.",
            "Search for the same command, hash, or parent process across other endpoints.",
            "If malicious behavior is confirmed, isolate the device and collect investigation package.",
        ],
        "kql_query": """
            DeviceProcessEvents
            | where DeviceName == "{host}"
            | where FileName in~ ("powershell.exe", "pwsh.exe")
            | where ProcessCommandLine has_any ("-enc", "EncodedCommand", "IEX", "Bypass", "Hidden")
            | project Timestamp, DeviceName, AccountName, FileName,
                      ProcessCommandLine, InitiatingProcessFileName
            | order by Timestamp desc
        """,
        "escalation": "Escalate to endpoint security if encoded PowerShell, suspicious parent process, or network download behavior is confirmed.",
    },
    "malware_detected": {
        "mitre_tactic": "Execution / Persistence",
        "mitre_technique": "T1204 - User Execution",
        "severity_reason": (
            "A malware detection may represent active execution, a blocked payload, "
            "or a file that needs containment validation."
        ),
        "triage_steps": [
            "Confirm Defender action status: blocked, quarantined, removed, or failed.",
            "Review file path, SHA256, detection name, and affected device timeline.",
            "Check whether the file executed or only existed on disk.",
            "Search for the file hash across other devices.",
            "If execution occurred or remediation failed, isolate the endpoint and escalate.",
        ],
        "kql_query": """
            DeviceFileEvents
            | where SHA256 == "{file_hash}" or DeviceName == "{host}"
            | project Timestamp, DeviceName, ActionType, FileName,
                      FolderPath, SHA256, InitiatingProcessAccountName
            | order by Timestamp desc
        """,
        "escalation": "Escalate to incident response if malware executed, spread is detected, or remediation did not complete.",
    },
    "impossible_travel": {
        "mitre_tactic": "Initial Access / Credential Access",
        "mitre_technique": "T1078 - Valid Accounts",
        "severity_reason": (
            "Impossible travel can indicate account compromise when sign-ins occur "
            "from distant locations within an unrealistic time window."
        ),
        "triage_steps": [
            "Compare both sign-in locations, timestamps, IP addresses, and device IDs.",
            "Check for VPN, corporate proxy, or known travel exception.",
            "Review successful sign-ins after the alert for suspicious application access.",
            "Ask the user to confirm travel and recent authentication activity.",
            "If suspicious, revoke sessions, reset credentials, and review mailbox rules.",
        ],
        "kql_query": """
            SigninLogs
            | where UserPrincipalName == "{user}"
            | where TimeGenerated between (datetime({start_time}) .. datetime({end_time}))
            | project TimeGenerated, UserPrincipalName, IPAddress, Location,
                      AppDisplayName, DeviceDetail, RiskLevelAggregated
            | order by TimeGenerated desc
        """,
        "escalation": "Escalate to IAM/SOC if the user cannot validate both locations or if risky follow-on activity is found.",
    },
    "mass_file_deletion": {
        "mitre_tactic": "Impact",
        "mitre_technique": "T1485 - Data Destruction",
        "severity_reason": (
            "Mass file deletion may indicate ransomware activity, insider threat, "
            "compromised account abuse, or accidental bulk deletion."
        ),
        "triage_steps": [
            "Identify deleted file count, affected paths, user, device, and cloud workload.",
            "Check whether deletion came from an expected admin or sync process.",
            "Review recent sign-ins and endpoint activity for the deleting account.",
            "Determine whether files can be restored from recycle bin, backup, or version history.",
            "If malicious or widespread, disable the account, isolate device, and start recovery steps.",
        ],
        "kql_query": """
            OfficeActivity
            | where UserId == "{user}"
            | where Operation has_any ("FileDeleted", "FileRecycled", "FileDeletedFirstStageRecycleBin")
            | where TimeGenerated between (datetime({start_time}) .. datetime({end_time}))
            | summarize DeletedFiles=count() by UserId, Site_Url, bin(TimeGenerated, 15m)
            | order by DeletedFiles desc
        """,
        "escalation": "Escalate immediately if deletion is continuing, business-critical data is affected, or account compromise is suspected.",
    },
}


def load_alert(alert_path):
    """Load one sample alert JSON file."""
    try:
        with open(alert_path, "r", encoding="utf-8") as alert_file:
            alert = json.load(alert_file)
    except FileNotFoundError as error:
        raise ValueError(f"Alert file was not found: {alert_path}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"Alert file is not valid JSON: {alert_path}") from error

    validate_alert(alert)
    return alert


def validate_alert(alert):
    """Validate the required shape for a sample alert."""
    if not isinstance(alert, dict):
        raise ValueError("Alert JSON must contain one JSON object.")

    missing_fields = sorted(REQUIRED_ALERT_FIELDS - set(alert))
    if missing_fields:
        raise ValueError(f"Alert JSON is missing required fields: {', '.join(missing_fields)}")

    for field_name in REQUIRED_ALERT_FIELDS:
        if not isinstance(alert[field_name], str) or not alert[field_name].strip():
            raise ValueError(f"Alert field must be a non-empty string: {field_name}")

    alert_type = alert["alert_type"].strip().lower()
    if alert_type not in TRIAGE_RULES:
        raise ValueError(f"No triage rule exists for alert_type: {alert_type}")

    severity = alert["severity"].strip().lower()
    if severity not in ALLOWED_SEVERITIES:
        raise ValueError(
            "Alert severity must be one of: "
            + ", ".join(sorted(ALLOWED_SEVERITIES))
        )


def get_rule(alert):
    """Return the rule pack for the alert type."""
    alert_type = alert.get("alert_type", "").strip().lower()
    if alert_type not in TRIAGE_RULES:
        raise ValueError(f"No triage rule exists for alert_type: {alert_type}")
    return TRIAGE_RULES[alert_type]


def clean_markdown(value):
    """Keep sample alert values readable in Markdown output."""
    text = str(value).replace("\r", " ").replace("\n", " ").strip()
    return text.replace("```", "` ` `")


def clean_kql_string(value):
    """Escape a value before placing it in a quoted KQL sample string."""
    text = str(value).replace("\r", " ").replace("\n", " ").strip()
    text = text.replace("\\", "\\\\").replace('"', '\\"')
    return text


def clean_kql_datetime(value):
    """Allow only simple ISO-like timestamp text in KQL datetime examples."""
    text = str(value).strip()
    if not re.fullmatch(r"[0-9T:Z+.\-]+", text):
        raise ValueError(f"Invalid datetime value for KQL query: {text}")
    return text


def format_query(template, alert):
    """Fill a KQL query template with safe sample alert fields."""
    return dedent(template).strip().format(
        user=clean_kql_string(alert.get("user", "unknown@example.com")),
        ip_address=clean_kql_string(alert.get("ip_address", "0.0.0.0")),
        location=clean_kql_string(alert.get("location", "Unknown")),
        host=clean_kql_string(alert.get("host", "UNKNOWN-HOST")),
        file_hash=clean_kql_string(alert.get("file_hash", "UNKNOWN_HASH")),
        start_time=clean_kql_datetime(alert.get("query_start_time", alert.get("timestamp", "2026-06-03T00:00:00Z"))),
        end_time=clean_kql_datetime(alert.get("query_end_time", alert.get("timestamp", "2026-06-03T23:59:59Z"))),
    )


def build_incident_summary(alert):
    """Create a short human-readable incident summary."""
    return (
        f"{clean_markdown(alert.get('source_product', 'Security tool'))} generated a "
        f"{clean_markdown(alert.get('severity', 'Unknown')).lower()} severity alert for "
        f"{clean_markdown(alert.get('user', 'an unknown user'))} on "
        f"{clean_markdown(alert.get('host', 'an unknown host'))}. "
        f"The alert was '{clean_markdown(alert.get('title', 'Untitled alert'))}' at "
        f"{clean_markdown(alert.get('timestamp', 'an unknown time'))}."
    )


def build_freshservice_update(alert, rule):
    """Create a ticket-ready update in a Freshservice-style format."""
    return dedent(
        f"""
        Analyst Update:
        Reviewed sample alert {clean_markdown(alert.get('alert_id', 'UNKNOWN'))} from {clean_markdown(alert.get('source_product', 'Unknown source'))}.
        Initial assessment: {clean_markdown(alert.get('title', 'Untitled alert'))} requires validation of user, device, and related activity.
        Current severity: {clean_markdown(alert.get('severity', 'Unknown'))} - {rule['severity_reason']}
        MITRE mapping: {rule['mitre_tactic']} ({rule['mitre_technique']}).
        Next action: Complete recommended triage steps and document whether the activity is expected, suspicious, or confirmed malicious.
        Escalation: {rule['escalation']}
        """
    ).strip()


def generate_report(alert):
    """Generate a Markdown triage report for one alert."""
    rule = get_rule(alert)
    triage_steps = "\n".join(f"{index}. {step}" for index, step in enumerate(rule["triage_steps"], start=1))
    kql_query = format_query(rule["kql_query"], alert)
    freshservice_update = build_freshservice_update(alert, rule)

    report_sections = [
        "# SOC Alert Triage Report",
        "## Short Incident Summary",
        build_incident_summary(alert),
        "## Severity Explanation",
        f"Alert severity: **{clean_markdown(alert.get('severity', 'Unknown'))}**\n\n{rule['severity_reason']}",
        "## Likely MITRE ATT&CK Tactic",
        f"- Tactic: {rule['mitre_tactic']}\n- Technique: {rule['mitre_technique']}",
        "## Recommended Triage Steps",
        triage_steps,
        "## KQL Hunting Query",
        f"```kql\n{kql_query}\n```",
        "## Freshservice-Style Ticket Update",
        freshservice_update,
        "## Escalation Recommendation",
        rule["escalation"],
        "## Sample Data Notice",
        "This report was generated from fake/sample alert data for portfolio and lab use only.",
    ]

    return "\n\n".join(report_sections)


def save_report(report, output_path):
    """Save a generated report to disk."""
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


def report_name_for_alert(alert_path):
    """Return a deterministic report filename for one alert input."""
    return f"{Path(alert_path).stem}-triage-report.md"


def generate_report_for_file(alert_path, output_path=None):
    """Generate a report for one alert file and optionally save it."""
    alert = load_alert(alert_path)
    report = generate_report(alert)
    if output_path:
        save_report(report, Path(output_path))
    return report


def generate_batch_reports(output_dir=None):
    """Generate reports for every sample alert JSON file."""
    output_dir = resolve_output_dir(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    saved_reports = []

    for alert_path in sorted(SAMPLE_INPUT_DIR.glob("*.json")):
        output_path = output_dir / report_name_for_alert(alert_path)
        generate_report_for_file(alert_path, output_path)
        saved_reports.append(output_path)

    return saved_reports


def parse_args():
    parser = argparse.ArgumentParser(description="Generate a rule-based SOC alert triage report.")
    parser.add_argument("alert_file", nargs="?", help="Path to one sample alert JSON file.")
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
            if args.alert_file or args.output:
                raise ValueError("--batch cannot be used with alert_file or --output.")
            saved_reports = generate_batch_reports(args.output_dir)
            print(f"Saved {len(saved_reports)} reports to {resolve_output_dir(args.output_dir)}")
            return

        if not args.alert_file:
            raise ValueError("alert_file is required unless --batch is used.")

        if args.output:
            generate_report_for_file(args.alert_file, args.output)
            print(f"Report saved to {Path(args.output)}")
        else:
            report = generate_report_for_file(args.alert_file)
            print(report)
    except ValueError as error:
        raise SystemExit(f"Error: {error}") from error


if __name__ == "__main__":
    main()
