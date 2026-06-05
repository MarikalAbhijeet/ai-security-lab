"""IsolationForest anomaly detection for synthetic security logs.

This is a lab model for fake/sample data only. It is not a production
detection system and does not connect to live security platforms.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


PROJECT_ROOT = Path(__file__).resolve().parent
SAMPLE_INPUT_DIR = PROJECT_ROOT / "sample-inputs"
SAMPLE_OUTPUT_DIR = PROJECT_ROOT / "sample-output"
DEFAULT_OUTPUT_PATH = SAMPLE_OUTPUT_DIR / "anomaly_report.md"

REQUIRED_COLUMNS = {
    "timestamp",
    "user",
    "source_ip",
    "country",
    "device_id",
    "user_agent",
    "failed_login_count",
    "mfa_result",
    "login_hour",
    "impossible_travel_flag",
    "new_device_flag",
    "risky_country_flag",
    "file_delete_count",
    "powershell_event_count",
    "expected_is_anomaly",
}

NUMERIC_FEATURES = [
    "failed_login_count",
    "login_hour",
    "impossible_travel_flag",
    "new_device_flag",
    "risky_country_flag",
    "file_delete_count",
    "powershell_event_count",
    "mfa_failure_flag",
]

BOOLEAN_LIKE_COLUMNS = [
    "impossible_travel_flag",
    "new_device_flag",
    "risky_country_flag",
    "expected_is_anomaly",
]

COUNT_COLUMNS = [
    "failed_login_count",
    "login_hour",
    "file_delete_count",
    "powershell_event_count",
]

ALLOWED_MFA_RESULTS = {"success", "failure", "denied", "not_required"}


def resolve_input_path(input_path):
    """Resolve and validate the CSV input path."""
    path = Path(input_path).resolve()
    project_root = PROJECT_ROOT.resolve()

    if path.suffix.lower() != ".csv":
        raise ValueError("Input file must use the .csv extension.")

    if project_root not in path.parents:
        raise ValueError("Input file must stay inside the ML anomaly detection project folder.")

    return path


def resolve_output_path(output_path):
    """Resolve and validate the Markdown output path."""
    path = Path(output_path or DEFAULT_OUTPUT_PATH).resolve()
    sample_output_dir = SAMPLE_OUTPUT_DIR.resolve()

    if path.suffix.lower() != ".md":
        raise ValueError("Output file must use the .md extension.")

    if path != sample_output_dir and sample_output_dir not in path.parents:
        raise ValueError("Output report must stay inside the sample-output folder.")

    return path


def load_logs(input_path):
    """Load synthetic sign-in/security logs from CSV."""
    path = resolve_input_path(input_path)
    try:
        logs = pd.read_csv(path)
    except FileNotFoundError as error:
        raise ValueError(f"Input file was not found: {path}") from error
    except pd.errors.ParserError as error:
        raise ValueError(f"Input file is not valid CSV: {path}") from error

    validate_logs(logs)
    return logs


def validate_logs(logs):
    """Validate required columns and basic data shape."""
    if not isinstance(logs, pd.DataFrame) or logs.empty:
        raise ValueError("Synthetic log CSV must contain at least one event.")

    missing_columns = sorted(REQUIRED_COLUMNS - set(logs.columns))
    if missing_columns:
        raise ValueError(f"Synthetic log CSV is missing required columns: {', '.join(missing_columns)}")

    if logs["timestamp"].isna().any() or (logs["timestamp"].astype(str).str.strip() == "").any():
        raise ValueError("timestamp values must not be empty.")

    parsed_timestamps = pd.to_datetime(logs["timestamp"], errors="coerce", utc=True, format="ISO8601")
    if parsed_timestamps.isna().any():
        raise ValueError("timestamp values must be valid date/time values.")

    for column in ["user", "source_ip", "country", "device_id", "user_agent", "mfa_result"]:
        if logs[column].isna().any() or (logs[column].astype(str).str.strip() == "").any():
            raise ValueError(f"{column} values must be non-empty.")

    mfa_values = logs["mfa_result"].astype(str).str.strip().str.lower()
    invalid_mfa_values = sorted(set(mfa_values) - ALLOWED_MFA_RESULTS)
    if invalid_mfa_values:
        raise ValueError(
            "mfa_result must be one of: "
            + ", ".join(sorted(ALLOWED_MFA_RESULTS))
        )

    for column in COUNT_COLUMNS:
        values = pd.to_numeric(logs[column], errors="coerce")
        if values.isna().any() or (values < 0).any():
            raise ValueError(f"{column} must contain non-negative numeric values.")

    for column in BOOLEAN_LIKE_COLUMNS:
        values = pd.to_numeric(logs[column], errors="coerce")
        if values.isna().any() or not values.isin([0, 1]).all():
            raise ValueError(f"{column} must contain only 0 or 1 values.")

    login_hours = pd.to_numeric(logs["login_hour"], errors="coerce")
    if ((login_hours < 0) | (login_hours > 23)).any():
        raise ValueError("login_hour must be between 0 and 23.")


def validate_contamination(contamination):
    """Validate the IsolationForest contamination value."""
    try:
        value = float(contamination)
    except (TypeError, ValueError) as error:
        raise ValueError("Contamination must be a decimal value between 0.01 and 0.5.") from error

    if value < 0.01 or value > 0.5:
        raise ValueError("Contamination must be between 0.01 and 0.5.")

    return value


def prepare_features(logs):
    """Convert validated security fields into numeric model features."""
    features = logs.copy()

    for column in COUNT_COLUMNS + BOOLEAN_LIKE_COLUMNS:
        features[column] = pd.to_numeric(features[column], errors="raise")

    features["mfa_failure_flag"] = features["mfa_result"].astype(str).str.lower().ne("success").astype(int)

    return features[NUMERIC_FEATURES]


def score_events(logs, contamination=0.15):
    """Train IsolationForest and score each event."""
    validate_logs(logs)
    contamination = validate_contamination(contamination)
    feature_frame = prepare_features(logs)
    scaled_features = StandardScaler().fit_transform(feature_frame)

    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=42,
    )
    predictions = model.fit_predict(scaled_features)
    raw_scores = model.decision_function(scaled_features)

    results = logs.copy()
    results["anomaly_score"] = -raw_scores
    results["is_anomaly"] = predictions == -1
    return results.sort_values(["is_anomaly", "anomaly_score"], ascending=[False, False])


def suspicion_reasons(event):
    """Build human-readable reasons for an anomalous event."""
    reasons = []

    if int(event["impossible_travel_flag"]) == 1:
        reasons.append("impossible travel indicator")
    if int(event["new_device_flag"]) == 1:
        reasons.append("new device sign-in")
    if int(event["risky_country_flag"]) == 1:
        reasons.append("risky country indicator")
    if int(event["failed_login_count"]) >= 5:
        reasons.append("high failed login count")
    if str(event["mfa_result"]).strip().lower() != "success":
        reasons.append("MFA did not succeed")
    if int(event["file_delete_count"]) >= 20:
        reasons.append("unusual file deletion volume")
    if int(event["powershell_event_count"]) >= 5:
        reasons.append("elevated PowerShell activity")

    if not reasons:
        reasons.append("unusual combination of numeric security features")

    return "; ".join(reasons)


def format_event_row(event):
    """Format one suspicious event for a Markdown table."""
    return (
        f"| {clean_markdown(event['timestamp'])} "
        f"| {clean_markdown(event['user'])} "
        f"| {clean_markdown(event['source_ip'])} "
        f"| {clean_markdown(event['country'])} "
        f"| {event['anomaly_score']:.4f} "
        f"| {suspicion_reasons(event)} |"
    )


def generate_report(scored_logs, contamination=0.15):
    """Generate a Markdown anomaly detection report."""
    total_events = len(scored_logs)
    anomalies = scored_logs[scored_logs["is_anomaly"]].copy()
    anomaly_count = len(anomalies)
    top_events = anomalies.head(10)

    event_rows = "\n".join(format_event_row(row) for _, row in top_events.iterrows())
    if not event_rows:
        event_rows = "| None | None | None | None | None | No anomalous events detected. |"

    sections = [
        "# ML Anomaly Detection Report",
        "## Summary",
        (
            f"- Total events analyzed: {total_events}\n"
            f"- Anomalous events identified: {anomaly_count}\n"
            f"- IsolationForest contamination setting: {validate_contamination(contamination)}\n"
            "- Data source: fake/synthetic security logs only"
        ),
        "## Top Suspicious Events",
        (
            "| Timestamp | User | Source IP | Country | Anomaly Score | Reasons for Suspicion |\n"
            "| --- | --- | --- | --- | --- | --- |\n"
            f"{event_rows}"
        ),
        "## Reasoning Note",
        (
            "Reasons for suspicion are heuristic triage explanations based on visible security fields. "
            "They are not IsolationForest feature attributions and should not be treated as model explainability."
        ),
        "## Recommended SOC Triage Steps",
        (
            "1. Review sign-in context for the flagged user, source IP, country, and device.\n"
            "2. Confirm whether impossible travel, new device, or risky-country indicators are expected.\n"
            "3. Check MFA outcome, failed login volume, and recent successful authentication activity.\n"
            "4. Review endpoint and cloud activity for file deletion or PowerShell spikes.\n"
            "5. Escalate to SOC/IAM if the user cannot validate the activity or follow-on activity looks suspicious."
        ),
        "## Related MITRE ATT&CK Mapping",
        (
            "- Initial Access / Credential Access: T1078 - Valid Accounts\n"
            "- Credential Access: T1110 - Brute Force\n"
            "- Execution: T1059.001 - PowerShell\n"
            "- Impact: T1485 - Data Destruction"
        ),
        "## Limitations and Human Review Warning",
        (
            "This is a synthetic lab model trained on fake sample data. IsolationForest results are anomaly "
            "scores, not confirmed incidents. A human analyst must validate context, business justification, "
            "identity signals, endpoint telemetry, and user confirmation before taking response action."
        ),
        "## Safe Data Notice",
        (
            "This report was generated from fake/synthetic security logs for portfolio and lab use only. "
            "Do not use real company, client, tenant, user, vendor, or production data in this lab."
        ),
    ]

    return "\n\n".join(sections)


def analyze_file(input_path, output_path=None, contamination=0.15):
    """Load, score, and report on one synthetic CSV file."""
    logs = load_logs(input_path)
    scored_logs = score_events(logs, contamination)
    report = generate_report(scored_logs, contamination)

    if output_path:
        save_report(report, output_path)

    return report


def save_report(report, output_path):
    """Save a Markdown report under sample-output."""
    path = resolve_output_path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report + "\n", encoding="utf-8")


def clean_markdown(value):
    """Keep synthetic values readable in Markdown output."""
    text = str(value).replace("\r", " ").replace("\n", " ").strip()
    return text.replace("|", "\\|").replace("```", "` ` `")


def parse_args():
    parser = argparse.ArgumentParser(description="Run IsolationForest anomaly detection on synthetic security logs.")
    parser.add_argument("--input", required=True, help="Path to one synthetic security log CSV file.")
    parser.add_argument(
        "--output",
        help="Optional path for the generated Markdown report. Must stay inside sample-output.",
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.15,
        help="Expected anomaly ratio for IsolationForest. Must be between 0.01 and 0.5.",
    )
    return parser.parse_args()


def main():
    try:
        args = parse_args()
        report = analyze_file(args.input, args.output, args.contamination)
        print(report)
        if args.output:
            print(f"\nReport saved to {resolve_output_path(args.output)}")
    except ValueError as error:
        raise SystemExit(f"Error: {error}") from error


if __name__ == "__main__":
    main()
