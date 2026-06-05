"""Unit tests for the ML anomaly detection lab."""

import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = PROJECT_ROOT / "anomaly_detector.py"

spec = importlib.util.spec_from_file_location("anomaly_detector", MODULE_PATH)
anomaly_detector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(anomaly_detector)


class AnomalyDetectorTests(unittest.TestCase):
    def setUp(self):
        self.sample_csv = PROJECT_ROOT / "sample-inputs" / "synthetic_signin_logs.csv"
        self.test_output_dir = PROJECT_ROOT / "sample-output" / "test-output"

    def tearDown(self):
        if self.test_output_dir.exists():
            shutil.rmtree(self.test_output_dir)

    def test_load_logs_validates_required_columns(self):
        logs = anomaly_detector.load_logs(self.sample_csv)

        self.assertGreater(len(logs), 0)
        self.assertTrue(anomaly_detector.REQUIRED_COLUMNS.issubset(set(logs.columns)))

    def test_missing_columns_raise_value_error(self):
        logs = pd.read_csv(self.sample_csv).drop(columns=["source_ip"])

        with self.assertRaises(ValueError) as context:
            anomaly_detector.validate_logs(logs)

        self.assertIn("missing required columns", str(context.exception))

    def test_score_events_identifies_anomalies(self):
        logs = anomaly_detector.load_logs(self.sample_csv)
        scored = anomaly_detector.score_events(logs, contamination=0.15)

        self.assertIn("anomaly_score", scored.columns)
        self.assertIn("is_anomaly", scored.columns)
        self.assertGreater(scored["is_anomaly"].sum(), 0)

    def test_expected_anomaly_column_not_used_as_feature(self):
        self.assertNotIn("expected_is_anomaly", anomaly_detector.NUMERIC_FEATURES)

    def test_generate_report_includes_required_sections(self):
        logs = anomaly_detector.load_logs(self.sample_csv)
        scored = anomaly_detector.score_events(logs, contamination=0.15)
        report = anomaly_detector.generate_report(scored, contamination=0.15)

        self.assertIn("# ML Anomaly Detection Report", report)
        self.assertIn("## Recommended SOC Triage Steps", report)
        self.assertIn("## Limitations and Human Review Warning", report)
        self.assertIn("T1078 - Valid Accounts", report)

    def test_analyze_file_saves_report_inside_sample_output(self):
        output_path = self.test_output_dir / "anomaly_report.md"

        report = anomaly_detector.analyze_file(self.sample_csv, output_path, contamination=0.15)

        self.assertTrue(output_path.exists())
        self.assertIn("# ML Anomaly Detection Report", report)

    def test_output_path_must_stay_inside_sample_output(self):
        unsafe_output = PROJECT_ROOT / "outside.md"

        with self.assertRaises(ValueError):
            anomaly_detector.resolve_output_path(unsafe_output)

    def test_input_path_must_stay_inside_project_folder(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            outside_csv = Path(temp_dir) / "logs.csv"
            outside_csv.write_text("timestamp,user\n2026-01-01T00:00:00Z,test@example.test\n", encoding="utf-8")

            with self.assertRaises(ValueError):
                anomaly_detector.load_logs(outside_csv)

    def test_invalid_contamination_raises_value_error(self):
        with self.assertRaises(ValueError):
            anomaly_detector.validate_contamination(0.75)

    def test_invalid_timestamp_raises_value_error(self):
        logs = pd.read_csv(self.sample_csv)
        logs.loc[0, "timestamp"] = "not-a-timestamp"

        with self.assertRaises(ValueError) as context:
            anomaly_detector.validate_logs(logs)

        self.assertIn("timestamp values must be valid", str(context.exception))

    def test_invalid_mfa_result_raises_value_error(self):
        logs = pd.read_csv(self.sample_csv)
        logs.loc[0, "mfa_result"] = "maybe"

        with self.assertRaises(ValueError) as context:
            anomaly_detector.validate_logs(logs)

        self.assertIn("mfa_result must be one of", str(context.exception))


if __name__ == "__main__":
    unittest.main()
