"""Tests for the Threat Evidence Workbench dashboard flow."""

import os
import sys
import unittest
from pathlib import Path

from streamlit.testing.v1 import AppTest


DASHBOARD_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = DASHBOARD_ROOT.parent
sys.path.insert(0, str(DASHBOARD_ROOT))


class EvidenceWorkbenchDashboardTests(unittest.TestCase):
    def setUp(self):
        os.environ["COPILOT_TEST_MODE"] = "true"

    def test_upload_report_and_copilot_summary_context(self):
        app = AppTest.from_file(str(DASHBOARD_ROOT / "app.py"))
        app.run(timeout=30)
        sample_path = REPO_ROOT / "evidence_analyzer" / "sample-inputs" / "sample_powershell_events.log"

        app.file_uploader[0].upload(sample_path.name, sample_path.read_bytes(), "text/plain").run(timeout=30)
        analyze_index = [button.label for button in app.button].index("Analyze evidence")
        app.button[analyze_index].click().run(timeout=60)

        report_text = "\n".join(markdown.value for markdown in app.markdown)
        context = app.session_state["copilot_session_context"]

        self.assertIn("# Threat Evidence Workbench Report", report_text)
        self.assertIn("Uploaded evidence summary from current session", context)
        self.assertNotIn("IEX (New-Object", context)

        self.assertIn("IOCs / Investigation Artifacts Observed", context)
        self.assertFalse((DASHBOARD_ROOT / sample_path.name).exists())


if __name__ == "__main__":
    unittest.main()
