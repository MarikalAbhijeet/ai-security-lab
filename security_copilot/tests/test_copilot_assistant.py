"""Tests for the offline Security Copilot assistant."""

import importlib.util
import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = PROJECT_ROOT / "copilot_assistant.py"

spec = importlib.util.spec_from_file_location("copilot_assistant", MODULE_PATH)
copilot_assistant = importlib.util.module_from_spec(spec)
sys.modules["copilot_assistant"] = copilot_assistant
spec.loader.exec_module(copilot_assistant)


class CopilotAssistantTests(unittest.TestCase):
    def test_discover_documents_excludes_sensitive_patterns(self):
        documents = copilot_assistant.discover_documents()
        document_text = "\n".join(str(path) for path in documents).lower()

        self.assertGreater(len(documents), 0)
        self.assertNotIn(".git", document_text)
        self.assertNotIn(".env", document_text)
        self.assertNotIn("security_copilot\\sample-output", document_text)
        self.assertNotIn("security_copilot/sample-output", document_text)
        self.assertNotIn("agents.md", document_text)
        self.assertNotIn("requirements.txt", document_text)

    def test_retrieve_returns_sources_for_power_shell_question(self):
        results = copilot_assistant.retrieve(
            "What should an analyst check for suspicious PowerShell?",
            top_k=5,
        )

        self.assertGreater(len(results), 0)
        self.assertTrue(any("soc" in result.document.relative_path.lower() for result in results))

    def test_answer_question_includes_sources_and_safe_note(self):
        result = copilot_assistant.answer_question(
            "How does prompt injection map to OWASP LLM Top 10?",
            top_k=4,
        )

        self.assertIn("local AI Security Lab", result["answer"])
        self.assertGreater(len(result["sources"]), 0)
        self.assertIn("Do not paste real secrets", result["safe_use_note"])

    def test_output_path_must_stay_inside_sample_output(self):
        unsafe_path = PROJECT_ROOT / "outside.md"

        with self.assertRaises(ValueError):
            copilot_assistant.resolve_output_path(unsafe_path)

    def test_index_root_must_stay_inside_repo(self):
        with self.assertRaises(ValueError):
            copilot_assistant.resolve_index_root(Path("C:/"))

    def test_question_validation_rejects_empty_question(self):
        with self.assertRaises(ValueError):
            copilot_assistant.validate_question(" ")

    def test_top_k_validation(self):
        with self.assertRaises(ValueError):
            copilot_assistant.validate_top_k(0)

    def test_hidden_and_build_paths_are_excluded(self):
        self.assertTrue(copilot_assistant.should_exclude_path(Path(".hidden") / "notes.md"))
        self.assertTrue(copilot_assistant.should_exclude_path(Path("build") / "notes.md"))
        self.assertTrue(copilot_assistant.should_exclude_path(Path("dist") / "notes.md"))

    def test_low_context_answer_is_clear(self):
        answer = copilot_assistant.synthesize_answer("unrelated question", [])

        self.assertIn("do not have enough local", answer.lower())


if __name__ == "__main__":
    unittest.main()
