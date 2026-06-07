"""Tests for local document retrieval."""

import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PROJECT_ROOT.parent
sys.path.insert(0, str(PROJECT_ROOT))

from retriever import discover_files, retrieve, resolve_index_root, should_exclude_path  # noqa: E402


class RetrieverTests(unittest.TestCase):
    def test_discovery_excludes_hidden_and_sensitive_paths(self):
        files = discover_files(REPO_ROOT)
        file_text = "\n".join(path.as_posix().lower() for path in files)

        self.assertGreater(len(files), 0)
        self.assertNotIn(".git", file_text)
        self.assertNotIn(".env", file_text)
        self.assertNotIn("security_copilot/sample-output", file_text)
        self.assertNotIn("security_copilot/sample-questions", file_text)
        self.assertNotIn("security_copilot/prompts", file_text)

    def test_should_exclude_sensitive_names(self):
        self.assertTrue(should_exclude_path(Path("docs") / "password_notes.md"))
        self.assertTrue(should_exclude_path(Path("docs") / "api_key_notes.md"))
        self.assertTrue(should_exclude_path(Path(".hidden") / "notes.md"))
        self.assertTrue(should_exclude_path(Path("node_modules") / "package.md"))
        self.assertFalse(should_exclude_path(Path("docs") / "key_concepts.md"))
        self.assertFalse(should_exclude_path(Path("docs") / "monkey_patch_notes.md"))

    def test_retrieve_returns_cited_chunks(self):
        chunks = retrieve("What KQL should I use for risky sign-ins?", index_root=REPO_ROOT, top_k=5)

        self.assertGreater(len(chunks), 0)
        self.assertTrue(all(chunk.source_path for chunk in chunks))
        self.assertTrue(all(chunk.score > 0 for chunk in chunks))

    def test_automation_and_playbook_sources_are_indexed(self):
        files = {path.relative_to(REPO_ROOT).as_posix() for path in discover_files(REPO_ROOT)}

        self.assertIn("automation/kql/suspicious-powershell.kql", files)
        self.assertIn("automation/powershell/Get-DefenderAlertSummary-Sample.ps1", files)
        self.assertIn("docs/soc_playbooks/suspicious-powershell-playbook.md", files)

    def test_soc_questions_prefer_matching_playbooks_and_kql(self):
        chunks = retrieve("What KQL should I run for suspicious PowerShell?", index_root=REPO_ROOT, top_k=5)
        sources = [chunk.source_path for chunk in chunks]

        self.assertIn("automation/kql/suspicious-powershell.kql", sources)
        self.assertIn("docs/soc_playbooks/suspicious-powershell-playbook.md", sources)
        self.assertFalse(any("03-prompt-injection-lab" in source for source in sources))

    def test_index_root_must_stay_inside_repo(self):
        with self.assertRaises(ValueError):
            resolve_index_root(Path("C:/"))


if __name__ == "__main__":
    unittest.main()
