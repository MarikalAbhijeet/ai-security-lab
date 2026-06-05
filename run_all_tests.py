"""Run all AI Security Lab project test suites."""

import subprocess
import sys
from pathlib import Path


PROJECTS = [
    "01-ai-soc-assistant",
    "02-ai-phishing-analyzer",
    "03-prompt-injection-lab",
    "04-ai-vendor-risk-toolkit",
]


def run_project_tests(repo_root, project_name):
    """Run unittest discovery for one project."""
    project_path = repo_root / project_name
    print(f"\n=== Running tests for {project_name} ===", flush=True)
    result = subprocess.run(
        [sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests"],
        cwd=project_path,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.stdout:
        print(result.stdout, end="", flush=True)
    if result.stderr:
        print(result.stderr, end="", flush=True)
    return result.returncode


def main():
    repo_root = Path(__file__).resolve().parent
    failures = []

    for project_name in PROJECTS:
        return_code = run_project_tests(repo_root, project_name)
        if return_code != 0:
            failures.append(project_name)

    if failures:
        print("\nTest failures:")
        for project_name in failures:
            print(f"- {project_name}")
        return 1

    print("\nAll project tests passed.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
