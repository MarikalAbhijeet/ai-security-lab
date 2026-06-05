# Testing Guide

This repository uses Python's standard `unittest` module. No external Python packages are required for version 1 of the projects.

All tests use fake/sample data only.

## Run All Tests

From the repository root:

```powershell
python .\run_all_tests.py
```

On Windows, if `python` is not available:

```powershell
py -3 .\run_all_tests.py
```

## Run Individual Project Tests

### Project 1: AI SOC Assistant

```powershell
cd .\01-ai-soc-assistant
python -m unittest discover -s tests
```

### Project 2: AI Phishing Analyzer

```powershell
cd .\02-ai-phishing-analyzer
python -m unittest discover -s tests
```

### Project 3: Prompt Injection Lab

```powershell
cd .\03-prompt-injection-lab
python -m unittest discover -s tests
```

### Project 4: AI Vendor Risk Toolkit

```powershell
cd .\04-ai-vendor-risk-toolkit
python -m unittest discover -s tests
```

## Batch Mode Test Coverage

Each project includes tests for:

- Single-file report generation
- JSON field validation
- Safe output path handling
- Batch report generation from `sample-inputs`
- Rejection of unsafe batch output directories
- Command-line batch mode and invalid batch argument combinations

By default, batch mode writes generated reports to each project's `sample-output/batch` folder. Custom batch output directories must remain inside that project's `sample-output` folder.

## GitHub Actions

The workflow at `.github/workflows/python-tests.yml` runs `python run_all_tests.py` on push and pull request.
