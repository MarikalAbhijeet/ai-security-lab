# Testing Guide

This repository uses Python's standard `unittest` module. Projects 1-4 use only the Python standard library. The dashboard uses Streamlit, Project 5 uses pandas and scikit-learn, and Security Copilot Chat uses scikit-learn for local TF-IDF retrieval. Copilot tests use mock mode and do not require Ollama.

All tests use fake/sample data only.

## Run All Tests

From the repository root:

```powershell
python -m pip install -r .\dashboard\requirements.txt
python -m pip install -r .\05-ml-anomaly-detection\requirements.txt
python -m pip install -r .\security_copilot\requirements.txt
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

### Project 5: ML Anomaly Detection

```powershell
cd .\05-ml-anomaly-detection
python -m pip install -r requirements.txt
python -m unittest discover -s tests
```

### Security Copilot Chat

```powershell
cd .\security_copilot
python -m pip install -r requirements.txt
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
