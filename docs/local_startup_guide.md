# Local Startup Guide

This guide explains how to start the AI Security Lab dashboard on Windows with the Ollama-powered Security Copilot.

All data in this lab must remain fake/sample only. Do not enter secrets, tokens, passwords, API keys, company data, client data, tenant data, production logs, or vendor confidential data.

## Install Ollama

1. Download Ollama for Windows from the official Ollama website.
2. Install it for your Windows user.
3. Open a new PowerShell window.

Verify the install:

```powershell
ollama --version
```

## Pull The Local Model Manually

The default Security Copilot model is `qwen2.5:3b`.

```powershell
ollama pull qwen2.5:3b
```

You can confirm installed models with:

```powershell
ollama list
```

## One-Command Dashboard Start

From the repository root:

```powershell
.\start-dashboard.ps1
```

The launcher sets these local environment variables for the dashboard process:

```powershell
COPILOT_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=qwen2.5:3b
OLLAMA_TIMEOUT_SECONDS=180
OLLAMA_HEALTH_TIMEOUT_SECONDS=10
COPILOT_TEST_MODE=false
```

It also checks whether Ollama is reachable, tries to start Ollama if needed, pulls `qwen2.5:3b` if the model is missing, preloads the model through the local Ollama API, and starts Streamlit.

## If PowerShell Blocks The Script

If PowerShell blocks local scripts, allow trusted local scripts for your current Windows user:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Then run:

```powershell
.\start-dashboard.ps1
```

## Verify The Dashboard Starts

After the script runs, Streamlit prints a local URL such as:

```text
http://localhost:8501
```

Open that URL in your browser. The dashboard should show:

- Project Reports
- Security Copilot Chat
- Ollama provider status
- Setup guidance if Ollama or the model is unavailable

## Manual Fallback

If you want to start the dashboard manually:

```powershell
$env:COPILOT_PROVIDER="ollama"
$env:OLLAMA_BASE_URL="http://localhost:11434"
$env:OLLAMA_MODEL="qwen2.5:3b"
$env:OLLAMA_TIMEOUT_SECONDS="180"
$env:OLLAMA_HEALTH_TIMEOUT_SECONDS="10"
$env:COPILOT_TEST_MODE="false"
python -m streamlit run .\dashboard\app.py
```

## Timeout Notes

The dashboard uses separate timeout settings for local Ollama:

- `OLLAMA_HEALTH_TIMEOUT_SECONDS=10` for health/model checks.
- `OLLAMA_TIMEOUT_SECONDS=180` for model answer generation.

If Ollama is reachable but the model response is slow, Security Copilot shows a timeout-specific message instead of saying setup is missing.

## Safety Reminder

Use fake/sample data only. Do not upload or type real secrets, tokens, passwords, API keys, company data, client data, tenant data, production security logs, or vendor confidential data into the dashboard or Security Copilot Chat.
