<#
Starts the AI Security Lab dashboard with local Ollama settings.

This script is portable: it resolves the repository root from the script location
and does not use hardcoded user paths.
#>

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $RepoRoot

$env:COPILOT_PROVIDER = "ollama"
$env:OLLAMA_BASE_URL = "http://localhost:11434"
$env:OLLAMA_MODEL = "qwen2.5:3b"
$env:OLLAMA_TIMEOUT_SECONDS = "180"
$env:OLLAMA_HEALTH_TIMEOUT_SECONDS = "10"
$env:COPILOT_TEST_MODE = "false"

$OllamaTagsUrl = "$($env:OLLAMA_BASE_URL)/api/tags"
$OllamaGenerateUrl = "$($env:OLLAMA_BASE_URL)/api/generate"

function Write-Step {
    param([string]$Message)
    Write-Host "[AI Security Lab] $Message"
}

function Test-OllamaReachable {
    try {
        Invoke-RestMethod -Uri $OllamaTagsUrl -Method Get -TimeoutSec ([int]$env:OLLAMA_HEALTH_TIMEOUT_SECONDS) | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

function Get-OllamaCommand {
    $UserInstallPath = Join-Path $env:LOCALAPPDATA "Programs\Ollama\ollama.exe"
    if (Test-Path -LiteralPath $UserInstallPath) {
        return $UserInstallPath
    }

    $PathCommand = Get-Command "ollama" -ErrorAction SilentlyContinue
    if ($PathCommand) {
        return $PathCommand.Source
    }

    return $null
}

Write-Step "Repository root: $RepoRoot"
Write-Step "Using local Security Copilot provider: $env:COPILOT_PROVIDER"
Write-Step "Using Ollama base URL: $env:OLLAMA_BASE_URL"
Write-Step "Using Ollama model: $env:OLLAMA_MODEL"
Write-Step "Using Ollama generation timeout: $env:OLLAMA_TIMEOUT_SECONDS seconds"
Write-Step "Using Ollama health timeout: $env:OLLAMA_HEALTH_TIMEOUT_SECONDS seconds"

$OllamaCommand = Get-OllamaCommand

if (-not (Test-OllamaReachable)) {
    Write-Step "Ollama is not reachable. Attempting to start Ollama..."
    if ($OllamaCommand) {
        Start-Process -FilePath $OllamaCommand -WindowStyle Hidden | Out-Null
        Start-Sleep -Seconds 6
    }
    else {
        Write-Warning "Ollama was not found at the Windows user install path or on PATH."
        Write-Warning "Install Ollama, then run: ollama pull qwen2.5:3b"
    }
}

$OllamaReady = Test-OllamaReachable

if ($OllamaReady -and $OllamaCommand) {
    Write-Step "Ollama is reachable. Checking for model $env:OLLAMA_MODEL..."
    $ModelList = (& $OllamaCommand list 2>$null) -join "`n"
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Could not read Ollama model list. The dashboard will still start and show setup guidance if needed."
    }
    elseif ($ModelList -notmatch [regex]::Escape($env:OLLAMA_MODEL)) {
        Write-Step "Model $env:OLLAMA_MODEL not found. Pulling model locally..."
        & $OllamaCommand pull $env:OLLAMA_MODEL
    }

    Write-Step "Preloading model $env:OLLAMA_MODEL..."
    $PreloadBody = @{
        model = $env:OLLAMA_MODEL
        prompt = "preload"
        stream = $false
    } | ConvertTo-Json

    try {
        Invoke-RestMethod -Uri $OllamaGenerateUrl -Method Post -ContentType "application/json" -Body $PreloadBody -TimeoutSec ([int]$env:OLLAMA_TIMEOUT_SECONDS) | Out-Null
        Write-Step "Model preload completed."
    }
    catch {
        Write-Warning "Model preload did not complete. The dashboard will still start and show setup guidance if needed."
    }
}
else {
    Write-Warning "Ollama is still not reachable. The dashboard will start, and Security Copilot will show setup-required guidance."
}

Write-Step "Starting Streamlit dashboard..."

$PythonCommand = Get-Command "python" -ErrorAction SilentlyContinue
if ($PythonCommand) {
    & $PythonCommand.Source -m streamlit run .\dashboard\app.py
}
else {
    Write-Step "python was not found on PATH. Trying py -3 instead..."
    & py -3 -m streamlit run .\dashboard\app.py
}
