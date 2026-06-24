#Requires -Version 5.1
<#
.SYNOPSIS
    Nexus Scanner - Installation Script for Windows
.DESCRIPTION
    Automated setup: checks Python/Semgrep, installs dependencies,
    creates .env config, and validates the installation.
.NOTES
    Run:  .\install.ps1
    Or:   powershell -ExecutionPolicy Bypass -File install.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ── Helpers ──────────────────────────────────────────────────────────────────

function Write-Step    { param([string]$Msg) Write-Host "`n[*] " -ForegroundColor Cyan   -NoNewline; Write-Host $Msg }
function Write-OK      { param([string]$Msg) Write-Host "[+] " -ForegroundColor Green  -NoNewline; Write-Host $Msg }
function Write-Warn    { param([string]$Msg) Write-Host "[!] " -ForegroundColor Yellow -NoNewline; Write-Host $Msg }
function Write-Err     { param([string]$Msg) Write-Host "[-] " -ForegroundColor Red    -NoNewline; Write-Host $Msg }
function Write-Info    { param([string]$Msg) Write-Host "    $Msg" -ForegroundColor Gray }

function Test-CommandExists {
    param([string]$Command)
    $null -ne (Get-Command $Command -ErrorAction SilentlyContinue)
}

# ── Banner ───────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "  =====================================================" -ForegroundColor DarkCyan
Write-Host "   N E X U S   S C A N N E R   —   I N S T A L L E R " -ForegroundColor Cyan
Write-Host "  =====================================================" -ForegroundColor DarkCyan
Write-Host "   AI-powered multi-vulnerability security scanner"     -ForegroundColor DarkGray
Write-Host "   https://github.com/your-username/nexus-scanner"     -ForegroundColor DarkGray
Write-Host ""

# ── Step 1: Python Check ─────────────────────────────────────────────────────

Write-Step "Checking Python installation..."

$pythonCmd = $null
foreach ($cmd in @("python", "python3", "py")) {
    if (Test-CommandExists $cmd) {
        $pythonCmd = $cmd
        break
    }
}

if (-not $pythonCmd) {
    Write-Err "Python not found on this system."
    Write-Host ""
    Write-Host "    Nexus requires Python 3.10 or higher." -ForegroundColor White
    Write-Host "    Download: https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    After installing, make sure to check" -ForegroundColor White
    Write-Host "    'Add Python to PATH' during setup." -ForegroundColor Yellow
    Write-Host ""
    $continue = Read-Host "    Installed Python already? Enter the full path (or press Enter to exit)"
    if (-not $continue) { exit 1 }
    if (Test-CommandExists $continue) {
        $pythonCmd = $continue
    } else {
        Write-Err "Cannot find '$continue'. Exiting."
        exit 1
    }
}

# Version check
$versionOutput = & $pythonCmd --version 2>&1
if ($versionOutput -match "Python (\d+)\.(\d+)\.(\d+)") {
    $major = [int]$Matches[1]
    $minor = [int]$Matches[2]
    $patch = $Matches[3]
    Write-OK "Python $major.$minor.$patch found ($pythonCmd)"

    if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 10)) {
        Write-Err "Python >= 3.10 required. Found $major.$minor.$patch"
        Write-Info "Download: https://www.python.org/downloads/"
        exit 1
    }
} else {
    Write-Warn "Could not parse Python version: $versionOutput"
}

# ── Step 2: pip Check ────────────────────────────────────────────────────────

Write-Step "Checking pip..."

$pipCmd = $null
if (& $pythonCmd -m pip --version 2>$null) {
    $pipCmd = "$pythonCmd -m pip"
    Write-OK "pip available via '$pythonCmd -m pip'"
} elseif (Test-CommandExists "pip") {
    $pipCmd = "pip"
    Write-OK "pip available as standalone command"
} else {
    Write-Err "pip not found."
    Write-Info "Installing pip..."
    & $pythonCmd -m ensurepip --upgrade 2>$null
    if ($LASTEXITCODE -eq 0) {
        $pipCmd = "$pythonCmd -m pip"
        Write-OK "pip installed successfully"
    } else {
        Write-Err "Failed to install pip. Please install manually:"
        Write-Info "https://pip.pypa.io/en/stable/installation/"
        exit 1
    }
}

# ── Step 3: Semgrep Check ────────────────────────────────────────────────────

Write-Step "Checking Semgrep..."

$semgrepOk = $false
if (Test-CommandExists "semgrep") {
    $semgrepVersion = & semgrep --version 2>&1
    if ($semgrepVersion -match "(\d+\.\d+)") {
        Write-OK "Semgrep $semgrepVersion found"
        $semgrepOk = $true
    }
}

if (-not $semgrepOk) {
    Write-Warn "Semgrep not found."
    Write-Host ""
    Write-Host "    Semgrep is required for tool-based vulnerability verification." -ForegroundColor White
    Write-Host ""
    Write-Host "    Install options:" -ForegroundColor White
    Write-Host "      [1] pip install semgrep  (recommended)" -ForegroundColor Yellow
    Write-Host "      [2] Skip (Semgrep features will be unavailable)" -ForegroundColor DarkGray
    Write-Host "      [3] Manual download: https://semgrep.dev/docs/getting-started/" -ForegroundColor DarkGray
    Write-Host ""

    $choice = Read-Host "    Choose [1/2/3] (default: 1)"
    if (-not $choice -or $choice -eq "1") {
        Write-Info "Installing Semgrep via pip..."
        & $pythonCmd -m pip install semgrep --quiet
        if ($LASTEXITCODE -eq 0) {
            Write-OK "Semgrep installed successfully"
            $semgrepOk = $true
        } else {
            Write-Warn "Semgrep installation failed. Continuing without it."
            Write-Info "You can install later: pip install semgrep"
        }
    } elseif ($choice -eq "3") {
        Start-Process "https://semgrep.dev/docs/getting-started/"
        Write-Info "Opened Semgrep docs in browser. Install manually, then re-run this script."
        exit 0
    } else {
        Write-Warn "Skipping Semgrep. Tool verification will be unavailable."
    }
}

# ── Step 4: Install Python Dependencies ──────────────────────────────────────

Write-Step "Installing Python dependencies..."

$reqFile = Join-Path $PSScriptRoot "requirements.txt"
if (-not (Test-Path $reqFile)) {
    Write-Err "requirements.txt not found at: $reqFile"
    Write-Info "Make sure you run this script from the nexus-scanner directory."
    exit 1
}

Write-Info "Running: $pythonCmd -m pip install -r requirements.txt"
& $pythonCmd -m pip install -r $reqFile --quiet --disable-pip-version-check
if ($LASTEXITCODE -eq 0) {
    Write-OK "All dependencies installed"
} else {
    Write-Warn "Some dependencies may have failed. Check the output above."
    Write-Info "Try manually: $pythonCmd -m pip install -r requirements.txt"
}

# ── Step 5: .env Configuration ───────────────────────────────────────────────

Write-Step "Configuration (.env file)..."

$envFile = Join-Path $PSScriptRoot ".env"
$envExample = Join-Path $PSScriptRoot ".env.example"

if (Test-Path $envFile) {
    Write-OK ".env already exists — skipping creation"
    Write-Info "To reconfigure, edit $envFile manually"
} else {
    Write-Host ""
    Write-Host "    Nexus needs an LLM API key to run semantic analysis." -ForegroundColor White
    Write-Host "    Supported providers: OpenRouter, DeepSeek, Xiaomi MiMo, OpenAI" -ForegroundColor DarkGray
    Write-Host ""

    $apiKey = Read-Host "    Enter your API key (or press Enter to skip)"
    $baseUrl = Read-Host "    Enter base URL (default: https://api.openai.com/v1)"
    $model = Read-Host "    Enter model name (default: gpt-4o-mini)"

    if (-not $baseUrl) { $baseUrl = "https://api.openai.com/v1" }
    if (-not $model)   { $model = "gpt-4o-mini" }

    $envContent = @"
# Nexus Scanner Configuration
# Generated by install.ps1 on $(Get-Date -Format "yyyy-MM-dd HH:mm")

NEXUS_API_KEY=$apiKey
NEXUS_BASE_URL=$baseUrl
NEXUS_MODEL=$model
"@

    Set-Content -Path $envFile -Value $envContent -Encoding UTF8
    Write-OK ".env created at $envFile"

    if (-not $apiKey) {
        Write-Warn "No API key entered. You'll need to edit .env before scanning."
        Write-Info "Edit: notepad $envFile"
    }
}

# ── Step 6: Create Output Directory ──────────────────────────────────────────

$outputDir = Join-Path $PSScriptRoot "outputs"
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    Write-OK "Created outputs/ directory"
}

$cacheDir = Join-Path $PSScriptRoot ".nexus_cache"
if (-not (Test-Path $cacheDir)) {
    New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null
    Write-OK "Created .nexus_cache/ directory"
}

# ── Step 7: Validation ───────────────────────────────────────────────────────

Write-Step "Validating installation..."

$checks = @()

# Check imports
$importTest = & $pythonCmd -c @"
import sys
modules = [
    'openai', 'yaml', 'pytest',
    'core.fact_card', 'core.hypothesis_card', 'core.evidence_chain',
    'perception.encoder', 'agents.semantic_analyst',
    'knowledge.vuln_patterns', 'compliance.owasp_mapper',
]
failed = []
for m in modules:
    try:
        __import__(m)
    except ImportError:
        failed.append(m)
if failed:
    print('FAIL:' + ','.join(failed))
else:
    print('OK')
"@ 2>&1

if ($importTest -match "^OK$") {
    Write-OK "All core modules importable"
    $checks += @{ Name = "Core modules"; Status = $true }
} else {
    $failedMods = $importTest -replace "^FAIL:", ""
    Write-Warn "Import failures: $failedMods"
    $checks += @{ Name = "Core modules"; Status = $false }
}

# Check Semgrep
if ($semgrepOk) {
    $checks += @{ Name = "Semgrep"; Status = $true }
} else {
    $checks += @{ Name = "Semgrep"; Status = $false }
}

# Check .env
if (Test-Path $envFile) {
    $envContent = Get-Content $envFile -Raw
    if ($envContent -match "NEXUS_API_KEY=\S+" -and $envContent -notmatch "your_api_key_here") {
        $checks += @{ Name = "API Key configured"; Status = $true }
    } else {
        $checks += @{ Name = "API Key configured"; Status = $false }
    }
} else {
    $checks += @{ Name = ".env file"; Status = $false }
}

# Check main entry point
$mainOk = & $pythonCmd -c "import main_p3" 2>&1
if ($LASTEXITCODE -eq 0) {
    $checks += @{ Name = "Entry point (main_p3)"; Status = $true }
} else {
    $checks += @{ Name = "Entry point (main_p3)"; Status = $false }
}

# ── Summary ──────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "  =====================================================" -ForegroundColor DarkCyan
Write-Host "   I N S T A L L A T I O N   S U M M A R Y" -ForegroundColor Cyan
Write-Host "  =====================================================" -ForegroundColor DarkCyan
Write-Host ""

$allPassed = $true
foreach ($check in $checks) {
    if ($check.Status) {
        Write-Host "    [OK]  " -ForegroundColor Green -NoNewline
    } else {
        Write-Host "    [--]  " -ForegroundColor Yellow -NoNewline
        $allPassed = $false
    }
    Write-Host $check.Name
}

Write-Host ""

if ($allPassed) {
    Write-Host "  Nexus Scanner is ready to use!" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Quick start:" -ForegroundColor White
    Write-Host "    python main_p3.py --target YOUR_CODE_DIR --api-key YOUR_KEY \" -ForegroundColor Gray
    Write-Host "        --base-url https://api.openai.com/v1 --model gpt-4o-mini" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Or use Docker:" -ForegroundColor White
    Write-Host "    docker build -t nexus-scanner ." -ForegroundColor Gray
    Write-Host "    docker run --rm -v ./your-code:/target:ro nexus-scanner --target /target" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Run tests:" -ForegroundColor White
    Write-Host "    python -m pytest tests/ -v" -ForegroundColor Gray
} else {
    Write-Host "  Installation completed with warnings." -ForegroundColor Yellow
    Write-Host "  Some features may not work until the above items are resolved." -ForegroundColor Yellow
    Write-Host ""

    if (-not ($checks | Where-Object { $_.Name -eq "API Key configured" -and $_.Status })) {
        Write-Host "  To configure your API key:" -ForegroundColor White
        Write-Host "    notepad .env" -ForegroundColor Gray
    }
    if (-not $semgrepOk) {
        Write-Host "  To install Semgrep:" -ForegroundColor White
        Write-Host "    pip install semgrep" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "  Docs: https://github.com/your-username/nexus-scanner" -ForegroundColor DarkGray
Write-Host ""
