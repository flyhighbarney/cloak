# cloakline one-shot installer.
#
# Does everything from a fresh clone in one command:
#   1. Self-elevates to Administrator (via UAC prompt).
#   2. Builds both binaries with `go build` (skip with -SkipBuild).
#   3. Installs the local inspection CA into the current user's trust
#      store. Windows shows one security dialog - click Yes.
#   4. Runs scripts\install.ps1 to configure pipeline.yaml, register the
#      scheduled task, verify cloakline is listening on :443, and add
#      the two hosts-file entries (with automatic rollback on failure).
#
# Usage from a normal PowerShell (no admin needed - script self-elevates):
#
#     .\scripts\bootstrap.ps1
#
# Flags:
#   -SkipBuild   Skip `go build` (use existing bin\*.exe files)
#   -SkipTrust   Skip CA install (assume it's already trusted)

param(
    [switch]$SkipBuild,
    [switch]$SkipTrust
)

$ErrorActionPreference = "Stop"

# --- fast-fail preflight (before elevation) -------------------------------
# Catch missing prerequisites BEFORE the UAC prompt, so the user isn't
# told to click Yes only to see an immediate failure.

if (-not $SkipBuild) {
    if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
        Write-Host ""
        Write-Host "  Go compiler not found on PATH." -ForegroundColor Red
        Write-Host "  Install Go 1.22+ from https://go.dev/dl/ and re-run this script," -ForegroundColor Red
        Write-Host "  or pre-build the binaries and re-run with -SkipBuild." -ForegroundColor Red
        Write-Host ""
        exit 1
    }
}

# --- self-elevation -------------------------------------------------------

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin   = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "cloakline bootstrap - requesting Administrator elevation..." -ForegroundColor Cyan
    # Relaunch self elevated, forwarding any flags the user passed.
    $forwarded = @()
    if ($SkipBuild) { $forwarded += '-SkipBuild' }
    if ($SkipTrust) { $forwarded += '-SkipTrust' }
    $argList = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', "`"$($MyInvocation.MyCommand.Path)`""
    ) + $forwarded
    Start-Process powershell -Verb RunAs -ArgumentList $argList -Wait
    exit
}

# --- setup ----------------------------------------------------------------

$RepoRoot   = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$BinDir     = Join-Path $RepoRoot "bin"
$CloakExe   = Join-Path $BinDir  "cloak.exe"
$DaemonExe  = Join-Path $BinDir  "cloakline.exe"
$InstallPS1 = Join-Path $RepoRoot "scripts\install.ps1"

Write-Host ""
Write-Host "  cloakline bootstrap" -ForegroundColor Cyan
Write-Host "  repo: $RepoRoot" -ForegroundColor DarkGray
Write-Host ""

# --- Step 1: build --------------------------------------------------------

if (-not $SkipBuild) {
    Write-Host "[1/3] Building binaries..." -ForegroundColor White
    $go = Get-Command go -ErrorAction SilentlyContinue
    if (-not $go) {
        Write-Host "  Go compiler not found on PATH." -ForegroundColor Red
        Write-Host "  Install Go 1.22+ from https://go.dev/dl/ and re-run this script," -ForegroundColor Red
        Write-Host "  or pre-build the binaries and re-run with -SkipBuild." -ForegroundColor Red
        exit 1
    }
    if (-not (Test-Path $BinDir)) {
        New-Item -ItemType Directory -Path $BinDir | Out-Null
    }
    Push-Location $RepoRoot
    try {
        Write-Host "  compiling cloakline (daemon)..." -ForegroundColor DarkGray
        & go build -trimpath -o $DaemonExe ./cmd/cloakline
        if ($LASTEXITCODE -ne 0) { throw "go build cmd/cloakline failed" }
        Write-Host "  compiling cloak (CLI)..." -ForegroundColor DarkGray
        & go build -trimpath -o $CloakExe ./cmd/cloak
        if ($LASTEXITCODE -ne 0) { throw "go build cmd/cloak failed" }
        Write-Host "  [OK] both binaries built" -ForegroundColor Green
    }
    finally { Pop-Location }
} else {
    Write-Host "[1/3] Skipping build (as requested)" -ForegroundColor DarkGray
    if (-not (Test-Path $DaemonExe) -or -not (Test-Path $CloakExe)) {
        Write-Host "  Missing bin\cloakline.exe or bin\cloak.exe. Re-run without -SkipBuild." -ForegroundColor Red
        exit 1
    }
}

# --- Step 2: trust CA -----------------------------------------------------

if (-not $SkipTrust) {
    Write-Host ""
    Write-Host "[2/3] Installing local inspection CA..." -ForegroundColor White
    Write-Host "  Windows will show a security dialog - click Yes to trust the CA." -ForegroundColor Yellow
    & $CloakExe trust install --yes
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  CA install failed. Aborting - hosts file has NOT been touched." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host ""
    Write-Host "[2/3] Skipping CA trust (as requested)" -ForegroundColor DarkGray
}

# --- Step 3: chain to install.ps1 -----------------------------------------

Write-Host ""
Write-Host "[3/3] Running full installer (safe-ordered hosts + task + verify)..." -ForegroundColor White
Write-Host ""

if (-not (Test-Path $InstallPS1)) {
    Write-Host "  scripts\install.ps1 not found at $InstallPS1" -ForegroundColor Red
    exit 1
}

& $InstallPS1
$installExit = $LASTEXITCODE
if ($installExit -ne 0) {
    Write-Host ""
    Write-Host "install.ps1 exited with code $installExit - see messages above." -ForegroundColor Red
    exit $installExit
}

# --- done -----------------------------------------------------------------

Write-Host ""
Write-Host "==================================================" -ForegroundColor Green
Write-Host "  cloakline is installed and running." -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Dashboard:   http://127.0.0.1:4001/admin"
Write-Host "  Live tail:   .\bin\cloak.exe tail"
Write-Host "  Doctor:      .\bin\cloak.exe doctor"
Write-Host ""
Write-Host "  Next: add your provider API keys via the dashboard,"
Write-Host "        or run .\bin\cloak.exe setup for the interactive wizard."
Write-Host ""
Write-Host "  Uninstall:   .\scripts\uninstall.ps1  (from admin PowerShell)"
Write-Host ""
Read-Host "Press Enter to close this window"
