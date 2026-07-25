# cloakline uninstaller. Removes the scheduled task, restores the hosts
# file, and reverts inspect.listen to :8443. Leaves the CA cert in place -
# remove that with 'cloak trust remove'.
#
# Pass -Purge to also delete the built binaries under <root>\bin. The npm
# wrapper (npx cloakline uninstall) removes them regardless, because
# leaving them makes the next install silently reuse the stale binary
# instead of downloading the new release.

param(
    [switch]$Purge
)

$ErrorActionPreference = "Stop"

function Require-Admin {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "This script must run as Administrator." -ForegroundColor Red; exit 1
    }
}
Require-Admin

$RepoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$PipelineYaml = Join-Path $RepoRoot "configs\pipeline.yaml"

Write-Host "cloakline uninstaller" -ForegroundColor Cyan

Write-Host "[1/4] Stopping and removing scheduled task..."
if (Get-ScheduledTask -TaskName "cloakline" -ErrorAction SilentlyContinue) {
    try { Stop-ScheduledTask -TaskName "cloakline" } catch {}
    Unregister-ScheduledTask -TaskName "cloakline" -Confirm:$false
    Write-Host "  removed" -ForegroundColor Green
} else { Write-Host "  no task found" -ForegroundColor DarkGray }

Write-Host "[2/4] Killing any running cloakline.exe..."
Get-Process -Name "cloakline" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

Write-Host "[3/4] Removing hosts entries..."
$HostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
$hosts = Get-Content -Path $HostsFile
$filtered = $hosts | Where-Object {
    ($_ -notmatch '127\.0\.0\.1\s+api\.anthropic\.com') -and
    ($_ -notmatch '127\.0\.0\.1\s+api\.openai\.com')
}
Set-Content -Path $HostsFile -Value $filtered -Encoding ASCII
ipconfig /flushdns | Out-Null
Write-Host "  hosts + DNS cache cleaned" -ForegroundColor Green

Write-Host "[4/4] Reverting inspect.listen to :8443..."
if (Test-Path $PipelineYaml) {
    $raw = Get-Content -Path $PipelineYaml -Raw
    $updated = $raw -replace '(\s+listen:\s*)"?:443"?', '$1":8443"'
    Set-Content -Path $PipelineYaml -Value $updated -Encoding UTF8
    Write-Host "  reverted" -ForegroundColor Green
}

if ($Purge) {
    Write-Host "[*] Purging binaries..."
    $BinDir = Join-Path $RepoRoot "bin"
    if (Test-Path $BinDir) {
        try {
            Remove-Item -Path $BinDir -Recurse -Force
            Write-Host "  removed $BinDir" -ForegroundColor Green
        } catch {
            Write-Host "  could not remove $BinDir : $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  no bin directory at $BinDir" -ForegroundColor DarkGray
    }
}

Write-Host ""
Write-Host "Uninstall complete." -ForegroundColor Cyan
Write-Host "  CA still trusted - remove with: cloak trust remove"
if (-not $Purge) {
    Write-Host "  Binaries left in bin/ - re-run with -Purge (or use 'npx cloakline uninstall') to remove"
}
