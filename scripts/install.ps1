# cloakline installer - Windows.
#
# SAFE ORDERING: hosts entries are the LAST thing added, only after
# cloakline is verified listening on :443. If ANY step fails, hosts
# is rolled back. Prevents the partial-install trap where Claude Code
# cannot reach api.anthropic.com because DNS points at 127.0.0.1 but
# nothing is listening.

$ErrorActionPreference = "Stop"
$Global:HostsAddedLines = @()

function Require-Admin {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "This script must run as Administrator." -ForegroundColor Red
        Write-Host "Right-click Start > Terminal (Admin) or Windows PowerShell (Admin)." -ForegroundColor Red
        exit 1
    }
}

function Test-PortListening {
    param([int]$Port)
    try {
        $conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction Stop
        return ($null -ne $conn)
    } catch {
        return $false
    }
}

function Test-HttpsResponds {
    param([string]$Target, [int]$Port)
    try {
        $req = [System.Net.HttpWebRequest]::Create("https://${Target}:${Port}/")
        $req.Timeout = 3000
        $req.ServerCertificateValidationCallback = { $true }
        try {
            $resp = $req.GetResponse()
            $resp.Close()
            return $true
        } catch [System.Net.WebException] {
            if ($_.Exception.Response) { return $true }
            return $false
        }
    } catch {
        return $false
    }
}

function Set-InspectListenPort {
    param([string]$ConfigPath, [string]$NewListen)
    $raw = Get-Content -Path $ConfigPath -Raw
    if (-not ($raw -match 'inspect:\s*[\r\n]+\s+enabled:\s*true')) {
        Write-Host "  pipeline.yaml: enabling inspect module" -ForegroundColor Green
        $raw = $raw -replace '(inspect:\s*[\r\n]+\s+enabled:\s*)false', '$1true'
    }
    $updated = $raw -replace '(\s+listen:\s*)"?:8443"?', ('$1"' + $NewListen + '"')
    if ($updated -eq $raw) {
        Write-Host "  pipeline.yaml: listen already set (expected '$NewListen')" -ForegroundColor DarkGray
    } else {
        Set-Content -Path $ConfigPath -Value $updated -Encoding UTF8
        Write-Host "  pipeline.yaml: inspect.listen -> $NewListen" -ForegroundColor Green
    }
}

function Install-ScheduledTaskForUser {
    param([string]$TaskName, [string]$ExePath, [string]$ConfigDir)
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Write-Host "  task: '$TaskName' already exists - updating" -ForegroundColor DarkGray
        try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue } catch {}
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    # Run as the current interactive user. Windows lets non-privileged
    # users bind port :443, so SYSTEM isn't needed and running as the
    # user keeps DPAPI keyvault + CA paths naturally aligned.
    $userAtLogon = "$env:USERDOMAIN\$env:USERNAME"
    $action    = New-ScheduledTaskAction -Execute $ExePath -Argument "--config `"$ConfigDir`"" -WorkingDirectory (Split-Path $ExePath -Parent)
    $trigger   = New-ScheduledTaskTrigger -AtLogOn -User $userAtLogon
    $principal = New-ScheduledTaskPrincipal -UserId $userAtLogon -RunLevel Highest -LogonType Interactive
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -Hidden
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "cloakline - local AI DLP gateway (runs as $userAtLogon)" | Out-Null
    Write-Host "  task: '$TaskName' registered (runs as $userAtLogon at that user's logon)" -ForegroundColor Green
}

function Add-HostsLineIfMissing {
    param([string]$Path, [string]$Line, [string]$Marker)
    $current = Get-Content -Path $Path -Raw -ErrorAction SilentlyContinue
    if ($current -match [regex]::Escape($Marker)) {
        Write-Host "  hosts: '$Marker' already present" -ForegroundColor DarkGray
        return $false
    }
    # Retry on transient locks — AV / Defender briefly holds the hosts
    # file open after writes, causing IOException on immediate rewrite.
    $lastErr = $null
    for ($attempt = 1; $attempt -le 6; $attempt++) {
        try {
            Add-Content -Path $Path -Value "`n$Line" -ErrorAction Stop
            Write-Host "  hosts: added '$Line'" -ForegroundColor Green
            return $true
        } catch {
            $lastErr = $_
            Start-Sleep -Milliseconds 500
        }
    }
    throw "could not write hosts (locked after 6 retries): $lastErr"
}

function Invoke-HostsRollback {
    if ($Global:HostsAddedLines.Count -eq 0) { return }
    $HostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
    Write-Host ""
    Write-Host "Rolling back hosts entries so nothing is left in a broken state..." -ForegroundColor Yellow
    for ($attempt = 1; $attempt -le 6; $attempt++) {
        try {
            $lines = Get-Content -Path $HostsFile -ErrorAction Stop
            foreach ($added in $Global:HostsAddedLines) {
                $lines = $lines | Where-Object { $_ -notmatch [regex]::Escape($added) }
            }
            Set-Content -Path $HostsFile -Value $lines -Encoding ASCII -ErrorAction Stop
            ipconfig /flushdns | Out-Null
            Write-Host "  hosts restored, DNS flushed" -ForegroundColor Green
            return
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }
    Write-Host "  WARNING: could not rewrite hosts after 6 retries. Remove these lines manually:" -ForegroundColor Red
    foreach ($added in $Global:HostsAddedLines) { Write-Host "    $added" -ForegroundColor Red }
}

function Invoke-Fatal {
    param([string]$Message)
    Write-Host ""
    Write-Host "FAILED: $Message" -ForegroundColor Red
    Invoke-HostsRollback
    exit 1
}

# --- main ---

Require-Admin

$RepoRoot     = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$ExePath      = Join-Path $RepoRoot "bin\cloakline.exe"
$ConfigDir    = Join-Path $RepoRoot "configs"
$PipelineYaml = Join-Path $ConfigDir "pipeline.yaml"
$HostsFile    = "$env:SystemRoot\System32\drivers\etc\hosts"

if (-not (Test-Path $ExePath))       { Invoke-Fatal "cloakline.exe not found at $ExePath - build it first" }
if (-not (Test-Path $PipelineYaml))  { Invoke-Fatal "pipeline.yaml not found at $PipelineYaml" }

Write-Host ""
Write-Host "cloakline installer (safe ordering)" -ForegroundColor Cyan
Write-Host "  repo: $RepoRoot"
Write-Host ""

Write-Host "[1/7] Prerequisite checks..."
Write-Host "  binary + config present" -ForegroundColor Green

Write-Host ""
Write-Host "[2/7] Configuring cloakline to listen on :443..."
try { Set-InspectListenPort -ConfigPath $PipelineYaml -NewListen ":443" }
catch { Invoke-Fatal "could not edit pipeline.yaml: $_" }

Write-Host ""
Write-Host "[3/7] Installing scheduled task..."
try { Install-ScheduledTaskForUser -TaskName "cloakline" -ExePath $ExePath -ConfigDir $ConfigDir }
catch { Invoke-Fatal "could not register scheduled task: $_" }

Write-Host ""
Write-Host "[4/7] Starting cloakline now..."
try {
    Start-ScheduledTask -TaskName "cloakline"
    Write-Host "  start requested" -ForegroundColor Green
} catch {
    Invoke-Fatal "could not start task: $_"
}

Write-Host ""
Write-Host "[5/7] Verifying cloakline is actually listening..."
$listeningOK = $false
$adminOK = $false
for ($i = 0; $i -lt 15; $i++) {
    Start-Sleep -Seconds 1
    if (-not $adminOK) {
        try {
            $r = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:4001/healthz" -TimeoutSec 2
            if ($r.StatusCode -eq 200) { $adminOK = $true; Write-Host "  admin :4001 responding ($i s)" -ForegroundColor Green }
        } catch {}
    }
    if (-not $listeningOK) {
        if (Test-PortListening -Port 443) {
            if (Test-HttpsResponds -Target "127.0.0.1" -Port 443) {
                $listeningOK = $true
                Write-Host "  :443 responding to TLS ($i s)" -ForegroundColor Green
            }
        }
    }
    if ($adminOK -and $listeningOK) { break }
}
if (-not $adminOK)    { Invoke-Fatal "cloakline admin :4001 did not respond within 15s - check Task Scheduler > 'cloakline' > History" }
if (-not $listeningOK) { Invoke-Fatal "cloakline is not listening on :443 - port may be in use by another service, or bind failed" }

Write-Host ""
Write-Host "[6/7] Adding hosts entries (safe now - cloakline is confirmed listening)..."
try {
    if (Add-HostsLineIfMissing -Path $HostsFile -Line "127.0.0.1 api.anthropic.com" -Marker "127.0.0.1 api.anthropic.com") {
        $Global:HostsAddedLines += "127.0.0.1 api.anthropic.com"
    }
    if (Add-HostsLineIfMissing -Path $HostsFile -Line "127.0.0.1 api.openai.com"    -Marker "127.0.0.1 api.openai.com") {
        $Global:HostsAddedLines += "127.0.0.1 api.openai.com"
    }
} catch {
    Invoke-Fatal "could not edit hosts file: $_"
}

ipconfig /flushdns | Out-Null

Write-Host ""
Write-Host "[7/7] Verifying DNS redirect..."
Start-Sleep -Seconds 1
# Use System.Net.Dns which uses the OS resolver — the same one Windows
# apps (including Claude Code) use. This honors the hosts file.
# Resolve-DnsName with -DnsOnly bypasses hosts and queries DNS
# servers directly, which is the WRONG question here.
try {
    $addrs = [System.Net.Dns]::GetHostAddresses("api.anthropic.com")
    $ips = @($addrs | ForEach-Object { $_.IPAddressToString })
    if ($ips -contains "127.0.0.1") {
        Write-Host "  api.anthropic.com -> 127.0.0.1 [OK]" -ForegroundColor Green
    } else {
        Invoke-Fatal "DNS did not update: got $($ips -join ','), expected 127.0.0.1 in the list"
    }
} catch {
    Invoke-Fatal "DNS check failed: $_"
}

Write-Host ""
Write-Host "Install complete." -ForegroundColor Cyan
Write-Host "  Dashboard: http://127.0.0.1:4001/admin"
Write-Host '  Try:       claude -p "help me reset password: hunter2xyz"'
Write-Host '  Uninstall: scripts\uninstall.ps1 (from admin PowerShell)'
Write-Host ""
Write-Host "IMPORTANT: If Claude Code (or any other client) starts failing with"
Write-Host "'connection refused', it means cloakline stopped. Run:"
Write-Host '  Get-ScheduledTask -TaskName "cloakline" | Start-ScheduledTask'
Write-Host "Or uninstall to restore Claude Code:"
Write-Host '  .\scripts\uninstall.ps1'
