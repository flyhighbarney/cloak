# cloakline PANIC RESTORE - one-command emergency unwind.
#
# Purpose: if Claude Code (or any other AI client) is broken RIGHT
# NOW because cloakline is in a bad state, this script gets you back
# to a clean baseline. Non-interactive; assumes you're OK with EVERY
# cloakline surface being removed.
#
# What it does, in dependency order:
#   1. Force-kill every cloakline.exe process (even ones we can't
#      stop through the scheduler because they were started elevated).
#   2. Stop + unregister the scheduled task.
#   3. Remove BOTH api.anthropic.com and api.openai.com from hosts.
#   4. Flush the DNS resolver cache.
#   5. Print the resolver's post-flush view of both hosts so you can
#      confirm real IPs are back.
#   6. Print a one-line "you're clean" or "check these" summary.
#
# What it does NOT do (deliberately):
#   - Remove the trusted CA from your cert store (that's separate;
#     use `cloak.exe trust remove` if you want that too).
#   - Delete the cloakline.exe binary or the AES-encrypted vault
#     files under %APPDATA%\cloakline.
#   - Revert configs/pipeline.yaml (leave your edits alone).
#
# Requires: Administrator. Exits non-zero if the panic couldn't
# complete (e.g., a cloakline process refuses to die).

$ErrorActionPreference = "Continue"  # keep going through every step

function Require-Admin {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "PANIC RESTORE needs Administrator." -ForegroundColor Red
        Write-Host "Right-click Start > Terminal (Admin), then re-run." -ForegroundColor Red
        exit 2
    }
}
Require-Admin

$anyFailure = $false
Write-Host ""
Write-Host "cloakline PANIC RESTORE" -ForegroundColor Cyan
Write-Host "  Undoing every surface cloakline installed on this machine."
Write-Host ""

# 1. Kill every cloakline.exe.
Write-Host "[1/5] Killing cloakline.exe processes..." -ForegroundColor Yellow
$procs = Get-Process -Name 'cloakline' -ErrorAction SilentlyContinue
if (-not $procs) {
    Write-Host "  no cloakline processes running" -ForegroundColor DarkGray
} else {
    foreach ($p in $procs) {
        try {
            Stop-Process -Id $p.Id -Force -ErrorAction Stop
            Write-Host "  killed PID $($p.Id)" -ForegroundColor Green
        } catch {
            Write-Host "  could not kill PID $($p.Id): $_" -ForegroundColor Red
            # taskkill has better privileges in some scenarios
            & taskkill.exe /F /PID $p.Id 2>&1 | Out-Null
            Start-Sleep -Milliseconds 500
            if (Get-Process -Id $p.Id -ErrorAction SilentlyContinue) {
                Write-Host "  taskkill also failed - process still alive (may need reboot)" -ForegroundColor Red
                $anyFailure = $true
            } else {
                Write-Host "  taskkill succeeded on PID $($p.Id)" -ForegroundColor Green
            }
        }
    }
}

# 2. Scheduled task.
Write-Host ""
Write-Host "[2/5] Removing scheduled task..." -ForegroundColor Yellow
if (Get-ScheduledTask -TaskName 'cloakline' -ErrorAction SilentlyContinue) {
    try { Stop-ScheduledTask -TaskName 'cloakline' -ErrorAction SilentlyContinue } catch {}
    Unregister-ScheduledTask -TaskName 'cloakline' -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "  task removed" -ForegroundColor Green
} else {
    Write-Host "  no task registered" -ForegroundColor DarkGray
}

# 3. Hosts file — remove BOTH entries with retry-on-lock.
Write-Host ""
Write-Host "[3/5] Cleaning hosts file..." -ForegroundColor Yellow
$hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
$success = $false
for ($i = 0; $i -lt 8; $i++) {
    try {
        $lines = Get-Content -Path $hostsFile -ErrorAction Stop
        $kept = $lines | Where-Object {
            ($_ -notmatch '127\.0\.0\.1\s+api\.anthropic\.com') -and
            ($_ -notmatch '127\.0\.0\.1\s+api\.openai\.com')
        }
        if (($kept | Measure-Object).Count -eq ($lines | Measure-Object).Count) {
            Write-Host "  no cloakline entries in hosts" -ForegroundColor DarkGray
        } else {
            Set-Content -Path $hostsFile -Value $kept -Encoding ASCII -ErrorAction Stop
            Write-Host "  hosts entries removed" -ForegroundColor Green
        }
        $success = $true
        break
    } catch {
        Start-Sleep -Milliseconds 500
    }
}
if (-not $success) {
    Write-Host "  could not rewrite hosts after 8 retries (locked by AV?)" -ForegroundColor Red
    Write-Host "  MANUALLY remove these lines from $hostsFile :" -ForegroundColor Red
    Write-Host "    127.0.0.1 api.anthropic.com" -ForegroundColor Red
    Write-Host "    127.0.0.1 api.openai.com"   -ForegroundColor Red
    $anyFailure = $true
}

# 4. Flush DNS cache.
Write-Host ""
Write-Host "[4/5] Flushing DNS cache..." -ForegroundColor Yellow
ipconfig /flushdns | Out-Null
Write-Host "  done" -ForegroundColor Green

# 5. Verify.
Write-Host ""
Write-Host "[5/5] Verifying real Anthropic / OpenAI are back..." -ForegroundColor Yellow
Start-Sleep -Seconds 1
foreach ($hostName in @('api.anthropic.com', 'api.openai.com')) {
    try {
        $rec = Resolve-DnsName -Name $hostName -DnsOnly:$false -ErrorAction Stop |
               Where-Object { $_.Type -eq 'A' } |
               Select-Object -First 1 -ExpandProperty IPAddress
        if ($rec -and $rec -ne '127.0.0.1') {
            Write-Host "  $hostName -> $rec  [OK]" -ForegroundColor Green
        } elseif ($rec -eq '127.0.0.1') {
            Write-Host "  $hostName still -> 127.0.0.1  [BAD]" -ForegroundColor Red
            Write-Host "         (hosts file removal may have failed, or resolver still cached)" -ForegroundColor DarkRed
            $anyFailure = $true
        } else {
            Write-Host "  $hostName -> no A record" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  $hostName lookup failed: $_" -ForegroundColor Yellow
    }
}

Write-Host ""
if ($anyFailure) {
    Write-Host "PANIC RESTORE finished with issues." -ForegroundColor Red
    Write-Host "If Claude Code is still broken, reboot the machine to force everything clean." -ForegroundColor Red
    exit 1
} else {
    Write-Host "Clean. Claude Code + Codex + all clients should work now." -ForegroundColor Green
    Write-Host "  To also revoke the local CA from your cert store:" -ForegroundColor DarkGray
    Write-Host '    .\bin\cloak.exe trust remove' -ForegroundColor DarkGray
    Write-Host "  To reinstall cloakline later (safely):" -ForegroundColor DarkGray
    Write-Host '    .\scripts\install.ps1' -ForegroundColor DarkGray
    exit 0
}
