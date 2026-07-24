# cloakline diagnostic - walks the full request path and reports the
# state of every layer that could stand between Claude Code (or any
# other client) and api.anthropic.com. Non-destructive. Run any time.
#
# Layers checked, in the order a request actually travels them:
#   1. hosts file       -> DNS redirect present?
#   2. Windows resolver -> does api.anthropic.com resolve to 127.0.0.1?
#   3. Scheduled task   -> is cloakline registered to run at logon?
#   4. Process          -> is cloakline.exe actually running?
#   5. Port :443        -> is something listening?
#   6. Admin :4001      -> does the dashboard respond?
#   7. TLS handshake    -> does a client-cert-trusting TLS request work?
#   8. Real Anthropic   -> can we reach the real host (bypassing hosts)?
#   9. CA trust         -> is the cloakline CA in the Windows user store?
#
# Exit code: 0 if everything's healthy AND the pipeline can serve
# Claude Code; non-zero if any critical layer is broken.
#
# If you see a red FAIL, the next line tells you exactly what to run
# to fix it.

$ErrorActionPreference = "Continue"

$critical = 0
$warnings = 0

function OK    { param($msg) Write-Host "  [OK]   $msg" -ForegroundColor Green }
function INFO  { param($msg) Write-Host "  [INFO] $msg" -ForegroundColor DarkGray }
function WARN  { param($msg, $fix)
    Write-Host "  [WARN] $msg" -ForegroundColor Yellow
    if ($fix) { Write-Host "         fix: $fix" -ForegroundColor DarkYellow }
    $script:warnings++
}
function FAIL  { param($msg, $fix)
    Write-Host "  [FAIL] $msg" -ForegroundColor Red
    if ($fix) { Write-Host "         fix: $fix" -ForegroundColor DarkRed }
    $script:critical++
}
function Section { param($n, $title)
    Write-Host ""
    Write-Host "[$n] $title" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "cloakline diagnostic" -ForegroundColor Cyan
Write-Host "  clock: $(Get-Date -Format o)"

$HostsFile     = "$env:SystemRoot\System32\drivers\etc\hosts"
$RepoRoot      = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$UninstallPath = Join-Path $RepoRoot "scripts\uninstall.ps1"
$PanicPath     = Join-Path $RepoRoot "scripts\panic-restore.ps1"

# ---------- 1. hosts file ----------
Section "1/9" "Hosts file"
$hostsRaw = Get-Content -Path $HostsFile -Raw -ErrorAction SilentlyContinue
$anthropicInHosts = $hostsRaw -match '127\.0\.0\.1\s+api\.anthropic\.com'
$openaiInHosts    = $hostsRaw -match '127\.0\.0\.1\s+api\.openai\.com'
if ($anthropicInHosts) { OK "api.anthropic.com -> 127.0.0.1 present" }
                  else { INFO "api.anthropic.com NOT in hosts (traffic to real Anthropic; cloakline not intercepting)" }
if ($openaiInHosts) { OK "api.openai.com -> 127.0.0.1 present" }
              else { INFO "api.openai.com NOT in hosts (not intercepted)" }

# ---------- 2. Windows resolver ----------
Section "2/9" "Windows resolver"
try {
    $dns = Resolve-DnsName -Name api.anthropic.com -DnsOnly:$false -ErrorAction Stop |
           Where-Object { $_.Type -eq 'A' } |
           Select-Object -First 1 -ExpandProperty IPAddress
    if ($anthropicInHosts) {
        if ($dns -eq '127.0.0.1') { OK "api.anthropic.com resolves to 127.0.0.1 (hosts effective)" }
                             else { FAIL "hosts entry present but resolver returns $dns" "ipconfig /flushdns" }
    } else {
        if ($dns -ne '127.0.0.1') { OK "resolves to $dns (real Anthropic)" }
                             else { FAIL "resolver returns 127.0.0.1 but hosts has no entry" "check hosts file for stale entries + run ipconfig /flushdns" }
    }
} catch {
    WARN "Resolve-DnsName failed: $_" "check network"
}

# ---------- 3. Scheduled task ----------
Section "3/9" "Scheduled task"
$task = Get-ScheduledTask -TaskName 'cloakline' -ErrorAction SilentlyContinue
if ($task) {
    OK "task 'cloakline' registered (state: $($task.State))"
    $info = Get-ScheduledTaskInfo -TaskName 'cloakline'
    INFO "last run: $($info.LastRunTime); last result: 0x$([Convert]::ToString($info.LastTaskResult, 16))"
} else {
    if ($anthropicInHosts -or $openaiInHosts) {
        FAIL "hosts entries present but scheduled task missing - traffic will hit dead port" "$PanicPath  (nukes hosts + restarts you clean)"
    } else {
        INFO "task not registered (cloakline not installed)"
    }
}

# ---------- 4. Process ----------
Section "4/9" "cloakline process"
$procs = Get-Process -Name 'cloakline' -ErrorAction SilentlyContinue
if ($procs) {
    foreach ($p in $procs) { OK "cloakline.exe running (PID $($p.Id), started $($p.StartTime))" }
} else {
    if ($anthropicInHosts -or $openaiInHosts) {
        FAIL "hosts intercepts traffic but cloakline.exe NOT running - clients get ConnectionRefused" "Start-ScheduledTask -TaskName cloakline    OR   $PanicPath to fully unwind"
    } else {
        INFO "cloakline.exe not running (nothing to intercept)"
    }
}

# ---------- 5. Port :443 ----------
Section "5/9" "Port :443 listener"
try {
    $conn443 = Get-NetTCPConnection -LocalPort 443 -State Listen -ErrorAction Stop |
               Where-Object { $_.LocalAddress -eq '0.0.0.0' -or $_.LocalAddress -eq '::' -or $_.LocalAddress -eq '127.0.0.1' }
    if ($conn443) {
        $pid443 = $conn443 | Select-Object -First 1 -ExpandProperty OwningProcess
        $ownerProc = Get-Process -Id $pid443 -ErrorAction SilentlyContinue
        if ($ownerProc -and $ownerProc.Name -eq 'cloakline') {
            OK "port 443 held by cloakline.exe (PID $pid443)"
        } elseif ($ownerProc) {
            WARN "port 443 held by $($ownerProc.Name) (PID $pid443), NOT cloakline - conflict" "stop the other process before cloakline can bind"
        } else {
            WARN "port 443 held by PID $pid443 (process gone?)" "reboot may help"
        }
    } else {
        if ($procs) { FAIL "cloakline running but not listening on :443" "check cloakline.err log; usually a bind conflict at startup" }
              else { INFO "nothing listening on :443 (cloakline not running)" }
    }
} catch {
    INFO "no listener on :443"
}

# ---------- 6. Admin :4001 ----------
Section "6/9" "Admin dashboard :4001"
try {
    $r = Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:4001/healthz' -TimeoutSec 3
    if ($r.StatusCode -eq 200) { OK "admin /healthz responds 200" }
                          else { WARN "admin returned $($r.StatusCode), not 200" }
} catch {
    if ($procs) { FAIL "cloakline running but admin :4001 not answering - crashed listener?" "check cloakline logs; restart via task" }
          else { INFO "no admin dashboard (cloakline not running)" }
}

# ---------- 7. TLS handshake through the interceptor ----------
Section "7/9" "TLS handshake to :443"
if ($procs) {
    try {
        # Bypass cert validation for the smoke test.
        $req = [System.Net.HttpWebRequest]::Create("https://127.0.0.1:443/")
        $req.Timeout = 3000
        $req.ServerCertificateValidationCallback = { $true }
        try {
            $resp = $req.GetResponse()
            OK "TLS handshake completes ($($resp.StatusCode))"
            $resp.Close()
        } catch [System.Net.WebException] {
            if ($_.Exception.Response) {
                OK "TLS handshake completes (server returned $([int]$_.Exception.Response.StatusCode))"
            } else {
                FAIL "TLS handshake failed: $($_.Exception.Message)" "check cloakline logs for cert issue"
            }
        }
    } catch { FAIL "TLS probe threw: $_" }
} else { INFO "skipped (cloakline not running)" }

# ---------- 8. Real Anthropic reachability ----------
Section "8/9" "Real Anthropic reachability (bypasses hosts)"
try {
    $realIp = (Resolve-DnsName -Name api.anthropic.com -Server 8.8.8.8 -DnsOnly -ErrorAction Stop |
               Where-Object { $_.Type -eq 'A' } |
               Select-Object -First 1 -ExpandProperty IPAddress)
    if ($realIp) {
        INFO "real Anthropic A record via 8.8.8.8: $realIp"
        $test = Test-NetConnection -ComputerName $realIp -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
        if ($test) { OK "TCP 443 reachable to real Anthropic ($realIp)" }
              else { WARN "cannot reach real Anthropic on :443 - network issue" "check firewall / VPN" }
    } else {
        WARN "no A record from public DNS"
    }
} catch {
    WARN "public DNS lookup failed: $_"
}

# ---------- 9. CA trust ----------
Section "9/9" "cloakline CA trust"
try {
    $caPath = Join-Path $env:APPDATA "cloakline\ca\ca-cert.pem"
    if (Test-Path $caPath) {
        $expected = Get-Content -Path $caPath -Raw
        # Extract SHA1 by loading via cert store — need X509 tools.
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $cert.Import($caPath)
        $thumb = $cert.Thumbprint
        $store = Get-ChildItem -Path Cert:\CurrentUser\Root -ErrorAction SilentlyContinue |
                 Where-Object { $_.Thumbprint -eq $thumb }
        if ($store) { OK "CA installed in Cert:\CurrentUser\Root ($thumb)" }
              else { WARN "CA on disk but NOT in user trust store" "cloak.exe trust install" }
    } else {
        INFO "no CA on disk yet (has 'cloak.exe trust install' ever run?)"
    }
} catch {
    WARN "CA check errored: $_"
}

# ---------- Summary ----------
Write-Host ""
Write-Host "----------------------------------------------------------" -ForegroundColor DarkGray
if ($critical -eq 0 -and $warnings -eq 0) {
    Write-Host "All layers healthy. Claude Code should work either way." -ForegroundColor Green
    exit 0
} elseif ($critical -eq 0) {
    Write-Host "$warnings warning(s); Claude Code should still work." -ForegroundColor Yellow
    exit 0
} else {
    Write-Host "$critical CRITICAL issue(s), $warnings warning(s)." -ForegroundColor Red
    Write-Host "If Claude Code is broken RIGHT NOW, run:" -ForegroundColor Red
    Write-Host "  $PanicPath" -ForegroundColor Red
    exit 1
}
