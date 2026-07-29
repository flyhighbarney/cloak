# Run this ONCE you have an Anthropic API key.
#   1. Get one at https://console.anthropic.com/settings/keys
#      (Costs ~$0.01 per test message with claude-3-5-sonnet.)
#   2. $env:ANTHROPIC_API_KEY = "sk-ant-..."
#   3. .\bin\test-claude.ps1

param(
  [string]$Prompt = "Hi Claude! In one short sentence, what makes you different from GPT-4?"
)

$env:PATH = "C:\Program Files\Go\bin;$env:PATH"
Set-Location (Split-Path $PSScriptRoot -Parent)

if (-not $env:ANTHROPIC_API_KEY) {
  Write-Host "ANTHROPIC_API_KEY not set." -ForegroundColor Red
  Write-Host "Get one at https://console.anthropic.com/settings/keys, then:"
  Write-Host "    `$env:ANTHROPIC_API_KEY = 'sk-ant-...'"
  exit 1
}
if (-not $env:OLLAMA_API_KEY) { $env:OLLAMA_API_KEY = "unused" }

Write-Host "== restarting policyd with anthropic + ollama routes ==" -ForegroundColor Cyan
Stop-Process -Name policyd -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
if (Test-Path "bin\policyd.log") { Clear-Content "bin\policyd.log" }
Start-Process -FilePath "bin\policyd.exe" -ArgumentList "--config", "configs" `
  -RedirectStandardOutput "bin\policyd.log" -RedirectStandardError "bin\policyd.err" -NoNewWindow | Out-Null
Start-Sleep -Seconds 2
Write-Host "  policyd ready. See bin\policyd.log for structured logs.`n"

# -------- Test 1: OpenAI-shaped ingress asking for a Claude model --------
Write-Host "== TEST 1: /v1/chat/completions + model=claude-3-5-sonnet ==" -ForegroundColor Cyan
$body1 = @{
  model = "claude-3-5-sonnet-20241022"
  messages = @(@{ role = "user"; content = $Prompt })
} | ConvertTo-Json -Compress

$t0 = Get-Date
try {
  $r = Invoke-WebRequest -Method Post -Uri "http://localhost:4000/v1/chat/completions" `
    -Body $body1 -ContentType "application/json" `
    -Headers @{"Authorization"="Bearer sk-gw-dev-alpha-000000000000"} `
    -UseBasicParsing -TimeoutSec 60
  $dt = ((Get-Date) - $t0).TotalSeconds
  Write-Host "  STATUS=$($r.StatusCode) took $([math]::Round($dt,1))s" -ForegroundColor Green
  Write-Host "  reply: $(($r.Content | ConvertFrom-Json).choices[0].message.content)"
} catch {
  Write-Host "  FAILED: $($_.Exception.Message)" -ForegroundColor Red
}

# -------- Test 2: Anthropic-shaped ingress via /v1/messages --------
Write-Host "`n== TEST 2: /v1/messages (native Anthropic wire) ==" -ForegroundColor Cyan
$body2 = @{
  model = "claude-3-5-sonnet-20241022"
  max_tokens = 200
  messages = @(@{ role = "user"; content = $Prompt })
} | ConvertTo-Json -Compress

$t0 = Get-Date
try {
  $r = Invoke-WebRequest -Method Post -Uri "http://localhost:4000/v1/messages" `
    -Body $body2 -ContentType "application/json" `
    -Headers @{"x-api-key"="sk-gw-dev-alpha-000000000000"} `
    -UseBasicParsing -TimeoutSec 60
  $dt = ((Get-Date) - $t0).TotalSeconds
  Write-Host "  STATUS=$($r.StatusCode) took $([math]::Round($dt,1))s" -ForegroundColor Green
  Write-Host "  reply: $(($r.Content | ConvertFrom-Json).content[0].text)"
} catch {
  Write-Host "  FAILED: $($_.Exception.Message)" -ForegroundColor Red
}

# -------- Test 3: PII redact + Claude reply (real end-to-end) --------
Write-Host "`n== TEST 3: PII redacted before reaching Claude ==" -ForegroundColor Cyan
$body3 = @{
  model = "claude-3-5-sonnet-20241022"
  max_tokens = 200
  messages = @(@{ role = "user"; content = "My name is John Doe and my email is jdoe@acme-legal.com. Reply with just my email address so I know you got it." })
} | ConvertTo-Json -Compress

$t0 = Get-Date
try {
  $r = Invoke-WebRequest -Method Post -Uri "http://localhost:4000/v1/messages" `
    -Body $body3 -ContentType "application/json" `
    -Headers @{"x-api-key"="sk-gw-dev-alpha-000000000000"} `
    -UseBasicParsing -TimeoutSec 60
  $dt = ((Get-Date) - $t0).TotalSeconds
  Write-Host "  STATUS=$($r.StatusCode) took $([math]::Round($dt,1))s" -ForegroundColor Green
  $reply = ($r.Content | ConvertFrom-Json).content[0].text
  Write-Host "  Claude's reply: $reply"
  if ($reply -match "jdoe@acme-legal.com") {
    Write-Host "  ✓ email restored on the way back — redact/restore round-trip works" -ForegroundColor Green
  } else {
    Write-Host "  Note: Claude may have refused or paraphrased. Check policyd log for tokenization." -ForegroundColor Yellow
  }
} catch {
  Write-Host "  FAILED: $($_.Exception.Message)" -ForegroundColor Red
}

# -------- Leak audit --------
Write-Host "`n== Log leak audit ==" -ForegroundColor Cyan
$patterns = @("jdoe@acme-legal.com", $env:ANTHROPIC_API_KEY, "sk-gw-dev-alpha-000000000000")
foreach ($p in $patterns) {
  $hits = Select-String -Path "bin\policyd.log" -SimpleMatch -Pattern $p -ErrorAction SilentlyContinue
  $label = if ($p -eq $env:ANTHROPIC_API_KEY) { "anthropic key" } elseif ($p -like "*acme*") { "planted email" } else { "virtual key" }
  if ($hits) {
    Write-Host "  LEAK: $label found in log ($($hits.Count) hits)" -ForegroundColor Red
  } else {
    Write-Host "  OK: $label — 0 hits" -ForegroundColor Green
  }
}

Write-Host "`n== Admin dashboard ==" -ForegroundColor Cyan
Write-Host "  http://localhost:4001/admin (shows all three requests + verdicts)"
Start-Process "http://localhost:4001/admin"
