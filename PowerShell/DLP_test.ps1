# --- CONFIG ---
$FormUrl        = "https://dlptest.com/http-post/"
$TextFieldName  = "data"
$UserAgent      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PowerShell-DLPTest/1.0"

# Optional: strings that indicate "blocked" or "triggered" in the response HTML
$TriggerIndicators = @(
  "blocked",
  "denied",
  "DLP",
  "policy",
  "rule triggered"
)

function Get-HiddenInputsFromHtml {
  param([string]$Html)

  $hidden = @{}
  $pattern = '<input[^>]*type=["'']hidden["''][^>]*>'
  [regex]::Matches($Html, $pattern) | ForEach-Object {
    $tag = $_.Value
    $name = [regex]::Match($tag, 'name=["'']([^"'']+)["'']').Groups[1].Value
    $value = [regex]::Match($tag, 'value=["'']([^"'']*)["'']').Groups[1].Value
    if ($name) { $hidden[$name] = $value }
  }
  return $hidden
}

# --- INPUT ---
Write-Host "Enter the text you want to test. Finish with an empty line:" -ForegroundColor Cyan
$lines = New-Object System.Collections.Generic.List[string]
while ($true) {
  $line = Read-Host
  if ([string]::IsNullOrWhiteSpace($line)) { break }
  $lines.Add($line)
}
$payloadText = ($lines -join "`n")

if ([string]::IsNullOrWhiteSpace($payloadText)) {
  Write-Host "No input provided. Exiting." -ForegroundColor Yellow
  exit 1
}

# --- SESSION ---
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession

try {
  # 1) GET the form page (collect cookies + hidden fields)
  Write-Host "`n[1/3] GET form page: $FormUrl" -ForegroundColor Cyan
  $formResp = Invoke-WebRequest -Uri $FormUrl -Method GET -WebSession $session -UserAgent $UserAgent -ErrorAction Stop

  $hiddenFields = Get-HiddenInputsFromHtml -Html $formResp.Content
  Write-Host ("Captured {0} hidden field(s)." -f $hiddenFields.Count) -ForegroundColor Gray

  # 2) Build POST body
  $body = @{}
  foreach ($k in $hiddenFields.Keys) { $body[$k] = $hiddenFields[$k] }
  $body[$TextFieldName] = $payloadText
  $body["submit"] = "Submit"

  # 3) POST
  Write-Host "[2/3] POST user content..." -ForegroundColor Cyan
  $postResp = Invoke-WebRequest -Uri $FormUrl -Method POST -WebSession $session -UserAgent $UserAgent `
    -ContentType "application/x-www-form-urlencoded" -Body $body -ErrorAction Stop

  Write-Host ("HTTP Status: {0}" -f $postResp.StatusCode) -ForegroundColor Gray

  # 4) Evaluate result
  Write-Host "[3/3] Evaluating response..." -ForegroundColor Cyan
  $html = $postResp.Content

  $matched = @()
  foreach ($indicator in $TriggerIndicators) {
    if ($html -match [regex]::Escape($indicator)) { $matched += $indicator }
  }

  if ($matched.Count -gt 0) {
    Write-Host "Possible trigger/block indicators found in response: $($matched -join ', ')" -ForegroundColor Yellow
  } else {
    Write-Host "No trigger indicators found using the current keyword list." -ForegroundColor Green
  }

  # Save response for review
  $outFile = Join-Path $PWD "dlptest_response.html"
  Set-Content -Path $outFile -Value $html -Encoding UTF8
  Write-Host "Saved response HTML to: $outFile" -ForegroundColor Gray

} catch {
  Write-Host "Request failed: $($_.Exception.Message)" -ForegroundColor Red
  if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
    Write-Host ("HTTP StatusCode: {0}" -f $_.Exception.Response.StatusCode) -ForegroundColor Red
  }
  exit 2
}
