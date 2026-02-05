param(
  [string]$OutputRoot = (Join-Path $env:USERPROFILE "DlpRuleTests"),
  [int]$TimeoutSec = 30,
  [int]$PauseMs = 250,
  [switch]$StorePayloadInEvidence
)

$TestPayloads = @(
  [pscustomobject]@{ Name = "Example_SSN"; Data = "111-22-3333" }
  # Add more:
  #,[pscustomobject]@{ Name = "Example_CCN"; Data = "4111 1111 1111 1111" }
)

$Targets = @(
  [pscustomobject]@{ Protocol = "HTTP";  PageUrl = "http://dlptest.com/http-post/" }
  [pscustomobject]@{ Protocol = "HTTPS"; PageUrl = "https://dlptest.com/https-post/" }
)

try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}

function New-SafeFileName([string]$Name) {
  if ([string]::IsNullOrWhiteSpace($Name)) { return "unnamed" }
  return ($Name -replace '[\\/:*?"<>|]', '_')
}

function Get-Sha256Hex([string]$Text) {
  if ($null -eq $Text) { $Text = "" }
  $sha = [System.Security.Cryptography.SHA256]::Create()
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
  (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join "")
}

function Get-HtmlAttr([string]$Tag, [string]$Attr) {
  if ([string]::IsNullOrWhiteSpace($Tag) -or [string]::IsNullOrWhiteSpace($Attr)) { return $null }
  $a = [regex]::Escape($Attr)

  $m = [regex]::Match($Tag, "(?is)\b$a\s*=\s*(['""])(.*?)\1")
  if ($m.Success) { return $m.Groups[2].Value }

  $m = [regex]::Match($Tag, "(?is)\b$a\s*=\s*([^\s>]+)")
  if ($m.Success) { return $m.Groups[1].Value.Trim("'`"") }

  return $null
}

function Resolve-Url([string]$BaseUrl, [string]$MaybeRelative) {
  if ([string]::IsNullOrWhiteSpace($MaybeRelative) -or $MaybeRelative -eq "#") { return $BaseUrl }
  try {
    $u = [Uri]$MaybeRelative
    if ($u.IsAbsoluteUri) { return $u.AbsoluteUri }
  } catch {}
  return (New-Object Uri ([Uri]$BaseUrl), $MaybeRelative).AbsoluteUri
}

function Get-DlpTestFormInfo {
  param(
    [Parameter(Mandatory=$true)][string]$Html,
    [Parameter(Mandatory=$true)][string]$PageUrl
  )

  $forms = [regex]::Matches($Html, '(?is)<form\b[^>]*>.*?</form>')
  if ($forms.Count -lt 1) { throw "No <form> blocks found in HTML." }

  $chosen = $null
  foreach ($f in $forms) {
    if ($f.Value -match '(?is)Test\s*Message|Text\s*Message|Test_Message') { $chosen = $f.Value; break }
  }
  if (-not $chosen) { $chosen = $forms[0].Value }

  $formTag = [regex]::Match($chosen, '(?is)<form\b[^>]*>')
  if (-not $formTag.Success) { throw "Could not parse <form> tag." }

  $action = Get-HtmlAttr $formTag.Value 'action'
  $method = Get-HtmlAttr $formTag.Value 'method'
  $enctype = Get-HtmlAttr $formTag.Value 'enctype'
  if ([string]::IsNullOrWhiteSpace($method)) { $method = 'post' }

  $actionUrl = Resolve-Url $PageUrl $action

  $inputs = @()
  foreach ($m in [regex]::Matches($chosen, '(?is)<input\b[^>]*>')) { $inputs += $m.Value }

  $textareas = @()
  foreach ($m in [regex]::Matches($chosen, '(?is)<textarea\b[^>]*>.*?</textarea>')) { $textareas += $m.Value }

  $fields = [ordered]@{}
  $submitName = $null
  $submitValue = $null

  foreach ($tag in $inputs) {
    $name = Get-HtmlAttr $tag 'name'
    if ([string]::IsNullOrWhiteSpace($name)) { continue }

    $type = Get-HtmlAttr $tag 'type'
    if ([string]::IsNullOrWhiteSpace($type)) { $type = 'text' }
    $type = $type.ToLowerInvariant()

    $value = Get-HtmlAttr $tag 'value'
    if ($null -eq $value) { $value = "" }

    if ($type -eq 'hidden') {
      $fields[$name] = $value
      continue
    }

    if ($type -eq 'submit' -and -not $submitName) {
      $submitName = $name
      $submitValue = $value
    }
  }

  if ($submitName) {
    if ([string]::IsNullOrWhiteSpace($submitValue)) { $submitValue = "Submit" }
    $fields[$submitName] = $submitValue
  }

  $msgName = $null
  foreach ($t in $textareas) {
    $n = Get-HtmlAttr $t 'name'
    if ([string]::IsNullOrWhiteSpace($n)) { continue }
    if ($n -match '(?i)honey|honeypot|captcha|hp') { continue }
    $msgName = $n
    break
  }

  if (-not $msgName) {
    foreach ($tag in $inputs) {
      $n = Get-HtmlAttr $tag 'name'
      if ([string]::IsNullOrWhiteSpace($n)) { continue }
      if ($n -match '(?i)honey|honeypot|captcha|hp') { continue }
      $t = Get-HtmlAttr $tag 'type'
      if ([string]::IsNullOrWhiteSpace($t)) { $t = 'text' }
      $t = $t.ToLowerInvariant()
      if ($t -in @('text','search','email','tel','url')) { $msgName = $n; break }
    }
  }

  if (-not $msgName) { throw "Could not identify a message input/textarea field name." }

  [pscustomobject]@{
    ActionUrl = $actionUrl
    Method = $method.ToUpperInvariant()
    Enctype = $enctype
    HiddenAndSubmitFields = $fields
    MessageFieldName = $msgName
  }
}

function Invoke-DlpPostTest {
  param(
    [Parameter(Mandatory=$true)][string]$PageUrl,
    [Parameter(Mandatory=$true)][string]$Protocol,
    [Parameter(Mandatory=$true)][string]$PayloadName,
    [Parameter(Mandatory=$true)][string]$PayloadText,
    [Parameter(Mandatory=$true)][string]$RunDir,
    [int]$TimeoutSec = 30,
    [switch]$StorePayloadInEvidence
  )

  $safePayloadName = New-SafeFileName $PayloadName
  $testId = "$(Get-Date -Format 'yyyyMMdd_HHmmssfff')_${Protocol}_${safePayloadName}"

  $requestFile  = Join-Path $RunDir "request_$testId.json"
  $responseFile = Join-Path $RunDir "response_$testId.html"
  $metaFile     = Join-Path $RunDir "meta_$testId.json"
  $errorFile    = Join-Path $RunDir "error_$testId.txt"
  $pageFile     = Join-Path $RunDir "page_$testId.html"

  $sw = [System.Diagnostics.Stopwatch]::StartNew()

  $result = [ordered]@{
    Timestamp = (Get-Date).ToString("o")
    Computer  = $env:COMPUTERNAME
    User      = $env:USERNAME
    Protocol  = $Protocol
    PageUrl   = $PageUrl
    PayloadName   = $PayloadName
    PayloadLength = ($PayloadText | Measure-Object -Character).Characters
    PayloadSha256 = Get-Sha256Hex $PayloadText

    Outcome   = $null
    Success   = $false

    StatusCode = $null
    FinalUri   = $null
    DurationMs = $null
    ObservedPayloadInResponse = $false

    EvidencePageFile    = $pageFile
    EvidenceRequestFile = $requestFile
    EvidenceResponseFile= $responseFile
    EvidenceMetaFile    = $metaFile
    EvidenceErrorFile   = $errorFile
  }

  $handler = $null
  $client = $null

  try {
    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.AllowAutoRedirect = $true
    $handler.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate
    $handler.UseCookies = $true
    $handler.CookieContainer = New-Object System.Net.CookieContainer
    $handler.UseProxy = $true
    $handler.Proxy = [System.Net.WebRequest]::DefaultWebProxy
    if ($handler.Proxy) { $handler.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials }
    try { $handler.DefaultProxyCredentials = [System.Net.CredentialCache]::DefaultCredentials } catch {}
    try { $handler.UseDefaultCredentials = $true } catch {}

    $client = New-Object System.Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSec)
    $client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT; PowerShell DLPTest)")
    $client.DefaultRequestHeaders.Accept.ParseAdd("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

    $getResp = $client.GetAsync($PageUrl).GetAwaiter().GetResult()
    $html = $getResp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    $html | Out-File -FilePath $pageFile -Encoding utf8

    $form = Get-DlpTestFormInfo -Html $html -PageUrl $PageUrl

    $fields = [ordered]@{}
    foreach ($k in $form.HiddenAndSubmitFields.Keys) { $fields[$k] = $form.HiddenAndSubmitFields[$k] }
    $fields[$form.MessageFieldName] = $PayloadText

    $reqObj = [ordered]@{
      PageUrl = $PageUrl
      ActionUrl = $form.ActionUrl
      Method = "POST"
      Enctype = $form.Enctype
      MessageFieldName = $form.MessageFieldName
      Fields = @{}
    }

    if ($StorePayloadInEvidence) {
      $reqObj.Fields = $fields
    } else {
      foreach ($k in $fields.Keys) {
        if ($k -eq $form.MessageFieldName) {
          $reqObj.Fields[$k] = "[REDACTED] sha256=$($result.PayloadSha256) len=$($result.PayloadLength)"
        } else {
          $reqObj.Fields[$k] = $fields[$k]
        }
      }
    }

    ($reqObj | ConvertTo-Json -Depth 10) | Out-File -FilePath $requestFile -Encoding utf8

    $content = $null
    if ($form.Enctype -and $form.Enctype -match '(?i)multipart/form-data') {
      $multi = New-Object System.Net.Http.MultipartFormDataContent
      foreach ($k in $fields.Keys) {
        $v = $fields[$k]; if ($null -eq $v) { $v = "" }
        $multi.Add((New-Object System.Net.Http.StringContent([string]$v)), $k)
      }
      $content = $multi
    } else {
      $pairs = New-Object 'System.Collections.Generic.List[System.Collections.Generic.KeyValuePair[string,string]]'
      foreach ($k in $fields.Keys) {
        $v = $fields[$k]; if ($null -eq $v) { $v = "" }
        $pairs.Add((New-Object 'System.Collections.Generic.KeyValuePair[string,string]' ($k, [string]$v)))
      }
      $content = New-Object System.Net.Http.FormUrlEncodedContent($pairs)
    }

    $postResp = $client.PostAsync($form.ActionUrl, $content).GetAwaiter().GetResult()
    $body = $postResp.Content.ReadAsStringAsync().GetAwaiter().GetResult()

    $sw.Stop()
    $result.DurationMs = $sw.ElapsedMilliseconds
    $result.StatusCode = [int]$postResp.StatusCode
    $result.FinalUri   = $postResp.RequestMessage.RequestUri.AbsoluteUri

    $body | Out-File -FilePath $responseFile -Encoding utf8

    try {
      if ($PayloadText -and $body -and $body.IndexOf($PayloadText, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        $result.ObservedPayloadInResponse = $true
      }
    } catch {}

    $meta = [ordered]@{
      StatusCode = $result.StatusCode
      FinalUri   = $result.FinalUri
      ResponseHeaders = @{}
    }
    foreach ($h in $postResp.Headers.GetEnumerator()) { $meta.ResponseHeaders[$h.Key] = ($h.Value -join '; ') }
    foreach ($h in $postResp.Content.Headers.GetEnumerator()) { $meta.ResponseHeaders[$h.Key] = ($h.Value -join '; ') }
    ($meta | ConvertTo-Json -Depth 10) | Out-File -FilePath $metaFile -Encoding utf8

    $host = ""
    try { $host = ([Uri]$result.FinalUri).Host.ToLowerInvariant() } catch {}

    $blockPatterns = @(
      "blocked","access denied","forbidden","security policy","policy violation","data loss","dlp",
      "web filter","this request was blocked","category blocked","denied"
    )

    $looksBlocked = $false
    foreach ($p in $blockPatterns) {
      if ($body -and $body.IndexOf($p, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { $looksBlocked = $true; break }
    }

    if ($result.StatusCode -ge 200 -and $result.StatusCode -lt 400 -and $host -like "*.dlptest.com" -and -not $looksBlocked) {
      $result.Success = $true
      $result.Outcome = "Allowed"
    } elseif ($looksBlocked -or ($result.StatusCode -in 401,403,407,451)) {
      $result.Success = $false
      $result.Outcome = "BlockedOrDenied"
    } else {
      $result.Success = $false
      $result.Outcome = "FailedOrUnknown"
    }
  }
  catch {
    $sw.Stop()
    $result.DurationMs = $sw.ElapsedMilliseconds
    $result.Success = $false
    $result.Outcome = "Failed"
    ($_ | Out-String) | Out-File -FilePath $errorFile -Encoding utf8
  }
  finally {
    if ($client) { $client.Dispose() }
    if ($handler) { $handler.Dispose() }
  }

  return [pscustomobject]$result
}

$runId = "Run_{0}" -f (Get-Date -Format "yyyyMMdd_HHmmss")
$runDir = Join-Path $OutputRoot $runId
New-Item -ItemType Directory -Path $runDir -Force | Out-Null

$runMeta = [ordered]@{
  RunId = $runId
  Started = (Get-Date).ToString("o")
  OutputDir = $runDir
  Computer = $env:COMPUTERNAME
  User = $env:USERNAME
  PSVersion = ($PSVersionTable.PSVersion.ToString())
  Targets = $Targets
  PayloadCount = $TestPayloads.Count
  StorePayloadInEvidence = [bool]$StorePayloadInEvidence
}
($runMeta | ConvertTo-Json -Depth 10) | Out-File -FilePath (Join-Path $runDir "run.json") -Encoding utf8

$results = New-Object System.Collections.Generic.List[object]

foreach ($p in $TestPayloads) {
  foreach ($t in $Targets) {
    $results.Add((Invoke-DlpPostTest -PageUrl $t.PageUrl -Protocol $t.Protocol -PayloadName $p.Name -PayloadText $p.Data -RunDir $runDir -TimeoutSec $TimeoutSec -StorePayloadInEvidence:$StorePayloadInEvidence)) | Out-Null
    if ($PauseMs -gt 0) { Start-Sleep -Milliseconds $PauseMs }
  }
}

$csvPath = Join-Path $runDir "results.csv"
$results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

$results | Sort-Object Timestamp | Format-Table Timestamp,Protocol,PayloadName,Outcome,StatusCode,DurationMs -AutoSize
"`nResults CSV: $csvPath`nEvidence folder: $runDir`n" | Write-Host
