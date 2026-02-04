$uri = "https://dlptest.com/http-post/"
$testData = @"
John Doe
SSN: 660-03-8360
Card: 4111 1111 1111 1111
"@

# Keep cookies/session like a browser
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession

# 1) GET the page (to capture cookies + hidden fields)
$get = Invoke-WebRequest -Uri $uri -WebSession $session -UseBasicParsing

$html = $get.Content

# 2) Try to find the textarea name used for the "Test Message" field
#    Fallback to "Test_Message" since the page labels it that way.
$textareaName = $null

# Look for a textarea element and grab its name=""
if ($html -match '(?is)<textarea[^>]*name="([^"]+)"[^>]*>') {
    $textareaName = $Matches[1]
}

if (-not $textareaName) {
    $textareaName = "Test_Message"
}

# 3) Collect hidden inputs in the first form on the page (often used by WP form plugins)
$body = @{}

# Grab hidden inputs: <input type="hidden" name="..." value="...">
$hiddenInputs = [regex]::Matches($html, '(?is)<input[^>]*type="hidden"[^>]*>')
foreach ($m in $hiddenInputs) {
    $tag = $m.Value
    $name = $null
    $value = ""

    if ($tag -match 'name="([^"]+)"') { $name = $Matches[1] }
    if ($tag -match 'value="([^"]*)"') { $value = $Matches[1] }

    if ($name) { $body[$name] = $value }
}

# Add the actual message field
$body[$textareaName] = $testData

# If there is a simple honeypot field ("If you are human, leave this field blank."), keep it blank.
# (If the site uses a different name, leaving it absent is typically fine.)
# $body["your_honeypot_field_name_here"] = ""

# 4) POST the form
$post = Invoke-WebRequest -Uri $uri -Method Post -WebSession $session -UseBasicParsing `
    -ContentType "application/x-www-form-urlencoded" -Body $body

# 5) Verify: HTTP status + quick indicator text
"HTTP Status: {0}" -f $post.StatusCode
"Response length: {0}" -f ($post.Content.Length)

# Optional: print a short snippet so you can confirm you landed on a results/response page
$post.Content.Substring(0, [Math]::Min(600, $post.Content.Length))
