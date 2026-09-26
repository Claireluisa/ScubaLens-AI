<#
    ScubaLens AI - Microsoft Foundry grounded explanation
    Sends MASKED ScubaGear findings to a model deployed in Microsoft Foundry
    (Azure OpenAI chat completions) and returns a plain-English, cited explanation.
    Every answer passes a deterministic groundedness check before it is shown.

    Works on Windows PowerShell 5.1 and PowerShell 7+.

    Configure (do NOT commit keys to GitHub):
        $env:AZURE_OPENAI_ENDPOINT   = "https://<resource>.openai.azure.com/"   (or .services.ai.azure.com)
        $env:AZURE_OPENAI_API_KEY    = "<key>"
        $env:AZURE_OPENAI_DEPLOYMENT = "gpt-4o-mini"

    Usage:
        .\scripts\Invoke-ScubaLensFoundry.ps1                 # calls Foundry
        .\scripts\Invoke-ScubaLensFoundry.ps1 -DryRun         # offline: shows exactly what would be sent
#>
param(
    [string]$InputPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'samples\sample_scubagear_results.json'),
    [switch]$DryRun,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
$maskScript = Join-Path $PSScriptRoot 'Invoke-ScubaLensMask.ps1'

function Say([string]$text, [string]$color = 'Gray') { if (-not $Quiet) { Write-Host $text -ForegroundColor $color } }

# 1. Mask personal data BEFORE anything leaves the machine
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('scubalens-foundry-' + [guid]::NewGuid() + '.json')
$key = [byte[]](1..32)   # demo key; production key comes from Azure Key Vault
& $maskScript -InputPath $InputPath -OutputPath $tmp -HmacKey $key 6>$null
$scan = Get-Content -Path $tmp -Raw | ConvertFrom-Json
Remove-Item $tmp -Force

$failed  = @($scan.Results | Where-Object { $_.Result -eq 'Fail' })
$allIds  = @($scan.Results | ForEach-Object { $_.PolicyId })
$failIds = @($failed | ForEach-Object { $_.PolicyId })

$facts = ($failed | ForEach-Object { "- $($_.PolicyId) [$($_.Product), $($_.Criticality)]: FAIL. $($_.Details)" }) -join "`n"

$system = @"
You are ScubaLens, a Microsoft 365 security assistant for a U.S. federal agency.
Rules:
1. Use ONLY the scan facts provided. Do not invent controls, numbers or settings.
2. Cite the SCuBA policy ID in square brackets for every factual sentence, e.g. [MS.AAD.3.2v1].
3. Every control listed is FAILING. Never say the tenant or any listed control is compliant or passing.
4. Tokens like [EMAIL_1A2B3C4D] are masked identities. Never try to guess who they are.
5. Do not write code. Fixes come only from pre-approved ScubaLens templates.
Answer in 3 short bullet points: the top risk, why it matters, and the first action.
"@

$user = "Latest ScubaGear results (personal data already masked):`n$facts`n`nExplain the risk to an agency CIO."

$messages = @(@{ role = 'system'; content = $system }, @{ role = 'user'; content = $user })
# Newer models (GPT-5 family, reasoning models) need max_completion_tokens and no temperature;
# older models get a fallback request below if the first one is rejected.
$body = @{ messages = $messages; max_completion_tokens = 2000 } | ConvertTo-Json -Depth 5
$legacyBody = @{ messages = $messages; max_tokens = 400; temperature = 0.2 } | ConvertTo-Json -Depth 5

# Safety check: nothing identifying may leave the machine
$leak = [regex]::Matches($body, '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b')
if ($leak.Count -gt 0) { throw "Blocked: personal data found in the prompt. Nothing was sent." }

Say "  Prompt sent to Microsoft Foundry (masked):" 'DarkGray'
$facts -split "`n" | ForEach-Object { Say "    $_" 'Green' }

if ($DryRun -or -not ($env:AZURE_OPENAI_ENDPOINT -and $env:AZURE_OPENAI_API_KEY -and $env:AZURE_OPENAI_DEPLOYMENT)) {
    Say ''
    Say '  Dry run: Foundry not configured, nothing was sent. Set AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_API_KEY and AZURE_OPENAI_DEPLOYMENT to call the model.' 'Yellow'
    return [pscustomobject]@{ Sent = $false; Body = $body; Answer = $null; Removed = @() }
}

# 2. Call the model deployed in Microsoft Foundry
$endpoint = $env:AZURE_OPENAI_ENDPOINT.Trim().TrimEnd('/')
$endpoint = $endpoint -replace '/openai.*$', '' -replace '/api/projects/.*$', ''
$uri = "$endpoint/openai/deployments/$($env:AZURE_OPENAI_DEPLOYMENT)/chat/completions?api-version=2025-01-01-preview"

Say ''
Say "  Calling Microsoft Foundry deployment '$($env:AZURE_OPENAI_DEPLOYMENT)'..." 'Cyan'
$v1uri = "$endpoint/openai/v1/chat/completions"
function Send-Foundry([string]$json, [string]$target) {
    Invoke-RestMethod -Method Post -Uri $target -Headers @{ 'api-key' = $env:AZURE_OPENAI_API_KEY } -ContentType 'application/json' -Body ([System.Text.Encoding]::UTF8.GetBytes($json)) -TimeoutSec 90
}
function With-Model([string]$json) { $o = $json | ConvertFrom-Json; $o | Add-Member -NotePropertyName model -NotePropertyValue $env:AZURE_OPENAI_DEPLOYMENT -Force; $o | ConvertTo-Json -Depth 6 }
function Get-Code($err) { try { [int]$err.Exception.Response.StatusCode } catch { $null } }
try {
    $resp = $null
    foreach ($attempt in @(@($body, $uri, $false), @($legacyBody, $uri, $false), @($body, $v1uri, $true), @($legacyBody, $v1uri, $true))) {
        $json = if ($attempt[2]) { With-Model $attempt[0] } else { $attempt[0] }
        try { $resp = Send-Foundry $json $attempt[1]; break }
        catch { $lastErr = $_; if (@(400, 404) -notcontains (Get-Code $_)) { throw } }
    }
    if (-not $resp) { throw $lastErr }
} catch {
    $code = $null
    try { $code = [int]$_.Exception.Response.StatusCode } catch { }
    $hint = switch ($code) {
        401 { 'Key rejected: check AZURE_OPENAI_API_KEY.' }
        400 { 'Request rejected by the model: check that the deployment is a chat model.' }
        404 { 'Deployment not found: check AZURE_OPENAI_DEPLOYMENT and the endpoint.' }
        429 { 'Quota or rate limit reached: wait a minute and retry.' }
        default { "Request failed: $($_.Exception.Message)" }
    }
    Say "  Foundry call failed. $hint" 'Red'
    return [pscustomobject]@{ Sent = $true; Body = $body; Answer = $null; Removed = @(); Error = $hint }
}
$answer = [string]$resp.choices[0].message.content

# 3. Deterministic groundedness check: remove unsupported claims
$kept = @(); $removed = @()
foreach ($line in ($answer -split "`r?`n")) {
    if (-not $line.Trim()) { continue }
    $cited   = @([regex]::Matches($line, 'MS\.[A-Z]+\.\d+\.\d+v\d+') | ForEach-Object { $_.Value })
    $unknown = @($cited | Where-Object { $allIds -notcontains $_ } | Select-Object -Unique)
    $falsePass = ($line -match '(?i)\b(is|are|now|fully)\s+(compliant|passing|secure)\b|\bpasses\b') -and (@($cited | Where-Object { $failIds -contains $_ }).Count -gt 0 -or $line -match '(?i)tenant')
    if ($unknown.Count -gt 0) { $removed += "Unknown control cited: $($unknown -join ', ')  |  $line" }
    elseif ($falsePass)      { $removed += "Contradicts scan (control is failing)  |  $line" }
    else { $kept += $line }
}

Say ''
Say '  Microsoft Foundry answer (verified against the scan):' 'Magenta'
$kept | ForEach-Object { Say "    $_" 'White' }
if ($removed.Count) {
    Say ''
    Say "  Groundedness check removed $($removed.Count) unsupported line(s):" 'Yellow'
    $removed | ForEach-Object { Say "    - $_" 'Yellow' }
} else {
    Say ''
    Say '  Groundedness check: every line cites a real, failing control. Nothing removed.' 'Green'
}
[pscustomobject]@{ Sent = $true; Body = $body; Answer = ($kept -join "`n"); Removed = $removed }
