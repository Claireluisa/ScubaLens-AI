<#
    ScubaLens AI - live terminal demo
    From ScubaGear finding to a tested, safety-gated fix package, in five steps.

    Runs offline on Windows PowerShell 5.1 or PowerShell 7+.
    No Microsoft 365 tenant, cloud account or extra modules needed.

    Usage (from the ScubaLens-AI folder):
        powershell -ExecutionPolicy Bypass -File .\demo.ps1          # runs straight through
        powershell -ExecutionPolicy Bypass -File .\demo.ps1 -Pause   # waits for Enter between steps (for presenting)
#>
param(
    [switch]$Pause
)

$ErrorActionPreference = 'Stop'
$root      = $PSScriptRoot
$scanPath  = Join-Path $root 'samples\sample_scubagear_results.json'
$maskPath  = Join-Path $root 'scripts\Invoke-ScubaLensMask.ps1'
$templates = Join-Path $root 'scripts\remediation'
$testPath  = Join-Path $root 'tests\Test-ScubaLens.ps1'
$outDir    = Join-Path $root 'out'

# Approved remediation templates: the only fixes ScubaLens is allowed to produce.
$templateMap = @{
    'MS.AAD.3.2v1'        = @{ File = 'Fix_EntraID_MFA.ps1';       Safety = 'Report-Only CA policy' }
    'MS.AAD.1.1v1'        = @{ File = 'Fix_LegacyAuth.ps1';        Safety = 'Report-Only CA policy' }
    'MS.SHAREPOINT.1.1v1' = @{ File = 'Fix_SharePointSharing.ps1'; Safety = 'Rollback file first' }
    'MS.AAD.3.1v1'        = @{ File = 'Fix_PhishResistantMFA_AllUsers.ps1';        Safety = 'Report-Only CA policy' }
    'MS.AAD.3.6v1'        = @{ File = 'Fix_PhishResistantMFA_PrivilegedRoles.ps1'; Safety = 'Report-Only CA policy' }
    'MS.AAD.5.1v1'        = @{ File = 'Fix_RestrictAppRegistration.ps1';           Safety = 'Rollback file first' }
    'MS.AAD.5.2v1'        = @{ File = 'Fix_RestrictUserConsent.ps1';               Safety = 'Rollback file first' }
    'MS.AAD.6.1v1'        = @{ File = 'Fix_PasswordNeverExpire.ps1';               Safety = 'Rollback file first' }
}

function Write-Step([int]$n, [string]$title) {
    Write-Host ''
    Write-Host ('=' * 72) -ForegroundColor DarkMagenta
    Write-Host (" STEP {0}  {1}" -f $n, $title) -ForegroundColor Magenta
    Write-Host ('=' * 72) -ForegroundColor DarkMagenta
}
function Wait-Step {
    if ($Pause) { Write-Host ''; Read-Host '  Press Enter to continue' | Out-Null }
}
function Get-ShortHash([string]$path) {
    (Get-FileHash -Path $path -Algorithm SHA256).Hash.Substring(0, 12)
}

Clear-Host
Write-Host ''
Write-Host '  ScubaLens AI' -ForegroundColor White -NoNewline
Write-Host '  |  From SCuBA finding to verified fix' -ForegroundColor DarkGray
Write-Host '  Offline demo on sample data. No tenant is changed.' -ForegroundColor DarkGray
Wait-Step

# ---------------------------------------------------------------------------
Write-Step 1 'Read the ScubaGear results'
$scan = Get-Content -Path $scanPath -Raw | ConvertFrom-Json
Write-Host ("  Tenant: {0}" -f $scan.MetaData.TenantDisplayName) -ForegroundColor Gray
Write-Host ''
Write-Host ('  {0,-22}{1,-12}{2,-10}{3}' -f 'POLICY', 'PRODUCT', 'RESULT', 'LEVEL') -ForegroundColor DarkGray
foreach ($r in $scan.Results) {
    $color = switch ($r.Result) { 'Fail' { 'Red' } 'Warning' { 'Yellow' } default { 'Green' } }
    Write-Host ('  {0,-22}{1,-12}' -f $r.PolicyId, $r.Product) -NoNewline
    Write-Host ('{0,-10}' -f $r.Result.ToUpper()) -ForegroundColor $color -NoNewline
    Write-Host $r.Criticality -ForegroundColor Gray
}
$failed = @($scan.Results | Where-Object { $_.Result -eq 'Fail' })
Write-Host ''
Write-Host ("  {0} required (SHALL) controls are failing." -f $failed.Count) -ForegroundColor Red
Wait-Step

# ---------------------------------------------------------------------------
Write-Step 2 'Mask personal data BEFORE anything reaches the AI'
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }
$maskedPath = Join-Path $outDir 'scan.masked.json'
$key = [byte[]](1..32)   # demo key only; production key is fetched from Azure Key Vault
& $maskPath -InputPath $scanPath -OutputPath $maskedPath -HmacKey $key 6>$null

$rawLine    = (Get-Content -Path $scanPath    | Select-String -Pattern 'Last policy change' | Select-Object -First 1).Line.Trim()
$maskedLine = (Get-Content -Path $maskedPath  | Select-String -Pattern 'Last policy change' | Select-Object -First 1).Line.Trim()
$rawText    = Get-Content -Path $scanPath -Raw
$maskedText = Get-Content -Path $maskedPath -Raw
$tokenCount = ([regex]::Matches($maskedText, '\[(EMAIL|GUID|IPV4|SSN|PHONE)_[0-9A-F]{8}\]')).Count

Write-Host '  BEFORE:' -ForegroundColor DarkGray
Write-Host "    $rawLine" -ForegroundColor Yellow
Write-Host '  AFTER (what the AI receives):' -ForegroundColor DarkGray
Write-Host "    $maskedLine" -ForegroundColor Green
Write-Host ''
Write-Host ("  {0} identifiers tokenized: emails, tenant ID, IP addresses, phone number." -f $tokenCount) -ForegroundColor Green
$leftover = [regex]::Matches($maskedText, '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}').Count
Write-Host ("  Email addresses left in AI input: {0}" -f $leftover) -ForegroundColor Green
Wait-Step

# ---------------------------------------------------------------------------
Write-Step 3 'Build the fix package from APPROVED templates only'
Write-Host '  The AI does not write free-form code. Each failure is matched to a' -ForegroundColor Gray
Write-Host '  pre-approved, tested template, and every file is fingerprinted.' -ForegroundColor Gray
Write-Host ''
$pkgDir = Join-Path $outDir 'fix-package'
if (Test-Path $pkgDir) { Remove-Item -Path $pkgDir -Recurse -Force }
New-Item -ItemType Directory -Path $pkgDir | Out-Null

$manifest = @()
Write-Host ('  {0,-22}{1,-28}{2,-24}{3}' -f 'POLICY', 'FIX SCRIPT', 'SAFETY', 'SHA-256') -ForegroundColor DarkGray
foreach ($f in $failed) {
    $t = $templateMap[$f.PolicyId]
    if ($null -eq $t) {
        Write-Host ('  {0,-22}' -f $f.PolicyId) -NoNewline
        Write-Host 'no approved template: routed to an engineer' -ForegroundColor Yellow
        continue
    }
    $dest = Join-Path $pkgDir $t.File
    Copy-Item -Path (Join-Path $templates $t.File) -Destination $dest
    $hash = Get-ShortHash $dest
    $manifest += [pscustomobject]@{ policyId = $f.PolicyId; script = $t.File; safety = $t.Safety; sha256 = (Get-FileHash $dest -Algorithm SHA256).Hash; status = 'Generated - awaiting human review' }
    Write-Host ('  {0,-22}{1,-28}{2,-24}' -f $f.PolicyId, $t.File, $t.Safety) -NoNewline
    Write-Host $hash -ForegroundColor Cyan
}
$manifest | ConvertTo-Json | Set-Content -Path (Join-Path $pkgDir 'manifest.json') -Encoding UTF8
Write-Host ''
Write-Host ("  Package written to: {0}" -f $pkgDir) -ForegroundColor Green
Write-Host '  Status: Generated. Nothing runs until an engineer approves it.' -ForegroundColor Green
Wait-Step

# ---------------------------------------------------------------------------
Write-Step 4 'Safety gate: test every approved template before release'
& $testPath
$gateOk = ($LASTEXITCODE -eq 0)
if ($gateOk) {
    Write-Host '  SAFETY GATE: PASSED. Package cleared for human review.' -ForegroundColor Green
} else {
    Write-Host '  SAFETY GATE: FAILED. Package blocked.' -ForegroundColor Red
}
Wait-Step

# ---------------------------------------------------------------------------
Write-Step 5 'Tamper test: what if a fix is changed to enforce immediately?'
$tamperRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('scubalens-tamper-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tamperRoot | Out-Null
foreach ($d in 'scripts', 'samples', 'tests') { Copy-Item -Path (Join-Path $root $d) -Destination $tamperRoot -Recurse }
$victim = Join-Path $tamperRoot 'scripts\remediation\Fix_LegacyAuth.ps1'
(Get-Content -Path $victim -Raw).Replace('enabledForReportingButNotEnforced', 'enabled') | Set-Content -Path $victim -Encoding UTF8
Write-Host '  Changed Fix_LegacyAuth.ps1:  state = "enabledForReportingButNotEnforced"  ->  "enabled"' -ForegroundColor Yellow
Write-Host '  (This would block legacy sign-ins for the whole tenant with no preview.)' -ForegroundColor DarkGray

$tamperOutput = & (Join-Path $tamperRoot 'tests\Test-ScubaLens.ps1') 6>&1 | ForEach-Object { "$_" }
$tamperBlocked = ($LASTEXITCODE -ne 0)
Write-Host ''
Write-Host '  Re-running the safety gate on the tampered package:' -ForegroundColor Gray
$tamperOutput | Where-Object { $_ -match '\[FAIL\]|tests passed' } | ForEach-Object { Write-Host $_ -ForegroundColor Red }
Remove-Item -Path $tamperRoot -Recurse -Force
Write-Host ''
if ($tamperBlocked) {
    Write-Host '  SAFETY GATE: FAILED (exit code 1). The unsafe fix never reaches an engineer.' -ForegroundColor Red
} else {
    Write-Host '  Unexpected: tampered package was not blocked.' -ForegroundColor Yellow
}
Wait-Step

# ---------------------------------------------------------------------------
Write-Host ''
Write-Host ('=' * 72) -ForegroundColor DarkMagenta
Write-Host ' SUMMARY' -ForegroundColor Magenta
Write-Host ('=' * 72) -ForegroundColor DarkMagenta
Write-Host ("  Failing SHALL controls found ........ {0}" -f $failed.Count)
Write-Host ("  Identifiers masked before AI ........ {0}" -f $tokenCount)
Write-Host ("  Fix scripts generated from templates  {0}" -f $manifest.Count)
Write-Host ("  Safety gate on real package ......... {0}" -f $(if ($gateOk) { 'PASSED' } else { 'FAILED' })) -ForegroundColor $(if ($gateOk) { 'Green' } else { 'Red' })
Write-Host ("  Tampered package blocked ............ {0}" -f $(if ($tamperBlocked) { 'YES' } else { 'NO' })) -ForegroundColor $(if ($tamperBlocked) { 'Green' } else { 'Red' })
Write-Host ''
Write-Host '  AI proposes. Identity authorizes. Humans approve. Enterprise controls execute.' -ForegroundColor White
Write-Host '  Next: open index.html to review, approve and export OSCAL evidence.' -ForegroundColor DarkGray
Write-Host ''
