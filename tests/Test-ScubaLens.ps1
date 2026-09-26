<#
    ScubaLens AI - safety and correctness tests
    Runs offline with PowerShell 7+. No Microsoft 365 tenant, cloud account or extra modules needed.

    Usage (from the repository root):
        pwsh ./tests/Test-ScubaLens.ps1

    Exit code 0 = all tests passed, 1 = at least one failure.
#>

$ErrorActionPreference = 'Stop'
$root        = Split-Path -Parent $PSScriptRoot
$scriptsDir  = Join-Path $root 'scripts'
$fixDir      = Join-Path $scriptsDir 'remediation'
$maskScript  = Join-Path $scriptsDir 'Invoke-ScubaLensMask.ps1'
$sampleInput = Join-Path $root 'samples/sample_scubagear_results.json'

$script:passed = 0
$script:failed = 0

function Test-Case {
    param([string]$Name, [scriptblock]$Body)
    try {
        $result = & $Body
        if ($result -eq $true) {
            $script:passed++
            Write-Host "  [PASS] $Name" -ForegroundColor Green
        } else {
            $script:failed++
            Write-Host "  [FAIL] $Name" -ForegroundColor Red
        }
    } catch {
        $script:failed++
        Write-Host "  [FAIL] $Name - $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ---------------------------------------------------------------
Write-Host "`n1. Every PowerShell script parses without syntax errors" -ForegroundColor Cyan
foreach ($file in Get-ChildItem -Path $scriptsDir -Filter *.ps1 -Recurse) {
    Test-Case "$($file.Name) has valid syntax" {
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$errors) | Out-Null
        $errors.Count -eq 0
    }
}

# ---------------------------------------------------------------
Write-Host "`n2. Conditional Access fixes are safe by default" -ForegroundColor Cyan
$caFixes = Get-ChildItem -Path $fixDir -Filter *.ps1 | Where-Object { (Get-Content $_.FullName -Raw) -match 'New-MgIdentityConditionalAccessPolicy' }
Test-Case "Found Conditional Access fix templates to check ($($caFixes.Count))" { $caFixes.Count -ge 1 }
foreach ($file in $caFixes) {
    $text = Get-Content -Path $file.FullName -Raw
    $name = $file.Name
    Test-Case "$name deploys in Report-Only mode" {
        $text -match 'state\s*=\s*"enabledForReportingButNotEnforced"'
    }
    Test-Case "$name never sets the policy to fully enforced" {
        -not ($text -match 'state\s*=\s*"enabled"')
    }
    Test-Case "$name requires break-glass accounts to be excluded" {
        ($text -match '\[Parameter\(Mandatory\s*=\s*\$true\)\]\s*\[string\[\]\]\$BreakGlassObjectIds') -and
        ($text -match 'excludeUsers\s*=\s*\$BreakGlassObjectIds')
    }
}

# ---------------------------------------------------------------
Write-Host "`n3. Tenant-setting fixes save a rollback file before changing anything" -ForegroundColor Cyan
$settingFixes = Get-ChildItem -Path $fixDir -Filter *.ps1 | Where-Object { (Get-Content $_.FullName -Raw) -match '(Set-SPOTenant|Update-Mg)' }
Test-Case "Found tenant-setting fix templates to check ($($settingFixes.Count))" { $settingFixes.Count -ge 1 }
foreach ($file in $settingFixes) {
    $lines = Get-Content -Path $file.FullName
    Test-Case "$($file.Name) writes its rollback file before the first change" {
        $rollbackLine = ($lines | Select-String -Pattern 'Out-File' | Select-Object -First 1).LineNumber
        $changeLine   = ($lines | Select-String -Pattern '^\s*(Set-SPOTenant|Update-Mg)' | Select-Object -First 1).LineNumber
        ($rollbackLine -gt 0) -and ($changeLine -gt 0) -and ($rollbackLine -lt $changeLine)
    }
}
$spo = Get-Content -Path (Join-Path $fixDir 'Fix_SharePointSharing.ps1')
Test-Case "SharePoint sharing is restricted to existing guests only" {
    ($spo -join "`n") -match 'Set-SPOTenant -SharingCapability ExistingExternalUserSharingOnly'
}

# ---------------------------------------------------------------
Write-Host "`n4. Pre-ingestion PII masking" -ForegroundColor Cyan
$tmp  = Join-Path ([System.IO.Path]::GetTempPath()) ("scubalens-test-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
$out1 = Join-Path $tmp 'masked1.json'
$out2 = Join-Path $tmp 'masked2.json'
$key  = [byte[]](1..32)   # test key only; production keys come from Azure Key Vault

& $maskScript -InputPath $sampleInput -OutputPath $out1 -HmacKey $key 6>$null
& $maskScript -InputPath $sampleInput -OutputPath $out2 -HmacKey $key 6>$null
$masked = Get-Content -Path $out1 -Raw

Test-Case "No email addresses remain" {
    -not ($masked -match '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
}
Test-Case "No tenant or object IDs (GUIDs) remain" {
    -not ($masked -match '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b')
}
Test-Case "No IPv4 addresses remain" {
    -not ($masked -match '\b(?:\d{1,3}\.){3}\d{1,3}\b')
}
Test-Case "No phone numbers remain" {
    -not ($masked -match '\(?\b\d{3}\)?[-. ]\d{3}[-. ]\d{4}\b')
}
Test-Case "SCuBA policy IDs are preserved (masking does not destroy findings)" {
    ($masked -match 'MS\.AAD\.3\.2v1') -and ($masked -match 'MS\.AAD\.1\.1v1') -and ($masked -match 'MS\.SHAREPOINT\.1\.1v1')
}
Test-Case "Output is still valid JSON" {
    $null = $masked | ConvertFrom-Json
    $true
}
Test-Case "Masking is deterministic (same input + key = identical output)" {
    (Get-FileHash $out1).Hash -eq (Get-FileHash $out2).Hash
}
Test-Case "Same identity gets the same token regardless of letter case" {
    $in  = Join-Path $tmp 'case.txt'
    $out = Join-Path $tmp 'case.masked.txt'
    Set-Content -Path $in -Value "jane.doe@agency.gov|JANE.DOE@agency.gov"
    & $maskScript -InputPath $in -OutputPath $out -HmacKey $key 6>$null
    $parts = (Get-Content -Path $out -Raw).Trim().Split('|')
    ($parts[0] -eq $parts[1]) -and ($parts[0] -like '`[EMAIL_*`]')
}
Test-Case "A different key produces different tokens" {
    $in  = Join-Path $tmp 'key.txt'
    $outA = Join-Path $tmp 'key.a.txt'
    $outB = Join-Path $tmp 'key.b.txt'
    Set-Content -Path $in -Value "jane.doe@agency.gov"
    & $maskScript -InputPath $in -OutputPath $outA -HmacKey $key 6>$null
    & $maskScript -InputPath $in -OutputPath $outB -HmacKey ([byte[]](32..63)) 6>$null
    (Get-Content $outA -Raw) -ne (Get-Content $outB -Raw)
}
Remove-Item -Path $tmp -Recurse -Force

# ---------------------------------------------------------------
Write-Host "`n5. Microsoft Foundry prompt contains no personal data" -ForegroundColor Cyan
$foundry = & (Join-Path $scriptsDir 'Invoke-ScubaLensFoundry.ps1') -InputPath $sampleInput -DryRun -Quiet
Test-Case "Dry run sends nothing" { -not $foundry.Sent }
Test-Case "Prompt has no emails, IPs or GUIDs" {
    -not ($foundry.Body -match '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b')
}
Test-Case "Prompt includes every failing SCuBA policy ID" {
    ($foundry.Body -match 'MS\.AAD\.3\.2v1') -and ($foundry.Body -match 'MS\.AAD\.1\.1v1') -and ($foundry.Body -match 'MS\.SHAREPOINT\.1\.1v1')
}
Test-Case "Prompt forbids compliance claims and code" {
    ($foundry.Body -match 'Never say the tenant or any listed control is compliant') -and ($foundry.Body -match 'Do not write code')
}

# ---------------------------------------------------------------
$total = $script:passed + $script:failed
Write-Host "`n$($script:passed) of $total tests passed." -ForegroundColor ($(if ($script:failed -eq 0) { 'Green' } else { 'Red' }))
if ($script:failed -gt 0) { exit 1 } else { exit 0 }
