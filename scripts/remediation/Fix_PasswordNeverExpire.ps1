<#  ScubaLens AI - One-Click Fix
    Control : MS.AAD.6.1v1 - User passwords SHALL NOT expire
    Safety  : Captures each domain's current setting to a rollback file before changing it.
    Requires: Microsoft.Graph PowerShell SDK, Domain.ReadWrite.All #>

Import-Module Microsoft.Graph.Identity.DirectoryManagement
Connect-MgGraph -Scopes "Domain.ReadWrite.All"

$domains = Get-MgDomain | Where-Object { $_.IsVerified }
$domains | ForEach-Object { "$($_.Id)=$($_.PasswordValidityPeriodInDays)" } | Out-File -FilePath ".\ScubaLens_AAD61_Rollback.txt"
Write-Host "Current password expiration settings saved for rollback."

foreach ($d in $domains) {
    # 2147483647 is the documented value for "passwords never expire"
    Update-MgDomain -DomainId $d.Id -PasswordValidityPeriodInDays 2147483647
    Write-Host "Password expiration disabled for $($d.Id)" -ForegroundColor Green
}
Write-Host "Re-run ScubaGear to verify MS.AAD.6.1v1 passes."
