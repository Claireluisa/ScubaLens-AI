<#  ScubaLens AI - One-Click Fix
    Control : MS.AAD.5.1v1 - Only administrators SHALL be allowed to register applications
    Safety  : Captures current setting to a rollback file before changing it.
    Requires: Microsoft.Graph PowerShell SDK, Policy.ReadWrite.Authorization #>

Import-Module Microsoft.Graph.Identity.SignIns
Connect-MgGraph -Scopes "Policy.ReadWrite.Authorization"

$current = Get-MgPolicyAuthorizationPolicy
"AllowedToCreateApps=$($current.DefaultUserRolePermissions.AllowedToCreateApps)" | Out-File -FilePath ".\ScubaLens_AAD51_Rollback.txt"
Write-Host "Current setting saved for rollback."

Update-MgPolicyAuthorizationPolicy -AuthorizationPolicyId $current.Id -DefaultUserRolePermissions @{ AllowedToCreateApps = $false }

Write-Host "Non-admin users can no longer register applications." -ForegroundColor Green
Write-Host "Re-run ScubaGear to verify MS.AAD.5.1v1 passes."
