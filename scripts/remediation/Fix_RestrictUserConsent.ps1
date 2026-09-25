<#  ScubaLens AI - One-Click Fix
    Control : MS.AAD.5.2v1 - User consent to applications SHALL be restricted
    Safety  : Captures current setting to a rollback file before changing it.
    Requires: Microsoft.Graph PowerShell SDK, Policy.ReadWrite.Authorization #>

Import-Module Microsoft.Graph.Identity.SignIns
Connect-MgGraph -Scopes "Policy.ReadWrite.Authorization"

$current = Get-MgPolicyAuthorizationPolicy
$assigned = $current.DefaultUserRolePermissions.PermissionGrantPoliciesAssigned -join ","
"PermissionGrantPoliciesAssigned=$assigned" | Out-File -FilePath ".\ScubaLens_AAD52_Rollback.txt"
Write-Host "Current consent policies saved for rollback: $assigned"

# No permission grant policies = users cannot consent to apps; admins approve instead.
Update-MgPolicyAuthorizationPolicy -AuthorizationPolicyId $current.Id -DefaultUserRolePermissions @{ PermissionGrantPoliciesAssigned = @() }

Write-Host "User consent to applications is now restricted." -ForegroundColor Green
Write-Host "Re-run ScubaGear to verify MS.AAD.5.2v1 passes."
