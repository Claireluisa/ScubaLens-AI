<#  ScubaLens AI - One-Click Fix
    Control : MS.AAD.3.2v1 - Enforce MFA for all users
    Safety  : Policy is created in REPORT-ONLY mode. Review sign-in logs, then enable.
    Requires: Microsoft.Graph PowerShell SDK, Policy.ReadWrite.ConditionalAccess #>

param(
    [Parameter(Mandatory = $true)]
    [string[]]$BreakGlassObjectIds   # Object IDs of emergency-access accounts to exclude
)

Import-Module Microsoft.Graph.Identity.SignIns
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess","Policy.Read.All"

$policy = @{
    displayName   = "ScubaLens - MS.AAD.3.2v1 - Require MFA for all users"
    state         = "enabledForReportingButNotEnforced"
    conditions    = @{
        users        = @{ includeUsers = @("All"); excludeUsers = $BreakGlassObjectIds }
        applications = @{ includeApplications = @("All") }
        clientAppTypes = @("all")
    }
    grantControls = @{ operator = "OR"; builtInControls = @("mfa") }
}

$result = New-MgIdentityConditionalAccessPolicy -BodyParameter $policy
Write-Host "Created policy $($result.Id) in Report-Only mode." -ForegroundColor Green
Write-Host "Re-run ScubaGear after enabling to verify MS.AAD.3.2v1 passes."
