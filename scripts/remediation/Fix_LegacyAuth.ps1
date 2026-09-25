<#  ScubaLens AI - One-Click Fix
    Control : MS.AAD.1.1v1 - Legacy authentication SHALL be blocked
    Safety  : Policy is created in REPORT-ONLY mode. Review sign-in logs, then enable.
    Requires: Microsoft.Graph PowerShell SDK, Policy.ReadWrite.ConditionalAccess #>

param(
    [Parameter(Mandatory = $true)]
    [string[]]$BreakGlassObjectIds
)

Import-Module Microsoft.Graph.Identity.SignIns
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess","Policy.Read.All"

$policy = @{
    displayName   = "ScubaLens - MS.AAD.1.1v1 - Block legacy authentication"
    state         = "enabledForReportingButNotEnforced"
    conditions    = @{
        users          = @{ includeUsers = @("All"); excludeUsers = $BreakGlassObjectIds }
        applications   = @{ includeApplications = @("All") }
        clientAppTypes = @("exchangeActiveSync","other")
    }
    grantControls = @{ operator = "OR"; builtInControls = @("block") }
}

$result = New-MgIdentityConditionalAccessPolicy -BodyParameter $policy
Write-Host "Created policy $($result.Id) in Report-Only mode." -ForegroundColor Green
