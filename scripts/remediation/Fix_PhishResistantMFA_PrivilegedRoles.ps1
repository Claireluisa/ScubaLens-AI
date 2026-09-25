<#  ScubaLens AI - One-Click Fix
    Control : MS.AAD.3.6v1 - Phishing-resistant MFA SHALL be required for highly privileged roles
    Safety  : Policy is created in REPORT-ONLY mode. Review sign-in logs, then enable.
    Requires: Microsoft.Graph PowerShell SDK, Policy.ReadWrite.ConditionalAccess #>

param(
    [Parameter(Mandatory = $true)]
    [string[]]$BreakGlassObjectIds,

    # Directory role template IDs. Review against your agency's list of highly privileged roles.
    [string[]]$PrivilegedRoleTemplateIds = @(
        "62e90394-69f5-4237-9190-012177145e10",   # Global Administrator
        "e8611ab8-c189-46e8-94e1-60213ab1f814",   # Privileged Role Administrator
        "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",   # Privileged Authentication Administrator
        "fe930be7-5e62-47db-91af-98c3a49a38b1",   # User Administrator
        "29232cdf-9323-42fd-ade2-1d097af3e4de",   # Exchange Administrator
        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c"    # SharePoint Administrator
    )
)

Import-Module Microsoft.Graph.Identity.SignIns
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess","Policy.Read.All"

# Built-in authentication strength: "Phishing-resistant MFA"
$phishingResistant = "00000000-0000-0000-0000-000000000004"

$policy = @{
    displayName   = "ScubaLens - MS.AAD.3.6v1 - Phishing-resistant MFA for privileged roles"
    state         = "enabledForReportingButNotEnforced"
    conditions    = @{
        users          = @{ includeRoles = $PrivilegedRoleTemplateIds; excludeUsers = $BreakGlassObjectIds }
        applications   = @{ includeApplications = @("All") }
        clientAppTypes = @("all")
    }
    grantControls = @{ operator = "OR"; authenticationStrength = @{ id = $phishingResistant } }
}

$result = New-MgIdentityConditionalAccessPolicy -BodyParameter $policy
Write-Host "Created policy $($result.Id) in Report-Only mode." -ForegroundColor Green
Write-Host "Re-run ScubaGear after enabling to verify MS.AAD.3.6v1 passes."
