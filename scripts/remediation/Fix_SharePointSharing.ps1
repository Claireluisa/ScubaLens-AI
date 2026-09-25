<#  ScubaLens AI - One-Click Fix
    Control : MS.SHAREPOINT.1.1v1 - Limit external sharing for SharePoint
    Safety  : Captures current setting to a rollback file before changing it.
    Requires: Microsoft.Online.SharePoint.PowerShell, SharePoint Administrator role #>

param(
    [Parameter(Mandatory = $true)]
    [string]$AdminUrl   # e.g. https://<tenant>-admin.sharepoint.com
)

Import-Module Microsoft.Online.SharePoint.PowerShell
Connect-SPOService -Url $AdminUrl

$before = (Get-SPOTenant).SharingCapability
"SharingCapability=$before" | Out-File -FilePath ".\ScubaLens_SPO_Rollback.txt"
Write-Host "Current setting: $before (saved for rollback)"

Set-SPOTenant -SharingCapability ExistingExternalUserSharingOnly

$after = (Get-SPOTenant).SharingCapability
Write-Host "New setting: $after" -ForegroundColor Green
Write-Host "Re-run ScubaGear to verify MS.SHAREPOINT.1.1v1 passes."
