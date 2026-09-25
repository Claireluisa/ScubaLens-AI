param(
    [Parameter(Mandatory)] [string]$InputPath,
    [Parameter(Mandatory)] [string]$OutputPath,
    [Parameter(Mandatory)] [byte[]]$HmacKey   # fetched from Azure Key Vault at runtime, never stored on disk
)
$hmac = [System.Security.Cryptography.HMACSHA256]::new($HmacKey)
$patterns = [ordered]@{
    EMAIL = '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
    GUID  = '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
    IPV4  = '\b(?:\d{1,3}\.){3}\d{1,3}\b'
    SSN   = '\b\d{3}-\d{2}-\d{4}\b'
    PHONE = '\(?\b\d{3}\)?[-. ]\d{3}[-. ]\d{4}\b'
}
$text  = Get-Content -Path $InputPath -Raw
$count = 0
foreach ($label in $patterns.Keys) {
    $count += [regex]::Matches($text, $patterns[$label]).Count
    $text = [regex]::Replace($text, $patterns[$label], {
        param($m)
        $bytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($m.Value.ToLowerInvariant()))
        '[{0}_{1}]' -f $label, ([BitConverter]::ToString($bytes, 0, 4) -replace '-', '')
    })
}
Set-Content -Path $OutputPath -Value $text -Encoding UTF8
Write-Host "Masked $count values -> $OutputPath"
