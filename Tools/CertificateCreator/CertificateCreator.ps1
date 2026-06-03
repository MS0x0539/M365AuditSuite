<#
.SYNOPSIS
    Creates a self-signed certificate and exports it as a .cer file.

.DESCRIPTION
    Interactively prompts for a certificate name (CN), validity period, and export path.
    Creates the certificate in the current user's personal certificate store and exports
    it as a .cer file. The thumbprint is displayed on completion, which can be used in
    app registrations or other scripts.

.NOTES
    Author  : Melih Sivrikaya
    Requires: Windows PowerShell 5.1 or later
#>
Write-Host "=== Certificate Creator ===" -ForegroundColor Cyan
Write-Host ""

# Certificate name
$certName = Read-Host "Certificate name (CN)"
if ([string]::IsNullOrWhiteSpace($certName)) {
    Write-Host "Certificate name cannot be empty." -ForegroundColor Red
    exit 1
}

# Validity period
$yearsInput = Read-Host "Validity period in years [default: 2]"
if ([string]::IsNullOrWhiteSpace($yearsInput)) {
    $years = 2
} elseif ($yearsInput -match '^\d+$' -and [int]$yearsInput -gt 0) {
    $years = [int]$yearsInput
} else {
    Write-Host "Invalid input. Using default of 2 years." -ForegroundColor Yellow
    $years = 2
}

# Export path — resolve best available default (OneDrive Desktop → Desktop → C:\Audit)
$defaultBase = $null
foreach ($candidate in @([Environment]::GetFolderPath('Desktop'), "$env:USERPROFILE\Desktop", "C:\Audit")) {
    if (-not $candidate) { continue }
    try {
        New-Item -ItemType Directory -Force -Path $candidate -ErrorAction Stop | Out-Null
        $defaultBase = $candidate
        break
    } catch { continue }
}
$defaultPath = if ($defaultBase) { Join-Path $defaultBase "$certName.cer" } else { "$certName.cer" }
$exportPath = Read-Host "Export path [default: $defaultPath]"
if ([string]::IsNullOrWhiteSpace($exportPath)) {
    $exportPath = $defaultPath
}

# Ensure export directory exists
$exportDir = Split-Path $exportPath -Parent
if (-not (Test-Path $exportDir)) {
    Write-Host "Directory '$exportDir' does not exist." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Creating certificate..." -ForegroundColor Cyan

$cert = New-SelfSignedCertificate `
    -Subject "CN=$certName" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -NotAfter (Get-Date).AddYears($years) `
    -KeySpec Signature `
    -KeyExportPolicy Exportable

Export-Certificate -Cert $cert -FilePath $exportPath | Out-Null

Write-Host ""
Write-Host "Certificate created successfully!" -ForegroundColor Green
Write-Host "  Name       : CN=$certName"
Write-Host "  Thumbprint : $($cert.Thumbprint)"
Write-Host "  Expires    : $($cert.NotAfter.ToString('yyyy-MM-dd'))"
Write-Host "  Exported to: $exportPath"
Write-Host ""
