<#
.SYNOPSIS
    Deletes one or more Entra ID security groups by display name.

.DESCRIPTION
    Connects to the tenant configured in the configuration section using certificate-based
    authentication and deletes the groups defined below. If a group is not found it is
    skipped without error.

.NOTES
    Author      : Melih Sivrikaya
    Permissions : Group.ReadWrite.All (application permission — grant admin consent)
    Auth        : Certificate-based (app registration: GroupCreator)
    Requires    : Microsoft.Graph PowerShell SDK
#>

# =====================
# Tenant configuration
# =====================
$TenantId              = "58288310-2b28-42b6-883b-dcef687a4e29"
$AppId                 = "0e5dca7e-c8c4-4e32-a584-7a17c1d8edb7"
$CertificateThumbprint = "DC9862E72F695A5F34D26689045F4F8EB6A3873C"

# =====================
# Group configuration
# =====================
$Groups = @(
    "AAD_SEC_ExampleGroup1"
    "AAD_SEC_ExampleGroup2"
)

# =====================
# Module check
# =====================
foreach ($module in @("Microsoft.Graph.Authentication", "Microsoft.Graph.Groups")) {
    try {
        Import-Module $module -ErrorAction Stop
    } catch {
        Write-Warning "Could not load '$module'. Ensure Microsoft.Graph is installed: Install-Module Microsoft.Graph -Scope CurrentUser"
        exit 1
    }
}

# =====================
# Connect
# =====================
Write-Host "=== Remove Security Groups ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
try {
    Connect-MgGraph -TenantId $TenantId -AppId $AppId -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
    Write-Host "Connected." -ForegroundColor Green
} catch {
    Write-Host "Failed to connect: $_" -ForegroundColor Red
    exit 1
}

# =====================
# Delete groups
# =====================
foreach ($groupName in $Groups) {
    Write-Host ""
    Write-Host "Processing: $groupName" -ForegroundColor Cyan

    $group = Get-MgGroup -Filter "displayName eq '$($groupName -replace "'","''")'" -ConsistencyLevel eventual -ErrorAction SilentlyContinue | Select-Object -First 1

    if (-not $group) {
        Write-Host "  Group not found. Skipping." -ForegroundColor DarkGray
        continue
    }

    try {
        Remove-MgGroup -GroupId $group.Id -ErrorAction Stop
        Write-Host "  Deleted (Id: $($group.Id))" -ForegroundColor Green
    } catch {
        Write-Host "  Failed to delete: $_" -ForegroundColor Red
    }
}

# =====================
# Disconnect
# =====================
try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch {}

Write-Host ""
Write-Host "Done!" -ForegroundColor Green
Write-Host ""
