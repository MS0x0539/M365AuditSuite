<#
.SYNOPSIS
    Reads and exports the members of one or more Entra ID security groups.

.DESCRIPTION
    Connects to the tenant configured in the configuration section using certificate-based
    authentication and retrieves all user members from the groups defined below.
    Results are exported to a date-stamped CSV on the Desktop, and a summary is
    printed to the console. Groups not found are skipped with a warning.

.NOTES
    Author      : Melih Sivrikaya
    Permissions : Group.Read.All, GroupMember.Read.All, User.Read.All
                  (application permissions — grant admin consent)
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
foreach ($module in @("Microsoft.Graph.Authentication", "Microsoft.Graph.Groups", "Microsoft.Graph.Users")) {
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
Write-Host "=== Read Group Users ===" -ForegroundColor Cyan
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
# Read members
# =====================
$results = foreach ($groupName in $Groups) {
    Write-Host ""
    Write-Host "Processing: $groupName" -ForegroundColor Cyan

    $group = Get-MgGroup -Filter "displayName eq '$($groupName -replace "'","''")'" -ConsistencyLevel eventual -ErrorAction SilentlyContinue | Select-Object -First 1

    if (-not $group) {
        Write-Host "  Group not found. Skipping." -ForegroundColor Yellow
        continue
    }

    $members = Get-MgGroupMember -GroupId $group.Id -All -ErrorAction SilentlyContinue

    $userCount = 0
    foreach ($member in $members) {
        if ($member.AdditionalProperties.'@odata.type' -ne "#microsoft.graph.user") { continue }

        $user = Get-MgUser -UserId $member.Id -Property DisplayName, Mail, UserPrincipalName -ErrorAction SilentlyContinue
        if (-not $user) { continue }

        $userCount++
        [PSCustomObject]@{
            GroupName         = $groupName
            DisplayName       = $user.DisplayName
            UserPrincipalName = $user.UserPrincipalName
            Email             = if ($user.Mail) { $user.Mail } else { $user.UserPrincipalName }
        }
    }

    Write-Host "  $userCount user(s) found." -ForegroundColor Green
}

# =====================
# Export
# =====================
$outputFile = "$([Environment]::GetFolderPath('Desktop'))\GroupMembers_$(Get-Date -Format 'yyyy-MM-dd').csv"
$results | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8

# =====================
# Disconnect
# =====================
try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch {}

Write-Host ""
Write-Host "Summary: $($results.Count) total member(s) across $($Groups.Count) group(s)." -ForegroundColor Cyan
Write-Host "Exported to: $outputFile" -ForegroundColor Green
Write-Host ""
