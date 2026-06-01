<#
.SYNOPSIS
    Removes hardcoded users from a role-assignable Entra ID security group.

.DESCRIPTION
    Connects to the tenant configured in the configuration section using certificate-based
    authentication and removes the specified users from the specified group. The group
    is not deleted. Users can be identified by UPN or display name. Users not found or
    not a member are skipped with a warning. Intended for role-assignable groups that
    have Entra ID roles assigned to them.

.NOTES
    Author      : Melih Sivrikaya
    Permissions : Group.ReadWrite.All, GroupMember.ReadWrite.All, User.Read.All
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
$GroupName = "AAD_SEC_ExampleGroup1"

$UsersToRemove = @(
    "user1@contoso.com"
    "John Doe"
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
Write-Host "=== Remove Users From Protected Group ===" -ForegroundColor Cyan
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
# Remove users
# =====================
Write-Host ""
Write-Host "Processing group: $GroupName" -ForegroundColor Cyan

$group = Get-MgGroup -Filter "displayName eq '$($GroupName -replace "'","''")'" -ConsistencyLevel eventual -ErrorAction SilentlyContinue | Select-Object -First 1

if (-not $group) {
    Write-Host "Group '$GroupName' not found." -ForegroundColor Red
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch {}
    exit 1
}

Write-Host "Group found (Id: $($group.Id))"

foreach ($identifier in $UsersToRemove) {
        $safe = $identifier -replace "'", "''"
        $user = Get-MgUser -Filter "userPrincipalName eq '$safe'" -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $user) {
            $user = Get-MgUser -Filter "displayName eq '$safe'" -ConsistencyLevel eventual -ErrorAction SilentlyContinue | Select-Object -First 1
        }

        if (-not $user) {
            Write-Host "  User '$identifier' not found. Skipping." -ForegroundColor Yellow
            continue
        }

        $isMember = Get-MgGroupMember -GroupId $group.Id -All -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq $user.Id }

        if (-not $isMember) {
            Write-Host "  '$identifier' is not a member. Skipping." -ForegroundColor DarkGray
            continue
        }

        try {
            Remove-MgGroupMemberByRef -GroupId $group.Id -DirectoryObjectId $user.Id -ErrorAction Stop
            Write-Host "  Removed '$identifier'" -ForegroundColor Green
        } catch {
            Write-Host "  Failed to remove '$identifier': $_" -ForegroundColor Red
        }
    }

# =====================
# Disconnect
# =====================
try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch {}

Write-Host ""
Write-Host "Done!" -ForegroundColor Green
Write-Host ""
