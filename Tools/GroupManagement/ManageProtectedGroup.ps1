<#
.SYNOPSIS
    Creates one or more Entra ID security groups with predefined members.

.DESCRIPTION
    Connects to the tenant configured in the configuration section using certificate-based
    authentication and creates the security groups defined below. For each group it checks
    if it already exists before creating, then adds any members by UPN or display name.

.NOTES
    Author      : Melih Sivrikaya
    Permissions : Group.ReadWrite.All, GroupMember.ReadWrite.All, User.Read.All,
                  RoleManagement.ReadWrite.Directory (application permissions — grant admin consent)
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
# RoleAssignable: $true requires RoleManagement.ReadWrite.Directory permission
$Groups = @(
    @{
        Name           = "AAD_SEC_ExampleGroup1"
        Description    = "Example group 1 description"
        RoleAssignable = $false
        Members        = @(
            "John Doe"
            "support@contoso.com"
        )
    }
    @{
        Name           = "AAD_SEC_ExampleGroup2"
        Description    = "Example group 2 description"
        RoleAssignable = $false
        Members        = @(
            "test@contoso.com"
        )
    }
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
Write-Host "=== Group Creator ===" -ForegroundColor Cyan
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
# Create groups
# =====================
foreach ($g in $Groups) {
    Write-Host ""
    Write-Host "Processing: $($g.Name)" -ForegroundColor Cyan

    # Check if group already exists
    $existing = Get-MgGroup -Filter "displayName eq '$($g.Name -replace "'","''")'" -ConsistencyLevel eventual -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($existing) {
        Write-Host "  Group already exists (Id: $($existing.Id)). Skipping creation." -ForegroundColor Yellow
        $group = $existing
    } else {
        try {
            $group = New-MgGroup `
                -DisplayName     $g.Name `
                -Description     $g.Description `
                -MailEnabled:    $false `
                -MailNickname    ("grp" + (-join ((65..90) + (97..122) | Get-Random -Count 8 | ForEach-Object { [char]$_ }))) `
                -SecurityEnabled:$true `
                -AdditionalProperties @{ isAssignableToRole = $g.RoleAssignable } `
                -ErrorAction Stop

            Write-Host "  Created (Id: $($group.Id))" -ForegroundColor Green
            Start-Sleep -Seconds 3
        } catch {
            Write-Host "  Failed to create group: $_" -ForegroundColor Red
            continue
        }
    }

    # Add members
    foreach ($identifier in $g.Members) {
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

        if ($isMember) {
            Write-Host "  '$identifier' already a member. Skipping." -ForegroundColor DarkGray
        } else {
            try {
                New-MgGroupMember -GroupId $group.Id -DirectoryObjectId $user.Id -ErrorAction Stop
                Write-Host "  Added '$identifier'" -ForegroundColor Green
            } catch {
                Write-Host "  Failed to add '$identifier': $_" -ForegroundColor Red
            }
        }
    }
}

# =====================
# Disconnect
# =====================
try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch {}

Write-Host ""
Write-Host "Done!" -ForegroundColor Green
Write-Host ""
