<#
.SYNOPSIS
    Removes an admin account from all groups and then deletes it.

.DESCRIPTION
    Connects to the tenant configured in the configuration section using certificate-based
    authentication. For each user in the list it:
      1. Removes the user from all non-dynamic groups
      2. Deletes the user account
    Step 1 ensures any PIM group-based eligibility or active activations are
    cleaned up before deletion, preventing orphaned role assignments.

.NOTES
    Author      : Melih Sivrikaya
    Permissions : User.ReadWrite.All, Group.ReadWrite.All, GroupMember.ReadWrite.All,
                  RoleManagement.ReadWrite.Directory
                  (application permissions — grant admin consent)
    Auth        : Certificate-based (app registration: AccountManagement)
    Requires    : Microsoft.Graph PowerShell SDK
#>

# =====================
# Tenant configuration
# =====================
$TenantId              = "58288310-2b28-42b6-883b-dcef687a4e29"
$AppId                 = "458e6a44-9f42-43fd-aea7-e5dacde156c8"
$CertificateThumbprint = "692D02E8823BDDAC78EFAD7ADB8EE49EC09EE54C"

# =====================
# Users to delete
# =====================
# Use UPN (preferred) or display name
$UsersToDelete = @(
    "admintest"
)

# =====================
# Module check
# =====================
foreach ($module in @("Microsoft.Graph.Authentication", "Microsoft.Graph.Users", "Microsoft.Graph.Groups", "Microsoft.Graph.Identity.Governance")) {
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
Write-Host "=== Delete Admin Account ===" -ForegroundColor Cyan
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
# Process users
# =====================
foreach ($identifier in $UsersToDelete) {
    Write-Host ""
    Write-Host "Processing: $identifier" -ForegroundColor Cyan

    # Resolve user — try UPN first, then display name
    $safe = $identifier -replace "'", "''"
    $user = Get-MgUser -Filter "userPrincipalName eq '$safe'" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $user) {
        $user = Get-MgUser -Filter "displayName eq '$safe'" -ConsistencyLevel eventual -ErrorAction SilentlyContinue | Select-Object -First 1
    }

    if (-not $user) {
        Write-Host "  User not found. Skipping." -ForegroundColor Yellow
        continue
    }

    Write-Host "  Found: $($user.DisplayName) (Id: $($user.Id))"

    # Step 1: Remove from all non-dynamic groups
    Write-Host "  Removing from groups..." -ForegroundColor Cyan
    $memberships = Get-MgUserMemberOf -UserId $user.Id -ErrorAction SilentlyContinue

    foreach ($membership in $memberships) {
        if ($membership.AdditionalProperties.'@odata.type' -ne "#microsoft.graph.group") { continue }

        $group = Get-MgGroup -GroupId $membership.Id -ErrorAction SilentlyContinue
        if (-not $group) { continue }

        if ($group.GroupTypes -contains "DynamicMembership") {
            Write-Host "    Skipping dynamic group: $($group.DisplayName)" -ForegroundColor DarkGray
            continue
        }

        try {
            Remove-MgGroupMemberByRef -GroupId $group.Id -DirectoryObjectId $user.Id -ErrorAction Stop
            Write-Host "    Removed from: $($group.DisplayName)" -ForegroundColor Green
        } catch {
            Write-Host "    Failed to remove from '$($group.DisplayName)': $_" -ForegroundColor Red
        }
    }

    # Step 2: Remove direct Entra ID role assignments
    Write-Host "  Removing direct role assignments..." -ForegroundColor Cyan
    $roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($user.Id)'" -ErrorAction SilentlyContinue

    foreach ($assignment in $roleAssignments) {
        try {
            Remove-MgRoleManagementDirectoryRoleAssignment -UnifiedRoleAssignmentId $assignment.Id -ErrorAction Stop
            Write-Host "    Removed role assignment: $($assignment.RoleDefinitionId)" -ForegroundColor Green
        } catch {
            Write-Host "    Failed to remove role assignment '$($assignment.RoleDefinitionId)': $_" -ForegroundColor Red
        }
    }

    if (-not $roleAssignments) {
        Write-Host "    No active role assignments found." -ForegroundColor DarkGray
    }

    # Step 3: Remove PIM eligible role assignments
    Write-Host "  Removing PIM eligible role assignments..." -ForegroundColor Cyan
    $eligibleAssignments = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter "principalId eq '$($user.Id)'" -ErrorAction SilentlyContinue

    if ($eligibleAssignments) {
        foreach ($eligible in $eligibleAssignments) {
            try {
                Remove-MgRoleManagementDirectoryRoleEligibilitySchedule -UnifiedRoleEligibilityScheduleId $eligible.Id -ErrorAction Stop
                Write-Host "    Removed eligible assignment: $($eligible.RoleDefinitionId)" -ForegroundColor Green
            } catch {
                Write-Host "    Failed to remove eligible assignment '$($eligible.RoleDefinitionId)': $_" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "    No eligible role assignments found." -ForegroundColor DarkGray
    }

    # Brief pause to allow role removal to propagate
    Write-Host "  Waiting 20 seconds for changes to propagate..." -ForegroundColor DarkGray
    Start-Sleep -Seconds 20

    # Step 4: Delete the user
    Write-Host "  Deleting user..." -ForegroundColor Cyan
    try {
        Remove-MgUser -UserId $user.Id -ErrorAction Stop
        Write-Host "  Deleted: $($user.DisplayName)" -ForegroundColor Green
    } catch {
        Write-Host "  Failed to delete user: $_" -ForegroundColor Red
    }
}

# =====================
# Disconnect
# =====================
try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch {}

Write-Host ""
Write-Host "Done!" -ForegroundColor Green
Write-Host ""
