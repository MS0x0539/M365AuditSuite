<#
.SYNOPSIS
    Removes all directly assigned active and eligible Entra ID roles from one or more users.

.DESCRIPTION
    Connects to the tenant configured in the configuration section using certificate-based
    authentication. For each user in the list it:
      1. Resolves the account by UPN (preferred) or display name
      2. Retrieves all direct active role assignments and removes them
      3. Retrieves all direct eligible (PIM) role assignments and removes them

    Only direct assignments are affected — roles inherited via group membership are
    not touched. After removal, role names are printed to the console for confirmation.

.NOTES
    Author      : Melih Sivrikaya
    Permissions : User.Read.All, RoleManagement.ReadWrite.Directory
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
# Target users
# =====================
# Use UPN (preferred) or display name
$TargetUsers = @(
    "j.doe@contoso.com"
)

# =====================
# Module check
# =====================
foreach ($module in @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Identity.Governance"
)) {
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
Write-Host "=== Remove Direct Role Assignments ===" -ForegroundColor Cyan
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
# Build role definition lookup (Id / TemplateId → DisplayName)
# =====================
Write-Host ""
Write-Host "Loading role definitions..." -ForegroundColor Cyan
$roleDefMap = @{}
Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction SilentlyContinue | ForEach-Object {
    $roleDefMap[$_.Id]         = $_.DisplayName
    $roleDefMap[$_.TemplateId] = $_.DisplayName
}

# =====================
# Process each user
# =====================
foreach ($identifier in $TargetUsers) {
    Write-Host ""
    Write-Host "========== Processing: $identifier ==========" -ForegroundColor Cyan

    # Resolve user — UPN first, then display name
    $safe = $identifier -replace "'", "''"
    $user = Get-MgUser -Filter "userPrincipalName eq '$safe'" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $user) {
        $user = Get-MgUser -Filter "displayName eq '$safe'" -ConsistencyLevel eventual -ErrorAction SilentlyContinue | Select-Object -First 1
    }

    if (-not $user) {
        Write-Host "  User '$identifier' not found. Skipping." -ForegroundColor Yellow
        continue
    }

    Write-Host "  Found: $($user.DisplayName) ($($user.UserPrincipalName))" -ForegroundColor Green

    # ── Active role assignments ───────────────────────────────────────────────
    Write-Host ""
    Write-Host "  Removing active role assignments..." -ForegroundColor Cyan

    $activeAssignments = Get-MgRoleManagementDirectoryRoleAssignment `
        -Filter "principalId eq '$($user.Id)'" -ErrorAction SilentlyContinue

    if (-not $activeAssignments) {
        Write-Host "    No active role assignments found." -ForegroundColor DarkGray
    } else {
        foreach ($assignment in $activeAssignments) {
            $roleName = if ($roleDefMap.ContainsKey($assignment.RoleDefinitionId)) {
                $roleDefMap[$assignment.RoleDefinitionId]
            } else {
                $assignment.RoleDefinitionId
            }
            try {
                Remove-MgRoleManagementDirectoryRoleAssignment `
                    -UnifiedRoleAssignmentId $assignment.Id -ErrorAction Stop
                Write-Host "    Removed active: $roleName" -ForegroundColor Green
            } catch {
                Write-Host "    Failed to remove active '$roleName': $_" -ForegroundColor Red
            }
        }
    }

    # ── Eligible (PIM) role assignments ──────────────────────────────────────
    Write-Host ""
    Write-Host "  Removing eligible role assignments..." -ForegroundColor Cyan

    $eligibleAssignments = Get-MgRoleManagementDirectoryRoleEligibilitySchedule `
        -Filter "principalId eq '$($user.Id)'" -ErrorAction SilentlyContinue

    if (-not $eligibleAssignments) {
        Write-Host "    No eligible role assignments found." -ForegroundColor DarkGray
    } else {
        foreach ($assignment in $eligibleAssignments) {
            $roleName = if ($roleDefMap.ContainsKey($assignment.RoleDefinitionId)) {
                $roleDefMap[$assignment.RoleDefinitionId]
            } else {
                $assignment.RoleDefinitionId
            }
            try {
                Remove-MgRoleManagementDirectoryRoleEligibilitySchedule `
                    -UnifiedRoleEligibilityScheduleId $assignment.Id -ErrorAction Stop
                Write-Host "    Removed eligible: $roleName" -ForegroundColor Green
            } catch {
                Write-Host "    Failed to remove eligible '$roleName': $_" -ForegroundColor Red
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
