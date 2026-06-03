<#
.SYNOPSIS
    Audits all Azure subscriptions and their RBAC assignments including PIM eligibility.

.DESCRIPTION
    Connects to Azure using the EasyPIM service principal and enumerates every
    subscription in the tenant. For each subscription collects:

    Active assignments     — all active role assignments at subscription scope plus
                            assignments inherited from the management group hierarchy.
                            With -Deep, also captures assignments at resource group
                            and resource level within each subscription.

    PIM eligible           — all PIM eligible role assignments at subscription scope
                            (including any inherited from the management group level).
                            With -Deep, also queries each resource group for eligible
                            assignments at that exact scope.

    AssignmentKind values:
        Active             — permanent or currently PIM-activated assignment
        Eligible (PIM)     — PIM eligible, not currently active

    EndDateTime:
        Permanent          — no expiry
        yyyy-MM-dd HH:mm   — time-limited assignment

    All principal types are included: users, groups, service principals, managed
    identities. Assignments are deduplicated across overlapping API calls.

    Results exported to Desktop\<OrgName>\AzureRBAC\AzureRBAC_<timestamp>.csv
    (UTF-8 with BOM for correct Excel rendering).

    ── PERFORMANCE ──────────────────────────────────────────────────────────────
    Default (no -Deep): one active-assignment call and one eligible call per sub —
    fast regardless of resource count.
    With -Deep: adds a full within-subscription active scan (all RG + resource scopes
    in one call) and one eligible call per resource group. Runtime scales with the
    number of resource groups. Large tenants may take several minutes.
    ────────────────────────────────────────────────────────────────────────────

    ── REQUIREMENTS ─────────────────────────────────────────────────────────────
    • EasyPIM service principal assigned Reader on the tenant root management group
      (Azure Portal → Management Groups → Tenant Root Group → Access control (IAM))
    • Az.Accounts and Az.Resources modules (auto-installed if missing)
    ────────────────────────────────────────────────────────────────────────────

.NOTES
    Author      : Melih Sivrikaya
    Permissions : Reader (Azure RBAC — assigned on tenant root management group)
    Auth        : Certificate-based (app registration: EasyPIM)
    Requires    : Az.Accounts, Az.Resources (installed automatically if missing)
#>

#Requires -Version 5.1

param (
    [switch] $Deep   # Also include resource group and resource level assignments
)

# =====================
# Tenant configuration
# =====================
$TenantId              = "58288310-2b28-42b6-883b-dcef687a4e29"
$TenantDisplayName     = "PSBV"
$AppId                 = "e3febffa-d27e-4193-936f-f3ca01b24af8"
$CertificateThumbprint = "6805FD0B9EBA398B82CB59CA87E67E2FD3075657"

# ===========================================================================
# SCRIPT INTERNALS — do not edit below this line
# ===========================================================================

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║       Azure Subscription RBAC Audit              ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

if ($Deep) {
    Write-Host "╔════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "║  DEEP MODE — resource groups + per-RG PIM eligibility  ║" -ForegroundColor Yellow
    Write-Host "║  Runtime scales with the number of resource groups.    ║" -ForegroundColor Yellow
    Write-Host "╚════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
    Write-Host ""
}

# ── Module check ─────────────────────────────────────────────────────────────
Write-Host "Checking modules..." -ForegroundColor Cyan
foreach ($module in @("Az.Accounts", "Az.Resources")) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Host "  Installing $module..." -ForegroundColor Yellow
        try {
            Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            Write-Host "  Installed: $module" -ForegroundColor Green
        } catch {
            Write-Host "  FATAL: Could not install '$module': $_" -ForegroundColor Red
            exit 1
        }
    }
    try {
        Import-Module $module -ErrorAction Stop
        Write-Host "  Loaded: $module" -ForegroundColor Green
    } catch {
        Write-Host "  FATAL: Could not load '$module': $_" -ForegroundColor Red
        exit 1
    }
}

# Check whether PIM eligible cmdlet is available (requires Az.Resources 5.3.0+)
$eligibleCmdletAvailable = $null -ne (Get-Command Get-AzRoleEligibilityScheduleInstance -ErrorAction SilentlyContinue)
if (-not $eligibleCmdletAvailable) {
    Write-Host "  WARN: Get-AzRoleEligibilityScheduleInstance not available — PIM eligible assignments will be skipped." -ForegroundColor Yellow
    Write-Host "        Update with: Update-Module Az.Resources" -ForegroundColor Yellow
}

# ── Connect ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "Connecting to Azure (service principal)..." -ForegroundColor Cyan
try {
    Connect-AzAccount `
        -ServicePrincipal `
        -TenantId              $TenantId `
        -ApplicationId         $AppId `
        -CertificateThumbprint $CertificateThumbprint `
        -ErrorAction Stop | Out-Null
    Write-Host "Connected — tenant: $TenantId ($TenantDisplayName)" -ForegroundColor Green
} catch {
    Write-Host "FATAL: Could not connect to Azure: $_" -ForegroundColor Red
    exit 1
}

# ── Output folder ─────────────────────────────────────────────────────────────
$timestamp    = Get-Date -Format "yyyyMMdd_HHmmss"
$exportFolder = Join-Path ([Environment]::GetFolderPath('Desktop')) (Join-Path $TenantDisplayName "AzureRBAC")
try {
    New-Item -ItemType Directory -Force -Path $exportFolder -ErrorAction Stop | Out-Null
} catch {
    $exportFolder = [Environment]::GetFolderPath('Desktop')
}
$csvFile = Join-Path $exportFolder ("AzureRBAC_{0}.csv" -f $timestamp)

# ── Helpers ───────────────────────────────────────────────────────────────────
$script:RoleDefCache   = @{}
$script:PrincipalCache = @{}

function Resolve-RoleName {
    param ([string] $RoleDefinitionId)
    $guid = $RoleDefinitionId.Split('/')[-1]
    if ($script:RoleDefCache.ContainsKey($guid)) { return $script:RoleDefCache[$guid] }
    try {
        $rd = Get-AzRoleDefinition -Id $guid -ErrorAction SilentlyContinue
        if ($rd) { $script:RoleDefCache[$guid] = $rd.Name; return $rd.Name }
    } catch {}
    return $guid
}

function Resolve-Principal {
    param ([string] $ObjectId, [string] $PrincipalType)
    if ($script:PrincipalCache.ContainsKey($ObjectId)) { return $script:PrincipalCache[$ObjectId] }

    $info = [PSCustomObject]@{ DisplayName = $ObjectId; SignInName = "N/A" }
    try {
        switch -Wildcard ($PrincipalType) {
            "User*" {
                $u = Get-AzADUser -ObjectId $ObjectId -ErrorAction SilentlyContinue
                if ($u) { $info = [PSCustomObject]@{
                    DisplayName = $u.DisplayName
                    SignInName  = if ($u.UserPrincipalName) { $u.UserPrincipalName } else { "N/A" }
                } }
            }
            "Group*" {
                $g = Get-AzADGroup -ObjectId $ObjectId -ErrorAction SilentlyContinue
                if ($g) { $info = [PSCustomObject]@{ DisplayName = $g.DisplayName; SignInName = "N/A" } }
            }
            default {
                $sp = Get-AzADServicePrincipal -ObjectId $ObjectId -ErrorAction SilentlyContinue
                if ($sp) { $info = [PSCustomObject]@{ DisplayName = $sp.DisplayName; SignInName = "N/A" } }
            }
        }
    } catch {}
    $script:PrincipalCache[$ObjectId] = $info
    return $info
}

function Get-ScopeType {
    param ([string] $Scope)
    switch -Regex ($Scope) {
        "^/providers/Microsoft\.Management/managementGroups/" { return "ManagementGroup" }
        "^/subscriptions/[^/]+$"                             { return "Subscription"    }
        "^/subscriptions/[^/]+/resourceGroups/[^/]+$"       { return "ResourceGroup"   }
        "^/subscriptions/.+/providers/"                      { return "Resource"        }
        "^/$"                                                { return "TenantRoot"      }
        default                                              { return "Other"           }
    }
}

function New-Row {
    param ($Sub, $Scope, $RoleName, $Kind, $PrincipalType, $DisplayName, $SignInName, $ObjectId, $EndDateTime)
    return [PSCustomObject]@{
        SubscriptionName   = $Sub.Name
        SubscriptionId     = $Sub.Id
        SubscriptionState  = $Sub.State
        Scope              = $Scope
        ScopeType          = Get-ScopeType $Scope
        RoleDefinitionName = $RoleName
        AssignmentKind     = $Kind
        PrincipalType      = $PrincipalType
        DisplayName        = $DisplayName
        SignInName         = $SignInName
        ObjectId           = $ObjectId
        EndDateTime        = $EndDateTime
    }
}

# ── Enumerate subscriptions ───────────────────────────────────────────────────
Write-Host ""
Write-Host "── Enumerating subscriptions ─────────────────────────" -ForegroundColor Cyan

try {
    $subscriptions = @(Get-AzSubscription -TenantId $TenantId -ErrorAction Stop | Sort-Object Name)
} catch {
    Write-Host "FATAL: Could not retrieve subscriptions: $_" -ForegroundColor Red
    try { Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null } catch {}
    exit 1
}

if ($subscriptions.Count -eq 0) {
    Write-Host "No subscriptions found — verify the Reader assignment on the root management group." -ForegroundColor Yellow
    try { Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null } catch {}
    exit 0
}

Write-Host "Found $($subscriptions.Count) subscription(s)." -ForegroundColor Green

# ── Main collection loop ──────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Collecting assignments ────────────────────────────" -ForegroundColor Cyan

$results = [System.Collections.Generic.List[PSCustomObject]]::new()
$errors  = [System.Collections.Generic.List[string]]::new()

for ($si = 0; $si -lt $subscriptions.Count; $si++) {
    $sub      = $subscriptions[$si]
    $progress = "[$($si + 1)/$($subscriptions.Count)]"
    Write-Host ""
    Write-Host ("  $progress {0}  [{1}]" -f $sub.Name, $sub.State) -ForegroundColor Cyan

    try {
        $null = Set-AzContext -SubscriptionId $sub.Id -TenantId $TenantId -ErrorAction Stop

        # Pre-populate role definition cache for this subscription (covers custom roles)
        $rdDefs = @(Get-AzRoleDefinition -Scope "/subscriptions/$($sub.Id)" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)
        foreach ($rd in $rdDefs) {
            $guid = $rd.Id.Split('/')[-1]
            if (-not $script:RoleDefCache.ContainsKey($guid)) { $script:RoleDefCache[$guid] = $rd.Name }
        }

        # ── Active: subscription scope + inherited from management group ──────
        $seenActiveKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $activeCount    = 0

        $subScopeActive = @(Get-AzRoleAssignment -Scope "/subscriptions/$($sub.Id)" -ErrorAction SilentlyContinue)
        foreach ($a in $subScopeActive) {
            $key = "$($a.ObjectId)|$($a.RoleDefinitionId)|$($a.Scope)"
            [void] $seenActiveKeys.Add($key)
            $results.Add((New-Row -Sub $sub -Scope $a.Scope -RoleName $a.RoleDefinitionName `
                -Kind "Active" -PrincipalType $a.ObjectType `
                -DisplayName $a.DisplayName `
                -SignInName  $(if ($a.SignInName) { $a.SignInName } else { "N/A" }) `
                -ObjectId    $a.ObjectId -EndDateTime "Permanent"))
            $activeCount++
        }

        # ── Active: resource group and resource level (Deep only) ─────────────
        $deepActiveCount = 0
        if ($Deep) {
            Write-Host "    Scanning all scopes within subscription..." -ForegroundColor DarkGray
            # Get-AzRoleAssignment without -Scope returns all within-subscription assignments
            # (subscription + resource group + resource). Deduplicated against the above.
            $allWithinSub = @(Get-AzRoleAssignment -ErrorAction SilentlyContinue)
            foreach ($a in $allWithinSub) {
                $key = "$($a.ObjectId)|$($a.RoleDefinitionId)|$($a.Scope)"
                if ($seenActiveKeys.Add($key)) {
                    $results.Add((New-Row -Sub $sub -Scope $a.Scope -RoleName $a.RoleDefinitionName `
                        -Kind "Active" -PrincipalType $a.ObjectType `
                        -DisplayName $a.DisplayName `
                        -SignInName  $(if ($a.SignInName) { $a.SignInName } else { "N/A" }) `
                        -ObjectId    $a.ObjectId -EndDateTime "Permanent"))
                    $deepActiveCount++
                }
            }
        }

        # ── PIM eligible: subscription scope (includes MG-inherited) ─────────
        $seenEligibleKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $eligibleCount    = 0

        if ($eligibleCmdletAvailable) {
            $eligibleSub = @(Get-AzRoleEligibilityScheduleInstance -Scope "/subscriptions/$($sub.Id)" -ErrorAction SilentlyContinue)
            foreach ($e in $eligibleSub) {
                $key = "$($e.PrincipalId)|$($e.RoleDefinitionId)|$($e.Scope)"
                [void] $seenEligibleKeys.Add($key)
                $roleName  = Resolve-RoleName  $e.RoleDefinitionId
                $principal = Resolve-Principal $e.PrincipalId $e.PrincipalType
                $endDt     = if ($e.EndDateTime) { $e.EndDateTime.ToString("yyyy-MM-dd HH:mm UTC") } else { "Permanent" }
                $results.Add((New-Row -Sub $sub -Scope $e.Scope -RoleName $roleName `
                    -Kind "Eligible (PIM)" -PrincipalType $e.PrincipalType `
                    -DisplayName $principal.DisplayName -SignInName $principal.SignInName `
                    -ObjectId    $e.PrincipalId -EndDateTime $endDt))
                $eligibleCount++
            }

            # ── PIM eligible: resource group scope (Deep only) ────────────────
            $deepEligibleCount = 0
            if ($Deep) {
                $rgs = @(Get-AzResourceGroup -ErrorAction SilentlyContinue)
                Write-Host "    Checking PIM eligible on $($rgs.Count) resource group(s)..." -ForegroundColor DarkGray

                $rgIdx = 0
                foreach ($rg in $rgs) {
                    $rgIdx++
                    if ($rgIdx % 10 -eq 0) {
                        Write-Host "      $rgIdx / $($rgs.Count) resource groups scanned" -ForegroundColor DarkGray
                    }
                    # Filter to exact RG scope — avoids re-capturing inherited assignments
                    $eligibleRG = @(Get-AzRoleEligibilityScheduleInstance -Scope $rg.ResourceId -ErrorAction SilentlyContinue) |
                        Where-Object { $_.Scope -eq $rg.ResourceId }
                    foreach ($e in $eligibleRG) {
                        $key = "$($e.PrincipalId)|$($e.RoleDefinitionId)|$($e.Scope)"
                        if ($seenEligibleKeys.Add($key)) {
                            $roleName  = Resolve-RoleName  $e.RoleDefinitionId
                            $principal = Resolve-Principal $e.PrincipalId $e.PrincipalType
                            $endDt     = if ($e.EndDateTime) { $e.EndDateTime.ToString("yyyy-MM-dd HH:mm UTC") } else { "Permanent" }
                            $results.Add((New-Row -Sub $sub -Scope $e.Scope -RoleName $roleName `
                                -Kind "Eligible (PIM)" -PrincipalType $e.PrincipalType `
                                -DisplayName $principal.DisplayName -SignInName $principal.SignInName `
                                -ObjectId    $e.PrincipalId -EndDateTime $endDt))
                            $deepEligibleCount++
                        }
                    }
                }
            }
        }

        # Per-subscription progress line
        $line = "    Active: $activeCount"
        if ($Deep) { $line += "  +$deepActiveCount RG/Resource" }
        $line += "  |  Eligible: $eligibleCount"
        if ($Deep -and $eligibleCmdletAvailable) { $line += "  +$deepEligibleCount RG" }
        Write-Host $line -ForegroundColor Green

    } catch {
        $errMsg = "[$($sub.Name)] $($_.Exception.Message)"
        $errors.Add($errMsg)
        Write-Host "    ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ── Export ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Exporting ─────────────────────────────────────────" -ForegroundColor Cyan

if ($results.Count -gt 0) {
    try {
        $csv = $results |
            Sort-Object SubscriptionName, ScopeType, AssignmentKind, RoleDefinitionName, DisplayName |
            ConvertTo-Csv -NoTypeInformation
        [System.IO.File]::WriteAllLines($csvFile, $csv, [System.Text.UTF8Encoding]::new($true))
        Write-Host "Exported $($results.Count) row(s) → $csvFile" -ForegroundColor Green
    } catch {
        Write-Host "ERROR: Could not write CSV: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "No assignments found — CSV not written." -ForegroundColor Yellow
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║              SUBSCRIPTION SUMMARY                ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

foreach ($grp in ($results | Group-Object SubscriptionName | Sort-Object Name)) {
    $active   = ($grp.Group | Where-Object { $_.AssignmentKind -eq "Active"         }).Count
    $eligible = ($grp.Group | Where-Object { $_.AssignmentKind -eq "Eligible (PIM)" }).Count
    $state    = ($grp.Group | Select-Object -First 1).SubscriptionState
    Write-Host ("  {0,-48} [{1}]  Active: {2,4}  Eligible: {3,4}" -f $grp.Name, $state, $active, $eligible) `
        -ForegroundColor White
}

Write-Host ""
$totalActive   = ($results | Where-Object { $_.AssignmentKind -eq "Active"         }).Count
$totalEligible = ($results | Where-Object { $_.AssignmentKind -eq "Eligible (PIM)" }).Count
Write-Host ("Total: {0} row(s)  —  Active: {1}  Eligible: {2}  across {3} subscription(s)." -f `
    $results.Count, $totalActive, $totalEligible, $subscriptions.Count) -ForegroundColor Cyan

if ($errors.Count -gt 0) {
    Write-Host ""
    Write-Host "Errors ($($errors.Count)):" -ForegroundColor Red
    foreach ($e in $errors) { Write-Host "  $e" -ForegroundColor Red }
}

Write-Host ""

# ── Disconnect ────────────────────────────────────────────────────────────────
try { Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null } catch {}
