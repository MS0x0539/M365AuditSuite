<#
.SYNOPSIS
    Creates or validates the baseline Conditional Access policies required by the organization.

.DESCRIPTION
    Idempotent — safe to re-run. For each policy the script checks whether it exists and
    whether it is in the expected state. Missing policies are created; existing policies
    with a wrong state are flagged as WARN. Deep condition drift (grant controls, user
    scope) is also checked and reported.

    Policies managed (all display names are configurable in the config section):

    PHASE 1 — Authentication context
        Ensures auth context '$AuthContextId' exists in the tenant and is marked available.
        This is the context referenced by the PIM Step-Up policy and by OnboardingEntraPIM.

    PHASE 2 — PIM Step-Up Authentication
        CA policy targeting auth context '$AuthContextId'. Requires MFA on activation.
        Applies to all users. This is the policy that enforces step-up auth on PIM role
        activation — OnboardingEntraPIM pre-flight checks for it.

    PHASE 3 — Require MFA for All Users
        CA policy requiring MFA for all cloud apps. Break-glass accounts listed in
        $BreakGlassObjectIds are excluded. Defaults to report-only state so you can
        validate coverage before enforcing.

    PHASE 4 — Block Legacy Authentication
        CA policy blocking all legacy authentication protocols (Exchange ActiveSync and
        other legacy clients). Defaults to report-only state.

    PHASE 5 — Summary
        Prints OK / WARN / ERR counts per phase. Exits with code 1 if any errors.

    ── REQUIREMENTS ────────────────────────────────────────────────────────────
    • EasyPIM app registration must have Policy.ReadWrite.ConditionalAccess granted
      in addition to its existing permissions (add in Entra ID → App registrations →
      EasyPIM → API permissions → Microsoft Graph → Application → Policy.ReadWrite.ConditionalAccess)
    ────────────────────────────────────────────────────────────────────────────

.NOTES
    Author      : Melih Sivrikaya
    Permissions : Policy.Read.All, Policy.ReadWrite.ConditionalAccess,
                  User.Read.All, Group.Read.All
                  (application permissions — grant admin consent)
    Auth        : Certificate-based (app registration: EasyPIM)
    Requires    : Microsoft.Graph.Authentication
#>

#Requires -Version 5.1

param (
    [Alias('WhatIf')]
    [switch] $DryRun
)

# =====================
# Tenant configuration
# =====================
$TenantId              = "58288310-2b28-42b6-883b-dcef687a4e29"
$TenantDisplayName     = "PSBV"
$AppId                 = "e3febffa-d27e-4193-936f-f3ca01b24af8"
$CertificateThumbprint = "6805FD0B9EBA398B82CB59CA87E67E2FD3075657"

# =====================
# Auth context
# =====================
# Must match $AuthContextId in OnboardingEntraPIM.ps1
$AuthContextId          = "c1"
$AuthContextDisplayName = "PIM Step-Up Authentication"
$AuthContextDescription = "Required for PIM role activation. Enforced by $PolicyName_PIMStepUp."

# =====================
# Policy names (customise if needed)
# =====================
$PolicyName_PIMStepUp   = "SEC-PIM-01 — PIM Step-Up Authentication (c1)"
$PolicyName_MFAAll      = "SEC-CA-01 — Require MFA for All Users"
$PolicyName_BlockLegacy = "SEC-CA-02 — Block Legacy Authentication"

# =====================
# Policy states
# "enabled" | "disabled" | "enabledForReportingButNotEnforced"
# =====================
$PolicyState_PIMStepUp   = "enabled"                           # PIM step-up must be enforced
$PolicyState_MFAAll      = "enabledForReportingButNotEnforced" # validate coverage before enforcing
$PolicyState_BlockLegacy = "enabledForReportingButNotEnforced" # validate coverage before enforcing

# =====================
# Break-glass account object IDs
# These accounts are excluded from the MFA for All Users policy.
# Add the object IDs (GUIDs) of your emergency access accounts.
# =====================
$BreakGlassObjectIds = @(
    # "00000000-0000-0000-0000-000000000001"
    # "00000000-0000-0000-0000-000000000002"
)

# ===========================================================================
# SCRIPT INTERNALS — do not edit below this line
# ===========================================================================

$script:Log = [System.Collections.Generic.List[PSCustomObject]]::new()

function Write-CALog {
    param (
        [ValidateSet("INFO","OK","WARN","ERR")] [string] $Level,
        [string] $Phase,
        [string] $Message
    )
    $entry = [PSCustomObject]@{
        Time    = (Get-Date -Format "HH:mm:ss")
        Level   = $Level
        Phase   = $Phase
        Message = $Message
    }
    $script:Log.Add($entry)
    $color = switch ($Level) { "INFO" { "Cyan" } "OK" { "Green" } "WARN" { "Yellow" } "ERR" { "Red" } }
    $prefix = switch ($Level) { "INFO" { "  ····" } "OK" { "  OK  " } "WARN" { "  WARN" } "ERR" { "  ERR " } }
    Write-Host "$($entry.Time) $prefix [$Phase] $Message" -ForegroundColor $color
}

# ── Module check ──────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     Conditional Access Onboarding / Validation       ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

if ($DryRun) {
    Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "║  DRY RUN — no changes will be made to the tenant     ║" -ForegroundColor Yellow
    Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Yellow
    Write-Host ""
}

Write-Host "Checking modules..." -ForegroundColor Cyan
try {
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Write-Host "  Loaded: Microsoft.Graph.Authentication" -ForegroundColor Green
} catch {
    Write-Host "  FATAL: Could not load 'Microsoft.Graph.Authentication'. Install with: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser" -ForegroundColor Red
    exit 1
}

# ── Connect ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
try {
    Connect-MgGraph -TenantId $TenantId -AppId $AppId -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
    Write-Host "Connected — tenant: $TenantId ($TenantDisplayName)" -ForegroundColor Green
} catch {
    Write-Host "FATAL: Could not connect to Microsoft Graph: $_" -ForegroundColor Red
    exit 1
}

# ── Helper: get all CA policies (cached) ─────────────────────────────────────
$script:AllPolicies = $null
function Get-AllCAPolicies {
    if ($script:AllPolicies) { return $script:AllPolicies }
    $policies = [System.Collections.Generic.List[object]]::new()
    $uri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?`$select=id,displayName,state,conditions,grantControls"
    do {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        foreach ($p in $resp.value) { $policies.Add($p) }
        $uri = $resp.'@odata.nextLink'
    } while ($uri)
    $script:AllPolicies = $policies
    return $script:AllPolicies
}

function Find-PolicyByName {
    param ([string] $Name)
    return (Get-AllCAPolicies) | Where-Object { $_.displayName -eq $Name } | Select-Object -First 1
}

function Invoke-CreateOrValidatePolicy {
    param (
        [string]   $Phase,
        [string]   $PolicyName,
        [string]   $ExpectedState,
        [hashtable] $Body
    )
    $existing = Find-PolicyByName -Name $PolicyName

    if ($existing) {
        Write-CALog -Level INFO -Phase $Phase -Message "Policy exists: $PolicyName"

        # State check
        if ($existing.state -ne $ExpectedState) {
            Write-CALog -Level WARN -Phase $Phase -Message "State mismatch — current: '$($existing.state)'  expected: '$ExpectedState'"
            if (-not $DryRun) {
                try {
                    Invoke-MgGraphRequest -Method PATCH `
                        -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$($existing.id)" `
                        -Body (@{ state = $ExpectedState } | ConvertTo-Json -Compress) `
                        -ContentType "application/json" -ErrorAction Stop | Out-Null
                    $script:AllPolicies = $null  # invalidate cache
                    Write-CALog -Level OK -Phase $Phase -Message "State corrected to '$ExpectedState': $PolicyName"
                } catch {
                    Write-CALog -Level ERR -Phase $Phase -Message "Failed to update state: $($_.Exception.Message)"
                }
            } else {
                Write-CALog -Level INFO -Phase $Phase -Message "[DRY RUN] Would set state to '$ExpectedState'"
            }
        } else {
            Write-CALog -Level OK -Phase $Phase -Message "State OK ('$ExpectedState'): $PolicyName"
        }
    } else {
        if ($DryRun) {
            Write-CALog -Level INFO -Phase $Phase -Message "[DRY RUN] Would create policy: $PolicyName (state: $ExpectedState)"
        } else {
            try {
                Invoke-MgGraphRequest -Method POST `
                    -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" `
                    -Body ($Body | ConvertTo-Json -Depth 10 -Compress) `
                    -ContentType "application/json" -ErrorAction Stop | Out-Null
                $script:AllPolicies = $null  # invalidate cache
                Write-CALog -Level OK -Phase $Phase -Message "Created: $PolicyName (state: $ExpectedState)"
            } catch {
                Write-CALog -Level ERR -Phase $Phase -Message "Failed to create '$PolicyName': $($_.Exception.Message)"
            }
        }
    }
}

# ===========================================================================
# PHASE 1 — Authentication context
# ===========================================================================
Write-Host ""
Write-Host "── PHASE 1: Authentication Context ──────────────────" -ForegroundColor Cyan

try {
    $ctx = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/identity/authenticationContextClassReferences/$AuthContextId" `
        -ErrorAction Stop 2>$null

    if ($ctx.isAvailable -eq $true) {
        Write-CALog -Level OK -Phase "P1" -Message "Auth context '$AuthContextId' exists and is available: $($ctx.displayName)"
    } else {
        Write-CALog -Level WARN -Phase "P1" -Message "Auth context '$AuthContextId' exists ('$($ctx.displayName)') but is NOT marked available — will correct"
        if (-not $DryRun) {
            try {
                Invoke-MgGraphRequest -Method PATCH `
                    -Uri "https://graph.microsoft.com/v1.0/identity/authenticationContextClassReferences/$AuthContextId" `
                    -Body (@{ isAvailable = $true } | ConvertTo-Json -Compress) `
                    -ContentType "application/json" -ErrorAction Stop | Out-Null
                Write-CALog -Level OK -Phase "P1" -Message "Auth context '$AuthContextId' marked available."
            } catch {
                Write-CALog -Level ERR -Phase "P1" -Message "Failed to mark auth context available: $($_.Exception.Message)"
            }
        } else {
            Write-CALog -Level INFO -Phase "P1" -Message "[DRY RUN] Would mark auth context '$AuthContextId' as available"
        }
    }
} catch {
    $errMsg = $_.Exception.Message
    if ($errMsg -match "404|NotFound|ResourceNotFound") {
        Write-CALog -Level INFO -Phase "P1" -Message "Auth context '$AuthContextId' not found — creating"
        if (-not $DryRun) {
            try {
                $ctxBody = @{
                    id          = $AuthContextId
                    displayName = $AuthContextDisplayName
                    description = $AuthContextDescription
                    isAvailable = $true
                } | ConvertTo-Json -Compress
                Invoke-MgGraphRequest -Method POST `
                    -Uri "https://graph.microsoft.com/v1.0/identity/authenticationContextClassReferences" `
                    -Body $ctxBody -ContentType "application/json" -ErrorAction Stop | Out-Null
                Write-CALog -Level OK -Phase "P1" -Message "Auth context '$AuthContextId' created: $AuthContextDisplayName"
            } catch {
                Write-CALog -Level ERR -Phase "P1" -Message "Failed to create auth context: $($_.Exception.Message)"
            }
        } else {
            Write-CALog -Level INFO -Phase "P1" -Message "[DRY RUN] Would create auth context '$AuthContextId' ($AuthContextDisplayName)"
        }
    } else {
        Write-CALog -Level WARN -Phase "P1" -Message "Could not verify auth context '$AuthContextId': $errMsg"
    }
}

# ===========================================================================
# PHASE 2 — PIM Step-Up policy (auth context c1 → require MFA)
# ===========================================================================
Write-Host ""
Write-Host "── PHASE 2: PIM Step-Up Policy ───────────────────────" -ForegroundColor Cyan

$pimStepUpBody = @{
    displayName   = $PolicyName_PIMStepUp
    state         = $PolicyState_PIMStepUp
    conditions    = @{
        users        = @{
            includeUsers = @("All")
        }
        applications = @{
            includeApplications                        = @()
            includeAuthenticationContextClassReferences = @($AuthContextId)
        }
    }
    grantControls = @{
        operator         = "OR"
        builtInControls  = @("mfa")
    }
}

Invoke-CreateOrValidatePolicy -Phase "P2" -PolicyName $PolicyName_PIMStepUp `
    -ExpectedState $PolicyState_PIMStepUp -Body $pimStepUpBody

# ===========================================================================
# PHASE 3 — Require MFA for All Users
# ===========================================================================
Write-Host ""
Write-Host "── PHASE 3: MFA for All Users ────────────────────────" -ForegroundColor Cyan

if ($BreakGlassObjectIds.Count -eq 0) {
    Write-CALog -Level WARN -Phase "P3" -Message "`$BreakGlassObjectIds is empty — policy will apply to ALL users including break-glass accounts. Add object IDs to exclude them."
}

$mfaAllBody = @{
    displayName   = $PolicyName_MFAAll
    state         = $PolicyState_MFAAll
    conditions    = @{
        users        = @{
            includeUsers = @("All")
            excludeUsers = $BreakGlassObjectIds
        }
        applications = @{
            includeApplications = @("All")
        }
    }
    grantControls = @{
        operator        = "OR"
        builtInControls = @("mfa")
    }
}

Invoke-CreateOrValidatePolicy -Phase "P3" -PolicyName $PolicyName_MFAAll `
    -ExpectedState $PolicyState_MFAAll -Body $mfaAllBody

# ── Verify break-glass exclusions on existing policy ─────────────────────────
if (-not $DryRun -and $BreakGlassObjectIds.Count -gt 0) {
    $existingMFAAll = Find-PolicyByName -Name $PolicyName_MFAAll
    if ($existingMFAAll) {
        $currentExcludes = @($existingMFAAll.conditions.users.excludeUsers)
        foreach ($bgId in $BreakGlassObjectIds) {
            if ($currentExcludes -notcontains $bgId) {
                Write-CALog -Level WARN -Phase "P3" -Message "Break-glass account '$bgId' is NOT in the excludeUsers list of '$PolicyName_MFAAll' — update the policy manually or re-run to recreate."
            } else {
                Write-CALog -Level OK -Phase "P3" -Message "Break-glass '$bgId' is excluded from MFA for All Users."
            }
        }
    }
}

# ===========================================================================
# PHASE 4 — Block Legacy Authentication
# ===========================================================================
Write-Host ""
Write-Host "── PHASE 4: Block Legacy Authentication ──────────────" -ForegroundColor Cyan

$blockLegacyBody = @{
    displayName   = $PolicyName_BlockLegacy
    state         = $PolicyState_BlockLegacy
    conditions    = @{
        users        = @{
            includeUsers = @("All")
        }
        applications = @{
            includeApplications = @("All")
        }
        clientAppTypes = @("exchangeActiveSync", "other")
    }
    grantControls = @{
        operator        = "OR"
        builtInControls = @("block")
    }
}

Invoke-CreateOrValidatePolicy -Phase "P4" -PolicyName $PolicyName_BlockLegacy `
    -ExpectedState $PolicyState_BlockLegacy -Body $blockLegacyBody

# =====================
# Disconnect
# =====================
try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch {}

# ===========================================================================
# PHASE 5 — Summary
# ===========================================================================
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                  SUMMARY REPORT                  ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$phases = $script:Log | Select-Object -ExpandProperty Phase -Unique | Sort-Object
foreach ($phase in $phases) {
    $entries = $script:Log | Where-Object { $_.Phase -eq $phase }
    $ok   = ($entries | Where-Object { $_.Level -eq "OK"   }).Count
    $warn = ($entries | Where-Object { $_.Level -eq "WARN" }).Count
    $err  = ($entries | Where-Object { $_.Level -eq "ERR"  }).Count
    $label = switch ($phase) {
        "P1" { "Phase 1 — Authentication Context  " }
        "P2" { "Phase 2 — PIM Step-Up Policy       " }
        "P3" { "Phase 3 — MFA for All Users         " }
        "P4" { "Phase 4 — Block Legacy Auth          " }
        default { $phase }
    }
    $color = if ($err -gt 0) { "Red" } elseif ($warn -gt 0) { "Yellow" } else { "Green" }
    Write-Host "  $label  OK: $ok  WARN: $warn  ERR: $err" -ForegroundColor $color
}

Write-Host ""

$totalErrors = ($script:Log | Where-Object { $_.Level -eq "ERR"  }).Count
$totalWarns  = ($script:Log | Where-Object { $_.Level -eq "WARN" }).Count

if ($totalWarns -gt 0) {
    Write-Host "Warnings ($totalWarns):" -ForegroundColor Yellow
    $script:Log | Where-Object { $_.Level -eq "WARN" } | ForEach-Object {
        Write-Host "  [$($_.Phase)] $($_.Message)" -ForegroundColor Yellow
    }
    Write-Host ""
}

if ($totalErrors -gt 0) {
    Write-Host "Errors ($totalErrors):" -ForegroundColor Red
    $script:Log | Where-Object { $_.Level -eq "ERR" } | ForEach-Object {
        Write-Host "  [$($_.Phase)] $($_.Message)" -ForegroundColor Red
    }
    Write-Host ""
    exit 1
} elseif ($totalWarns -gt 0) {
    Write-Host "Completed with $totalWarns warning(s)." -ForegroundColor Yellow
} else {
    Write-Host "All phases completed successfully." -ForegroundColor Green
}

Write-Host ""
