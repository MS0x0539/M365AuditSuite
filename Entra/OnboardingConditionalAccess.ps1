<#
.SYNOPSIS
    Creates or validates the PIM Conditional Access prerequisites — auth context and step-up policy.

.DESCRIPTION
    Idempotent — safe to re-run. Covers only the CA components required by OnboardingEntraPIM.

    PHASE 1 — Authentication context
        Ensures auth context '$AuthContextId' exists in the tenant and is marked available.
        This is the context referenced by the PIM Step-Up policy and checked by the
        OnboardingEntraPIM pre-flight (PRE-CA).

    PHASE 2 — PIM Step-Up Authentication policy
        CA policy targeting auth context '$AuthContextId'. Requires MFA on activation.
        Applies to all users. This enforces step-up auth whenever a PIM role activation
        triggers the authentication context.

    PHASE 3 — Summary
        Prints OK / WARN / ERR counts per phase. Exits with code 1 if any errors.

    ── REQUIREMENTS ────────────────────────────────────────────────────────────
    • EasyPIM app registration must have Policy.ReadWrite.ConditionalAccess granted
      in addition to its existing permissions (Entra ID → App registrations →
      EasyPIM → API permissions → Microsoft Graph → Application →
      Policy.ReadWrite.ConditionalAccess → Grant admin consent)
    ────────────────────────────────────────────────────────────────────────────

.NOTES
    Author      : Melih Sivrikaya
    Permissions : Policy.Read.All, Policy.ReadWrite.ConditionalAccess
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
# Policy name and state (customise if needed)
# =====================
$PolicyName_PIMStepUp  = "PIM — Enforce Re-Authentication (c1)"
$PolicyState_PIMStepUp = "enabled"   # "enabled" | "disabled" | "enabledForReportingButNotEnforced"

# =====================
# Auth context
# Must match $AuthContextId in OnboardingEntraPIM.ps1
# =====================
$AuthContextId          = "c1"
$AuthContextDisplayName = "PIM Step-Up Authentication"
$AuthContextDescription = "Required for PIM role activation. Enforced by $PolicyName_PIMStepUp."

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
    if ($errMsg -match "BadRequest|Bad Request") {
        # Graph returns 400 on the individual auth context GET for some tenants — same quirk
        # handled in OnboardingEntraPIM PRE-CA. Context is assumed present; Phase 2 will confirm
        # it is usable when the CA policy is created or validated successfully.
        Write-CALog -Level OK -Phase "P1" -Message "Auth context '$AuthContextId' — individual lookup returned 400 (known API quirk); assumed present."
    } elseif ($errMsg -match "404|NotFound|ResourceNotFound") {
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

# ── Pre-check: detect any existing policy already targeting c1 (any name) ────
# If a policy with a different name already targets c1, warn before creating a duplicate.
try {
    $existingC1Policies = (Get-AllCAPolicies) | Where-Object {
        $refs = @($_.conditions.applications.includeAuthenticationContextClassReferences)
        $refs -contains $AuthContextId
    }
    $unmanaged = $existingC1Policies | Where-Object { $_.displayName -ne $PolicyName_PIMStepUp }
    foreach ($p in $unmanaged) {
        Write-CALog -Level WARN -Phase "P2" -Message "Existing policy targeting '$AuthContextId' found with a different name: '$($p.displayName)' (state: $($p.state)) — this may be a duplicate. Review and remove it if this script's policy will replace it."
    }
} catch {
    Write-CALog -Level INFO -Phase "P2" -Message "Could not scan for existing c1 policies: $($_.Exception.Message)"
}

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

# ── Condition drift check ─────────────────────────────────────────────────────
# Runs regardless of DryRun — read-only. Validates the three properties that must
# be correct for PIM step-up MFA to actually fire.
$p2Policy = Find-PolicyByName -Name $PolicyName_PIMStepUp
if ($p2Policy) {
    $ctxRefs      = @($p2Policy.conditions.applications.includeAuthenticationContextClassReferences)
    $includeUsers = @($p2Policy.conditions.users.includeUsers)
    $grantCtrls   = @($p2Policy.grantControls.builtInControls)

    if ($ctxRefs -notcontains $AuthContextId) {
        Write-CALog -Level WARN -Phase "P2" -Message "Drift: auth context '$AuthContextId' is not in includeAuthenticationContextClassReferences — PIM step-up MFA will NOT fire."
    } else {
        Write-CALog -Level OK -Phase "P2" -Message "Drift OK: auth context '$AuthContextId' is referenced."
    }

    if ($includeUsers -notcontains "All") {
        Write-CALog -Level WARN -Phase "P2" -Message "Drift: includeUsers is not 'All' — policy does not cover all users (current: $($includeUsers -join ', '))."
    } else {
        Write-CALog -Level OK -Phase "P2" -Message "Drift OK: user scope is All."
    }

    if ($grantCtrls -notcontains "mfa") {
        Write-CALog -Level WARN -Phase "P2" -Message "Drift: grant control 'mfa' is missing (current: $($grantCtrls -join ', ')) — step-up authentication is not enforced."
    } else {
        Write-CALog -Level OK -Phase "P2" -Message "Drift OK: grant control is mfa."
    }
}

# =====================
# Disconnect
# =====================
try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch {}

# ===========================================================================
# PHASE 3 — Summary
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
