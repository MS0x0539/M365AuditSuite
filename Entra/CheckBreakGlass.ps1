<#
.SYNOPSIS
    Validates the health of configured break-glass emergency access accounts.

.DESCRIPTION
    Performs a read-only health check on each account listed in $BreakGlassAccounts.
    For each account the following is verified:

    • Account exists and is not blocked from sign-in
    • Has a permanent (non-PIM) Global Administrator role assignment
    • Last sign-in is within $MaxDaysSinceSignIn days (configurable; warn if stale)
    • No phone-based authentication methods registered (SMS / voice call are weak
      for break-glass; FIDO2 hardware keys are the recommended method)
    • Is excluded from all enabled CA policies that require MFA for all users

    Results are printed to the console and exported to a CSV on the Desktop.

    ── REQUIREMENTS ────────────────────────────────────────────────────────────
    • ExportReadAudit app registration must have UserAuthenticationMethod.Read.All
      added to its existing permissions (Entra ID → App registrations →
      ExportReadAudit → API permissions → add UserAuthenticationMethod.Read.All)
    • If UserAuthenticationMethod.Read.All is not granted the auth method check
      is skipped gracefully with a WARN
    ────────────────────────────────────────────────────────────────────────────

.NOTES
    Author      : Melih Sivrikaya
    Permissions : User.Read.All, Directory.Read.All, RoleManagement.Read.Directory,
                  AuditLog.Read.All, Policy.Read.All,
                  UserAuthenticationMethod.Read.All
                  (application permissions — grant admin consent)
    Auth        : Certificate-based (app registration: ExportReadAudit)
    Requires    : Microsoft.Graph.Authentication
#>

#Requires -Version 5.1

# =====================
# Tenant configuration
# =====================
$TenantId              = "58288310-2b28-42b6-883b-dcef687a4e29"
$TenantDisplayName     = "PSBV"
$AppId                 = "2d048869-cd36-4bf6-baa7-712fc1cb8214"
$CertificateThumbprint = "2BA37CACAA2C69A6F64ADF8587A74D73DBA8ED01"

# =====================
# Break-glass accounts
# Resolved by UPN or display name
# =====================
$BreakGlassAccounts = @(
     "ms@psbv.org"
     #"breakglass2@psbv.org"
)

# =====================
# Thresholds
# =====================
$MaxDaysSinceSignIn = 180   # WARN if break-glass has not signed in within this many days

# ===========================================================================
# SCRIPT INTERNALS — do not edit below this line
# ===========================================================================

# Global Admin role template ID — consistent across all Entra tenants
$GlobalAdminRoleTemplateId = "62e90394-69f5-4237-9190-012177145e10"

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║         Break-Glass Account Health Check          ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ── Module check ─────────────────────────────────────────────────────────────
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

if ($BreakGlassAccounts.Count -eq 0) {
    Write-Host ""
    Write-Host "No break-glass accounts configured in `$BreakGlassAccounts — nothing to check." -ForegroundColor Yellow
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch {}
    exit 0
}

# ── Output folder ─────────────────────────────────────────────────────────────
$timestamp    = Get-Date -Format "yyyyMMdd_HHmmss"
$exportFolder = Join-Path ([Environment]::GetFolderPath('Desktop')) (Join-Path $TenantDisplayName "BreakGlass")
try {
    New-Item -ItemType Directory -Force -Path $exportFolder -ErrorAction Stop | Out-Null
} catch {
    $exportFolder = [Environment]::GetFolderPath('Desktop')
}
$csvFile = Join-Path $exportFolder ("CheckBreakGlass_{0}.csv" -f $timestamp)

# ── Fetch all CA policies once ────────────────────────────────────────────────
Write-Host ""
Write-Host "── Loading CA policies ───────────────────────────────" -ForegroundColor Cyan
$allCAPolicies = [System.Collections.Generic.List[object]]::new()
try {
    $caUri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?`$select=id,displayName,state,conditions,grantControls"
    do {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $caUri -ErrorAction Stop
        foreach ($p in $resp.value) { $allCAPolicies.Add($p) }
        $caUri = $resp.'@odata.nextLink'
    } while ($caUri)
    Write-Host "  Loaded $($allCAPolicies.Count) CA polic(ies)." -ForegroundColor Green
} catch {
    Write-Host "  WARN: Could not load CA policies — CA exclusion check will be skipped: $($_.Exception.Message)" -ForegroundColor Yellow
}

# ── Check UserAuthenticationMethod.Read.All permission ───────────────────────
$authMethodPermAvailable = $false
try {
    # Probe with a known-existing endpoint — if permission is missing this throws 403
    $probeUser = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/users?`$top=1&`$select=id" -ErrorAction Stop 2>$null
    # Now try auth methods endpoint with the first user found
    if ($probeUser.value -and $probeUser.value[0].id) {
        Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/users/$($probeUser.value[0].id)/authentication/methods?`$top=1" `
            -ErrorAction Stop 2>$null | Out-Null
        $authMethodPermAvailable = $true
    }
} catch {
    if ($_.Exception.Message -match "403|Forbidden|Authorization_RequestDenied") {
        Write-Host "  WARN: UserAuthenticationMethod.Read.All not granted — auth method check will be skipped." -ForegroundColor Yellow
        Write-Host "        Add this permission to the ExportReadAudit app registration." -ForegroundColor DarkGray
    }
}

# ── Main check loop ───────────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Checking accounts ─────────────────────────────────" -ForegroundColor Cyan

$results = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($accountName in $BreakGlassAccounts) {
    Write-Host ""
    Write-Host "  Account: $accountName" -ForegroundColor Cyan

    $row = [PSCustomObject]@{
        Account             = $accountName
        Exists              = "UNKNOWN"
        AccountEnabled      = "UNKNOWN"
        PermanentGlobalAdmin = "UNKNOWN"
        LastSignIn          = "UNKNOWN"
        LastSignInDaysAgo   = "UNKNOWN"
        SignInStaleness     = "UNKNOWN"
        AuthMethods         = "UNKNOWN"
        WeakAuthMethod      = "UNKNOWN"
        CAExcluded          = "UNKNOWN"
        OverallStatus       = "UNKNOWN"
    }

    # ── Resolve user ─────────────────────────────────────────────────────────
    $userObj       = $null
    $signInActivity = $null
    try {
        if ($accountName -match '@') {
            $userObj = Invoke-MgGraphRequest -Method GET `
                -Uri ("https://graph.microsoft.com/v1.0/users/{0}?`$select=id,displayName,userPrincipalName,accountEnabled" -f $accountName) `
                -ErrorAction Stop
        } else {
            $safe     = $accountName -replace "'", "''"
            $userResp = Invoke-MgGraphRequest -Method GET `
                -Uri "https://graph.microsoft.com/v1.0/users?`$filter=displayName eq '$safe'&`$select=id,displayName,userPrincipalName,accountEnabled&`$top=1" `
                -Headers @{ ConsistencyLevel = "eventual" } `
                -ErrorAction Stop
            $userObj = $userResp.value | Select-Object -First 1
        }
    } catch {
        Write-Host "    ERR  User lookup failed: $($_.Exception.Message)" -ForegroundColor Red
    }

    # signInActivity fetched separately — requires AuditLog.Read.All
    if ($userObj) {
        try {
            $saResp = Invoke-MgGraphRequest -Method GET `
                -Uri ("https://graph.microsoft.com/v1.0/users/{0}?`$select=signInActivity" -f $userObj.id) `
                -ErrorAction Stop
            $signInActivity = $saResp.signInActivity
        } catch {}
    }

    if (-not $userObj) {
        Write-Host "    ERR  Account not found in tenant." -ForegroundColor Red
        $row.Exists = "NOT FOUND"
        $row.OverallStatus = "ERR"
        $results.Add($row)
        continue
    }

    $row.Exists  = "OK"
    $row.Account = $userObj.userPrincipalName

    # ── Account enabled ───────────────────────────────────────────────────────
    if ($userObj.accountEnabled -eq $true) {
        Write-Host "    OK   Account is enabled." -ForegroundColor Green
        $row.AccountEnabled = "Enabled"
    } else {
        Write-Host "    ERR  Account is BLOCKED from sign-in." -ForegroundColor Red
        $row.AccountEnabled = "BLOCKED"
    }

    # ── Permanent Global Admin check ──────────────────────────────────────────
    $isPermanentGA = $false
    try {
        # Resolve Global Admin role definition ID for this tenant
        $gaRoleResp = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?`$filter=templateId eq '$GlobalAdminRoleTemplateId'&`$select=id" `
            -ErrorAction Stop
        $gaRoleId = $gaRoleResp.value[0].id

        # Check permanent (non-PIM) assignment
        $assignResp = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($userObj.id)' and roleDefinitionId eq '$gaRoleId'&`$select=id" `
            -ErrorAction Stop
        $isPermanentGA = ($assignResp.value.Count -gt 0)
    } catch {
        Write-Host "    WARN Could not verify Global Admin assignment: $($_.Exception.Message)" -ForegroundColor Yellow
        $row.PermanentGlobalAdmin = "CHECK FAILED"
    }

    if ($isPermanentGA) {
        Write-Host "    OK   Has permanent Global Administrator assignment." -ForegroundColor Green
        $row.PermanentGlobalAdmin = "OK — Permanent GA"
    } elseif ($row.PermanentGlobalAdmin -ne "CHECK FAILED") {
        Write-Host "    WARN No permanent Global Administrator assignment found." -ForegroundColor Yellow
        $row.PermanentGlobalAdmin = "WARN — No permanent GA"
    }

    # ── Last sign-in ──────────────────────────────────────────────────────────
    $lastSignIn = $signInActivity.lastSignInDateTime
    if ($lastSignIn) {
        $lastSignInDate = [datetime]::Parse($lastSignIn)
        $daysAgo = [math]::Round(([datetime]::UtcNow - $lastSignInDate.ToUniversalTime()).TotalDays)
        $row.LastSignIn        = $lastSignInDate.ToString("yyyy-MM-dd HH:mm UTC")
        $row.LastSignInDaysAgo = $daysAgo

        if ($daysAgo -gt $MaxDaysSinceSignIn) {
            Write-Host "    WARN Last sign-in was $daysAgo days ago ($($lastSignInDate.ToString('yyyy-MM-dd'))) — exceeds ${MaxDaysSinceSignIn}d threshold." -ForegroundColor Yellow
            $row.SignInStaleness = "WARN — Stale ($daysAgo days)"
        } else {
            Write-Host "    OK   Last sign-in $daysAgo day(s) ago ($($lastSignInDate.ToString('yyyy-MM-dd')))." -ForegroundColor Green
            $row.SignInStaleness = "OK"
        }
    } else {
        Write-Host "    WARN No sign-in activity recorded for this account." -ForegroundColor Yellow
        $row.LastSignIn        = "Never"
        $row.LastSignInDaysAgo = "N/A"
        $row.SignInStaleness   = "WARN — Never signed in"
    }

    # ── Authentication methods ────────────────────────────────────────────────
    if ($authMethodPermAvailable) {
        try {
            $methodResp = Invoke-MgGraphRequest -Method GET `
                -Uri "https://graph.microsoft.com/v1.0/users/$($userObj.id)/authentication/methods" `
                -ErrorAction Stop
            $methods = $methodResp.value | ForEach-Object {
                switch ($_.'@odata.type') {
                    "#microsoft.graph.fido2AuthenticationMethod"               { "FIDO2" }
                    "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod" { "Authenticator" }
                    "#microsoft.graph.phoneAuthenticationMethod"               { "Phone (SMS/Voice)" }
                    "#microsoft.graph.softwareOathAuthenticationMethod"        { "OATH TOTP" }
                    "#microsoft.graph.temporaryAccessPassAuthenticationMethod" { "TAP" }
                    "#microsoft.graph.passwordAuthenticationMethod"            { "Password" }
                    "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod" { "Windows Hello" }
                    "#microsoft.graph.emailAuthenticationMethod"               { "Email OTP" }
                    default { $_.'@odata.type'.Split('.')[-1] }
                }
            }
            $weakMethods = $methods | Where-Object { $_ -in @("Phone (SMS/Voice)", "Email OTP") }
            $methodList  = ($methods | Where-Object { $_ -ne "Password" }) -join ", "
            $row.AuthMethods = if ($methodList) { $methodList } else { "Password only" }

            if ($weakMethods.Count -gt 0) {
                Write-Host "    WARN Weak auth method(s) registered: $($weakMethods -join ', ') — consider FIDO2 hardware key for break-glass." -ForegroundColor Yellow
                $row.WeakAuthMethod = "WARN — $($weakMethods -join ', ')"
            } else {
                Write-Host "    OK   Auth methods: $($row.AuthMethods)" -ForegroundColor Green
                $row.WeakAuthMethod = "OK"
            }
        } catch {
            Write-Host "    WARN Could not retrieve auth methods: $($_.Exception.Message)" -ForegroundColor Yellow
            $row.AuthMethods    = "CHECK FAILED"
            $row.WeakAuthMethod = "CHECK FAILED"
        }
    } else {
        $row.AuthMethods    = "SKIPPED (permission missing)"
        $row.WeakAuthMethod = "SKIPPED"
    }

    # ── CA policy exclusion check ─────────────────────────────────────────────
    if ($allCAPolicies.Count -gt 0) {
        # Find enabled policies that include All users and require MFA
        $mfaAllPolicies = $allCAPolicies | Where-Object {
            $_.state -eq "enabled" -and
            $_.conditions.users.includeUsers -contains "All" -and
            $_.grantControls.builtInControls -contains "mfa"
        }

        $notExcluded = [System.Collections.Generic.List[string]]::new()
        foreach ($policy in $mfaAllPolicies) {
            $excludedUsers = @($policy.conditions.users.excludeUsers)
            if ($excludedUsers -notcontains $userObj.id) {
                $notExcluded.Add($policy.displayName)
            }
        }

        if ($mfaAllPolicies.Count -eq 0) {
            Write-Host "    INFO No enabled MFA-for-all-users CA policies found." -ForegroundColor Cyan
            $row.CAExcluded = "INFO — No MFA-all-users policy active"
        } elseif ($notExcluded.Count -gt 0) {
            Write-Host "    WARN NOT excluded from $($notExcluded.Count) MFA CA polic(ies): $($notExcluded -join '; ')" -ForegroundColor Yellow
            $row.CAExcluded = "WARN — Not excluded from: $($notExcluded -join '; ')"
        } else {
            Write-Host "    OK   Excluded from all enabled MFA-for-all-users CA policies." -ForegroundColor Green
            $row.CAExcluded = "OK"
        }
    } else {
        $row.CAExcluded = "SKIPPED (CA policies unavailable)"
    }

    # ── Overall status ────────────────────────────────────────────────────────
    $hasErr  = $row.PSObject.Properties.Value | Where-Object { $_ -is [string] -and $_ -like "ERR*" }
    $hasWarn = $row.PSObject.Properties.Value | Where-Object { $_ -is [string] -and $_ -like "WARN*" }
    $row.OverallStatus = if ($hasErr) { "ERR" } elseif ($hasWarn) { "WARN" } else { "OK" }

    $results.Add($row)
}

# ── Export CSV ────────────────────────────────────────────────────────────────
if ($results.Count -gt 0) {
    try {
        $csv = $results | ConvertTo-Csv -NoTypeInformation
        [System.IO.File]::WriteAllLines($csvFile, $csv, [System.Text.UTF8Encoding]::new($true))
        Write-Host ""
        Write-Host "CSV exported → $csvFile" -ForegroundColor DarkGray
    } catch {
        Write-Host "Could not export CSV: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                  SUMMARY                         ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

foreach ($r in $results) {
    $color = switch ($r.OverallStatus) { "OK" { "Green" } "WARN" { "Yellow" } default { "Red" } }
    Write-Host ("  [{0}]  {1}" -f $r.OverallStatus, $r.Account) -ForegroundColor $color
}

Write-Host ""

$errCount  = ($results | Where-Object { $_.OverallStatus -eq "ERR"  }).Count
$warnCount = ($results | Where-Object { $_.OverallStatus -eq "WARN" }).Count
$okCount   = ($results | Where-Object { $_.OverallStatus -eq "OK"   }).Count
Write-Host "Accounts checked: $($results.Count)  —  OK: $okCount  WARN: $warnCount  ERR: $errCount" -ForegroundColor Cyan
Write-Host ""

# ── Disconnect ────────────────────────────────────────────────────────────────
try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch {}

if ($errCount -gt 0) { exit 1 }
