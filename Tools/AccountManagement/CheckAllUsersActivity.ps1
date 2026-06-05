<#
.SYNOPSIS
    Tenant-wide user activity check — reports every user's last sign-in across
    all sign-in types and flags users inactive beyond a configurable threshold.

.DESCRIPTION
    Checks every user in the tenant against all three SignInActivity fields
    stored on the user record:

        • lastSuccessfulSignInDateTime      — most recent successful sign-in
                                              of any type (interactive or not)
        • lastSignInDateTime                — most recent interactive sign-in
        • lastNonInteractiveSignInDateTime  — most recent token refresh /
                                              silent background sign-in

    The "true last activity" for each user is the most recent timestamp
    across all three fields. Users are classified as:

        INACTIVE   — last activity older than the threshold
        NEVER      — no sign-in recorded in any field (never signed in
                     or joined after the data was last recorded)
        ACTIVE     — last activity within the threshold

    Console output shows INACTIVE and NEVER users (the ones that matter).
    The full CSV export includes every user with all activity dates.

    Read-only — no changes are made to the tenant.

.NOTES
    Author      : Melih Sivrikaya
    Auth        : Certificate-based (app registration: ExportReadAudit)

    Permissions : User.Read.All       — user objects and SignInActivity property
                  AuditLog.Read.All   — required to read SignInActivity

    Requires    : Microsoft.Graph.Authentication, Microsoft.Graph.Users

    Notes       : SignInActivity is stored on the user object and is not limited
                  by sign-in log retention. It reflects the last known activity
                  regardless of how long ago it occurred.
                  Guest users are included and labelled as Guest in output.
#>

#Requires -Version 5.1

# =====================
# Tenant configuration
# =====================
$TenantId              = "58288310-2b28-42b6-883b-dcef687a4e29"
$AppId                 = "2d048869-cd36-4bf6-baa7-712fc1cb8214"
$CertificateThumbprint = "2BA37CACAA2C69A6F64ADF8587A74D73DBA8ED01"

# ===========================================================================
# SCRIPT INTERNALS — do not edit below this line
# ===========================================================================

# ── Module check ──────────────────────────────────────────────────────────────
$requiredModules = @(
    "Microsoft.Graph.Authentication"
    "Microsoft.Graph.Users"
)
foreach ($mod in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod -ErrorAction SilentlyContinue)) {
        Write-Host "FATAL: Required module '$mod' is not installed." -ForegroundColor Red
        Write-Host "       Run: Install-Module $mod -Scope CurrentUser" -ForegroundColor Yellow
        exit 1
    }
}
Import-Module Microsoft.Graph.Authentication, Microsoft.Graph.Users -ErrorAction SilentlyContinue

# ── Export folder resolution ───────────────────────────────────────────────────
function Resolve-ExportFolder {
    param([string]$TenantTag)
    $candidates = @(
        [Environment]::GetFolderPath('Desktop')
        "$env:USERPROFILE\Desktop"
        "C:\Audit"
    )
    foreach ($base in $candidates) {
        if (-not $base) { continue }
        $target = Join-Path $base (Join-Path $TenantTag "AccountManagement")
        try {
            New-Item -ItemType Directory -Force -Path $target -ErrorAction Stop | Out-Null
            return $target
        } catch { continue }
    }
    return $null
}

# ── Connect ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  === CheckAllUsersActivity" -ForegroundColor Cyan
Write-Host "  Connecting to Microsoft Graph..." -ForegroundColor DarkGray
Write-Host ""

try {
    Connect-MgGraph `
        -TenantId              $TenantId `
        -AppId                 $AppId `
        -CertificateThumbprint $CertificateThumbprint `
        -NoWelcome `
        -ErrorAction Stop

    $tenantName = $TenantId
    try {
        $org = Get-MgOrganization -Property DisplayName -ErrorAction Stop | Select-Object -First 1
        if ($org -and $org.DisplayName) { $tenantName = $org.DisplayName }
    } catch {}

    Write-Host ("  Connected: {0}" -f $tenantName) -ForegroundColor Green
} catch {
    Write-Host "FATAL: Could not connect to Microsoft Graph: $_" -ForegroundColor Red
    exit 1
}

try {

# ── Input ─────────────────────────────────────────────────────────────────────
Write-Host ""
$threshDays = 0
do {
    $threshStr   = (Read-Host "  Inactivity threshold (days)").Trim()
    $validThresh = [int]::TryParse($threshStr, [ref]$threshDays) -and $threshDays -gt 0
    if (-not $validThresh) { Write-Host "  Enter a positive whole number." -ForegroundColor Yellow }
} while (-not $validThresh)

# ── Resolve export folder ─────────────────────────────────────────────────────
$tenantTag    = $tenantName -replace '[^A-Za-z0-9_-]', ''
$exportFolder = Resolve-ExportFolder -TenantTag $tenantTag
if (-not $exportFolder) {
    Write-Host "  WARN: Could not create export folder — CSV export will be skipped." -ForegroundColor Yellow
}

# ── Fetch all users ───────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  Fetching all users..." -ForegroundColor DarkGray

$userProps = "Id,DisplayName,UserPrincipalName,AccountEnabled,UserType,CreatedDateTime,SignInActivity"
$allUsers  = @(Get-MgUser -All -Property $userProps -ErrorAction Stop)
Write-Host ("  Users found         : {0}" -f $allUsers.Count) -ForegroundColor DarkGray

# ── Process ───────────────────────────────────────────────────────────────────
Write-Host "  Processing..." -ForegroundColor DarkGray

$now     = Get-Date
$results = [System.Collections.Generic.List[PSCustomObject]]::new()
$idx     = 0

foreach ($u in $allUsers) {
    $idx++
    Write-Host ("`r  [{0}/{1}]  {2,-50}" -f $idx, $allUsers.Count, `
        $u.DisplayName.PadRight(50).Substring(0, 50)) -NoNewline -ForegroundColor DarkGray

    $sa       = $u.SignInActivity
    $lastSucc = if ($sa -and $sa.LastSuccessfulSignInDateTime)     { [datetime]$sa.LastSuccessfulSignInDateTime     } else { $null }
    $lastInt  = if ($sa -and $sa.LastSignInDateTime)               { [datetime]$sa.LastSignInDateTime               } else { $null }
    $lastNi   = if ($sa -and $sa.LastNonInteractiveSignInDateTime) { [datetime]$sa.LastNonInteractiveSignInDateTime } else { $null }

    $candidates  = @($lastSucc, $lastInt, $lastNi) | Where-Object { $null -ne $_ } | Sort-Object -Descending
    $lastActive  = if ($candidates.Count -gt 0) { $candidates[0] } else { $null }
    $daysSince   = if ($null -ne $lastActive) { [math]::Floor(($now - $lastActive).TotalDays) } else { $null }

    $status = if     ($null -eq $daysSince)           { "NEVER"    }
              elseif ($daysSince -ge $threshDays)      { "INACTIVE" }
              else                                    { "ACTIVE"   }

    $results.Add([PSCustomObject]@{
        DisplayName              = $u.DisplayName
        UserPrincipalName        = $u.UserPrincipalName
        AccountEnabled           = $u.AccountEnabled
        UserType                 = if ($u.UserType) { $u.UserType } else { "Member" }
        CreatedDate              = if ($u.CreatedDateTime) { ([datetime]$u.CreatedDateTime).ToString("yyyy-MM-dd") } else { "" }
        UsageStatus              = $status
        DaysSinceLastActivity    = if ($null -ne $daysSince) { $daysSince } else { "" }
        TrueLastActivity         = if ($null -ne $lastActive) { $lastActive.ToUniversalTime().ToString("yyyy-MM-dd HH:mm UTC") } else { "" }
        LastSuccessfulSignIn     = if ($null -ne $lastSucc) { $lastSucc.ToUniversalTime().ToString("yyyy-MM-dd HH:mm UTC") } else { "" }
        LastInteractiveSignIn    = if ($null -ne $lastInt)  { $lastInt.ToUniversalTime().ToString("yyyy-MM-dd HH:mm UTC")  } else { "" }
        LastNonInteractiveSignIn = if ($null -ne $lastNi)   { $lastNi.ToUniversalTime().ToString("yyyy-MM-dd HH:mm UTC")   } else { "" }
    })
}

Write-Host ""   # clear progress line

# ── Counts ────────────────────────────────────────────────────────────────────
$cntInactive = ($results | Where-Object { $_.UsageStatus -eq "INACTIVE" }).Count
$cntNever    = ($results | Where-Object { $_.UsageStatus -eq "NEVER"    }).Count
$cntActive   = ($results | Where-Object { $_.UsageStatus -eq "ACTIVE"   }).Count

# ── Console output — INACTIVE and NEVER users only ────────────────────────────
$flagged = @($results |
    Where-Object { $_.UsageStatus -in @("INACTIVE","NEVER") } |
    Sort-Object @{Expression = { if ($_.UsageStatus -eq "NEVER") { [int]::MaxValue } else { [int]$_.DaysSinceLastActivity } }; Descending = $true})

if ($flagged.Count -gt 0) {
    Write-Host ""
    Write-Host ("  Inactive / never signed in  —  threshold: {0} days" -f $threshDays) -ForegroundColor Cyan
    Write-Host ""
    Write-Host ("  {0,4}  {1,-36} {2,-36} {3,-10} {4,-8} {5}" -f `
        "#", "Display Name", "UPN", "Status", "Days", "Last Activity") -ForegroundColor Gray
    Write-Host ("  " + ("─" * 110)) -ForegroundColor DarkGray

    for ($i = 0; $i -lt $flagged.Count; $i++) {
        $r      = $flagged[$i]
        $color  = if ($r.UsageStatus -eq "NEVER") { "DarkGray" } else { "Red" }
        $days   = if ($r.DaysSinceLastActivity -ne "") { $r.DaysSinceLastActivity.ToString() } else { "—" }
        $last   = if ($r.TrueLastActivity -ne "") { $r.TrueLastActivity } else { "Never" }
        $name   = if ($r.DisplayName.Length    -gt 35) { $r.DisplayName.Substring(0,34)    + "…" } else { $r.DisplayName    }
        $upn    = if ($r.UserPrincipalName.Length -gt 35) { $r.UserPrincipalName.Substring(0,34) + "…" } else { $r.UserPrincipalName }
        $disabledFlag = if (-not $r.AccountEnabled) { " [DISABLED]" } else { "" }
        $guestFlag    = if ($r.UserType -eq "Guest")   { " [GUEST]"    } else { "" }
        Write-Host ("  {0,4}  {1,-36} {2,-36} {3,-10} {4,-8} {5}{6}{7}" -f `
            ($i + 1), $name, $upn, $r.UsageStatus, $days, $last, $disabledFlag, $guestFlag) -ForegroundColor $color
    }
} else {
    Write-Host ""
    Write-Host ("  No users found inactive beyond {0} days." -f $threshDays) -ForegroundColor Green
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  Summary" -ForegroundColor Gray
Write-Host ("    Total users       : {0}" -f $results.Count)                     -ForegroundColor White
Write-Host ("    INACTIVE (>{0}d)   : {1}" -f $threshDays, $cntInactive)         -ForegroundColor $(if ($cntInactive -gt 0) { "Red"     } else { "Green"   })
Write-Host ("    NEVER signed in   : {0}" -f $cntNever)                          -ForegroundColor $(if ($cntNever    -gt 0) { "DarkGray"} else { "Green"   })
Write-Host ("    ACTIVE            : {0}" -f $cntActive)                         -ForegroundColor Green

# ── CSV export ────────────────────────────────────────────────────────────────
if ($exportFolder) {
    $ts      = Get-Date -Format "yyyyMMdd_HHmmss"
    $csvPath = Join-Path $exportFolder "CheckAllUsersActivity_${threshDays}d_${ts}.csv"
    try {
        $sorted  = @($results | Sort-Object @{
            Expression = { switch ($_.UsageStatus) { "NEVER" {0} "INACTIVE" {1} default {2} } }
        }, @{
            Expression = { if ($_.DaysSinceLastActivity -ne "") { [int]$_.DaysSinceLastActivity } else { [int]::MaxValue } }
            Descending = $true
        })
        $csv = $sorted | ConvertTo-Csv -NoTypeInformation
        [System.IO.File]::WriteAllLines($csvPath, $csv, (New-Object System.Text.UTF8Encoding $true))
        Write-Host ""
        Write-Host ("  CSV exported to: {0}" -f $csvPath) -ForegroundColor Green
    } catch {
        Write-Host ("  CSV export failed: {0}" -f $_) -ForegroundColor Red
    }
}

} catch {
    Write-Host ""
    Write-Host ("ERROR: {0}" -f $_.Exception.Message) -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
} finally {
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
    Write-Host ""
    Write-Host "  Disconnected." -ForegroundColor DarkGray
    Write-Host ""
}
