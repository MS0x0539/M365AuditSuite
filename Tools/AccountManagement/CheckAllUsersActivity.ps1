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
        NEVER      — no sign-in recorded in any field
        ACTIVE     — last activity within the threshold

    Account types are derived from AccountEnabled, license count, mail
    presence, and UserType:

        User              — Member, enabled, has at least one license
        Unlicensed User   — Member, enabled, no licenses
        Disabled User     — Member, disabled, has at least one license
        Shared/Resource   — Member, disabled, no licenses, has mail address
                            (covers shared mailboxes, room and equipment mailboxes)
        System/Orphaned   — Member, disabled, no licenses, no mail address
        Guest             — UserType is Guest

    After loading all users, shows account type counts and prompts for a
    filter so the console output and CSV only include the relevant scope.
    AccountType and LicenseCount are always present as CSV columns for
    further filtering in Excel.

    Read-only — no changes are made to the tenant.

.NOTES
    Author      : Melih Sivrikaya
    Auth        : Certificate-based (app registration: ExportReadAudit)

    Permissions : User.Read.All       — user objects, SignInActivity,
                                        AssignedLicenses, Mail
                  AuditLog.Read.All   — required to read SignInActivity

    Requires    : Microsoft.Graph.Authentication, Microsoft.Graph.Users

    Notes       : SignInActivity is not limited by sign-in log retention.
                  Shared mailboxes and room/equipment mailboxes cannot be
                  distinguished from each other via Graph alone — both appear
                  as Shared/Resource. Use Get-EXOMailbox for exact types.
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

# ── Account type classification ────────────────────────────────────────────────
# Derived from AccountEnabled, license count, mail presence, and UserType.
# Cannot distinguish shared mailboxes from room/equipment mailboxes via Graph
# alone — both are disabled + unlicensed + have a mail address.
function Get-AccountType {
    param(
        [bool]   $Enabled,
        [int]    $LicenseCount,
        [bool]   $HasMail,
        [string] $UserType
    )
    if ($UserType -eq "Guest")                          { return "Guest"            }
    if ($Enabled  -and $LicenseCount -gt 0)             { return "User"             }
    if ($Enabled  -and $LicenseCount -eq 0)             { return "Unlicensed User"  }
    if (-not $Enabled -and $LicenseCount -gt 0)         { return "Disabled User"    }
    if (-not $Enabled -and $LicenseCount -eq 0 -and $HasMail) { return "Shared/Resource" }
    return "System/Orphaned"
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

# ── Threshold prompt ──────────────────────────────────────────────────────────
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

$userProps = "Id,DisplayName,UserPrincipalName,AccountEnabled,UserType,CreatedDateTime,SignInActivity,AssignedLicenses,Mail"
$allUsers  = @(Get-MgUser -All -Property $userProps -ErrorAction Stop)
Write-Host ("  Users found         : {0}" -f $allUsers.Count) -ForegroundColor DarkGray

# ── Process all users ─────────────────────────────────────────────────────────
Write-Host "  Processing..." -ForegroundColor DarkGray

$now     = Get-Date
$results = [System.Collections.Generic.List[PSCustomObject]]::new()
$idx     = 0

foreach ($u in $allUsers) {
    $idx++
    Write-Host ("`r  [{0}/{1}]  {2,-50}" -f $idx, $allUsers.Count, `
        $u.DisplayName.PadRight(50).Substring(0, 50)) -NoNewline -ForegroundColor DarkGray

    # Sign-in activity
    $sa        = $u.SignInActivity
    $lastSucc  = if ($sa -and $sa.LastSuccessfulSignInDateTime)     { [datetime]$sa.LastSuccessfulSignInDateTime     } else { $null }
    $lastInt   = if ($sa -and $sa.LastSignInDateTime)               { [datetime]$sa.LastSignInDateTime               } else { $null }
    $lastNi    = if ($sa -and $sa.LastNonInteractiveSignInDateTime) { [datetime]$sa.LastNonInteractiveSignInDateTime } else { $null }

    $candidates = @($lastSucc, $lastInt, $lastNi) | Where-Object { $null -ne $_ } | Sort-Object -Descending
    $lastActive = if ($candidates.Count -gt 0) { $candidates[0] } else { $null }
    $daysSince  = if ($null -ne $lastActive) { [math]::Floor(($now - $lastActive).TotalDays) } else { $null }
    $status     = if     ($null -eq $daysSince)      { "NEVER"    }
                  elseif ($daysSince -ge $threshDays) { "INACTIVE" }
                  else                               { "ACTIVE"   }

    # Account type
    $licCount   = if ($u.AssignedLicenses) { $u.AssignedLicenses.Count } else { 0 }
    $hasMail    = ($null -ne $u.Mail -and $u.Mail.Length -gt 0)
    $userType   = if ($u.UserType) { $u.UserType } else { "Member" }
    $acctType   = Get-AccountType -Enabled $u.AccountEnabled -LicenseCount $licCount `
                                  -HasMail $hasMail -UserType $userType

    $results.Add([PSCustomObject]@{
        DisplayName              = $u.DisplayName
        UserPrincipalName        = $u.UserPrincipalName
        AccountType              = $acctType
        LicenseCount             = $licCount
        AccountEnabled           = $u.AccountEnabled
        UserType                 = $userType
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

# ── Account type counts ───────────────────────────────────────────────────────
$typeCounts = $results | Group-Object AccountType | Sort-Object Name
Write-Host ""
Write-Host "  Account type breakdown:" -ForegroundColor Gray
foreach ($g in $typeCounts) {
    $col = switch ($g.Name) {
        "User"             { "White"    }
        "Guest"            { "DarkGray" }
        "Service Account"  { "DarkGray" }
        "Disabled User"    { "DarkGray" }
        "Shared/Resource"  { "DarkGray" }
        default            { "DarkGray" }
    }
    Write-Host ("    {0,-20}: {1}" -f $g.Name, $g.Count) -ForegroundColor $col
}

# ── Account type filter prompt ────────────────────────────────────────────────
$cntUsers      = ($results | Where-Object { $_.AccountType -eq "User"                                              }).Count
$cntLicensed   = ($results | Where-Object { $_.LicenseCount -gt 0                                                  }).Count
$cntMembers    = ($results | Where-Object { $_.UserType -eq "Member"                                               }).Count

Write-Host ""
Write-Host "  Account type filter:" -ForegroundColor Cyan
Write-Host ("  [A]  All account types                     ({0})" -f $results.Count) -ForegroundColor White
Write-Host ("  [U]  Users only (Member, enabled, licensed) ({0})" -f $cntUsers)     -ForegroundColor White
Write-Host ("  [L]  Licensed accounts only                ({0})" -f $cntLicensed)   -ForegroundColor White
Write-Host ("  [M]  Members only (excludes guests)        ({0})" -f $cntMembers)    -ForegroundColor White
Write-Host ""

$filterChoice = ""
$validFilters = @("A","U","L","M")
while ($filterChoice -notin $validFilters) {
    $filterChoice = (Read-Host "  Filter").ToUpper().Trim()
    if ($filterChoice -notin $validFilters) { Write-Host "  Enter A, U, L, or M." -ForegroundColor Yellow }
}

$filtered = switch ($filterChoice) {
    "U" { @($results | Where-Object { $_.AccountType -eq "User"            }) }
    "L" { @($results | Where-Object { $_.LicenseCount -gt 0               }) }
    "M" { @($results | Where-Object { $_.UserType -eq "Member"             }) }
    default { @($results) }
}

$filterLabel = switch ($filterChoice) {
    "U" { "Users only (Member, enabled, licensed)" }
    "L" { "Licensed accounts only" }
    "M" { "Members only (excludes guests)" }
    default { "All account types" }
}

# ── Counts within filter ──────────────────────────────────────────────────────
$cntInactive = ($filtered | Where-Object { $_.UsageStatus -eq "INACTIVE" }).Count
$cntNever    = ($filtered | Where-Object { $_.UsageStatus -eq "NEVER"    }).Count
$cntActive   = ($filtered | Where-Object { $_.UsageStatus -eq "ACTIVE"   }).Count

# ── Console output — INACTIVE and NEVER only ──────────────────────────────────
$flagged = @($filtered |
    Where-Object { $_.UsageStatus -in @("INACTIVE","NEVER") } |
    Sort-Object @{Expression = { if ($_.UsageStatus -eq "NEVER") { [int]::MaxValue } else { [int]$_.DaysSinceLastActivity } }; Descending = $true})

Write-Host ""
if ($flagged.Count -gt 0) {
    Write-Host ("  Inactive / never signed in  —  threshold: {0} days  —  {1}" -f $threshDays, $filterLabel) -ForegroundColor Cyan
    Write-Host ""
    Write-Host ("  {0,4}  {1,-30} {2,-34} {3,-18} {4,-10} {5,-8} {6}" -f `
        "#", "Display Name", "UPN", "Account Type", "Status", "Days", "Last Activity") -ForegroundColor Gray
    Write-Host ("  " + ("─" * 120)) -ForegroundColor DarkGray

    for ($i = 0; $i -lt $flagged.Count; $i++) {
        $r     = $flagged[$i]
        $color = if ($r.UsageStatus -eq "NEVER") { "DarkGray" } else { "Red" }
        $days  = if ($r.DaysSinceLastActivity -ne "") { $r.DaysSinceLastActivity.ToString() } else { "—" }
        $last  = if ($r.TrueLastActivity -ne "") { $r.TrueLastActivity } else { "Never" }
        $name  = if ($r.DisplayName.Length       -gt 29) { $r.DisplayName.Substring(0,28)       + "…" } else { $r.DisplayName       }
        $upn   = if ($r.UserPrincipalName.Length -gt 33) { $r.UserPrincipalName.Substring(0,32) + "…" } else { $r.UserPrincipalName }
        Write-Host ("  {0,4}  {1,-30} {2,-34} {3,-18} {4,-10} {5,-8} {6}" -f `
            ($i + 1), $name, $upn, $r.AccountType, $r.UsageStatus, $days, $last) -ForegroundColor $color
    }
} else {
    Write-Host ("  No accounts found inactive beyond {0} days  ({1})." -f $threshDays, $filterLabel) -ForegroundColor Green
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host ("  Summary  —  {0}" -f $filterLabel) -ForegroundColor Gray
Write-Host ("    Accounts in scope : {0}" -f $filtered.Count)                      -ForegroundColor White
Write-Host ("    INACTIVE (>{0}d)   : {1}" -f $threshDays, $cntInactive)           -ForegroundColor $(if ($cntInactive -gt 0) { "Red"      } else { "Green"    })
Write-Host ("    NEVER signed in   : {0}" -f $cntNever)                            -ForegroundColor $(if ($cntNever    -gt 0) { "DarkGray" } else { "Green"    })
Write-Host ("    ACTIVE            : {0}" -f $cntActive)                           -ForegroundColor Green

# ── CSV export ────────────────────────────────────────────────────────────────
if ($exportFolder) {
    $ts      = Get-Date -Format "yyyyMMdd_HHmmss"
    $suffix  = switch ($filterChoice) { "U" {"Users"} "L" {"Licensed"} "M" {"Members"} default {"All"} }
    $csvPath = Join-Path $exportFolder "CheckAllUsersActivity_${threshDays}d_${suffix}_${ts}.csv"
    try {
        $sorted = @($filtered | Sort-Object @{
            Expression = { switch ($_.UsageStatus) { "NEVER" {0} "INACTIVE" {1} default {2} } }
        }, @{
            Expression = { if ($_.DaysSinceLastActivity -ne "") { [int]$_.DaysSinceLastActivity } else { [int]::MaxValue } }
            Descending = $true
        }, AccountType, DisplayName)
        $csv = $sorted | ConvertTo-Csv -NoTypeInformation
        [System.IO.File]::WriteAllLines($csvPath, $csv, (New-Object System.Text.UTF8Encoding $true))
        Write-Host ""
        Write-Host ("  CSV exported to: {0}" -f $csvPath) -ForegroundColor Green
        Write-Host "  Tip: filter the AccountType column in Excel to further narrow the results." -ForegroundColor DarkGray
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
