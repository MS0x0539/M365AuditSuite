<#
.SYNOPSIS
    Checks all available sign-in activity sources for a user to determine
    whether they have been inactive for a specified number of days.

.DESCRIPTION
    Comprehensive inactivity check covering every available sign-in source:

    Source 1 — SignInActivity on the user record (authoritative, not retention-limited):
        • lastSuccessfulSignInDateTime      — most recent successful sign-in of any type
        • lastSignInDateTime                — most recent interactive sign-in
        • lastNonInteractiveSignInDateTime  — most recent token refresh / silent sign-in

    Source 2 — Sign-in log events within the threshold window (detailed evidence):
        • Interactive and non-interactive events from the audit log
        • Per event: date/time, type, application, IP address, result, risk level

    The definitive "last active" date is the most recent timestamp across all
    sources. A clear colour-coded ACTIVE / INACTIVE verdict is printed with
    supporting detail.

    Prompts for a user (UPN or display name) and an inactivity threshold in days.
    Read-only — no changes are made to the tenant.

.NOTES
    Author      : Melih Sivrikaya
    Auth        : Certificate-based (app registration: ExportReadAudit)

    Permissions : User.Read.All       — user object and SignInActivity property
                  AuditLog.Read.All   — sign-in log events and SignInActivity reads

    Requires    : Microsoft.Graph.Authentication, Microsoft.Graph.Users,
                  Microsoft.Graph.Identity.SignIns

    Notes       : Sign-in log retention is 30 days (Entra ID P1) or 90 days (P2).
                  Activity older than the retention window is still reflected in the
                  SignInActivity dates on the user record — those are the authoritative
                  source for inactivity determination.
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
    "Microsoft.Graph.Identity.SignIns"
)
foreach ($mod in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod -ErrorAction SilentlyContinue)) {
        Write-Host "FATAL: Required module '$mod' is not installed." -ForegroundColor Red
        Write-Host "       Run: Install-Module $mod -Scope CurrentUser" -ForegroundColor Yellow
        exit 1
    }
}
Import-Module Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Identity.SignIns `
    -ErrorAction SilentlyContinue

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-SignInRow {
    param(
        [string]  $Label,
        [object]  $Date,
        [int]     $ThresholdDays,
        [datetime]$Now
    )
    if ($null -eq $Date) {
        Write-Host ("    {0,-36}: Never recorded" -f $Label) -ForegroundColor DarkGray
        return
    }
    $dt   = [datetime]$Date
    $days = [math]::Floor(($Now - $dt).TotalDays)
    $col  = if ($days -ge $ThresholdDays) { "Yellow" } else { "Green" }
    Write-Host ("    {0,-36}: {1}  ({2}d ago)" -f $Label, $dt.ToUniversalTime().ToString("yyyy-MM-dd HH:mm UTC"), $days) `
        -ForegroundColor $col
}

function Write-VerdictBox {
    param([string]$Color, [string[]]$Lines)
    $innerWidth = ($Lines | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum + 4
    if ($innerWidth -lt 50) { $innerWidth = 50 }
    $bar = "═" * $innerWidth
    Write-Host ("  ╔{0}╗" -f $bar) -ForegroundColor $Color
    foreach ($line in $Lines) {
        $padding = $innerWidth - $line.Length - 2
        Write-Host ("  ║  {0}{1}║" -f $line, ("" * $padding).PadRight($padding)) -ForegroundColor $Color
    }
    Write-Host ("  ╚{0}╝" -f $bar) -ForegroundColor $Color
}

# ── Connect ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  === CheckUserActivity" -ForegroundColor Cyan
Write-Host "  Connecting to Microsoft Graph..." -ForegroundColor DarkGray
Write-Host ""

try {
    Connect-MgGraph `
        -TenantId              $TenantId `
        -AppId                 $AppId `
        -CertificateThumbprint $CertificateThumbprint `
        -NoWelcome `
        -ErrorAction Stop
    Write-Host "  Connected." -ForegroundColor Green
} catch {
    Write-Host "FATAL: Could not connect to Microsoft Graph: $_" -ForegroundColor Red
    exit 1
}

try {

# ── Input ─────────────────────────────────────────────────────────────────────
Write-Host ""
$userQuery = (Read-Host "  User (UPN or display name)").Trim()
if (-not $userQuery) {
    Write-Host "  No user entered." -ForegroundColor Yellow; exit 0
}

$threshDays = 0
do {
    $threshStr   = (Read-Host "  Inactivity threshold (days)").Trim()
    $validThresh = [int]::TryParse($threshStr, [ref]$threshDays) -and $threshDays -gt 0
    if (-not $validThresh) { Write-Host "  Enter a positive whole number." -ForegroundColor Yellow }
} while (-not $validThresh)

# ── Resolve user ──────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  Resolving user..." -ForegroundColor DarkGray

$userProps = "Id,DisplayName,UserPrincipalName,AccountEnabled,UserType,CreatedDateTime,SignInActivity"
$mgUser    = $null

try {
    $mgUser = Get-MgUser -UserId $userQuery -Property $userProps -ErrorAction Stop
} catch {
    try {
        $escaped  = $userQuery -replace "'", "''"
        $found    = @(Get-MgUser -Filter "displayName eq '$escaped'" -Property $userProps -Top 10 -ErrorAction Stop)
        if ($found.Count -eq 1) {
            $mgUser = $found[0]
        } elseif ($found.Count -gt 1) {
            Write-Host "  Multiple users found — select one:" -ForegroundColor Yellow
            Write-Host ""
            for ($i = 0; $i -lt $found.Count; $i++) {
                Write-Host ("    [{0}]  {1,-42} {2}" -f ($i + 1), $found[$i].DisplayName, $found[$i].UserPrincipalName) -ForegroundColor White
            }
            Write-Host ""
            $pick     = (Read-Host "  Number").Trim()
            $pickIdx  = 0
            if ([int]::TryParse($pick, [ref]$pickIdx) -and $pickIdx -ge 1 -and $pickIdx -le $found.Count) {
                $mgUser = $found[$pickIdx - 1]
            }
        }
    } catch {}
}

if (-not $mgUser) {
    Write-Host "  User not found: '$userQuery'" -ForegroundColor Red; exit 1
}

$now = Get-Date

# ── Extract SignInActivity from user record ────────────────────────────────────
$sa                 = $mgUser.SignInActivity
$lastInteractive    = if ($sa -and $sa.LastSignInDateTime)               { [datetime]$sa.LastSignInDateTime               } else { $null }
$lastNonInteractive = if ($sa -and $sa.LastNonInteractiveSignInDateTime) { [datetime]$sa.LastNonInteractiveSignInDateTime } else { $null }
$lastSuccessful     = if ($sa -and $sa.LastSuccessfulSignInDateTime)     { [datetime]$sa.LastSuccessfulSignInDateTime     } else { $null }

# ── Fetch sign-in log events ──────────────────────────────────────────────────
Write-Host "  Fetching sign-in log events (last $threshDays days)..." -ForegroundColor DarkGray

$logEvents = @()
$logFailed = $false
try {
    $startStr  = $now.AddDays(-$threshDays).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $logFilter = "userId eq '$($mgUser.Id)' and createdDateTime ge $startStr"
    $logEvents = @(Get-MgAuditLogSignIn -Filter $logFilter -All -Top 500 -ErrorAction Stop |
                   Sort-Object CreatedDateTime -Descending)
    Write-Host ("  Sign-in events      : {0}" -f $logEvents.Count) -ForegroundColor DarkGray
} catch {
    $logFailed = $true
    Write-Host ("  Sign-in log unavailable: {0}" -f $_.Exception.Message) -ForegroundColor DarkGray
}

# ── Determine true last activity ──────────────────────────────────────────────
$candidates   = @($lastInteractive, $lastNonInteractive, $lastSuccessful)
if ($logEvents.Count -gt 0) { $candidates += [datetime]$logEvents[0].CreatedDateTime }
$candidates   = $candidates | Where-Object { $null -ne $_ } | Sort-Object -Descending
$lastActivity = if ($candidates.Count -gt 0) { $candidates[0] } else { $null }
$daysSince    = if ($null -ne $lastActivity) { [math]::Floor(($now - $lastActivity).TotalDays) } else { $null }
$isInactive   = ($null -eq $daysSince) -or ($daysSince -ge $threshDays)

# ── Output ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host ("  === {0}  ({1})" -f $mgUser.UserPrincipalName, $mgUser.DisplayName) -ForegroundColor Cyan
Write-Host ("  " + ("─" * 70)) -ForegroundColor DarkGray

# Account info
Write-Host ""
Write-Host "  Account" -ForegroundColor Gray
Write-Host ("    {0,-36}: {1}" -f "Enabled", (if ($mgUser.AccountEnabled) { "Yes" } else { "No — already disabled" })) `
    -ForegroundColor (if ($mgUser.AccountEnabled) { "White" } else { "Red" })
Write-Host ("    {0,-36}: {1}" -f "User type", (if ($mgUser.UserType) { $mgUser.UserType } else { "Member" })) `
    -ForegroundColor DarkGray
$createdStr = if ($mgUser.CreatedDateTime) { ([datetime]$mgUser.CreatedDateTime).ToString("yyyy-MM-dd") } else { "Unknown" }
Write-Host ("    {0,-36}: {1}" -f "Created", $createdStr) -ForegroundColor DarkGray

# Sign-in activity from user record
Write-Host ""
Write-Host "  Sign-in Activity  —  user record  (authoritative, not retention-limited)" -ForegroundColor Gray
Write-SignInRow -Label "Last successful (any type)"  -Date $lastSuccessful     -ThresholdDays $threshDays -Now $now
Write-SignInRow -Label "Last interactive"            -Date $lastInteractive    -ThresholdDays $threshDays -Now $now
Write-SignInRow -Label "Last non-interactive"        -Date $lastNonInteractive -ThresholdDays $threshDays -Now $now

# Sign-in log events
Write-Host ""
Write-Host ("  Sign-in Log Events  —  last {0} days  (audit log)" -f $threshDays) -ForegroundColor Gray

if ($logFailed) {
    Write-Host "    Could not retrieve log events (AuditLog.Read.All may not be granted)." -ForegroundColor DarkGray
} elseif ($logEvents.Count -eq 0) {
    Write-Host "    No events found in this window." -ForegroundColor DarkGray
    Write-Host "    (Logs retain 30d on P1 / 90d on P2 — older activity is in the user record above.)" -ForegroundColor DarkGray
} else {
    $shown = [math]::Min($logEvents.Count, 25)
    Write-Host ""
    Write-Host ("  {0,-20} {1,-18} {2,-32} {3,-18} {4,-9} {5}" -f `
        "Date / Time (UTC)", "Type", "Application", "IP Address", "Result", "Risk") -ForegroundColor Gray
    Write-Host ("  " + ("─" * 103)) -ForegroundColor DarkGray

    for ($i = 0; $i -lt $shown; $i++) {
        $ev     = $logEvents[$i]
        $dt     = ([datetime]$ev.CreatedDateTime).ToUniversalTime().ToString("yyyy-MM-dd HH:mm")
        $types  = $ev.SignInEventTypes
        $evType = if (-not $types -or $types.Count -eq 0)         { "Interactive"     }
                  elseif ($types -contains "nonInteractiveUser")   { "Non-interactive" }
                  elseif ($types -contains "interactiveUser")      { "Interactive"     }
                  else                                             { $types[0]         }
        $app    = if ($ev.AppDisplayName) {
                      if ($ev.AppDisplayName.Length -gt 31) { $ev.AppDisplayName.Substring(0,30) + "…" }
                      else { $ev.AppDisplayName }
                  } else { "—" }
        $ip     = if ($ev.IpAddress) { $ev.IpAddress } else { "—" }
        $result = if ($ev.Status -and $ev.Status.ErrorCode -eq 0) { "Success" } else { "Failure" }
        $risk   = if ($ev.RiskLevelDuringSignIn -and
                      $ev.RiskLevelDuringSignIn -notin @("none","hidden","unknownFutureValue")) {
                      $ev.RiskLevelDuringSignIn
                  } else { "—" }
        $col    = if   ($result -eq "Failure") { "Yellow" }
                  elseif ($risk -ne "—")        { "Yellow" }
                  else                          { "White"  }
        Write-Host ("  {0,-20} {1,-18} {2,-32} {3,-18} {4,-9} {5}" -f `
            $dt, $evType, $app, $ip, $result, $risk) -ForegroundColor $col
    }

    if ($logEvents.Count -gt 25) {
        Write-Host ("  ... {0} more events not shown (use AuditSuite report [15] for full export)." -f ($logEvents.Count - 25)) `
            -ForegroundColor DarkGray
    }
}

# ── Verdict ───────────────────────────────────────────────────────────────────
Write-Host ""

$lastStr = if ($null -ne $lastActivity) {
    "$($lastActivity.ToUniversalTime().ToString('yyyy-MM-dd HH:mm UTC'))  ($daysSince days ago)"
} else {
    "No activity found in any source"
}

if ($isInactive) {
    $daysOver = if ($null -ne $daysSince) { $daysSince - $threshDays } else { $null }
    $overLine = if ($null -ne $daysOver)  { "$daysOver days past the $threshDays-day threshold" } else { "No activity on record in any source" }
    Write-VerdictBox -Color "Red" -Lines @(
        "VERDICT  :  INACTIVE",
        "Last activity : $lastStr",
        "Threshold     : $threshDays days",
        $overLine
    )
} else {
    Write-VerdictBox -Color "Green" -Lines @(
        "VERDICT  :  ACTIVE",
        "Last activity : $lastStr",
        "Threshold     : $threshDays days",
        "Within the inactivity threshold"
    )
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
