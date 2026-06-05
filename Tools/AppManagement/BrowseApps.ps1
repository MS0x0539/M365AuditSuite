<#
.SYNOPSIS
    Interactive read-only browser for App Registrations and Enterprise Applications.

.DESCRIPTION
    Connects once, loads all app registration and enterprise application data into
    memory, then presents a menu-driven interface for browsing, filtering, searching,
    and inspecting detail — without making any changes to the tenant.

    App Registrations — filter views:
        All | Privileged | No owner | Expiring / expired credentials |
        Multi-tenant | Search by name

    Enterprise Applications — filter views:
        All | Tenant-owned | Third-party | Disabled |
        Apps with delegated grants | Search by name

    From any list view, enter a number to open the full detail view.
    Use [X] in a list view to export the current list to a timestamped CSV.
    Use [R] from the main menu to reload all data without reconnecting.

.NOTES
    Author      : Melih Sivrikaya
    Auth        : Certificate-based (app registration: ExportReadAudit)

    Permissions : Application.Read.All — app registrations, service principals,
                                         owners, credentials, app role assignments
                  User.Read.All        — resolve owner UPNs to display names

    Optional    : Directory.Read.All   — delegated permission grants (gracefully
                                         skipped if the permission is not granted)
                  AuditLog.Read.All   — SP sign-in activity report (last used dates
                                         per sign-in type; gracefully skipped if absent)

    Requires    : Microsoft.Graph.Authentication, Microsoft.Graph.Applications,
                  Microsoft.Graph.Users
#>

#Requires -Version 5.1

# =====================
# Tenant configuration
# =====================
$TenantId              = "58288310-2b28-42b6-883b-dcef687a4e29"
$AppId                 = "2d048869-cd36-4bf6-baa7-712fc1cb8214"
$CertificateThumbprint = "2BA37CACAA2C69A6F64ADF8587A74D73DBA8ED01"

# =====================
# Credential expiry thresholds (days)
# =====================
$CriticalDays = 14
$WarningDays  = 30
$NoticeDays   = 60

# =====================
# Activity / stale threshold (days)
# =====================
# Apps with no sign-in recorded within this many days are flagged Stale.
# Note: Graph retains sign-in activity for 30 days (P1) or 90 days (P2).
# "No activity" does not mean the app has never been used.
$StaleActivityDays = 90

# ===========================================================================
# SCRIPT INTERNALS — do not edit below this line
# ===========================================================================

# ── In-memory data stores ─────────────────────────────────────────────────────
$script:AllAppRegs        = $null   # [List[PSCustomObject]] processed app registrations
$script:AllEnterpriseApps = $null   # [List[PSCustomObject]] processed service principals
$script:SpByAppId         = @{}     # SP lookup by AppId  (for permission name resolution)
$script:SpById            = @{}     # SP lookup by ObjectId
$script:OAuthGrants        = @{}     # Hashtable: clientObjectId → List[grant]
$script:HasOAuthAccess     = $false  # true when Directory.Read.All is available
$script:ActivityByAppId    = @{}     # Hashtable: appId → SP sign-in activity record
$script:HasActivityAccess  = $false  # true when AuditLog.Read.All is available
$script:TenantDisplay      = ""      # friendly name for header
$script:ExportFolder       = $null   # resolved once after connect

# ── Privileged permission names ───────────────────────────────────────────────
$PrivilegedPermissions = [System.Collections.Generic.HashSet[string]]@(
    "Directory.ReadWrite.All", "Domain.ReadWrite.All", "Organization.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory", "RoleManagementPolicy.ReadWrite.Directory",
    "Policy.ReadWrite.ConditionalAccess", "Policy.ReadWrite.PermissionGrant",
    "Policy.ReadWrite.AuthenticationMethod", "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All", "DelegatedPermissionGrant.ReadWrite.All",
    "User.ReadWrite.All", "UserAuthenticationMethod.ReadWrite.All",
    "PrivilegedAccess.ReadWrite.AzureAD", "PrivilegedAccess.ReadWrite.AzureADGroup",
    "PrivilegedAccess.ReadWrite.AzureResources",
    "PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup",
    "PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup",
    "Group.ReadWrite.All", "GroupMember.ReadWrite.All",
    "Mail.ReadWrite", "Mail.Send", "MailboxSettings.ReadWrite",
    "Files.ReadWrite.All", "Sites.FullControl.All", "Sites.ReadWrite.All",
    "Exchange.ManageAsApp", "full_access_as_app"
)

$MicrosoftTenantId = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"

# ── Expiry helpers ────────────────────────────────────────────────────────────
function Get-ExpiryStatus {
    param([int]$Days)
    if ($Days -le 0)             { return "EXPIRED"  }
    if ($Days -le $CriticalDays) { return "CRITICAL" }
    if ($Days -le $WarningDays)  { return "WARNING"  }
    if ($Days -le $NoticeDays)   { return "NOTICE"   }
    return "OK"
}

function Get-ExpiryColor {
    param([string]$Status)
    switch ($Status) {
        "EXPIRED"  { return "Red"    }
        "CRITICAL" { return "Red"    }
        "WARNING"  { return "Yellow" }
        "NOTICE"   { return "Yellow" }
        default    { return "Green"  }
    }
}

function Get-ExpiryRank {
    param([string]$Status)
    switch ($Status) {
        "EXPIRED"  { return 0 }
        "CRITICAL" { return 1 }
        "WARNING"  { return 2 }
        "NOTICE"   { return 3 }
        "OK"       { return 4 }
        default    { return 5 }   # "NONE" — no credentials
    }
}

function Get-WorstExpiry {
    param([object[]]$ExpiryItems)
    if (-not $ExpiryItems -or $ExpiryItems.Count -eq 0) { return "NONE" }
    $best = 5
    foreach ($c in $ExpiryItems) {
        $r = Get-ExpiryRank $c.Status
        if ($r -lt $best) { $best = $r }
    }
    $map = @{ 0 = "EXPIRED"; 1 = "CRITICAL"; 2 = "WARNING"; 3 = "NOTICE"; 4 = "OK"; 5 = "NONE" }
    return $map[$best]
}

# ── Activity helpers ──────────────────────────────────────────────────────────
# Safely extract a datetime from a beta API response block (hashtable or object).
function Get-ActivityDate {
    param([object]$Block)
    if (-not $Block) { return $null }
    $raw = if ($Block -is [System.Collections.IDictionary]) { $Block['lastSignInDateTime'] }
           else { $Block.lastSignInDateTime }
    if (-not $raw) { return $null }
    try { return [datetime]$raw } catch { return $null }
}

function Get-UsageColor {
    param([string]$Status)
    switch ($Status) {
        "Active"      { return "Green"   }
        "Stale"       { return "Yellow"  }
        "No activity" { return "DarkGray"}
        default       { return "DarkGray"}
    }
}

# ── CSV export ────────────────────────────────────────────────────────────────
function Resolve-ExportFolder {
    param([string]$TenantTag)
    $candidates = @(
        [Environment]::GetFolderPath('Desktop')
        "$env:USERPROFILE\Desktop"
        "C:\Audit"
    )
    foreach ($base in $candidates) {
        if (-not $base) { continue }
        $target = Join-Path $base (Join-Path $TenantTag "AppManagement")
        try {
            New-Item -ItemType Directory -Force -Path $target -ErrorAction Stop | Out-Null
            return $target
        } catch { continue }
    }
    return $null
}

function Export-ListToCsv {
    param([object[]]$Data, [string]$Prefix)
    if (-not $Data -or $Data.Count -eq 0) {
        Write-Host "  Nothing to export." -ForegroundColor Yellow
        return
    }
    if (-not $script:ExportFolder) {
        Write-Host "  Export folder not resolved." -ForegroundColor Red
        return
    }
    $folder = $script:ExportFolder
    $ts   = Get-Date -Format "yyyyMMdd_HHmmss"
    $dest = Join-Path $folder "${Prefix}_${ts}.csv"
    try {
        $csv = $Data | ConvertTo-Csv -NoTypeInformation
        [System.IO.File]::WriteAllLines($dest, $csv, (New-Object System.Text.UTF8Encoding $true))
        Write-Host "  Exported to: $dest" -ForegroundColor Green
    } catch {
        Write-Host "  Export failed: $_" -ForegroundColor Red
    }
}

# ── Page header ───────────────────────────────────────────────────────────────
function Show-Header {
    param([string]$Section = "")
    Write-Host ""
    $heading = "  === App Browser"
    if ($script:TenantDisplay) { $heading += "  |  $($script:TenantDisplay)" }
    if ($Section)              { $heading += "  |  $Section" }
    Write-Host $heading -ForegroundColor Cyan
    Write-Host ("  " + ("─" * 70)) -ForegroundColor DarkGray
}

# ── Data loading ──────────────────────────────────────────────────────────────
function Initialize-AppData {
    Write-Host ""
    Write-Host "  Loading data from Microsoft Graph..." -ForegroundColor Cyan

    # App registrations
    Write-Host "  Fetching app registrations..." -ForegroundColor DarkGray
    $rawApps = Get-MgApplication -All `
        -Property "Id,DisplayName,AppId,CreatedDateTime,SignInAudience,RequiredResourceAccess,Tags,KeyCredentials,PasswordCredentials" `
        -ErrorAction Stop
    Write-Host ("  App registrations  : {0}" -f $rawApps.Count) -ForegroundColor DarkGray

    # Service principals (all — needed for name resolution and enterprise app list)
    Write-Host "  Fetching service principals..." -ForegroundColor DarkGray
    $rawSPs = Get-MgServicePrincipal -All `
        -Property "Id,DisplayName,AppId,AppOwnerOrganizationId,ServicePrincipalType,AccountEnabled,Homepage,Tags,SignInAudience,AppRoles,Oauth2PermissionScopes" `
        -ErrorAction Stop
    Write-Host ("  Service principals : {0}" -f $rawSPs.Count) -ForegroundColor DarkGray

    $script:SpByAppId = @{}
    $script:SpById    = @{}
    foreach ($sp in $rawSPs) {
        $script:SpByAppId[$sp.AppId] = $sp
        $script:SpById[$sp.Id]       = $sp
    }

    # Delegated permission grants (optional — requires Directory.Read.All)
    $script:OAuthGrants    = @{}
    $script:HasOAuthAccess = $false
    try {
        Write-Host "  Fetching delegated permission grants..." -ForegroundColor DarkGray
        $allGrants = Get-MgOauth2PermissionGrant -All -ErrorAction Stop
        foreach ($g in $allGrants) {
            if (-not $script:OAuthGrants[$g.ClientId]) {
                $script:OAuthGrants[$g.ClientId] = [System.Collections.Generic.List[object]]::new()
            }
            $script:OAuthGrants[$g.ClientId].Add($g)
        }
        $script:HasOAuthAccess = $true
        Write-Host ("  Delegated grants   : {0}" -f $allGrants.Count) -ForegroundColor DarkGray
    } catch {
        Write-Host "  Delegated grants   : skipped (Directory.Read.All not granted)" -ForegroundColor DarkGray
    }

    # SP sign-in activity (beta endpoint — optional, requires AuditLog.Read.All)
    $script:ActivityByAppId   = @{}
    $script:HasActivityAccess = $false
    try {
        Write-Host "  Fetching SP sign-in activity..." -ForegroundColor DarkGray
        $actUri   = "https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities?`$top=999"
        $actItems = [System.Collections.Generic.List[object]]::new()
        do {
            $actResponse = Invoke-MgGraphRequest -Method GET -Uri $actUri -ErrorAction Stop
            if ($actResponse['value']) { foreach ($item in $actResponse['value']) { $actItems.Add($item) } }
            $actUri = $actResponse['@odata.nextLink']
        } while ($actUri)
        foreach ($item in $actItems) {
            $aid = if ($item -is [System.Collections.IDictionary]) { $item['appId'] } else { $item.appId }
            if ($aid) { $script:ActivityByAppId[$aid] = $item }
        }
        $script:HasActivityAccess = $true
        Write-Host ("  SP sign-in activity : {0} records" -f $actItems.Count) -ForegroundColor DarkGray
    } catch {
        Write-Host "  SP sign-in activity : skipped (AuditLog.Read.All not granted or beta endpoint unavailable)" -ForegroundColor DarkGray
    }

    $now = Get-Date

    # ── Process app registrations ──────────────────────────────────────────────
    Write-Host "  Processing app registrations (fetching owners)..." -ForegroundColor DarkGray
    $script:AllAppRegs = [System.Collections.Generic.List[PSCustomObject]]::new()
    $appIdx = 0

    foreach ($app in $rawApps) {
        $appIdx++
        Write-Host ("  `r  [{0}/{1}] {2,-50}" -f $appIdx, $rawApps.Count, $app.DisplayName.PadRight(50).Substring(0,50)) -NoNewline -ForegroundColor DarkGray

        # Owners
        $ownerNames = [System.Collections.Generic.List[string]]::new()
        try {
            $owners = Get-MgApplicationOwner -ApplicationId $app.Id -ErrorAction Stop
            foreach ($owner in $owners) {
                $resolved = $null
                try {
                    $u = Get-MgUser -UserId $owner.Id -Property UserPrincipalName -ErrorAction Stop
                    $resolved = $u.UserPrincipalName
                } catch {}
                if (-not $resolved) {
                    try {
                        $sp2 = Get-MgServicePrincipal -ServicePrincipalId $owner.Id -Property DisplayName -ErrorAction Stop
                        $resolved = "$($sp2.DisplayName) [SP]"
                    } catch {}
                }
                $ownerNames.Add($(if ($resolved) { $resolved } else { $owner.Id }))
            }
        } catch {}

        # My Apps visibility
        $ownSP       = $script:SpByAppId[$app.AppId]
        $myAppsLabel = if (-not $ownSP) { "No SP" } elseif ($ownSP.Tags -contains "HideApp") { "Hidden" } else { "Visible" }

        # Permissions
        $appPerms = [System.Collections.Generic.List[PSCustomObject]]::new()
        $delPerms = [System.Collections.Generic.List[PSCustomObject]]::new()

        foreach ($ra in $app.RequiredResourceAccess) {
            $resSP   = $script:SpByAppId[$ra.ResourceAppId]
            $resName = if ($resSP) { $resSP.DisplayName } else { $ra.ResourceAppId }
            foreach ($perm in $ra.ResourceAccess) {
                $permName = $null
                if ($resSP) {
                    $permName = if ($perm.Type -eq "Role") {
                        ($resSP.AppRoles | Where-Object { $_.Id -eq $perm.Id }).Value
                    } else {
                        ($resSP.Oauth2PermissionScopes | Where-Object { $_.Id -eq $perm.Id }).Value
                    }
                }
                if (-not $permName) { $permName = $perm.Id.ToString() }
                $fullName = if ($resName -eq "Microsoft Graph") { $permName } else { "$resName / $permName" }
                $bare     = if ($fullName -match " / (.+)$") { $Matches[1] } else { $fullName }
                $isPriv   = $PrivilegedPermissions.Contains($bare) -or $PrivilegedPermissions.Contains($fullName)
                $permObj  = [PSCustomObject]@{ Name = $fullName; IsPrivileged = $isPriv }
                if ($perm.Type -eq "Role") { $appPerms.Add($permObj) } else { $delPerms.Add($permObj) }
            }
        }

        $privList = [System.Collections.Generic.List[string]]::new()
        foreach ($p in $appPerms) { if ($p.IsPrivileged) { $privList.Add($p.Name) } }
        foreach ($p in $delPerms) { if ($p.IsPrivileged) { $privList.Add($p.Name) } }

        # Credentials
        $creds = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($cert in $app.KeyCredentials) {
            if (-not $cert.EndDateTime) { continue }
            $days  = [math]::Floor(($cert.EndDateTime - $now).TotalDays)
            $thumb = if ($cert.CustomKeyIdentifier) {
                ($cert.CustomKeyIdentifier | ForEach-Object { $_.ToString("X2") }) -join ""
            } else { "" }
            $creds.Add([PSCustomObject]@{
                CredType = "Certificate"
                Name     = if ($cert.DisplayName) { $cert.DisplayName } else { "(no name)" }
                Thumb    = $thumb
                Start    = if ($cert.StartDateTime) { $cert.StartDateTime.ToString("yyyy-MM-dd") } else { "" }
                End      = $cert.EndDateTime.ToString("yyyy-MM-dd")
                Days     = $days
                Status   = Get-ExpiryStatus $days
            })
        }
        foreach ($secret in $app.PasswordCredentials) {
            if (-not $secret.EndDateTime) { continue }
            $days = [math]::Floor(($secret.EndDateTime - $now).TotalDays)
            $creds.Add([PSCustomObject]@{
                CredType = "Secret"
                Name     = if ($secret.DisplayName) { $secret.DisplayName } else { "(no name)" }
                Thumb    = ""
                Start    = if ($secret.StartDateTime) { $secret.StartDateTime.ToString("yyyy-MM-dd") } else { "" }
                End      = $secret.EndDateTime.ToString("yyyy-MM-dd")
                Days     = $days
                Status   = Get-ExpiryStatus $days
            })
        }

        # Federated identity credentials (workload identity federation)
        $fedCreds = [System.Collections.Generic.List[PSCustomObject]]::new()
        try {
            $fedIdentities = Get-MgApplicationFederatedIdentityCredential -ApplicationId $app.Id -All -ErrorAction Stop
            foreach ($f in $fedIdentities) {
                $fedCreds.Add([PSCustomObject]@{
                    Name      = if ($f.Name)     { $f.Name     } else { "(no name)" }
                    Issuer    = if ($f.Issuer)   { $f.Issuer   } else { "" }
                    Subject   = if ($f.Subject)  { $f.Subject  } else { "" }
                    Audiences = if ($f.Audiences){ ($f.Audiences -join ", ") } else { "" }
                })
            }
        } catch {}

        $audienceLabel = switch ($app.SignInAudience) {
            "AzureADMyOrg"                       { "Single-tenant"         }
            "AzureADMultipleOrgs"                { "Multi-tenant"           }
            "AzureADandPersonalMicrosoftAccount" { "Multi-tenant + Personal"}
            default { if ($app.SignInAudience) { $app.SignInAudience } else { "Single-tenant" } }
        }

        # ── Usage / sign-in activity ───────────────────────────────────────────
        # Invoke-MgGraphRequest always returns hashtables; $null['key'] safely returns $null
        $actRecord = $script:ActivityByAppId[$app.AppId]
        $lastAppDt = Get-ActivityDate ($actRecord['lastSignInActivity'])
        $lastDelDt = Get-ActivityDate ($actRecord['lastDelegatedSignInActivity'])
        $lastNiDt  = Get-ActivityDate ($actRecord['lastNonInteractiveSignInActivity'])
        $lastUsedDt  = @($lastAppDt, $lastDelDt, $lastNiDt) | Where-Object { $null -ne $_ } | Sort-Object -Descending | Select-Object -First 1
        $daysSinceUse = if ($null -ne $lastUsedDt) { [math]::Floor(($now - $lastUsedDt).TotalDays) } else { $null }
        $usageStatus  = if     (-not $script:HasActivityAccess)       { "Unknown"     }
                        elseif ($null -eq $lastUsedDt)                 { "No activity" }
                        elseif ($daysSinceUse -le $StaleActivityDays)  { "Active"      }
                        else                                           { "Stale"       }

        $script:AllAppRegs.Add([PSCustomObject]@{
            DisplayName     = $app.DisplayName
            AppId           = $app.AppId
            ObjectId        = $app.Id
            CreatedDate     = if ($app.CreatedDateTime) { $app.CreatedDateTime.ToString("yyyy-MM-dd") } else { "" }
            SignInAudience  = $audienceLabel
            Owners          = $ownerNames
            HasOwner        = ($ownerNames.Count -gt 0)
            AppPerms        = $appPerms
            DelPerms        = $delPerms
            TotalPerms      = $appPerms.Count + $delPerms.Count
            IsPrivileged    = ($privList.Count -gt 0)
            PrivilegedPerms          = $privList
            Creds                    = $creds
            WorstExpiry              = Get-WorstExpiry $creds
            WorstCred                = ($creds | Sort-Object { Get-ExpiryRank $_.Status }, Days | Select-Object -First 1)
            FedCreds                 = $fedCreds
            HasFederation            = ($fedCreds.Count -gt 0)
            MyAppsVisible            = $myAppsLabel
            UsageStatus              = $usageStatus
            LastUsed                 = $lastUsedDt
            DaysSinceUse             = $daysSinceUse
            LastAppSignIn            = $lastAppDt
            LastDelegatedSignIn      = $lastDelDt
            LastNonInteractiveSignIn = $lastNiDt
        })
    }

    Write-Host ""   # clear the progress line

    # ── Process enterprise applications ────────────────────────────────────────
    Write-Host "  Processing enterprise apps..." -ForegroundColor DarkGray
    $script:AllEnterpriseApps = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($sp in $rawSPs) {
        $ownerType = if     ($sp.AppOwnerOrganizationId -eq $MicrosoftTenantId) { "Microsoft"   }
                     elseif (-not $sp.AppOwnerOrganizationId)                   { "Tenant"      }
                     else                                                        { "Third-party" }
        $isHidden  = $sp.Tags -contains "HideApp"
        $hasGrants = $script:HasOAuthAccess -and $script:OAuthGrants.ContainsKey($sp.Id)

        $script:AllEnterpriseApps.Add([PSCustomObject]@{
            DisplayName          = $sp.DisplayName
            AppId                = $sp.AppId
            ObjectId             = $sp.Id
            ServicePrincipalType = if ($sp.ServicePrincipalType) { $sp.ServicePrincipalType } else { "—" }
            OwnerType            = $ownerType
            AppOwnerOrgId        = if ($sp.AppOwnerOrganizationId) { $sp.AppOwnerOrganizationId } else { "—" }
            AccountEnabled       = $sp.AccountEnabled
            SignInAudience       = if ($sp.SignInAudience) { $sp.SignInAudience } else { "—" }
            Homepage             = if ($sp.Homepage) { $sp.Homepage } else { "—" }
            VisibleInMyApps      = if ($isHidden) { "Hidden" } else { "Visible" }
            HasDelegatedGrants   = $hasGrants
        })
    }

    Write-Host ""
    Write-Host ("  Ready.  App registrations: {0}  |  Enterprise apps: {1}" -f `
        $script:AllAppRegs.Count, $script:AllEnterpriseApps.Count) -ForegroundColor Green
}

# ── App Registration — sub-menu ───────────────────────────────────────────────
function Show-AppRegMenu {
    :appregmenu while ($true) {
        $cntAll    = $script:AllAppRegs.Count
        $cntPriv   = ($script:AllAppRegs | Where-Object { $_.IsPrivileged }).Count
        $cntNoOwn  = ($script:AllAppRegs | Where-Object { -not $_.HasOwner }).Count
        $cntExpiry = ($script:AllAppRegs | Where-Object { $_.WorstExpiry -in @("EXPIRED","CRITICAL","WARNING","NOTICE") }).Count
        $cntMulti  = ($script:AllAppRegs | Where-Object { $_.SignInAudience -ne "Single-tenant" }).Count
        $cntStale  = ($script:AllAppRegs | Where-Object { $_.UsageStatus -in @("Stale","No activity") }).Count

        Show-Header "App Registrations"
        Write-Host ""
        Write-Host ("  Total: {0}  |  Privileged: {1}  |  No owner: {2}  |  Expiring: {3}  |  Multi-tenant: {4}" -f `
            $cntAll, $cntPriv, $cntNoOwn, $cntExpiry, $cntMulti) -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  [A]  All app registrations              ($cntAll)" -ForegroundColor White
        if ($cntPriv  -gt 0) { Write-Host "  [B]  Privileged apps only               ($cntPriv)"   -ForegroundColor Red    }
        else                 { Write-Host "  [B]  Privileged apps only               (none)"        -ForegroundColor DarkGray }
        if ($cntNoOwn -gt 0) { Write-Host "  [C]  Apps without an owner              ($cntNoOwn)"  -ForegroundColor Yellow }
        else                 { Write-Host "  [C]  Apps without an owner              (none)"        -ForegroundColor DarkGray }
        if ($cntExpiry -gt 0){ Write-Host "  [D]  Expiring / expired credentials     ($cntExpiry)" -ForegroundColor Yellow }
        else                 { Write-Host "  [D]  Expiring / expired credentials     (none)"        -ForegroundColor DarkGray }
        if ($cntMulti -gt 0) { Write-Host "  [E]  Multi-tenant apps                  ($cntMulti)"  -ForegroundColor Yellow }
        else                 { Write-Host "  [E]  Multi-tenant apps                  (none)"        -ForegroundColor DarkGray }
        if ($script:HasActivityAccess) {
            if ($cntStale -gt 0) { Write-Host "  [F]  No recent activity / stale         ($cntStale)" -ForegroundColor Yellow }
            else                 { Write-Host "  [F]  No recent activity / stale         (none)"       -ForegroundColor DarkGray }
        } else {
            Write-Host "  [F]  No recent activity / stale         (requires AuditLog.Read.All)" -ForegroundColor DarkGray
        }
        Write-Host "  [S]  Search by name" -ForegroundColor White
        Write-Host "  [Q]  Back" -ForegroundColor DarkGray
        Write-Host ""

        $choice = (Read-Host "  Choice").ToUpper().Trim()
        switch ($choice) {
            "A" {
                Show-AppRegList -Apps @($script:AllAppRegs | Sort-Object DisplayName) `
                    -Title "All App Registrations" -CsvPrefix "AppRegs_All"
            }
            "B" {
                $f = @($script:AllAppRegs | Where-Object { $_.IsPrivileged } | Sort-Object DisplayName)
                Show-AppRegList -Apps $f -Title "Privileged App Registrations" -CsvPrefix "AppRegs_Privileged"
            }
            "C" {
                $f = @($script:AllAppRegs | Where-Object { -not $_.HasOwner } | Sort-Object DisplayName)
                Show-AppRegList -Apps $f -Title "App Registrations Without an Owner" -CsvPrefix "AppRegs_NoOwner"
            }
            "D" {
                $f = @($script:AllAppRegs |
                    Where-Object { $_.WorstExpiry -in @("EXPIRED","CRITICAL","WARNING","NOTICE") } |
                    Sort-Object { Get-ExpiryRank $_.WorstExpiry }, DisplayName)
                Show-AppRegList -Apps $f -Title "Apps with Expiring / Expired Credentials" -CsvPrefix "AppRegs_Expiry"
            }
            "E" {
                $f = @($script:AllAppRegs | Where-Object { $_.SignInAudience -ne "Single-tenant" } | Sort-Object DisplayName)
                Show-AppRegList -Apps $f -Title "Multi-tenant App Registrations" -CsvPrefix "AppRegs_MultiTenant"
            }
            "F" {
                if (-not $script:HasActivityAccess) {
                    Write-Host "  SKIP: AuditLog.Read.All is not granted for this app registration." -ForegroundColor Yellow
                    Read-Host "  [Enter] Continue"
                } else {
                    # Sort stale (recorded but old) before no-activity, then by days desc
                    $f = @($script:AllAppRegs |
                        Where-Object { $_.UsageStatus -in @("Stale","No activity") } |
                        Sort-Object @{Expression={ if ($_.UsageStatus -eq "Stale") { 0 } else { 1 } }},
                                    @{Expression={ if ($null -ne $_.DaysSinceUse) { $_.DaysSinceUse } else { [int]::MaxValue } }; Descending=$true})
                    Show-AppRegList -Apps $f -Title "No Recent Activity / Stale Apps" -CsvPrefix "AppRegs_Stale"
                }
            }
            "S" {
                Write-Host ""
                $term = (Read-Host "  Search term").Trim()
                if ($term) {
                    $f = @($script:AllAppRegs | Where-Object { $_.DisplayName -like "*$term*" } | Sort-Object DisplayName)
                    Show-AppRegList -Apps $f -Title "Search: '$term'" -CsvPrefix "AppRegs_Search_$($term -replace '[^\w]','_')"
                }
            }
            "Q" { return }
        }
    }
}

# ── App Registration — list view ──────────────────────────────────────────────
function Show-AppRegList {
    param(
        [object[]]$Apps,
        [string]  $Title,
        [string]  $CsvPrefix
    )

    if (-not $Apps -or $Apps.Count -eq 0) {
        Write-Host ""
        Write-Host "  No app registrations match this filter." -ForegroundColor Yellow
        Read-Host "  [Enter] Back"
        return
    }

    :listloop while ($true) {
        Show-Header $Title
        Write-Host ""
        Write-Host ("  {0,4}  {1,-44} {2,-22} {3,-6} {4,-6} {5,-19}" -f `
            "#", "Display Name", "Sign-in Audience", "Perms", "Owner", "Cred Expiry") -ForegroundColor Gray
        Write-Host ("  " + ("─" * 108)) -ForegroundColor DarkGray

        for ($i = 0; $i -lt $Apps.Count; $i++) {
            $a       = $Apps[$i]
            $flags   = ""
            if ($a.IsPrivileged)              { $flags += " [PRIVILEGED]"   }
            if (-not $a.HasOwner)             { $flags += " [NO OWNER]"     }
            if ($a.UsageStatus -eq "Stale")   { $flags += " [STALE]"        }
            if ($a.UsageStatus -eq "No activity" -and $script:HasActivityAccess) { $flags += " [NO ACTIVITY]" }
            $color   = if     ($a.IsPrivileged)                                        { "Red"    }
                       elseif (-not $a.HasOwner)                                       { "Yellow" }
                       elseif ($a.WorstExpiry -in @("EXPIRED","CRITICAL"))             { "Red"    }
                       elseif ($a.WorstExpiry -in @("WARNING","NOTICE"))               { "Yellow" }
                       elseif ($a.UsageStatus -eq "Stale")                             { "Yellow" }
                       else                                                            { "Green"  }
            $ownerStr  = if ($a.HasOwner) { "Yes" } else { "No" }
            $expiryStr = if (-not $a.WorstCred) { "—" } else {
                $wc = $a.WorstCred
                if ($wc.Days -le 0) { "$($wc.Status) ($([math]::Abs($wc.Days))d ago)" }
                else                { "$($wc.Status) ($($wc.Days)d)"                   }
            }
            $nameStr   = if ($a.DisplayName.Length -gt 44) { $a.DisplayName.Substring(0,41) + "..." } else { $a.DisplayName }
            Write-Host ("  {0,4}  {1,-44} {2,-22} {3,-6} {4,-6} {5,-19}{6}" -f `
                ($i + 1), $nameStr, $a.SignInAudience, $a.TotalPerms, $ownerStr, $expiryStr, $flags) -ForegroundColor $color
        }

        Write-Host ""
        Write-Host ("  Total: {0}" -f $Apps.Count) -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Enter a # for full detail, [X] export to CSV, or [Q] Back" -ForegroundColor DarkGray
        $userInput = (Read-Host "  Choice").Trim()

        if ($userInput -match '^\d+$') {
            $idx = [int]$userInput - 1
            if ($idx -ge 0 -and $idx -lt $Apps.Count) {
                Show-AppRegDetail -App $Apps[$idx]
            } else {
                Write-Host "  Number out of range (1–$($Apps.Count))." -ForegroundColor Yellow
            }
        } elseif ($userInput.ToUpper() -eq "X") {
            # Flatten for CSV (lists → semicolon-joined strings)
            $csvRows = $Apps | ForEach-Object {
                $certCreds   = @($_.Creds | Where-Object { $_.CredType -eq "Certificate" })
                $secretCreds = @($_.Creds | Where-Object { $_.CredType -eq "Secret"      })
                [PSCustomObject]@{
                    DisplayName            = $_.DisplayName
                    AppId                  = $_.AppId
                    ObjectId               = $_.ObjectId
                    CreatedDate            = $_.CreatedDate
                    SignInAudience         = $_.SignInAudience
                    IsPrivileged           = $_.IsPrivileged
                    TotalPermissions       = $_.TotalPerms
                    HasOwner               = $_.HasOwner
                    Owners                 = ($_.Owners -join "; ")
                    VisibleInMyApps        = $_.MyAppsVisible
                    UsageStatus            = $_.UsageStatus
                    LastUsed               = if ($_.LastUsed)                { $_.LastUsed.ToString("yyyy-MM-dd") }                else { "" }
                    DaysSinceLastUse       = if ($null -ne $_.DaysSinceUse)  { $_.DaysSinceUse }                                  else { "" }
                    LastAppCredSignIn      = if ($_.LastAppSignIn)           { $_.LastAppSignIn.ToString("yyyy-MM-dd") }           else { "" }
                    LastDelegatedSignIn    = if ($_.LastDelegatedSignIn)     { $_.LastDelegatedSignIn.ToString("yyyy-MM-dd") }     else { "" }
                    LastNonInteractiveSignIn = if ($_.LastNonInteractiveSignIn) { $_.LastNonInteractiveSignIn.ToString("yyyy-MM-dd") } else { "" }
                    HasCertificate         = ($certCreds.Count -gt 0)
                    WorstCertExpiry        = Get-WorstExpiry $certCreds
                    Certificates           = (($certCreds | Sort-Object Days | ForEach-Object {
                                                "$($_.Name)  |  expires $($_.End)  |  $($_.Status)"
                                            }) -join "; ")
                    HasSecret              = ($secretCreds.Count -gt 0)
                    WorstSecretExpiry      = Get-WorstExpiry $secretCreds
                    Secrets                = (($secretCreds | Sort-Object Days | ForEach-Object {
                                                "$($_.Name)  |  expires $($_.End)  |  $($_.Status)"
                                            }) -join "; ")
                    HasFederation          = $_.HasFederation
                    FederationCredentials  = (($_.FedCreds | ForEach-Object {
                                                "$($_.Name)  |  $($_.Issuer) / $($_.Subject)"
                                            }) -join "; ")
                    PrivilegedPermissions  = ($_.PrivilegedPerms -join "; ")
                    ApplicationPermissions = (($_.AppPerms | ForEach-Object { $_.Name }) -join "; ")
                    DelegatedPermissions   = (($_.DelPerms | ForEach-Object { $_.Name }) -join "; ")
                }
            }
            Export-ListToCsv -Data $csvRows -Prefix $CsvPrefix
            Read-Host "  [Enter] Continue"
        } elseif ($userInput.ToUpper() -eq "Q") {
            return
        }
    }
}

# ── App Registration — detail view ────────────────────────────────────────────
function Show-AppRegDetail {
    param([PSCustomObject]$App)

    Show-Header "App Registration Detail"
    Write-Host ""
    Write-Host ("  {0}" -f $App.DisplayName) -ForegroundColor White
    Write-Host ""
    Write-Host ("  App ID        : {0}" -f $App.AppId)          -ForegroundColor DarkGray
    Write-Host ("  Object ID     : {0}" -f $App.ObjectId)       -ForegroundColor DarkGray
    Write-Host ("  Created       : {0}" -f $App.CreatedDate)    -ForegroundColor DarkGray
    $audColor = if ($App.SignInAudience -ne "Single-tenant") { "Yellow" } else { "DarkGray" }
    Write-Host ("  Audience      : {0}" -f $App.SignInAudience) -ForegroundColor $audColor
    Write-Host ("  MyApps        : {0}" -f $App.MyAppsVisible)  -ForegroundColor DarkGray

    # Owners
    Write-Host ""
    if ($App.HasOwner) {
        Write-Host "  Owners:" -ForegroundColor Gray
        foreach ($o in $App.Owners) {
            Write-Host ("    • {0}" -f $o) -ForegroundColor White
        }
    } else {
        Write-Host "  Owners        : [NONE ASSIGNED]" -ForegroundColor Yellow
    }

    # Application permissions
    if ($App.AppPerms.Count -gt 0) {
        Write-Host ""
        Write-Host ("  Application Permissions ({0}):" -f $App.AppPerms.Count) -ForegroundColor Gray
        foreach ($p in ($App.AppPerms | Sort-Object @{Expression="IsPrivileged";Descending=$true}, Name)) {
            if ($p.IsPrivileged) {
                Write-Host ("    • {0}  [PRIVILEGED]" -f $p.Name) -ForegroundColor Red
            } else {
                Write-Host ("    • {0}" -f $p.Name) -ForegroundColor White
            }
        }
    }

    # Delegated permissions
    if ($App.DelPerms.Count -gt 0) {
        Write-Host ""
        Write-Host ("  Delegated Permissions ({0}):" -f $App.DelPerms.Count) -ForegroundColor Gray
        foreach ($p in ($App.DelPerms | Sort-Object @{Expression="IsPrivileged";Descending=$true}, Name)) {
            if ($p.IsPrivileged) {
                Write-Host ("    • {0}  [PRIVILEGED]" -f $p.Name) -ForegroundColor Red
            } else {
                Write-Host ("    • {0}" -f $p.Name) -ForegroundColor DarkGray
            }
        }
    }

    if ($App.TotalPerms -eq 0) {
        Write-Host ""
        Write-Host "  Permissions   : (none declared)" -ForegroundColor DarkGray
    }

    # Sign-in activity
    Write-Host ""
    Write-Host "  Sign-in Activity:" -ForegroundColor Gray
    if (-not $script:HasActivityAccess) {
        Write-Host "    (AuditLog.Read.All not granted — activity data unavailable)" -ForegroundColor DarkGray
    } else {
        $usageColor = Get-UsageColor $App.UsageStatus
        Write-Host ("    Status           : {0}" -f $App.UsageStatus) -ForegroundColor $usageColor
        if ($null -ne $App.LastUsed) {
            Write-Host ("    Last used (any)  : {0}  ({1}d ago)" -f $App.LastUsed.ToString("yyyy-MM-dd"), $App.DaysSinceUse) -ForegroundColor $usageColor
        } else {
            Write-Host "    Last used (any)  : No activity recorded in retention window" -ForegroundColor DarkGray
        }
        if ($App.LastAppSignIn)             { Write-Host ("    App credential   : {0}" -f $App.LastAppSignIn.ToString("yyyy-MM-dd"))            -ForegroundColor DarkGray }
        if ($App.LastDelegatedSignIn)       { Write-Host ("    Delegated        : {0}" -f $App.LastDelegatedSignIn.ToString("yyyy-MM-dd"))      -ForegroundColor DarkGray }
        if ($App.LastNonInteractiveSignIn)  { Write-Host ("    Non-interactive  : {0}" -f $App.LastNonInteractiveSignIn.ToString("yyyy-MM-dd")) -ForegroundColor DarkGray }
        Write-Host "    Note: retention is 30d (P1) / 90d (P2) — no activity in window does not mean never used." -ForegroundColor DarkGray
    }

    # Credentials
    Write-Host ""
    if ($App.Creds.Count -gt 0) {
        Write-Host "  Credentials:" -ForegroundColor Gray
        foreach ($c in ($App.Creds | Sort-Object Days)) {
            $color     = Get-ExpiryColor $c.Status
            $daysLabel = if ($c.Days -le 0) { "EXPIRED $([math]::Abs($c.Days))d ago" } else { "in $($c.Days)d" }
            $thumbStr  = if ($c.Thumb -and $c.Thumb.Length -gt 0) {
                "  Thumb: $($c.Thumb.Substring(0, [math]::Min(16, $c.Thumb.Length)))..."
            } else { "" }
            Write-Host ("    [{0,-8}] {1,-14} {2,-30} expires {3}  ({4}){5}" -f `
                $c.Status, $c.CredType, $c.Name, $c.End, $daysLabel, $thumbStr) -ForegroundColor $color
        }
    } else {
        Write-Host "  Credentials   : (none)" -ForegroundColor DarkGray
    }

    # Federated identity credentials
    Write-Host ""
    if ($App.HasFederation) {
        Write-Host ("  Federated Identity Credentials ({0}):" -f $App.FedCreds.Count) -ForegroundColor Gray
        foreach ($f in $App.FedCreds) {
            Write-Host ("    • {0}" -f $f.Name) -ForegroundColor Cyan
            if ($f.Issuer)    { Write-Host ("      Issuer    : {0}" -f $f.Issuer)    -ForegroundColor DarkGray }
            if ($f.Subject)   { Write-Host ("      Subject   : {0}" -f $f.Subject)   -ForegroundColor DarkGray }
            if ($f.Audiences) { Write-Host ("      Audiences : {0}" -f $f.Audiences) -ForegroundColor DarkGray }
        }
    } else {
        Write-Host "  Federation    : (none)" -ForegroundColor DarkGray
    }

    Write-Host ""
    Read-Host "  [Enter] Back to list"
}

# ── Enterprise Applications — sub-menu ───────────────────────────────────────
function Show-EnterpriseAppMenu {
    :eamenu while ($true) {
        $cntAll       = $script:AllEnterpriseApps.Count
        $cntTenant    = ($script:AllEnterpriseApps | Where-Object { $_.OwnerType -eq "Tenant"      }).Count
        $cntMs        = ($script:AllEnterpriseApps | Where-Object { $_.OwnerType -eq "Microsoft"   }).Count
        $cntThird     = ($script:AllEnterpriseApps | Where-Object { $_.OwnerType -eq "Third-party" }).Count
        $cntDisabled  = ($script:AllEnterpriseApps | Where-Object { $_.AccountEnabled -eq $false   }).Count
        $cntGrants    = ($script:AllEnterpriseApps | Where-Object { $_.HasDelegatedGrants           }).Count

        Show-Header "Enterprise Applications"
        Write-Host ""
        Write-Host ("  Total: {0}  |  Tenant: {1}  |  Microsoft: {2}  |  Third-party: {3}  |  Disabled: {4}" -f `
            $cntAll, $cntTenant, $cntMs, $cntThird, $cntDisabled) -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  [A]  All enterprise applications        ($cntAll)"    -ForegroundColor White
        Write-Host "  [B]  Tenant-owned only                  ($cntTenant)" -ForegroundColor White
        if ($cntThird   -gt 0) { Write-Host "  [C]  Third-party only                  ($cntThird)"   -ForegroundColor Yellow }
        else                   { Write-Host "  [C]  Third-party only                  (none)"         -ForegroundColor DarkGray }
        if ($cntDisabled -gt 0){ Write-Host "  [D]  Disabled applications              ($cntDisabled)" -ForegroundColor Red    }
        else                   { Write-Host "  [D]  Disabled applications              (none)"         -ForegroundColor DarkGray }
        if ($script:HasOAuthAccess) {
            if ($cntGrants -gt 0) { Write-Host "  [E]  Apps with delegated grants         ($cntGrants)" -ForegroundColor Yellow }
            else                  { Write-Host "  [E]  Apps with delegated grants         (none)"        -ForegroundColor DarkGray }
        } else {
            Write-Host "  [E]  Apps with delegated grants         (requires Directory.Read.All)" -ForegroundColor DarkGray
        }
        Write-Host "  [S]  Search by name" -ForegroundColor White
        Write-Host "  [Q]  Back" -ForegroundColor DarkGray
        Write-Host ""

        $choice = (Read-Host "  Choice").ToUpper().Trim()
        switch ($choice) {
            "A" {
                Show-EnterpriseAppList -Apps @($script:AllEnterpriseApps | Sort-Object OwnerType, DisplayName) `
                    -Title "All Enterprise Applications" -CsvPrefix "EnterpriseApps_All"
            }
            "B" {
                $f = @($script:AllEnterpriseApps | Where-Object { $_.OwnerType -eq "Tenant" } | Sort-Object DisplayName)
                Show-EnterpriseAppList -Apps $f -Title "Tenant-Owned Enterprise Applications" -CsvPrefix "EnterpriseApps_Tenant"
            }
            "C" {
                $f = @($script:AllEnterpriseApps | Where-Object { $_.OwnerType -eq "Third-party" } | Sort-Object DisplayName)
                Show-EnterpriseAppList -Apps $f -Title "Third-Party Enterprise Applications" -CsvPrefix "EnterpriseApps_ThirdParty"
            }
            "D" {
                $f = @($script:AllEnterpriseApps | Where-Object { $_.AccountEnabled -eq $false } | Sort-Object DisplayName)
                Show-EnterpriseAppList -Apps $f -Title "Disabled Enterprise Applications" -CsvPrefix "EnterpriseApps_Disabled"
            }
            "E" {
                if (-not $script:HasOAuthAccess) {
                    Write-Host "  SKIP: Directory.Read.All is not granted for this app registration." -ForegroundColor Yellow
                    Read-Host "  [Enter] Continue"
                } else {
                    $f = @($script:AllEnterpriseApps | Where-Object { $_.HasDelegatedGrants } | Sort-Object DisplayName)
                    Show-EnterpriseAppList -Apps $f -Title "Apps with Delegated Permission Grants" -CsvPrefix "EnterpriseApps_Grants"
                }
            }
            "S" {
                Write-Host ""
                $term = (Read-Host "  Search term").Trim()
                if ($term) {
                    $f = @($script:AllEnterpriseApps | Where-Object { $_.DisplayName -like "*$term*" } | Sort-Object DisplayName)
                    Show-EnterpriseAppList -Apps $f -Title "Search: '$term'" `
                        -CsvPrefix "EnterpriseApps_Search_$($term -replace '[^\w]','_')"
                }
            }
            "Q" { return }
        }
    }
}

# ── Enterprise Applications — list view ───────────────────────────────────────
function Show-EnterpriseAppList {
    param(
        [object[]]$Apps,
        [string]  $Title,
        [string]  $CsvPrefix
    )

    if (-not $Apps -or $Apps.Count -eq 0) {
        Write-Host ""
        Write-Host "  No enterprise applications match this filter." -ForegroundColor Yellow
        Read-Host "  [Enter] Back"
        return
    }

    :listloop while ($true) {
        Show-Header $Title
        Write-Host ""
        Write-Host ("  {0,4}  {1,-45} {2,-22} {3,-14} {4}" -f `
            "#", "Display Name", "Type", "Owner", "Enabled") -ForegroundColor Gray
        Write-Host ("  " + ("─" * 98)) -ForegroundColor DarkGray

        for ($i = 0; $i -lt $Apps.Count; $i++) {
            $a = $Apps[$i]
            $color = if     ($a.AccountEnabled -eq $false)        { "Red"     }
                     elseif ($a.OwnerType -eq "Tenant")           { "Green"   }
                     elseif ($a.OwnerType -eq "Third-party")      { "Yellow"  }
                     else                                         { "DarkGray"}
            $enabledStr = if ($a.AccountEnabled) { "Enabled" } else { "Disabled" }
            $grantsFlag = if ($a.HasDelegatedGrants) { " [GRANTS]" } else { "" }
            $nameStr    = if ($a.DisplayName.Length -gt 45) { $a.DisplayName.Substring(0,42) + "..." } else { $a.DisplayName }
            Write-Host ("  {0,4}  {1,-45} {2,-22} {3,-14} {4}{5}" -f `
                ($i + 1), $nameStr, $a.ServicePrincipalType, $a.OwnerType, $enabledStr, $grantsFlag) -ForegroundColor $color
        }

        Write-Host ""
        Write-Host ("  Total: {0}" -f $Apps.Count) -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Enter a # for full detail, [X] export to CSV, or [Q] Back" -ForegroundColor DarkGray
        $userInput = (Read-Host "  Choice").Trim()

        if ($userInput -match '^\d+$') {
            $idx = [int]$userInput - 1
            if ($idx -ge 0 -and $idx -lt $Apps.Count) {
                Show-EnterpriseAppDetail -Sp $Apps[$idx]
            } else {
                Write-Host "  Number out of range (1–$($Apps.Count))." -ForegroundColor Yellow
            }
        } elseif ($userInput.ToUpper() -eq "X") {
            $csvRows = $Apps | ForEach-Object {
                [PSCustomObject]@{
                    DisplayName          = $_.DisplayName
                    AppId                = $_.AppId
                    ObjectId             = $_.ObjectId
                    ServicePrincipalType = $_.ServicePrincipalType
                    OwnerType            = $_.OwnerType
                    AppOwnerOrgId        = $_.AppOwnerOrgId
                    AccountEnabled       = $_.AccountEnabled
                    VisibleInMyApps      = $_.VisibleInMyApps
                    SignInAudience       = $_.SignInAudience
                    Homepage             = $_.Homepage
                    HasDelegatedGrants   = $_.HasDelegatedGrants
                }
            }
            Export-ListToCsv -Data $csvRows -Prefix $CsvPrefix
            Read-Host "  [Enter] Continue"
        } elseif ($userInput.ToUpper() -eq "Q") {
            return
        }
    }
}

# ── Enterprise Applications — detail view ─────────────────────────────────────
function Show-EnterpriseAppDetail {
    param([PSCustomObject]$Sp)

    Show-Header "Enterprise Application Detail"
    Write-Host ""
    Write-Host ("  {0}" -f $Sp.DisplayName) -ForegroundColor White
    Write-Host ""
    Write-Host ("  App ID        : {0}" -f $Sp.AppId)                -ForegroundColor DarkGray
    Write-Host ("  Object ID     : {0}" -f $Sp.ObjectId)             -ForegroundColor DarkGray
    Write-Host ("  Type          : {0}" -f $Sp.ServicePrincipalType) -ForegroundColor DarkGray
    $ownerColor = if ($Sp.OwnerType -eq "Third-party") { "Yellow" } elseif ($Sp.OwnerType -eq "Tenant") { "Green" } else { "DarkGray" }
    Write-Host ("  Owner         : {0}" -f $Sp.OwnerType)            -ForegroundColor $ownerColor
    if ($Sp.AppOwnerOrgId -ne "—") {
        Write-Host ("  Owner Org ID  : {0}" -f $Sp.AppOwnerOrgId)   -ForegroundColor DarkGray
    }
    $enabledColor = if ($Sp.AccountEnabled) { "Green" } else { "Red" }
    Write-Host ("  Enabled       : {0}" -f $Sp.AccountEnabled)       -ForegroundColor $enabledColor
    Write-Host ("  MyApps        : {0}" -f $Sp.VisibleInMyApps)      -ForegroundColor DarkGray
    if ($Sp.SignInAudience -ne "—") {
        Write-Host ("  Audience      : {0}" -f $Sp.SignInAudience)   -ForegroundColor DarkGray
    }
    if ($Sp.Homepage -ne "—") {
        Write-Host ("  Homepage      : {0}" -f $Sp.Homepage)         -ForegroundColor DarkGray
    }

    # Granted application permissions
    Write-Host ""
    Write-Host "  Granted Application Permissions:" -ForegroundColor Gray
    try {
        $assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $Sp.ObjectId -All -ErrorAction Stop
        if ($assignments -and $assignments.Count -gt 0) {
            foreach ($a in ($assignments | Sort-Object ResourceDisplayName)) {
                $resourceSP = $script:SpById[$a.ResourceId]
                $roleName   = if ($resourceSP) {
                    $role = $resourceSP.AppRoles | Where-Object { $_.Id -eq $a.AppRoleId }
                    if ($role -and $role.Value) { $role.Value } else { $a.AppRoleId.ToString() }
                } else { $a.AppRoleId.ToString() }
                $resName  = if ($a.ResourceDisplayName) { $a.ResourceDisplayName } else { $a.ResourceId.ToString() }
                $fullName = if ($resName -eq "Microsoft Graph") { $roleName } else { "$resName / $roleName" }
                $bare     = if ($fullName -match " / (.+)$") { $Matches[1] } else { $fullName }
                $isPriv   = $PrivilegedPermissions.Contains($bare) -or $PrivilegedPermissions.Contains($fullName)
                if ($isPriv) {
                    Write-Host ("    • {0}  [PRIVILEGED]" -f $fullName) -ForegroundColor Red
                } else {
                    Write-Host ("    • {0}" -f $fullName) -ForegroundColor White
                }
            }
        } else {
            Write-Host "    (none)" -ForegroundColor DarkGray
        }
    } catch {
        Write-Host ("    (could not retrieve: {0})" -f $_.Exception.Message) -ForegroundColor DarkGray
    }

    # Delegated permission grants
    if ($script:HasOAuthAccess) {
        Write-Host ""
        Write-Host "  Delegated Permission Grants:" -ForegroundColor Gray
        $grants = $script:OAuthGrants[$Sp.ObjectId]
        if ($grants -and $grants.Count -gt 0) {
            foreach ($g in $grants) {
                $resName   = if ($script:SpById[$g.ResourceId]) { $script:SpById[$g.ResourceId].DisplayName } else { $g.ResourceId }
                $grantedTo = if ($g.ConsentType -eq "AllPrincipals") { "All users (admin consent)" } else {
                    try { (Get-MgUser -UserId $g.PrincipalId -Property UserPrincipalName -ErrorAction Stop).UserPrincipalName }
                    catch { $g.PrincipalId }
                }
                $scopeStr  = if ($g.Scope) { $g.Scope.Trim() } else { "(none)" }
                $scopeDisp = if ($scopeStr.Length -gt 100) { $scopeStr.Substring(0,97) + "..." } else { $scopeStr }
                $grantColor = if ($g.ConsentType -eq "AllPrincipals") { "Yellow" } else { "DarkGray" }
                Write-Host ("    Resource  : {0}" -f $resName)     -ForegroundColor White
                Write-Host ("    Granted to: {0}" -f $grantedTo)   -ForegroundColor $grantColor
                Write-Host ("    Scopes    : {0}" -f $scopeDisp)   -ForegroundColor DarkGray
                Write-Host ""
            }
        } else {
            Write-Host "    (none)" -ForegroundColor DarkGray
        }
    }

    Write-Host ""
    Read-Host "  [Enter] Back to list"
}

# ── Main menu ─────────────────────────────────────────────────────────────────
function Show-MainMenu {
    :mainloop while ($true) {
        Show-Header
        Write-Host ""
        Write-Host ("  [1]  App Registrations       ({0} apps)" -f $script:AllAppRegs.Count)        -ForegroundColor White
        Write-Host ("  [2]  Enterprise Applications  ({0} apps)" -f $script:AllEnterpriseApps.Count) -ForegroundColor White
        Write-Host "  [R]  Refresh data" -ForegroundColor DarkGray
        Write-Host "  [Q]  Quit" -ForegroundColor DarkGray
        Write-Host ""

        $choice = (Read-Host "  Choice").ToUpper().Trim()
        switch ($choice) {
            "1" { Show-AppRegMenu }
            "2" { Show-EnterpriseAppMenu }
            "R" { Initialize-AppData }
            "Q" { break mainloop }
        }
    }
}

# ── Entry point ───────────────────────────────────────────────────────────────

# Module check
$requiredModules = @(
    "Microsoft.Graph.Authentication"
    "Microsoft.Graph.Applications"
    "Microsoft.Graph.Users"
)
foreach ($mod in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod -ErrorAction SilentlyContinue)) {
        Write-Host "FATAL: Required module '$mod' is not installed." -ForegroundColor Red
        Write-Host "       Run: Install-Module $mod -Scope CurrentUser" -ForegroundColor Yellow
        exit 1
    }
}
Import-Module Microsoft.Graph.Authentication, Microsoft.Graph.Applications, Microsoft.Graph.Users `
    -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "  === App Browser — Entra ID" -ForegroundColor Cyan
Write-Host "  Connecting to Microsoft Graph..." -ForegroundColor DarkGray

try {
    Connect-MgGraph `
        -TenantId              $TenantId `
        -AppId                 $AppId `
        -CertificateThumbprint $CertificateThumbprint `
        -NoWelcome `
        -ErrorAction Stop

    # Try to resolve a friendly tenant display name
    try {
        $org = Get-MgOrganization -Property DisplayName -ErrorAction Stop | Select-Object -First 1
        $script:TenantDisplay = if ($org -and $org.DisplayName) { $org.DisplayName } else { $TenantId }
    } catch {
        $script:TenantDisplay = $TenantId
    }

    # Resolve export folder once — Desktop (OneDrive) → Desktop → C:\Audit\
    $tenantTag            = $script:TenantDisplay -replace '[^A-Za-z0-9_-]', ''
    $script:ExportFolder  = Resolve-ExportFolder -TenantTag $tenantTag
    if (-not $script:ExportFolder) {
        Write-Host "  WARN: Could not create export folder under any Desktop location — CSV exports will fail." -ForegroundColor Yellow
    }

    Write-Host ("  Connected: {0}" -f $script:TenantDisplay) -ForegroundColor Green
} catch {
    Write-Host "FATAL: Could not connect to Microsoft Graph: $_" -ForegroundColor Red
    exit 1
}

try {
    Initialize-AppData
    Show-MainMenu
} catch {
    Write-Host ""
    Write-Host ("ERROR: {0}" -f $_.Exception.Message) -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
} finally {
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
    Write-Host ""
    Write-Host "  Disconnected. Goodbye." -ForegroundColor DarkGray
    Write-Host ""
}
