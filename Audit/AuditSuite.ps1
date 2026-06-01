<#
.SYNOPSIS
    Entra / M365 audit suite — twenty-eight reports in one interactive script, plus an HTML executive report when running all.

.DESCRIPTION
    Presents a menu to run any of the following audit reports:

      [1]  Conditional Access Policy Report
           All CA policies with resolved users, groups, roles, apps, and locations.

      [2]  License Usage
           All subscribed SKUs with purchased / consumed / available unit counts.

      [3]  App Registration Security Audit
           All app registrations: permissions, owners, privileged flag, My Apps visibility.

      [4]  App Registration Expiry
           All certificates and client secrets, categorised by days until expiry.

      [5]  Device Export
           All Entra devices with Intune sync, compliance, stale, and owner data.

      [6]  Role Assignments
           All active and eligible (PIM) Entra ID role assignments with group expansion.

      [7]  Role Policies
           PIM policy settings per role: activation, eligible/active assignment, notifications.

      [8]  PIM Activation & Request History
           Recent role activation requests, admin assignments, approvals, and denials with justification.

      [9]  PIM Security Alerts
           Active PIM security alerts: too many privileged users, roles activated without MFA, and more.

      [10] Find Inactive Devices
           Devices inactive beyond a configurable threshold (Entra + Intune last activity).

      [11] Find Inactive Users
           Users with no sign-in activity beyond a configurable threshold.

      [12] Domain Export
           All verified and unverified domains with type, services, and federation status.

      [13] Guest User Report
           All external/guest accounts with state, sign-in activity, and pending invitations.

      [14] Group Export
           All groups with type, dynamic/assigned, member count, owner count, and visibility.

      [15] Sign-in Log Export
           Recent sign-in events with IP, location, risk level, device, and CA status.

      [16] Directory Audit Log
           Recent directory changes — who changed what, categorised by activity type.

      [17] Enterprise Applications Export
           All service principals with owner type (Tenant / Microsoft / Third-party) and status.

      [18] Delegated Permission Grants
           OAuth consent grants — which apps users or admins have consented to and what scopes.

      [19] Authentication Methods Policy
           Tenant-wide authentication method configuration (FIDO2, Authenticator, SMS, TAP, etc.)

      [20] Named Locations Export
           All named locations (IP-based and country-based) with IP ranges, trusted flag, and country codes.

      [21] Security Defaults Status
           Whether Security Defaults are enabled or disabled, with a note if it conflicts with CA policies.

      [22] External Collaboration / B2B Settings
           Guest invite permissions, guest user role, email-verified join, and default member permissions.

      [23] Administrative Units
           All AUs with member counts, scoped admin assignments, and membership type (assigned vs dynamic).

      [24] Intune Compliance Policies
           All compliance policies with platform, assignment targets, and unassigned policy flags.

      [25] Risky Users
           Identity Protection users currently flagged as at-risk with risk level, state, and last event.

      [26] Risk Detections
           Individual risk events (leaked credentials, atypical travel, anonymous IP, etc.) by lookback period.

      [27] Microsoft Secure Score
           Current tenant score vs max, comparisons to industry/all tenants, and top improvement actions.

      [28] M365 Usage Reports
           Active users, email activity, Teams usage, OneDrive and SharePoint usage by selected period.

      [A]  Run all reports

    Connects once, runs the chosen report(s), then disconnects.
    All CSV exports land in a per-tenant subfolder. The script tries locations in order:
    Desktop (OneDrive), Desktop (default), C:\Audit\. First writable location wins.

.NOTES
    Author      : Melih Sivrikaya
    Auth        : Certificate-based (app registration: ExportReadAudit)

    Permissions : All permissions are application-type and require admin consent.
                  Policy.Read.All                         — CA policies, auth methods, security defaults, B2B settings
                  User.Read.All                           — users, sign-in activity, inactive users
                  Group.Read.All                          — groups, members, owners
                  Directory.Read.All                      — domains, administrative units, directory objects
                  RoleManagement.Read.Directory           — role assignments, PIM policies, activation history
                  Application.Read.All                    — app registrations, service principals, permission grants
                  Device.Read.All                         — Entra device objects
                  DeviceManagementManagedDevices.Read.All — Intune device sync data
                  DeviceManagementConfiguration.Read.All  — Intune compliance policies
                  AuditLog.Read.All                       — sign-in logs, directory audit logs, PIM history
                  Domain.Read.All                         — tenant domain information
                  RoleManagementAlert.Read.Directory      — PIM security alerts
                  PrivilegedAccess.Read.AzureAD           — PIM privileged access for Azure AD roles
                  PrivilegedAccess.Read.AzureADGroup      — PIM privileged access for groups
                  IdentityRiskyUser.Read.All              — risky users (requires Entra ID P2)
                  IdentityRiskEvent.Read.All              — risk detections (requires Entra ID P2)
                  SecurityEvents.Read.All                 — Microsoft Secure Score
                  Reports.Read.All                        — M365 usage reports

    Requires    : Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns,
                  Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Users,
                  Microsoft.Graph.Groups, Microsoft.Graph.Applications,
                  Microsoft.Graph.DeviceManagement, Microsoft.Graph.Identity.Governance,
                  Microsoft.Graph.Reports

    Notes       : [25] and [26] will fail gracefully if the tenant does not have Entra ID P2.
                  [26] User and site names in usage reports may appear as hashed IDs if the tenant
                  has "Conceal user, group, and site names in all reports" enabled. This is a
                  tenant-level privacy setting found in M365 Admin Center → Settings → Org settings
                  → Services → Reports. Disable it to see real names in usage exports.
#>

#Requires -Version 5.1

# =====================
# Tenant configuration
# =====================
# CertificateThumbprint is shared across all tenants.
# Add TenantId + AppId for each tenant as you on-board them.
$CertificateThumbprint = "2BA37CACAA2C69A6F64ADF8587A74D73DBA8ED01"

$Tenants = @(
    [PSCustomObject]@{ Name = "PSBV"; TenantId = "58288310-2b28-42b6-883b-dcef687a4e29"; AppId = "2d048869-cd36-4bf6-baa7-712fc1cb8214" }
    [PSCustomObject]@{ Name = "Tenant2"; TenantId = ""; AppId = "" }
    [PSCustomObject]@{ Name = "Tenant3"; TenantId = ""; AppId = "" }
)

# =====================
# Report configuration
# =====================
# [4] App Registration Expiry — days-to-expiry thresholds
$CriticalDays = 14
$WarningDays  = 30
$NoticeDays   = 60

# [5] Device Export — devices not seen for longer than this are flagged stale
$StaleDays = 90

# ===========================================================================
# SCRIPT INTERNALS — do not edit below this line
# ===========================================================================

# ── Export folder resolution ──────────────────────────────────────────────────
# Tries locations in order; uses the first one where a subfolder can be created:
#   1. System Desktop (OneDrive Desktop if synced)
#   2. Default user Desktop ($env:USERPROFILE\Desktop)
#   3. C:\Audit\ (created if it does not exist)
function Resolve-ExportFolder {
    param([string]$TenantTag)
    $candidates = @(
        [Environment]::GetFolderPath('Desktop')
        "$env:USERPROFILE\Desktop"
        "C:\Audit"
    )
    foreach ($base in $candidates) {
        if (-not $base) { continue }
        $target = Join-Path $base $TenantTag
        try {
            New-Item -ItemType Directory -Force -Path $target -ErrorAction Stop | Out-Null
            return $target
        } catch {
            continue
        }
    }
    return $null
}
$script:ExportFolder = $null   # resolved after tenant selection

# ── Executive report findings collector ───────────────────────────────────────
$script:Findings = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-Finding {
    param(
        [string] $Category,
        [ValidateSet("Critical","High","Medium","Low","Info")]
        [string] $Severity,
        [string] $Title,
        [string] $Detail,
        [string] $Recommendation
    )
    $script:Findings.Add([PSCustomObject]@{
        Category       = $Category
        Severity       = $Severity
        Title          = $Title
        Detail         = $Detail
        Recommendation = $Recommendation
    })
}

# ── Shared lookup tables ───────────────────────────────────────────────────────

$TrustTypeLabels = @{
    "AzureAd"   = "Entra Joined"
    "ServerAd"  = "Hybrid Entra Joined"
    "Workplace" = "Entra Registered"
}

$SkuNames = @{
    "SPB"                          = "Microsoft 365 Business Premium"
    "O365_BUSINESS_PREMIUM"        = "Microsoft 365 Business Premium"
    "M365_BUSINESS"                = "Microsoft 365 Business Premium"
    "SMB_BUSINESS_PREMIUM"         = "Microsoft 365 Business Premium"
    "O365_BUSINESS_ESSENTIALS"     = "Microsoft 365 Business Basic"
    "SMB_BUSINESS_ESSENTIALS"      = "Microsoft 365 Business Basic"
    "O365_BUSINESS"                = "Microsoft 365 Apps for Business"
    "SMB_BUSINESS"                 = "Microsoft 365 Apps for Business"
    "MCOMEETADV"                   = "Microsoft 365 Audio Conferencing"
    "SPE_E3"                       = "Microsoft 365 E3"
    "SPE_E5"                       = "Microsoft 365 E5"
    "SPE_F1"                       = "Microsoft 365 F1"
    "STANDARDPACK"                 = "Office 365 E1"
    "ENTERPRISEPACK"               = "Office 365 E3"
    "ENTERPRISEPREMIUM"            = "Office 365 E5"
    "DESKLESSPACK"                 = "Office 365 F3"
    "EXCHANGESTANDARD"             = "Exchange Online Plan 1"
    "EXCHANGEENTERPRISE"           = "Exchange Online Plan 2"
    "EXCHANGEARCHIVE_ADDON"        = "Exchange Online Archiving (add-on)"
    "SHAREPOINTSTANDARD"           = "SharePoint Online Plan 1"
    "SHAREPOINTENTERPRISE"         = "SharePoint Online Plan 2"
    "WACONEDRIVESTANDARD"          = "OneDrive for Business Plan 1"
    "WACONEDRIVEENTERPRISE"        = "OneDrive for Business Plan 2"
    "MCOSTANDARD"                  = "Skype for Business Online Plan 2"
    "MCOEV"                        = "Microsoft Teams Phone Standard"
    "MCOPSTN1"                     = "Teams Domestic Calling Plan"
    "MCOPSTN2"                     = "Teams Domestic & International Calling Plan"
    "TEAMS_EXPLORATORY"            = "Microsoft Teams Exploratory"
    "EMS"                          = "Enterprise Mobility + Security E3"
    "EMSPREMIUM"                   = "Enterprise Mobility + Security E5"
    "AAD_PREMIUM"                  = "Entra ID P1 (Azure AD Premium P1)"
    "AAD_PREMIUM_P2"               = "Entra ID P2 (Azure AD Premium P2)"
    "INTUNE_A"                     = "Microsoft Intune Plan 1"
    "WIN_DEF_ATP"                  = "Microsoft Defender for Endpoint P2"
    "DEFENDER_ENDPOINT_P1"         = "Microsoft Defender for Endpoint P1"
    "ATP_ENTERPRISE"               = "Microsoft Defender for Office 365 P1"
    "THREAT_INTELLIGENCE"          = "Microsoft Defender for Office 365 P2"
    "RIGHTSMANAGEMENT"             = "Azure Information Protection P1"
    "PROJECTESSENTIALS"            = "Project Plan 1"
    "PROJECTPROFESSIONAL"          = "Project Plan 3"
    "PROJECTPREMIUM"               = "Project Plan 5"
    "VISIOONLINE_PLAN1"            = "Visio Plan 1"
    "VISIOCLIENT"                  = "Visio Plan 2"
    "POWER_BI_STANDARD"            = "Power BI Free"
    "POWER_BI_PRO"                 = "Power BI Pro"
    "POWER_BI_PREMIUM_PER_USER"    = "Power BI Premium Per User"
    "POWERAPPS_PER_USER"           = "Power Apps per User Plan"
    "FLOW_FREE"                    = "Power Automate Free"
    "WIN10_PRO_ENT_SUB"            = "Windows Enterprise E3"
}

$SpecialUserValues = @{
    "All"                   = "All Users"
    "GuestsOrExternalUsers" = "Guests or External Users"
    "None"                  = "None"
}

$SpecialAppValues = @{
    "All"                   = "All Applications"
    "None"                  = "None"
    "Office365"             = "Office 365"
    "MicrosoftAdminPortals" = "Microsoft Admin Portals"
}

$UserActionLabels = @{
    "urn:user:registersecurityinfo" = "Register security info"
    "urn:user:registerdevice"       = "Register or join device"
}

$CAStateLabels = @{
    "enabled"                           = "Enabled"
    "disabled"                          = "Disabled"
    "enabledForReportingButNotEnforced" = "Report-only"
}

$GrantLabels = @{
    "mfa"                  = "Require MFA"
    "compliantDevice"      = "Require Compliant Device"
    "domainJoinedDevice"   = "Require Hybrid Entra Joined"
    "approvedApplication"  = "Require Approved App"
    "compliantApplication" = "Require App Protection Policy"
    "passwordChange"       = "Require Password Change"
    "block"                = "Block Access"
}

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

# ── Shared resolution caches (reset before each CA report run) ─────────────────
$script:_UserCache  = @{}
$script:_GroupCache = @{}
$script:_AppCache   = @{}

# ── Shared helper functions ────────────────────────────────────────────────────

function Resolve-User {
    param([string]$Id)
    if ($SpecialUserValues[$Id])                { return $SpecialUserValues[$Id] }
    if ($script:_UserCache.ContainsKey($Id))    { return $script:_UserCache[$Id] }
    try {
        $u = Get-MgUser -UserId $Id -Property UserPrincipalName -ErrorAction Stop
        $script:_UserCache[$Id] = $u.UserPrincipalName; return $u.UserPrincipalName
    } catch { $script:_UserCache[$Id] = $Id; return $Id }
}

function Resolve-Group {
    param([string]$Id)
    if ($script:_GroupCache.ContainsKey($Id))   { return $script:_GroupCache[$Id] }
    try {
        $g = Get-MgGroup -GroupId $Id -Property DisplayName -ErrorAction Stop
        $script:_GroupCache[$Id] = $g.DisplayName; return $g.DisplayName
    } catch { $script:_GroupCache[$Id] = $Id; return $Id }
}

function Resolve-App {
    param([string]$Id)
    if ($SpecialAppValues[$Id])                 { return $SpecialAppValues[$Id] }
    if ($script:_AppCache.ContainsKey($Id))     { return $script:_AppCache[$Id] }
    try {
        $sp = Get-MgServicePrincipal -Filter "appId eq '$Id'" -Property DisplayName -ErrorAction Stop |
              Select-Object -First 1
        $name = if ($sp) { $sp.DisplayName } else { $Id }
        $script:_AppCache[$Id] = $name; return $name
    } catch { $script:_AppCache[$Id] = $Id; return $Id }
}

function Resolve-List {
    param([string[]]$Ids, [scriptblock]$Resolver)
    if (-not $Ids -or $Ids.Count -eq 0) { return "—" }
    return ($Ids | ForEach-Object { & $Resolver $_ }) -join " | "
}

function Format-GrantControls {
    param($Grant)
    if (-not $Grant) { return "—" }
    $controls = @()
    foreach ($c in $Grant.BuiltInControls) {
        $label = if ($GrantLabels[$c]) { $GrantLabels[$c] } else { $c }
        $controls += $label
    }
    if ($Grant.AuthenticationStrength -and $Grant.AuthenticationStrength.DisplayName) {
        $controls += $Grant.AuthenticationStrength.DisplayName
    }
    if ($controls.Count -eq 0) { return "—" }
    $sep = if ($Grant.Operator -eq "AND") { " + " } else { " or " }
    return $controls -join $sep
}

function Format-SessionControls {
    param($Session)
    if (-not $Session) { return "—" }
    $parts = @()
    if ($Session.SignInFrequency -and $null -ne $Session.SignInFrequency.Value) {
        $parts += "Sign-in frequency: $($Session.SignInFrequency.Value) $($Session.SignInFrequency.Type)"
    }
    if ($Session.PersistentBrowser -and $Session.PersistentBrowser.Mode) {
        $parts += "Persistent browser: $($Session.PersistentBrowser.Mode)"
    }
    if ($Session.ApplicationEnforcedRestrictions -and $Session.ApplicationEnforcedRestrictions.IsEnabled) {
        $parts += "App enforced restrictions"
    }
    if ($Session.CloudAppSecurity -and $Session.CloudAppSecurity.IsEnabled) {
        $parts += "Cloud App Security: $($Session.CloudAppSecurity.CloudAppSecurityType)"
    }
    if ($parts.Count -eq 0) { return "—" }
    return $parts -join " | "
}

function Write-CsvBom {
    param([object[]]$Data, [string]$Path)
    if (-not $Data -or $Data.Count -eq 0) {
        Write-Host "  No data to export — CSV skipped." -ForegroundColor DarkGray
        return
    }
    $dest = Join-Path $script:ExportFolder (Split-Path $Path -Leaf)
    try {
        $csv = $Data | ConvertTo-Csv -NoTypeInformation
        [System.IO.File]::WriteAllLines($dest, $csv, (New-Object System.Text.UTF8Encoding $true))
        Write-Host "  CSV exported to: $dest" -ForegroundColor Green
    } catch {
        Write-Host "  Failed to export CSV: $_" -ForegroundColor Red
    }
}

# ── [1] Conditional Access Policy Report ──────────────────────────────────────
function Invoke-CAAccessReport {
    Write-Host ""
    Write-Host "  Running: Conditional Access Policy Report" -ForegroundColor Cyan

    # Reset caches
    $script:_UserCache  = @{}
    $script:_GroupCache = @{}
    $script:_AppCache   = @{}

    $locationLookup = @{}
    $roleLookup     = @{}

    try {
        $locations = Get-MgIdentityConditionalAccessNamedLocation -All -ErrorAction Stop
        foreach ($loc in $locations) { $locationLookup[$loc.Id] = $loc.DisplayName }
        Write-Host "  Named locations  : $($locations.Count)" -ForegroundColor DarkGray
    } catch {
        Write-Host "  WARN: Could not retrieve named locations. $_" -ForegroundColor Yellow
    }

    try {
        $roleTemplates = Get-MgDirectoryRoleTemplate -All -ErrorAction Stop
        foreach ($r in $roleTemplates) { $roleLookup[$r.Id] = $r.DisplayName }
        Write-Host "  Role templates   : $($roleTemplates.Count)" -ForegroundColor DarkGray
    } catch {
        Write-Host "  WARN: Could not retrieve role templates. $_" -ForegroundColor Yellow
    }

    $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
    Write-Host "  CA policies      : $($policies.Count)" -ForegroundColor DarkGray

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($policy in $policies) {
        $cond  = $policy.Conditions
        $users = $cond.Users
        $apps  = $cond.Applications
        $locs  = $cond.Locations
        $state = if ($CAStateLabels[$policy.State]) { $CAStateLabels[$policy.State] } else { $policy.State }

        # User actions
        $userActions = "—"
        if ($apps.IncludeUserActions -and $apps.IncludeUserActions.Count -gt 0) {
            $userActions = ($apps.IncludeUserActions | ForEach-Object {
                if ($UserActionLabels[$_]) { $UserActionLabels[$_] } else { $_ }
            }) -join " | "
        }

        # User / group resolution via script-scope functions
        $incUsers  = Resolve-List -Ids $users.IncludeUsers  -Resolver { param($id) Resolve-User  $id }
        $excUsers  = Resolve-List -Ids $users.ExcludeUsers  -Resolver { param($id) Resolve-User  $id }
        $incGroups = Resolve-List -Ids $users.IncludeGroups -Resolver { param($id) Resolve-Group $id }
        $excGroups = Resolve-List -Ids $users.ExcludeGroups -Resolver { param($id) Resolve-Group $id }

        # Role resolution — inlined so $roleLookup is in scope
        $incRoles = "—"
        if ($users.IncludeRoles -and $users.IncludeRoles.Count -gt 0) {
            $incRoles = ($users.IncludeRoles | ForEach-Object { if ($roleLookup[$_]) { $roleLookup[$_] } else { $_ } }) -join " | "
        }
        $excRoles = "—"
        if ($users.ExcludeRoles -and $users.ExcludeRoles.Count -gt 0) {
            $excRoles = ($users.ExcludeRoles | ForEach-Object { if ($roleLookup[$_]) { $roleLookup[$_] } else { $_ } }) -join " | "
        }

        # App resolution
        $incApps = "—"
        if ($userActions -eq "—" -and $apps.IncludeApplications -and $apps.IncludeApplications.Count -gt 0) {
            $incApps = Resolve-List -Ids $apps.IncludeApplications -Resolver { param($id) Resolve-App $id }
        }
        $excApps = Resolve-List -Ids $apps.ExcludeApplications -Resolver { param($id) Resolve-App $id }

        # Location resolution — inlined so $locationLookup is in scope
        $incLocs = "—"
        if ($locs -and $locs.IncludeLocations -and $locs.IncludeLocations.Count -gt 0) {
            $incLocs = ($locs.IncludeLocations | ForEach-Object {
                if ($_ -eq "AllTrusted")    { "All Trusted Locations" }
                elseif ($_ -eq "All")       { "Any Location" }
                elseif ($locationLookup[$_]){ $locationLookup[$_] }
                else                        { $_ }
            }) -join " | "
        }
        $excLocs = "—"
        if ($locs -and $locs.ExcludeLocations -and $locs.ExcludeLocations.Count -gt 0) {
            $excLocs = ($locs.ExcludeLocations | ForEach-Object {
                if ($_ -eq "AllTrusted")    { "All Trusted Locations" }
                elseif ($_ -eq "All")       { "Any Location" }
                elseif ($locationLookup[$_]){ $locationLookup[$_] }
                else                        { $_ }
            }) -join " | "
        }

        # Remaining fields
        $platforms = "Any"
        if ($cond.Platforms -and $cond.Platforms.IncludePlatforms -and $cond.Platforms.IncludePlatforms.Count -gt 0) {
            $platforms = $cond.Platforms.IncludePlatforms -join " | "
        }
        $clientAppTypes = "—"
        if ($cond.ClientAppTypes -and $cond.ClientAppTypes.Count -gt 0) {
            $clientAppTypes = $cond.ClientAppTypes -join " | "
        }
        $signInRisk = "—"
        if ($cond.SignInRiskLevels -and $cond.SignInRiskLevels.Count -gt 0) {
            $signInRisk = $cond.SignInRiskLevels -join " | "
        }
        $userRisk = "—"
        if ($cond.UserRiskLevels -and $cond.UserRiskLevels.Count -gt 0) {
            $userRisk = $cond.UserRiskLevels -join " | "
        }
        $grantControls = Format-GrantControls   $policy.GrantControls
        $sessionCtrls  = Format-SessionControls $policy.SessionControls

        $results.Add([PSCustomObject]@{
            PolicyName       = $policy.DisplayName
            State            = $state
            IncludeUsers     = $incUsers
            ExcludeUsers     = $excUsers
            IncludeGroups    = $incGroups
            ExcludeGroups    = $excGroups
            IncludeRoles     = $incRoles
            ExcludeRoles     = $excRoles
            IncludeApps      = $incApps
            ExcludeApps      = $excApps
            UserActions      = $userActions
            IncludeLocations = $incLocs
            ExcludeLocations = $excLocs
            Platforms        = $platforms
            ClientAppTypes   = $clientAppTypes
            SignInRisk       = $signInRisk
            UserRisk         = $userRisk
            GrantControls    = $grantControls
            SessionControls  = $sessionCtrls
        })
    }

    $sorted = $results | Sort-Object State, PolicyName
    $stateColors = @{ "Enabled" = "Green"; "Report-only" = "Yellow"; "Disabled" = "DarkGray" }

    foreach ($entry in $sorted) {
        $sc = if ($stateColors[$entry.State]) { $stateColors[$entry.State] } else { "White" }
        Write-Host ""
        Write-Host ("  [{0}]  {1}" -f $entry.State.ToUpper(), $entry.PolicyName) -ForegroundColor $sc
        if ($entry.IncludeUsers     -ne "—") { Write-Host ("    Include Users   : {0}" -f $entry.IncludeUsers)     -ForegroundColor White }
        if ($entry.ExcludeUsers     -ne "—") { Write-Host ("    Exclude Users   : {0}" -f $entry.ExcludeUsers)     -ForegroundColor DarkYellow }
        if ($entry.IncludeGroups    -ne "—") { Write-Host ("    Include Groups  : {0}" -f $entry.IncludeGroups)    -ForegroundColor White }
        if ($entry.ExcludeGroups    -ne "—") { Write-Host ("    Exclude Groups  : {0}" -f $entry.ExcludeGroups)    -ForegroundColor DarkYellow }
        if ($entry.IncludeRoles     -ne "—") { Write-Host ("    Include Roles   : {0}" -f $entry.IncludeRoles)     -ForegroundColor White }
        if ($entry.ExcludeRoles     -ne "—") { Write-Host ("    Exclude Roles   : {0}" -f $entry.ExcludeRoles)     -ForegroundColor DarkYellow }
        if ($entry.UserActions      -ne "—") { Write-Host ("    User Actions    : {0}" -f $entry.UserActions)       -ForegroundColor White }
        if ($entry.IncludeApps      -ne "—") { Write-Host ("    Applications    : {0}" -f $entry.IncludeApps)      -ForegroundColor White }
        if ($entry.ExcludeApps      -ne "—") { Write-Host ("    Exclude Apps    : {0}" -f $entry.ExcludeApps)      -ForegroundColor DarkYellow }
        if ($entry.IncludeLocations -ne "—") { Write-Host ("    Locations       : {0}" -f $entry.IncludeLocations) -ForegroundColor White }
        if ($entry.ExcludeLocations -ne "—") { Write-Host ("    Exclude Locs    : {0}" -f $entry.ExcludeLocations) -ForegroundColor DarkYellow }
        if ($entry.Platforms        -ne "Any") { Write-Host ("    Platforms       : {0}" -f $entry.Platforms)      -ForegroundColor White }
        if ($entry.SignInRisk       -ne "—") { Write-Host ("    Sign-in Risk    : {0}" -f $entry.SignInRisk)        -ForegroundColor White }
        if ($entry.UserRisk         -ne "—") { Write-Host ("    User Risk       : {0}" -f $entry.UserRisk)          -ForegroundColor White }
        if ($entry.GrantControls    -ne "—") { Write-Host ("    Grant           : {0}" -f $entry.GrantControls)     -ForegroundColor Cyan }
        if ($entry.SessionControls  -ne "—") { Write-Host ("    Session         : {0}" -f $entry.SessionControls)   -ForegroundColor Cyan }
    }

    Write-Host ""
    Write-Host ("  Total: {0}  |  Enabled: {1}  |  Report-only: {2}  |  Disabled: {3}" -f
        $results.Count,
        ($results | Where-Object State -eq "Enabled").Count,
        ($results | Where-Object State -eq "Report-only").Count,
        ($results | Where-Object State -eq "Disabled").Count) -ForegroundColor Cyan

    # ── Executive findings ────────────────────────────────────────────────────
    $reportOnly = ($results | Where-Object State -eq "Report-only").Count
    $disabled   = ($results | Where-Object State -eq "Disabled").Count
    if ($reportOnly -gt 0) {
        Add-Finding -Category "Conditional Access" -Severity "Medium" `
            -Title "$reportOnly CA polic$(if ($reportOnly -eq 1) {'y'} else {'ies'}) in Report-only mode" `
            -Detail "Report-only policies log results but do not enforce controls — users are not blocked or prompted." `
            -Recommendation "Review report-only policies and promote to Enabled when confident in their scope."
    }
    if ($disabled -gt 0) {
        Add-Finding -Category "Conditional Access" -Severity "Low" `
            -Title "$disabled CA polic$(if ($disabled -eq 1) {'y'} else {'ies'}) disabled" `
            -Detail "Disabled policies provide no protection whatsoever." `
            -Recommendation "Review disabled policies and enable or remove them."
    }

    Write-CsvBom -Data $sorted -Path (Join-Path $script:ExportFolder "AuditSuite_CAAccessReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv")
}

# ── [2] License Usage ─────────────────────────────────────────────────────────
function Invoke-LicenseUsage {
    Write-Host ""
    Write-Host "  Running: License Usage" -ForegroundColor Cyan

    $skus = Get-MgSubscribedSku -All -ErrorAction Stop
    Write-Host "  Subscribed SKUs  : $($skus.Count)" -ForegroundColor DarkGray

    $results = foreach ($sku in $skus) {
        $purchased    = $sku.PrepaidUnits.Enabled
        $warning      = $sku.PrepaidUnits.Warning
        $suspended    = $sku.PrepaidUnits.Suspended
        $consumed     = $sku.ConsumedUnits
        $available    = $purchased - $consumed
        $usagePct     = if ($purchased -gt 0) { [math]::Round(($consumed / $purchased) * 100, 1) } else { 0 }
        $friendlyName = if ($SkuNames[$sku.SkuPartNumber]) { $SkuNames[$sku.SkuPartNumber] } else { $sku.SkuPartNumber }

        [PSCustomObject]@{
            LicenseName   = $friendlyName
            SkuPartNumber = $sku.SkuPartNumber
            SkuId         = $sku.SkuId
            Status        = $sku.CapabilityStatus
            Purchased     = $purchased
            Consumed      = $consumed
            Available     = $available
            Warning       = $warning
            Suspended     = $suspended
            UsagePct      = $usagePct
        }
    }

    $sorted = $results | Sort-Object Consumed -Descending

    Write-Host ""
    $headerLine = "  {0,-48} {1,-12} {2,9} {3,9} {4,9} {5,8}" -f "License", "Status", "Purchased", "Consumed", "Available", "Usage%"
    Write-Host $headerLine -ForegroundColor Gray
    Write-Host ("  " + "─" * 101) -ForegroundColor DarkGray

    foreach ($entry in $sorted) {
        $color = if ($entry.Available -le 0) { "Red" } elseif ($entry.UsagePct -ge 90) { "Yellow" } else { "Green" }
        Write-Host ("  {0,-48} {1,-12} {2,9} {3,9} {4,9} {5,7}%" -f $entry.LicenseName, $entry.Status, $entry.Purchased, $entry.Consumed, $entry.Available, $entry.UsagePct) -ForegroundColor $color
        if ($entry.Warning   -gt 0) { Write-Host ("    ^ $($entry.Warning) unit(s) in warning state (expiring)") -ForegroundColor Yellow }
        if ($entry.Suspended -gt 0) { Write-Host ("    ^ $($entry.Suspended) unit(s) suspended")                 -ForegroundColor Red }
    }

    Write-Host ""
    $fullyUsed    = ($results | Where-Object { $_.Available -le 0 }).Count
    $nearCapacity = ($results | Where-Object { $_.UsagePct -ge 90 -and $_.Available -gt 0 }).Count
    Write-Host "  Total SKUs: $($results.Count)" -ForegroundColor Cyan
    if ($fullyUsed    -gt 0) { Write-Host "  At capacity (0 left) : $fullyUsed"    -ForegroundColor Red }
    if ($nearCapacity -gt 0) { Write-Host "  Near capacity (>=90%): $nearCapacity" -ForegroundColor Yellow }

    # ── Executive findings ────────────────────────────────────────────────────
    foreach ($entry in ($results | Where-Object { $_.Available -le 0 -and $_.Status -eq "Enabled" })) {
        Add-Finding -Category "License Management" -Severity "Medium" `
            -Title "License at capacity: $($entry.LicenseName)" `
            -Detail "$($entry.Consumed) / $($entry.Purchased) units consumed. No licenses available for new assignments." `
            -Recommendation "Purchase additional licenses or review and reclaim unused assignments."
    }

    Write-CsvBom -Data $sorted -Path (Join-Path $script:ExportFolder "AuditSuite_LicenseUsage_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv")
}

# ── [3] App Registration Security Audit ───────────────────────────────────────
function Invoke-AppRegistrationAudit {
    Write-Host ""
    Write-Host "  Running: App Registration Security Audit" -ForegroundColor Cyan

    $apps = Get-MgApplication -All -Property Id,DisplayName,AppId,CreatedDateTime,SignInAudience,RequiredResourceAccess,Tags -ErrorAction Stop
    Write-Host "  App registrations: $($apps.Count)" -ForegroundColor DarkGray

    $allSPs = Get-MgServicePrincipal -All -Property AppId,DisplayName,Tags,AppRoles,Oauth2PermissionScopes -ErrorAction Stop
    Write-Host "  Service principals: $($allSPs.Count)" -ForegroundColor DarkGray

    $spByAppId = @{}
    foreach ($sp in $allSPs) { $spByAppId[$sp.AppId] = $sp }

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($app in $apps) {
        $ownerNames = [System.Collections.Generic.List[string]]::new()
        try {
            $owners = Get-MgApplicationOwner -ApplicationId $app.Id -ErrorAction Stop
            foreach ($owner in $owners) {
                $resolved = $null
                try { $u = Get-MgUser -UserId $owner.Id -Property UserPrincipalName -ErrorAction Stop; $resolved = "$($owner.Id) ($($u.UserPrincipalName))" } catch {}
                if (-not $resolved) {
                    try { $sp = Get-MgServicePrincipal -ServicePrincipalId $owner.Id -Property DisplayName -ErrorAction Stop; $resolved = "$($owner.Id) ($($sp.DisplayName))" } catch {}
                }
                $ownerNames.Add($(if ($resolved) { $resolved } else { $owner.Id }))
            }
        } catch {}

        $ownSP = $spByAppId[$app.AppId]
        $visibleInMyApps = if (-not $ownSP) { "No SP" } elseif ($ownSP.Tags -contains "HideApp") { "Hidden" } else { "Visible" }

        $appPerms = [System.Collections.Generic.List[string]]::new()
        $delPerms = [System.Collections.Generic.List[string]]::new()

        foreach ($ra in $app.RequiredResourceAccess) {
            $resSP   = $spByAppId[$ra.ResourceAppId]
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
                if ($perm.Type -eq "Role") { $appPerms.Add($fullName) } else { $delPerms.Add($fullName) }
            }
        }

        $privMatches = [System.Collections.Generic.List[string]]::new()
        foreach ($perm in ($appPerms + $delPerms)) {
            $bare = if ($perm -match " / (.+)$") { $Matches[1] } else { $perm }
            if ($PrivilegedPermissions.Contains($bare) -or $PrivilegedPermissions.Contains($perm)) { $privMatches.Add($perm) }
        }

        $audienceLabel = switch ($app.SignInAudience) {
            "AzureADMyOrg"                       { "Single-tenant" }
            "AzureADMultipleOrgs"                { "Multi-tenant" }
            "AzureADandPersonalMicrosoftAccount" { "Multi-tenant + Personal" }
            default                              { $app.SignInAudience }
        }

        $results.Add([PSCustomObject]@{
            AppDisplayName         = $app.DisplayName
            AppId                  = $app.AppId
            CreatedDate            = if ($app.CreatedDateTime) { $app.CreatedDateTime.ToString("yyyy-MM-dd") } else { "" }
            SignInAudience         = $audienceLabel
            IsPrivileged           = if ($privMatches.Count -gt 0) { "Yes" } else { "No" }
            TotalPermissions       = $appPerms.Count + $delPerms.Count
            HasOwner               = if ($ownerNames.Count -gt 0) { "Yes" } else { "No" }
            Owners                 = ($ownerNames -join "; ")
            VisibleInMyApps        = $visibleInMyApps
            ApplicationPermissions = ($appPerms -join "; ")
            DelegatedPermissions   = ($delPerms -join "; ")
            PrivilegedPermissions  = ($privMatches -join "; ")
        })
    }

    $sorted = $results | Sort-Object @(
        @{ Expression = { if ($_.IsPrivileged -eq "Yes") { 0 } else { 1 } } }
        @{ Expression = { if ($_.HasOwner     -eq "No")  { 0 } else { 1 } } }
        @{ Expression = "AppDisplayName" }
    )

    Write-Host ""
    foreach ($entry in $sorted) {
        $flags = ""
        if ($entry.IsPrivileged -eq "Yes") { $flags += " [PRIVILEGED]" }
        if ($entry.HasOwner     -eq "No")  { $flags += " [NO OWNER]"   }
        $color = if ($entry.IsPrivileged -eq "Yes") { "Red" } elseif ($entry.HasOwner -eq "No") { "Yellow" } else { "Green" }
        Write-Host ("  {0,-45} {1,-22} Perms: {2,-3} Owner: {3,-3} MyApps: {4}{5}" -f $entry.AppDisplayName, $entry.SignInAudience, $entry.TotalPermissions, $entry.HasOwner, $entry.VisibleInMyApps, $flags) -ForegroundColor $color
        if ($entry.IsPrivileged -eq "Yes" -and $entry.PrivilegedPermissions) {
            Write-Host ("    → " + $entry.PrivilegedPermissions) -ForegroundColor DarkRed
        }
    }

    $totalPriv    = ($results | Where-Object { $_.IsPrivileged -eq "Yes" }).Count
    $totalNoOwner = ($results | Where-Object { $_.HasOwner     -eq "No"  }).Count
    $totalMulti   = ($results | Where-Object { $_.SignInAudience -ne "Single-tenant" }).Count
    Write-Host ""
    Write-Host "  Total app registrations : $($results.Count)" -ForegroundColor Cyan
    if ($totalPriv    -gt 0) { Write-Host "  Privileged              : $totalPriv"    -ForegroundColor Red    }
    if ($totalNoOwner -gt 0) { Write-Host "  No owner                : $totalNoOwner" -ForegroundColor Yellow }
    if ($totalMulti   -gt 0) { Write-Host "  Multi-tenant            : $totalMulti"   -ForegroundColor Yellow }

    # ── Executive findings ────────────────────────────────────────────────────
    foreach ($entry in ($results | Where-Object { $_.IsPrivileged -eq "Yes" -and $_.HasOwner -eq "No" })) {
        Add-Finding -Category "App Registrations" -Severity "High" `
            -Title "Privileged app without owner: $($entry.AppDisplayName)" `
            -Detail "This app holds elevated permissions ($($entry.PrivilegedPermissions -replace ';',', ')) and has no assigned owner — no one is accountable for it." `
            -Recommendation "Assign an owner to this app registration and review whether all permissions are still required."
    }
    foreach ($entry in ($results | Where-Object { $_.IsPrivileged -eq "No" -and $_.HasOwner -eq "No" })) {
        Add-Finding -Category "App Registrations" -Severity "Low" `
            -Title "App without owner: $($entry.AppDisplayName)" `
            -Detail "No owner assigned — accountability and lifecycle management are absent." `
            -Recommendation "Assign an owner to ensure the app registration is maintained."
    }

    Write-CsvBom -Data $sorted -Path (Join-Path $script:ExportFolder "AuditSuite_AppRegistrationAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv")
}

# ── [4] App Registration Expiry ───────────────────────────────────────────────
function Invoke-AppRegistrationExpiry {
    Write-Host ""
    Write-Host "  Running: App Registration Expiry" -ForegroundColor Cyan

    $apps = Get-MgApplication -All -Property DisplayName,AppId,KeyCredentials,PasswordCredentials -ErrorAction Stop
    Write-Host "  App registrations: $($apps.Count)" -ForegroundColor DarkGray

    $now     = Get-Date
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($app in $apps) {
        foreach ($cert in $app.KeyCredentials) {
            if (-not $cert.EndDateTime) { continue }
            $days   = [math]::Floor(($cert.EndDateTime - $now).TotalDays)
            $status = if ($days -le 0) { "EXPIRED" } elseif ($days -le $CriticalDays) { "CRITICAL" } elseif ($days -le $WarningDays) { "WARNING" } elseif ($days -le $NoticeDays) { "NOTICE" } else { "OK" }
            $thumb  = if ($cert.CustomKeyIdentifier) { ($cert.CustomKeyIdentifier | ForEach-Object { $_.ToString("X2") }) -join "" } else { "" }
            $results.Add([PSCustomObject]@{ AppDisplayName = $app.DisplayName; AppId = $app.AppId; Type = "Certificate"; Name = if ($cert.DisplayName) { $cert.DisplayName } else { "(no name)" }; Thumbprint = $thumb; StartDate = $cert.StartDateTime.ToString("yyyy-MM-dd"); EndDate = $cert.EndDateTime.ToString("yyyy-MM-dd"); DaysRemaining = $days; Status = $status })
        }
        foreach ($secret in $app.PasswordCredentials) {
            if (-not $secret.EndDateTime) { continue }
            $days   = [math]::Floor(($secret.EndDateTime - $now).TotalDays)
            $status = if ($days -le 0) { "EXPIRED" } elseif ($days -le $CriticalDays) { "CRITICAL" } elseif ($days -le $WarningDays) { "WARNING" } elseif ($days -le $NoticeDays) { "NOTICE" } else { "OK" }
            $results.Add([PSCustomObject]@{ AppDisplayName = $app.DisplayName; AppId = $app.AppId; Type = "Secret"; Name = if ($secret.DisplayName) { $secret.DisplayName } else { "(no name)" }; Thumbprint = ""; StartDate = $secret.StartDateTime.ToString("yyyy-MM-dd"); EndDate = $secret.EndDateTime.ToString("yyyy-MM-dd"); DaysRemaining = $days; Status = $status })
        }
    }

    if ($results.Count -eq 0) {
        Write-Host "  No credentials found." -ForegroundColor Yellow
        return
    }

    $sorted = $results | Sort-Object DaysRemaining
    Write-Host ""
    foreach ($entry in $sorted) {
        $color     = switch ($entry.Status) { "EXPIRED" { "Red" } "CRITICAL" { "Red" } "WARNING" { "Yellow" } "NOTICE" { "Yellow" } default { "Green" } }
        $daysLabel = if ($entry.DaysRemaining -le 0) { "EXPIRED $([math]::Abs($entry.DaysRemaining))d ago" } else { "in $($entry.DaysRemaining)d" }
        Write-Host ("  [{0,-8}] {1,-45} {2,-11} {3,-30} expires {4} ({5})" -f $entry.Status, $entry.AppDisplayName, $entry.Type, $entry.Name, $entry.EndDate, $daysLabel) -ForegroundColor $color
    }

    Write-Host ""
    @("EXPIRED","CRITICAL","WARNING","NOTICE","OK") | ForEach-Object {
        $cnt = ($results | Where-Object Status -eq $_).Count
        if ($cnt -gt 0) {
            $c = if ($_ -in "EXPIRED","CRITICAL") { "Red" } elseif ($_ -in "WARNING","NOTICE") { "Yellow" } else { "Green" }
            Write-Host ("  {0,-8}: {1}" -f $_, $cnt) -ForegroundColor $c
        }
    }

    # ── Executive findings ────────────────────────────────────────────────────
    foreach ($entry in ($results | Where-Object Status -eq "EXPIRED")) {
        Add-Finding -Category "Credential Expiry" -Severity "Critical" `
            -Title "Expired credential: $($entry.AppDisplayName)" `
            -Detail "$($entry.Type) '$($entry.Name)' expired on $($entry.EndDate). Authentication using this credential is failing." `
            -Recommendation "Renew or replace this credential immediately to restore service."
    }
    foreach ($entry in ($results | Where-Object Status -eq "CRITICAL")) {
        Add-Finding -Category "Credential Expiry" -Severity "Critical" `
            -Title "Credential expiring in $($entry.DaysRemaining) day$(if ($entry.DaysRemaining -ne 1) {'s'}): $($entry.AppDisplayName)" `
            -Detail "$($entry.Type) '$($entry.Name)' expires $($entry.EndDate). Service disruption imminent." `
            -Recommendation "Renew this credential before $($entry.EndDate) to prevent outage."
    }
    foreach ($entry in ($results | Where-Object Status -eq "WARNING")) {
        Add-Finding -Category "Credential Expiry" -Severity "High" `
            -Title "Credential expiring in $($entry.DaysRemaining) day$(if ($entry.DaysRemaining -ne 1) {'s'}): $($entry.AppDisplayName)" `
            -Detail "$($entry.Type) '$($entry.Name)' expires $($entry.EndDate)." `
            -Recommendation "Plan and execute renewal within the next $($entry.DaysRemaining) days."
    }
    foreach ($entry in ($results | Where-Object Status -eq "NOTICE")) {
        Add-Finding -Category "Credential Expiry" -Severity "Medium" `
            -Title "Credential expiring in $($entry.DaysRemaining) day$(if ($entry.DaysRemaining -ne 1) {'s'}): $($entry.AppDisplayName)" `
            -Detail "$($entry.Type) '$($entry.Name)' expires $($entry.EndDate)." `
            -Recommendation "Schedule renewal to avoid a future incident."
    }

    Write-CsvBom -Data $sorted -Path (Join-Path $script:ExportFolder "AuditSuite_AppRegistrationExpiry_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv")
}

# ── [5] Device Export ─────────────────────────────────────────────────────────
function Invoke-DeviceExport {
    Write-Host ""
    Write-Host "  Running: Device Export" -ForegroundColor Cyan

    $devices = Get-MgDevice -All `
        -Property Id,DisplayName,DeviceId,OperatingSystem,OperatingSystemVersion,TrustType,IsCompliant,IsManaged,AccountEnabled,ApproximateLastSignInDateTime,OnPremisesLastSyncDateTime,RegisteredOwners `
        -ExpandProperty RegisteredOwners -ErrorAction Stop
    Write-Host "  Entra devices    : $($devices.Count)" -ForegroundColor DarkGray

    $intuneByDeviceId = @{}
    try {
        $intuneDevices = Get-MgDeviceManagementManagedDevice -All -Property AzureAdDeviceId,LastSyncDateTime -ErrorAction Stop
        foreach ($d in $intuneDevices) { if ($d.AzureAdDeviceId) { $intuneByDeviceId[$d.AzureAdDeviceId] = $d.LastSyncDateTime } }
        Write-Host "  Intune devices   : $($intuneDevices.Count)" -ForegroundColor DarkGray
    } catch {
        Write-Host "  WARN: Could not retrieve Intune devices. $_" -ForegroundColor Yellow
    }

    $now     = Get-Date
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($device in $devices) {
        $daysSince = $null; $isStale = $false
        if ($device.ApproximateLastSignInDateTime) {
            $daysSince = [math]::Floor(($now - $device.ApproximateLastSignInDateTime).TotalDays)
            $isStale   = $daysSince -gt $StaleDays
        }
        $intuneSync      = $intuneByDeviceId[$device.DeviceId]
        $daysSinceIntune = if ($intuneSync) { [math]::Floor(($now - $intuneSync).TotalDays) } else { $null }
        $ownerUpn        = ""
        if ($device.RegisteredOwners -and $device.RegisteredOwners.Count -gt 0) {
            $ownerUpn = ($device.RegisteredOwners | ForEach-Object { $upn = $_.AdditionalProperties['userPrincipalName']; if ($upn) { $upn } else { $_.Id } }) -join "; "
        }
        $trustLabel = if (-not $device.TrustType) { "Unknown" } elseif ($TrustTypeLabels[$device.TrustType]) { $TrustTypeLabels[$device.TrustType] } else { $device.TrustType }

        $results.Add([PSCustomObject]@{
            DisplayName         = $device.DisplayName
            DeviceId            = $device.DeviceId
            ObjectId            = $device.Id
            OperatingSystem     = $device.OperatingSystem
            OSVersion           = $device.OperatingSystemVersion
            TrustType           = $trustLabel
            IsCompliant         = if ($null -eq $device.IsCompliant) { "Unknown" } else { $device.IsCompliant.ToString() }
            IsManaged           = if ($null -eq $device.IsManaged)   { "Unknown" } else { $device.IsManaged.ToString() }
            AccountEnabled      = $device.AccountEnabled.ToString()
            LastSignIn          = if ($device.ApproximateLastSignInDateTime) { $device.ApproximateLastSignInDateTime.ToString("yyyy-MM-dd") } else { "Never" }
            DaysSinceSignIn     = if ($null -ne $daysSince) { $daysSince } else { "" }
            IsStale             = if ($null -ne $daysSince) { $isStale.ToString() } else { "Unknown" }
            OnPremisesLastSync  = if ($device.OnPremisesLastSyncDateTime) { $device.OnPremisesLastSyncDateTime.ToString("yyyy-MM-dd") } else { "" }
            IntuneLastSync      = if ($intuneSync) { $intuneSync.ToString("yyyy-MM-dd") } else { "" }
            DaysSinceIntuneSync = if ($null -ne $daysSinceIntune) { $daysSinceIntune } else { "" }
            RegisteredOwner     = $ownerUpn
        })
    }

    $sorted = $results | Sort-Object @(
        @{ Expression = { if ($_.IsStale -eq "True") { 0 } else { 1 } } }
        @{ Expression = { if ($_.AccountEnabled -eq "False") { 0 } else { 1 } } }
        @{ Expression = "DisplayName" }
    )

    Write-Host ""
    foreach ($entry in $sorted) {
        $flags = ""
        if ($entry.IsStale        -eq "True")  { $flags += " [STALE]" }
        if ($entry.AccountEnabled -eq "False")  { $flags += " [DISABLED]" }
        if ($entry.IsCompliant    -eq "False")  { $flags += " [NON-COMPLIANT]" }
        $color = if ($entry.IsStale -eq "True" -or $entry.AccountEnabled -eq "False") { "Red" } elseif ($entry.IsCompliant -eq "False") { "Yellow" } else { "Green" }
        Write-Host ("  {0,-40} {1,-25} {2,-18} Last: {3,-12} Owner: {4}{5}" -f $entry.DisplayName, $entry.TrustType, $entry.OperatingSystem, $entry.LastSignIn, $(if ($entry.RegisteredOwner) { $entry.RegisteredOwner } else { "(none)" }), $flags) -ForegroundColor $color
    }

    $totalStale        = ($results | Where-Object { $_.IsStale        -eq "True"  }).Count
    $totalDisabled     = ($results | Where-Object { $_.AccountEnabled -eq "False" }).Count
    $totalNonCompliant = ($results | Where-Object { $_.IsCompliant    -eq "False" }).Count
    Write-Host ""
    Write-Host "  Total devices: $($results.Count)" -ForegroundColor Cyan
    $results | Group-Object OperatingSystem | Sort-Object Count -Descending | ForEach-Object { Write-Host ("  {0,-18}: {1}" -f $_.Name, $_.Count) -ForegroundColor Cyan }
    Write-Host ""
    if ($totalStale        -gt 0) { Write-Host "  Stale (>$StaleDays days): $totalStale"         -ForegroundColor Red    }
    if ($totalDisabled     -gt 0) { Write-Host "  Disabled        : $totalDisabled"   -ForegroundColor Red    }
    if ($totalNonCompliant -gt 0) { Write-Host "  Non-compliant   : $totalNonCompliant" -ForegroundColor Yellow }

    # ── Executive findings ────────────────────────────────────────────────────
    if ($totalStale -gt 0) {
        Add-Finding -Category "Devices" -Severity "Medium" `
            -Title "$totalStale stale device$(if ($totalStale -ne 1) {'s'}) (>$StaleDays days inactive)" `
            -Detail "Stale devices may represent unmanaged or abandoned endpoints with outdated security posture." `
            -Recommendation "Investigate stale devices and disable or delete objects that are no longer in active use."
    }
    if ($totalNonCompliant -gt 0) {
        Add-Finding -Category "Devices" -Severity "Medium" `
            -Title "$totalNonCompliant non-compliant device$(if ($totalNonCompliant -ne 1) {'s'})" `
            -Detail "Non-compliant devices may be accessing corporate resources without meeting security requirements." `
            -Recommendation "Enforce Intune compliance policies and configure Conditional Access to block non-compliant devices."
    }

    Write-CsvBom -Data $sorted -Path (Join-Path $script:ExportFolder "AuditSuite_DeviceExport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv")
}

# ── [6] Role Assignments ──────────────────────────────────────────────────────
function Invoke-RoleAssignments {
    Write-Host ""
    Write-Host "  Running: Role Assignments" -ForegroundColor Cyan

    $roleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop
    $roleDefMap      = @{}
    foreach ($rd in $roleDefinitions) { $roleDefMap[$rd.Id] = $rd.DisplayName; $roleDefMap[$rd.TemplateId] = $rd.DisplayName }

    $aadUsers = Get-MgUser  -All -Property "Id,DisplayName,UserPrincipalName" -ErrorAction Stop
    $groups   = Get-MgGroup -All -Property "Id,DisplayName,Description"       -ErrorAction Stop
    Write-Host "  Role definitions : $($roleDefinitions.Count)" -ForegroundColor DarkGray
    Write-Host "  Users            : $($aadUsers.Count)"        -ForegroundColor DarkGray

    $activeAssignments = Get-MgRoleManagementDirectoryRoleAssignment -All -ErrorAction Stop
    Write-Host "  Active assignments: $($activeAssignments.Count)" -ForegroundColor DarkGray

    $eligibleAssignments = @()
    try {
        $eligibleAssignments = Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -ExpandProperty "*" -All -ErrorAction Stop
        Write-Host "  Eligible (PIM)   : $($eligibleAssignments.Count)" -ForegroundColor DarkGray
    } catch {
        Write-Host "  WARN: Eligible assignments unavailable — tenant may not have Entra P2." -ForegroundColor Yellow
    }

    $groupMemberCache = @{}
    function Get-GroupMemberNames { param([string]$GroupId)
        if (-not $GroupId) { return "" }
        if ($groupMemberCache.ContainsKey($GroupId)) { return $groupMemberCache[$GroupId] }
        try {
            $names = (Get-MgGroupTransitiveMember -GroupId $GroupId -All -ErrorAction Stop |
                      ForEach-Object { $_.AdditionalProperties["displayName"] } | Where-Object { $_ }) -join " | "
        } catch { $names = "" }
        $groupMemberCache[$GroupId] = $names; return $names
    }

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($a in $activeAssignments) {
        $user  = $aadUsers | Where-Object { $_.Id -eq $a.PrincipalId }
        $group = $groups   | Where-Object { $_.Id -eq $a.PrincipalId }
        $role  = $roleDefinitions | Where-Object { $_.TemplateId -eq $a.RoleDefinitionId }
        $results.Add([PSCustomObject]@{
            AssignmentType    = "Active"
            RoleDisplayName   = $role.DisplayName
            UserDisplayName   = $user.DisplayName
            UserPrincipalName = $user.UserPrincipalName
            GroupDisplayName  = $group.DisplayName
            GroupMembers      = if ($group) { Get-GroupMemberNames $group.Id } else { "" }
            PrincipalId       = $a.PrincipalId
        })
    }

    foreach ($a in $eligibleAssignments) {
        $user  = $aadUsers | Where-Object { $_.Id -eq $a.PrincipalId }
        $group = $groups   | Where-Object { $_.Id -eq $a.PrincipalId }
        $role  = $roleDefinitions | Where-Object { $_.TemplateId -eq $a.RoleDefinition.TemplateId }
        $results.Add([PSCustomObject]@{
            AssignmentType    = "Eligible"
            RoleDisplayName   = $role.DisplayName
            UserDisplayName   = $user.DisplayName
            UserPrincipalName = $user.UserPrincipalName
            GroupDisplayName  = $group.DisplayName
            GroupMembers      = if ($group) { Get-GroupMemberNames $group.Id } else { "" }
            PrincipalId       = $a.PrincipalId
        })
    }

    $sorted = $results | Sort-Object RoleDisplayName, AssignmentType, UserDisplayName, GroupDisplayName
    Write-Host ""
    foreach ($entry in $sorted) {
        $color = if ($entry.AssignmentType -eq "Active") { "Green" } else { "Yellow" }
        $principal = if ($entry.UserPrincipalName) { $entry.UserPrincipalName } elseif ($entry.GroupDisplayName) { "$($entry.GroupDisplayName) (group)" } else { $entry.PrincipalId }
        Write-Host ("  [{0,-8}] {1,-50} {2}" -f $entry.AssignmentType, $entry.RoleDisplayName, $principal) -ForegroundColor $color
    }

    Write-Host ""
    Write-Host "  Total assignments: $($results.Count)  |  Active: $(($results | Where-Object AssignmentType -eq 'Active').Count)  |  Eligible: $(($results | Where-Object AssignmentType -eq 'Eligible').Count)" -ForegroundColor Cyan

    Write-CsvBom -Data $sorted -Path (Join-Path $script:ExportFolder "AuditSuite_RoleAssignments_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv")
}

# ── [7] Role Policies ─────────────────────────────────────────────────────────
function Invoke-RolePolicies {
    Write-Host ""
    Write-Host "  Running: Role Policies (PIM)" -ForegroundColor Cyan

    $roleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop
    $roleDefMap = @{}
    foreach ($rd in $roleDefinitions) { $roleDefMap[$rd.Id] = $rd.DisplayName; $roleDefMap[$rd.TemplateId] = $rd.DisplayName }

    $policyAssignments = Get-MgPolicyRoleManagementPolicyAssignment `
        -Filter "scopeId eq '/' and scopeType eq 'DirectoryRole'" -All `
        -ExpandProperty "policy(`$expand=rules)" -ErrorAction Stop
    Write-Host "  Policy assignments: $($policyAssignments.Count)" -ForegroundColor DarkGray

    $approverGroupCache = @{}
    function Get-ApproverMembers { param([string]$GroupId)
        if (-not $GroupId) { return "" }
        if ($approverGroupCache.ContainsKey($GroupId)) { return $approverGroupCache[$GroupId] }
        try {
            $names = (Get-MgGroupTransitiveMember -GroupId $GroupId -All -ErrorAction Stop |
                      ForEach-Object { $_.AdditionalProperties["displayName"] } | Where-Object { $_ }) -join " | "
        } catch { $names = "" }
        $approverGroupCache[$GroupId] = $names; return $names
    }

    function Get-PolicyRule { param([object[]]$Rules, [string]$RuleId)
        if ($null -eq $Rules) { return $null }
        return $Rules | Where-Object { $_.Id -eq $RuleId } | Select-Object -First 1
    }
    function Get-RuleProp { param([object]$Rule, [string]$Key)
        if ($null -eq $Rule) { return $null }; return $Rule.AdditionalProperties[$Key]
    }

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($assignment in $policyAssignments) {
        $roleId   = $assignment.RoleDefinitionId
        $roleName = if ($roleDefMap[$roleId]) { $roleDefMap[$roleId] } else { $roleId }
        try {
            $rules = if ($assignment.Policy) { $assignment.Policy.Rules } else { $null }

            $actRule       = Get-PolicyRule $rules "Expiration_EndUser_Assignment"
            $actEnablement = Get-PolicyRule $rules "Enablement_EndUser_Assignment"
            $actApproval   = Get-PolicyRule $rules "Approval_EndUser_Assignment"
            $enabledRules  = Get-RuleProp $actEnablement "enabledRules"
            $approvalSetting = Get-RuleProp $actApproval "setting"
            $approvalRequired = if ($null -ne $approvalSetting) { $approvalSetting.isApprovalRequired } else { $false }

            $approverNames = @()
            if ($null -ne $approvalSetting -and $null -ne $approvalSetting.approvalStages) {
                foreach ($stage in $approvalSetting.approvalStages) {
                    foreach ($ap in $stage.primaryApprovers) {
                        $dict = $ap -as [System.Collections.IDictionary]
                        if ($dict) {
                            $name = $dict["description"]; if (-not $name) { $name = $dict["groupId"] }
                            if ($name) { $approverNames += $name }
                        }
                    }
                }
            }

            $eligExpiry = Get-PolicyRule $rules "Expiration_Admin_Eligibility"
            $actExpiry  = Get-PolicyRule $rules "Expiration_Admin_Assignment"

            $results.Add([PSCustomObject]@{
                RoleName                      = $roleName
                Activation_MaxDuration        = Get-RuleProp $actRule "maximumDuration"
                Activation_RequireMFA         = ($enabledRules -contains "MultiFactorAuthentication")
                Activation_RequireJustification = ($enabledRules -contains "Justification")
                Activation_RequireTicketing   = ($enabledRules -contains "Ticketing")
                Activation_ApprovalRequired   = $approvalRequired
                Activation_Approvers          = ($approverNames -join " | ")
                Eligible_ExpirationRequired   = Get-RuleProp $eligExpiry "isExpirationRequired"
                Eligible_MaxDuration          = Get-RuleProp $eligExpiry "maximumDuration"
                Active_ExpirationRequired     = Get-RuleProp $actExpiry  "isExpirationRequired"
                Active_MaxDuration            = Get-RuleProp $actExpiry  "maximumDuration"
            })
        } catch {
            Write-Host "  WARN: Skipping '$roleName': $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    $sorted = $results | Sort-Object RoleName
    Write-Host ""
    foreach ($entry in $sorted) {
        $approvalFlag = if ($entry.Activation_ApprovalRequired) { " [APPROVAL REQUIRED]" } else { "" }
        $color = if ($entry.Activation_ApprovalRequired) { "Yellow" } else { "Green" }
        Write-Host ("  {0,-55} Max: {1,-12} MFA: {2,-5} Justif: {3}{4}" -f $entry.RoleName, $entry.Activation_MaxDuration, $entry.Activation_RequireMFA, $entry.Activation_RequireJustification, $approvalFlag) -ForegroundColor $color
    }

    Write-Host ""
    Write-Host "  Total role policies: $($results.Count)" -ForegroundColor Cyan

    # ── Executive findings ────────────────────────────────────────────────────
    $noMFA           = ($results | Where-Object { $_.Activation_RequireMFA           -eq $false }).Count
    $noJustification = ($results | Where-Object { $_.Activation_RequireJustification -eq $false }).Count
    if ($noMFA -gt 0) {
        Add-Finding -Category "PIM Role Policies" -Severity "High" `
            -Title "$noMFA role$(if ($noMFA -ne 1) {'s'}) do not require MFA on activation" `
            -Detail "Privileged roles can be activated without completing multi-factor authentication, lowering the bar for privilege escalation." `
            -Recommendation "Enable MFA as an activation requirement on all PIM-managed roles."
    }
    if ($noJustification -gt 0) {
        Add-Finding -Category "PIM Role Policies" -Severity "Medium" `
            -Title "$noJustification role$(if ($noJustification -ne 1) {'s'}) do not require justification on activation" `
            -Detail "No business justification is captured when these roles are activated, limiting the audit trail." `
            -Recommendation "Enable justification requirement on all PIM-managed roles to maintain accountability."
    }

    Write-CsvBom -Data $sorted -Path (Join-Path $script:ExportFolder "AuditSuite_RolePolicies_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv")
}

# ── [8] PIM Activation & Request History ─────────────────────────────────────
function Invoke-PIMActivationHistory {
    param([int]$Days = 0)
    Write-Host ""
    Write-Host "  Running: PIM Activation & Request History" -ForegroundColor Cyan

    if ($Days -gt 0) {
        $lookback = $Days
        Write-Host "  Lookback         : $lookback days (default)" -ForegroundColor DarkGray
    } else {
        $lookback = $null
        while ($null -eq $lookback) {
            $inp = Read-Host "  How many days back to export (e.g. 30)"
            if ($inp -match '^\d+$' -and [int]$inp -gt 0) { $lookback = [int]$inp }
            else { Write-Host "  Please enter a positive number." -ForegroundColor Yellow }
        }
    }

    # Uses directory audit log (AuditLog.Read.All) filtered to RoleManagement category.
    # This covers all PIM activations, approvals, denials, and admin assignments
    # without requiring write permissions on the schedule request API.

    # Build role definition map for resolving role GUIDs.
    # Three ID systems need to be covered:
    #   1. roleDefinitions — template-based IDs used by the modern PIM API
    #   2. directoryRoles  — activated role object IDs used by the older directory role API
    #   3. TemplateId      — well-known cross-tenant GUIDs (same on every tenant)
    $roleDefMap = @{}
    try {
        $roleDefs = Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop
        foreach ($rd in $roleDefs) {
            $roleDefMap[$rd.Id] = $rd.DisplayName
            if ($rd.TemplateId) { $roleDefMap[$rd.TemplateId] = $rd.DisplayName }
        }
    } catch {}
    try {
        $dirRoles = Get-MgDirectoryRole -All -ErrorAction Stop
        foreach ($dr in $dirRoles) {
            $roleDefMap[$dr.Id] = $dr.DisplayName
            if ($dr.RoleTemplateId) { $roleDefMap[$dr.RoleTemplateId] = $dr.DisplayName }
        }
    } catch {}

    $since = (Get-Date).AddDays(-$lookback).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $allEntries = [System.Collections.Generic.List[object]]::new()
    $uri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=category eq 'RoleManagement' and activityDateTime ge $since&`$orderby=activityDateTime desc"
    try {
        do {
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            foreach ($e in $response.value) { $allEntries.Add($e) }
            $uri = $response.'@odata.nextLink'
        } while ($uri)
    } catch {
        Write-Host "  FATAL: Could not retrieve PIM audit log: $_" -ForegroundColor Red
        return
    }
    Write-Host "  Audit entries    : $($allEntries.Count)" -ForegroundColor DarkGray

    $ResultColors = @{
        "success"            = "Green"
        "failure"            = "Red"
        "timeout"            = "Yellow"
        "unknownFutureValue" = "DarkGray"
    }

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($entry in $allEntries) {
        $initiatedBy = if ($entry.initiatedBy.user.userPrincipalName) { $entry.initiatedBy.user.userPrincipalName }
                       elseif ($entry.initiatedBy.app.displayName)    { "$($entry.initiatedBy.app.displayName) (app)" }
                       else                                            { "—" }

        $roleName  = "—"
        $principal = "—"

        # 1. Try modifiedProperties — most reliable, covers both add and remove events
        if ($entry.modifiedProperties) {
            # Try Role.DisplayName
            $roleProp = $entry.modifiedProperties | Where-Object { $_.displayName -eq "Role.DisplayName" } | Select-Object -First 1
            if ($roleProp) {
                $val = if ($roleProp.newValue -and $roleProp.newValue -notin @('""','"','')) { $roleProp.newValue -replace '^"|"$','' }
                       elseif ($roleProp.oldValue -and $roleProp.oldValue -notin @('""','"','')) { $roleProp.oldValue -replace '^"|"$','' }
                       else { $null }
                # Ignore generic type-name strings that Graph sometimes stores as the display name
                if ($val -and $val -notin @("User","Role","Group","ServicePrincipal","Device")) { $roleName = $val }
            }
            # Fallback: try Role.TemplateId and resolve via roleDefMap
            if ($roleName -eq "—") {
                $tidProp = $entry.modifiedProperties | Where-Object { $_.displayName -eq "Role.TemplateId" } | Select-Object -First 1
                if ($tidProp) {
                    $tid = if ($tidProp.newValue -and $tidProp.newValue -notin @('""','"','')) { $tidProp.newValue -replace '^"|"$','' }
                           elseif ($tidProp.oldValue -and $tidProp.oldValue -notin @('""','"','')) { $tidProp.oldValue -replace '^"|"$','' }
                           else { $null }
                    if ($tid -and $roleDefMap[$tid]) { $roleName = $roleDefMap[$tid] }
                }
            }
        }

        # 2. Resolve principal from targetResources (non-Role types)
        if ($entry.targetResources -and $entry.targetResources.Count -gt 0) {
            foreach ($tr in $entry.targetResources) {
                if ($tr.type -eq "Role") { continue }
                $name = if ($tr.userPrincipalName) { $tr.userPrincipalName }
                        elseif ($tr.displayName -and $tr.displayName -ne $tr.type) { $tr.displayName }
                        else { $tr.id }
                if ($principal -eq "—") { $principal = $name } else { $principal += " | $name" }
            }
        }

        # 3. Fallback: try targetResources type=Role if still unresolved
        if ($roleName -eq "—" -and $entry.targetResources) {
            $roleTr = $entry.targetResources | Where-Object { $_.type -eq "Role" } | Select-Object -First 1
            if ($roleTr) {
                $roleName = if     ($roleTr.displayName -and $roleTr.displayName -notin @("Role","User","Group","")) { $roleTr.displayName }
                            elseif ($roleDefMap[$roleTr.id]) { $roleDefMap[$roleTr.id] }
                            else   { $roleTr.id }
            }
        }

        # Pull justification from additionalDetails
        $justification = "—"
        if ($entry.additionalDetails) {
            $justProp = $entry.additionalDetails | Where-Object { $_.key -in @("justification","Justification") } | Select-Object -First 1
            if ($justProp) { $justification = $justProp.value }
        }

        $results.Add([PSCustomObject]@{
            DateTime      = if ($entry.activityDateTime) { ([datetime]$entry.activityDateTime).ToString("yyyy-MM-dd HH:mm") } else { "—" }
            Activity      = $entry.activityDisplayName
            Result        = if ($entry.result) { $entry.result } else { "—" }
            Role          = $roleName
            Principal     = $principal
            InitiatedBy   = $initiatedBy
            Justification = $justification
            CorrelationId = $entry.correlationId
        })
    }

    # Post-process: batch-resolve any role GUIDs that survived all previous lookups
    $unresolvedGuids = $results |
        Where-Object { $_.Role -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' } |
        Select-Object -ExpandProperty Role -Unique
    if ($unresolvedGuids) {
        Write-Host "  Resolving $($unresolvedGuids.Count) unresolved role GUID(s)..." -ForegroundColor DarkGray
        $resolvedNames = @{}
        foreach ($guid in $unresolvedGuids) {
            # Try as role definition (modern API)
            try {
                $rd = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/$guid" -ErrorAction Stop
                if ($rd.displayName) { $resolvedNames[$guid] = $rd.displayName; continue }
            } catch {}
            # Try as activated directory role object (older API — used by Add/Remove-MgDirectoryRoleMember)
            try {
                $dr = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$guid" -ErrorAction Stop
                if ($dr.displayName) { $resolvedNames[$guid] = $dr.displayName; continue }
            } catch {}
            # Try as group (role-assignable groups are tracked by group ID in the audit log)
            try {
                $grp = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/$($guid)?`$select=displayName,isAssignableToRole" -ErrorAction Stop
                if ($grp.displayName) {
                    $label = if ($grp.isAssignableToRole) { "$($grp.displayName) (role group)" } else { $grp.displayName }
                    $resolvedNames[$guid] = $label; continue
                }
            } catch {}
        }
        foreach ($r in $results) {
            if ($resolvedNames[$r.Role]) {
                $r.Role = $resolvedNames[$r.Role]
            } elseif ($r.Role -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' -and $r.Activity -eq "Update role") {
                $r.Role = "PIM policy update"
            }
        }
    }

    $sorted = $results | Sort-Object DateTime -Descending

    Write-Host ""
    $header = "  {0,-18} {1,-45} {2,-10} {3,-35} {4,-35} {5}" -f "DateTime", "Activity", "Result", "Role", "Principal", "Initiated By"
    Write-Host $header -ForegroundColor Gray
    Write-Host ("  " + "─" * 150) -ForegroundColor DarkGray

    foreach ($entry in $sorted) {
        $color = if ($ResultColors[$entry.Result]) { $ResultColors[$entry.Result] } else { "White" }
        Write-Host ("  {0,-18} {1,-45} {2,-10} {3,-35} {4,-35} {5}" -f $entry.DateTime, $entry.Activity, $entry.Result, $entry.Role, $entry.Principal, $entry.InitiatedBy) -ForegroundColor $color
    }

    $success  = ($results | Where-Object { $_.Result -eq "success" }).Count
    $failures = ($results | Where-Object { $_.Result -eq "failure" }).Count
    Write-Host ""
    Write-Host "  Total events     : $($results.Count)" -ForegroundColor Cyan
    if ($success  -gt 0) { Write-Host "  Success          : $success"  -ForegroundColor Green  }
    if ($failures -gt 0) { Write-Host "  Failures         : $failures" -ForegroundColor Red    }
    Write-Host ""
    Write-Host "  Breakdown by activity (top 10):" -ForegroundColor Gray
    $results | Group-Object Activity | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object {
        Write-Host ("    {0,-55}: {1}" -f $_.Name, $_.Count) -ForegroundColor White
    }

    Write-CsvBom -Data $sorted -Path (Join-Path $script:ExportFolder "AuditSuite_PIMActivationHistory_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv")
}

# ── [9] PIM Security Alerts ───────────────────────────────────────────────────
function Invoke-PIMSecurityAlerts {
    Write-Host ""
    Write-Host "  Running: PIM Security Alerts" -ForegroundColor Cyan

    $SeverityColors = @{
        "high"          = "Red"
        "medium"        = "Yellow"
        "low"           = "DarkYellow"
        "informational" = "Cyan"
        "unknown"       = "DarkGray"
    }

    $allAlerts = [System.Collections.Generic.List[object]]::new()
    $uri = "https://graph.microsoft.com/beta/identityGovernance/roleManagementAlerts/alerts?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'&`$expand=alertDefinition"
    try {
        do {
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            foreach ($a in $response.value) { $allAlerts.Add($a) }
            $uri = $response.'@odata.nextLink'
        } while ($uri)
    } catch {
        Write-Host "  FATAL: Could not retrieve PIM alerts." -ForegroundColor Red
        Write-Host "  Error: $_" -ForegroundColor Red
        return
    }
    Write-Host "  PIM alerts found : $($allAlerts.Count)" -ForegroundColor DarkGray

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($alert in $allAlerts) {
        $def = $alert.alertDefinition
        $results.Add([PSCustomObject]@{
            DisplayName     = $alert.displayName
            Severity        = if ($alert.severity) { $alert.severity } else { "unknown" }
            IsActive        = $alert.isActive.ToString()
            IncidentCount   = if ($null -ne $alert.incidentCount) { $alert.incidentCount } else { 0 }
            LastModified    = if ($alert.lastModifiedDateTime) { ([datetime]$alert.lastModifiedDateTime).ToString("yyyy-MM-dd HH:mm") } else { "—" }
            SecurityImpact  = if ($def -and $def.securityImpact)  { $def.securityImpact  } else { "—" }
            HowToPrevent    = if ($def -and $def.howToPrevent)    { $def.howToPrevent    } else { "—" }
            MitigationSteps = if ($def -and $def.mitigationSteps) { $def.mitigationSteps } else { "—" }
            IsRemediatable  = if ($def -and $null -ne $def.isRemediatable) { $def.isRemediatable.ToString() } else { "—" }
        })
    }

    $sorted = $results | Sort-Object @(
        @{ Expression = { if ($_.IsActive -eq "True") { 0 } else { 1 } } }
        @{ Expression = { switch ($_.Severity) { "high" { 0 } "medium" { 1 } "low" { 2 } "informational" { 3 } default { 4 } } } }
    )

    $activeAlerts = $sorted | Where-Object { $_.IsActive -eq "True" }

    Write-Host ""
    if ($activeAlerts.Count -eq 0) {
        Write-Host "  No active PIM security alerts." -ForegroundColor Green
    } else {
        Write-Host "  Active alerts:" -ForegroundColor Gray
        Write-Host ("  " + "─" * 110) -ForegroundColor DarkGray
        foreach ($entry in $activeAlerts) {
            $color = if ($SeverityColors[$entry.Severity]) { $SeverityColors[$entry.Severity] } else { "White" }
            Write-Host ("  [{0,-13}] {1,-55} Incidents: {2}" -f $entry.Severity.ToUpper(), $entry.DisplayName, $entry.IncidentCount) -ForegroundColor $color
            if ($entry.SecurityImpact -ne "—") {
                Write-Host ("    Impact  : {0}" -f $entry.SecurityImpact.Substring(0, [Math]::Min(110, $entry.SecurityImpact.Length))) -ForegroundColor DarkGray
            }
            if ($entry.HowToPrevent -ne "—") {
                Write-Host ("    Prevent : {0}" -f $entry.HowToPrevent.Substring(0, [Math]::Min(110, $entry.HowToPrevent.Length))) -ForegroundColor DarkGray
            }
        }
    }

    $high     = ($activeAlerts | Where-Object { $_.Severity -eq "high"   }).Count
    $medium   = ($activeAlerts | Where-Object { $_.Severity -eq "medium" }).Count
    $inactive = ($results      | Where-Object { $_.IsActive -eq "False"  }).Count
    Write-Host ""
    Write-Host "  Total alerts     : $($results.Count)" -ForegroundColor Cyan
    Write-Host "  Active           : $($activeAlerts.Count)" -ForegroundColor $(if ($activeAlerts.Count -gt 0) { "Yellow" } else { "Green" })
    Write-Host "  Resolved/inactive: $inactive" -ForegroundColor DarkGray
    if ($high   -gt 0) { Write-Host "  High severity    : $high"   -ForegroundColor Red    }
    if ($medium -gt 0) { Write-Host "  Medium severity  : $medium" -ForegroundColor Yellow }

    # ── Executive findings ────────────────────────────────────────────────────
    foreach ($alert in $activeAlerts) {
        $sev = switch ($alert.Severity) { "high" { "High" } "medium" { "Medium" } default { "Low" } }
        $detail = if ($alert.SecurityImpact -ne "—") { $alert.SecurityImpact.Substring(0, [Math]::Min(200, $alert.SecurityImpact.Length)) } else { "$($alert.IncidentCount) incident(s) detected." }
        $rec    = if ($alert.HowToPrevent   -ne "—") { $alert.HowToPrevent.Substring(0,   [Math]::Min(200, $alert.HowToPrevent.Length))   } else { "Review and remediate this alert in the Entra ID PIM portal." }
        Add-Finding -Category "PIM Security Alerts" -Severity $sev `
            -Title $alert.DisplayName `
            -Detail $detail `
            -Recommendation $rec
    }

    Write-CsvBom -Data $sorted -Path (Join-Path $script:ExportFolder "AuditSuite_PIMSecurityAlerts_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv")
}

# ── [10] Find Inactive Devices ────────────────────────────────────────────────
function Invoke-FindInactiveDevices {
    param([int]$Threshold = 0)
    Write-Host ""
    Write-Host "  Running: Find Inactive Devices" -ForegroundColor Cyan

    if ($Threshold -gt 0) {
        $threshold = $Threshold
        Write-Host "  Inactivity threshold : $threshold days (default)" -ForegroundColor DarkGray
    } else {
        $threshold = $null
        while ($null -eq $threshold) {
            $thresholdInput = Read-Host "  Flag devices inactive for more than how many days"
            if ($thresholdInput -match '^\d+$' -and [int]$thresholdInput -gt 0) { $threshold = [int]$thresholdInput }
            else { Write-Host "  Please enter a positive number." -ForegroundColor Yellow }
        }
    }

    $devices = Get-MgDevice -All `
        -Property Id,DisplayName,DeviceId,OperatingSystem,OperatingSystemVersion,TrustType,IsCompliant,IsManaged,AccountEnabled,ApproximateLastSignInDateTime `
        -ErrorAction Stop
    Write-Host "  Entra devices    : $($devices.Count)" -ForegroundColor DarkGray

    $intuneByDeviceId = @{}
    try {
        $intuneDevices = Get-MgDeviceManagementManagedDevice -All -Property AzureAdDeviceId,LastSyncDateTime -ErrorAction Stop
        foreach ($d in $intuneDevices) { if ($d.AzureAdDeviceId) { $intuneByDeviceId[$d.AzureAdDeviceId] = $d.LastSyncDateTime } }
    } catch {
        Write-Host "  WARN: Could not retrieve Intune devices. $_" -ForegroundColor Yellow
    }

    $now     = Get-Date
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($device in $devices) {
        $entraDate  = $device.ApproximateLastSignInDateTime
        $intuneDate = $intuneByDeviceId[$device.DeviceId]
        $lastActivity = $null
        if   ($entraDate  -and -not $intuneDate) { $lastActivity = $entraDate  }
        elseif ($intuneDate -and -not $entraDate)  { $lastActivity = $intuneDate }
        elseif ($entraDate  -and $intuneDate)      { $lastActivity = if ($entraDate -gt $intuneDate) { $entraDate } else { $intuneDate } }

        $daysSince  = if ($lastActivity) { [math]::Floor(($now - $lastActivity).TotalDays) } else { $null }
        $isInactive = ($null -eq $daysSince) -or ($daysSince -gt $threshold)
        if (-not $isInactive) { continue }

        $trustLabel = if (-not $device.TrustType) { "Unknown" } elseif ($TrustTypeLabels[$device.TrustType]) { $TrustTypeLabels[$device.TrustType] } else { $device.TrustType }

        $results.Add([PSCustomObject]@{
            DisplayName       = $device.DisplayName
            DeviceId          = $device.DeviceId
            ObjectId          = $device.Id
            OperatingSystem   = $device.OperatingSystem
            OSVersion         = $device.OperatingSystemVersion
            TrustType         = $trustLabel
            IsCompliant       = if ($null -eq $device.IsCompliant) { "Unknown" } else { $device.IsCompliant.ToString() }
            AccountEnabled    = $device.AccountEnabled.ToString()
            EntraLastSignIn   = if ($entraDate)  { $entraDate.ToString("yyyy-MM-dd")  } else { "Never" }
            IntuneLastSync    = if ($intuneDate) { $intuneDate.ToString("yyyy-MM-dd") } else { "" }
            LastActivity      = if ($lastActivity) { $lastActivity.ToString("yyyy-MM-dd") } else { "Never" }
            DaysSinceActivity = if ($null -ne $daysSince) { $daysSince } else { "" }
        })
    }

    if ($results.Count -eq 0) {
        Write-Host "  No inactive devices found (threshold: $threshold days)." -ForegroundColor Green
        return
    }

    $sorted = $results | Sort-Object @(
        @{ Expression = { if ($_.LastActivity -eq "Never") { 0 } else { 1 } } }
        @{ Expression = "DaysSinceActivity"; Descending = $true }
    )

    Write-Host ""
    foreach ($entry in $sorted) {
        $daysLabel = if ($entry.DaysSinceActivity -ne "") { "$($entry.DaysSinceActivity)d ago" } else { "never seen" }
        $color     = if ($entry.LastActivity -eq "Never" -or ($entry.DaysSinceActivity -ne "" -and [int]$entry.DaysSinceActivity -gt ($threshold * 2))) { "Red" } else { "Yellow" }
        Write-Host ("  {0,-40} {1,-22} {2,-20} Last activity: {3}" -f $entry.DisplayName, $entry.TrustType, $entry.OperatingSystem, $daysLabel) -ForegroundColor $color
    }

    $neverSeen = ($results | Where-Object { $_.LastActivity -eq "Never" }).Count
    Write-Host ""
    Write-Host "  Inactive devices (>$threshold days): $($results.Count)" -ForegroundColor Yellow
    if ($neverSeen -gt 0) { Write-Host "  Never seen: $neverSeen" -ForegroundColor Red }

    # ── Executive findings ────────────────────────────────────────────────────
    if ($results.Count -gt 0) {
        $neverNote = if ($neverSeen -gt 0) { " $neverSeen device(s) have never been seen at all." } else { "" }
        Add-Finding -Category "Devices" -Severity "Low" `
            -Title "$($results.Count) device$(if ($results.Count -ne 1) {'s'}) inactive for more than $threshold days" `
            -Detail "Inactive devices consume licenses and expand the attack surface.$neverNote" `
            -Recommendation "Review the inactive device list and disable or delete devices no longer in use."
    }

    Write-CsvBom -Data $sorted -Path (Join-Path $script:ExportFolder "AuditSuite_InactiveDevices_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv")
}

# ── [9] Find Inactive Users ───────────────────────────────────────────────────
function Invoke-FindInactiveUsers {
    param([int]$Threshold = 0)
    Write-Host ""
    Write-Host "  Running: Find Inactive Users" -ForegroundColor Cyan

    if ($Threshold -gt 0) {
        $threshold = $Threshold
        Write-Host "  Inactivity threshold : $threshold days (default)" -ForegroundColor DarkGray
    } else {
        $threshold = $null
        while ($null -eq $threshold) {
            $thresholdInput = Read-Host "  Flag users inactive for more than how many days"
            if ($thresholdInput -match '^\d+$' -and [int]$thresholdInput -gt 0) { $threshold = [int]$thresholdInput }
            else { Write-Host "  Please enter a positive number." -ForegroundColor Yellow }
        }
    }

    $users = Get-MgUser -All `
        -Property "Id,DisplayName,UserPrincipalName,UserType,AccountEnabled,SignInActivity" `
        -ErrorAction Stop
    Write-Host "  Users            : $($users.Count)" -ForegroundColor DarkGray

    $now     = Get-Date
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($user in $users) {
        $lastInteractive    = $user.SignInActivity.LastSignInDateTime
        $lastNonInteractive = $user.SignInActivity.LastNonInteractiveSignInDateTime

        # Most recent of interactive and non-interactive
        $lastActivity = $null
        if   ($lastInteractive    -and -not $lastNonInteractive) { $lastActivity = $lastInteractive }
        elseif ($lastNonInteractive -and -not $lastInteractive)    { $lastActivity = $lastNonInteractive }
        elseif ($lastInteractive    -and $lastNonInteractive)      { $lastActivity = if ($lastInteractive -gt $lastNonInteractive) { $lastInteractive } else { $lastNonInteractive } }

        $daysSince  = if ($lastActivity) { [math]::Floor(($now - $lastActivity).TotalDays) } else { $null }
        $isInactive = ($null -eq $daysSince) -or ($daysSince -gt $threshold)

        $results.Add([PSCustomObject]@{
            DisplayName              = $user.DisplayName
            UserPrincipalName        = $user.UserPrincipalName
            UserType                 = $user.UserType
            AccountEnabled           = $user.AccountEnabled.ToString()
            LastInteractiveSignIn    = if ($lastInteractive)    { $lastInteractive.ToString("yyyy-MM-dd")    } else { "Never" }
            LastNonInteractiveSignIn = if ($lastNonInteractive) { $lastNonInteractive.ToString("yyyy-MM-dd") } else { "Never" }
            LastActivity             = if ($lastActivity) { $lastActivity.ToString("yyyy-MM-dd") } else { "Never" }
            DaysSinceActivity        = if ($null -ne $daysSince) { $daysSince } else { "" }
            IsInactive               = $isInactive.ToString()
        })
    }

    $sorted = $results | Sort-Object @(
        @{ Expression = { if ($_.IsInactive -eq "True") { 0 } else { 1 } } }
        @{ Expression = { if ($_.LastActivity -eq "Never") { 0 } else { 1 } } }
        @{ Expression = "DaysSinceActivity"; Descending = $true }
    )

    Write-Host ""
    foreach ($entry in ($sorted | Where-Object { $_.IsInactive -eq "True" })) {
        $daysLabel = if ($entry.DaysSinceActivity -ne "") { "$($entry.DaysSinceActivity)d ago" } else { "never seen" }
        $color     = if ($entry.LastActivity -eq "Never") { "Red" } elseif ($entry.AccountEnabled -eq "False") { "DarkGray" } else { "Yellow" }
        Write-Host ("  {0,-40} {1,-42} Last activity: {2}" -f $entry.DisplayName, $entry.UserPrincipalName, $daysLabel) -ForegroundColor $color
    }

    $inactive  = ($results | Where-Object { $_.IsInactive -eq "True" }).Count
    $neverSeen = ($results | Where-Object { $_.LastActivity -eq "Never" }).Count
    Write-Host ""
    Write-Host "  Total users              : $($results.Count)"      -ForegroundColor Cyan
    Write-Host "  Inactive (>$threshold days): $inactive"            -ForegroundColor Yellow
    if ($neverSeen -gt 0) { Write-Host "  Never seen               : $neverSeen" -ForegroundColor Red }

    # ── Executive findings ────────────────────────────────────────────────────
    $inactiveEnabled = ($results | Where-Object { $_.IsInactive -eq "True" -and $_.AccountEnabled -eq "True" }).Count
    if ($inactiveEnabled -gt 0) {
        Add-Finding -Category "Identity" -Severity "Medium" `
            -Title "$inactiveEnabled enabled account$(if ($inactiveEnabled -ne 1) {'s'}) inactive for more than $threshold days" `
            -Detail "Enabled accounts with no sign-in activity are orphaned credentials that could be exploited if compromised." `
            -Recommendation "Disable or delete accounts that are no longer actively used."
    }

    Write-CsvBom -Data $sorted -Path (Join-Path $script:ExportFolder "AuditSuite_InactiveUsers_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv")
}

# ── [10] Domain Export ────────────────────────────────────────────────────────
function Invoke-DomainExport {
    Write-Host ""
    Write-Host "  Running: Domain Export" -ForegroundColor Cyan

    $domains = Get-MgDomain -All -ErrorAction Stop
    Write-Host "  Domains found    : $($domains.Count)" -ForegroundColor DarkGray

    $results = foreach ($domain in $domains) {
        $services = if ($domain.SupportedServices -and $domain.SupportedServices.Count -gt 0) {
            $domain.SupportedServices -join " | "
        } else { "—" }

        [PSCustomObject]@{
            DomainName       = $domain.Id
            IsDefault        = $domain.IsDefault.ToString()
            IsInitial        = $domain.IsInitial.ToString()
            IsVerified       = $domain.IsVerified.ToString()
            IsAdminManaged   = $domain.IsAdminManaged.ToString()
            AuthType         = $domain.AuthenticationType
            SupportedServices = $services
        }
    }

    $sorted = $results | Sort-Object @(
        @{ Expression = { if ($_.IsDefault -eq "True") { 0 } else { 1 } } }
        @{ Expression = "DomainName" }
    )

    Write-Host ""
    $headerLine = "  {0,-45} {1,-9} {2,-9} {3,-10} {4,-15} {5}" -f "Domain", "Default", "Verified", "AuthType", "AdminManaged", "Services"
    Write-Host $headerLine -ForegroundColor Gray
    Write-Host ("  " + "─" * 110) -ForegroundColor DarkGray

    foreach ($entry in $sorted) {
        $color = if ($entry.IsDefault  -eq "True")  { "Green"  } `
                 elseif ($entry.IsVerified -eq "False") { "Yellow" } `
                 else { "White" }
        Write-Host ("  {0,-45} {1,-9} {2,-9} {3,-10} {4,-15} {5}" -f `
            $entry.DomainName,
            $entry.IsDefault,
            $entry.IsVerified,
            $entry.AuthType,
            $entry.IsAdminManaged,
            $entry.SupportedServices) -ForegroundColor $color
    }

    $unverified = ($results | Where-Object { $_.IsVerified -eq "False" }).Count
    $federated  = ($results | Where-Object { $_.AuthType -eq "Federated" }).Count
    Write-Host ""
    Write-Host "  Total domains  : $($results.Count)" -ForegroundColor Cyan
    if ($unverified -gt 0) { Write-Host "  Unverified     : $unverified" -ForegroundColor Yellow }
    if ($federated  -gt 0) { Write-Host "  Federated      : $federated"  -ForegroundColor Cyan   }

    Write-CsvBom -Data $sorted -Path (Join-Path $script:ExportFolder "AuditSuite_DomainExport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv")
}

# ── [11] Guest User Report ────────────────────────────────────────────────────
function Invoke-GuestUserReport {
    Write-Host ""
    Write-Host "  Running: Guest User Report" -ForegroundColor Cyan

    $guests = Get-MgUser -All -Filter "userType eq 'Guest'" `
        -Property "Id,DisplayName,UserPrincipalName,Mail,ExternalUserState,ExternalUserStateChangeDateTime,CreatedDateTime,AccountEnabled,SignInActivity" `
        -ErrorAction Stop
    Write-Host "  Guest accounts   : $($guests.Count)" -ForegroundColor DarkGray

    $now     = Get-Date
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($guest in $guests) {
        $lastInteractive    = $guest.SignInActivity.LastSignInDateTime
        $lastNonInteractive = $guest.SignInActivity.LastNonInteractiveSignInDateTime
        $lastActivity       = $null
        if   ($lastInteractive    -and -not $lastNonInteractive) { $lastActivity = $lastInteractive }
        elseif ($lastNonInteractive -and -not $lastInteractive)  { $lastActivity = $lastNonInteractive }
        elseif ($lastInteractive    -and $lastNonInteractive)    { $lastActivity = if ($lastInteractive -gt $lastNonInteractive) { $lastInteractive } else { $lastNonInteractive } }
        $daysSince = if ($lastActivity) { [math]::Floor(($now - $lastActivity).TotalDays) } else { $null }

        $results.Add([PSCustomObject]@{
            DisplayName       = $guest.DisplayName
            UserPrincipalName = $guest.UserPrincipalName
            ExternalEmail     = if ($guest.Mail) { $guest.Mail } else { "—" }
            AccountEnabled    = $guest.AccountEnabled.ToString()
            ExternalUserState = if ($guest.ExternalUserState) { $guest.ExternalUserState } else { "—" }
            StateChangedDate  = if ($guest.ExternalUserStateChangeDateTime) { $guest.ExternalUserStateChangeDateTime.ToString("yyyy-MM-dd") } else { "—" }
            CreatedDate       = if ($guest.CreatedDateTime) { $guest.CreatedDateTime.ToString("yyyy-MM-dd") } else { "—" }
            LastSignIn        = if ($lastActivity) { $lastActivity.ToString("yyyy-MM-dd") } else { "Never" }
            DaysSinceSignIn   = if ($null -ne $daysSince) { $daysSince } else { "" }
        })
    }

    $sorted = $results | Sort-Object @(
        @{ Expression = { if ($_.ExternalUserState -eq "PendingAcceptance") { 0 } else { 1 } } }
        @{ Expression = { if ($_.LastSignIn -eq "Never") { 0 } else { 1 } } }
        @{ Expression = "DaysSinceSignIn"; Descending = $true }
    )

    Write-Host ""
    $header = "  {0,-35} {1,-32} {2,-12} {3,-22} {4,-12} {5}" -f "Display Name", "External Email", "Enabled", "State", "Created", "Last Sign-in"
    Write-Host $header -ForegroundColor Gray
    Write-Host ("  " + "─" * 120) -ForegroundColor DarkGray

    foreach ($entry in $sorted) {
        $color = if ($entry.ExternalUserState -eq "PendingAcceptance") { "Yellow" }
                 elseif ($entry.LastSignIn -eq "Never")                { "Red"    }
                 elseif ($entry.AccountEnabled -eq "False")            { "DarkGray" }
                 else                                                   { "Green"  }
        $daysLabel = if ($entry.DaysSinceSignIn -ne "") { "$($entry.DaysSinceSignIn)d ago" } else { "never" }
        Write-Host ("  {0,-35} {1,-32} {2,-12} {3,-22} {4,-12} {5}" -f `
            $entry.DisplayName, $entry.ExternalEmail, $entry.AccountEnabled, $entry.ExternalUserState, $entry.CreatedDate, $daysLabel) -ForegroundColor $color
    }

    $pending = ($results | Where-Object { $_.ExternalUserState -eq "PendingAcceptance" }).Count
    $never   = ($results | Where-Object { $_.LastSignIn        -eq "Never"             }).Count
    Write-Host ""
    Write-Host "  Total guests     : $($results.Count)" -ForegroundColor Cyan
    if ($pending -gt 0) { Write-Host "  Pending acceptance: $pending" -ForegroundColor Yellow }
    if ($never   -gt 0) { Write-Host "  Never signed in  : $never"    -ForegroundColor Red    }

    Write-CsvBom -Data $sorted -Path (Join-Path $script:ExportFolder "AuditSuite_GuestUsers_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv")
}

# ── [12] Group Export ─────────────────────────────────────────────────────────
function Invoke-GroupExport {
    Write-Host ""
    Write-Host "  Running: Group Export" -ForegroundColor Cyan

    $groups = Get-MgGroup -All `
        -Property "Id,DisplayName,Description,GroupTypes,MailEnabled,SecurityEnabled,Visibility,CreatedDateTime,MembershipRule,MembershipRuleProcessingState,ResourceProvisioningOptions,OnPremisesSyncEnabled,IsAssignableToRole" `
        -ErrorAction Stop
    Write-Host "  Groups found     : $($groups.Count)" -ForegroundColor DarkGray
    Write-Host "  Fetching member and owner counts..." -ForegroundColor DarkGray

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($group in $groups) {
        $isDynamic = $group.GroupTypes -contains "DynamicMembership"
        $isUnified = $group.GroupTypes -contains "Unified"
        $isTeam    = $group.ResourceProvisioningOptions -contains "Team"
        $isHybrid  = $group.OnPremisesSyncEnabled -eq $true

        $groupType = if ($isTeam)                                              { "Team"                  }
                     elseif ($isUnified)                                       { "Microsoft 365"         }
                     elseif ($group.MailEnabled -and -not $group.SecurityEnabled) { "Distribution"      }
                     elseif ($group.SecurityEnabled -and $group.MailEnabled)   { "Mail-enabled Security" }
                     else                                                       { "Security"              }

        # Efficient member count via CountVariable (avoids fetching all members)
        $memberCount = 0
        try {
            Get-MgGroupMember -GroupId $group.Id -Top 1 -CountVariable memberCnt -ConsistencyLevel eventual -ErrorAction Stop | Out-Null
            $memberCount = if ($memberCnt) { [int]$memberCnt } else { 0 }
        } catch {}

        $ownerCount = 0
        try { $ownerCount = (Get-MgGroupOwner -GroupId $group.Id -All -ErrorAction Stop).Count } catch {}

        $results.Add([PSCustomObject]@{
            DisplayName          = $group.DisplayName
            GroupType            = $groupType
            MembershipType       = if ($isDynamic) { "Dynamic" } else { "Assigned" }
            MemberCount          = $memberCount
            OwnerCount           = $ownerCount
            SecurityEnabled      = $group.SecurityEnabled.ToString()
            MailEnabled          = $group.MailEnabled.ToString()
            Visibility           = if ($group.Visibility) { $group.Visibility } else { "—" }
            IsHybridSynced       = $isHybrid.ToString()
            IsRoleAssignable     = ($group.IsAssignableToRole -eq $true).ToString()
            MembershipRule       = if ($isDynamic -and $group.MembershipRule) { $group.MembershipRule } else { "—" }
            CreatedDate          = if ($group.CreatedDateTime) { $group.CreatedDateTime.ToString("yyyy-MM-dd") } else { "—" }
            Description          = if ($group.Description) { $group.Description } else { "—" }
        })
    }

    $sorted = $results | Sort-Object GroupType, DisplayName
    Write-Host ""
    $header = "  {0,-45} {1,-20} {2,-12} {3,8} {4,7} {5,-12} {6,-8} {7}" -f "Display Name", "Type", "Membership", "Members", "Owners", "Visibility", "Hybrid", "RoleAssignable"
    Write-Host $header -ForegroundColor Gray
    Write-Host ("  " + "─" * 130) -ForegroundColor DarkGray

    foreach ($entry in $sorted) {
        $flags     = ""
        if ($entry.OwnerCount        -eq 0)      { $flags += " [NO OWNER]"       }
        if ($entry.IsRoleAssignable  -eq "True")  { $flags += " [ROLE-ASSIGNABLE]" }
        $color = if ($entry.IsRoleAssignable -eq "True") { "Cyan"   }
                 elseif ($entry.OwnerCount   -eq 0)      { "Yellow" }
                 else                                     { "Green"  }
        Write-Host ("  {0,-45} {1,-20} {2,-12} {3,8} {4,7} {5,-12} {6,-8} {7}{8}" -f `
            $entry.DisplayName, $entry.GroupType, $entry.MembershipType, $entry.MemberCount, $entry.OwnerCount, $entry.Visibility, $entry.IsHybridSynced, $entry.IsRoleAssignable, $flags) -ForegroundColor $color
    }

    $noOwner        = ($results | Where-Object { $_.OwnerCount       -eq 0      }).Count
    $roleAssignable = ($results | Where-Object { $_.IsRoleAssignable -eq "True" }).Count
    Write-Host ""
    Write-Host "  Total groups     : $($results.Count)" -ForegroundColor Cyan
    $results | Group-Object GroupType | Sort-Object Count -Descending | ForEach-Object {
        Write-Host ("  {0,-25}: {1}" -f $_.Name, $_.Count) -ForegroundColor Cyan
    }
    if ($noOwner        -gt 0) { Write-Host "  No owner         : $noOwner"        -ForegroundColor Yellow }
    if ($roleAssignable -gt 0) { Write-Host "  Role-assignable  : $roleAssignable" -ForegroundColor Cyan   }

    Write-CsvBom -Data $sorted -Path (Join-Path $script:ExportFolder "AuditSuite_GroupExport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv")
}

# ── [13] Sign-in Log Export ───────────────────────────────────────────────────
function Invoke-SignInLogExport {
    param([int]$Days = 0)
    Write-Host ""
    Write-Host "  Running: Sign-in Log Export" -ForegroundColor Cyan

    if ($Days -gt 0) {
        $lookback = $Days
        Write-Host "  Lookback         : $lookback days (default)" -ForegroundColor DarkGray
    } else {
        $lookback = $null
        while ($null -eq $lookback) {
            $inp = Read-Host "  How many days back to export (e.g. 7)"
            if ($inp -match '^\d+$' -and [int]$inp -gt 0) { $lookback = [int]$inp }
            else { Write-Host "  Please enter a positive number." -ForegroundColor Yellow }
        }
    }

    $since = (Get-Date).AddDays(-$lookback).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    Write-Host "  Fetching sign-in logs (last $lookback days)..." -ForegroundColor DarkGray

    try {
        $signIns = Get-MgAuditLogSignIn -All -Filter "createdDateTime ge $since" -ErrorAction Stop
        Write-Host "  Sign-in records  : $($signIns.Count)" -ForegroundColor DarkGray
    } catch {
        Write-Host "  FATAL: Could not retrieve sign-in logs: $_" -ForegroundColor Red
        return
    }

    $results = foreach ($s in $signIns) {
        $location = if ($s.Location) { "$($s.Location.City), $($s.Location.CountryOrRegion)" } else { "—" }
        $risk     = if ($s.RiskLevelDuringSignIn -and $s.RiskLevelDuringSignIn -ne "none") { $s.RiskLevelDuringSignIn } else { "—" }
        $status   = if ($s.Status.ErrorCode -eq 0) { "Success" } else { "Failure ($($s.Status.ErrorCode))" }

        [PSCustomObject]@{
            DateTime                = $s.CreatedDateTime.ToString("yyyy-MM-dd HH:mm:ss")
            UserPrincipalName       = $s.UserPrincipalName
            AppDisplayName          = $s.AppDisplayName
            IPAddress               = $s.IpAddress
            Location                = $location
            Status                  = $status
            RiskLevel               = $risk
            ConditionalAccessStatus = if ($s.ConditionalAccessStatus) { $s.ConditionalAccessStatus } else { "—" }
            DeviceName              = if ($s.DeviceDetail.DisplayName)    { $s.DeviceDetail.DisplayName    } else { "—" }
            OperatingSystem         = if ($s.DeviceDetail.OperatingSystem) { $s.DeviceDetail.OperatingSystem } else { "—" }
            Browser                 = if ($s.DeviceDetail.Browser)        { $s.DeviceDetail.Browser        } else { "—" }
            ClientAppUsed           = $s.ClientAppUsed
        }
    }

    $sorted   = $results | Sort-Object DateTime -Descending
    $failures = $results | Where-Object { $_.Status -ne "Success" }
    $risky    = $results | Where-Object { $_.RiskLevel -ne "—" }

    Write-Host ""
    Write-Host ("  Total  : {0}  |  Failures: {1}  |  Risky: {2}" -f $results.Count, $failures.Count, $risky.Count) -ForegroundColor Cyan

    if ($failures.Count -gt 0) {
        Write-Host ""
        Write-Host "  Recent failures (first 10):" -ForegroundColor Yellow
        foreach ($f in ($failures | Sort-Object DateTime -Descending | Select-Object -First 10)) {
            Write-Host ("    {0}  {1,-42} {2}" -f $f.DateTime, $f.UserPrincipalName, $f.Status) -ForegroundColor Yellow
        }
        if ($failures.Count -gt 10) { Write-Host "    ... and $($failures.Count - 10) more — see CSV" -ForegroundColor DarkGray }
    }
    if ($risky.Count -gt 0) {
        Write-Host ""
        Write-Host "  Risky sign-ins:" -ForegroundColor Red
        foreach ($r in ($risky | Sort-Object DateTime -Descending | Select-Object -First 10)) {
            Write-Host ("    {0}  {1,-42} Risk: {2}" -f $r.DateTime, $r.UserPrincipalName, $r.RiskLevel) -ForegroundColor Red
        }
    }

    Write-CsvBom -Data $sorted -Path (Join-Path $script:ExportFolder "AuditSuite_SignInLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv")
}

# ── [14] Directory Audit Log ──────────────────────────────────────────────────
function Invoke-DirectoryAuditLog {
    param([int]$Days = 0)
    Write-Host ""
    Write-Host "  Running: Directory Audit Log" -ForegroundColor Cyan

    if ($Days -gt 0) {
        $lookback = $Days
        Write-Host "  Lookback         : $lookback days (default)" -ForegroundColor DarkGray
    } else {
        $lookback = $null
        while ($null -eq $lookback) {
            $inp = Read-Host "  How many days back to export (e.g. 7)"
            if ($inp -match '^\d+$' -and [int]$inp -gt 0) { $lookback = [int]$inp }
            else { Write-Host "  Please enter a positive number." -ForegroundColor Yellow }
        }
    }

    $since = (Get-Date).AddDays(-$lookback).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    Write-Host "  Fetching directory audit logs (last $lookback days)..." -ForegroundColor DarkGray

    try {
        $auditLogs = Get-MgAuditLogDirectoryAudit -All -Filter "activityDateTime ge $since" -ErrorAction Stop
        Write-Host "  Audit log entries: $($auditLogs.Count)" -ForegroundColor DarkGray
    } catch {
        Write-Host "  FATAL: Could not retrieve directory audit logs: $_" -ForegroundColor Red
        return
    }

    $results = foreach ($entry in $auditLogs) {
        $initiatedBy = if ($entry.InitiatedBy.User.UserPrincipalName) { $entry.InitiatedBy.User.UserPrincipalName }
                       elseif ($entry.InitiatedBy.App.DisplayName)    { "$($entry.InitiatedBy.App.DisplayName) (app)" }
                       else                                            { "—" }

        $targets = if ($entry.TargetResources -and $entry.TargetResources.Count -gt 0) {
            ($entry.TargetResources | ForEach-Object { if ($_.DisplayName) { $_.DisplayName } else { $_.Id } }) -join " | "
        } else { "—" }

        [PSCustomObject]@{
            DateTime      = $entry.ActivityDateTime.ToString("yyyy-MM-dd HH:mm:ss")
            Activity      = $entry.ActivityDisplayName
            Category      = $entry.Category
            InitiatedBy   = $initiatedBy
            Targets       = $targets
            Result        = $entry.Result
            CorrelationId = $entry.CorrelationId
        }
    }

    $sorted = $results | Sort-Object DateTime -Descending

    Write-Host ""
    Write-Host "  Total entries    : $($results.Count)" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Breakdown by category:" -ForegroundColor Gray
    $results | Group-Object Category | Sort-Object Count -Descending | ForEach-Object {
        Write-Host ("  {0,-35}: {1}" -f $_.Name, $_.Count) -ForegroundColor White
    }

    Write-CsvBom -Data $sorted -Path (Join-Path $script:ExportFolder "AuditSuite_DirectoryAuditLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv")
}

# ── [15] Enterprise Applications Export ──────────────────────────────────────
function Invoke-EnterpriseAppExport {
    Write-Host ""
    Write-Host "  Running: Enterprise Applications Export" -ForegroundColor Cyan

    $microsoftTenantId = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"

    $sps = Get-MgServicePrincipal -All `
        -Property "Id,DisplayName,AppId,AppOwnerOrganizationId,ServicePrincipalType,AccountEnabled,Homepage,Tags,SignInAudience" `
        -ErrorAction Stop
    Write-Host "  Service principals: $($sps.Count)" -ForegroundColor DarkGray

    $results = foreach ($sp in $sps) {
        $ownerType = if ($sp.AppOwnerOrganizationId -eq $microsoftTenantId) { "Microsoft"   }
                     elseif (-not $sp.AppOwnerOrganizationId)               { "Tenant"      }
                     else                                                    { "Third-party" }
        $isHidden  = $sp.Tags -contains "HideApp"

        [PSCustomObject]@{
            DisplayName          = $sp.DisplayName
            AppId                = $sp.AppId
            ObjectId             = $sp.Id
            ServicePrincipalType = $sp.ServicePrincipalType
            OwnerType            = $ownerType
            AccountEnabled       = $sp.AccountEnabled.ToString()
            VisibleInMyApps      = if ($isHidden) { "Hidden" } else { "Visible" }
            SignInAudience       = if ($sp.SignInAudience) { $sp.SignInAudience } else { "—" }
            Homepage             = if ($sp.Homepage) { $sp.Homepage } else { "—" }
            AppOwnerOrgId        = if ($sp.AppOwnerOrganizationId) { $sp.AppOwnerOrganizationId } else { "—" }
        }
    }

    $sorted = $results | Sort-Object OwnerType, DisplayName
    Write-Host ""
    $header = "  {0,-45} {1,-20} {2,-14} {3,-10} {4}" -f "Display Name", "Type", "Owner", "Enabled", "MyApps"
    Write-Host $header -ForegroundColor Gray
    Write-Host ("  " + "─" * 100) -ForegroundColor DarkGray

    foreach ($entry in $sorted) {
        $color = if ($entry.OwnerType -eq "Tenant")      { "Green"    }
                 elseif ($entry.OwnerType -eq "Third-party") { "Yellow" }
                 else                                         { "DarkGray" }
        Write-Host ("  {0,-45} {1,-20} {2,-14} {3,-10} {4}" -f `
            $entry.DisplayName, $entry.ServicePrincipalType, $entry.OwnerType, $entry.AccountEnabled, $entry.VisibleInMyApps) -ForegroundColor $color
    }

    $tenantApps = ($results | Where-Object { $_.OwnerType -eq "Tenant"      }).Count
    $thirdParty = ($results | Where-Object { $_.OwnerType -eq "Third-party" }).Count
    $disabled   = ($results | Where-Object { $_.AccountEnabled -eq "False"  }).Count
    Write-Host ""
    Write-Host "  Total SPs        : $($results.Count)" -ForegroundColor Cyan
    Write-Host "  Tenant-owned     : $tenantApps"       -ForegroundColor Green
    Write-Host "  Third-party      : $thirdParty"       -ForegroundColor Yellow
    if ($disabled -gt 0) { Write-Host "  Disabled         : $disabled" -ForegroundColor DarkGray }

    Write-CsvBom -Data $sorted -Path (Join-Path $script:ExportFolder "AuditSuite_EnterpriseApps_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv")
}

# ── [16] Delegated Permission Grants ─────────────────────────────────────────
function Invoke-DelegatedPermissionGrants {
    Write-Host ""
    Write-Host "  Running: Delegated Permission Grants" -ForegroundColor Cyan

    $grants = Get-MgOauth2PermissionGrant -All -ErrorAction Stop
    Write-Host "  Permission grants: $($grants.Count)" -ForegroundColor DarkGray

    # Build SP lookup by object ID for efficient resolution
    $allSPs = Get-MgServicePrincipal -All -Property "Id,DisplayName" -ErrorAction Stop
    $spById = @{}
    foreach ($sp in $allSPs) { $spById[$sp.Id] = $sp.DisplayName }

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($grant in $grants) {
        $clientName   = if ($spById[$grant.ClientId])   { $spById[$grant.ClientId]   } else { $grant.ClientId }
        $resourceName = if ($spById[$grant.ResourceId]) { $spById[$grant.ResourceId] } else { $grant.ResourceId }

        $grantedTo = "All Users (admin consent)"
        if ($grant.ConsentType -eq "Principal" -and $grant.PrincipalId) {
            try {
                $u = Get-MgUser -UserId $grant.PrincipalId -Property UserPrincipalName -ErrorAction Stop
                $grantedTo = $u.UserPrincipalName
            } catch { $grantedTo = $grant.PrincipalId }
        }

        $expiryStr = "—"
        if ($grant.ExpiryTime) {
            try { $expiryStr = ([datetime]$grant.ExpiryTime).ToString("yyyy-MM-dd") } catch {}
        }

        $results.Add([PSCustomObject]@{
            ClientApp    = $clientName
            ResourceApp  = $resourceName
            ConsentType  = if ($grant.ConsentType -eq "AllPrincipals") { "Admin (all users)" } else { "User" }
            GrantedTo    = $grantedTo
            Scopes       = if ($grant.Scope) { $grant.Scope.Trim() } else { "—" }
            Expiry       = $expiryStr
        })
    }

    $sorted = $results | Sort-Object ConsentType, ClientApp
    Write-Host ""
    $header = "  {0,-38} {1,-32} {2,-20} {3}" -f "Client App", "Resource", "Consent Type", "Granted To"
    Write-Host $header -ForegroundColor Gray
    Write-Host ("  " + "─" * 120) -ForegroundColor DarkGray

    foreach ($entry in $sorted) {
        $color = if ($entry.ConsentType -eq "Admin (all users)") { "Yellow" } else { "Green" }
        Write-Host ("  {0,-38} {1,-32} {2,-20} {3}" -f $entry.ClientApp, $entry.ResourceApp, $entry.ConsentType, $entry.GrantedTo) -ForegroundColor $color
    }

    $adminConsent = ($results | Where-Object { $_.ConsentType -eq "Admin (all users)" }).Count
    $userConsent  = ($results | Where-Object { $_.ConsentType -eq "User"              }).Count
    Write-Host ""
    Write-Host "  Total grants     : $($results.Count)" -ForegroundColor Cyan
    Write-Host "  Admin consent    : $adminConsent"     -ForegroundColor Yellow
    Write-Host "  User consent     : $userConsent"      -ForegroundColor Green

    Write-CsvBom -Data $sorted -Path (Join-Path $script:ExportFolder "AuditSuite_DelegatedPermissionGrants_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv")
}

# ── [17] Authentication Methods Policy ───────────────────────────────────────
function Invoke-AuthMethodsPolicy {
    Write-Host ""
    Write-Host "  Running: Authentication Methods Policy" -ForegroundColor Cyan

    $policy = Get-MgPolicyAuthenticationMethodPolicy -ErrorAction Stop

    $MethodNames = @{
        "Fido2"                  = "FIDO2 Security Key"
        "MicrosoftAuthenticator" = "Microsoft Authenticator"
        "Sms"                    = "SMS"
        "TemporaryAccessPass"    = "Temporary Access Pass"
        "HardwareOath"           = "Hardware OATH Token"
        "SoftwareOath"           = "Software OATH Token"
        "Email"                  = "Email OTP"
        "X509Certificate"        = "Certificate-based Auth"
        "Voice"                  = "Voice Call"
    }

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($method in $policy.AuthenticationMethodConfigurations) {
        $methodName = if ($MethodNames[$method.Id]) { $MethodNames[$method.Id] } else { $method.Id }

        # Resolve include targets
        $includeTargets = "—"
        $rawIncludes = $method.AdditionalProperties["includeTargets"]
        if ($rawIncludes -and @($rawIncludes).Count -gt 0) {
            $includeTargets = (@($rawIncludes) | ForEach-Object {
                $id = $_.id
                if ($id -eq "all_users") { "All Users" }
                else {
                    $gname = $id
                    try { $g = Get-MgGroup -GroupId $id -Property DisplayName -ErrorAction Stop; $gname = $g.DisplayName } catch {}
                    $gname
                }
            }) -join " | "
        }

        # Resolve exclude targets
        $excludeTargets = "—"
        $rawExcludes = $method.AdditionalProperties["excludeTargets"]
        if ($rawExcludes -and @($rawExcludes).Count -gt 0) {
            $excludeTargets = (@($rawExcludes) | ForEach-Object {
                $id = $_.id
                $gname = $id
                try { $g = Get-MgGroup -GroupId $id -Property DisplayName -ErrorAction Stop; $gname = $g.DisplayName } catch {}
                $gname
            }) -join " | "
        }

        $results.Add([PSCustomObject]@{
            Method         = $methodName
            State          = if ($method.State -eq "enabled") { "Enabled" } else { "Disabled" }
            IncludeTargets = $includeTargets
            ExcludeTargets = $excludeTargets
        })
    }

    $sorted = $results | Sort-Object @(
        @{ Expression = { if ($_.State -eq "Enabled") { 0 } else { 1 } } }
        @{ Expression = "Method" }
    )

    Write-Host ""
    $header = "  {0,-30} {1,-10} {2,-40} {3}" -f "Method", "State", "Include Targets", "Exclude Targets"
    Write-Host $header -ForegroundColor Gray
    Write-Host ("  " + "─" * 110) -ForegroundColor DarkGray

    foreach ($entry in $sorted) {
        $color = if ($entry.State -eq "Enabled") { "Green" } else { "DarkGray" }
        Write-Host ("  {0,-30} {1,-10} {2,-40} {3}" -f $entry.Method, $entry.State, $entry.IncludeTargets, $entry.ExcludeTargets) -ForegroundColor $color
    }

    $enabled  = ($results | Where-Object { $_.State -eq "Enabled"  }).Count
    $disabled = ($results | Where-Object { $_.State -eq "Disabled" }).Count
    Write-Host ""
    Write-Host "  Total methods    : $($results.Count)" -ForegroundColor Cyan
    Write-Host "  Enabled          : $enabled"          -ForegroundColor Green
    Write-Host "  Disabled         : $disabled"         -ForegroundColor DarkGray

    Write-CsvBom -Data $sorted -Path (Join-Path $script:ExportFolder "AuditSuite_AuthMethodsPolicy_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv")
}

# ── [18] Named Locations Export ───────────────────────────────────────────────
function Invoke-NamedLocationsExport {
    Write-Host ""
    Write-Host "  Running: Named Locations Export" -ForegroundColor Cyan

    $locations = Get-MgIdentityConditionalAccessNamedLocation -All -ErrorAction Stop
    Write-Host "  Named locations  : $($locations.Count)" -ForegroundColor DarkGray

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($loc in $locations) {
        $odataType = $loc.AdditionalProperties["@odata.type"]
        $locType   = switch ($odataType) {
            "#microsoft.graph.ipNamedLocation"      { "IP"      }
            "#microsoft.graph.countryNamedLocation" { "Country" }
            default                                 { $odataType }
        }

        $isTrusted      = "—"
        $ipRanges       = "—"
        $countries      = "—"
        $includeUnknown = "—"

        if ($locType -eq "IP") {
            $isTrusted = ($loc.AdditionalProperties["isTrusted"] -eq $true).ToString()
            $ranges    = $loc.AdditionalProperties["ipRanges"]
            if ($ranges -and @($ranges).Count -gt 0) {
                $ipRanges = (@($ranges) | ForEach-Object { $_["cidrAddress"] } | Where-Object { $_ }) -join " | "
            }
        } elseif ($locType -eq "Country") {
            $countryList    = $loc.AdditionalProperties["countriesAndRegions"]
            $includeUnknown = ($loc.AdditionalProperties["includeUnknownCountriesAndRegions"] -eq $true).ToString()
            if ($countryList -and @($countryList).Count -gt 0) {
                $countries = (@($countryList)) -join " | "
            }
        }

        $results.Add([PSCustomObject]@{
            DisplayName            = $loc.DisplayName
            LocationType           = $locType
            IsTrusted              = $isTrusted
            IPRanges               = $ipRanges
            Countries              = $countries
            IncludeUnknownCountries = $includeUnknown
            CreatedDate            = if ($loc.CreatedDateTime)  { $loc.CreatedDateTime.ToString("yyyy-MM-dd")  } else { "—" }
            ModifiedDate           = if ($loc.ModifiedDateTime) { $loc.ModifiedDateTime.ToString("yyyy-MM-dd") } else { "—" }
        })
    }

    $sorted = $results | Sort-Object LocationType, DisplayName

    Write-Host ""
    $header = "  {0,-38} {1,-10} {2,-8} {3}" -f "Display Name", "Type", "Trusted", "Ranges / Countries"
    Write-Host $header -ForegroundColor Gray
    Write-Host ("  " + "─" * 110) -ForegroundColor DarkGray

    foreach ($entry in $sorted) {
        $detail = if ($entry.LocationType -eq "IP")      { $entry.IPRanges  }
                  elseif ($entry.LocationType -eq "Country") { $entry.Countries }
                  else                                       { "—"              }
        $color  = if ($entry.IsTrusted -eq "True") { "Green" }
                  elseif ($entry.LocationType -eq "Country") { "Cyan" }
                  else { "White" }
        Write-Host ("  {0,-38} {1,-10} {2,-8} {3}" -f $entry.DisplayName, $entry.LocationType, $entry.IsTrusted, $detail) -ForegroundColor $color
    }

    $ipCount      = ($results | Where-Object { $_.LocationType -eq "IP"      }).Count
    $countryCount = ($results | Where-Object { $_.LocationType -eq "Country" }).Count
    $trustedCount = ($results | Where-Object { $_.IsTrusted    -eq "True"    }).Count
    Write-Host ""
    Write-Host "  Total locations  : $($results.Count)" -ForegroundColor Cyan
    Write-Host "  IP-based         : $ipCount"          -ForegroundColor Cyan
    Write-Host "  Country-based    : $countryCount"     -ForegroundColor Cyan
    if ($trustedCount -gt 0) { Write-Host "  Trusted          : $trustedCount" -ForegroundColor Green }

    Write-CsvBom -Data $sorted -Path (Join-Path $script:ExportFolder "AuditSuite_NamedLocations_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv")
}

# ── [19] Security Defaults Status ────────────────────────────────────────────
function Invoke-SecurityDefaultsStatus {
    Write-Host ""
    Write-Host "  Running: Security Defaults Status" -ForegroundColor Cyan

    $policyResult = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy" -ErrorAction Stop
    $isEnabled    = [bool]$policyResult.isEnabled

    Write-Host ""
    if ($isEnabled) {
        Write-Host "  Security Defaults : ENABLED" -ForegroundColor Green
        Write-Host "  Note: CA policies are bypassed when Security Defaults is on." -ForegroundColor Yellow
    } else {
        Write-Host "  Security Defaults : DISABLED" -ForegroundColor Yellow
        Write-Host "  Note: Ensure Conditional Access policies are covering MFA and access controls." -ForegroundColor DarkGray
    }

    $result = [PSCustomObject]@{
        SecurityDefaultsEnabled = $isEnabled.ToString()
        Note                    = if ($isEnabled) { "Security Defaults active — CA policies are bypassed" } else { "Security Defaults disabled — verify CA policies are in place" }
    }

    # ── Executive findings ────────────────────────────────────────────────────
    if ($isEnabled) {
        Add-Finding -Category "Identity Security" -Severity "Info" `
            -Title "Security Defaults are enabled" `
            -Detail "Security Defaults enforce baseline MFA for all users but bypass Conditional Access policies entirely." `
            -Recommendation "If using Conditional Access for granular control, consider disabling Security Defaults."
    } else {
        Add-Finding -Category "Identity Security" -Severity "Info" `
            -Title "Security Defaults are disabled" `
            -Detail "Security Defaults are off. Protection relies entirely on Conditional Access policies being correctly configured." `
            -Recommendation "Verify that Conditional Access policies cover all MFA and access control requirements."
    }

    Write-CsvBom -Data @($result) -Path (Join-Path $script:ExportFolder "AuditSuite_SecurityDefaults_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv")
}

# ── [20] External Collaboration / B2B Settings ────────────────────────────────
function Invoke-ExternalCollaborationSettings {
    Write-Host ""
    Write-Host "  Running: External Collaboration / B2B Settings" -ForegroundColor Cyan

    $authPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
    # Graph returns a collection; take the first (there is only ever one)
    if ($authPolicy -is [System.Collections.IEnumerable] -and $authPolicy -isnot [string]) {
        $authPolicy = $authPolicy | Select-Object -First 1
    }

    $inviteLabel = switch ($authPolicy.AllowInvitesFrom) {
        "none"                             { "Nobody"                                    }
        "adminsAndGuestInviters"           { "Admins and Guest Inviters"                 }
        "adminsGuestInvitersAndAllMembers" { "Admins, Guest Inviters, and all Members"   }
        "everyone"                         { "Everyone (including Guests)"               }
        default                            { $authPolicy.AllowInvitesFrom               }
    }

    $guestRoleLabel = switch ($authPolicy.GuestUserRoleId) {
        "a0b1b346-4d3e-4e8b-98f8-753987be4970" { "Member (full member access)"      }
        "10dae51f-b6af-4016-8d66-8c2a99b929b3" { "Guest (limited access)"           }
        "2af84b1e-32c8-42b7-82bc-daa82404023b" { "Restricted Guest (very limited)"  }
        default                                 { $authPolicy.GuestUserRoleId        }
    }

    $perms = $authPolicy.DefaultUserRolePermissions

    $inviteColor    = if ($authPolicy.AllowInvitesFrom -in @("everyone","adminsGuestInvitersAndAllMembers")) { "Yellow" } else { "Green" }
    $guestRoleColor = switch ($authPolicy.GuestUserRoleId) {
        "a0b1b346-4d3e-4e8b-98f8-753987be4970" { "Red"    }
        "10dae51f-b6af-4016-8d66-8c2a99b929b3" { "Yellow" }
        default                                 { "Green"  }
    }

    Write-Host ""
    Write-Host ("  Guest invite permissions  : {0}" -f $inviteLabel) -ForegroundColor $inviteColor
    Write-Host ("  Guest user role           : {0}" -f $guestRoleLabel) -ForegroundColor $guestRoleColor
    Write-Host ("  Email-verified users join : {0}" -f $authPolicy.AllowEmailVerifiedUsersToJoinOrganization) -ForegroundColor $(if ($authPolicy.AllowEmailVerifiedUsersToJoinOrganization) { "Yellow" } else { "Green" })
    Write-Host ""
    Write-Host "  Default member permissions:" -ForegroundColor Gray
    Write-Host ("  Can create apps            : {0}" -f $perms.AllowedToCreateApps)           -ForegroundColor $(if ($perms.AllowedToCreateApps)           { "Yellow" } else { "Green" })
    Write-Host ("  Can create security groups : {0}" -f $perms.AllowedToCreateSecurityGroups) -ForegroundColor $(if ($perms.AllowedToCreateSecurityGroups) { "Yellow" } else { "Green" })
    Write-Host ("  Can create tenants         : {0}" -f $perms.AllowedToCreateTenants)        -ForegroundColor $(if ($perms.AllowedToCreateTenants)        { "Red"    } else { "Green" })
    Write-Host ("  Can read other users       : {0}" -f $perms.AllowedToReadOtherUsers)       -ForegroundColor "DarkGray"

    $result = [PSCustomObject]@{
        AllowInvitesFrom              = $inviteLabel
        GuestUserRole                 = $guestRoleLabel
        AllowEmailVerifiedUsersToJoin = $authPolicy.AllowEmailVerifiedUsersToJoinOrganization.ToString()
        UsersCanCreateApps            = $perms.AllowedToCreateApps.ToString()
        UsersCanCreateSecurityGroups  = $perms.AllowedToCreateSecurityGroups.ToString()
        UsersCanCreateTenants         = $perms.AllowedToCreateTenants.ToString()
        UsersCanReadOtherUsers        = $perms.AllowedToReadOtherUsers.ToString()
    }

    # ── Executive findings ────────────────────────────────────────────────────
    if ($authPolicy.AllowInvitesFrom -in @("everyone","adminsGuestInvitersAndAllMembers")) {
        Add-Finding -Category "External Collaboration" -Severity "Medium" `
            -Title "Guest invitations permitted for: $inviteLabel" `
            -Detail "Broad invite permissions increase the risk of uncontrolled external access to tenant resources." `
            -Recommendation "Restrict guest invitations to Admins and Guest Inviters only."
    }
    if ($authPolicy.GuestUserRoleId -eq "a0b1b346-4d3e-4e8b-98f8-753987be4970") {
        Add-Finding -Category "External Collaboration" -Severity "High" `
            -Title "Guest users configured with full member-level access" `
            -Detail "External guest accounts have Member permissions, granting them broad visibility into the directory." `
            -Recommendation "Change the guest user role to 'Guest (limited access)' to restrict external user permissions."
    }
    if ($perms.AllowedToCreateTenants) {
        Add-Finding -Category "External Collaboration" -Severity "Low" `
            -Title "Regular users can create new Microsoft tenants" `
            -Detail "Any member can spin up a new tenant, which may lead to shadow IT or uncontrolled data flows." `
            -Recommendation "Disable 'Users can create tenants' in External Collaboration Settings."
    }

    Write-CsvBom -Data @($result) -Path (Join-Path $script:ExportFolder "AuditSuite_ExternalCollaboration_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv")
}

# ── [21] Administrative Units ─────────────────────────────────────────────────
function Invoke-AdministrativeUnitsExport {
    Write-Host ""
    Write-Host "  Running: Administrative Units" -ForegroundColor Cyan

    $aus = Get-MgDirectoryAdministrativeUnit -All `
        -Property "Id,DisplayName,Description,Visibility,MembershipType,MembershipRule" `
        -ErrorAction Stop
    Write-Host "  Administrative units: $($aus.Count)" -ForegroundColor DarkGray

    if ($aus.Count -eq 0) {
        Write-Host "  No administrative units found." -ForegroundColor Yellow
        return
    }

    # Resolve role definition names once
    $roleDefMap = @{}
    try {
        $roleDefs = Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop
        foreach ($rd in $roleDefs) { $roleDefMap[$rd.Id] = $rd.DisplayName; $roleDefMap[$rd.TemplateId] = $rd.DisplayName }
    } catch {}

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($au in $aus) {
        $memberCount = 0
        try {
            Get-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId $au.Id -Top 1 -CountVariable auMemberCnt -ConsistencyLevel eventual -ErrorAction Stop | Out-Null
            $memberCount = if ($auMemberCnt) { [int]$auMemberCnt } else { 0 }
        } catch {}

        $scopedAdminList = [System.Collections.Generic.List[string]]::new()
        try {
            $scopedMembers = Get-MgDirectoryAdministrativeUnitScopedRoleMember -AdministrativeUnitId $au.Id -All -ErrorAction Stop
            foreach ($sm in $scopedMembers) {
                $roleName  = if ($roleDefMap[$sm.RoleId]) { $roleDefMap[$sm.RoleId] } else { $sm.RoleId }
                $adminName = if ($sm.RoleMemberInfo.DisplayName) { $sm.RoleMemberInfo.DisplayName } else { $sm.RoleMemberInfo.Id }
                $scopedAdminList.Add("$adminName ($roleName)")
            }
        } catch {}

        $results.Add([PSCustomObject]@{
            DisplayName      = $au.DisplayName
            Description      = if ($au.Description)     { $au.Description     } else { "—" }
            Visibility       = if ($au.Visibility)       { $au.Visibility      } else { "—" }
            MembershipType   = if ($au.MembershipType)   { $au.MembershipType  } else { "Assigned" }
            MemberCount      = $memberCount
            ScopedAdminCount = $scopedAdminList.Count
            ScopedAdmins     = if ($scopedAdminList.Count -gt 0) { $scopedAdminList -join " | " } else { "—" }
        })
    }

    $sorted = $results | Sort-Object DisplayName
    Write-Host ""
    $header = "  {0,-40} {1,-12} {2,-12} {3,8} {4,8}  {5}" -f "Display Name", "Visibility", "Membership", "Members", "Admins", "Scoped Admins"
    Write-Host $header -ForegroundColor Gray
    Write-Host ("  " + "─" * 125) -ForegroundColor DarkGray

    foreach ($entry in $sorted) {
        $color = if ($entry.ScopedAdminCount -eq 0) { "Yellow" } else { "Green" }
        $flag  = if ($entry.ScopedAdminCount -eq 0) { " [NO SCOPED ADMIN]" } else { "" }
        Write-Host ("  {0,-40} {1,-12} {2,-12} {3,8} {4,8}  {5}{6}" -f `
            $entry.DisplayName, $entry.Visibility, $entry.MembershipType, $entry.MemberCount, $entry.ScopedAdminCount, $entry.ScopedAdmins, $flag) -ForegroundColor $color
    }

    $noAdmin = ($results | Where-Object { $_.ScopedAdminCount -eq 0 }).Count
    Write-Host ""
    Write-Host "  Total AUs        : $($results.Count)" -ForegroundColor Cyan
    if ($noAdmin -gt 0) { Write-Host "  No scoped admin  : $noAdmin" -ForegroundColor Yellow }

    Write-CsvBom -Data $sorted -Path (Join-Path $script:ExportFolder "AuditSuite_AdministrativeUnits_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv")
}

# ── [22] Intune Compliance Policies ──────────────────────────────────────────
function Invoke-IntuneCompliancePolicies {
    Write-Host ""
    Write-Host "  Running: Intune Compliance Policies" -ForegroundColor Cyan

    try {
        $policies = Get-MgDeviceManagementDeviceCompliancePolicy -All -ErrorAction Stop
    } catch {
        Write-Host "  FATAL: Could not retrieve compliance policies. Ensure 'DeviceManagementConfiguration.Read.All' is granted on the app registration." -ForegroundColor Red
        return
    }
    Write-Host "  Compliance policies: $($policies.Count)" -ForegroundColor DarkGray

    if ($policies.Count -eq 0) {
        Write-Host "  No compliance policies found." -ForegroundColor Yellow
        return
    }

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($policy in $policies) {
        $odataType = $policy.AdditionalProperties["@odata.type"]
        $platform  = switch -Wildcard ($odataType) {
            "*windows10*" { "Windows 10/11" }
            "*ios*"       { "iOS"           }
            "*android*"   { "Android"       }
            "*macOS*"     { "macOS"         }
            "*linux*"     { "Linux"         }
            default       { $odataType -replace '#microsoft\.graph\.',''}
        }

        $assignments = [System.Collections.Generic.List[string]]::new()
        try {
            $assigns = Get-MgDeviceManagementDeviceCompliancePolicyAssignment -DeviceCompliancePolicyId $policy.Id -All -ErrorAction Stop
            foreach ($a in $assigns) {
                $targetType = $a.Target.AdditionalProperties["@odata.type"]
                $label = switch -Wildcard ($targetType) {
                    "*allDevices*"       { "All Devices" }
                    "*allLicensedUsers*" { "All Users"   }
                    "*groupAssignment*"  {
                        $gid = $a.Target.AdditionalProperties["groupId"]
                        try { (Get-MgGroup -GroupId $gid -Property DisplayName -ErrorAction Stop).DisplayName } catch { $gid }
                    }
                    "*exclusionGroup*"   {
                        $gid = $a.Target.AdditionalProperties["groupId"]
                        $gname = try { (Get-MgGroup -GroupId $gid -Property DisplayName -ErrorAction Stop).DisplayName } catch { $gid }
                        "Exclude: $gname"
                    }
                    default { $targetType }
                }
                $assignments.Add($label)
            }
        } catch {}

        $results.Add([PSCustomObject]@{
            PolicyName      = $policy.DisplayName
            Platform        = $platform
            CreatedDate     = if ($policy.CreatedDateTime)      { $policy.CreatedDateTime.ToString("yyyy-MM-dd")      } else { "—" }
            ModifiedDate    = if ($policy.LastModifiedDateTime) { $policy.LastModifiedDateTime.ToString("yyyy-MM-dd") } else { "—" }
            AssignmentCount = $assignments.Count
            AssignedTo      = if ($assignments.Count -gt 0) { $assignments -join " | " } else { "Not assigned" }
        })
    }

    $sorted = $results | Sort-Object Platform, PolicyName
    Write-Host ""
    $header = "  {0,-45} {1,-15} {2,-12} {3}" -f "Policy Name", "Platform", "Modified", "Assigned To"
    Write-Host $header -ForegroundColor Gray
    Write-Host ("  " + "─" * 115) -ForegroundColor DarkGray

    foreach ($entry in $sorted) {
        $color = if ($entry.AssignmentCount -eq 0) { "Yellow" } else { "Green" }
        $flag  = if ($entry.AssignmentCount -eq 0) { " [NOT ASSIGNED]" } else { "" }
        Write-Host ("  {0,-45} {1,-15} {2,-12} {3}{4}" -f $entry.PolicyName, $entry.Platform, $entry.ModifiedDate, $entry.AssignedTo, $flag) -ForegroundColor $color
    }

    $unassigned = ($results | Where-Object { $_.AssignmentCount -eq 0 }).Count
    Write-Host ""
    Write-Host "  Total policies   : $($results.Count)" -ForegroundColor Cyan
    $results | Group-Object Platform | Sort-Object Count -Descending | ForEach-Object {
        Write-Host ("  {0,-20}: {1}" -f $_.Name, $_.Count) -ForegroundColor Cyan
    }
    if ($unassigned -gt 0) { Write-Host "  Not assigned     : $unassigned" -ForegroundColor Yellow }

    Write-CsvBom -Data $sorted -Path (Join-Path $script:ExportFolder "AuditSuite_IntuneCompliancePolicies_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv")
}

# ── [23] Risky Users ──────────────────────────────────────────────────────────
function Invoke-RiskyUsersReport {
    Write-Host ""
    Write-Host "  Running: Risky Users" -ForegroundColor Cyan

    $allUsers = [System.Collections.Generic.List[object]]::new()
    $uri = "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers"
    try {
        do {
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            foreach ($u in $response.value) { $allUsers.Add($u) }
            $uri = $response.'@odata.nextLink'
        } while ($uri)
    } catch {
        Write-Host "  FATAL: Could not retrieve risky users. Ensure 'IdentityRiskyUser.Read.All' is granted and the tenant has Entra ID P2." -ForegroundColor Red
        return
    }
    Write-Host "  Risky users found: $($allUsers.Count)" -ForegroundColor DarkGray

    $RiskStateLabels = @{
        "atRisk"               = "At Risk"
        "confirmedCompromised" = "Confirmed Compromised"
        "remediated"           = "Remediated"
        "dismissed"            = "Dismissed"
        "confirmedSafe"        = "Confirmed Safe"
        "none"                 = "None"
    }

    $results = foreach ($u in $allUsers) {
        [PSCustomObject]@{
            DisplayName       = $u.userDisplayName
            UserPrincipalName = $u.userPrincipalName
            RiskLevel         = if ($u.riskLevel)  { $u.riskLevel  } else { "none" }
            RiskState         = if ($RiskStateLabels[$u.riskState]) { $RiskStateLabels[$u.riskState] } else { $u.riskState }
            RiskDetail        = if ($u.riskDetail -and $u.riskDetail -ne "none") { $u.riskDetail } else { "—" }
            LastUpdated       = if ($u.riskLastUpdatedDateTime) { ([datetime]$u.riskLastUpdatedDateTime).ToString("yyyy-MM-dd HH:mm") } else { "—" }
            IsDeleted         = $u.isDeleted.ToString()
        }
    }

    $sorted = $results | Sort-Object @(
        @{ Expression = { switch ($_.RiskLevel) { "high" { 0 } "medium" { 1 } "low" { 2 } default { 3 } } } }
        @{ Expression = "DisplayName" }
    )

    Write-Host ""
    $header = "  {0,-35} {1,-42} {2,-10} {3,-25} {4}" -f "Display Name", "UPN", "Level", "State", "Last Updated"
    Write-Host $header -ForegroundColor Gray
    Write-Host ("  " + "─" * 120) -ForegroundColor DarkGray

    foreach ($entry in $sorted) {
        $color = switch ($entry.RiskLevel) { "high" { "Red" } "medium" { "Yellow" } "low" { "DarkYellow" } default { "DarkGray" } }
        Write-Host ("  {0,-35} {1,-42} {2,-10} {3,-25} {4}" -f $entry.DisplayName, $entry.UserPrincipalName, $entry.RiskLevel, $entry.RiskState, $entry.LastUpdated) -ForegroundColor $color
    }

    $high   = ($results | Where-Object { $_.RiskLevel -eq "high"   }).Count
    $medium = ($results | Where-Object { $_.RiskLevel -eq "medium" }).Count
    $low    = ($results | Where-Object { $_.RiskLevel -eq "low"    }).Count
    Write-Host ""
    Write-Host "  Total risky users: $($results.Count)" -ForegroundColor Cyan
    if ($high   -gt 0) { Write-Host "  High             : $high"   -ForegroundColor Red       }
    if ($medium -gt 0) { Write-Host "  Medium           : $medium" -ForegroundColor Yellow    }
    if ($low    -gt 0) { Write-Host "  Low              : $low"    -ForegroundColor DarkYellow }

    # ── Executive findings ────────────────────────────────────────────────────
    if ($high -gt 0) {
        Add-Finding -Category "Identity Risk" -Severity "Critical" `
            -Title "$high user$(if ($high -ne 1) {'s'}) at high identity risk" `
            -Detail "High-risk users have been flagged by Entra ID Protection as likely compromised. Immediate action required." `
            -Recommendation "Force password reset, revoke all active sessions, and investigate sign-in activity for each high-risk user."
    }
    if ($medium -gt 0) {
        Add-Finding -Category "Identity Risk" -Severity "High" `
            -Title "$medium user$(if ($medium -ne 1) {'s'}) at medium identity risk" `
            -Detail "Medium-risk users show signs of suspicious activity requiring review." `
            -Recommendation "Investigate sign-in activity for each medium-risk user and take remediation action where appropriate."
    }

    Write-CsvBom -Data $sorted -Path (Join-Path $script:ExportFolder "AuditSuite_RiskyUsers_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv")
}

# ── [24] Risk Detections ──────────────────────────────────────────────────────
function Invoke-RiskDetectionsReport {
    param([int]$Days = 0)
    Write-Host ""
    Write-Host "  Running: Risk Detections" -ForegroundColor Cyan

    if ($Days -gt 0) {
        $lookback = $Days
        Write-Host "  Lookback         : $lookback days (default)" -ForegroundColor DarkGray
    } else {
        $lookback = $null
        while ($null -eq $lookback) {
            $inp = Read-Host "  How many days back to export (e.g. 30)"
            if ($inp -match '^\d+$' -and [int]$inp -gt 0) { $lookback = [int]$inp }
            else { Write-Host "  Please enter a positive number." -ForegroundColor Yellow }
        }
    }

    $RiskEventTypeLabels = @{
        "anonymizedIPAddress"                          = "Anonymized IP Address"
        "atypicalTravelActivity"                       = "Atypical Travel"
        "leakedCredentials"                            = "Leaked Credentials"
        "maliciousIPAddress"                           = "Malicious IP Address"
        "unfamiliarFeatures"                           = "Unfamiliar Sign-in Properties"
        "malwareInfectedIPAddress"                     = "Malware Linked IP"
        "suspiciousIPAddress"                          = "Suspicious IP Address"
        "investigationsThreatIntelligence"             = "Microsoft Threat Intelligence"
        "adminConfirmedUserCompromised"                = "Admin Confirmed Compromised"
        "mcasImpossibleTravel"                         = "Impossible Travel (MCAS)"
        "mcasSuspiciousInboxManipulationRules"         = "Suspicious Inbox Rules (MCAS)"
        "investigationsThreatIntelligenceSigninLinked" = "Threat Intelligence (sign-in)"
        "suspiciousInboxForwarding"                    = "Suspicious Inbox Forwarding"
        "generic"                                      = "Generic"
    }

    $since = (Get-Date).AddDays(-$lookback).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $allDetections = [System.Collections.Generic.List[object]]::new()
    $uri = "https://graph.microsoft.com/v1.0/identityProtection/riskDetections?`$filter=activityDateTime ge $since&`$orderby=activityDateTime desc"
    try {
        do {
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            foreach ($d in $response.value) { $allDetections.Add($d) }
            $uri = $response.'@odata.nextLink'
        } while ($uri)
    } catch {
        Write-Host "  FATAL: Could not retrieve risk detections. Ensure 'IdentityRiskEvent.Read.All' is granted and the tenant has Entra ID P2." -ForegroundColor Red
        return
    }
    Write-Host "  Detections found : $($allDetections.Count)" -ForegroundColor DarkGray

    $results = foreach ($d in $allDetections) {
        $eventType = if ($RiskEventTypeLabels[$d.riskEventType]) { $RiskEventTypeLabels[$d.riskEventType] } else { $d.riskEventType }
        $location  = if ($d.location) { "$($d.location.city), $($d.location.countryOrRegion)" } else { "—" }
        [PSCustomObject]@{
            DateTime          = if ($d.activityDateTime) { ([datetime]$d.activityDateTime).ToString("yyyy-MM-dd HH:mm") } else { "—" }
            UserPrincipalName = $d.userPrincipalName
            DisplayName       = $d.userDisplayName
            RiskEventType     = $eventType
            RiskLevel         = if ($d.riskLevel) { $d.riskLevel } else { "—" }
            RiskState         = if ($d.riskState) { $d.riskState } else { "—" }
            IPAddress         = if ($d.ipAddress) { $d.ipAddress } else { "—" }
            Location          = $location
            Activity          = if ($d.activity)  { $d.activity  } else { "—" }
        }
    }

    $sorted = $results | Sort-Object DateTime -Descending

    Write-Host ""
    $header = "  {0,-18} {1,-35} {2,-38} {3,-8} {4}" -f "DateTime", "UPN", "Risk Event Type", "Level", "Location"
    Write-Host $header -ForegroundColor Gray
    Write-Host ("  " + "─" * 115) -ForegroundColor DarkGray

    foreach ($entry in $sorted) {
        $color = switch ($entry.RiskLevel) { "high" { "Red" } "medium" { "Yellow" } "low" { "DarkYellow" } default { "White" } }
        Write-Host ("  {0,-18} {1,-35} {2,-38} {3,-8} {4}" -f $entry.DateTime, $entry.UserPrincipalName, $entry.RiskEventType, $entry.RiskLevel, $entry.Location) -ForegroundColor $color
    }

    $high   = ($results | Where-Object { $_.RiskLevel -eq "high"   }).Count
    $medium = ($results | Where-Object { $_.RiskLevel -eq "medium" }).Count
    Write-Host ""
    Write-Host "  Total detections : $($results.Count)" -ForegroundColor Cyan
    Write-Host "  By type (top 5):" -ForegroundColor Gray
    $results | Group-Object RiskEventType | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {
        Write-Host ("    {0,-42}: {1}" -f $_.Name, $_.Count) -ForegroundColor White
    }
    if ($high   -gt 0) { Write-Host "  High risk        : $high"   -ForegroundColor Red    }
    if ($medium -gt 0) { Write-Host "  Medium risk      : $medium" -ForegroundColor Yellow }

    # ── Executive findings ────────────────────────────────────────────────────
    if ($high -gt 0) {
        Add-Finding -Category "Identity Risk" -Severity "Critical" `
            -Title "$high high-risk detection$(if ($high -ne 1) {'s'}) in the last $lookback days" `
            -Detail "High-risk events detected: may include leaked credentials, impossible travel, or confirmed compromise." `
            -Recommendation "Review each high-risk detection immediately and remediate affected accounts."
    }
    if ($medium -gt 0) {
        Add-Finding -Category "Identity Risk" -Severity "High" `
            -Title "$medium medium-risk detection$(if ($medium -ne 1) {'s'}) in the last $lookback days" `
            -Detail "Medium-risk events detected: suspicious sign-in properties or atypical activity patterns." `
            -Recommendation "Investigate medium-risk detections and apply remediation where warranted."
    }

    Write-CsvBom -Data $sorted -Path (Join-Path $script:ExportFolder "AuditSuite_RiskDetections_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv")
}

# ── [25] Microsoft Secure Score ───────────────────────────────────────────────
function Invoke-SecureScoreReport {
    Write-Host ""
    Write-Host "  Running: Microsoft Secure Score" -ForegroundColor Cyan

    try {
        $scoreResponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/security/secureScores?`$top=1&`$orderby=createdDateTime desc" -ErrorAction Stop
    } catch {
        Write-Host "  FATAL: Could not retrieve Secure Score. Ensure 'SecurityEvents.Read.All' is granted." -ForegroundColor Red
        return
    }

    $latest = $scoreResponse.value | Select-Object -First 1
    if (-not $latest) { Write-Host "  No Secure Score data found." -ForegroundColor Yellow; return }

    $current = [math]::Round($latest.currentScore, 1)
    $max     = [math]::Round($latest.maxScore, 1)
    $pct     = if ($max -gt 0) { [math]::Round(($current / $max) * 100, 1) } else { 0 }
    $date    = ([datetime]$latest.createdDateTime).ToString("yyyy-MM-dd")

    $comparisons = $latest.averageComparativeScores
    $allAvg      = ($comparisons | Where-Object { $_.basis -eq "AllTenants" } | Select-Object -First 1).averageScore
    $industryAvg = ($comparisons | Where-Object { $_.basis -eq "Industry"   } | Select-Object -First 1).averageScore
    $sizeAvg     = ($comparisons | Where-Object { $_.basis -like "SeatSize*" } | Select-Object -First 1).averageScore

    $scoreColor = if ($pct -ge 80) { "Green" } elseif ($pct -ge 50) { "Yellow" } else { "Red" }
    Write-Host ""
    Write-Host ("  Score            : {0} / {1}  ({2}%)" -f $current, $max, $pct) -ForegroundColor $scoreColor
    Write-Host ("  As of            : {0}" -f $date) -ForegroundColor DarkGray
    if ($allAvg)      { Write-Host ("  All tenants avg  : {0:F1}" -f $allAvg)      -ForegroundColor DarkGray }
    if ($industryAvg) { Write-Host ("  Industry avg     : {0:F1}" -f $industryAvg) -ForegroundColor DarkGray }
    if ($sizeAvg)     { Write-Host ("  Same size avg    : {0:F1}" -f $sizeAvg)     -ForegroundColor DarkGray }

    # Fetch control profiles for titles and max scores
    $controlProfiles = @{}
    try {
        $profileUri = "https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles?`$top=500"
        do {
            $profileResponse = Invoke-MgGraphRequest -Method GET -Uri $profileUri -ErrorAction Stop
            foreach ($p in $profileResponse.value) { $controlProfiles[$p.id] = $p }
            $profileUri = $profileResponse.'@odata.nextLink'
        } while ($profileUri)
    } catch {}

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($cs in $latest.controlScores) {
        $ctrlProfile = $controlProfiles[$cs.controlName]
        $maxScore    = if ($ctrlProfile -and $null -ne $ctrlProfile.maxScore) { $ctrlProfile.maxScore } else { $null }
        $scorePct    = if ($maxScore -gt 0) { [math]::Round(($cs.score / $maxScore) * 100, 0) } else { 0 }
        $results.Add([PSCustomObject]@{
            Title        = if ($ctrlProfile -and $ctrlProfile.title) { $ctrlProfile.title } else { $cs.controlName }
            Category     = if ($ctrlProfile) { $ctrlProfile.controlCategory } else { "—" }
            Tier         = if ($ctrlProfile) { $ctrlProfile.tier            } else { "—" }
            Score        = [math]::Round($cs.score, 1)
            MaxScore     = if ($null -ne $maxScore) { $maxScore } else { "—" }
            ScorePct     = $scorePct
            IsDeprecated = if ($ctrlProfile) { $ctrlProfile.deprecated.ToString() } else { "False" }
        })
    }

    # Category breakdown
    Write-Host ""
    Write-Host "  Score by category:" -ForegroundColor Gray
    Write-Host ("  " + "─" * 60) -ForegroundColor DarkGray
    $results | Where-Object { $_.Category -ne "—" } | Group-Object Category | ForEach-Object {
        $catScore = ($_.Group | Measure-Object Score    -Sum).Sum
        $catMax   = ($_.Group | Where-Object { $_.MaxScore -ne "—" } | ForEach-Object { [decimal]$_.MaxScore } | Measure-Object -Sum).Sum
        $catPct   = if ($catMax -gt 0) { [math]::Round(($catScore / $catMax) * 100, 0) } else { 0 }
        $c = if ($catPct -ge 80) { "Green" } elseif ($catPct -ge 50) { "Yellow" } else { "Red" }
        Write-Host ("  {0,-25}: {1,5:F1} / {2,-5:F0}  ({3}%)" -f $_.Name, $catScore, $catMax, $catPct) -ForegroundColor $c
    }

    # Top improvement actions not yet completed
    $improvements = $results | Where-Object { $_.ScorePct -lt 100 -and $_.IsDeprecated -eq "False" -and $_.MaxScore -ne "—" } |
        Sort-Object { [decimal]$_.MaxScore } -Descending | Select-Object -First 15
    Write-Host ""
    Write-Host "  Top improvement actions (by potential gain):" -ForegroundColor Gray
    Write-Host ("  " + "─" * 80) -ForegroundColor DarkGray
    foreach ($entry in $improvements) {
        $c = if ($entry.ScorePct -eq 0) { "Red" } elseif ($entry.ScorePct -lt 50) { "Yellow" } else { "Green" }
        Write-Host ("  {0,-58} {1,5}/{2,-5} ({3}%)" -f $entry.Title, $entry.Score, $entry.MaxScore, $entry.ScorePct) -ForegroundColor $c
    }

    # ── Executive findings ────────────────────────────────────────────────────
    $sev = if ($pct -ge 80) { "Info" } elseif ($pct -ge 50) { "Medium" } else { "High" }
    $comparison = if ($allAvg) { " All-tenants average: $([math]::Round($allAvg,1))%." } else { "" }
    $comparison += if ($industryAvg) { " Industry average: $([math]::Round($industryAvg,1))%." } else { "" }
    Add-Finding -Category "Secure Score" -Severity $sev `
        -Title "Microsoft Secure Score: $current / $max ($pct%)" `
        -Detail "Overall security posture score as of $date.$comparison" `
        -Recommendation "Review the top improvement actions in the Microsoft Secure Score portal to increase the score."

    Write-CsvBom -Data ($results | Sort-Object Category, Title) -Path (Join-Path $script:ExportFolder "AuditSuite_SecureScore_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv")
}

# ── [26] M365 Usage Reports ───────────────────────────────────────────────────
function Invoke-M365UsageReports {
    param([string]$Period = "")
    Write-Host ""
    Write-Host "  Running: M365 Usage Reports" -ForegroundColor Cyan

    if (-not $Period) {
        $periodChoice = $null
        while ($periodChoice -notin @("7","30","90","180")) {
            $periodChoice = Read-Host "  Select period in days (7 / 30 / 90 / 180)"
            if ($periodChoice -notin @("7","30","90","180")) { Write-Host "  Please enter 7, 30, 90, or 180." -ForegroundColor Yellow }
        }
        $Period = "D$periodChoice"
    }

    Write-Host "  Period           : $Period" -ForegroundColor DarkGray

    $reports = @(
        @{ Name = "Office365 Active Users"; Uri = "https://graph.microsoft.com/v1.0/reports/getOffice365ActiveUserDetail(period='$Period')";   File = "AuditSuite_Usage_ActiveUsers_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"   }
        @{ Name = "Email Activity";         Uri = "https://graph.microsoft.com/v1.0/reports/getEmailActivityUserDetail(period='$Period')";     File = "AuditSuite_Usage_EmailActivity_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"  }
        @{ Name = "Teams User Activity";    Uri = "https://graph.microsoft.com/v1.0/reports/getTeamsUserActivityUserDetail(period='$Period')"; File = "AuditSuite_Usage_TeamsActivity_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"  }
        @{ Name = "OneDrive Usage";         Uri = "https://graph.microsoft.com/v1.0/reports/getOneDriveUsageAccountDetail(period='$Period')"; File = "AuditSuite_Usage_OneDriveUsage_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"  }
        @{ Name = "SharePoint Site Usage";  Uri = "https://graph.microsoft.com/v1.0/reports/getSharePointSiteUsageDetail(period='$Period')";  File = "AuditSuite_Usage_SharePoint_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"     }
    )

    Write-Host ""
    foreach ($report in $reports) {
        $dest = Join-Path $script:ExportFolder $report.File
        try {
            Invoke-MgGraphRequest -Method GET -Uri $report.Uri -OutputFilePath $dest -ErrorAction Stop
            $lineCount = [math]::Max(0, (Get-Content $dest | Measure-Object -Line).Lines - 1)
            Write-Host ("  [{0,-28}] {1,6} rows  →  {2}" -f $report.Name, $lineCount, $dest) -ForegroundColor Green
        } catch {
            Write-Host ("  [{0,-28}] FAILED: {1}" -f $report.Name, $_.Exception.Message) -ForegroundColor Red
        }
    }

    Write-Host ""
    Write-Host "  Note: User/site names may be anonymized depending on tenant privacy settings in the M365 admin center." -ForegroundColor DarkGray
}

# ── Executive Report ──────────────────────────────────────────────────────────
function Invoke-ExecutiveReport {
    param([string]$TenantName)

    Write-Host ""
    Write-Host "  Running: Executive Report" -ForegroundColor Cyan

    if ($script:Findings.Count -eq 0) {
        Write-Host "  No findings collected — executive report skipped." -ForegroundColor DarkGray
        return
    }

    $reportDate = (Get-Date).ToString("yyyy-MM-dd HH:mm")

    $critical = ($script:Findings | Where-Object Severity -eq "Critical").Count
    $high     = ($script:Findings | Where-Object Severity -eq "High").Count
    $medium   = ($script:Findings | Where-Object Severity -eq "Medium").Count
    $low      = ($script:Findings | Where-Object Severity -eq "Low").Count
    $info     = ($script:Findings | Where-Object Severity -eq "Info").Count

    $overallRisk  = if ($critical -gt 0) { "CRITICAL" } elseif ($high -gt 0) { "HIGH" } elseif ($medium -gt 0) { "MEDIUM" } elseif ($low -gt 0) { "LOW" } else { "GOOD" }
    $bannerColor  = switch ($overallRisk) { "CRITICAL" { "#b71c1c" } "HIGH" { "#e65100" } "MEDIUM" { "#f9a825" } "LOW" { "#558b2f" } default { "#1b5e20" } }

    $severityOrder = @{ "Critical" = 0; "High" = 1; "Medium" = 2; "Low" = 3; "Info" = 4 }
    $sorted = $script:Findings | Sort-Object { $severityOrder[$_.Severity] }, Category, Title

    function hesc { param([string]$s); $s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' }

    $rows = foreach ($f in $sorted) {
        $bg = switch ($f.Severity) {
            "Critical" { "#b71c1c" } "High" { "#e65100" } "Medium" { "#f9a825" }
            "Low"      { "#558b2f" } "Info" { "#1565c0" } default  { "#757575" }
        }
        "<tr><td><span class='badge' style='background:$bg'>$(hesc $f.Severity)</span></td><td>$(hesc $f.Category)</td><td><strong>$(hesc $f.Title)</strong></td><td>$(hesc $f.Detail)</td><td>$(hesc $f.Recommendation)</td></tr>"
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>M365 Security Executive Report - $TenantName</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#f4f6f8;color:#1a1a2e;font-size:14px}
.hdr{background:#0d47a1;color:#fff;padding:28px 40px 20px}
.hdr h1{font-size:22px;font-weight:300;letter-spacing:.5px}
.hdr .sub{margin-top:6px;opacity:.75;font-size:12px}
.banner{background:$bannerColor;color:#fff;padding:10px 40px;font-size:13px;font-weight:700;letter-spacing:1px}
.body{padding:28px 40px}
.cards{display:flex;gap:14px;margin-bottom:28px;flex-wrap:wrap}
.card{background:#fff;border-radius:6px;padding:18px 20px;flex:1;min-width:100px;box-shadow:0 1px 4px rgba(0,0,0,.1);text-align:center;border-top:4px solid #ccc}
.card.c{border-color:#b71c1c}.card.h{border-color:#e65100}.card.m{border-color:#f9a825}.card.l{border-color:#558b2f}.card.i{border-color:#1565c0}
.card .n{font-size:34px;font-weight:700;line-height:1}
.card.c .n{color:#b71c1c}.card.h .n{color:#e65100}.card.m .n{color:#f9a825}.card.l .n{color:#558b2f}.card.i .n{color:#1565c0}
.card .lbl{font-size:11px;text-transform:uppercase;letter-spacing:.8px;color:#666;margin-top:4px}
h2{font-size:15px;font-weight:600;color:#0d47a1;margin-bottom:14px}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:6px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.1)}
thead tr{background:#e3f2fd}
th{padding:11px 14px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.4px;color:#0d47a1;font-weight:600}
td{padding:11px 14px;border-top:1px solid #f0f0f0;vertical-align:top;line-height:1.45}
tr:hover td{background:#fafafa}
td:nth-child(4){color:#333;font-size:13px}
td:nth-child(5){color:#0d47a1;font-size:13px}
.badge{display:inline-block;padding:2px 9px;border-radius:10px;color:#fff;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.4px;white-space:nowrap}
.footer{margin-top:28px;font-size:11px;color:#999;text-align:center;padding-bottom:28px}
</style>
</head>
<body>
<div class="hdr">
  <h1>M365 Security Executive Report</h1>
  <div class="sub">Tenant: <strong>$TenantName</strong> &nbsp;&bull;&nbsp; Generated: $reportDate &nbsp;&bull;&nbsp; M365AuditSuite</div>
</div>
<div class="banner">Overall Risk Level: $overallRisk &nbsp;&bull;&nbsp; $($script:Findings.Count) finding$(if ($script:Findings.Count -ne 1) {'s'}) identified</div>
<div class="body">
  <div class="cards">
    <div class="card c"><div class="n">$critical</div><div class="lbl">Critical</div></div>
    <div class="card h"><div class="n">$high</div><div class="lbl">High</div></div>
    <div class="card m"><div class="n">$medium</div><div class="lbl">Medium</div></div>
    <div class="card l"><div class="n">$low</div><div class="lbl">Low</div></div>
    <div class="card i"><div class="n">$info</div><div class="lbl">Info</div></div>
  </div>
  <h2>Findings</h2>
  <table>
    <thead><tr><th style="width:85px">Severity</th><th style="width:155px">Category</th><th style="width:210px">Finding</th><th>Detail</th><th style="width:210px">Recommendation</th></tr></thead>
    <tbody>
      $($rows -join "`n      ")
    </tbody>
  </table>
  <div class="footer">Generated by M365AuditSuite &nbsp;&bull;&nbsp; Author: Melih Sivrikaya &nbsp;&bull;&nbsp; $reportDate &nbsp;&bull;&nbsp; For internal use only</div>
</div>
</body>
</html>
"@

    $reportPath = Join-Path $script:ExportFolder "AuditSuite_ExecutiveReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    try {
        [System.IO.File]::WriteAllText($reportPath, $html, (New-Object System.Text.UTF8Encoding $false))
        Write-Host "  Executive report : $reportPath" -ForegroundColor Green
        $riskColor = if ($critical -gt 0) { "Red" } elseif ($high -gt 0) { "Yellow" } elseif ($medium -gt 0) { "DarkYellow" } else { "Green" }
        Write-Host ("  Risk level       : $overallRisk  |  Critical: $critical  High: $high  Medium: $medium  Low: $low  Info: $info") -ForegroundColor $riskColor
    } catch {
        Write-Host "  Failed to write executive report: $_" -ForegroundColor Red
    }
}

# ===========================================================================
# MAIN
# ===========================================================================

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║             Entra / M365 Audit Suite             ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ── Module check ─────────────────────────────────────────────────────────────
Write-Host "Checking modules..." -ForegroundColor Cyan
foreach ($module in @(
    "Microsoft.Graph.Authentication"
    "Microsoft.Graph.Identity.SignIns"
    "Microsoft.Graph.Identity.DirectoryManagement"
    "Microsoft.Graph.Users"
    "Microsoft.Graph.Groups"
    "Microsoft.Graph.Applications"
    "Microsoft.Graph.DeviceManagement"
    "Microsoft.Graph.Identity.Governance"
    "Microsoft.Graph.Reports"
)) {
    try {
        Import-Module $module -ErrorAction Stop
        Write-Host "  Loaded: $module" -ForegroundColor Green
    } catch {
        Write-Host "  FATAL: Could not load '$module'. Install with: Install-Module $module -Scope CurrentUser" -ForegroundColor Red
        exit 1
    }
}

# ── Tenant selection ──────────────────────────────────────────────────────────
Write-Host ""
Write-Host "Select a tenant:" -ForegroundColor Cyan
for ($i = 0; $i -lt $Tenants.Count; $i++) {
    $t      = $Tenants[$i]
    $status = if ($t.TenantId -and $t.AppId) { "" } else { " [not configured]" }
    $color  = if ($t.TenantId -and $t.AppId) { "White" } else { "DarkGray" }
    Write-Host ("  [{0,2}]  {1}{2}" -f ($i + 1), $t.Name, $status) -ForegroundColor $color
}
Write-Host ""

$tenantChoice = $null
while ($null -eq $tenantChoice) {
    $tenantInput = Read-Host "Enter tenant number (1-$($Tenants.Count))"
    if ($tenantInput -match '^\d+$') {
        $idx = [int]$tenantInput - 1
        if ($idx -ge 0 -and $idx -lt $Tenants.Count) {
            $selected = $Tenants[$idx]
            if (-not $selected.TenantId -or -not $selected.AppId) {
                Write-Host "  '$($selected.Name)' is not configured yet — add TenantId and AppId in the script." -ForegroundColor Yellow
            } else {
                $tenantChoice = $selected
            }
        } else {
            Write-Host "  Please enter a number between 1 and $($Tenants.Count)." -ForegroundColor Yellow
        }
    } else {
        Write-Host "  Please enter a number between 1 and $($Tenants.Count)." -ForegroundColor Yellow
    }
}

# Sanitise tenant name for use in folder/filenames (strip special characters)
$script:TenantTag    = $tenantChoice.Name -replace '[^A-Za-z0-9_-]', ''
$script:ExportFolder = Resolve-ExportFolder -TenantTag $script:TenantTag

if (-not $script:ExportFolder) {
    Write-Host "FATAL: Could not create an export folder in any of the expected locations." -ForegroundColor Red
    Write-Host "       Tried: Desktop (OneDrive), Desktop (default), C:\Audit\$($script:TenantTag)" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "  Tenant      : $($tenantChoice.Name)" -ForegroundColor Green
Write-Host "  Export folder: $script:ExportFolder"  -ForegroundColor DarkGray

# ── Menu ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "Select a report to run:" -ForegroundColor Cyan
Write-Host "  [1]  Conditional Access Policy Report" -ForegroundColor White
Write-Host "  [2]  License Usage"                    -ForegroundColor White
Write-Host "  [3]  App Registration Security Audit"  -ForegroundColor White
Write-Host "  [4]  App Registration Expiry"          -ForegroundColor White
Write-Host "  [5]  Device Export"                    -ForegroundColor White
Write-Host "  [6]  Role Assignments"                 -ForegroundColor White
Write-Host "  [7]  Role Policies (PIM)"              -ForegroundColor White
Write-Host "  [8]  PIM Activation & Request History" -ForegroundColor White
Write-Host "  [9]  PIM Security Alerts"              -ForegroundColor White
Write-Host "  [10] Find Inactive Devices"            -ForegroundColor White
Write-Host "  [11] Find Inactive Users"              -ForegroundColor White
Write-Host "  [12] Domain Export"                    -ForegroundColor White
Write-Host "  [13] Guest User Report"                -ForegroundColor White
Write-Host "  [14] Group Export"                     -ForegroundColor White
Write-Host "  [15] Sign-in Log Export"               -ForegroundColor White
Write-Host "  [16] Directory Audit Log"              -ForegroundColor White
Write-Host "  [17] Enterprise Applications Export"   -ForegroundColor White
Write-Host "  [18] Delegated Permission Grants"      -ForegroundColor White
Write-Host "  [19] Authentication Methods Policy"    -ForegroundColor White
Write-Host "  [20] Named Locations Export"           -ForegroundColor White
Write-Host "  [21] Security Defaults Status"         -ForegroundColor White
Write-Host "  [22] External Collaboration Settings"  -ForegroundColor White
Write-Host "  [23] Administrative Units"             -ForegroundColor White
Write-Host "  [24] Intune Compliance Policies"       -ForegroundColor White
Write-Host "  [25] Risky Users"                      -ForegroundColor White
Write-Host "  [26] Risk Detections"                  -ForegroundColor White
Write-Host "  [27] Microsoft Secure Score"           -ForegroundColor White
Write-Host "  [28] M365 Usage Reports"               -ForegroundColor White
Write-Host "  [A]  Run all reports           (inactive devices/users: 30 days  |  sign-in/audit log: 7 days  |  risk detections: 30 days  |  usage: 30 days)" -ForegroundColor White
Write-Host ""

$choice = $null
$validChoices = @("1","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","17","18","19","20","21","22","23","24","25","26","27","28","A","a")
while ($choice -notin $validChoices) {
    $choice = Read-Host "Enter choice (1-28 / A)"
}
$choice = $choice.ToUpper()

# ── Connect ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
try {
    Connect-MgGraph -TenantId $tenantChoice.TenantId -AppId $tenantChoice.AppId -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
    Write-Host "Connected to tenant: $($tenantChoice.Name) ($($tenantChoice.TenantId))" -ForegroundColor Green
} catch {
    Write-Host "FATAL: Could not connect to Microsoft Graph: $_" -ForegroundColor Red
    exit 1
}

# ── Dispatch ──────────────────────────────────────────────────────────────────
$runAll = $choice -eq "A"

try {
    if ($runAll -or $choice -eq "1") { Invoke-CAAccessReport       }
    if ($runAll -or $choice -eq "2") { Invoke-LicenseUsage         }
    if ($runAll -or $choice -eq "3") { Invoke-AppRegistrationAudit }
    if ($runAll -or $choice -eq "4") { Invoke-AppRegistrationExpiry}
    if ($runAll -or $choice -eq "5") { Invoke-DeviceExport         }
    if ($runAll -or $choice -eq "6") { Invoke-RoleAssignments      }
    if ($runAll -or $choice -eq "7") { Invoke-RolePolicies         }
    if ($runAll -or $choice -eq "8")  { Invoke-PIMActivationHistory -Days      $(if ($runAll) { 30    } else { 0    }) }
    if ($runAll -or $choice -eq "9")  { Invoke-PIMSecurityAlerts                                                      }
    if ($runAll -or $choice -eq "10") { Invoke-FindInactiveDevices -Threshold $(if ($runAll) { 30    } else { 0    }) }
    if ($runAll -or $choice -eq "11") { Invoke-FindInactiveUsers   -Threshold $(if ($runAll) { 30    } else { 0    }) }
    if ($runAll -or $choice -eq "12") { Invoke-DomainExport                                                           }
    if ($runAll -or $choice -eq "13") { Invoke-GuestUserReport                                                        }
    if ($runAll -or $choice -eq "14") { Invoke-GroupExport                                                            }
    if ($runAll -or $choice -eq "15") { Invoke-SignInLogExport    -Days       $(if ($runAll) { 7     } else { 0    }) }
    if ($runAll -or $choice -eq "16") { Invoke-DirectoryAuditLog  -Days       $(if ($runAll) { 7     } else { 0    }) }
    if ($runAll -or $choice -eq "17") { Invoke-EnterpriseAppExport                                                    }
    if ($runAll -or $choice -eq "18") { Invoke-DelegatedPermissionGrants                                              }
    if ($runAll -or $choice -eq "19") { Invoke-AuthMethodsPolicy                                                      }
    if ($runAll -or $choice -eq "20") { Invoke-NamedLocationsExport                                                   }
    if ($runAll -or $choice -eq "21") { Invoke-SecurityDefaultsStatus                                                 }
    if ($runAll -or $choice -eq "22") { Invoke-ExternalCollaborationSettings                                          }
    if ($runAll -or $choice -eq "23") { Invoke-AdministrativeUnitsExport                                              }
    if ($runAll -or $choice -eq "24") { Invoke-IntuneCompliancePolicies                                               }
    if ($runAll -or $choice -eq "25") { Invoke-RiskyUsersReport                                                       }
    if ($runAll -or $choice -eq "26") { Invoke-RiskDetectionsReport -Days     $(if ($runAll) { 30    } else { 0    }) }
    if ($runAll -or $choice -eq "27") { Invoke-SecureScoreReport                                                      }
    if ($runAll -or $choice -eq "28") { Invoke-M365UsageReports    -Period    $(if ($runAll) { "D30" } else { ""   }) }
    if ($runAll)                      { Invoke-ExecutiveReport -TenantName $tenantChoice.Name }
} catch {
    Write-Host ""
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
}

# ── Disconnect ────────────────────────────────────────────────────────────────
try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}

Write-Host ""
Write-Host "Done." -ForegroundColor Green
Write-Host ""
