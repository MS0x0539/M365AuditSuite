<#
.SYNOPSIS
    Onboards or validates a tenant's full PIM configuration against the authorization matrix.

.DESCRIPTION
    This script is the authoritative onboarding tool for Entra ID PIM configuration.
    It is fully idempotent — safe to re-run against an already-configured tenant to
    validate and correct any drift. Every action is logged; a full summary is printed
    at the end.

    The script executes the following phases in order:

    PHASE 1 — Role-assignable group provisioning
        Creates any role-assignable security groups that do not yet exist.
        Existing groups are detected and their description corrected if drifted.

    PHASE 2 — PIM group policies (PIM4Groups only)
        Configures the activation policy for PIM4Groups groups BEFORE member
        assignments so that permanent eligibility is enabled in time:
        8-hour activation window, MFA + justification + ticket required,
        permanent eligibility and active assignment allowed, notifications enabled.

    PHASE 3 — Group membership
        Ensures each group contains exactly the members defined in $GroupConfigs.
        Unexpected members are removed (drift correction). Users not found in the
        tenant are flagged and skipped. For PIM4Groups, users are assigned as
        eligible members via EasyPIM instead of direct membership.

    PHASE 4 — Group role assignments
        Assigns the active and eligible Entra ID roles defined per group. Assignments
        are made to the group object itself (not to individual users). Already-assigned
        roles are skipped gracefully.

    PHASE 5 — Standard PIM role policies (all roles, no approval)
        Applies the standard role policy to every role in $StandardRoles:
        MFA + justification + ticket on activation, authentication context c1,
        notifications to the configured recipients. No approval required.

    PHASE 6 — Privileged PIM role policies (5 roles, approval required)
        Applies an elevated policy to the 5 most sensitive roles:
          Global Administrator, Privileged Role Administrator,
          Privileged Authentication Administrator, Security Administrator,
          Conditional Access Administrator.
        Same requirements as Phase 5 plus mandatory approval from two approver groups.
        Activation window is limited to 4 hours.

    PHASE 7 — Summary report
        Prints a full breakdown of every action taken, grouped by phase, with
        OK / WARN / ERR status. Any errors result in a non-zero exit code.

    ── REQUIREMENTS ────────────────────────────────────────────────────────────
    • Entra ID P2 or Microsoft Entra ID Governance license on the target tenant
    • The EasyPIM app registration must be granted admin consent for all permissions
      listed below in every tenant this script targets
    • The certificate must be installed in the current user's personal cert store
    ────────────────────────────────────────────────────────────────────────────

.NOTES
    Author      : Melih Sivrikaya
    Permissions : Group.ReadWrite.All, GroupMember.ReadWrite.All, User.Read.All,
                  RoleManagement.ReadWrite.Directory,
                  Policy.ReadWrite.PermissionGrant,
                  Policy.Read.All,
                  PrivilegedAccess.ReadWrite.AzureADGroup
                  (application permissions — grant admin consent)
    Auth        : Certificate-based (app registration: EasyPIM)
    Requires    : Microsoft.Graph.Authentication, Microsoft.Graph.Groups,
                  Microsoft.Graph.Users, EasyPIM PowerShell module
#>

#Requires -Version 5.1

param (
    [switch] $DryRun
)

# =====================
# Tenant configuration
# =====================
$TenantId              = "58288310-2b28-42b6-883b-dcef687a4e29"
$AppId                 = "e3febffa-d27e-4193-936f-f3ca01b24af8"
$CertificateThumbprint = "6805FD0B9EBA398B82CB59CA87E67E2FD3075657"

# =====================
# Policy configuration
# =====================
$Justification = "PIM onboarding / authorization matrix enforcement | EasyPIM"

$Recipients = @(
    "pim-notifications@psbv.org"
    "security@psbv.org"
)

# Activation requirements (used for role activation and PIM4Groups activation)
$ActivationRequirements = @(
    "Justification"
    "MultiFactorAuthentication"
    "Ticketing"
)

# Active assignment requirements (used when directly assigning active roles)
$ActiveAssignmentRequirements = @(
    "Justification"
    "MultiFactorAuthentication"
)

# Names of the two approver groups (must exist in $GroupConfigs below)
$ApproverGroupName_M365     = "AAD_SEC_AADRoles_M365_PIM_Approvers"
$ApproverGroupName_Security = "AAD_SEC_AADRoles_Security_PIM_Approvers"

# =====================
# Privileged roles (require approval — Phase 6)
# =====================
$PrivilegedRoles = @(
    "Global Administrator"
    "Privileged Role Administrator"
    "Privileged Authentication Administrator"
    "Security Administrator"
    "Conditional Access Administrator"
)

# =====================
# Standard roles (no approval — Phase 5)
# All roles that should have the standard PIM policy applied.
# The 5 privileged roles above are handled separately in Phase 6.
# =====================
$StandardRoles = @(
    "Agent ID Administrator"
    "Agent ID Developer"
    "Agent Registry Administrator"
    "AI Administrator"
    "Application Administrator"
    "Application Developer"
    "Attack Payload Author"
    "Attack Simulation Administrator"
    "Attribute Assignment Administrator"
    "Attribute Assignment Reader"
    "Attribute Definition Administrator"
    "Attribute Definition Reader"
    "Attribute Log Administrator"
    "Attribute Log Reader"
    "Attribute Provisioning Administrator"
    "Attribute Provisioning Reader"
    "Authentication Administrator"
    "Authentication Extensibility Administrator"
    "Authentication Policy Administrator"
    "Azure DevOps Administrator"
    "Azure Information Protection Administrator"
    "B2C IEF Keyset Administrator"
    "B2C IEF Policy Administrator"
    "Billing Administrator"
    "Cloud App Security Administrator"
    "Cloud Application Administrator"
    "Cloud Device Administrator"
    "Compliance Administrator"
    "Compliance Data Administrator"
    "Customer LockBox Access Approver"
    "Desktop Analytics Administrator"
    "Directory Readers"
    "Directory Writers"
    "Domain Name Administrator"
    "Dragon Administrator"
    "Dynamics 365 Administrator"
    "Dynamics 365 Business Central Administrator"
    "Edge Administrator"
    "Exchange Administrator"
    "Exchange Backup Administrator"
    "Exchange Recipient Administrator"
    "Extended Directory User Administrator"
    "External ID User Flow Administrator"
    "External ID User Flow Attribute Administrator"
    "External Identity Provider Administrator"
    "Fabric Administrator"
    "Global Reader"
    "Global Secure Access Administrator"
    "Global Secure Access Log Reader"
    "Groups Administrator"
    "Guest Inviter"
    "Helpdesk Administrator"
    "Hybrid Identity Administrator"
    "Identity Governance Administrator"
    "Insights Administrator"
    "Insights Analyst"
    "Insights Business Leader"
    "Intune Administrator"
    "IoT Device Administrator"
    "Kaizala Administrator"
    "Knowledge Administrator"
    "Knowledge Manager"
    "License Administrator"
    "Lifecycle Workflows Administrator"
    "Message Center Privacy Reader"
    "Message Center Reader"
    "Microsoft 365 Backup Administrator"
    "Microsoft 365 Migration Administrator"
    "Azure AD Joined Device Local Administrator"
    "Microsoft Graph Data Connect Administrator"
    "Microsoft Hardware Warranty Administrator"
    "Microsoft Hardware Warranty Specialist"
    "Network Administrator"
    "Office Apps Administrator"
    "Organizational Branding Administrator"
    "Organizational Data Source Administrator"
    "Organizational Messages Approver"
    "Organizational Messages Writer"
    "Password Administrator"
    "People Administrator"
    "Permissions Management Administrator"
    "Places Administrator"
    "Power Platform Administrator"
    "Printer Administrator"
    "Printer Technician"
    "Reports Reader"
    "Search Administrator"
    "Search Editor"
    "Security Operator"
    "Security Reader"
    "Service Support Administrator"
    "SharePoint Administrator"
    "SharePoint Advanced Management Administrator"
    "SharePoint Backup Administrator"
    "SharePoint Embedded Administrator"
    "Skype for Business Administrator"
    "Teams Administrator"
    "Teams Communications Administrator"
    "Teams Communications Support Specialist"
    "Teams Communications Support Specialist"
    "Teams Devices Administrator"
    "Teams Reader"
    "Teams Telephony Administrator"
    "Tenant Creator"
    "Usage Summary Reports Reader"
    "User Administrator"
    "User Experience Success Manager"
    "Virtual Visits Administrator"
    "Viva Glint Tenant Administrator"
    "Viva Goals Administrator"
    "Viva Pulse Administrator"
    "Windows 365 Administrator"
    "Windows Update Deployment Administrator"
    "Yammer Administrator"
)

# =====================
# Group configuration
# =====================
# PIM4Group = $false  → users added as direct members; roles assigned to the group via PIM
# PIM4Group = $true   → group gets a PIM activation policy; users are eligible members
#
# EligibleRoles : roles assigned as PIM-eligible to the group (group activates to get the role)
# ActiveRoles   : roles assigned as permanently active to the group
# Users         : display names of beheer accounts to add
$GroupConfigs = @(
    @{
        DisplayName   = "AAD_SEC_AADRoles_M365_HP"
        Description   = "Role-assignable group for M365 high-privileged administrators (5 sensitive roles, approval required)."
        PIM4Group     = $false
        Users         = @(
            "Beheer Daan van den Berg"
            "Beheer Lotte Vermeer"
            "Beheer Sander Hoekstra"
            "Beheer Inge de Vries"
        )
        EligibleRoles = @(
            "Global Administrator"
            "Privileged Role Administrator"
            "Privileged Authentication Administrator"
            "Security Administrator"
            "Conditional Access Administrator"
        )
        ActiveRoles   = @()
    }
    @{
        DisplayName   = "AAD_SEC_AADRoles_M365"
        Description   = "Role-assignable group for M365 administrators."
        PIM4Group     = $false
        Users         = @(
            "Beheer Joost Bakker"
            "Beheer Miriam Janssen"
            "Beheer Thijs Willems"
            "Beheer Fleur Smits"
            "Beheer Bram Kuiper"
            "Beheer Noor van Dijk"
            "Beheer Lars Hendriks"
            "Beheer Eva Mulder"
            "Beheer Tim Visser"
            "Beheer Rosa de Boer"
            "Beheer Koen Peters"
        )
        EligibleRoles = @(
            "User Administrator"
            "Service Support Administrator"
            "Billing Administrator"
            "Exchange Administrator"
            "SharePoint Administrator"
            "Application Administrator"
            "Intune Administrator"
            "License Administrator"
            "Authentication Administrator"
            "Teams Administrator"
            "Groups Administrator"
            "Power Platform Administrator"
            "Azure DevOps Administrator"
            "Office Apps Administrator"
            "Attribute Definition Administrator"
            "Global Secure Access Administrator"
        )
        ActiveRoles   = @(
            "Azure AD Joined Device Local Administrator"
            "Security Reader"
            "Global Reader"
        )
    }
    @{
        DisplayName   = "AAD_SEC_AADRoles_Security"
        Description   = "Role-assignable group for Operational Security Officers."
        PIM4Group     = $false
        Users         = @(
            "Beheer Ruben Schouten"
            "Beheer Anke Brouwer"
            "Beheer Pieter Dekker"
        )
        EligibleRoles = @(
            "User Administrator"
            "Privileged Authentication Administrator"
            "Attack Simulation Administrator"
        )
        ActiveRoles   = @(
            "Security Reader"
            "Security Operator"
            "Global Reader"
        )
    }
    @{
        DisplayName   = "AAD_SEC_AADRoles_Security_TISO"
        Description   = "Role-assignable group for Technical Information Security Officers."
        PIM4Group     = $false
        Users         = @(
            "Beheer Femke Linders"
            "Beheer Maarten van Vliet"
        )
        EligibleRoles = @()
        ActiveRoles   = @(
            "Security Reader"
            "Global Reader"
        )
    }
    @{
        DisplayName   = "AAD_SEC_AADRoles_Security_PIM_Approvers"
        Description   = "Approver group for PIM activation of privileged roles (Security team)."
        PIM4Group     = $false
        Users         = @(
            # M365 HP
            "Beheer Daan van den Berg"
            "Beheer Lotte Vermeer"
            "Beheer Sander Hoekstra"
            "Beheer Inge de Vries"
            # M365
            "Beheer Joost Bakker"
            "Beheer Miriam Janssen"
            "Beheer Thijs Willems"
            "Beheer Fleur Smits"
            "Beheer Bram Kuiper"
            "Beheer Noor van Dijk"
            "Beheer Lars Hendriks"
            "Beheer Eva Mulder"
            "Beheer Tim Visser"
            "Beheer Rosa de Boer"
            "Beheer Koen Peters"
            # Security
            "Beheer Ruben Schouten"
            "Beheer Anke Brouwer"
            "Beheer Pieter Dekker"
        )
        EligibleRoles = @()
        ActiveRoles   = @()
    }
    @{
        DisplayName   = "AAD_SEC_AADRoles_M365_PIM_Approvers"
        Description   = "Approver group for PIM activation of privileged roles (M365)."
        PIM4Group     = $false
        Users         = @(
            # M365 HP
            "Beheer Daan van den Berg"
            "Beheer Lotte Vermeer"
            "Beheer Sander Hoekstra"
            "Beheer Inge de Vries"
            # M365
            "Beheer Joost Bakker"
            "Beheer Miriam Janssen"
            "Beheer Thijs Willems"
            "Beheer Fleur Smits"
            "Beheer Bram Kuiper"
            "Beheer Noor van Dijk"
            "Beheer Lars Hendriks"
            "Beheer Eva Mulder"
            "Beheer Tim Visser"
            "Beheer Rosa de Boer"
            "Beheer Koen Peters"
            # Security
            "Beheer Ruben Schouten"
            "Beheer Anke Brouwer"
            "Beheer Pieter Dekker"
        )
        EligibleRoles = @()
        ActiveRoles   = @()
    }
    @{
        DisplayName   = "AAD_SEC_AADRoles_Architectuur"
        Description   = "Role-assignable group for Architectuur — full reader permissions including Security Reader."
        PIM4Group     = $false
        Users         = @(
            "Beheer Wouter Claassen"
            "Beheer Anouk Bergman"
            "Beheer Stefan Prins"
            "Beheer Ingrid Vos"
        )
        EligibleRoles = @()
        ActiveRoles   = @(
            "Security Reader"
            "Global Reader"
        )
    }
    @{
        DisplayName   = "AAD_SEC_AADRoles_AzureInfra"
        Description   = "Role-assignable group for Azure / Infra (S&S) — read in tenant and Hybrid Administrator eligible."
        PIM4Group     = $false
        Users         = @()
        EligibleRoles = @(
            "Hybrid Identity Administrator"
        )
        ActiveRoles   = @(
            "Global Reader"
        )
    }
    @{
        DisplayName   = "AAD_SEC_AADRoles_DataPlatform"
        Description   = "Role-assignable group for Dataplatform — Fabric Administrator eligible."
        PIM4Group     = $false
        Users         = @(
            "Beheer Niels van Rooij"
            "Beheer Sophie de Groot"
            "Beheer Bart Kuipers"
            "Beheer Hanna Wijnen"
            "Beheer Jeroen Oosterhout"
            "Beheer Lisa van den Heuvel"
        )
        EligibleRoles = @(
            "Fabric Administrator"
        )
        ActiveRoles   = @()
    }
    @{
        DisplayName   = "AAD_SEC_AADRoles_FB"
        Description   = "Role-assignable group for Functioneel Beheer M365 — Yammer Administrator active."
        PIM4Group     = $false
        Users         = @(
            "Beheer Cas Vrijhof"
            "Beheer Judith Manders"
        )
        EligibleRoles = @()
        ActiveRoles   = @(
            "Yammer Administrator"
        )
    }
    @{
        DisplayName   = "AAD_SEC_AADRoles_IAM_Saviynt"
        Description   = "Role-assignable group for Saviynt — read users in tenant."
        PIM4Group     = $false
        Users         = @(
            "Beheer Mark Timmers"
        )
        EligibleRoles = @()
        ActiveRoles   = @(
            "Global Reader"
        )
    }
    @{
        DisplayName   = "AAD_SEC_AADRoles_CloudPlatform"
        Description   = "Role-assignable group for Cloud Platform Team."
        PIM4Group     = $false
        Users         = @(
            "Beheer Dylan van Leeuwen"
            "Beheer Roos Hartman"
            "Beheer Stijn Bosman"
            "Beheer Vera Jacobs"
        )
        EligibleRoles = @(
            "Hybrid Identity Administrator"
        )
        ActiveRoles   = @(
            "Global Reader"
        )
    }
    @{
        DisplayName   = "AAD_SEC_AADRoles_SDLS"
        Description   = "Role-assignable group for Service Desk and Local Support."
        PIM4Group     = $false
        Users         = @(
            "Beheer Tom van der Wal"
            "Beheer Nathalie Dijkstra"
            "Beheer Kevin Meijer"
            "Beheer Esther Bogaard"
            "Beheer Rick Scholten"
            "Beheer Chantal van Ee"
            "Beheer Marco Brink"
            "Beheer Sandra Koops"
            "Beheer Bas Lammers"
            "Beheer Joyce Smeets"
            "Beheer Patrick van Heijst"
            "Beheer Leonie Verhoeven"
            "Beheer Dennis Hooijmans"
            "Beheer Manon de Haan"
            "Beheer Wesley Kusters"
            "Beheer Iris van der Plas"
            "Beheer Frank Nieuwenhuis"
            "Beheer Tamara Ooms"
            "Beheer Jens Roosen"
            "Beheer Petra Vermeulen"
            "Beheer Quinten van Beek"
            "Beheer Nadia Willemsen"
            "Beheer Guus Steenbakkers"
            "Beheer Amber Theunissen"
            "Beheer Ronnie van Galen"
        )
        EligibleRoles = @()
        ActiveRoles   = @(
            "Teams Telephony Administrator"
            "User Administrator"
            "Helpdesk Administrator"
            "Directory Readers"
            "Message Center Reader"
            "Teams Communications Support Specialist"
            "Message Center Privacy Reader"
            "Password Administrator"
            "Groups Administrator"
            "Exchange Recipient Administrator"
            "Authentication Administrator"
            "Azure AD Joined Device Local Administrator"
            "Reports Reader"
        )
    }
    @{
        DisplayName   = "AAD_SEC_AADRoles_M365_EXOGSAIN"
        Description   = "PIM4Groups — Exchange, Global Secure Access & Intune Administrator active."
        PIM4Group     = $true
        Users         = @(
            "Beheer Joost Bakker"
            "Beheer Miriam Janssen"
            "Beheer Thijs Willems"
            "Beheer Fleur Smits"
            "Beheer Bram Kuiper"
            "Beheer Noor van Dijk"
            "Beheer Lars Hendriks"
            "Beheer Eva Mulder"
            "Beheer Tim Visser"
            "Beheer Rosa de Boer"
            "Beheer Koen Peters"
        )
        EligibleRoles = @()
        ActiveRoles   = @(
            "Exchange Administrator"
            "Application Administrator"
            "Intune Administrator"
            "Global Secure Access Administrator"
        )
    }
)

# ===========================================================================
# SCRIPT INTERNALS — do not edit below this line
# ===========================================================================

# ── Error / result tracking ─────────────────────────────────────────────────
$script:Log = [System.Collections.Generic.List[PSCustomObject]]::new()

function Write-PIMLog {
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

    $color = switch ($Level) {
        "INFO" { "Cyan"    }
        "OK"   { "Green"   }
        "WARN" { "Yellow"  }
        "ERR"  { "Red"     }
    }
    $prefix = switch ($Level) {
        "INFO" { "  ····" }
        "OK"   { "  OK  " }
        "WARN" { "  WARN" }
        "ERR"  { "  ERR " }
    }
    Write-Host "$($entry.Time) $prefix [$Phase] $Message" -ForegroundColor $color
}

# ── Module check ─────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║       PIM Onboarding / Validation Script         ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

if ($DryRun) {
    Write-Host "╔══════════════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "║  DRY RUN — no changes will be made to the tenant ║" -ForegroundColor Yellow
    Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Yellow
    Write-Host ""
}
Write-Host "Checking modules..." -ForegroundColor Cyan

foreach ($module in @(
    "Microsoft.Graph.Authentication"
    "Microsoft.Graph.Groups"
    "Microsoft.Graph.Users"
    "EasyPIM"
)) {
    try {
        Import-Module $module -ErrorAction Stop
        Write-Host "  Loaded: $module" -ForegroundColor Green
    } catch {
        Write-Host "  FATAL: Could not load '$module'. Install with: Install-Module $module -Scope CurrentUser" -ForegroundColor Red
        exit 1
    }
}

# ── Connect ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
try {
    Connect-MgGraph -TenantId $TenantId -AppId $AppId -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
    Write-Host "Connected to tenant: $TenantId" -ForegroundColor Green
} catch {
    Write-Host "FATAL: Could not connect to Microsoft Graph: $_" -ForegroundColor Red
    exit 1
}

# ── Helper: resolve user by display name ─────────────────────────────────────
function Resolve-User {
    param ([string] $DisplayName)
    $safe = $DisplayName -replace "'", "''"
    return Get-MgUser -Filter "displayName eq '$safe'" -ConsistencyLevel eventual `
        -ErrorAction SilentlyContinue | Select-Object -First 1
}

# ── Helper: resolve group by display name ────────────────────────────────────

function Resolve-Group {
    param ([string] $DisplayName)
    $safe = $DisplayName -replace "'", "''"
    return Get-MgGroup -Filter "displayName eq '$safe'" -ConsistencyLevel eventual `
        -ErrorAction SilentlyContinue | Select-Object -First 1
}

# ── Shared notification config ────────────────────────────────────────────────
$NotificationConfig = @{
    isDefaultRecipientEnabled = "true"
    notificationLevel         = "All"
    Recipients                = $Recipients
}

# ===========================================================================
# PRE-FLIGHT — Verify all configured users exist in the tenant
# ===========================================================================
Write-Host ""
Write-Host "── PRE-FLIGHT: User existence check ─────────────────" -ForegroundColor Cyan

$allConfiguredUsers = $GroupConfigs |
    ForEach-Object { $_.Users } |
    Where-Object   { $_ } |
    Sort-Object    -Unique

$missingUsers  = [System.Collections.Generic.List[string]]::new()
$resolvedUsers = @{}

foreach ($displayName in $allConfiguredUsers) {
    $userObj = Resolve-User -DisplayName $displayName
    if ($userObj) {
        $resolvedUsers[$displayName] = $userObj
    } else {
        $missingUsers.Add($displayName)
    }
}

if ($missingUsers.Count -eq 0) {
    Write-PIMLog -Level OK -Phase "PRE" -Message "All $($allConfiguredUsers.Count) configured users found in tenant."
} else {
    Write-PIMLog -Level WARN -Phase "PRE" -Message "$($missingUsers.Count) of $($allConfiguredUsers.Count) users not found in tenant — they will be skipped in Phase 3."
    foreach ($missing in $missingUsers) {
        Write-PIMLog -Level WARN -Phase "PRE" -Message "Not found: $missing"
    }
}

# ── Authentication context + Conditional Access check ────────────────────────
Write-Host ""
Write-Host "── PRE-FLIGHT: Authentication context check ─────────" -ForegroundColor Cyan

try {
    $authContextResponse = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/identity/authenticationContextClassReferences/c1" `
        -ErrorAction Stop

    if ($authContextResponse.isAvailable -eq $true) {
        Write-PIMLog -Level OK -Phase "PRE" -Message "Authentication context 'c1' exists and is available: $($authContextResponse.displayName)"
    } else {
        Write-PIMLog -Level WARN -Phase "PRE" -Message "Authentication context 'c1' exists but is NOT marked available — Phases 5/6 will set it on role policies but it won't be enforced."
    }
} catch {
    Write-PIMLog -Level WARN -Phase "PRE" -Message "Authentication context 'c1' not found — Phases 5/6 will still apply it to role policies but no enforcement will occur until a CA policy is created."
}

try {
    $caPolicies = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?`$select=displayName,state,conditions" `
        -ErrorAction Stop

    $c1Policies = $caPolicies.value | Where-Object {
        $_.conditions.authenticationContext.authenticationContextClassReferences |
            Where-Object { $_.id -eq "c1" }
    }

    if ($c1Policies.Count -gt 0) {
        foreach ($policy in $c1Policies) {
            $stateLabel = if ($policy.state -eq "enabled") { "enabled" } else { "⚠ $($policy.state)" }
            Write-PIMLog -Level OK -Phase "PRE" -Message "CA policy targeting 'c1' found: '$($policy.displayName)' [$stateLabel]"
        }
    } else {
        Write-PIMLog -Level WARN -Phase "PRE" -Message "No Conditional Access policy found targeting authentication context 'c1' — role activation will not enforce it until one is created."
    }
} catch {
    Write-PIMLog -Level WARN -Phase "PRE" -Message "Could not retrieve Conditional Access policies: $($_.Exception.Message)"
}

# ===========================================================================
# PHASE 1 — Create role-assignable groups
# ===========================================================================
Write-Host ""
Write-Host "── PHASE 1: Group Provisioning ──────────────────────" -ForegroundColor Cyan

foreach ($config in $GroupConfigs) {
    $groupName = $config.DisplayName
    $existing  = Resolve-Group -DisplayName $groupName

    if ($existing) {
        $config['_GroupId'] = $existing.Id
        Write-PIMLog -Level OK -Phase "P1" -Message "Group exists: $groupName (Id: $($existing.Id))"

        # Check description drift
        if ($existing.Description -ne $config.Description) {
            if ($DryRun) {
                Write-PIMLog -Level INFO -Phase "P1" -Message "[DRY RUN] Would update description for: $groupName"
            } else {
                try {
                    Update-MgGroup -GroupId $existing.Id -Description $config.Description -ErrorAction Stop
                    Write-PIMLog -Level OK -Phase "P1" -Message "Description updated: $groupName"
                } catch {
                    Write-PIMLog -Level ERR -Phase "P1" -Message "Failed to update description for '$groupName': $($_.Exception.Message)"
                }
            }
        }
    } else {
        if ($DryRun) {
            Write-PIMLog -Level INFO -Phase "P1" -Message "[DRY RUN] Would create group: $groupName"
            $config['_GroupId'] = "[DRY-RUN-ID]"
        } else {
            Write-PIMLog -Level INFO -Phase "P1" -Message "Creating group: $groupName"
            try {
                $newGroup = New-MgGroup `
                    -DisplayName      $groupName `
                    -Description      $config.Description `
                    -MailEnabled:     $false `
                    -MailNickname     ("grp" + (-join ((65..90) + (97..122) | Get-Random -Count 8 | ForEach-Object { [char]$_ }))) `
                    -SecurityEnabled: $true `
                    -AdditionalProperties @{ isAssignableToRole = $true } `
                    -ErrorAction Stop

                $config['_GroupId'] = $newGroup.Id
                Write-PIMLog -Level OK -Phase "P1" -Message "Created: $groupName (Id: $($newGroup.Id))"
                Write-PIMLog -Level INFO -Phase "P1" -Message "Waiting 22s for directory propagation after group creation..."
                Start-Sleep -Seconds 22
            } catch {
                $config['_GroupId'] = $null
                Write-PIMLog -Level ERR -Phase "P1" -Message "Failed to create '$groupName': $($_.Exception.Message)"
            }
        }
    }
}

# ===========================================================================
# PHASE 2 — PIM group policies (PIM4Groups only)
# Must run before Phase 3 so AllowPermanentEligibility is enabled
# before eligible member assignments are attempted.
# ===========================================================================
Write-Host ""
Write-Host "── PHASE 2: PIM Group Policies ──────────────────────" -ForegroundColor Cyan

foreach ($config in $GroupConfigs | Where-Object { $_.PIM4Group -eq $true }) {
    $groupName = $config.DisplayName
    $groupId   = $config['_GroupId']

    if (-not $groupId) {
        Write-PIMLog -Level WARN -Phase "P2" -Message "Skipping '$groupName' — no group Id"
        continue
    }

    if ($DryRun) {
        Write-PIMLog -Level INFO -Phase "P2" -Message "[DRY RUN] Would apply PIM group policy (8h, MFA+justification+ticket): $groupName"
    } else {
        Write-PIMLog -Level INFO -Phase "P2" -Message "Applying PIM group policy: $groupName"
        Write-PIMLog -Level INFO -Phase "P2" -Message "Waiting 10s before applying PIM policy..."
        Start-Sleep -Seconds 10

        try {
            Set-PIMGroupPolicy `
                -TenantID                       $TenantId `
                -GroupID                        $groupId `
                -Type                           "member" `
                -ActivationDuration             "PT8H" `
                -ActivationRequirement          $ActivationRequirements `
                -ActiveAssignmentRequirement    $ActiveAssignmentRequirements `
                -AllowPermanentEligibility      $true `
                -AllowPermanentActiveAssignment $true `
                -Notification_EligibleAssignment_Alert $NotificationConfig `
                -Notification_ActiveAssignment_Alert   $NotificationConfig `
                -Notification_Activation_Alert         $NotificationConfig
            Write-PIMLog -Level OK -Phase "P2" -Message "PIM policy applied: $groupName"
        } catch {
            Write-PIMLog -Level ERR -Phase "P2" -Message "Failed to apply PIM policy on '$groupName': $($_.Exception.Message)"
        }
    }
}

# ===========================================================================
# PHASE 3 — Group membership
# ===========================================================================
Write-Host ""
Write-Host "── PHASE 3: Group Membership ────────────────────────" -ForegroundColor Cyan

foreach ($config in $GroupConfigs) {
    $groupName = $config.DisplayName
    $groupId   = $config['_GroupId']

    if (-not $groupId) {
        Write-PIMLog -Level WARN -Phase "P3" -Message "Skipping '$groupName' — group has no Id (creation failed in Phase 1)"
        continue
    }

    Write-PIMLog -Level INFO -Phase "P3" -Message "Processing members for: $groupName"

    # Build expected member ID set (only users that resolved successfully)
    $expectedIds = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($displayName in $config.Users) {
        if ($resolvedUsers.ContainsKey($displayName)) {
            [void] $expectedIds.Add($resolvedUsers[$displayName].Id)
        }
    }

    # ── Drift removal (regular groups only) ──────────────────────────────────
    if (-not $config.PIM4Group) {
        $currentMembers = Get-MgGroupMember -GroupId $groupId -All -ErrorAction SilentlyContinue

        foreach ($member in $currentMembers) {
            if (-not $expectedIds.Contains($member.Id)) {
                $memberDisplay = $member.AdditionalProperties['displayName']
                if ($DryRun) {
                    Write-PIMLog -Level INFO -Phase "P3" -Message "[DRY RUN] Would remove unexpected member: $memberDisplay → $groupName"
                } else {
                    try {
                        Remove-MgGroupMemberByRef -GroupId $groupId -DirectoryObjectId $member.Id -ErrorAction Stop
                        Write-PIMLog -Level OK -Phase "P3" -Message "Removed unexpected member: $memberDisplay → $groupName"
                    } catch {
                        Write-PIMLog -Level ERR -Phase "P3" -Message "Failed to remove '$memberDisplay' → '$groupName': $($_.Exception.Message)"
                    }
                }
            }
        }
    } else {
        # PIM4Group: compare current eligible members against config and remove drift
        $currentEligible = Get-PIMGroupEligibleAssignment -TenantID $TenantId -GroupID $groupId -Type "member" -ErrorAction SilentlyContinue

        foreach ($assignment in $currentEligible) {
            if (-not $expectedIds.Contains($assignment.principalid)) {
                $principalDisplay = $assignment.principalName
                if ($DryRun) {
                    Write-PIMLog -Level INFO -Phase "P3" -Message "[DRY RUN] Would remove unexpected eligible member: $principalDisplay → $groupName"
                } else {
                    try {
                        Remove-PIMGroupEligibleAssignment -TenantID $TenantId -GroupID $groupId -PrincipalID $assignment.principalid -Type "member" -Justification $Justification -ErrorAction Stop
                        Write-PIMLog -Level OK -Phase "P3" -Message "Removed unexpected eligible member: $principalDisplay → $groupName"
                    } catch {
                        Write-PIMLog -Level ERR -Phase "P3" -Message "Failed to remove eligible '$principalDisplay' → '$groupName': $($_.Exception.Message)"
                    }
                }
            }
        }
    }

    # ── Add missing members ───────────────────────────────────────────────────
    foreach ($displayName in $config.Users) {
        $userObj = if ($resolvedUsers.ContainsKey($displayName)) { $resolvedUsers[$displayName] } else { $null }

        if (-not $userObj) {
            $missingLevel = if ($DryRun) { "WARN" } else { "ERR" }
            Write-PIMLog -Level $missingLevel -Phase "P3" -Message "User not found: '$displayName' (group: $groupName)"
            continue
        }

        if ($config.PIM4Group) {
            # PIM4Groups: add as eligible member via EasyPIM
            if ($DryRun) {
                Write-PIMLog -Level INFO -Phase "P3" -Message "[DRY RUN] Would assign eligible member: $displayName → $groupName"
            } else {
                try {
                    New-PIMGroupEligibleAssignment `
                        -TenantID      $TenantId `
                        -GroupID       $groupId `
                        -PrincipalID   $userObj.Id `
                        -Type          "member" `
                        -Justification $Justification `
                        -Permanent | Out-Null
                    Write-PIMLog -Level OK -Phase "P3" -Message "Eligible member assigned: $displayName → $groupName"
                } catch {
                    # EasyPIM throws if already assigned — treat as OK
                    if ($_.Exception.Message -match "already") {
                        Write-PIMLog -Level OK -Phase "P3" -Message "Already eligible: $displayName → $groupName"
                    } else {
                        Write-PIMLog -Level ERR -Phase "P3" -Message "Failed eligible assignment '$displayName' → '$groupName': $($_.Exception.Message)"
                    }
                }
            }
        } else {
            # Regular group: add as direct member
            if ($DryRun) {
                Write-PIMLog -Level INFO -Phase "P3" -Message "[DRY RUN] Would add member: $displayName → $groupName"
            } else {
                $isMember = Get-MgGroupMember -GroupId $groupId -All -ErrorAction SilentlyContinue |
                    Where-Object { $_.Id -eq $userObj.Id }

                if ($isMember) {
                    Write-PIMLog -Level OK -Phase "P3" -Message "Already member: $displayName → $groupName"
                } else {
                    try {
                        New-MgGroupMember -GroupId $groupId -DirectoryObjectId $userObj.Id -ErrorAction Stop
                        Write-PIMLog -Level OK -Phase "P3" -Message "Added member: $displayName → $groupName"
                    } catch {
                        Write-PIMLog -Level ERR -Phase "P3" -Message "Failed to add '$displayName' → '$groupName': $($_.Exception.Message)"
                    }
                }
            }
        }
    }
}

# ===========================================================================
# PHASE 4 — Assign roles to groups
# ===========================================================================
Write-Host ""
Write-Host "── PHASE 4: Group Role Assignments ──────────────────" -ForegroundColor Cyan

foreach ($config in $GroupConfigs) {
    $groupName = $config.DisplayName
    $groupId   = $config['_GroupId']

    if (-not $groupId) {
        Write-PIMLog -Level WARN -Phase "P4" -Message "Skipping '$groupName' — no group Id"
        continue
    }

    foreach ($role in $config.ActiveRoles) {
        if ($DryRun) {
            Write-PIMLog -Level INFO -Phase "P4" -Message "[DRY RUN] Would assign [Active  ] $role → $groupName"
        } else {
            try {
                New-PIMEntraRoleActiveAssignment `
                    -TenantID      $TenantId `
                    -RoleName      $role `
                    -PrincipalID   $groupId `
                    -Justification $Justification `
                    -Permanent | Out-Null
                Write-PIMLog -Level OK -Phase "P4" -Message "[Active  ] $role → $groupName"
            } catch {
                if ($_.Exception.Message -match "already") {
                    Write-PIMLog -Level OK -Phase "P4" -Message "[Active  ] Already assigned: $role → $groupName"
                } else {
                    Write-PIMLog -Level ERR -Phase "P4" -Message "[Active  ] Failed '$role' → '$groupName': $($_.Exception.Message)"
                }
            }
            Start-Sleep -Seconds 2
        }
    }

    foreach ($role in $config.EligibleRoles) {
        if ($DryRun) {
            Write-PIMLog -Level INFO -Phase "P4" -Message "[DRY RUN] Would assign [Eligible] $role → $groupName"
        } else {
            try {
                New-PIMEntraRoleEligibleAssignment `
                    -TenantID      $TenantId `
                    -RoleName      $role `
                    -PrincipalID   $groupId `
                    -Justification $Justification `
                    -Permanent | Out-Null
                Write-PIMLog -Level OK -Phase "P4" -Message "[Eligible] $role → $groupName"
            } catch {
                if ($_.Exception.Message -match "already") {
                    Write-PIMLog -Level OK -Phase "P4" -Message "[Eligible] Already assigned: $role → $groupName"
                } else {
                    Write-PIMLog -Level ERR -Phase "P4" -Message "[Eligible] Failed '$role' → '$groupName': $($_.Exception.Message)"
                }
            }
            Start-Sleep -Seconds 2
        }
    }
}

# ===========================================================================
# PHASE 5 — Standard PIM role policies (no approval)
# ===========================================================================
Write-Host ""
Write-Host "── PHASE 5: Standard Role Policies ──────────────────" -ForegroundColor Cyan
Write-PIMLog -Level INFO -Phase "P5" -Message "Applying standard policy to $($StandardRoles.Count) roles..."

foreach ($role in $StandardRoles) {
    if ($DryRun) {
        Write-PIMLog -Level INFO -Phase "P5" -Message "[DRY RUN] Would apply standard policy: $role"
    } else {
        try {
            Set-PIMEntraRolePolicy -TenantId $TenantId -RoleName $role `
                -ActivationRequirement          $ActivationRequirements `
                -ActiveAssignmentRequirement    $ActiveAssignmentRequirements `
                -AuthenticationContext_Enabled  $true `
                -AuthenticationContext_Value    "c1" `
                -Notification_EligibleAssignment_Alert $NotificationConfig `
                -Notification_ActiveAssignment_Alert   $NotificationConfig `
                -Notification_Activation_Alert         $NotificationConfig
            Write-PIMLog -Level OK -Phase "P5" -Message "$role"
        } catch {
            Write-PIMLog -Level ERR -Phase "P5" -Message "Failed '$role': $($_.Exception.Message)"
        }
    }
}

# ===========================================================================
# PHASE 6 — Privileged PIM role policies (approval required)
# ===========================================================================
Write-Host ""
Write-Host "── PHASE 6: Privileged Role Policies (approval) ─────" -ForegroundColor Cyan

# Resolve approver group IDs
$approverGroup_M365     = Resolve-Group -DisplayName $ApproverGroupName_M365
$approverGroup_Security = Resolve-Group -DisplayName $ApproverGroupName_Security

if (-not $approverGroup_M365) {
    $lvl = if ($DryRun) { "WARN" } else { "ERR" }
    Write-PIMLog -Level $lvl -Phase "P6" -Message "Approver group not found: '$ApproverGroupName_M365'$(if (-not $DryRun) { ' — privileged role policies CANNOT be applied.' })"
}
if (-not $approverGroup_Security) {
    $lvl = if ($DryRun) { "WARN" } else { "ERR" }
    Write-PIMLog -Level $lvl -Phase "P6" -Message "Approver group not found: '$ApproverGroupName_Security'$(if (-not $DryRun) { ' — privileged role policies CANNOT be applied.' })"
}

if ($approverGroup_M365 -and $approverGroup_Security) {
    $Approvers = @(
        @{ Id = $approverGroup_M365.Id;     Name = $ApproverGroupName_M365;     Type = "group" }
        @{ Id = $approverGroup_Security.Id; Name = $ApproverGroupName_Security; Type = "group" }
    )

    Write-PIMLog -Level INFO -Phase "P6" -Message "Approvers resolved: $ApproverGroupName_M365, $ApproverGroupName_Security"
    Write-PIMLog -Level INFO -Phase "P6" -Message "Applying privileged policy to $($PrivilegedRoles.Count) roles..."

    foreach ($role in $PrivilegedRoles) {
        if ($DryRun) {
            Write-PIMLog -Level INFO -Phase "P6" -Message "[DRY RUN] Would apply privileged policy (4h, approval required): $role"
        } else {
            try {
                Set-PIMEntraRolePolicy -TenantId $TenantId -RoleName $role `
                    -ActivationRequirement          $ActivationRequirements `
                    -ActiveAssignmentRequirement    $ActiveAssignmentRequirements `
                    -ActivationDuration             "PT4H" `
                    -AuthenticationContext_Enabled  $true `
                    -AuthenticationContext_Value    "c1" `
                    -ApprovalRequired               $true `
                    -Approvers                      $Approvers `
                    -Notification_EligibleAssignment_Alert $NotificationConfig `
                    -Notification_ActiveAssignment_Alert   $NotificationConfig `
                    -Notification_Activation_Alert         $NotificationConfig
                Write-PIMLog -Level OK -Phase "P6" -Message "$role"
            } catch {
                Write-PIMLog -Level ERR -Phase "P6" -Message "Failed '$role': $($_.Exception.Message)"
            }
        }
    }
} elseif ($DryRun) {
    Write-PIMLog -Level INFO -Phase "P6" -Message "[DRY RUN] Approver groups would be created in Phase 1 — enumerating privileged role policies:"
    foreach ($role in $PrivilegedRoles) {
        Write-PIMLog -Level INFO -Phase "P6" -Message "[DRY RUN] Would apply privileged policy (4h, approval required, approvers: $ApproverGroupName_M365 + $ApproverGroupName_Security): $role"
    }
} else {
    Write-PIMLog -Level WARN -Phase "P6" -Message "Phase 6 skipped — one or both approver groups could not be resolved."
}

# =====================
# Disconnect
# =====================
try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch {}

# ===========================================================================
# PHASE 7 — Summary report
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

    $phaseLabel = switch ($phase) {
        "PRE" { "Pre-flight — User Existence Check     " }
        "P1"  { "Phase 1 — Group Provisioning          " }
        "P2"  { "Phase 2 — PIM Group Policies          " }
        "P3"  { "Phase 3 — Group Membership            " }
        "P4"  { "Phase 4 — Group Role Assignments      " }
        "P5"  { "Phase 5 — Standard Role Policies      " }
        "P6"  { "Phase 6 — Privileged Role Policies    " }
        default { $phase }
    }

    $statusColor = if ($err -gt 0) { "Red" } elseif ($warn -gt 0) { "Yellow" } else { "Green" }
    Write-Host "  $phaseLabel  OK: $ok  WARN: $warn  ERR: $err" -ForegroundColor $statusColor
}

Write-Host ""

$totalErrors = ($script:Log | Where-Object { $_.Level -eq "ERR" }).Count
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
