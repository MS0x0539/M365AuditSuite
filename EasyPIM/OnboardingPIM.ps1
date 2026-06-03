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
        Activation window set by $StandardActivationDuration, justification + ticket
        required, permanent eligibility and active assignment allowed, notifications
        enabled. Note: AuthenticationContext is not supported for group policies
        (Microsoft API limitation) — step-up auth relies on justification + ticketing only.

    PHASE 3 — Group membership
        Ensures each group contains exactly the members defined in $GroupConfigs.
        Unexpected members are removed (drift correction). Users not found in the
        tenant are flagged and skipped. For PIM4Groups, users are assigned as
        eligible members via EasyPIM instead of direct membership. Time-limited
        eligible assignments are corrected to permanent automatically.

    PHASE 4 — Group role assignments
        Assigns the active and eligible Entra ID roles defined per group. Assignments
        are made to the group object itself (not to individual users). Already-assigned
        roles are skipped gracefully. Time-limited assignments are corrected to permanent.

    PHASE 5 — Standard PIM role policies (all roles, no approval)
        Applies the standard role policy to every role in $StandardRoles:
        justification + ticket on activation, authentication context $AuthContextId,
        activation window $StandardActivationDuration, notifications to configured
        recipients. No approval required. Throttle-resilient (auto-retry on 429).

    PHASE 6 — Privileged PIM role policies (5 roles, approval required)
        Same requirements as Phase 5 plus mandatory approval from two approver groups.
        Activation window set by $PrivilegedActivationDuration. Throttle-resilient.

    PHASE 7 — Direct assignment audit
        Two scans run in sequence:

        (1) Direct role assignments — scans for Entra ID roles assigned directly to
        users, service principals, or groups not managed by this script. Covers
        permanent (non-PIM) assignments, PIM Active (Direct), and PIM Eligible
        (Direct) assignments. Findings are grouped by role, printed as WARN, and
        exported to OnboardingPIM_DirectAssignments_<timestamp>.csv.

        (2) Unmanaged PIM4Groups — scans for PIM for Groups configurations in the
        tenant that are not listed in $GroupConfigs. These represent groups outside
        the authorization matrix. Findings are exported to
        OnboardingPIM_UnmanagedPIM4Groups_<timestamp>.csv. Recently deleted groups
        that still appear in PIM4Groups are flagged as INFO (auto-cleanup within 24h).

        Both CSVs are written to the transcript folder only if findings exist.

    PHASE 8 — Summary report
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
    Permissions : Directory.ReadWrite.All,
                  Group.ReadWrite.All,
                  Policy.Read.All,
                  PrivilegedAccess.ReadWrite.AzureAD,
                  PrivilegedAccess.ReadWrite.AzureADGroup,
                  PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup,
                  PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup,
                  RoleManagement.ReadWrite.Directory,
                  RoleManagementPolicy.ReadWrite.AzureADGroup,
                  RoleManagementPolicy.ReadWrite.Directory
                  (application permissions — grant admin consent)
    Auth        : Certificate-based (app registration: EasyPIM)
    Requires    : Microsoft.Graph.Authentication, Microsoft.Graph.Groups,
                  Microsoft.Graph.Users, EasyPIM PowerShell module
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
# Policy configuration
# =====================
$AuthContextId                = "c1"     # Authentication context ID used in Phase 5/6 and PRE-CA check
$StandardActivationDuration   = "PT8H"   # Activation window for standard roles (Phase 5) and PIM4Groups (Phase 2)
$PrivilegedActivationDuration = "PT4H"   # Activation window for privileged roles with approval (Phase 6)

$Justification = "PIM onboarding / authorization matrix enforcement | EasyPIM"

$Recipients = @(
    "pim-notifications@psbv.org"
    "security@psbv.org"
)

# Activation requirements (used for role activation and PIM4Groups activation)
# Note: MultiFactorAuthentication is intentionally omitted here — when AuthenticationContext
# is enabled ($AuthContextId), the CA policy enforces MFA. Including it would trigger MfaAndAcrsConflict.
$ActivationRequirements = @(
    "Justification"
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
    "AI Reader"
    "Authentication Administrator"
    "Authentication Extensibility Administrator"
    "Authentication Extensibility Password Administrator"
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
    "Customer Delegated Admin Relationship Administrator"
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
    "Entra Backup Administrator"
    "Entra Backup Reader"
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
    "Purview Workload Content Administrator"
    "Purview Workload Content Reader"
    "Purview Workload Content Writer"
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
    "Teams Communications Support Engineer"
    "Teams Communications Support Specialist"
    "Teams External Collaboration Administrator"
    "Teams Devices Administrator"
    "Teams Reader"
    "Teams Telephony Administrator"
    "Tenant Creator"
    "Tenant Governance Administrator"
    "Tenant Governance Reader"
    "Tenant Governance Relationship Administrator"
    "Tenant Governance Relationship Reader"
    "Usage Summary Reports Reader"
    "User Administrator"
    "User Experience Success Manager"
    "Virtual Visits Administrator"
    "Viva Glint Tenant Administrator"
    "Viva Goals Administrator"
    "Viva Pulse Administrator"
    "Windows 365 Administrator"
    "Yammer Administrator"
    "Windows Update Deployment Administrator"
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
        Users         = @(
            "Beheer Arjan Visscher"
            "Beheer Tessa Blom"
            "Beheer Gijs Hendrikx"
            "Beheer Sofie Wolters"
            "Beheer Martijn Groen"
            "Beheer Sjoerd Koolen"
            "Beheer Mandy Verbruggen"
            "Beheer Hugo van Zanten"
        )
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

# ── Transcript — started after Graph connect so tenant name can be resolved ──
$script:RunTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$transcriptFolder    = $null
$transcriptFile      = $null

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

# ── Notification config comparator ───────────────────────────────────────────
# Compares a policy's notification block against the desired $NotificationConfig.
# Returns $true if recipients, notificationLevel, and isDefaultRecipientEnabled all match.
# Returns $false if the block is null or any field differs — triggering a policy re-apply.
# If EasyPIM doesn't expose the notification properties, callers default to $false (force apply).
function Test-NotifConfig {
    param (
        [object]    $PolicyNotif,
        [hashtable] $Expected
    )
    if (-not $PolicyNotif) { return $false }

    # Compare recipient lists order-independently
    $currentRecipients  = @($PolicyNotif.Recipients | Sort-Object)
    $expectedRecipients = @($Expected.Recipients    | Sort-Object)
    if ($currentRecipients.Count -ne $expectedRecipients.Count) { return $false }
    for ($i = 0; $i -lt $currentRecipients.Count; $i++) {
        if ($currentRecipients[$i] -ne $expectedRecipients[$i]) { return $false }
    }

    return (
        $PolicyNotif.isDefaultRecipientEnabled -eq $Expected.isDefaultRecipientEnabled -and
        $PolicyNotif.notificationLevel         -eq $Expected.notificationLevel
    )
}

# ── Throttle-resilient retry wrapper ─────────────────────────────────────────
# Runs $ScriptBlock up to $MaxRetries times; retries on 429 with exponential back-off.
# Uses & (not dot-source) so outer script variables are readable via scope chain.
function Invoke-WithRetry {
    param(
        [scriptblock] $ScriptBlock,
        [string]      $Phase,
        [string]      $Label,
        [int]         $MaxRetries = 3
    )
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            & $ScriptBlock
            return
        } catch {
            $msg = $_.Exception.Message
            if ($msg -match "429|TooManyRequests|Too Many Requests|Throttled" -and $attempt -lt $MaxRetries) {
                $delaySec = 30 * $attempt
                Write-PIMLog -Level WARN -Phase $Phase -Message "API throttled — waiting ${delaySec}s [retry $attempt of $($MaxRetries - 1)]: $Label"
                Start-Sleep -Seconds $delaySec
            } else {
                throw
            }
        }
    }
}

# ── Module check ─────────────────────────────────────────────────────────────
try {

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

# EasyPIM version check
$easyPIMModule = Get-Module EasyPIM
if ($easyPIMModule) {
    $minVersion = [Version]"2.3.1"
    if ($easyPIMModule.Version -lt $minVersion) {
        Write-Host "  WARN: EasyPIM $($easyPIMModule.Version) is older than minimum tested version $minVersion — consider: Update-Module EasyPIM" -ForegroundColor Yellow
    } else {
        Write-Host "  EasyPIM version: $($easyPIMModule.Version)" -ForegroundColor Green
    }
}

# ── Connect ───────────────────────────────────────────────────────────────────
Write-Host ""
$tenantLabel = if ($TenantDisplayName.Length -gt 41) { $TenantDisplayName.Substring(0, 38) + "..." } else { $TenantDisplayName }
Write-Host "╔════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
Write-Host "║                     TARGET TENANT                      ║" -ForegroundColor Yellow
Write-Host "╠════════════════════════════════════════════════════════╣" -ForegroundColor Yellow
Write-Host ("║  Tenant     : {0,-41}║" -f $tenantLabel) -ForegroundColor Yellow
Write-Host ("║  Tenant ID  : {0,-41}║" -f $TenantId) -ForegroundColor Yellow
Write-Host ("║  App ID     : {0,-41}║" -f $AppId) -ForegroundColor Yellow
Write-Host ("║  Thumbprint : {0,-41}║" -f $CertificateThumbprint) -ForegroundColor Yellow
Write-Host "╚════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Press Ctrl+C within 3 seconds to cancel..." -ForegroundColor DarkGray
Start-Sleep -Seconds 1; Write-Host "  3..." -ForegroundColor DarkGray -NoNewline
Start-Sleep -Seconds 1; Write-Host " 2..." -ForegroundColor DarkGray -NoNewline
Start-Sleep -Seconds 1; Write-Host " 1..." -ForegroundColor DarkGray
Write-Host ""

Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
try {
    Connect-MgGraph -TenantId $TenantId -AppId $AppId -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
    Write-Host "Connected to tenant: $TenantId" -ForegroundColor Green
} catch {
    Write-Host "FATAL: Could not connect to Microsoft Graph: $_" -ForegroundColor Red
    exit 1
}

# Resolve tenant display name → Desktop/<TenantName>/OnboardingPIM/
$orgDisplayName = "Unknown"
try {
    $orgResp = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/organization?`$select=displayName" `
        -ErrorAction Stop
    if ($orgResp.value -and $orgResp.value[0].displayName) {
        $orgDisplayName = $orgResp.value[0].displayName -replace '[<>:"/\\|?*]', '_'
    }
} catch {}

$transcriptFolder = Join-Path ([Environment]::GetFolderPath('Desktop')) (Join-Path $orgDisplayName "OnboardingPIM")
try {
    New-Item -ItemType Directory -Force -Path $transcriptFolder -ErrorAction Stop | Out-Null
} catch {
    $transcriptFolder = [Environment]::GetFolderPath('Desktop')
}

$transcriptFile = Join-Path $transcriptFolder ("OnboardingPIM_{0}.txt" -f $script:RunTimestamp)
try {
    Start-Transcript -Path $transcriptFile -NoClobber -ErrorAction Stop
    Write-Host "Transcript : $transcriptFile" -ForegroundColor DarkGray
    Write-Host "Author     : Melih Sivrikaya" -ForegroundColor DarkGray
    Write-Host "Script     : OnboardingPIM.ps1" -ForegroundColor DarkGray
    Write-Host "Run date   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
    Write-Host "Tenant     : $TenantId ($orgDisplayName)" -ForegroundColor DarkGray
    Write-Host ""
} catch {
    Write-Host "Could not start transcript: $_" -ForegroundColor Yellow
    $transcriptFile = $null
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
    isDefaultRecipientEnabled = $true
    notificationLevel         = "All"
    Recipients                = $Recipients
}

# ===========================================================================
# PRE-FLIGHT — Permission validation
# ===========================================================================
Write-Host ""
Write-Host "── PRE-FLIGHT: Permission validation ────────────────" -ForegroundColor Cyan

$permissionTests = @(
    @{ Name = "Directory.ReadWrite.All";                              Uri = "https://graph.microsoft.com/v1.0/users?`$top=1&`$select=id" }
    @{ Name = "Group.ReadWrite.All";                                  Uri = "https://graph.microsoft.com/v1.0/groups?`$top=1&`$select=id" }
    @{ Name = "RoleManagement.ReadWrite.Directory";                   Uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?`$top=1&`$select=displayName" }
    @{ Name = "RoleManagementPolicy.ReadWrite.Directory";             Uri = "https://graph.microsoft.com/v1.0/policies/roleManagementPolicies?`$top=1&`$select=id" }
    @{ Name = "Policy.Read.All";                                      Uri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?`$top=1&`$select=id" }
    @{ Name = "PrivilegedAccess.ReadWrite.AzureADGroup";              Uri = "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$top=1&`$select=id" }
    @{ Name = "PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup";  Uri = "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentSchedules?`$top=1&`$select=id" }
)

foreach ($test in $permissionTests) {
    try {
        Invoke-MgGraphRequest -Method GET -Uri $test.Uri -ErrorAction Stop 2>$null | Out-Null
        Write-PIMLog -Level OK -Phase "PRE-PERM" -Message "Permission OK: $($test.Name)"
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match "BadRequest|Bad Request") {
            # 400 BadRequest means the server responded — permission is granted, endpoint just needs specific parameters
            Write-PIMLog -Level OK -Phase "PRE-PERM" -Message "Permission OK: $($test.Name)"
        } elseif ($msg -match "Forbidden|Unauthorized|Authorization") {
            Write-PIMLog -Level WARN -Phase "PRE-PERM" -Message "Permission MISSING: $($test.Name) — grant admin consent in the app registration"
        } else {
            Write-PIMLog -Level INFO -Phase "PRE-PERM" -Message "Permission check inconclusive for $($test.Name): $msg"
        }
    }
}

# ── Authentication context + Conditional Access check ────────────────────────
Write-Host ""
Write-Host "── PRE-FLIGHT: Authentication context check ─────────" -ForegroundColor Cyan

$script:C1AuthContextOk = $false
$script:C1CAPolicyOk    = $false

try {
    # Use the individual item GET — avoids list-endpoint SDK header injection issues
    $c1Ctx = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/identity/authenticationContextClassReferences/$AuthContextId" `
        -ErrorAction Stop 2>$null

    if ($c1Ctx.isAvailable -eq $true) {
        $script:C1AuthContextOk = $true
        Write-PIMLog -Level OK -Phase "PRE-CA" -Message "Authentication context '$AuthContextId' found and available: $($c1Ctx.displayName)"
    } else {
        Write-PIMLog -Level WARN -Phase "PRE-CA" -Message "Authentication context '$AuthContextId' exists ('$($c1Ctx.displayName)') but is NOT marked available — enable it in Entra > Protection > Authentication contexts."
    }
} catch {
    $errMsg = $_.Exception.Message
    if ($errMsg -match "404|NotFound|Not Found|ResourceNotFound") {
        Write-PIMLog -Level WARN -Phase "PRE-CA" -Message "Authentication context '$AuthContextId' not found — create it under Entra > Protection > Authentication contexts."
    } elseif ($errMsg -match "BadRequest|Bad Request") {
        # Graph returns 400 on this endpoint for some tenants — server responded, so context likely exists; CA policy check below is the real gate
        $script:C1AuthContextOk = $true
        Write-PIMLog -Level OK -Phase "PRE-CA" -Message "Authentication context '$AuthContextId' — individual lookup not supported by API; CA policy check will confirm."
    } else {
        Write-PIMLog -Level INFO -Phase "PRE-CA" -Message "Could not verify authentication context '$AuthContextId' via API ($errMsg) — check manually in Entra > Protection > Authentication contexts."
        $script:C1AuthContextOk = $true
    }
}

try {
    $caPolicies = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?`$select=displayName,state,conditions" `
        -ErrorAction Stop 2>$null

    # Graph v1.0 stores auth context under conditions.applications.includeAuthenticationContextClassReferences
    # as a plain string array (e.g. ["c1"]) — not an object with {id: "c1"}.
    # JSON matching is used to avoid property-navigation issues with hashtable vs PSObject responses.
    $authContextPattern = [regex]::Escape($AuthContextId)
    $c1Policies = $caPolicies.value | Where-Object {
        $policyJson = $_ | ConvertTo-Json -Depth 10 -Compress
        $policyJson -match '"includeAuthenticationContextClassReferences"' -and
        $policyJson -match ('"' + $authContextPattern + '"')
    }

    if ($c1Policies.Count -gt 0) {
        $enabledCount = ($c1Policies | Where-Object { $_.state -eq "enabled" }).Count
        foreach ($policy in $c1Policies) {
            $stateLabel = if ($policy.state -eq "enabled") { "enabled" } else { "⚠ $($policy.state)" }
            Write-PIMLog -Level OK -Phase "PRE-CA" -Message "CA policy targeting '$AuthContextId': '$($policy.displayName)' [$stateLabel]"
        }
        if ($enabledCount -gt 0) {
            $script:C1CAPolicyOk = $true
        } else {
            Write-PIMLog -Level WARN -Phase "PRE-CA" -Message "CA policies targeting '$AuthContextId' exist but none are enabled."
        }
    } else {
        if ($script:C1AuthContextOk) {
            Write-PIMLog -Level WARN -Phase "PRE-CA" -Message "Authentication context '$AuthContextId' is available in the tenant but not in use in any CA policy — create a policy targeting '$AuthContextId' to enforce step-up auth on PIM activation."
        } else {
            Write-PIMLog -Level WARN -Phase "PRE-CA" -Message "No Conditional Access policy found targeting authentication context '$AuthContextId'."
        }
    }
} catch {
    Write-PIMLog -Level WARN -Phase "PRE-CA" -Message "Could not retrieve Conditional Access policies: $($_.Exception.Message)"
}

# Combined enforcement check — logged as WARN so it always surfaces in the end summary
if (-not $script:C1AuthContextOk -or -not $script:C1CAPolicyOk) {
    $missing = @()
    if (-not $script:C1AuthContextOk) { $missing += "authentication context '$AuthContextId' (create it under Protection > Authentication contexts)" }
    if (-not $script:C1CAPolicyOk)    { $missing += "an enabled Conditional Access policy targeting '$AuthContextId' (required to enforce step-up auth on PIM activation)" }
    Write-PIMLog -Level WARN -Phase "PRE-CA" -Message "⚠ Authentication enforcement is INCOMPLETE. Missing: $($missing -join '; ')"
} else {
    Write-PIMLog -Level OK -Phase "PRE-CA" -Message "Authentication context '$AuthContextId' and CA enforcement are fully in place."
}

# ── License validation ────────────────────────────────────────────────────────
Write-Host ""
Write-Host "── PRE-FLIGHT: License validation ───────────────────" -ForegroundColor Cyan

$p2SkuPartNumbers = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@(
    "AAD_PREMIUM_P2"             # Azure AD Premium P2 (standalone)
    "ENTRA_IDENTITY_GOV"         # Microsoft Entra ID Governance
    "SPE_E5"                     # Microsoft 365 E5
    "EMSPREMIUM"                 # Enterprise Mobility + Security E5
    "M365_G5"                    # Microsoft 365 G5
    "IDENTITY_THREAT_PROTECTION" # Microsoft 365 E5 Security add-on
) | ForEach-Object { [void] $p2SkuPartNumbers.Add($_) }

try {
    $skuResp    = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/subscribedSkus?`$select=skuPartNumber,capabilityStatus" `
        -ErrorAction Stop
    $matchedSku = $skuResp.value |
        Where-Object { $_.capabilityStatus -eq "Enabled" -and $p2SkuPartNumbers.Contains($_.skuPartNumber) } |
        Select-Object -First 1

    if ($matchedSku) {
        Write-PIMLog -Level OK -Phase "PRE-LIC" -Message "License verified: $($matchedSku.skuPartNumber) — Entra ID P2 / Governance confirmed."
    } else {
        $allEnabled = ($skuResp.value | Where-Object { $_.capabilityStatus -eq "Enabled" } |
            Select-Object -ExpandProperty skuPartNumber) -join ", "
        Write-PIMLog -Level WARN -Phase "PRE-LIC" -Message "No Entra ID P2 or Governance license detected — PIM operations will fail. Enabled SKUs: $allEnabled"
    }
} catch {
    Write-PIMLog -Level WARN -Phase "PRE-LIC" -Message "Could not verify license: $($_.Exception.Message)"
}

# ── Entra role discovery — auto-expand $StandardRoles ────────────────────────
Write-Host ""
Write-Host "── PRE-FLIGHT: Entra role discovery ─────────────────" -ForegroundColor Cyan

try {
    $allTenantRoles = [System.Collections.Generic.List[string]]::new()
    $roleUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?`$select=displayName,isEnabled,isBuiltIn"
    do {
        $response = Invoke-MgGraphRequest -Method GET -Uri $roleUri -ErrorAction Stop
        foreach ($role in $response.value) {
            if ($role.isEnabled -eq $true -and $role.isBuiltIn -eq $true) {
                $allTenantRoles.Add($role.displayName)
            }
        }
        $roleUri = $response.'@odata.nextLink'
    } while ($roleUri)

    # Build a set of all roles already explicitly managed
    $managedRoles = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $StandardRoles)   { [void] $managedRoles.Add($r) }
    foreach ($r in $PrivilegedRoles) { [void] $managedRoles.Add($r) }

    # Roles that should never receive a PIM activation policy — not admin roles
    $excludedFromPolicy = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    @(
        "User"
        "Guest User"
        "Restricted Guest User"
        "Device Join"
        "Device Users"
        "Device Managers"
        "Workplace Device Join"
        "Directory Synchronization Accounts"
        "On Premises Directory Sync Account"
        "Partner Tier1 Support"
        "Partner Tier2 Support"
    ) | ForEach-Object { [void] $excludedFromPolicy.Add($_) }

    # Find roles in the tenant not yet in either list and not excluded
    $newRoles = $allTenantRoles | Where-Object {
        -not $managedRoles.Contains($_) -and -not $excludedFromPolicy.Contains($_)
    } | Sort-Object

    if ($newRoles.Count -eq 0) {
        Write-PIMLog -Level OK -Phase "PRE-DISC" -Message "All $($allTenantRoles.Count) tenant roles are accounted for in the policy lists."
    } else {
        Write-PIMLog -Level INFO -Phase "PRE-DISC" -Message "Discovered $($newRoles.Count) role(s) not in policy lists — adding to standard policy scope:"
        foreach ($r in $newRoles) {
            Write-PIMLog -Level INFO -Phase "PRE-DISC" -Message "  + $r"
            $script:StandardRoles += $r
        }
        Write-PIMLog -Level OK -Phase "PRE-DISC" -Message "Standard role list expanded to $($script:StandardRoles.Count) roles for Phase 5."
    }

    # Filter $StandardRoles to only roles that actually exist in this tenant.
    # Prevents false ERRs in Phase 5 for preview/future roles in the static list.
    $tenantRoleSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $allTenantRoles) { [void] $tenantRoleSet.Add($r) }
    $removedCount = 0
    $script:StandardRoles = @($script:StandardRoles | Where-Object {
        if ($tenantRoleSet.Contains($_)) { $true } else { $removedCount++; $false }
    })
    if ($removedCount -gt 0) {
        Write-PIMLog -Level INFO -Phase "PRE-DISC" -Message "Removed $removedCount role(s) from standard list — not present in this tenant (preview/future roles)."
    }
} catch {
    Write-PIMLog -Level WARN -Phase "PRE-DISC" -Message "Could not fetch tenant role definitions — Phase 5 will use the static list only: $($_.Exception.Message)"
}

# ===========================================================================
# PRE-FLIGHT — Configuration validation
# ===========================================================================
Write-Host ""
Write-Host "── PRE-FLIGHT: Configuration validation ─────────────" -ForegroundColor Cyan

# Check 1: both approver group names must be present in $GroupConfigs
$configGroupNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($c in $GroupConfigs) { [void] $configGroupNames.Add($c.DisplayName) }

foreach ($approverName in @($ApproverGroupName_M365, $ApproverGroupName_Security)) {
    if ($configGroupNames.Contains($approverName)) {
        Write-PIMLog -Level OK -Phase "PRE-CFG" -Message "Approver group in GroupConfigs: $approverName"
    } else {
        Write-PIMLog -Level WARN -Phase "PRE-CFG" -Message "Approver group '$approverName' is NOT in GroupConfigs — Phase 1 will not create it and Phase 6 will be skipped entirely"
    }
}

# Check 2: PIM4Groups must have empty EligibleRoles (roles are active on the group; membership is eligible)
foreach ($c in $GroupConfigs | Where-Object { $_.PIM4Group -eq $true }) {
    if ($c.EligibleRoles -and $c.EligibleRoles.Count -gt 0) {
        Write-PIMLog -Level WARN -Phase "PRE-CFG" -Message "PIM4Group '$($c.DisplayName)' has EligibleRoles defined — this is likely a misconfiguration. Roles assigned to PIM4Groups should be ActiveRoles; membership eligibility is handled by PIM4Groups itself."
    } else {
        Write-PIMLog -Level OK -Phase "PRE-CFG" -Message "PIM4Group configuration OK: $($c.DisplayName)"
    }
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
    Write-PIMLog -Level OK -Phase "PRE-USR" -Message "All $($allConfiguredUsers.Count) configured users found in tenant."
} else {
    Write-PIMLog -Level WARN -Phase "PRE-USR" -Message "$($missingUsers.Count) of $($allConfiguredUsers.Count) users not found in tenant — they will be skipped in Phase 3."
    foreach ($missing in $missingUsers) {
        Write-PIMLog -Level WARN -Phase "PRE-USR" -Message "Not found: $missing"
    }
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
        $config['_IsNew']   = $false
        Write-PIMLog -Level OK -Phase "P1" -Message "Group exists: $groupName (Id: $($existing.Id))"

        # Check isAssignableToRole — cannot be changed after creation, warn if wrong
        if ($existing.IsAssignableToRole -ne $true) {
            Write-PIMLog -Level WARN -Phase "P1" -Message "Group '$groupName' is NOT role-assignable (isAssignableToRole = false). PIM role assignments will fail. The group must be deleted and recreated with isAssignableToRole = true."
        }

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
            $config['_IsNew']   = $false
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
                $config['_IsNew']   = $true
                Write-PIMLog -Level OK -Phase "P1" -Message "Created: $groupName (Id: $($newGroup.Id))"
                Write-PIMLog -Level INFO -Phase "P1" -Message "Waiting 22s for directory propagation after group creation..."
                Start-Sleep -Seconds 22
            } catch {
                $config['_GroupId'] = $null
                $config['_IsNew']   = $false
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

    # Note: Set-PIMGroupPolicy does not support -AuthenticationContext_Enabled — this is a
    # Microsoft API limitation. AuthContext enforcement is not available for group activation
    # policies (only for role policies in Phase 5/6). Step-up auth for EXOGSAIN group
    # membership activation relies solely on Justification+Ticketing requirements.
    if ($DryRun) {
        Write-PIMLog -Level INFO -Phase "P2" -Message "[DRY RUN] Would apply PIM group policy ($StandardActivationDuration, justification+ticket, permanent eligibility): $groupName"
    } else {
        try {
            $currentGroupPolicy = Get-PIMGroupPolicy -TenantID $TenantId -GroupID $groupId -Type "member" -ErrorAction SilentlyContinue

            if (-not $currentGroupPolicy) {
                Write-PIMLog -Level INFO -Phase "P2" -Message "Could not read current policy for '$groupName' — will apply"
                $groupPolicyOk = $false
            } else {
                $groupEnablementRules = ($currentGroupPolicy.EnablementRules -split ',').Trim()

                # Notification drift check — if EasyPIM exposes the properties, compare all three types
                $p2NotifOk = $true
                if ($currentGroupPolicy.PSObject.Properties['Notification_Activation_Alert']) {
                    $p2NotifOk = (
                        (Test-NotifConfig $currentGroupPolicy.Notification_Activation_Alert         $NotificationConfig) -and
                        (Test-NotifConfig $currentGroupPolicy.Notification_EligibleAssignment_Alert $NotificationConfig) -and
                        (Test-NotifConfig $currentGroupPolicy.Notification_ActiveAssignment_Alert   $NotificationConfig)
                    )
                }

                $groupPolicyOk = (
                    $currentGroupPolicy.ActivationDuration               -eq $StandardActivationDuration -and
                    $currentGroupPolicy.AllowPermanentEligibleAssignment  -eq $true  -and
                    $currentGroupPolicy.AllowPermanentActiveAssignment    -eq $true  -and
                    ($groupEnablementRules -contains 'Justification')               -and
                    ($groupEnablementRules -contains 'Ticketing')                   -and
                    $p2NotifOk
                )
            }

            if ($groupPolicyOk) {
                Write-PIMLog -Level OK -Phase "P2" -Message "Already configured: $groupName"
            } else {
                Write-PIMLog -Level INFO -Phase "P2" -Message "Applying PIM group policy: $groupName"
                if ($config['_IsNew']) {
                    Write-PIMLog -Level INFO -Phase "P2" -Message "New group — waiting 10s for policy API propagation..."
                    Start-Sleep -Seconds 10
                }

                Set-PIMGroupPolicy `
                    -TenantID                       $TenantId `
                    -GroupID                        $groupId `
                    -Type                           "member" `
                    -ActivationDuration             $StandardActivationDuration `
                    -ActivationRequirement          $ActivationRequirements `
                    -ActiveAssignmentRequirement    $ActiveAssignmentRequirements `
                    -AllowPermanentEligibility      $true `
                    -AllowPermanentActiveAssignment $true `
                    -Notification_EligibleAssignment_Alert $NotificationConfig `
                    -Notification_ActiveAssignment_Alert   $NotificationConfig `
                    -Notification_Activation_Alert         $NotificationConfig
                Write-PIMLog -Level OK -Phase "P2" -Message "PIM policy applied: $groupName"
            }
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

    # ── Drift removal + current state snapshot ───────────────────────────────
    $currentEligibleIds = [System.Collections.Generic.HashSet[string]]::new()
    $currentMemberIds   = [System.Collections.Generic.HashSet[string]]::new()

    if (-not $config.PIM4Group) {
        $currentMembers = Get-MgGroupMember -GroupId $groupId -All -ErrorAction SilentlyContinue

        foreach ($member in $currentMembers) {
            [void] $currentMemberIds.Add($member.Id)
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
        # PIM4Group: check for permanent active assignments — these bypass the eligible-only membership model.
        # Get-MgGroupMember is intentionally NOT used here because it also returns users who have a live
        # PIM activation session (time-limited active), and removing those would kick them out mid-session.
        # assignmentSchedules only contains explicit permanent/scheduled active assignments, not activations.
        try {
            $permActiveUri = "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentSchedules?`$filter=groupId eq '$groupId' and accessId eq 'member'"
            do {
                $resp = Invoke-MgGraphRequest -Method GET -Uri $permActiveUri -ErrorAction Stop
                foreach ($sched in $resp.value) {
                    # Resolve principal display name
                    $principalName = $sched.principalId
                    try {
                        $p = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/directoryObjects/$($sched.principalId)?`$select=displayName" -ErrorAction SilentlyContinue
                        if ($p.displayName) { $principalName = $p.displayName }
                    } catch {}

                    if ($DryRun) {
                        Write-PIMLog -Level WARN -Phase "P3" -Message "[DRY RUN] Permanent active member in PIM4Group '$groupName': $principalName — would remove (only eligible assignments are valid in PIM4Groups)"
                    } else {
                        try {
                            # Cancel the active assignment schedule via Graph
                            $cancelBody = @{ action = "adminRemove"; justification = $Justification; groupId = $groupId; principalId = $sched.principalId; accessId = "member" } | ConvertTo-Json -Compress
                            Invoke-WithRetry -Phase "P3" -Label "[PIM4G] cancel permanent active $principalName → $groupName" -ScriptBlock {
                                Invoke-MgGraphRequest -Method POST `
                                    -Uri "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleRequests" `
                                    -Body $cancelBody -ContentType "application/json" -ErrorAction Stop | Out-Null
                            }
                            Write-PIMLog -Level OK -Phase "P3" -Message "Removed permanent active member from PIM4Group: $principalName → $groupName"
                        } catch {
                            Write-PIMLog -Level ERR -Phase "P3" -Message "Failed to remove permanent active member '$principalName' from PIM4Group '$groupName': $($_.Exception.Message)"
                        }
                    }
                }
                $permActiveUri = $resp.'@odata.nextLink'
            } while ($permActiveUri)
        } catch {
            Write-PIMLog -Level WARN -Phase "P3" -Message "Could not check permanent active assignments for PIM4Group '$groupName': $($_.Exception.Message)"
        }

        # PIM4Group: fetch current eligible members for both drift removal and skip-check
        $currentEligible = Get-PIMGroupEligibleAssignment -TenantID $TenantId -GroupID $groupId -Type "member" -ErrorAction SilentlyContinue

        foreach ($assignment in $currentEligible) {
            # Only treat as "already correctly assigned" if permanent
            $isPermanent = [string]::IsNullOrEmpty($assignment.endDateTime)
            if ($isPermanent) {
                [void] $currentEligibleIds.Add($assignment.principalid)
            } else {
                if ($expectedIds.Contains($assignment.principalid)) {
                    Write-PIMLog -Level WARN -Phase "P3" -Message "Eligible assignment for '$($assignment.principalName)' → '$groupName' is time-limited (expires: $($assignment.endDateTime)) — removing to re-assign as permanent"
                    if (-not $DryRun) {
                        try {
                            Invoke-WithRetry -Phase "P3" -Label "[PIM4G] remove timed $($assignment.principalName) → $groupName" -ScriptBlock {
                                Remove-PIMGroupEligibleAssignment -TenantID $TenantId -GroupID $groupId -PrincipalID $assignment.principalid -Type "member" -Justification $Justification -ErrorAction Stop
                            }
                            Write-PIMLog -Level INFO -Phase "P3" -Message "Removed time-limited eligible assignment: $($assignment.principalName) → $groupName"
                        } catch {
                            Write-PIMLog -Level WARN -Phase "P3" -Message "Could not remove time-limited assignment for '$($assignment.principalName)': $($_.Exception.Message)"
                        }
                    }
                }
            }

            if (-not $expectedIds.Contains($assignment.principalid)) {
                $principalDisplay = $assignment.principalName
                if ($DryRun) {
                    Write-PIMLog -Level INFO -Phase "P3" -Message "[DRY RUN] Would remove unexpected eligible member: $principalDisplay → $groupName"
                } else {
                    try {
                        Invoke-WithRetry -Phase "P3" -Label "[PIM4G] remove unexpected $principalDisplay → $groupName" -ScriptBlock {
                            Remove-PIMGroupEligibleAssignment -TenantID $TenantId -GroupID $groupId -PrincipalID $assignment.principalid -Type "member" -Justification $Justification -ErrorAction Stop
                        }
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
            Write-PIMLog -Level WARN -Phase "P3" -Message "User not found: '$displayName' (group: $groupName) — skipped (flagged in PRE-USR)"
            continue
        }

        if ($config.PIM4Group) {
            # PIM4Groups: add as eligible member via EasyPIM
            if ($DryRun) {
                Write-PIMLog -Level INFO -Phase "P3" -Message "[DRY RUN] Would assign eligible member: $displayName → $groupName"
            } elseif ($currentEligibleIds.Contains($userObj.Id)) {
                Write-PIMLog -Level OK -Phase "P3" -Message "Already eligible: $displayName → $groupName"
            } else {
                try {
                    Invoke-WithRetry -Phase "P3" -Label "[PIM4G] assign eligible $displayName → $groupName" -ScriptBlock {
                        New-PIMGroupEligibleAssignment `
                            -TenantID      $TenantId `
                            -GroupID       $groupId `
                            -PrincipalID   $userObj.Id `
                            -Type          "member" `
                            -Justification $Justification `
                            -Permanent | Out-Null
                    }
                    Write-PIMLog -Level OK -Phase "P3" -Message "Eligible member assigned: $displayName → $groupName"
                } catch {
                    if ($_.Exception.Message -match "already|BadRequest") {
                        Write-PIMLog -Level OK -Phase "P3" -Message "Already eligible: $displayName → $groupName"
                    } else {
                        Write-PIMLog -Level ERR -Phase "P3" -Message "Failed eligible assignment '$displayName' → '$groupName': $($_.Exception.Message)"
                    }
                }
            }
        } else {
            # Regular group: add as direct member
            if ($DryRun) {
                if ($currentMemberIds.Contains($userObj.Id)) {
                    Write-PIMLog -Level OK   -Phase "P3" -Message "Already member: $displayName → $groupName"
                } else {
                    Write-PIMLog -Level INFO -Phase "P3" -Message "[DRY RUN] Would add member: $displayName → $groupName"
                }
            } elseif ($currentMemberIds.Contains($userObj.Id)) {
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

# ===========================================================================
# PHASE 4 — Assign roles to groups
# ===========================================================================
Write-Host ""
Write-Host "── PHASE 4: Group Role Assignments ──────────────────" -ForegroundColor Cyan

$p4Total = $GroupConfigs.Count
$p4Index = 0

foreach ($config in $GroupConfigs) {
    $p4Index++
    $p4Progress = "[$p4Index/$p4Total]"
    $groupName = $config.DisplayName
    $groupId   = $config['_GroupId']

    if (-not $groupId) {
        Write-PIMLog -Level WARN -Phase "P4" -Message "$p4Progress Skipping '$groupName' — no group Id"
        continue
    }

    Write-PIMLog -Level INFO -Phase "P4" -Message "$p4Progress Processing role assignments for: $groupName"

    # Fetch current role assignments upfront — always run (needed for DryRun reporting too)
    # Only add to "already assigned" sets if the assignment is permanent (noExpiration)
    $assignedEligibleRoles = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $assignedActiveRoles   = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $timedEligibleRoles    = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $timedActiveRoles      = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    try {
        $eligUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?`$filter=principalId eq '$groupId'&`$expand=roleDefinition(`$select=displayName)"
        do {
            $resp = Invoke-MgGraphRequest -Method GET -Uri $eligUri -ErrorAction Stop
            foreach ($inst in $resp.value) {
                $expType = $inst.scheduleInfo.expiration.type
                if ($expType -eq 'noExpiration' -or [string]::IsNullOrEmpty($expType)) {
                    [void] $assignedEligibleRoles.Add($inst.roleDefinition.displayName)
                } else {
                    [void] $timedEligibleRoles.Add($inst.roleDefinition.displayName)
                    Write-PIMLog -Level WARN -Phase "P4" -Message "$p4Progress [Eligible] Time-limited assignment detected: $($inst.roleDefinition.displayName) → $groupName (expires: $($inst.scheduleInfo.expiration.endDateTime))"
                }
            }
            $eligUri = $resp.'@odata.nextLink'
        } while ($eligUri)
    } catch {
        Write-PIMLog -Level WARN -Phase "P4" -Message "$p4Progress Could not fetch current eligible assignments for '$groupName' — will attempt all assignments: $($_.Exception.Message)"
    }

    try {
        $actUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?`$filter=principalId eq '$groupId'&`$expand=roleDefinition(`$select=displayName)"
        do {
            $resp = Invoke-MgGraphRequest -Method GET -Uri $actUri -ErrorAction Stop
            foreach ($inst in $resp.value) {
                $expType = $inst.scheduleInfo.expiration.type
                if ($expType -eq 'noExpiration' -or [string]::IsNullOrEmpty($expType)) {
                    [void] $assignedActiveRoles.Add($inst.roleDefinition.displayName)
                } else {
                    [void] $timedActiveRoles.Add($inst.roleDefinition.displayName)
                    Write-PIMLog -Level WARN -Phase "P4" -Message "$p4Progress [Active  ] Time-limited assignment detected: $($inst.roleDefinition.displayName) → $groupName (expires: $($inst.scheduleInfo.expiration.endDateTime))"
                }
            }
            $actUri = $resp.'@odata.nextLink'
        } while ($actUri)
    } catch {
        Write-PIMLog -Level WARN -Phase "P4" -Message "$p4Progress Could not fetch current active assignments for '$groupName' — will attempt all assignments: $($_.Exception.Message)"
    }

    # Build config sets here — used both for correction below and drift removal further down
    $configActiveSet   = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $configEligibleSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $config.ActiveRoles)   { [void] $configActiveSet.Add($r) }
    foreach ($r in $config.EligibleRoles) { [void] $configEligibleSet.Add($r) }

    # ── Correct time-limited in-config assignments ────────────────────────────
    # Explicitly remove them so the loops below can re-create them as permanent.
    foreach ($role in @($timedEligibleRoles)) {
        if ($configEligibleSet.Contains($role)) {
            if ($DryRun) {
                Write-PIMLog -Level INFO -Phase "P4" -Message "$p4Progress [DRY RUN] Would remove time-limited [Eligible] $role → $groupName (to re-assign as permanent)"
            } else {
                try {
                    Invoke-WithRetry -Phase "P4" -Label "[Eligible] remove timed $role → $groupName" -ScriptBlock {
                        Remove-PIMEntraRoleEligibleAssignment -TenantID $TenantId -RoleName $role -PrincipalID $groupId -Justification $Justification -ErrorAction Stop | Out-Null
                    }
                    Write-PIMLog -Level INFO -Phase "P4" -Message "$p4Progress [Eligible] Removed time-limited assignment: $role → $groupName"
                    Start-Sleep -Seconds 2
                } catch {
                    Write-PIMLog -Level WARN -Phase "P4" -Message "$p4Progress [Eligible] Could not remove time-limited '$role' → '$groupName': $($_.Exception.Message)"
                }
            }
        }
    }
    foreach ($role in @($timedActiveRoles)) {
        if ($configActiveSet.Contains($role)) {
            if ($DryRun) {
                Write-PIMLog -Level INFO -Phase "P4" -Message "$p4Progress [DRY RUN] Would remove time-limited [Active  ] $role → $groupName (to re-assign as permanent)"
            } else {
                try {
                    Invoke-WithRetry -Phase "P4" -Label "[Active] remove timed $role → $groupName" -ScriptBlock {
                        Remove-PIMEntraRoleActiveAssignment -TenantID $TenantId -RoleName $role -PrincipalID $groupId -Justification $Justification -ErrorAction Stop | Out-Null
                    }
                    Write-PIMLog -Level INFO -Phase "P4" -Message "$p4Progress [Active  ] Removed time-limited assignment: $role → $groupName"
                    Start-Sleep -Seconds 2
                } catch {
                    Write-PIMLog -Level WARN -Phase "P4" -Message "$p4Progress [Active  ] Could not remove time-limited '$role' → '$groupName': $($_.Exception.Message)"
                }
            }
        }
    }

    foreach ($role in $config.ActiveRoles) {
        if ($DryRun) {
            if ($assignedActiveRoles.Contains($role)) {
                Write-PIMLog -Level OK   -Phase "P4" -Message "$p4Progress [Active  ] Already assigned: $role → $groupName"
            } else {
                Write-PIMLog -Level INFO -Phase "P4" -Message "$p4Progress [DRY RUN] Would assign [Active  ] $role → $groupName"
            }
        } elseif ($assignedActiveRoles.Contains($role)) {
            Write-PIMLog -Level OK -Phase "P4" -Message "$p4Progress [Active  ] Already assigned: $role → $groupName"
        } else {
            try {
                Invoke-WithRetry -Phase "P4" -Label "[Active] $role → $groupName" -ScriptBlock {
                    New-PIMEntraRoleActiveAssignment `
                        -TenantID      $TenantId `
                        -RoleName      $role `
                        -PrincipalID   $groupId `
                        -Justification $Justification `
                        -Permanent | Out-Null
                }
                Write-PIMLog -Level OK -Phase "P4" -Message "$p4Progress [Active  ] $role → $groupName"
            } catch {
                if ($_.Exception.Message -match "already|BadRequest") {
                    Write-PIMLog -Level OK -Phase "P4" -Message "$p4Progress [Active  ] Already assigned: $role → $groupName"
                } else {
                    Write-PIMLog -Level ERR -Phase "P4" -Message "$p4Progress [Active  ] Failed '$role' → '$groupName': $($_.Exception.Message)"
                }
            }
            Start-Sleep -Seconds 2
        }
    }

    foreach ($role in $config.EligibleRoles) {
        if ($DryRun) {
            if ($assignedEligibleRoles.Contains($role)) {
                Write-PIMLog -Level OK   -Phase "P4" -Message "$p4Progress [Eligible] Already assigned: $role → $groupName"
            } else {
                Write-PIMLog -Level INFO -Phase "P4" -Message "$p4Progress [DRY RUN] Would assign [Eligible] $role → $groupName"
            }
        } elseif ($assignedEligibleRoles.Contains($role)) {
            Write-PIMLog -Level OK -Phase "P4" -Message "$p4Progress [Eligible] Already assigned: $role → $groupName"
        } else {
            try {
                Invoke-WithRetry -Phase "P4" -Label "[Eligible] $role → $groupName" -ScriptBlock {
                    New-PIMEntraRoleEligibleAssignment `
                        -TenantID      $TenantId `
                        -RoleName      $role `
                        -PrincipalID   $groupId `
                        -Justification $Justification `
                        -Permanent | Out-Null
                }
                Write-PIMLog -Level OK -Phase "P4" -Message "$p4Progress [Eligible] $role → $groupName"
            } catch {
                if ($_.Exception.Message -match "already|BadRequest") {
                    Write-PIMLog -Level OK -Phase "P4" -Message "$p4Progress [Eligible] Already assigned: $role → $groupName"
                } else {
                    Write-PIMLog -Level ERR -Phase "P4" -Message "$p4Progress [Eligible] Failed '$role' → '$groupName': $($_.Exception.Message)"
                }
            }
            Start-Sleep -Seconds 2
        }
    }

    # ── Role drift removal ────────────────────────────────────────────────────

    foreach ($role in @($assignedActiveRoles)) {
        if (-not $configActiveSet.Contains($role)) {
            if ($DryRun) {
                Write-PIMLog -Level INFO -Phase "P4" -Message "$p4Progress [DRY RUN] Would remove [Active  ] $role ← $groupName (no longer in config)"
            } else {
                try {
                    Invoke-WithRetry -Phase "P4" -Label "[Active] drift remove $role ← $groupName" -ScriptBlock {
                        Remove-PIMEntraRoleActiveAssignment -TenantID $TenantId -RoleName $role -PrincipalID $groupId -Justification $Justification -ErrorAction Stop | Out-Null
                    }
                    Write-PIMLog -Level OK -Phase "P4" -Message "$p4Progress [Active  ] Removed drift: $role ← $groupName"
                } catch {
                    Write-PIMLog -Level ERR -Phase "P4" -Message "$p4Progress [Active  ] Failed to remove '$role' ← '$groupName': $($_.Exception.Message)"
                }
                Start-Sleep -Seconds 2
            }
        }
    }

    foreach ($role in @($assignedEligibleRoles)) {
        if (-not $configEligibleSet.Contains($role)) {
            if ($DryRun) {
                Write-PIMLog -Level INFO -Phase "P4" -Message "$p4Progress [DRY RUN] Would remove [Eligible] $role ← $groupName (no longer in config)"
            } else {
                try {
                    Invoke-WithRetry -Phase "P4" -Label "[Eligible] drift remove $role ← $groupName" -ScriptBlock {
                        Remove-PIMEntraRoleEligibleAssignment -TenantID $TenantId -RoleName $role -PrincipalID $groupId -Justification $Justification -ErrorAction Stop | Out-Null
                    }
                    Write-PIMLog -Level OK -Phase "P4" -Message "$p4Progress [Eligible] Removed drift: $role ← $groupName"
                } catch {
                    Write-PIMLog -Level ERR -Phase "P4" -Message "$p4Progress [Eligible] Failed to remove '$role' ← '$groupName': $($_.Exception.Message)"
                }
                Start-Sleep -Seconds 2
            }
        }
    }
}

# ===========================================================================
# PHASE 5 — Standard PIM role policies (no approval)
# ===========================================================================
Write-Host ""
Write-Host "── PHASE 5: Standard Role Policies ──────────────────" -ForegroundColor Cyan
$p5Total = $script:StandardRoles.Count
$p5Index = 0
Write-PIMLog -Level INFO -Phase "P5" -Message "Applying standard policy to $p5Total roles..."

foreach ($role in $script:StandardRoles) {
    $p5Index++
    $p5Progress = "[$p5Index/$p5Total]"
    if ($DryRun) {
        Write-PIMLog -Level INFO -Phase "P5" -Message "$p5Progress [DRY RUN] Would apply standard policy: $role"
    } else {
        try {
            $currentPolicy = Get-PIMEntraRolePolicy -TenantID $TenantId -RoleName $role -ErrorAction SilentlyContinue

            if (-not $currentPolicy) {
                Write-PIMLog -Level INFO -Phase "P5" -Message "$p5Progress Policy read returned null for '$role' — will apply"
                $alreadyConfigured = $false
            } else {
                $p5EnablementRules  = ($currentPolicy.EnablementRules -split ',').Trim()

                # Notification drift check
                $p5NotifOk = $true
                if ($currentPolicy.PSObject.Properties['Notification_Activation_Alert']) {
                    $p5NotifOk = (
                        (Test-NotifConfig $currentPolicy.Notification_Activation_Alert         $NotificationConfig) -and
                        (Test-NotifConfig $currentPolicy.Notification_EligibleAssignment_Alert $NotificationConfig) -and
                        (Test-NotifConfig $currentPolicy.Notification_ActiveAssignment_Alert   $NotificationConfig)
                    )
                }

                $alreadyConfigured = (
                    $currentPolicy.ActivationDuration              -eq $StandardActivationDuration -and
                    $currentPolicy.AllowPermanentEligibleAssignment -eq $true                      -and
                    $currentPolicy.AllowPermanentActiveAssignment   -eq $true                      -and
                    $currentPolicy.AuthenticationContext_Enabled   -eq $true                       -and
                    $currentPolicy.AuthenticationContext_Value     -eq $AuthContextId              -and
                    $currentPolicy.ApprovalRequired                -eq $false                      -and
                    ($p5EnablementRules -contains 'Justification')                                 -and
                    ($p5EnablementRules -contains 'Ticketing')                                     -and
                    $p5NotifOk
                )
            }

            if ($alreadyConfigured) {
                Write-PIMLog -Level OK -Phase "P5" -Message "$p5Progress Already configured: $role"
            } else {
                Invoke-WithRetry -Phase "P5" -Label $role -ScriptBlock {
                    Set-PIMEntraRolePolicy -TenantId $TenantId -RoleName $role `
                        -ActivationRequirement          $ActivationRequirements `
                        -ActiveAssignmentRequirement    $ActiveAssignmentRequirements `
                        -ActivationDuration             $StandardActivationDuration `
                        -AllowPermanentEligibility      $true `
                        -AllowPermanentActiveAssignment $true `
                        -AuthenticationContext_Enabled  $true `
                        -AuthenticationContext_Value    $AuthContextId `
                        -Notification_EligibleAssignment_Alert $NotificationConfig `
                        -Notification_ActiveAssignment_Alert   $NotificationConfig `
                        -Notification_Activation_Alert         $NotificationConfig
                    Write-PIMLog -Level OK -Phase "P5" -Message "$p5Progress Policy applied: $role"
                }
            }
        } catch {
            Write-PIMLog -Level ERR -Phase "P5" -Message "$p5Progress Failed '$role': $($_.Exception.Message)"
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
            Write-PIMLog -Level INFO -Phase "P6" -Message "[DRY RUN] Would apply privileged policy ($PrivilegedActivationDuration, approval required): $role"
        } else {
            try {
                $currentPolicy = Get-PIMEntraRolePolicy -TenantID $TenantId -RoleName $role -ErrorAction SilentlyContinue

                if (-not $currentPolicy) {
                    Write-PIMLog -Level INFO -Phase "P6" -Message "Policy read returned null for '$role' — will apply"
                    $alreadyConfigured = $false
                } else {
                    $p6EnablementRules  = ($currentPolicy.EnablementRules -split ',').Trim()

                    # Check approver drift — verify both expected groups are still in the policy
                    $approversOk = $false
                    if ($currentPolicy.PSObject.Properties['Approvers'] -and $currentPolicy.Approvers) {
                        $currentApproverIds = @($currentPolicy.Approvers | ForEach-Object { $_.Id })
                        $approversOk = ($currentApproverIds -contains $approverGroup_M365.Id) -and
                                       ($currentApproverIds -contains $approverGroup_Security.Id)
                    }
                    # If EasyPIM doesn't expose Approvers, force re-apply — safer than silently skipping

                    # Notification drift check
                    $p6NotifOk = $true
                    if ($currentPolicy.PSObject.Properties['Notification_Activation_Alert']) {
                        $p6NotifOk = (
                            (Test-NotifConfig $currentPolicy.Notification_Activation_Alert         $NotificationConfig) -and
                            (Test-NotifConfig $currentPolicy.Notification_EligibleAssignment_Alert $NotificationConfig) -and
                            (Test-NotifConfig $currentPolicy.Notification_ActiveAssignment_Alert   $NotificationConfig)
                        )
                    }

                    $alreadyConfigured = (
                        $currentPolicy.AllowPermanentEligibleAssignment -eq $true                        -and
                        $currentPolicy.AllowPermanentActiveAssignment   -eq $true                        -and
                        $currentPolicy.AuthenticationContext_Enabled    -eq $true                        -and
                        $currentPolicy.AuthenticationContext_Value      -eq $AuthContextId               -and
                        $currentPolicy.ApprovalRequired                 -eq $true                        -and
                        $currentPolicy.ActivationDuration               -eq $PrivilegedActivationDuration -and
                        ($p6EnablementRules -contains 'Justification')                                   -and
                        ($p6EnablementRules -contains 'Ticketing')                                       -and
                        $approversOk                                                                     -and
                        $p6NotifOk
                    )
                }

                if ($alreadyConfigured) {
                    Write-PIMLog -Level OK -Phase "P6" -Message "Already configured: $role"
                } else {
                    Invoke-WithRetry -Phase "P6" -Label $role -ScriptBlock {
                        Set-PIMEntraRolePolicy -TenantId $TenantId -RoleName $role `
                            -ActivationRequirement          $ActivationRequirements `
                            -ActiveAssignmentRequirement    $ActiveAssignmentRequirements `
                            -ActivationDuration             $PrivilegedActivationDuration `
                            -AllowPermanentEligibility      $true `
                            -AllowPermanentActiveAssignment $true `
                            -AuthenticationContext_Enabled  $true `
                            -AuthenticationContext_Value    $AuthContextId `
                            -ApprovalRequired               $true `
                            -Approvers                      $Approvers `
                            -Notification_EligibleAssignment_Alert $NotificationConfig `
                            -Notification_ActiveAssignment_Alert   $NotificationConfig `
                            -Notification_Activation_Alert         $NotificationConfig
                        Write-PIMLog -Level OK -Phase "P6" -Message "Policy applied: $role"
                    }
                }
            } catch {
                Write-PIMLog -Level ERR -Phase "P6" -Message "Failed '$role': $($_.Exception.Message)"
            }
        }
    }
} elseif ($DryRun) {
    Write-PIMLog -Level INFO -Phase "P6" -Message "[DRY RUN] Approver groups would be created in Phase 1 — enumerating privileged role policies:"
    foreach ($role in $PrivilegedRoles) {
        Write-PIMLog -Level INFO -Phase "P6" -Message "[DRY RUN] Would apply privileged policy ($PrivilegedActivationDuration, approval required, approvers: $ApproverGroupName_M365 + $ApproverGroupName_Security): $role"
    }
} else {
    Write-PIMLog -Level WARN -Phase "P6" -Message "Phase 6 skipped — one or both approver groups could not be resolved."
}

# ===========================================================================
# PHASE 7 — Direct role assignment audit (non-group, non-PIM)
# ===========================================================================
Write-Host ""
Write-Host "── PHASE 7: Direct Assignment Audit ─────────────────" -ForegroundColor Cyan
Write-PIMLog -Level INFO -Phase "P7" -Message "Scanning for direct role assignments to users, service principals, and unmanaged groups..."

# Build set of group IDs managed by this script — used to suppress expected assignments
$managedGroupIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($config in $GroupConfigs) {
    if ($config['_GroupId'] -and $config['_GroupId'] -ne '[DRY-RUN-ID]') {
        [void] $managedGroupIds.Add($config['_GroupId'])
    }
}

try {
    # ── Step 1: Build role definition map (id → name) ─────────────────────────
    Write-PIMLog -Level INFO -Phase "P7" -Message "Step 1/5 — Building role definition map..."
    $roleDefMap = @{}
    $rdUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?`$select=id,displayName"
    do {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $rdUri -ErrorAction Stop
        foreach ($rd in $resp.value) { $roleDefMap[$rd.id] = $rd.displayName }
        $rdUri = $resp.'@odata.nextLink'
    } while ($rdUri)

    # ── Step 2: Fetch permanent direct assignments (non-PIM) ──────────────────
    Write-PIMLog -Level INFO -Phase "P7" -Message "Step 2/5 — Fetching permanent (non-PIM) role assignments..."
    $rawAssignments = [System.Collections.Generic.List[PSCustomObject]]::new()
    $permUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$select=principalId,roleDefinitionId"
    do {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $permUri -ErrorAction Stop
        foreach ($a in $resp.value) {
            $rawAssignments.Add([PSCustomObject]@{ PrincipalId = $a.principalId; RoleDefinitionId = $a.roleDefinitionId; AssignmentType = "Permanent (non-PIM)" })
        }
        $permUri = $resp.'@odata.nextLink'
    } while ($permUri)

    # ── Step 3: Fetch PIM active direct assignments (memberType = Direct) ─────
    Write-PIMLog -Level INFO -Phase "P7" -Message "Step 3/5 — Fetching PIM active and eligible direct assignments..."
    $pimUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?`$select=principalId,roleDefinitionId,memberType"
    do {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $pimUri -ErrorAction Stop
        foreach ($a in $resp.value | Where-Object { $_.memberType -eq 'Direct' }) {
            $rawAssignments.Add([PSCustomObject]@{ PrincipalId = $a.principalId; RoleDefinitionId = $a.roleDefinitionId; AssignmentType = "PIM Active (Direct)" })
        }
        $pimUri = $resp.'@odata.nextLink'
    } while ($pimUri)

    # ── Step 3b: Fetch PIM eligible direct assignments ────────────────────────
    $eligUri2 = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?`$select=principalId,roleDefinitionId,memberType"
    do {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $eligUri2 -ErrorAction Stop
        foreach ($a in $resp.value | Where-Object { $_.memberType -eq 'Direct' }) {
            $rawAssignments.Add([PSCustomObject]@{ PrincipalId = $a.principalId; RoleDefinitionId = $a.roleDefinitionId; AssignmentType = "PIM Eligible (Direct)" })
        }
        $eligUri2 = $resp.'@odata.nextLink'
    } while ($eligUri2)

    # ── Step 4: Deduplicate ───────────────────────────────────────────────────
    # Steps 2+3 (Permanent/PIM Active) dedup by PrincipalId+RoleId — the same PIM-active
    # assignment can appear in both /roleAssignments and /roleAssignmentScheduleInstances.
    # Step 3b (PIM Eligible) uses its own set so an eligible assignment for the same
    # role/principal still surfaces alongside any active one as a separate finding.
    $seenActiveKeys   = [System.Collections.Generic.HashSet[string]]::new()
    $seenEligibleKeys = [System.Collections.Generic.HashSet[string]]::new()
    $uniqueAssignments = $rawAssignments | Where-Object {
        if ($_.AssignmentType -eq "PIM Eligible (Direct)") {
            $seenEligibleKeys.Add("$($_.PrincipalId)_$($_.RoleDefinitionId)")
        } else {
            $seenActiveKeys.Add("$($_.PrincipalId)_$($_.RoleDefinitionId)")
        }
    }

    # ── Step 5: Resolve principals in batch (users, service principals, groups) ─
    $principalIds  = @($uniqueAssignments | Select-Object -ExpandProperty PrincipalId -Unique)
    Write-PIMLog -Level INFO -Phase "P7" -Message "Step 4/5 — Resolving $($principalIds.Count) unique principals..."
    $principalMap  = @{}
    $batchSize     = 1000
    for ($i = 0; $i -lt $principalIds.Count; $i += $batchSize) {
        $batch = $principalIds[$i..([Math]::Min($i + $batchSize - 1, $principalIds.Count - 1))]
        $body  = @{ ids = $batch; types = @("user", "servicePrincipal", "group") } | ConvertTo-Json -Compress
        $resolved = $null
        Invoke-WithRetry -Phase "P7" -Label "resolve principals batch $([Math]::Floor($i / $batchSize) + 1)" -ScriptBlock {
            $script:p7BatchResult = Invoke-MgGraphRequest -Method POST `
                -Uri "https://graph.microsoft.com/v1.0/directoryObjects/getByIds" `
                -Body $body -ContentType "application/json" -ErrorAction Stop
        }
        $resolved = $script:p7BatchResult
        foreach ($obj in $resolved.value) {
            $principalMap[$obj.id] = [PSCustomObject]@{
                DisplayName = $obj.displayName
                UPN         = if ($obj.userPrincipalName) { $obj.userPrincipalName } else { "N/A" }
                Type        = switch ($obj.'@odata.type') {
                    '#microsoft.graph.user'             { "User" }
                    '#microsoft.graph.servicePrincipal' { "Service Principal" }
                    '#microsoft.graph.group'            { "Group" }
                    default                             { "Unknown" }
                }
                IsGroup     = ($obj.'@odata.type' -eq '#microsoft.graph.group')
                Id          = $obj.id
            }
        }
    }

    # ── Step 6: Build audit list — users, SPs, and unmanaged groups ───────────
    $auditList = $uniqueAssignments | ForEach-Object {
        $principal = $principalMap[$_.PrincipalId]
        if (-not $principal) { return }
        # Suppress groups that are managed by this script — their assignments are expected
        if ($principal.IsGroup -and $managedGroupIds.Contains($principal.Id)) { return }
        [PSCustomObject]@{
            RoleName           = if ($roleDefMap[$_.RoleDefinitionId]) { $roleDefMap[$_.RoleDefinitionId] } else { $_.RoleDefinitionId }
            PrincipalType      = $principal.Type
            DisplayName        = $principal.DisplayName
            UserPrincipalName  = $principal.UPN
            AssignmentType     = $_.AssignmentType
            RequiredCorrection = if ($principal.IsGroup) {
                "Unmanaged group with direct role assignment — add to GroupConfigs or remove"
            } elseif ($principal.Type -eq "Service Principal") {
                "Review SP role assignment — service principals cannot join PIM groups; consider a managed identity or scoped app registration instead"
            } else {
                "Remove direct assignment — reassign via PIM group"
            }
        }
    } | Where-Object { $_ }

    # ── Step 7: Report ────────────────────────────────────────────────────────
    Write-PIMLog -Level INFO -Phase "P7" -Message "Step 5/5 — Reporting $($auditList.Count) finding(s)..."
    if ($auditList.Count -eq 0) {
        Write-PIMLog -Level OK -Phase "P7" -Message "No direct user/SP/unmanaged-group role assignments found — all roles are properly managed."
    } else {
        Write-PIMLog -Level WARN -Phase "P7" -Message "$($auditList.Count) direct assignment(s) found — see CSV for required corrections."
        Write-Host ""

        foreach ($group in ($auditList | Group-Object RoleName | Sort-Object Name)) {
            Write-Host "  $($group.Name)" -ForegroundColor Yellow
            foreach ($row in $group.Group) {
                Write-Host "    ├ [$($row.PrincipalType)] $($row.DisplayName) ($($row.UserPrincipalName))  [$($row.AssignmentType)]" -ForegroundColor White
            }
        }
        Write-Host ""

        if ($transcriptFolder) {
            $csvFile = Join-Path $transcriptFolder ("OnboardingPIM_DirectAssignments_{0}.csv" -f $script:RunTimestamp)
            try {
                # Write UTF-8 with BOM so Excel opens the file without garbling special characters
                $csv = $auditList | ConvertTo-Csv -NoTypeInformation
                [System.IO.File]::WriteAllLines($csvFile, $csv, [System.Text.UTF8Encoding]::new($true))
                Write-PIMLog -Level OK -Phase "P7" -Message "CSV exported: $csvFile"
            } catch {
                Write-PIMLog -Level WARN -Phase "P7" -Message "Could not export CSV: $($_.Exception.Message)"
            }
        } else {
            Write-PIMLog -Level WARN -Phase "P7" -Message "No writable folder available — CSV not exported."
        }
    }
} catch {
    Write-PIMLog -Level WARN -Phase "P7" -Message "Could not complete direct assignment audit: $($_.Exception.Message)"
}

# ── Step 8: Discover unmanaged PIM4Groups ────────────────────────────────────
Write-Host ""
Write-PIMLog -Level INFO -Phase "P7" -Message "Scanning for PIM4Groups not in the authorization matrix..."

$managedPIM4Ids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($config in $GroupConfigs | Where-Object { $_.PIM4Group -eq $true }) {
    if ($config['_GroupId'] -and $config['_GroupId'] -ne '[DRY-RUN-ID]') {
        [void] $managedPIM4Ids.Add($config['_GroupId'])
    }
}

try {
    $seenPIM4Ids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $pgUri = "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$select=groupId"
    do {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $pgUri -ErrorAction Stop
        foreach ($sched in $resp.value) { [void] $seenPIM4Ids.Add($sched.groupId) }
        $pgUri = $resp.'@odata.nextLink'
    } while ($pgUri)

    $unknownPIM4List = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($gid in $seenPIM4Ids) {
        if ($managedPIM4Ids.Contains($gid)) { continue }
        $groupName    = "(unresolved)"
        $groupDesc    = "N/A"
        $groupDeleted = $false
        try {
            $groupResp = Invoke-MgGraphRequest -Method GET `
                -Uri "https://graph.microsoft.com/v1.0/groups/$gid`?`$select=displayName,description" `
                -ErrorAction Stop
            if ($groupResp.displayName) { $groupName = $groupResp.displayName }
            if ($groupResp.description) { $groupDesc  = $groupResp.description  }
        } catch {
            if ($_.Exception.Message -match "404|NotFound|Not Found|ResourceNotFound") {
                # Group object is gone — PIM4Groups configurations for deleted groups can linger
                # in Entra for up to 24 hours before they are automatically cleaned up.
                $groupName    = "(deleted group)"
                $groupDesc    = "Group no longer exists — PIM4Groups config will auto-clean within 24h."
                $groupDeleted = $true
            }
        }
        $unknownPIM4List.Add([PSCustomObject]@{
            GroupId     = $gid
            DisplayName = $groupName
            Description = $groupDesc
            Finding     = if ($groupDeleted) {
                "Recently deleted group — PIM4Groups configuration is pending auto-cleanup (up to 24h). No action needed."
            } else {
                "PIM4Group not in authorization matrix — review and add to GroupConfigs or remove"
            }
        })
    }

    $deletedPIM4Count   = ($unknownPIM4List | Where-Object { $_.DisplayName -eq "(deleted group)" }).Count
    $unmanagedPIM4Count = $unknownPIM4List.Count - $deletedPIM4Count

    if ($unknownPIM4List.Count -eq 0) {
        Write-PIMLog -Level OK -Phase "P7" -Message "No unmanaged PIM4Groups found — all PIM for Groups configurations are in the authorization matrix."
    } else {
        if ($unmanagedPIM4Count -gt 0) {
            Write-PIMLog -Level WARN -Phase "P7" -Message "$unmanagedPIM4Count unmanaged PIM4Group(s) found — not in authorization matrix (action required)."
        }
        if ($deletedPIM4Count -gt 0) {
            Write-PIMLog -Level INFO -Phase "P7" -Message "$deletedPIM4Count deleted PIM4Group(s) still visible — pending auto-cleanup within 24h (no action needed)."
        }
        Write-Host ""
        foreach ($entry in $unknownPIM4List) {
            Write-Host "  $($entry.DisplayName)  (Id: $($entry.GroupId))" -ForegroundColor Yellow
            if ($entry.Description -ne "N/A") {
                Write-Host "    $($entry.Description)" -ForegroundColor DarkGray
            }
        }
        Write-Host ""

        if ($transcriptFolder) {
            $pim4CsvFile = Join-Path $transcriptFolder ("OnboardingPIM_UnmanagedPIM4Groups_{0}.csv" -f $script:RunTimestamp)
            try {
                $csv = $unknownPIM4List | ConvertTo-Csv -NoTypeInformation
                [System.IO.File]::WriteAllLines($pim4CsvFile, $csv, [System.Text.UTF8Encoding]::new($true))
                Write-PIMLog -Level OK -Phase "P7" -Message "Unmanaged PIM4Groups CSV exported: $pim4CsvFile"
            } catch {
                Write-PIMLog -Level WARN -Phase "P7" -Message "Could not export PIM4Groups CSV: $($_.Exception.Message)"
            }
        }
    }
} catch {
    Write-PIMLog -Level WARN -Phase "P7" -Message "Could not scan for unmanaged PIM4Groups: $($_.Exception.Message)"
}

# =====================
# Disconnect
# =====================
try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch {}

# ===========================================================================
# PHASE 8 — Summary report
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
        "PRE-PERM" { "Pre-flight — Permission Validation    " }
        "PRE-CA"   { "Pre-flight — Auth Context & CA        " }
        "PRE-LIC"  { "Pre-flight — License Validation       " }
        "PRE-DISC" { "Pre-flight — Role Discovery           " }
        "PRE-CFG"  { "Pre-flight — Configuration Validation " }
        "PRE-USR"  { "Pre-flight — User Existence Check     " }
        "P1"       { "Phase 1 — Group Provisioning          " }
        "P2"       { "Phase 2 — PIM Group Policies          " }
        "P3"       { "Phase 3 — Group Membership            " }
        "P4"       { "Phase 4 — Group Role Assignments      " }
        "P5"       { "Phase 5 — Standard Role Policies      " }
        "P6"       { "Phase 6 — Privileged Role Policies    " }
        "P7"       { "Phase 7 — Direct Assignment Audit     " }
        default    { $phase }
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

} finally {
    # Always stop the transcript — runs on normal exit, errors, and Ctrl+C
    if ($transcriptFile) {
        Write-Host "Transcript saved to: $transcriptFile" -ForegroundColor DarkGray
        try { Stop-Transcript -ErrorAction SilentlyContinue } catch {}
    }
}
