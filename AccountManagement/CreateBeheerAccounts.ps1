<#
.SYNOPSIS
    Mass-creates all beheer (admin) accounts defined in the PIM authorization matrix.

.DESCRIPTION
    Creates all beheer accounts referenced in OnboardingPIM.ps1, grouped by department.
    Each account is created with a random 16-character temporary password that must be
    changed on first sign-in. A full summary including all generated passwords is printed
    at the end — passwords are never stored in the script or on disk.

    The script is idempotent — accounts that already exist (matched by UPN) are detected
    and skipped without error.

    ── ACCOUNT CONVENTIONS ───────────────────────────────────────────────────────
    • UPN format   : b.[firstname].[lastname_last_word]@psbv.org
    • DisplayName  : Beheer [FirstName] [LastName]
    • EmployeeID   : B000001 … B000062
    • JobTitle     : Beheerder
    • EmployeeType : Beheerder
    ──────────────────────────────────────────────────────────────────────────────

.NOTES
    Author      : Melih Sivrikaya
    Permissions : User.ReadWrite.All (application permission — grant admin consent)
    Auth        : Certificate-based (app registration: AccountManagement)
    Requires    : Microsoft.Graph.Authentication, Microsoft.Graph.Users
#>

#Requires -Version 5.1

param (
    [switch] $DryRun
)

# =====================
# Tenant configuration
# =====================
$TenantId              = "58288310-2b28-42b6-883b-dcef687a4e29"
$AppId                 = "458e6a44-9f42-43fd-aea7-e5dacde156c8"
$CertificateThumbprint = "692D02E8823BDDAC78EFAD7ADB8EE49EC09EE54C"

# =====================
# Shared account properties
# =====================
$CompanyName      = "PSBV"
$City             = "Zwolle"
$Country          = "Netherlands"
$State            = "Overijssel"
$PostalCode       = "8000 AA"
$StreetAddress    = "Schuurmanstraat 4"
$OfficeLocation   = "Hoofdkantoor"
$UsageLocation    = "NL"
$EmployeeType     = "Beheerder"
$JobTitle         = "Beheerder"
$PasswordPolicies = "DisablePasswordExpiration"
$EmployeeHireDate = "2026-06-02T00:00:00Z"
$Domain           = "psbv.org"

# =====================
# Beheer accounts
# =====================
# Each entry: FirstName, LastName (full, incl. tussenvoegsel), UPNPrefix, Department, EmployeeID
$BeheerAccounts = @(

    # ── M365 HP ───────────────────────────────────────────────────────────────
    @{ FirstName = "Daan";    LastName = "van den Berg"; UPNPrefix = "b.daan.berg";      Department = "M365"; EmployeeID = "B000001" }
    @{ FirstName = "Lotte";   LastName = "Vermeer";      UPNPrefix = "b.lotte.vermeer";  Department = "M365"; EmployeeID = "B000002" }
    @{ FirstName = "Sander";  LastName = "Hoekstra";     UPNPrefix = "b.sander.hoekstra";Department = "M365"; EmployeeID = "B000003" }
    @{ FirstName = "Inge";    LastName = "de Vries";     UPNPrefix = "b.inge.vries";     Department = "M365"; EmployeeID = "B000004" }

    # ── M365 ──────────────────────────────────────────────────────────────────
    @{ FirstName = "Joost";   LastName = "Bakker";       UPNPrefix = "b.joost.bakker";   Department = "M365";    EmployeeID = "B000005" }
    @{ FirstName = "Miriam";  LastName = "Janssen";      UPNPrefix = "b.miriam.janssen"; Department = "M365";    EmployeeID = "B000006" }
    @{ FirstName = "Thijs";   LastName = "Willems";      UPNPrefix = "b.thijs.willems";  Department = "M365";    EmployeeID = "B000007" }
    @{ FirstName = "Fleur";   LastName = "Smits";        UPNPrefix = "b.fleur.smits";    Department = "M365";    EmployeeID = "B000008" }
    @{ FirstName = "Bram";    LastName = "Kuiper";       UPNPrefix = "b.bram.kuiper";    Department = "M365";    EmployeeID = "B000009" }
    @{ FirstName = "Noor";    LastName = "van Dijk";     UPNPrefix = "b.noor.dijk";      Department = "M365";    EmployeeID = "B000010" }
    @{ FirstName = "Lars";    LastName = "Hendriks";     UPNPrefix = "b.lars.hendriks";  Department = "M365";    EmployeeID = "B000011" }
    @{ FirstName = "Eva";     LastName = "Mulder";       UPNPrefix = "b.eva.mulder";     Department = "M365";    EmployeeID = "B000012" }
    @{ FirstName = "Tim";     LastName = "Visser";       UPNPrefix = "b.tim.visser";     Department = "M365";    EmployeeID = "B000013" }
    @{ FirstName = "Rosa";    LastName = "de Boer";      UPNPrefix = "b.rosa.boer";      Department = "M365";    EmployeeID = "B000014" }
    @{ FirstName = "Koen";    LastName = "Peters";       UPNPrefix = "b.koen.peters";    Department = "M365";    EmployeeID = "B000015" }

    # ── Security (OSO) ────────────────────────────────────────────────────────
    @{ FirstName = "Ruben";   LastName = "Schouten";     UPNPrefix = "b.ruben.schouten"; Department = "Security";               EmployeeID = "B000016" }
    @{ FirstName = "Anke";    LastName = "Brouwer";      UPNPrefix = "b.anke.brouwer";   Department = "Security";               EmployeeID = "B000017" }
    @{ FirstName = "Pieter";  LastName = "Dekker";       UPNPrefix = "b.pieter.dekker";  Department = "Security";               EmployeeID = "B000018" }

    # ── Security (TISO) ───────────────────────────────────────────────────────
    @{ FirstName = "Femke";   LastName = "Linders";      UPNPrefix = "b.femke.linders";  Department = "Security";               EmployeeID = "B000019" }
    @{ FirstName = "Maarten"; LastName = "van Vliet";    UPNPrefix = "b.maarten.vliet";  Department = "Security";               EmployeeID = "B000020" }

    # ── Architectuur ─────────────────────────────────────────────────────────
    @{ FirstName = "Wouter";  LastName = "Claassen";     UPNPrefix = "b.wouter.claassen";Department = "Architectuur";           EmployeeID = "B000021" }
    @{ FirstName = "Anouk";   LastName = "Bergman";      UPNPrefix = "b.anouk.bergman";  Department = "Architectuur";           EmployeeID = "B000022" }
    @{ FirstName = "Stefan";  LastName = "Prins";        UPNPrefix = "b.stefan.prins";   Department = "Architectuur";           EmployeeID = "B000023" }
    @{ FirstName = "Ingrid";  LastName = "Vos";          UPNPrefix = "b.ingrid.vos";     Department = "Architectuur";           EmployeeID = "B000024" }

    # ── Dataplatform ─────────────────────────────────────────────────────────
    @{ FirstName = "Niels";   LastName = "van Rooij";    UPNPrefix = "b.niels.rooij";    Department = "Dataplatform";           EmployeeID = "B000025" }
    @{ FirstName = "Sophie";  LastName = "de Groot";     UPNPrefix = "b.sophie.groot";   Department = "Dataplatform";           EmployeeID = "B000026" }
    @{ FirstName = "Bart";    LastName = "Kuipers";      UPNPrefix = "b.bart.kuipers";   Department = "Dataplatform";           EmployeeID = "B000027" }
    @{ FirstName = "Hanna";   LastName = "Wijnen";       UPNPrefix = "b.hanna.wijnen";   Department = "Dataplatform";           EmployeeID = "B000028" }
    @{ FirstName = "Jeroen";  LastName = "Oosterhout";   UPNPrefix = "b.jeroen.oosterhout"; Department = "Dataplatform";        EmployeeID = "B000029" }
    @{ FirstName = "Lisa";    LastName = "van den Heuvel";UPNPrefix = "b.lisa.heuvel";   Department = "Dataplatform";           EmployeeID = "B000030" }

    # ── IAM / Saviynt ─────────────────────────────────────────────────────────
    @{ FirstName = "Mark";    LastName = "Timmers";      UPNPrefix = "b.mark.timmers";   Department = "IAM";                    EmployeeID = "B000031" }

    # ── Servicedesk/Local Support & Local Support ─────────────────────────────────────────
    @{ FirstName = "Tom";     LastName = "van der Wal";  UPNPrefix = "b.tom.wal";           Department = "Servicedesk/Local Support"; EmployeeID = "B000036" }
    @{ FirstName = "Nathalie";LastName = "Dijkstra";     UPNPrefix = "b.nathalie.dijkstra"; Department = "Servicedesk/Local Support"; EmployeeID = "B000037" }
    @{ FirstName = "Kevin";   LastName = "Meijer";       UPNPrefix = "b.kevin.meijer";      Department = "Servicedesk/Local Support"; EmployeeID = "B000038" }
    @{ FirstName = "Esther";  LastName = "Bogaard";      UPNPrefix = "b.esther.bogaard";    Department = "Servicedesk/Local Support"; EmployeeID = "B000039" }
    @{ FirstName = "Rick";    LastName = "Scholten";     UPNPrefix = "b.rick.scholten";     Department = "Servicedesk/Local Support"; EmployeeID = "B000040" }
    @{ FirstName = "Chantal"; LastName = "van Ee";       UPNPrefix = "b.chantal.ee";        Department = "Servicedesk/Local Support"; EmployeeID = "B000041" }
    @{ FirstName = "Marco";   LastName = "Brink";        UPNPrefix = "b.marco.brink";       Department = "Servicedesk/Local Support"; EmployeeID = "B000042" }
    @{ FirstName = "Sandra";  LastName = "Koops";        UPNPrefix = "b.sandra.koops";      Department = "Servicedesk/Local Support"; EmployeeID = "B000043" }
    @{ FirstName = "Bas";     LastName = "Lammers";      UPNPrefix = "b.bas.lammers";       Department = "Servicedesk/Local Support"; EmployeeID = "B000044" }
    @{ FirstName = "Joyce";   LastName = "Smeets";       UPNPrefix = "b.joyce.smeets";      Department = "Servicedesk/Local Support"; EmployeeID = "B000045" }
    @{ FirstName = "Patrick"; LastName = "van Heijst";   UPNPrefix = "b.patrick.heijst";    Department = "Servicedesk/Local Support"; EmployeeID = "B000046" }
    @{ FirstName = "Leonie";  LastName = "Verhoeven";    UPNPrefix = "b.leonie.verhoeven";  Department = "Servicedesk/Local Support"; EmployeeID = "B000047" }
    @{ FirstName = "Dennis";  LastName = "Hooijmans";    UPNPrefix = "b.dennis.hooijmans";  Department = "Servicedesk/Local Support"; EmployeeID = "B000048" }
    @{ FirstName = "Manon";   LastName = "de Haan";      UPNPrefix = "b.manon.haan";        Department = "Servicedesk/Local Support"; EmployeeID = "B000049" }
    @{ FirstName = "Wesley";  LastName = "Kusters";      UPNPrefix = "b.wesley.kusters";    Department = "Servicedesk/Local Support"; EmployeeID = "B000050" }
    @{ FirstName = "Iris";    LastName = "van der Plas"; UPNPrefix = "b.iris.plas";         Department = "Servicedesk/Local Support"; EmployeeID = "B000051" }
    @{ FirstName = "Frank";   LastName = "Nieuwenhuis";  UPNPrefix = "b.frank.nieuwenhuis"; Department = "Servicedesk/Local Support"; EmployeeID = "B000052" }
    @{ FirstName = "Tamara";  LastName = "Ooms";         UPNPrefix = "b.tamara.ooms";       Department = "Servicedesk/Local Support"; EmployeeID = "B000053" }
    @{ FirstName = "Jens";    LastName = "Roosen";       UPNPrefix = "b.jens.roosen";       Department = "Servicedesk/Local Support"; EmployeeID = "B000054" }
    @{ FirstName = "Petra";   LastName = "Vermeulen";    UPNPrefix = "b.petra.vermeulen";   Department = "Servicedesk/Local Support"; EmployeeID = "B000055" }
    @{ FirstName = "Quinten"; LastName = "van Beek";     UPNPrefix = "b.quinten.beek";      Department = "Servicedesk/Local Support"; EmployeeID = "B000056" }
    @{ FirstName = "Nadia";   LastName = "Willemsen";    UPNPrefix = "b.nadia.willemsen";   Department = "Servicedesk/Local Support"; EmployeeID = "B000057" }
    @{ FirstName = "Guus";    LastName = "Steenbakkers"; UPNPrefix = "b.guus.steenbakkers"; Department = "Servicedesk/Local Support"; EmployeeID = "B000058" }
    @{ FirstName = "Amber";   LastName = "Theunissen";   UPNPrefix = "b.amber.theunissen";  Department = "Servicedesk/Local Support"; EmployeeID = "B000059" }
    @{ FirstName = "Ronnie";  LastName = "van Galen";    UPNPrefix = "b.ronnie.galen";      Department = "Servicedesk/Local Support"; EmployeeID = "B000060" }

    # ── Cloud ────────────────────────────────────────────────────────
    @{ FirstName = "Dylan";   LastName = "van Leeuwen";  UPNPrefix = "b.dylan.leeuwen";  Department = "Cloud";         EmployeeID = "B000032" }
    @{ FirstName = "Roos";    LastName = "Hartman";      UPNPrefix = "b.roos.hartman";   Department = "Cloud";         EmployeeID = "B000033" }
    @{ FirstName = "Stijn";   LastName = "Bosman";       UPNPrefix = "b.stijn.bosman";   Department = "Cloud";         EmployeeID = "B000034" }
    @{ FirstName = "Vera";    LastName = "Jacobs";       UPNPrefix = "b.vera.jacobs";    Department = "Cloud";         EmployeeID = "B000035" }

    # ── Functioneel Beheer ────────────────────────────────────────────────────
    @{ FirstName = "Cas";     LastName = "Vrijhof";      UPNPrefix = "b.cas.vrijhof";    Department = "Functioneel Beheer"; EmployeeID = "B000061" }
    @{ FirstName = "Judith";  LastName = "Manders";      UPNPrefix = "b.judith.manders"; Department = "Functioneel Beheer"; EmployeeID = "B000062" }
)

# ===========================================================================
# SCRIPT INTERNALS — do not edit below this line
# ===========================================================================

# ── Logging ──────────────────────────────────────────────────────────────────
$script:Log = [System.Collections.Generic.List[PSCustomObject]]::new()

function Write-BeheerLog {
    param (
        [ValidateSet("INFO","OK","WARN","ERR")] [string] $Level,
        [string] $Message
    )
    $entry = [PSCustomObject]@{
        Time    = (Get-Date -Format "HH:mm:ss")
        Level   = $Level
        Message = $Message
    }
    $script:Log.Add($entry)

    $color = switch ($Level) {
        "INFO" { "Cyan"   }
        "OK"   { "Green"  }
        "WARN" { "Yellow" }
        "ERR"  { "Red"    }
    }
    $prefix = switch ($Level) {
        "INFO" { "  ····" }
        "OK"   { "  OK  " }
        "WARN" { "  WARN" }
        "ERR"  { "  ERR " }
    }
    Write-Host "$($entry.Time) $prefix $Message" -ForegroundColor $color
}

# ── Password generator ───────────────────────────────────────────────────────
function New-RandomPassword {
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    do {
        $generatedPwd = -join ((1..16) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
        $hasUpper     = $generatedPwd -cmatch '[A-Z]'
        $hasLower     = $generatedPwd -cmatch '[a-z]'
        $hasDigit     = $generatedPwd -match '[0-9]'
    } until ($hasUpper -and $hasLower -and $hasDigit)
    return $generatedPwd
}

# ── Banner ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║       Beheer Accounts — Mass Create Script       ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

if ($DryRun) {
    Write-Host "╔══════════════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "║  DRY RUN — no changes will be made to the tenant ║" -ForegroundColor Yellow
    Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Yellow
    Write-Host ""
}

# ── Module check ─────────────────────────────────────────────────────────────
Write-Host "Checking modules..." -ForegroundColor Cyan
foreach ($module in @("Microsoft.Graph.Authentication", "Microsoft.Graph.Users")) {
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

# ── Create accounts ───────────────────────────────────────────────────────────
Write-Host ""
Write-Host "── Creating beheer accounts ($($BeheerAccounts.Count) total) ──────────────" -ForegroundColor Cyan
Write-Host ""

$script:PasswordSummary = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($account in $BeheerAccounts) {
    $displayName = "Beheer $($account.FirstName) $($account.LastName)"
    $upn         = "$($account.UPNPrefix)@$Domain"

    # Check if user already exists
    $existing = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction SilentlyContinue |
        Select-Object -First 1

    if ($existing) {
        Write-BeheerLog -Level OK -Message "Already exists: $displayName ($upn)"
        $script:PasswordSummary.Add([PSCustomObject]@{
            DisplayName = $displayName
            UPN         = $upn
            Department  = $account.Department
            EmployeeID  = $account.EmployeeID
            Password    = "(existing account)"
            Status      = "Skipped"
        })
        continue
    }

    $password = New-RandomPassword

    if ($DryRun) {
        Write-BeheerLog -Level INFO -Message "[DRY RUN] Would create: $displayName ($upn) | Dept: $($account.Department)"
        $script:PasswordSummary.Add([PSCustomObject]@{
            DisplayName = $displayName
            UPN         = $upn
            Department  = $account.Department
            EmployeeID  = $account.EmployeeID
            Password    = "(dry run)"
            Status      = "DryRun"
        })
        continue
    }

    $params = @{
        accountEnabled    = $true
        givenName         = $account.FirstName
        surname           = $account.LastName
        displayName       = $displayName
        userPrincipalName = $upn
        mailNickname      = $account.EmployeeID
        department        = $account.Department
        jobTitle          = $JobTitle
        companyName       = $CompanyName
        employeeId        = $account.EmployeeID
        employeeType      = $EmployeeType
        employeeHireDate  = $EmployeeHireDate
        city              = $City
        officeLocation    = $OfficeLocation
        country           = $Country
        postalCode        = $PostalCode
        state             = $State
        streetAddress     = $StreetAddress
        usageLocation     = $UsageLocation
        passwordPolicies  = $PasswordPolicies
        passwordProfile   = @{
            password                      = $password
            forceChangePasswordNextSignIn = $true
        }
    }

    try {
        New-MgUser -BodyParameter $params -ErrorAction Stop | Out-Null
        Write-BeheerLog -Level OK -Message "Created: $displayName ($upn)"
        $script:PasswordSummary.Add([PSCustomObject]@{
            DisplayName = $displayName
            UPN         = $upn
            Department  = $account.Department
            EmployeeID  = $account.EmployeeID
            Password    = $password
            Status      = "Created"
        })
    } catch {
        Write-BeheerLog -Level ERR -Message "Failed to create '$displayName' ($upn): $($_.Exception.Message)"
        $script:PasswordSummary.Add([PSCustomObject]@{
            DisplayName = $displayName
            UPN         = $upn
            Department  = $account.Department
            EmployeeID  = $account.EmployeeID
            Password    = "(error)"
            Status      = "Failed"
        })
    }
}

# ── Disconnect ────────────────────────────────────────────────────────────────
try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch {}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                  SUMMARY REPORT                  ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$created  = $script:PasswordSummary | Where-Object { $_.Status -eq "Created" }
$skipped  = $script:PasswordSummary | Where-Object { $_.Status -eq "Skipped" }
$failed   = $script:PasswordSummary | Where-Object { $_.Status -eq "Failed"  }
$dryrun   = $script:PasswordSummary | Where-Object { $_.Status -eq "DryRun"  }

Write-Host "  Total accounts : $($BeheerAccounts.Count)" -ForegroundColor Cyan
if ($DryRun) {
    Write-Host "  Would create   : $($dryrun.Count)" -ForegroundColor Yellow
} else {
    Write-Host "  Created        : $($created.Count)"  -ForegroundColor Green
    Write-Host "  Skipped        : $($skipped.Count)"  -ForegroundColor Cyan
    Write-Host "  Failed         : $($failed.Count)"   -ForegroundColor $(if ($failed.Count -gt 0) { "Red" } else { "Green" })
}
Write-Host ""

if ($created.Count -gt 0) {
    Write-Host "╔══════════════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "║           TEMPORARY PASSWORDS (one-time)         ║" -ForegroundColor Yellow
    Write-Host "║      User must change password on first login     ║" -ForegroundColor Yellow
    Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Yellow
    Write-Host ""
    foreach ($entry in $created) {
        Write-Host "  $($entry.UPN.PadRight(45)) $($entry.Password)" -ForegroundColor Yellow
    }
    Write-Host ""
}

if ($failed.Count -gt 0) {
    Write-Host "Failed accounts:" -ForegroundColor Red
    foreach ($entry in $failed) {
        Write-Host "  $($entry.UPN)" -ForegroundColor Red
    }
    Write-Host ""
    exit 1
}

Write-Host "Done!" -ForegroundColor Green
Write-Host ""
