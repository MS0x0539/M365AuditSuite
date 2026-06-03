<#
.SYNOPSIS
    Updates properties of an existing Entra ID user account.

.DESCRIPTION
    Connects to the tenant configured in the configuration section using certificate-based
    authentication and updates the properties defined in the configuration section for the
    specified user. Comment out any property you do not want to change — only uncommented
    fields are sent to the API.

.NOTES
    Author      : Melih Sivrikaya
    Permissions : User.ReadWrite.All (application permission — grant admin consent)
    Auth        : Certificate-based (app registration: AccountManagement)
    Requires    : Microsoft.Graph PowerShell SDK
#>

# =====================
# Tenant configuration
# =====================
$TenantId              = "58288310-2b28-42b6-883b-dcef687a4e29"
$AppId                 = "458e6a44-9f42-43fd-aea7-e5dacde156c8"
$CertificateThumbprint = "692D02E8823BDDAC78EFAD7ADB8EE49EC09EE54C"

# =====================
# Target user
# =====================
# Use UPN (preferred) or display name
$TargetUser = "j.doe-a@contoso.com"

# =====================
# Properties to update
# Comment out any line you do not want to change
# =====================
$UpdateParams = @{
    # Identity
    DisplayName       = "Beheer Jane Doe"
    GivenName         = "Jane"
    Surname           = "Doe"
    UserPrincipalName = "j.doe-a@contoso.com"
    MailNickname      = "j.doe-a"

    # Job info
    JobTitle          = "Consultant"
    Department        = "IT"
    CompanyName       = "Contoso"
    EmployeeId        = "jdoe-a"
    EmployeeType      = "Administrator"
    EmployeeHireDate  = "2026-01-01T00:00:00Z"

    # Contact
    BusinessPhones    = [string[]]@("020 000 00 00")
    MobilePhone       = "06 000 00 00"

    # Address
    StreetAddress     = "Keizersgracht 1"
    City              = "Amsterdam"
    State             = "Noord-Holland"
    PostalCode        = "1000 AA"
    Country           = "Netherlands"

    # Settings
    OfficeLocation    = "Office Building A"
    UsageLocation     = "NL"
    AccountEnabled    = $true
    PasswordPolicies  = "DisablePasswordExpiration"
}

# =====================
# Module check
# =====================
foreach ($module in @("Microsoft.Graph.Authentication", "Microsoft.Graph.Users")) {
    try {
        Import-Module $module -ErrorAction Stop
    } catch {
        Write-Warning "Could not load '$module'. Ensure Microsoft.Graph is installed: Install-Module Microsoft.Graph -Scope CurrentUser"
        exit 1
    }
}

# =====================
# Connect
# =====================
Write-Host "=== Edit Account ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
try {
    Connect-MgGraph -TenantId $TenantId -AppId $AppId -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
    Write-Host "Connected." -ForegroundColor Green
} catch {
    Write-Host "Failed to connect: $_" -ForegroundColor Red
    exit 1
}

# =====================
# Resolve user
# =====================
Write-Host ""
Write-Host "Looking up user: $TargetUser" -ForegroundColor Cyan

$safe = $TargetUser -replace "'", "''"
$user = Get-MgUser -Filter "userPrincipalName eq '$safe'" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $user) {
    $user = Get-MgUser -Filter "displayName eq '$safe'" -ConsistencyLevel eventual -ErrorAction SilentlyContinue | Select-Object -First 1
}

if (-not $user) {
    Write-Host "User '$TargetUser' not found." -ForegroundColor Red
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch {}
    exit 1
}

Write-Host "Found: $($user.DisplayName) (Id: $($user.Id))" -ForegroundColor Green

# =====================
# Update user
# =====================
Write-Host "Applying updates..." -ForegroundColor Cyan
try {
    Update-MgUser -UserId $user.Id -BodyParameter $UpdateParams -ErrorAction Stop
    Write-Host "User updated successfully." -ForegroundColor Green
} catch {
    Write-Host "Failed to update user: $_" -ForegroundColor Red
}

# =====================
# Disconnect
# =====================
try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch {}

Write-Host ""
Write-Host "Done!" -ForegroundColor Green
Write-Host ""
