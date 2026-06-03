<#
.SYNOPSIS
    Creates a new regular user account in the configured Entra ID tenant.

.DESCRIPTION
    Connects to the tenant configured in the configuration section using certificate-based
    authentication and creates a new user with the properties defined below.
    A random 16-character password (uppercase, lowercase, digits) is generated
    and displayed in the console after account creation — no password is stored
    in the script.

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
# Account configuration
# =====================
$FirstName       = "Jane"
$LastName        = "Doe"
$Department      = "HR"
$JobTitle        = "Consultant"
$EmployeeHireDate = "2026-01-01T00:00:00Z"   # yyyy-mm-ddT00:00:00Z
$EmployeeID      = "Z000000"                  # e.g. Z00001
$UPN             = "j.doe@contoso.com"         # userPrincipalName

$City            = "Amsterdam"
$OfficeLocation  = "Office Building A"
$Country         = "Netherlands"
$CompanyName     = "Contoso"
$PostalCode      = "1000 AA"
$State           = "Noord-Holland"
$StreetAddress   = "Keizersgracht 1"
$EmployeeType    = "Medewerker"
$UsageLocation   = "NL"
$BusinessPhones  = [string[]]@("020 000 00 00")
$PasswordPolicies = "DisablePasswordExpiration"

# =====================
# Password generation (16 chars: uppercase + lowercase + digits, no special chars)
# =====================
function New-RandomPassword {
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    do {
        $generatedPwd = -join ((1..16) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
        $hasUpper  = $generatedPwd -cmatch '[A-Z]'
        $hasLower  = $generatedPwd -cmatch '[a-z]'
        $hasDigit  = $generatedPwd -match '[0-9]'
    } until ($hasUpper -and $hasLower -and $hasDigit)
    return $generatedPwd
}

$Password = New-RandomPassword

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
Write-Host "=== Create New Regular Account ===" -ForegroundColor Cyan
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
# Create user
# =====================
Write-Host ""
Write-Host "Creating user: $FirstName $LastName ($UPN)" -ForegroundColor Cyan

$params = @{
    accountEnabled    = $true
    givenName         = $FirstName
    surname           = $LastName
    displayName       = "$FirstName $LastName"
    userPrincipalName = $UPN
    mailNickname      = $EmployeeID
    department        = $Department
    jobTitle          = $JobTitle
    companyName       = $CompanyName
    employeeId        = $EmployeeID
    employeeType      = $EmployeeType
    employeeHireDate  = $EmployeeHireDate
    city              = $City
    officeLocation    = $OfficeLocation
    country           = $Country
    postalCode        = $PostalCode
    state             = $State
    streetAddress     = $StreetAddress
    businessPhones    = $BusinessPhones
    usageLocation     = $UsageLocation
    passwordPolicies  = $PasswordPolicies
    passwordProfile   = @{
        password                     = $Password
        forceChangePasswordNextSignIn = $true
    }
}

try {
    $user = New-MgUser -BodyParameter $params -ErrorAction Stop
    Write-Host "User created successfully." -ForegroundColor Green
    Write-Host "  Id  : $($user.Id)" -ForegroundColor Green
    Write-Host "  UPN : $($user.UserPrincipalName)" -ForegroundColor Green
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "  Temporary password: $Password" -ForegroundColor Yellow
    Write-Host "  (user must change on first sign-in)  " -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow
} catch {
    Write-Host "Failed to create user: $_" -ForegroundColor Red
}

# =====================
# Disconnect
# =====================
try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch {}

Write-Host ""
Write-Host "Done!" -ForegroundColor Green
Write-Host ""
