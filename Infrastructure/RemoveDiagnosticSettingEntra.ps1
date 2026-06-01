<#
.SYNOPSIS
    Removes the Contributor role on /providers/Microsoft.aadiam from a user.

.DESCRIPTION
    Checks whether a specified user holds the Azure RBAC Contributor role on the
    /providers/Microsoft.aadiam scope and removes it if found. Use this script to
    revoke diagnostic settings permissions after configuration is complete.
    Automatically installs the Az PowerShell module if not present.

.NOTES
    Author      : Melih Sivrikaya
    Permissions : Contributor on /providers/Microsoft.aadiam (Azure RBAC — assigned interactively)
    Auth        : Interactive (delegated) — prompts for sign-in via Connect-AzAccount
    Requires    : Az PowerShell module (installed automatically if missing)
    Prereq      : The executing account must have "Access management for Azure resources"
                  enabled in Entra ID (Entra ID > Properties). This setting can only be
                  toggled by a Global Administrator.
#>
Write-Host "=== Entra Diagnostic Settings - Remove Role Assignment ===" -ForegroundColor Cyan
Write-Host "This removes the Contributor role on /providers/Microsoft.aadiam"
Write-Host "Which is required to enable diagnostics monitoring on an Entra tenant."
Write-Host ""
Write-Host "IMPORTANT: Your account must have 'Access management for Azure resources' enabled." -ForegroundColor Yellow
Write-Host "This can be toggled in Entra ID > Properties by a Global Administrator." -ForegroundColor Yellow
Write-Host ""

$userAccount = Read-Host "User account (UPN)"
if ([string]::IsNullOrWhiteSpace($userAccount)) {
    Write-Host "User account cannot be empty." -ForegroundColor Red
    exit 1
}

# Check and install Az module
if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
    Write-Host ""
    Write-Host "Az module not found. Installing..." -ForegroundColor Yellow
    try {
        Install-Module -Name Az -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        Write-Host "Az module installed successfully." -ForegroundColor Green
    } catch {
        Write-Host "Failed to install Az module: $_" -ForegroundColor Red
        exit 1
    }
}

Import-Module Az.Accounts -ErrorAction Stop
Import-Module Az.Resources -ErrorAction Stop

# Connect
Write-Host ""
Write-Host "Connecting to Azure as $userAccount..." -ForegroundColor Cyan
try {
    Connect-AzAccount -AccountId $userAccount -AuthScope MicrosoftGraphEndpointResourceId -ErrorAction Stop
} catch {
    Write-Host "Failed to connect: $_" -ForegroundColor Red
    exit 1
}

# Check if assignment exists
Write-Host "Checking role assignment for $userAccount..." -ForegroundColor Cyan
$assignment = Get-AzRoleAssignment `
    -SignInName $userAccount `
    -Scope "/providers/Microsoft.aadiam" `
    -RoleDefinitionName "Contributor" `
    -ErrorAction SilentlyContinue

if (-not $assignment) {
    Write-Host ""
    Write-Host "No Contributor role assignment found for $userAccount on /providers/Microsoft.aadiam." -ForegroundColor Yellow
    exit 0
}

# Remove role
Write-Host "Removing Contributor role from $userAccount..." -ForegroundColor Cyan
try {
    Remove-AzRoleAssignment `
        -SignInName $userAccount `
        -Scope "/providers/Microsoft.aadiam" `
        -RoleDefinitionName "Contributor" `
        -ErrorAction Stop

    Write-Host ""
    Write-Host "Done!" -ForegroundColor Green
    Write-Host "  User  : $userAccount"
    Write-Host "  Scope : /providers/Microsoft.aadiam"
    Write-Host "  Role  : Contributor (removed)"
} catch {
    Write-Host "Failed to remove role: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
