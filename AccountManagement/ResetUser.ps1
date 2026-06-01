<#
.SYNOPSIS
    Interactive account recovery tool — password reset, auth method reset, TAP issuance, and session revocation.

.DESCRIPTION
    Interactive script for help desk use. Resolves a user by UPN or display name,
    then presents a menu to choose the recovery action:

      [1] Password reset only
          Generates a random temporary password and forces change on next sign-in.

      [2] Auth reset + TAP only
          Removes all authentication methods (except password) and issues a
          Temporary Access Pass so the user can re-register MFA.

      [3] Password reset + Auth reset + TAP
          Performs both of the above in sequence.

      [4] Revoke sessions only
          Invalidates all active sign-in sessions (refresh tokens) for the user.
          Forces re-authentication on next access.

    Methods removed during auth reset:
      • Microsoft Authenticator
      • FIDO2 security key
      • Phone (SMS / voice call)
      • Software OATH token
      • Windows Hello for Business
      • Email OTP
      • Existing Temporary Access Pass
      • Password — intentionally kept (cannot be removed via API)

.NOTES
    Author      : Melih Sivrikaya
    Permissions : User.ReadWrite.All, UserAuthenticationMethod.ReadWrite.All,
                  User-PasswordProfile.ReadWrite.All, User.RevokeSessions.All
                  (application permissions — grant admin consent)
    Auth        : Certificate-based (app registration: AccountManagement)
    Requires    : Microsoft.Graph.Authentication, Microsoft.Graph.Users,
                  Microsoft.Graph.Identity.SignIns
#>

#Requires -Version 5.1

# =====================
# Tenant configuration
# =====================
$TenantId              = "58288310-2b28-42b6-883b-dcef687a4e29"
$AppId                 = "458e6a44-9f42-43fd-aea7-e5dacde156c8"
$CertificateThumbprint = "692D02E8823BDDAC78EFAD7ADB8EE49EC09EE54C"

# =====================
# TAP configuration
# =====================
$TapLifetimeMinutes = 480    # 8 hours
$TapIsUsableOnce    = $true # $true = one-time use only; $false = reusable within lifetime

# ===========================================================================
# SCRIPT INTERNALS — do not edit below this line
# ===========================================================================

# Friendly display names per auth method type
$MethodLabels = @{
    "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod"  = "Microsoft Authenticator"
    "#microsoft.graph.fido2AuthenticationMethod"                   = "FIDO2 Security Key"
    "#microsoft.graph.phoneAuthenticationMethod"                   = "Phone (SMS / Voice)"
    "#microsoft.graph.softwareOathAuthenticationMethod"            = "Software OATH Token"
    "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod" = "Windows Hello for Business"
    "#microsoft.graph.emailAuthenticationMethod"                   = "Email OTP"
    "#microsoft.graph.temporaryAccessPassAuthenticationMethod"     = "Temporary Access Pass"
    "#microsoft.graph.passwordAuthenticationMethod"                = "Password"
}

# ── Helper: generate random password ─────────────────────────────────────────
function New-RandomPassword {
    $upper   = "ABCDEFGHJKLMNPQRSTUVWXYZ".ToCharArray()
    $lower   = "abcdefghjkmnpqrstuvwxyz".ToCharArray()
    $digits  = "23456789".ToCharArray()
    $special = "!@#$%^&*".ToCharArray()

    $chars = @(
        ($upper   | Get-Random -Count 3)
        ($lower   | Get-Random -Count 4)
        ($digits  | Get-Random -Count 3)
        ($special | Get-Random -Count 2)
    ) | ForEach-Object { $_ }

    return -join ($chars | Sort-Object { Get-Random })
}

# ── Helper: display result box ────────────────────────────────────────────────
function Write-ResultBox {
    param (
        [string]   $Title,
        [string[]] $Lines,
        [string]   $Color = "Green"
    )
    $width = 52
    $inner = $width - 4  # space between "║  " and "  ║"

    Write-Host ""
    Write-Host ("╔" + "═" * ($width - 2) + "╗") -ForegroundColor $Color
    Write-Host ("║  {0,-$inner}║" -f $Title) -ForegroundColor $Color
    Write-Host ("╠" + "═" * ($width - 2) + "╣") -ForegroundColor $Color
    Write-Host ("║" + " " * ($width - 2) + "║") -ForegroundColor $Color
    foreach ($line in $Lines) {
        Write-Host ("║  {0,-$inner}║" -f $line) -ForegroundColor $Color
    }
    Write-Host ("║" + " " * ($width - 2) + "║") -ForegroundColor $Color
    Write-Host ("╚" + "═" * ($width - 2) + "╝") -ForegroundColor $Color
}

# ─────────────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║          Account Recovery Tool                   ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ── Module check ─────────────────────────────────────────────────────────────
Write-Host "Checking modules..." -ForegroundColor Cyan
foreach ($module in @(
    "Microsoft.Graph.Authentication"
    "Microsoft.Graph.Users"
    "Microsoft.Graph.Identity.SignIns"
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

# ── Resolve user ──────────────────────────────────────────────────────────────
Write-Host ""
$userInput = Read-Host "Enter UPN or display name"
$safe      = $userInput -replace "'", "''"

$userObj = Get-MgUser -Filter "userPrincipalName eq '$safe'" -ConsistencyLevel eventual `
    -Property Id,DisplayName,UserPrincipalName -ErrorAction SilentlyContinue | Select-Object -First 1

if (-not $userObj) {
    $userObj = Get-MgUser -Filter "displayName eq '$safe'" -ConsistencyLevel eventual `
        -Property Id,DisplayName,UserPrincipalName -ErrorAction SilentlyContinue | Select-Object -First 1
}

if (-not $userObj) {
    Write-Host ""
    Write-Host "User not found: '$userInput'" -ForegroundColor Red
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch {}
    exit 1
}

Write-Host ""
Write-Host "  User  : $($userObj.DisplayName)" -ForegroundColor Green
Write-Host "  UPN   : $($userObj.UserPrincipalName)" -ForegroundColor Green
Write-Host "  ID    : $($userObj.Id)" -ForegroundColor Green

# ── Action menu ───────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "What would you like to do?" -ForegroundColor Cyan
Write-Host "  [1]  Password reset only" -ForegroundColor White
Write-Host "  [2]  Auth reset + TAP only" -ForegroundColor White
Write-Host "  [3]  Password reset + Auth reset + TAP" -ForegroundColor White
Write-Host "  [4]  Revoke sessions only" -ForegroundColor White
Write-Host ""

$choice = $null
while ($choice -notin @("1","2","3","4")) {
    $choice = Read-Host "Enter choice (1/2/3/4)"
}

$doPasswordReset  = $choice -in @("1","3")
$doAuthReset      = $choice -in @("2","3")
$doRevokeSession  = $choice -in @("4")

# ── List current auth methods (when auth reset is selected) ───────────────────
$removable = [System.Collections.Generic.List[PSCustomObject]]::new()

if ($doAuthReset) {
    Write-Host ""
    Write-Host "Current authentication methods:" -ForegroundColor Cyan

    $methods = Get-MgUserAuthenticationMethod -UserId $userObj.Id -ErrorAction SilentlyContinue

    if (-not $methods -or $methods.Count -eq 0) {
        Write-Host "  (none registered)" -ForegroundColor Yellow
    } else {
        foreach ($method in $methods) {
            $odataType  = $method.AdditionalProperties['@odata.type']
            $label      = if ($MethodLabels[$odataType]) { $MethodLabels[$odataType] } else { $odataType }
            $isPassword = $odataType -eq "#microsoft.graph.passwordAuthenticationMethod"

            if ($isPassword) {
                Write-Host "  [KEEP  ] $label" -ForegroundColor DarkGray
            } else {
                Write-Host "  [REMOVE] $label" -ForegroundColor Yellow
                $removable.Add([PSCustomObject]@{ Id = $method.Id; Type = $odataType; Label = $label })
            }
        }
    }
}

# ── Confirm ───────────────────────────────────────────────────────────────────
Write-Host ""
$summary = switch ($choice) {
    "1" { "Reset password for $($userObj.DisplayName)." }
    "2" { "Remove $($removable.Count) auth method(s) and issue a TAP for $($userObj.DisplayName)." }
    "3" { "Reset password, remove $($removable.Count) auth method(s), and issue a TAP for $($userObj.DisplayName)." }
    "4" { "Revoke all active sessions for $($userObj.DisplayName)." }
}
Write-Host $summary -ForegroundColor Yellow
Write-Host ""
$confirm = Read-Host "Type YES to continue"
if ($confirm -ne "YES") {
    Write-Host "Aborted." -ForegroundColor Red
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch {}
    exit 0
}

# ── Password reset ────────────────────────────────────────────────────────────
if ($doPasswordReset) {
    Write-Host ""
    Write-Host "Resetting password..." -ForegroundColor Cyan

    $newPassword = New-RandomPassword
    try {
        Update-MgUser -UserId $userObj.Id -PasswordProfile @{
            password                      = $newPassword
            forceChangePasswordNextSignIn = $true
        } -ErrorAction Stop

        Write-ResultBox -Title "PASSWORD RESET" -Lines @(
            "User     : $($userObj.DisplayName)"
            "Password : $newPassword"
            "Note     : Must change on next sign-in"
        ) -Color Green
    } catch {
        Write-Host "  Failed to reset password: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ── Auth reset ────────────────────────────────────────────────────────────────
if ($doAuthReset) {
    Write-Host ""
    Write-Host "Removing authentication methods..." -ForegroundColor Cyan

    if ($removable.Count -eq 0) {
        Write-Host "  No removable methods found." -ForegroundColor Yellow
    } else {
        foreach ($method in $removable) {
            try {
                switch ($method.Type) {
                    "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod" {
                        Remove-MgUserAuthenticationMicrosoftAuthenticatorMethod `
                            -UserId $userObj.Id `
                            -MicrosoftAuthenticatorAuthenticationMethodId $method.Id `
                            -ErrorAction Stop
                    }
                    "#microsoft.graph.fido2AuthenticationMethod" {
                        Remove-MgUserAuthenticationFido2Method `
                            -UserId $userObj.Id `
                            -Fido2AuthenticationMethodId $method.Id `
                            -ErrorAction Stop
                    }
                    "#microsoft.graph.phoneAuthenticationMethod" {
                        Remove-MgUserAuthenticationPhoneMethod `
                            -UserId $userObj.Id `
                            -PhoneAuthenticationMethodId $method.Id `
                            -ErrorAction Stop
                    }
                    "#microsoft.graph.softwareOathAuthenticationMethod" {
                        Remove-MgUserAuthenticationSoftwareOathMethod `
                            -UserId $userObj.Id `
                            -SoftwareOathAuthenticationMethodId $method.Id `
                            -ErrorAction Stop
                    }
                    "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod" {
                        Remove-MgUserAuthenticationWindowsHelloForBusinessMethod `
                            -UserId $userObj.Id `
                            -WindowsHelloForBusinessAuthenticationMethodId $method.Id `
                            -ErrorAction Stop
                    }
                    "#microsoft.graph.emailAuthenticationMethod" {
                        Remove-MgUserAuthenticationEmailMethod `
                            -UserId $userObj.Id `
                            -EmailAuthenticationMethodId $method.Id `
                            -ErrorAction Stop
                    }
                    "#microsoft.graph.temporaryAccessPassAuthenticationMethod" {
                        Remove-MgUserAuthenticationTemporaryAccessPassMethod `
                            -UserId $userObj.Id `
                            -TemporaryAccessPassAuthenticationMethodId $method.Id `
                            -ErrorAction Stop
                    }
                }
                Write-Host "  Removed: $($method.Label)" -ForegroundColor Green
            } catch {
                Write-Host "  Failed to remove $($method.Label): $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }

    # ── Create TAP ────────────────────────────────────────────────────────────
    Write-Host ""
    Write-Host "Creating Temporary Access Pass..." -ForegroundColor Cyan

    try {
        $tap = New-MgUserAuthenticationTemporaryAccessPassMethod `
            -UserId $userObj.Id `
            -BodyParameter @{
                startDateTime     = (Get-Date).ToUniversalTime().ToString("o")
                lifetimeInMinutes = $TapLifetimeMinutes
                isUsableOnce      = $TapIsUsableOnce
            } `
            -ErrorAction Stop

        $expiresAt = (Get-Date).AddMinutes($TapLifetimeMinutes).ToString("HH:mm")

        Write-ResultBox -Title "TEMPORARY ACCESS PASS" -Lines @(
            "User     : $($userObj.DisplayName)"
            "TAP      : $($tap.TemporaryAccessPass)"
            "Valid    : $TapLifetimeMinutes min (until ~$expiresAt today)"
            "Reuse    : $(if ($TapIsUsableOnce) { 'One-time use only' } else { 'Reusable within lifetime' })"
        ) -Color Green
    } catch {
        Write-Host "  Failed to create TAP: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ── Revoke sessions ───────────────────────────────────────────────────────────
if ($doRevokeSession) {
    Write-Host ""
    Write-Host "Revoking all active sessions..." -ForegroundColor Cyan

    try {
        Revoke-MgUserSignInSession -UserId $userObj.Id -ErrorAction Stop | Out-Null

        Write-ResultBox -Title "SESSIONS REVOKED" -Lines @(
            "User : $($userObj.DisplayName)"
            "All refresh tokens have been invalidated."
            "User must re-authenticate on next access."
        ) -Color Green
    } catch {
        Write-Host "  Failed to revoke sessions: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ── Disconnect ────────────────────────────────────────────────────────────────
try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch {}
Write-Host ""
