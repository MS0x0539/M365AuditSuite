# M365AuditSuite

A collection of PowerShell scripts for Microsoft 365 / Entra ID administration, security auditing, PIM management, and account lifecycle automation.

**Author:** Melih Sivrikaya  
**Organization:** PSBV  
**Auth model:** Certificate-based app-only authentication throughout (except Infrastructure scripts which use interactive Azure login)

---

## Folder structure

```
M365AuditSuite/
├── AccountManagement/
├── Audit/
├── EasyPIM/
├── GroupManagement/
└── Infrastructure/
```

---

## AccountManagement

All scripts in this folder use the **AccountManagement** app registration with certificate-based authentication.

### CreateNewAccount.ps1
Creates a new regular user account in Entra ID. Fills all standard user properties (name, department, job title, address, phone, usage location, etc.). Generates a random 16-character temporary password (upper + lower + digits) and prints it to the console. The user must change it on first sign-in.

**Permissions:** `User.ReadWrite.All`

### DeleteAccount.ps1
Removes one or more accounts safely:
1. Removes the user from all non-dynamic groups
2. Removes all directly assigned active Entra ID roles
3. Removes all PIM eligible role assignments
4. Waits 20 seconds for propagation, then deletes the account

Accepts UPN or display name. Supports a list of users.

**Permissions:** `User.ReadWrite.All`, `Group.ReadWrite.All`, `GroupMember.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`

### EditAccount.ps1
Updates properties of an existing user. All fields are listed in the config section — comment out any field you do not want to change. Resolves the user by UPN first, falls back to display name.

**Permissions:** `User.ReadWrite.All`

### RemoveRoles.ps1
Strips all directly assigned Entra ID roles from one or more users — both active assignments and PIM eligible assignments. Builds a role name lookup map so role names (not GUIDs) are printed to the console. Does not touch roles inherited via group membership.

**Permissions:** `User.Read.All`, `RoleManagement.ReadWrite.Directory`

### ResetUser.ps1
Interactive help desk tool. Resolves a user by UPN or display name, then presents a menu:

| Option | Action |
|--------|--------|
| `[1]` | Password reset — generates a random temporary password, forces change on next sign-in |
| `[2]` | Auth reset + TAP — removes all auth methods except password, issues a Temporary Access Pass (8h, one-time use) |
| `[3]` | Password reset + auth reset + TAP |
| `[4]` | Revoke sessions — invalidates all active refresh tokens |

Lists all current auth methods before confirmation. Displays results in a formatted box.

**Permissions:** `User.ReadWrite.All`, `UserAuthenticationMethod.ReadWrite.All`, `User.RevokeSessions.All`

---

## Audit

### AuditSuite.ps1
A single interactive script that covers 28 audit reports for any configured tenant. On launch it presents a tenant selection menu followed by a report menu. All CSV exports land in a per-tenant subfolder, timestamped. The script resolves the export location automatically: Desktop (OneDrive) → Desktop (default) → `C:\Audit\<TenantName>\`.

**Running option `[A]` (all reports) also generates an HTML executive report** — a single-page, C-level summary with severity-classified findings (Critical / High / Medium / Low / Info), an overall risk level banner, and per-finding recommendations. The report is saved alongside the CSVs as `AuditSuite_ExecutiveReport_<timestamp>.html`.

Uses the **ExportReadAudit** app registration. The `$Tenants` array at the top of the script holds all tenant entries — add `TenantId` and `AppId` to onboard a new tenant.

| # | Report | Description |
|---|--------|-------------|
| 1 | Conditional Access Policy Report | All CA policies with resolved users, groups, roles, apps, and locations |
| 2 | License Usage | SKU inventory with purchased / consumed / available counts and usage % |
| 3 | App Registration Security Audit | All app regs with permissions, owners, privileged flag, and My Apps visibility |
| 4 | App Registration Expiry | Certificates and secrets sorted by days until expiry (EXPIRED / CRITICAL / WARNING / NOTICE / OK) |
| 5 | Device Export | All Entra devices with Intune sync, compliance, stale flag, and registered owner |
| 6 | Role Assignments | All active and eligible (PIM) role assignments with group expansion |
| 7 | Role Policies | PIM policy settings per role: activation duration, MFA, justification, ticketing, approval |
| 8 | PIM Activation & Request History | Audit log of role activations, approvals, denials, and admin assignments (configurable lookback) |
| 9 | PIM Security Alerts | Active PIM security alerts (too many Global Admins, roles activated without MFA, etc.) |
| 10 | Find Inactive Devices | Devices with no sign-in beyond a configurable threshold |
| 11 | Find Inactive Users | Users with no sign-in beyond a configurable threshold |
| 12 | Domain Export | All verified and unverified domains with type, services, and federation status |
| 13 | Guest User Report | All external/guest accounts with sign-in activity and pending invitations |
| 14 | Group Export | All groups with type, membership type, member count, owner count, and visibility |
| 15 | Sign-in Log Export | Recent sign-in events with IP, location, risk level, device, and CA policy outcome |
| 16 | Directory Audit Log | Recent directory changes — who changed what, by category |
| 17 | Enterprise Applications Export | All service principals with owner type (Tenant / Microsoft / Third-party) and status |
| 18 | Delegated Permission Grants | OAuth consent grants — apps, users/admins, and granted scopes |
| 19 | Authentication Methods Policy | Tenant-wide auth method configuration (FIDO2, Authenticator, SMS, TAP, etc.) |
| 20 | Named Locations Export | All named locations with IP ranges, trusted flag, and country codes |
| 21 | Security Defaults Status | Whether Security Defaults are enabled, with a note if CA policies are also active |
| 22 | External Collaboration / B2B Settings | Guest invite permissions, guest role, email-verified join |
| 23 | Administrative Units | All AUs with member counts, scoped admin assignments, and membership type |
| 24 | Intune Compliance Policies | All compliance policies with platform, assignment targets, and unassigned flags |
| 25 | Risky Users | Users currently flagged at-risk (requires Entra ID P2) |
| 26 | Risk Detections | Individual risk events by lookback period — leaked credentials, atypical travel, etc. (requires Entra ID P2) |
| 27 | Microsoft Secure Score | Current score vs max, industry comparison, top improvement actions |
| 28 | M365 Usage Reports | Active users, email activity, Teams usage, OneDrive and SharePoint usage |
| A | Run all reports + executive report | Runs all 28 with sensible defaults (inactive/risk: 30 days, sign-in/audit: 7 days, usage: 30 days) and generates an HTML executive report |

**Permissions:** `Policy.Read.All`, `User.Read.All`, `Group.Read.All`, `Directory.Read.All`, `RoleManagement.Read.Directory`, `Application.Read.All`, `Device.Read.All`, `DeviceManagementManagedDevices.Read.All`, `DeviceManagementConfiguration.Read.All`, `AuditLog.Read.All`, `Domain.Read.All`, `RoleManagementAlert.Read.Directory`, `PrivilegedAccess.Read.AzureAD`, `PrivilegedAccess.Read.AzureADGroup`, `IdentityRiskyUser.Read.All`, `IdentityRiskEvent.Read.All`, `SecurityEvents.Read.All`, `Reports.Read.All`

---

## EasyPIM

### OnboardingPIM.ps1
Authoritative, fully idempotent PIM onboarding and drift-correction script. Safe to re-run against an already-configured tenant. Supports a `-DryRun` switch that logs all planned actions without making any changes.

**7 phases:**

| Phase | Action |
|-------|--------|
| P1 | Create role-assignable security groups if they do not exist |
| P2 | Ensure group membership (direct members for standard groups, eligible members via EasyPIM for PIM4Groups) |
| P3 | Assign active and eligible Entra ID roles to the group objects |
| P4 | Apply PIM group activation policy to PIM4Groups (8h window, MFA + justification + ticket required) |
| P5 | Apply standard PIM role policy to all standard roles (no approval required) |
| P6 | Apply privileged PIM role policy to the 5 most sensitive roles with mandatory approval from two approver groups |
| P7 | Summary report — OK / WARN / ERR counts per phase; exits with code 1 if any errors |

**Privileged roles (approval required):** Global Administrator, Privileged Role Administrator, Privileged Authentication Administrator, Security Administrator, Conditional Access Administrator

**Requires:** Entra ID P2 or Microsoft Entra ID Governance license, `EasyPIM` PowerShell module

**Permissions:** `Group.ReadWrite.All`, `GroupMember.ReadWrite.All`, `User.Read.All`, `RoleManagement.ReadWrite.Directory`, `Policy.ReadWrite.PermissionGrant`, `PrivilegedAccess.ReadWrite.AzureADGroup`

---

## GroupManagement

All scripts in this folder use the **GroupCreator** app registration with certificate-based authentication.

### ManageProtectedGroup.ps1
Creates one or more Entra ID security groups with predefined members. Checks for existence before creating (idempotent). Supports both regular and role-assignable groups. Resolves members by UPN or display name.

**Permissions:** `Group.ReadWrite.All`, `GroupMember.ReadWrite.All`, `User.Read.All`, `RoleManagement.ReadWrite.Directory`

### ReadProtectedGroup.ps1
Reads all user members from one or more groups and exports the result to a date-stamped CSV on the Desktop. Prints a per-group member count to the console.

**Permissions:** `Group.Read.All`, `GroupMember.Read.All`, `User.Read.All`

### RemoveProtectedGroup.ps1
Deletes one or more groups by display name. Groups not found are skipped silently.

**Permissions:** `Group.ReadWrite.All`

### RemoveUserFromProtectedGroup.ps1
Removes specific users from a single group. Accepts UPN or display name. Skips users not found or not currently a member.

**Permissions:** `Group.ReadWrite.All`, `GroupMember.ReadWrite.All`, `User.Read.All`

---

## Infrastructure

### CertificateCreator.ps1
Interactive utility. Prompts for a certificate name (CN), validity period (default 2 years), and export path. Creates the certificate in the current user's personal certificate store (`Cert:\CurrentUser\My`) and exports a `.cer` file. Prints the thumbprint on completion — use this thumbprint when adding the certificate to an app registration.

**Auth:** None — local operation only.

### AssignDiagnosticSettingEntra.ps1
Assigns the Azure RBAC **Contributor** role on `/providers/Microsoft.aadiam` to a specified user. This permission is required to configure Entra ID diagnostic settings (audit logs, sign-in logs forwarding to Log Analytics / Event Hub / Storage). Installs the Az PowerShell module automatically if not present.

**Prereq:** The executing account must have *Access management for Azure resources* enabled in Entra ID → Properties (Global Administrator only).  
**Auth:** Interactive (`Connect-AzAccount`)

### RemoveDiagnosticSettingEntra.ps1
Checks whether a user holds the Contributor role on `/providers/Microsoft.aadiam` and removes it if found. Use this to revoke diagnostic settings permissions after configuration is complete.

**Prereq:** Same as above.  
**Auth:** Interactive (`Connect-AzAccount`)

---

## Requirements

- PowerShell 5.1 or later
- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation)
- [EasyPIM module](https://github.com/kayasax/EasyPIM) (OnboardingPIM.ps1 only)
- Az PowerShell module (Infrastructure diagnostic scripts only)
- Entra ID P2 or Microsoft Entra ID Governance (PIM features and risk reports)

Each script lists its required modules in the `.NOTES` block. Modules are imported but never auto-installed — install them manually with `Install-Module <module> -Scope CurrentUser` if missing.
