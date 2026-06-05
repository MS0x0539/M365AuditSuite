# M365AuditSuite

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A collection of PowerShell scripts for Microsoft 365 / Entra ID administration, security auditing, PIM management, and account lifecycle automation.

**Author:** Melih Sivrikaya  
**Organization:** PSBV  
**Auth model:** Certificate-based app-only authentication throughout (except Azure scripts which use interactive Azure login)

> **Before you use these scripts:** the `TenantId`, `AppId`, and `CertificateThumbprint` values hardcoded in each script are specific to the author's environment and will not work in yours. Replace them with your own app registration details before running anything. See the [Requirements](#requirements) section for what you need to set up.

---

## Folder structure

```
M365AuditSuite/
├── Azure/
│   ├── AzureAudit/
│   │   └── AuditAzureIAM.ps1
│   ├── AssignDiagnosticSettingEntra.ps1
│   └── RemoveDiagnosticSettingEntra.ps1
├── EasyPIM/
│   ├── OnboardingEntraPIM.ps1
│   └── OnboardingAzureRBACPIM.ps1          (in development)
├── Entra/
│   ├── EntraAudit/
│   │   └── AuditSuite.ps1
│   ├── CheckBreakGlass.ps1
│   └── OnboardingConditionalAccess.ps1
└── Tools/
    ├── AccountManagement/
    │   ├── CheckAllUsersActivity.ps1
    │   ├── CheckUserActivity.ps1
    │   ├── CreateNewAccount.ps1
    │   ├── CreateBeheerAccounts.ps1
    │   ├── DeleteAccount.ps1
    │   ├── EditAccount.ps1
    │   ├── RemoveRoles.ps1
    │   └── ResetUser.ps1
    ├── CertificateCreator/
    │   └── CertificateCreator.ps1
    ├── AppManagement/
    │   └── BrowseApps.ps1
    └── GroupManagement/
        ├── ManageProtectedGroup.ps1
        ├── ReadProtectedGroup.ps1
        ├── RemoveProtectedGroup.ps1
        └── RemoveUserFromProtectedGroup.ps1
```

---

## Azure

### AuditAzureIAM.ps1

Audits all Azure subscriptions in the tenant and their RBAC assignments, including PIM eligible assignments. For each subscription collects all active role assignments at subscription scope (including those inherited from the management group hierarchy) and all PIM eligible assignments. Accepts a `-Deep` switch to also include assignments at resource group and resource level — runtime scales with resource group count on large tenants.

Exports to `Desktop\<OrgName>\AzureRBAC\AzureRBAC_<timestamp>.csv` (UTF-8 with BOM for correct Excel rendering).

**Auth:** Certificate-based (app registration: EasyPIM — requires Reader on the tenant root management group via Azure RBAC)  
**Permissions:** Reader (Azure RBAC, assigned on tenant root management group)  
**Requires:** `Az.Accounts`, `Az.Resources` (auto-installed if missing)

### AssignDiagnosticSettingEntra.ps1

Assigns the Azure RBAC **Contributor** role on `/providers/Microsoft.aadiam` to a specified user. This permission is required to configure Entra ID diagnostic settings (audit logs, sign-in logs forwarding to Log Analytics / Event Hub / Storage). Installs the Az PowerShell module automatically if not present.

**Prereq:** The executing account must have *Access management for Azure resources* enabled in Entra ID → Properties (Global Administrator only).  
**Auth:** Interactive (`Connect-AzAccount`)

### RemoveDiagnosticSettingEntra.ps1

Checks whether a user holds the Contributor role on `/providers/Microsoft.aadiam` and removes it if found. Use this to revoke diagnostic settings permissions after configuration is complete.

**Prereq:** Same as above.  
**Auth:** Interactive (`Connect-AzAccount`)

---

## EasyPIM

### OnboardingEntraPIM.ps1

Authoritative, fully idempotent PIM onboarding and drift-correction script. Safe to re-run against an already-configured tenant. Supports a `-DryRun` switch that logs all planned actions without making any changes.

**8 phases:**

| Phase | Action |
|-------|--------|
| P1 | Create role-assignable security groups if they do not exist; correct description drift on existing groups |
| P2 | Apply PIM group activation policy to PIM4Groups before member assignments (permanent eligibility, justification + ticket required) |
| P3 | Ensure each group contains exactly the members defined in the config; remove unexpected members; assign eligible members via EasyPIM for PIM4Groups |
| P4 | Assign active and eligible Entra ID roles to the group objects; correct time-limited assignments to permanent |
| P5 | Apply standard PIM role policy to all standard roles (justification + ticket, auth context c1, no approval required) |
| P6 | Apply privileged PIM role policy to the 5 most sensitive roles with mandatory approval from two approver groups |
| P7 | Direct assignment audit — scan for roles assigned directly to users, SPs, or unmanaged groups; scan for unmanaged PIM4Groups configs; export findings to CSV |
| P8 | Summary report — OK / WARN / ERR counts per phase; exits with code 1 if any errors |

**Privileged roles (approval required):** Global Administrator, Privileged Role Administrator, Privileged Authentication Administrator, Security Administrator, Conditional Access Administrator

**Requires:** Entra ID P2 or Microsoft Entra ID Governance license, `EasyPIM` PowerShell module

**Permissions:** `Directory.ReadWrite.All`, `Group.ReadWrite.All`, `Policy.Read.All`, `PrivilegedAccess.ReadWrite.AzureAD`, `PrivilegedAccess.ReadWrite.AzureADGroup`, `PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup`, `PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup`, `RoleManagement.ReadWrite.Directory`, `RoleManagementPolicy.ReadWrite.AzureADGroup`, `RoleManagementPolicy.ReadWrite.Directory`

### OnboardingAzureRBACPIM.ps1

In development.

---

## Entra

### AuditSuite.ps1

A single interactive script that covers 32 audit reports for any configured tenant. On launch it presents a tenant selection menu followed by a report menu. All CSV exports land in a per-tenant subfolder, timestamped. The script resolves the export location automatically: Desktop (OneDrive) → Desktop (default) → `C:\Audit\<TenantName>\`.

**Running option `[A]` or `[R]` generates an interactive HTML executive report** saved as `AuditSuite_ExecutiveReport_<timestamp>.html`. The report includes:

- **Overall risk level** (CRITICAL → GOOD) in the header
- **Severity cards** — Critical / High / Medium / Low / Info counts, each with a CVSS v3.1 range score gauge; click any card to instantly filter the findings list
- **Risk by Category** — stacked horizontal bar chart showing severity composition per category; bar width is severity-weighted (Critical=10 pts, High=6, Medium=3, Low=1, Info=0) so single informational findings don't inflate the chart; hover any segment for a per-severity tooltip
- **Interactive findings list** — grouped by category in collapsible sections; each finding expands to reveal full detail and a concrete recommendation
- **Filter controls** — free-text search, severity dropdown, category dropdown, and Expand All / Collapse All / Clear / Print buttons
- CVSS scores are indicative severity mappings aligned with CVSS v3.1 ranges, not CVE-specific values

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
| 29 | Password Never Expires | All enabled accounts with DisablePasswordExpiration set, sorted by days since last password change |
| 30 | Guest Users with Privileged Roles | Cross-references all guest/external accounts against active and PIM-eligible role assignments |
| 31 | Legacy Authentication Sign-ins | Recent sign-ins using legacy protocols (EAS, IMAP4, POP3, SMTP, MAPI, EWS) that bypass CA and MFA |
| 32 | Authentication Method Adoption | Tenant-wide count of users registered per authentication method |
| A | Run all reports + executive report | Runs all 32 with sensible defaults (inactive/risk: 30 days, sign-in/audit: 7 days, legacy auth: 30 days, usage: D30) and generates an HTML executive report alongside all CSVs |
| R | Report-only (no CSVs) | Same as A but skips all CSV exports — only the HTML executive report is written to disk. M365 Usage Reports (28) are also skipped as they are download-only with no findings |

**Permissions:** `Policy.Read.All`, `User.Read.All`, `Group.Read.All`, `Directory.Read.All`, `RoleManagement.Read.Directory`, `Application.Read.All`, `Device.Read.All`, `DeviceManagementManagedDevices.Read.All`, `DeviceManagementConfiguration.Read.All`, `AuditLog.Read.All`, `Domain.Read.All`, `RoleManagementAlert.Read.Directory`, `PrivilegedAccess.Read.AzureAD`, `PrivilegedAccess.Read.AzureADGroup`, `IdentityRiskyUser.Read.All`, `IdentityRiskEvent.Read.All`, `SecurityEvents.Read.All`, `Reports.Read.All`

### CheckBreakGlass.ps1

Read-only health check for configured break-glass emergency access accounts. For each account verifies:

- Account exists and is not blocked from sign-in
- Has a permanent (non-PIM) Global Administrator role assignment
- Last sign-in is within a configurable threshold (default: 180 days)
- No weak authentication methods registered (SMS / voice call); reports strong methods (FIDO2, Authenticator, OATH TOTP, Windows Hello) separately
- Is excluded from all enabled CA policies that require MFA for all users

Results are printed to the console and exported to `Desktop\<TenantName>\BreakGlass\CheckBreakGlass_<timestamp>.csv`. The `UserAuthenticationMethod.Read.All` permission is optional — the auth method check is skipped gracefully if the permission is not granted.

**Permissions:** `User.Read.All`, `Directory.Read.All`, `RoleManagement.Read.Directory`, `AuditLog.Read.All`, `Policy.Read.All`, `UserAuthenticationMethod.Read.All` (optional)

### OnboardingConditionalAccess.ps1

Idempotent script that creates or validates the CA prerequisites required by `OnboardingEntraPIM.ps1`. Covers only the PIM-related CA components. Supports a `-DryRun` switch.

**2 phases:**

| Phase | Action |
|-------|--------|
| P1 | Ensure authentication context `c1` exists in the tenant and is marked available |
| P2 | Ensure the PIM Step-Up policy exists, is enabled, and targets auth context `c1` with MFA grant control for all users; detects and warns about duplicate policies already targeting `c1` |

Includes drift detection on the P2 policy — validates auth context reference, user scope, and grant control independently of create/update.

**Permissions:** `Policy.Read.All`, `Policy.ReadWrite.ConditionalAccess`

---

## Tools

### AppManagement

Scripts in this folder use the **ExportReadAudit** app registration with certificate-based authentication.

#### BrowseApps.ps1

Interactive read-only browser for App Registrations and Enterprise Applications. Connects once, loads all data into memory, and presents a menu-driven interface — no changes are made to the tenant at any point.

**App Registrations — filter views:**

| Filter | Description |
|--------|-------------|
| All | Full list, sorted by name |
| Privileged | Apps holding one or more privileged permissions (e.g. `Directory.ReadWrite.All`, `User.ReadWrite.All`) |
| No owner | Apps with no assigned owner — no accountability for lifecycle or permissions |
| Expiring / expired credentials | Apps with certificates or client secrets at EXPIRED / CRITICAL / WARNING / NOTICE status |
| Multi-tenant | Apps registered for audiences beyond the home tenant |
| No recent activity / stale | Apps with no sign-in recorded within `$StaleActivityDays` (default 90) or no activity in the retention window (requires `AuditLog.Read.All`) |
| Search by name | Wildcard name search across all app registrations |

**Enterprise Applications — filter views:**

| Filter | Description |
|--------|-------------|
| All | Full list, sorted by owner type then name |
| Tenant-owned | Service principals created by the tenant (your own apps) |
| Third-party | Service principals owned by external organisations |
| Disabled | SPs with `AccountEnabled = false` |
| Apps with delegated grants | SPs that have active OAuth2 delegated permission grants (requires `Directory.Read.All`) |
| Search by name | Wildcard name search across all service principals |

**List view** shows credential expiry status with days remaining (e.g. `CRITICAL (3d)`, `EXPIRED (12d ago)`) matching the AuditSuite expiry report format. Flags such as `[PRIVILEGED]`, `[NO OWNER]`, `[STALE]`, and `[NO ACTIVITY]` appear inline.

**Detail view** (enter a number from any list) shows:
- App Registration: owners, all permissions with privileged ones flagged in red, sign-in activity breakdown (app credential / delegated / non-interactive, with days since last use), certificates and secrets with individual expiry status and days remaining, federated identity credentials (issuer, subject, audiences)
- Enterprise Application: SP type, owner classification, granted application permissions with privileged flag, delegated permission grants per user or admin consent

**CSV export** — press **[X]** in any list. App Registration exports include: `UsageStatus`, `LastUsed`, `DaysSinceLastUse`, `LastAppCredSignIn`, `LastDelegatedSignIn`, `LastNonInteractiveSignIn`, `HasCertificate`, `WorstCertExpiry`, `Certificates` (name / expiry date / status per cert), `HasSecret`, `WorstSecretExpiry`, `Secrets`, `HasFederation`, `FederationCredentials`, plus all permissions columns. Exports land in `Desktop\<TenantName>\AppManagement\` — resolved with the same 3-way logic as all other scripts: Desktop (OneDrive) → Desktop (default) → `C:\Audit\<TenantName>\AppManagement\`.

Use **[R]** from the main menu to reload all data without reconnecting.

**Configurable thresholds** (top of script):

| Variable | Default | Purpose |
|---|---|---|
| `$CriticalDays` | 14 | Credential expiry critical threshold |
| `$WarningDays` | 30 | Credential expiry warning threshold |
| `$NoticeDays` | 60 | Credential expiry notice threshold |
| `$StaleActivityDays` | 90 | Days without sign-in before an app is flagged stale |

**Permissions:** `Application.Read.All`, `User.Read.All`

**Optional:**
- `Directory.Read.All` — delegated permission grants view (skipped gracefully if absent)
- `AuditLog.Read.All` — SP sign-in activity report for last-used dates (skipped gracefully if absent)

> **Note:** Sign-in activity retention is 30 days (Entra ID P1) or 90 days (P2). "No activity" means no sign-in recorded within the retention window — it does not prove the app is unused.

---

### AccountManagement

All scripts in this folder use the **AccountManagement** app registration with certificate-based authentication, except `CheckUserActivity.ps1` which uses **ExportReadAudit** (requires `AuditLog.Read.All`).

#### CheckAllUsersActivity.ps1

Tenant-wide bulk inactivity check. Checks every user against all three `SignInActivity` fields on the user record, classifies each as ACTIVE / INACTIVE / NEVER, prints a console table of flagged users, and exports a full CSV for all users. One prompt: inactivity threshold in days.

**Permissions:** `User.Read.All`, `AuditLog.Read.All`

#### CheckUserActivity.ps1

Comprehensive read-only inactivity check for a single user. Prompts for a UPN or display name and an inactivity threshold in days. Checks every available sign-in source and prints a clear **ACTIVE / INACTIVE** verdict with full detail.

**Two sources checked:**

| Source | What it covers |
|---|---|
| `SignInActivity` on the user object | `lastSuccessfulSignInDateTime` (any type), `lastSignInDateTime` (interactive), `lastNonInteractiveSignInDateTime` — authoritative, not limited by log retention |
| Sign-in log events (audit log) | Per-event detail: date/time, type, application, IP address, result, risk level — limited to 30d (P1) or 90d (P2) retention |

The verdict uses the most recent timestamp across all sources. If the user record shows no activity and the logs show no events, the user is reported **INACTIVE** regardless of retention window.

**Permissions:** `User.Read.All`, `AuditLog.Read.All`

#### CreateNewAccount.ps1
Creates a new regular user account in Entra ID. Fills all standard user properties (name, department, job title, address, phone, usage location, etc.). Generates a random 16-character temporary password (upper + lower + digits) and prints it to the console. The user must change it on first sign-in.

**Permissions:** `User.ReadWrite.All`

#### CreateBeheerAccounts.ps1
Mass-creates all beheer (administrator) accounts defined in the PIM authorization matrix. Idempotent — skips accounts that already exist by UPN. Each account receives a random 16-character temporary password; passwords are printed to the console at the end of the run and never written to disk. Supports a `-DryRun` switch.

**Permissions:** `User.ReadWrite.All`

#### DeleteAccount.ps1
Removes one or more accounts safely:
1. Removes the user from all non-dynamic groups
2. Removes all directly assigned active Entra ID roles
3. Removes all PIM eligible role assignments
4. Waits 20 seconds for propagation, then deletes the account

Accepts UPN or display name. Supports a list of users.

**Permissions:** `User.ReadWrite.All`, `Group.ReadWrite.All`, `GroupMember.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`

#### EditAccount.ps1
Updates properties of an existing user. All fields are listed in the config section — comment out any field you do not want to change. Resolves the user by UPN first, falls back to display name.

**Permissions:** `User.ReadWrite.All`

#### RemoveRoles.ps1
Strips all directly assigned Entra ID roles from one or more users — both active assignments and PIM eligible assignments. Builds a role name lookup map so role names (not GUIDs) are printed to the console. Does not touch roles inherited via group membership.

**Permissions:** `User.Read.All`, `RoleManagement.ReadWrite.Directory`

#### ResetUser.ps1
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

### GroupManagement

All scripts in this folder use the **GroupCreator** app registration with certificate-based authentication.

#### ManageProtectedGroup.ps1
Creates one or more Entra ID security groups with predefined members. Checks for existence before creating (idempotent). Supports both regular and role-assignable groups. Resolves members by UPN or display name.

**Permissions:** `Group.ReadWrite.All`, `GroupMember.ReadWrite.All`, `User.Read.All`, `RoleManagement.ReadWrite.Directory`

#### ReadProtectedGroup.ps1
Reads all user members from one or more groups and exports the result to a date-stamped CSV on the Desktop. Prints a per-group member count to the console.

**Permissions:** `Group.Read.All`, `GroupMember.Read.All`, `User.Read.All`

#### RemoveProtectedGroup.ps1
Deletes one or more groups by display name. Groups not found are skipped silently.

**Permissions:** `Group.ReadWrite.All`

#### RemoveUserFromProtectedGroup.ps1
Removes specific users from a single group. Accepts UPN or display name. Skips users not found or not currently a member.

**Permissions:** `Group.ReadWrite.All`, `GroupMember.ReadWrite.All`, `User.Read.All`

---

### CertificateCreator

#### CertificateCreator.ps1
Interactive utility. Prompts for a certificate name (CN), validity period (default 2 years), and export path. Creates the certificate in the current user's personal certificate store (`Cert:\CurrentUser\My`) and exports a `.cer` file. Prints the thumbprint on completion — use this thumbprint when adding the certificate to an app registration.

**Auth:** None — local operation only.

---

## Requirements

- PowerShell 5.1 or later
- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation)
- [EasyPIM module](https://github.com/kayasax/EasyPIM) (`OnboardingEntraPIM.ps1` only)
- Az PowerShell module (`Azure/` scripts only — auto-installed by the Azure scripts)
- Entra ID P2 or Microsoft Entra ID Governance (PIM features and risk reports)

Each script lists its required modules in the `.NOTES` block. Modules are imported but never auto-installed — install them manually with `Install-Module <module> -Scope CurrentUser` if missing (exception: Azure scripts auto-install `Az.Accounts` and `Az.Resources`).
