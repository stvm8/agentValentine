# Chain: Azure Static Site Blob → Cred Zip → az CLI Auth → Key Vault ACL Bypass → Secrets Exfil
Tags: azure, blob, anonymous, keyvault, network-acl, bypass, azureservices, initial-access
Chain Severity: High
Entry Condition: Target exposes an Azure Static Website URL containing /$web/ path segment; blob container has anonymous read access enabled

## Node 1 — Anonymous Blob Enumeration via Static Site URL
Technique: [[Cloud/Azure_Attacks#Azure Blob Anonymous Enumeration via Static Site URL]]
Strike Vector: "anonymous azure blob listing"
Condition: Target URL contains /$web/ indicating Azure Static Website; storage account name discoverable from HTTP response or DNS CNAME
Standalone Severity: Medium
Branches:
  - Container listing succeeds anonymously; interesting files (zips, scripts, configs) present → Node 2
  - Container listing returns 403/404 (public access disabled) → [TERMINAL] No anonymous access — try authenticated enum if creds available

## Node 2 — Credential Extraction from Downloaded Artifact
Technique: [[Cloud/Azure_Attacks#Azure Blob Anonymous Enumeration via Static Site URL]]
Strike Vector: "anonymous blob download + credential extraction"
Condition: Downloadable artifact (zip, script, config) found in blob listing; artifact contains hardcoded credentials in plaintext or PowerShell secure string
Standalone Severity: High
Branches:
  - Credentials found (UPN + password, clientId + secret, connection string) → Node 3
  - Artifact contains only non-credential content → [TERMINAL] Information Disclosure — enumerate remaining blobs before closing

## Node 3 — az CLI Authentication as Low-Priv User
Technique: [[Cloud/Azure_Attacks#Azure AD UPN/SPN Harvesting via az CLI]]
Strike Vector: "azure cloud initial access via leaked credential"
Condition: Valid UPN + password extracted from blob artifact; account exists and is not locked/disabled
Standalone Severity: High
Branches:
  - Authentication succeeds; subscription visible → Node 4
  - Authentication fails (MFA enforced, account disabled, wrong format) → [TERMINAL] Credential unusable — check for service principal clientId/secret in same artifact

## Node 4 — Key Vault Network ACL Bypass via AzureServices
Technique: [[Cloud/Azure_Attacks#Azure Key Vault Network ACL Bypass via AzureServices Trusted Bypass]]
Strike Vector: "azure key vault network acl bypass"
Condition: Authenticated identity has Key Vault Secrets User (or Key Vault Administrator) RBAC on a vault; vault networkAcls.bypass = "AzureServices" (visible via `az keyvault show`)
Standalone Severity: High
Branches:
  - bypass = AzureServices confirmed; secret list and show succeed despite IP allowlist → Node 5
  - bypass = None; IP allowlist enforced; current egress IP not in allowlist → [TERMINAL] Network ACL blocks access — pivot to allowed IP range or escalate RBAC first
  - RBAC insufficient (Key Vault Reader only, no Secrets User) → [TERMINAL] Role too low — enumerate other role assignments before closing

## Node 5 — Key Vault Secrets Exfiltration
Technique: [[Cloud/Azure_Attacks#Azure Key Vault Network ACL Bypass via AzureServices Trusted Bypass]]
Strike Vector: "azure key vault secrets exfil"
Condition: Secrets readable via `az keyvault secret show`; values are plaintext credentials, API keys, or certificates
Standalone Severity: Critical
Branches:
  - Secrets contain credentials for other services (DB, API, cloud accounts) → [ESCALATE] Pivot using extracted secrets; re-enter chain at Node 3 with new identity
  - Secrets contain certificate/PFX → [ESCALATE] Authenticate as service principal via certificate; check app registration permissions
  - Secrets are opaque tokens with no further pivot surface → [TERMINAL] Chain Complete (High) — document all extracted secret values
