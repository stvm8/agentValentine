# Chain: Azure Domain Recon → Subdomain Enum → UPN Spray → Website Contributor → Kudu SCM → DB Exfil
Tags: azure, entra, recon, subdomain, spray, app-service, kudu, scm, website-contributor, db-exfil
Chain Severity: High
Entry Condition: Target company domain known; employee names and/or leaked password discoverable from public sources

## Node 1 — EntraID Tenant Discovery
Technique: [[Cloud/Azure_Attacks#Azure EntraID Tenant Discovery via getuserrealm + openid-configuration]]
Strike Vector: "entra id tenant recon"
Condition: Target domain given; need to confirm Azure AD presence and extract Tenant ID before any credentials available
Standalone Severity: Low
Branches:
  - NameSpaceType = Managed (cloud-only Azure AD) → Node 2
  - NameSpaceType = Federated (on-prem ADFS) → Node 2 (spray still viable but MFA/ADFS policies may block; note federation URL for token-based attacks)
  - Domain not found in Azure AD → [TERMINAL] Tenant not on Azure — pivot to other identity providers

## Node 2 — Azure Infrastructure Subdomain Enumeration
Technique: [[Cloud/Azure_Attacks#Azure Infrastructure Subdomain Enumeration via azsubenum]]
Strike Vector: "azure subdomain enumeration"
Condition: Company slug known (NOT full domain — use bare slug e.g. `contoso` not `contoso.com`); permutations wordlist available
Standalone Severity: Low
Branches:
  - App Services discovered (`<name>.azurewebsites.net`) → Node 3 (browse for employee names + attack surface)
  - Blob storage discovered (`<name>.blob.core.windows.net`) → [BRANCH] Test anonymous listing in parallel; re-enter [[Chain: azure_blob_to_keyvault]] Node 1
  - No Azure services found → [TERMINAL] Company may use different Azure naming convention — try alternate slugs or manual DNS enumeration

## Node 3 — Employee Name Harvest from App Pages
Technique: Manual OSINT
Strike Vector: "employee name harvest"
Condition: Discovered App Service URLs browsable; pages contain employee names (About Us, team pages, author fields)
Standalone Severity: Low
Branches:
  - New names found beyond initial target site → Node 4 (expand UPN list and re-spray)
  - No names found on app pages → Node 4 (use names from main site only)

## Node 4 — UPN Generation + Password Spray
Technique: [[Cloud/Azure_Attacks#Azure UPN Generation + Password Spray via oh365userfinder]]
Strike Vector: "azure upn spray"
Condition: Employee names collected; candidate password available (pastebin, source leak, config file, common corporate pattern); oh365userfinder.py available
Standalone Severity: Med
Branches:
  - Spray HIT — valid UPN + password found → Node 5
  - Spray misses all accounts — password wrong → [TERMINAL] No valid creds — pivot to other password sources or enumerate more names from additional subdomains
  - Smart Lockout triggered — too many attempts per account → [TERMINAL] Locked out — wait lockout window (default 60s–5min) before retrying with different accounts

## Node 5 — az CLI Authentication + Resource Enumeration
Technique: [[Cloud/Azure_Attacks#Azure AD UPN/SPN Harvesting via az CLI]]
Strike Vector: "azure initial access + resource recon"
Condition: Valid UPN + password from spray; `az login` succeeds
Standalone Severity: High
Branches:
  - `az resource list` reveals App Service with Website Contributor RBAC → Node 6
  - `az resource list` reveals Key Vault → [BRANCH] Check RBAC and ACL bypass; enter [[Chain: azure_blob_to_keyvault]] Node 4
  - `az resource list` returns empty or unauthorized → [TERMINAL] Account has no resource-level RBAC — enumerate AD objects (UPNs, SPNs, group memberships) for pivot

## Node 6 — Website Contributor → Kudu SCM Shell
Technique: [[Cloud/Azure_Attacks#Azure App Service Kudu SCM Shell via Website Contributor Role]]
Strike Vector: "app service kudu scm exploitation"
Condition: Authenticated identity confirmed with `Website Contributor` role on App Service (use `az role assignment list --all` — not `--assignee`, which misses resource-scoped assignments); SCM endpoint accessible at `<appname>.scm.azurewebsites.net`
Standalone Severity: High
Branches:
  - SCM accessible; Debug Console (PowerShell/Bash) functional → Node 7
  - SCM returns 403 despite correct role — network restriction on SCM → [TERMINAL] SCM network-locked — check App Service IP restrictions via `az webapp show`
  - Role assignment exists but SCM authentication loop (no SSO) → [TERMINAL] SCM auth blocked — may require browser session with AAD cookie

## Node 7 — Credential Extraction from Deployed Scripts
Technique: [[Cloud/Azure_Attacks#Azure App Service Kudu SCM Shell via Website Contributor Role]]
Strike Vector: "credential harvest from app service files"
Condition: Kudu Debug Console shell active; deployed scripts/configs present in app directory
Standalone Severity: High
Branches:
  - Hardcoded DB connection string / password found in .ps1/.sh/.json/.env file → Node 8
  - Environment variables contain secrets (check via `env` or `$Env:` in PowerShell) → Node 8
  - No credentials in files or env — app uses managed identity → [BRANCH] Query IMDS for managed identity token; enter SSRF-Cloud-Tenant chain Node 2A

## Node 8 — SQL Database Exfiltration via Kudu Shell
Technique: [[Cloud/Azure_Attacks#Azure App Service Kudu SCM Shell via Website Contributor Role]]
Strike Vector: "sql exfil via kudu shell sqlcmd"
Condition: DB connection string extracted (server FQDN, username, password, database name); `sqlcmd` available in Kudu shell (Windows App Service); Azure SQL firewall permits connections from App Service (common — "Allow Azure services" default)
Standalone Severity: Critical
Branches:
  - `sqlcmd` connects; tables enumerable and data readable → [TERMINAL] Chain Complete (High) — exfil target tables
  - DB firewall blocks App Service IP — "Allow Azure services" not enabled → [TERMINAL] DB network-restricted — check if other App Service env vars contain alternative connection or storage account SAS tokens
  - DB credentials valid but account is read-only → [TERMINAL] Partial (Medium) — document schema and any PII/flag columns found
