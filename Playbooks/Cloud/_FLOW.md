# Cloud (AWS) Attack Decision Flow

> Match your **current state** to a starting point below. Follow the techniques listed, then advance to the next starting point based on what you gain.

## 1. Unauthenticated (External Recon)
**Signal:** No AWS credentials yet; external access only

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| S3 Public Bucket Enumeration | S3_Secrets.md | Bucket name known | Exposed files, credentials |
| CloudTrail Enumeration | CloudTrail_Evasion.md | ListTrails/DescribeTrails permission | Logging coverage map |

→ **Next:** Find creds in bucket → [3. Low-Privilege IAM]. Find SSRF → [2].

---

## 2. SSRF / RCE on EC2, Lambda, or Fargate
**Signal:** SSRF or command injection on a cloud-hosted workload

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| IMDSv1 Credential Theft (EC2) | SSRF_Metadata.md | SSRF + IMDSv1 enabled | IAM role credentials |
| IMDSv2 Token-Based Access (EC2) | SSRF_Metadata.md | SSRF with PUT support or shell | IAM role credentials (extra step) |
| Fargate Container Credential Theft | SSRF_Metadata.md | SSRF/LFI in Fargate container | ECS task role credentials |
| Lambda Credential Theft | SSRF_Metadata.md | SSRF/RCE in Lambda | Lambda IAM credentials |
| EC2 UserData Exfiltration | SSRF_Metadata.md | Shell or SSRF on EC2 | Bootstrap secrets (passwords, keys) |
| Lambda RCE Credential Exfil Chain | Lambda_Serverless.md | RCE via API Gateway | AWS creds from env/runtime API |

→ **Next:** IAM credentials obtained → [3. Low-Privilege IAM] or [4. IAM Escalation].

---

## 3. Low-Privilege IAM User
**Signal:** Have valid AWS access key + secret key with limited permissions

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| S3 Bucket Access + Object ACLs | S3_Secrets.md | s3:ListBucket, s3:GetObject | Data, configs, credentials |
| S3 Pre-Signed URL Generation | S3_Secrets.md | s3:GetObject | Shareable temporary access URL |
| SecretManager Full Dump | S3_Secrets.md | secretsmanager:ListSecrets + GetSecretValue | Plaintext DB passwords, API keys |
| KMS Key Decrypt | S3_Secrets.md | kms:Decrypt | Decrypted sensitive files |
| DynamoDB Data Exfiltration | S3_Secrets.md | dynamodb:ListTables + Scan | Full table contents |
| RDS IAM Token Auth | S3_Secrets.md | rds-db:connect | Database access via temp token |
| Lambda Source Code Extraction | Lambda_Serverless.md | lambda:GetFunction | Source code with hardcoded secrets |
| Lambda Env Variable Exfiltration | Lambda_Serverless.md | lambda:GetFunction | Env vars with DB creds, API keys |
| API Gateway Enumeration | Lambda_Serverless.md | apigateway:GET permissions | Exposed endpoints, Lambda targets |
| ECS/Fargate Enumeration | VPC_LateralMovement.md | ecs:ListClusters + Describe | Container IPs, network topology |

→ **Next:** Check IAM permissions for escalation → [4]. Find secrets → use for [6] or [7]. Find Lambda targets → [5].

---

## 4. IAM Privilege Escalation Paths
**Signal:** Identified specific IAM permissions that allow self-escalation

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| CreateAccessKey (hijack admin) | IAM_PrivEsc.md | iam:CreateAccessKey on admin user | Admin user's access keys |
| CreateLoginProfile (set password) | IAM_PrivEsc.md | iam:CreateLoginProfile, no existing login | Console access as target |
| UpdateLoginProfile (reset password) | IAM_PrivEsc.md | iam:UpdateLoginProfile | Console access (overwrites password) |
| AttachUserPolicy / AttachRolePolicy | IAM_PrivEsc.md | iam:AttachUserPolicy or AttachRolePolicy | AdministratorAccess on self/role |
| PutUserPolicy (inline admin) | IAM_PrivEsc.md | iam:PutUserPolicy on self | Wildcard (*:*) permissions |
| CreatePolicyVersion + SetDefault | IAM_PrivEsc.md | iam:CreatePolicyVersion | Escalated policy to admin |
| AddUserToGroup (join admin group) | IAM_PrivEsc.md | iam:AddUserToGroup | Admin group permissions |
| UpdateAssumeRolePolicy + AssumeRole | IAM_PrivEsc.md | iam:UpdateAssumeRolePolicy | Assume privileged role |
| PassRole + Lambda Create + Invoke | IAM_PrivEsc.md | iam:PassRole + lambda:Create + Invoke | Admin via Lambda execution |
| Lambda UpdateFunctionCode (inject) | IAM_PrivEsc.md | lambda:UpdateFunctionCode | Code exec with Lambda's role |
| PassRole + EC2 RunInstances | IAM_PrivEsc.md | iam:PassRole + ec2:RunInstances | EC2 with admin role |
| PassRole + AssociateIamInstanceProfile | IAM_PrivEsc.md | iam:PassRole + ec2:AssociateIamInstanceProfile | Swap EC2 to admin role |
| Glue UpdateDevEndpoint | IAM_PrivEsc.md | glue:UpdateDevEndpoint | SSH to Glue with service role |

→ **Next:** Admin achieved → [9. Secrets/Storage] + [10. Post-Exploitation Stealth].

---

## 5. Lambda / Serverless Access
**Signal:** Can read, modify, or invoke Lambda functions

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| Source Code Extraction | Lambda_Serverless.md | lambda:GetFunction | Hardcoded secrets, logic flaws |
| Env Variable Exfiltration | Lambda_Serverless.md | lambda:GetFunction | DB passwords, API keys, creds |
| Layer Backdoor (stealthy persistence) | Lambda_Serverless.md | lambda:PublishLayerVersion | Persistent code injection |
| Function Code Update (backdoor) | Lambda_Serverless.md | lambda:UpdateFunctionCode | Code exec on every invocation |
| PrivEsc via PassRole + Create + Invoke | Lambda_Serverless.md | PassRole + Create + Invoke | Admin policy on your user |
| API Gateway Endpoint Enumeration | Lambda_Serverless.md | apigateway:GET | Exposed endpoints for RCE |

→ **Next:** Secrets found → use for [3]. Admin escalated → [9] + [10].

---

## 6. EC2 / EBS Access
**Signal:** Can create/modify EC2 instances, snapshots, or AMIs

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| EBS Shadow Copy (steal NTDS.dit) | EBS_ShadowCopy.md | ec2:CreateSnapshot + ModifySnapshotAttribute | AD domain hashes (Windows EC2) |
| EBS Snapshot Attach (data exfil) | EBS_ShadowCopy.md | CreateSnapshot + CreateVolume + AttachVolume | Full filesystem access |
| EC2 AMI Clone (full instance copy) | VPC_LateralMovement.md | ec2:CreateImage + RunInstances | Complete instance clone |
| SSM Command Execution | VPC_LateralMovement.md | ssm:SendCommand, SSM agent on target | Agentless shell without SSH/RDP |
| Instance Connect (SSH key inject) | GoldenSAML.md | ec2-instance-connect:SendSSHPublicKey | 60-second SSH access window |

→ **Next:** Shell obtained → enumerate from inside → [3] or [7]. NTDS.dit → crack hashes.

---

## 7. VPC Network Position (Pivoting)
**Signal:** Shell or credentials on a workload inside a VPC

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| VPC Peering Chain Pivot | VPC_LateralMovement.md | Shell in peered VPC | Access to adjacent VPCs |
| EKS Service Account Token Theft | VPC_LateralMovement.md | RCE on EKS pod | K8s API access (may be cluster-admin) |
| ECS/Fargate Network Enumeration | VPC_LateralMovement.md | ecs:Describe permissions | Container IPs, SG mappings |
| ECR Backdoor Image Injection | VPC_LateralMovement.md | ecr:PutImage | Supply chain persistence |

→ **Next:** New VPC access → enumerate new targets. K8s admin → cluster takeover.

---

## 8. SAML Federation / Console Access
**Signal:** Compromised ADFS or have API keys needing console access

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| Golden SAML (forge assertions) | GoldenSAML.md | ADFS token-signing private key | Any federated user, MFA bypass |
| API Keys → Console URL | GoldenSAML.md | Valid static or STS credentials | Browser-based console session |

→ **Next:** Console access → full enumeration + exploitation via GUI.

---

## 9. Secrets / Storage Access
**Signal:** Have permissions to read secrets or storage services

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| SecretManager Full Dump | S3_Secrets.md | ListSecrets + GetSecretValue | Plaintext secrets (DB, API, OAuth) |
| KMS Decrypt Encrypted Files | S3_Secrets.md | kms:Decrypt | Decrypted sensitive data |
| DynamoDB Data Exfil | S3_Secrets.md | Scan permission | Full table contents |
| RDS IAM Token Database Access | S3_Secrets.md | rds-db:connect | Database access via temp token |
| S3 Object Enumeration + Download | S3_Secrets.md | s3:ListBucket + GetObject | Backups, configs, PII |

→ **Next:** Use discovered creds for further access. Document findings for report.

---

## 10. Post-Exploitation (Stealth)
**Signal:** Need to operate undetected in compromised AWS account

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| Disable CloudTrail Entirely | CloudTrail_Evasion.md | cloudtrail:DeleteTrail | Complete audit log removal |
| Blind Global Service Logging | CloudTrail_Evasion.md | cloudtrail:UpdateTrail | IAM/STS calls not logged |
| Limit CloudTrail to Single Region | CloudTrail_Evasion.md | cloudtrail:UpdateTrail | Unmonitored regions |
| GuardDuty UA Evasion (Pacu/Boto3) | CloudTrail_Evasion.md | Pentest OS detection concern | Avoid Kali/Parrot detection |

→ **Next:** Stealth established → continue exploitation from [3] or [4].

---
# Cloud (Azure) Attack Decision Flow

> Match your **current state** to a starting point below. Follow the techniques listed, then advance to the next starting point based on what you gain.

## A1. Unauthenticated (External Recon)
**Signal:** No Azure credentials; target domain or company name only

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| EntraID Tenant Discovery | Azure_Attacks.md | Target domain | Tenant ID + Managed/Federated status |
| Azure Subdomain Enumeration (azsubenum) | Azure_Attacks.md | Company slug (NOT full domain) + permutations.txt | Storage accounts, App Services, SCM endpoints |
| Anonymous Blob Enum via $web Static Site | Azure_Attacks.md | /$web/ URL pattern | Blob listing, downloadable artifacts with creds |

→ **Next:** Tenant ID confirmed → [A2]. Blob creds found → [A3]. App Services discovered → browse for employee names → [A2].
| Full chain: [[azure_blob_to_keyvault]] — Anonymous Blob Enum → Cred Zip Download → az CLI Auth → Key Vault ACL Bypass → Secrets Exfil |
| Full chain: [[azure_recon_to_kudu_dbexfil]] — EntraID Recon → Subdomain Enum → Name Harvest → UPN Spray → az CLI Auth → Website Contributor → Kudu SCM Shell → DB Creds → SQL Exfil |

---

## A2. Initial Access (Credential Acquisition)
**Signal:** Have employee names and/or a candidate password; no authenticated session yet

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| UPN Generation + Password Spray (oh365userfinder) | Azure_Attacks.md | Employee names + domain + candidate password | Valid UPN + password |
| Anonymous Blob Artifact Download + Cred Extraction | Azure_Attacks.md | Blob listing from A1 with zip/script/config present | Hardcoded UPN, password, clientId, secret |

→ **Next:** Valid UPN + password → [A3]. ClientId + secret found → [A5].

---

## A3. Low-Privilege Authenticated User
**Signal:** Have valid UPN + password; `az login` succeeds

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| Azure AD UPN/SPN Harvesting | Azure_Attacks.md | Any authenticated az CLI session | Full UPN list + service principal inventory |
| Resource Enumeration | Azure_Attacks.md | `az resource list` + `az role assignment list --all` | RBAC roles, resource types, high-value targets |
| Key Vault ACL Bypass (AzureServices) | Azure_Attacks.md | Key Vault Secrets User RBAC + bypass=AzureServices | Plaintext secrets despite IP allowlist |
| Storage Account Key Extraction | Azure_Attacks.md | `listkeys` permission on storage account | Full blob/queue/table read-write access |

> **Note:** Use `az role assignment list --all` — not `--assignee` — to surface resource-scoped assignments.

→ **Next:** Website Contributor found → [A4]. Key Vault secrets yield creds → re-enter [A3] or [A5] with new identity. `Microsoft.Authorization/roleAssignments/write` found → [A6].

---

## A4. App Service / Kudu Shell Access
**Signal:** Compromised identity has `Website Contributor` (or higher) on an App Service

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| Kudu SCM Shell via Website Contributor | Azure_Attacks.md | Website Contributor RBAC + SCM endpoint reachable | Interactive shell; credential files in deployed scripts |
| Managed Identity Token Theft via IMDS | Azure_Attacks.md | Shell on resource with managed identity assigned | Azure Bearer JWT for ARM/Key Vault/Graph |

→ **Next:** DB creds found in scripts → query Azure SQL via `sqlcmd` in Kudu shell. Managed identity token obtained → enumerate identity's RBAC → re-enter [A3] with new token. Identity has `Microsoft.Authorization/roleAssignments/write` → [A6].

---

## A5. Service Principal / App Registration Abuse
**Signal:** Found a clientId + secret/certificate in source code, env vars, Key Vault, or blob artifact

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| EntraID App Secret / Certificate Abuse | Azure_Attacks.md | clientId + secret (or PFX) + Tenant ID | OAuth2 token as service principal with inherited RBAC + Graph API permissions |

→ **Next:** SP token obtained → enumerate SP's RBAC via ARM API → re-enter [A3]. SP has `Directory.ReadWrite.All` or `RoleManagement.ReadWrite.Directory` → full tenant compromise path. SP has `Microsoft.Authorization/roleAssignments/write` → [A6].

---

## A6. RBAC Privilege Escalation
**Signal:** Compromised identity has `User Access Administrator` or a custom role with `Microsoft.Authorization/roleAssignments/write`

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| RBAC Escalation via User Access Administrator | Azure_Attacks.md | `roleAssignments/write` at subscription/RG/resource scope | Owner or Contributor on target scope |

→ **Next:** Owner on subscription → full resource access → [A7].

---

## A7. Post-Exploitation (Owner / High-Privilege)
**Signal:** Have Owner or Contributor role at subscription or resource group scope

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| Storage Account Key Extraction (all accounts) | Azure_Attacks.md | `listkeys` permission (Owner has it) | Full read-write to all storage in subscription |
| Key Vault Full Secrets Dump | Azure_Attacks.md | Key Vault Secrets User/Administrator RBAC | All secrets, keys, and certificates in vault |
| Managed Identity Token Theft via IMDS | Azure_Attacks.md | Shell on any VM/App Service with managed identity | Lateral movement tokens for adjacent resources |
| Azure AD UPN/SPN Harvesting | Azure_Attacks.md | Authenticated session | Full directory enumeration for persistence targets |

→ **Next:** Document all findings. Pivot using extracted secrets and tokens. Identify persistence opportunities (new app registration secret, new managed identity, new RBAC assignment).
