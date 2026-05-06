# Cloud (AWS) Attack Decision Flow

> Match your **current state** to a starting point below. Follow the techniques listed, then advance to the next starting point based on what you gain.

## 1. Unauthenticated (External Recon)
**Signal:** No AWS credentials yet; external access only

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| S3 Public Bucket Enumeration | S3_Secrets.md | Bucket name known | Exposed files, credentials |
| Amazon Macie Dashboard Abuse (Data Exposure Mapping) | IAM.md | macie:ListClassificationJobs, DescribeClassificationJob, GetFindings permissions | Data exposure patterns and sensitive locations (often finds public S3 buckets) |
| Public S3 Bucket Anonymous Download | S3_Secrets.md | S3 bucket name (no AWS credentials required for public buckets) | Unencrypted files: credentials, config, backups, source code |
| CloudTrail Enumeration | CloudTrail_Evasion.md | ListTrails/DescribeTrails permission | Logging coverage map |
| AWS Account ID Enumeration via s3recon (s3:ResourceAccount Wildcard Brute-Force) | S3_Secrets.md | Bucket name known; assumable role available; account ID unknown/incorrect | Exact 12-digit account ID of bucket owner (120 requests) |
| AWS Account ID Enumeration via sts:GetAccessKeyInfo | STS.md | Leaked AWS access key (AKIA* format) | 12-digit account ID owning the key; enables downstream enumeration |
| AWS Console Credential Spray Attack (GoAWSConsoleSpray) | IAM.md | Valid AWS access key + secret + target account ID; enumerated usernames | Valid AWS console login session; full AWS Management Console access |
| IAM Access Key Last-Used Enumeration (Username Discovery) | IAM.md | Valid AWS access key ID (from source code, Lambda env, error messages) | Associated IAM username enabling credential spraying and lateral movement |
| Credential Spraying Against Discovered IAM Users | IAM.md | IAM username(s) from key enumeration + password wordlist | Valid AWS credentials for target user and access to that user's permissions |
| Terraform State File (tfstate) Sensitive Data Disclosure | CI_CD.md | .tfstate file accessible (S3/VCS/artifact) | IAM policies, role ARNs, trust conditions, OIDC provider URLs with wildcard conditions |
| Terraform Cloud OIDC Wildcard Trust Policy AssumeRole | CI_CD.md | Trust policy StringLike wildcard on app.terraform.io:sub + free Terraform Cloud account | STS credentials for targeted IAM role |

→ **Next:** Find creds in bucket → [3. Low-Privilege IAM]. Find SSRF → [2]. Access key found → IAM Access Key Last-Used Enumeration → Credential Spraying → valid credentials → [3. Low-Privilege IAM]. Account ID confirmed → use for cross-account attacks. Console session obtained → use as [3. Low-Privilege IAM]. tfstate wildcard found → OIDC AssumeRole → [4. IAM Escalation].
| Full chain: [[CANDIDATE: terraform-oidc-wildcard-s3]] — tfstate Disclosure → Terraform Cloud OIDC Wildcard AssumeRole → IAM CreateUser+AttachPolicy → S3 Flag Exfil |

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
| Spring Boot Actuator → SSRF Discovery | Web/SSRF.md | Spring Boot app with /actuator exposed | Env vars (bucket names, secrets) + proxy endpoint for SSRF |

→ **Next:** IAM credentials obtained → [3. Low-Privilege IAM] or [4. IAM Escalation].
| Full chain: [[ssrf-cloud-tenant]] — SSRF → Cloud Metadata → IAM (+ S3 VPC Endpoint bypass branch via presigned URL + SSRF proxy) |

---

## 3. Low-Privilege IAM User
**Signal:** Have valid AWS access key + secret key with limited permissions

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| S3 Bucket Access + Object ACLs | S3_Secrets.md | s3:ListBucket, s3:GetObject | Data, configs, credentials |
| S3 Pre-Signed URL Generation | S3_Secrets.md | s3:GetObject | Shareable temporary access URL |
| S3 VPC Endpoint Policy Bypass via Presigned URL + SSRF | S3_Secrets.md | s3:GetObject + SSRF proxy inside target VPC | Private S3 object access bypassing aws:SourceVpce restriction |
| SecretManager Full Dump | S3_Secrets.md | secretsmanager:ListSecrets + GetSecretValue | Plaintext DB passwords, API keys |
| KMS Key Decrypt | S3_Secrets.md | kms:Decrypt | Decrypted sensitive files |
| DynamoDB Data Exfiltration | S3_Secrets.md | dynamodb:ListTables + Scan | Full table contents |
| RDS IAM Token Auth | S3_Secrets.md | rds-db:connect | Database access via temp token |
| Secrets Manager Secret Extraction | S3_Secrets.md | secretsmanager:ListSecrets + GetSecretValue | Plaintext DB passwords, API keys, OAuth tokens |
| Lambda Source Code Extraction | Lambda_Serverless.md | lambda:GetFunction | Source code with hardcoded secrets |
| Lambda Env Variable Exfiltration | Lambda_Serverless.md | lambda:GetFunction | Env vars with DB creds, API keys |
| API Gateway Enumeration | Lambda_Serverless.md | apigateway:GET permissions | Exposed endpoints, Lambda targets |
| ECS/Fargate Enumeration | VPC_LateralMovement.md | ecs:ListClusters + Describe | Container IPs, network topology |
| SNS Topic StringLike Endpoint Condition Bypass via Query Parameter | SNS.md | SNS topic ARN known; resource policy allows sns:Subscribe; controlled HTTPS endpoint | HTTPS SNS subscription capturing all topic notifications (tokens, secrets) |
| IAM Permission Bruteforcing (Enumerate Available Actions) | IAM.md | Valid AWS credentials for the target IAM principal | Complete list of IAM actions available to the compromised principal |
| Encrypted Archive Cracking (zip2john + John the Ripper) | S3_Secrets.md | Encrypted ZIP/RAR archive from S3; John the Ripper installed | Plaintext extraction of archive contents and access to credentials |

→ **Next:** Check IAM permissions for escalation → [4]. Find secrets → use for [6] or [7]. Find Lambda targets → [5]. SNS token captured → use for authenticated Lambda invocation. Permission bruteforce → identify escalation paths. Archive found → crack and extract → [3] or [4].

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
| IAM Permission Escalation via CreateAccessKey + DeleteAccessKey (Key Rotation Attack) | IAM.md | iam:CreateAccessKey + iam:DeleteAccessKey on target user with 2 existing keys | New valid access keys for target user with their full permissions |
| iam:CreateUser + AttachUserPolicy + CreateAccessKey (Prefix-Scoped) | IAM_PrivEsc.md | Role has CreateUser+AttachUserPolicy+CreateAccessKey scoped to username prefix | New IAM user with target policy permissions + persistent access keys |

→ **Next:** Admin achieved → [9. Secrets/Storage] + [10. Post-Exploitation Stealth]. Key rotation attack → new creds for target user → [3] or [4].

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
| Python os.path.join() Absolute Path Traversal in Lambda | Lambda_Serverless.md | User input reaches os.path.join as second arg; filter only blocks ..; unvalidated APIGW present | Read arbitrary S3 objects outside intended prefix (private bucket, flag files) |

→ **Next:** Secrets found → use for [3]. Admin escalated → [9] + [10].
| Full chain: [[s3-multiservice-chain]] — s3recon account ID enum → SNS StringLike bypass → token capture → dual APIGW bypass → os.path.join path traversal → private S3 flag read |

---

## 6. EC2 / EBS Access
**Signal:** Can create/modify EC2 instances, snapshots, or AMIs

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| EBS Shadow Copy (steal NTDS.dit) | EBS_ShadowCopy.md | ec2:CreateSnapshot + ModifySnapshotAttribute | AD domain hashes (Windows EC2) |
| EBS Snapshot Attach (data exfil) | EBS_ShadowCopy.md | CreateSnapshot + CreateVolume + AttachVolume | Full filesystem access |
| EBS Snapshot Dumping via dsnap | EC2.md | ec2:DescribeSnapshots; dsnap tool installed | Snapshot filesystem dump (configs, SSH keys) |
| SSH Private Key Extraction from Snapshot | EC2.md | Snapshot filesystem access; target uses SSH key auth | SSH private keys for lateral movement |
| Docker Container Build from Snapshot | EC2.md | dsnap dump or mounted snapshot; Docker installed | Interactive container access for credential harvesting |
| Credential Rotation Bypass via Snapshot SSH Keys | EC2.md | SSH key extracted from snapshot | SSH access bypassing temporary credential expiration |
| EC2 AMI Clone (full instance copy) | VPC_LateralMovement.md | ec2:CreateImage + RunInstances | Complete instance clone |
| SSM Command Execution | VPC_LateralMovement.md | ssm:SendCommand, SSM agent on target | Agentless shell without SSH/RDP |
| Instance Connect (SSH key inject) | GoldenSAML.md | ec2-instance-connect:SendSSHPublicKey | 60-second SSH access window |

→ **Next:** Shell obtained → enumerate from inside → [3] or [7]. NTDS.dit → crack hashes. dsnap dump obtained → extract SSH keys for persistent access. Key rotation detected → use snapshot-extracted SSH keys to regain access.

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
| Full chain: [[azure_spray_to_automation_secrets]] — UPN Spray → Valid Creds → Key Vault SSH Key → VM Shell → Bash History Harvest → New User → Automation Account → Runbook Export → Flag/Cred Harvest |

---

## A2. Initial Access (Credential Acquisition)
**Signal:** Have employee names and/or a candidate password; no authenticated session yet

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| UPN Generation + Password Spray (oh365userfinder) | Azure_Attacks.md | Employee names + domain + candidate password | Valid UPN + password |
| Azure Credential Spray via Entra ID (MSOLSpray) | Azure_Attacks.md | Entra ID user list (from GraphRunner); no MFA confirmed | Valid Entra ID credentials for compromised accounts |
| Anonymous Blob Artifact Download + Cred Extraction | Azure_Attacks.md | Blob listing from A1 with zip/script/config present | Hardcoded UPN, password, clientId, secret |
| MFA Gap Enumeration & CA Bypass via User-Agent Spoofing | Azure_Attacks.md | Valid UPN + password + findmeaccess.py | ARM token without MFA via spoofed UA |

→ **Next:** Valid UPN + password → [A3]. ClientId + secret found → [A5]. Spray found valid accounts → [A3].
| Full chain: [[azure_mfa_gap_to_storage_exfil]] — MFA Gap Audit → CA Bypass (UA Spoof) → ARM Token → WP Admin RCE → IMDS MI Token → Blob Storage Exfil |
| Full chain: [[CANDIDATE: azure-spray-refresh-persistence]] — Credential Spray (MSOLSpray) → Valid Creds → MSAL Token Extraction → Refresh Token (~90-day persistence) |

---

## A3. Low-Privilege Authenticated User
**Signal:** Have valid UPN + password; `az login` succeeds

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| Azure AD UPN/SPN Harvesting | Azure_Attacks.md | Any authenticated az CLI session | Full UPN list + service principal inventory |
| Resource Enumeration | Azure_Attacks.md | `az resource list` + `az role assignment list --all` | RBAC roles, resource types, high-value targets |
| Azure Function HTTP Trigger SQL Injection | Azure_Attacks.md | Identified HTTP-triggered function endpoint; application filters input on one column | Full database schema enumeration and credential exfiltration |
| Key Vault ACL Bypass (AzureServices) | Azure_Attacks.md | Key Vault Secrets User RBAC + bypass=AzureServices | Plaintext secrets despite IP allowlist |
| SSH Key Extraction from Key Vault | Azure_Attacks.md | Key Vault Secrets User RBAC on vault with SSH key secrets | SSH private key for VM access |
| Storage Account Key Extraction | Azure_Attacks.md | `listkeys` permission on storage account | Full blob/queue/table read-write access |
| Storage Blob Recently Deleted Versions | Azure_Attacks.md | Storage Blob Data Reader/Contributor; soft-delete enabled | Deleted blob versions with credentials, data exports, logs |
| Refresh Token Extraction from ~/.azure/ | Azure_Attacks.md | Shell on Azure VM/app service with user login | Refresh token (~90-day lifetime) for sustained access |
| Automation Account Credential + Variable Harvesting | Azure_Attacks.md | Reader role on Automation Account + PowerShell | Plaintext credentials, variables (passwords/flags/API keys) |
| Teams Message Extraction via Graph API | Azure_Attacks.md | Compromised credentials + Graph API Chat.Read.All permission | Plaintext Teams messages including embedded credentials/secrets |
| Azure AD Group Membership to Storage Table Access | Azure_Attacks.md | AD group membership + custom RBAC with table read dataAction | Full table entity read + data exfiltration |
| Azure Custom Role Capability Inference via Role Definition Query | Azure_Attacks.md | Reader+ RBAC + ability to query role definitions | Full breakdown of custom role capabilities |
| Azure Storage Table Entity Query via Custom Role | Azure_Attacks.md | Table read RBAC + storage account and table name | All rows/columns from target table exported as plaintext |

> **Note:** Use `az resource list` with resource type `Microsoft.Web/sites` to discover Function Apps. Use `az role assignment list --all` — not `--assignee` — to surface resource-scoped assignments. For custom roles, query definitions via `az role definition list --custom-role-only true` to discover dataActions granting table/storage access.

→ **Next:** Website Contributor found → [A4]. Key Vault secrets yield creds/SSH keys → use SSH key for VM access, re-enter [A3] or [A5] with new identity. Automation Account discovered → harvest creds/variables for escalation. `Microsoft.Authorization/roleAssignments/write` found → [A6]. Function App discovered → test HTTP endpoints for SQL injection. Storage account with deleted blobs → enumerate recently deleted versions. Custom role with table read → [Azure Storage Table Entity Query], exfiltrate + continue lateral movement.
| Full chain: [[CANDIDATE: azure-blob-deleted-exfil]] — Storage Enumeration → Show Deleted Blobs → Download Recently Deleted Versions (data exports with plaintext creds) |
| Full chain: [[CANDIDATE: azure-function-sqli-exfil]] — Function App Discovery → HTTP Trigger Endpoint Testing → UNION SQL Injection → Schema + Credential Exfil |

---

## A4. App Service / Kudu Shell Access
**Signal:** Compromised identity has `Website Contributor` (or higher) on an App Service, OR WordPress admin credentials available

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| Kudu SCM Shell via Website Contributor | Azure_Attacks.md | Website Contributor RBAC + SCM endpoint reachable | Interactive shell; credential files in deployed scripts |
| Managed Identity Token Theft via IMDS | Azure_Attacks.md | Shell on resource with managed identity assigned | Azure Bearer JWT for ARM/Key Vault/Graph |
| WordPress Admin Plugin Upload RCE | API_WebShell.md | WordPress admin creds + plugin upload not blocked | Shell as web server user; IMDS env vars exposed |

→ **Next:** DB creds found in scripts → query Azure SQL via `sqlcmd` in Kudu shell. Managed identity token obtained → enumerate identity's RBAC → re-enter [A3] with new token. Identity has `Microsoft.Authorization/roleAssignments/write` → [A6].

---

## A5. Service Principal / App Registration Abuse
**Signal:** Found a clientId + secret/certificate in source code, env vars, Key Vault, or blob artifact

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| EntraID App Secret / Certificate Abuse | Azure_Attacks.md | clientId + secret (or PFX) + Tenant ID | OAuth2 token as service principal with inherited RBAC + Graph API permissions |
| Multi-Tenant OAuth Admin Consent Hijack | Azure_Attacks.md | Multi-tenant SP creds + Global Admin in victim tenant | Delegated Graph permissions (User.Invite.All, Group.Read.All) in victim tenant |
| Azure Web App Admin Account Creation via skipRecaptcha Bypass | Azure_Attacks.md | Web endpoint connected to EntraID + SP token | Global Administrator account in victim tenant |
| Azure Dynamic Group Manipulation via User.Invite.All | Azure_Attacks.md | User.Invite.All + predictable dynamic group rule | Guest user auto-joins group → inherits app role assignments + resource access |
| Azure Service Principal Notes/Metadata URL Extraction | Azure_Attacks.md | Graph token + resourceId from appRoleAssignments | Blob storage URLs or sensitive paths from SP object metadata |

→ **Next:** SP token obtained → enumerate SP's RBAC via ARM API → re-enter [A3]. SP has `Directory.ReadWrite.All` or `RoleManagement.ReadWrite.Directory` → full tenant compromise path. SP has `Microsoft.Authorization/roleAssignments/write` → [A6]. Multi-tenant OAuth consent granted → enumerate groups/guest invite → SP metadata → blob exfil.
| Full chain: [[azure-multitenant-oauth-to-blob-exfil]] — SP Auth → skipRecaptcha GA Creation → OAuth Admin Consent → Graph Token → Group Enum → Guest Invite → Dynamic Group Join → SP Metadata URL → Blob Exfil |

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
| Automation Runbook Script Extraction | Azure_Attacks.md | Reader role on Automation Account + PowerShell | Full runbook scripts (often contain hardcoded creds/logic) |
| Managed Identity Token Theft via IMDS | Azure_Attacks.md | Shell on any VM/App Service with managed identity | Lateral movement tokens for adjacent resources |
| Azure AD UPN/SPN Harvesting | Azure_Attacks.md | Authenticated session | Full directory enumeration for persistence targets |

→ **Next:** Document all findings. Pivot using extracted secrets and tokens. Review runbook scripts for service principal creds and API endpoints. Identify persistence opportunities (new app registration secret, new managed identity, new RBAC assignment).

---

## 8. Container Escape (Shell Inside Container)
**Signal:** Shell obtained inside a Docker/container workload; need to escape to host

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| Docker Socket Escape | Container_Escape.md | /var/run/docker.sock mounted in container | Full host root access via new privileged container |
| Privileged Container Breakout (nsenter/disk) | Container_Escape.md | Container running --privileged | Host filesystem R/W; host root shell via nsenter |
| Kubernetes Service Account Token Abuse | Container_Escape.md | K8s SA token in /var/run/secrets + cluster-admin | Full cluster control |
| Container Escape via Writable core_pattern | Container_Escape.md | /proc/sys/kernel/core_pattern writable + segfault trigger | Host OS command execution on next segfault |

→ **Next:** Host access achieved → read /flag or enumerate host for lateral movement. Check host IAM metadata endpoint for cloud creds.

---

## K1. Kubernetes Pod Access (Initial Shell in Pod)
**Signal:** Shell obtained inside a Kubernetes pod; service account token mounted at `/var/run/secrets/kubernetes.io/serviceaccount/`; need to enumerate cluster and escalate

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| Kubernetes CoreDNS Brute Force Service Discovery | Kubernetes.md | coredns-enum in pod; service CIDR known/guessable | Full service list with IPs and DNS names without kubectl get services |
| OCI Image Layer Extraction via ORAS | Kubernetes.md | ORAS binary in pod; pod SA has registry pull access | Source code, hardcoded secrets, API endpoints from other images in registry |
| Kubernetes Kubelet URL Injection via Unauthenticated Debug Proxy | Kubernetes.md | Unauthenticated debug service found (HTTP, port 8080); node_ip user-controlled | RCE in any kubelet-reachable container; SA token theft from target container |
| Kubernetes Service Account Long-Lived Token Minting via Secret Creation | Kubernetes.md | SA has create on secrets; target SA name known | Long-lived token for target SA enabling RBAC escalation |
| Kubernetes Node Proxy API Server Loopback Attack (NCC-E003660-JAV) | Kubernetes.md | SA has nodes/proxy GET + nodes/status PATCH | Cluster-admin access to all secrets across all namespaces |

→ **Next:** Service map from CoreDNS → enumerate discovered services. ORAS → source code reveals injection vectors. Kubelet URL injection → RCE → SA token theft → re-enter with new identity. SA token minting → escalated SA. Node proxy loopback → cluster-admin → all secrets.
| Full chain: [[k8s-pod-to-cluster-admin-node-proxy]] — ORAS OCI recon → CoreDNS service discovery → Kubelet URL injection → SA token theft → SA token minting → Node proxy loopback → Cluster-admin secrets |

---

## C1. CI/CD Pipeline Access (Self-Hosted Runner Compromise)
**Signal:** Target uses self-hosted GitHub Actions runners; CI workflow runs pytest; runner hostname pattern suggests `*-runner-*` or similar; actions-runner/ directory found on machine; non-ephemeral package installation (user site-packages persist across runs)

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| Trojanized Pytest Plugin → CI Runner Secret Exfiltration | CI_CD.md | Ability to inject into Python site-packages/_pytest/ on self-hosted runner; pytest used in CI; runner non-ephemeral | All CI env vars (GITHUB_TOKEN, KUBECONFIG, cloud creds) from every test run via Fernet-encrypted dead-drop |
| CI Runner Supply Chain IR Forensics | CI_CD.md | Shell on compromised runner; attacker dead-drop repo with .secret Fernet blobs | XOR-decode obfuscated key → Fernet decrypt → full env var recovery from all runners |

→ **Next:** GITHUB_TOKEN recovered → repo access (push, read secrets). KUBECONFIG → Kubernetes cluster access → K1. Cloud creds (GCP/AWS) → respective cloud flows.
| Full chain: [[ci-runner-supply-chain-exfil]] — trojanized pytest package → pytest_sessionfinish hook → env var collection → Fernet encrypt → GitHub dead-drop push → Worker log deletion → flag/credential recovery |

---

# Cloud (GCP) Attack Decision Flow

> Match your **current state** to a starting point below. Follow the techniques listed, then advance to the next starting point based on what you gain.

## G1. Unauthenticated (External Recon / SSRF)
**Signal:** No GCP credentials; SSRF vulnerability in GCP-hosted application OR shell on GCP resource (Compute Engine VM / Cloud Function / Cloud Run)

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| GCP Metadata Server SSRF — Service Account Token Theft | GCP_Attacks.md | SSRF or shell on GCP resource + metadata server reachable + Metadata-Flavor header injectable | OAuth2 access token for attached service account with all granted GCP API roles |
| GCP Metadata Server SSRF — Gopher Protocol Header Injection Bypass | GCP_Attacks.md | SSRF + header filtering (blocks Metadata-Flavor) + gopher protocol supported | Bypassed header filters; OAuth2 token for service account via gopher protocol |

→ **Next:** Token obtained → [G2].
| Full chain: [[CANDIDATE: gcp-metadata-lateral-movement-chain]] — Metadata Token → Service Account Permission Bruteforcing → Secrets Manager Access → IAM Enumeration → Credential Spray |

---

## G2. Low-Privilege Service Account (Metadata Token / Stolen SA Key)
**Signal:** Have OAuth2 token from GCP metadata server OR compromised service account JSON key file; need to map available permissions and enumerate lateral movement targets

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| GCP Service Account Permission Bruteforcing & Enumeration | GCP_Attacks.md | gcloud authenticated as service account with JSON key OR stolen metadata token | Effective permissions of SA; high-value resources (Compute instances, Secrets Manager, IAM policies, Storage) |
| GCP IAM testIamPermissions API — Service Account Permission Enumeration | GCP_Attacks.md | Compromised service account + target SA email known | Abusable permissions on target SA (often iam.serviceAccounts.getAccessToken for token minting) |
| GCP IAM Policy Enumeration for User Discovery | GCP_Attacks.md | gcloud authenticated as service account with IAM read permissions (common) | List of IAM members (users, SAs, groups) and their roles; username wordlist for credential spraying |

→ **Next:** Permissions enumerated → look for Secrets Manager, VM metadata, or IAM escalation paths → [G3] or [G4] OR token minting via testIamPermissions → [G2'] (higher-privilege SA).
| Full chain: [[CANDIDATE: gcp-sa-lateral-movement]] — Service Account Bruteforcing → VM Metadata Extraction → Secrets Access → IAM User Enum → Web App Spray |

---

## G3. Secrets Access (Lateral Movement via Application Passwords)
**Signal:** Compromised service account has `secretmanager.secretAccessor` or can access secrets; need to harvest plaintext credentials for web application or database

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| GCP Secrets Manager Access via Service Account | GCP_Attacks.md | Service account with secretmanager permissions or shell on GCP VM with SA attached | Plaintext application passwords, API keys, SSH keys, database credentials, service account keys |
| GCP VM Metadata Credential Extraction | GCP_Attacks.md | Shell on GCP Compute Engine VM + user home directory readable + gcloud CLI installed | Cached service account credentials (application_default_credentials.json, adc.json, SA JSON keys) for lateral movement to other GCP services or off-box exfil |

→ **Next:** Secrets harvested → use for web app spray/authentication, re-enter [G2] with new service account identity, or pivot to database. VM creds extracted → authenticate as different SA.

---

## G4. Privilege Escalation (High-Privilege Service Account)
**Signal:** Current service account has IAM write permissions (iam.serviceAccountKeys.create or setIamPolicy); pivot to high-privilege role

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| GCP Service Account Key Creation — Persistent Access | GCP_Attacks.md | Authenticated GCP session + `iam.serviceAccountKeys.create` permission on high-privilege SA | Downloaded JSON key file for target SA — persistent credential with no automatic expiry (survives token revocations) |
| GCP Default Service Account Abuse — Editor Privesc from Compromised VM | GCP_Attacks.md | Shell on Compute Engine VM + default SA attached + Editor role or broad scopes | Project-wide Editor access — read/write Compute, Storage, BigQuery, Secrets Manager, most GCP services |
| GCP IAM Policy Binding Escalation — Self-Grant Owner | GCP_Attacks.md | Authenticated GCP session + `setIamPolicy` permission | Owner role on GCP project/folder/org — full administrative control |

→ **Next:** Owner/Editor role achieved → [G5] for full tenant enumeration and exfiltration.

---

## G5. Container & Artifact Access
**Signal:** Have permissions to access Container Registry / Artifact Registry and need to extract source code, secrets, or establish persistence

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| GCP Artifact Registry — Private Docker Image Enumeration & Extraction | GCP_Attacks.md | Service account has artifactregistry.repositories.list or storage.buckets.list permissions; docker/docker-cli accessible | Private Docker images with embedded credentials, API keys, hardcoded secrets, source code; Dockerfile environment variable harvest |
| GCS-to-S3 Interoperability — Access Private GCS Buckets via S3 Tools | GCP_Attacks.md | GCS service account HMAC credentials (access_key_id + secret_key); s3cmd or aws-cli installed | Full read/write access to GCS buckets using S3-compatible tools — obfuscated data exfiltration avoiding gcloud CLI logs |

→ **Next:** Container creds extracted → lateral move to new SA. S3-compatible exfil established → flag/data harvest.

---

## G6. Post-Exploitation (Owner / Full Tenant Access)
**Signal:** Have Owner role at project or organizational level; need to document all findings and establish persistence

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| GCP Service Account Key Creation — Persistent Access | GCP_Attacks.md | `iam.serviceAccountKeys.create` permission on any SA | Long-lived JSON key for persistence across token revocations and session rotations |

→ **Next:** Create persistent service account key for long-term access. Enumerate all Secrets Manager secrets. Audit Artifact Registry for supply chain opportunities. Document full project RBAC and resource inventory.
