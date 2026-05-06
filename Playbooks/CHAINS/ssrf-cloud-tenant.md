# Chain: SSRF → Cloud Metadata → IAM PrivEsc → Full Tenant
Tags: ssrf, cloud, metadata, iam, aws, gcp, azure, tenant, privesc
Chain Severity: Critical
Entry Condition: SSRF confirmed on a cloud-hosted target (AWS/GCP/Azure)

## Node 1 — SSRF Confirmed
Technique: [[Web/SSRF]]
Strike Vector: "SSRF reachability"
Condition: User-controlled URL parameter or header reflected/fetched by server
Standalone Severity: High
Branches:
  - Cloud metadata endpoint reachable (169.254.169.254 / 169.254.170.2 / metadata.google.internal) → Node 2A
  - Internal services reachable (non-metadata RFC1918 response) → [[Chain: ssrf-internal-pivot]] Node 1

## Node 2A — Cloud Metadata Extracted
Technique: [[Cloud/SSRF_Metadata]]
Strike Vector: "cloud metadata via SSRF"
Condition: SSRF reaches cloud metadata endpoint and returns credential material (token, key, role)
Standalone Severity: High
Branches:
  - IAM credentials (access key + secret + session token) in response → Node 3
  - Instance role name only (no creds) → [TERMINAL] Information Disclosure — role enumeration (Medium)

## Node 3 — IAM Privilege Escalation
Technique: [[Cloud/IAM_PrivEsc]]
Strike Vector: "IAM privesc via stolen metadata creds"
Condition: Valid cloud credentials obtained from metadata; caller identity confirmed via sts:GetCallerIdentity or equivalent
Standalone Severity: Critical
Branches:
  - Role allows iam:PassRole / iam:CreatePolicyVersion / iam:AttachUserPolicy or equivalent → Node 4
  - Role is scoped low (read-only, single service) → [TERMINAL] Credential Theft — limited role (High)
  - Role scoped to S3 + VPC endpoint policy restricts bucket access → Node 3B (Presigned URL + SSRF bypass)

## Node 3B — S3 VPC Endpoint Bypass via Presigned URL [added: 2026-05]
Technique: [[Cloud/S3_Secrets#S3-VPC-Endpoint-Policy-Bypass]]
Strike Vector: "S3 VPC endpoint restriction bypass via presigned URL through SSRF proxy"
Condition: Stolen IAM creds have s3:GetObject; bucket denies direct access via aws:SourceVpce condition; EC2 running SSRF proxy is inside the target VPC
Standalone Severity: High
Branches:
  - Presigned URL routed through SSRF proxy within VPC succeeds → [TERMINAL] Private S3 Object Access — VPC policy bypassed (High)
  - SSRF proxy blocks outbound to S3 or URL encoding rejected → [TERMINAL] Blocked — try direct VPC routing if shell access available

## Node 4 — Full Tenant Compromise
Technique: [[Cloud/IAM]]
Strike Vector: "full tenant takeover via escalated IAM"
Condition: Admin-equivalent permissions obtained (AdministratorAccess or custom policy with * actions)
Standalone Severity: Critical
Branches:
  - Persistent access established (new key, backdoor role, SSM session) → [TERMINAL] Chain Complete (Critical)
  - Escalation blocked by SCP / permission boundary → [TERMINAL] Partial Escalation (High) — document boundary config
