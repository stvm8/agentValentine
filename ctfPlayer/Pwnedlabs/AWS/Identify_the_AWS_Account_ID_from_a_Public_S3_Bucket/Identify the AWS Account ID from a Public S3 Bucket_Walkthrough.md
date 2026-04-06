# CTF Walkthrough: Identify the AWS Account ID from a Public S3 Bucket

**Platform:** Pwnedlabs | **Category:** Cloud / AWS IAM | **Difficulty:** Easy | **IP:** 54.204.171.32

---

## Executive Summary

The challenge provides a public IP address and a pair of AWS IAM long-term credentials (access key + secret). The objective is to identify the AWS Account ID that owns the S3 bucket. Rather than performing any network enumeration against the IP, the fastest and most reliable path is to leverage the `sts:GetCallerIdentity` API call — an AWS API endpoint that returns the Account ID, ARN, and User ID for any valid credential pair **and cannot be denied by IAM policy**. A single authenticated API call yields the flag in under one second.

---

## Reconnaissance

### Understanding the Given Assets

Before touching any tooling, analyze the given artifacts:

| Asset | Value | Meaning |
|-------|-------|---------|
| IP Address | `54.204.171.32` | Public IP — likely an EC2 instance hosting or referencing an S3 bucket |
| AWS Access Key ID | `AKIAWHEOTHRFW4CEP7HK` | `AKIA` prefix = **long-term IAM user credentials** (not a role/session) |
| AWS Secret Access Key | `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` | The signing secret for the above key |

**Key insight from the Access Key prefix:**

AWS Access Key IDs encode their type in the first four characters:

| Prefix | Type |
|--------|------|
| `AKIA` | Long-term IAM user key |
| `ASIA` | Temporary STS session key |
| `AROA` | IAM role ID |
| `AGPA` | IAM group ID |

`AKIA` keys are static and belong to a specific IAM user under a specific AWS account. This is exactly the information we need to extract.

### Why Skip Network Enumeration?

In a traditional CTF, we would start with Nmap. Here, however, the target is not a traditional host — it is an **AWS API endpoint**. The IP `54.204.171.32` is almost certainly an EC2 instance or an S3 bucket endpoint. Scanning it with Nmap would yield standard HTTP/HTTPS ports and no direct path to the Account ID. The credentials are the real attack surface.

---

## Core Technique: `sts:GetCallerIdentity`

### What is AWS STS?

AWS Security Token Service (STS) is the AWS service responsible for issuing and validating temporary credentials. One of its API actions, `GetCallerIdentity`, returns metadata about the IAM identity associated with the credentials used to sign the request.

**The critical security property:** Unlike almost every other AWS API call, `sts:GetCallerIdentity` **cannot be denied by an IAM policy**. Even an IAM user with zero attached policies, or with an explicit `Deny *` policy, can still successfully call this endpoint. AWS intentionally designed it this way — it is used for authentication verification, not authorization.

This makes it a universal oracle: **any valid AWS key pair will always reveal its Account ID through this call.**

### Official AWS Documentation Behavior

The API returns three fields:

| Field | Description |
|-------|-------------|
| `UserId` | The unique identifier for the IAM entity |
| `Account` | The 12-digit AWS Account ID — **this is our flag** |
| `Arn` | The full ARN, revealing the account ID and entity name |

---

## Exploitation

### Step 1 — Configure AWS Credentials

Export the credentials as environment variables to avoid writing them to the filesystem or the `~/.aws/credentials` file:

```bash
export AWS_ACCESS_KEY_ID="AKIAWHEOTHRFW4CEP7HK"
export AWS_SECRET_ACCESS_KEY="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"
export AWS_DEFAULT_REGION="us-east-1"
```

Using environment variables is best practice during engagements — it avoids credential persistence on disk and keeps secrets out of shell history files (when prefixed with a space or used via `export`).

### Step 2 — Call STS GetCallerIdentity

```bash
aws sts get-caller-identity
```

### Output

```json
{
    "UserId": "AIDAWHEOTHRF62U7I6AWZ",
    "Account": "427648302155",
    "Arn": "arn:aws:iam::427648302155:user/s3user"
}
```

**Flag captured:** `427648302155`

### Output Analysis

| Field | Value | Interpretation |
|-------|-------|----------------|
| `UserId` | `AIDAWHEOTHRF62U7I6AWZ` | Unique ID for the IAM user (`AIDA` prefix = IAM User ID) |
| `Account` | `427648302155` | **The AWS Account ID — this is the flag** |
| `Arn` | `arn:aws:iam::427648302155:user/s3user` | Full resource path: this is an IAM user named `s3user` |

The ARN format `arn:aws:<service>::<account-id>:<resource-type>/<resource-name>` independently confirms the Account ID appears twice — in the `Account` field and embedded in the `Arn`.

The username `s3user` is also significant: this is a purpose-built IAM user scoped to S3 operations, which is the type of credential that would be embedded in application code or left exposed in a public repository.

---

## Beyond Root: Why This Matters in Real Engagements

### The Exposed Credential Pipeline

This challenge models a real-world attack scenario:

```
Developer commits code to GitHub
    └─> AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY hardcoded in source
        └─> Attacker finds key via GitHub dorks / truffleHog / gitleaks
            └─> aws sts get-caller-identity
                └─> Account ID revealed (427648302155)
                    └─> Account ID used to:
                        ├─> Enumerate S3 buckets (aws s3 ls)
                        ├─> Bruteforce bucket names (s3:ListBucket 403 vs 404 oracle)
                        ├─> Escalate via misconfigured IAM policies
                        └─> Pivot to internal services (EC2, RDS, Lambda)
```

### The Account ID Oracle — Why It's Dangerous

Even if an attacker cannot access any resource (all IAM policies are locked down), the Account ID alone enables:

1. **S3 Bucket Enumeration via 403/404 Oracle:** When a bucket exists but access is denied, S3 returns `403 AccessDenied`. When a bucket does not exist, it returns `404 NoSuchBucket`. An attacker can brute-force bucket names formatted as `<company-name>-<environment>-<service>` and infer existence from the response code — no credentials needed for public buckets, but knowing the Account ID narrows the target namespace.

2. **IAM Role Cross-Account Trust Exploitation:** If any IAM role in the account has a trust policy with overly broad conditions (`"Principal": {"AWS": "*"}`), knowing the Account ID allows crafting `sts:AssumeRole` requests.

3. **Bucket Policy Condition Bypass Research:** Researchers can use the Account ID with tools like `enumerate-iam` or `Pacu` to map what services the `s3user` key can reach.

### Defensive Recommendations

| Control | Implementation |
|---------|---------------|
| Secret Scanning | Integrate `truffleHog` or `gitleaks` into CI/CD pre-commit hooks |
| Key Rotation | Rotate IAM keys every 90 days; use STS temporary credentials where possible |
| IAM Least Privilege | `s3user` should have `Condition: {"StringEquals": {"s3:prefix": ["specific/path/"]}}` |
| CloudTrail Alerting | Alert on `sts:GetCallerIdentity` calls from unknown IP ranges |
| AWS Organizations SCP | Use Service Control Policies to restrict key usage to specific IP ranges |

---

## Flag

```
427648302155
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `aws-cli` | Authenticated AWS API interaction |
| `aws sts get-caller-identity` | Account ID resolution via STS oracle |
