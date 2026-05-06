# Chain: Trojanized Pytest Plugin → CI Runner Secret Exfiltration → Fernet Decrypt Recovery
Tags: supply-chain, pytest, github-actions, self-hosted-runner, fernet, xor-obfuscation, dead-drop, env-var-exfil, anti-forensics, ci-cd
Chain Severity: Critical
Entry Condition: Self-hosted GitHub Actions runner with persistent Python package installation (not ephemeral); pytest used in CI workflow; ability to install/modify a Python package on the runner (trojanized PyPI package or internal package index)

## Node 1 — Trojanized Pytest Package Deployment
Technique: [[Cloud/CI_CD#Trojanized Pytest Plugin → CI Runner Secret Exfiltration]]
Strike Vector: "trojanized pytest package installation"
Condition: Control over a Python package installed on the runner (via PyPI typosquat, dependency confusion, or internal index compromise); self-hosted runner confirmed (`actions-runner/` directory present)
Standalone Severity: Med
Branches:
  - Package installed successfully with malicious `_pytest/` hook file → Node 2
  - Runner uses ephemeral (fresh-container) environment → package not persisted across runs → [TERMINAL] Persistence blocked — target package-build step or Dockerfile instead
  - `pip install` blocked by allowlist → attempt dependency confusion via internal package index if writable

## Node 2 — pytest_sessionfinish Auto-Load: Env Var Collection
Technique: [[Cloud/CI_CD#Trojanized Pytest Plugin → CI Runner Secret Exfiltration]]
Strike Vector: "pytest_sessionfinish hook execution"
Condition: Malicious file present in `_pytest/` directory of installed package; CI workflow runs pytest; hook auto-loads without configuration
Standalone Severity: High
Branches:
  - `pytest_sessionfinish` fires after test session → collects `dict(os.environ)` including GITHUB_TOKEN, KUBECONFIG, AWS/GCP creds → Node 3
  - pytest version pins conftest loading to specific directories → verify `_pytest/` is in the auto-scan path for the runner's pytest version
  - CI workflow uses `--no-plugins` flag → hook blocked → [TERMINAL] Plugin loading disabled — target conftest.py in project root instead

## Node 3 — Fernet Encrypt + GitHub Contents API Dead Drop
Technique: [[Cloud/CI_CD#Trojanized Pytest Plugin → CI Runner Secret Exfiltration]]
Strike Vector: "fernet encrypt and github dead-drop push"
Condition: Attacker-controlled GitHub repo (dead drop) with hardcoded PAT; `cryptography` library available on runner; outbound HTTPS to `api.github.com` unrestricted
Standalone Severity: High
Branches:
  - Fernet-encrypted blob pushed to dead-drop repo via GitHub Contents API PUT → Node 4
  - `cryptography` not installed on runner → fallback to base64 + XOR for encryption (weaker but functional)
  - Outbound HTTPS to github.com blocked → use alternate exfil channel (DNS, Burp Collaborator, S3 pre-signed URL)
  - PAT expired or revoked → [TERMINAL] Exfil channel broken — rotate dead-drop infra before deployment

## Node 4 — Anti-Forensics: Workspace + Worker Log Deletion
Technique: [[Cloud/CI_CD#Trojanized Pytest Plugin → CI Runner Secret Exfiltration]]
Strike Vector: "workspace and Worker log deletion"
Condition: RCE as runner process owner; `$GITHUB_WORKSPACE` set; `_diag/Worker_*.log` files present
Standalone Severity: Med
Branches:
  - `os.listdir($GITHUB_WORKSPACE)` + `shutil.rmtree` wipes workspace; `_diag/Worker_*` logs deleted → IR obscured → Node 5
  - Permission denied deleting logs → proceed anyway (exfil already complete; log deletion is opsec-only)
  - Empty workspace + no Worker logs detected by IR team → investigated via site-packages → Node 5 (IR path)

## Node 5A — Attacker: Fernet Decrypt All Exfiltrated Blobs
Technique: [[Cloud/CI_CD#Trojanized Pytest Plugin → CI Runner Secret Exfiltration]]
Strike Vector: "fernet decrypt all runner secrets"
Condition: Fernet key known (hardcoded in malicious package); dead-drop repo accessible; `.secret` files present in `data/` directory
Standalone Severity: High
Branches:
  - Sparse clone (`git clone --depth 1 --filter=blob:none --sparse`) + `git sparse-checkout set data` → decrypt all `.secret` files → filter for token/key/secret/cred/flag/pass → [TERMINAL] All CI secrets exfiltrated (Critical)
  - Runner hostnames not matching expected pattern → enumerate all `.secret` files regardless of hostname
  - Fernet decryption fails (key mismatch) → re-extract key from XOR-obfuscated array in malicious file using `_s()` helper (key=17)

## Node 5B — IR Defender: Recover Fernet Key + Decrypt Dead Drop
Technique: [[Cloud/CI_CD#CI Runner Supply Chain IR Forensics]]
Strike Vector: "site-packages forensic recovery"
Condition: Shell on compromised runner; `actions-runner/` directory present; empty workspace + no Worker logs (anti-forensic indicators)
Standalone Severity: Low
Branches:
  - `grep -rl "GITHUB_TOKEN\|encrypt\|Fernet" ~/.local/lib/python3.*/site-packages/` finds malicious hook → extract XOR key (k=17) → recover Fernet key + PAT + dead-drop repo → sparse clone + decrypt → [TERMINAL] Full incident reconstruction (High)
  - Malicious package already removed → check pip history, GitHub Actions logs, network flow logs for dead-drop repo hostname
