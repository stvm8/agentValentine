# Chain: azure_adgroup_to_table_exfil

**Threat Model:** Azure AD Group Membership → Custom Role Privilege Escalation → Storage Table Data Exfiltration

**Severity:** High

**Entry Point:** Compromised Azure user account (esp. external contractor or consultant) with indirect access to sensitive resources via AD group membership.

---

## Attack Flow

### Node 1: Compromised User Authentication
- **Goal:** Obtain credentials for an Azure user (via phishing, credential spray, prior breach, etc.)
- **Action:** Authenticate to Azure CLI with compromised credentials
- **Detection Bypass:** MFA not enforced on user; alternative: bypass via CA policy gaps (device, location, UA spoofing)
- **Outcome:** Valid `az` CLI session; ability to enumerate tenant resources
- **Failure Risk:** MFA enforcement blocks authentication; Conditional Access blocks sign-in

---

### Node 2: AD Group Membership Discovery
- **Goal:** Enumerate groups the compromised user belongs to
- **Action:** Run `az ad user get-member-groups --id <user-id>` to extract all group memberships
- **Assumption:** User has read permission on their own groups (default Azure AD behavior)
- **Detection Bypass:** Enumeration is silent; no audit trail in most default setups
- **Outcome:** Identify groups that grant privilege escalation paths (e.g., `CUSTOMER-DATABASE-ACCESS`, `Yolo-MFA`, etc.)
- **Failure Risk:** User is not group-enrolled; groups exist but grant no elevated permissions

---

### Node 3: Custom Role Query & Permissions Analysis
- **Goal:** Enumerate custom roles and identify which ones grant data-plane access
- **Action:** Query custom role definitions to find data action scopes (esp. `Microsoft.Storage/storageAccounts/tableServices/tables/entities/read`)
- **Command:** `az role definition list --custom-role-only true --query "[?roleName=='<GroupName>']"`
- **Detection Bypass:** Role definition queries are typically not audited; silent enumeration
- **Outcome:** Map group → custom role → storage data-plane permissions (esp. table entity reads)
- **Failure Risk:** Role uses condition-based access (scoped to specific storage accounts); user lacks explicit role assignment

---

### Node 4: Storage Account & Table Discovery
- **Goal:** Identify storage accounts accessible to the user
- **Action:** Run `az storage account list` to enumerate all storage accounts in the subscription
- **Constraint:** User must have Reader role or higher to list accounts; custom role may grant only data-plane access
- **Detection Bypass:** Storage account enumeration is not typically flagged as anomalous
- **Outcome:** Identify target storage account (e.g., `custdatabase` containing customer payment card data)
- **Failure Risk:** User lacks Reader permission; role is scoped to specific storage account only

---

### Node 5: Table Entity Enumeration & Exfiltration
- **Goal:** Query and export all entity records from sensitive tables
- **Action:** Run `az storage entity query --table-name <table> --account-name <storage> --output table --auth-mode login`
- **Constraint:** Custom role must grant `Microsoft.Storage/storageAccounts/tableServices/tables/entities/read` data action
- **Detection Bypass:** Table queries via authenticated CLI are logged but may not trigger alerts unless bulk/unusual volume is detected
- **Outcome:** Full exfiltration of sensitive data (PII, payment card numbers, PAN, CVV, customer IDs, etc.)
- **Failure Risk:** Table does not exist; user lacks entity read permission; rate limiting blocks bulk queries

---

## Exploitation Prerequisites

1. **Compromised User Credential:** Valid Azure AD user (internal or external/contractor)
2. **AD Group Membership:** User enrolled in one or more groups that inherit role assignments
3. **Custom Role with Data Actions:** Organization has defined a custom role with broad data-plane permissions (e.g., table entity read)
4. **No Row-Level Security (RLS):** Sensitive tables lack field-level encryption or redaction
5. **Unrestricted Storage Access:** Storage account has no policy-based access restrictions; no IP whitelist or network isolation
6. **No Audit Alerts:** Azure Monitor/Sentinel not configured to detect bulk table reads or external user access

---

## Detection Signals

### KQL: Contractor Accessing Storage Tables
```kql
AzureActivity
| where OperationNameValue contains "table" and OperationNameValue contains "entities"
  and Properties contains "read"
| where Caller contains "ext." or UserPrincipalName contains "consultant"
| project TimeGenerated, Caller, OperationName, Resource, Properties
```

### KQL: Bulk Table Entity Reads
```kql
AzureActivity
| where Resource contains "tableServices" and Resource contains "entities"
  and OperationNameValue =~ "Microsoft.Storage/storageAccounts/tableServices/tables/entities/read"
| summarize ReadCount = count() by bin(TimeGenerated, 5m), Resource, Caller
| where ReadCount > 100
```

### KQL: AD Group Membership Queries by External Users
```kql
AzureActivity
| where OperationName =~ "Get member groups" or OperationNameValue contains "memberOf"
| where Caller contains "ext." or UserPrincipalName contains "@.*\\.com" // non-corporate domain
| project TimeGenerated, Caller, OperationName, Properties
```

---

## Remediation Priority

| Control | Severity | Impact |
|---------|----------|--------|
| Restrict custom role scope to single storage account/table | **Critical** | Eliminates over-scoped permission grant |
| Implement row-level encryption or field masking on sensitive tables | **High** | Protects data even if read permission is granted |
| Enforce MFA + Conditional Access for contractor accounts | **High** | Prevents initial compromise or constrains access |
| Implement Azure Storage access policies (IP, network isolation, VNET) | **High** | Restricts data-plane access to authorized networks only |
| Enable advanced threat protection + anomaly alerts on table reads | **Medium** | Detects and responds to bulk/unusual access |
| Use PIM for just-in-time privilege elevation instead of persistent roles | **Medium** | Reduces standing privilege window; requires approval workflows |

---

## References

- **Source Lab:** Pwnedlabs — Unlock Access with Azure Key Vault
- **Related Chains:** [[azure_blob_to_keyvault]], [[azure_spray_to_automation_secrets]]
- **Azure Docs:** [Azure Storage Table entities](https://learn.microsoft.com/en-us/azure/storage/tables/table-storage-overview)
- **Attack Pattern:** MITRE ATT&CK — [T1087 Account Discovery](https://attack.mitre.org/techniques/T1087/), [T1526 Cloud Service Discovery](https://attack.mitre.org/techniques/T1526/), [T1537 Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)
