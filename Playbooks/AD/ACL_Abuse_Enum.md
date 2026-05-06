# ACL Abuse — Enumeration

> **Pre-req:** `source /opt/venvTools/bin/activate`

## ACL Enumeration

### Find Abusable ACLs with PowerView [added: 2026-04]
- **Tags:** #ACLEnum #PowerView #DACL #AccessControl #FindInterestingDomainAcl #ACE #PrivilegeEscalation
- **Trigger:** Valid domain credentials obtained; need to discover non-default permissions granting modify rights over AD objects
- **Prereq:** Valid domain credentials, PowerView loaded on domain-joined host
- **Yields:** List of abusable ACEs (GenericWrite, WriteDACL, ForceChangePassword, etc.) on domain objects for controlled principals
- **Opsec:** Med
- **Context:** Have valid credentials — find non-standard ACEs granting modification rights
- **Payload/Method:**
  ```powershell
  Import-Module .\PowerView.ps1

  # Find all interesting ACLs (non-builtin objects with modify rights)
  Find-InterestingDomainAcl

  # Find ACLs for a specific user's SID
  $sid = Convert-NameToSid <TARGET_USER>
  Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}

  # Resolve GUIDs to human-readable right names
  Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}

  # Check ACLs on all users for a specific identity
  foreach($line in [System.IO.File]::ReadLines("C:\users.txt")) {
      get-acl "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access |
      Where-Object {$_.IdentityReference -match 'DOMAIN\\username'}
  }
  ```

## ACL Enumeration — Bulk Methods

### ACL Enumeration — Bulk ACL Check per User (foreach loop) [added: 2026-04]
- **Tags:** #ACLEnum #BulkACL #PowerShell #GetACL #AttackPath #ADEnumeration #T1069
- **Trigger:** Compromised user obtained; need to discover all objects they have ACL rights over
- **Prereq:** Valid domain credentials, AD module available, list of domain users
- **Yields:** Complete mapping of all AD objects the compromised user has modify/control rights over
- **Opsec:** Med
- **Context:** Enumerate which objects a specific compromised user has ACL rights over -- finds hidden attack paths
- **Payload/Method:**
  ```powershell
  # Dump all users to file
  Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt

  # Check ACLs for each user where compromised user has rights
  foreach($line in [System.IO.File]::ReadLines("C:\Users\user\Desktop\ad_users.txt")) {
    Get-Acl "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access |
    Where-Object {$_.IdentityReference -match 'DOMAIN\\compromiseduser'}
  }
  ```

### GUID Reverse Lookup for ACE ObjectType [added: 2026-04]
- **Tags:** #GUIDLookup #ACE #ObjectType #ExtendedRights #ACLEnum #ADEnumeration #T1069
- **Trigger:** ACL enumeration returned an ACE with a raw GUID ObjectType that needs resolution to human-readable name
- **Prereq:** Valid domain credentials, AD PowerShell module, access to Configuration naming context
- **Yields:** Human-readable extended right name for a GUID (e.g., User-Force-Change-Password)
- **Opsec:** Low
- **Context:** Found an ACE with a GUID ObjectType -- resolve it to a human-readable right name
- **Payload/Method:**
  ```powershell
  $guid = "00299570-246d-11d0-a768-00aa006e0529"
  Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" `
    -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |
    Select Name,DisplayName,DistinguishedName,rightsGuid |
    ?{$_.rightsGuid -eq $guid} | fl
  ```

### ACL Enumeration via PowerView with SID Mapping [added: 2026-04]
- **Tags:** #ACLEnum #PowerView #SIDMapping #ConvertNameToSid #GetDomainObjectACL #ADEnumeration #T1069
- **Trigger:** Need to map a specific user's SID to all domain objects they control; PowerView available
- **Prereq:** Valid domain credentials, PowerView loaded on domain-joined host
- **Yields:** All domain objects where the target SID has non-default ACL rights (with optional GUID resolution)
- **Opsec:** Med
- **Context:** Map a user's SID to all domain objects they have rights over -- more reliable than name-based search
- **Payload/Method:**
  ```powershell
  Import-Module .\PowerView.ps1
  $sid = Convert-NameToSid <TARGET_USER>
  Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}
  # With resolved GUIDs for readability:
  Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}
  ```

## PASSWD_NOTREQD Flag Enumeration

### Find Accounts That Don't Require Passwords [added: 2026-04]
- **Tags:** #PASSWD_NOTREQD #UACFlag #WeakAccounts #PowerView #AccountMisconfig #CredentialAccess #T1078
- **Trigger:** AD enumeration phase; searching for weak/misconfigured accounts
- **Prereq:** Valid domain credentials, PowerView loaded
- **Yields:** Accounts with no password requirement (potential empty password login) or passwords in description fields
- **Opsec:** Low
- **Context:** Account has PASSWD_NOTREQD UAC flag — can set empty or any password
- **Payload/Method:**
  ```powershell
  # Find these accounts
  Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol

  # Check user description fields for embedded passwords
  Get-DomainUser * | Select-Object samaccountname,description
  ```

## GPO Enumeration

### GPO Enumeration — Windows (PowerView Advanced) [added: 2026-04]
- **Tags:** #GPOEnum #PowerView #GPOLinks #OUMapping #SiteGPO #ADEnumeration #T1615
- **Trigger:** Need to map GPO links to sites/OUs and identify which computers are affected by each GPO
- **Prereq:** Valid domain credentials, PowerView loaded on domain-joined host
- **Yields:** Complete GPO-to-OU-to-computer mapping; modifiable GPOs for current user
- **Opsec:** Low
- **Context:** Enumerate GPO links on Sites and OUs, and list computers per OU
- **Payload/Method:**
  ```powershell
  # GPOs linked to Sites
  Get-DomainSite -Properties gplink

  # GPOs linked to OUs
  Get-DomainOU | select name, gplink

  # List computers per OU
  Get-DomainOU | foreach {
    $ou = $_.distinguishedname
    Get-DomainComputer -SearchBase $ou -Properties dnshostname |
      select @{Name='OU';Expression={$ou}}, @{Name='FQDN';Expression={$_.dnshostname}}
  }

  # Find GPOs current user can modify
  Get-GPOEnumeration
  ```

### Query GPO DACLs with dacledit.py [added: 2026-04]
- **Tags:** #GPO_DACL #dacledit #GPOPermissions #LinuxAD #ACLEnum #GroupPolicy #T1484.001
- **Trigger:** Need to verify who has write access to a specific GPO before attempting abuse
- **Prereq:** Valid domain credentials, dacledit.py available, GPO distinguished name known
- **Yields:** DACL listing for the GPO showing which principals have write/modify rights
- **Opsec:** Low
- **Context:** Check who has write access to a specific GPO from Linux
- **Payload/Method:**
  ```bash
  proxychains4 -q python3 examples/dacledit.py <DOMAIN>/<USER>:<PASSWORD> \
    -target-dn "CN={<GPO_GUID>},CN=Policies,CN=System,DC=<DOMAIN_PART1>,DC=<DOMAIN_PART2>" -dc-ip <DC_IP>
  ```
