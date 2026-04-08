# LDAP Enumeration – Native AD Queries

### Install RSAT Tools [added: 2026-04]
- **Tags:** #RSAT #ADModule #PowerShell #Prerequisites #WindowsSetup #DomainEnum
- **Trigger:** Need to run AD PowerShell cmdlets but Get-ADUser/Get-ADGroup not available
- **Prereq:** Windows host with internet access or RSAT offline installer
- **Yields:** Full AD PowerShell module with Get-ADUser, Get-ADGroup, Get-ADComputer, etc.
- **Opsec:** Low
- **Context:** AD PowerShell cmdlets require RSAT. Check and install if missing.
- **Payload/Method:**
  ```powershell
  Get-WindowsCapability -Name RSAT* -Online | Select-Object -Property Name, State
  Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online
  ```

### Run Commands as Another Domain User [added: 2026-04]
- **Tags:** #runas #NetOnly #CredentialImpersonation #DomainAuth #AlternateCredentials #T1134
- **Trigger:** Have domain credentials but logged in as local user on non-domain-joined machine
- **Prereq:** Valid domain username and password; network access to DC
- **Yields:** PowerShell session authenticated to AD for LDAP queries and enumeration
- **Opsec:** Low
- **Context:** You have credentials for a domain user but are logged in as a local user. Use runas /netonly to authenticate to AD without a domain-joined machine.
- **Payload/Method:**
  ```cmd
  runas /netonly /user:DOMAIN\username powershell
  ```

### LDAP Filter: List All AD Groups [added: 2026-04]
- **Tags:** #LDAP #GroupEnum #GetADObject #ADEnumeration #DomainRecon #T1069
- **Trigger:** Initial domain enumeration phase, need to map group structure
- **Prereq:** Valid domain credentials; RSAT or LDAP access
- **Yields:** Complete list of all AD group objects in the domain
- **Opsec:** Low
- **Context:** Basic enumeration of all group objects in the domain.
- **Payload/Method:**
  ```powershell
  Get-ADObject -LDAPFilter '(objectClass=group)' | select cn
  ```

### LDAP Filter: Find Disabled Users [added: 2026-04]
- **Tags:** #LDAP #DisabledAccounts #UserAccountControl #UAC #DormantAccounts #T1087
- **Trigger:** Looking for service accounts or dormant accounts that may be re-enabled for persistence
- **Prereq:** Valid domain credentials; RSAT
- **Yields:** List of disabled user accounts for potential re-enablement or password reuse analysis
- **Opsec:** Low
- **Context:** Identify disabled accounts (userAccountControl bit 0x2 set). Useful for finding service accounts or accounts that may be re-enabled.
- **Payload/Method:**
  ```powershell
  Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=2)' | select name
  ```

### Count Users in a Specific OU [added: 2026-04]
- **Tags:** #LDAP #OUEnum #SearchBase #UserCount #ADScope #T1087
- **Trigger:** Need to scope enumeration to a specific department or OU
- **Prereq:** Valid domain credentials; knowledge of OU distinguished name
- **Yields:** User count within targeted OU for scoping
- **Opsec:** Low
- **Context:** Scope enumeration to a specific Organizational Unit.
- **Payload/Method:**
  ```powershell
  (Get-ADUser -SearchBase "OU=Employees,DC=DOMAIN,DC=LOCAL" -Filter *).count
  ```

### Find Administrative Groups [added: 2026-04]
- **Tags:** #AdminGroups #AdminCount #AdminSDHolder #HighValue #PrivilegedGroups #T1069.002
- **Trigger:** Mapping high-value targets during domain enumeration
- **Prereq:** Valid domain credentials; RSAT
- **Yields:** List of groups protected by AdminSDHolder (Domain Admins, Enterprise Admins, etc.)
- **Opsec:** Low
- **Context:** Enumerate groups with adminCount=1 (protected by AdminSDHolder).
- **Payload/Method:**
  ```powershell
  Get-ADGroup -Filter "adminCount -eq 1" | select Name
  ```

### Find ASREPRoastable Admin Users [added: 2026-04]
- **Tags:** #ASREPRoast #AdminCount #PreAuth #DONT_REQ_PREAUTH #HighValueTarget #T1558.004
- **Trigger:** Looking for quick-win credential attacks against privileged accounts
- **Prereq:** Valid domain credentials; RSAT
- **Yields:** Admin accounts vulnerable to ASREPRoasting (no pre-auth + adminCount=1)
- **Opsec:** Low
- **Context:** Find admin accounts that don't require Kerberos Pre-Authentication -- high-value ASREPRoast targets.
- **Payload/Method:**
  ```powershell
  Get-ADUser -Filter {adminCount -eq '1' -and DoesNotRequirePreAuth -eq 'True'}
  ```

### Enumerate UAC Values for Admin Users [added: 2026-04]
- **Tags:** #UAC #UserAccountControl #AdminEnum #Misconfiguration #FlagAnalysis #T1087
- **Trigger:** Need to audit admin accounts for dangerous UAC flags
- **Prereq:** Valid domain credentials; RSAT
- **Yields:** UAC flags on admin accounts revealing misconfigurations (DONT_EXPIRE_PASSWORD, PASSWD_NOTREQD)
- **Opsec:** Low
- **Context:** Check userAccountControl flags on admin accounts for misconfigurations (DONT_EXPIRE_PASSWORD, PASSWD_NOTREQD, etc.).
- **Payload/Method:**
  ```powershell
  Get-ADUser -Filter {adminCount -gt 0} -Properties admincount,useraccountcontrol
  ```

### Find Computers by Hostname Pattern [added: 2026-04]
- **Tags:** #ComputerEnum #DNSHostname #InfraMapping #SQLServer #DomainController #T1018
- **Trigger:** Need to find specific infrastructure (SQL servers, DCs, file servers)
- **Prereq:** Valid domain credentials; RSAT
- **Yields:** Computer objects matching hostname pattern for targeted enumeration
- **Opsec:** Low
- **Context:** Target specific infrastructure (SQL servers, DCs, etc.) by DNS hostname pattern.
- **Payload/Method:**
  ```powershell
  Get-ADComputer -Filter "DNSHostName -like 'SQL*'"
  ```

### WMI Group Enumeration [added: 2026-04]
- **Tags:** #WMI #GroupEnum #Win32_Group #AlternativeEnum #NoRSAT #T1069
- **Trigger:** RSAT not available but WMI access exists
- **Prereq:** WMI access to domain; valid domain credentials
- **Yields:** List of domain groups via WMI (alternative to LDAP when AD cmdlets unavailable)
- **Opsec:** Low
- **Context:** Alternative to LDAP when AD cmdlets are unavailable. Uses WMI to list domain groups.
- **Payload/Method:**
  ```powershell
  Get-WmiObject -Class win32_group -Filter "Domain='DOMAINNAME'"
  ```

### ADSI Searcher: Find All Computers [added: 2026-04]
- **Tags:** #ADSI #adsisearcher #Lightweight #NoRSAT #NoPowerView #ComputerEnum #T1018
- **Trigger:** Minimal tooling environment, need to query AD without RSAT or PowerView
- **Prereq:** Any PowerShell session with domain connectivity
- **Yields:** List of all domain-joined computer objects
- **Opsec:** Low
- **Context:** Lightweight ADSI-based query when neither RSAT nor PowerView is available. Works in any PowerShell session.
- **Payload/Method:**
  ```powershell
  ([adsisearcher]"(&(objectClass=Computer))").FindAll()
  ```

### Query Installed Software [added: 2026-04]
- **Tags:** #PostExploit #SoftwareEnum #CIMInstance #Win32Product #PrivEsc #T1518
- **Trigger:** Initial foothold obtained, need to enumerate installed software for privesc vectors
- **Prereq:** Local access to target host
- **Yields:** List of installed software for privilege escalation or lateral movement opportunities
- **Opsec:** Low
- **Context:** Post-compromise enumeration of installed software for privilege escalation vectors or loot.
- **Payload/Method:**
  ```powershell
  get-ciminstance win32_product | fl
  ```

### Get Full AD Group Properties [added: 2026-04]
- **Tags:** #ADGroup #GroupProperties #Membership #SID #DetailedEnum #T1069.002
- **Trigger:** Need full details on a specific group (membership, description, SID)
- **Prereq:** Valid domain credentials; RSAT
- **Yields:** Complete group properties including membership list, SID, description, and managed-by
- **Opsec:** Low
- **Context:** Retrieve all properties of a specific AD group including membership, description, and SID.
- **Payload/Method:**
  ```powershell
  Get-ADGroup -Identity "<GROUP_NAME>" -Properties *
  ```
