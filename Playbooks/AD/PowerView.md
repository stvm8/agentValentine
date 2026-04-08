# PowerView & SharpView – AD Enumeration

## Domain & Policy Enumeration

### View Domain Password Policy [added: 2026-04]
- **Tags:** #PowerView #PasswordPolicy #DomainPolicy #SprayPrep #GetDomainPolicy #T1201
- **Trigger:** Before password spraying; need lockout threshold and complexity requirements
- **Prereq:** PowerView loaded; valid domain user context
- **Yields:** Password policy details (lockout threshold, min length, complexity) for safe spraying
- **Opsec:** Low
- **Context:** Check password policy for spray attack parameters (lockout threshold, complexity).
- **Payload/Method:** `Get-DomainPolicy`

### Get Domain Information [added: 2026-04]
- **Tags:** #SharpView #DomainInfo #ForestInfo #DomainController #FunctionalLevel #T1087.002
- **Trigger:** Initial domain enumeration; need basic domain info
- **Prereq:** SharpView binary; valid domain user context
- **Yields:** Domain name, forest, domain controllers, functional level
- **Opsec:** Low
- **Context:** Basic domain info (forest, domain controllers, functional level).
- **Payload/Method:** `.\SharpView.exe Get-Domain`

## User Enumeration

### Count All Domain Users [added: 2026-04]
- **Tags:** #PowerView #UserCount #DomainScope #QuickEnum #GetDomainUser #T1087.002
- **Trigger:** Initial domain enumeration; scoping the environment size
- **Prereq:** PowerView loaded; valid domain user context
- **Yields:** Total count of domain user objects
- **Opsec:** Low
- **Context:** Quick scope of domain size.
- **Payload/Method:** `(Get-DomainUser).count`

### Convert Username to SID / SID to Username [added: 2026-04]
- **Tags:** #SharpView #SIDConversion #ConvertToSID #ACLAnalysis #NameResolution #T1087.002
- **Trigger:** Need to translate between SAM account names and SIDs for ACL analysis
- **Prereq:** SharpView binary; valid domain user context
- **Yields:** SID-to-username or username-to-SID translation for ACL interpretation
- **Opsec:** Low
- **Context:** Translate between SAM account names and SIDs for ACL analysis.
- **Payload/Method:**
  ```
  .\SharpView.exe ConvertTo-SID -Name sally.jones
  .\SharpView.exe Convert-ADName -ObjectName S-1-5-21-XXXX-1724
  ```

### List All UAC Values for a User [added: 2026-04]
- **Tags:** #PowerView #UAC #UserAccountControl #ConvertFromUACValue #FlagAnalysis #T1087
- **Trigger:** Need to decode UAC flags for specific user to find misconfigurations
- **Prereq:** PowerView loaded; valid domain user context
- **Yields:** Decoded UAC flags showing all account settings and misconfigurations
- **Opsec:** Low
- **Context:** Decode all userAccountControl flags to identify misconfigurations.
- **Payload/Method:** `Get-DomainUser harry.jones | ConvertFrom-UACValue -showall`

### Find ASREPRoastable Users [added: 2026-04]
- **Tags:** #SharpView #ASREPRoast #PreAuth #DONT_REQ_PREAUTH #KerberosEnum #T1558.004
- **Trigger:** Looking for accounts vulnerable to ASREPRoasting during domain enumeration
- **Prereq:** SharpView binary; valid domain user context
- **Yields:** List of users without Kerberos pre-authentication (ASREPRoast targets)
- **Opsec:** Low
- **Context:** Users without Kerberos Pre-Auth required -- targets for AS-REP roasting.
- **Payload/Method:** `.\SharpView.exe Get-DomainUser -KerberosPreauthNotRequired`

### Find Users with SPNs (Kerberoastable) [added: 2026-04]
- **Tags:** #SharpView #Kerberoasting #SPN #ServiceAccount #GetDomainUser #T1558.003
- **Trigger:** Looking for Kerberoastable accounts during domain enumeration
- **Prereq:** SharpView binary; valid domain user context
- **Yields:** List of users with SPNs set (Kerberoastable targets)
- **Opsec:** Low
- **Context:** Users with SPNs set are Kerberoastable targets.
- **Payload/Method:** `.\SharpView.exe Get-DomainUser -SPN`

### Find Users with Non-Blank Descriptions [added: 2026-04]
- **Tags:** #PowerView #Description #PasswordHint #CredentialLeak #UserEnum #T1087.002
- **Trigger:** Checking for passwords or hints stored in user description fields
- **Prereq:** PowerView loaded; valid domain user context
- **Yields:** User descriptions that may contain passwords or sensitive hints
- **Opsec:** Low
- **Context:** Descriptions often contain passwords or hints.
- **Payload/Method:** `Get-DomainUser -Properties samaccountname,description | Where {$_.description -ne $null}`

### Find Where Domain Users Are Logged In [added: 2026-04]
- **Tags:** #PowerView #UserHunting #SessionEnum #DAHunting #FindDomainUserLocation #T1033
- **Trigger:** Hunting for DA/admin sessions for token impersonation or lateral movement
- **Prereq:** PowerView loaded; valid domain user context; SMB access to targets
- **Yields:** Machines where target users have active sessions (DA hunting)
- **Opsec:** Med
- **Context:** Identify which machines have active user sessions -- useful for targeting specific users (DA hunting).
- **Payload/Method:** `Find-DomainUserLocation`

### Find Foreign Domain Users [added: 2026-04]
- **Tags:** #PowerView #ForeignGroup #TrustEnum #CrossDomain #ForeignUser #T1087.002
- **Trigger:** Trust relationships identified; looking for cross-domain access paths
- **Prereq:** PowerView loaded; valid domain user context
- **Yields:** Users from trusted/foreign domains with access in current domain
- **Opsec:** Low
- **Context:** Find users from trusted/foreign domains with access in the current domain.
- **Payload/Method:** `Find-ForeignGroup`

## Group Enumeration

### List Domain Groups [added: 2026-04]
- **Tags:** #PowerView #GroupEnum #DomainGroups #GetDomainGroup #ADEnum #T1069.002
- **Trigger:** Initial domain enumeration; mapping group structure
- **Prereq:** PowerView loaded; valid domain user context
- **Yields:** Complete list of all domain groups by name
- **Opsec:** Low
- **Context:** Enumerate all domain groups by name.
- **Payload/Method:** `Get-DomainGroup -Properties Name`

### Get Members of a Specific Group [added: 2026-04]
- **Tags:** #SharpView #GroupMembers #GetDomainGroupMember #MembershipEnum #T1069.002
- **Trigger:** Need to enumerate members of high-value groups (Domain Admins, Help Desk)
- **Prereq:** SharpView binary; valid domain user context
- **Yields:** Membership list of targeted group (users and nested groups)
- **Opsec:** Low
- **Context:** Enumerate membership of high-value groups (Domain Admins, Help Desk, etc.).
- **Payload/Method:** `.\SharpView.exe Get-DomainGroupMember -Identity 'Help Desk'`

### List Protected (AdminCount) Groups [added: 2026-04]
- **Tags:** #SharpView #AdminCount #AdminSDHolder #ProtectedGroups #HighValue #T1069.002
- **Trigger:** Identifying high-value groups protected by AdminSDHolder
- **Prereq:** SharpView binary; valid domain user context
- **Yields:** List of groups protected by AdminSDHolder (high-value targets)
- **Opsec:** Low
- **Context:** Groups protected by AdminSDHolder -- high-value targets.
- **Payload/Method:** `.\SharpView.exe Get-DomainGroup -AdminCount`

### Find Managed Security Groups [added: 2026-04]
- **Tags:** #SharpView #ManagedGroups #GroupManager #PrivEsc #MembershipAbuse #T1069.002
- **Trigger:** Looking for groups where the manager can modify membership (privesc path)
- **Prereq:** SharpView binary; valid domain user context
- **Yields:** Managed groups where the manager can add/remove members (potential privesc)
- **Opsec:** Low
- **Context:** Managed groups can have their membership modified by the manager -- potential privilege escalation path.
- **Payload/Method:** `.\SharpView.exe Find-ManagedSecurityGroups`

### Get Local Groups on a Remote Host [added: 2026-04]
- **Tags:** #PowerView #LocalGroups #GetNetLocalGroup #RemoteEnum #LateralMovement #T1069.001
- **Trigger:** Planning lateral movement; need to know local group membership on target
- **Prereq:** PowerView/SharpView loaded; valid domain user context; SMB access to target
- **Yields:** Local group membership on remote host (local admins, RDP users, etc.)
- **Opsec:** Low
- **Context:** Enumerate local group membership on a target for lateral movement planning.
- **Payload/Method:**
  ```
  Get-NetLocalGroup -ComputerName <HOST>
  .\SharpView.exe Get-NetLocalGroupMember -ComputerName <HOST>
  ```

## Computer Enumeration

### List Domain Computers [added: 2026-04]
- **Tags:** #PowerView #ComputerEnum #GetDomainComputer #ADInventory #DomainJoined #T1018
- **Trigger:** Initial domain enumeration; mapping all domain-joined machines
- **Prereq:** PowerView loaded; valid domain user context
- **Yields:** Complete list of all domain-joined computer objects
- **Opsec:** Low
- **Context:** Get all domain-joined computers.
- **Payload/Method:** `Get-DomainComputer`

### Find Unconstrained Delegation Computers [added: 2026-04]
- **Tags:** #SharpView #UnconstrainedDelegation #TGTCache #DelegationEnum #HighValue #T1558
- **Trigger:** Looking for delegation misconfigurations for credential theft
- **Prereq:** SharpView binary; valid domain user context
- **Yields:** Computers with unconstrained delegation (cache TGTs of connecting users)
- **Opsec:** Low
- **Context:** Computers with unconstrained delegation cache TGTs of connecting users -- high-value for credential theft.
- **Payload/Method:** `.\SharpView.exe Get-DomainComputer -Unconstrained`

### Find Constrained Delegation Computers [added: 2026-04]
- **Tags:** #PowerView #ConstrainedDelegation #TrustedToAuth #S4U #ImpersonationTarget #T1558
- **Trigger:** Looking for constrained delegation configurations for S4U abuse
- **Prereq:** PowerView loaded; valid domain user context
- **Yields:** Computers configured for constrained delegation (can impersonate users to specific services)
- **Opsec:** Low
- **Context:** Computers configured for constrained delegation can impersonate users to specific services.
- **Payload/Method:** `Get-DomainComputer -TrustedToAuth`

### Test Local Admin Access on Remote Host [added: 2026-04]
- **Tags:** #PowerView #AdminAccess #TestAdminAccess #PrivCheck #LateralMovement #T1069.001
- **Trigger:** Before attempting lateral movement; verify local admin on target
- **Prereq:** PowerView loaded; valid domain user context
- **Yields:** Boolean confirmation of local admin access on target host
- **Opsec:** Low
- **Context:** Quickly check if current user has local admin on a target before attempting lateral movement.
- **Payload/Method:** `Test-AdminAccess -ComputerName <HOST>`

### Enumerate Open Shares on Remote Host [added: 2026-04]
- **Tags:** #SharpView #ShareEnum #GetNetShare #NetworkShares #DataDiscovery #T1135
- **Trigger:** Need to find accessible shares on target for data discovery or lateral movement
- **Prereq:** SharpView binary; valid domain user context; SMB access to target
- **Yields:** List of network shares on remote host
- **Opsec:** Low
- **Context:** Find accessible network shares for data discovery or lateral movement.
- **Payload/Method:** `.\SharpView.exe Get-NetShare -ComputerName <HOST>`

## ACL Enumeration

### Enumerate ACLs on a Specific Object [added: 2026-04]
- **Tags:** #PowerView #ACLEnum #GetDomainObjectAcl #WriteDACL #GenericAll #T1222
- **Trigger:** Need to check who has modification rights over a specific AD object
- **Prereq:** PowerView loaded; valid domain user context
- **Yields:** All ACEs on target object showing who has write/modify/dangerous permissions
- **Opsec:** Low
- **Context:** Check who has modification rights over a user/group/computer -- key for ACL abuse chains.
- **Payload/Method:** `Get-DomainObjectAcl -Identity <username>`

### Find Interesting Domain ACLs [added: 2026-04]
- **Tags:** #PowerView #ACLAbuse #FindInterestingDomainAcl #AttackPath #WriteDACL #T1222
- **Trigger:** Need to discover ACL-based attack paths across the domain
- **Prereq:** PowerView loaded; valid domain user context
- **Yields:** Objects with modification rights (WriteDACL, GenericAll, etc.) over non-built-in objects
- **Opsec:** Med
- **Context:** Discover objects with modification rights (WriteDACL, GenericAll, etc.) over non-built-in objects -- attack path discovery.
- **Payload/Method:** `Find-InterestingDomainAcl`

### Get ACLs on a File Share [added: 2026-04]
- **Tags:** #PowerView #ShareACL #GetPathAcl #FilePermissions #ShareSecurity #T1222
- **Trigger:** Need to check permissions on sensitive shares (backups, configs)
- **Prereq:** PowerView loaded; valid domain user context; network access to share
- **Yields:** ACL entries on file share showing read/write/modify permissions
- **Opsec:** Low
- **Context:** Check permissions on sensitive shares (backups, configs).
- **Payload/Method:** `Get-PathAcl "\\SERVER\ShareName"`

## GPO Enumeration

### List All GPO Names [added: 2026-04]
- **Tags:** #SharpView #GPOEnum #GetDomainGPO #GroupPolicy #PolicyEnum #T1615
- **Trigger:** Enumerating GPOs for interesting configurations or modification paths
- **Prereq:** SharpView binary; valid domain user context
- **Yields:** Complete list of all GPO display names in the domain
- **Opsec:** Low
- **Context:** Enumerate Group Policy Objects for interesting configurations.
- **Payload/Method:** `.\SharpView.exe Get-DomainGPO | findstr displayname`

### List GPOs Applied to a Specific Host [added: 2026-04]
- **Tags:** #PowerView #GPOScope #ComputerGPO #AppLocker #AuditPolicy #T1615
- **Trigger:** Need to understand GPO policies on a specific target (AppLocker, firewall, audit)
- **Prereq:** PowerView loaded; valid domain user context
- **Yields:** GPOs applied to target host (AppLocker, firewall, audit policies)
- **Opsec:** Low
- **Context:** See which GPOs affect a target host (AppLocker, firewall, audit policies).
- **Payload/Method:**
  ```
  Get-DomainGPO -ComputerIdentity <HOST>
  gpresult /r /S <HOST>
  ```

### Find GPO Permissions (Writeable GPOs) [added: 2026-04]
- **Tags:** #PowerView #GPOAbuse #WritableGPO #GetObjectAcl #ScheduledTask #T1484.001
- **Trigger:** Looking for GPOs that can be modified for malicious settings deployment
- **Prereq:** PowerView loaded; valid domain user context
- **Yields:** GPOs with writable ACLs (can push malicious scheduled tasks, scripts)
- **Opsec:** Low
- **Context:** If you can modify a GPO, you can push malicious settings (scheduled tasks, scripts) to all hosts in scope.
- **Payload/Method:** `Get-DomainGPO | Get-ObjectAcl`

### List All OUs [added: 2026-04]
- **Tags:** #SharpView #OUEnum #GetDomainOU #OrganizationalUnit #ADStructure #T1087.002
- **Trigger:** Mapping OU structure to understand GPO application and target locations
- **Prereq:** SharpView binary; valid domain user context
- **Yields:** Complete OU structure showing how GPOs are applied and where targets reside
- **Opsec:** Low
- **Context:** Map the OU structure to understand how GPOs are applied and where targets reside.
- **Payload/Method:** `.\SharpView.exe Get-DomainOU`

## Trust Enumeration

### View Domain Trusts [added: 2026-04]
- **Tags:** #PowerView #DomainTrust #GetDomainTrust #TrustRelationship #CrossDomain #T1482
- **Trigger:** Initial domain enumeration; identifying cross-domain/forest attack paths
- **Prereq:** PowerView loaded; valid domain user context
- **Yields:** Trust relationships (type, direction, transitivity) for cross-domain attack paths
- **Opsec:** Low
- **Context:** Identify trust relationships for cross-domain/cross-forest attack paths.
- **Payload/Method:** `Get-DomainTrust`

### Map All Reachable Domain Trusts [added: 2026-04]
- **Tags:** #PowerView #TrustMapping #GetDomainTrustMapping #ForestEnum #RecursiveTrust #T1482
- **Trigger:** Need full picture of all trust relationships across the forest
- **Prereq:** PowerView loaded; valid domain user context
- **Yields:** Complete recursive trust map across all reachable domains in the forest
- **Opsec:** Med
- **Context:** Recursively enumerate trusts across all reachable domains -- full picture of the forest.
- **Payload/Method:** `Get-DomainTrustMapping`

### Get SharpView Help for Any Function [added: 2026-04]
- **Tags:** #SharpView #Help #Reference #ParameterLookup #Documentation #ToolUsage
- **Trigger:** Need quick reference for SharpView function parameters
- **Prereq:** SharpView binary
- **Yields:** Function parameter documentation for SharpView commands
- **Opsec:** Low
- **Context:** Quick reference for SharpView function parameters.
- **Payload/Method:** `.\SharpView.exe Get-DomainUser -Help`
