---
title: agent_learnings
created: 2026-04-05
modified: 2026-04-05
type: note
---
#Nmap #Recon Issue: Used sudo for nmap unnecessarily. Solution: nmap -sV -sC scans do not require sudo; only raw SYN scans (-sS) need root privileges.
#Windows #CSharp #Compilation Issue: Exploits requiring Visual Studio or complex .NET framework references (like SharpWSUS) cannot be reliably compiled via Linux 'mcs' or 'dotnet'. Solution: Immediately halt and ask the user to compile it on a Windows VM and transfer the .exe to the workspace.
#JustEat #OIDC #JWT Issue: JWT from browser localStorage works in curl WITHOUT proxy. Caido proxy strips/corrupts Authorization header. Solution: Always test curl without -x for JWT-authed endpoints.
#JustEat #OIDC #JWT Issue: Manual hex transcription of JWT corrupts bytes. Solution: Split JWT at dots (console.log each part separately) - each part alone doesn't trigger extension's JWT block filter.
#JustEat #JWT #Auth Issue: je-at cookie (sameSite:lax, domain:just-eat.co.uk) NOT sent cross-domain to uk.api.just-eat.io. Solution: API uses Bearer token in Authorization header, set explicitly by SPA JS from oidc.user localStorage key.
#JustEat #IDOR #Consumer Issue: /consumer/{id}/orders/uk returns 404 - no direct consumer ID path. Only /consumer/me/orders/uk (200) exists. consumerId resolved from JWT sub claim, not from URL or injected headers.
#JustEat #IDOR #Headers Issue: X-Consumer-ID, X-User-ID, X-Forwarded-User, X-JWT-Sub headers all ignored - consumerId stays bound to JWT sub. Header injection IDOR: negative on this endpoint.
#Lime #OAuth #Google Issue: admintool client_id org_internal — Google-level restriction blocks non @li.me/@lime.bike accounts. Frontend vde domain check is redundant. -> Both frontend AND GCP app settings enforce domain.
#Lime #API #CORS Issue: data-entrypoint-api.limeinternal.com returns 403 CORS Forbidden without Origin header -> Fix: Always add Origin + Referer matching the SPA domain.
#OpenVaultBank #API #InfoDisc Issue: /health endpoint leaks full DB credentials + JWT signing hints unauthenticated -> Always probe /health, /status, /ping, /debug on any FastAPI/Rails app; check for DB URLs, secrets, flags.
#OpenVaultBank #MassAssign #PrivEsc Issue: PUT /profile accepts role field, escalates customer to admin -> Check all PUT/PATCH profile/user endpoints for mass assignment; send {"role":"admin"} as first test.
#OpenVaultBank #BOLA #Accounts Issue: GET/PUT /accounts/{id} has no ownership check, any valid JWT reads/writes any account -> Integer IDs + no owner validation = BOLA; always enumerate sequential IDs with your token.
#OpenVaultBank #ResetCode #ATO Issue: POST /auth/reset-request returns debug_code in response body (3-digit) -> Instant ATO for any user. Always check reset endpoints for leaked codes in response body, headers, or debug fields.
#OpenVaultBank #API #Debug Issue: Debug endpoint /api/v1/debug exposed unauthenticated with flag + JWT hints + registered users. Solution: Always fuzz for /debug, /test, /dev on any API; check api_logs for 200 status non-standard paths.
#OpenVaultBank #SSRF #DB Issue: Leaked Supabase DB creds from /health → psql direct access → pgjwt functions available for JWT operations, pg_net for SSRF out. Solution: DB creds in health = full DB access; always try psql and enumerate extensions (pgjwt, pg_net, http).
#OpenVaultBank #Register #API Issue: POST /auth/register required undocumented 'ssn_last4' field — 422 without it. Solution: On 422 'field required' check Pydantic error 'loc' array for missing field names.
#LDAP #tcpdump #Cleartext Issue: LDAP Simple Bind sends passwords in cleartext over TCP on port 389. Solution: Use tcpdump with cap_net_raw+ep capability to sniff binds on localhost/network interface.
#Linux #Capabilities #Privesc Issue: Binaries with =ep (all caps enabled) in user directories allow arbitrary file read/write as root. Solution: Check getcap -r on user home dirs and accessible binaries for escalation paths.
#Fail2ban #IptablesIP Issue: Aggressive nmap scans (--min-rate 5000) trigger automated IP bans for ~60-90 seconds. Solution: Use slower scans (-T2/-T3) or single ports. Wait for ban to lift before retrying.

#Jenkins #Groovy Groovy Script Console has direct JVM access to internal APIs: CredentialsProvider.lookupCredentials() extracts all credential types, hudson.util.Secret.decrypt() decrypts Jenkins-encrypted values, Java File I/O via new File() may bypass bash-level permission restrictions.

#Jenkins #Credentials Always enumerate plugin-specific config files (s3explorer.xml, etc.) for encrypted credential storage—multiple credential sets often exist with different permissions/purposes.

#Privesc #Password Password reuse across services/OS accounts is a high-yield enumeration vector—check backup scripts, deployment configs, CI/CD logs for plaintext passwords that may apply to root/admin accounts.

#Groovy #RCE Process output capture: avoid .text immediately after execute()—use consumeProcessOutput(StringBuffer, StringBuffer) + waitFor() pattern instead.

#Groovy #Privesc JVM File I/O (new File().text) may succeed where forked shell commands fail—JVM may inherit elevated permissions or capabilities that subprocess forking doesn't preserve.

#CTF #Methodology Avoid rabbit-hole local privesc enumeration (SUID, sudo -l, capabilities, systemd) if credential/password vectors are available—password reuse is often simpler than kernel exploits or capability abuse.

#AWS #S3 Cross-credential S3 access: different IAM credential sets can have different permissions on same bucket/prefix. Test all harvested credentials against all discovered buckets.

#IMDS #EC2 IMDSv2 token-based queries preferred, but EC2 instances may lack IAM roles entirely—fallback to local credential harvesting if IMDS returns 404. Don't over-invest in IMDS if simpler paths exist.

#SSH #Auth Writing SSH keys via Groovy Java File API is viable privesc path when JVM has file write permissions that forked shells don't—critical for jenkins-to-root lateral movement.

#Docker #AWS #CodeCommit Issue: AWS creds hardcoded in Docker image ENV/RUN layers and CodeCommit dev branch source code -> Solution: docker history --no-trunc reveals ENV vars and RUN args; check all git branches (especially dev) for hardcoded secrets in source commits; second cred set led to S3 bucket with flag.
#AWS #S3 #XSS Issue: S3 bucket used for web asset hosting was publicly writable (no ACL/policy restriction). Vector: attacker uploads malicious JS to bucket overwriting legitimate scripts → XSS on admin panel. Solution: Apply strict bucket policy denying s3:PutObject to public/anonymous; use pre-signed URLs for uploads.
#AWS #S3 #Sensitive-Exposure Issue: Sensitive credentials XLSX file served directly from web root with no auth check — accessible without session. Solution: Never serve sensitive files from web root; use authenticated download endpoints or pre-signed S3 URLs with expiry.
#AWS #S3 #XSS Issue: S3 self-exfil fetch PUT (browser→S3) produced no cookie drop despite clean payload upload. Lessons: (1) Always verify admin bot execution environment FIRST (SSH in, check cron/ps for headless browser) before uploading payload — wasted cycles on exfil channel debugging when the bot may not run JS at all. (2) Backup the ORIGINAL file BEFORE first poison attempt, not after — pulling backup from already-poisoned S3 creates stacked payloads and a dirty restore. (3) Previous session's stale payload in S3 must be identified and cleaned before starting a new session — check S3 asset content before assuming it is clean. (4) VPN listener (Image beacon) unreliable in cloud labs — lab VM typically cannot reach attacker tun0; always prefer self-contained exfil (S3 PUT, DNS-less) as first choice.
#AWS #S3 #XSS Issue: Skipped /opt enumeration before payload deployment — missed Selenium+Chrome headless bot script, wasted cycles debugging JS execution and exfil channel. Solution: ALWAYS check /opt (and /home, /srv) for automation/bot scripts during initial SSH enum BEFORE crafting any client-side payload. Confirm JS execution environment first.
#AWS #S3 #XSS Issue: Appended XHR payload AFTER JS file contents instead of prepending BEFORE. Solution: Always PREPEND cookie-steal payload before legitimate JS content so it executes first, before any framework init that could interfere.
#AWS #S3 #XSS Issue: Wasted 4+ rounds on wrong exfil channels (VPN beacon port 80, Python listener, S3 self-exfil PUT) before landing on correct approach. Solution: When bot automation runs on the target server itself, listener goes ON the server (nc via SSH) and payload points to localhost — not attacker VPN. Check bot script location first to determine correct exfil direction.
#Cognito #AWS #SSRF Issue: Cognito Identity Pool unauth APIs (get-id, get-credentials-for-identity) require NO creds — use --no-sign-request. User Pool Client ID exposed in Cognito Hosted UI URL query string (?client_id=). Auth role unlocks Lambda SSRF -> file:///proc/self/environ leaks Lambda IAM keys -> lateral move to restricted S3 bucket with sensitive PDFs.

