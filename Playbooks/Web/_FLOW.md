# Web / API Attack Decision Flow

> Match your **current state** to a starting point below. Follow the techniques listed, then advance to the next starting point based on what you gain.

## 1. Black-Box (URL Only)
**Signal:** Have target URL but no internal knowledge or credentials

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| DNS Zone Transfer → Vhost Discovery | SQLi_to_RCE.md | DNS server accessible, AXFR allowed | Internal vhosts, subdomains |
| Git Source Code Disclosure | API_WebShell.md | Dev Git platform found (Gogs/Gitea) | Source code, API endpoints, secrets |
| Credential Extraction from Git Commit History | API_WebShell.md | Public or readable Git repo (Bitbucket/GitHub/GitLab) | Hardcoded AWS keys, API credentials, passwords, OAuth tokens; AWS account ID enumeration |
| GraphQL Introspection Query | GraphQL.md | GraphQL endpoint found | Full API schema, all queries/mutations |
| SSRF via PDF Generation / HTML Injection | SSRF.md | PDF/image generation endpoint | Internal service access, file read |
| Blind SSRF via Webhook/URL | SSRF.md | URL parameter or webhook input | Internal network mapping via OOB |
| Spring Boot Actuator Recon → SSRF Discovery | SSRF.md | Java app with /actuator exposed | Env vars (bucket names, secrets) + proxy endpoint revealing SSRF surface |
| Certificate Transparency (crt.sh) + GitHub CNAME History Subdomain Recon | SSRF.md | Target domain; no creds required | Hidden/historical subdomains and internal hostnames |
| Nested Subdomain Pattern Fuzzing via ffuf | SSRF.md | Known subdomain prefix pattern | Additional live subdomains at deeper nesting levels |

→ **Next:** Endpoints discovered → [2. Unauthenticated Endpoints]. Creds found (from git history) → pivot to cloud/infrastructure attacks. GraphQL schema → [5. GraphQL].

---

## 2. Unauthenticated Endpoints Found
**Signal:** Have accessible endpoints without authentication; testing for injection and logic flaws

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| Boolean SQLi → File Path → RCE | SQLi_to_RCE.md | Confirmed SQLi + MySQL backend | RCE via webshell |
| Stored PHP Webshell via API | API_WebShell.md | Unsanitized API + file-write endpoint | RCE via stored webshell |
| OS Command Injection | Command_Injection.md | Input passed to system commands | RCE |
| SSTI Detection via Math Expressions | SSTI.md | User input reflected in template output | Template engine identification |
| XXE Injection | Command_Injection.md | XML parser accepts external entities | File read, SSRF, data exfil |
| Reflected XSS via URL Parameter | XSS.md | Unescaped user input in response | Session theft, phishing |
| LFI / Path Traversal | Command_Injection.md | File path parameter | Source code, config files, /etc/passwd |
| Basic SSRF to Internal Services | SSRF.md | URL/IP parameter | Internal service access |
| Capital: Unauthenticated Redis Access | API_WebShell.md | Network access to Redis 6379; no auth required | Direct DB access; extraction of secrets, sessions, credentials |
| OpenAPI / Swagger Documentation Endpoint Discovery via ffuf | GraphQL.md | Web app with undocumented REST API | Full route map, parameters, auth requirements |
| Client-Side Authentication Validation Bypass via Direct API | API_WebShell.md | Registration/auth enforced only in JS; direct API accessible | Registered account bypassing domain/invite restriction |
| vAPI: Sequential ID Enumeration (BOLA) | API_WebShell.md | REST API with numeric ID params | Unauthorized user data access |
| Capital: BFLA via FFUF Endpoint Fuzzing | API_WebShell.md | API with bearer token auth; hidden admin endpoints | Hidden admin endpoints accessible as unprivileged user |
| ParaBank: User Enumeration via FFUF + Loan History Leak | API_WebShell.md | Unauthenticated REST API with sequential numeric IDs | Leaked user accounts, loan histories, account balances |
| Go Registration TOCTOU → NULL Permission Admin JWT | Race_Condition.md | Go app; two-step non-atomic registration (CreateUser + UpdatePermissions); PermissionAdmin = 0 | Admin JWT via NULL→0 zero-value race; full admin access |

→ **Next:** SQLi → [4]. SSTI detected → [6. SSTI Confirmed]. RCE → post-exploitation. Auth obtained → [3]. LLM chatbot found → [9. LLM Chatbot].
| Full chain: [[go-registration-race-null-admin]] — source code review reveals non-atomic registration → asyncio/aiohttp concurrent race → NULL-permission admin JWT → flag endpoint access |

---

## 3. Authenticated User Access
**Signal:** Have valid credentials or session token for the application

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| Stored PHP Webshell via API | API_WebShell.md | Auth'd API endpoint + file-write | RCE via webshell |
| Boolean SQLi (auth'd endpoints) | SQLi_to_RCE.md | SQLi in auth'd parameters | Data extraction, potential RCE |
| JWT None Algorithm Attack | JWT_Attacks.md | JWT-based auth, weak validation | Auth bypass, privilege escalation |
| JWT Algorithm Confusion HS256/RS256 | JWT_Attacks.md | JWT with RS256 + public key known | Forge tokens as any user |
| JWT Secret Brute Force | JWT_Attacks.md | JWT with HS256, weak secret | Forge tokens |
| JWT kid Header Injection | JWT_Attacks.md | JWT with kid parameter | Auth bypass via path traversal |
| Stored XSS via User Input | XSS.md | User input stored and rendered | Admin session theft, ATO |
| vAPI: Stored XSS via Note Endpoint | XSS.md | Note API stores unsanitized HTML; text/html response | Stored XSS in admin/team browsers |
| Blind XSS via Contact/Ticket | XSS.md | Input rendered in admin panel | Admin cookie exfil |
| Capital: Excessive Data Exposure → CC Harvesting | API_WebShell.md | Profile/payment endpoint returns CC data; no authz check | Extracted CC data (name, number, CVC, expiry); unauthorized purchases on victim cards |
| ParaBank: Unrestricted Loan Request Creation | API_WebShell.md | Authenticated session; loan endpoint accepts any amount | Arbitrary loan amounts approved; financial fraud/theft |
| ParaBank: Transfer Funds via API | API_WebShell.md | Authenticated session; transfer endpoint allows unlimited transfers | Direct fund transfers to attacker account; financial theft |
| GraphQL Batching Attack | GraphQL.md | GraphQL endpoint, rate-limited | Brute force bypass |
| DOM-Based XSS | XSS.md | Client-side JS processes URL params | Session theft without server interaction |

→ **Next:** JWT forged → admin access. RCE → post-exploitation. SQLi → [4]. DB creds found → [4a]. CC data exposed → credential harvesting attack.
| Full chain: [[parabank-bola-account-takeover-fraud]] — user enumeration via FFUF → unauthenticated account takeover → loan creation + fund transfer → financial theft |

---

## 4a. Database Credentials Obtained
**Signal:** Valid DB credentials found (app config, SQLi dump, credential reuse); direct DB access confirmed

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| PostgreSQL pgcrypto Heap Overflow → RCE (CVE-2026-2005) | SQLi_to_RCE.md | Postgres ≤ 17.7/16.11/15.15/14.20/18.1 + CREATE priv | OS RCE as postgres via COPY TO PROGRAM |
| PostgreSQL Credential Interception via tcpdump + tcpkill | SQLi_to_RCE.md | Network access to port 5432 + cap_net_raw + no TLS | Plaintext PostgreSQL credentials |
| PostgreSQL COPY FROM PROGRAM RCE (Superuser) | SQLi_to_RCE.md | psql access with superuser or pg_execute_server_program | OS reverse shell as postgres user |

→ **Next:** RCE achieved → post-exploitation (privesc via Linux/Windows flows).
| Full chain: [[postgres-pgcrypto-rce]] — pgcrypto heap overflow → CurrentUserId overwrite → superuser → OS RCE |
| Full chain: [[postgres-sniff-host-escape]] — tcpdump+tcpkill cred sniff → COPY FROM PROGRAM RCE → core_pattern container escape → host shell |

---

## 4. SQL Injection Confirmed
**Signal:** SQLi verified (boolean, time-based, or error-based)

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| Boolean SQLi → Extract File Path → RCE | SQLi_to_RCE.md | MySQL backend + writable web dir | Webshell via extracted paths |

→ **Next:** RCE achieved → post-exploitation (privesc via Linux/Windows flows).

---

## 5. GraphQL Endpoint Found
**Signal:** GraphQL endpoint identified, schema available or partially recovered

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| GraphQL Introspection Query | GraphQL.md | Introspection enabled (default) | Full schema |
| GraphQL Batching Attack | GraphQL.md | Batching supported | Rate limit bypass for brute force |
| GraphQL Injection / Query Manipulation | GraphQL.md | Schema known, circular types | DoS, IDOR, unauthorized data access |

→ **Next:** IDOR found → data extraction. Auth bypass → [3].

---

## 5a. Authentication Brute Force / Rate Limit Bypass
**Signal:** Login endpoint lacks rate limiting or has bypasses; ready to test credential brute force or OTP enumeration

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| vAPI: Credential Stuffing via ffuf Pitchfork | API_WebShell.md | Email/password wordlists + no rate limiting | Valid user credentials; authenticated session |
| vAPI: Rate Limiting Bypass via OTP Enumeration | API_WebShell.md | OTP verification endpoint + 4-6 digit range | 2FA bypass; full account takeover |
| vAPI: Version Downgrade Attack | API_WebShell.md | Legacy API version (v1) lacks rate limiting vs v2 | Unrestricted brute force on legacy endpoint |
| Capital: Brute Force Authentication via Credential Hints | API_WebShell.md | Target user(s) identified + profile/post hints + low-privilege account | Valid credentials for target user; complete account takeover |
| Capital: Improper Asset Management (Version Enumeration) | API_WebShell.md | Known API version + access to endpoint | Accessible retired API versions; bypass current security | 

→ **Next:** Valid creds obtained → [3. Authenticated Access]. 2FA bypassed → account takeover → [3]. Version downgrade found → test legacy endpoint attacks.

---

## 5b. CORS or Authorization Misconfiguration
**Signal:** CORS headers misconfigured or authorization checking missing

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| vAPI: CORS Misconfiguration Exploitation | API_WebShell.md | API returns Access-Control-Allow-Origin: * + Credentials: true | Unauthorized access from attacker domain; XSS + credential theft |

→ **Next:** Sensitive data accessed → lateral movement. XSS combined with stored payload → [3].

---

## 6. SSTI Confirmed
**Signal:** Template injection detected via math expression (e.g., {{7*7}} returns 49)

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| Jinja2 SSTI to RCE | SSTI.md | Python/Flask backend confirmed | RCE |
| Twig SSTI to RCE | SSTI.md | PHP/Symfony backend confirmed | RCE |
| Freemarker SSTI to RCE | SSTI.md | Java backend confirmed | RCE |

→ **Next:** RCE achieved → post-exploitation.

---

## 7. Deserialization Vector Found
**Signal:** Serialized objects in cookies, parameters, or API bodies (Java rO0AB, PHP O:, Python pickle)

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| Java Deserialization via ysoserial | Deserialization.md | Java app + gadget chain library | RCE |
| PHP Object Injection via unserialize | Deserialization.md | PHP app + exploitable magic methods | RCE, file read/write |
| Python Pickle RCE | Deserialization.md | Python app + pickle.loads on input | RCE |
| .NET ViewState Deserialization | Deserialization.md | ASP.NET + known machine key | RCE |

→ **Next:** RCE achieved → post-exploitation.

---

## 8. SSRF Confirmed
**Signal:** Server makes requests to attacker-controlled URL or internal addresses

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| Basic SSRF to Internal Services | SSRF.md | SSRF on URL parameter | Internal service access |
| SSRF to Cloud Metadata | SSRF.md | Target on cloud (AWS/GCP/Azure) | Cloud credentials (IAM role keys) |
| Blind SSRF via OOB | SSRF.md | No direct response, OOB possible | Internal network mapping |

→ **Next:** Cloud creds → Cloud/_FLOW.md. Internal access → lateral movement.

---

## 9. LLM Chatbot / AI Assistant Found
**Signal:** Application exposes a chat interface, AI assistant, or automated Q&A backed by an LLM; user input is processed by a model

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| LLM Chatbot Prompt Injection / Jailbreak | Command_Injection.md | LLM-backed endpoint; arbitrary text input | System prompt disclosure, flag/secret exfil, instruction override |

→ **Next:** System prompt leaked → flag/credential extraction. Tool-call injection → SSRF or RCE if model has tool access.
| Full chain: [[needle-haystack-subdomain-llm]] — crt.sh recon → nested subdomain fuzzing → OpenAPI discovery → client-side auth bypass → LLM chatbot prompt injection → flag exfil |
