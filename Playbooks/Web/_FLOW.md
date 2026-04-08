# Web / API Attack Decision Flow

> Match your **current state** to a starting point below. Follow the techniques listed, then advance to the next starting point based on what you gain.

## 1. Black-Box (URL Only)
**Signal:** Have target URL but no internal knowledge or credentials

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| DNS Zone Transfer → Vhost Discovery | SQLi_to_RCE.md | DNS server accessible, AXFR allowed | Internal vhosts, subdomains |
| Git Source Code Disclosure | API_WebShell.md | Dev Git platform found (Gogs/Gitea) | Source code, API endpoints, secrets |
| GraphQL Introspection Query | GraphQL.md | GraphQL endpoint found | Full API schema, all queries/mutations |
| SSRF via PDF Generation / HTML Injection | SSRF.md | PDF/image generation endpoint | Internal service access, file read |
| Blind SSRF via Webhook/URL | SSRF.md | URL parameter or webhook input | Internal network mapping via OOB |

→ **Next:** Endpoints discovered → [2. Unauthenticated Endpoints]. Creds found → [3. Authenticated User]. GraphQL schema → [5. GraphQL].

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

→ **Next:** SQLi → [4]. SSTI detected → [6. SSTI Confirmed]. RCE → post-exploitation. Auth obtained → [3].

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
| Blind XSS via Contact/Ticket | XSS.md | Input rendered in admin panel | Admin cookie exfil |
| GraphQL Batching Attack | GraphQL.md | GraphQL endpoint, rate-limited | Brute force bypass |
| DOM-Based XSS | XSS.md | Client-side JS processes URL params | Session theft without server interaction |

→ **Next:** JWT forged → admin access. RCE → post-exploitation. SQLi → [4].

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
