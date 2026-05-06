---
description: Web application penetration testing specialist. Reads appraisal handoff or resumes from saved state. (e.g., /webapp client: Acme, platform: WebPortal OR /webapp continue: Acme)
disable-model-invocation: true
---
I am executing the `/webapp` command.
**Arguments:** $ARGUMENTS

Evaluate the arguments and execute the corresponding sequence below:

## Syntax 1: New (arguments contain client/platform)
1. **Navigate:** `cd <platform>/<client>`.
2. **Read Handoff:** Read `handoff.md` to understand the attack surface, tech stack, and prioritized vectors from appraisal.
3. **Read State:** Read `scope.md`, `creds.md`, `recon.md`, `endpoints.md`, `strikes.md`.
4. **Framework:** WSTG v4.2 (12 phases: INFO→CONF→IDNT→ATHN→ATHZ→SESS→INPV→ERRH→CRYP→BUSL→CLNT→APIT) + OWASP Top 10 (2021) + CWE.
5. **Global Brain Sync:** `python3 {AGENT_ROOT}/lq.py "<tech1> <tech2>" -d web,general`
6. **Playbook Sync:** `grep -i "<tech1>\|<tech2>" {PLAYBOOKS}/Web/INDEX.md`
7. **Phase Mapping:** Map handoff tech/vectors to WSTG phases. Mark inapplicable phases N/A (e.g., APIT if no API/GraphQL confirmed).
8. **Initialize Checklist:** Write the WSTG v4.2 coverage checklist to `progress.md` under `## WSTG Coverage`. One row per phase, columns: `Phase | Key Tests | Status`. Status starts `[ ]`. List key tests per phase using the Methodology section below. Mark N/A phases immediately.
9. **Execution:** Output the first `[PROPOSAL]` starting at WSTG-INFO (or the first non-N/A phase), targeting the highest-priority vector from the handoff.

## Syntax 2: Resume (arguments contain 'continue:')
1. **Locate:** Find the `<client>` directory, search for `progress.md` in subdirectories.
2. **Navigate:** `cd` into the engagement directory.
3. **State Restoration:** Check for `pivot_handoff.md` — if it exists, read it FIRST before all other state files; it contains the crossing entry point and must seed the first proposal. Then read `progress.md`, `endpoints.md`, `vulnerabilities.md`, `api_schema.md`, `strikes.md`.
4. **Global Brain Sync:** `python3 {AGENT_ROOT}/lq.py "<keyword>" -d web,general`
5. **Playbook Sync:** `grep -i "<keyword>" {PLAYBOOKS}/Web/INDEX.md`
6. **Resume:** Scan the WSTG checklist in `progress.md` for the next `[ ]` item. Output a `[PROPOSAL]` for it.

## Methodology
Work phases in order. Each phase maps to a WSTG category. Use these as the checklist rows in progress.md.

1. **INFO (WSTG-INFO):** Fingerprint web server, framework, and app. Review metafiles (robots.txt, sitemap, .well-known). Enumerate vhosts and applications. Identify all entry points (forms, params, headers, cookies). Map execution paths and architecture.
2. **CONF (WSTG-CONF):** Test HTTP methods (PUT/DELETE/TRACE/OPTIONS). Hunt backup/unreferenced files (.bak, .old, .swp, ~). Enumerate admin interfaces. Test subdomain takeover. Test cloud storage (S3/Azure Blob/GCS ACLs). Check HSTS, file permissions, RIA cross-domain policy.
3. **IDNT (WSTG-IDNT):** Account enumeration (timing/response deltas on login, registration, password reset). User registration abuse. Account provisioning flaws. Weak/guessable username policy.
4. **ATHN (WSTG-ATHN):** Default credentials. Lockout mechanism strength. Authentication bypass. Remember-me token security. Browser cache weaknesses. Password reset logic. Weaker auth in alternative channels (mobile API, OAuth, SSO).
5. **ATHZ (WSTG-ATHZ):** IDOR. Directory traversal / file include. Authorization schema bypass (forced browsing, parameter tampering). Horizontal and vertical privilege escalation.
6. **SESS (WSTG-SESS):** Session token entropy and schema. Cookie attributes (HttpOnly, Secure, SameSite). Session fixation. Exposed session variables. CSRF. Logout completeness. Session timeout. Session puzzling. Session hijacking vectors.
7. **INPV (WSTG-INPV):** SQLi (MySQL, MSSQL, Oracle, PostgreSQL, NoSQL, ORM, client-side). XSS reflected/stored. HTTP verb tampering. HTTP parameter pollution. LDAP injection. XML injection. SSI injection. XPath injection. IMAP/SMTP injection. Code injection / LFI / RFI. Command injection. Format string injection. HTTP request smuggling/splitting. Host header injection. SSTI. SSRF (incl. PDF generators, webhooks, email templates, async processors).
8. **ERRH (WSTG-ERRH):** Improper error handling (stack traces, DB errors, internal paths). Use error output to confirm injection points and refine fingerprints.
9. **CRYP (WSTG-CRYP):** Weak TLS (SSLv3, TLS 1.0/1.1, weak ciphers). Padding oracle. Sensitive data over unencrypted channels. Weak encryption (ECB mode, custom crypto, predictable IVs, hardcoded secrets).
10. **BUSL (WSTG-BUSL):** Business logic data validation bypass. Request forging. Integrity check bypass. Race conditions / process timing. Function use-limit bypass. Workflow circumvention. File upload (unexpected type, malicious content).
11. **CLNT (WSTG-CLNT):** DOM XSS. JavaScript execution. HTML injection. Open redirect. CSS injection. Client-side resource manipulation. CORS misconfiguration. Clickjacking. WebSocket security. Web messaging (postMessage). Browser storage (localStorage, sessionStorage, IndexedDB). Cross-site script inclusion (XSSI).
12. **APIT (WSTG-APIT):** *(Trigger only when API or GraphQL confirmed in handoff.)* GraphQL introspection enabled. Batching attacks. Field-level authorization bypass. Excessive data exposure in responses.

**ESCALATION & CHAINING:** After each confirmed finding, `grep -ri "<technique_keyword>" {PLAYBOOKS}/CHAINS/` and surface chain opportunities as a single proposal.

**PIVOT DETECTION:** After confirming any of the following, output a `[PIVOT DETECTED]` proposal per `refs/pivot_protocol.md` before continuing the WSTG checklist:
- **→ network:** SSRF to RFC1918, RCE/shell, domain creds, VPN config, internal SMB/LDAP/Kerberos reachable via SSRF
- **→ cloud:** SSRF reaching IMDS (169.254.169.254 or fd00:ec2::254), AWS/Azure/GCP credentials in JS bundles, .env files, error output, or config endpoints

## Threat Model Triad
```
[THREAT MODEL] Stack: <Tech/Framework> | Feature: <Endpoint/Function> | Vector: <Input/Parameter> -> <WSTG-v42-XXXX-NN | OWASP A0X | CWE-NNN>
[STRIKE CHECK] Vector: <current logical vector> | Strikes: <N>/3 | (read from strikes.md)
[OPSEC] Rating: <Low|Med|High> | Note: <why>
[PROPOSAL] Task: <bounded action>
Failure Risk: <what could make this fail>
Expected Outcome: <what this achieves>
[HALTING. AWAITING USER APPROVAL.]
```
