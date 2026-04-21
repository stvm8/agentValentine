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
4. **Framework:** OWASP Web Application Security Top 10 (2021) + CWE.
5. **Global Brain Sync:** `grep -i "<tech1>\|<tech2>" {LEARNINGS}/web.md {LEARNINGS}/general.md`
6. **Playbook Sync:** `grep -i "<tech1>\|<tech2>" {PLAYBOOKS}/Web/INDEX.md`
7. **OWASP Mapping:** Based on handoff vectors, identify priority OWASP categories (A01-A10).
8. **Execution:** Output the first `[PROPOSAL]` targeting the highest-priority vector from the handoff.

## Syntax 2: Resume (arguments contain 'continue:')
1. **Locate:** Find the `<client>` directory, search for `progress.md` in subdirectories.
2. **Navigate:** `cd` into the engagement directory.
3. **State Restoration:** Read `progress.md`, `endpoints.md`, `vulnerabilities.md`, `api_schema.md`, `strikes.md`.
4. **Global Brain Sync:** `grep -i "<keyword>" {LEARNINGS}/web.md {LEARNINGS}/general.md`
5. **Playbook Sync:** `grep -i "<keyword>" {PLAYBOOKS}/Web/INDEX.md`
6. **Resume:** Output a `[PROPOSAL]` for the next untested OWASP category or endpoint from progress.md.

## Methodology
1. **INJECTION TESTING (A03):** SQLi, XSS (reflected/stored/DOM), SSTI, command injection, header injection on identified input vectors.
2. **ACCESS CONTROL (A01):** IDOR, privilege escalation (horizontal/vertical), forced browsing, path traversal.
3. **AUTH FLAWS (A07):** Session management, JWT attacks, password reset logic, MFA bypass, credential stuffing detection.
4. **BUSINESS LOGIC:** Rate limiting bypass, workflow abuse, race conditions, price manipulation.
5. **SSRF & 2ND ORDER (A10):** Server-side request forgery, PDF generators, email templates, webhooks, async processors.
6. **SECURITY MISCONFIGURATION (A05):** Verbose errors, debug endpoints, default creds, CORS misconfig, missing security headers.
7. **CRYPTOGRAPHIC FAILURES (A02):** Weak TLS, hardcoded secrets, insecure token generation.
8. **ESCALATION & CHAINING:** Chain low-severity findings upward for maximum impact.

## Threat Model Triad
```
[THREAT MODEL] Stack: <Tech/Framework> | Feature: <Endpoint/Function> | Vector: <Input/Parameter> -> <OWASP/CWE Deduction & Chain Potential>
[STRIKE CHECK] Vector: <current logical vector> | Strikes: <N>/3 | (read from strikes.md)
[PROPOSAL] Task: <bounded action>
Expected Outcome: <what this achieves>
[HALTING. AWAITING USER APPROVAL.]
```
