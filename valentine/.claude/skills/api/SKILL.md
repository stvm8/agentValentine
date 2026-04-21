---
description: API penetration testing specialist. Reads appraisal handoff or resumes from saved state. (e.g., /api client: Acme, platform: MobileAPI OR /api continue: Acme)
disable-model-invocation: true
---
I am executing the `/api` command.
**Arguments:** $ARGUMENTS

Evaluate the arguments and execute the corresponding sequence below:

## Syntax 1: New (arguments contain client/platform)
1. **Navigate:** `cd <platform>/<client>`.
2. **Read Handoff:** Read `handoff.md` to understand the API surface, authentication mechanisms, and prioritized vectors.
3. **Read State:** Read `scope.md`, `creds.md`, `api_schema.md`, `endpoints.md`, `strikes.md`.
4. **Framework:** OWASP API Security Top 10 (2023).
5. **Global Brain Sync:** `grep -i "<tech1>\|<tech2>" {LEARNINGS}/web.md {LEARNINGS}/general.md`
6. **Playbook Sync:** `grep -i "<tech1>\|<tech2>" {PLAYBOOKS}/Web/INDEX.md`
7. **API Mapping:** Based on handoff vectors, identify priority OWASP API categories (API1-API10).
8. **Execution:** Output the first `[PROPOSAL]` targeting the highest-priority API vector.

## Syntax 2: Resume (arguments contain 'continue:')
1. **Locate:** Find the `<client>` directory, search for `progress.md` in subdirectories.
2. **Navigate:** `cd` into the engagement directory.
3. **State Restoration:** Read `progress.md`, `api_schema.md`, `endpoints.md`, `vulnerabilities.md`, `strikes.md`.
4. **Global Brain Sync:** `grep -i "<keyword>" {LEARNINGS}/web.md {LEARNINGS}/general.md`
5. **Playbook Sync:** `grep -i "<keyword>" {PLAYBOOKS}/Web/INDEX.md`
6. **Resume:** Output a `[PROPOSAL]` for the next untested API category or endpoint.

## Methodology
1. **BOLA (API1):** Test every endpoint with mismatched user IDs, tampered object references, GUID enumeration.
2. **AUTH FLAWS (API2):** Token manipulation, missing auth on endpoints, JWT attacks (alg:none, key confusion, brute).
3. **MASS ASSIGNMENT (API3):** Send unexpected fields in request bodies, check for property injection, role escalation via hidden params.
4. **RESOURCE CONSUMPTION (API4):** Pagination abuse, unbounded queries, GraphQL depth/complexity attacks (do NOT cause DoS).
5. **FUNCTION-LEVEL AUTH (API5):** Access admin endpoints with user tokens, method tampering (GET->PUT->DELETE), endpoint discovery via path manipulation.
6. **SSRF (API6):** URL parameters, webhook configs, file import features, redirect abuse.
7. **SECURITY MISCONFIGURATION (API7):** CORS, verbose errors, debug endpoints, default creds, missing rate limiting.
8. **INJECTION (API8):** SQLi, NoSQLi, command injection in API parameters, headers, and JSON bodies.
9. **ASSET MANAGEMENT (API9):** Deprecated API versions (`/v1/`, `/beta/`, `/internal/`), undocumented endpoints, shadow APIs.
10. **UNSAFE CONSUMPTION (API10):** Third-party API interactions, SSRF via integrations, webhook chain abuse.

## Threat Model Triad
```
[THREAT MODEL] Stack: <Tech/Framework> | Feature: <API Endpoint/Method> | Vector: <Parameter/Header/Body> -> <OWASP API/CWE Deduction & Chain Potential>
[STRIKE CHECK] Vector: <current logical vector> | Strikes: <N>/3 | (read from strikes.md)
[PROPOSAL] Task: <bounded action>
Expected Outcome: <what this achieves>
[HALTING. AWAITING USER APPROVAL.]
```
