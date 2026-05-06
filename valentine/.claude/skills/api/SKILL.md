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
4. **Framework:** OWASP API Security Top 10 (2023) + CWE.
5. **Global Brain Sync:** `python3 {AGENT_ROOT}/lq.py "<tech1> <tech2>" -d web,general`
6. **Playbook Sync:** `grep -i "<tech1>\|<tech2>" {PLAYBOOKS}/Web/INDEX.md`
7. **Schema Parse:** If a Swagger/OpenAPI file or Postman collection is in scope, parse it immediately:
   - Extract all endpoints (method + path + parameters) into `endpoints.md`
   - Extract auth schemes (Bearer/JWT, API Key, OAuth2 flows, mTLS) into `api_schema.md`
   - Note versioning (v1/v2/beta) and base URLs
   - Flag: object ID parameters (BOLA candidates), URL-accepting parameters (SSRF candidates), admin/internal paths (BFLA candidates), batch/pagination parameters (API4 candidates)
8. **Category Mapping:** Map handoff tech/vectors to OWASP API Top 10 categories. Mark inapplicable categories N/A (e.g., API10 if no third-party integrations documented; API6 if no multi-step business flows in schema).
9. **Initialize Checklist:** Write the OWASP API Top 10 (2023) coverage checklist to `progress.md` under `## API Coverage`. One row per category, columns: `Category | Key Tests | Status`. Status starts `[ ]`. Mark N/A categories immediately.
10. **Execution:** Output the first `[PROPOSAL]` starting at API1-BOLA (or the highest-priority vector from the handoff), using schema-derived endpoints as targets — not generic paths.

## Syntax 2: Resume (arguments contain 'continue:')
1. **Locate:** Find the `<client>` directory, search for `progress.md` in subdirectories.
2. **Navigate:** `cd` into the engagement directory.
3. **State Restoration:** Check for `pivot_handoff.md` — if it exists, read it FIRST before all other state files; it contains the crossing entry point and must seed the first proposal. Then read `progress.md`, `api_schema.md`, `endpoints.md`, `vulnerabilities.md`, `strikes.md`.
4. **Global Brain Sync:** `python3 {AGENT_ROOT}/lq.py "<keyword>" -d web,general`
5. **Playbook Sync:** `grep -i "<keyword>" {PLAYBOOKS}/Web/INDEX.md`
6. **Resume:** Scan the API coverage checklist in `progress.md` for the next `[ ]` item. Output a `[PROPOSAL]` for it.

## Methodology
Work categories in order. Each maps to an OWASP API Security Top 10 (2023) risk. Use these as checklist rows in progress.md.

1. **BOLA (API1):** For every endpoint with an object ID parameter (path, query, body): substitute IDs across user accounts, try predictable sequences and UUIDs from other sessions, test both direct and indirect object references. Confirm horizontal privilege escalation on read AND write/delete operations.
2. **BROKEN AUTH (API2):** JWT attacks (alg:none, weak secret brute, RS256→HS256 key confusion, expired token acceptance). Test for missing auth on endpoints (remove Authorization header entirely). API key exposure in responses, logs, or error output. OAuth2 flow abuse (open redirect in redirect_uri, authorization code interception). Token replay and reuse across sessions.
3. **BROKEN OBJECT PROPERTY AUTH (API3):** Mass assignment — send unexpected/privileged fields in request bodies (role, is_admin, price, status, verified). Excessive data exposure — compare full response schema against what the authenticated user is authorized to see; flag server-side fields that should be filtered but are returned.
4. **RESOURCE CONSUMPTION (API4):** Rate limiting absent or bypassable (IP rotation, X-Forwarded-For spoofing, header manipulation). Pagination abuse (request maximum page size, unbounded query parameters). Batch endpoint size limits. File upload size and type limits. GraphQL query depth/complexity (test shallow depth only — no DoS).
5. **BFLA (API5):** Access admin or elevated-function endpoints using standard user tokens. HTTP method tampering on restricted endpoints (GET→PUT→DELETE→PATCH). Discover hidden admin/internal paths (`/admin`, `/internal`, `/management`, `/v2/admin`, `/debug`). Test all role tiers available in scope against every restricted endpoint.
6. **BUSINESS FLOW ABUSE (API6):** Multi-step workflow bypass (skip required steps, replay completed steps, reorder calls). Race conditions in critical flows (purchase, coupon redemption, account creation — use concurrent requests). Quantity/value manipulation (negative quantities, zero-price, integer overflow/underflow). Enforce-once logic bypass (single-use tokens, one-time discounts, limited-use invites).
7. **SSRF (API7):** Any endpoint accepting a URL parameter. Webhook URL validation (does the server fetch arbitrary URLs?). Import/export via URL, PDF/image generation from URL. Test for RFC1918 access (10.x, 172.16-31.x, 192.168.x) and IMDS (169.254.169.254, fd00:ec2::254). DNS rebinding candidates.
8. **SECURITY MISCONFIGURATION (API8):** CORS misconfiguration (wildcard or reflected Origin). Verbose error messages (stack traces, DB errors, internal paths). Unnecessary HTTP methods enabled. Missing security headers (HSTS, X-Content-Type-Options, etc.). API documentation exposed in production (`/docs`, `/swagger-ui`, `/redoc`, `/openapi.json`, `/api-docs`). Default or weak credentials on management interfaces. Weak TLS (ciphers, protocol version, certificate validity).
9. **INVENTORY (API9):** Older API versions accessible alongside current (test `/v1/` paths when `/v3/` is current; test `/beta/`, `/internal/`, `/legacy/`). Undocumented/shadow endpoints not in the provided schema (fuzz common REST patterns, check JS bundles or mobile app binaries for route leaks). Staging/debug endpoints reachable in production.
10. **UNSAFE CONSUMPTION (API10):** Identify all third-party API integrations from schema and docs. Test for injection in data returned from external sources and consumed without sanitization. Webhook chain abuse. Verify SSL/TLS is enforced on all outbound third-party connections (downgrade test where applicable).

**ESCALATION & CHAINING:** After each confirmed finding, `grep -ri "<technique_keyword>" {PLAYBOOKS}/CHAINS/` and surface chain opportunities as a single proposal.

**HANDOFF TRIGGERS:**

After completing manual API testing, offer these next steps:

**If BOLA/IDOR suspected but not fully verified:**
```
Run: /apiTesting swagger.json
Purpose: Automated baseline scan (all OWASP Top 10)
Context prepared: endpoints.md, creds.md, api_schema.md
Result: Will identify all BOLA/IDOR candidates + other categories
```

**If BOLA/IDOR confirmed:**
```
Run: /idorDeep swagger.json --from-api
Purpose: Deep IDOR methodology (encoding tricks, parameter pollution)
Context prepared: progress.md, vulnerabilities.md, creds.md, endpoints.md
Result: Sophisticated IDOR patterns with exploitation details
```

**If all manual API testing complete:**
```
Run: /apiTesting swagger.json (full suite)
Purpose: Catch automated findings your manual testing may have missed
Context prepared: endpoints.md, creds.md, api_schema.md
```

**PIVOT DETECTION:** After confirming any of the following, output a `[PIVOT DETECTED]` proposal per `refs/pivot_protocol.md` before continuing the API checklist:
- **→ network:** SSRF reaching RFC1918 (API7), domain/SMB credentials in responses, internal hostnames or subnets exposed in error output
- **→ cloud:** SSRF reaching IMDS (169.254.169.254 or fd00:ec2::254), AWS/Azure/GCP credentials in API responses or verbose errors

## Threat Model Triad
```
[THREAT MODEL] Stack: <Tech/Framework> | Feature: <Endpoint/Method> | Vector: <Parameter/Header/Body> -> <OWASP API Top 10 Category | CWE-NNN>
[STRIKE CHECK] Vector: <current logical vector> | Strikes: <N>/3 | (read from strikes.md)
[OPSEC] Rating: <Low|Med|High> | Note: <why>
[PROPOSAL] Task: <bounded action>
Failure Risk: <what could make this fail>
Expected Outcome: <what this achieves>
[HALTING. AWAITING USER APPROVAL.]
```
