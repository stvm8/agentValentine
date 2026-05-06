---
description: Methodical deep-dive IDOR/BFLA testing with encoding tricks, parameter manipulation, and context-dependent failure detection (e.g., /idorDeep swagger.json --from-apiTesting)
disable-model-invocation: true
---

I am executing the `/idorDeep` command.
**Arguments:** $ARGUMENTS

## Entry Points

### Entry 1: From `/apiTesting` (BOLA/IDOR found)
```
/idorDeep swagger.json --from-apiTesting
```
**Context provided by `/apiTesting`:**
- `vulnerabilities.md` — BOLA/IDOR findings from automated tests
- `endpoints.md` — All endpoints from swagger
- `creds.md` — Attacker + victim tokens already acquired
- `api_schema.md` — Auth schemes and ID parameter locations

**Your action:** Read these files, parse findings, skip Step 1-2, jump to Step 3.

### Entry 2: From `/api` (manual testing found IDOR)
```
/idorDeep swagger.json --from-api
```
**Context provided by `/api`:**
- `progress.md` — What was tested, what failed, current findings
- `vulnerabilities.md` — Manual findings including IDOR candidates
- `creds.md` — Attacker + victim tokens + roles
- `endpoints.md` — Endpoints with parameter details
- `api_schema.md` — Auth context

**Your action:** Read these files, understand manual findings, enhance with deep methodology.

### Entry 3: Standalone (fresh IDOR testing)
```
/idorDeep swagger.json --interactive
```
**Your action:** Run full workflow from scratch (all 7 steps).

---

## Workflow — Execute based on entry point

### Step 1: Account & Token Setup (skip if --from-apiTesting or --from-api)

Ask user:
> "I need test accounts to perform IDOR testing. Provide:
> 1. **Attacker account** (username/password OR token)
> 2. **Victim account** (username/password OR token)
> 3. **Admin account** (optional, for vertical escalation testing)
>
> OR provide pre-acquired tokens:
> - attacker_token = <token>
> - victim_token = <token>
> - admin_token = <token> (optional)"

If credentials provided: Acquire tokens via login endpoint (from swagger).
If tokens provided: Inject directly into environment.

Create `creds.md`:
```markdown
## Authentication Context

| Account | Token | User ID | Roles |
|---------|-------|---------|-------|
| Attacker | <token> | <id> | <roles> |
| Victim | <token> | <id> | <roles> |
| Admin | <token> | <id> | <roles> |
```

Store tokens in `./generated/idor.environment.json` for injection.

### Step 2: Feature Discovery (skip if --from-apiTesting or --from-api)

Parse swagger for ID parameters:
```bash
cat <swagger-path> | jq '.paths[] | select(.parameters? | map(select(.name | contains("id"))))'
```

Extract all endpoints that:
- Accept ID parameters (path, query, body)
- Modify or return data (POST, PUT, PATCH, DELETE, GET)
- Are NOT `/admin/*` or `/internal/*` (test separately later)

Create `endpoints.md`:
```markdown
## Exploitable Endpoints

| Endpoint | Method | ID Parameter | ID Type | Data Returned |
|----------|--------|--------------|---------|---|
| /users/{id} | GET | path: id | numeric | user profile |
| /users/{id}/profile | PUT | path: id | numeric | full user object |
| /users/{id}/settings | PATCH | path: id | numeric | settings object |
| /resources/{id} | GET | path: id | UUID | resource data |
| /export?user_id=X | GET | query: user_id | numeric | export file |
```

### Step 3: Traffic Capture & Request Extraction

Ask user:
> "Provide a sample request for IDOR testing. You can:
> 1. Copy-paste a curl command (with token)
> 2. Paste raw HTTP request
> 3. Provide endpoint + token (I'll construct it)
>
> Example:
> ```
> curl -H "Authorization: Bearer TOKEN" http://api.target.com/users/123/profile
> ```"

Parse the request:
```
Extracted:
- Endpoint: /users/{id}/profile
- Method: GET
- ID parameter: 123 (in path)
- Auth header: Authorization: Bearer <attacker_token>
- Current user ID: 123
```

### Step 4: Horizontal Escalation Testing (Access peer-level resources)

Test 6 ID manipulation techniques on the extracted endpoint:

#### 4a — Direct ID Swap (baseline)
```
Replace 123 with victim_id in the request
GET /users/124/profile
Expected: Either access granted (IDOR) or 403 (protected)
```

#### 4b — Numeric ID Sequences & Prediction
```
Try sequential IDs: 122, 124, 125, 126, 200, 1, 999, 10000
Test ranges around victim_id
Document which IDs return data
```

#### 4c — Encoding Tricks (if ID is encoded in response)
```
If victim_id = 42, try:
- Base64: NDI=
- Hex: 2a
- URL-encoded: %34%32
- Double URL-encoded: %25%33%34%25%33%32
- Decimal: 042

Example: GET /users/NDI=/profile
```

#### 4d — UUID Prediction & Collision
```
If ID type is UUID:
- Swap victim UUID directly
- Try sequential UUID prefixes (UUID v1 pattern)
- Test nil UUID (00000000-0000-0000-0000-000000000000)
- Try common patterns: UUID-1, UUID-2, admin-uuid

Example: GET /users/550e8400-e29b-41d4-a716-446655440000/profile
```

#### 4e — Parameter Pollution & Nesting
```
Try multiple ID parameters in same request:
- GET /users/123/profile?victim_id=124
- GET /users/123/profile?id=124
- POST body: { "id": 123, "victim_id": 124 }
- Nested: { "user": { "id": 124 } }

Also try HTTP method switching on same endpoint:
- GET /users/124/profile (read)
- POST /users/124/profile (create/update)
- PATCH /users/124/profile (partial update)
- DELETE /users/124/profile (delete)
```

#### 4f — Context-Dependent Failures (state validation bypass)
```
Capture 3+ requests from attacker account in sequence.
Test if:
- Step 1 result affects Step 2 ID validation
- Reordering requests bypasses checks
- Repeating same ID twice changes behavior
- ID validation tied to request order, not actual access

Example flow:
1. GET /users/123/profile → returns status: "active"
2. GET /users/124/profile → should fail, but succeeds if state carries over
3. PATCH /users/124/profile → succeeds if context not re-validated
```

### Step 5: Vertical Escalation Testing (Access higher-privilege resources)

If admin_token available:

Test admin-only endpoints with attacker token:
```
Attacker has: role = "user"
Admin has: role = "admin"

Try:
- GET /admin/users (attacker_token) → should 403, but returns all users (BFLA)
- PATCH /admin/settings (attacker_token) → should 403, but succeeds (BFLA)
- DELETE /admin/logs (attacker_token) → should 403, but succeeds (BFLA)
```

Test HTTP method tampering:
```
- GET /admin/users (protected) → 403
- POST /admin/users (same endpoint, different method) → 200 (allows bypass)
- PUT /admin/users → 200
```

Test role substitution:
```
POST /users/update-role
Body: { "user_id": 123, "role": "admin" }
Result: Attacker elevates own role to admin (mass assignment + privilege escalation)
```

### Step 6: Parse Results & Document Findings

For each successful IDOR test, record:

```markdown
## IDOR Findings

### Finding 1: Horizontal Escalation via Direct ID Swap
- **Endpoint:** GET /users/{id}/profile
- **Method:** Horizontal (peer-level access)
- **Technique:** Direct ID Swap (4a)
- **Request:** GET /users/124/profile (attacker accessing victim_id=124)
- **Response:** 200 OK — Returns full victim user profile
- **Data Exposed:** name, email, phone, address, payment_method
- **Severity:** HIGH (Confidentiality breach)
- **Fix:** Validate request.user_id == path.id server-side

### Finding 2: Vertical Escalation via Role Parameter
- **Endpoint:** POST /users/123/update-profile
- **Method:** Vertical (privilege escalation)
- **Technique:** Mass Assignment (4e)
- **Request:** POST with body { "role": "admin" }
- **Response:** 200 OK — Attacker now has admin role
- **Impact:** Full system compromise
- **Severity:** CRITICAL
- **Fix:** Whitelist updatable fields, reject role parameter from user input

### Finding 3: Context-Dependent Bypass via Request Order
- **Endpoint:** POST /transfer
- **Method:** Context-dependent
- **Technique:** State Validation Bypass (4f)
- **Flow:** 
  1. POST /transfer from=123 to=999 amount=100 → success
  2. Immediately POST /transfer from=999 to=123 amount=100 → succeeds (should fail, attacker can't send from 999)
- **Impact:** Funds transferred from unowned account
- **Severity:** CRITICAL
- **Fix:** Lock account state during transaction, re-validate ownership on each transfer
```

Update `vulnerabilities.md`:
```markdown
## IDOR/BFLA Findings

Total: X findings
- Critical: Y
- High: Z
- Medium: W

[List all findings from Step 6]
```

### Step 7: Report & Handoff to /robin

Generate `idor-findings.md`:
```markdown
# Deep IDOR Testing Report

**Target:** <API URL>
**Swagger:** <file>
**Tested Accounts:** Attacker (role: user), Victim (role: user), Admin (role: admin)

## Summary
- Total tests: X
- Vulnerable endpoints: Y
- Horizontal escalations: Z
- Vertical escalations: W

## Findings
[From Step 6]

## Chains Identified
- IF horizontal IDOR on /users/{id}/profile THEN attacker can enumerate all users + extract emails + SSRF via email validation endpoint
- IF vertical escalation on /admin/settings THEN attacker can modify API rate limits + disable audit logging
- IF context-dependent bypass on /transfer THEN attacker can drain multiple accounts + race condition on balance check

## Recommendation
Run `/robin` with these findings to map full exploitation chains.
```

Output to user:
```
[!] Deep IDOR testing complete.

Findings saved to: ./idor-findings.md
Next: Run '/robin' to analyze chains and escalation paths.
```

---

## Rules

1. **No blind guessing:** Always extract real IDs from responses first. If ID not available, test predictable sequences (1-100, common UUIDs).
2. **All 6 techniques:** Test all manipulation methods (4a-4f) on EVERY endpoint. Don't stop at first success.
3. **Document state:** Record what each ID returns, what roles own what resources. Build a mental map.
4. **Method switching:** For every endpoint, test GET/POST/PUT/PATCH/DELETE. Access control sometimes varies by method.
5. **Nested objects:** If response contains nested IDs (e.g., `{ user: { id: 123 } }`), test those too.
6. **No data exfil:** Do NOT extract sensitive data beyond confirming IDOR exists. Check findings without copying PII.
7. **Rate limit aware:** Space requests 300ms apart. If rate limited, pause and resume. Log rate limit responses as findings.
8. **Output to disk:** Pipe all test results to `./idor-test-results.json`. Never echo raw data into context.

---

## Context Handoff Requirements

When calling `/idorDeep`:
- **From `/apiTesting`:** Must have `vulnerabilities.md`, `endpoints.md`, `creds.md`, `api_schema.md`
- **From `/api`:** Must have `progress.md`, `vulnerabilities.md`, `creds.md`, `endpoints.md`
- **Standalone:** None required, but user must provide swagger + credentials

When handing off to `/robin`:
- Output: `idor-findings.md` with all findings + identified chains
- Must include: endpoint, technique, data exposed, severity, fix recommendation
