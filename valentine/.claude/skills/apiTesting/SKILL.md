---
description: Automated API security testing via Newman with intelligent auth resolution (e.g., /apiTesting swagger.json OR /apiTesting continue: Acme)
disable-model-invocation: true
---

I am executing the `/apiTesting` command.
**Arguments:** $ARGUMENTS

Evaluate the arguments and execute the corresponding sequence below:

## Syntax 1: New test (arguments contain swagger path or file)
1. **Verify tools:** `which newman` and `node --version`. If Newman missing: `npm install --prefix ~/.npm-global newman newman-reporter-htmlextra`.
2. **Locate swagger:** Find the OpenAPI/Swagger file. If multiple exist, ask user to specify. If none: ask user to provide path or paste content.
3. **Extract target URL:** Ask user: "What is the base URL of the API? (e.g. http://localhost:8081)". Accept env var or default if already set.
4. **Generate collection:** Create `generated/` and `reports/` directories, then run:
   ```bash
   node ./security-tests/generator/generate-collection.js \
     --swagger <swagger-path> \
     --output ./generated/security-collection.json
   ```
5. **Detect auth scheme:** Parse swagger for `securitySchemes`, custom auth headers, and login endpoints. Output findings:
   - No auth → "All endpoints public, proceeding unauthenticated."
   - Bearer/OAuth → "Bearer token auth detected."
   - API Key → "API key auth detected."
   - Basic → "HTTP Basic auth detected."
   - Custom header → "Custom token header detected."
   - Login endpoint found → "Token acquisition endpoint identified."

6. **Acquire tokens (critical):** Follow this decision tree:
   - **A — No auth:** Proceed to step 7 (Newman run).
   - **B — Auth + login endpoint exists:** Run auth-resolver.js:
     ```bash
     node /opt/Pentester/agentValentine/scripts/auth-resolver.js \
       --swagger <swagger-path> \
       --env ./generated/security-collection.environment.json \
       [--credentials ./credentials.json if exists]
     ```
     If exit 0: tokens acquired. Proceed to step 7.
     If exit 2: resolver failed. Go to Case C.
   - **C — Auth required, no login endpoint OR resolver failed:** Ask user:
     > "This API requires authentication but I couldn't acquire a token automatically.
     > I need:
     > 1. An auth token for an **attacker account** (test user)
     > 2. An auth token for a **victim account** (second test user, for BOLA/IDOR)
     > 3. The victim's user ID
     >
     > OR provide credentials (username/password) and the login endpoint path.
     > If you only have one account, I'll skip BOLA tests."
     Store tokens for injection in step 7.
   - **D — API Key only:** Ask: "This API uses API key auth. Please provide your API key."
   - **E — Bearer token (no login):** Ask for attacker + victim tokens.
   - **F — Basic auth:** Ask for username and password. Base64 encode: `echo -n "user:pass" | base64`.

7. **Run Newman:**
   ```bash
   newman run ./generated/security-collection.json \
     --environment ./generated/security-collection.environment.json \
     --env-var "base_url=$TARGET_URL" \
     [--env-var "attacker_token=<token>" if manual] \
     [--env-var "victim_token=<token>" if manual] \
     [--env-var "victim_user_id=<id>" if manual] \
     [--env-var "api_key=<key>" if API key auth] \
     --reporters cli,htmlextra,junit \
     --reporter-htmlextra-export ./reports/security-report.html \
     --reporter-htmlextra-title "Security Report — $(date +%Y-%m-%d)" \
     --reporter-htmlextra-logs \
     --reporter-junit-export ./reports/junit-results.xml \
     --color on \
     --timeout-request 15000 \
     --delay-request 300
   ```
   Capture exit code and save stdout to temp file for parsing.

8. **Parse results:** Read `./reports/junit-results.xml`. For each failed test:
   - Extract endpoint (METHOD /path)
   - Extract test name and failure message
   - Map severity: Critical (auth bypass, BOLA data, injection), High (mass assignment, data leak, CORS wildcard), Medium (missing headers, version disclosure)
   - Write findings to `./reports/findings.md`

9. **Report findings:**
   ```markdown
   ## Security Test Results
   
   **Target:**      <url>
   **Swagger:**     <file>
   **Auth method:** <what was used>
   **Total tests:** <n>
   **Passed:**      <n>
   **Failed:**      <n>
   
   ### Findings
   
   [For each failure:]
   - **Endpoint:** METHOD /path
   - **Test:** <test name>
   - **Finding:** <vulnerability description>
   - **Severity:** Critical | High | Medium
   - **Fix:** One-sentence recommendation
   
   ### No findings
   [If all passed:] No security issues detected in this run.
   ```

10. **Output report path:** `echo "Full report: $(pwd)/reports/security-report.html"` and tell user to open it in browser.

11. **HANDOFF: IDOR/BOLA findings detected**
    If findings include API1 (BOLA) or API5 (BFLA):
    ```markdown
    [!] BOLA/IDOR vulnerabilities detected in automated tests.
    
    **For deep IDOR methodology (encoding tricks, parameter pollution, context-dependent failures):**
    
    Run: /idorDeep swagger.json --from-apiTesting
    
    Context prepared:
    - vulnerabilities.md — automated findings
    - endpoints.md — all ID parameters
    - creds.md — attacker + victim tokens
    - api_schema.md — auth schemes
    
    No re-asking required. Ready to test immediately.
    ```

## Syntax 2: Resume (arguments contain 'continue:')
1. **Locate engagement:** Find `<client>` directory.
2. **Navigate:** `cd` into engagement directory.
3. **Read state:** Load `progress.md`, `vulnerabilities.md`, `creds.md` if they exist.
4. **Resume:** Ask user:
   > "Resume API testing. Do you want to:
   > 1. Re-run tests with updated credentials?
   > 2. Run tests on a different API/swagger file?
   > 3. Continue from where we left off?"
5. Execute corresponding workflow above.

## Auth Quick-Reference

| Swagger Pattern | Detection | Action |
|---|---|---|
| `securitySchemes: bearer` | JWT/OAuth Bearer | Ask for Bearer token |
| `securitySchemes: apiKey` | API key header | Ask for API key |
| `securitySchemes: basic` | HTTP Basic | Ask for username + password |
| Header param: `Authorization-Token` | Custom token | Run auth-resolver.js |
| Header param: `X-API-Key` | API key | Ask for key |
| Login endpoint in paths | Token-based, self-contained | Run auth-resolver.js |
| No security anywhere | Public API | Proceed without auth |

## credentials.json Format

For fully automated token acquisition, ask user to create (never commit):

```json
{
  "attacker": {
    "username": "attacker_user",
    "password": "AttackerPass123!",
    "email": "attacker@test.com"
  },
  "victim": {
    "username": "victim_user",
    "password": "VictimPass123!",
    "email": "victim@test.com"
  }
}
```

Add to `.gitignore`: `credentials.json`

## Rules

1. Always regenerate collection from swagger — never reuse stale collections.
2. Never store tokens in collection file — always inject via `--env-var`.
3. Never commit `credentials.json` — remind user to `.gitignore` it.
4. If Newman exits 1, parse ALL failures before reporting.
5. If an endpoint returns 500 on any test, flag it as a finding.
6. If user only has one account, skip BOLA tests and note in report.
7. Always tell user exactly which variables are missing if run fails due to auth.
8. Pipe all Newman output to disk; never echo raw XML/JSON into context.

## Files Created

- `generated/security-collection.json` — Newman collection
- `generated/security-collection.environment.json` — Auth variables
- `reports/security-report.html` — Full test report (browser-viewable)
- `reports/junit-results.xml` — Machine-readable results
- `reports/findings.md` — Markdown summary
