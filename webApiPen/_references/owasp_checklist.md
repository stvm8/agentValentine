# OWASP Coverage Checklist

Use this as a mental checklist. Confirm and log each vector in `vulnerabilities.md`.

## Web Application (OWASP Top 10 2021 + CWE)

- **A01 -- Broken Access Control (CWE-284, CWE-285, CWE-639):** IDOR on object IDs, horizontal/vertical privilege escalation, forced browsing to admin paths, missing function-level access control.
- **A02 -- Cryptographic Failures (CWE-311, CWE-326, CWE-327):** Data transmitted in clear (HTTP), weak ciphers, sensitive data in JS/HTML, insecure cookie flags (no `Secure`, `HttpOnly`, `SameSite`).
- **A03 -- Injection (CWE-89, CWE-79, CWE-94, CWE-917):** SQL, NoSQL, LDAP, OS command, SSTI (Jinja2, Twig, Freemarker), XSS (reflected, stored, DOM), HTML injection.
- **A04 -- Insecure Design (CWE-840):** Missing rate limits on sensitive flows (OTP, password reset), predictable tokens, flawed multi-step logic (skip steps, replay tokens).
- **A05 -- Security Misconfiguration (CWE-16):** Default creds, verbose error messages exposing stack traces, open CORS (`Access-Control-Allow-Origin: *`), exposed debug endpoints (`/actuator`, `/.env`, `/swagger-ui`), directory listing.
- **A06 -- Vulnerable Components (CWE-1035):** Identify versions via headers/JS, cross-reference with public CVEs.
- **A07 -- Auth Failures (CWE-287, CWE-307, CWE-384):** Weak session tokens, missing session invalidation on logout, JWT `alg:none`, JWT algorithm confusion (RS256->HS256), insecure "Remember Me" tokens.
- **A08 -- Software & Data Integrity (CWE-494, CWE-502, CWE-829):** Deserialization (Java, PHP, Python Pickle), insecure CI/CD pipelines, unsigned updates.
- **A09 -- Logging & Monitoring Failures (CWE-778):** Note absence of rate limiting, lack of error alerting (informational -- document, do not exploit).
- **A10 -- SSRF (CWE-918):** URL parameters pointing to internal resources, PDF/image renderers, webhooks that fetch external URLs. Test for cloud metadata (`169.254.169.254`, `fd00:ec2::254`).

## API Security (OWASP API Top 10 2023)

- **API1 -- BOLA/IDOR:** Enumerate object IDs (sequential, UUID prediction, hash-based). Test with different authenticated users' tokens.
- **API2 -- Broken Authentication:** Weak API key generation, missing token expiry, JWT flaws, OAuth misconfiguration (redirect_uri bypass, state parameter missing).
- **API3 -- Broken Object Property Level Authorization (Mass Assignment):** Send unexpected fields in `POST`/`PUT`/`PATCH`. Look for `role`, `isAdmin`, `balance`, `verified` fields.
- **API4 -- Unrestricted Resource Consumption:** Identify but DO NOT test in a way that causes service degradation. Document missing rate limits on expensive operations (file upload, report generation, email sending). Confirm limit absence with 2-3 rapid requests maximum.
- **API5 -- Broken Function Level Authorization:** Test low-privilege users against admin-level methods (`DELETE`, `PUT`) on every endpoint. Check versioned APIs (`/v1/` vs `/v2/` vs `/admin/`).
- **API6 -- Unrestricted Access to Sensitive Business Flows:** Identify flows for account creation, discount application, referral codes, and voting/rating -- check for replay and automation abuse (minimal PoC only).
- **API7 -- SSRF:** Same as A10 above. APIs with `url`, `callback`, `webhook`, `redirect` parameters are primary targets.
- **API8 -- Security Misconfiguration:** GraphQL introspection enabled in production, excessive HTTP methods allowed (`TRACE`, `OPTIONS`), permissive CORS on APIs, exposed API documentation (Swagger/Postman) with real credentials.
- **API9 -- Improper Inventory Management:** Enumerate deprecated API versions (`/v1/`, `/beta/`, `/internal/`). Older versions often lack security controls present in the current version.
- **API10 -- Unsafe Consumption of APIs:** If the target consumes third-party APIs, test for injection via third-party data responses (e.g., webhook payloads parsed unsafely).
