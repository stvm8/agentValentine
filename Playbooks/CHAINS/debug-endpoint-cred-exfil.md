# Chain: Debug Endpoint Exposure + Config Parsing → Credential & API Key Exfil

Tags: debug-endpoint, config-exposure, environment-variables, credentials, api-keys, secrets, infrastructure-misconfig, web, api

Chain Severity: Critical

Entry Condition: Application left in debug or development mode in production; `/debug`, `/health`, `/actuator`, `/__debug__`, or similar admin endpoint accessible; response includes environment variables, config files, or dependency injection metadata; no authentication required

## Node 1 — Debug Endpoint Enumeration
Technique: [[Web/Debug_Endpoints#Debug Endpoint Discovery]]
Strike Vector: "common debug path fuzzing"
Condition: Target domain/path known; no WAF or WAF permissive; http/https accessible
Standalone Severity: Low
Branches:
  - ffuf against wordlist: `/debug`, `/__debug__`, `/debugger`, `/admin/debug`, `/api/debug`, `/actuator`, `/actuator/env`, `/metrics`, `/health`, `/info` → 200 OK response → Node 2
  - Spring Boot actuator endpoints: `/actuator/env`, `/actuator/configprops` → 200 OK → immediately contains ENV vars and config → Node 3
  - Flask debug mode: `/?__debugger__=on` or `/?__debugger__=console` → Werkzeug debugger active → Python REPL accessible → [TERMINAL] Direct RCE (escalate to admin/data exfil) skip to Node 4
  - .env file exposed via web server misconfiguration (`/.env` → text/plain) → parse directly for creds

## Node 2 — Response Analysis: Config Leakage Detection
Technique: [[Web/Debug_Endpoints#Debug Metadata Parsing]]
Strike Vector: "parse debug response for secrets"
Condition: Debug endpoint returns 200 OK; response body contains metadata, config, or runtime info
Standalone Severity: Med
Branches:
  - Response includes `"DATABASE_URL": "postgres://user:pass@host:5432/db"` → credentials extracted → Node 4
  - Response includes `"AWS_ACCESS_KEY_ID": "AKIA..."` or `"AZURE_CONNECTION_STRING"` → cloud creds extracted → Node 4
  - Response includes `"JWT_SECRET": "super-secret-key"` or `"ENCRYPTION_KEY"` → use to forge tokens or decrypt data → Node 3 (escalate to token forging or data decryption)
  - Response lists loaded packages/versions (e.g., Rails, Django, Spring Boot version) → identify known CVEs in those versions → potentially chain with CVE (separate vector)

## Node 3 — Token Forging or Config Manipulation
Technique: [[Web/Debug_Endpoints#Secret Extraction → Token Forging]]
Strike Vector: "jwt secret or encryption key abuse"
Condition: JWT_SECRET, encryption key, or signing key extracted from Node 2
Standalone Severity: High
Branches:
  - JWT_SECRET exposed → craft admin JWT with `{"role": "admin", "user_id": 1}` payload; sign with extracted secret → use forged token on API endpoints → admin endpoints accessible → Node 4
  - Session encryption key exposed → decrypt existing session tokens; inspect for user_id, role fields; forge new session with admin privs
  - API key format known from debug response (e.g., `sk_live_...` pattern) → iterate through debug endpoint to extract multiple keys; test which keys grant highest privileges

## Node 4 — Credential Validation & Account Takeover
Technique: [[Web/Debug_Endpoints#Credential Exfil → Account Takeover]]
Strike Vector: "validate extracted credentials"
Condition: Database, cloud, or API credentials obtained from Node 2; target service accessible
Standalone Severity: High
Branches:
  - Database credentials (PostgreSQL, MySQL, MongoDB) → connect directly: `psql -h HOST -U user -p 5432 db` → query sensitive tables (users, api_keys, flags) → data exfiltrated → Node 5
  - AWS/Azure credentials → use aws-cli or az-cli to enumerate permissions; if creds belong to admin/service principal → S3 bucket access, database snapshots, secrets manager → Node 5
  - API key for internal service (Stripe, Twilio, SendGrid) → use key to access service API; enumerate payment history, send phishing SMS, or access internal webhooks

## Node 5 — Lateral Movement & Full Data Exfil
Technique: [[Web/Debug_Endpoints#Database Access → Full Exfil]]
Strike Vector: "bulk database export"
Condition: Database credentials validated; database accessible; data schema known or enumerable
Standalone Severity: Critical
Branches:
  - Query sensitive tables: `SELECT * FROM users, api_keys, admin_logs, customer_data LIMIT 10000` → export to CSV or JSON → [TERMINAL] Chain Complete (Critical)
  - Database contains credentials for other systems (backup storage, secondary API services, SSH keys in notes) → extract and chain to secondary compromise
  - Audit logging disabled or accessible to current user role → query logs to identify admin accounts for targeted spray or impersonation

## Node 6 — Persistence & Anti-Forensics (Optional)
Technique: [[Web/Debug_Endpoints#Persistence]]
Strike Vector: "maintain access via debug endpoint"
Condition: Debug endpoint still accessible; database or config write access available
Standalone Severity: Critical
Branches:
  - Create new admin user via database: `INSERT INTO users (username, password_hash, role) VALUES ('attacker', hash('password'), 'admin')` → persistent admin access even after debug endpoint patched
  - Modify environment variables (if endpoint allows POST/PUT) to create persistent backdoor or webhook → escalate to application code execution
  - Update logging/monitoring config to suppress alerts on attacker's source IP or API key usage

## Detection & Logging Gaps
- Debug endpoints often not logged to WAF/IDS (treated as informational, not suspicious)
- Environment variable queries do not trigger application-level logging (no business transaction)
- Config exfiltration via debug endpoint often bypasses data loss prevention (DLP) tools (endpoint not classified as sensitive data access)
- Debug endpoint responses cached (headers include Cache-Control) → response accessible via CDN or Wayback Machine after patching
