# Chain: OAuth Scope Downgrade + Cross-Tenant User Enum → Account Takeover

Tags: oauth, oidc, scope-downgrade, token-reuse, implicit-flow, lateral-movement, account-takeover, web, authorization

Chain Severity: High

Entry Condition: OAuth/OIDC flow with implicit or authorization-code flow; broad default scopes (user.read, profile, email, offline_access); no scope validation on token refresh or scope-specific checks per endpoint; multi-tenant or multi-service ecosystem visible

## Node 1 — Intercept Authorization Code
Technique: [[Web/OAuth#Scope Downgrade → Lateral Movement]]
Strike Vector: "authorization code interception"
Condition: Caido proxy active; implicit or auth-code flow accessible; user performs login
Standalone Severity: Low
Branches:
  - `code` parameter captured in redirect URI → Node 2
  - `state` parameter validation enforced → verify state token stored; if mismatch, [TERMINAL] CSRF protected
  - Flow uses `response_mode=fragment` (implicit) → token in URL fragment, visible in browser history or logs → Node 3 (direct token access, skip code exchange)

## Node 2 — Token Exchange with Scope Downgrade
Technique: [[Web/OAuth#Scope Downgrade → Lateral Movement]]
Strike Vector: "scope parameter manipulation during code exchange"
Condition: Authorization code obtained; redirect URI known; scope parameter modifiable in POST request
Standalone Severity: Med
Branches:
  - Original auth URL: `scope=user.read+profile+email+offline_access` → resend code exchange with `scope=user.read` only (remove high-priv scopes) → server honors requested scope, issues token with downgraded scopes → Node 3
  - Authorization Server validates requested scopes against original auth request → scope mismatch rejected → [TERMINAL] Scope binding enforced; retry with original full scope list
  - Refresh token issued but scope bindings retained → offline_access token usable for refresh with original scopes → switch to Node 4 (refresh path)

## Node 3 — Reduced-Scope Token: Secondary Service Enumeration
Technique: [[Web/OAuth#Scope Downgrade → Lateral Movement]]
Strike Vector: "service discovery with downgraded token"
Condition: Access token obtained (downgraded or full scopes); Bearer token usable; secondary services present (e.g., Teams, SharePoint, Slack workspace, internal APIs)
Standalone Severity: Med
Branches:
  - Query `/api/services` or `/api/me/apps` endpoint with downgraded token → returns service list (Teams, Outlook, SharePoint, etc.) → Node 4
  - `/api/me` endpoint with full-scope token reflects scopes → `scopes: ["user.read"]` only → downgrade confirmed; proceed to enumerate secondary services
  - Service enumeration endpoint does not exist → query static service discovery (e.g., crt.sh, GitHub repo for API docs listing all services)

## Node 4 — Cross-Tenant User Enumeration
Technique: [[Web/OAuth#Scope Downgrade → Lateral Movement]]
Strike Vector: "user enumeration via service cross-reference"
Condition: Secondary service(s) identified; /api/users or /api/members endpoint present; email-based lookups available
Standalone Severity: High
Branches:
  - Query `/api/teams/{team-id}/members` or `/graph/users?filter=mail+eq+'victim@example.com'` with downgraded token → response reveals user IDs/permissions (e.g., member, owner, guest) even if user.read scope limited → Node 5
  - Endpoint requires higher-privilege scope → [TERMINAL] Access denied; escalate via refresh token (Node 4 alt) or switch to primary service
  - Rate limiting on user queries → batch via graph batch endpoint (POST `/graph/$batch`) or distribute across multiple tokens

## Node 5 — Credential Spray on Leaked Password + Service Access
Technique: [[Web/OAuth#Scope Downgrade → Lateral Movement]]
Strike Vector: "credential spray on enumerated accounts"
Condition: User list harvested (from Node 4); leaked password or passwordlist available (breach DB, LinkedIn); target service login endpoint known
Standalone Severity: High
Branches:
  - Spray credentials (ffuf, MSOLSpray, or custom script) against login endpoint (`/auth/login`, `/oauth/token`, `/graph/authenticate`) → valid creds found → generate new OAuth token with full scopes → Node 6
  - MFA enforced → spray fails; attempt MFA bypass (SMS intercept, TOTP brute if guessable, or malware delivery)
  - Password spraying against secondary service (e.g., Teams) while OAuth token still valid → if account exists and password matches primary service, lateral access confirmed

## Node 6 — Lateral Privilege Escalation + Data Exfil
Technique: [[Web/OAuth#Scope Downgrade → Lateral Movement]]
Strike Vector: "cross-service privilege escalation"
Condition: Valid credentials obtained for secondary service; new OAuth token generated; admin endpoint or high-priv data accessible via token
Standalone Severity: High
Branches:
  - New token issued with admin scope (if credentials belong to admin account) → query high-priv endpoints (`/api/admin`, `/graph/directoryObjects`, `/api/sensitive-data`) → plaintext credentials, API keys, flags exfiltrated → [TERMINAL] Chain Complete (High)
  - Token scope still limited → if refresh token available from Node 4, request new token with full admin scope (refresh endpoint may not validate scope restrictions as tightly)
  - Cross-tenant access possible (if OAuth client allows multi-tenant) → iterate through other tenant domains; repeat user enum and spray on each → escalate privilege chain across organization

## Detection & Logging Gaps
- Authorization servers often log scope REQUESTED, not scope GRANTED — scope downgrade may not trigger alerts
- Cross-service enumeration queries often return 200 OK with partial data rather than 403, avoiding security logs
- Refresh token usage typically not logged per-scope or per-service — difficult to detect reuse with elevated scopes
