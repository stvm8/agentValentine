# Chain: GraphQL Batch Query Limit Bypass + MFA Reset Spray → Account Takeover

Tags: graphql, batching, rate-limit-bypass, mfa-reset, account-enumeration, mutation-abuse, web, api

Chain Severity: High

Entry Condition: GraphQL endpoint exposed; batching enabled (POST array of queries); rate limiting implemented per-request or per-client IP, not per-operation; password reset or MFA disable mutations available; user enumeration possible

## Node 1 — GraphQL Batching Endpoint Discovery
Technique: [[Web/GraphQL#Batch Query Detection]]
Strike Vector: "graphql batching feature enumeration"
Condition: GraphQL endpoint identified (`/graphql`, `/api/graphql`, `/gql`); introspection enabled or docs available
Standalone Severity: Low
Branches:
  - Send single query → 200 OK, response received → Node 2
  - Send POST with array `[{query: ...}, {query: ...}]` → 200 OK with array response → batching enabled → Node 2
  - Batching rejected (400/413 response) → [TERMINAL] Batching not supported; pivot to single-query RateLimit bypass or N+1 enumeration
  - GraphQL endpoint not found → enumerate via common paths: `/graphql`, `/api/graphql`, `/query`, `/gql`, `/relay`

## Node 2 — Rate Limit Validation: Per-Request vs Per-Operation
Technique: [[Web/GraphQL#Batch Rate Limit Validation]]
Strike Vector: "rate limit scope discovery"
Condition: Batching confirmed; rate-limiting headers visible (RateLimit-Limit, RateLimit-Remaining, X-RateLimit-*)
Standalone Severity: Med
Branches:
  - Send single query with 100 operations in array → check RateLimit-Remaining: counts as 1 request (not 100 operations) → rate limiting is per-request, not per-operation → Node 3 (exploit confirmed)
  - Send 100 separate single-query requests → RateLimit-Remaining decrements by 1 per request (as expected) → send 50 batched queries in single request → RateLimit-Remaining decrements by 1 total → per-request rate limiting confirmed → Node 3
  - RateLimit-Remaining decrements per-operation (e.g., batch of 10 decrements by 10) → rate limiting correctly implemented per-operation → [TERMINAL] Batch bypass not exploitable; pivot to credential spray at base limit or MFA social engineering

## Node 3 — Enumerate Valid Users (Password Reset Target)
Technique: [[Web/GraphQL#User Enumeration via Batch]]
Strike Vector: "batch user enumeration"
Condition: Rate limiting bypassed; user query or search mutation available; user email/username list obtainable (LinkedIn, GitHub, org site)
Standalone Severity: Med
Branches:
  - Batch 50 queries: `query { user(email: "victim1@example.com") { id exists } }` × 50 different emails in single POST → 50 user lookups in 1 request → response includes `exists: true/false` per email → valid users identified → Node 4
  - Introspection disabled but user search mutation exists (`searchUsers(term: ...)`) → batch 50 searches in single request → Node 4
  - User enum blocked (no user query public) → attempt mutation batching (password reset, MFA disable) directly on guessed usernames; 403 on invalid user vs 200 on valid indicates user existence

## Node 4 — Batch Password Reset Initiation
Technique: [[Web/GraphQL#Batch Mutation Abuse]]
Strike Vector: "batch password reset trigger"
Condition: Valid user list obtained; password reset mutation available (`requestPasswordReset(email: ...)` or similar); rate limiting bypassed per Node 3
Standalone Severity: High
Branches:
  - Batch 50 mutations: `mutation { requestPasswordReset(email: "victim1@example.com") { success resetToken } }` in single POST → 50 reset requests in 1 API call → bypasses per-operation rate limiting → response includes `resetToken` field (unredacted) → Node 5
  - Response includes reset token in response body (common mistake) → extract tokens directly from batch response → skip email interception
  - Reset tokens only sent via email, not in response → attempt to intercept email or access victim's email account (requires secondary vector or social engineering)
  - MFA disable mutation available: `disableMFA(email: ...)` → use batch to disable MFA for 50 users without requiring current password → Node 6

## Node 5 — Token Capture & Extract Reset Links
Technique: [[Web/GraphQL#Password Reset Token Extraction]]
Strike Vector: "password reset token hijacking"
Condition: Reset tokens obtained from Node 4 response or intercepted via email; webhook or callback URL modifiable in request
Standalone Severity: High
Branches:
  - Reset tokens returned unmasked in GraphQL response → copy tokens directly to password reset confirmation endpoint: `POST /reset-password?token=<TOKEN>&new_password=attacker123` → reset executed → Node 6
  - Email-only delivery → attempt to access victim's email via OAuth (if email provider OAuth scope overly broad) or social engineer email provider support; or set up callback webhook to capture reset email via DNS exfiltration
  - Token validity short-lived (< 5 min) → immediately attempt reset; or spam resets to create token queue, allowing delayed token use

## Node 6 — Mass Account Takeover & Lateral Movement
Technique: [[Web/GraphQL#Account Takeover Chain]]
Strike Vector: "bulk password reset execution"
Condition: Reset tokens obtained; password reset endpoint accessible; victim accounts compromised
Standalone Severity: High
Branches:
  - Batch 50 password reset confirmations in single GraphQL mutation → 50 accounts reset in 1 request → iterate through batches to compromise all enumerated users → [TERMINAL] Chain Complete (High)
  - Compromised accounts include admin or privileged users → use admin account to access admin panel, export all user data, disable audit logging, create backdoor account
  - All users reset but no high-priv accounts found → attempt lateral movement via shared resources (document stores, shared folders, internal wikis) accessible to any authenticated user

## Detection & Logging Gaps
- Batch requests often logged as single POST event — operation count not tracked
- GraphQL introspection does not appear in WAF rules (appears as legitimate query)
- Password reset mutation spam logged per-request (1 entry for 50 mutations) not per-operation
- Email interception logs may not correlate with GraphQL batch request timestamps
