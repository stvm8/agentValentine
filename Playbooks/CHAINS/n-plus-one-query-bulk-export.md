# Chain: N+1 Query Exploitation + Bulk Export → Mass Data Exfiltration

Tags: n-plus-one, query-optimization, performance-degradation, bulk-export, data-exfil, api, web, sql-injection

Chain Severity: High

Entry Condition: REST/GraphQL API with inefficient query patterns; list endpoints accept pagination or filtering; bulk export or report generation endpoint available; no rate limiting on export operations; database query performance not optimized for large result sets

## Node 1 — N+1 Query Pattern Identification
Technique: [[Web/API_Performance#N+1 Query Detection]]
Strike Vector: "n-plus-one query observation"
Condition: API endpoint returns list of objects with nested relationships (e.g., `/api/users` returns user list with associated teams, projects, permissions); performance monitoring enabled (Caido timing, HTTP timing headers)
Standalone Severity: Low
Branches:
  - Request `/api/users?limit=10` → takes 50ms; request `/api/users?limit=100` → takes 5 seconds (100x multiplier, not linear) → N+1 pattern confirmed → Node 2
  - Response includes timing headers (`Server-Timing: db;dur=5000`) → database query time explicitly visible in response
  - GraphQL field resolver includes related objects without batching (e.g., query users { teams { projects { members } } }) → each nested level triggers separate queries → exponential query growth → Node 2
  - API docs or source code review reveals `for user in users: user.teams = db.query(...)` pattern (sequential loop queries) → N+1 confirmed

## Node 2 — Query Amplification via Pagination Bypass
Technique: [[Web/API_Performance#Pagination Bypass]]
Strike Vector: "pagination limit manipulation"
Condition: N+1 pattern identified; list endpoint accepts `limit` or `page_size` parameter; large limits cause exponential query expansion
Standalone Severity: Med
Branches:
  - Endpoint default: `limit=10` → attempt `limit=10000` or `limit=999999` → no validation on max limit → server processes entire dataset → database overloaded, response time increases 100x → Node 3
  - Endpoint enforces max limit (e.g., `limit >= 1000` rejected) → use negative limit: `limit=-1` or `limit=2147483647` (max int) → bypass validation, request all records → Node 3
  - Pagination via cursor: `cursor=abc123` → mutate cursor to null or manipulate to reset pagination → retrieve all records without iterating through pages
  - Export endpoint ignores pagination entirely: `/api/export?format=csv` → returns all data regardless of `limit` parameter → Node 3

## Node 3 — Trigger Bulk Export Endpoint
Technique: [[Web/API_Performance#Bulk Export Triggering]]
Strike Vector: "bulk export with amplified dataset"
Condition: Pagination bypass confirmed or N+1 amplified; export endpoint accessible (`/api/export`, `/api/report`, `/api/download`); authentication may be required but authorization weak
Standalone Severity: High
Branches:
  - POST `/api/export?format=csv&table=users&limit=999999` → generates CSV with all user records (N+1 queries execute for each row) → response returns file download → Node 4
  - Export endpoint accepts filter parameters: `/api/export?filter=department:engineering` → amplify dataset by requesting all departments in single export, export repeats N+1 for each nested relationship → Node 4
  - Export operation async (returns job ID, file ready later) → request multiple exports simultaneously (`/api/export` 10 times in rapid succession) → database query queue grows, all requests serve same large dataset → Node 4
  - Endpoint lacks role-based access control (RBAC) → any authenticated user can export full dataset (admin-only data exposed to low-priv users)

## Node 4 — File Download & Credential Harvesting
Technique: [[Web/API_Performance#Bulk Export Download]]
Strike Vector: "export file retrieval"
Condition: Export triggered; download URL or file ID returned in response; file contains plaintext data (CSV, JSON, XML)
Standalone Severity: High
Branches:
  - Export response includes file URL: `"download_url": "/api/files/export_123456.csv"` → fetch file → CSV contains plaintext API keys, database passwords, SSH keys → Node 5
  - CSV includes multiple tables: users (credentials), api_keys, payment_methods, internal_docs → parse file for sensitive data
  - Export includes user emails + password hashes → attempt hash cracking (if weak algorithm like MD5/SHA1) → plaintext passwords → credential spray
  - Metadata in export headers includes admin email, server info, API version → use for secondary targeting (phishing, targeted exploit)

## Node 5 — Credential Reuse & Lateral Movement
Technique: [[Web/API_Performance#Credential Exfil → Lateral Movement]]
Strike Vector: "extracted credential reuse"
Condition: Export file obtained; plaintext credentials, API keys, SSH keys, or password hashes extracted
Standalone Severity: High
Branches:
  - Database credentials found in export → connect to production database directly → query sensitive tables (customers, transactions, PII) → [TERMINAL] Chain Complete (High)
  - API keys found → use keys on secondary APIs (internal services, cloud providers, payment processors) → gain access to additional systems
  - SSH keys or service account keys found → use for shell access to production servers, container registries, or deployment systems
  - Password hashes cracked → spray credentials against other services (AD, email, cloud portals) → gain foothold in adjacent systems

## Node 6 — Scale Attack Across Multiple Exports
Technique: [[Web/API_Performance#Bulk Export Chain]]
Strike Vector: "iterative export exploitation"
Condition: Initial export successful; multiple export endpoints or filters available
Standalone Severity: Critical
Branches:
  - Repeat export on secondary tables: `/api/export?table=transactions` → full financial history exfil; `/api/export?table=audit_logs` → security logs containing failed login attempts, privilege changes → [TERMINAL] Chain Complete (Critical)
  - Use discovered admin credentials to enable audit logging bypass or data masking disable → re-export with all sensitive fields visible
  - Automate export spam (script loop over all possible filters and tables) → exfil entire database without touching production server directly

## Detection & Logging Gaps
- N+1 queries logged per-request, not per-query-amplification (appears as 1 export request, not 10,000 database queries)
- Large result set exports often not flagged by WAF/DLP if downloaded as file (file download traffic often bypasses inspection)
- Pagination bypass (limit=999999) may not log if treated as data validation error rather than suspicious behavior
- Export auditing often logs file creation, not file content or recipient — exfiltrated data not audited per exported record
