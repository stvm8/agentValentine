# Chain: Go Registration TOCTOU → NULL Permission Admin JWT → Flag
Tags: go, race-condition, toctou, jwt, null-permission, admin, asyncio, aiohttp, web, registration, zero-value
Chain Severity: High
Entry Condition: Go web app with source code review available; non-atomic two-step registration (CreateUser + UpdatePermissions); `PermissionAdmin = 0`; `permission_level` column has no DEFAULT value

## Node 1 — Source Code Review: Non-Atomic Registration
Technique: [[Web/Race_Condition#Go Registration TOCTOU → NULL Permission Admin JWT]]
Strike Vector: "non-atomic registration DB calls"
Condition: Source code accessible (Gogs, Gitea, leaked repo, or CTF-provided); registration handler visible
Standalone Severity: Low
Branches:
  - Two separate DB calls observed (`CreateUser` then `UpdatePermissions`) without transaction → Node 2
  - Atomic single INSERT or transaction wrapping both ops → [TERMINAL] Race window closed — no TOCTOU vulnerability
  - `permission_level` has DEFAULT value (e.g., DEFAULT 1) → NULL will not scan as 0; PermissionAdmin must match DEFAULT value

## Node 2 — Race Window Validation
Technique: [[Web/Race_Condition#Go Registration TOCTOU → NULL Permission Admin JWT]]
Strike Vector: "race window timing confirmation"
Condition: Endpoints known (`/auth/register`, `/auth/login`); Go integer zero-value mechanic confirmed (`var userPerms int` scans NULL as 0)
Standalone Severity: Med
Branches:
  - `PermissionAdmin = 0` constant confirmed in source → timing race is exploitable → Node 3
  - `PermissionAdmin` is non-zero (e.g., 1 or 99) → NULL scans as 0 ≠ PermissionAdmin → [TERMINAL] Race not exploitable for admin — NULL lands as lowest role, not admin
  - App uses `sql.NullInt64` (not `int`) → NULL scan would error, not zero-value → [TERMINAL] Type-safe scanning blocks race

## Node 3 — asyncio/aiohttp Concurrent Race Exploit
Technique: [[Web/Race_Condition#Go Registration TOCTOU → NULL Permission Admin JWT]]
Strike Vector: "asyncio concurrent register+login race"
Condition: Python asyncio + aiohttp available; registration and login endpoints reachable; concurrent 1 register + 30 login requests per attempt
Standalone Severity: High
Branches:
  - Race succeeds — login during NULL window returns JWT → Node 4
  - No tokens returned in batch → attempt count low; retry (success typically within 5–20 attempts across 500 max)
  - Python threading used instead of asyncio → GIL prevents true concurrency → switch to asyncio + aiohttp
  - Rate limiting blocks concurrent requests → add jitter or reduce parallel logins per batch

## Node 4 — NULL→0 Admin JWT: Admin Endpoint Access
Technique: [[Web/Race_Condition#Go Registration TOCTOU → NULL Permission Admin JWT]]
Strike Vector: "admin JWT validation"
Condition: JWT obtained from race window; admin endpoint known (e.g., `/admin`)
Standalone Severity: High
Branches:
  - JWT passes admin check (HTTP 200 on `/admin`) → Node 5
  - JWT returns 403 → race produced non-admin token (UpdatePermissions ran before login); retry race loop
  - JWT expires quickly → race and admin check must be in same attempt loop; automate check immediately on token receipt

## Node 5 — Flag Exfil via Admin Endpoint
Technique: [[Web/Race_Condition#Go Registration TOCTOU → NULL Permission Admin JWT]]
Strike Vector: "admin flag endpoint access"
Condition: Admin JWT confirmed; flag endpoint identified (e.g., `/admin/confessions/approve/flag` or enumerated from source)
Standalone Severity: High
Branches:
  - POST to flag endpoint with admin JWT → plaintext flag in response → [TERMINAL] Chain Complete (High)
  - Flag endpoint path unknown → enumerate admin routes from source code (`/admin/*` handlers) → retry with correct path
