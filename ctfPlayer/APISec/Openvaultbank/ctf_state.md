# CTF State — Openvaultbank

## Platform
- APISec CTF — https://openvaultbank.com
- Backend: https://web-production-16ec6a.up.railway.app/api/v1
- Date: 2026-04-03

## Flags Captured (2/?)
1. `OVB{h3alth_ch3ck_l3aks_ev3rything}` — GET /api/v1/health (unauthenticated)
2. `OVB{d3bug_endp0int_sh0uld_b3_d1sabl3d}` — GET /api/v1/debug (unauthenticated)

## Active Credentials
- attacker@evil.com / Password123! → role:admin (mass assignment escalated)
- admin@ovb.com / admin123 → original admin
- alice@ovb.com / alice123

## Completed Exploits
- [x] Health endpoint info disclosure (DB creds, flag)
- [x] Debug endpoint discovery (flag)
- [x] Registration (POST /auth/register with ssn_last4 field)
- [x] Mass assignment PUT /profile → role:admin
- [x] BOLA GET /accounts/{id} (any account with any token)
- [x] RBAC bypass GET /admin/accounts (customer token)
- [x] RBAC bypass GET /admin/users (hashed passwords exposed)
- [x] Mass assignment PUT /accounts/{id} (balance, credit_limit)
- [x] ATO POST /auth/reset-request → debug_code in response body
- [x] ATO POST /auth/reset-confirm → reset admin + alice passwords
- [x] Unauthorized fund transfer POST /payments (BOLA)
- [x] Excessive data exposure GET /accounts (SSN, routing numbers)
- [x] Login enumeration POST /auth/token (different messages)
- [x] DB direct access via leaked creds

## Stuck / Unknown
- GET /admin/stats → requires X-Analytics-Key header (401 without it)
  - Not in: rockyou, xato-net-10M, Pwdb-1M, best66+rockyou rules
  - Not in: custom wordlists (OVB theme, developer names, common keys)
  - Status: 3-STRIKES EXHAUSTED — key is likely a random Railway env var
  - jwt_secrets_to_try table was empty (reset cleared it)

## Full API Surface
- POST /auth/register (ssn_last4 required)
- POST /auth/token
- GET /api/v1/health (unauth — flag here)
- GET /api/v1/debug (unauth — flag here)
- GET/PUT /profile
- GET /accounts (own accounts, SSN exposed)
- GET/PUT /accounts/{id} (BOLA — no ownership check)
- GET /accounts/{id}/transactions (BOLA)
- POST /payments (BOLA — no ownership on from_account_id)
- GET /payments/{id} (BOLA)
- GET /admin/accounts (RBAC bypass — no role check)
- GET /admin/users (RBAC bypass — returns hashed passwords)
- GET /admin/stats (requires X-Analytics-Key)
- POST /admin/reset (resets DB to original state)
- POST /auth/reset-request (leaks debug_code)
- POST /auth/reset-confirm

## Backend Info
- FastAPI + SQLAlchemy + Pydantic v2
- Supabase PostgreSQL backend
- JWT HS256, 3600s expiry
- pgjwt extension in DB (sign/verify/algorithm_sign functions)
- Admin default: admin@ovb.com / admin123
