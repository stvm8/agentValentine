---
tags: [bugbounty, apisec, p1_to_p4, openvaultbank]
date: 2026-04-03
---

# OpenVault Bank — Target Map

## Stack
- Frontend: React SPA (Lovable.app hosted), Vite, Cloudflare CDN
- Backend: FastAPI (Python) → `https://web-production-16ec6a.up.railway.app`
- Database: Supabase PostgreSQL (aws-1-us-west-1.pooler.supabase.com)
- Auth: JWT Bearer (HS256), 1-hour expiry
- API Spec: `https://openvaultbank.com/openapi.yaml` (EXPOSED)

## API Base
`https://web-production-16ec6a.up.railway.app/api/v1`

## All Endpoints (from openapi.yaml)
| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | /auth/register | None | Returns JWT immediately |
| POST | /auth/token | None | Login |
| POST | /auth/reset-request | None | **LEAKS debug_code in response** |
| POST | /auth/reset-confirm | None | Accepts 3-digit code |
| GET | /health | None | **LEAKS full DB credentials + flag** |
| GET | /accounts | Bearer | Own accounts only |
| GET | /accounts/{id} | Bearer | **BOLA — any account readable** |
| PUT | /accounts/{id} | Bearer | **BOLA + balance/limit writable** |
| GET | /accounts/{id}/transactions | Bearer | **BOLA** |
| POST | /payments | Bearer | Transfer between accounts |
| GET | /payments/{id} | Bearer | **BOLA** |
| GET | /profile | Bearer | Own profile |
| PUT | /profile | Bearer | **Mass assignment — role field accepted** |
| GET | /admin/accounts | Bearer+Admin | All accounts + SSN |
| GET | /admin/users | Bearer+Admin | All users + hashed passwords |
| GET | /admin/stats | X-Analytics-Key | Stats (separate password) |
| POST | /admin/reset | None | DB reset (intentional) |

## Leaked Credentials
- **DB URL:** `postgresql://postgres.ljvmdzjbrmodpmheugie:C7JjqMazeea49LQw@aws-1-us-west-1.pooler.supabase.com:6543/postgres`
- **Flag (health):** `OVB{h3alth_ch3ck_l3aks_ev3rything}`
