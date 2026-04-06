---
title: loot
created: 2026-04-05
modified: 2026-04-05
type: note
tags: [#ctfPlayer #findings]
---

# Loot — Openvaultbank

| Flag | Source | Notes |
|------|--------|-------|
| `OVB{h3alth_ch3ck_l3aks_ev3rything}` | GET /api/v1/health (unauthenticated) | Info disclosure — DB creds + flag |
| `OVB{d3bug_endp0int_sh0uld_b3_d1sabl3d}` | GET /api/v1/debug (unauthenticated) | Debug panel active — Charlie left it on |

## Additional Loot

| Item | Value | Source |
|------|-------|--------|
| Supabase DB creds | postgres.ljvmdzjbrmodpmheugie / C7JjqMazeea49LQw | /health endpoint |
| admin@ovb.com plaintext | admin123 | bundle.js hardcoded |
| alice@ovb.com plaintext | alice123 | bundle.js hardcoded |
| bob@ovb.com plaintext | bob123 | bundle.js hardcoded |
| carol@ovb.com plaintext | carol123 | bundle.js hardcoded |
| JWT algorithm | HS256, 3600s expiry | /debug endpoint |
| All bcrypt hashes | /admin/users | Mass assignment → admin escalation |
| SSN last 4 all users | /admin/accounts | BOLA + Excessive Data Exposure |
| DB direct access | Supabase pooler port 6543 | Health leak → full DB access |
